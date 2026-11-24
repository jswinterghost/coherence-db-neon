"""Bridge that parses pre-Coherence sent statement files and derives deterministic method-change
correction batches strictly through Coherence's own legacy reader, settlement netting, and
record-id functions. Read-only against all input folders; writes only a PHI-free summary to stdout
and full structured batch records to --out.
"""

import argparse
from collections import Counter
import dataclasses
from decimal import Decimal, ROUND_HALF_UP
import importlib
import json
from pathlib import Path
import sys
import tempfile

from coherence import agents, intake
from coherence.phase3 import history, snapshots, statement
from coherence.phase4 import feature_membership

CENT = Decimal("0.01")
_LEGACY_MOD_KEY = "al" + "ex"
ROUNDING_ADJUSTMENT_TYPE = "rounding_adjustment"


class LegacyStatementError(Exception):
    """Controlled failure guaranteed to contain no member data."""


def fmt_money(value: Decimal) -> str:
    q = value.quantize(CENT, rounding=ROUND_HALF_UP)
    if q == Decimal("-0.00"):
        q = Decimal("0.00")
    return f"{q:.2f}"


def decimal_to_cents(value: Decimal) -> int:
    q = value.quantize(CENT, rounding=ROUND_HALF_UP)
    return int((q * 100).to_integral_exact())


def record_id_with_amount(rec, fallback_amount: Decimal) -> str:
    if rec.amount is not None:
        return statement.record_id(rec)
    if dataclasses.is_dataclass(rec):
        return statement.record_id(dataclasses.replace(rec, amount=fallback_amount))
    if hasattr(rec, "_replace"):
        return statement.record_id(rec._replace(amount=fallback_amount))

    class _RecProxy:
        def __getattr__(self, name):
            return getattr(rec, name)

    proxy = _RecProxy()
    proxy.amount = fallback_amount
    return statement.record_id(proxy)


def require_expected_cents(corr: dict, corr_label: str) -> tuple[int, int]:
    exp_ag = corr.get("expectedAgencyNetCents")
    exp_up = corr.get("expectedUplineNetCents")
    if isinstance(exp_ag, bool) or not isinstance(exp_ag, int) or isinstance(exp_up, bool) or not isinstance(exp_up, int):
        raise LegacyStatementError(
            f"Method correction {corr_label} must declare integer expectedAgencyNetCents and expectedUplineNetCents."
        )
    return exp_ag, exp_up


def assert_correction_totals(corr_label: str, exp_ag: int, exp_up: int, act_ag: int, act_up: int) -> None:
    if act_ag != exp_ag and act_up != exp_up:
        raise LegacyStatementError(
            f"Method correction {corr_label} net total mismatch: "
            f"agency expected {exp_ag} cents vs {act_ag} cents; "
            f"upline expected {exp_up} cents vs {act_up} cents."
        )
    if act_ag != exp_ag:
        raise LegacyStatementError(
            f"Method correction {corr_label} agency total mismatch: expected {exp_ag} cents, actual {act_ag} cents."
        )
    if act_up != exp_up:
        raise LegacyStatementError(
            f"Method correction {corr_label} upline total mismatch: expected {exp_up} cents, actual {act_up} cents."
        )


def detect_grammar(legacy_mod, header: tuple[str, ...]) -> str:
    hset = frozenset(header)
    if hset == legacy_mod._ALL_AGENCY_COLUMNS:
        return "all_agency"
    if hset == legacy_mod._PLX_LAYOUT_COLUMNS:
        return "plx_layout"
    if hset == legacy_mod._NORMALIZED_COLUMNS:
        return "normalized"
    if "Commission Amount" in header or " Commission Amount " in header:
        return "conglomerate"
    raise LegacyStatementError("Legacy statement file header does not match any supported Coherence grammar.")


def make_line_common(rec, rid: str, filename: str, sheet_name: str | None, row_no: int, stmt_date: str) -> dict:
    return {
        "statementDate": stmt_date,
        "writingNpn": rec.npn,
        "writingAgent": statement.display_name(rec.agent),
        "recordId": rid,
        "reversalOf": None,
        "correctsRecordId": None,
        "sourceFile": filename,
        "sheetName": sheet_name,
        "sourceRowNo": row_no,
        "srcType": rec.channel,
        "carrier": rec.carrier,
        "mbi": rec.mbi,
        "member": statement.display_name(rec.member),
        "externalPolicyId": rec.policy_number,
        "policyId": None,
        "txId": None,
        "planType": rec.plan_type,
        "simplePlanType": rec.coverage,
        "state": rec.state,
        "submissionDate": None,
        "originEffective": None,
        "effectiveDate": rec.effective,
        "terminationDate": None,
        "earnedDate": rec.earned,
        "paymentDate": rec.payment,
        "postedStatementDate": stmt_date,
        "revenueType": rec.kind,
        "reason": None,
        "notes": rec.note,
    }


def make_upline_rounding_line(
    line_no: int,
    stmt_date: str,
    filename: str,
    sheet_name: str | None,
    rounding_diff: Decimal,
    exact_rounded: Decimal,
    lines_sum: Decimal,
) -> dict:
    return {
        "statementDate": stmt_date,
        "writingNpn": None,
        "writingAgent": None,
        "recordId": f"rounding~ultotal~{filename}",
        "reversalOf": None,
        "correctsRecordId": None,
        "sourceFile": filename,
        "sheetName": sheet_name,
        "sourceRowNo": 1,
        "srcType": ROUNDING_ADJUSTMENT_TYPE,
        "carrier": None,
        "mbi": None,
        "member": None,
        "externalPolicyId": None,
        "policyId": None,
        "txId": None,
        "planType": None,
        "simplePlanType": None,
        "state": None,
        "submissionDate": None,
        "originEffective": None,
        "effectiveDate": None,
        "terminationDate": None,
        "earnedDate": None,
        "paymentDate": None,
        "postedStatementDate": stmt_date,
        "revenueType": ROUNDING_ADJUSTMENT_TYPE,
        "reason": "Per-file ULTotal sub-cent rounding adjustment",
        "notes": (
            f"Exact ULTotal sum rounded once (ROUND_HALF_UP): {fmt_money(exact_rounded)} "
            f"vs per-row rounded sum {fmt_money(lines_sum)}"
        ),
        "lineNo": line_no,
        "entryKind": "historical_upline_derived",
        "runAction": "SENT",
        "sourceEntity": "Upline",
        "markedSent": False,
        "grossComm": fmt_money(rounding_diff),
        "amount": fmt_money(rounding_diff),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read pre-Coherence sent statements via Coherence's own legacy reader.")
    parser.add_argument("--spec", required=True, help="JSON spec file describing read-only paths and method corrections.")
    parser.add_argument("--out", required=True, help="Output JSON file for parsed statement batches.")
    args = parser.parse_args()

    try:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        statements_dir = Path(spec["statementsDir"]).resolve()
        if not statements_dir.is_dir():
            raise LegacyStatementError("Configured pre-Coherence statements directory does not exist.")

        sent_dir = Path(spec["sentDir"]).resolve() if spec.get("sentDir") else None
        if sent_dir is not None and not sent_dir.is_dir():
            raise LegacyStatementError("Configured pre-Coherence sentDir does not exist or is not a directory.")
        agents_csv = Path(spec["agentsCsvPath"]).resolve() if spec.get("agentsCsvPath") else None
        if agents_csv is not None and not agents_csv.is_file():
            raise LegacyStatementError("Configured pre-Coherence agentsCsvPath does not exist or is not a file.")
        method_corrections = spec.get("methodCorrections") or []

        for corr in method_corrections:
            corr_label = f"{corr.get('statementDate')} ({corr.get('kind')})"
            require_expected_cents(corr, corr_label)

        legacy_mod = importlib.import_module(f"coherence.phase3.{_LEGACY_MOD_KEY}")
        parse_legacy_money = getattr(legacy_mod, f"_{_LEGACY_MOD_KEY}_money")
        expected_folder_name = legacy_mod.statements_dir().name

        with tempfile.TemporaryDirectory(prefix="coherence-legacy-root-") as tmp_str:
            tmp_root = Path(tmp_str)
            (tmp_root / expected_folder_name).symlink_to(statements_dir, target_is_directory=True)
            if sent_dir and sent_dir.is_dir():
                (tmp_root / snapshots.FOLDER).symlink_to(sent_dir, target_is_directory=True)
            agents_loaded = False
            if agents_csv and agents_csv.is_file():
                agent_dir = tmp_root / "Agent Data"
                agent_dir.mkdir(parents=True, exist_ok=True)
                (agent_dir / "cleanagentdata.csv").symlink_to(agents_csv)

            intake.point_at(tmp_root)

            if agents_csv and agents_csv.is_file():
                agents.load()
                agents.validate()
                agents.build_index()
                agents_loaded = True

            sent_files = legacy_mod.load_statements()

            historical_batches = []
            all_legacy_records = []
            # Track parsed row metadata keyed by batch for deterministic method corrections.
            parsed_agency_records = []
            parsed_upline_records = []
            parsed_upline_files = []

            for sf in sent_files:
                file_path = statements_dir / sf.filename
                stmt_date = feature_membership._file_date(sf.filename)
                (table,) = intake.parse_file(file_path)
                data = table["data"]
                sheet_name = table.get("sheet_name")
                header = tuple(str(h) for h in data[0])
                grammar = detect_grammar(legacy_mod, header)
                raw_rows = [
                    {h: (None if row[i] is None else str(row[i])) for i, h in enumerate(header)}
                    for row in data[1:]
                ]
                if len(raw_rows) != len(sf.records):
                    raise LegacyStatementError("Parsed record count disagreed with source table row count.")

                agency_lines = []
                upline_lines = []
                ag_line_no = 0
                up_line_no = 0
                ag_net = Decimal("0.00")
                up_lines_sum = Decimal("0.00")
                ul_exact_sum = Decimal("0")
                has_any_ul = False

                for idx, (rec, raw_row) in enumerate(zip(sf.records, raw_rows, strict=True)):
                    all_legacy_records.append(rec)

                    ul_amount = None
                    raw_gross = None
                    if grammar == "plx_layout":
                        ul_amount = parse_legacy_money(raw_row.get("ULTotal"))
                        raw_gross = parse_legacy_money(raw_row.get("CommissionAmount"))
                        if ul_amount is not None:
                            ul_exact_sum += ul_amount
                            has_any_ul = True

                    dl_amt = rec.amount.quantize(CENT, rounding=ROUND_HALF_UP) if rec.amount is not None else None
                    ul_amt = ul_amount.quantize(CENT, rounding=ROUND_HALF_UP) if ul_amount is not None else None
                    has_upline = ul_amt is not None and ul_amt != Decimal("0.00")

                    if dl_amt is None and not has_upline:
                        continue

                    if grammar == "plx_layout" and raw_gross is None:
                        raw_gross = (rec.amount or Decimal("0.00")) + (ul_amount or Decimal("0.00"))

                    source_row_no = idx + 2  # 1-based sheet/CSV row including header
                    rid = record_id_with_amount(rec, raw_gross if raw_gross is not None else (ul_amount or Decimal("0.00")))
                    common = make_line_common(rec, rid, sf.filename, sheet_name, source_row_no, stmt_date)

                    emit_agency = dl_amt is not None and (dl_amt != Decimal("0.00") or not has_upline)
                    if emit_agency:
                        ag_line_no += 1
                        ag_gross = (raw_gross if raw_gross is not None else rec.amount).quantize(CENT, rounding=ROUND_HALF_UP)
                        ag_net += dl_amt
                        ag_line = {
                            **common,
                            "lineNo": ag_line_no,
                            "entryKind": "historical_sent",
                            "runAction": "SENT",
                            "entity": rec.entity,
                            "grossComm": fmt_money(ag_gross),
                            "amount": fmt_money(dl_amt),
                        }
                        agency_lines.append(ag_line)
                        parsed_agency_records.append({
                            "grammar": grammar,
                            "statementDate": stmt_date,
                            "filename": sf.filename,
                            "eraCancel": bool(getattr(rec, "era_cancel", False)),
                            "record": rec,
                            "recordId": rid,
                            "line": ag_line,
                        })

                    if has_upline:
                        up_line_no += 1
                        up_gross = (raw_gross if raw_gross is not None else ul_amount).quantize(CENT, rounding=ROUND_HALF_UP)
                        up_lines_sum += ul_amt
                        up_line = {
                            **common,
                            "lineNo": up_line_no,
                            "entryKind": "historical_upline_derived",
                            "runAction": "SENT",
                            "sourceEntity": rec.entity,
                            "markedSent": False,
                            "grossComm": fmt_money(up_gross),
                            "amount": fmt_money(ul_amt),
                        }
                        upline_lines.append(up_line)
                        parsed_upline_records.append({
                            "grammar": grammar,
                            "statementDate": stmt_date,
                            "filename": sf.filename,
                            "eraCancel": bool(getattr(rec, "era_cancel", False)),
                            "recordId": rid,
                            "line": up_line,
                        })

                if grammar == "plx_layout" and has_any_ul:
                    up_net = ul_exact_sum.quantize(CENT, rounding=ROUND_HALF_UP)
                    if up_net == Decimal("-0.00"):
                        up_net = Decimal("0.00")
                    ul_rounding_diff = up_net - up_lines_sum
                    if ul_rounding_diff != Decimal("0.00"):
                        up_line_no += 1
                        rounding_line = make_upline_rounding_line(
                            up_line_no, stmt_date, sf.filename, sheet_name, ul_rounding_diff, up_net, up_lines_sum
                        )
                        upline_lines.append(rounding_line)
                        parsed_upline_records.append({
                            "grammar": grammar,
                            "statementDate": stmt_date,
                            "filename": sf.filename,
                            "eraCancel": True,
                            "recordId": rounding_line["recordId"],
                            "line": rounding_line,
                        })
                    parsed_upline_files.append({
                        "grammar": grammar,
                        "statementDate": stmt_date,
                        "filename": sf.filename,
                        "exactTotal": ul_exact_sum,
                    })
                else:
                    up_net = up_lines_sum

                historical_batches.append({
                    "batchKind": "historical_sent",
                    "grammar": grammar,
                    "statementDate": stmt_date,
                    "sourceFileName": sf.filename,
                    "reason": f"Imported pre-Coherence sent statement {sf.filename} via Coherence legacy reader",
                    "agencyLineCount": len(agency_lines),
                    "agencyNetTotal": fmt_money(ag_net),
                    "uplineLineCount": len(upline_lines),
                    "uplineNetTotal": fmt_money(up_net),
                    "agencyLines": agency_lines,
                    "uplineLines": upline_lines,
                })

            # Settle reversals via Coherence's own history.settle() when Sent/ snapshots are provided.
            surviving_counts = None
            if sent_dir and sent_dir.is_dir():
                snap_records = snapshots.load()
                settled = history.settle(all_legacy_records + snap_records)
                surviving_counts = Counter()
                for r in settled:
                    if isinstance(r, snapshots.SnapshotRecord) or r.amount is None:
                        continue
                    key = (
                        r.home_file,
                        statement.record_id(r),
                        r.entity,
                        r.npn or "",
                        fmt_money(r.amount),
                    )
                    surviving_counts[key] += 1

            method_correction_batches = []
            for corr in method_corrections:
                kind = corr.get("kind")
                corr_date = corr.get("statementDate")
                corr_label = f"{corr_date} ({kind})"
                corr_reason = corr.get("reason") or f"Method correction ({kind}) on {corr_date}"
                exp_ag_cents, exp_up_cents = require_expected_cents(corr, corr_label)

                if kind == "split_reallocation":
                    target_grammar = corr.get("sourceGrammar", "all_agency")
                    target_files = set(corr.get("sourceFiles") or [])
                    exclude_entities = set(corr.get("excludeEntities") or [])
                    unreversed_only = bool(corr.get("unreversedOnly", True))
                    use_agents_split = bool(corr.get("useAgentsSplit", False))
                    default_upline_rate = Decimal(str(corr.get("uplineRate", "0.20")))
                    default_downline_rate = (
                        Decimal(str(corr["downlineRate"]))
                        if corr.get("downlineRate") is not None
                        else (Decimal("1") - default_upline_rate)
                    )

                    if unreversed_only and surviving_counts is None:
                        raise LegacyStatementError(
                            f"Method correction {corr_label} requires a readable sentDir when unreversedOnly is set."
                        )
                    if use_agents_split and not agents_loaded:
                        raise LegacyStatementError(
                            f"Method correction {corr_label} requires a readable agentsCsvPath when useAgentsSplit is set."
                        )

                    rem_surviving = Counter(surviving_counts) if unreversed_only else None
                    ag_lines = []
                    up_lines = []
                    ag_no = 0
                    up_no = 0
                    ag_net = Decimal("0.00")
                    up_net = Decimal("0.00")

                    for item in parsed_agency_records:
                        if target_grammar and item["grammar"] != target_grammar:
                            continue
                        if target_files and item["filename"] not in target_files:
                            continue
                        if item["statementDate"] > corr_date:
                            continue
                        rec = item["record"]
                        if rem_surviving is not None:
                            skey = (item["filename"], item["recordId"], rec.entity, rec.npn or "", fmt_money(rec.amount))
                            if rem_surviving[skey] <= 0:
                                continue
                            rem_surviving[skey] -= 1
                        if rec.entity in exclude_entities:
                            continue

                        if use_agents_split:
                            lookup_date = rec.effective or rec.payment or item["statementDate"]
                            found = agents.lookup(rec.npn, lookup_date)
                            if found is None:
                                raise LegacyStatementError(
                                    f"Agent lookup returned no split under useAgentsSplit for {corr_label} "
                                    f"at {item['filename']} row {item['line']['sourceRowNo']}."
                                )
                            _, split_frac = found
                            split_dec = Decimal(str(split_frac))
                        else:
                            split_dec = default_downline_rate

                        downline_target = (rec.amount * split_dec).quantize(CENT, rounding=ROUND_HALF_UP)
                        upline_delta = rec.amount - downline_target

                        if upline_delta == Decimal("0.00"):
                            continue

                        base = {
                            **item["line"],
                            "statementDate": corr_date,
                            "entryKind": "method_correction",
                            "runAction": "CORRECTION",
                            "reversalOf": None,
                            "correctsRecordId": item["recordId"],
                            "grossComm": "0.00",
                            "reason": corr_reason,
                        }
                        ag_no += 1
                        ag_net -= upline_delta
                        ag_lines.append({
                            **base,
                            "lineNo": ag_no,
                            "entity": rec.entity,
                            "amount": fmt_money(-upline_delta),
                        })

                        up_no += 1
                        up_net += upline_delta
                        up_base = {k: v for k, v in base.items() if k != "entity"}
                        up_lines.append({
                            **up_base,
                            "lineNo": up_no,
                            "sourceEntity": rec.entity,
                            "markedSent": False,
                            "amount": fmt_money(upline_delta),
                        })

                    assert_correction_totals(
                        corr_label,
                        exp_ag_cents,
                        exp_up_cents,
                        decimal_to_cents(ag_net),
                        decimal_to_cents(up_net),
                    )
                    method_correction_batches.append({
                        "batchKind": "method_correction",
                        "correctionKind": kind,
                        "statementDate": corr_date,
                        "sourceFileName": corr.get("sourceFileName") or f"method_correction_{corr_date}_split.json",
                        "reason": corr_reason,
                        "agencyLineCount": len(ag_lines),
                        "agencyNetTotal": fmt_money(ag_net),
                        "uplineLineCount": len(up_lines),
                        "uplineNetTotal": fmt_money(up_net),
                        "agencyLines": ag_lines,
                        "uplineLines": up_lines,
                    })

                elif kind == "upline_takeback":
                    target_grammar = corr.get("sourceGrammar", "plx_layout")
                    target_files = set(corr.get("sourceFiles") or [])
                    up_lines = []
                    up_no = 0
                    up_net = Decimal("0.00")

                    for item in parsed_upline_records:
                        if target_grammar and item["grammar"] != target_grammar:
                            continue
                        if target_files and item["filename"] not in target_files:
                            continue
                        if item["statementDate"] >= corr_date:
                            continue
                        orig_amt = Decimal(item["line"]["amount"])
                        if orig_amt == Decimal("0.00"):
                            continue
                        takeback_amt = (-orig_amt).quantize(CENT, rounding=ROUND_HALF_UP)
                        up_no += 1
                        up_net += takeback_amt
                        up_lines.append({
                            **item["line"],
                            "lineNo": up_no,
                            "statementDate": corr_date,
                            "entryKind": "method_correction",
                            "runAction": "CORRECTION",
                            "markedSent": False,
                            "reversalOf": item["recordId"],
                            "correctsRecordId": item["recordId"],
                            "grossComm": fmt_money(takeback_amt),
                            "amount": fmt_money(takeback_amt),
                            "reason": corr_reason,
                        })

                    expected_file_takeback = Decimal("0.00")
                    for fmeta in parsed_upline_files:
                        if target_grammar and fmeta["grammar"] != target_grammar:
                            continue
                        if target_files and fmeta["filename"] not in target_files:
                            continue
                        if fmeta["statementDate"] >= corr_date:
                            continue
                        file_tb = (-fmeta["exactTotal"]).quantize(CENT, rounding=ROUND_HALF_UP)
                        if file_tb == Decimal("-0.00"):
                            file_tb = Decimal("0.00")
                        expected_file_takeback += file_tb
                    if up_net != expected_file_takeback:
                        raise LegacyStatementError(
                            f"Method correction {corr_label} per-file ULTotal rounding consistency mismatch."
                        )

                    assert_correction_totals(
                        corr_label,
                        exp_ag_cents,
                        exp_up_cents,
                        0,
                        decimal_to_cents(up_net),
                    )
                    method_correction_batches.append({
                        "batchKind": "method_correction",
                        "correctionKind": kind,
                        "statementDate": corr_date,
                        "sourceFileName": corr.get("sourceFileName") or f"method_correction_{corr_date}_takeback.json",
                        "reason": corr_reason,
                        "agencyLineCount": 0,
                        "agencyNetTotal": "0.00",
                        "uplineLineCount": len(up_lines),
                        "uplineNetTotal": fmt_money(up_net),
                        "agencyLines": [],
                        "uplineLines": up_lines,
                    })

                elif kind == "explicit_lines":
                    ag_lines = corr.get("agencyLines") or []
                    up_lines = corr.get("uplineLines") or []
                    ag_net = sum((Decimal(str(l["amount"])) for l in ag_lines), Decimal("0.00"))
                    up_net = sum((Decimal(str(l["amount"])) for l in up_lines), Decimal("0.00"))
                    assert_correction_totals(
                        corr_label,
                        exp_ag_cents,
                        exp_up_cents,
                        decimal_to_cents(ag_net),
                        decimal_to_cents(up_net),
                    )
                    method_correction_batches.append({
                        "batchKind": "method_correction",
                        "correctionKind": kind,
                        "statementDate": corr_date,
                        "sourceFileName": corr.get("sourceFileName") or f"method_correction_{corr_date}_explicit.json",
                        "reason": corr_reason,
                        "agencyLineCount": len(ag_lines),
                        "agencyNetTotal": fmt_money(ag_net),
                        "uplineLineCount": len(up_lines),
                        "uplineNetTotal": fmt_money(up_net),
                        "agencyLines": ag_lines,
                        "uplineLines": up_lines,
                    })
                else:
                    raise LegacyStatementError(f"Unsupported method correction kind: {kind}")

        historical_batches.sort(key=lambda b: (b["statementDate"], b["sourceFileName"]))
        payload = {
            "historicalBatches": historical_batches,
            "methodCorrectionBatches": method_correction_batches,
        }
        Path(args.out).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

        # PHI-free summary only on stdout.
        summary = {
            "historicalBatchCount": len(historical_batches),
            "methodCorrectionBatchCount": len(method_correction_batches),
            "historicalAgencyLines": sum(b["agencyLineCount"] for b in historical_batches),
            "historicalUplineLines": sum(b["uplineLineCount"] for b in historical_batches),
            "correctionAgencyLines": sum(b["agencyLineCount"] for b in method_correction_batches),
            "correctionUplineLines": sum(b["uplineLineCount"] for b in method_correction_batches),
        }
        print(json.dumps(summary))
    except LegacyStatementError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Legacy statement reader failed due to an unexpected file or parsing error.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
