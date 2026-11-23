"""Overlay checker that runs inside the run's sealed Coherence Python environment so only Coherence's own reader (coherence.overlay._read) parses approvals files.

Supports run review checks (<date> <candidate_path> <surface>) and standalone parsing (--parse-only <candidate_path> [--extends <parent_path>]). Prints one member-data-free JSON summary to stdout; writes full new_rows JSON only to --out. Read-only against the run folder.
"""

import argparse
import json
import sys
from pathlib import Path

import polars as pl
from coherence import overlay, run


class OverlayValidationError(Exception):
    """Controlled validation failure guaranteed to contain no member data."""


def detect_header_kind(path: Path) -> str:
    if not path.is_file():
        raise OverlayValidationError("Approvals file is missing.")
    frame = pl.read_csv(path, n_rows=0, infer_schema_length=0, null_values="")
    cols = tuple(frame.columns)
    if cols == overlay.ADJUSTMENT_COLUMNS:
        return "v2"
    if cols == overlay.ADJUSTMENT_COLUMNS_V1:
        return "v1"
    raise OverlayValidationError("The saved file header does not match the v1 or v2 overlay contract.")


def normalize_row(row: dict, row_no: int | None = None) -> dict:
    out = {} if row_no is None else {"row_no": row_no}
    for col in overlay.ADJUSTMENT_COLUMNS:
        val = row.get(col)
        out[col] = None if val is None or val == "" else str(val)
    return out


def find_first_diff_row(parent_rows: list[dict], rows: list[dict]) -> int:
    limit = min(len(parent_rows), len(rows))
    for idx in range(limit):
        if rows[idx] != parent_rows[idx]:
            return idx + 1
    return limit + 1


def validate_rows_have_ids(rows: list[dict]) -> None:
    for idx, row in enumerate(rows, start=1):
        if not row.get("record_id"):
            raise OverlayValidationError(f"Approvals row {idx} carries no record_id.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and parse a Coherence overlay.csv using Coherence's own reader.")
    parser.add_argument("--parse-only", action="store_true", help="Parse a standalone overlay.csv without a run folder.")
    parser.add_argument("--extends", default=None, help="Optional parent overlay.csv path for --parse-only prefix check.")
    parser.add_argument("--answers", action="store_true", help="Include overlay.current() (and optional bible.answers()) in --out JSON.")
    parser.add_argument("--bible-keys-file", default=None, help="Optional JSON file containing an array of Bible record_id keys.")
    parser.add_argument("--out", default=None, help="Path to write full JSON payload including new_rows.")
    parser.add_argument("args", nargs="+")
    parsed = parser.parse_args()

    try:
        extra_payload: dict = {}
        if parsed.parse_only:
            if len(parsed.args) != 1:
                raise OverlayValidationError("Usage: --parse-only <candidate_path>")
            candidate = Path(parsed.args[0])
            header_kind = detect_header_kind(candidate)
            rows = overlay._read(candidate)
            validate_rows_have_ids(rows)
            parent_rows = overlay._read(Path(parsed.extends)) if parsed.extends else []
            if parent_rows and rows[: len(parent_rows)] != parent_rows:
                first_diff = find_first_diff_row(parent_rows, rows)
                raise OverlayValidationError(
                    f"The approvals file does not begin with every row of its parent approvals file (first differing row: {first_diff})."
                )
            shared = len(parent_rows)
            new_rows = [normalize_row(row, shared + i + 1) for i, row in enumerate(rows[shared:])]
            summary = {
                "header_kind": header_kind,
                "prior": shared,
                "current": 0,
                "shared": shared,
                "rows": len(rows),
                "added": len(new_rows),
            }
            if parsed.answers or parsed.bible_keys_file:
                current_map = overlay.current(rows)
                extra_payload["current_by_key"] = {
                    k: normalize_row(v) for k, v in current_map.items()
                }
                summary["current_count"] = len(current_map)
                if parsed.bible_keys_file:
                    keys_data = json.loads(Path(parsed.bible_keys_file).read_text(encoding="utf-8"))
                    if not isinstance(keys_data, list):
                        raise OverlayValidationError("Bible keys file must contain a JSON array.")
                    from coherence.phase3 import bible as bible_mod

                    bible_map = bible_mod.answers(rows, {str(k) for k in keys_data})
                    extra_payload["bible_answers_by_key"] = {
                        k: normalize_row(v) for k, v in bible_map.items()
                    }
                    summary["bible_answer_count"] = len(bible_map)
        else:
            if len(parsed.args) != 3:
                raise OverlayValidationError("Usage: <date> <candidate_path> <surface>")
            date, candidate_str, surface = parsed.args
            if surface not in ("bible", "adjust"):
                raise OverlayValidationError("Surface must be 'bible' or 'adjust'.")
            candidate = Path(candidate_str)
            header_kind = detect_header_kind(candidate)
            root = run.root(date)
            prior = overlay._read(root / overlay.PRIOR_REL)
            rows = overlay._read(candidate)
            validate_rows_have_ids(rows)
            if rows[: len(prior)] != prior:
                first_diff = find_first_diff_row(prior, rows)
                raise OverlayValidationError(
                    f"The saved file does not begin with the run's prior approvals (first differing row: {first_diff})."
                )
            current = overlay._read(root / overlay.RUN_REL) if surface == "adjust" else []
            if current and rows[: len(current)] != current:
                first_diff = find_first_diff_row(current, rows)
                raise OverlayValidationError(
                    f"The saved file does not begin with this run's Bible review (first differing row: {first_diff})."
                )
            shared = max(len(prior), len(current))
            new_rows = [normalize_row(row, shared + i + 1) for i, row in enumerate(rows[shared:])]
            summary = {
                "header_kind": header_kind,
                "prior": len(prior),
                "current": len(current),
                "shared": shared,
                "rows": len(rows),
                "added": len(new_rows),
            }

        if parsed.out:
            out_path = Path(parsed.out)
            out_path.write_text(
                json.dumps({**summary, "new_rows": new_rows, **extra_payload}, ensure_ascii=False),
                encoding="utf-8",
            )
            print(json.dumps(summary))
        else:
            print(json.dumps({**summary, "new_rows": new_rows, **extra_payload}, ensure_ascii=False))
    except OverlayValidationError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Overlay check failed due to an unexpected file or parsing error.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
