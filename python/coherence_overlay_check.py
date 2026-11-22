"""Extended Nusear overlay checker for the Coherence database web app (R5.8).

Runs under the run's sealed Coherence Python environment so ONLY Coherence's own
overlay reader (`coherence.overlay._read`) ever parses an approvals file.

Modes:
  1. Run review check:
     python coherence_overlay_check.py <date> <candidate_path> <surface> [--out <json_path>]
  2. Standalone approvals file parse (for priors and historical imports):
     python coherence_overlay_check.py --parse-only <candidate_path> [--extends <parent_path>] [--out <json_path>]

Prints one compact JSON summary line (no member data) to stdout.
If --out <json_path> is provided, writes the full JSON report including `new_rows` to that file.
Exits non-zero with a plain message (no member data) on any refusal. Reads only; writes nothing to the run folder.
"""

import argparse
import json
import sys
from pathlib import Path

import polars as pl
from coherence import overlay, run


def detect_header_kind(path: Path) -> str:
    if not path.is_file():
        raise ValueError("Approvals file is missing.")
    frame = pl.read_csv(path, n_rows=0, infer_schema_length=0, null_values="")
    cols = tuple(frame.columns)
    if cols == overlay.ADJUSTMENT_COLUMNS:
        return "v2"
    if cols == overlay.ADJUSTMENT_COLUMNS_V1:
        return "v1"
    raise ValueError("The saved file header does not match the v1 or v2 overlay contract.")


def normalize_row(row: dict, row_no: int) -> dict:
    out = {"row_no": row_no}
    for col in overlay.ADJUSTMENT_COLUMNS:
        val = row.get(col)
        out[col] = None if val is None or val == "" else str(val)
    return out


def validate_rows_have_ids(rows: list[dict]) -> None:
    for idx, row in enumerate(rows, start=1):
        if not row.get("record_id"):
            raise ValueError(f"Approvals row {idx} carries no record_id.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and parse a Coherence overlay.csv using Coherence's own reader.")
    parser.add_argument("--parse-only", action="store_true", help="Parse a standalone overlay.csv without a run folder.")
    parser.add_argument("--extends", default=None, help="Optional parent overlay.csv path for --parse-only prefix check.")
    parser.add_argument("--out", default=None, help="Path to write full JSON payload including new_rows.")
    parser.add_argument("args", nargs="+")
    parsed = parser.parse_args()

    try:
        if parsed.parse_only:
            if len(parsed.args) != 1:
                raise ValueError("Usage: --parse-only <candidate_path>")
            candidate = Path(parsed.args[0])
            header_kind = detect_header_kind(candidate)
            rows = overlay._read(candidate)
            validate_rows_have_ids(rows)
            parent_rows = overlay._read(Path(parsed.extends)) if parsed.extends else []
            if parent_rows and rows[: len(parent_rows)] != parent_rows:
                raise ValueError("The approvals file does not begin with every row of its parent approvals file.")
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
        else:
            if len(parsed.args) != 3:
                raise ValueError("Usage: <date> <candidate_path> <surface>")
            date, candidate_str, surface = parsed.args
            if surface not in ("bible", "adjust"):
                raise ValueError("Surface must be 'bible' or 'adjust'.")
            candidate = Path(candidate_str)
            header_kind = detect_header_kind(candidate)
            root = run.root(date)
            prior = overlay._read(root / overlay.PRIOR_REL)
            rows = overlay._read(candidate)
            validate_rows_have_ids(rows)
            if rows[: len(prior)] != prior:
                raise ValueError("The saved file does not begin with the run's prior approvals.")
            current = overlay._read(root / overlay.RUN_REL) if surface == "adjust" else []
            if current and rows[: len(current)] != current:
                raise ValueError("The saved file does not begin with this run's Bible review.")
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
            out_path.write_text(json.dumps({**summary, "new_rows": new_rows}, ensure_ascii=False), encoding="utf-8")
            print(json.dumps(summary))
        else:
            print(json.dumps({**summary, "new_rows": new_rows}, ensure_ascii=False))
    except Exception as exc:
        # Never print member data / record_ids to stderr; emit concise reason only.
        msg = str(exc).splitlines()[0] if str(exc) else "Overlay check failed."
        print(msg, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
