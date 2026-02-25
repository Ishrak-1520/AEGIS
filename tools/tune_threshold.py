"""
tools/tune_threshold.py
-----------------------
Reads an existing raw_sift_responses.jsonl benchmark file and sweeps score
thresholds from 40 to 95 (step 5) to find the optimal cut-off — no API calls.

Usage:
    python tools/tune_threshold.py --results path/to/raw_sift_responses.jsonl
"""

import argparse
import csv
import json
import sys
from pathlib import Path

DEFAULT_THRESHOLD = 70
THRESHOLDS = list(range(40, 100, 5))  # 40, 45, 50, … 95


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_records(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[WARN] Skipping malformed record on line {lineno}: {exc}",
                      file=sys.stderr)
    return records


def classify(records: list[dict], threshold: int) -> dict:
    """Re-classify every record at *threshold* and return metric dict."""
    green = orange = red = 0

    for rec in records:
        vuln_score = rec.get("vuln_score")
        vuln_issue_count = rec.get("vuln_issue_count", 0) or 0
        fix_recognized = rec.get("fix_recognized", False)

        # Null / missing score → treat as 100 (not vulnerable)
        if vuln_score is None:
            effective_score = 100
        else:
            effective_score = int(vuln_score)

        vuln_predicted = (effective_score < threshold) or (vuln_issue_count > 0)

        if vuln_predicted and fix_recognized:
            green += 1
        elif vuln_predicted and not fix_recognized:
            orange += 1
        else:
            red += 1

    total = green + orange + red
    if total == 0:
        return {}

    precision = green / (green + orange) if (green + orange) > 0 else 0.0
    recall    = green / (green + red)    if (green + red)    > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    return {
        "threshold":   threshold,
        "green":       green,
        "orange":      orange,
        "red":         red,
        "total":       total,
        "green_pct":   100 * green  / total,
        "orange_pct":  100 * orange / total,
        "red_pct":     100 * red    / total,
        "precision":   precision,
        "recall":      recall,
        "f1":          f1,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

HEADER = (
    f"{'Thresh':>6}  "
    f"{'Green':>5} {'Green%':>7}  "
    f"{'Orange':>6} {'Orange%':>8}  "
    f"{'Red':>4} {'Red%':>6}  "
    f"{'Prec':>6}  {'Recall':>6}  {'F1':>6}  "
    f"{'Notes'}"
)
ROW_FMT = (
    "{threshold:>6}  "
    "{green:>5} {green_pct:>6.1f}%  "
    "{orange:>6} {orange_pct:>7.1f}%  "
    "{red:>4} {red_pct:>5.1f}%  "
    "{precision:>6.3f}  {recall:>6.3f}  {f1:>6.3f}  "
    "{notes}"
)


def print_table(rows: list[dict], best_f1_thresh: int, best_green_thresh: int) -> None:
    sep = "-" * len(HEADER)
    print()
    print(HEADER)
    print(sep)
    for r in rows:
        notes = []
        if r["threshold"] == best_f1_thresh:
            notes.append("◀ best F1")
        if r["threshold"] == best_green_thresh:
            notes.append("◀ best Green%")
        if r["threshold"] == DEFAULT_THRESHOLD:
            notes.append("(current default)")
        r_display = dict(r, notes=" | ".join(notes))
        print(ROW_FMT.format(**r_display))
    print(sep)
    print()


def save_csv(rows: list[dict], out_path: Path) -> None:
    fieldnames = [
        "threshold", "green", "orange", "red", "total",
        "green_pct", "orange_pct", "red_pct",
        "precision", "recall", "f1",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: (f"{r[k]:.4f}" if isinstance(r[k], float) else r[k])
                             for k in fieldnames})
    print(f"Full table saved → {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sweep SIFT score thresholds over existing benchmark results."
    )
    parser.add_argument(
        "--results",
        required=True,
        metavar="FILE",
        help="Path to raw_sift_responses.jsonl",
    )
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.is_file():
        sys.exit(f"[ERROR] File not found: {results_path}")

    records = load_records(results_path)
    if not records:
        sys.exit("[ERROR] No valid records loaded — check the file format.")

    print(f"\nLoaded {len(records)} records from: {results_path}")

    rows: list[dict] = []
    for t in THRESHOLDS:
        row = classify(records, t)
        if row:
            rows.append(row)

    if not rows:
        sys.exit("[ERROR] Classification produced no results.")

    best_f1_thresh    = max(rows, key=lambda r: r["f1"])["threshold"]
    best_green_thresh = max(rows, key=lambda r: r["green_pct"])["threshold"]

    print_table(rows, best_f1_thresh, best_green_thresh)

    # Summary
    best_f1_row    = next(r for r in rows if r["threshold"] == best_f1_thresh)
    best_green_row = next(r for r in rows if r["threshold"] == best_green_thresh)
    default_row    = next((r for r in rows if r["threshold"] == DEFAULT_THRESHOLD), None)

    print(f"  Best F1      → threshold={best_f1_thresh}  "
          f"F1={best_f1_row['f1']:.3f}  "
          f"Green={best_f1_row['green_pct']:.1f}%")
    print(f"  Best Green%  → threshold={best_green_thresh}  "
          f"Green={best_green_row['green_pct']:.1f}%  "
          f"F1={best_green_row['f1']:.3f}")
    if default_row:
        print(f"  Default ({DEFAULT_THRESHOLD})   → "
              f"F1={default_row['f1']:.3f}  "
              f"Green={default_row['green_pct']:.1f}%")
    print()

    # Save CSV next to this script, in tools/
    out_path = Path(__file__).parent / "threshold_sweep_results.csv"
    save_csv(rows, out_path)


if __name__ == "__main__":
    main()
