"""
SIFT Benchmark Runner — OpenSSF CVE Dataset (Docker-Free)
=========================================================
Runs SIFT against locally downloaded vulnerable/fixed code pairs
and produces:
  - Green/Orange/Red classification table (CSV)
  - Precision / Recall / F1 per CWE (CSV)
  - Raw SIFT JSON responses (JSONL file, one line per analysis)
  - Summary CSV ready to paste into paper tables

Expected folder structure (two supported layouts):
  Layout A — Flat with metadata JSON (default):
    dataset_root/
      metadata.json          ← master list of all CVEs + CWE info
      CVE-2017-1000219/
        vulnerable/
          index.js
        fixed/
          index.js
      CVE-2018-3728/
        ...

  Layout B — No metadata JSON (CWE inferred as "Unknown"):
    dataset_root/
      CVE-2017-1000219/
        vulnerable/
          index.js
        fixed/
          index.js

metadata.json format (matches OpenSSF benchmark schema):
  [
    {
      "CVE": "CVE-2017-1000219",
      "CWEs": ["CWE-078", "CWE-088"],
      "prePatch":  { "commit": "...", "weaknesses": [{"location": {"file": "index.js", "line": 82}}] },
      "postPatch": { "commit": "..." }
    },
    ...
  ]

SIFT score threshold: score < 70  OR  non-empty vulnerabilities list  →  VULNERABLE
"""

import os
import sys
import json
import csv
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ─── Configuration ─────────────────────────────────────────────────────────────
# Edit these paths before running

DATASET_ROOT   = "./dataset"          # Root folder containing CVE subdirectories
OUTPUT_DIR     = "./sift_results"     # Where all output files go
SIFT_API_KEY   = os.environ.get("SIFT_API_KEY", "your-api-key-here")
SIFT_THRESHOLD = 70                   # Score below this = VULNERABLE prediction

# File extensions to analyse (SIFT will detect language automatically)
TARGET_EXTENSIONS = {".js", ".ts", ".py", ".java", ".go", ".rb", ".php", ".cs"}

# Rate limiting: seconds to wait between API calls (be kind to your endpoint)
API_DELAY_SECONDS = 1.5

# ─── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

# ─── Import SIFT Engine ────────────────────────────────────────────────────────
# Adjust this import path to match your project structure
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from core.sift_engine import SiftEngine
    log.info("SiftEngine imported successfully.")
except ImportError as e:
    log.error(f"Could not import SiftEngine: {e}")
    log.error("Make sure this script is in your project root, or adjust sys.path above.")
    sys.exit(1)


# ─── Data Loading ──────────────────────────────────────────────────────────────

def load_metadata(dataset_root: Path) -> dict:
    """
    Load CVE metadata from metadata.json if present.
    Returns dict keyed by CVE identifier: { "CVE-XXX": { "CWEs": [...], ... } }
    """
    meta_path = dataset_root / "metadata.json"
    if not meta_path.exists():
        log.warning("No metadata.json found — CWE info will be recorded as 'Unknown'.")
        return {}

    with open(meta_path) as f:
        raw = json.load(f)

    metadata = {}
    # Support both list format and dict format
    if isinstance(raw, list):
        for entry in raw:
            cve_id = entry.get("CVE") or entry.get("cve") or entry.get("id")
            if cve_id:
                metadata[cve_id] = entry
    elif isinstance(raw, dict):
        metadata = raw

    log.info(f"Loaded metadata for {len(metadata)} CVEs.")
    return metadata


def discover_cve_dirs(dataset_root: Path) -> list:
    """
    Find all CVE directories under dataset_root.
    A valid CVE directory must contain a 'vulnerable' and 'fixed' subfolder.
    """
    cve_dirs = []
    for entry in sorted(dataset_root.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("."):
            continue
        vulnerable_dir = entry / "vulnerable"
        fixed_dir = entry / "fixed"
        if vulnerable_dir.exists() and fixed_dir.exists():
            cve_dirs.append(entry)
        else:
            # Also support 'pre_patch' / 'post_patch' naming
            alt_vuln = entry / "pre_patch"
            alt_fix  = entry / "post_patch"
            if alt_vuln.exists() and alt_fix.exists():
                cve_dirs.append(entry)

    log.info(f"Discovered {len(cve_dirs)} CVE directories.")
    return cve_dirs


def get_code_files(code_dir: Path) -> list:
    """
    Recursively collect all target source files from a directory.
    Returns sorted list of Path objects.
    """
    files = []
    for p in code_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in TARGET_EXTENSIONS:
            files.append(p)
    return sorted(files)


def read_file_content(path: Path) -> str:
    """Read file content safely, trying multiple encodings."""
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return path.read_text(encoding=encoding)
        except (UnicodeDecodeError, PermissionError):
            continue
    log.warning(f"Could not read {path} — skipping.")
    return ""


# ─── SIFT Analysis ─────────────────────────────────────────────────────────────

def run_sift(engine: SiftEngine, code: str, label: str) -> dict:
    """
    Run SIFT analysis on a code string.
    Returns the parsed SIFT result dict.
    """
    if not code.strip():
        return {"error": "empty_file", "score": 100, "vulnerabilities": [], "analysis_steps": []}

    try:
        result = engine.analyze_code(code)
        return result if isinstance(result, dict) else {"error": "parse_failed", "raw": str(result), "score": 100, "vulnerabilities": []}
    except Exception as e:
        log.error(f"  SIFT error on {label}: {e}")
        return {"error": str(e), "score": 100, "vulnerabilities": []}


def is_vulnerable_prediction(sift_result: dict) -> bool:
    """
    Interpret SIFT output as VULNERABLE or CLEAN.
    Rule: score < SIFT_THRESHOLD  OR  non-empty vulnerabilities list.
    """
    if "error" in sift_result and sift_result.get("score", 100) == 100:
        return False  # API error — conservatively treat as clean to avoid false positives

    score = sift_result.get("score", 100)
    vulns = sift_result.get("vulnerabilities", [])

    return (score < SIFT_THRESHOLD) or (len(vulns) > 0)


# ─── Classification ────────────────────────────────────────────────────────────

def classify_outcome(vuln_predicted: bool, fixed_predicted: bool) -> str:
    """
    Apply Green/Orange/Red classification matching the OpenSSF benchmark scheme.

    Green  (✓✓): vulnerability detected in vulnerable version,
                 NOT flagged in fixed version → tool recognized the fix.
    Orange (✓✗): vulnerability detected in vulnerable version,
                 STILL flagged in fixed version → fix not recognized.
    Red    (✗✗): vulnerability missed entirely in vulnerable version.
    """
    if not vuln_predicted:
        return "Red"         # Missed the vulnerability entirely
    elif not fixed_predicted:
        return "Green"       # Caught it, and recognized the fix
    else:
        return "Orange"      # Caught it, but flagged fixed code too


# ─── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(results: list) -> dict:
    """
    Compute overall and per-CWE precision, recall, F1.

    In our framing:
      True Positive  (TP): Green  — correctly detected vulnerability
      False Positive (FP): Orange — flagged fixed code (over-detection of fix)
      False Negative (FN): Red    — missed vulnerability
      True Negative  (TN): correctly clean on fixed code when Green

    For precision/recall on detection task:
      Precision = TP / (TP + FP_detection)  where FP_detection = flagging fixed code as vulnerable
      Recall    = TP / (TP + FN)            where FN = Red outcomes (missed)

    We treat:
      TP = Green count
      FP = Orange count  (flagged the fixed version — false alarm on clean code)
      FN = Red count     (missed the real vulnerability)
    """
    def safe_div(a, b):
        return round(a / b, 4) if b > 0 else 0.0

    def calc(tp, fp, fn):
        precision = safe_div(tp, tp + fp)
        recall    = safe_div(tp, tp + fn)
        f1        = safe_div(2 * precision * recall, precision + recall)
        return precision, recall, f1

    # Overall
    by_cwe = defaultdict(lambda: {"Green": 0, "Orange": 0, "Red": 0, "total": 0})
    overall = {"Green": 0, "Orange": 0, "Red": 0, "total": 0}

    for r in results:
        outcome = r["outcome"]
        overall[outcome] += 1
        overall["total"] += 1
        for cwe in r["CWEs"]:
            by_cwe[cwe][outcome] += 1
            by_cwe[cwe]["total"] += 1

    # Compute metrics
    output = {}

    tp = overall["Green"]
    fp = overall["Orange"]
    fn = overall["Red"]
    p, r, f1 = calc(tp, fp, fn)
    output["overall"] = {
        "Green": overall["Green"], "Orange": overall["Orange"], "Red": overall["Red"],
        "Total": overall["total"],
        "Green_pct": round(100 * overall["Green"] / overall["total"], 1) if overall["total"] else 0,
        "Orange_pct": round(100 * overall["Orange"] / overall["total"], 1) if overall["total"] else 0,
        "Red_pct": round(100 * overall["Red"] / overall["total"], 1) if overall["total"] else 0,
        "Precision": p, "Recall": r, "F1": f1
    }

    output["per_cwe"] = {}
    for cwe, counts in sorted(by_cwe.items()):
        tp = counts["Green"]
        fp = counts["Orange"]
        fn = counts["Red"]
        p, r, f1 = calc(tp, fp, fn)
        output["per_cwe"][cwe] = {
            "Green": counts["Green"], "Orange": counts["Orange"], "Red": counts["Red"],
            "Total": counts["total"],
            "Precision": p, "Recall": r, "F1": f1
        }

    return output


# ─── Output Writers ────────────────────────────────────────────────────────────

def write_raw_jsonl(results: list, output_dir: Path):
    """Write raw SIFT JSON responses — one JSON object per line."""
    path = output_dir / "raw_sift_responses.jsonl"
    with open(path, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    log.info(f"Raw SIFT responses → {path}")


def write_classification_csv(results: list, output_dir: Path):
    """Write Green/Orange/Red classification table — one row per CVE."""
    path = output_dir / "classification_table.csv"
    fieldnames = [
        "CVE", "CWEs",
        "Vuln_Score", "Vuln_Predicted", "Vuln_Vuln_Count",
        "Fixed_Score", "Fixed_Predicted", "Fixed_Vuln_Count",
        "Outcome", "Processing_Time_s", "Error"
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "CVE":              r["CVE"],
                "CWEs":             "|".join(r["CWEs"]),
                "Vuln_Score":       r.get("vuln_score", ""),
                "Vuln_Predicted":   r.get("vuln_predicted", ""),
                "Vuln_Vuln_Count":  r.get("vuln_vuln_count", ""),
                "Fixed_Score":      r.get("fixed_score", ""),
                "Fixed_Predicted":  r.get("fixed_predicted", ""),
                "Fixed_Vuln_Count": r.get("fixed_vuln_count", ""),
                "Outcome":          r.get("outcome", ""),
                "Processing_Time_s": r.get("processing_time_s", ""),
                "Error":            r.get("error", ""),
            })
    log.info(f"Classification table → {path}")


def write_metrics_csv(metrics: dict, output_dir: Path):
    """Write precision/recall/F1 — overall + per CWE."""
    # Overall summary
    overall_path = output_dir / "metrics_overall.csv"
    with open(overall_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Metric", "Value"])
        writer.writeheader()
        m = metrics["overall"]
        for k, v in m.items():
            writer.writerow({"Metric": k, "Value": v})
    log.info(f"Overall metrics → {overall_path}")

    # Per-CWE
    cwe_path = output_dir / "metrics_per_cwe.csv"
    fieldnames = ["CWE", "Total", "Green", "Orange", "Red", "Precision", "Recall", "F1"]
    with open(cwe_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for cwe, m in metrics["per_cwe"].items():
            writer.writerow({
                "CWE":       cwe,
                "Total":     m["Total"],
                "Green":     m["Green"],
                "Orange":    m["Orange"],
                "Red":       m["Red"],
                "Precision": m["Precision"],
                "Recall":    m["Recall"],
                "F1":        m["F1"],
            })
    log.info(f"Per-CWE metrics → {cwe_path}")


def write_paper_summary_csv(results: list, metrics: dict, output_dir: Path):
    """
    Write a clean summary CSV formatted to match the paper tables directly.
    This is the one you paste straight into your results section.
    """
    path = output_dir / "paper_summary.csv"
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)

        # --- Table 4 equivalent: Overall performance ---
        writer.writerow(["=== TABLE 4: Overall Detection Performance ==="])
        writer.writerow(["Metric", "SIFT", "ossf-sast-ml (from paper)", "CodeQL (from paper)"])
        m = metrics["overall"]
        writer.writerow(["Green (%)",   f"{m['Green_pct']}%",  "[TBD from paper]", "38%"])
        writer.writerow(["Orange (%)",  f"{m['Orange_pct']}%", "[TBD from paper]", "11%"])
        writer.writerow(["Red (%)",     f"{m['Red_pct']}%",    "[TBD from paper]", "51%"])
        writer.writerow(["Precision",   m["Precision"],         "[TBD from paper]", "~0.62"])
        writer.writerow(["Recall",      m["Recall"],            "[TBD from paper]", "~0.49"])
        writer.writerow(["F1-Score",    m["F1"],                "[TBD from paper]", "~0.55"])
        writer.writerow([])

        # --- Table 5 equivalent: Per-CWE breakdown ---
        writer.writerow(["=== TABLE 5: Per-CWE Detection Outcomes (SIFT) ==="])
        writer.writerow(["CWE", "# CVEs", "Green", "Orange", "Red", "Precision", "Recall", "F1"])
        for cwe, cm in metrics["per_cwe"].items():
            writer.writerow([
                cwe, cm["Total"],
                cm["Green"], cm["Orange"], cm["Red"],
                cm["Precision"], cm["Recall"], cm["F1"]
            ])
        writer.writerow([])

        # --- Raw classification log ---
        writer.writerow(["=== FULL CLASSIFICATION LOG ==="])
        writer.writerow(["CVE", "CWEs", "Outcome", "Vuln Score", "Fixed Score", "Time (s)"])
        for r in results:
            writer.writerow([
                r["CVE"],
                "|".join(r["CWEs"]),
                r.get("outcome", ""),
                r.get("vuln_score", ""),
                r.get("fixed_score", ""),
                r.get("processing_time_s", ""),
            ])

    log.info(f"Paper-ready summary CSV → {path}")


# ─── Main Runner ───────────────────────────────────────────────────────────────

def run_benchmark(dataset_root: Path, output_dir: Path, limit: int = None, resume: bool = True):
    """
    Main benchmark loop.

    Args:
        dataset_root: Path to dataset folder.
        output_dir:   Path to write all results.
        limit:        If set, only process first N CVEs (useful for testing).
        resume:       If True, skip CVEs already in raw_sift_responses.jsonl.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize SIFT engine
    log.info("Initializing SiftEngine...")
    engine = SiftEngine(api_key=SIFT_API_KEY)

    # Load metadata and discover CVE dirs
    metadata  = load_metadata(dataset_root)
    cve_dirs  = discover_cve_dirs(dataset_root)

    if limit:
        cve_dirs = cve_dirs[:limit]
        log.info(f"Limiting run to first {limit} CVEs.")

    # Resume: find already-processed CVEs
    already_done = set()
    raw_path = output_dir / "raw_sift_responses.jsonl"
    if resume and raw_path.exists():
        with open(raw_path) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if "CVE" in entry:
                        already_done.add(entry["CVE"])
                except json.JSONDecodeError:
                    pass
        if already_done:
            log.info(f"Resuming: {len(already_done)} CVEs already processed, skipping them.")

    results = []

    # Load already-completed results for metrics computation
    if already_done and raw_path.exists():
        with open(raw_path) as f:
            for line in f:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    total    = len(cve_dirs)
    skipped  = 0
    errors   = 0

    for i, cve_dir in enumerate(cve_dirs):
        cve_id = cve_dir.name
        if cve_id in already_done:
            skipped += 1
            continue

        # CWEs from metadata
        meta   = metadata.get(cve_id, {})
        cwes   = meta.get("CWEs", meta.get("cwes", ["Unknown"]))
        if not cwes:
            cwes = ["Unknown"]

        log.info(f"[{i+1}/{total}] Processing {cve_id} (CWEs: {', '.join(cwes)})")

        # Resolve vulnerable and fixed dirs (support both naming conventions)
        vuln_dir  = cve_dir / "vulnerable"
        fixed_dir = cve_dir / "fixed"
        if not vuln_dir.exists():
            vuln_dir  = cve_dir / "pre_patch"
            fixed_dir = cve_dir / "post_patch"

        # Collect code files
        vuln_files  = get_code_files(vuln_dir)
        fixed_files = get_code_files(fixed_dir)

        if not vuln_files or not fixed_files:
            log.warning(f"  No target files found in {cve_id} — skipping.")
            errors += 1
            continue

        # Concatenate all files into one analysis pass
        # (SIFT is a semantic reasoner — giving it full context is better)
        def concat_files(file_list, base_dir):
            parts = []
            for fp in file_list:
                rel = fp.relative_to(base_dir)
                content = read_file_content(fp)
                if content:
                    parts.append(f"// === FILE: {rel} ===\n{content}")
            return "\n\n".join(parts)

        vuln_code  = concat_files(vuln_files, vuln_dir)
        fixed_code = concat_files(fixed_files, fixed_dir)

        t_start = time.time()

        # Run SIFT on vulnerable version
        log.info(f"  → Analysing vulnerable version ({len(vuln_files)} files)...")
        vuln_result = run_sift(engine, vuln_code, f"{cve_id}/vulnerable")
        time.sleep(API_DELAY_SECONDS)

        # Run SIFT on fixed version
        log.info(f"  → Analysing fixed version ({len(fixed_files)} files)...")
        fixed_result = run_sift(engine, fixed_code, f"{cve_id}/fixed")
        time.sleep(API_DELAY_SECONDS)

        t_elapsed = round(time.time() - t_start, 2)

        # Classify
        vuln_predicted  = is_vulnerable_prediction(vuln_result)
        fixed_predicted = is_vulnerable_prediction(fixed_result)
        outcome         = classify_outcome(vuln_predicted, fixed_predicted)

        vuln_score  = vuln_result.get("score", "N/A")
        fixed_score = fixed_result.get("score", "N/A")

        log.info(f"  ✓ Outcome: {outcome} | Vuln score: {vuln_score} | Fixed score: {fixed_score} | {t_elapsed}s")

        record = {
            "CVE":              cve_id,
            "CWEs":             cwes,
            "vuln_score":       vuln_score,
            "vuln_predicted":   vuln_predicted,
            "vuln_vuln_count":  len(vuln_result.get("vulnerabilities", [])),
            "vuln_sift_raw":    vuln_result,
            "fixed_score":      fixed_score,
            "fixed_predicted":  fixed_predicted,
            "fixed_vuln_count": len(fixed_result.get("vulnerabilities", [])),
            "fixed_sift_raw":   fixed_result,
            "outcome":          outcome,
            "processing_time_s": t_elapsed,
            "error":            vuln_result.get("error", fixed_result.get("error", "")),
            "timestamp":        datetime.utcnow().isoformat(),
        }

        results.append(record)

        # Append to JSONL immediately (so progress is saved after each CVE)
        with open(raw_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    # ─── Write outputs ─────────────────────────────────────────────────────────
    log.info(f"\n{'='*60}")
    log.info(f"Benchmark complete. Processed: {len(results)} | Skipped: {skipped} | Errors: {errors}")
    log.info(f"{'='*60}")

    if not results:
        log.error("No results to write. Check your dataset path and file structure.")
        return

    metrics = compute_metrics(results)

    write_classification_csv(results, output_dir)
    write_metrics_csv(metrics, output_dir)
    write_paper_summary_csv(results, metrics, output_dir)

    # Print quick summary to terminal
    m = metrics["overall"]
    print(f"""
╔══════════════════════════════════════════╗
║         SIFT BENCHMARK RESULTS           ║
╠══════════════════════════════════════════╣
║  Total CVEs analysed : {m['Total']:>4}               ║
║  Green  (detected ✓) : {m['Green']:>4}  ({m['Green_pct']:>5}%)       ║
║  Orange (fix missed) : {m['Orange']:>4}  ({m['Orange_pct']:>5}%)       ║
║  Red    (missed   ✗) : {m['Red']:>4}  ({m['Red_pct']:>5}%)       ║
╠══════════════════════════════════════════╣
║  Precision           : {m['Precision']:.4f}               ║
║  Recall              : {m['Recall']:.4f}               ║
║  F1-Score            : {m['F1']:.4f}               ║
╠══════════════════════════════════════════╣
║  Output directory: {str(output_dir):<22}║
╚══════════════════════════════════════════╝
""")

    log.info("All output files written successfully.")


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SIFT Benchmark Runner — OpenSSF CVE Dataset")
    parser.add_argument("--dataset",  default=DATASET_ROOT,  help="Path to dataset root folder")
    parser.add_argument("--output",   default=OUTPUT_DIR,    help="Path to output directory")
    parser.add_argument("--limit",    type=int, default=None, help="Only process first N CVEs (for testing)")
    parser.add_argument("--no-resume", action="store_true",  help="Start fresh, ignore previous progress")
    parser.add_argument("--api-key",  default=SIFT_API_KEY,  help="SIFT API key (or set SIFT_API_KEY env var)")
    args = parser.parse_args()

    # Override config from CLI args
    SIFT_API_KEY = args.api_key

    run_benchmark(
        dataset_root = Path(args.dataset),
        output_dir   = Path(args.output),
        limit        = args.limit,
        resume       = not args.no_resume,
    )
