"""
SIFT Benchmark Runner — Hybrid Mode
=====================================
- Vulnerable code : read from local src_downloaded/CVE-XXXX/ folder
- Fixed code      : fetched from GitHub using postPatch commit in CVE JSON
- Metadata/CWEs   : read from CVEs/ JSON files

Folder layout expected:
    ossf-cve-benchmark/
        CVEs/
            CVE-2016-10735        <- JSON file (no extension)
            CVE-2017-0931
            ...
        src_downloaded/
            CVE-2016-10735/
                util              <- local JS file (no extension)
            CVE-2017-0931/
                index.js
            ...

Green  = SIFT flags vulnerable version  AND  does NOT flag fixed version
Orange = SIFT flags vulnerable version  AND  still flags fixed version
Red    = SIFT misses the vulnerability entirely

Outputs -> OUTPUT_DIR:
    raw_sift_responses.jsonl   one JSON per CVE, saved live (auto-resume safe)
    classification_table.csv   Green/Orange/Red per CVE
    metrics_per_cwe.csv        Precision / Recall / F1 per CWE
    metrics_overall.csv        Overall summary numbers
    paper_summary.csv          Pre-formatted for paper Tables 4 & 5
"""

import os, sys, json, csv, time, logging, argparse, re
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Configuration — edit these if needed ──────────────────────────────────────
BASE_DIR       = r"C:\xampp\htdocs\CGP-2\datasets\ossf-cve-benchmark"
CVE_JSON_DIR   = os.path.join(BASE_DIR, "CVEs")
SRC_LOCAL_DIR  = os.path.join(BASE_DIR, "src_downloaded")
OUTPUT_DIR     = os.path.join(BASE_DIR, "sift_results")
SIFT_API_KEY   = os.environ.get("SIFT_API_KEY", "your-api-key-here")
SIFT_THRESHOLD = 70       # score < this  OR  non-empty vulnerabilities → VULNERABLE
API_DELAY      = 1.5      # seconds between SIFT API calls
GITHUB_DELAY   = 0.5      # seconds between GitHub fetches
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")  # optional — raises rate limit 60→5000/hr

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger(__name__)

# ── Import SIFT ───────────────────────────────────────────────────────────────
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from core.sift_engine import SiftEngine
    log.info("SiftEngine imported OK.")
except ImportError as e:
    log.error(f"Cannot import SiftEngine: {e}")
    log.error("Run this script from your CyberGuard Pro project root.")
    sys.exit(1)


# ── Local file helpers ────────────────────────────────────────────────────────

def read_local_vulnerable(src_dir: Path, cve_id: str) -> tuple[str, str]:
    """
    Read the local vulnerable JS file for a CVE.
    Returns (code_string, filename) or ("", "") if not found.

    Handles files with no extension (e.g. 'util') and with extension (e.g. 'util.js').
    """
    cve_folder = src_dir / cve_id
    if not cve_folder.exists():
        return "", ""

    # Collect all files (any extension, or no extension)
    candidates = [p for p in cve_folder.iterdir() if p.is_file()
                  and not p.name.startswith(".")]

    if not candidates:
        return "", ""

    # If multiple files, concatenate all (some CVEs may have multiple files)
    parts = []
    names = []
    for p in sorted(candidates):
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            if content.strip():
                parts.append(f"// === FILE: {p.name} ===\n{content}")
                names.append(p.name)
        except Exception as e:
            log.warning(f"  Cannot read {p}: {e}")

    return "\n\n".join(parts), ", ".join(names)


# ── GitHub fetch helpers ───────────────────────────────────────────────────────

def repo_to_raw_base(repo_url: str) -> str:
    """
    Convert GitHub repo URL to raw.githubusercontent.com base path.
    e.g. https://github.com/twbs/bootstrap.git
      -> https://raw.githubusercontent.com/twbs/bootstrap
    """
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    match = re.search(r'github\.com[:/](.+)', url)
    if not match:
        return ""
    return f"https://raw.githubusercontent.com/{match.group(1).lstrip('/')}"


def fetch_file(raw_base: str, commit: str, filepath: str) -> str:
    """Fetch a single file from GitHub raw at a specific commit."""
    url = f"{raw_base}/{commit}/{filepath}"
    headers = {"User-Agent": "SIFT-Benchmark/1.0"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        time.sleep(GITHUB_DELAY)
        return content
    except urllib.error.HTTPError as e:
        if e.code == 429:
            log.warning("  GitHub rate limit — waiting 60s then retrying...")
            time.sleep(60)
            return fetch_file(raw_base, commit, filepath)
        elif e.code == 404:
            log.warning(f"  404: {filepath} @ {commit[:8]}")
        else:
            log.warning(f"  HTTP {e.code}: {filepath}")
        return ""
    except Exception as e:
        log.warning(f"  Fetch error {filepath}: {e}")
        return ""


def fetch_fixed_code(raw_base: str, post_commit: str,
                     weaknesses: list, local_filename: str) -> str:
    """
    Fetch the fixed version of the vulnerable file(s) from GitHub.

    Strategy:
      1. Try each file path from weaknesses[].location.file directly
      2. If that 404s, try matching by filename stem against local file
         (handles cases where the path changed between commits)
    """
    if not raw_base or not post_commit:
        return ""

    parts = []
    seen  = set()

    for weakness in weaknesses:
        loc      = weakness.get("location", {})
        filepath = loc.get("file", "")
        if not filepath or filepath in seen:
            continue
        seen.add(filepath)

        content = fetch_file(raw_base, post_commit, filepath)

        # Fallback: try just the filename (in case directory structure changed)
        if not content and "/" in filepath:
            just_name = filepath.split("/")[-1]
            content = fetch_file(raw_base, post_commit, just_name)

        if content:
            parts.append(f"// === FILE: {filepath} (fixed) ===\n{content}")

    return "\n\n".join(parts)


# ── CVE JSON helpers ──────────────────────────────────────────────────────────

def load_cve_json_files(cve_json_dir: Path) -> list:
    """Return sorted list of CVE JSON file paths."""
    files = []
    for p in sorted(cve_json_dir.iterdir()):
        if not p.is_file():
            continue
        if p.name.lower().startswith("metadata") or p.name.startswith("."):
            continue
        if p.name.upper().startswith("CVE-"):
            files.append(p)
    log.info(f"Found {len(files)} CVE JSON files.")
    return files


def parse_cve_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        log.warning(f"Cannot parse {path.name}: {e}")
        return None


def extract_cwes(data: dict) -> list:
    for field in ("CWEs", "cwes", "CWE", "cwe", "cwe_ids"):
        v = data.get(field)
        if isinstance(v, list) and v:
            cwes = [str(x) for x in v if str(x).upper().startswith("CWE")]
            if cwes:
                return cwes
        elif isinstance(v, str) and v.upper().startswith("CWE"):
            return [v]
    return ["Unknown"]


# ── SIFT helpers ──────────────────────────────────────────────────────────────

def run_sift(engine, code: str, label: str) -> dict:
    if not code or not code.strip():
        return {"error": "no_code", "score": 100, "vulnerabilities": []}
    try:
        result = engine.analyze_code(code)
        return result if isinstance(result, dict) else \
               {"error": "bad_return_type", "score": 100, "vulnerabilities": []}
    except Exception as e:
        log.error(f"  SIFT error [{label}]: {e}")
        return {"error": str(e), "score": 100, "vulnerabilities": []}


def is_vulnerable(result: dict) -> bool:
    score = result.get("score", 100)
    vulns = result.get("vulnerabilities", [])
    return (score < SIFT_THRESHOLD) or (len(vulns) > 0)


def classify(vuln_pred: bool, fixed_pred: bool) -> str:
    """Green / Orange / Red — matches OpenSSF benchmark classification."""
    if not vuln_pred:  return "Red"
    if not fixed_pred: return "Green"
    return "Orange"


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(results: list) -> dict:
    def sdiv(a, b): return round(a / b, 4) if b else 0.0
    def prf(tp, fp, fn):
        p  = sdiv(tp, tp + fp)
        r  = sdiv(tp, tp + fn)
        f1 = sdiv(2 * p * r, p + r)
        return p, r, f1

    overall = {"Green": 0, "Orange": 0, "Red": 0, "total": 0}
    by_cwe  = defaultdict(lambda: {"Green": 0, "Orange": 0, "Red": 0, "total": 0})

    for r in results:
        o = r.get("outcome", "Red")
        overall[o]       += 1
        overall["total"] += 1
        for cwe in r.get("CWEs", ["Unknown"]):
            by_cwe[cwe][o]       += 1
            by_cwe[cwe]["total"] += 1

    def summary(c):
        tp, fp, fn = c["Green"], c["Orange"], c["Red"]
        t = c["total"]
        p, r, f1 = prf(tp, fp, fn)
        return {"Green": tp, "Orange": fp, "Red": fn, "Total": t,
                "Green_pct":  round(100 * tp / t, 1) if t else 0,
                "Orange_pct": round(100 * fp / t, 1) if t else 0,
                "Red_pct":    round(100 * fn / t, 1) if t else 0,
                "Precision": p, "Recall": r, "F1": f1}

    return {"overall": summary(overall),
            "per_cwe": {cwe: summary(c) for cwe, c in sorted(by_cwe.items())}}


# ── Output writers ────────────────────────────────────────────────────────────

def write_all(results: list, metrics: dict, output_dir: Path):

    # 1. Raw JSONL (rewrite consolidated copy)
    p = output_dir / "raw_sift_responses.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    log.info(f"Raw responses    -> {p}")

    # 2. Classification CSV
    p = output_dir / "classification_table.csv"
    fields = ["CVE", "CWEs", "Outcome",
              "Vuln_Score", "Vuln_Pred", "Vuln_Issues",
              "Fixed_Score", "Fixed_Pred", "Fixed_Issues",
              "Local_File", "Fixed_Fetched", "Time_s", "Error"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "CVE":          r["CVE"],
                "CWEs":         "|".join(r.get("CWEs", [])),
                "Outcome":      r.get("outcome", ""),
                "Vuln_Score":   r.get("vuln_score", ""),
                "Vuln_Pred":    r.get("vuln_predicted", ""),
                "Vuln_Issues":  r.get("vuln_issue_count", ""),
                "Fixed_Score":  r.get("fixed_score", ""),
                "Fixed_Pred":   r.get("fixed_predicted", ""),
                "Fixed_Issues": r.get("fixed_issue_count", ""),
                "Local_File":   r.get("local_file", ""),
                "Fixed_Fetched":r.get("fixed_fetched", ""),
                "Time_s":       r.get("processing_time_s", ""),
                "Error":        r.get("error", ""),
            })
    log.info(f"Classification   -> {p}")

    # 3. Per-CWE metrics
    p = output_dir / "metrics_per_cwe.csv"
    fields2 = ["CWE", "Total", "Green", "Orange", "Red",
                "Green%", "Orange%", "Red%", "Precision", "Recall", "F1"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields2)
        w.writeheader()
        for cwe, m in metrics["per_cwe"].items():
            w.writerow({"CWE": cwe, "Total": m["Total"],
                        "Green": m["Green"], "Orange": m["Orange"], "Red": m["Red"],
                        "Green%":  f"{m['Green_pct']}%",
                        "Orange%": f"{m['Orange_pct']}%",
                        "Red%":    f"{m['Red_pct']}%",
                        "Precision": m["Precision"],
                        "Recall":    m["Recall"],
                        "F1":        m["F1"]})
    log.info(f"Per-CWE metrics  -> {p}")

    # 4. Overall metrics
    p = output_dir / "metrics_overall.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Metric", "Value"])
        w.writeheader()
        for k, v in metrics["overall"].items():
            w.writerow({"Metric": k, "Value": v})
    log.info(f"Overall metrics  -> {p}")

    # 5. Paper-ready summary
    p = output_dir / "paper_summary.csv"
    m = metrics["overall"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)

        w.writerow(["=== TABLE 4: Overall Detection Performance ==="])
        w.writerow(["Metric", "SIFT", "ossf-sast-ml (paper)", "CodeQL (paper)"])
        w.writerow(["Green (%)",  f"{m['Green_pct']}%",  "[from paper]", "38%"])
        w.writerow(["Orange (%)", f"{m['Orange_pct']}%", "[from paper]", "11%"])
        w.writerow(["Red (%)",    f"{m['Red_pct']}%",    "[from paper]", "51%"])
        w.writerow(["Precision",  m["Precision"],         "[from paper]", "~0.62"])
        w.writerow(["Recall",     m["Recall"],            "[from paper]", "~0.49"])
        w.writerow(["F1-Score",   m["F1"],                "[from paper]", "~0.55"])
        w.writerow([])

        w.writerow(["=== TABLE 5: Per-CWE Breakdown (SIFT) ==="])
        w.writerow(["CWE", "Total", "Green", "Orange", "Red",
                    "Green%", "Orange%", "Red%", "Precision", "Recall", "F1"])
        for cwe, cm in metrics["per_cwe"].items():
            w.writerow([cwe, cm["Total"], cm["Green"], cm["Orange"], cm["Red"],
                        f"{cm['Green_pct']}%", f"{cm['Orange_pct']}%",
                        f"{cm['Red_pct']}%",
                        cm["Precision"], cm["Recall"], cm["F1"]])
        w.writerow([])

        w.writerow(["=== FULL CLASSIFICATION LOG ==="])
        w.writerow(["CVE", "CWEs", "Outcome", "Vuln Score",
                    "Fixed Score", "Local File", "Time (s)"])
        for r in results:
            w.writerow([r["CVE"], "|".join(r.get("CWEs", [])),
                        r.get("outcome", ""), r.get("vuln_score", ""),
                        r.get("fixed_score", ""), r.get("local_file", ""),
                        r.get("processing_time_s", "")])

    log.info(f"Paper summary    -> {p}")


# ── Main benchmark loop ───────────────────────────────────────────────────────

def run_benchmark(cve_json_dir: Path, src_local_dir: Path, output_dir: Path,
                  limit: int = None, resume: bool = True):

    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("Initializing SiftEngine...")
    engine = SiftEngine(api_key=SIFT_API_KEY)

    cve_files = load_cve_json_files(cve_json_dir)
    if limit:
        cve_files = cve_files[:limit]
        log.info(f"Limited to first {limit} CVEs.")

    # Resume: skip already-done CVEs
    raw_path     = output_dir / "raw_sift_responses.jsonl"
    already_done = set()
    results      = []

    if resume and raw_path.exists():
        with open(raw_path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if "CVE" in e:
                        already_done.add(e["CVE"])
                        results.append(e)
                except json.JSONDecodeError:
                    pass
        if already_done:
            log.info(f"Resuming — {len(already_done)} CVEs already done, skipping.")

    total        = len(cve_files)
    fetch_fails  = 0
    local_misses = 0
    errors       = 0

    for i, cve_file in enumerate(cve_files):
        cve_id = cve_file.stem if cve_file.suffix else cve_file.name
        if cve_id in already_done:
            continue

        log.info(f"[{i+1}/{total}] {cve_id}")

        # ── Parse CVE JSON ────────────────────────────────────────────────────
        data = parse_cve_json(cve_file)
        if data is None:
            errors += 1
            continue

        cwes        = extract_cwes(data)
        repo_url    = data.get("repository", "")
        pre_patch   = data.get("prePatch",  {})
        post_patch  = data.get("postPatch", {})
        weaknesses  = pre_patch.get("weaknesses", [])
        post_commit = post_patch.get("commit", "")
        raw_base    = repo_to_raw_base(repo_url)

        # ── Step 1: Read local vulnerable file ───────────────────────────────
        vuln_code, local_file = read_local_vulnerable(src_local_dir, cve_id)
        if not vuln_code:
            local_misses += 1
            log.warning(f"  No local file found in src_downloaded/{cve_id} — skipping.")
            record = {
                "CVE": cve_id, "CWEs": cwes,
                "vuln_score": None, "vuln_predicted": False, "vuln_issue_count": 0,
                "vuln_sift_raw": {}, "fixed_score": None, "fixed_predicted": False,
                "fixed_issue_count": 0, "fixed_sift_raw": {},
                "outcome": "Red", "local_file": "", "fixed_fetched": False,
                "processing_time_s": 0, "error": "local_file_missing",
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue

        log.info(f"  Local file: {local_file} ({len(vuln_code):,} chars)")

        # ── Step 2: Fetch fixed version from GitHub ───────────────────────────
        log.info(f"  Fetching fixed version (commit {post_commit[:8] if post_commit else '?'})...")
        fixed_code = fetch_fixed_code(raw_base, post_commit, weaknesses, local_file)

        if not fixed_code:
            fetch_fails += 1
            log.warning(f"  Could not fetch fixed version — recording as Red")
            record = {
                "CVE": cve_id, "CWEs": cwes,
                "vuln_score": None, "vuln_predicted": False, "vuln_issue_count": 0,
                "vuln_sift_raw": {}, "fixed_score": None, "fixed_predicted": False,
                "fixed_issue_count": 0, "fixed_sift_raw": {},
                "outcome": "Red", "local_file": local_file, "fixed_fetched": False,
                "processing_time_s": 0, "error": "github_fetch_failed",
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue

        log.info(f"  Fixed version fetched ({len(fixed_code):,} chars)")

        # ── Step 3: Run SIFT on both versions ────────────────────────────────
        t = time.time()

        log.info(f"  SIFT -> vulnerable version...")
        vr = run_sift(engine, vuln_code, f"{cve_id}/vuln")
        time.sleep(API_DELAY)

        log.info(f"  SIFT -> fixed version...")
        fr = run_sift(engine, fixed_code, f"{cve_id}/fixed")
        time.sleep(API_DELAY)

        elapsed = round(time.time() - t, 2)

        vp      = is_vulnerable(vr)
        fp      = is_vulnerable(fr)
        outcome = classify(vp, fp)

        log.info(f"  ✓ {outcome} | Vuln: {vr.get('score','?')} | "
                 f"Fixed: {fr.get('score','?')} | {elapsed}s | CWEs: {cwes}")

        record = {
            "CVE": cve_id, "CWEs": cwes,
            "vuln_score":        vr.get("score"),
            "vuln_predicted":    vp,
            "vuln_issue_count":  len(vr.get("vulnerabilities", [])),
            "vuln_sift_raw":     vr,
            "fixed_score":       fr.get("score"),
            "fixed_predicted":   fp,
            "fixed_issue_count": len(fr.get("vulnerabilities", [])),
            "fixed_sift_raw":    fr,
            "outcome":           outcome,
            "local_file":        local_file,
            "fixed_fetched":     True,
            "processing_time_s": elapsed,
            "error":             vr.get("error", fr.get("error", "")),
            "timestamp":         datetime.utcnow().isoformat(),
        }
        results.append(record)

        # Save immediately after each CVE (crash-safe)
        with open(raw_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # ── Write all output files ────────────────────────────────────────────────
    log.info(f"\n{'='*55}")
    log.info(f"Done. Processed: {len(results)} | "
             f"Local misses: {local_misses} | "
             f"Fetch fails: {fetch_fails} | "
             f"Errors: {errors}")

    if not results:
        log.error("No results. Check your dataset paths.")
        return

    metrics = compute_metrics(results)
    write_all(results, metrics, output_dir)

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
╚══════════════════════════════════════════╝
Output: {output_dir}
""")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="SIFT Hybrid Benchmark Runner")
    p.add_argument("--cve-json-dir", default=CVE_JSON_DIR,
                   help="Path to CVEs/ folder (JSON metadata files)")
    p.add_argument("--src-dir",      default=SRC_LOCAL_DIR,
                   help="Path to src_downloaded/ folder (local vulnerable files)")
    p.add_argument("--output",       default=OUTPUT_DIR,
                   help="Output directory")
    p.add_argument("--limit",        type=int, default=None,
                   help="Only process first N CVEs (for testing)")
    p.add_argument("--no-resume",    action="store_true",
                   help="Start fresh, ignore previous progress")
    p.add_argument("--api-key",      default=SIFT_API_KEY,
                   help="SIFT API key")
    p.add_argument("--gh-token",     default=GITHUB_TOKEN,
                   help="GitHub personal access token (optional, avoids rate limits)")
    p.add_argument("--threshold",    type=int, default=SIFT_THRESHOLD,
                   help="SIFT vulnerability score threshold (default: 70)")
    args = p.parse_args()

    SIFT_API_KEY   = args.api_key
    GITHUB_TOKEN   = args.gh_token
    SIFT_THRESHOLD = args.threshold

    run_benchmark(
        cve_json_dir  = Path(args.cve_json_dir),
        src_local_dir = Path(args.src_dir),
        output_dir    = Path(args.output),
        limit         = args.limit,
        resume        = not args.no_resume,
    )
