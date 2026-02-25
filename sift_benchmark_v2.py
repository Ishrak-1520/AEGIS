"""
SIFT Benchmark v2 — Fixed (Empty Response + Large File Handling)
================================================================
Fixes applied over v2:
  1. Code truncation — files > MAX_CODE_CHARS are truncated with a note
     so the model always receives a manageable context window
  2. Retry logic — up to 3 attempts per SIFT call with backoff
  3. Fallback to raw score only when JSON parse fails but a number is present
  4. analyze_fixed_code() now also truncates large inputs

Root cause of v2 failures:
  LongCat-Flash-Lite returns empty content when the code payload is too large
  (svg_text_utils.js was 18,173 chars — over the model's practical limit).
  The OpenAI client then raises JSONDecodeError on the empty body.
"""

import os, sys, json, csv, time, logging, argparse, re
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_DIR       = r"C:\xampp\htdocs\CGP-2\datasets\ossf-cve-benchmark"
CVE_JSON_DIR   = os.path.join(BASE_DIR, "CVEs")
SRC_LOCAL_DIR  = os.path.join(BASE_DIR, "src_downloaded")
OUTPUT_DIR     = os.path.join(BASE_DIR, "sift_results_v2")
SIFT_API_KEY   = os.environ.get("SIFT_API_KEY", "your-api-key-here")
SIFT_THRESHOLD = 70
API_DELAY      = 1.5
GITHUB_DELAY   = 0.5
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")

# Max characters to send to SIFT per analysis call.
# LongCat-Flash-Lite struggles above ~8000 chars raw code.
MAX_CODE_CHARS = 8000

# Retry settings for SIFT API calls
MAX_RETRIES    = 3
RETRY_DELAY    = 5  # seconds between retries

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
    sys.exit(1)


# ── Code truncation ───────────────────────────────────────────────────────────

def truncate_code(code: str, max_chars: int = MAX_CODE_CHARS,
                  label: str = "") -> tuple:
    """
    Truncate code to max_chars, keeping the beginning and end (most
    vulnerability-relevant parts) and inserting a truncation note.
    Returns (truncated_code, was_truncated).
    """
    if len(code) <= max_chars:
        return code, False

    half       = max_chars // 2
    head       = code[:half]
    tail       = code[-(max_chars - half):]
    chars_cut  = len(code) - max_chars

    truncated = (
        head
        + f"\n\n// [...TRUNCATED {chars_cut} characters for context window — "
          f"focus on patterns in visible code...]\n\n"
        + tail
    )
    log.info(f"  ⚠ Truncated {label}: {len(code):,} → {len(truncated):,} chars")
    return truncated, True


# ── Local file reader ─────────────────────────────────────────────────────────

def read_local_vulnerable(src_dir: Path, cve_id: str) -> tuple:
    cve_folder = src_dir / cve_id
    if not cve_folder.exists():
        return "", ""
    candidates = [p for p in cve_folder.iterdir()
                  if p.is_file() and not p.name.startswith(".")]
    if not candidates:
        return "", ""
    parts, names = [], []
    for p in sorted(candidates):
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            if content.strip():
                parts.append(f"// === FILE: {p.name} ===\n{content}")
                names.append(p.name)
        except Exception as e:
            log.warning(f"  Cannot read {p}: {e}")
    return "\n\n".join(parts), ", ".join(names)


# ── GitHub fetch helpers ──────────────────────────────────────────────────────

def repo_to_raw_base(repo_url: str) -> str:
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    match = re.search(r'github\.com[:/](.+)', url)
    if not match:
        return ""
    return f"https://raw.githubusercontent.com/{match.group(1).lstrip('/')}"


def fetch_file(raw_base: str, commit: str, filepath: str) -> str:
    url = f"{raw_base}/{commit}/{filepath}"
    headers = {"User-Agent": "SIFT-Benchmark/2.0"}
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
            log.warning("  GitHub rate limit — waiting 60s...")
            time.sleep(60)
            return fetch_file(raw_base, commit, filepath)
        elif e.code == 404:
            log.warning(f"  404: {filepath} @ {commit[:8]}")
        else:
            log.warning(f"  HTTP {e.code}: {filepath}")
        return ""
    except Exception as e:
        log.warning(f"  Fetch error: {e}")
        return ""


def fetch_fixed_code(raw_base: str, post_commit: str, weaknesses: list) -> str:
    if not raw_base or not post_commit:
        return ""
    parts, seen = [], set()
    for weakness in weaknesses:
        loc      = weakness.get("location", {})
        filepath = loc.get("file", "")
        if not filepath or filepath in seen:
            continue
        seen.add(filepath)
        content = fetch_file(raw_base, post_commit, filepath)
        if not content and "/" in filepath:
            content = fetch_file(raw_base, post_commit, filepath.split("/")[-1])
        if content:
            parts.append(f"// === FILE: {filepath} (fixed) ===\n{content}")
    return "\n\n".join(parts)


# ── CVE JSON helpers ──────────────────────────────────────────────────────────

def load_cve_json_files(cve_json_dir: Path) -> list:
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


# ── SIFT call wrappers with retry ─────────────────────────────────────────────

def is_valid_result(result: dict) -> bool:
    """Check if a SIFT result is usable (has score or vulnerabilities)."""
    if "error" in result and "score" not in result:
        return False
    if result.get("score") is None and not result.get("vulnerabilities"):
        return False
    return True


def run_sift_vulnerable(engine: SiftEngine, code: str,
                        label: str, filename: str = None) -> dict:
    """
    Run analyze_code() with truncation + retry logic.
    Returns a valid result dict or a structured error dict.
    """
    # Truncate if needed
    code_to_send, was_truncated = truncate_code(code, MAX_CODE_CHARS, label)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = engine.analyze_code(code_to_send, filename=filename)
            if isinstance(result, dict) and is_valid_result(result):
                if was_truncated:
                    result["truncated"] = True
                return result
            else:
                log.warning(f"  [{label}] Attempt {attempt}: invalid result "
                            f"({result.get('error', 'no score')})")
        except Exception as e:
            log.warning(f"  [{label}] Attempt {attempt}: exception — {e}")

        if attempt < MAX_RETRIES:
            log.info(f"  Retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    # All retries exhausted
    log.error(f"  [{label}] All {MAX_RETRIES} attempts failed.")
    return {"error": "all_retries_failed", "score": 100,
            "vulnerabilities": [], "truncated": was_truncated}


def run_sift_fixed(engine: SiftEngine, vuln_code: str, fixed_code: str,
                   label: str, filename: str = None) -> dict:
    """
    Run analyze_fixed_code() with truncation + retry logic.
    Both versions are truncated to MAX_CODE_CHARS / 2 each to fit the
    combined prompt (vulnerable + fixed + diff) within the context window.
    """
    # Truncate each version to half budget so combined fits
    half_budget = MAX_CODE_CHARS // 2
    vuln_to_send,  _ = truncate_code(vuln_code,  half_budget, f"{label}/vuln")
    fixed_to_send, _ = truncate_code(fixed_code, half_budget, f"{label}/fixed")

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = engine.analyze_fixed_code(
                vuln_to_send, fixed_to_send, filename=filename
            )
            if isinstance(result, dict):
                # analyze_fixed_code is valid even if fix_recognized is False
                if "score" in result or "fix_recognized" in result:
                    return result
            log.warning(f"  [{label}/fix] Attempt {attempt}: invalid result")
        except Exception as e:
            log.warning(f"  [{label}/fix] Attempt {attempt}: exception — {e}")

        if attempt < MAX_RETRIES:
            log.info(f"  Retrying fix analysis in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    log.error(f"  [{label}/fix] All {MAX_RETRIES} attempts failed.")
    return {"error": "all_retries_failed", "score": 100,
            "vulnerabilities": [], "fix_recognized": False,
            "fix_explanation": "All retries failed — recorded as unrecognized"}


# ── Classification ────────────────────────────────────────────────────────────

def is_vulnerable_vuln(result: dict) -> bool:
    """Vulnerable version: score < threshold OR non-empty vulnerabilities."""
    score = result.get("score", 100)
    vulns = result.get("vulnerabilities", [])
    # If all retries failed, score=100 → not vulnerable → Red (conservative)
    return (isinstance(score, (int, float)) and score < SIFT_THRESHOLD) \
           or (len(vulns) > 0)


def is_fix_recognized(result: dict) -> bool:
    """
    Fixed version: prefer explicit fix_recognized field.
    Fallback: inverted score (score >= threshold = fix effective = clean).
    """
    if "fix_recognized" in result:
        return bool(result["fix_recognized"])
    score = result.get("score", 0)
    vulns = result.get("vulnerabilities", [])
    return (isinstance(score, (int, float)) and score >= SIFT_THRESHOLD) \
           and (len(vulns) == 0)


def classify(vuln_detected: bool, fix_recognized: bool) -> str:
    if not vuln_detected: return "Red"
    if fix_recognized:    return "Green"
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


# ── Writers ───────────────────────────────────────────────────────────────────

def write_all(results: list, metrics: dict, output_dir: Path):
    # Raw JSONL
    p = output_dir / "raw_sift_responses.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    log.info(f"Raw responses    -> {p}")

    # Classification CSV
    p = output_dir / "classification_table.csv"
    fields = ["CVE", "CWEs", "Outcome",
              "Vuln_Score", "Vuln_Detected", "Vuln_Issues",
              "Fixed_Score", "Fix_Recognized", "Fix_Explanation",
              "Truncated", "Local_File", "Fixed_Fetched", "Time_s", "Error"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "CVE":             r["CVE"],
                "CWEs":            "|".join(r.get("CWEs", [])),
                "Outcome":         r.get("outcome", ""),
                "Vuln_Score":      r.get("vuln_score", ""),
                "Vuln_Detected":   r.get("vuln_detected", ""),
                "Vuln_Issues":     r.get("vuln_issue_count", ""),
                "Fixed_Score":     r.get("fixed_score", ""),
                "Fix_Recognized":  r.get("fix_recognized", ""),
                "Fix_Explanation": str(r.get("fix_explanation", ""))[:150],
                "Truncated":       r.get("truncated", False),
                "Local_File":      r.get("local_file", ""),
                "Fixed_Fetched":   r.get("fixed_fetched", ""),
                "Time_s":          r.get("processing_time_s", ""),
                "Error":           r.get("error", ""),
            })
    log.info(f"Classification   -> {p}")

    # Per-CWE metrics
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
                        "Recall": m["Recall"], "F1": m["F1"]})
    log.info(f"Per-CWE metrics  -> {p}")

    # Overall metrics
    p = output_dir / "metrics_overall.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Metric", "Value"])
        w.writeheader()
        for k, v in metrics["overall"].items():
            w.writerow({"Metric": k, "Value": v})
    log.info(f"Overall metrics  -> {p}")

    # Paper summary
    p = output_dir / "paper_summary.csv"
    m = metrics["overall"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["=== TABLE 4: Overall Detection Performance ==="])
        w.writerow(["Metric", "SIFT v2 (diff-aware)", "SIFT v1 (baseline)",
                    "ossf-sast-ml (paper)", "CodeQL (paper)"])
        w.writerow(["Green (%)",  f"{m['Green_pct']}%",  "18.4%", "[from paper]", "38%"])
        w.writerow(["Orange (%)", f"{m['Orange_pct']}%", "37.2%", "[from paper]", "11%"])
        w.writerow(["Red (%)",    f"{m['Red_pct']}%",    "44.4%", "[from paper]", "51%"])
        w.writerow(["Precision",  m["Precision"],  "0.331", "[from paper]", "~0.62"])
        w.writerow(["Recall",     m["Recall"],     "0.293", "[from paper]", "~0.49"])
        w.writerow(["F1-Score",   m["F1"],         "0.311", "[from paper]", "~0.55"])
        w.writerow([])
        w.writerow(["=== TABLE 5: Per-CWE Breakdown (SIFT v2) ==="])
        w.writerow(["CWE", "Total", "Green", "Orange", "Red",
                    "Green%", "Orange%", "Red%", "Precision", "Recall", "F1"])
        for cwe, cm in metrics["per_cwe"].items():
            w.writerow([cwe, cm["Total"], cm["Green"], cm["Orange"], cm["Red"],
                        f"{cm['Green_pct']}%", f"{cm['Orange_pct']}%",
                        f"{cm['Red_pct']}%",
                        cm["Precision"], cm["Recall"], cm["F1"]])
    log.info(f"Paper summary    -> {p}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run_benchmark(cve_json_dir: Path, src_local_dir: Path, output_dir: Path,
                  limit: int = None, resume: bool = True):

    output_dir.mkdir(parents=True, exist_ok=True)
    log.info("Initializing SiftEngine...")
    engine = SiftEngine(api_key=SIFT_API_KEY)

    cve_files = load_cve_json_files(cve_json_dir)
    if limit:
        cve_files = cve_files[:limit]
        log.info(f"Limited to first {limit} CVEs.")

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
            log.info(f"Resuming — {len(already_done)} already done.")

    total        = len(cve_files)
    fetch_fails  = 0
    local_misses = 0
    errors       = 0

    for i, cve_file in enumerate(cve_files):
        cve_id = cve_file.stem if cve_file.suffix else cve_file.name
        if cve_id in already_done:
            continue

        log.info(f"[{i+1}/{total}] {cve_id}")

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

        # Step 1: Local vulnerable file
        vuln_code, local_file = read_local_vulnerable(src_local_dir, cve_id)
        if not vuln_code:
            local_misses += 1
            log.warning(f"  No local file in src_downloaded/{cve_id}")
            record = {
                "CVE": cve_id, "CWEs": cwes, "vuln_score": None,
                "vuln_detected": False, "vuln_issue_count": 0, "vuln_sift_raw": {},
                "fixed_score": None, "fix_recognized": False,
                "fix_explanation": "local file missing", "fixed_sift_raw": {},
                "outcome": "Red", "truncated": False,
                "local_file": "", "fixed_fetched": False,
                "processing_time_s": 0, "error": "local_file_missing",
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue

        log.info(f"  Local: {local_file} ({len(vuln_code):,} chars)")

        # Step 2: Fetch fixed version
        log.info(f"  Fetching fixed @ {post_commit[:8] if post_commit else '?'}...")
        fixed_code = fetch_fixed_code(raw_base, post_commit, weaknesses)
        if not fixed_code:
            fetch_fails += 1
            log.warning(f"  Could not fetch fixed version — Red")
            record = {
                "CVE": cve_id, "CWEs": cwes, "vuln_score": None,
                "vuln_detected": False, "vuln_issue_count": 0, "vuln_sift_raw": {},
                "fixed_score": None, "fix_recognized": False,
                "fix_explanation": "fetch failed", "fixed_sift_raw": {},
                "outcome": "Red", "truncated": False,
                "local_file": local_file, "fixed_fetched": False,
                "processing_time_s": 0, "error": "github_fetch_failed",
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue

        log.info(f"  Fixed fetched ({len(fixed_code):,} chars)")

        t = time.time()

        # Step 3: Analyze vulnerable (with truncation + retry)
        log.info(f"  SIFT analyze_code() → vulnerable...")
        vr = run_sift_vulnerable(engine, vuln_code, cve_id, filename=local_file)
        time.sleep(API_DELAY)

        # Step 4: Analyze fixed (diff-aware, with truncation + retry)
        log.info(f"  SIFT analyze_fixed_code() → fixed (diff-aware)...")
        fr = run_sift_fixed(engine, vuln_code, fixed_code, cve_id,
                            filename=local_file)
        time.sleep(API_DELAY)

        elapsed        = round(time.time() - t, 2)
        vuln_detected  = is_vulnerable_vuln(vr)
        fix_recognized = is_fix_recognized(fr)
        outcome        = classify(vuln_detected, fix_recognized)
        fix_exp        = fr.get("fix_explanation", "")
        was_truncated  = vr.get("truncated", False) or fr.get("truncated", False)

        log.info(f"  ✓ {outcome} | Vuln: {vr.get('score','?')} | "
                 f"Fix score: {fr.get('score','?')} | "
                 f"Fix recognized: {fix_recognized} | {elapsed}s"
                 + (" [TRUNCATED]" if was_truncated else ""))
        if fix_exp:
            log.info(f"    Fix: {str(fix_exp)[:120]}")

        record = {
            "CVE": cve_id, "CWEs": cwes,
            "vuln_score":        vr.get("score"),
            "vuln_detected":     vuln_detected,
            "vuln_issue_count":  len(vr.get("vulnerabilities", [])),
            "vuln_sift_raw":     vr,
            "fixed_score":       fr.get("score"),
            "fix_recognized":    fix_recognized,
            "fix_explanation":   fix_exp,
            "fixed_sift_raw":    fr,
            "outcome":           outcome,
            "truncated":         was_truncated,
            "local_file":        local_file,
            "fixed_fetched":     True,
            "processing_time_s": elapsed,
            "error":             vr.get("error", fr.get("error", "")),
            "timestamp":         datetime.utcnow().isoformat(),
        }
        results.append(record)
        with open(raw_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # Outputs
    log.info(f"\n{'='*55}")
    log.info(f"Done. Total:{len(results)} | Local misses:{local_misses} | "
             f"Fetch fails:{fetch_fails} | Errors:{errors}")
    if not results:
        log.error("No results.")
        return

    metrics = compute_metrics(results)
    write_all(results, metrics, output_dir)

    m = metrics["overall"]
    print(f"""
╔══════════════════════════════════════════════════╗
║       SIFT v2 BENCHMARK RESULTS (Diff-Aware)     ║
╠══════════════════════════════════════════════════╣
║  Total CVEs analysed : {m['Total']:>4}                    ║
║  Green  (detected ✓) : {m['Green']:>4}  ({m['Green_pct']:>5}%)          ║
║  Orange (fix missed) : {m['Orange']:>4}  ({m['Orange_pct']:>5}%)          ║
║  Red    (missed   ✗) : {m['Red']:>4}  ({m['Red_pct']:>5}%)          ║
╠══════════════════════════════════════════════════╣
║  Precision           : {m['Precision']:.4f}                    ║
║  Recall              : {m['Recall']:.4f}                    ║
║  F1-Score            : {m['F1']:.4f}                    ║
╠══════════════════════════════════════════════════╣
║  v1 baseline: Green 18.4%  Orange 37.2%          ║
╚══════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cve-json-dir", default=CVE_JSON_DIR)
    p.add_argument("--src-dir",      default=SRC_LOCAL_DIR)
    p.add_argument("--output",       default=OUTPUT_DIR)
    p.add_argument("--limit",        type=int, default=None)
    p.add_argument("--no-resume",    action="store_true")
    p.add_argument("--api-key",      default=SIFT_API_KEY)
    p.add_argument("--gh-token",     default=GITHUB_TOKEN)
    p.add_argument("--threshold",    type=int, default=SIFT_THRESHOLD)
    p.add_argument("--max-chars",    type=int, default=MAX_CODE_CHARS,
                   help="Max code chars per SIFT call (default 8000)")
    args = p.parse_args()

    SIFT_API_KEY   = args.api_key
    GITHUB_TOKEN   = args.gh_token
    SIFT_THRESHOLD = args.threshold
    MAX_CODE_CHARS = args.max_chars

    run_benchmark(Path(args.cve_json_dir), Path(args.src_dir),
                  Path(args.output), args.limit, not args.no_resume)
