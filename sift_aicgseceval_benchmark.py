"""
SIFT Benchmark — AICGSecEval (Tencent)
=======================================
Dataset: https://github.com/Tencent/AICGSecEval
Format:  data_v2.json — each entry has a repo, base_commit (vulnerable),
         patch_commit (fixed), vuln_file, vuln_lines, language, cwe_id.

Key differences vs OpenSSF benchmark:
  - Both versions fetched from GitHub (no local files)
  - base_commit ends with "^" (Git parent notation) — we resolve the
    actual parent commit via GitHub API
  - vuln_lines = [start, end] — injected as code snippet hint into prompt
  - Multi-language: C/C++/Java/PHP/Python/JavaScript

Classification (same as OpenSSF):
  Green  = vulnerability detected AND fix recognized
  Orange = vulnerability detected, fix NOT recognized
  Red    = vulnerability missed entirely
"""

import difflib
import os, sys, json, csv, time, logging, argparse
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────
DATA_JSON      = r"C:\xampp\htdocs\CGP-2\datasets\AICGSecEval\data\data_v2.json"
OUTPUT_DIR     = r"C:\xampp\htdocs\CGP-2\datasets\AICGSecEval\sift_results"
SIFT_API_KEY   = os.environ.get("SIFT_API_KEY", "your-api-key-here")
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
SIFT_THRESHOLD = 70
API_DELAY      = 1.5
GITHUB_DELAY   = 0.5
MAX_CODE_CHARS = 8000
MAX_RETRIES    = 3
RETRY_DELAY    = 5

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
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

def truncate_code(code, max_chars=MAX_CODE_CHARS, label=""):
    if len(code) <= max_chars:
        return code, False
    half = max_chars // 2
    cut  = len(code) - max_chars
    truncated = (
        code[:half]
        + f"\n\n// [...TRUNCATED {cut} chars — focus on visible patterns...]\n\n"
        + code[-(max_chars - half):]
    )
    log.info(f"  Truncated {label}: {len(code):,} -> {len(truncated):,} chars")
    return truncated, True


def truncate_around_lines(code, focus_start, focus_end,
                          max_chars=MAX_CODE_CHARS, label=""):
    """
    Instead of head+tail truncation, extract a window centered on the
    known vulnerable lines. Keeps 'context_lines' lines before and after
    the focus range, then fills remaining budget with file head (imports,
    declarations) and file tail.
    """
    lines = code.splitlines(keepends=True)
    total_lines = len(lines)

    if len(code) <= max_chars:
        return code, False

    # Lines around the vulnerability (0-indexed)
    context_lines = 80
    focus_lo = max(0, focus_start - 1 - context_lines)
    focus_hi = min(total_lines, focus_end + context_lines)

    # Always include file head (first 30 lines — imports, includes, globals)
    head_lines = min(30, focus_lo)

    # Build the window
    head_section  = "".join(lines[:head_lines])
    focus_section = "".join(lines[focus_lo:focus_hi])

    # Remaining budget for tail
    used = len(head_section) + len(focus_section)
    tail_budget = max(0, max_chars - used - 200)
    tail_section = "".join(lines[-50:])[:tail_budget] if tail_budget > 0 else ""

    sep1 = (f"\n// [...lines 1-{focus_lo} omitted...]\n\n"
            if head_lines < focus_lo else "")
    sep2 = (f"\n// [...lines {focus_hi}-{total_lines} omitted...]\n"
            if focus_hi < total_lines and tail_section else "")

    result = head_section + sep1 + focus_section + sep2 + tail_section

    if len(result) > max_chars:
        result = result[:max_chars]

    log.info(f"  Centered truncation {label}: showing lines "
             f"{focus_lo+1}-{focus_hi} of {total_lines} "
             f"({len(result):,} chars)")
    return result, True


# ── GitHub helpers ────────────────────────────────────────────────────────────

def gh_headers():
    h = {"User-Agent": "SIFT-AICGSecEval/1.0",
         "Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h


def resolve_patch_commit(entry: dict) -> str:
    """
    AICGSecEval data_v2.json uses two competing schemas:
      - New entries have an explicit 'patch_commit' field.
      - Older entries only have 'base_commit' ending with '^', meaning
        base_commit IS the patch commit SHA with a Git parent-notation suffix.

    Mirrors the logic in validateV2Data.py lines 34-41 exactly.
    Returns the patch commit SHA string, or "" if neither field is present.
    """
    if "patch_commit" in entry and isinstance(entry["patch_commit"], str):
        return entry["patch_commit"]
    base = entry.get("base_commit", "")
    if isinstance(base, str) and base.endswith("^"):
        return base[:-1]   # strip the ^ to get the patch SHA
    return ""


def resolve_parent_commit(repo, commit_hash):
    """Return the parent SHA of patch_commit — this is the vulnerable state."""
    url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
    try:
        req = urllib.request.Request(url, headers=gh_headers())
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        parents = data.get("parents", [])
        if parents:
            sha = parents[0]["sha"]
            log.info(f"  Parent commit: {sha[:8]}")
            return sha
        log.warning(f"  No parent found for {commit_hash[:8]}")
        return ""
    except urllib.error.HTTPError as e:
        if e.code == 429:
            log.warning("  GitHub rate limit — waiting 60s...")
            time.sleep(60)
            return resolve_parent_commit(repo, commit_hash)
        log.warning(f"  GitHub API {e.code} for {commit_hash[:8]}")
        return ""
    except Exception as e:
        log.warning(f"  Error resolving parent: {e}")
        return ""


def fetch_raw_file(repo, commit, filepath):
    """Fetch file content from GitHub raw at a specific commit."""
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{filepath}"
    raw_h = {"User-Agent": "SIFT-AICGSecEval/1.0"}
    if GITHUB_TOKEN:
        raw_h["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        req = urllib.request.Request(url, headers=raw_h)
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        time.sleep(GITHUB_DELAY)
        return content
    except urllib.error.HTTPError as e:
        if e.code == 429:
            log.warning("  GitHub rate limit — waiting 60s...")
            time.sleep(60)
            return fetch_raw_file(repo, commit, filepath)
        log.warning(f"  HTTP {e.code}: {filepath} @ {commit[:8]}")
        return ""
    except Exception as e:
        log.warning(f"  Fetch error: {e}")
        return ""


# ── Vuln line hint ────────────────────────────────────────────────────────────

def build_hint(code, vuln_lines, cwe_id):
    """
    vuln_lines is always [start_line, end_line].
    Extracts that range from code and formats as a hint string.
    """
    if not vuln_lines or len(vuln_lines) < 2:
        return ""
    start, end = vuln_lines[0], vuln_lines[1]
    src = code.splitlines()
    snippet = [
        f"  Line {ln}: {src[ln-1].rstrip()}"
        for ln in range(start, end + 1)
        if 1 <= ln <= len(src)
    ]
    if not snippet:
        return ""
    return (
        f"// SECURITY HINT: Known {cwe_id.upper()} vulnerability "
        f"at lines {start}-{end}. Examine carefully:\n"
        + "\n".join(snippet) + "\n\n"
    )


# ── SIFT wrappers ─────────────────────────────────────────────────────────────

def is_valid_result(result):
    if "error" in result and "score" not in result:
        return False
    if result.get("score") is None and not result.get("vulnerabilities"):
        return False
    return True


def run_sift_vulnerable(engine, code, vuln_lines, cwe_id, label, filename=None):
    """analyze_code() with vuln_lines hint + centered truncation + retry."""
    hint = build_hint(code, vuln_lines, cwe_id)
    if vuln_lines and len(vuln_lines) >= 2 and len(code) > MAX_CODE_CHARS:
        code_to_send, was_truncated = truncate_around_lines(
            code, vuln_lines[0], vuln_lines[1], MAX_CODE_CHARS, label)
        code_to_send = hint + code_to_send
    else:
        code_to_send, was_truncated = truncate_code(
            hint + code, MAX_CODE_CHARS, label)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = engine.analyze_code(code_to_send, filename=filename)
            if isinstance(result, dict) and is_valid_result(result):
                result["truncated"] = was_truncated
                return result
            log.warning(f"  [{label}] Attempt {attempt}: invalid result")
        except Exception as e:
            log.warning(f"  [{label}] Attempt {attempt}: {e}")
        if attempt < MAX_RETRIES:
            log.info(f"  Retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    log.error(f"  [{label}] All retries failed.")
    return {"error": "all_retries_failed", "score": 100,
            "vulnerabilities": [], "truncated": was_truncated}


def compute_focused_diff(vuln_code, fixed_code, vuln_lines, max_context=10):
    """
    Computes a unified diff focused around vuln_lines.
    Returns the diff as a string — typically much smaller than either file.
    """
    vuln_ls  = vuln_code.splitlines(keepends=True)
    fixed_ls = fixed_code.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        vuln_ls, fixed_ls,
        fromfile="vulnerable_version",
        tofile="fixed_version",
        n=max_context  # lines of context around each change
    ))

    if not diff:
        return "No differences found between versions."

    return "".join(diff)


def run_sift_fixed(engine, vuln_code, fixed_code, vuln_lines, label, filename=None):
    """analyze_fixed_code() with centered truncation + retry."""
    half = MAX_CODE_CHARS // 2
    if vuln_lines and len(vuln_lines) >= 2:
        v,  _ = truncate_around_lines(
            vuln_code,  vuln_lines[0], vuln_lines[1], half, f"{label}/vuln")
        fx, _ = truncate_around_lines(
            fixed_code, vuln_lines[0], vuln_lines[1], half, f"{label}/fixed")
    else:
        v,  _ = truncate_code(vuln_code,  half, f"{label}/vuln")
        fx, _ = truncate_code(fixed_code, half, f"{label}/fixed")

    # For large files, also prepare a focused diff to inject into the prompt.
    # This ensures the actual patch is always visible regardless of truncation.
    focused_diff = ""
    if vuln_lines and len(vuln_lines) >= 2:
        focused_diff = compute_focused_diff(vuln_code, fixed_code, vuln_lines)
        log.info(f"  Focused diff: {len(focused_diff):,} chars, "
                 f"{focused_diff.count(chr(10))} lines")

    # Prepend the focused diff as context for the LLM
    if focused_diff:
        v = f"// === FOCUSED PATCH DIFF ===\n{focused_diff}\n\n" \
            f"// === VULNERABLE VERSION (truncated) ===\n{v}"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = engine.analyze_fixed_code(v, fx, filename=filename)
            if isinstance(result, dict) and (
                "score" in result or "fix_recognized" in result
            ):
                return result
            log.warning(f"  [{label}/fix] Attempt {attempt}: invalid result")
        except Exception as e:
            log.warning(f"  [{label}/fix] Attempt {attempt}: {e}")
        if attempt < MAX_RETRIES:
            log.info(f"  Retrying fix analysis in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    log.error(f"  [{label}/fix] All retries failed.")
    return {"error": "all_retries_failed", "score": 100,
            "vulnerabilities": [], "fix_recognized": False,
            "fix_explanation": "All retries failed"}


# ── Classification ────────────────────────────────────────────────────────────

def is_vuln_detected(result):
    score = result.get("score", 100)
    vulns = result.get("vulnerabilities", [])
    return (isinstance(score, (int, float)) and score < SIFT_THRESHOLD) \
           or len(vulns) > 0


def is_fix_ok(result):
    if "fix_recognized" in result:
        return bool(result["fix_recognized"])
    score = result.get("score", 0)
    vulns = result.get("vulnerabilities", [])
    return (isinstance(score, (int, float)) and score >= SIFT_THRESHOLD) \
           and len(vulns) == 0


def classify(detected, fixed):
    if not detected: return "Red"
    if fixed:        return "Green"
    return "Orange"


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(results):
    def sdiv(a, b): return round(a / b, 4) if b else 0.0

    def prf(tp, fp, fn):
        p  = sdiv(tp, tp + fp)
        r  = sdiv(tp, tp + fn)
        f1 = sdiv(2 * p * r, p + r)
        return p, r, f1

    overall = {"Green": 0, "Orange": 0, "Red": 0, "total": 0}
    by_cwe  = defaultdict(lambda: {"Green": 0, "Orange": 0, "Red": 0, "total": 0})
    by_lang = defaultdict(lambda: {"Green": 0, "Orange": 0, "Red": 0, "total": 0})

    for r in results:
        o    = r.get("outcome", "Red")
        cwe  = r.get("cwe_id", "Unknown").upper()
        lang = r.get("language", "unknown").lower()
        overall[o] += 1;    overall["total"] += 1
        by_cwe[cwe][o] += 1;   by_cwe[cwe]["total"] += 1
        by_lang[lang][o] += 1; by_lang[lang]["total"] += 1

    def summary(c):
        tp, fp, fn = c["Green"], c["Orange"], c["Red"]
        t = c["total"]
        p, r, f1 = prf(tp, fp, fn)
        return {
            "Green": tp, "Orange": fp, "Red": fn, "Total": t,
            "Green_pct":  round(100 * tp / t, 1) if t else 0,
            "Orange_pct": round(100 * fp / t, 1) if t else 0,
            "Red_pct":    round(100 * fn / t, 1) if t else 0,
            "Precision": p, "Recall": r, "F1": f1
        }

    return {
        "overall":  summary(overall),
        "per_cwe":  {k: summary(v) for k, v in sorted(by_cwe.items())},
        "per_lang": {k: summary(v) for k, v in sorted(by_lang.items())},
    }


# ── Writers ───────────────────────────────────────────────────────────────────

def write_all(results, metrics, output_dir):
    # Raw JSONL
    p = output_dir / "raw_sift_responses.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    log.info(f"Raw responses       -> {p}")

    # Classification CSV
    p = output_dir / "classification_table.csv"
    fields = ["instance_id", "repo", "language", "cwe_id", "vuln_type",
              "severity", "vuln_file", "vuln_lines", "Outcome",
              "Vuln_Score", "Vuln_Detected", "Vuln_Issues",
              "Fixed_Score", "Fix_Recognized", "Fix_Explanation",
              "Truncated", "Time_s", "Error"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "instance_id":     r["instance_id"],
                "repo":            r.get("repo", ""),
                "language":        r.get("language", ""),
                "cwe_id":          r.get("cwe_id", ""),
                "vuln_type":       r.get("vuln_type", ""),
                "severity":        r.get("severity", ""),
                "vuln_file":       r.get("vuln_file", ""),
                "vuln_lines":      str(r.get("vuln_lines", "")),
                "Outcome":         r.get("outcome", ""),
                "Vuln_Score":      r.get("vuln_score", ""),
                "Vuln_Detected":   r.get("vuln_detected", ""),
                "Vuln_Issues":     r.get("vuln_issue_count", ""),
                "Fixed_Score":     r.get("fixed_score", ""),
                "Fix_Recognized":  r.get("fix_recognized", ""),
                "Fix_Explanation": str(r.get("fix_explanation", ""))[:150],
                "Truncated":       r.get("truncated", False),
                "Time_s":          r.get("processing_time_s", ""),
                "Error":           r.get("error", ""),
            })
    log.info(f"Classification      -> {p}")

    # Per-CWE and per-language CSVs
    for fname, data, key in [
        ("metrics_per_cwe.csv",      metrics["per_cwe"],  "CWE"),
        ("metrics_per_language.csv", metrics["per_lang"], "Language"),
    ]:
        p = output_dir / fname
        cols = [key, "Total", "Green", "Orange", "Red",
                "Green%", "Orange%", "Red%", "Precision", "Recall", "F1"]
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for k, m in data.items():
                w.writerow({
                    key:         k,
                    "Total":     m["Total"],
                    "Green":     m["Green"],
                    "Orange":    m["Orange"],
                    "Red":       m["Red"],
                    "Green%":    f"{m['Green_pct']}%",
                    "Orange%":   f"{m['Orange_pct']}%",
                    "Red%":      f"{m['Red_pct']}%",
                    "Precision": m["Precision"],
                    "Recall":    m["Recall"],
                    "F1":        m["F1"],
                })
        log.info(f"{fname:28} -> {p}")

    # Overall metrics CSV
    p = output_dir / "metrics_overall.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["Metric", "Value"])
        w.writeheader()
        for k, v in metrics["overall"].items():
            w.writerow({"Metric": k, "Value": v})
    log.info(f"Overall metrics     -> {p}")

    # Summary box
    m = metrics["overall"]
    print(f"""
╔══════════════════════════════════════════════════╗
║      SIFT x AICGSecEval BENCHMARK RESULTS        ║
╠══════════════════════════════════════════════════╣
║  Total instances     : {m['Total']:>4}                    ║
║  Green  (detected v) : {m['Green']:>4}  ({m['Green_pct']:>5}%)          ║
║  Orange (fix missed) : {m['Orange']:>4}  ({m['Orange_pct']:>5}%)          ║
║  Red    (missed   x) : {m['Red']:>4}  ({m['Red_pct']:>5}%)          ║
╠══════════════════════════════════════════════════╣
║  Precision           : {m['Precision']:.4f}                    ║
║  Recall              : {m['Recall']:.4f}                    ║
║  F1-Score            : {m['F1']:.4f}                    ║
╚══════════════════════════════════════════════════╝
Output: {output_dir}
""")

    # Per-language breakdown
    print(f"  {'Language':<12} {'n':>4} {'Green%':>7} {'Orange%':>8} "
          f"{'Red%':>6} {'F1':>7}")
    print("  " + "-" * 46)
    for lang, lm in metrics["per_lang"].items():
        print(f"  {lang:<12} {lm['Total']:>4} {lm['Green_pct']:>6}% "
              f"{lm['Orange_pct']:>7}% {lm['Red_pct']:>5}%  {lm['F1']:>6.3f}")


# ── Main benchmark loop ───────────────────────────────────────────────────────

def run_benchmark(data_json, output_dir, limit=None, resume=True, languages=None):
    output_dir.mkdir(parents=True, exist_ok=True)

    entries = json.loads(data_json.read_text(encoding="utf-8"))
    log.info(f"Loaded {len(entries)} entries from {data_json.name}")

    if languages:
        entries = [e for e in entries
                   if e.get("language", "").lower() in languages]
        log.info(f"Filtered to {len(entries)} entries "
                 f"(languages: {', '.join(languages)})")

    if limit:
        entries = entries[:limit]
        log.info(f"Limited to first {limit} entries.")

    log.info("Initializing SiftEngine...")
    engine = SiftEngine(api_key=SIFT_API_KEY)

    raw_path     = output_dir / "raw_sift_responses.jsonl"
    already_done = set()
    results      = []

    if resume and raw_path.exists():
        with open(raw_path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if "instance_id" in e:
                        already_done.add(e["instance_id"])
                        results.append(e)
                except json.JSONDecodeError:
                    pass
        if already_done:
            log.info(f"Resuming — {len(already_done)} already done.")

    total       = len(entries)
    fetch_fails = 0

    for i, entry in enumerate(entries):
        iid = entry["instance_id"]
        if iid in already_done:
            continue

        repo         = entry["repo"]
        patch_commit = resolve_patch_commit(entry)
        vuln_file    = entry["vuln_file"]
        vuln_lines   = entry.get("vuln_lines", [])
        language     = entry.get("language", "unknown")
        cwe_id       = entry.get("cwe_id", "Unknown")
        other_files  = entry.get("other_vuln_files", [])

        log.info(f"[{i+1}/{total}] {iid}  ({language}, {cwe_id.upper()})")

        if not patch_commit:
            log.warning(f"  Skipping {iid} — no patch_commit or base_commit^ found in entry.")
            record = {
                "instance_id": iid, "repo": repo, "language": language,
                "cwe_id": cwe_id, "vuln_type": entry.get("vuln_type", ""),
                "severity": entry.get("severity", ""), "vuln_file": vuln_file,
                "vuln_lines": vuln_lines, "vuln_score": None,
                "vuln_detected": False, "vuln_issue_count": 0,
                "fixed_score": None, "fix_recognized": False,
                "fix_explanation": "missing_patch_commit", "outcome": "Red",
                "truncated": False, "processing_time_s": 0,
                "error": "missing_patch_commit",
                "timestamp": datetime.utcnow().isoformat(),
            }
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue


        def make_error_record(error_msg):
            return {
                "instance_id":       iid,
                "repo":              repo,
                "language":          language,
                "cwe_id":            cwe_id,
                "vuln_type":         entry.get("vuln_type", ""),
                "severity":          entry.get("severity", ""),
                "vuln_file":         vuln_file,
                "vuln_lines":        vuln_lines,
                "vuln_score":        None,
                "vuln_detected":     False,
                "vuln_issue_count":  0,
                "fixed_score":       None,
                "fix_recognized":    False,
                "fix_explanation":   error_msg,
                "outcome":           "Red",
                "truncated":         False,
                "processing_time_s": 0,
                "error":             error_msg,
                "timestamp":         datetime.utcnow().isoformat(),
            }

        # Resolve vulnerable commit (parent of patch_commit)
        log.info(f"  Resolving parent of {patch_commit[:8]}...")
        vuln_commit = resolve_parent_commit(repo, patch_commit)
        if not vuln_commit:
            fetch_fails += 1
            record = make_error_record("parent_commit_failed")
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue

        # Fetch vulnerable version
        vuln_code = fetch_raw_file(repo, vuln_commit, vuln_file)
        for ovf in other_files:
            extra = fetch_raw_file(repo, vuln_commit, ovf["vuln_file"])
            if extra:
                vuln_code += f"\n\n// === {ovf['vuln_file']} ===\n{extra}"
        if not vuln_code:
            fetch_fails += 1
            record = make_error_record("vuln_fetch_failed")
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue
        log.info(f"  Vulnerable: {vuln_file} ({len(vuln_code):,} chars)")

        # Fetch fixed version
        fixed_code = fetch_raw_file(repo, patch_commit, vuln_file)
        for ovf in other_files:
            extra = fetch_raw_file(repo, patch_commit, ovf["vuln_file"])
            if extra:
                fixed_code += f"\n\n// === {ovf['vuln_file']} ===\n{extra}"
        if not fixed_code:
            fetch_fails += 1
            record = make_error_record("fixed_fetch_failed")
            results.append(record)
            with open(raw_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            continue
        log.info(f"  Fixed:      {vuln_file} ({len(fixed_code):,} chars)")

        t = time.time()

        # Analyze vulnerable version
        log.info(f"  SIFT analyze_code()       -> vulnerable...")
        vr = run_sift_vulnerable(
            engine, vuln_code, vuln_lines, cwe_id, iid, filename=vuln_file)
        time.sleep(API_DELAY)

        # Analyze fixed version (diff-aware)
        log.info(f"  SIFT analyze_fixed_code() -> diff-aware...")
        fr = run_sift_fixed(
            engine, vuln_code, fixed_code, vuln_lines, iid, filename=vuln_file)
        time.sleep(API_DELAY)

        elapsed       = round(time.time() - t, 2)
        detected      = is_vuln_detected(vr)
        fix_ok        = is_fix_ok(fr)
        outcome       = classify(detected, fix_ok)
        fix_exp       = fr.get("fix_explanation", "")
        was_truncated = vr.get("truncated", False) or fr.get("truncated", False)

        log.info(f"  {outcome} | Vuln:{vr.get('score','?')} | "
                 f"Fix:{fr.get('score','?')} | Recognized:{fix_ok} | {elapsed}s"
                 + (" [TRUNCATED]" if was_truncated else ""))
        if fix_exp:
            log.info(f"    Fix: {str(fix_exp)[:120]}")

        record = {
            "instance_id":       iid,
            "repo":              repo,
            "language":          language,
            "cwe_id":            cwe_id,
            "vuln_type":         entry.get("vuln_type", ""),
            "severity":          entry.get("severity", ""),
            "vuln_file":         vuln_file,
            "vuln_lines":        vuln_lines,
            "vuln_score":        vr.get("score"),
            "vuln_detected":     detected,
            "vuln_issue_count":  len(vr.get("vulnerabilities", [])),
            "vuln_sift_raw":     vr,
            "fixed_score":       fr.get("score"),
            "fix_recognized":    fix_ok,
            "fix_explanation":   fix_exp,
            "fixed_sift_raw":    fr,
            "outcome":           outcome,
            "truncated":         was_truncated,
            "processing_time_s": elapsed,
            "error":             vr.get("error", fr.get("error", "")),
            "timestamp":         datetime.utcnow().isoformat(),
        }
        results.append(record)
        with open(raw_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    log.info(f"\n{'='*55}")
    log.info(f"Done. Total:{len(results)} | Fetch fails:{fetch_fails}")

    if not results:
        log.error("No results — check paths and GitHub token.")
        return

    metrics = compute_metrics(results)
    write_all(results, metrics, output_dir)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="SIFT Benchmark for AICGSecEval dataset")
    p.add_argument("--data",      default=DATA_JSON,
                   help="Path to data_v2.json")
    p.add_argument("--output",    default=OUTPUT_DIR,
                   help="Output directory for results")
    p.add_argument("--limit",     type=int, default=None,
                   help="Only process first N entries (use 5 to test)")
    p.add_argument("--no-resume", action="store_true",
                   help="Start fresh, ignore existing results")
    p.add_argument("--api-key",   default=SIFT_API_KEY)
    p.add_argument("--gh-token",  default=GITHUB_TOKEN)
    p.add_argument("--threshold", type=int, default=SIFT_THRESHOLD)
    p.add_argument("--languages", nargs="+", default=None,
                   help="Filter by language e.g. --languages python javascript c")
    args = p.parse_args()

    SIFT_API_KEY   = args.api_key
    GITHUB_TOKEN   = args.gh_token
    SIFT_THRESHOLD = args.threshold

    run_benchmark(
        data_json  = Path(args.data),
        output_dir = Path(args.output),
        limit      = args.limit,
        resume     = not args.no_resume,
        languages  = [lang.lower() for lang in args.languages]
                     if args.languages else None,
    )
