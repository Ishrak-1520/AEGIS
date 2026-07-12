"""
SIFT Benchmark — Quick Setup Validator
=======================================
Run this FIRST before the full benchmark to verify:
  1. Your folder structure is correct
  2. SIFT API key works
  3. SIFT can analyse JS files
  4. Output files are written correctly

Usage:
    python verify_setup.py --dataset ./dataset --api-key YOUR_KEY
"""

import os
import sys
import json
import argparse
from pathlib import Path

# ─── Adjust this path if needed ───────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

def check_step(label, fn):
    """Run a check, print pass/fail."""
    try:
        result = fn()
        print(f"  ✅ {label}")
        return result
    except Exception as e:
        print(f"  ❌ {label}")
        print(f"     ERROR: {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset",  default="./dataset",   help="Dataset root path")
    parser.add_argument("--api-key",  default=os.environ.get("SIFT_API_KEY", ""), help="SIFT API key")
    parser.add_argument("--output",   default="./sift_results", help="Output dir")
    args = parser.parse_args()

    print("\n" + "="*55)
    print("  SIFT Benchmark — Setup Verification")
    print("="*55 + "\n")

    # ── Step 1: Dataset structure ──────────────────────────────
    print("STEP 1: Dataset Structure")
    dataset_root = Path(args.dataset)

    check_step(f"Dataset folder exists: {dataset_root}",
               lambda: dataset_root.exists() or (_ for _ in ()).throw(FileNotFoundError(f"Not found: {dataset_root}")))

    def find_cve_dirs():
        dirs = [d for d in dataset_root.iterdir()
                if d.is_dir() and not d.name.startswith(".")
                and ((d/"vulnerable").exists() or (d/"pre_patch").exists())]
        if not dirs:
            raise ValueError("No CVE directories with vulnerable/fixed subfolders found")
        return dirs

    cve_dirs = check_step("CVE directories with vulnerable/fixed subfolders found", find_cve_dirs)

    if cve_dirs:
        print(f"     Found {len(cve_dirs)} CVE directories")
        print(f"     First 3: {[d.name for d in cve_dirs[:3]]}")

    def check_metadata():
        meta_path = dataset_root / "metadata.json"
        if not meta_path.exists():
            print(f"     ⚠️  No metadata.json found — CWEs will be recorded as 'Unknown'")
            print(f"        (This is OK, but you'll lose per-CWE metrics)")
            return None
        with open(meta_path) as f:
            data = json.load(f)
        count = len(data) if isinstance(data, list) else len(data.keys())
        print(f"     metadata.json has {count} entries")
        return data

    check_step("metadata.json check", check_metadata)
    print()

    # ── Step 2: SIFT engine import ─────────────────────────────
    print("STEP 2: SIFT Engine")
    def import_sift():
        from core.sift_engine import SiftEngine
        return SiftEngine
    SiftEngine = check_step("Import SiftEngine from core.sift_engine", import_sift)

    if SiftEngine is None:
        print("\n  ⚠️  Cannot continue without SiftEngine. Check your project path.")
        print("  Tip: Run this script from your project root directory.\n")
        sys.exit(1)

    def init_engine():
        if not args.api_key or args.api_key == "your-api-key-here":
            raise ValueError("No API key provided. Use --api-key or set SIFT_API_KEY env var.")
        engine = SiftEngine(api_key=args.api_key)
        return engine

    engine = check_step("Initialize SiftEngine with API key", init_engine)
    print()

    # ── Step 3: Live API test on one real file ─────────────────
    print("STEP 3: Live SIFT Analysis (first CVE in dataset)")
    if engine and cve_dirs:
        cve_dir  = cve_dirs[0]
        vuln_dir = cve_dir / "vulnerable" if (cve_dir / "vulnerable").exists() else cve_dir / "pre_patch"
        js_files = list(vuln_dir.rglob("*.js")) + list(vuln_dir.rglob("*.ts")) + list(vuln_dir.rglob("*.py"))

        def read_and_analyse():
            if not js_files:
                raise FileNotFoundError(f"No JS/TS/PY files in {vuln_dir}")
            # Just use first file for the test
            code = js_files[0].read_text(encoding="utf-8", errors="replace")[:3000]  # cap to 3k chars
            print(f"     Analysing: {js_files[0].name} ({len(code)} chars)")
            result = engine.analyze_code(code)
            if not isinstance(result, dict):
                raise ValueError(f"Expected dict, got {type(result)}")
            score = result.get("score", "N/A")
            vulns = result.get("vulnerabilities", [])
            print(f"     SIFT score: {score} | Vulnerabilities found: {len(vulns)}")
            return result

        live_result = check_step(f"Run SIFT on {cve_dir.name}/vulnerable", read_and_analyse)
    else:
        print("  ⚠️  Skipping live test (no engine or no CVE dirs).")
        live_result = None
    print()

    # ── Step 4: Output directory ───────────────────────────────
    print("STEP 4: Output Setup")
    output_dir = Path(args.output)
    def make_output():
        output_dir.mkdir(parents=True, exist_ok=True)
        test_file = output_dir / "_verify_test.txt"
        test_file.write_text("ok")
        test_file.unlink()
        return True
    check_step(f"Create and write to output dir: {output_dir}", make_output)
    print()

    # ── Summary ───────────────────────────────────────────────
    print("="*55)
    print("  Verification Complete")
    print("="*55)
    if cve_dirs and engine and live_result:
        print(f"""
  ✅ Everything looks good! Run the full benchmark with:

     python sift_benchmark.py \\
       --dataset {args.dataset} \\
       --output  {args.output} \\
       --api-key YOUR_KEY

  💡 Tip: Test with 5 CVEs first to check output format:

     python sift_benchmark.py \\
       --dataset {args.dataset} \\
       --output  {args.output}_test \\
       --api-key YOUR_KEY \\
       --limit 5
""")
    else:
        print("\n  ⚠️  Some checks failed. Fix the errors above before running the full benchmark.\n")

if __name__ == "__main__":
    main()
