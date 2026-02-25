import os
import sys
import argparse
import ast
import json
import re
from pathlib import Path
from typing import List, Tuple

# bring in evaluation helpers
from evaluate_metrics import compute_standard_metrics, compute_cscore
from sift_reasoning_eval import XAIEvaluator
from sift_engine import SiftEngine

def sift_scan(path: str, sample_limit: int = 10) -> Tuple[List[int], List[int], List[float]]:
    y_true: List[int] = []
    y_pred: List[int] = []
    fidelity: List[float] = []

    # Initialize your REAL AI engine using your environment variable
    engine = SiftEngine(api_key=os.environ.get("SIFT_API_KEY", ""))

    files = []
    valid_extensions = {'.py', '.js', '.ts'}
    for root, _, filenames in os.walk(path):
        for fn in filenames:
            # include any file with a permitted source code extension
            filepath = os.path.join(root, fn)
            _, ext = os.path.splitext(fn)
            if ext in valid_extensions:
                files.append(filepath)
    if not files:
        return y_true, y_pred, fidelity

    # Limit to 10 files so you can see the results quickly!
    # Change this number later when you want to scan the whole dataset.
    # files = files[:sample_limit]

    def extract_control_flow(code_content: str) -> List[Tuple[int, str]]:
        """Return list of (lineno, type) for loops, branches, and calls in AST."""
        cf_list: List[Tuple[int, str]] = []
        try:
            tree = ast.parse(code_content)
        except SyntaxError:
            return cf_list
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                cf_list.append((node.lineno, "loop"))
            elif isinstance(node, ast.If):
                cf_list.append((node.lineno, "branch"))
            elif isinstance(node, ast.Call):
                cf_list.append((node.lineno, "call"))
        return cf_list

    def get_ground_truth_line(filepath: str, base_path: str) -> int:
        """Return the ground truth vulnerability line for a file, or -1 if clean."""
        match = re.search(r"CVE-\d{4}-\d{4,}", filepath)
        if not match:
            return -1
        cve_id = match.group(0)

        # locate JSON file by searching upward for CVEs directory
        base = Path(base_path)
        json_path = base / "CVEs" / f"{cve_id}.json"
        if not json_path.exists():
            for parent in base.parents:
                candidate = parent / "CVEs" / f"{cve_id}.json"
                if candidate.exists():
                    json_path = candidate
                    break
        if not json_path.exists():
            return -1

        def _search_line(obj) -> int:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in ("line", "lines", "lineNumber") and isinstance(v, int):
                        return v
                    res = _search_line(v)
                    if res != -1:
                        return res
            elif isinstance(obj, list):
                for item in obj:
                    res = _search_line(item)
                    if res != -1:
                        return res
            return -1

        try:
            with open(json_path, 'r', encoding='utf-8') as jf:
                data = json.load(jf)
            return _search_line(data)
        except Exception:
            return -1

    # 🛡️ GRACEFUL DEGRADATION SAFETY NET 🛡️
    try:
        for i, filepath in enumerate(files, start=1):
            
            with open(filepath, errors='ignore') as f:
                code_content = f.read()

            # PROGRESS TRACKER: Shows exact file count (e.g., [1/223])
            print(f"[{i}/{len(files)}] Scanning {os.path.basename(filepath)} with live SIFT Engine...")
            
            # Call your live Longcat API!
            result = engine.analyze_code(code_content, filename=os.path.basename(filepath))

            # --- AUTO-STOP IF API OUT OF TOKENS ---
            if "error" in result:
                err_msg = str(result["error"]).lower()
                if "quota" in err_msg or "rate limit" in err_msg or "token" in err_msg or "429" in err_msg or "insufficient" in err_msg:
                    print(f"\n🛑 API LIMIT REACHED: {result['error']}")
                    print("Halting the scan early to save your partial Executive Summary...")
                    break 

            # Only calculate metrics if the AI successfully analyzed the code!
            true_line = get_ground_truth_line(filepath, path)
            is_vuln = 1 if true_line > 0 else 0
            y_true.append(is_vuln)

            vulns = result.get("vulnerabilities", [])
            predicted = 1 if vulns else 0
            y_pred.append(predicted)

            # XAI Fidelity evaluation
            evaluator = XAIEvaluator(true_trigger_line=true_line)
            cf = extract_control_flow(code_content)
            explanation = result.get("analysis_steps", "")
            fidelity.append(evaluator.fidelity(explanation, cf))

    except KeyboardInterrupt:
        # This catches when you manually press Ctrl+C in the terminal!
        print("\n\n⚠️ MANUAL OVERRIDE DETECTED (Ctrl+C)!")
        print("Safely stopping the scan to calculate your partial Executive Summary...")

    return y_true, y_pred, fidelity

def main():
    parser = argparse.ArgumentParser(description="Run SIFT against a mounted codebase")
    parser.add_argument("--target", required=True, help="Path to the target codebase inside container")
    args = parser.parse_args()

    target = args.target
    if not os.path.exists(target):
        print(f"Error: target path '{target}' does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning files under {target} ...")
    y_true, y_pred, fidelity_scores = sift_scan(target)

    total = len(y_true)
    
    # Check to prevent dividing by zero if 0 files were scanned
    if total == 0:
        print("\nNo files were successfully scanned. Cannot generate Executive Summary.")
        sys.exit(0)

    precision, recall, f1 = compute_standard_metrics(y_true, y_pred)
    cscore = compute_cscore(y_true, y_pred)
    avg_fidelity = sum(fidelity_scores) / total if total > 0 else 0.0

    print("\n===== EXECUTIVE SUMMARY =====")
    print(f"Total files scanned      : {total}")
    print(f"Precision                : {precision:.3f}")
    print(f"Recall                   : {recall:.3f}")
    print(f"F1 Score                 : {f1:.3f}")
    print(f"Cost-aware Cscore        : {cscore:.3f}")
    print(f"Average explanation fidelity : {avg_fidelity:.3f}")
    print("============================\n")

if __name__ == "__main__":
    main()