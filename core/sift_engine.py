import difflib
import json
import logging
import re
from typing import Dict, Any, Optional

import requests  # CRITICAL: Required for Real-Time Registry checks
import pygments
from pygments.lexers import guess_lexer
from pygments.util import ClassNotFound
import openai

# Configure logging
logger = logging.getLogger(__name__)

class SiftEngine:
    """
    SiftEngine handles automated code auditing, language detection, and 
    real-time registry verification (Hybrid AI-Static Analysis).
    """

    def __init__(self, api_key: str):
        """
        Initialize the SiftEngine with the API and model.
        """
        self.client = openai.OpenAI(
            base_url="https://api.longcat.chat/openai",
            api_key=api_key
        )
        
        # Using the standard model ID for research benchmarks
        self.model = "LongCat-Flash-Thinking"
        logger.info("SiftEngine initialized with model: %s", self.model)

    def detect_language(self, code_content: str) -> str:
        """
        Detects the programming language of the provided code using Pygments.
        """
        try:
            lexer = guess_lexer(code_content)
            if lexer.name == "Text only":
                return "Unknown"
            return lexer.name
        except ClassNotFound:
            return "Unknown"

    def _verify_imports_with_pypi(self, code_content: str) -> str:
        """
        [Research Feature] Real-Time Registry-Aware Verification.
        Checks PyPI to detect 'Slopsquatting' or Hallucinated Imports.
        """
        imports = re.findall(r'^\s*(?:import|from)\s+(\w+)', code_content, re.MULTILINE)
        imports = list(set(imports)) # Deduplicate
        
        if not imports:
            return "No external imports detected."

        results = []
        std_lib = {
            'os', 'sys', 'json', 'math', 'datetime', 're', 'random', 'time', 
            'logging', 'threading', 'collections', 'typing', 'subprocess', 'sqlite3', 'requests', 'flask'
        }

        for pkg in imports:
            if pkg in std_lib:
                continue
                
            try:
                response = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=1.0)
                
                if response.status_code == 200:
                    results.append(f"[VERIFIED] Package '{pkg}' exists on PyPI registry.")
                elif response.status_code == 404:
                    results.append(f"[CRITICAL] Package '{pkg}' NOT FOUND on PyPI. This is likely a HALLUCINATION.")
                else:
                    results.append(f"[WARNING] Could not verify '{pkg}' (Status: {response.status_code}).")
            except Exception:
                results.append(f"[UNKNOWN] Network error verifying '{pkg}'.")
        
        return "\n".join(results)

    def _verify_imports_with_npm(self, code_content: str) -> str:
        """
        Checks npm registry to detect hallucinated or non-existent JS packages.
        Mirrors _verify_imports_with_pypi() but for JavaScript/TypeScript.
        """
        import time as _time

        # Extract require() and import ... from ... statements
        require_pkgs = re.findall(
            r'require\s*\(\s*["\']([^"\'\./ ][^"\']*)["\']', code_content)
        import_pkgs  = re.findall(
            r'(?:^|\s)import\s+.*?\s+from\s+["\']([^"\'\./ ][^"\']*)["\']',
            code_content, re.MULTILINE)

        packages = list(set(require_pkgs + import_pkgs))

        if not packages:
            return "No external npm imports detected."

        # Node.js built-in modules — skip these
        node_builtins = {
            'fs', 'path', 'http', 'https', 'crypto', 'os', 'util',
            'events', 'stream', 'buffer', 'url', 'querystring',
            'child_process', 'cluster', 'readline', 'zlib', 'net',
            'tls', 'dns', 'domain', 'vm', 'assert', 'v8', 'perf_hooks',
            'worker_threads', 'module', 'process', 'console', 'timers'
        }

        results = []
        for pkg in packages:
            if pkg in node_builtins:
                continue
            # Strip sub-paths: 'lodash/merge' -> 'lodash'
            root_pkg = pkg.split('/')[0]
            _time.sleep(0.3)  # rate limit
            try:
                resp = requests.get(
                    f"https://registry.npmjs.org/{root_pkg}",
                    timeout=3.0,
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    results.append(
                        f"[VERIFIED] Package '{root_pkg}' exists on npm registry.")
                elif resp.status_code == 404:
                    results.append(
                        f"[CRITICAL] Package '{root_pkg}' NOT FOUND on npm. "
                        f"Likely hallucinated or typosquatted.")
                else:
                    results.append(
                        f"[WARNING] Could not verify '{root_pkg}' "
                        f"(HTTP {resp.status_code}).")
            except Exception:
                results.append(
                    f"[UNKNOWN] Network error verifying npm package '{root_pkg}'.")

        return "\n".join(results) if results else "All imports are Node.js built-ins."

    def detect_regex_patterns(self, code: str) -> list:
        """
        Scans JavaScript/Python source code for regex patterns that may
        cause catastrophic backtracking (ReDoS / CWE-730).
        Returns a list of dicts: {pattern, line, reason}
        """
        warnings = []
        lines = code.splitlines()

        # Extract regex literals and RegExp constructors
        regex_sources = []
        for i, line in enumerate(lines, 1):
            # JS regex literals: /pattern/flags
            for m in re.finditer(r'/([^/\n]{3,})/[gimsuy]*', line):
                regex_sources.append((i, m.group(1)))
            # JS RegExp constructor: new RegExp("pattern")
            for m in re.finditer(r'new\s+RegExp\(["\'](\S[^"\']{2,})["\']', line):
                regex_sources.append((i, m.group(1)))
            # Python re.compile: re.compile("pattern")
            for m in re.finditer(r're\.compile\(["\'](\S[^"\']{2,})["\']', line):
                regex_sources.append((i, m.group(1)))

        # Check each extracted pattern for dangerous structures
        danger_patterns = [
            (r'(\([^)]*[+*]\)[+*])', "Nested quantifier — (a+)+ style"),
            (r'(\([^)]*[+*]\)\?)', "Nested optional quantifier"),
            (r'(\([^|)]+\|[^|)]+\)[+*])', "Alternation with quantifier — (a|b)+ style"),
            (r'(\.\*[^$\n]{0,5}\.\*)', "Multiple wildcards — .*.* style"),
            (r'(\[[^\]]+\][+*][+*])', "Repeated character class"),
        ]

        for line_no, src in regex_sources:
            for danger_re, reason in danger_patterns:
                if re.search(danger_re, src):
                    warnings.append({
                        "pattern": src[:80],
                        "line": line_no,
                        "reason": reason
                    })
                    break  # one warning per pattern is enough

        return warnings

    def analyze_code(self, code_content: str, filename: str = None, **kwargs) -> dict:
        """
        Analyze code using Hybrid AI-Static Analysis.
        """
        try:
            language = self.detect_language(code_content)
            
            registry_context = ""
            if language.lower() in ['python', 'python 3']:
                registry_context = self._verify_imports_with_pypi(code_content)
            elif language.lower() in ['javascript', 'typescript', 'jsx', 'tsx',
                                       'js', 'ts', 'node.js', 'node']:
                registry_context = self._verify_imports_with_npm(code_content)

            # ReDoS pre-analysis (CWE-730)
            regex_warnings = self.detect_regex_patterns(code_content)
            regex_context = ""
            if regex_warnings:
                lines_out = [f"  Line {w['line']}: /{w['pattern']}/ — {w['reason']}"
                             for w in regex_warnings]
                regex_context = (
                    "REGEX ALERT — Potential ReDoS patterns detected:\n"
                    + "\n".join(lines_out)
                    + "\nSpecifically evaluate these for catastrophic backtracking "
                      "(CWE-730). A vulnerable regex can hang the server with a "
                      "crafted input string."
                )

            system_prompt = (
                "You are Sift, a code security auditor. "
                "Analyze the provided code for vulnerabilities: injection risks, "
                "logic gaps, and hallucinated/non-existent imports. "
                "Use the REAL-TIME REGISTRY CONTEXT if provided — flag any package "
                "marked NOT FOUND as a hallucination. "
                "Reason step by step. "
                "For EVERY vulnerability found, provide a concrete suggested_fix "
                "showing the corrected code or remediation approach. "
                "Return ONLY a valid JSON object with no markdown fences, "
                "no extra text before or after. "
                "JSON schema: "
                '{"analysis_steps": "string", '
                '"score": <integer 0-100, 100=safe>, '
                '"vulnerabilities": [{"type": "Hallucination"|"Security"|"Logic", '
                '"name": "string", "line": <int>, "description": "string", '
                '"suggested_fix": "string — corrected code snippet or remediation"}]}'
            )

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"""
                    FILENAME: {filename or 'Unknown'}
                    LANGUAGE: {language}

                    REAL-TIME REGISTRY CONTEXT:
                    {registry_context}

                    REGEX ANALYSIS:
                    {regex_context if regex_context else 'No suspicious regex patterns detected.'}

                    CODE TO ANALYZE:
                    {code_content}
                    """}
                ],
                response_format={"type": "json_object"}
            )

            content = response.choices[0].message.content
            if not content or not content.strip():
                raise ValueError("Empty response from model — likely context overflow")

            try:
                clean_content = content.strip()
                if clean_content.startswith("```json"): clean_content = clean_content[7:]
                if clean_content.startswith("```"): clean_content = clean_content[3:]
                if clean_content.endswith("```"): clean_content = clean_content[:-3]
                
                # Sanitize raw backslashes generated by the LLM (common in regex explanations)
                sanitized_content = re.sub(r'\\(?![/"bfnrtu])', r'\\\\', clean_content.strip())
                result = json.loads(sanitized_content, strict=False)
                result["regex_warnings"] = regex_warnings
                return result
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
                return {
                    "error": "Failed to parse AI response", 
                    "raw_content": content,
                    "score": 0,
                    "vulnerabilities": []
                }

        except Exception as e:
            logger.error(f"Error during code analysis: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Fix-Recognition Methods
    # ------------------------------------------------------------------

    def compute_diff_summary(self, vulnerable_code: str, fixed_code: str) -> str:
        """
        Uses Python's difflib.unified_diff to extract the changed lines between
        the vulnerable and fixed versions and returns them as a formatted string
        suitable for injection into an LLM prompt.
        """
        vulnerable_lines = vulnerable_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)

        diff_lines = list(difflib.unified_diff(
            vulnerable_lines,
            fixed_lines,
            fromfile="vulnerable_version",
            tofile="fixed_version",
            lineterm=""
        ))

        if not diff_lines:
            return "No differences detected between the two versions."

        return "\n".join(diff_lines)

    def analyze_fixed_code(self, vulnerable_code: str, fixed_code: str,
                           filename: str = None) -> dict:
        """
        Analyze a patched version of previously vulnerable code.

        Uses a fix-recognition system prompt with INVERTED scoring:
          - HIGH score (80-100): the patch fully resolves the vulnerability (clean).
          - LOW score  (0-69):  the dangerous pattern still exists (still vulnerable).

        Returns the same JSON structure as analyze_code() with two extra fields:
          - fix_recognized (bool): True if the patch is deemed effective.
          - fix_explanation (str): Explanation of why the fix does or does not work.
        """
        try:
            diff_summary = self.compute_diff_summary(vulnerable_code, fixed_code)

            system_prompt = """
            You are Sift, a specialized code security patch reviewer.
            You are reviewing a PATCHED version of previously vulnerable code.

            Your task is to determine whether the applied patch FULLY resolves the
            original vulnerability, or whether the dangerous pattern still exists
            in the fixed version.

            INSTRUCTIONS:
            - Analyze the diff between the vulnerable and fixed versions step-by-step.
            - Step 1: Identify exactly what the vulnerable pattern was and which lines
              contained it.
            - Step 2: Examine the fixed version to check whether that exact pattern
              (or an equivalent bypass) is still reachable.
            - Step 3: State clearly whether the fix is complete, partial, or ineffective.
            - Do NOT flag unrelated style issues. Focus strictly on whether the
              security-relevant change is sufficient.

            SCORING RULES (inverted from standard auditing):
            - 80–100: The patch fully resolves the vulnerability — the code is now clean.
            - 70–79:  The patch significantly reduces risk but may leave minor edge cases.
            - 0–69:   The dangerous pattern still exists or can be trivially bypassed.

            OUTPUT FORMAT (Strict JSON — no extra fields, no markdown fences):
            {
                "analysis_steps": "Step 1: ... Step 2: ... Step 3: ...",
                "score": <0-100 integer>,
                "vulnerabilities": [
                    {
                        "type": "Hallucination" | "Security" | "Logic",
                        "name": "Short Title",
                        "line": <int>,
                        "description": "Detailed explanation"
                    }
                ],
                "fix_recognized": <true | false>,
                "fix_explanation": "Concise explanation of why the fix is or is not effective."
            }

            If the patch is fully effective, 'vulnerabilities' may be an empty list.
            """

            user_message = f"""
            FILENAME: {filename or 'Unknown'}

            === VULNERABLE VERSION ===
            {vulnerable_code}

            === FIXED VERSION ===
            {fixed_code}

            === DIFF SUMMARY ===
            {diff_summary}

            Does this patch fully resolve the vulnerability, or does the dangerous
            pattern still exist in the fixed version?
            """

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_message}
                ]
            )

            content = response.choices[0].message.content
            if not content:
                return {"error": "Empty response from AI model"}

            try:
                clean_content = content.strip()
                if clean_content.startswith("```json"):
                    clean_content = clean_content[7:]
                if clean_content.startswith("```"):
                    clean_content = clean_content[3:]
                if clean_content.endswith("```"):
                    clean_content = clean_content[:-3]

                # Sanitize raw backslashes (common in LLM regex explanations)
                sanitized_content = re.sub(
                    r'\\(?![/\"bfnrtu])', r'\\\\', clean_content.strip()
                )
                result = json.loads(sanitized_content, strict=False)
                return result

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from analyze_fixed_code: {e}")
                return {
                    "error": "Failed to parse AI response",
                    "raw_content": content,
                    "score": 0,
                    "vulnerabilities": [],
                    "fix_recognized": False,
                    "fix_explanation": "Parse error — see raw_content."
                }

        except Exception as e:
            logger.error(f"Error during fix analysis: {e}")
            return {"error": str(e)}