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
        self.model = "LongCat-Flash-Thinking-2601" 
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

    def analyze_code(self, code_content: str, filename: str = None, **kwargs) -> dict:
        """
        Analyze code using Hybrid AI-Static Analysis.
        """
        try:
            language = self.detect_language(code_content)
            
            registry_context = ""
            if language.lower() in ['python', 'python 3']:
                registry_context = self._verify_imports_with_pypi(code_content)

            system_prompt = """
            You are Sift, a specialized code integrity auditor. Your goal is to detect:
            1. Hallucinated Imports (Libraries that do not exist).
            2. Logic Gaps (Unfinished code, empty handlers).
            3. Injection Risks (Security vulnerabilities).

            INSTRUCTIONS:
            - Analyze the code step-by-step using explicit Chain-of-Thought reasoning.
            - Step 1: Identify all variables and their data dependencies explicitly.
            - Step 2: Walk through the control flow, explaining each branch, loop, or call.
            - Use the provided 'REAL-TIME REGISTRY CONTEXT'. If a package is listed as NOT FOUND, you MUST flag it as a Hallucination.
            - Do NOT flag stylistic issues (PEP8). Focus on correctness and security.
            
            OUTPUT FORMAT (Strict JSON):
            {
                "analysis_steps": "Step 1: Checked imports and dependencies... Step 2: Detailed control flow reasoning...",
                "score": <0-100 integer, 100 is safe>,
                "vulnerabilities": [
                    {
                        "type": "Hallucination" | "Security" | "Logic",
                        "name": "Short Title",
                        "line": <int>,
                        "description": "Detailed explanation"
                    }
                ]
            }
            """

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"""
                    FILENAME: {filename or 'Unknown'}
                    LANGUAGE: {language}
                    
                    REAL-TIME REGISTRY CONTEXT:
                    {registry_context}
                    
                    CODE TO ANALYZE:
                    {code_content}
                    """}
                ]
            )

            content = response.choices[0].message.content
            if not content:
                return {"error": "Empty response from AI model"}

            try:
                clean_content = content.strip()
                if clean_content.startswith("```json"): clean_content = clean_content[7:]
                if clean_content.startswith("```"): clean_content = clean_content[3:]
                if clean_content.endswith("```"): clean_content = clean_content[:-3]
                
                result = json.loads(clean_content.strip())
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