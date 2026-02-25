"""Reasoning and explainability evaluation for SIFT module.

This module provides utilities to craft chain-of-thought prompts and to
measure explanation quality using simulated XAI metrics.

The components are:

* ``generate_cot_prompt`` - produce a CoT prompt that forces analysis of data
  dependencies and control flow before the final vulnerability verdict.
* ``evaluate_monitorability`` - a dummy "LLM-as-a-Judge" that scores the
  legibility/faithfulness of an explanation.
* ``XAIEvaluator`` - class computing recovery rate and fidelity metrics based
  on provided explanation and code information.
"""

import re
from typing import List, Tuple


# ---------- CoT prompting engine ------------------------------------------------

def generate_cot_prompt(code_snippet: str) -> str:
    """Return a Chain-of-Thought prompt for SIFT.

    The prompt wraps the provided ``code_snippet`` with explicit instructions to
    trace the data dependencies and control flow step-by-step.  The model is
    required to reason out loud before producing a final ``<verdict>`` token
    saying whether a vulnerability is present.
    """
    template = (
        "You are an expert code auditor. Examine the following code:\n\n"
        "{code}\n\n"
        "Step 1: Identify all variables and their data dependencies.\n"
        "Step 2: Walk through the control flow, explaining each branch.\n"
        "Step 3: Based on the above reasoning, conclude with either\n"
        "'VERDICT: vulnerable' or 'VERDICT: clean'.  Do not state the verdict until\n"
        "the full reasoning has been presented.\n"
        "Provide your reasoning chain-of-thought explicitly."
    )
    return template.format(code=code_snippet)


# ---------- secondary-LLM monitorability eval ----------------------------------

def evaluate_monitorability(sift_explanation: str, source_code: str) -> float:
    """Simulate a judge scoring explanation legibility/faithfulness.

    This dummy implementation awards points for:

    * references to variable names found in ``source_code``
    * the presence of keywords like "branch", "dependency", "flow" in the
      explanation.

    Scores are normalized to [0.0, 1.0].
    """
    # simple heuristics
    score = 0.0
    # reward every variable name mention
    vars_in_code = set(re.findall(r"\b[a-zA-Z_]\w*\b", source_code))
    for var in vars_in_code:
        if re.search(r"\b" + re.escape(var) + r"\b", sift_explanation):
            score += 0.001
    # reward keywords
    for kw in ("branch", "dependency", "control flow", "data flow"):
        if kw in sift_explanation.lower():
            score += 0.1
    return max(0.0, min(1.0, score))


# ---------- XAI metrics --------------------------------------------------------


class XAIEvaluator:
    """Compute simple XAI metrics for SIFT explanations.

    Attributes:
        true_trigger_line (int): the actual line number of the vulnerability trigger.
    """

    def __init__(self, true_trigger_line: int):
        self.true_trigger_line = true_trigger_line

    def recovery_rate(self, predicted_line: int) -> float:
        """Return 1.0 if ``predicted_line`` matches the true trigger, else 0.0."""
        return 1.0 if predicted_line == self.true_trigger_line else 0.0

    def fidelity(self, explanation: str, control_flow: List[Tuple[int, str]]) -> float:
        """Simulate fidelity by checking how many listed control-flow steps appear.

        ``control_flow`` is a list of pairs ``(line_number, description)``; the
        fidelity score is fraction of descriptions whose keywords appear in the
        explanation text.
        """
        if not control_flow:
            return 0.0
        hits = 0
        for _, desc in control_flow:
            if not desc:
                continue
            # check any significant word from description appears in explanation
            words = re.findall(r"\w+", desc.lower())
            for w in words:
                if w and w in explanation.lower():
                    hits += 1
                    break
        return hits / len(control_flow)


# ---------- demonstration -----------------------------------------------------

if __name__ == '__main__':
    snippet = """for i in range(len(data)):\n    if data[i] == None:\n        process(i)"""
    print("CoT prompt:\n", generate_cot_prompt(snippet))

    explanation = "The loop iterates over data; branch when data[i] is None.\n"
    score = evaluate_monitorability(explanation, snippet)
    print("Monitorability score:", score)

    evaluator = XAIEvaluator(true_trigger_line=2)
    print("Recovery (correct):", evaluator.recovery_rate(2))
    print("Recovery (wrong):", evaluator.recovery_rate(3))
    cf = [(1, "loop start"), (2, "branch if None"), (3, "call process")]
    print("Fidelity:", evaluator.fidelity(explanation, cf))
