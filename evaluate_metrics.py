"""Evaluate SIFT vulnerability detection metrics including a cost-aware score.

This module provides standard precision/recall/F1 calculations and a
custom Cscore that heavily penalizes false negatives (missed
vulnerabilities). It also defines a benchmarking helper capable of
checking output against synthetic detection and patching targets.

A minimal ``__main__`` section exercises the functions with mock data
and proves that Cscore collapses when false negatives increase.
"""

from typing import List, Tuple


# ---------- metric calculations ------------------------------------------------

def compute_standard_metrics(y_true: List[int], y_pred: List[int]) -> Tuple[float, float, float]:
    """Return (precision, recall, f1) for binary labels.

    True/false positives/negatives are computed using 1 for vuln and 0 for clean.
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")

    tp = fp = fn = tn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 1 and p == 0:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return precision, recall, f1


def compute_cscore(y_true: List[int], y_pred: List[int], alpha: float = 10.0, beta: float = 1.0) -> float:
    """Cost-aware score that penalizes false negatives more than false positives.

    The formula is::

        Cscore = TP / (TP + alpha * FN + beta * FP)

    ``alpha`` should be much larger than ``beta`` to reflect the high cost of
    missing a vulnerability.  ``beta`` can be 1 by default.

    Returns a value between 0 and 1; higher is better.
    """
    tp = fp = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 1 and p == 0:
            fn += 1

    denom = tp + alpha * fn + beta * fp
    return tp / denom if denom > 0 else 0.0


# ---------- benchmarking -------------------------------------------------------


class SiftBenchmark:
    """Encapsulate evaluation targets for SIFT detection & patching.

    Attributes are the threshold values for the two primary goals.
    """

    def __init__(self,
                 detection_target: float = 0.86,
                 patching_target: float = 0.68):
        self.detection_target = detection_target
        self.patching_target = patching_target

    def evaluate_detection(self, y_true: List[int], y_pred: List[int]) -> Tuple[float, bool]:
        """Compute recall (success rate) and whether the target was met."""
        _, recall, _ = compute_standard_metrics(y_true, y_pred)
        success = recall >= self.detection_target
        return recall, success

    def evaluate_patching(self, y_true: List[int], y_pred: List[int]) -> Tuple[float, bool]:
        """Placeholder for patching/remediation evaluation.

        In this simple implementation we treat precision as the proportion of
        reported vulnerabilities that were actually patched successfully.
        """
        precision, _, _ = compute_standard_metrics(y_true, y_pred)
        success = precision >= self.patching_target
        return precision, success


# ---------- simple unit test ---------------------------------------------------


def _mock_data(num_vuln: int = 100, num_clean: int = 100) -> Tuple[List[int], List[int]]:
    """Return a tuple ``(y_true, y_pred)`` with configurable errors.

    By default the predictor is perfect; callers may modify ``y_pred`` later
    to introduce false negatives/positives.
    """
    y_true = [1] * num_vuln + [0] * num_clean
    y_pred = y_true.copy()
    return y_true, y_pred


if __name__ == '__main__':
    # create baseline dataset
    y_true, y_pred = _mock_data(100, 100)

    # scenario 1: perfect prediction
    perfect_c = compute_cscore(y_true, y_pred)
    print(f"Perfect Cscore: {perfect_c:.4f}")

    # scenario 2: introduce a few false negatives and positives
    # false negative: flip 5 vulnerable examples to clean
    for i in range(5):
        y_pred[i] = 0
    # false positive: flip 3 clean examples to vulnerable
    for i in range(100, 103):
        y_pred[i] = 1

    imperfect_c = compute_cscore(y_true, y_pred)
    print(f"Imperfect Cscore (5 FN, 3 FP): {imperfect_c:.4f}")

    assert imperfect_c < perfect_c, "Cscore should drop when errors introduced"

    # unit test demonstrating sensitivity to false negatives
    # construct second scenario with more FNs but same number of FPs
    y_pred2 = y_true.copy()
    for i in range(20):
        y_pred2[i] = 0
    for i in range(100, 103):
        y_pred2[i] = 1

    c1 = compute_cscore(y_true, y_pred)
    c2 = compute_cscore(y_true, y_pred2)
    print(f"Cscore with 5 FN: {c1:.4f}, with 20 FN: {c2:.4f}")
    assert c2 < c1 * 0.6, "Cscore should drop drastically when FN increases"

    # show benchmark class usage
    bench = SiftBenchmark()
    detect_rate, detect_ok = bench.evaluate_detection(y_true, y_pred)
    patch_rate, patch_ok = bench.evaluate_patching(y_true, y_pred)
    print(f"Detection recall: {detect_rate:.3f}, meets target: {detect_ok}")
    print(f"Patching precision: {patch_rate:.3f}, meets target: {patch_ok}")

    print("All self-tests passed.")
