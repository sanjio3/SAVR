"""Evaluation metrics for AI review scoring against a labelled golden set.

Given per-case (expected, predicted) labels, compute the confusion matrix and
precision / recall / F1 / accuracy. "positive" == a real vulnerability
(``true_positive`` label); "negative" == not a vulnerability (``false_positive`` label).
"""

from __future__ import annotations

from typing import Dict, List

POSITIVE = "true_positive"
NEGATIVE = "false_positive"


def _round(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def score_outcome(expected: str, predicted: str) -> str:
    """Classify a single case into tp/fp/fn/tn (predicted 'uncertain' counts as negative)."""
    exp = (expected or "").strip().lower()
    pred = (predicted or "").strip().lower()
    pred_positive = pred == POSITIVE
    exp_positive = exp == POSITIVE
    if exp_positive and pred_positive:
        return "true_positive"
    if not exp_positive and pred_positive:
        return "false_positive"
    if exp_positive and not pred_positive:
        return "false_negative"
    return "true_negative"


def pass_at_k(hits: List[bool], k: int = 3) -> bool:
    """pass@k: the case is "solved" if *any* of the first ``k`` attempts is a hit."""
    return any(list(hits)[:k]) if hits else False


def pass_hat_k(hits: List[bool], k: int = 3) -> bool:
    """pass^k: stability -- *all* of the first ``k`` attempts must be a hit."""
    window = list(hits)[:k]
    return bool(window) and all(window)


def aggregate(outcomes: List[str]) -> Dict[str, float]:
    tp = outcomes.count("true_positive")
    fp = outcomes.count("false_positive")
    fn = outcomes.count("false_negative")
    tn = outcomes.count("true_negative")
    total = tp + fp + fn + tn
    precision = _round(tp, tp + fp)
    recall = _round(tp, tp + fn)
    f1 = _round(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    accuracy = _round(tp + tn, total)
    return {
        "total": total,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }
