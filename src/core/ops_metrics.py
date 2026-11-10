"""Operations dashboard aggregation (G12, 第四版 §2.6/§6.4).

Pure functions over lists of records (findings / autonomy actions / fix-feedback
/ instances) that compute the ROI-style operating metrics: denoise rate, false-
kill rate, adoption rate, auto-close count, language/project coverage. No I/O —
the service layer supplies the record lists.
"""

from typing import Any, Dict, List


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def denoise_rate(*, total_findings: int, auto_closed: int, human_false_positive: int) -> float:
    """Share of findings removed as noise (auto-closed + human-marked FP)."""
    return _rate(auto_closed + human_false_positive, total_findings)


def false_kill_rate(*, autonomy_closed: int, autonomy_rolled_back: int) -> float:
    """Share of autonomous closures later rolled back (i.e. wrongly killed)."""
    return _rate(autonomy_rolled_back, autonomy_closed)


def coverage(records: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    """Count distinct values of ``key`` (e.g. language / project) -> frequency."""
    counts: Dict[str, int] = {}
    for record in records or []:
        value = str(record.get(key) or "").strip() or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def aggregate_ops_metrics(
    *,
    findings: List[Dict[str, Any]],
    autonomy_actions: List[Dict[str, Any]],
    fix_feedback_metrics: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble the operating dashboard payload from raw record lists."""
    total_findings = len(findings)

    human_fp = sum(1 for f in findings if str(f.get("status") or "").lower() in {"false_positive", "rejected", "wont_fix"})

    closures = [a for a in autonomy_actions if str(a.get("action") or "").lower() in {"close", "auto_close", "suppress"}]
    autonomy_closed = sum(1 for a in closures if a.get("applied"))
    autonomy_rolled_back = sum(1 for a in closures if a.get("rolled_back"))
    auto_closed_net = max(0, autonomy_closed - autonomy_rolled_back)

    return {
        "total_findings": total_findings,
        "auto_closed": auto_closed_net,
        "autonomy_closed": autonomy_closed,
        "autonomy_rolled_back": autonomy_rolled_back,
        "human_false_positive": human_fp,
        "denoise_rate": denoise_rate(
            total_findings=total_findings,
            auto_closed=auto_closed_net,
            human_false_positive=human_fp,
        ),
        "false_kill_rate": false_kill_rate(
            autonomy_closed=autonomy_closed,
            autonomy_rolled_back=autonomy_rolled_back,
        ),
        "adoption_rate": fix_feedback_metrics.get("adoption_rate", 0.0),
        "misleading_rate": fix_feedback_metrics.get("misleading_rate", 0.0),
        "retest_pass_rate": fix_feedback_metrics.get("retest_pass_rate", 0.0),
        "coverage": {
            "by_language": coverage(findings, "language"),
            "by_family": coverage(findings, "display_family"),
        },
    }
