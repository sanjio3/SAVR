"""Annual cost model + scan-trigger planning (G9, 第四版 §2.12).

Estimates annual SAST spend from average scan cost and predicted scan frequency,
and recommends a model/timing split (cheap model for routine triggers, high-
capability model for key deep scans). Pure arithmetic — no I/O, no network.
"""

from typing import Any, Dict, List, Optional

# Advisory per-1K-token prices mirror src/core/model_gateway._PROVIDER_COST_PER_1K,
# kept here so cost planning works without importing the gateway runtime.
MODEL_COST_PER_1K = {
    "anthropic": 0.009,
    "claude-opus-4-8": 0.009,
    "qwen": 0.002,
    "doubao": 0.001,
    "minimax": 0.001,
    "offline-heuristic": 0.0,
}
_DEFAULT_COST_PER_1K = 0.002

# How often each trigger fires, expressed as scans per month (advisory defaults).
TRIGGER_MONTHLY_FREQUENCY = {
    "pr": 60.0,          # per-PR gate on an active repo
    "merge_main": 20.0,  # merges to main
    "pre_release": 4.0,  # release candidates
    "nightly": 30.0,     # nightly full scan
    "weekly": 4.0,       # weekly deep scan
    "key_project": 8.0,  # ad-hoc key-project deep scans
}


def model_unit_cost(model: str) -> float:
    return MODEL_COST_PER_1K.get((model or "").lower(), _DEFAULT_COST_PER_1K)


def scan_cost(*, input_tokens: int, output_tokens: int, model: str) -> float:
    """Cost (USD) of a single scan given its token usage and model."""
    unit = model_unit_cost(model)
    return round((int(input_tokens) + int(output_tokens)) / 1000.0 * unit, 6)


def average_scan_cost(records: List[Dict[str, Any]]) -> float:
    """Mean ``cost_usd`` across scan cost records (0.0 when empty)."""
    costs = [float(r.get("cost_usd") or 0.0) for r in records or []]
    return round(sum(costs) / len(costs), 6) if costs else 0.0


def predicted_scans_per_year(policies: List[Dict[str, Any]]) -> float:
    """Sum enabled policies' monthly frequency × 12.

    Each policy may carry an explicit ``monthly_frequency``; otherwise it is
    derived from its ``trigger`` via ``TRIGGER_MONTHLY_FREQUENCY``.
    """
    total_monthly = 0.0
    for policy in policies or []:
        if not policy.get("enabled", True):
            continue
        freq = policy.get("monthly_frequency")
        if not freq:
            freq = TRIGGER_MONTHLY_FREQUENCY.get(str(policy.get("trigger") or "").lower(), 0.0)
        total_monthly += float(freq or 0.0)
    return round(total_monthly * 12.0, 4)


def annual_cost(
    *,
    avg_scan_cost: float,
    policies: Optional[List[Dict[str, Any]]] = None,
    predicted_scans: Optional[float] = None,
    variance: float = 0.2,
) -> Dict[str, Any]:
    """Estimate annual cost as ``avg_scan_cost × predicted_scans`` with a band.

    ``predicted_scans`` may be given directly, else derived from ``policies``.
    Returns a point estimate plus a low/high band (±``variance``).
    """
    scans = predicted_scans if predicted_scans is not None else predicted_scans_per_year(policies or [])
    point = round(float(avg_scan_cost) * float(scans), 4)
    low = round(point * (1 - variance), 4)
    high = round(point * (1 + variance), 4)
    return {
        "avg_scan_cost": round(float(avg_scan_cost), 6),
        "predicted_scans": round(float(scans), 4),
        "annual_cost": point,
        "annual_cost_low": low,
        "annual_cost_high": high,
        "variance": variance,
    }


def recommend_model_split(
    *,
    routine_model: str = "doubao",
    deep_model: str = "anthropic",
) -> Dict[str, Any]:
    """Recommend a cost/timing split: cheap model routine, strong model deep."""
    return {
        "routine": {
            "model": routine_model,
            "unit_cost_per_1k": model_unit_cost(routine_model),
            "triggers": ["pr", "merge_main", "nightly"],
            "scan_mode": "filter_first",
            "note": "日常高频触发用低成本模型 + 过滤器前置，控制年度成本。",
        },
        "deep": {
            "model": deep_model,
            "unit_cost_per_1k": model_unit_cost(deep_model),
            "triggers": ["pre_release", "weekly", "key_project"],
            "scan_mode": "pure_ai",
            "note": "发布前/重点项目用高能力模型 + 纯 AI 全量深扫，保召回。",
        },
    }
