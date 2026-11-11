"""Conditional autonomy: decide whether a finding may be actioned automatically.

The engine grades a finding by (AI verdict, AI confidence, impact) and matches it
against enabled :class:`AutonomyPolicy` rows. A matching policy either *applies* an
automatic action immediately or holds it in *gray* (canary) mode based on a
deterministic per-finding bucket vs. the policy's ``gray_percent`` ramp. Every
decision is auditable and reversible (see ``autonomy_actions`` + rollback).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Optional

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
IMPACT_RANK = {"low": 1, "medium": 2, "high": 3}

_SEVERITY_TO_IMPACT = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "unknown": "low",
}

# Decisions
APPLY = "apply"        # policy matched and finding falls inside the gray ramp -> act now
HOLD = "hold"          # policy matched but finding is outside the ramp -> keep manual
NO_MATCH = "no_match"  # no enabled policy matched -> manual review as usual


@dataclass
class AutonomyPolicy:
    id: Optional[int]
    name: str
    action: str = "auto_close"
    min_confidence: str = "high"
    verdict: str = "false_positive"
    max_impact: str = "medium"
    gray_percent: int = 0
    require_ai_agree: bool = True
    enabled: bool = True


@dataclass
class AutonomyDecision:
    decision: str
    action: str = ""
    policy: Optional[AutonomyPolicy] = None
    gray_bucket: int = 0
    impact: str = "low"
    reason: str = ""


def impact_for_severity(severity: str) -> str:
    return _SEVERITY_TO_IMPACT.get((severity or "unknown").strip().lower(), "low")


def gray_bucket(key: str) -> int:
    """Deterministic 0-99 bucket for a finding, so gray ramps are stable across runs."""
    digest = hashlib.sha256((key or "").encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def evaluate(
    *,
    verdict: str,
    confidence: str,
    severity: str,
    bucket_key: str,
    policies: List[AutonomyPolicy],
    human_agrees: Optional[bool] = None,
) -> AutonomyDecision:
    """Return the autonomy decision for a finding against the ordered policy list."""
    verdict = (verdict or "").strip().lower()
    confidence = (confidence or "low").strip().lower()
    impact = impact_for_severity(severity)
    bucket = gray_bucket(bucket_key)
    conf_rank = CONFIDENCE_RANK.get(confidence, 0)
    impact_rank = IMPACT_RANK.get(impact, 1)

    for policy in policies:
        if not policy.enabled:
            continue
        if policy.verdict and policy.verdict != verdict:
            continue
        if conf_rank < CONFIDENCE_RANK.get(policy.min_confidence, 3):
            continue
        if impact_rank > IMPACT_RANK.get(policy.max_impact, 2):
            continue
        if policy.require_ai_agree and human_agrees is False:
            continue
        if bucket < max(0, min(100, policy.gray_percent)):
            return AutonomyDecision(
                decision=APPLY, action=policy.action, policy=policy, gray_bucket=bucket,
                impact=impact, reason=f"matched policy '{policy.name}'; bucket {bucket} < ramp {policy.gray_percent}",
            )
        return AutonomyDecision(
            decision=HOLD, action=policy.action, policy=policy, gray_bucket=bucket,
            impact=impact, reason=f"matched policy '{policy.name}'; bucket {bucket} >= ramp {policy.gray_percent}",
        )
    return AutonomyDecision(decision=NO_MATCH, gray_bucket=bucket, impact=impact, reason="no enabled policy matched")
