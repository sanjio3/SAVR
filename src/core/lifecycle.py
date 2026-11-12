"""Vulnerability lifecycle status model and transition rules.

A vulnerability instance (identified by ``vulnerability_hash_v2``) moves through a
small, explicit state machine so that discovery, review, fix, retest and closure
are all driven by the same object instead of ad-hoc ``raw_json`` flags.
"""

from typing import Dict, Set

OPEN = "open"
CONFIRMED = "confirmed"
FALSE_POSITIVE = "false_positive"
IN_FIX = "in_fix"
RETESTING = "retesting"
FIXED = "fixed"
REOPENED = "reopened"
CLOSED = "closed"

STATUSES: Set[str] = {OPEN, CONFIRMED, FALSE_POSITIVE, IN_FIX, RETESTING, FIXED, REOPENED, CLOSED}

# Statuses that mean the instance no longer needs active work.
CLOSED_STATUSES: Set[str] = {FIXED, FALSE_POSITIVE, CLOSED}

_TRANSITIONS: Dict[str, Set[str]] = {
    OPEN: {CONFIRMED, FALSE_POSITIVE, IN_FIX, RETESTING},
    CONFIRMED: {IN_FIX, RETESTING, FALSE_POSITIVE, CLOSED},
    IN_FIX: {RETESTING, CONFIRMED, FALSE_POSITIVE},
    RETESTING: {FIXED, REOPENED, CONFIRMED, FALSE_POSITIVE},
    FIXED: {REOPENED, RETESTING},
    REOPENED: {CONFIRMED, IN_FIX, RETESTING, FALSE_POSITIVE},
    FALSE_POSITIVE: {REOPENED, RETESTING},
    CLOSED: {REOPENED, RETESTING},
}


def normalize(status: str) -> str:
    value = (status or OPEN).strip().lower()
    return value if value in STATUSES else OPEN


def can_transition(current: str, target: str) -> bool:
    current = normalize(current)
    target = (target or "").strip().lower()
    if target not in STATUSES:
        return False
    if current == target:
        return True
    return target in _TRANSITIONS.get(current, set())


def ensure_transition(current: str, target: str) -> str:
    if not can_transition(current, target):
        raise ValueError(f"Illegal lifecycle transition: {current or OPEN} -> {target}")
    return normalize(target)


def status_for_human_decision(decision: str) -> str:
    mapping = {
        "true_positive": CONFIRMED,
        "false_positive": FALSE_POSITIVE,
    }
    return mapping.get((decision or "").strip().lower(), "")


def status_for_retest_result(result: str, current: str) -> str:
    """Resolve the target status after a retest, given the current status."""
    result = (result or "").strip().lower()
    current = normalize(current)
    if result == "fixed":
        return FIXED
    if result == "still_vulnerable":
        return REOPENED if current in CLOSED_STATUSES else CONFIRMED
    # inconclusive or unknown: leave the instance parked in retesting.
    return RETESTING
