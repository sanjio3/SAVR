"""Fuzzy hash matching for cross-scan conclusion inheritance (G8).

When code moves, line numbers drift, or a sink changes slightly, the exact
``vulnerability_hash_v2`` changes and the historical review conclusion would be
lost. This module fuzzy-matches a new finding against known findings by
(family, file basename, sink, source/route, code block) so the prior instance
status and review conclusion can be inherited via a recorded hash migration.
"""

from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional

from src.core.vuln_hash import hash_components, vulnerability_hash_v2

DEFAULT_THRESHOLD = 0.75

# Field weights for the weighted-average similarity (non-SCA findings).
_WEIGHTS = {"basename": 0.30, "sink": 0.30, "source": 0.20, "code_block": 0.20}
_SCA_WEIGHTS = {"component": 0.4, "vulnerability_id": 0.4, "version": 0.2}


def _basename(file_tail: str) -> str:
    return (file_tail or "").split("/")[-1]


def _field_score(a: str, b: str, *, exact_only: bool = False) -> Optional[float]:
    a, b = a or "", b or ""
    if not a and not b:
        return None  # neither side has data -> exclude from the average
    if a == b:
        return 1.0
    if exact_only:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _weighted(scores: Dict[str, Optional[float]], weights: Dict[str, float]) -> float:
    num = 0.0
    denom = 0.0
    for key, weight in weights.items():
        score = scores.get(key)
        if score is None:
            continue
        num += weight * score
        denom += weight
    return round(num / denom, 4) if denom else 0.0


def component_similarity(comp_a: Dict[str, Any], comp_b: Dict[str, Any]) -> float:
    """Similarity in [0, 1] between two hash-component dicts.

    Family must match exactly; otherwise the findings are unrelated (0.0).
    """
    fam_a = str(comp_a.get("family") or "")
    fam_b = str(comp_b.get("family") or "")
    if not fam_a or fam_a != fam_b:
        return 0.0

    if fam_a == "sca":
        scores = {
            "component": _field_score(comp_a.get("component", ""), comp_b.get("component", "")),
            "vulnerability_id": _field_score(comp_a.get("vulnerability_id", ""), comp_b.get("vulnerability_id", ""), exact_only=True),
            "version": _field_score(comp_a.get("version", ""), comp_b.get("version", "")),
        }
        return _weighted(scores, _SCA_WEIGHTS)

    scores = {
        "basename": _field_score(_basename(comp_a.get("file_tail", "")), _basename(comp_b.get("file_tail", ""))),
        "sink": _field_score(comp_a.get("sink", ""), comp_b.get("sink", "")),
        "source": _field_score(comp_a.get("source", "") or comp_a.get("route", ""),
                               comp_b.get("source", "") or comp_b.get("route", "")),
        "code_block": _field_score(comp_a.get("code_block", ""), comp_b.get("code_block", ""), exact_only=True),
    }
    return _weighted(scores, _WEIGHTS)


def _components_of(item: Dict[str, Any]) -> Dict[str, Any]:
    comps = item.get("hash_components")
    if isinstance(comps, dict) and comps:
        return comps
    return hash_components(item)


def _drift_reason(comp_new: Dict[str, Any], comp_old: Dict[str, Any]) -> str:
    diffs: List[str] = []
    if _basename(comp_new.get("file_tail", "")) != _basename(comp_old.get("file_tail", "")):
        diffs.append("file")
    if comp_new.get("sink") != comp_old.get("sink"):
        diffs.append("sink")
    if comp_new.get("code_block") != comp_old.get("code_block"):
        diffs.append("code_block")
    if (comp_new.get("source") or comp_new.get("route")) != (comp_old.get("source") or comp_old.get("route")):
        diffs.append("source")
    return "drift:" + ",".join(diffs) if diffs else "exact"


def match_finding(
    new_finding: Dict[str, Any],
    candidates: List[Dict[str, Any]],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> Optional[Dict[str, Any]]:
    """Find the best fuzzy match for ``new_finding`` among ``candidates``.

    Each candidate must carry ``vulnerability_hash_v2`` and either
    ``hash_components`` or the raw fields needed to compute them. Returns a match
    descriptor (old_hash/new_hash/similarity/reason/candidate) or ``None``.
    """
    new_comp = _components_of(new_finding)
    new_hash = new_finding.get("vulnerability_hash_v2") or vulnerability_hash_v2(new_finding)

    best: Optional[Dict[str, Any]] = None
    for cand in candidates:
        cand_hash = cand.get("vulnerability_hash_v2")
        if not cand_hash or cand_hash == new_hash:
            continue  # exact matches inherit through the normal path, not migration
        cand_comp = _components_of(cand)
        sim = component_similarity(new_comp, cand_comp)
        if best is None or sim > best["similarity"]:
            best = {
                "old_hash": cand_hash,
                "new_hash": new_hash,
                "similarity": sim,
                "reason": _drift_reason(new_comp, cand_comp),
                "candidate": cand,
            }
    if best and best["similarity"] >= threshold:
        return best
    return None
