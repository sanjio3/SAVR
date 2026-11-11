"""Cross-scan conclusion inheritance via fuzzy hash migration (G8).

When code moves, line numbers drift, or a sink changes slightly, the exact
``vulnerability_hash_v2`` changes and the prior review conclusion / instance
status would be lost. This service fuzzy-matches a new finding against known
findings (which persist ``hash_components``); on a strong match it records a
hash migration and carries the prior status + review conclusion onto the new
instance.
"""

from typing import Any, Dict, List, Optional

from src.core.hash_matcher import DEFAULT_THRESHOLD, match_finding
from src.core.vuln_hash import canonicalize_vuln_for_hash, hash_components, vulnerability_hash_v2
from src.infrastructure.db import Database
from src.infrastructure.repositories import (
    FindingRepository,
    HashMigrationRepository,
    VulnerabilityInstanceRepository,
)


class HashMigrationService:
    def __init__(self, db: Database, *, threshold: float = DEFAULT_THRESHOLD):
        self.db = db
        self.threshold = threshold
        self.findings = FindingRepository(db)
        self.instances = VulnerabilityInstanceRepository(db)
        self.migrations = HashMigrationRepository(db)

    def _candidates(self, workspace_id: int, exclude_hash: str) -> List[Dict[str, Any]]:
        """Distinct prior findings (by hash) with their component data."""
        seen: set = set()
        candidates: List[Dict[str, Any]] = []
        for record in self.findings.list(workspace_id=workspace_id):
            raw = record.raw or {}
            cand_hash = str(raw.get("vulnerability_hash_v2") or "")
            if not cand_hash or cand_hash == exclude_hash or cand_hash in seen:
                continue
            seen.add(cand_hash)
            comps = raw.get("hash_components") or hash_components(canonicalize_vuln_for_hash(raw))
            candidates.append({
                "vulnerability_hash_v2": cand_hash,
                "hash_components": comps,
            })
        return candidates

    def match_and_inherit(
        self,
        new_finding: Dict[str, Any],
        *,
        workspace_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Try to inherit a prior conclusion for ``new_finding``.

        Returns the migration descriptor (with the inherited instance) when a
        match at/above threshold is found and applied; otherwise ``None``. An
        exact hash match is left to the normal instance path and returns ``None``.
        """
        new_hash = new_finding.get("vulnerability_hash_v2") or vulnerability_hash_v2(canonicalize_vuln_for_hash(new_finding))

        candidates = self._candidates(workspace_id, new_hash)
        if not candidates:
            return None

        enriched = dict(new_finding)
        enriched.setdefault("hash_components", hash_components(new_finding))
        enriched["vulnerability_hash_v2"] = new_hash

        match = match_finding(enriched, candidates, threshold=self.threshold)
        if not match:
            return None

        old_inst = self.instances.get_by_hash(workspace_id, match["old_hash"])
        if not old_inst:
            return None  # no historical instance to inherit from
        old_status = old_inst.get("status") or "open"
        old_conclusion = old_inst.get("review_conclusion") or ""

        self.migrations.record(
            old_hash=match["old_hash"],
            new_hash=new_hash,
            similarity=match["similarity"],
            reason=match["reason"],
            workspace_id=workspace_id,
        )
        inherited = self.instances.inherit(
            workspace_id,
            new_hash,
            status=old_status,
            review_conclusion=old_conclusion,
        )
        return {
            "old_hash": match["old_hash"],
            "new_hash": new_hash,
            "similarity": match["similarity"],
            "reason": match["reason"],
            "inherited_status": old_status,
            "inherited_review_conclusion": old_conclusion,
            "instance": inherited,
        }
