"""Retest service: drive a vulnerability instance through its lifecycle after a fix.

A retest re-verifies whether a previously found vulnerability (identified by
``vulnerability_hash_v2``) is still exploitable, then transitions the instance's
lifecycle status accordingly and records an auditable ``retest_runs`` entry.

Strategies:

* ``manual`` - the caller supplies the retest ``result`` (``fixed`` /
  ``still_vulnerable`` / ``inconclusive``), e.g. after a manual verification.
* ``idor`` - re-run the DAST-IDOR replay for the given ``app_id`` and check whether
  the same ``vulnerability_hash_v2`` still appears in the fresh findings.
* ``git_diff`` - pull the ``base_ref``/``patch_ref`` code delta for the files on
  the vulnerability chain, analyse only that chain (no full re-scan) and decide
  ``fixed`` / ``not_fixed`` / ``uncertain`` (第四版 G1 / 第一版 §2.13).
"""

from typing import Any, Dict, List, Optional

from src.core import git_diff, lifecycle
from src.infrastructure.db import Database
from src.infrastructure.repositories import (
    FindingRepository,
    ReviewRepository,
    RetestRepository,
    VulnerabilityInstanceRepository,
)


class RetestService:
    def __init__(self, db: Database, d1_service: Optional[Any] = None):
        self.db = db
        self.finding_repository = FindingRepository(db)
        self.instance_repository = VulnerabilityInstanceRepository(db)
        self.retest_repository = RetestRepository(db)
        self.review_repository = ReviewRepository(db)
        self.d1_service = d1_service

    def instance_detail(self, workspace_id: int, vulnerability_hash_v2: str) -> Dict[str, Any]:
        instance = self.instance_repository.get_by_hash(workspace_id, vulnerability_hash_v2)
        if instance is None:
            raise ValueError(f"vulnerability instance not found: {vulnerability_hash_v2}")
        findings = self.finding_repository.list_by_hash(workspace_id, vulnerability_hash_v2)
        return {
            "instance": instance,
            "findings": [self._finding_summary(finding) for finding in findings],
            "ai_reviews": self.review_repository.ai_reviews_for_hash(vulnerability_hash_v2),
            "human_reviews": self.review_repository.human_reviews_for_hash(vulnerability_hash_v2),
            "retests": self.retest_repository.list_for_hash(vulnerability_hash_v2),
        }

    def list_instances(self, workspace_id: Optional[int] = None, status: str = "") -> List[Dict[str, Any]]:
        return self.instance_repository.list(workspace_id=workspace_id, status=status)

    def retest(
        self,
        workspace_id: int,
        vulnerability_hash_v2: str,
        *,
        strategy: str = "manual",
        result: str = "",
        app_id: str = "",
        base_ref: str = "",
        patch_ref: str = "",
        repo_path: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        created_by: str = "local",
    ) -> Dict[str, Any]:
        instance = self.instance_repository.get_by_hash(workspace_id, vulnerability_hash_v2)
        if instance is None:
            raise ValueError(f"vulnerability instance not found: {vulnerability_hash_v2}")
        previous_status = lifecycle.normalize(instance.get("status"))
        strategy = (strategy or "manual").strip().lower()
        evidence = dict(evidence or {})

        if strategy == "idor":
            resolved_result, probe_evidence = self._retest_idor(workspace_id, vulnerability_hash_v2, app_id)
            evidence.update(probe_evidence)
        elif strategy == "git_diff":
            resolved_result, probe_evidence = self._retest_git_diff(
                workspace_id, vulnerability_hash_v2,
                base_ref=base_ref or str(evidence.get("base_ref", "")),
                patch_ref=patch_ref or str(evidence.get("patch_ref", "")),
                repo_path=repo_path or str(evidence.get("repo_path", "")),
            )
            evidence.update(probe_evidence)
        else:
            strategy = "manual"
            resolved_result = (result or "inconclusive").strip().lower()

        if resolved_result not in {"fixed", "still_vulnerable", "inconclusive"}:
            resolved_result = "inconclusive"

        # Resolve the target from the *current* status so a regression on a closed instance
        # reopens it. If the direct transition is not legal, route through ``retesting``.
        target = lifecycle.status_for_retest_result(resolved_result, previous_status)
        if lifecycle.can_transition(previous_status, target):
            new_status = target
        elif lifecycle.can_transition(previous_status, lifecycle.RETESTING) and lifecycle.can_transition(lifecycle.RETESTING, target):
            new_status = target
        else:
            new_status = previous_status
        finding_id = self._latest_finding_id(workspace_id, vulnerability_hash_v2)
        if new_status != previous_status:
            self.instance_repository.set_status(workspace_id, vulnerability_hash_v2, new_status)
        run = self.retest_repository.add(
            workspace_id=workspace_id,
            vulnerability_hash_v2=vulnerability_hash_v2,
            finding_id=finding_id,
            strategy=strategy,
            result=resolved_result,
            previous_status=previous_status,
            new_status=new_status,
            detail=str(evidence.get("detail", "")),
            evidence=evidence,
            created_by=created_by,
        )
        return {"retest": run, "instance": self.instance_repository.get_by_hash(workspace_id, vulnerability_hash_v2)}

    def set_status(self, workspace_id: int, vulnerability_hash_v2: str, target_status: str, created_by: str = "local") -> Dict[str, Any]:
        instance = self.instance_repository.get_by_hash(workspace_id, vulnerability_hash_v2)
        if instance is None:
            raise ValueError(f"vulnerability instance not found: {vulnerability_hash_v2}")
        current = lifecycle.normalize(instance.get("status"))
        new_status = lifecycle.ensure_transition(current, target_status)
        updated = self.instance_repository.set_status(workspace_id, vulnerability_hash_v2, new_status)
        return {"previous_status": current, "instance": updated}

    def _retest_idor(self, workspace_id: int, vulnerability_hash_v2: str, app_id: str):
        if not self.d1_service or not app_id:
            return "inconclusive", {"detail": "IDOR retest requires a d1_service and app_id", "strategy_available": False}
        scan_result = self.d1_service.scan(app_id, {"execute_http": False})
        hashes = {str(item.get("vulnerability_hash_v2") or "") for item in scan_result.get("findings") or []}
        still_present = vulnerability_hash_v2 in hashes
        return (
            "still_vulnerable" if still_present else "fixed",
            {
                "detail": f"re-scanned app {app_id}: {'hash still present' if still_present else 'hash no longer reported'}",
                "app_id": app_id,
                "finding_count": scan_result.get("finding_count", 0),
                "candidate_count": scan_result.get("candidate_count", 0),
            },
        )

    def _retest_git_diff(self, workspace_id: int, vulnerability_hash_v2: str, *, base_ref: str, patch_ref: str, repo_path: str):
        if not base_ref or not patch_ref:
            return "inconclusive", {"detail": "git_diff retest requires base_ref and patch_ref", "strategy_available": False}
        findings = self.finding_repository.list_by_hash(workspace_id, vulnerability_hash_v2)
        if not findings:
            return "inconclusive", {"detail": "no finding on record for this vulnerability hash", "strategy_available": False}
        latest = findings[0]
        raw = dict(latest.raw or {})
        raw.setdefault("file", latest.file_path)
        raw.setdefault("file_path", latest.file_path)
        family = str(raw.get("display_family") or raw.get("type") or latest.finding_type or "unknown").lower()
        resolved_repo = repo_path or str(raw.get("project_path") or raw.get("project_root") or raw.get("root") or "")
        outcome = git_diff.targeted_retest(resolved_repo, base_ref, patch_ref, raw, family=family)
        mapping = {git_diff.FIXED: "fixed", git_diff.NOT_FIXED: "still_vulnerable", git_diff.UNCERTAIN: "inconclusive"}
        resolved = mapping.get(outcome.get("result"), "inconclusive")
        return resolved, {
            "strategy_available": outcome.get("strategy_available", True),
            "base_ref": base_ref,
            "patch_ref": patch_ref,
            "repo_path": resolved_repo,
            "affected_files": outcome.get("affected_files", []),
            "fix_signals": outcome.get("fix_signals", []),
            "sink_removed": outcome.get("sink_removed", False),
            "diff": outcome.get("diff", ""),
            "detail": outcome.get("detail", ""),
        }

    def _latest_finding_id(self, workspace_id: int, vulnerability_hash_v2: str) -> Optional[int]:
        findings = self.finding_repository.list_by_hash(workspace_id, vulnerability_hash_v2)
        return findings[0].id if findings else None

    @staticmethod
    def _finding_summary(finding) -> Dict[str, Any]:
        return {
            "id": finding.id,
            "task_id": finding.task_id,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "file_path": finding.file_path,
            "line": finding.line,
            "title": finding.title,
            "created_at": finding.created_at,
        }
