"""Autonomy service: evaluate policies against findings and apply reversible actions."""

from typing import Any, Dict, List, Optional

from src.core import autonomy, lifecycle
from src.infrastructure.db import Database
from src.infrastructure.repositories import (
    AutonomyRepository,
    FindingRepository,
    VulnerabilityInstanceRepository,
)


class AutonomyService:
    def __init__(self, db: Database):
        self.db = db
        self.repository = AutonomyRepository(db)
        self.finding_repository = FindingRepository(db)
        self.instance_repository = VulnerabilityInstanceRepository(db)

    # ---- policy management ------------------------------------------------
    def upsert_policy(self, **fields: Any) -> Dict[str, Any]:
        return self.repository.upsert_policy(**fields)

    def list_policies(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        return self.repository.list_policies(enabled_only=enabled_only)

    def list_actions(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return self.repository.list_actions(workspace_id=workspace_id)

    # ---- evaluation -------------------------------------------------------
    def evaluate_finding(self, finding_id: int, *, created_by: str = "system") -> Dict[str, Any]:
        finding = self.finding_repository.get(finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} not found")
        raw = dict(finding.raw or {})
        ai = raw.get("ai_review") or {}
        verdict = str(ai.get("ai_verdict") or "")
        confidence = str(ai.get("confidence") or "low")
        severity = str(finding.severity or raw.get("severity") or "unknown")
        vuln_hash = str(raw.get("vulnerability_hash_v2") or "")
        human = raw.get("human_decision") or {}
        human_agrees = human.get("adopted_ai_judgement") if human else None

        policies = [self._to_policy(row) for row in self.repository.list_policies(enabled_only=True)]
        decision = autonomy.evaluate(
            verdict=verdict, confidence=confidence, severity=severity,
            bucket_key=vuln_hash or f"finding:{finding_id}", policies=policies,
            human_agrees=human_agrees,
        )

        previous_status = ""
        new_status = ""
        applied = False
        if decision.decision == autonomy.APPLY and vuln_hash:
            instance = self.instance_repository.get_by_hash(finding.workspace_id, vuln_hash)
            if instance:
                previous_status = lifecycle.normalize(instance.get("status"))
                target = self._target_status(decision.action)
                if target and lifecycle.can_transition(previous_status, target):
                    self.instance_repository.set_status(finding.workspace_id, vuln_hash, target)
                    new_status = target
                    applied = True

        if decision.decision == autonomy.NO_MATCH:
            return {"decision": decision.decision, "reason": decision.reason, "impact": decision.impact, "action": None}

        action_row = self.repository.add_action(
            workspace_id=finding.workspace_id,
            policy_id=(decision.policy.id if decision.policy else None),
            policy_name=(decision.policy.name if decision.policy else ""),
            finding_id=finding_id,
            vulnerability_hash_v2=vuln_hash,
            action=decision.action,
            decision=decision.decision,
            previous_status=previous_status,
            new_status=new_status,
            gray_bucket=decision.gray_bucket,
            applied=applied,
            reason=decision.reason,
            evidence={"verdict": verdict, "confidence": confidence, "impact": decision.impact},
            created_by=created_by,
        )
        return {
            "decision": decision.decision,
            "reason": decision.reason,
            "impact": decision.impact,
            "applied": applied,
            "action": action_row,
        }

    def rollback_action(self, action_id: int) -> Dict[str, Any]:
        action = self.repository.get_action(action_id)
        if action is None:
            raise ValueError(f"autonomy action {action_id} not found")
        if action["rolled_back"]:
            return {"status": "already_rolled_back", "action": action}
        if action["applied"] and action["vulnerability_hash_v2"] and action["previous_status"]:
            current = self.instance_repository.get_by_hash(action["workspace_id"], action["vulnerability_hash_v2"])
            if current:
                cur_status = lifecycle.normalize(current.get("status"))
                # A rollback is an administrative revert of our own action, not a
                # forward state-machine transition. Only revert when the instance
                # still holds the status this action applied (nobody changed it
                # since), then restore the recorded previous status directly.
                if cur_status == lifecycle.normalize(action["new_status"]):
                    self.instance_repository.set_status(
                        action["workspace_id"], action["vulnerability_hash_v2"],
                        lifecycle.normalize(action["previous_status"]),
                    )
        self.repository.mark_rolled_back(action_id)
        return {"status": "rolled_back", "action": self.repository.get_action(action_id)}

    @staticmethod
    def _target_status(action: str) -> str:
        return {
            "auto_close": lifecycle.FALSE_POSITIVE,
            "auto_confirm": lifecycle.CONFIRMED,
        }.get(action, "")

    @staticmethod
    def _to_policy(row: Dict[str, Any]) -> autonomy.AutonomyPolicy:
        return autonomy.AutonomyPolicy(
            id=row["id"], name=row["name"], action=row["action"], min_confidence=row["min_confidence"],
            verdict=row["verdict"], max_impact=row["max_impact"], gray_percent=row["gray_percent"],
            require_ai_agree=row["require_ai_agree"], enabled=row["enabled"],
        )
