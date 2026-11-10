from datetime import datetime
from typing import Any, Dict, List, Optional

from src.core import lifecycle
from src.core.model_gateway import ModelGateway, gateway_from_config, resolve_llm_config
from src.core.patcher import build_patch_draft
from src.core.standards import standards_for_family
from src.core.vuln_hash import enrich_finding_hash
from src.infrastructure.repositories import (
    FindingRepository,
    FixFeedbackRepository,
    ModelRunRepository,
    ReviewRepository,
    VulnerabilityInstanceRepository,
)


class FindingWorkflowService:
    def __init__(
        self,
        finding_repository: FindingRepository,
        review_repository: Optional[ReviewRepository] = None,
        model_run_repository: Optional[ModelRunRepository] = None,
        instance_repository: Optional[VulnerabilityInstanceRepository] = None,
        model_gateway: Optional[ModelGateway] = None,
    ):
        self.finding_repository = finding_repository
        db = finding_repository.db
        self.review_repository = review_repository or ReviewRepository(db)
        self.model_run_repository = model_run_repository or ModelRunRepository(db)
        self.instance_repository = instance_repository or VulnerabilityInstanceRepository(db)
        self.fix_feedback_repository = FixFeedbackRepository(db)
        self.model_gateway = model_gateway or gateway_from_config(
            # 2026-09-19：gray-review 此前用无参 ModelGateway() —— 它只认
            # SAST_AI_MODEL_PROVIDER 环境变量，生产环境不设 → provider 恒空 →
            # 恒 offline-heuristic，而离线 handler 又只是把确定性 reason 原样返回，
            # 于是这个「AI 复核」节点实际从未调用过模型（API /findings/{id}/ai-review
            # 与 autonomy_service 都读它的输出，所以是有消费方的真节点）。
            # 现改为从根配置的 llm 段取真实 provider，同时保留原来的离线兜底文本，
            # 保证「离线时行为与接入前逐字节一致」。
            resolve_llm_config(None),
            offline_handler=lambda purpose, prompt, context: str(context.get("reason", "")),
        )

    def generate_ai_review(self, finding_id: int) -> Dict[str, Any]:
        finding = self._get_finding(finding_id)
        raw = dict(finding.raw or {})
        family = str(raw.get("display_family") or raw.get("type") or finding.finding_type or "unknown").lower()
        verdict, confidence, matched_accept, matched_reject, standards = self.classify_finding(raw, family)
        review = {
            "ai_verdict": verdict,
            "confidence": confidence,
            "reason": self._reason(verdict, matched_accept, matched_reject, raw),
            "matched_acceptance_criteria": matched_accept,
            "matched_rejection_criteria": matched_reject,
            "missing_evidence": self._missing_evidence(verdict, raw),
            "model": self.model_gateway.model,
            "provider": self.model_gateway.provider,
            "prompt_version": standards.get("prompt_version", "terminal-first-v1"),
            "created_at": datetime.utcnow().isoformat(),
            "auto_close_candidate": verdict == "false_positive" and confidence in {"high", "medium"},
            "auto_close_status": "gray_candidate" if verdict == "false_positive" else "not_applicable",
        }
        raw["ai_review"] = review
        raw = enrich_finding_hash(raw)
        self.finding_repository.update_raw(finding_id, raw)
        vuln_hash = str(raw.get("vulnerability_hash_v2") or "")
        # Route the explanation through the model gateway so telemetry (latency/tokens/
        # cost) is real. Offline mode returns the deterministic heuristic reason.
        prompt = self._review_prompt(family, raw, standards)
        response = self.model_gateway.complete(
            purpose="gray-review",
            prompt=prompt,
            context={"reason": review["reason"], "verdict": verdict, "confidence": confidence},
            prompt_version=review["prompt_version"],
        )
        model_run_id = self.model_run_repository.record(
            purpose="gray-review",
            model=response.model,
            prompt_version=response.prompt_version,
            input_summary=f"finding={finding_id} family={family}",
            output_summary=f"verdict={verdict} confidence={confidence}",
            status=response.status,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=response.cost_usd,
            latency_ms=response.latency_ms,
            error_message=response.error_message,
            metadata={"finding_id": finding_id, "vulnerability_hash_v2": vuln_hash, "provider": response.provider},
        )
        if vuln_hash:
            self.review_repository.add_ai_review(
                finding_id=finding_id,
                vulnerability_hash_v2=vuln_hash,
                verdict=verdict,
                confidence=confidence,
                model=review["model"],
                prompt_version=review["prompt_version"],
                model_run_id=model_run_id,
                criteria={
                    "matched_acceptance_criteria": matched_accept,
                    "matched_rejection_criteria": matched_reject,
                    "reason": review["reason"],
                },
                missing_evidence=review["missing_evidence"],
            )
        return review

    def record_human_decision(self, finding_id: int, decision: str, reason_type: str = "", reason_detail: str = "", reviewer: str = "local") -> Dict[str, Any]:
        finding = self._get_finding(finding_id)
        raw = dict(finding.raw or {})
        ai_verdict = ((raw.get("ai_review") or {}).get("ai_verdict") or "").lower()
        normalized = decision if decision in {"true_positive", "false_positive", "uncertain", "needs_more_evidence"} else "uncertain"
        human = {
            "decision": normalized,
            "reason_type": reason_type,
            "reason_detail": reason_detail,
            "reviewer": reviewer,
            "adopted_ai_judgement": bool(ai_verdict and ((ai_verdict == normalized) or (ai_verdict == "true_positive" and normalized == "true_positive") or (ai_verdict == "false_positive" and normalized == "false_positive"))),
            "created_at": datetime.utcnow().isoformat(),
        }
        raw["human_decision"] = human
        raw["review_status"] = "reviewed"
        self.finding_repository.update_raw(finding_id, raw)
        vuln_hash = str(raw.get("vulnerability_hash_v2") or "")
        if vuln_hash:
            self.review_repository.add_human_review(
                finding_id=finding_id,
                vulnerability_hash_v2=vuln_hash,
                decision=normalized,
                reviewer=reviewer,
                reason_type=reason_type,
                reason_detail=reason_detail,
                adopted_ai_judgement=human["adopted_ai_judgement"],
            )
            lifecycle_status = self._apply_human_lifecycle(finding.workspace_id, vuln_hash, normalized)
            if lifecycle_status:
                human["lifecycle_status"] = lifecycle_status
        return human

    def _apply_human_lifecycle(self, workspace_id: int, vuln_hash: str, decision: str) -> str:
        target = lifecycle.status_for_human_decision(decision)
        if not target:
            return ""
        instance = self.instance_repository.get_by_hash(workspace_id, vuln_hash)
        if not instance:
            return ""
        current = lifecycle.normalize(instance.get("status"))
        if not lifecycle.can_transition(current, target):
            return current
        updated = self.instance_repository.set_status(workspace_id, vuln_hash, target)
        return (updated or {}).get("status", target)

    def review_history(self, finding_id: int) -> Dict[str, Any]:
        finding = self._get_finding(finding_id)
        vuln_hash = str((finding.raw or {}).get("vulnerability_hash_v2") or "")
        instance = self.instance_repository.get_by_hash(finding.workspace_id, vuln_hash) if vuln_hash else None
        return {
            "finding_id": finding_id,
            "vulnerability_hash_v2": vuln_hash,
            "instance": instance,
            "ai_reviews": self.review_repository.ai_reviews_for_hash(vuln_hash) if vuln_hash else [],
            "human_reviews": self.review_repository.human_reviews_for_hash(vuln_hash) if vuln_hash else [],
        }

    def generate_fix_suggestion(self, finding_id: int) -> Dict[str, Any]:
        finding = self._get_finding(finding_id)
        raw = dict(finding.raw or {})
        family = str(raw.get("display_family") or raw.get("type") or finding.finding_type or "unknown").lower()
        standards = standards_for_family(family)
        suggestion = {
            "summary": raw.get("fix") or self._default_fix(family),
            "patch_strategy": self._patch_strategy(family),
            "validation_steps": self._validation_steps(family, standards),
            "risk_notes": "Patch draft is advisory only; review business logic and add regression tests before merging.",
            "created_at": datetime.utcnow().isoformat(),
        }
        raw["fix_suggestion"] = suggestion
        self.finding_repository.update_raw(finding_id, raw)
        return suggestion

    def generate_patch_draft(self, finding_id: int) -> Dict[str, Any]:
        finding = self._get_finding(finding_id)
        raw = dict(finding.raw or {})
        suggestion = raw.get("fix_suggestion") or self.generate_fix_suggestion(finding_id)
        strategy = str(suggestion.get("patch_strategy", "add validation or authorization check"))
        root = str(raw.get("project_path") or raw.get("project_root") or raw.get("root") or "")
        patch = build_patch_draft(finding.file_path or "target-file", finding.line or 1, strategy, root=root or None)
        patch["created_at"] = datetime.utcnow().isoformat()
        raw["patch_draft"] = patch
        self.finding_repository.update_raw(finding_id, raw)
        return patch

    def review_queue(self, task_id: Optional[int] = None, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return [finding.__dict__ for finding in self.finding_repository.list(workspace_id=workspace_id, task_id=task_id) if not (finding.raw or {}).get("human_decision")]

    def record_fix_feedback(
        self,
        finding_id: int,
        *,
        adopted: bool = False,
        misleading: bool = False,
        led_to_retest_pass: Optional[bool] = None,
        suggestion_id: str = "",
        comment: str = "",
        created_by: str = "local",
    ) -> Dict[str, Any]:
        """Record developer feedback on a fix suggestion (G7 / §2.3).

        ``led_to_retest_pass`` is auto-backfilled from the latest retest run for
        this vulnerability hash when the caller does not supply it explicitly.
        """
        finding = self._get_finding(finding_id)
        vuln_hash = str((finding.raw or {}).get("vulnerability_hash_v2") or "")
        if led_to_retest_pass is None:
            led_to_retest_pass = self._latest_retest_passed(vuln_hash)
        return self.fix_feedback_repository.add(
            workspace_id=finding.workspace_id,
            finding_id=finding_id,
            vulnerability_hash_v2=vuln_hash,
            suggestion_id=suggestion_id,
            adopted=adopted,
            misleading=misleading,
            led_to_retest_pass=bool(led_to_retest_pass),
            comment=comment,
            created_by=created_by,
        )

    def fix_feedback_metrics(self, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        return self.fix_feedback_repository.metrics(workspace_id=workspace_id)

    def _latest_retest_passed(self, vuln_hash: str) -> bool:
        if not vuln_hash:
            return False
        row = self.finding_repository.db.execute(
            "SELECT result FROM retest_runs WHERE vulnerability_hash_v2 = ? ORDER BY id DESC LIMIT 1",
            (vuln_hash,),
            fetchone=True,
        )
        return bool(row) and str(row["result"]) == "fixed"

    def review_metrics(self, task_id: Optional[int] = None, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        findings = self.finding_repository.list(workspace_id=workspace_id, task_id=task_id)
        ai_total = adopted = ai_false = ai_true = adopted_false = adopted_true = 0
        auto_candidates = 0
        for finding in findings:
            raw = finding.raw or {}
            ai = raw.get("ai_review") or {}
            human = raw.get("human_decision") or {}
            if ai:
                ai_total += 1
                if ai.get("ai_verdict") == "false_positive":
                    ai_false += 1
                if ai.get("ai_verdict") == "true_positive":
                    ai_true += 1
                if ai.get("auto_close_candidate"):
                    auto_candidates += 1
            if human.get("adopted_ai_judgement"):
                adopted += 1
                if ai.get("ai_verdict") == "false_positive":
                    adopted_false += 1
                if ai.get("ai_verdict") == "true_positive":
                    adopted_true += 1
        return {
            "ai_review_total": ai_total,
            "adoption_rate": self._rate(adopted, ai_total),
            "false_positive_adoption_rate": self._rate(adopted_false, ai_false),
            "true_positive_adoption_rate": self._rate(adopted_true, ai_true),
            "noise_reduction_simulated": self._rate(auto_candidates, ai_total),
            "auto_close_candidates": auto_candidates,
            "human_reviewed": sum(1 for item in findings if (item.raw or {}).get("human_decision")),
            "finding_count": len(findings),
            "persisted": self.review_repository.metrics(),
        }

    def _get_finding(self, finding_id: int):
        finding = self.finding_repository.get(finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} not found")
        return finding

    @classmethod
    def classify_finding(cls, raw: Dict[str, Any], family: str):
        """Pure classifier: returns (verdict, confidence, matched_accept, matched_reject, standards).

        Shared by ``generate_ai_review`` and the evaluation framework so scoring uses
        exactly the same decision logic as production review.
        """
        standards = standards_for_family(family)
        matched_reject = cls._matched_rejection(raw, standards.get("reject", []))
        matched_accept = cls._matched_acceptance(raw, standards.get("accept", []))
        if matched_reject and not bool(raw.get("executed") and raw.get("exploitable")):
            verdict = "false_positive"
            confidence = "high" if len(matched_reject) >= 2 else "medium"
        elif raw.get("exploitable") is True or matched_accept:
            verdict = "true_positive"
            confidence = "high" if raw.get("exploitable") is True else "medium"
        else:
            verdict = "uncertain"
            confidence = "low"
        return verdict, confidence, matched_accept, matched_reject, standards

    @staticmethod
    def _review_prompt(family: str, raw: Dict[str, Any], standards: Dict[str, Any]) -> str:
        """Assemble the review prompt, injecting acceptance/rejection standards as context."""
        accept = "; ".join(str(item.get("id")) for item in standards.get("accept", []) or [])
        reject = "; ".join(str(item.get("id")) for item in standards.get("reject", []) or [])
        evidence = " ".join(
            str(raw.get(key, ""))
            for key in ("entry_point", "sink", "description", "data_flow", "d2_evidence")
        ).strip()
        return (
            f"Task: gray-review a {family} finding for exploitability.\n"
            f"Acceptance criteria: {accept or 'n/a'}\n"
            f"Rejection criteria: {reject or 'n/a'}\n"
            f"Evidence: {evidence[:1500]}\n"
            f"Decide true_positive / false_positive / uncertain with a confidence."
        )

    @staticmethod
    def _matched_rejection(raw: Dict[str, Any], criteria: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        text = " ".join(str(raw.get(key, "")) for key in ("description", "data_flow", "code_snippet", "fix", "d2_evidence")).lower()
        matched = []
        for criterion in criteria:
            cid = str(criterion.get("id", ""))
            if any(token in text for token in cid.split("_")) and cid:
                matched.append(criterion)
        if raw.get("has_call_chain") is False and raw.get("has_http_entry") is False:
            matched.extend([item for item in criteria if item.get("id") == "unreachable_sink"])
        return matched[:5]

    @staticmethod
    def _matched_acceptance(raw: Dict[str, Any], criteria: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        matched = []
        if raw.get("exploitable") is True:
            return criteria[:2]
        if raw.get("entry_point") and raw.get("sink"):
            matched = criteria[:1]
        return matched

    @staticmethod
    def _missing_evidence(verdict: str, raw: Dict[str, Any]) -> List[str]:
        missing = []
        if not raw.get("entry_point") and not raw.get("entry_route"):
            missing.append("entry/source evidence")
        if not raw.get("sink"):
            missing.append("sink evidence")
        if raw.get("executed") is not True:
            missing.append("dynamic execution evidence")
        if verdict == "uncertain":
            missing.append("manual review decision")
        return missing

    @staticmethod
    def _reason(verdict: str, accept: List[Dict[str, Any]], reject: List[Dict[str, Any]], raw: Dict[str, Any]) -> str:
        if verdict == "false_positive":
            return "AI gray review found rejection criteria: " + ", ".join(str(item.get("id")) for item in reject)
        if verdict == "true_positive":
            return "AI gray review found acceptance criteria or D2 exploitability evidence: " + ", ".join(str(item.get("id")) for item in accept)
        return "Evidence is incomplete; keep this finding in manual review."

    @staticmethod
    def _default_fix(family: str) -> str:
        return {
            "idor": "Enforce owner/tenant/permission checks before returning or mutating resources.",
            "ssrf": "Validate URL scheme, host and destination with an allowlist and block internal ranges.",
            "command-execution": "Avoid shell execution with user input; use safe APIs and argument arrays.",
            "sql-injection": "Use parameterized queries or ORM binding for all user-controlled values.",
            "sca": "Upgrade the vulnerable dependency to a fixed version or apply vendor mitigation.",
        }.get(family, "Add validation, authorization, safe APIs, and regression tests for the vulnerable path.")

    @staticmethod
    def _patch_strategy(family: str) -> str:
        return {
            "idor": "Add resource ownership check near the resource lookup and before side effects.",
            "ssrf": "Introduce centralized outbound URL validator and deny private network targets.",
            "command-execution": "Replace shell=True/string command with safe API or fixed command arguments.",
            "sql-injection": "Replace string concatenation with prepared statements.",
            "sca": "Bump dependency version in the relevant manifest/lockfile.",
        }.get(family, "Add a narrow guard close to the source-to-sink boundary.")

    @staticmethod
    def _validation_steps(family: str, standards: Dict[str, Any]) -> List[str]:
        steps = ["Run the focused unit/regression test for the vulnerable path."]
        for evidence in standards.get("dynamic_evidence", []) or []:
            steps.append(f"Verify the original payload no longer produces {evidence} evidence.")
        steps.append("Re-run SAST-AI focused retest for the same vulnerability hash.")
        return steps

    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0
