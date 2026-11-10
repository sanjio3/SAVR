"""Taint rule feedback closure (G6).

Implements the whitebox rule feedback loop from the first-edition spec §2.7:
AI-discovered source/sink/sanitizer patterns become ``taint_rule_candidates``;
a human confirms one; on confirmation the rule is rendered into the generated
rule file and a regression is run against the golden set. The merge is only
committed when the regression does not degrade evaluation metrics.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.application.evaluation_service import EvaluationService
from src.infrastructure.db import Database
from src.infrastructure.repositories import TaintRuleRepository

_VALID_KINDS = {"source", "sink", "sanitizer"}
_DEFAULT_GENERATED_RULES = Path(__file__).resolve().parents[1] / "config" / "rules" / "generated_rules.yaml"
# Metrics that must not regress for a rule to be merged.
_GATE_METRICS = ("precision", "recall", "f1")


class RuleFeedbackService:
    def __init__(
        self,
        db: Database,
        *,
        generated_rules_path: Optional[str] = None,
        evaluation_service: Optional[EvaluationService] = None,
    ):
        self.db = db
        self.repository = TaintRuleRepository(db)
        self.evaluation_service = evaluation_service or EvaluationService(db)
        self.generated_rules_path = Path(generated_rules_path) if generated_rules_path else _DEFAULT_GENERATED_RULES

    @staticmethod
    def rule_hash(kind: str, language: str, pattern: str, family: str) -> str:
        payload = f"{kind}|{language}|{pattern}|{family}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:24]

    def record_candidate(
        self,
        *,
        kind: str,
        pattern: str,
        language: str = "",
        family: str = "",
        confidence: str = "medium",
        workspace_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        kind = str(kind or "").strip().lower()
        if kind not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {sorted(_VALID_KINDS)}")
        if not str(pattern or "").strip():
            raise ValueError("pattern is required")
        candidate = {
            "kind": kind,
            "language": str(language or "").strip().lower(),
            "pattern": pattern,
            "family": str(family or "").strip().lower(),
            "confidence": confidence,
            "rule_hash": self.rule_hash(kind, language, pattern, family),
        }
        return self.repository.upsert_candidate(workspace_id, candidate)

    def ingest_from_a2(self, findings: List[Dict[str, Any]], workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Harvest new source/sink/sanitizer patterns emitted by A2 findings."""
        recorded: List[Dict[str, Any]] = []
        for finding in findings or []:
            raw = finding if isinstance(finding, dict) else {}
            family = str(raw.get("display_family") or raw.get("family") or "").lower()
            language = str(raw.get("language") or "").lower()
            for kind in _VALID_KINDS:
                for pattern in raw.get(f"new_{kind}s") or raw.get(f"new_{kind}") or []:
                    if not str(pattern).strip():
                        continue
                    recorded.append(self.record_candidate(
                        kind=kind, pattern=str(pattern), language=language,
                        family=family, confidence="candidate", workspace_id=workspace_id,
                    ))
        return recorded

    def list_candidates(self, workspace_id: Optional[int] = None, status: str = "", kind: str = "") -> List[Dict[str, Any]]:
        return self.repository.list_candidates(workspace_id=workspace_id, status=status, kind=kind)

    def confirm(self, rule_id: int, confirmed_by: str = "local") -> Dict[str, Any]:
        candidate = self.repository.get_candidate(rule_id)
        if candidate is None:
            raise ValueError(f"taint rule candidate {rule_id} not found")

        before = self._baseline_metrics()
        self._append_generated_rule(candidate, confirmed_by)
        after = self._baseline_metrics()

        regressed = [m for m in _GATE_METRICS if after.get(m, 0.0) < before.get(m, 0.0) - 1e-9]
        regression_passed = not regressed
        detail = {"before": before, "after": after, "regressed_metrics": regressed}

        if regression_passed:
            updated = self.repository.set_status(
                rule_id, "merged", confirmed_by=confirmed_by,
                regression_passed=True, regression_detail=detail,
            )
        else:
            # Roll back the merge; keep the candidate flagged as regression-failed.
            self._remove_generated_rule(candidate)
            updated = self.repository.set_status(
                rule_id, "regression_failed", confirmed_by=confirmed_by,
                regression_passed=False, regression_detail=detail,
            )
        return {"candidate": updated, "regression": detail}

    def metrics(self, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        candidates = self.repository.list_candidates(workspace_id=workspace_id)
        total = len(candidates)
        merged = sum(1 for c in candidates if c["status"] == "merged")
        failed = sum(1 for c in candidates if c["status"] == "regression_failed")
        pending = sum(1 for c in candidates if c["status"] == "candidate")
        return {
            "total": total,
            "merged": merged,
            "regression_failed": failed,
            "pending": pending,
            "merge_rate": round(merged / total, 4) if total else 0.0,
        }

    def _baseline_metrics(self) -> Dict[str, float]:
        outcome = self.evaluation_service.run(name="taint-rule-regression")
        metrics = outcome.get("metrics") or {}
        return {m: float(metrics.get(m, 0.0)) for m in _GATE_METRICS}

    def _load_generated(self) -> Dict[str, Any]:
        if not self.generated_rules_path.exists():
            return {"version": 1, "rules": []}
        try:
            data = yaml.safe_load(self.generated_rules_path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("version", 1)
        rules = data.get("rules")
        data["rules"] = rules if isinstance(rules, list) else []
        return data

    def _write_generated(self, data: Dict[str, Any]) -> None:
        self.generated_rules_path.parent.mkdir(parents=True, exist_ok=True)
        self.generated_rules_path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8"
        )

    def _append_generated_rule(self, candidate: Dict[str, Any], confirmed_by: str) -> None:
        data = self._load_generated()
        rule_hash = candidate["rule_hash"]
        if any(r.get("rule_hash") == rule_hash for r in data["rules"]):
            return
        data["rules"].append({
            "rule_hash": rule_hash,
            "kind": candidate["kind"],
            "language": candidate["language"],
            "pattern": candidate["pattern"],
            "family": candidate["family"],
            "confirmed_by": confirmed_by,
        })
        self._write_generated(data)

    def _remove_generated_rule(self, candidate: Dict[str, Any]) -> None:
        data = self._load_generated()
        rule_hash = candidate["rule_hash"]
        data["rules"] = [r for r in data["rules"] if r.get("rule_hash") != rule_hash]
        self._write_generated(data)
