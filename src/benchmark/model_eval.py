"""Model evaluation matrix (G4).

Runs :class:`EvaluationService` across a cartesian product of experiment
dimensions (``model x prompt_version x scan_mode x agent_impl``) and produces a
comparison table plus a recommended combination. The evaluation itself is fully
offline/deterministic by default, so the matrix is safe to run in tests without
external network access.
"""

from itertools import product
from typing import Any, Dict, List, Optional

from src.application.evaluation_service import EvaluationService


class ModelEvalMatrix:
    def __init__(self, service: EvaluationService):
        self.service = service

    def run(
        self,
        *,
        name: str = "matrix",
        dataset_path: str = "",
        repeat: int = 1,
        seed_jitter: bool = False,
        models: Optional[List[str]] = None,
        prompt_versions: Optional[List[str]] = None,
        scan_modes: Optional[List[str]] = None,
        agent_impls: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        models = models or ["local-heuristic-review"]
        prompt_versions = prompt_versions or ["terminal-first-v1"]
        scan_modes = scan_modes or [""]
        agent_impls = agent_impls or [""]
        combos = list(product(models, prompt_versions, scan_modes, agent_impls))
        rows: List[Dict[str, Any]] = []
        for model, prompt_version, scan_mode, agent_impl in combos:
            outcome = self.service.run(
                name=name,
                dataset_path=dataset_path,
                model=model,
                prompt_version=prompt_version,
                repeat=repeat,
                seed_jitter=seed_jitter,
                scan_mode=scan_mode,
                agent_impl=agent_impl,
            )
            metrics = outcome["metrics"]
            run_row = outcome.get("run") or {}
            rows.append({
                "run_id": run_row.get("id"),
                "model": model,
                "prompt_version": prompt_version,
                "scan_mode": scan_mode,
                "agent_impl": agent_impl,
                "precision": metrics.get("precision", 0.0),
                "recall": metrics.get("recall", 0.0),
                "f1": metrics.get("f1", 0.0),
                "accuracy": metrics.get("accuracy", 0.0),
                "pass_at_3": metrics.get("pass_at_3", 0.0),
                "pass_hat_3": metrics.get("pass_hat_3", 0.0),
            })
        return {
            "name": name,
            "dataset": dataset_path or "builtin",
            "repeat": max(1, int(repeat)),
            "combos": len(rows),
            "rows": rows,
            "recommendation": self._recommend(rows),
        }

    @staticmethod
    def _recommend(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not rows:
            return {}
        # High-capability pick: best F1, tie-broken by pass@3 then pass^3 stability.
        best_quality = max(
            rows,
            key=lambda r: (r.get("f1") or 0.0, r.get("pass_at_3") or 0.0, r.get("pass_hat_3") or 0.0),
        )
        # Everyday pick: among the best-quality tier, the most stable (pass^3).
        top_f1 = max((r.get("f1") or 0.0) for r in rows)
        tier = [r for r in rows if (r.get("f1") or 0.0) >= top_f1] or rows
        everyday = max(tier, key=lambda r: (r.get("pass_hat_3") or 0.0, r.get("pass_at_3") or 0.0))
        dims = ("model", "prompt_version", "scan_mode", "agent_impl")
        metric_keys = ("f1", "precision", "recall", "pass_at_3", "pass_hat_3")
        return {
            "best_quality": {k: best_quality.get(k) for k in dims + metric_keys},
            "everyday": {k: everyday.get(k) for k in dims + metric_keys},
            "note": "日常用低成本/高稳定组合，重点深扫用高能力组合",
        }
