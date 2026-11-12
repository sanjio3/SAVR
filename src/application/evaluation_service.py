"""Evaluation service: run a labelled golden set through the AI review classifier."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.application.finding_workflow_service import FindingWorkflowService
from src.core import evaluation
from src.infrastructure.db import Database
from src.infrastructure.repositories import EvaluationRepository

# Built-in minimal golden set so evaluation works out of the box. Extend by pointing
# ``run`` at a JSON dataset file with the same case shape.
_DEFAULT_GOLDEN_SET: List[Dict[str, Any]] = [
    {"case_id": "sqli-exploited", "family": "sql-injection", "expected": "true_positive",
     "raw": {"type": "SQL Injection", "display_family": "sql-injection", "entry_point": "GET /users",
             "sink": "cursor.execute", "exploitable": True, "executed": True}},
    {"case_id": "ssrf-unreachable", "family": "ssrf", "expected": "false_positive",
     "raw": {"type": "SSRF", "display_family": "ssrf", "sink": "requests.get",
             "has_call_chain": False, "has_http_entry": False}},
    {"case_id": "cmd-exploited", "family": "command-execution", "expected": "true_positive",
     "raw": {"type": "Command Execution", "display_family": "command-execution",
             "entry_point": "POST /run", "sink": "os.system", "exploitable": True, "executed": True}},
    {"case_id": "idor-uncertain", "family": "idor", "expected": "false_positive",
     "raw": {"type": "IDOR", "display_family": "idor", "sink": "get_object",
             "has_call_chain": False, "has_http_entry": False}},
]


class EvaluationService:
    def __init__(self, db: Database):
        self.db = db
        self.repository = EvaluationRepository(db)

    def run(
        self,
        *,
        name: str = "adhoc",
        dataset_path: str = "",
        model: str = "local-heuristic-review",
        prompt_version: str = "terminal-first-v1",
        repeat: int = 1,
        seed_jitter: bool = False,
        scan_mode: str = "",
        agent_impl: str = "",
    ) -> Dict[str, Any]:
        cases = self._load_dataset(dataset_path)
        repeat = max(1, int(repeat))
        results: List[Dict[str, Any]] = []
        outcomes: List[str] = []
        pass_at_hits: List[bool] = []
        pass_hat_hits: List[bool] = []
        for case in cases:
            raw = dict(case.get("raw") or {})
            family = str(case.get("family") or raw.get("display_family") or "unknown").lower()
            expected = case.get("expected", "")
            case_hits: List[bool] = []
            first_verdict = ""
            verdict = confidence = ""
            outcome = ""
            for attempt in range(repeat):
                run_raw = self._jitter(raw, attempt) if (seed_jitter and attempt) else raw
                verdict, confidence, _, _, _ = FindingWorkflowService.classify_finding(run_raw, family)
                outcome = evaluation.score_outcome(expected, verdict)
                case_hits.append(outcome in {"true_positive", "true_negative"})
                if attempt == 0:
                    first_verdict = verdict
            # First-attempt outcome drives the confusion matrix (backward compatible).
            outcomes.append(evaluation.score_outcome(expected, first_verdict))
            pass_at_hits.append(evaluation.pass_at_k(case_hits, repeat))
            pass_hat_hits.append(evaluation.pass_hat_k(case_hits, repeat))
            results.append({
                "case_id": case.get("case_id", ""),
                "family": family,
                "expected": expected,
                "predicted": verdict,
                "outcome": outcome,
                "confidence": confidence,
                "detail": {"raw_keys": sorted(raw.keys()), "attempts": repeat, "hits": case_hits},
            })
        metrics = evaluation.aggregate(outcomes)
        pass_at_3 = round(sum(1 for hit in pass_at_hits if hit) / len(pass_at_hits), 4) if pass_at_hits else 0.0
        pass_hat_3 = round(sum(1 for hit in pass_hat_hits if hit) / len(pass_hat_hits), 4) if pass_hat_hits else 0.0
        metrics["pass_at_3"] = pass_at_3
        metrics["pass_hat_3"] = pass_hat_3
        summary = {
            "name": name,
            "model": model,
            "prompt_version": prompt_version,
            "dataset": dataset_path or "builtin",
            "repeat": repeat,
            "scan_mode": scan_mode,
            "agent_impl": agent_impl,
            **metrics,
        }
        run_row = self.repository.add_run(summary, results)
        return {"run": run_row, "results": results, "metrics": metrics}

    def run_matrix(
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
        """Run a model evaluation matrix (G4) across dimension combinations."""
        from src.benchmark.model_eval import ModelEvalMatrix

        return ModelEvalMatrix(self).run(
            name=name,
            dataset_path=dataset_path,
            repeat=repeat,
            seed_jitter=seed_jitter,
            models=models,
            prompt_versions=prompt_versions,
            scan_modes=scan_modes,
            agent_impls=agent_impls,
        )

    @staticmethod
    def _jitter(raw: Dict[str, Any], attempt: int) -> Dict[str, Any]:
        """Deterministic perturbation hook for temperature>0 emulation.

        The offline heuristic is deterministic, so jitter is a no-op placeholder that
        keeps the (expected==predicted) hit stable; once a real LLM at temperature>0 is
        wired in, pass@k and pass^k will diverge naturally.
        """
        return dict(raw)

    def list_runs(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.repository.list_runs(limit=limit)

    def run_detail(self, run_id: int) -> Dict[str, Any]:
        runs = {row["id"]: row for row in self.repository.list_runs(limit=1000)}
        if run_id not in runs:
            raise ValueError(f"evaluation run {run_id} not found")
        return {"run": runs[run_id], "results": self.repository.results_for_run(run_id)}

    def compare(self, run_id_a: int, run_id_b: int) -> Dict[str, Any]:
        runs = {row["id"]: row for row in self.repository.list_runs(limit=1000)}
        if run_id_a not in runs or run_id_b not in runs:
            raise ValueError("both evaluation runs must exist to compare")
        a, b = runs[run_id_a], runs[run_id_b]
        return {
            "a": a,
            "b": b,
            "delta": {metric: round(b[metric] - a[metric], 4) for metric in ("precision", "recall", "f1", "accuracy")},
        }

    @staticmethod
    def _load_dataset(dataset_path: str) -> List[Dict[str, Any]]:
        if not dataset_path:
            return list(_DEFAULT_GOLDEN_SET)
        path = Path(dataset_path)
        if not path.is_file():
            raise ValueError(f"dataset not found: {dataset_path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        cases = data.get("cases") if isinstance(data, dict) else data
        if not isinstance(cases, list):
            raise ValueError("dataset must be a list of cases or an object with a 'cases' list")
        return cases
