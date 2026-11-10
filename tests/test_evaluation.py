from pathlib import Path

import pytest

from src.core import evaluation
from src.core.model_gateway import ModelGateway, estimate_tokens
from src.application.evaluation_service import EvaluationService
from src.infrastructure.db import Database


def test_estimate_tokens_and_offline_gateway():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    gateway = ModelGateway(offline_handler=lambda purpose, prompt, ctx: "hello world")
    assert gateway.is_offline
    response = gateway.complete(purpose="test", prompt="a longer prompt here", prompt_version="v1")
    assert response.text == "hello world"
    assert response.provider == "offline-heuristic"
    assert response.output_tokens > 0
    assert response.latency_ms >= 0
    assert response.prompt_version == "v1"


def test_score_outcome_matrix():
    assert evaluation.score_outcome("true_positive", "true_positive") == "true_positive"
    assert evaluation.score_outcome("false_positive", "true_positive") == "false_positive"
    assert evaluation.score_outcome("true_positive", "uncertain") == "false_negative"
    assert evaluation.score_outcome("false_positive", "false_positive") == "true_negative"


def test_aggregate_precision_recall_f1():
    metrics = evaluation.aggregate(["true_positive", "true_positive", "false_positive", "false_negative", "true_negative"])
    assert metrics["precision"] == round(2 / 3, 4)
    assert metrics["recall"] == round(2 / 3, 4)
    assert metrics["total"] == 5


def test_pass_at_k_and_pass_hat_k():
    assert evaluation.pass_at_k([False, True, False], 3) is True
    assert evaluation.pass_hat_k([False, True, False], 3) is False
    assert evaluation.pass_at_k([True, True, True], 3) is True
    assert evaluation.pass_hat_k([True, True, True], 3) is True
    assert evaluation.pass_at_k([], 3) is False
    assert evaluation.pass_hat_k([], 3) is False
    # k window restricts how many attempts count.
    assert evaluation.pass_hat_k([True, True, False], 2) is True


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(str(tmp_path / "app.db"))


def test_evaluation_run_on_builtin_golden_set(db: Database):
    service = EvaluationService(db)
    outcome = service.run(name="unit")
    metrics = outcome["metrics"]
    # The builtin golden set is separable by the heuristic -> perfect scores.
    assert metrics["total"] == 4
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0

    runs = service.list_runs()
    assert len(runs) == 1
    detail = service.run_detail(runs[0]["id"])
    assert len(detail["results"]) == 4


def test_evaluation_run_with_repeat_records_pass_at_k(db: Database):
    service = EvaluationService(db)
    outcome = service.run(name="stability", repeat=3, seed_jitter=True)
    metrics = outcome["metrics"]
    # Deterministic offline heuristic => pass@3 == pass^3 == 1.0 on the separable set.
    assert metrics["pass_at_3"] == 1.0
    assert metrics["pass_hat_3"] == 1.0

    run = service.list_runs()[0]
    assert run["pass_at_3"] == 1.0
    assert run["pass_hat_3"] == 1.0
    assert outcome["results"][0]["detail"]["attempts"] == 3
