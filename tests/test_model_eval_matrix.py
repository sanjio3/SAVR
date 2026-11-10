from pathlib import Path

import pytest

from src.application.evaluation_service import EvaluationService
from src.benchmark.model_eval import ModelEvalMatrix
from src.infrastructure.db import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(str(tmp_path / "app.db"))


def test_matrix_produces_row_per_combination(db: Database):
    service = EvaluationService(db)
    matrix = ModelEvalMatrix(service)
    result = matrix.run(
        name="grid",
        models=["cheap-model", "strong-model"],
        prompt_versions=["p1", "p2"],
        scan_modes=["filter_first", "pure_ai"],
    )
    # 2 models x 2 prompts x 2 scan_modes x 1 (default agent) = 8 combos.
    assert result["combos"] == 8
    assert len(result["rows"]) == 8
    # Each combo persisted a run row with an id.
    assert all(row["run_id"] for row in result["rows"])
    # All four dimensions are recorded on every row.
    for row in result["rows"]:
        assert row["model"] in {"cheap-model", "strong-model"}
        assert row["prompt_version"] in {"p1", "p2"}
        assert row["scan_mode"] in {"filter_first", "pure_ai"}


def test_matrix_recommendation_present(db: Database):
    service = EvaluationService(db)
    result = service.run_matrix(name="reco", models=["a", "b"])
    reco = result["recommendation"]
    assert "best_quality" in reco
    assert "everyday" in reco
    assert reco["best_quality"]["model"] in {"a", "b"}


def test_matrix_runs_persist_and_listable(db: Database):
    service = EvaluationService(db)
    service.run_matrix(name="persisted", models=["m1", "m2", "m3"])
    runs = service.list_runs()
    # 3 combos => 3 persisted evaluation runs.
    assert len(runs) == 3
    # scan_mode / agent_impl columns exist on persisted rows (from G3 migration).
    assert all("scan_mode" in run and "agent_impl" in run for run in runs)


def test_matrix_defaults_single_combo(db: Database):
    service = EvaluationService(db)
    result = service.run_matrix()
    assert result["combos"] == 1
    assert result["rows"][0]["model"] == "local-heuristic-review"
