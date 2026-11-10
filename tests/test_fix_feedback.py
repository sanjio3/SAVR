"""G7: developer fix-feedback (第四版 §2.3)."""

from pathlib import Path

import pytest

from src.application.finding_workflow_service import FindingWorkflowService
from src.application.retest_service import RetestService
from src.infrastructure.db import Database
from src.infrastructure.repositories import FindingRepository


def _seed_workspace_task(db: Database) -> None:
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1, "task", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )


def _seed_finding(db: Database) -> int:
    repo = FindingRepository(db)
    repo.replace_for_task(1, 1, [{
        "type": "SQL Injection",
        "display_family": "sql-injection",
        "file": "app/dao.py",
        "line": 10,
        "sink": "cursor.execute",
        "exploitable": True,
    }])
    return repo.list(workspace_id=1, task_id=1)[0].id


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    _seed_workspace_task(database)
    return database


def test_fix_feedback_persists_and_aggregates(db: Database):
    finding_id = _seed_finding(db)
    service = FindingWorkflowService(FindingRepository(db))

    fb = service.record_fix_feedback(finding_id, adopted=True, comment="applied the patch")
    assert fb["adopted"] is True
    assert fb["misleading"] is False
    assert fb["led_to_retest_pass"] is False  # no retest yet

    metrics = service.fix_feedback_metrics(workspace_id=1)
    assert metrics["total"] == 1
    assert metrics["adoption_rate"] == 1.0
    assert metrics["misleading_rate"] == 0.0


def test_fix_feedback_backfills_retest_pass(db: Database):
    finding_id = _seed_finding(db)
    workflow = FindingWorkflowService(FindingRepository(db))
    workflow.generate_ai_review(finding_id)
    workflow.record_human_decision(finding_id, decision="true_positive")

    finding = FindingRepository(db).get(finding_id)
    vuln_hash = finding.raw["vulnerability_hash_v2"]
    RetestService(db).retest(1, vuln_hash, strategy="manual", result="fixed")

    fb = workflow.record_fix_feedback(finding_id, adopted=True)
    assert fb["led_to_retest_pass"] is True

    metrics = workflow.fix_feedback_metrics(workspace_id=1)
    assert metrics["retest_pass_rate"] == 1.0


def test_fix_feedback_missing_finding_raises(db: Database):
    service = FindingWorkflowService(FindingRepository(db))
    with pytest.raises(ValueError):
        service.record_fix_feedback(999, adopted=True)
