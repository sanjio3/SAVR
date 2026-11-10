from pathlib import Path

import pytest

from src.application.finding_workflow_service import FindingWorkflowService
from src.application.retest_service import RetestService
from src.core import lifecycle
from src.infrastructure.db import Database
from src.infrastructure.repositories import FindingRepository, VulnerabilityInstanceRepository


def _seed_workspace_task(db: Database) -> None:
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    db.execute(
        """
        INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (1, "task", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )


def _seed_finding(db: Database, raw: dict) -> int:
    repo = FindingRepository(db)
    repo.replace_for_task(1, 1, [raw])
    findings = repo.list(workspace_id=1, task_id=1)
    return findings[0].id


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    _seed_workspace_task(database)
    return database


def test_ai_review_and_human_decision_persist_to_tables(db: Database):
    finding_id = _seed_finding(db, {
        "type": "SQL Injection",
        "display_family": "sql-injection",
        "file": "app/dao.py",
        "line": 10,
        "sink": "cursor.execute",
        "entry_point": "GET /users",
        "exploitable": True,
    })
    service = FindingWorkflowService(FindingRepository(db))

    review = service.generate_ai_review(finding_id)
    assert review["ai_verdict"] == "true_positive"

    history = service.review_history(finding_id)
    assert len(history["ai_reviews"]) == 1
    assert history["ai_reviews"][0]["verdict"] == "true_positive"

    # A model run was recorded in the gateway ledger.
    runs = db.execute("SELECT * FROM model_runs", fetchall=True)
    assert len(runs) == 1
    assert runs[0]["purpose"] == "gray-review"

    human = service.record_human_decision(finding_id, decision="true_positive", reason_type="exploited")
    assert human["adopted_ai_judgement"] is True
    assert human["lifecycle_status"] == lifecycle.CONFIRMED

    history = service.review_history(finding_id)
    assert len(history["human_reviews"]) == 1
    assert history["instance"]["status"] == lifecycle.CONFIRMED

    metrics = service.review_metrics(workspace_id=1)
    assert metrics["persisted"]["human_review_total"] == 1
    assert metrics["persisted"]["adopted_ai_judgement"] == 1


def test_false_positive_decision_moves_instance_to_false_positive(db: Database):
    finding_id = _seed_finding(db, {
        "type": "SSRF",
        "display_family": "ssrf",
        "file": "app/net.py",
        "line": 5,
        "sink": "requests.get",
    })
    service = FindingWorkflowService(FindingRepository(db))
    service.generate_ai_review(finding_id)
    human = service.record_human_decision(finding_id, decision="false_positive", reason_type="unreachable")
    assert human["lifecycle_status"] == lifecycle.FALSE_POSITIVE


def test_retest_manual_fixed_then_reopen(db: Database):
    finding_id = _seed_finding(db, {
        "type": "SQL Injection",
        "display_family": "sql-injection",
        "file": "app/dao.py",
        "line": 10,
        "sink": "cursor.execute",
        "exploitable": True,
    })
    workflow = FindingWorkflowService(FindingRepository(db))
    workflow.generate_ai_review(finding_id)
    workflow.record_human_decision(finding_id, decision="true_positive")

    instance_repo = VulnerabilityInstanceRepository(db)
    finding = FindingRepository(db).get(finding_id)
    vuln_hash = finding.raw["vulnerability_hash_v2"]
    assert instance_repo.get_by_hash(1, vuln_hash)["status"] == lifecycle.CONFIRMED

    retest = RetestService(db)
    result = retest.retest(1, vuln_hash, strategy="manual", result="fixed")
    assert result["retest"]["result"] == "fixed"
    assert result["instance"]["status"] == lifecycle.FIXED

    # A regression re-opens a fixed instance.
    result2 = retest.retest(1, vuln_hash, strategy="manual", result="still_vulnerable")
    assert result2["instance"]["status"] == lifecycle.REOPENED

    detail = retest.instance_detail(1, vuln_hash)
    assert len(detail["retests"]) == 2
    assert detail["instance"]["status"] == lifecycle.REOPENED


def test_manual_status_update_rejects_illegal_transition(db: Database):
    finding_id = _seed_finding(db, {
        "type": "Path Traversal",
        "display_family": "path-traversal",
        "file": "app/files.py",
        "line": 3,
        "sink": "open",
    })
    FindingRepository(db)  # ensure instance created via finding
    finding = FindingRepository(db).get(finding_id)
    vuln_hash = finding.raw["vulnerability_hash_v2"]
    retest = RetestService(db)
    with pytest.raises(ValueError):
        retest.set_status(1, vuln_hash, lifecycle.FIXED)  # open -> fixed is illegal
    ok = retest.set_status(1, vuln_hash, lifecycle.CONFIRMED)
    assert ok["instance"]["status"] == lifecycle.CONFIRMED
