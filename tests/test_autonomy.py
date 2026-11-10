from pathlib import Path

import pytest

from src.application.autonomy_service import AutonomyService
from src.application.finding_workflow_service import FindingWorkflowService
from src.core import autonomy, lifecycle
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
    return repo.list(workspace_id=1, task_id=1)[0].id


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    _seed_workspace_task(database)
    return database


def test_pure_engine_apply_and_hold():
    policy = autonomy.AutonomyPolicy(id=1, name="p", action="auto_close", min_confidence="high",
                                     verdict="false_positive", max_impact="medium", gray_percent=100)
    decision = autonomy.evaluate(verdict="false_positive", confidence="high", severity="LOW",
                                 bucket_key="abc", policies=[policy])
    assert decision.decision == autonomy.APPLY
    # gray_percent 0 -> everything holds
    policy.gray_percent = 0
    held = autonomy.evaluate(verdict="false_positive", confidence="high", severity="LOW",
                             bucket_key="abc", policies=[policy])
    assert held.decision == autonomy.HOLD


def test_impact_gate_blocks_high_severity():
    policy = autonomy.AutonomyPolicy(id=1, name="p", action="auto_close", min_confidence="high",
                                     verdict="false_positive", max_impact="medium", gray_percent=100)
    decision = autonomy.evaluate(verdict="false_positive", confidence="high", severity="CRITICAL",
                                 bucket_key="abc", policies=[policy])
    assert decision.decision == autonomy.NO_MATCH


def test_autonomy_auto_close_and_rollback(db: Database):
    finding_id = _seed_finding(db, {
        "type": "SSRF", "display_family": "ssrf", "file": "app/net.py", "line": 5,
        "sink": "requests.get", "has_call_chain": False, "has_http_entry": False, "severity": "LOW",
    })
    workflow = FindingWorkflowService(FindingRepository(db))
    review = workflow.generate_ai_review(finding_id)
    assert review["ai_verdict"] == "false_positive"

    service = AutonomyService(db)
    service.upsert_policy(name="auto-close-fp", action="auto_close", min_confidence="medium",
                          verdict="false_positive", max_impact="medium", gray_percent=100)
    result = service.evaluate_finding(finding_id)
    assert result["decision"] == autonomy.APPLY
    assert result["applied"] is True

    finding = FindingRepository(db).get(finding_id)
    vuln_hash = finding.raw["vulnerability_hash_v2"]
    instance = VulnerabilityInstanceRepository(db).get_by_hash(1, vuln_hash)
    assert instance["status"] == lifecycle.FALSE_POSITIVE

    rollback = service.rollback_action(result["action"]["id"])
    assert rollback["status"] == "rolled_back"
    reverted = VulnerabilityInstanceRepository(db).get_by_hash(1, vuln_hash)
    assert reverted["status"] == lifecycle.OPEN


def test_autonomy_no_policy_means_manual(db: Database):
    finding_id = _seed_finding(db, {
        "type": "SSRF", "display_family": "ssrf", "file": "app/net.py", "line": 5,
        "sink": "requests.get", "has_call_chain": False, "has_http_entry": False,
    })
    FindingWorkflowService(FindingRepository(db)).generate_ai_review(finding_id)
    result = AutonomyService(db).evaluate_finding(finding_id)
    assert result["decision"] == autonomy.NO_MATCH
    assert result["action"] is None
