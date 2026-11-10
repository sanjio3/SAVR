"""G12: operations dashboard aggregation + ticket export (第四版 §2.6/§2.3)."""

from pathlib import Path

import pytest

from src.application.metrics_service import MetricsService
from src.core import ops_metrics
from src.infrastructure.db import Database
from src.infrastructure.repositories import AutonomyRepository, FindingRepository

WORKSPACE_ID = 1


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    database.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (WORKSPACE_ID, "task1", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    return database


def test_denoise_rate_counts_auto_and_human_noise():
    rate = ops_metrics.denoise_rate(total_findings=100, auto_closed=30, human_false_positive=10)
    assert rate == pytest.approx(0.4)
    assert ops_metrics.denoise_rate(total_findings=0, auto_closed=0, human_false_positive=0) == 0.0


def test_false_kill_rate_is_rollbacks_over_closures():
    assert ops_metrics.false_kill_rate(autonomy_closed=20, autonomy_rolled_back=2) == pytest.approx(0.1)
    assert ops_metrics.false_kill_rate(autonomy_closed=0, autonomy_rolled_back=0) == 0.0


def test_coverage_counts_distinct_values_sorted_by_frequency():
    records = [
        {"language": "python"}, {"language": "python"}, {"language": "java"}, {"language": ""},
    ]
    cov = ops_metrics.coverage(records, "language")
    assert cov == {"python": 2, "java": 1, "unknown": 1}
    assert list(cov.keys())[0] == "python"


def test_aggregate_ops_metrics_combines_sources():
    findings = [
        {"status": "false_positive", "language": "python", "display_family": "sql-injection"},
        {"status": "confirmed", "language": "python", "display_family": "xss"},
        {"status": "open", "language": "java", "display_family": "sql-injection"},
    ]
    autonomy_actions = [
        {"action": "auto_close", "applied": True, "rolled_back": False},
        {"action": "auto_close", "applied": True, "rolled_back": True},
        {"action": "suppress", "applied": True, "rolled_back": False},
    ]
    fix_metrics = {"adoption_rate": 0.8, "misleading_rate": 0.05, "retest_pass_rate": 0.9}
    result = ops_metrics.aggregate_ops_metrics(
        findings=findings, autonomy_actions=autonomy_actions, fix_feedback_metrics=fix_metrics,
    )
    assert result["total_findings"] == 3
    assert result["autonomy_closed"] == 3
    assert result["autonomy_rolled_back"] == 1
    assert result["auto_closed"] == 2  # net of rollback
    assert result["human_false_positive"] == 1
    # denoise = (auto_closed_net 2 + human_fp 1) / 3
    assert result["denoise_rate"] == pytest.approx(round(3 / 3, 4))
    # false kill = 1 rollback / 3 closed
    assert result["false_kill_rate"] == pytest.approx(round(1 / 3, 4))
    assert result["adoption_rate"] == 0.8
    assert result["coverage"]["by_language"] == {"python": 2, "java": 1}
    assert result["coverage"]["by_family"]["sql-injection"] == 2


def _seed_finding(db: Database, *, status: str, family: str, language: str) -> None:
    finding = {
        "type": family,
        "display_family": family,
        "severity": "HIGH",
        "file": "app/x.py",
        "line": 1,
        "status": status,
        "language": language,
        "description": "demo",
    }
    repo = FindingRepository(db)
    existing = repo.list(workspace_id=WORKSPACE_ID, task_id=1)
    payloads = [
        {
            "type": f.finding_type, "display_family": (f.raw or {}).get("display_family"),
            "severity": f.severity, "file": f.file_path, "line": f.line,
            "status": (f.raw or {}).get("status"), "language": (f.raw or {}).get("language"),
            "description": (f.raw or {}).get("description"),
        }
        for f in existing
    ]
    payloads.append(finding)
    repo.replace_for_task(task_id=1, workspace_id=WORKSPACE_ID, findings=payloads)


def test_service_ops_dashboard_from_persisted_records(db: Database):
    _seed_finding(db, status="false_positive", family="sql-injection", language="python")
    _seed_finding(db, status="confirmed", family="xss", language="java")

    autonomy = AutonomyRepository(db)
    a1 = autonomy.add_action(workspace_id=WORKSPACE_ID, action="auto_close", applied=True)
    autonomy.add_action(workspace_id=WORKSPACE_ID, action="auto_close", applied=True)
    autonomy.mark_rolled_back(a1["id"])

    dashboard = MetricsService(db).ops_dashboard(workspace_id=WORKSPACE_ID)
    assert dashboard["total_findings"] == 2
    assert dashboard["human_false_positive"] == 1
    assert dashboard["autonomy_closed"] == 2
    assert dashboard["autonomy_rolled_back"] == 1
    assert dashboard["auto_closed"] == 1
    assert 0.0 <= dashboard["denoise_rate"] <= 1.0
    assert dashboard["false_kill_rate"] == pytest.approx(0.5)
    assert set(dashboard["coverage"]["by_language"]) == {"python", "java"}


def test_export_ticket_returns_offline_payload(db: Database):
    _seed_finding(db, status="confirmed", family="sql-injection", language="python")
    finding = FindingRepository(db).list(workspace_id=WORKSPACE_ID, task_id=1)[0]
    ticket = MetricsService(db).export_ticket(finding.id, platform="offline", project="APPSEC")
    assert ticket["platform"] == "offline"
    assert ticket["delivered"] is False
    assert ticket["project"] == "APPSEC"
    assert "sql-injection" in ticket["labels"]
    assert ticket["body"]


def test_export_ticket_missing_finding_raises(db: Database):
    with pytest.raises(ValueError):
        MetricsService(db).export_ticket(9999)
