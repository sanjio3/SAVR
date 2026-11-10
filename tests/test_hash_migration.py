"""G8: Hash v1->v2 migration mapping + similarity fallback (第四版 §2.10)."""

from pathlib import Path

import pytest

from src.application.hash_migration_service import HashMigrationService
from src.core.hash_matcher import component_similarity, match_finding
from src.core.vuln_hash import enrich_finding_hash
from src.infrastructure.db import Database
from src.infrastructure.repositories import (
    FindingRepository,
    VulnerabilityInstanceRepository,
)

WORKSPACE_ID = 1


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    for task_id in (1, 2, 3):
        database.execute(
            "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (WORKSPACE_ID, f"task{task_id}", "completed", "done", "/tmp/out", "{}", "{}", "", now),
        )
    return database


def _finding(*, code: str, line: int) -> dict:
    return {
        "type": "sql injection",
        "display_family": "sql-injection",
        "file": "app/api/orders/handler.py",
        "line": line,
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "code_snippet": code,
    }


def test_component_similarity_high_on_code_drift():
    a = enrich_finding_hash(_finding(code="q = 'SELECT * FROM o WHERE id=' + id\ncursor.execute(q)", line=10))
    b = enrich_finding_hash(_finding(code="log('trace')\nq = 'SELECT * FROM o WHERE id=' + id\ncursor.execute(q)", line=42))
    assert a["vulnerability_hash_v2"] != b["vulnerability_hash_v2"]
    sim = component_similarity(a["hash_components"], b["hash_components"])
    assert sim >= 0.75


def test_match_finding_returns_none_below_threshold():
    a = enrich_finding_hash(_finding(code="cursor.execute(q)", line=1))
    unrelated = enrich_finding_hash({
        "type": "xss",
        "display_family": "xss",
        "file": "web/templates/render.py",
        "sink": "render_template_string",
        "code_snippet": "return render_template_string(user_input)",
    })
    assert match_finding(a, [unrelated]) is None


def _seed_old_finding(db: Database) -> dict:
    old = enrich_finding_hash(_finding(code="q = 'SELECT * FROM o WHERE id=' + id\ncursor.execute(q)", line=10))
    FindingRepository(db).replace_for_task(task_id=1, workspace_id=WORKSPACE_ID, findings=[old])
    return old


def test_line_drift_inherits_prior_status_and_conclusion(db: Database):
    old = _seed_old_finding(db)
    instances = VulnerabilityInstanceRepository(db)
    instances.inherit(
        WORKSPACE_ID,
        old["vulnerability_hash_v2"],
        status="confirmed",
        review_conclusion="accepted: exploitable SQLi",
    )

    drifted = enrich_finding_hash(_finding(
        code="# added logging\nlog('trace')\nq = 'SELECT * FROM o WHERE id=' + id\ncursor.execute(q)",
        line=57,
    ))
    assert drifted["vulnerability_hash_v2"] != old["vulnerability_hash_v2"]
    FindingRepository(db).replace_for_task(task_id=2, workspace_id=WORKSPACE_ID, findings=[drifted])

    service = HashMigrationService(db)
    result = service.match_and_inherit(drifted, workspace_id=WORKSPACE_ID)

    assert result is not None
    assert result["old_hash"] == old["vulnerability_hash_v2"]
    assert result["new_hash"] == drifted["vulnerability_hash_v2"]
    assert result["similarity"] >= 0.75
    assert result["inherited_status"] == "confirmed"
    assert "accepted" in result["inherited_review_conclusion"]

    new_inst = instances.get_by_hash(WORKSPACE_ID, drifted["vulnerability_hash_v2"])
    assert new_inst["status"] == "confirmed"
    assert new_inst["review_conclusion"] == "accepted: exploitable SQLi"


def test_exact_hash_needs_no_migration(db: Database):
    old = _seed_old_finding(db)
    service = HashMigrationService(db)
    result = service.match_and_inherit(old, workspace_id=WORKSPACE_ID)
    assert result is None


def test_migration_row_recorded(db: Database):
    old = _seed_old_finding(db)
    VulnerabilityInstanceRepository(db).inherit(
        WORKSPACE_ID, old["vulnerability_hash_v2"], status="confirmed", review_conclusion="ok"
    )
    drifted = enrich_finding_hash(_finding(
        code="log()\nq = 'SELECT * FROM o WHERE id=' + id\ncursor.execute(q)",
        line=99,
    ))
    FindingRepository(db).replace_for_task(task_id=3, workspace_id=WORKSPACE_ID, findings=[drifted])

    service = HashMigrationService(db)
    service.match_and_inherit(drifted, workspace_id=WORKSPACE_ID)

    migration = service.migrations.get_by_new_hash(drifted["vulnerability_hash_v2"], WORKSPACE_ID)
    assert migration is not None
    assert migration["old_hash"] == old["vulnerability_hash_v2"]
    assert migration["reason"].startswith("drift:") or migration["reason"] == "exact"
