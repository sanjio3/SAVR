from pathlib import Path

import pytest

from src.application.entry_discovery_service import EntryDiscoveryService
from src.infrastructure.db import Database
from src.infrastructure.repositories import EntryAssetRepository


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(str(tmp_path / "app.db"))


def _make_project(tmp_path: Path) -> str:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "api.py").write_text(
        "\n".join([
            "@app.get('/users/{uid}')",
            "def get_user(uid):",
            "    return uid",
            "@app.post('/users')",
            "def create_user():",
            "    return 'ok'",
        ]),
        encoding="utf-8",
    )
    return str(proj)


def test_discover_and_persist_entries_and_rules(tmp_path: Path, db: Database):
    repo = EntryAssetRepository(db)
    service = EntryDiscoveryService(repo)
    project = _make_project(tmp_path)

    result = service.discover_and_persist(project, workspace_id=1, task_id=None)
    assert result["status"] == "completed"
    assert result["entry_count"] >= 2
    assert result["persisted_entry_count"] >= 2

    assets = repo.list_entries(workspace_id=1)
    assert len(assets) >= 2
    assert all(a["entry_hash"] for a in assets)

    # Idempotent: re-running does not duplicate assets.
    service.discover_and_persist(project, workspace_id=1, task_id=None)
    assert len(repo.list_entries(workspace_id=1)) == len(assets)


def test_rule_candidate_confirmation_workflow(tmp_path: Path, db: Database):
    repo = EntryAssetRepository(db)
    service = EntryDiscoveryService(repo)
    service.discover_and_persist(_make_project(tmp_path), workspace_id=1)

    candidates = repo.list_rule_candidates(workspace_id=1, status="candidate")
    assert candidates
    rule_id = candidates[0]["id"]

    confirmed = repo.set_rule_status(rule_id, "confirmed", confirmed_by="alice")
    assert confirmed["status"] == "confirmed"
    assert confirmed["confirmed_by"] == "alice"
    assert not repo.list_rule_candidates(workspace_id=1, status="candidate") or \
        all(c["id"] != rule_id for c in repo.list_rule_candidates(workspace_id=1, status="candidate"))
