import pytest

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Point the shared container at a throwaway DB before it is (re)built.
    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "api.db"))
    from src.api import dependencies as deps

    fresh = deps.AppContainer()
    saved = dict(deps.container.__dict__)
    deps.container.__dict__.update(fresh.__dict__)

    from src.api.app import app

    try:
        with TestClient(app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        deps.container.__dict__.update(saved)


def test_auth_disabled_allows_reviewer_endpoint(client):
    # Default: SAST_AI_AUTH_ENABLED unset -> admin principal, access granted.
    resp = client.get("/api/audit/log")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_rbac_enforced_when_auth_enabled(client, monkeypatch):
    monkeypatch.setenv("SAST_AI_AUTH_ENABLED", "1")
    monkeypatch.setenv(
        "SAST_AI_API_KEYS",
        '{"viewer-key": "viewer", "reviewer-key": "reviewer"}',
    )

    # No key -> 401.
    assert client.get("/api/audit/log").status_code == 401
    # Viewer key is below the reviewer threshold -> 403.
    assert client.get("/api/audit/log", headers={"X-API-Key": "viewer-key"}).status_code == 403
    # Reviewer key -> 200.
    ok = client.get("/api/audit/log", headers={"X-API-Key": "reviewer-key"})
    assert ok.status_code == 200


def test_mutating_request_is_audited(client):
    from src.api import dependencies as deps

    before = len(deps.container.audit_log_repository.list(limit=1000))
    resp = client.post(
        "/api/autonomy/policies",
        json={"name": "audited-policy", "gray_percent": 50},
    )
    assert resp.status_code == 200
    entries = deps.container.audit_log_repository.list(limit=1000)
    assert len(entries) == before + 1
    latest = entries[0]
    assert latest["method"] == "POST"
    assert latest["path"] == "/api/autonomy/policies"
    assert latest["status_code"] == 200
