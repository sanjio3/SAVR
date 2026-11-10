import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.iast.canary import CanaryFactory


@pytest.fixture
def client(tmp_path):
    # 用独立临时 db，避免污染默认库
    db_path = str(tmp_path / "api.db")
    import os
    os.environ["SAST_AI_DB_PATH"] = db_path
    # app/container 在导入时已建；重设 container.db 指向临时库并重建 schema
    from src.api.dependencies import container
    from src.infrastructure.db import Database
    from src.iast.service import IastService
    container.db = Database(db_path)
    container.iast_service = IastService(container.db)
    return TestClient(app)


def test_register_and_ingest_via_api(client):
    r = client.post("/api/iast/sessions", json={
        "target_url": "http://x:19000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1",
    })
    assert r.status_code == 200, r.text
    token = r.json()["probe_token"]
    assert token

    canary = CanaryFactory.build("sql-injection")
    payload = {
        "agentId": "p1", "appName": "mall",
        "events": [{"eventType": "sink_call", "vulnType": "sqli", "canary": canary,
                    "sink": {"file": "Ctrl.java", "line": 42}, "evidence": {"payload": canary}}],
    }
    r2 = client.post("/api/iast/events", json=payload, headers={"X-Iast-Token": token})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0


def test_ingest_without_token_rejected(client):
    client.post("/api/iast/sessions", json={
        "target_url": "http://x:19000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1",
    })
    r = client.post("/api/iast/events", json={"agentId": "p1", "appName": "mall", "events": [{"eventType": "sink_call"}]})
    assert r.status_code == 200
    assert r.json()["rejected"] == 1
