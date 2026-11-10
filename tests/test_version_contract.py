"""环境契约（重构文档 §4.2）单测：版本钉死 + 事件隔离。

覆盖：
- validate_version_contract 三态（matched / mismatch / unverified）；
- register_session 落 version_status；
- A0 门禁在版本不一致时硬阻断（含 facade 预处理门禁路径）；
- poll_events_by_canary 按 app_name / agent_id / trace_id 隔离；
- facade 的 event_source 闭包把目标 scope 传给 poll（隔离不跨 app 泄漏）。

不碰真实网络：db 用临时文件库；探活用注入 http_probe 或 patch("requests.request")。
"""
import os
import tempfile
from datetime import datetime
from unittest.mock import patch

import pytest

from src.agents.d2_facade import D2Agent
from src.application.d1_service import D1Service
from src.iast.env_readiness import check_environment_readiness
from src.iast.service import IastService
from src.iast.version_contract import (
    VERSION_STATUS_MATCHED,
    VERSION_STATUS_MISMATCH,
    VERSION_STATUS_UNVERIFIED,
    validate_version_contract,
)
from src.infrastructure.db import Database


_DB_COUNTER = [0]


def _db():
    # Database.execute 每次调用开新连接，:memory: 无法跨连接持久化，故用临时文件库。
    _DB_COUNTER[0] += 1
    path = os.path.join(tempfile.gettempdir(), f"savr_vc_{os.getpid()}_{_DB_COUNTER[0]}.db")
    return Database(path)


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def _insert_event(db, app_name, agent_id, canary, state, trace_id=""):
    sess = db.execute(
        "SELECT id, workspace_id FROM iast_sessions WHERE app_name = ? AND agent_id = ?",
        (app_name, agent_id), fetchone=True,
    )
    assert sess is not None, f"会话未注册：{app_name}/{agent_id}"
    db.execute(
        """INSERT INTO iast_events
           (session_id, workspace_id, app_name, agent_id, event_type, trace_id, canary, canary_state,
            sink_file, sink_line, ingested_at, ingest_bucket)
           VALUES (?, ?, ?, ?, 'sink_call', ?, ?, ?, '', 0, ?, 0)""",
        (sess["id"], sess["workspace_id"], app_name, agent_id, trace_id, canary, state,
         datetime.utcnow().isoformat()),
    )


# ---------- 版本契约：三态 ----------

def test_validate_matched():
    c = validate_version_contract("1.0.0", "1.0.0")
    assert c.matched is True
    assert c.status == VERSION_STATUS_MATCHED


def test_validate_mismatch():
    c = validate_version_contract("2.0.0", "1.0.0")
    assert c.matched is False
    assert c.status == VERSION_STATUS_MISMATCH
    assert "不一致" in c.block_reason()


@pytest.mark.parametrize("probe,sast", [("", "1.0.0"), ("1.0.0", ""), ("", "")])
def test_validate_unverified(probe, sast):
    c = validate_version_contract(probe, sast)
    assert c.status == VERSION_STATUS_UNVERIFIED
    assert c.matched is False


def test_validate_uses_env_pinned(monkeypatch):
    monkeypatch.setenv("SAST_CODE_VERSION", "1.0.0")
    c = validate_version_contract("1.0.0")
    assert c.status == VERSION_STATUS_MATCHED


# ---------- register_session 落 version_status ----------

def test_register_session_stores_version_status(monkeypatch):
    monkeypatch.setenv("SAST_CODE_VERSION", "1.0.0")
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "m", "agent_id": "m1", "probe_version": "1.0.0"})
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "x", "agent_id": "x1", "probe_version": "9.9.9"})
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "u", "agent_id": "u1"})  # 未上报 → unverified

    def status(app, agent):
        row = db.execute("SELECT version_status FROM iast_sessions WHERE app_name = ? AND agent_id = ?",
                         (app, agent), fetchone=True)
        return row["version_status"]

    assert status("m", "m1") == VERSION_STATUS_MATCHED
    assert status("x", "x1") == VERSION_STATUS_MISMATCH
    assert status("u", "u1") == VERSION_STATUS_UNVERIFIED


# ---------- A0 门禁：版本不一致硬阻断 ----------

def test_a0_blocks_on_version_mismatch(monkeypatch):
    monkeypatch.setenv("SAST_CODE_VERSION", "1.0.0")
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "demo", "agent_id": "a1", "probe_version": "2.0.0"})
    # 令目标可达 + 心跳新鲜，孤立出「版本不一致」这一个阻断因素
    db.execute("UPDATE iast_sessions SET last_heartbeat_at = ? WHERE app_name = 'demo' AND agent_id = 'a1'",
               (datetime.utcnow().isoformat(),))

    r = check_environment_readiness(db, "http://app.local", "demo", "a1",
                                    http_probe=lambda url, t: 200)
    assert r.version_matched is False
    assert r.is_ready() is False
    assert "版本" in r.block_reason()
    assert "不一致" in r.detail.get("version_note", "")


def test_a0_version_matched_does_not_block(monkeypatch):
    monkeypatch.setenv("SAST_CODE_VERSION", "1.0.0")
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "demo", "agent_id": "a1", "probe_version": "1.0.0"})
    db.execute("UPDATE iast_sessions SET last_heartbeat_at = ? WHERE app_name = 'demo' AND agent_id = 'a1'",
               (datetime.utcnow().isoformat(),))

    r = check_environment_readiness(db, "http://app.local", "demo", "a1",
                                    http_probe=lambda url, t: 200)
    assert r.version_matched is True
    assert r.is_ready() is True


def test_facade_blocks_on_version_mismatch(monkeypatch):
    """facade 预处理 A0 门禁在版本不一致时阻断发流量，不进入触发事务。"""
    monkeypatch.setenv("SAST_CODE_VERSION", "1.0.0")
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://app.local", "code_path": "/repo",
                          "app_name": "demo", "agent_id": "a1", "probe_version": "2.0.0"})
    db.execute("UPDATE iast_sessions SET last_heartbeat_at = ? WHERE app_name = 'demo' AND agent_id = 'a1'",
               (datetime.utcnow().isoformat(),))

    facade = D2Agent()
    with patch("requests.request", return_value=FakeResponse(200)):
        vr = facade.verify(
            {"id": "v1", "type": "SQLI"}, {},
            external_target={"service_url": "http://app.local", "app_name": "demo", "agent_id": "a1", "probe_mode": "monitor"},
            trigger_spec={"target_endpoint": "/api/x", "taint_marker": "c", "param_name": "q", "param_location": "query"},
            iast_service=svc, dast_operator=None,
        )
    assert vr.exploitable is False
    assert vr.dast_impact_evidence.get("blocked") is True
    assert "版本" in vr.reason


# ---------- 事件隔离：poll scoping ----------

def test_poll_events_isolation_by_app():
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://a", "code_path": "/r", "app_name": "app-a", "agent_id": "a1"})
    svc.register_session({"target_url": "http://b", "code_path": "/r", "app_name": "app-b", "agent_id": "b1"})
    _insert_event(db, "app-a", "a1", "C", "no-arrival")
    _insert_event(db, "app-b", "b1", "C", "sink-reached")

    # 限定 app-a：只看到自己的 no-arrival，看不到 app-b 的 sink-reached（防混流）
    rows_a = svc.poll_events_by_canary("C", app_name="app-a", agent_id="a1")
    assert [r["canary_state"] for r in rows_a] == ["no-arrival"]

    rows_b = svc.poll_events_by_canary("C", app_name="app-b", agent_id="b1")
    assert [r["canary_state"] for r in rows_b] == ["sink-reached"]

    # 不限定：退化为纯 canary 匹配（向后兼容）
    rows_all = svc.poll_events_by_canary("C")
    assert len(rows_all) == 2


def test_poll_events_isolation_by_trace_id():
    db = _db()
    svc = IastService(db)
    svc.register_session({"target_url": "http://a", "code_path": "/r", "app_name": "app-a", "agent_id": "a1"})
    _insert_event(db, "app-a", "a1", "C", "no-arrival", trace_id="t1")
    _insert_event(db, "app-a", "a1", "C", "sink-reached", trace_id="t2")

    rows = svc.poll_events_by_canary("C", app_name="app-a", agent_id="a1", trace_id="t2")
    assert [r["canary_state"] for r in rows] == ["sink-reached"]


# ---------- facade event_source 闭包传递 scope ----------

def test_facade_event_source_scopes_by_target():
    captured = {}

    class FakeIast:
        def poll_events_by_canary(self, canary, since_id=0, limit=50,
                                  app_name=None, agent_id=None, trace_id=None):
            captured.update(canary=canary, app_name=app_name, agent_id=agent_id, trace_id=trace_id)
            return [{"id": 1, "canary_state": "sink-reached"}]

    def fake_request(method, url, **kw):
        return FakeResponse(200, "ok")

    facade = D2Agent()
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        facade.verify(
            {"id": "v1", "type": "SQLI"}, {},
            external_target={"service_url": "http://app.local", "app_name": "app-a", "agent_id": "a1", "probe_mode": "monitor"},
            trigger_spec={"target_endpoint": "/api/x", "http_method": "GET", "param_name": "q",
             "param_location": "query", "taint_marker": "s4st41abc", "vulnerability_hash_v2": "h1"},
            iast_service=FakeIast(), dast_operator=D1Service(),
        )

    assert captured.get("app_name") == "app-a"
    assert captured.get("agent_id") == "a1"
