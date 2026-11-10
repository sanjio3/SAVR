"""A0 环境识别（重构文档 §3.14）单测 + facade 门禁集成测试。

不碰真实网络：http_probe / db 均注入；facade 测试用 patch("requests.request") 控探活。
"""
import os
import tempfile
import time
from datetime import datetime, timedelta
from unittest.mock import patch

from src.iast.env_readiness import (
    EnvCheckConfig,
    EnvironmentReadiness,
    check_environment_readiness,
)
from src.iast.service import IastService
from src.infrastructure.db import Database


_DB_COUNTER = [0]


def _db():
    # 注意：Database.execute 每次调用开新连接，:memory: 无法跨连接持久化；
    # 故用临时文件库（与现有 iast 测试一致），schema 随 _init_schema 自动建表。
    _DB_COUNTER[0] += 1
    path = os.path.join(tempfile.gettempdir(), f"savr_a0_{os.getpid()}_{_DB_COUNTER[0]}.db")
    return Database(path)


def _register_session(db, target_url="http://app.local", app_name="demo", agent_id="a1",
                      heartbeat=""):
    svc = IastService(db)
    svc.register_session({
        "target_url": target_url, "code_path": "/repo", "app_name": app_name,
        "agent_id": agent_id, "settings": {},
    })
    if heartbeat:
        db.execute(
            "UPDATE iast_sessions SET last_heartbeat_at = ? WHERE app_name = ? AND agent_id = ?",
            (heartbeat, app_name, agent_id),
        )


# ---------------- 纯函数 check_environment_readiness ----------------
def test_target_down_blocks():
    db = _db()

    def probe_down(url, ms):
        raise RuntimeError("connection refused")

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_down)
    assert r.target_reachable is False
    assert r.is_ready() is False
    assert "目标不可达" in r.block_reason()


def test_target_5xx_blocks():
    db = _db()

    def probe_503(url, ms):
        return 503

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_503)
    assert r.target_reachable is False
    assert "不可达" in r.block_reason()


def test_4xx_reachable():
    db = _db()

    def probe_401(url, ms):
        return 401

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_401)
    assert r.target_reachable is True


def test_env_probe_db_independent_endpoint_ignores_db_5xx():
    """Fix #3（2026-09-08）：根路径 5xx（DB 崩）但静态资源 404（进程存活）应判可达，避免自毒化。"""
    db = _db()

    def probe(url, ms):
        # 仿真 target-mall：根路径打到 H2 内存库崩 500，静态资源返回 404（进程仍在线）
        if url.rstrip("/").endswith("/favicon.ico"):
            return 404
        return 500

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe)
    assert r.target_reachable is True, r.detail
    assert "/favicon.ico" in (r.detail.get("target_note") or "")


def test_env_probe_all_candidates_5xx_blocks():
    """全部候选端点（含静态资源）持续 5xx → 仍判不可达（靶场真不健康）。"""
    db = _db()

    def probe(url, ms):
        return 503

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe)
    assert r.target_reachable is False
    assert "不可达" in r.block_reason()


def test_env_probe_connection_refused_blocks():
    """全部候选端点连接失败（进程离线）→ 判不可达。"""
    db = _db()

    def probe(url, ms):
        raise RuntimeError("connection refused")

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe)
    assert r.target_reachable is False
    assert "不可达" in r.block_reason()


def test_no_session_inconsistent():
    db = _db()

    def probe_200(url, ms):
        return 200

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_200)
    assert r.consistent is False
    assert r.probe_online is False
    assert r.is_ready() is False
    assert "未找到匹配" in (r.detail.get("consistent_note") or "")


def test_fresh_heartbeat_ready():
    db = _db()
    _register_session(db, heartbeat=datetime.utcnow().isoformat())

    def probe_200(url, ms):
        return 200

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_200)
    assert r.target_reachable is True
    assert r.probe_online is True
    assert r.consistent is True
    assert r.is_ready() is True
    assert r.block_reason() == ""


def test_stale_heartbeat_but_recent_event_ready():
    db = _db()
    old = (datetime.utcnow() - timedelta(seconds=120)).isoformat()
    _register_session(db, heartbeat=old)
    # 写入一条近期 iast_events（近期事件回探路径）
    now_iso = datetime.utcnow().isoformat()
    db.execute(
        """INSERT INTO iast_events
           (session_id, workspace_id, app_name, agent_id, event_type, vuln_type, canary, canary_state,
            sink_file, sink_line, ingested_at, ingest_bucket)
           VALUES (?, ?, ?, ?, 'sink_call', '', '', '', '', 0, ?, 0)""",
        (1, 1, "demo", "a1", now_iso),
    )

    def probe_200(url, ms):
        return 200

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_200)
    assert r.probe_online is True
    assert r.detail.get("probe_liveness") == "recent_event"
    assert r.is_ready() is True


def test_stale_heartbeat_no_event_offline():
    db = _db()
    old = (datetime.utcnow() - timedelta(seconds=120)).isoformat()
    _register_session(db, heartbeat=old)

    def probe_200(url, ms):
        return 200

    r = check_environment_readiness(db, "http://app.local", "demo", "a1", http_probe=probe_200)
    assert r.probe_online is False
    assert r.detail.get("probe_liveness") == "no_recent_signal"
    assert r.is_ready() is False
    assert "探针离线" in r.block_reason()


# ---------------- IastService 方法 + 状态回写 ----------------
def test_iast_service_method_writes_status():
    db = _db()
    _register_session(db, heartbeat=datetime.utcnow().isoformat())
    svc = IastService(db)

    def probe_200(url, ms):
        return 200

    ready = svc.check_environment_readiness("http://app.local", "demo", "a1", http_probe=probe_200)
    assert ready["ready"] is True
    row = db.execute("SELECT status FROM iast_sessions WHERE app_name='demo' AND agent_id='a1'", fetchone=True)
    assert row["status"] == "ready"

    # 未就绪 → status=unready
    def probe_down(url, ms):
        raise RuntimeError("boom")

    unready = svc.check_environment_readiness("http://app.local", "demo", "a1", http_probe=probe_down)
    assert unready["ready"] is False
    row2 = db.execute("SELECT status FROM iast_sessions WHERE app_name='demo' AND agent_id='a1'", fetchone=True)
    assert row2["status"] == "unready"


# ---------------- facade 预处理门禁 ----------------
class _FakeDast:
    def __init__(self):
        self.called = False

    def replay(self, spec, target, session=None, accounts=None):
        self.called = True
        from src.iast.orchestrator import DastImpact
        return DastImpact(reached=True, status_code=200, body="ok")


def test_facade_a0_blocks_when_env_not_ready():
    """A0 未就绪 → facade 阻断、不调用 dast_operator.replay、明确报错（非静默）。"""
    db = _db()
    # 会话存在但心跳陈旧 + 无近期事件 → 探针离线 → 未就绪
    _register_session(db, heartbeat=(datetime.utcnow() - timedelta(seconds=120)).isoformat())
    iast = IastService(db)
    dast = _FakeDast()

    from src.agents.d2_facade import D2Agent
    facade = D2Agent()
    external_target = {"service_url": "http://app.local", "app_name": "demo", "agent_id": "a1"}
    trigger_spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
                    "param_location": "query", "taint_marker": "s4st41abc",
                    "vulnerability_hash_v2": "h1"}

    # 探活走 requests.request（打 target_url 的 HEAD/GET）；replay 由 _FakeDast 接管，assert 不被调用
    with patch("requests.request", return_value=type("R", (), {"status_code": 200, "text": ""})()):
        vr = facade.verify(
            {"id": "v1", "type": "SQLI"}, {}, external_target=external_target, trigger_spec=trigger_spec,
            iast_service=iast, dast_operator=dast,
        )

    assert dast.called is False, "A0 未就绪时 D1 不应发流量"
    assert vr.exploitable is False
    assert "环境未就绪" in vr.reason
    assert vr.dast_impact_evidence.get("blocked") is True
    # Fix #4（2026-09-08）：环境门禁未过（探针未就绪 / 连续 5xx / 不可达）= 靶场不健康，
    # 标 target_unhealthy 可重试，而非 final_state="" 或 no_evidence（永久非漏洞）。
    assert vr.final_state == "target_unhealthy"
    assert vr.dast_impact_evidence.get("target_unhealthy") is True


def test_facade_a0_passes_when_ready():
    """A0 就绪 → facade 放行，dast_operator.replay 被调用，不报环境阻断。"""
    db = _db()
    _register_session(db, heartbeat=datetime.utcnow().isoformat())
    iast = IastService(db)
    dast = _FakeDast()

    from src.agents.d2_facade import D2Agent
    facade = D2Agent()
    external_target = {"service_url": "http://app.local", "app_name": "demo", "agent_id": "a1"}
    trigger_spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
                    "param_location": "query", "taint_marker": "s4st41abc",
                    "vulnerability_hash_v2": "h1"}

    with patch("requests.request", return_value=type("R", (), {"status_code": 200, "text": ""})()):
        vr = facade.verify(
            {"id": "v1", "type": "SQLI"}, {}, external_target=external_target, trigger_spec=trigger_spec,
            iast_service=iast, dast_operator=dast,
        )

    assert dast.called is True, "A0 就绪时 D1 应发流量"
    assert "环境未就绪" not in vr.reason
