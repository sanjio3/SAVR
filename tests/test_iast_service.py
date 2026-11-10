from pathlib import Path

from src.iast.canary import CanaryFactory
from src.iast.service import IastService
from src.infrastructure.db import Database


def _svc(tmp_path: Path) -> IastService:
    return IastService(Database(str(tmp_path / "iast.db")))


def test_register_creates_workspace_by_code_path(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    assert sess["workspace_id"]
    assert sess["probe_token"]
    # 再次注册同 code_path 不新建 workspace
    sess2 = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    assert sess2["workspace_id"] == sess["workspace_id"]
    assert sess2["probe_token"] == sess["probe_token"]  # 保留 token


def test_register_multi_app_same_code_path_upserts_session(tmp_path):
    svc = _svc(tmp_path)
    s1 = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall-order", "agent_id": "p1"})
    s2 = svc.register_session({"target_url": "http://x:11001", "code_path": "/repo/mall", "app_name": "mall-pay", "agent_id": "p1"})
    assert s1["workspace_id"] == s2["workspace_id"]
    assert s1["id"] != s2["id"]


def test_ingest_auth_and_canary_match(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    canary = CanaryFactory.build("sql-injection")
    spec = svc.register_trigger_spec({
        "workspace_id": sess["workspace_id"], "session_id": sess["id"], "family": "sql-injection",
        "taint_marker": canary, "target_endpoint": "/api/x", "vulnerability_hash_v2": "h123",
    })
    assert spec["id"]
    events = [{"eventType": "sink_call", "vulnType": "sqli", "canary": canary,
               "sink": {"file": "Ctrl.java", "line": 42}, "evidence": {"payload": f"x='{canary}'"}}]
    res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
    assert res["accepted"] == 1
    assert res["rejected"] == 0
    row = svc.db.execute("SELECT canary_match, canary_state FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True)
    assert row["canary_match"] == 1
    assert row["canary_state"] == "sink-reached"


def test_ingest_wrong_token_rejected(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    res = svc.ingest_events(app_name="mall", agent_id="p1", token="wrong", events=[{"eventType": "sink_call"}])
    assert res["accepted"] == 0
    assert res["rejected"] == 1


def test_heartbeat_updates_last_heartbeat(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    assert sess["last_heartbeat_at"] == ""
    updated = svc.update_heartbeat(sess["id"], sess["probe_token"])
    assert updated["last_heartbeat_at"] != ""
    fetched = svc.get_session(sess["id"])
    assert fetched["last_heartbeat_at"] == updated["last_heartbeat_at"]


def test_heartbeat_wrong_token_rejected(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    try:
        svc.update_heartbeat(sess["id"], "wrong-token")
        assert False, "应因 token 不匹配抛错"
    except ValueError:
        pass


def test_heartbeat_unknown_session(tmp_path):
    svc = _svc(tmp_path)
    try:
        svc.update_heartbeat(99999, "")
        assert False, "应因 session 不存在抛错"
    except ValueError:
        pass


def test_canary_hit_upgrades_vulnerability_instance_to_confirmed(tmp_path):
    """§3.2/§3.3：canary 命中事件 → vulnerability_instances 合一 + status=confirmed_runtime。"""
    from src.iast.canary import CanaryFactory
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    canary = CanaryFactory.build("command-execution")
    svc.register_trigger_spec({
        "workspace_id": sess["workspace_id"], "session_id": sess["id"], "family": "command-execution",
        "taint_marker": canary, "target_endpoint": "/api/cmd", "vulnerability_hash_v2": "h-unique-1",
    })
    events = [{"eventType": "sink_call", "vulnType": "rce", "canary": canary,
               "sink": {"file": "Ctrl.java", "line": 42, "method": "exec"},
               "evidence": {"payload": canary}}]
    svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
    row = svc.db.execute(
        "SELECT status, family, source, title FROM vulnerability_instances WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
        (sess["workspace_id"], "h-unique-1"), fetchone=True,
    )
    assert row is not None
    assert row["status"] == "confirmed_runtime"
    assert row["family"] == "command_execution"
    assert row["source"] == "iast"


def test_canary_observed_event_marks_arrived_state(tmp_path):
    """§7.1 探针侧「本请求已观测到 canary」轻量事件：canary_state=arrived，消解 no-arrival 歧义。"""
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    canary = CanaryFactory.build("command-execution")
    events = [{
        "eventType": "canary_observed",
        "vulnType": "rce",
        "traceId": "trace-abc-123",
        "canary": canary,
        "evidence": {"payload": canary},
    }]
    res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
    assert res["accepted"] == 1
    row = svc.db.execute("SELECT canary_state, canary_match, trace_id, event_type FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True)
    assert row["event_type"] == "canary_observed"
    assert row["canary_state"] == "arrived"
    assert row["canary_match"] == 1
    assert row["trace_id"] == "trace-abc-123"


def test_canary_hit_no_dup_instance_on_repeat(tmp_path):
    """§3.2/§3.3：多次 canary 命中同 hash → 仅合一实例、status 维持 confirmed_runtime。"""
    from src.iast.canary import CanaryFactory
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    canary = CanaryFactory.build("command-execution")
    svc.register_trigger_spec({
        "workspace_id": sess["workspace_id"], "session_id": sess["id"], "family": "command-execution",
        "taint_marker": canary, "target_endpoint": "/api/cmd", "vulnerability_hash_v2": "h-dup-1",
    })
    for _ in range(2):
        svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=[
            {"eventType": "sink_call", "canary": canary, "sink": {"file": "Ctrl.java", "line": 42}, "evidence": {"payload": canary}}
        ])
    count = svc.db.execute(
        "SELECT COUNT(*) AS n FROM vulnerability_instances WHERE vulnerability_hash_v2 = ?",
        ("h-dup-1",), fetchone=True,
    )["n"]
    assert count == 1


def test_canary_observed_event_marks_arrived_state(tmp_path):
    """§7.1 探针侧「本请求已观测到 canary」轻量事件：canary_state=arrived，消解 no-arrival 歧义。"""
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    canary = CanaryFactory.build("command-execution")
    events = [{
        "eventType": "canary_observed",
        "vulnType": "rce",
        "traceId": "trace-abc-123",
        "canary": canary,
        "evidence": {"payload": canary},
    }]
    res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
    assert res["accepted"] == 1
    row = svc.db.execute("SELECT canary_state, canary_match, trace_id, event_type FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True)
    assert row["event_type"] == "canary_observed"
    assert row["canary_state"] == "arrived"
    assert row["canary_match"] == 1
    assert row["trace_id"] == "trace-abc-123"



def test_ingest_dedup(tmp_path):
    svc = _svc(tmp_path)
    sess = svc.register_session({"target_url": "http://x:11000", "code_path": "/repo/mall", "app_name": "mall", "agent_id": "p1"})
    ev = {"eventType": "sink_call", "vulnType": "sqli", "canary": "s4st41abc123def456|OR1=1deadbeef",
          "sink": {"file": "Ctrl.java", "line": 42}, "evidence": {"payload": "x"}}
    r1 = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=[ev])
    r2 = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=[ev])
    assert r1["accepted"] == 1 and r2["accepted"] == 1  # 重复事件静默丢弃但算 accepted
    count = svc.db.execute("SELECT COUNT(*) AS c FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True)["c"]
    assert count == 1
