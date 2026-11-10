"""agent_bridge._translate_probe_event 回归测试（层1A + 层2A 根因修复锁死）。

背景（2026-08-30 决议 / 2026-08-31 实证）：
真正的根因不在探针（探针 EventBuffer 已正确回带 canary + canaryState），也不在 backend
的 _store_event（它已信任 canaryState），而是在 agent_bridge 的翻译层：
- 修复前：_translate_probe_event 只从 payload/context/traceId 扫描 canary 身份段，
  漏掉 header 通道 A（X-SASTAI-Trace）仅落在探针 canary 字段的身份 → header 路径 0 行；
  且完全丢弃探针断言的 canaryState → backend 退回 CanaryMatcher 子串匹配 → 永远 arrived。
- 修复后：优先采用探针 canary 字段（层1A，修复 header 0 行）；透传 canaryState，
  对 sink 型事件在无探针断言时兜底 sink-reached（层2A）。

本文件锁死上述行为，使未来任何「只扫 payload」「静默丢 canaryState」的回退都被测试拦下。
"""

import os
import tempfile

# 必须在 import src.api.* 之前设定，避免导入期 AppContainer() 连接默认 data/app.db。
_TMP = tempfile.mkdtemp(prefix="sastai_bridge_")
os.environ["SAST_AI_DB_PATH"] = os.path.join(_TMP, "app.db")

from src.api.routers.agent_bridge import _translate_probe_event  # noqa: E402
from src.iast.canary import CanaryFactory, CanaryMatcher  # noqa: E402


def _ident(canary: str) -> str:
    return CanaryMatcher.find_identity(canary)


# ---------------- 层1A：header 通道 canary 提取 ----------------

def test_header_channel_canary_only_in_canary_field_is_extracted():
    """层1A 回归：canary 仅落在探针 canary 字段（header 通道 A），payload/context/traceId 均无 → 仍能提取身份。
    修复前只扫 payload/context/traceId → 提取失败 → header 路径 0 行。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {
        "eventType": "SINK_HIT", "severity": "HIGH", "traceId": "t-1",
        "sink": "com.demo.Ctrl.query", "payload": "SELECT * FROM users", "context": {},
        "canary": canary,  # 仅此一处
    }
    out = _translate_probe_event(ev)
    assert out["canary"] == _ident(canary)
    assert out["canary_source"] == "platform"
    # SINK_HIT + 有身份、探针未断言 → 兜底 sink-reached
    assert out["canaryState"] == "sink-reached"


def test_param_channel_canary_in_payload_still_extracted():
    """层1A：canary 落在 payload（参数通道 B）时仍提取成功（回归确保两条通道不互斥）。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {
        "eventType": "TAINT_FLOW", "sink": "c.s.C.q",
        "payload": f"id=1 OR 1=1 {canary}", "context": {},
    }
    out = _translate_probe_event(ev)
    assert out["canary"] == _ident(canary)
    assert out["canary_source"] == "platform"


# ---------------- 层2A：canaryState 透传 / 兜底 ----------------

def test_canary_state_sink_reached_forwarded():
    """设计一① 回归：探针显式断言 canaryState=sink-reached（在 sink 现场确证 canary 抵达危险函数实参）
    → 归一到独立态 sink-reached-probe，使 D2 即便 attack_degraded 也判有害（不降级）。
    原行为是把探针断言原样透传为 sink-reached；现在改为独立态以区别于 Python 被动兜底 sink-reached。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {
        "eventType": "SINK_HIT", "sink": "c.s.C.q", "payload": f"x={canary}",
        "canary": canary, "canaryState": "sink-reached",
    }
    out = _translate_probe_event(ev)
    assert out["canaryState"] == "sink-reached-probe"


def test_probe_asserted_positive_states_normalize_to_sink_reached_probe():
    """设计一① 回归：探针显式断言的任意正抵达态（sink-reached / arrived / arrival-sanitized）
    一律归一到 sink-reached-probe——这是探针在 sink 现场主动断言，区别于 Python 被动兜底。"""
    canary = CanaryFactory.build("sql-injection")
    for asserted in ("sink-reached", "arrived", "arrival-sanitized"):
        ev = {
            "eventType": "SINK_HIT", "sink": "c.s.C.q", "payload": f"x={canary}",
            "canary": canary, "canaryState": asserted,
        }
        out = _translate_probe_event(ev)
        assert out["canaryState"] == "sink-reached-probe", asserted


def test_canary_state_arrived_forwarded():
    """层2A 回归：探针显式断言 canaryState=arrived（正抵达态）→ 归一到 sink-reached-probe。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {
        "eventType": "SINK_HIT", "payload": f"x={canary}",
        "canary": canary, "canaryState": "arrived",
    }
    out = _translate_probe_event(ev)
    assert out["canaryState"] == "sink-reached-probe"


def test_canary_state_no_arrival_forwarded():
    """设计一① 回归：探针显式判否 canaryState=no-arrival → 尊重探针判否，保留为 no-arrival（不误判 sink-reached-probe）。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {
        "eventType": "SINK_HIT", "payload": f"x={canary}",
        "canary": canary, "canaryState": "no-arrival",
    }
    out = _translate_probe_event(ev)
    assert out["canaryState"] == "no-arrival"


def test_sink_event_with_identity_no_state_falls_back_sink_reached():
    """层2A 回归：sink 型事件命中 canary 但探针未断言 canaryState → 兜底 sink-reached。

    2026-10-07 更新（方法A 第三处）：本锁原断言 TAINT_FLOW 判 sink-reached，
    而那正是 r63-verify 到达假阳性的根因 —— TAINT_FLOW 的 canary_match 是
    **trace 级**（请求带过 canary 就算 1）、不校验 sink 实参，实测真 TP(00001) 与
    安全 FP(00063/00064) 签名完全一致（run 239 的 162 个「到达」spec 里 0 个带
    真实 sink 级断言）。TAINT_FLOW 已从「参与到达裁决」里摘掉。

    到达现在只认「探针在 sink **实参**里断言的抵达态」：
      - 事件是 SINK_HIT          → 仍兜底 sink-reached（真阳性不能被砍，见下条测试）
      - 事件是 TAINT_FLOW        → 不再构成到达（降级为「污点流过」的观测记录）
    回滚开关：SAST_AI_TAINT_FLOW_AS_ARRIVAL=1 恢复旧行为。
    完整回归锁见 tests/test_agent_bridge_arrival_scope.py（6 条）。
    """
    canary = CanaryFactory.build("sql-injection")
    ev = {"eventType": "TAINT_FLOW", "payload": f"sql={canary}"}
    out = _translate_probe_event(ev)
    assert out["canary"] == _ident(canary)
    assert out["canaryState"] != "sink-reached", (
        "TAINT_FLOW 是 trace 级信号，不得单独构成 sink-reached（r63 到达假阳性根因）")
    assert out["canaryState"] != "sink-reached-probe"


def test_sink_hit_with_identity_no_state_still_falls_back_sink_reached():
    """收紧后仍必须保住真阳性：SINK_HIT 无 canaryState 时照旧兜底 sink-reached。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {"eventType": "SINK_HIT", "payload": f"sql={canary}"}
    out = _translate_probe_event(ev)
    assert out["canary"] == _ident(canary)
    assert out["canaryState"] == "sink-reached"


def test_non_sink_event_with_identity_no_state_is_empty():
    """回归：非 sink 型事件（如 TAINT_SOURCE）命中 canary 但未断言 → canaryState 为空（不误判 sink-reached）。"""
    canary = CanaryFactory.build("sql-injection")
    ev = {"eventType": "TAINT_SOURCE", "payload": f"x={canary}", "canary": canary}
    out = _translate_probe_event(ev)
    assert out["canary"] == _ident(canary)
    assert out["canaryState"] == ""


# ---------------- 无 canary：绝不自造合成身份键 ----------------

def test_no_canary_no_synthetic_identity():
    """回归：事件无任何 canary 身份段 → canary 空、source=none、state 空，绝不自造合成身份键。"""
    ev = {"eventType": "SINK_HIT", "payload": "SELECT * FROM users WHERE id=1", "context": {}}
    out = _translate_probe_event(ev)
    assert out["canary"] == ""
    assert out["canary_source"] == "none"
    assert out["canaryState"] == ""


# ---------------- 端到端：经 /api/agent/events 落库验证 ----------------

# ---------------- item 5：sink_method / stack_trace 透传 ----------------

def test_sink_method_and_stack_trace_passthrough():
    """item 5 回归：探针 SINK_HIT 现场上报 sinkMethod + stackTrace（2026-09-15 新增字段），
    翻译层须回填到 translated event 的 sink.method 与 stackTrace，供后端 ingest 写入
    iast_events.sink_method / stack_trace（此前这俩列恒空，归因精度不足）。"""
    ev = {
        "eventType": "SINK_HIT", "severity": "HIGH", "traceId": "t-5",
        "sink": "com.demo.OrderController.importXml",
        "sinkMethod": "com.demo.OrderController.importXml(java.lang.String)",
        "stackTrace": "at com.demo.OrderController.importXml(OrderController.java:42)\nat com.demo.OrderController.doPost(OrderController.java:30)\n",
        "payload": "<xml>", "context": {},
    }
    out = _translate_probe_event(ev)
    assert out["sink"]["method"] == "com.demo.OrderController.importXml(java.lang.String)", \
        "sink.method 应来自顶层 sinkMethod 字段"
    assert "OrderController.importXml" in out["stackTrace"], \
        "stackTrace 应来自顶层 stackTrace 字段"
    # 兜底：顶层缺省时退回 context.stackTrace
    ev2 = {
        "eventType": "SINK_HIT", "sink": "f",
        "context": {"stackTrace": "at com.demo.Deep.call(Deep.java:9)"},
    }
    out2 = _translate_probe_event(ev2)
    assert out2["stackTrace"] == "at com.demo.Deep.call(Deep.java:9)", \
        "顶层缺 stackTrace 时应退回 context.stackTrace"


def _make_client(tmp_path):
    db_path = str(tmp_path / "api.db")
    os.environ["SAST_AI_DB_PATH"] = db_path
    from src.api.dependencies import container
    from src.api.app import app
    from src.infrastructure.db import Database
    from src.iast.service import IastService
    from fastapi.testclient import TestClient
    container.db = Database(db_path)
    container.iast_service = IastService(container.db)
    return TestClient(app), container


def test_agent_bridge_header_channel_stored_as_sink_reached_with_attribution(tmp_path):
    """端到端回归（层1A+2A+3C）：探针经 /api/agent/events 上报 header 通道 canary
    → 翻译层提取身份 + 兜底 sink-reached → 落库 iast_events 的 canary_state='sink-reached'、
    canary_match=1，并按 canary 身份段反查 trigger_specs 归属 task_id（层3C）。

    这正是「96% 事件无 canary / 永远 arrived」根因修复后的期望终态。"""
    client, container = _make_client(tmp_path)

    # 注册探针会话，拿到 X-Agent-Token 用的 probe_token
    r = client.post("/api/iast/sessions", json={
        "target_url": "http://x:19000", "code_path": "/repo/app",
        "app_name": "app1", "agent_id": "p1",
    })
    assert r.status_code == 200, r.text
    token = r.json()["probe_token"]

    # 取该会话的 workspace/session id，并造一个 scan_task 供 task 归属
    sess_row = container.db.execute(
        "SELECT id, workspace_id FROM iast_sessions ORDER BY id DESC LIMIT 1", fetchone=True
    )
    assert sess_row is not None
    sid = int(sess_row["id"])
    workspace_id = int(sess_row["workspace_id"])
    container.db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (workspace_id, "t1", "pending", "queued", "/tmp/o", "2026-01-01"),
    )
    task_id = int(container.db.execute(
        "SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])

    # 登记一条带 canary 的 trigger_spec（A2 假说），使运行期事件能归属 task
    canary = CanaryFactory.build("sql-injection")
    container.iast_service.register_trigger_spec({
        "workspace_id": workspace_id, "session_id": sid, "task_id": task_id,
        "vulnerability_hash_v2": "h-bridge-1", "family": "sql-injection",
        "taint_marker": canary, "target_endpoint": "/api/x",
    })

    # header 通道：canary 仅落在探针 canary 字段，payload/context/traceId 均无
    payload = {
        "agentId": "p1", "appName": "app1",
        "events": [{
            "eventType": "SINK_HIT", "severity": "HIGH", "traceId": "trace-1",
            "sink": "com.demo.Ctrl.query", "payload": "SELECT * FROM users",
            "context": {}, "canary": canary,
            # 不传 canaryState → 应兜底 sink-reached
        }],
    }
    r2 = client.post("/api/agent/events", json=payload, headers={"X-Agent-Token": token})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["accepted"] == 1, body
    assert body["rejected"] == 0, body

    row = container.db.execute(
        "SELECT canary, canary_state, canary_match, task_id, event_type "
        "FROM iast_events WHERE session_id = ? ORDER BY id DESC LIMIT 1",
        (sid,), fetchone=True,
    )
    assert row is not None, "header 通道事件应已落库（修复前为 0 行）"
    assert row["canary"] == _ident(canary), "应提取出 header 通道的身份段"
    assert row["canary_state"] == "sink-reached", "应透传/兜底为 sink-reached（修复前为 arrived/no-arrival）"
    assert row["canary_match"] == 1
    assert row["task_id"] == task_id, "应按 canary 身份段归属 task（层3C）"
    assert row["event_type"] == "SINK_HIT"
