"""任务4 IAST 校验函数 hook 回归测试：把 BOLA 从「响应差分」升级为「探针授权 hook 语义确认」。

覆盖：
1. IastService.poll_authz_blindspots —— 按 canary 拉取 BOLA_SUSPECT / AUTHZ_BLINDSPOT 事件，
   空 canary 返回 []，app_name / agent_id 过滤生效。
2. D1Service._confirm_authz_hook —— 解析 source_value 中 "authorization: ..." → 越权对象清单，
   去重保序；命中即 confirmed。
3. D1Service._bola_reason —— 双证/单证/无 三种措辞。
4. D2Judge.judge —— biz_confirmed（含 authz_hook_confirmed）直接判 harmful，理由强调鉴权机制缺失。
5. I2Adjudicator.adjudicate_final_state —— biz_confirmed 即便 iast_state=no-arrival 也走
   FINAL_CONFIRMED_ATTRIBUTABLE（业务族不走 canary→sink，确认即攻击证据）。

db 用 tmp_path 文件库（Database 每次开新连接，:memory: 无法跨连接持久化）。
"""
from pathlib import Path
from types import SimpleNamespace

from src.iast.adjudicator import (
    D2Judge,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    I2Adjudicator,
)
from src.iast.orchestrator import STATE_NO_ARRIVAL, STATE_SINK_REACHED
from src.iast.service import IastService
from src.application.d1_service import D1Service
from src.infrastructure.db import Database


CANARY = "s4st41abcdef0123456789"  # 22 字符身份段：s4st41 + 16 hex


def _seed_session(tmp_path: Path):
    db = Database(str(tmp_path / "app.db"))
    svc = IastService(db)
    sess = svc.register_session({
        "target_url": "http://app.local", "code_path": "/repo",
        "app_name": "mall", "agent_id": "p1",
    })
    return db, svc, sess


def _add_bola_event(db, sess, canary=CANARY, source_value="missing object-level authorization: Order:123,User:7 |canary:" + CANARY,
                    app_name="mall", agent_id="p1", event_type="BOLA_SUSPECT"):
    db.execute(
        """INSERT INTO iast_events
           (session_id, workspace_id, task_id, app_name, agent_id, event_type, vuln_type,
            trace_id, canary, canary_match, canary_state, source_value, principal, ingested_at, ingest_bucket)
           VALUES (?, ?, ?, ?, ?, ?, 'bola', ?, ?, 1, 'sink-reached', ?, ?, ?, 0)""",
        (sess["id"], sess["workspace_id"], sess.get("task_id"), app_name, agent_id,
         event_type, "trace-1", canary, source_value, "attacker", "2026-01-01T00:00:00"),
    )


# ------------------------------------------------------------------ 1. poll_authz_blindspots #
def test_poll_authz_blindspots_filters_by_canary(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    _add_bola_event(db, sess, canary=CANARY, source_value="missing object-level authorization: Order:123 |canary:" + CANARY)
    _add_bola_event(db, sess, canary="s4st41other000000000000", source_value="missing object-level authorization: Other:9 |canary:s4st41other000000000000")

    rows = svc.poll_authz_blindspots(CANARY)
    assert len(rows) == 1
    assert "Order:123" in rows[0]["source_value"]


def test_poll_authz_blindspots_empty_canary_returns_empty(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    _add_bola_event(db, sess)
    assert svc.poll_authz_blindspots("") == []
    assert svc.poll_authz_blindspots(None) == []


def test_poll_authz_blindspots_app_agent_filter(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    _add_bola_event(db, sess, app_name="mall", agent_id="p1")
    _add_bola_event(db, sess, app_name="other", agent_id="p2", canary=CANARY,
                    source_value="missing object-level authorization: X:1 |canary:" + CANARY)

    # app_name 过滤：mall 事件 source_value 含 Order:123，other 事件含 X:1；过滤后应只返回 mall 那条。
    # 注：SELECT 不回带 app_name 列，故用 source_value 内容验证过滤生效。
    rows = svc.poll_authz_blindspots(CANARY, app_name="mall")
    assert len(rows) == 1
    assert "Order:123" in rows[0]["source_value"]
    assert "X:1" not in rows[0]["source_value"]


def test_poll_authz_blindspots_event_type_set(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    # 仅命中 BOLA_SUSPECT / AUTHZ_BLINDSPOT 两类，普通 sink_call 不应被捞回
    _add_bola_event(db, sess, event_type="BOLA_SUSPECT")
    db.execute(
        """INSERT INTO iast_events
           (session_id, workspace_id, task_id, app_name, agent_id, event_type, vuln_type,
            trace_id, canary, canary_match, canary_state, source_value, principal, ingested_at, ingest_bucket)
           VALUES (?, ?, ?, ?, ?, 'sink_call', 'ci', ?, ?, 1, 'sink-reached', ?, ?, ?, 0)""",
        (sess["id"], sess["workspace_id"], sess.get("task_id"), "mall", "p1",
         "trace-2", CANARY, "normal sink", "attacker", "2026-01-01T00:00:00"),
    )
    rows = svc.poll_authz_blindspots(CANARY)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "BOLA_SUSPECT"


# ------------------------------------------------------------------ 2. _confirm_authz_hook #
def test_confirm_authz_hook_parses_objects_and_confirms(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    _add_bola_event(db, sess, source_value="missing object-level authorization: Order:123,User:7 |canary:" + CANARY)

    d1 = D1Service(db=db)
    res = d1._confirm_authz_hook(CANARY, {"app_name": "mall", "agent_id": "p1"}, attempts=1)
    assert res["authz_hook_confirmed"] is True
    assert res["authz_hook_events"] == 1
    assert res["authz_hook_objects"] == ["Order:123", "User:7"]


def test_confirm_authz_hook_dedup_preserves_order(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    # 两条事件各含重复对象，验证去重保序
    _add_bola_event(db, sess, source_value="missing object-level authorization: Order:123,User:7 |canary:" + CANARY)
    _add_bola_event(db, sess, source_value="missing object-level authorization: User:7,Order:123 |canary:" + CANARY)

    d1 = D1Service(db=db)
    res = d1._confirm_authz_hook(CANARY, {"app_name": "mall", "agent_id": "p1"}, attempts=1)
    assert res["authz_hook_objects"] == ["Order:123", "User:7"]


def test_confirm_authz_hook_no_events(tmp_path):
    db, svc, sess = _seed_session(tmp_path)
    d1 = D1Service(db=db)
    res = d1._confirm_authz_hook(CANARY, {"app_name": "mall", "agent_id": "p1"}, attempts=1)
    assert res["authz_hook_confirmed"] is False
    assert res["authz_hook_objects"] == []


# ------------------------------------------------------------------ 3. _bola_reason #
def test_bola_reason_both():
    r = D1Service._bola_reason(True, True, "42", ["Order:123"])
    assert "双重证据" in r or "结果泄露" in r
    assert "Order:123" in r


def test_bola_reason_leak_only():
    r = D1Service._bola_reason(True, False, "42", [])
    assert "响应差分" in r


def test_bola_reason_hook_only():
    r = D1Service._bola_reason(False, True, "42", ["User:7"])
    assert "授权 hook" in r or "归属校验" in r


def test_bola_reason_none():
    r = D1Service._bola_reason(False, False, "42", [])
    assert "未观测" in r


# ------------------------------------------------------------------ 4. D2Judge.judge biz_confirmed #
def test_d2_judge_biz_confirmed_harmful_with_authz_hook():
    judge = D2Judge()
    per_hyp = {"H1": SimpleNamespace(state=STATE_NO_ARRIVAL)}
    raw = {"business_logic": {
        "confirmed": True, "authz_hook_confirmed": True, "category": "bola",
        "authz_hook_objects": ["Order:123"],
    }}
    verdicts = judge.judge(per_hyp, raw_dast_impact=raw)
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.harmful is True
    assert "鉴权机制缺失" in v.reason
    assert v.detail.get("authz_hook_confirmed") is True
    assert v.detail.get("authz_hook_objects") == ["Order:123"]


def test_d2_judge_biz_confirmed_leak_only():
    judge = D2Judge()
    per_hyp = {"H1": SimpleNamespace(state=STATE_NO_ARRIVAL)}
    raw = {"business_logic": {"confirmed": True, "authz_hook_confirmed": False, "category": "bola"}}
    v = judge.judge(per_hyp, raw_dast_impact=raw)[0]
    assert v.harmful is True
    assert "响应差分" in v.reason or "受害者资源" in v.reason


# ------------------------------------------------------------------ 5. adjudicate_final_state biz_confirmed #
def test_adjudicate_final_state_biz_confirmed_even_without_sink(tmp_path):
    # 关键：BOLA 不走 canary→sink，iast_state=no-arrival 时 biz_confirmed 仍应判 confirmed_attributable
    verdict = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL},
        dast_impact_evidence={"business_logic": {
            "confirmed": True, "authz_hook_confirmed": True, "category": "bola",
            "authz_hook_objects": ["Order:123"],
        }},
    )
    assert verdict["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert verdict["confirmed"] is True
    assert verdict["confidence"] == "high"
    assert "authz" in verdict["judge_reason"].lower() or "授权" in verdict["judge_reason"]


def test_adjudicate_final_state_biz_confirmed_leak_only_medium(tmp_path):
    verdict = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL},
        dast_impact_evidence={"business_logic": {
            "confirmed": True, "authz_hook_confirmed": False, "confidence": "medium", "category": "bola",
        }},
    )
    assert verdict["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert verdict["confirmed"] is True
    assert verdict["confidence"] == "medium"


def test_adjudicate_final_state_biz_confirmed_not_swallowed_by_degraded(tmp_path):
    # 即使存在降级攻击标记（attack_degraded），只要 biz_confirmed，也不应被降级块拦截
    verdict = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL},
        dast_impact_evidence={"attack_degraded": True, "business_logic": {
            "confirmed": True, "authz_hook_confirmed": True, "category": "bola",
            "authz_hook_objects": ["Order:123"],
        }},
    )
    assert verdict["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert verdict["confirmed"] is True
    assert verdict.get("authz_hook_confirmed") is True
