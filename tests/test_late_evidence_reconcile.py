"""I1 迟到证据补捞回归守卫。

背景：D2 裁决与探针事件摄取是并发的，per-spec 有界轮询窗口（15×1.5s≈22s）远小于真实
摄取延迟（task-7 实测跨度约 4.5 分钟：04:40:23→04:44:51，而 D2 阶段 04:40:22→04:44:42，
两者几乎完全重叠）。结果是事件最终落库、canary 也逐字符可匹配（spec815↔事件2640、
spec763↔事件2743），裁决却早已按 no-iast-evidence 定稿，产生
「sink_reached=1 却 iast_state=no-iast-evidence」的矛盾行。

reconcile_late_iast_evidence 的做法：Phase1 全部重放结束后先做一次全局摄取静止等待，
再对仍为 no-iast-evidence 的 spec 按 canary 重查，查到即按既有 BL 确认口径升级。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 单测不真实等待：把静止等待与最大等待窗口压到 0
os.environ["SAST_AI_I1_QUIET_SECONDS"] = "0"
os.environ["SAST_AI_I1_MAX_WAIT"] = "0"

from src.agents.d2_facade import (  # noqa: E402
    _iast_stream_head,
    reconcile_late_iast_evidence,
)

MARKER = "s4st41637baa18c191cbf9PAYLOADc184c174"
CANARY = "s4st41637baa18c191cbf9"


class _FakeDB:
    def __init__(self, head):
        self.head = head

    def execute(self, sql, params=None, fetchall=False):
        if "MAX(id)" in sql:
            return [(self.head,)]
        return []


class _FakeIast:
    def __init__(self, head, events, blinds=None):
        self.db = _FakeDB(head)
        self.events = events
        self.blinds = blinds or {}

    def poll_events_by_canary(self, canary, since_id=0, limit=50,
                              app_name=None, agent_id=None, trace_id=None):
        return self.events.get(canary, [])

    def poll_authz_blindspots(self, canary, app_name=None, agent_id=None):
        return self.blinds.get(canary, [])


class _FakeResult:
    def __init__(self, state):
        self.iast_evidence = {
            "state": state,
            "business_logic": True,
            "iast_reached": False,
        }
        self.verification_decision = {"verification_status": "unconfirmed"}
        self.exploitable = False
        self.business_confirmed = False
        self.final_state = "no_evidence"


def test_stream_head_normal_and_failure():
    assert _iast_stream_head(_FakeIast(100, {}), None, None) == 100
    assert _iast_stream_head(_FakeIast(None, {}), None, None) is None


def test_late_sink_reached_upgraded():
    svc = _FakeIast(100, {CANARY: [{"event_type": "BOLA_SUSPECT", "canary_state": "sink-reached"}]})
    hit = _FakeResult("no-iast-evidence")
    miss = _FakeResult("no-iast-evidence")
    other = _FakeResult("iast-reached")

    n = reconcile_late_iast_evidence(
        [
            (hit, {"id": 815, "taint_marker": MARKER}, "h1"),
            (miss, {"id": 999, "taint_marker": "s4st41deadbeefdeadbeefPAYLOAD0"}, "h2"),
            (other, {"id": 1, "taint_marker": MARKER}, "h3"),
        ],
        svc,
    )

    assert n == 1
    assert hit.iast_evidence["state"] == "iast-reached"
    assert hit.iast_evidence["late_reconciled"] is True
    assert hit.iast_evidence["iast_reached"] is True
    assert hit.iast_evidence["iast_event_count"] == 1
    # v2 B3 确认闸（2026-10-10）：迟到补捞「仅到达」只升 unconfirmed（证据缺失 ≠ 阴性，
    # 但也绝不臆断有害）——须经值级 hit_live / sink 异常签名 / authz 盲点才准予确认。
    assert hit.verification_decision["verification_status"] == "unconfirmed"
    assert hit.exploitable is False and hit.business_confirmed is False
    assert hit.final_state == "unconfirmed"

    # 查不到事件的必须保持原状，不得误升级
    assert miss.iast_evidence["state"] == "no-iast-evidence"
    assert miss.exploitable is False
    # 已确认的不得被回退或改写
    assert other.iast_evidence["state"] == "iast-reached"
    assert other.iast_evidence.get("late_reconciled") is None


def test_authz_blindspot_takes_priority():
    svc = _FakeIast(
        100,
        {CANARY: [{"event_type": "BOLA_SUSPECT", "canary_state": "sink-reached"}]},
        {CANARY: [{"x": 1}]},
    )
    r = _FakeResult("no-iast-evidence")
    assert reconcile_late_iast_evidence([(r, {"id": 5, "taint_marker": MARKER}, "h")], svc) == 1
    assert r.iast_evidence["state"] == "iast-authz-confirmed"
    assert r.iast_evidence["iast_authz_confirmed"] is True


def test_empty_and_no_service_safe():
    svc = _FakeIast(100, {})
    assert reconcile_late_iast_evidence([], svc) == 0
    assert reconcile_late_iast_evidence(
        [(_FakeResult("no-iast-evidence"), {"id": 1}, "h")], None
    ) == 0


# --------------------------------------------------------------------------- #
# 2026-10-29（本轮实证）：非 BL 路径的迟到补捞
#
# 背景：D2 Phase1 与探针事件落库抢同一把 SQLite 单写者锁，事件按 ~4 分钟一批排队落库，
# 裁决时事件还没到 ⇒ trustbound 13 个用例在 iast_events 里都有
# canary_state=sink-reached-probe + StandardSessionFacade.setAttribute 真 sink 事件，
# 却全被判 no-arrival（召回 27/28 → 15/28）。
# --------------------------------------------------------------------------- #

TRUSTBOUND_SINK = "org.apache.catalina.session.StandardSessionFacade.setAttribute"


def _sink_event(sink_file, state="sink-reached-probe"):
    return {
        "event_type": "SINK_HIT",
        "canary_state": state,
        "sink_file": sink_file,
        "source_value": MARKER,          # 值级 hit_live 的依据
    }


def test_non_bl_no_arrival_upgraded_when_genuine_sink_hit():
    """trustbound：no-arrival + 本族真 sink + hit_live ⇒ 升 confirmed_exploitable。"""
    svc = _FakeIast(100, {CANARY: [_sink_event(TRUSTBOUND_SINK)]})
    r = _FakeResult("no-arrival")
    ts = {"id": 1, "taint_marker": MARKER, "family": "trust_boundary_violation"}

    assert reconcile_late_iast_evidence([(r, ts, "h")], svc) == 1
    assert r.iast_evidence["state"] == "sink-reached-probe"
    assert r.iast_evidence["late_reconciled"] is True
    assert r.iast_evidence["matched_sink_file"] == TRUSTBOUND_SINK
    assert r.iast_evidence["value_hit"]["form"] == "hit_live"
    assert r.verification_decision["verification_status"] == "confirmed_exploitable"
    assert r.exploitable is True
    assert r.final_state == "confirmed"


def test_non_bl_cross_family_sink_not_upgraded():
    """族-sink 归属闸：session setAttribute 不能用来确认 sql_injection spec（否则凭空造 FP）。

    本轮 dry-run 实测：只加 is_genuine_sink_identity 会有 31 条 sql_injection spec
    落在 putValue 上被误确认。
    """
    svc = _FakeIast(100, {CANARY: [_sink_event(TRUSTBOUND_SINK)]})
    r = _FakeResult("no-arrival")
    ts = {"id": 2, "taint_marker": MARKER, "family": "sql_injection"}

    assert reconcile_late_iast_evidence([(r, ts, "h")], svc) == 0
    assert r.iast_evidence["state"] == "no-arrival"
    assert r.verification_decision["verification_status"] == "unconfirmed"
    assert r.exploitable is False


def test_non_bl_property_family_never_upgraded():
    """属性族不走运行时补捞：安全用例（SHA-256）同样把 canary 送进 MessageDigest。"""
    svc = _FakeIast(100, {CANARY: [
        _sink_event("java.security.MessageDigest.getInstance")]})
    r = _FakeResult("no-arrival")
    ts = {"id": 3, "taint_marker": MARKER, "family": "weak_hash"}

    assert reconcile_late_iast_evidence([(r, ts, "h")], svc) == 0
    assert r.iast_evidence["state"] == "no-arrival"
    assert r.exploitable is False


def test_non_bl_reach_without_value_live_not_confirmed():
    """只有到达、值级 miss ⇒ 不确认（口径与主路径一致：到达单独不足）。"""
    ev = _sink_event(TRUSTBOUND_SINK)
    ev["source_value"] = ""              # 拿不到 canary 原文
    svc = _FakeIast(100, {CANARY: [ev]})
    r = _FakeResult("no-arrival")
    ts = {"id": 4, "taint_marker": MARKER, "family": "trust_boundary_violation"}

    assert reconcile_late_iast_evidence([(r, ts, "h")], svc) == 1
    assert r.iast_evidence["state"] == "sink-reached-probe"
    assert r.verification_decision["verification_status"] == "sink_reached"
    assert r.exploitable is False
