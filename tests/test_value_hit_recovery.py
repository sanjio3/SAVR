# -*- coding: utf-8 -*-
"""值级证据幂等补捞回归锁（2026-10-11，r75 实证后新增）。

背景：r75 用 spec 的 taint_marker 对**落库事件**离线重算，得到 38 条 hit_live 且真值
100% TP；但送进确认闸的 iast_evidence.value_hit 是空的，闸门于是把这批到达态全部判成
arrival_without_semantics（57 条），sqli-1 的 ② 仍是 0。补捞把这条事实重新接回闸门。

锁定契约：
  1. 聚合层没有 value_hit、但落库事件比得出命中 ⇒ 补捞产出 hit_live，并打 recovered 标记；
  2. 已有 value_hit ⇒ **不覆盖**（幂等，绝不篡改聚合层既有的事实）；
  3. 比不出命中 ⇒ 返回空（miss = 证据缺失，绝不臆断有害）；
  4. 无匹配事件 / db 为 None / 无 marker ⇒ 返回空，不抛异常；
  5. 端到端：补捞出的 hit_live 能让到达态走 runtime_arrival 准入（不再被判无语义）。
"""
import json

import src.agents.d2_facade  # noqa: F401  通道注册前置（memory 铁律）
import pytest

from src.agents.d2_facade import _recover_value_hit
from src.cli.benchmark_cli import _confirm_gate_decide
from src.iast.canary import CanaryMatcher

MARKER = "s4st41deadbeef00112345PAYLOAD775a7bce"
IDENT = CanaryMatcher.find_identity(MARKER)


class FakeDB:
    """只实现补捞用到的 execute(sql, params, fetchall=True) 契约。"""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, sql, params=None, fetchall=False):
        self.calls.append((sql, params))
        return list(self.rows) if fetchall else None


def _event(sv, evidence=None):
    return {"source_value": sv, "evidence_json": evidence,
            "sink_file": "org.hsqldb.jdbc.JDBCConnection.prepareStatement",
            "sink_method": "prepareStatement", "sink_line": 38}


def test_recovers_hit_live_from_events():
    db = FakeDB([_event(f"SELECT * FROM users WHERE id='{MARKER}'")])
    ie = {"matched_event_ids": [1], "value_hit": {}}
    vh = _recover_value_hit(db, ie, [{"taint_marker": MARKER}])
    assert vh.get("hit") is True
    assert vh.get("form") == "hit_live"
    assert vh.get("recovered") is True


def test_recovers_using_identity_when_marker_split():
    """值里只出现身份段（完整 marker 被截断）时，也必须能靠身份段比对上。"""
    db = FakeDB([_event(f"... WHERE id='{IDENT}'")])
    ie = {"matched_event_ids": [7], "value_hit": {}}
    vh = _recover_value_hit(db, ie, [{"taint_marker": MARKER}])
    assert vh.get("hit") is True and vh.get("form") == "hit_live"


def test_does_not_override_existing_value_hit():
    """已有聚合结果 ⇒ 不覆盖（幂等）。"""
    db = FakeDB([_event(f"...'{MARKER}'")])
    existing = {"hit": True, "form": "hit_sanitized", "where": "source_value"}
    # 调用方（_adjudicate_result）只在为空时调用；这里直接验证函数本身不改输入
    ie = {"matched_event_ids": [1], "value_hit": dict(existing)}
    ie["value_hit"] = dict(existing)
    _recover_value_hit(db, ie, [{"taint_marker": MARKER}])
    assert ie["value_hit"] == existing


def test_returns_empty_when_no_match():
    db = FakeDB([_event("SELECT * FROM users WHERE id=42")])
    ie = {"matched_event_ids": [1], "value_hit": {}}
    assert _recover_value_hit(db, ie, [{"taint_marker": MARKER}]) == {}


def test_returns_empty_without_events_or_db():
    assert _recover_value_hit(None, {"matched_event_ids": [1]}, [{"taint_marker": MARKER}]) == {}
    assert _recover_value_hit(FakeDB([]), {"matched_event_ids": []},
                              [{"taint_marker": MARKER}]) == {}
    assert _recover_value_hit(FakeDB([_event("x")]), {"matched_event_ids": [1]}, []) == {}


def test_db_error_is_swallowed():
    class Boom:
        def execute(self, *a, **k):
            raise RuntimeError("db down")

    assert _recover_value_hit(Boom(), {"matched_event_ids": [1]},
                              [{"taint_marker": MARKER}]) == {}


def test_gate_admits_arrival_with_recovered_hit_live():
    """端到端：补捞出的 hit_live 必须让到达态准入，而不是被判 arrival_without_semantics。"""
    ok, code, _why = _confirm_gate_decide(
        "sink-reached-probe",
        {"matched_event_ids": [1],
         "value_hit": {"hit": True, "form": "hit_live", "recovered": True}},
        {"differential": {"attempted": True, "harmful": False},
         "value_level_hit": True, "value_hit_form": "hit_live"},
        {},
    )
    assert ok is True
    assert code == "runtime_arrival"


def test_gate_still_rejects_when_recovery_finds_nothing():
    """补捞也算不出 ⇒ 保持 B6 收紧，到达单独不构成确认。"""
    ok, code, _why = _confirm_gate_decide(
        "sink-reached-probe",
        {"matched_event_ids": [1], "value_hit": {}},
        {"differential": {"attempted": True, "harmful": False}},
        {},
    )
    assert ok is False
    assert code == "arrival_without_semantics"
