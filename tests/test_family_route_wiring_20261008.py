"""2026-10-08 族路由「接通」回归锁。

锁三件此前「代码写了但从未生效」的事：
1. judge_attribute_family 支持「Cookie 已创建但从未设 flag」——securecookie 真漏洞形态。
   旧判据只认 setSecure/setHttpOnly 事件，而真漏洞恰恰**从不调用**这两个方法，
   于是本族系统性失效（run 246 实测 TP 确认率 1/6）。
2. post-pass 按 capability_family 过滤而非 family。family 是上游 A1/A2 的主张，会被 LLM
   自由命名带偏（run 246 实测：capability_family 命中 156 条 vs family 仅 34 条，
   post-pass 此前漏掉 78% 的目标 spec）。
3. apply_family_route 准入放开到 unconfirmed/sink_reached，但 no_evidence 仍不得晋升。

以及一条负向锁：safe 用例（显式 setSecure(true)/setHttpOnly(true)）绝不能被判成缺失。
"""
from __future__ import annotations

import sqlite3

import pytest

from src.core.family_verdict import (
    CONFIRMED_CODE_PROPERTY,
    apply_family_route,
    judge_attribute_family,
)
from src.cli.benchmark_cli import _apply_family_route_postpass


class _FakeDB:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def execute(self, sql, params=(), fetchall=False):
        cur = self.conn.execute(sql, tuple(params))
        rows = [dict(r) for r in cur.fetchall()]
        self.conn.commit()
        return rows if fetchall else rows


@pytest.fixture()
def db(tmp_path):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, "
        "capability_family TEXT, taint_marker TEXT, session_id INTEGER, "
        "verification_status TEXT, iast_state TEXT, positive_evidence_rule TEXT)")
    conn.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, canary TEXT, "
        "sink_file TEXT, source_value TEXT, evidence_json TEXT, canary_state TEXT)")
    yield _FakeDB(conn)
    conn.close()


# ---------------------------------------------------------------- judge 层

def _ev(sink_file, source_value=""):
    return {"sink_file": sink_file, "source_value": source_value, "evidence_json": "{}"}


def test_cookie_created_without_any_flag_is_code_property():
    """真漏洞形态：new Cookie(...) 后从不设 flag → flag 缺失成立。"""
    evs = [_ev("javax.servlet.http.Cookie.<init>")]
    status, detail = judge_attribute_family(evs)
    assert status == CONFIRMED_CODE_PROPERTY
    assert "从未" in detail or "未调用" in detail


def test_cookie_with_true_flags_is_not_flagged_missing():
    """负向锁：safe 用例显式开启 flag，即使有 <init> 事件也不得判成缺失。"""
    evs = [
        _ev("javax.servlet.http.Cookie.<init>"),
        _ev("javax.servlet.http.Cookie.setSecure", "[true]"),
        _ev("javax.servlet.http.Cookie.setHttpOnly", "[true]"),
    ]
    status, _ = judge_attribute_family(evs)
    assert status == "unconfirmed", "显式开启 flag 的 safe 用例不得被判成 flag 缺失"


def test_cookie_explicit_false_flag_is_code_property():
    """显式关闭 flag 仍然是确证缺失（原有判据不得被新判据挤掉）。"""
    evs = [_ev("javax.servlet.http.Cookie.setSecure", "[false]")]
    status, _ = judge_attribute_family(evs)
    assert status == CONFIRMED_CODE_PROPERTY


def test_no_cookie_event_at_all_stays_unconfirmed():
    """无事件不臆断。"""
    status, _ = judge_attribute_family([_ev("java.io.FileInputStream.<init>")])
    assert status == "unconfirmed"


# ---------------------------------------------------------------- 准入层

_ALGO_EV = [_ev("java.security.MessageDigest.getInstance", "[MD5]")]


def test_unconfirmed_is_admitted_for_judge():
    """M4 之后属性族停在 unconfirmed，必须能进 judge（核心缺口）。"""
    status, detail = apply_family_route("weak_hash", "unconfirmed", _ALGO_EV)
    assert status == CONFIRMED_CODE_PROPERTY and detail["applied"] is True


def test_no_evidence_is_still_not_admitted():
    """no_evidence 明示「本轮什么都没观测到」，不得拿残留事件晋升。"""
    status, detail = apply_family_route("weak_hash", "no_evidence", _ALGO_EV)
    assert status == "no_evidence" and detail["applied"] is False


def test_confirmed_exploitable_is_downgraded_when_no_family_event():
    """借别族 sink 抬上来的 confirmed_exploitable，本族无事件时要能出清。"""
    status, detail = apply_family_route(
        "weak_hash", "confirmed_exploitable", [_ev("java.io.FileInputStream.<init>")])
    assert status == "unconfirmed" and detail["applied"] is True


def test_unconfirmed_is_not_overwritten_by_unconfirmed():
    """judge 判 unconfirmed 且原状态就是 unconfirmed 时不接受，避免覆盖归因线索。"""
    status, detail = apply_family_route("weak_hash", "unconfirmed", [])
    assert status == "unconfirmed" and detail["applied"] is False


# ---------------------------------------------------------------- post-pass 过滤层

_IDENT = "s4st41" + "c" * 16


def _add_spec(db, task_id, spec_id, family, cap_family, marker, status,
              iast_state="sink-reached-probe"):
    db.execute(
        "INSERT INTO trigger_specs (id, task_id, family, capability_family, taint_marker, "
        "session_id, verification_status, iast_state) VALUES (?,?,?,?,?,?,?,?)",
        (spec_id, task_id, family, cap_family, marker, 1, status, iast_state))


def _add_event(db, task_id, event_id, canary, sink_file):
    db.execute(
        "INSERT INTO iast_events (id, task_id, canary, sink_file, source_value, "
        "evidence_json, canary_state) VALUES (?,?,?,?,?,?,?)",
        (event_id, task_id, canary, sink_file, "", "{}", "sink-reached-probe"))


def test_postpass_matches_on_capability_family_not_declared_family(db):
    """family 被上游写错（broken_access_control）但 capability_family 是 weak_random 时，
    post-pass 必须照样接得住 —— 这正是此前漏掉 78% 目标 spec 的成因。"""
    _add_spec(db, 1, 11, "broken_access_control", "weak_random", _IDENT + "P1", "unconfirmed")
    _add_event(db, 1, 101, _IDENT, "java.util.Random.nextInt")
    n = _apply_family_route_postpass(1, db)
    assert n == 1, "capability_family 命中而 family 未命中时必须仍然选中"
    row = db.execute("SELECT verification_status, positive_evidence_rule FROM trigger_specs "
                     "WHERE id=11", fetchall=True)[0]
    assert row["verification_status"] == CONFIRMED_CODE_PROPERTY
    assert row["positive_evidence_rule"] == "non_crypto_random_source_called", (
        "positive_evidence_rule 必须落库，否则它仍是无人消费的死字段")


def test_postpass_falls_back_to_family_when_column_absent():
    """老库 / 最小夹具没有 capability_family 列时退回 family 过滤，不得整体失败。"""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, "
        "taint_marker TEXT, session_id INTEGER, verification_status TEXT, iast_state TEXT)")
    conn.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, canary TEXT, "
        "sink_file TEXT, source_value TEXT, evidence_json TEXT, canary_state TEXT)")
    sdb = _FakeDB(conn)
    sdb.execute(
        "INSERT INTO trigger_specs (id, task_id, family, taint_marker, session_id, "
        "verification_status, iast_state) VALUES (1, 9, 'weak_random', ?, 1, 'unconfirmed', '')",
        (_IDENT + "P9",))
    sdb.execute(
        "INSERT INTO iast_events (id, task_id, canary, sink_file, source_value, "
        "evidence_json, canary_state) VALUES (1, 9, ?, 'java.util.Random.nextInt', '', '{}', '')",
        (_IDENT,))
    n = _apply_family_route_postpass(9, sdb)
    assert n == 1, "无 capability_family 列时必须退回 family 过滤而不是崩掉"
    conn.close()
