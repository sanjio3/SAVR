"""属性路由族 post-pass 的回归锁（2026-10-04 落地）。

事故：`_TARGET_FAMILIES` 原先只有三族（weak_hash / weak_crypto / secure_cookie），
**weak_random 没在里面**。而 2026-10-03 的「判据错配出清」已经把 weak_random 定性为
**代码属性主张**（家庭级文档原话：终态只能是 confirmed_code_property，绝不能是
confirmed_exploitable），family_verdict 里的路由事实也随之改成 random_source。

结果就是两不着地：M4 通道注册表上线后 weak_random 的仲裁主判据变成 code_property
（harmful=False），既够不到 confirmed_exploitable，又没人把它路由到
confirmed_code_property，整族凭空掉成 unconfirmed。
实测 run 90 的 weakrand 类别 L2 TP 由 16 掉到 7（run 46→ run 90 共 -12 条里有 -9 条在此）。

本文件锁三件事：
    1. weak_random 必须在 post-pass 目标族里（含有足够的事件证据时判成 confirmed_code_property）；
    2. post-pass 必须也能接到 **unconfirmed** 的 spec（M4 之后属性族不再先落到 confirmed_exploitable）；
    3. 结果与当前状态相同时**不得写回**——否则会把 unconfirmed→unconfirmed 也写一遍，
       顺手把 iast_state 里的原始诊断态（no-arrival / safe-pattern-veto）覆盖成
       family-route:unconfirmed，丢掉归因线索。
"""
from __future__ import annotations

import sqlite3

import pytest

from src.cli.benchmark_cli import _apply_family_route_postpass


class _FakeDB:
    """最小 sdb 替身：execute(sql, params, fetchall=True) -> List[dict]。"""

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
        "taint_marker TEXT, session_id INTEGER, verification_status TEXT, iast_state TEXT)")
    conn.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, canary TEXT, "
        "sink_file TEXT, source_value TEXT, evidence_json TEXT, canary_state TEXT)")
    yield _FakeDB(conn)
    conn.close()


def _add_spec(db, task_id, spec_id, family, marker, status, iast_state="sink-reached-probe"):
    db.execute(
        "INSERT INTO trigger_specs (id, task_id, family, taint_marker, session_id, "
        "verification_status, iast_state) VALUES (?,?,?,?,?,?,?)",
        (spec_id, task_id, family, marker, 1, status, iast_state))


def _add_event(db, task_id, event_id, canary, sink_file, state="sink-reached-probe"):
    db.execute(
        "INSERT INTO iast_events (id, task_id, canary, sink_file, source_value, "
        "evidence_json, canary_state) VALUES (?,?,?,?,?,?,?)",
        (event_id, task_id, canary, sink_file, "", "{}", state))


_IDENT = "s4st41" + "a" * 16


def _state_of(db, spec_id):
    rows = db.execute(
        "SELECT verification_status, iast_state FROM trigger_specs WHERE id=?",
        (spec_id,), fetchall=True)
    return rows[0]["verification_status"], rows[0]["iast_state"]


def test_weak_random_with_random_sink_is_routed_to_code_property(db):
    """有 java.util.Random sink 事件 → confirmed_code_property（不是 exploitable、也不是留 unconfirmed）。

    2026-10-04 修正断言：第二项以前期望 `family-route:confirmed_code_property`，
    那正是「路由标记覆盖到达证据」的 bug——本用例的 spec 初始 iast_state 就是
    `sink-reached-probe`（见 _add_spec 默认值），覆盖后 L3 运行时到达指标会凭空少一条。
    现在契约是：**到达态保留原值，路由结果只体现在 verification_status**。
    详见 tests/test_family_route_preserves_arrival.py。
    """
    _add_spec(db, 1, 11, "weak_random", _IDENT + "PAYLOAD1", "confirmed_exploitable")
    _add_event(db, 1, 101, _IDENT, "java.util.Random.nextInt")
    n = _apply_family_route_postpass(1, db)
    assert n == 1
    assert _state_of(db, 11) == ("confirmed_code_property", "sink-reached-probe")


def test_weak_random_unconfirmed_spec_is_picked_up(db):
    """M4 之后属性族停在 unconfirmed，post-pass 必须照样接得住（这是本次的核心缺口）。"""
    _add_spec(db, 2, 21, "weak_random", _IDENT + "PAYLOAD2", "unconfirmed")
    _add_event(db, 2, 201, _IDENT, "java.util.Random.nextDouble")
    n = _apply_family_route_postpass(2, db)
    assert n == 1, "weak_random 的 unconfirmed spec 必须被 post-pass 选中并重判"
    assert _state_of(db, 21)[0] == "confirmed_code_property"


def test_secure_random_case_stays_unconfirmed(db):
    """安全用例（SecureRandom）没有 Random sink 事件 → 维持 unconfirmed，不得无证据晋升。"""
    _add_spec(db, 3, 31, "weak_random", _IDENT + "PAYLOAD3", "unconfirmed")
    _add_event(db, 3, 301, _IDENT, "java.security.SecureRandom.nextBytes")
    n = _apply_family_route_postpass(3, db)
    assert n == 0, "没有弱随机源证据时不许写回"


def test_diagnostic_iast_state_is_not_overwritten_when_nothing_changes(db):
    """判定结果等于当前状态时不得写回 —— iast_state 里的原始诊断态要留着归因。"""
    _add_spec(db, 4, 41, "weak_random", _IDENT + "PAYLOAD4", "unconfirmed",
              iast_state="no-arrival")
    # 事件存在但 sink 不匹配（无 Random 证据）→ 判定仍是 unconfirmed
    _add_event(db, 4, 401, _IDENT, "javax.servlet.http.Cookie.setHttpOnly")
    n = _apply_family_route_postpass(4, db)
    assert n == 0
    status, iast_state = _state_of(db, 41)
    assert status == "unconfirmed"
    assert iast_state == "no-arrival", "原始诊断态被 post-pass 覆盖会丢掉归因线索"


def test_dataflow_family_is_untouched(db):
    """数据流族（如 sqli）不在目标表里，post-pass 对它们零干预。"""
    _add_spec(db, 5, 51, "sql_injection", _IDENT + "PAYLOAD5", "confirmed_exploitable")
    _add_event(db, 5, 501, _IDENT, "java.sql.Statement.execute")
    n = _apply_family_route_postpass(5, db)
    assert n == 0
    status, iast_state = _state_of(db, 51)
    assert status == "confirmed_exploitable"
    assert iast_state == "sink-reached-probe"
