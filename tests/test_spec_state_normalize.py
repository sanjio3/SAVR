#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""`payload_unavailable` 口径归一的单测。

锁的是判据本身，不是某次跑批的数字：
「既没有弹、又没发出去」才算 payload 缺口；有弹没发、有发无弹，都不能归到这里。
"""
import json
import sqlite3

import pytest

from src.core.spec_state_normalize import (
    ATTR_NO_PAYLOAD,
    STATE_PAYLOAD_UNAVAILABLE,
    is_dynamic_eligible,
    normalize_payload_unavailable,
)


@pytest.fixture()
def db():
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, "
        "attack_payloads_json TEXT, iast_state TEXT, failure_attribution TEXT, "
        "failure_attribution_reason TEXT, verification_status TEXT)"
    )
    con.execute(
        "CREATE TABLE replay_attempts (id INTEGER PRIMARY KEY, task_id INTEGER, spec_id INTEGER)"
    )
    yield con
    con.close()


def _add(con, sid, *, family="deserialization", payloads=None, state="no-arrival",
         status="unconfirmed", task=1):
    con.execute(
        "INSERT INTO trigger_specs VALUES (?,?,?,?,?,?,?,?)",
        (sid, task, family, json.dumps(payloads or []), state, "", "", status),
    )


def _attempt(con, sid, task=1):
    con.execute("INSERT INTO replay_attempts (task_id, spec_id) VALUES (?,?)", (task, sid))


def test_no_payload_and_no_attempt_marks_payload_unavailable(db):
    """A2 没弹 + D1 没发 ⇒ payload_unavailable（本轮的 deserialization 就是这类）。"""
    _add(db, 1, family="deserialization", payloads=[])
    out = normalize_payload_unavailable(db, 1)
    assert out["marked"] == 1
    row = db.execute("SELECT iast_state, failure_attribution FROM trigger_specs WHERE id=1").fetchone()
    assert row[0] == STATE_PAYLOAD_UNAVAILABLE
    assert row[1] == ATTR_NO_PAYLOAD


def test_with_payload_but_no_attempt_stays_no_arrival(db):
    """有弹却没发 ⇒ 另一种故障，必须留在 no-arrival 等查，不能被顺手抹平。"""
    _add(db, 2, payloads=["' OR 1=1--"])
    out = normalize_payload_unavailable(db, 1)
    assert out["marked"] == 0
    row = db.execute("SELECT iast_state FROM trigger_specs WHERE id=2").fetchone()
    assert row[0] == "no-arrival"


def test_attempted_but_no_payload_stays_no_arrival(db):
    """发过请求（D1 用净化感知合成）但库里没存弹 ⇒ 不是 payload 缺口，留 no-arrival。

    OWASP 上大量 spec 是这种形态：attack_payloads 空但有 attempt。
    """
    _add(db, 3, payloads=[])
    _attempt(db, 3)
    out = normalize_payload_unavailable(db, 1)
    assert out["marked"] == 0
    assert db.execute("SELECT iast_state FROM trigger_specs WHERE id=3").fetchone()[0] == "no-arrival"


def test_does_not_touch_verification_status(db):
    """口径归一绝不改 verification_status（不升也不降）。"""
    _add(db, 4, payloads=[], status="confirmed_exploitable")
    normalize_payload_unavailable(db, 1)
    assert db.execute("SELECT verification_status FROM trigger_specs WHERE id=4").fetchone()[0] \
        == "confirmed_exploitable"


def test_idempotent(db):
    _add(db, 5, payloads=[])
    assert normalize_payload_unavailable(db, 1)["marked"] == 1
    assert normalize_payload_unavailable(db, 1)["marked"] == 0  # 已经是 payload_unavailable，不再处理


def test_dry_run_does_not_write(db):
    _add(db, 6, payloads=[])
    assert normalize_payload_unavailable(db, 1, dry_run=True)["marked"] == 1
    assert db.execute("SELECT iast_state FROM trigger_specs WHERE id=6").fetchone()[0] == "no-arrival"


def test_only_same_task(db):
    _add(db, 7, payloads=[], task=1)
    _add(db, 8, payloads=[], task=2)
    normalize_payload_unavailable(db, 1)
    assert db.execute("SELECT iast_state FROM trigger_specs WHERE id=8").fetchone()[0] == "no-arrival"


def test_dynamic_eligibility_is_semantic_not_template_based():
    """动态分母的准入按「危害能否靠投放载荷证明」分类，与靶场无关。

    历史教训：一开始用 `family_map.is_d2_supported`（模板存在性）判定，
    结果 crlf_injection / ssti / url_redirect 这些**明明能靠重放确认**的族被误排除。
    所以改成按族的语义分类，这条用例锁住三个方向的判断。
    """
    # 注入类：把载荷投进去能观测到危害
    for fam in ("sql_injection", "xss", "deserialization", "ssti",
                "crlf_injection", "url_redirect", "ssrf", "xxe"):
        assert is_dynamic_eligible(fam) is True, fam
    # 属性类：危害是「某个开关/属性不对」，没有投载荷的语义
    for fam in ("secure_cookie", "weak_crypto", "information_exposure", "log_injection", "unmapped"):
        assert is_dynamic_eligible(fam) is False, fam
    # 无 HTTP 入口
    assert is_dynamic_eligible("rmi") is False


def test_classify_dynamic_three_buckets():
    from src.core.spec_state_normalize import classify_dynamic

    assert classify_dynamic("sql_injection") == "replay"
    assert classify_dynamic("csrf") == "replay"       # 不带 token 打一发即可证伪
    assert classify_dynamic("cors") == "replay"       # 带 Origin 打一发看 ACAO
    assert classify_dynamic("secure_cookie") == "property"
    assert classify_dynamic("rmi") == "no_entry"


# ── sink-reached 状态一致性（2026-11-01，阶段 3 前置）──────────────────────────
#
# 事故：本轮的 74 条 sink-reached 里，6 条既没有 replay_attempts、其文件/类
# 在任何 iast_event 里也从未出现 —— 状态凭空产生。它会让「到了 sink 判不出」的
# 归因失真，所以必须降级。判据是「确定性观测」，不是启发式。


@pytest.fixture()
def db_sink():
    con = sqlite3.connect(":memory:")
    con.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, "
        "expected_sink_file TEXT, expected_sink_line INTEGER, iast_state TEXT, "
        "failure_attribution TEXT, failure_attribution_reason TEXT, verification_status TEXT)"
    )
    con.execute(
        "CREATE TABLE replay_attempts (id INTEGER PRIMARY KEY, task_id INTEGER, spec_id INTEGER)"
    )
    con.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, "
        "sink_file TEXT, stack_trace TEXT)"
    )
    yield con
    con.close()


def _add_sink(con, sid, sink_file, *, state="sink-reached", task=1):
    con.execute(
        "INSERT INTO trigger_specs VALUES (?,?,?,?,?,?,?,?,?)",
        (sid, task, "path_traversal", sink_file, 10, state, "", "", "unconfirmed"),
    )


def test_sink_reached_without_attempt_or_event_is_downgraded(db_sink):
    from src.core.spec_state_normalize import reconcile_sink_state_without_evidence

    _add_sink(db_sink, 1, "src/A.java")          # 无重放、无事件 → 应降级
    r = reconcile_sink_state_without_evidence(db_sink, 1)
    assert r["downgraded"] == 1
    assert db_sink.execute("SELECT iast_state FROM trigger_specs WHERE id=1").fetchone()[0] == "no-arrival"


def test_sink_reached_with_probe_event_is_kept(db_sink):
    """有探针事件的不能降级 —— 即使这个 spec 自己没发过请求（事件来自同端点其它 spec）。"""
    from src.core.spec_state_normalize import reconcile_sink_state_without_evidence

    _add_sink(db_sink, 2, "src/B.java")
    db_sink.execute(
        "INSERT INTO iast_events VALUES (1,1,'','at org.joychou.controller.B.read(B.java:10)')")
    r = reconcile_sink_state_without_evidence(db_sink, 1)
    assert r["downgraded"] == 0
    assert db_sink.execute("SELECT iast_state FROM trigger_specs WHERE id=2").fetchone()[0] == "sink-reached"


def test_sink_reached_with_attempt_is_kept(db_sink):
    """发过请求的不能降级 —— 那是「发了没到」的判据问题，不是状态造假。"""
    from src.core.spec_state_normalize import reconcile_sink_state_without_evidence

    _add_sink(db_sink, 3, "src/C.java")
    db_sink.execute("INSERT INTO replay_attempts VALUES (1,1,3)")
    r = reconcile_sink_state_without_evidence(db_sink, 1)
    assert r["downgraded"] == 0
