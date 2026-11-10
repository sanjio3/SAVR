"""spec 去重（Phase 0d）的回归锁（2026-11-02 落地）。

事故：第一版去重只按 `(endpoint, sink_line, family)` 三要素合并，实测在 本轮上
把 **13 条已确认的 spec 压成了未确认**。原因是同一 sink 的**不同污点源**不是重复：

    /vuln1                       L26 expression_injection  参数 `_body` vs `express`
    /deserialize/rememberMe/vuln L50 deserialization       空参数+query vs `rememberMe`+cookie
    /jsonp/object2jsonp          L77 jsonp_referer         空 vs `callback`
    /xstream                     L29 deserialization       `_body` vs `xml`

这四组里「能打通的那条」常常只有一条，合并等于把有效弹压掉。

本文件锁三件事：
    1. 五要素（endpoint/line/family/param/location）全同才合并；
    2. 同位置同族但参数不同 ⇒ **不合并**（这是主锁）；
    3. 组内保留已确认的那条，其余置 `replayable=0`；
    4. **不得写 `suppressed_by_safe_verdict`** —— `reports.py` 会据此把该 spec 挂的
       finding 从报告里剔除，而实测 29 个重复组里 24 组 finding_id 不同，
       写了就会静默少报 24 个 finding（见 test_dedupe_must_not_touch_suppressed_flag）。
"""
from __future__ import annotations

import sqlite3

import pytest


class _DB:
    """最小 Database 兼容层：`execute(sql, params, fetchall=True)`。"""

    def __init__(self, con):
        self.con = con

    def execute(self, sql, params=(), fetchall=False):
        cur = self.con.execute(sql, params)
        return cur.fetchall() if fetchall else cur


@pytest.fixture()
def con():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INT, target_endpoint TEXT, "
        "expected_sink_line INT, family TEXT, param_name TEXT, param_location TEXT, "
        "verification_status TEXT, replayable INT, suppressed_by_safe_verdict INT, "
        "suppress_rule TEXT, failure_attribution TEXT, failure_attribution_reason TEXT)"
    )
    yield c
    c.close()


def _add(con, sid, ep, line, fam, pname="", ploc="query", status="unconfirmed", task=1):
    con.execute(
        "INSERT INTO trigger_specs VALUES (?,?,?,?,?,?,?,?,1,0,'','','')",
        (sid, task, ep, line, fam, pname, ploc, status),
    )


def _live(con):
    """仍在重放集合里的 spec（replayable=1）。"""
    return {r[0] for r in con.execute(
        "SELECT id FROM trigger_specs WHERE COALESCE(replayable,1)=1")}


def test_identical_specs_are_merged(con):
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "/a", 10, "xss", "q", "query")
    _add(con, 2, "/a", 10, "xss", "q", "query")
    _add(con, 3, "/a", 10, "xss", "q", "query")
    assert _apply_spec_dedupe_postpass(1, _DB(con)) == 2
    assert _live(con) == {1}


def test_same_sink_different_param_is_not_merged(con):
    """主锁：同 sink 同族但参数不同 = 不同污点源，合并会压掉能打通的那条。"""
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "/a", 10, "xss", "_body", "body")
    _add(con, 2, "/a", 10, "xss", "express", "body")
    _add(con, 3, "/a", 10, "xss", "", "query")
    assert _apply_spec_dedupe_postpass(1, _DB(con)) == 0
    assert _live(con) == {1, 2, 3}


def test_same_sink_different_location_is_not_merged(con):
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "/a", 10, "deserialization", "rememberMe", "cookie")
    _add(con, 2, "/a", 10, "deserialization", "rememberMe", "query")
    assert _apply_spec_dedupe_postpass(1, _DB(con)) == 0
    assert _live(con) == {1, 2}


def test_confirmed_member_is_kept(con):
    """组内必须保留已确认的那条 —— 否则去重会顺手清掉确认。"""
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "/a", 10, "xss", "q", "query", "unconfirmed")
    _add(con, 2, "/a", 10, "xss", "q", "query", "confirmed_exploitable")
    assert _apply_spec_dedupe_postpass(1, _DB(con)) == 1
    kept = con.execute(
        "SELECT id, verification_status FROM trigger_specs "
        "WHERE COALESCE(replayable,1)=1").fetchone()
    assert tuple(kept) == (2, "confirmed_exploitable")


def test_spec_without_endpoint_is_never_merged(con):
    """没有端点的 spec 不能判重（不同文件同号行会被误并）。"""
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "", 10, "xss", "q", "query")
    _add(con, 2, "", 10, "xss", "q", "query")
    assert _apply_spec_dedupe_postpass(1, _DB(con)) == 0
    assert _live(con) == {1, 2}


def test_dedupe_must_not_touch_suppressed_flag(con):
    """去重只停重放，不许动 suppressed —— 否则 reports.py 会把 finding 一起剔掉。"""
    from src.cli.benchmark_cli import _apply_spec_dedupe_postpass

    _add(con, 1, "/a", 10, "xss", "q", "query")
    _add(con, 2, "/a", 10, "xss", "q", "query")
    _apply_spec_dedupe_postpass(1, _DB(con))
    row = con.execute(
        "SELECT replayable, COALESCE(suppressed_by_safe_verdict,0), suppress_rule "
        "FROM trigger_specs WHERE id=2").fetchone()
    assert tuple(row) == (0, 0, "duplicate_spec"), row
