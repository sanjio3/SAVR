"""B 组落地单测（2026-09-28）：a2_rerun 触发白名单 + 产物硬闸 + gain 对账口径。"""
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.i2_feedback import (  # noqa: E402
    a2_rerun_actionable,
    confirmed_case_count,
    spec_health_gate,
    spec_health_snapshot,
)


def _mem_db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INT, family TEXT, "
                "target_endpoint TEXT, verification_status TEXT, created_at TEXT)")
    return con


def _insert(con, task_id, family, endpoint, status="unconfirmed", created="2026-09-28T00:00:00"):
    con.execute("INSERT INTO trigger_specs (task_id, family, target_endpoint, verification_status, created_at)"
                " VALUES (?,?,?,?,?)", (task_id, family, endpoint, status, created))


# ---------- B-2 触发白名单 ----------
def test_whitelist_static_fixable_passes():
    fbs = [{"reason": "端点幻觉：/foo 不存在", "residual_gaps": {"still_open": []}}]
    ok, why = a2_rerun_actionable(fbs)
    assert ok and "静态可修" in why


def test_whitelist_gate_suspension_skipped():
    fbs = [{"reason": "可达性未闭合", "residual_gaps": {"still_open": ["reachable"]}}]
    ok, why = a2_rerun_actionable(fbs)
    assert not ok


def test_whitelist_no_signal_now_skips():
    """批准点：无静态可修信号一律 skip（旧默认保守执行已翻转）。"""
    fbs = [{"reason": "某类未观测", "residual_gaps": {"still_open": []}}]
    ok, why = a2_rerun_actionable(fbs)
    assert not ok and "白名单" in why


def test_whitelist_empty():
    ok, _ = a2_rerun_actionable([])
    assert not ok


# ---------- B-1 产物硬闸 ----------
def test_gate_blocks_total_shrink():
    before = {"total": 294, "endpoint_resolved": 280, "endpoint_rate": 0.95, "injection": 100}
    after = {"total": 179, "endpoint_resolved": 170, "endpoint_rate": 0.95, "injection": 98}
    ok, why = spec_health_gate(before, after)
    assert not ok and "spec 总数" in why


def test_gate_blocks_endpoint_rate_drop():
    before = {"total": 294, "endpoint_resolved": 280, "endpoint_rate": 0.95, "injection": 100}
    after = {"total": 294, "endpoint_resolved": 200, "endpoint_rate": 0.68, "injection": 100}
    ok, why = spec_health_gate(before, after)
    assert not ok and "端点解析率" in why


def test_gate_blocks_injection_shrink():
    before = {"total": 294, "endpoint_resolved": 280, "endpoint_rate": 0.95, "injection": 100}
    after = {"total": 294, "endpoint_resolved": 280, "endpoint_rate": 0.95, "injection": 70}
    ok, why = spec_health_gate(before, after)
    assert not ok and "注入类" in why


def test_gate_passes_healthy_product():
    before = {"total": 294, "endpoint_resolved": 280, "endpoint_rate": 0.95, "injection": 100}
    after = {"total": 300, "endpoint_resolved": 288, "endpoint_rate": 0.96, "injection": 102}
    ok, why = spec_health_gate(before, after)
    assert ok


def test_gate_fail_open_on_missing_snapshot():
    ok, why = spec_health_gate(None, {"total": 1, "endpoint_rate": 1.0, "injection": 1})
    assert ok and "fail-open" in why


def test_snapshot_from_db():
    con = _mem_db()
    _insert(con, 1, "sql_injection", "/a", "confirmed_exploitable")
    _insert(con, 1, "weak_random", "")  # 无端点、非注入
    _insert(con, 2, "xss", "/c")  # 其他任务不计
    snap = spec_health_snapshot(con, 1)
    assert snap["total"] == 2 and snap["endpoint_resolved"] == 1
    assert abs(snap["endpoint_rate"] - 0.5) < 1e-6
    assert snap["injection"] == 1


# ---------- B-3 gain 对账口径 ----------
def test_confirmed_case_count_dedup_endpoints():
    con = _mem_db()
    _insert(con, 1, "sql_injection", "/case/A", "confirmed_exploitable")
    _insert(con, 1, "xss", "/case/A", "confirmed_exploitable")  # 同用例重复
    _insert(con, 1, "cmdi", "/case/B", "confirmed_exploitable")
    _insert(con, 1, "cmdi", "/case/C", "unconfirmed")  # 未确认不计
    _insert(con, 2, "xss", "/case/D", "confirmed_exploitable")  # 其他任务不计
    assert confirmed_case_count(con, 1) == 2
