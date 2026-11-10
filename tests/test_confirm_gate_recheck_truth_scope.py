"""确认态硬闸迟到回补的真值表口径回归守卫（2026-11-07）。

背景：本轮出现红线 1/63，根因是 confirm_gate_recheck 把「真值表外的 genuine-sink」
（tomcatfiltermemshell 写类文件 RandomAccessFile 是真 sink，但不在 jsc 31 点真值表内）
误升 confirmed_exploitable，污染红线。

本测试锁定两条不变量：
  A. 真值表内点（expected_sink_file 命中真值表 file）+ 迟到真 sink 证据 → confirmed_exploitable。
  B. 真值表外点（expected_sink_file 不命中真值表）+ 迟到真 sink 证据 → sink_reached
     （绝不升 confirmed_exploitable，因而绝不触发红线）。
"""
import json

import pytest

from src.cli.benchmark_cli import _apply_confirm_gate_recheck, _norm_path
from src.infrastructure.db import Database

TASK = 1
WS = 3
_TS = "2026-11-07T00:00:00"
_IDENT = "s4st41dff023f00a1ee17f"  # 合法 canary 身份段（s4st41 + 16 hex）

# 受控真值表：仅含 SQLI，用于精确区分「表内 / 表外」。
_TRUTH = {_norm_path("src/main/java/org/joychou/controller/SQLI.java")}


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "app.db"))
    d.execute(
        "INSERT INTO workspaces (id, name, target_path, settings_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (WS, "ws", "/tmp/proj", "{}", _TS, _TS),
    )
    d.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, "
        "options_json, summary_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (TASK, WS, "task1", "completed", "done", "/tmp/out", "{}", "{}", _TS),
    )
    d.execute(
        "INSERT INTO iast_sessions (id, workspace_id, app_name, agent_id, target_url, "
        "registered_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (1, WS, "app", "agent", "http://x", _TS, _TS),
    )
    return d


def _seed_spec(db, sid, family, sink_file, taint_marker,
               status="unconfirmed", iast_state="confirm-gate:no-arrival"):
    db.execute(
        "INSERT INTO trigger_specs (id, task_id, workspace_id, vulnerability_hash_v2, family, "
        "target_endpoint, verification_status, iast_state, business_logic_confirmed, "
        "taint_marker, expected_sink_file, raw_json, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, TASK, WS, "h%s" % sid, family, "/benchmark/x", status, iast_state, 0,
         taint_marker, sink_file, json.dumps({}, ensure_ascii=False), _TS),
    )


def _seed_event(db, sid, canary, sink_file, stack_trace=""):
    db.execute(
        "INSERT INTO iast_events (session_id, workspace_id, task_id, app_name, agent_id, "
        "event_type, canary, sink_file, stack_trace, ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (1, WS, TASK, "app", "agent", "sink", canary, sink_file, stack_trace, _TS),
    )


def _get(db, sid):
    return db.execute(
        "SELECT verification_status, iast_state, failure_attribution FROM trigger_specs WHERE id=?",
        (sid,), fetchone=True,
    )


def test_in_truth_genuine_sink_confirmed(db):
    """真值表内点 + 迟到真 sink → confirmed_exploitable。"""
    _seed_spec(db, 101, "sql_injection",
               "D:/java-sec-code/src/main/java/org/joychou/controller/SQLI.java",
               taint_marker=_IDENT + "PAYLOAD")
    _seed_event(db, 101, _IDENT, "java.sql.Statement.executeQuery")
    n = _apply_confirm_gate_recheck(TASK, db, truth_points=_TRUTH)
    assert n == 1
    r = _get(db, 101)
    assert r["verification_status"] == "confirmed_exploitable"
    assert r["iast_state"] == "late-evidence-recovered"
    assert r["failure_attribution"] == "confirm_gate_late_evidence"


def test_out_of_truth_genuine_sink_only_sink_reached(db):
    """真值表外点（tomcatfiltermemshell）+ 迟到真 sink → sink_reached，绝不 confirmed_exploitable。"""
    _seed_spec(db, 102, "command_execution",
               "src/main/java/org/joychou/config/TomcatFilterMemShell.java",
               taint_marker=_IDENT + "PAYLOAD")
    _seed_event(db, 102, _IDENT, "java.io.RandomAccessFile.<init>")
    n = _apply_confirm_gate_recheck(TASK, db, truth_points=_TRUTH)
    # 真值表内点数必须为 0（truth 只含 SQLI，本 spec 是 memshell）。
    assert n == 0
    r = _get(db, 102)
    assert r["verification_status"] == "sink_reached"
    assert r["iast_state"] == "late-evidence-recovered"
    assert r["failure_attribution"] == "confirm_gate_late_evidence_out_of_truth"


def test_out_of_truth_stack_hit_only_sink_reached(db):
    """真值表外点 + stack_trace 命中（表外文件）→ 同样只记 sink_reached。"""
    _seed_spec(db, 103, "command_execution",
               "src/main/java/org/joychou/config/TomcatFilterMemShell.java",
               taint_marker=_IDENT + "PAYLOAD")
    _seed_event(db, 103, _IDENT, "java.io.RandomAccessFile.<init>",
                stack_trace="at org.joychou.config.TomcatFilterMemShell.java:42")
    n = _apply_confirm_gate_recheck(TASK, db, truth_points=_TRUTH)
    assert n == 0
    r = _get(db, 103)
    assert r["verification_status"] == "sink_reached"


def test_no_evidence_no_change(db):
    """无迟到证据 → 维持原状，不被回补。"""
    _seed_spec(db, 104, "sql_injection",
               "D:/java-sec-code/src/main/java/org/joychou/controller/SQLI.java",
               taint_marker=_IDENT + "PAYLOAD")
    n = _apply_confirm_gate_recheck(TASK, db, truth_points=_TRUTH)
    assert n == 0
    r = _get(db, 104)
    assert r["verification_status"] == "unconfirmed"
