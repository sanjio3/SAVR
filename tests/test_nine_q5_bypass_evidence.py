"""净化器判定九问（Q5）单测：一等公民证据列 + 终态诊断 canary + 终态可重开。"""
from __future__ import annotations

import json
import tempfile
import os

from src.infrastructure.db import Database
from src.agents.i2_feedback import (
    mark_filtered_not_exploitable, reopen_terminal_on_runtime_evidence, FILTERED_NOT_EXPLOITABLE,
)
from src.core.filter_verdict import terminal_diagnostic_canary, is_terminal


def _make_db():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    # trigger_specs 有 FK → workspaces，测试需先有 workspace 行
    db.execute("INSERT INTO workspaces (name, target_path, created_at, updated_at) "
               "VALUES (?,?,?,?)", ("ws", ".", "now", "now"))
    return db, path


def _insert_spec(db, task_id, raw_json, iast_state="", vstatus=""):
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, family, "
        "target_endpoint, http_method, taint_marker, expected_sink_file, raw_json, "
        "verification_status, iast_state, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, task_id, "h1", "sqli", "/x", "GET", "mk", "sink.java",
         raw_json, vstatus, iast_state, "now"),
    )
    return db.execute("SELECT id FROM trigger_specs WHERE task_id=?", (task_id,),
                      fetchone=True)["id"]


def _terminal_raw(filter_spec):
    return json.dumps({
        "filter_verdict": {"verdict": "non_bypassable", "confidence": "high",
                           "reason": "允许集拦下该族全部最小利用串"},
        "filter_spec": filter_spec,
    })


def test_q5_columns_exist_after_migration():
    db, _ = _make_db()
    cols = {r["name"] for r in db.execute("PRAGMA table_info(trigger_specs)", fetchall=True)}
    assert {"bypass_state", "bypass_reason", "filter_spec_json"} <= cols


def test_q5_mark_writes_first_class_evidence():
    db, _ = _make_db()
    spec = {"kind": "allow", "patterns": ["^[a-zA-Z0-9_.-]+$"], "source": "deterministic"}
    _insert_spec(db, 1, _terminal_raw(spec))
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 1
    row = db.execute("SELECT verification_status, bypass_state, bypass_reason, filter_spec_json "
                     "FROM trigger_specs WHERE task_id=1", (), fetchone=True)
    assert row["verification_status"] == FILTERED_NOT_EXPLOITABLE
    assert row["bypass_state"] == "non_bypassable"
    assert "拦下" in (row["bypass_reason"] or "")
    parsed = json.loads(row["filter_spec_json"] or "{}")
    assert parsed.get("kind") == "allow"


def test_q5_mark_skips_confirmed():
    db, _ = _make_db()
    _insert_spec(db, 1, _terminal_raw({"kind": "allow", "patterns": ["x"]}), vstatus="confirmed_exploitable")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 0


def test_q5_reopen_on_runtime_sink_reached():
    db, _ = _make_db()
    _insert_spec(db, 1, _terminal_raw({"kind": "allow", "patterns": ["x"]}), iast_state="sink-reached")
    # 先标成终态证据
    mark_filtered_not_exploitable(db, 1)
    n = reopen_terminal_on_runtime_evidence(db, 1)
    assert n == 1
    row = db.execute("SELECT bypass_state, verification_status FROM trigger_specs WHERE task_id=1",
                     (), fetchone=True)
    assert row["bypass_state"] == "undetermined"
    assert row["verification_status"] == ""  # 重开待复核


def test_q5_reopen_not_triggered_on_arrival_sanitized():
    # arrival-sanitized 是「过滤器有效」正向证据，与 non_bypassable 一致，不重开
    db, _ = _make_db()
    _insert_spec(db, 1, _terminal_raw({"kind": "allow", "patterns": ["x"]}), iast_state="arrival-sanitized")
    mark_filtered_not_exploitable(db, 1)
    n = reopen_terminal_on_runtime_evidence(db, 1)
    assert n == 0


def test_q5_terminal_diagnostic_canary_is_benign():
    c = terminal_diagnostic_canary("sqli")
    assert c  # 非空无害串
    # 不应含破坏性 SQL
    assert "DROP" not in c.upper() and "TRUNCATE" not in c.upper()


def test_is_terminal_respects_env_switch():
    v = {"verdict": "non_bypassable", "confidence": "high"}
    assert is_terminal(v) is True
    os.environ["SAST_AI_VERDICT_TERMINAL"] = "0"
    try:
        assert is_terminal(v) is False
    finally:
        os.environ.pop("SAST_AI_VERDICT_TERMINAL", None)
