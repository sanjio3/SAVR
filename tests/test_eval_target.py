"""M4 评估 harness 的回归锁（tools/eval_target.py）。

锁三件事：
  1. label 模式能算出与对账一致的口径（precision / recall / 抑损）；
  2. 分母只统计「本任务扫到的分组」（防止用全量真值表时召回被算成个位数）；
  3. proxy / compare 模式在无标签时可用。
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "eval_target.py"
IDENT_A = "s4st41" + "a" * 16
IDENT_B = "s4st41" + "b" * 16
IDENT_C = "s4st41" + "c" * 16


def _mk_db(path: Path):
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, target_endpoint TEXT, "
        "expected_sink_file TEXT, taint_marker TEXT, family TEXT, capability_family TEXT, "
        "verification_status TEXT, iast_state TEXT, suppressed_by_safe_verdict INTEGER, "
        "suppress_rule TEXT, finding_id INTEGER)")
    con.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, canary TEXT, "
        "sink_file TEXT, source_value TEXT)")
    # A: TP 检出，S4（payload 在 sink 实参里）
    con.execute("INSERT INTO trigger_specs VALUES (1,1,'/a/Test1','T1.java',?,"
                "'sql_injection','sql_injection','confirmed_exploitable','sink-reached-probe',0,'',NULL)",
                (IDENT_A + "PAYLOAD" + "xyz",))
    # B: FP 检出，S3（到 sink 但实参无 payload）
    con.execute("INSERT INTO trigger_specs VALUES (2,1,'/a/Test2','T2.java',?,"
                "'sql_injection','sql_injection','sink_reached','sink-reached',0,'',NULL)",
                (IDENT_B + "PAYLOAD" + "xyz",))
    # C: TP 被抑制（抑损）
    con.execute("INSERT INTO trigger_specs VALUES (3,1,'/a/Test3','T3.java',?,"
                "'sql_injection','sql_injection','unconfirmed','value-gate-absent',1,"
                "'value-gate-absent',NULL)", (IDENT_C + "PAYLOAD" + "xyz",))
    con.executemany(
        "INSERT INTO iast_events (task_id, canary, sink_file, source_value) VALUES (1,?,?,?)",
        [(IDENT_A, "java.sql.Statement.execute", "[SELECT xyz]"),
         (IDENT_B, "java.sql.Statement.execute", "[SELECT 1]")])
    con.commit()
    con.close()


def _run(*args):
    p = subprocess.run([sys.executable, str(TOOL), *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def test_label_mode_metrics_and_loss(tmp_path):
    db = tmp_path / "t.db"
    _mk_db(db)
    labels = tmp_path / "labels.jsonl"
    labels.write_text("\n".join([
        json.dumps({"group": "/a/Test1", "label": "tp"}),
        json.dumps({"group": "/a/Test2", "label": "fp"}),
        json.dumps({"group": "/a/Test3", "label": "tp"}),
    ]), encoding="utf-8")
    rc, out = _run("--db", str(db), "--task", "1", "--labels", str(labels))
    assert rc == 0, out
    assert "精确率 50.0%" in out, out          # TP 1 / 检出 2
    assert "召回   50.0%" in out, out          # TP 1 / 真值 2
    assert "抑损（TP 被抑制）1" in out, out


def test_threshold_returns_exit_2(tmp_path):
    db = tmp_path / "t.db"
    _mk_db(db)
    labels = tmp_path / "labels.jsonl"
    labels.write_text(json.dumps({"group": "/a/Test1", "label": "tp"}), encoding="utf-8")
    rc, _ = _run("--db", str(db), "--task", "1", "--labels", str(labels),
                 "--min-precision", "0.9")
    assert rc == 2


def test_proxy_and_compare_modes(tmp_path):
    db = tmp_path / "t.db"
    _mk_db(db)
    rc, out = _run("--db", str(db), "--task", "1", "--proxy")
    assert rc == 0 and "S4:" in out and "S3:" in out, out
    rc2, out2 = _run("--db", str(db), "--compare", "1", "1")
    assert rc2 == 0 and "新增检出 0" in out2, out2
