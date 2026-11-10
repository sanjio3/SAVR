# -*- coding: utf-8 -*-
"""四档口径 `confirmed_replay` 收紧的回归锁。

2026-11-06：628 的 `sqli.java` 靠零发包的 `business-logic-confirmed` 撑起一个
真值点，旧口径把「裁决凭空确认」算成动态证明。收紧为「confirmed_exploitable
+ 非 framework: + 确有 replay_attempts」，旧口径保留为 legacy 双列。
"""
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools import jsc_four_tier as ft  # noqa: E402


SCHEMA = """
CREATE TABLE trigger_specs (
    id INTEGER PRIMARY KEY, task_id INTEGER, expected_sink_file TEXT, family TEXT,
    verification_status TEXT, positive_evidence_rule TEXT, iast_state TEXT
);
CREATE TABLE replay_attempts (
    id INTEGER PRIMARY KEY, task_id INTEGER, spec_id INTEGER
);
CREATE TABLE findings (id INTEGER PRIMARY KEY, task_id INTEGER, file_path TEXT, finding_type TEXT);
"""


def _seed(tmp_path, rows):
    """rows: (id, file, family, status, rule, with_attempt)"""
    db = str(tmp_path / "t.db")
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    for i, (spec_id, f, fam, status, rule, with_attempt) in enumerate(rows, 1):
        con.execute(
            "INSERT INTO trigger_specs VALUES (?,?,?,?,?,?,?)",
            (spec_id, 1, f, fam, status, rule, "sink-reached"))
        if with_attempt:
            con.execute("INSERT INTO replay_attempts VALUES (?,?,?)", (i, 1, spec_id))
    con.commit()
    con.close()
    return db


@pytest.fixture
def mixed(tmp_path):
    return _seed(tmp_path, [
        (1, "src/A.java", "sqli", "confirmed_exploitable", "", True),
        (2, "src/B.java", "sqli", "confirmed_exploitable", "", False),
        (3, "src/C.java", "sqli", "confirmed_exploitable", "framework:expr_engine", True),
        (4, "src/D.java", "sqli", "confirmed_code_property", "", True),
        (5, "src/E.java", "sqli", "unconfirmed", "", True),
    ])


def test_zero_replay_confirmation_is_not_dynamic_proof(mixed):
    _, specs = ft.load_task(mixed, 1)
    by_id_file = {s["base"]: s for s in specs}
    assert by_id_file["a.java"]["confirmed_replay"] is True
    assert by_id_file["b.java"]["confirmed_replay"] is False
    assert by_id_file["b.java"]["confirmed_replay_legacy"] is True
    assert by_id_file["b.java"]["has_attempts"] is False


def test_framework_and_non_exploitable_excluded_from_both(mixed):
    _, specs = ft.load_task(mixed, 1)
    by = {s["base"]: s for s in specs}
    for base in ("c.java", "d.java", "e.java"):
        assert by[base]["confirmed_replay"] is False
        assert by[base]["confirmed_replay_legacy"] is False
    assert by["d.java"]["confirmed"] is True  # 仍计入 confirmed 总数


def test_compute_keeps_legacy_columns_for_history_comparison(mixed):
    # compute() 不重新归一 truth 的 family（load_truth 才做），这里手动对齐。
    fam = ft._fam("sqli")
    truth = [{"file": "src/A.java", "base": "a.java", "family": fam, "detectability": ""},
             {"file": "src/B.java", "base": "b.java", "family": fam, "detectability": ""}]
    findings, specs = ft.load_task(mixed, 1)
    rows = {r["base"]: r for r in ft.compute(truth, findings, specs)}
    assert rows["a.java"]["rep_fam"] is True
    assert rows["a.java"]["rep_fam_legacy"] is True
    assert rows["b.java"]["rep_fam"] is False
    assert rows["b.java"]["rep_fam_legacy"] is True


def test_compute_fp_reports_both_and_flags_excluded_zero_replay(tmp_path):
    # 真值里没有 B.java/E.java，制造旧口径下的「红线误报」。
    db = _seed(tmp_path, [
        (1, "src/A.java", "sqli", "confirmed_exploitable", "", True),
        (2, "src/B.java", "sqli", "confirmed_exploitable", "", False),
    ])
    truth = [{"base": "a.java", "family": ft._fam("sqli")}]
    _, specs = ft.load_task(db, 1)
    fp = ft.compute_fp(truth, specs)
    assert fp["replay"] == 1 and len(fp["fp_replay"]) == 0
    assert fp["replay_legacy"] == 2 and len(fp["fp_replay_legacy"]) == 1
    assert [x["base"] for x in fp["fp_zero_replay_excluded"]] == ["b.java"]


def test_sql_pushes_attempt_filter_down(mixed):
    """过滤必须在 SQL 的 EXISTS 里，不能把整张 attempts 表捞回 Python。"""
    import inspect
    src = inspect.getsource(ft.load_task)
    assert "EXISTS(SELECT 1 FROM replay_attempts" in src
