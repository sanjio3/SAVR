# -*- coding: utf-8 -*-
"""影子真值口径回归锁：主表只读、候选去重、输出显式标注、红线变化可预期。

2026-11-07：L1 的 log4j.java/xss 是真值表未覆盖的真实反射 XSS。
补真值属于口径决策而非代码修复，所以主真值表保持不动，另给四档脚本一个只读
--truth-addendum，把「若采纳，历史轮次会怎么变」算成实测数字再交给评审。
"""
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools import jsc_four_tier as ft  # noqa: E402
from tools import truth_addendum_impact as tai  # noqa: E402

HEADER = "file,family,scope,detectability,evidence,note\n"
FAM = ft._fam("xss")

SCHEMA = """
CREATE TABLE trigger_specs (
    id INTEGER PRIMARY KEY, task_id INTEGER, expected_sink_file TEXT, family TEXT,
    verification_status TEXT, positive_evidence_rule TEXT, iast_state TEXT
);
CREATE TABLE replay_attempts (id INTEGER PRIMARY KEY, task_id INTEGER, spec_id INTEGER);
CREATE TABLE findings (id INTEGER PRIMARY KEY, task_id INTEGER, file_path TEXT, finding_type TEXT);
"""


@pytest.fixture
def truth_files(tmp_path):
    main = tmp_path / "truth.csv"
    main.write_text(HEADER + "src/A.java,xss,in_scope,static_sink,,\n", encoding="utf-8")
    add = tmp_path / "add.csv"
    add.write_text(HEADER
                   + "src/B.java,xss,in_scope,static_sink,,\n"
                   + "src/A.java,xss,in_scope,static_sink,,duplicate\n", encoding="utf-8")
    return str(main), str(add)


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "t.db")
    con = sqlite3.connect(p)
    con.executescript(SCHEMA)
    con.execute("INSERT INTO trigger_specs VALUES (1,1,'src/B.java','xss',"
                "'confirmed_exploitable','','sink-reached')")
    con.execute("INSERT INTO replay_attempts VALUES (1,1,1)")
    con.commit()
    con.close()
    return p


def _merge(main, add):
    base = ft.load_truth(main)
    seen = {(t["base"], t["family"]) for t in base}
    return base, [t for t in ft.load_truth(add)
                  if (t["base"], t["family"]) not in seen]


def test_addendum_is_read_only_and_deduplicated(truth_files):
    main, add = truth_files
    before = open(main, "rb").read()
    base, added = _merge(main, add)
    assert [t["base"] for t in base] == ["a.java"]
    assert [t["base"] for t in added] == ["b.java"]
    assert open(main, "rb").read() == before


def test_shipped_addendum_is_proposed_not_adopted():
    """防止有人把候选口径悄悄采纳进主真值表。"""
    p = os.path.join(ROOT, "config", "truth_addendum_l1_log4j_xss.csv")
    rows = ft.load_truth(p)
    assert len(rows) == 1
    assert (rows[0]["base"], rows[0]["family"]) == ("log4j.java", FAM)
    assert "NOT ADOPTED" in open(p, encoding="utf-8").read()
    main = ft.load_truth(ft.DEFAULT_TRUTH)
    assert ("log4j.java", FAM) not in {(t["base"], t["family"]) for t in main}


def test_metrics_show_redline_cleared_only_under_shadow(truth_files, db):
    main, add = truth_files
    base, added = _merge(main, add)
    _, specs = ft.load_task(db, 1)
    a = tai.metrics(base, [], specs, {})
    b = tai.metrics(base + added, [], specs, {})
    assert a["fp_replay"] == 1 and b["fp_replay"] == 0
    assert a["replay"] == b["replay"] == 1     # 分母不变，不是靠缩小分母把红线洗白
    assert b["rep_fam"] - a["rep_fam"] == 1
    assert b["dyn_den"] - a["dyn_den"] == 1
    assert a["fp_replay_specs"] == ["b.java/%s" % FAM]
    assert b["fp_replay_specs"] == []


def test_main_marks_shadow_output_and_keeps_truth_untouched(truth_files, db, monkeypatch, capsys):
    main, add = truth_files
    before = open(main, "rb").read()
    monkeypatch.setattr(sys, "argv", ["jsc_four_tier.py", "--task-id", "1",
                                      "--truth", main, "--db", db,
                                      "--truth-addendum", add])
    assert ft.main() == 0
    out = capsys.readouterr().out
    assert "[影子口径] 追加 1 条候选真值" in out
    assert "影子口径 +1" in out
    assert "不是正式读数" in out
    assert open(main, "rb").read() == before


def test_main_rejects_missing_addendum(truth_files, db, monkeypatch):
    main, _ = truth_files
    monkeypatch.setattr(sys, "argv", ["jsc_four_tier.py", "--task-id", "1",
                                      "--truth", main, "--db", db,
                                      "--truth-addendum", main + ".missing"])
    assert ft.main() == 2


def test_impact_report_is_pure_and_shows_both_columns(truth_files, db, tmp_path):
    main, add = truth_files
    base, added = _merge(main, add)
    _, specs = ft.load_task(db, 1)
    marker = tmp_path / "report.md"
    rep = tai.build_report(base, added, {1: ([], specs)}, {},
                           "truth.csv", "add.csv", "in_scope", db)
    assert "主口径" in rep and "影子口径" in rep
    assert "红线 1/1 → 0/1" in rep
    assert not marker.exists()   # 落盘只发生在 main() 带 --output
