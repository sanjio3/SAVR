# -*- coding: utf-8 -*-
"""回归锁：泛化比较的分子分母必须同粒度。

2026-11-09 L2实测：RuoYi 真值表 6 条 in_scope 行里，
`SysUserMapper.xml / sql_injection` 占了 3 行（`/system/user/list`、
`/system/role/authUser/allocatedList`、`/system/role/authUser/unallocatedList`
三个不同路由的实例），而匹配只到 `(文件, 族)` 一级。

旧实现：分母 = 真值行数（6），分子 = 去重后的 `(文件, 族)` 命中数（≤4），
于是输出了 `动态 4/6`、`重放 2/6` 这种分子分母不同粒度的读数；同一轮
`jsc_four_tier.py` 按行算又是 `6/6`，两个工具互相打架。

锁定三条不变量：
  A. 分母 = 不同 `(文件, 族)` 真值点的个数；
  B. 分子不超过分母（同粒度）；
  C. jsc 真值表 31 行全为不同对 ⇒ 历史读数零变化（24/24 不变）。
"""
import csv
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import generalization_compare as G  # noqa: E402

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


def _db(tmp_path, specs):
    """specs: (id, file, family, status, rule)"""
    path = str(tmp_path / "t.db")
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    for sid, f, fam, status, rule in specs:
        con.execute("INSERT INTO trigger_specs VALUES (?,?,?,?,?,?,?)",
                    (sid, 1, f, fam, status, rule, "sink-reached"))
        con.execute("INSERT INTO replay_attempts VALUES (?,?,?)", (sid, 1, sid))
    con.commit()
    con.close()
    return path


def _truth(tmp_path, rows):
    """rows: (file, family)"""
    path = str(tmp_path / "truth.csv")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["file", "family", "scope", "detectability", "evidence", "note"])
        for f, fam in rows:
            w.writerow([f, fam, "in_scope", "static_sink", "", ""])
    return path


def test_duplicate_truth_rows_do_not_inflate_denominator(tmp_path):
    """RuoYi 形态：6 行真值、4 个不同 (文件, 族)。"""
    truth = _truth(tmp_path, [
        ("src/SysUserMapper.xml", "sql_injection"),
        ("src/SysUserMapper.xml", "sql_injection"),
        ("src/SysUserMapper.xml", "sql_injection"),
        ("src/SysDeptMapper.xml", "sql_injection"),
        ("src/SysRoleMapper.xml", "sql_injection"),
        ("src/JobInvokeUtil.java", "command_execution"),
    ])
    db = _db(tmp_path, [
        (1, "src/SysUserMapper.xml", "sql_injection", "confirmed_code_property",
         "framework:mybatis_dollar_substitution"),
        (2, "src/SysDeptMapper.xml", "sql_injection", "confirmed_code_property",
         "framework:mybatis_dollar_substitution"),
        (3, "src/SysRoleMapper.xml", "sql_injection", "confirmed_exploitable", ""),
        (4, "src/JobInvokeUtil.java", "command_execution", "confirmed_exploitable", ""),
    ])
    m = G.measure(1, truth, db, set())
    assert m["denominator"] == 4, "分母必须是不同的 (文件, 族) 真值点"
    assert m["truth_rows"] == 6, "真值行数要单独保留"
    for key in ("static_fam", "dyn_fam", "rep_fam", "strict_replay"):
        assert m[key] <= m["denominator"], "%s 超过分母，分子分母不同粒度" % key
    assert m["static_fam"] == 4
    assert m["rep_fam"] == 2


def test_distinct_truth_rows_keep_historical_denominator(tmp_path):
    """jsc 形态：31 行全不同对 ⇒ 分母就是行数，历史读数不变。"""
    rows = [("src/F%d.java" % i, "sqli") for i in range(31)]
    truth = _truth(tmp_path, rows)
    db = _db(tmp_path, [(1, "src/F0.java", "sqli", "confirmed_exploitable", "")])
    m = G.measure(1, truth, db, set())
    assert m["denominator"] == 31
    assert m["truth_rows"] == 31


def test_real_jsc_truth_table_has_no_duplicate_pairs():
    """实盘校验：jsc 真值表没有任何重复 (文件, 族)，所以本次修正对历史零影响。"""
    path = os.path.join(ROOT, "data", "java_sec_code_truth_v2.csv")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8-sig") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("scope") or "").strip() == "in_scope"]
    pairs = {(os.path.basename(r["file"].replace("\\", "/")).lower(),
              r["family"].strip().lower()) for r in rows}
    assert len(pairs) == len(rows)
