# -*- coding: utf-8 -*-
"""回归锁：OWASP 抽样轮分层对账必须用 shard 宇宙 + 无表头真值。

锁定不变量：
  A. 分母是 mini 130 例宇宙（TP 79 / FP 51），不是全集 2740；
  B. 确认层用 gate_quality_redline 的全确认态集合，红线 actual<=limit 才 PASS；
  C. 未确认 TP 口径与红线一致（全确认态），不把 confirmed_code_property 误算成漏检；
  D. 分层 L1/L2/L3 的 tp+fp==cases，precision 分母是 tp+fp 不是 tp_all。
"""
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import gate_quality_redline as gate  # noqa: E402
import reconcile_owasp_mini as rmini  # noqa: E402


@pytest.fixture
def mini_env(tmp_path, monkeypatch):
    """构造 10 例宇宙的小样本：6 TP / 4 FP，含 code_property / 未确认 / 假到达。"""
    cases = [f"BenchmarkTest{i:05d}" for i in range(1, 11)]
    truth = {c: (i <= 6) for i, c in enumerate(cases, start=1)}
    universe = set(cases)
    monkeypatch.setattr(gate, "load_truth", lambda name: truth)
    monkeypatch.setattr(gate, "load_shard_cases", lambda name: universe)

    db = str(tmp_path / "app.db")
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, "
        "target_endpoint TEXT, verification_status TEXT, iast_state TEXT, family TEXT)")
    ep = lambda i: f"/x/BenchmarkTest{i:05d}"  # noqa: E731
    rows = []
    # 1-3 严格确认，4 code_property（仍属全确认态），5 未确认，6 完全无 spec
    rows += [(ep(i), "confirmed_exploitable", "sink-reached-probe", "sqli") for i in range(1, 4)]
    rows.append((ep(4), "confirmed_code_property", "sink-reached-probe", "weak_hash"))
    rows.append((ep(5), "unconfirmed", "sink-reached", "xss"))
    # 7-8 是 FP 用例，只到达不算确认；9 是 FP 但被全确认态误确认（假确认）
    rows.append((ep(7), "sink_reached", "sink-reached-probe", "xss"))
    rows.append((ep(8), "no_evidence", "no-arrival", "xss"))
    rows.append((ep(9), "confirmed_exploitable", "sink-reached-probe", "xss"))
    rows.append((ep(10), "sink_reached", "sink-reached", "xss"))
    con.executemany(
        "INSERT INTO trigger_specs (task_id,target_endpoint,verification_status,"
        "iast_state,family) VALUES (647,?,?,?,?)", rows)
    con.commit()
    con.close()
    monkeypatch.setattr(rmini, "DB", db)
    return truth, universe


def test_universe_is_shard_not_full_truth(mini_env):
    d = rmini.measure(647, "mini")
    assert d["truth_total"] == 10
    assert d["universe_cases"] == 10
    assert d["tp_basis"] == 6 and d["fp_basis"] == 4
    assert d["specs"] == 9


def test_layers_use_tp_plus_fp_denominator(mini_env):
    d = rmini.measure(647, "mini")
    for name, layer in d["layers"].items():
        assert layer["cases"] == layer["tp"] + layer["fp"], name
        assert 0.0 <= layer["recall_pct"] <= 100.0
        assert 0.0 <= layer["precision_pct"] <= 100.0


def test_all_confirmed_states_count_and_missed_tp(mini_env):
    d = rmini.measure(647, "mini")
    strict = d["layers"]["L2_confirmed_strict"]
    allst = d["layers"]["L2_confirmed_all_states"]
    # 严格口径只算 confirmed_exploitable：TP 1/2/3 + FP 9
    assert strict["tp"] == 3 and strict["fp"] == 1
    # 全确认态补上 case 4 的 confirmed_code_property，不能把它算成漏检
    assert allst["tp"] == 4 and allst["fp"] == 1
    # TP 共 6 个（1..6），确认 1/2/3/4 => 未确认 5、6 共 2 个
    assert d["missed_tp"]["count"] == 2
    assert sorted(d["missed_tp"]["cases"]) == ["BenchmarkTest00005", "BenchmarkTest00006"]
    assert d["missed_tp"]["by_status"].get("<no_spec>") == 1


def test_redline_uses_fp_basis_of_shard(mini_env):
    d = rmini.measure(647, "mini")
    assert d["redline"]["actual"] == 1  # case 9 是 FP 却进确认态
    assert d["redline"]["limit"] == int(round(4 * 0.66))  # 3，不是全集 2740 的 1808
    assert d["redline"]["pass"] is True  # 1 <= 3


def test_text_format_mentions_shard_and_pass(monkeypatch, capsys, mini_env):
    monkeypatch.setattr(sys, "argv", ["reconcile_owasp_mini.py", "--task-id", "647",
                                     "--shard", "mini"])
    assert rmini.main() == 0
    out = capsys.readouterr().out
    assert "shard=mini" in out and "宇宙=10" in out and "PASS" in out


def test_missed_tp_attributed_by_truth_category(mini_env, monkeypatch):
    """本轮实测：spec family 会把 weakrand 整族标成 xss，归因必须用真值 category。"""
    _, universe = mini_env
    monkeypatch.setattr(rmini, "load_truth_categories",
                        lambda: {c: "weakrand" for c in universe})
    d = rmini.measure(647, "mini")
    assert d["missed_tp"]["by_truth_category"] == {"weakrand": 2}
    # 内部族标签仍单独保留，用于排查族错配，但不能当真值族用
    assert d["missed_tp"]["by_spec_family"].get("xss") == 1
    assert "by_truth_category" in d["missed_tp"]


def test_multi_spec_state_aggregated_not_overwritten(mini_env):
    """一个用例多条 spec 时不能让最后一条覆盖确认态 / 终态。"""
    con = sqlite3.connect(rmini.DB)
    # case 5 原为 unconfirmed，补一条 sink_reached：用例级最强态应为 sink_reached
    con.execute("INSERT INTO trigger_specs (task_id,target_endpoint,verification_status,"
                "iast_state,family) VALUES (647,?,?,?,?)",
                ("/x/BenchmarkTest00005", "sink_reached", "sink-reached", "xss"))
    # case 1 已确认，尾部补 unconfirmed 不应把它踢出确认集
    con.execute("INSERT INTO trigger_specs (task_id,target_endpoint,verification_status,"
                "iast_state,family) VALUES (647,?,?,?,?)",
                ("/x/BenchmarkTest00001", "unconfirmed", "", "xss"))
    con.commit()
    con.close()
    d = rmini.measure(647, "mini")
    assert d["layers"]["L2_confirmed_all_states"]["tp"] == 4
    assert d["missed_tp"]["by_status"]["sink_reached"] == 1
    assert d["missed_tp"]["multi_spec_cases"] == 1


def test_text_output_labels_truth_category(monkeypatch, capsys, mini_env):
    _, universe = mini_env
    monkeypatch.setattr(rmini, "load_truth_categories",
                        lambda: {c: "weakrand" for c in universe})
    monkeypatch.setattr(sys, "argv", ["reconcile_owasp_mini.py", "--task-id", "647",
                                     "--shard", "mini"])
    assert rmini.main() == 0
    out = capsys.readouterr().out
    assert "按真值 category" in out and "weakrand" in out
