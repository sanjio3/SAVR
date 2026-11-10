"""泛化比较工具读取预登记例外的回归锁（2026-11-07）。

历史缺陷：tools/generalization_compare.py 硬判 `fp_replay == 0`，完全不读
config/generalization.yaml 的 execution.pre_registered_exceptions。Gate 0 已
批准的 L1_log4j_xss 例外在官方工具里仍显示「红线误报 未通过（1 条）」，
发布对账口径与闸门口径互相打架。

例外必须满足：按当前 mode 的层匹配、按 (basename, family) 匹配、
按 spec 条数卡 max_count_per_round。

2026-11-08 评审通过口径变更：本轮（L3 run1）实测复现了同一条已披露
限制，原「不外溢到 L3 / L2」的隐含假设被证伪，例外范围扩到 L3_stability。
L2_cross_target 仍绝对不放行；L3 下也必须继续严格匹配特征、每轮 1 条上限，
且其他任何新红线照旧停链。见 docs/l3_run1_reconciliation.md。
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "tools") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "tools"))
import generalization_compare as G  # noqa: E402


CONFIG = os.path.join(ROOT, "config", "generalization.yaml")


def _exceptions():
    return G.load_pre_registered_exceptions(CONFIG)


def _var(items):
    keys = sorted({(str(a), str(b)) for a, b in items})
    return {
        "task_id": 635,
        "truth": "java_sec_code_truth_v2.csv",
        "denominator": 24,
        "static_fam": 29,
        "dyn_fam": 20,
        "rep_fam": 19,
        "strict_replay": 19,
        "confirmed": 51,
        "replay": 39,
        "fp_confirmed": 5,
        "fp_replay": len(items),
        "fp_replay_keys": keys,
        "fp_replay_items": [(str(a), str(b)) for a, b in items],
        "hits": {"rep_fam": []},
        "strict_hits": [],
        "attrib": {},
        "rules": {},
    }


def test_real_config_loads_l1_exception():
    exs = _exceptions()
    assert len(exs) == 1
    ex = exs[0]
    assert ex["id"] == "L1_log4j_xss"
    assert ex["match"]["applies_to"] == ["L1_blind_route", "L3_stability"]
    assert ex["match"]["file_basename"] == "log4j.java"
    assert ex["match"]["family"] == "xss"
    assert ex["max_count_per_round"] == 1


def test_missing_config_fails_closed():
    assert G.load_pre_registered_exceptions(os.path.join(ROOT, "no-such-file.yaml")) == []


def test_blind_mode_redline_cleared_by_exception():
    var = _var([("log4j.java", "xss")])
    out = G.apply_pre_registered_exceptions(var, "blind", _exceptions())
    assert out["layer"] == "L1_blind_route"
    assert out["fp_replay_effective"] == 0
    assert out["violations"] == []
    assert len(out["matched"]) == 1
    assert out["matched"][0]["id"] == "L1_log4j_xss"


def test_exception_never_leaks_to_cross_target():
    var = _var([("log4j.java", "xss")])
    out = G.apply_pre_registered_exceptions(var, "cross-target", _exceptions())
    assert out["layer"] == "L2_cross_target"
    assert out["fp_replay_effective"] == 1
    assert out["matched"] == []


def test_cap_enforced_per_spec_not_per_key():
    var = _var([("log4j.java", "xss"), ("log4j.java", "xss")])
    assert len(var["fp_replay_keys"]) == 1  # 去重键只有 1 个
    out = G.apply_pre_registered_exceptions(var, "blind", _exceptions())
    assert out["fp_replay_effective"] == 1, "第 2 条同特征红线必须留下"
    assert len(out["violations"]) == 1
    assert "max_count_per_round" in out["violations"][0]


def test_unmatched_redline_still_blocks():
    var = _var([("log4j.java", "xss"), ("foo.java", "sql_injection")])
    out = G.apply_pre_registered_exceptions(var, "blind", _exceptions())
    assert out["fp_replay_effective"] == 1
    assert out["effective_keys"] == [("foo.java", "sql_injection")]


def test_no_exceptions_keeps_legacy_behaviour():
    var = _var([("log4j.java", "xss")])
    out = G.apply_pre_registered_exceptions(var, "blind", [])
    assert out["fp_replay_effective"] == 1
    assert out["matched"] == []


def test_render_reports_pass_with_approved_exception():
    var = _var([("log4j.java", "xss")])
    var["exceptions"] = G.apply_pre_registered_exceptions(var, "blind", _exceptions())
    text = G.render(None, var, "blind")
    assert "L1_log4j_xss 放行 log4j.java/xss" in text
    assert "原始 1 条 → 有效 0 条，通过" in text
    assert "未通过" not in text


def test_render_reports_fail_without_exception():
    var = _var([("log4j.java", "xss")])
    var["exceptions"] = G.apply_pre_registered_exceptions(var, "cross-target", _exceptions())
    text = G.render(None, var, "cross-target")
    assert "有效 1 条，未通过" in text


def test_render_reports_fail_on_cap_violation():
    var = _var([("log4j.java", "xss"), ("log4j.java", "xss")])
    var["exceptions"] = G.apply_pre_registered_exceptions(var, "blind", _exceptions())
    text = G.render(None, var, "blind")
    assert "[违规]" in text
    assert "有效 1 条，未通过" in text


def test_stability_mode_redline_cleared_by_same_known_limitation():
    """L3 放行的是同一条已批准限制，不是新增例外。"""
    var = _var([("log4j.java", "xss")])
    out = G.apply_pre_registered_exceptions(var, "stability", _exceptions())
    assert out["layer"] == "L3_stability"
    assert out["fp_replay_effective"] == 0
    assert out["violations"] == []
    assert out["matched"][0]["id"] == "L1_log4j_xss"


def test_cap_still_enforced_in_stability():
    """L3 每轮仍最多放行 1 条，第 2 条按新红线处理。"""
    var = _var([("log4j.java", "xss"), ("log4j.java", "xss")])
    out = G.apply_pre_registered_exceptions(var, "stability", _exceptions())
    assert out["fp_replay_effective"] == 1
    assert len(out["violations"]) == 1


def test_other_new_redline_still_blocks_in_stability():
    """扩范围不得掩盖 L3 的其他新红线。"""
    var = _var([("log4j.java", "xss"), ("foo.java", "sql_injection")])
    out = G.apply_pre_registered_exceptions(var, "stability", _exceptions())
    assert out["fp_replay_effective"] == 1
    assert out["effective_keys"] == [("foo.java", "sql_injection")]


def test_render_reports_pass_with_approved_exception_in_stability():
    var = _var([("log4j.java", "xss")])
    var["exceptions"] = G.apply_pre_registered_exceptions(var, "stability", _exceptions())
    text = G.render(None, var, "stability")
    assert "L1_log4j_xss 放行 log4j.java/xss" in text
    assert "原始 1 条 → 有效 0 条，通过" in text
