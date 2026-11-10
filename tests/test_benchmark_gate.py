"""OWASP Benchmark 对账门槛的单测（tools/benchmark_gate.py）。

只测纯逻辑（metrics / run / compare），不依赖 DB 与真实扫描任务，
保证门槛本身不会因为环境变化而静默失效。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.benchmark_gate import (  # noqa: E402
    compare, metrics, run, FAMILY_MAP,
)


def _case(tp, fp, tn, fn):
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": 0.5, "fpr": 0.5, "precision": 0.5, "f1": 0.5, "score": 0.0}


def test_metrics_basic():
    m = metrics(30, 18, 81, 76)
    assert m["tp"] == 30 and m["fp"] == 18 and m["tn"] == 81 and m["fn"] == 76
    # 205 用例里 106 真漏洞、99 假阳性
    assert abs(m["tpr"] - 30 / 106) < 1e-3
    assert abs(m["fpr"] - 18 / 99) < 1e-3


def test_metrics_zero_division_safe():
    m = metrics(0, 0, 0, 0)
    assert m["tpr"] == 0.0 and m["fpr"] == 0.0 and m["precision"] == 0.0 and m["f1"] == 0.0


def test_strict_requires_family_match():
    """用例被报但族名不匹配 -> 严格口径不算 TP。这是双口径的核心差异。"""
    truth = {
        "BenchmarkTest00001": {"category": "pathtraver", "real": True},
        "BenchmarkTest00002": {"category": "xss", "real": True},
    }
    # 00001 是 pathtraver，却被报成 XSS；00002 是 xss，报成 XSS
    per = {
        "BenchmarkTest00001": [{"blob": "xss response.getwriter 直出", "type": "XSS"}],
        "BenchmarkTest00002": [{"blob": "xss response.getwriter 直出", "type": "XSS"}],
    }
    loose, _ = run(truth, per, strict=False)
    strict, _ = run(truth, per, strict=True)
    assert loose["tp"] == 2          # 宽松：两个都被报
    assert strict["tp"] == 1         # 严格：只有族名对上的 00002
    assert strict["fn"] == 1


def test_unmapped_category_never_counts():
    """类别不在族名映射表里时，严格口径恒为 0。

    防御意义：新增类别却忘了配 FAMILY_MAP 时，不会因"用例被报了"就虚增 TP。
    2026-09-24 之前 crypto/hash/weakrand/securecookie/trustbound 正是映射为空、
    严格口径 TPR 恒 0 的状态；它们现已补上规则，故这里改用未映射类别来验证语义。
    """
    truth = {"BenchmarkTest00003": {"category": "some_unmapped_category", "real": True}}
    per = {"BenchmarkTest00003": [{"blob": "xss 直出", "type": "XSS"}]}
    strict, _ = run(truth, per, strict=True)
    assert strict["tp"] == 0
    assert strict["fn"] == 1


def test_five_former_gap_categories_now_mapped():
    """曾经的五个能力空白类别必须都有族名映射，防止有人误删回退到全 0。"""
    for cat in ("crypto", "hash", "weakrand", "securecookie", "trustbound"):
        assert FAMILY_MAP.get(cat), f"{cat} 的族名映射不应为空"


def _l2(tpr=0.5, fpr=0.2, score=0.3):
    return {"tpr": tpr, "fpr": fpr, "score": score,
            "tp": 0, "fp": 0, "tn": 0, "fn": 0, "precision": 0.5, "f1": 0.5}


def _res(count, loose_fpr, strict_tpr, strict_score, l2_tpr, l2_score,
         redline=None):
    """按 compare 的真实消费面构造一个 evaluate 结果。

    2026-10-04 起 compare 的主判据改为 L2 确认层，所以 res/base 都要带 l2_* 与 redline，
    否则会走 SKIP 分支而不是真的比对（正是这里要防的「静默不判定」）。
    """
    return {
        "file_count": count,
        "loose": {"fpr": loose_fpr, "score": strict_score, "tpr": 0.7},
        "strict": {"tpr": strict_tpr, "score": strict_score},
        "l2_loose": _l2(),
        "l2_strict": _l2(tpr=l2_tpr, score=l2_score),
        "redline": redline or {"actual": 10, "limit": 65, "fp_basis": 99,
                               "ratio": 0.66, "pass": True},
    }


def test_compare_pass_on_identical():
    res = _res(232, 0.6465, 0.3396, 0.1477, 0.5, 0.3)
    ok, lines = compare(res, res)
    assert ok is True
    assert any("OK" in ln for ln in lines)


def test_compare_fail_on_l2_strict_score_drop():
    """主判据已改为 L2 确认层（2026-10-04）：L2 严格 Score 回落超容差即 FAIL。"""
    base = _res(232, 0.6465, 0.3396, 0.1477, 0.5000, 0.3000)
    cur = _res(232, 0.9495, 0.2830, 0.1012, 0.4535, 0.2535)  # L2 Score -4.65pp
    ok, lines = compare(cur, base)
    assert ok is False
    assert any("严格 Score(L2)" in ln and "FAIL" in ln for ln in lines)


def test_compare_fail_on_l2_tpr_drop():
    base = _res(232, 0.6465, 0.3396, 0.1477, 0.5000, 0.3000)
    cur = _res(232, 0.6465, 0.3396, 0.1477, 0.4600, 0.3000)  # L2 TPR -4pp > 3pp
    ok, lines = compare(cur, base)
    assert ok is False
    assert any("严格 TPR(L2)" in ln and "FAIL" in ln for ln in lines)


def test_compare_fail_on_fake_confirm_redline():
    """假确认红线破线即 FAIL —— 这是「不许靠无差别确认刷召回」的闸门。"""
    base = _res(232, 0.6465, 0.3396, 0.1477, 0.5, 0.3)
    cur = _res(232, 0.6465, 0.3396, 0.1477, 0.5, 0.3,
               redline={"actual": 70, "limit": 65, "fp_basis": 99,
                        "ratio": 0.66, "pass": False})
    ok, lines = compare(cur, base)
    assert ok is False
    assert any("假确认红线" in ln and "FAIL" in ln for ln in lines)


def test_l1_regression_is_observation_only():
    """L1 检出层劣化不再判 FAIL（2026-09-28 批准口径：L1 只作过程观测）。

    这条是防止有人把 L1 噪声判据偷偷加回来 —— 那会与「一把尺子管验收」的决议冲突。
    """
    base = _res(232, 0.6061, 0.7075, 0.5156, 0.5, 0.3)
    cur = _res(232, 0.8788, 0.9623, 0.2653, 0.5, 0.3)  # L1 FPR +27pp、Score -25pp
    ok, lines = compare(cur, base)
    assert ok is True
    assert any("obs" in ln and "宽松 FPR(L1)" in ln for ln in lines)


def test_compare_without_l2_data_skips_l2_check():
    """基线/本轮缺 L2 数据时必须显式 SKIP，不能静默当成 0 去比对（会误判 FAIL）。"""
    old = {"file_count": 232,
           "loose": {"fpr": 0.6465, "score": 0.0988, "tpr": 0.7453},
           "strict": {"tpr": 0.3396, "score": 0.1477}}
    ok, lines = compare(dict(old), old)
    assert ok is True
    assert any("SKIP" in ln for ln in lines)


if __name__ == "__main__":
    import traceback
    fns = [(n, o) for n, o in sorted(globals().items()) if n.startswith("test_") and callable(o)]
    failed = 0
    for n, fn in fns:
        try:
            fn()
            print(f"  PASS  {n}")
        except Exception:
            failed += 1
            print(f"  FAIL  {n}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
