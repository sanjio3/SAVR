"""D2 入口概率闸门（src/cli/benchmark_cli._d2_primitives_gate_impl）单测。

锁定三件事：分派阈值边界、无信号一律 full（保召回）、坏值不炸。
"""
from src.cli.benchmark_cli import _d2_primitives_gate_impl as gate


def _vuln(vp=None, **extra):
    if vp is None:
        return {"file": "T.java", "line": 1, "type": "sqli"}
    return {"file": "T.java", "line": 1, "type": "sqli",
            "exploit_spec": {"primitives": {"vuln": True, "vuln_prob": vp, **extra}}}


def test_no_signal_is_full():
    g = gate(_vuln())
    assert g["action"] == "full" and g["source"] == "none" and g["vuln_prob"] == 0.0


def test_empty_primitives_is_full():
    g = gate({"exploit_spec": {"primitives": {}}})
    assert g["action"] == "full"
    g2 = gate({"exploit_spec": {}})
    assert g2["action"] == "full"


def test_bad_value_is_full():
    g = gate(_vuln("not-a-number"))
    assert g["action"] == "full" and g["source"] == "none"
    g2 = gate({"exploit_spec": {"primitives": None}})
    assert g2["action"] == "full"
    g3 = gate({"exploit_spec": "garbage"})
    assert g3["action"] == "full"


def test_boundaries_default_thresholds():
    # 与 benchmark_cli 的应用默认一致：full=0.85 / skip=0.3
    # （skip 由 0.5 下调，run 465 A/B 实测 0.5 掉 TP 3 个）
    assert gate(_vuln(0.95), skip=0.3)["action"] == "full"
    assert gate(_vuln(0.85), skip=0.3)["action"] == "full"        # 边界含等于
    assert gate(_vuln(0.849), skip=0.3)["action"] == "canary_only"
    assert gate(_vuln(0.3), skip=0.3)["action"] == "canary_only"  # 边界含等于
    assert gate(_vuln(0.299), skip=0.3)["action"] == "skip"
    assert gate(_vuln(0.0), skip=0.3)["action"] == "skip"


def test_custom_thresholds():
    g = gate(_vuln(0.7), full=0.9, skip=0.6)
    assert g["action"] == "canary_only"
    assert gate(_vuln(0.7), full=0.9, skip=0.8)["action"] == "skip"
    assert gate(_vuln(0.7), full=0.5, skip=0.3)["action"] == "full"


def test_result_carries_thresholds_for_audit():
    g = gate(_vuln(0.4), full=0.85, skip=0.5)
    assert g["threshold_full"] == 0.85 and g["threshold_skip"] == 0.5
    assert g["source"] == "llm" and g["vuln_prob"] == 0.4
