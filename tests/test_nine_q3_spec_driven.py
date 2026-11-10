"""净化器判定九问（Q3）单测：候选池接规格驱动生成器（感知 filter_spec）。"""
from __future__ import annotations

from src.core.sanitizer_miner import FilterSpec
from src.iast.sanitizer_forge import synthesize, _spec_driven_candidates


def test_q3_deny_case_sensitive_yields_case_mutated_survivor():
    # 黑名单大小写敏感（case_sensitive=True）且只有 'script' token：大小写变异可绕过 → 应成为候选
    spec = FilterSpec(FilterSpec.KIND_DENY, tokens=["script"], case_sensitive=True, source="deterministic")
    out = _spec_driven_candidates(spec, "xss")
    assert any("SCRIPT" in c for c in out), out
    cands = synthesize(spec, "xss")["candidates"]
    assert any("SCRIPT" in c for c in cands), cands


def test_q3_allow_overwide_whitelist_yields_fitting_candidate():
    # 白名单过宽（允许 ';'）：规格驱动探针串整串落入允许集 → 成为候选（探测白名单过宽）
    spec = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["^[a-zA-Z0-9;]+$"], source="deterministic")
    cands = synthesize(spec, "command_execution")["candidates"]
    # 至少应有静态种子 ';id' 或规格驱动探针串落入
    assert any(";" in c for c in cands), cands


def test_q3_narrow_allow_whitelist_blocks_all_exploit_seeds():
    # 极窄白名单 [abc]：真实利用串（含 ';' 等注入语法）全被拦，verdict 仍判 non_bypassable，
    # 不误判可绕过；仅剩的「白名单拟合探针」是 benign 探测串，不含注入语法。
    spec = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["^[abc]+$"], source="deterministic")
    res = synthesize(spec, "command_execution")
    # 不应有任何含注入语法的真实利用串幸存
    assert not any(";" in c or "'" in c for c in res["candidates"]), res["candidates"]
    from src.core.filter_verdict import classify
    v = classify(spec, "command_execution")
    assert v["verdict"] == "non_bypassable", v


def test_q3_static_pool_still_bootstrap_when_no_spec():
    # 无 spec 时静态池仍作 bootstrap
    out = _spec_driven_candidates(None, "command_execution")
    assert any("id" in c for c in out)
