"""净化器判定九问（Q1/Q2）单测：实证判定 + 归一化/正则感知 + 删裸空格。"""
from __future__ import annotations

from src.core.sanitizer_miner import FilterSpec
from src.core.filter_verdict import (
    classify, VERDICT_NON_BYPASSABLE, VERDICT_BYPASSABLE, VERDICT_UNDETERMINED,
    FAMILY_REQUIRED,
)
from src.core.sanitizer_miner import simulate_filter_safe, filter_regex_supported


def _allow(pat: str, **kw) -> FilterSpec:
    return FilterSpec(FilterSpec.KIND_ALLOW, patterns=[pat], source="deterministic", **kw)


def _deny(tokens, **kw) -> FilterSpec:
    return FilterSpec(FilterSpec.KIND_DENY, tokens=list(tokens), source="deterministic", **kw)


def test_q1_allow_whitelist_blocks_all_exploit_strings_is_non_bypassable():
    # java-sec-code 命令注入白名单：拦下全部命令利用串 → 真净化器
    spec = _allow("^[a-zA-Z0-9_.-]+$")
    v = classify(spec, "command_execution")
    assert v["verdict"] == VERDICT_NON_BYPASSABLE, v
    assert v.get("confidence") == "high"


def test_q1_sqli_whitelist_is_non_bypassable():
    spec = _allow("^[a-zA-Z0-9_/.\\-]+$")
    v = classify(spec, "sqli")
    assert v["verdict"] == VERDICT_NON_BYPASSABLE, v


def test_q1_normalization_guard_never_non_bypassable():
    # 守卫含 Normalizer.normalize → 静态字符集无法覆盖，fail-open 到 undetermined
    spec = _allow("^[a-zA-Z0-9]+$", has_normalization=True)
    v = classify(spec, "command_execution")
    assert v["verdict"] == VERDICT_UNDETERMINED, v


def test_q1_decode_first_never_non_bypassable():
    spec = _allow("^[a-zA-Z0-9]+$", decode_first=True)
    v = classify(spec, "command_execution")
    assert v["verdict"] == VERDICT_UNDETERMINED, v


def test_q4_possessive_quantifier_regex_unsupported():
    # 占有量词 X*+ Java 支持、Python re 不支持 → simulate_filter_safe 返回 None
    assert filter_regex_supported("^[a-zA-Z0-9]++$") is False
    spec = _allow("^[a-zA-Z0-9]++$")
    assert simulate_filter_safe(spec, "abc") is None
    v = classify(spec, "command_execution")
    assert v["verdict"] == VERDICT_UNDETERMINED, v


def test_q4_atomic_group_regex_unsupported():
    assert filter_regex_supported("(?>a+)") is False
    assert filter_regex_supported("\\p{L}") is False


def test_q2_sqli_bare_space_removed_from_required():
    # Q2：空格(" ")不再是 sqli 的独立可满足 token
    assert " " not in FAMILY_REQUIRED["sqli"], FAMILY_REQUIRED["sqli"]


def test_q2_allow_set_with_space_but_blocks_quote_is_non_bypassable_not_false_bypassable():
    # 允许集含空格但拦了引号 → 旧逻辑会把空格当 expressible 误判 bypassable（假阳性）；
    # 现空格已从 FAMILY_REQUIRED 删除，且 verdict 只认利用串实证，应判 non_bypassable（无候选时）。
    spec = _allow("^[a-zA-Z0-9_/.\\- ]+$")  # 含空格
    v = classify(spec, "sqli", candidates=None)
    # 利用串 ' OR 1=1-- 含引号/空格，不在允许集 → 全拦 → non_bypassable
    assert v["verdict"] == VERDICT_NON_BYPASSABLE, v


def test_q2_exploit_string_passes_whitelist_is_not_non_bypassable():
    # 白名单过宽：命令注入白名单允许 ';' → 利用串 ;id 可整串落入 → 不判终态
    spec = _allow("^[a-zA-Z0-9;]+$")
    v = classify(spec, "command_execution", candidates=None)
    assert v["verdict"] != VERDICT_NON_BYPASSABLE, v
    assert v["verdict"] == VERDICT_UNDETERMINED, v


def test_q1_deny_blacklist_blocks_all_exploit_strings_is_non_bypassable():
    # XSS 黑名单覆盖 < > javascript: → 利用串全含其一（含 javascript: URI）→ 全拦 → non_bypassable
    spec = _deny(["<", ">", "javascript:"])
    v = classify(spec, "xss")
    assert v["verdict"] == VERDICT_NON_BYPASSABLE, v


def test_q1_deny_blacklist_misses_variant_is_undetermined_not_non_bypassable():
    # 黑名单 token 只覆盖 '<script>'，但 <img onerror=...> 不含该 token → 不能判终态
    spec = _deny(["<script>"])
    v = classify(spec, "xss")
    assert v["verdict"] == VERDICT_UNDETERMINED, v


def test_q1_xss_deny_token_blocks_script_exploit():
    spec = _deny(["<"])
    assert simulate_filter_safe(spec, "<script>alert(1)</script>") is False
    assert simulate_filter_safe(spec, "javascript:alert(1)") is True  # 不含 '<' → 过（正确）
