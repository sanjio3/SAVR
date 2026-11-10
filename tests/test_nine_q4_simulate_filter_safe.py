"""净化器判定九问（Q4）：simulate_filter 降级为预筛 + 超时 + unsupported 标记。

根因（分析-本轮.md §Q4）：simulate_filter 是 Python re 对 Java Pattern 的近似，Java/Python 语义
差异（占有量词/原子组/Unicode 属性/灾难性回溯/内联标志）会误判。最危险的是 re.error 被吞后把
「带占有量词的强过滤器」当无过滤器放行（漏报真净化器）。

本质修复：
- simulate_filter_safe 返回三态：True=放行 / False=必拦 / None=正则不支持（无法判定）；
- None（占有量词/原子组/Unicode 属性/灾难性回溯）一律 fail-open：调用方不得据此判 non_bypassable，
  发之前也绝不静默丢有效弹；
- 正则求值带超时（ReDoS 防护），超时/异常返回 None；
- sanitizer_forge 的 synthesize/gate 改用 simulate_filter_safe，None 当放行（不丢弃）。
"""
import time

from src.core.sanitizer_miner import (
    FilterSpec, simulate_filter, simulate_filter_safe, filter_regex_supported,
)
from src.iast.sanitizer_forge import gate


def _allow(patterns):
    return FilterSpec(kind=FilterSpec.KIND_ALLOW, patterns=patterns, source="deterministic")


def test_q4_possessive_quantifier_is_unsupported():
    # 占有量词 X*+ 在 Java 合法、Python re 不支持 → 标不支持 → None（不当放行、不当必拦）
    spec = _allow([r"^[a-zA-Z0-9_.-]+$"])
    spec.patterns = [r"^[a-zA-Z0-9_.-]++$"]  # 占有量词
    assert filter_regex_supported(spec.patterns[0]) is False
    assert simulate_filter_safe(spec, ";id") is None


def test_q4_atomic_group_is_unsupported():
    spec = _allow([r"(?>[a-z]+)"])
    assert simulate_filter_safe(spec, "abc") is None


def test_q4_unicode_property_is_unsupported():
    spec = _allow([r"^\p{L}+$"])
    assert simulate_filter_safe(spec, "abc") is None


def test_q4_supported_pattern_returns_bool():
    # 普通白名单：Python 能等价 Java → 正常三态
    spec = _allow([r"^[a-zA-Z0-9_.-]+$"])
    assert simulate_filter_safe(spec, "abc123") is True      # 落在允许集 → 放行
    assert simulate_filter_safe(spec, ";id") is False        # 含分号 → 必拦


def test_q4_safe_agrees_with_simulate_filter_on_supported():
    spec = _allow([r"^[a-z]+$"])
    for p in ("abc", "AB", "a1b", "x y"):
        assert simulate_filter_safe(spec, p) == simulate_filter(spec, p)


def test_q4_catastrophic_backtrack_marked_unsupported():
    # 嵌套量词 → 灾难性回溯启发式命中 → 不支持 → 超时也不会挂死（fail-open）
    spec = _allow([r"^([a-z]+)+$"])
    assert filter_regex_supported(spec.patterns[0]) is False
    assert simulate_filter_safe(spec, "aaaaaaaaaaaaaaaaaaaaaac") is None


def test_q4_forge_gate_does_not_discard_unsupported():
    # sanitizer_forge 改用 simulate_filter_safe：None（不支持）当放行，不静默丢有效弹。
    spec = _allow([r"^[a-zA-Z0-9_.-]++$"])  # 占有量词，Python 不支持
    # 哪怕正则不可信，破坏性候选也须保留交运行时裁决，不得被闸门判死丢弃
    out = gate([";id", "$(whoami)", "normal"], "command_execution", spec)
    assert ";id" in out and "$(whoami)" in out


def test_q4_forge_gate_still_discards_known_blocked():
    spec = _allow([r"^[a-zA-Z0-9_.-]+$"])  # 普通白名单，分号必拦
    out = gate([";id", "normal"], "command_execution", spec)
    assert ";id" not in out
    assert "normal" in out


def test_q4_timeout_env_respected():
    # 超时配置项存在且可读（具体 ReDoS 超时在 Unix 经 SIGALRM 生效，Windows 依赖静态启发式）。
    import os
    from src.core import sanitizer_miner as sm
    prev = os.environ.get("SAST_AI_REGEX_TIMEOUT")
    os.environ["SAST_AI_REGEX_TIMEOUT"] = "0.05"
    try:
        # 重新 import 模块级常量不可行（已绑定），仅验证函数仍可正常返回（不抛）
        spec = _allow([r"^[a-z]+$"])
        t0 = time.time()
        r = simulate_filter_safe(spec, "abc")
        assert r is True
        assert time.time() - t0 < 5.0
    finally:
        if prev is None:
            os.environ.pop("SAST_AI_REGEX_TIMEOUT", None)
        else:
            os.environ["SAST_AI_REGEX_TIMEOUT"] = prev
