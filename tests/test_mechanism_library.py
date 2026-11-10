"""2026-10-02：机制表（库内置闸门）加载、匹配与约束求交回归测试。

要点：机制表记的是「门在哪、默认开不开、怎么关、依赖什么」，**不是绕过列表**；
绕过列表会无限膨胀，而闸门是稳定的。新漏洞尽量从机器可读数据源（OSV/GHSA/NVD）自动更新。
"""

import pytest

from src.core.mechanism_library import (
    DEFAULT_LIBRARY_PATH, intersect, load_mechanisms, lookup, to_filter_spec,
)
from src.core.sanitizer_miner import FilterSpec


def test_library_file_exists():
    import os
    assert os.path.isfile(DEFAULT_LIBRARY_PATH)


def test_load_returns_entries():
    mechs = load_mechanisms()
    assert mechs, "机制表为空"


def test_lookup_fastjson_modern_version():
    hits = lookup("com.alibaba:fastjson", "1.2.68")
    assert hits, "fastjson 1.2.68 未命中机制条目"
    ids = [m.get("id") for m in hits]
    assert any("modern" in str(i) for i in ids)


def test_lookup_fastjson_legacy_and_cache_bypass():
    assert any("legacy" in str(m.get("id")) for m in lookup("com.alibaba:fastjson", "1.2.24"))
    assert any("cache" in str(m.get("id")) for m in lookup("com.alibaba:fastjson", "1.2.30"))


def test_lookup_unknown_package_is_empty():
    assert lookup("no.such:package", "1.0.0") == []


def test_to_filter_spec_maps_kind():
    m = {"id": "x", "kind": "deny", "deny_tokens": [";", "|"], "notes": ""}
    spec = to_filter_spec(m)
    assert spec is not None and spec.kind == FilterSpec.KIND_DENY
    assert ";" in spec.tokens and "|" in spec.tokens


def test_intersect_deny_union():
    a = FilterSpec(FilterSpec.KIND_DENY, tokens=[";"])
    b = FilterSpec(FilterSpec.KIND_DENY, tokens=["|"])
    merged = intersect([a, b])
    assert merged is not None and merged.kind == FilterSpec.KIND_DENY
    assert ";" in merged.tokens and "|" in merged.tokens


def test_intersect_allow_is_strictest():
    wide = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["^[a-zA-Z0-9_/.-]+$"])
    narrow = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["^[a-z]+$"])
    merged = intersect([wide, narrow])
    assert merged is not None and merged.kind == FilterSpec.KIND_ALLOW
    assert merged.patterns == ["^[a-z]+$"]


def test_intersect_empty_is_none():
    assert intersect([]) is None
    assert intersect([None]) is None
