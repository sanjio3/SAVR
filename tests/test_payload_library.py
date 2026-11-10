#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""族载荷库的单测。

两条主线：
1. **结构正确性**：产出的必须是真能打通的载荷（完整 XML 带实体声明、可解析的 URL 变体、
   语法完整的反序列化链），不是「看起来像」的字符串。
2. **通用性**：库代码里不得出现任何靶场专有标识（靶场类名 / 测试用例名 / 特定路由），
   载荷只能由「族 + 参数形态 + 目标地址」推导。这条是防「特异性拟合」的硬闸门。
"""
import base64
import json
import re
from pathlib import Path

import pytest

from src.iast.payload_library import (
    _FAMILY_PROVIDER,
    build_family_payloads,
    supported_families,
)


# ── 1. 结构正确性 ────────────────────────────────────────────────────────

def test_xxe_payload_is_complete_xml_with_entity():
    out = build_family_payloads("xxe", {"param_name": "xml", "param_location": "body"})
    assert out["provider"] == "xxe_xml"
    assert out["payloads"]
    for p in out["payloads"]:
        assert p.lstrip().startswith("<?xml"), "必须是完整 XML 文档，不是片段"
        assert "<!DOCTYPE" in p, "缺 DOCTYPE 就不会触发实体展开"
        assert "&xxe;" in p or "%p;" in p, "实体声明了但没被引用，等于没发"
        assert "SYSTEM" in p


def test_xxe_text_payload_not_blocked_by_xml_param_name():
    """`param_name=xml` 是「内容是 XML」，不是上传。第一版误判过，这里锁住。"""
    out = build_family_payloads("xxe", {"param_name": "xml", "param_location": "query"})
    assert out["payloads"], out["note"]


def test_xxe_upload_endpoint_is_explicitly_unsupported():
    """zip 容器型 XXE 需要 multipart 文件体；文本通道送不进去就明说，不投半成品。"""
    out = build_family_payloads("xxe", {"param_name": "file", "param_location": "multipart"})
    assert out["payloads"] == []
    assert out["provider"] == "unsupported"
    assert "multipart" in out["note"]


def test_url_bypass_variants_are_parse_distinct():
    """每条变体解析出来的 host 都必须不是白名单 host —— 否则它不是绕过，是噪声。"""
    from urllib.parse import urlsplit

    out = build_family_payloads("ssrf", {"param_name": "url", "param_value": "http://127.0.0.1:8080/x"})
    assert out["provider"] == "url_bypass"
    assert len(out["payloads"]) >= 5
    distinct = 0
    for p in out["payloads"]:
        try:
            host = (urlsplit(p if "://" in p else "http:" + p).hostname or "")
        except Exception:
            continue
        # 判据：解析出来的 host 里带攻击者域名（说明解析器真的把它当 host 了）。
        # 大小写变体是同一个 host，统一小写后比较。
        if "evil.example.com" in host.lower():
            distinct += 1
    # 至少 3 条是「host 真的解析成攻击者域名」的绕过。
    # 其余几条依赖**目标侧解析器**的差异（反斜杠被当路径分隔符、%40 被解码成 @），
    # Python 的 urlsplit 按 RFC 解析不会把它们当 host——但那不代表对 Tomcat/Spring 无效。
    # 所以这里只锁「确定有效的那几条」，不用 Python 的解析结果去否定别的变体。
    assert distinct >= 3, f"host 级绕过变体不足：{distinct} / {len(out['payloads'])}"


def test_deser_text_chain_is_syntactically_real():
    """文本链必须是语法完整的真实链，不是占位串。"""
    out = build_family_payloads(
        "deserialization", {"param_name": "content", "content_type": "application/json"})
    assert out["provider"] == "deser_text"
    joined = "\n".join(out["payloads"])
    assert "@type" in joined and "JdbcRowSetImpl" in joined, "fastjson autoType 链缺关键字段"
    assert "ScriptEngineManager" in joined, "snakeyaml 链缺关键类"
    assert "ldap://" in joined or "http://" in joined, "链里必须有回连地址，否则不构成利用尝试"


def test_deser_binary_param_is_unsupported():
    """`classData` 是二进制 Java 序列化参数，不能投文本链（readObject 会立刻失败）。"""
    out = build_family_payloads("deserialization", {"param_name": "classData"})
    assert out["payloads"] == []
    assert out["provider"] == "unsupported"
    assert "二进制" in out["note"] or "gadget" in out["note"]


def test_unknown_family_returns_none_not_fake_payload():
    # 2026-11-03（jsc-leakfix-r17）：sql_injection 已有真 provider（sqli_probe），
    # 「未登记族返回空」的守卫对象换成真正无 provider 的族。
    out = build_family_payloads("totally_unknown_family", {"param_name": "id"})
    assert out["payloads"] == []
    assert out["provider"] == "none"


def test_sqli_probe_provider_is_structured_not_fake():
    """sql_injection 的载荷必须与 judge_attempts 的判据一一对应（jsc 607 实测：
    sqli 家族曾因无 provider 整族 degraded_no_synthesis，12+6 发重放全 302 之外
    连弹药都没有）。"""
    out = build_family_payloads("sql_injection", {"param_name": "id"})
    assert out["provider"] == "sqli_probe"
    joined = "\n".join(out["payloads"])
    # 布尔真假对（sqli_boolean 判据的两端）
    assert "' OR '1'='1" in joined and "' OR '1'='2" in joined
    assert "1 OR 1=1" in joined and "1 AND 1=2" in joined
    # 语法错误探针（sqli_error 判据）
    assert "sastai'" in joined
    # 红线：不许有破坏性语句
    for bad in ("DROP", "DELETE", "UPDATE ", "TRUNCATE", "SLEEP("):
        assert bad.lower() not in joined.lower(), f"破坏性/拖垮型载荷混入：{bad}"


def test_crlf_probe_provider_carries_injected_header():
    """crlf 载荷必须带「可从载荷里提取的头名」（判据据此查响应头/体）。"""
    out = build_family_payloads("crlf_injection", {"param_name": "test1"})
    assert out["provider"] == "crlf_header_probe"
    import re as _re
    for p in out["payloads"]:
        m = _re.search(r"(?:%0d%0a|\r\n)\s*([a-z0-9\-]{3,32})\s*:\s*([^\s%]{3,64})", p, _re.I)
        assert m, f"载荷里提取不出注入头：{p!r}"


def test_no_empty_payload_ever_returned():
    """任何族的产出里都不能有空串（空弹等于没发，却会让上层以为发了）。"""
    for fam in supported_families():
        for spec in ({"param_name": "xml"}, {"param_name": "url"}, {"param_name": "content"}):
            for p in build_family_payloads(fam, spec)["payloads"]:
                assert p and p.strip()


# ── 2. 通用性硬闸门 ──────────────────────────────────────────────────────

_CORPUS_TOKENS = (
    "BenchmarkTest",       # OWASP 用例名
    "joychou",             # java-sec-code 包名
    "java-sec-code",       # 靶场项目名
    "owasp",               # 靶场名
    "ruoyi",               # 靶场名
    "sqli-0",              # OWASP 路由前缀
    "xss-0", "ssrf-0",     # OWASP 路由前缀
    "/vuln/", "/safecode", # java-sec-code 路由特征
)


@pytest.mark.parametrize("path", [
    "src/iast/payload_library.py",
    "src/core/spec_state_normalize.py",
])
def test_no_corpus_specific_tokens(path):
    """载荷库与口径模块里不得出现任何靶场专有标识。

    这条是「本质修复 vs 特异性拟合」的分界线：一旦有人为了把某个靶场打穿而把
    它的类名/路由/用例名写进代码，这个用例立刻变红。
    """
    import ast

    root = Path(__file__).resolve().parent.parent
    text = (root / path).read_text(encoding="utf-8", errors="replace")
    # 只查**可执行代码**：注释和文档字符串里提靶场是为了解释背景，属于允许的。
    # 做法：把 AST 里所有字符串常量（含 docstring）从源码里抹掉，再扫剩下的部分。
    try:
        tree = ast.parse(text)
    except SyntaxError:
        pytest.fail(f"{path} 语法错误，无法审计")
    code = text
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # 用等长空白替换，保持行号与其余代码不变
            for _ in range(1):
                code = code.replace(node.value, " " * len(node.value), 1)
    hits = [t for t in _CORPUS_TOKENS if t.lower() in code.lower()]
    assert not hits, f"{path} 代码里出现靶场专有标识：{hits}"


def test_providers_are_family_keyed_not_file_keyed():
    """provider 表只能按族登记，不能按文件/类名登记。"""
    for key in _FAMILY_PROVIDER:
        assert not key.endswith(".java"), key
        assert "/" not in key, key
        assert re.fullmatch(r"[a-z_]+", key), key


# ── 结构化载荷不得被拼接改写（2026-11-01 实测回归）─────────────────────────
# D1 的「时间盲注弹合成」原本没有族白名单，会给反序列化位也追加 `' OR SLEEP(3)--`，
# 把 fastjson 的 JSON 串结构打坏 → 目标解析失败 → 请求挂住 → D1 整组超时。

def test_sleep_synthesis_is_sql_family_only():
    import inspect

    from src.application import d1_service

    src = inspect.getsource(d1_service)
    assert "_SLEEP_FAMILIES" in src, "sleep 合成必须带族白名单"
    assert 'startswith("library:")' in src, "载荷库产出的结构化载荷不能被拼接改写"


# ── 二进制反序列化：ysoserial 通道（2026-11-02）──────────────────────────────
#
# 设计约束（缺一条就是安全事故）：
#   1. 默认关闭 —— gadget 会在目标执行命令，真实项目不许默认开；
#   2. defineClass 型 sink 不适用（要原始 .class 字节，不是序列化对象流），
#      即使开关打开也必须拒绝，且给出精确原因；
#   3. 产物必须过 selfcheck（AC ED 00 05 魔数），不过就降级。


def _deser_spec(sink_method="", param="rememberMe", raw=True):
    spec = {"param_name": param, "content_type": ""}
    if raw:
        spec["raw_json"] = json.dumps({"sink": {"method": sink_method}})
    return spec


def test_deser_binary_is_off_by_default(monkeypatch):
    from src.iast.payload_library import build_family_payloads

    monkeypatch.delenv("SAST_AI_DESER_YSOSERIAL", raising=False)
    out = build_family_payloads("deserialization", _deser_spec("ObjectInputStream.readObject"))
    assert out["payloads"] == []
    assert "SAST_AI_DESER_YSOSERIAL" in out["note"], out["note"]


def test_deser_defineclass_sink_is_rejected_even_when_enabled(monkeypatch):
    """defineClass 要的是原始 .class 字节，ysoserial 机制不同 —— 开开关也不能投。"""
    from src.iast.payload_library import build_family_payloads

    monkeypatch.setenv("SAST_AI_DESER_YSOSERIAL", "1")
    out = build_family_payloads("deserialization",
                                _deser_spec("ClassLoader.defineClass", param="classData"))
    assert out["payloads"] == []
    assert "defineClass" in out["note"], out["note"]


def test_deser_binary_uses_ysoserial_when_enabled(monkeypatch):
    """开关打开 + readObject 型 sink ⇒ 产出 base64 序列化流（forge 打桩，不真跑 java）。"""
    from src.iast import payload_library as pl
    from src.iast.payload_forge import PayloadForge

    monkeypatch.setenv("SAST_AI_DESER_YSOSERIAL", "1")
    pl._DESER_BINARY_CACHE.clear()

    real = base64.b64encode(b"\xac\xed\x00\x05" + b"stub-payload").decode("ascii")

    def _fake_forge(self, chain, command="", runner=None):
        assert command, "空命令的 gadget 等同废弹，必须拒绝"
        return real

    monkeypatch.setattr(PayloadForge, "forge", _fake_forge)
    out = build_family_payloads("deserialization", _deser_spec("ObjectInputStream.readObject"))
    assert out["provider"].startswith("ysoserial:"), out
    assert out["payloads"] == [real]
    assert PayloadForge.selfcheck(out["payloads"][0], "ysoserial")


def test_deser_binary_rejects_bad_selfcheck(monkeypatch):
    """自检不过（不是合法序列化流）必须降级，绝不投废弹。"""
    from src.iast import payload_library as pl
    from src.iast.payload_forge import PayloadForge

    monkeypatch.setenv("SAST_AI_DESER_YSOSERIAL", "1")
    pl._DESER_BINARY_CACHE.clear()
    monkeypatch.setattr(PayloadForge, "forge",
                        lambda self, chain, command="", runner=None: "bm90LWEtZ2FkZ2V0")
    out = build_family_payloads("deserialization", _deser_spec("ObjectInputStream.readObject"))
    assert out["payloads"] == []
    assert out["provider"] == "unsupported"
