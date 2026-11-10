"""A2 载荷合成（synthesize_payload）的回归锁（2026-11-02）。

事故：本轮的 156 条 spec 里只有 **25 条有 attack_payloads（16%）**，
而库里 `payload_synthesized` 标记**一条都没有**——合成等于没发生。两个错叠在一起：

1. **写错位置**：旧实现 `spec["payload"] = tpl` 写的是**字符串**，
   而消费方 `attack_context.select_attack_payloads` 读的是
   `exploit_spec["payload"]["candidate_payloads"]`（字典里的数组）⇒ 直接返回空。
2. **族覆盖不全**：模板表只有 14 个族，`deserialization` 不在里面
   （jsc 里 18 条 deser spec 全空），jndi / log_injection / jsonp / cors / url_redirect 也缺。

本文件锁四件事：写入位置、族覆盖、不覆盖 A2 真载荷、属性族不合成。
"""
from __future__ import annotations

import pytest

from src.agents.a2_integrated_analyst import synthesize_payload


def _spec(**payload):
    return {
        "entry": {"route": "/x", "method": "GET", "parameter_name": "q",
                  "parameter_location": "query", "content_type": ""},
        "payload": dict({"payload_family": "", "candidate_payloads": []}, **payload),
    }


def test_writes_into_candidate_payloads_not_top_level_string():
    """主锁：必须写进 payload.candidate_payloads —— 消费方只读那里。"""
    sp = _spec()
    ok, first = synthesize_payload("sql_injection", sp)
    assert ok and first
    assert isinstance(sp["payload"], dict)
    assert sp["payload"]["candidate_payloads"], sp["payload"]
    assert sp["payload"].get("payload_synthesized") is True


def test_deserialization_now_has_a_payload():
    """deserialization 原来不在模板表里 ⇒ 18 条 spec 全空。"""
    sp = _spec()
    ok, first = synthesize_payload("deserialization", sp)
    assert ok, "deserialization 必须能合成文本型载荷"
    assert "javax.script" in first or "java.net" in first, first


@pytest.mark.parametrize("fam", ["jndi_injection", "log_injection", "jsonp_referer",
                                 "cors", "url_redirect", "xxe", "ssrf"])
def test_newly_covered_families(fam):
    sp = _spec()
    ok, first = synthesize_payload(fam, sp)
    assert ok and first, fam


def test_does_not_override_a2_real_payload():
    sp = _spec(candidate_payloads=["' OR SLEEP(3)--"])
    ok, first = synthesize_payload("sql_injection", sp)
    assert ok is False
    assert sp["payload"]["candidate_payloads"] == ["' OR SLEEP(3)--"]
    assert "payload_synthesized" not in sp["payload"]


def test_placeholder_payload_is_replaced():
    """A2 的占位串（base64(serialized_object)）不算真载荷，必须被替换。"""
    sp = _spec(candidate_payloads=["base64(serialized_object)"])
    ok, first = synthesize_payload("deserialization", sp)
    assert ok and first != "base64(serialized_object)"


@pytest.mark.parametrize("fam", ["weak_crypto", "weak_random", "weak_hash", "secure_cookie"])
def test_property_families_are_not_synthesized(fam):
    """属性族不该有载荷（它们走静态算法门禁），合成会制造「投了假弹」的假证据。"""
    sp = _spec()
    ok, _ = synthesize_payload(fam, sp)
    assert ok is False


def test_legacy_string_payload_is_kept_and_candidates_written_to_sibling():
    """A2 的 per-file spec 里 `payload` 是**字符串**，不能强行改成 dict。

    正确行为：原字符串保留（下游按字符串读），候选数组写到兄弟键 `payload_candidates`，
    由 `select_attack_payloads` 兼容读取。已有真载荷时不重复合成。
    """
    sp = {"entry": {}, "payload": "' OR 1=1--"}
    ok, first = synthesize_payload("sql_injection", sp)
    assert sp["payload"] == "' OR 1=1--", "原字符串必须保留"
    assert ok is False, "已有真载荷，不重复合成"
    assert first == "' OR 1=1--"


def test_legacy_placeholder_string_gets_sibling_candidates():
    """占位串不是真载荷 ⇒ 合成并写到兄弟键，原字段保持不动。"""
    sp = {"entry": {}, "payload": "generic_payload"}
    ok, first = synthesize_payload("sql_injection", sp)
    assert ok and first
    assert sp["payload"] == "generic_payload", "原字段不动"
    assert sp["payload_candidates"] and sp["payload_candidates"][0] == first
