"""方案1a sink 模式 gadget 构造器回归测试。

锁死 ctf-java-quote 自定义反序列化链的造弹闭环（C8 三点决议）：
- _sink_is_transformer_field 的识别边界：deserialization + commonscollections 命中；
  JNDI / 空 payload / 非 deserialization 族（如 xss 也含 "transform" 字样）不误触发。
- build_for_sink_pattern 产出合法 Java 序列化流（selfcheck 通过），且 command 可控。
- selfcheck_payload 复用 PayloadForge.selfcheck 语义（非序列化流判 False）。
- _selfcheck_or_raise 对废弹直接报错（杜绝把废弹当真弹投出）。
- select_attack_payloads 把 ysoserial 文本标签当 degraded 过滤（落到 sca_forge）。
- sca_forge_attack_payloads 对文本标签 spec 经 方案1a 造出真字节（生产路径闭环）。
"""
import base64
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

import pytest

from src.iast.gadget_builder import (
    build_for_sink_pattern,
    selfcheck_payload,
    _sink_is_transformer_field,
)
from src.iast.attack_context import (
    select_attack_payloads,
    sca_forge_attack_payloads,
    _is_ysoserial_text_label,
    _selfcheck_or_raise,
)
from src.iast import gadget_builder as _gb


def _gadget_toolchain_ready() -> bool:
    """造弹闭环需要本地 JDK 与 commons-collections jar。

    jar 是第三方二进制，不随仓库分发；干净 clone / CI 上没有它时本组用例跳过，
    不把「环境缺依赖」误报成「造弹逻辑坏了」。
    """
    try:
        return bool(_gb._resolve_java()) and os.path.isfile(_gb._CC_JAR)
    except Exception:  # noqa: BLE001
        return False


needs_gadget_toolchain = pytest.mark.skipif(
    not _gadget_toolchain_ready(),
    reason="需要本地 JDK 与 commons-collections jar（第三方二进制不入库）",
)

CC_SPEC = {
    "family": "deserialization",
    "category": "deserialization",
    "attack_payloads": ["ysoserial CommonsCollections6 calc"],
}
JNDI_SPEC = {
    "family": "deserialization",
    "attack_payloads": ['{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}'],
}
EMPTY_SPEC = {"family": "deserialization", "attack_payloads": []}
NON_DESER_SPEC = {"family": "xss", "attack_payloads": ["ysoserial CommonsCollections6 calc"]}
NO_SIGNAL_SPEC = {"family": "deserialization", "attack_payloads": ["some plain text label"]}


def test_sink_detection_boundaries():
    # 命中的：deserialization + commonscollections 信号
    assert _sink_is_transformer_field(CC_SPEC) is True
    # 不误命中：JNDI、空、非 deserialization 族、无 CC 信号
    assert _sink_is_transformer_field(JNDI_SPEC) is False
    assert _sink_is_transformer_field(EMPTY_SPEC) is False
    assert _sink_is_transformer_field(NON_DESER_SPEC) is False
    assert _sink_is_transformer_field(NO_SIGNAL_SPEC) is False
    # 仅 family、无任何信号也不触发
    assert _sink_is_transformer_field({"family": "deserialization"}) is False


@needs_gadget_toolchain
def test_build_produces_valid_serialization():
    b64 = build_for_sink_pattern(CC_SPEC, command="ping -n 1 127.0.0.1")
    assert b64
    assert selfcheck_payload(b64) is True
    raw = base64.b64decode(b64)
    assert raw.startswith(b"\xac\xed\x00\x05")


def test_build_non_matching_returns_none():
    assert build_for_sink_pattern(NON_DESER_SPEC) is None
    assert build_for_sink_pattern(JNDI_SPEC) is None
    assert build_for_sink_pattern(NO_SIGNAL_SPEC) is None


def test_selfcheck_rejects_non_serialization():
    assert selfcheck_payload("not-a-serialization-stream") is False
    assert selfcheck_payload(base64.b64encode(b"hello world").decode()) is False
    # 真序列化流通过
    assert selfcheck_payload(base64.b64encode(b"\xac\xed\x00\x05abcd1234").decode()) is True


def test_is_ysoserial_text_label():
    assert _is_ysoserial_text_label("ysoserial CommonsCollections6 calc") is True
    assert _is_ysoserial_text_label("ysoserial JRMPClient payload") is True
    # 真字节流不被误杀
    real = base64.b64encode(b"\xac\xed\x00\x05abcd1234").decode()
    assert _is_ysoserial_text_label(real) is False
    assert _is_ysoserial_text_label("calc.exe") is False
    assert _is_ysoserial_text_label("echo hi") is False


def test_selfcheck_or_raise_gate():
    # 废弹直接报错（评审第 3 点：报错而非降级）
    with pytest.raises(RuntimeError):
        _selfcheck_or_raise(["definitely-not-a-serialization"])
    # 真字节不报错
    real = base64.b64encode(b"\xac\xed\x00\x05abcd1234").decode()
    _selfcheck_or_raise([real])  # 不应抛


def test_select_filters_text_label():
    # A2 文本标签被过滤，落到 sca_forge，不当真弹投出
    assert select_attack_payloads(CC_SPEC) == []


@needs_gadget_toolchain
def test_sca_forge_produces_real_gadget():
    # 生产路径：文本标签 spec -> sca_forge -> 方案1a 真字节
    out = sca_forge_attack_payloads(CC_SPEC, db=None)
    assert out and len(out) == 1
    assert selfcheck_payload(out[0]) is True
    # 非匹配族不会经 方案1a 造弹（落到后续 SCA/ysoserial 或返回空）
    assert sca_forge_attack_payloads(NON_DESER_SPEC, db=None) != [out[0]]
