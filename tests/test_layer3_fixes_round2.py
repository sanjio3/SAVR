"""本轮（2026-11-04 晚）四处修复的回归锁。

1. **表达式族载荷自检**：`expression_injection` / `spel` 族此前没有归组 ⇒
   A2 造的占位载荷（`express = 'System.out.println(...)'`）被当成合法弹放行 ⇒
   它占住 attack_payloads ⇒ 族载荷库（7*7 / #{7*7}）永远不被调用 ⇒
   端点恒 attempts=0、真值点恒漏（jsc 619 spec 237801 实测）。

2. **Shiro rememberMe 载荷的 AES 包装**：Shiro 的 rememberMe cookie 密文格式是
   `base64( IV(16B) || AES-CBC-PKCS5(序列化流) )` —— 只投 ciphertext 永远解不开。
   （用 shiro-core 1.2.4 的 AesCipherService 实测确定，不是猜的。）

3. **参数位置以源码为准**：`@CookieValue` / `getHeader` 的绑定通道此前被当成
   query ⇒ D1 投错通道 ⇒ 端点恒 no-arrival（jsc 619 spec 237862 实测）。

4. **族载荷库与 A2 载荷合并**：A2 载荷形态对但**目标集不全**时（如 XXE 只给
   `file:///etc/passwd`，而靶场在 Windows），库弹（同时含 win.ini）被整体挡住。
"""
from __future__ import annotations

import base64
import os

import pytest

# 2026-11-06 开源可移植性：靶场源码路径由 SAST_AI_SDL_ROOT 提供，未设置时
# 依赖源码的用例显式跳过，不硬编码任何开发机绝对路径。
LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")


def _jsc_root() -> str:
    return os.path.join(LOCAL_ROOT, "java-sec-code") if LOCAL_ROOT else ""


# ── 1. 表达式族载荷自检 ──────────────────────────────────────────────────

def test_expression_family_is_grouped_for_selfcheck():
    """表达式族必须有自检分组，否则 A2 占位载荷会占住弹药库。"""
    from src.iast.attack_context import _payload_check_group
    assert _payload_check_group("expression_injection") == "expression_injection"
    assert _payload_check_group("spel_injection") == "expression_injection"


def test_expression_assignment_payload_is_rejected():
    """`express = '...'` 是赋值语句不是表达式 ⇒ 判废（让弹药库上位）。"""
    from src.iast.attack_context import classify_payload_family_mismatch
    bad = """express = 'System.out.println("Hello, World!");'"""
    assert classify_payload_family_mismatch(bad, "expression_injection")


def test_expression_side_effect_only_payload_is_rejected():
    """纯副作用语句（只打印）不产生可观测求值结果 ⇒ 判废。"""
    from src.iast.attack_context import classify_payload_family_mismatch
    assert classify_payload_family_mismatch('System.out.println("x");', "expression_injection")
    assert classify_payload_family_mismatch("print(1)", "expression_injection")


@pytest.mark.parametrize("payload", ["7*7", "#{7*7}", "1+1", "'x'.concat('y')",
                                     "T(java.lang.Runtime).getRuntime()"])
def test_real_expression_payloads_pass_selfcheck(payload):
    """真表达式必须放行（否则会误杀真弹）。"""
    from src.iast.attack_context import classify_payload_family_mismatch
    assert classify_payload_family_mismatch(payload, "expression_injection") is None


def test_expression_selfcheck_does_not_affect_other_families():
    """自检规则只作用于表达式族，不影响其它族。"""
    from src.iast.attack_context import classify_payload_family_mismatch
    assert classify_payload_family_mismatch("http://127.0.0.1:8080/", "ssrf") is None
    assert classify_payload_family_mismatch("rO0ABXNyAC5qYXZheQ==", "deserialization") is None


# ── 2. Shiro rememberMe 的 AES 包装 ──────────────────────────────────────

def _shiro_key_b64() -> str:
    return "kPH+bIxk5D2deZiIxcaaaA=="


def test_rememberme_payload_has_iv_prefix():
    """密文格式 = IV(16B) || AES-CBC-PKCS5(密文) ⇒ 解密后前 16 字节是 IV。

    依据：shiro-core 1.2.4 的 JcaCipherService 默认
    generateInitializationVectors=true / initializationVectorSize=128 /
    mode=CBC / padding=PKCS5Padding（tools/ShiroProbe.java 实测）。
    """
    from src.iast.payload_library import _shiro_rememberme_payloads
    raw = b"\xac\xed\x00\x05" + b"sastai" * 8
    out = _shiro_rememberme_payloads(base64.b64encode(raw).decode(), _shiro_key_b64())
    assert out, "没产出 rememberMe 载荷"
    blob = base64.b64decode(out[0])
    # IV(16) + 密文(16 的倍数)
    assert len(blob) % 16 == 0, len(blob)
    assert len(blob) >= 32, len(blob)
    # 密文部分解开后应还原出原始内容（尾部是 PKCS5 padding）
    from Cryptodome.Cipher import AES
    key = base64.b64decode(_shiro_key_b64())
    iv, enc = blob[:16], blob[16:]
    dec = AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
    pad = dec[-1]
    assert 1 <= pad <= 16
    assert dec[:-pad] == raw


def test_rememberme_payload_requires_key():
    """没有 key 就不能造（不硬编码靶场常量、不瞎猜）。"""
    from src.iast.payload_library import _shiro_rememberme_payloads
    raw = base64.b64encode(b"\xac\xed\x00\x05abc").decode()
    assert _shiro_rememberme_payloads(raw, "") == []


def test_rememberme_key_discovery_reads_source():
    """key 必须能从目标源码自动发现（每个应用 key 不同）。"""
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    from src.iast.payload_library import _discover_shiro_key
    spec = {"raw_json": '{"sink": {"file": '
                           '"src/main/java/org/joychou/controller/Shiro.java"}}'}
    key = _discover_shiro_key(spec)
    assert key, "没从源码发现 Shiro 的 key"


def test_aes_wrap_decision_is_source_based():
    """「要不要 AES 包装」由**源码**判定，不靠 cookie 通道猜。

    两个 rememberMe 端点机制不同：Shiro.java 有 AES 解密、Deserialize.java 没有。
    """
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    from src.iast.payload_library import _sink_needs_aes_wrap
    shiro = {"raw_json": '{"sink": {"file": '
                             '"src/main/java/org/joychou/controller/Shiro.java"}}'}
    deser = {"raw_json": '{"sink": {"file": '
                            '"src/main/java/org/joychou/controller/Deserialize.java"}}'}
    assert _sink_needs_aes_wrap(shiro) is True
    assert _sink_needs_aes_wrap(deser) is False


# ── 3. 参数位置以源码为准 ───────────────────────────────────────────────

def _resolve(ep, line, pname, ploc, file, fam="xss"):
    from src.core.param_resolver import resolve_trigger_endpoint

    class _V:
        pass

    v = _V()
    v.file = file
    v.line = line
    v.finding_type = fam
    v.rule_name = "x"
    v.sink = "ResponseBody.return"
    v.code_snippet = ""
    v.description = ""
    v.exploit_spec = {"entry": {"route": ep, "method": "GET",
                                 "parameter_name": pname, "parameter_location": ploc}}
    return resolve_trigger_endpoint(v, None, _jsc_root(), None)


def test_cookie_value_param_resolves_to_cookie_channel():
    """`@CookieValue("xss")` ⇒ cookie 通道（源码是 ground truth）。"""
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    out = _resolve("/xss/stored/show", 57, "xss", "query",
                   "src/main/java/org/joychou/controller/XSS.java")
    assert out.get("param_location") == "cookie", out
    assert out.get("param_name") == "xss", out


def test_plain_string_param_resolves_to_query_channel():
    """`reflect(String xss)` ⇒ query 通道（不是 cookie）。"""
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    out = _resolve("/xss/reflect", 29, "xss", "cookie",
                   "src/main/java/org/joychou/controller/XSS.java")
    assert out.get("param_location") == "query", out


def test_get_header_param_resolves_to_header_channel():
    """`request.getHeader("origin")` ⇒ header 通道。"""
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    out = _resolve("/cors/vuln/origin", 28, "origin", "query",
                   "src/main/java/org/joychou/controller/Cors.java", "cors")
    assert out.get("param_location") == "header", out


def test_a2_location_is_overridden_by_source():
    """A2 给了错位置时，源码位置优先（契约三维度必须同源）。"""
    root = _jsc_root()
    if not os.path.isdir(root):
        pytest.skip("无靶场源码")
    out = _resolve("/rce/jscmd", 95, "jsurl", "body",
                   "src/main/java/org/joychou/controller/Rce.java", "command_execution")
    assert out.get("param_location") == "query", out
    assert out.get("param_name_source") == "source-recovered", out


# ── 4. 族载荷库与 A2 载荷合并 ────────────────────────────────────────────

def test_xxe_library_payloads_cover_windows_target():
    """XXE 库弹必须同时含 Windows 与 Unix 目标（靶场 OS 未知）。"""
    from src.iast.payload_library import build_family_payloads
    out = build_family_payloads("xxe", {"param_name": "body", "param_location": "body"})
    assert out["payloads"], out
    joined = " ".join(out["payloads"])
    assert "win.ini" in joined, out
    assert "/etc/passwd" in joined, out


# ── 5. sink 专用形态前置（2026-11-06，jsc 623 实测）──────────────────────
#
# 623 真跑：/shiro/deserialize 唯一投出的是 sca_forge 的原始序列化流，
# 响应「RememberMe cookie decrypt error」；载荷库按源码判定的 AES-CBC 包装弹
# 明明能造出来，却因为 (a) sca_forge 非空跳过了库分支、(b) 补投只做观测不改判定，
# 五轮（607/617/619/622/623）都进不了主路径。

def _fake_gadget_b64() -> str:
    """最小合法 Java 序列化流（AC ED 00 05 魔数），够过 PayloadForge.selfcheck。"""
    return base64.b64encode(b"\xac\xed\x00\x05" + b"A" * 40).decode("ascii")


def _build_deser_with_mocks(monkeypatch, need_aes: bool):
    import src.iast.payload_library as pl
    from src.iast.payload_forge import PayloadForge
    monkeypatch.setenv("SAST_AI_DESER_YSOSERIAL", "1")
    monkeypatch.setattr(pl, "_sink_needs_aes_wrap", lambda spec: need_aes)
    monkeypatch.setattr(pl, "_discover_shiro_key", lambda spec: _shiro_key_b64())
    monkeypatch.setattr(PayloadForge, "forge",
                        lambda self, chain, command="": _fake_gadget_b64())
    pl._DESER_BINARY_CACHE.clear()
    spec = {"param_name": "rememberMe", "param_location": "cookie"}
    return pl


def test_aes_sink_marks_sink_specific_and_puts_wrapped_first(monkeypatch):
    """源码判定需要 AES 解密的 sink：库弹必须给 sink_specific 且包装形态排在首位。"""
    pl = _build_deser_with_mocks(monkeypatch, need_aes=True)
    out = pl.build_family_payloads(
        "deserialization", {"param_name": "rememberMe", "param_location": "cookie"})
    assert out.get("sink_specific") is True, out
    assert len(out["payloads"]) == 2, out
    assert not out["payloads"][0].startswith("rO0"), out  # 首位不能是裸序列化流
    assert any(p.startswith("rO0") for p in out["payloads"]), out  # 原始流留作对照


def test_sink_specific_flag_survives_cache_hit(monkeypatch):
    """D1 每个 spec 会调库两次；缓存命中路径也必须回传该标记，否则前置失效。"""
    pl = _build_deser_with_mocks(monkeypatch, need_aes=True)
    spec = {"param_name": "rememberMe", "param_location": "cookie"}
    first = pl.build_family_payloads("deserialization", spec)
    second = pl.build_family_payloads("deserialization", spec)
    assert first.get("sink_specific") is True, first
    assert second.get("sink_specific") is True, second
    assert second["payloads"] == first["payloads"]


def test_plain_objectinputstream_sink_is_not_sink_specific(monkeypatch):
    """无 AES 的 Deserialize.java 投原始流就对，不能被误判成专用形态。"""
    pl = _build_deser_with_mocks(monkeypatch, need_aes=False)
    out = pl.build_family_payloads(
        "deserialization", {"param_name": "rememberMe", "param_location": "cookie"})
    assert out.get("sink_specific") is False, out
    assert out["payloads"][0].startswith("rO0"), out


def test_frontload_prefers_library_sink_specific(monkeypatch):
    """库标记 sink_specific 时，包装形态必须顶掉 sca_forge 的原始流成为首发。"""
    pl = _build_deser_with_mocks(monkeypatch, need_aes=True)
    spec = {"param_name": "rememberMe", "param_location": "cookie"}
    out = pl.frontload_sink_specific("deserialization", spec, ["rO0ABXdummy"])
    assert out["changed"] is True
    assert not out["payloads"][0].startswith("rO0"), out
    assert "rO0ABXdummy" in out["payloads"], out  # 原始流留作对照形态


def test_frontload_wraps_existing_gadget_when_library_is_gated(monkeypatch):
    """库被早退闸门拦空时，仍能基于已有原始流现场做 AES 包装（623 真跑形态）。"""
    import src.iast.payload_library as pl
    monkeypatch.setattr(pl, "build_family_payloads",
                        lambda family, spec=None: {"provider": "unsupported",
                                                   "payloads": [], "note": "gated"})
    monkeypatch.setattr(pl, "_sink_needs_aes_wrap", lambda spec: True)
    monkeypatch.setattr(pl, "_discover_shiro_key", lambda spec: _shiro_key_b64())
    raw = _fake_gadget_b64()
    out = pl.frontload_sink_specific("deserialization", {}, [raw])
    assert out["changed"] is True
    assert out["provider"] == "sink_aes_wrap", out
    assert not out["payloads"][0].startswith("rO0"), out
    assert raw in out["payloads"], out


def test_frontload_fills_empty_chain_from_library(monkeypatch):
    """A2 / sca_forge 全空时，库弹至少别让该 spec 空手。"""
    import src.iast.payload_library as pl
    monkeypatch.setattr(pl, "build_family_payloads",
                        lambda family, spec=None: {"provider": "deser_text",
                                                   "payloads": ["<xml/>"], "note": ""})
    monkeypatch.setattr(pl, "_sink_needs_aes_wrap", lambda spec: False)
    out = pl.frontload_sink_specific("deserialization", {}, [])
    assert out["changed"] is True
    assert out["payloads"] == ["<xml/>"], out


def test_frontload_is_noop_for_unrelated_family(monkeypatch):
    """无源码专用形态时不得改写载荷链（防止波及其它族）。"""
    import src.iast.payload_library as pl
    monkeypatch.setattr(pl, "build_family_payloads",
                        lambda family, spec=None: {"provider": "none",
                                                   "payloads": [], "note": ""})
    monkeypatch.setattr(pl, "_sink_needs_aes_wrap", lambda spec: False)
    out = pl.frontload_sink_specific("xss", {}, ["<svg onload=1>"])
    assert out["changed"] is False
    assert out["payloads"] == ["<svg onload=1>"], out


def test_d1_frontloads_sink_specific_payload():
    """D1 必须消费载荷层的前置契约（主判定只认 attack_payloads[0]）。"""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    src = (root / "src" / "application" / "d1_service.py").read_text(encoding="utf-8")
    assert "sink 专用形态前置" in src
    assert "frontload_sink_specific" in src
    # 补投仍是观测用，不能靠"追加在后面"来替代前置
    assert "只做观测记录" in src
