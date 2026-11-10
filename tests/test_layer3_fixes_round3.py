"""jsc 624 剩余 8 个漏点的五类根因回归锁（2026-11-06）。

逐点证据先于修复，全部来自 623/624 真跑 DB 与活靶场对照实验：

1. **确认态硬闸吞掉响应层 oracle 正向证据**：`/ssrf/urlConnection/vuln` 在 624
   已 `oracle_state=exploitable / oracle_signal=error_reflect`，却被硬闸降级成
   `confirm-gate:sink-reached`；硬闸只读 raw_json，读不到 spec 列的 oracle 结论。
2. **孤儿 spec 被当成「已有结论」跳过**：`unconfirmed` 是 trigger_spec 初始默认值，
   `/deserialize/rememberMe/vuln`、`/xstream`、`/vuln1` 共 11 条 replayable=1 的
   spec 零 replay_attempts，却因 `_has_verdict` 含 unconfirmed 永远不补进 D2。
3. **D1 重放全程未认证**：workspace 4 配了 login.credentials、兜底登录实测能拿到
   JSESSIONID，但真跑里 sqli 全部 302 → /login，业务代码一次都没进。
4. **主参数位被 rep canary 覆盖**：主注入放好 2816 字符 AES 包装弹后，
   multi-match 循环用 taint_marker 覆盖同名 cookie ⇒ 实际投出 canary，
   靶场恒返回 "RememberMe cookie decrypt error"（五轮 shiro 恒漏终因）。
5. **白名单域绕过没有对应载荷/判据**：`/url/vuln/url_bypass` 只在 host 以白名单域
   结尾时 sendRedirect，而库弹全是 evil.example.com ⇒ oracle 恒 no_location。
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ── 1. 响应层 oracle 正向证据 ────────────────────────────────────────────

def test_oracle_positive_signal_is_strict():
    """只认 exploitable + 非空 signal + 与本族严格匹配；防把靶场报错页当证据。"""
    from src.cli.benchmark_cli import _oracle_positive_signal
    assert _oracle_positive_signal("ssrf", "exploitable", "error_reflect") == "error_reflect"
    assert _oracle_positive_signal("ssrf", "exploitable", "internal_url_reflect") == "internal_url_reflect"
    assert _oracle_positive_signal("url_redirect", "exploitable", "location_reflect") == "location_reflect"
    # inconclusive / 空 signal / 跨族信号一律不认
    assert _oracle_positive_signal("ssrf", "inconclusive", "error_reflect") == ""
    assert _oracle_positive_signal("ssrf", "exploitable", "no_ssrf_effect") == ""
    assert _oracle_positive_signal("ssrf", "exploitable", "") == ""
    assert _oracle_positive_signal("xss", "exploitable", "error_reflect") == ""
    assert _oracle_positive_signal("ssrf", "not_exploitable", "boolean_diff") == ""


def test_confirmation_gate_and_recheck_consume_oracle_evidence():
    """硬闸 / 迟到证据回补 / oracle 升级三处必须同源，避免「一处认一处不认」。"""
    src = _src("src/cli/benchmark_cli.py")
    assert "_oracle_positive_signal" in src
    assert src.count("_oracle_positive_signal(") >= 4, src.count("_oracle_positive_signal(")
    assert "oracle_state, oracle_signal, positive_evidence_rule" in src
    assert "行为 oracle 已确证" in src
    assert "事后复核 oracle=" in src
    # 升级闸门必须允许纯响应事实在 no-arrival 时生效
    assert "_RESPONSE_ONLY_ORACLE_SIGNALS" in src
    assert '"error_reflect", "internal_url_reflect"' in src
    assert "_arrived or _sig in _RESPONSE_ONLY_ORACLE_SIGNALS" in src


def test_oracle_upgrade_no_longer_hardcodes_arrival_states_in_sql():
    """SQL 里写死 iast_state IN ('sink-reached',...) 会让 confirm-gate:* 永远漏掉。"""
    src = _src("src/cli/benchmark_cli.py")
    assert "AND iast_state IN ('sink-reached', 'sink-reached-probe')" not in src
    assert "_st.startswith((\"sink-reached\", \"confirm-gate:\"" in src


# ── 2. 孤儿 spec 按「是否真重放过」准入 ──────────────────────────────────

class _FakeDB:
    """最小 DB 桩：只实现 _enqueue_orphan_trigger_specs 用到的 execute。"""

    def __init__(self, replayed):
        self._replayed = set(replayed)

    def execute(self, sql, params=None, fetchall=False):
        assert "replay_attempts" in sql
        return [{"spec_id": sid} for sid in sorted(self._replayed)]


def _orphan_spec(sid, status, endpoint="/xstream", replayable=1):
    return {
        "id": sid,
        "verification_status": status,
        "replayable": replayable,
        "target_endpoint": endpoint,
        "vulnerability_hash_v2": "vh%d" % sid,
        "family": "deserialization",
        "category": "deserialization",
        "expected_sink_file": "XStreamRce.java",
        "expected_sink_line": 29,
        "raw_json": "{}",
    }


def test_orphan_zero_replay_unconfirmed_is_enqueued():
    """unconfirmed 是初始默认值，零重放 spec 必须补进 D2。"""
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    by = {"k": [
        _orphan_spec(1, "unconfirmed"),
        _orphan_spec(2, "confirmed_code_property", "/vuln1"),
        _orphan_spec(3, "sink_reached"),
    ]}
    vulns = []
    n = _enqueue_orphan_trigger_specs(vulns, by, db=_FakeDB(set()), task_id=624)
    assert n == 3, n
    assert {v["orphan_spec_id"] for v in vulns} == {1, 2, 3}


def test_orphan_already_replayed_is_not_reenqueued():
    """真发过请求的 unconfirmed 不得重复投放、不得覆盖既有证据。"""
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    by = {"k": [_orphan_spec(1, "unconfirmed"), _orphan_spec(2, "unconfirmed", "/vuln1")]}
    vulns = []
    n = _enqueue_orphan_trigger_specs(vulns, by, db=_FakeDB({1}), task_id=624)
    assert n == 1
    assert vulns[0]["orphan_spec_id"] == 2


def test_orphan_terminal_state_is_never_reenqueued():
    """终态确认/作废不补，即便零重放。"""
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    by = {"k": [_orphan_spec(1, "confirmed_exploitable"),
                _orphan_spec(2, "invalidated"),
                _orphan_spec(3, "no_evidence")]}
    vulns = []
    n = _enqueue_orphan_trigger_specs(vulns, by, db=_FakeDB(set()), task_id=624)
    assert n == 1
    assert vulns[0]["orphan_spec_id"] == 3


# ── 3. D1 会话自愈 ───────────────────────────────────────────────────────

def test_d1_session_selfheal_is_wired():
    """构造请求处必须有最后一道会话自愈，不依赖上游 replay() 分支是否走对。"""
    src = _src("src/application/d1_service.py")
    assert "会话自愈" in src
    assert "_fallback_auth_cookies(_fb_target)" in src
    assert "if not cookies and not headers:" in src
    assert "_fallback_auth_logged" in src


def test_d1_main_slot_is_not_overwritten_by_rep_canary():
    """主参数位保留真弹：这是 shiro 五轮恒漏的终因，必须锁住。"""
    src = _src("src/application/d1_service.py")
    assert "主参数位不得被 canary 覆盖" in src
    assert "attack_payload_used" in src
    assert "_structured" in src
    assert "跳过 rep canary 覆盖" in src
    # 只护结构化弹，文本族基线不动
    assert '"deserialization" in _fam_text' in src


def test_replay_attempt_payload_is_not_truncated_at_2000():
    """2816 字符 AES 包装弹被截到 2000 会造出非 16 倍数的假样本。"""
    src = _src("src/application/d1_service.py")
    assert 'str(payload or "")[:8000]' in src
    assert "2000 会把 Shiro rememberMe" in src


# ── 4. 白名单域感知绕过 ──────────────────────────────────────────────────

def test_allowlist_domains_discovered_from_source(tmp_path, monkeypatch):
    """`String domainwhitelist[] = {...}`（方括号在变量名后）必须能被解析。"""
    import src.iast.source_infer as si
    from src.iast.payload_library import _discover_allowlist_domains
    j = tmp_path / "URLWhiteList.java"
    j.write_text(
        'class URLWhiteList {\n'
        '    private String domainwhitelist[] = {"joychou.org", "joychou.com"};\n'
        '    void v(String url) { if (host.endsWith("." + domain)) redirect(url); }\n'
        '}\n', encoding="utf-8")
    monkeypatch.setattr(si, "resolve_source_path", lambda p: str(j))
    got = _discover_allowlist_domains({"expected_sink_file": "URLWhiteList.java"})
    assert got == ["joychou.org", "joychou.com"], got


def test_allowlist_aware_bypass_payload_is_first(tmp_path, monkeypatch):
    """主判定只认 attack_payloads[0]，绕过形态必须前置。"""
    import src.iast.source_infer as si
    from src.iast.payload_library import build_family_payloads
    j = tmp_path / "URLWhiteList.java"
    j.write_text('private String domainwhitelist[] = {"joychou.org"};\n', encoding="utf-8")
    monkeypatch.setattr(si, "resolve_source_path", lambda p: str(j))
    out = build_family_payloads("url_whitelist_bypass",
                                {"expected_sink_file": "URLWhiteList.java",
                                 "param_name": "url", "param_location": "query"})
    assert out["provider"] == "url_bypass_allowlist_aware", out
    first = out["payloads"][0]
    assert "joychou.org" in first and "evil.example.com" in first, first
    assert "\\@" in first, first


def test_url_bypass_without_source_keeps_original_variants(monkeypatch):
    """发现不到白名单域时不得退化成猜的域名，保持原 7 发。"""
    import src.iast.payload_library as pl
    monkeypatch.setattr(pl, "_discover_allowlist_domains", lambda spec: [])
    out = pl.build_family_payloads("url_whitelist_bypass", {})
    assert out["provider"] == "url_bypass"
    assert len(out["payloads"]) == 7


def test_redirect_oracle_uses_primary_payload_and_reflected_injection():
    """白名单端点回显的是注入的绕过 URL，不是保留域名；判据必须认。"""
    from src.iast import response_oracle as orc
    payload = "http://evil.example.com\\@www.joychou.org/a.html"
    probes = orc.build_probes("url_redirect", payload=payload,
                              servlet_name="url_bypass", probe_token="p1")
    assert any(p.note == "primary_payload" and p.payload == payload for p in probes), probes
    arm = orc.ArmResult(arm="redirect", payload=payload, status=302, body="",
                        elapsed_ms=5, headers={"Location": payload})
    v = orc.judge("url_redirect", [arm], baseline_ms=5)
    assert v["verdict"] == "exploitable", v
    assert v["signal"] == "location_reflect", v
    # 固定跳转到登录页不含注入值 ⇒ 不得误升
    fixed = orc.ArmResult(arm="redirect", payload=payload, status=302, body="",
                          elapsed_ms=5, headers={"Location": "/login"})
    v2 = orc.judge("url_redirect", [fixed], baseline_ms=5)
    assert v2["verdict"] != "exploitable", v2
