# -*- coding: utf-8 -*-
"""值级证据通道投放回归锁（2026-10-10 r73 对账根因修复）。

背景：D1 修复前「头 canary + 参数真实 payload」——canary 身份段从不进入参数值，
sink 实参记录里永远比对不到我方数据（r73 实测 400 spec / 2009 条 canary 事件仅 1 条
可比对命中），值级通道 _ch_value_level_sink_arg 被结构性饿死，B6 语义门把 7 个 sink 族
全部拒成 unconfirmed → 动态召回 24.8%。

修复：主载荷（真实 payload）末尾追加 canary 身份段，让「我方数据真的出现在 sink 实参里」
成为可比对事实。锁定四个契约：
1. 真实 payload → 追加身份段（payload + s4st41...）；
2. 退化模式（无 payload，参数位本就是 canary）→ 不重复追加；
3. sleep 主载荷 → 不追加（保住时延盲注通道的 SQL 语法）；
4. 全链路四态：hit_live 放行确认门 / hit_sanitized 阴性 / miss 证据缺失不确认。
"""
import re
from unittest.mock import patch

import src.agents.d2_facade  # noqa: F401  通道注册前置（memory 铁律）
import pytest

from src.application.d1_service import D1Service
from src.agents.d2_facade import _ch_value_level_sink_arg
from src.cli.benchmark_cli import _confirm_gate_decide
from src.iast.canary import CanaryMatcher
from src.iast.orchestrator import DastImpact, compute_value_hit

MARKER = "s4st41deadbeef00112345"  # s4st41 + 16 hex（find_identity 的合法形态）
IDENT = CanaryMatcher.find_identity(MARKER)


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


def _replay_requests(spec):
    """收集一次 replay 发出的全部请求（主弹/基线/探针可有多发，捕获单发会被覆盖误导）。"""
    reqs = []

    def fake_request(method, url, params=None, headers=None, cookies=None, json=None, data=None, **kw):
        reqs.append({"method": method, "url": url, "params": params, "headers": headers or {},
                     "cookies": cookies or {}, "json": json, "data": data})
        return FakeResponse(200, "ok")

    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = D1Service().replay(spec, target)
    assert isinstance(imp, DastImpact)
    return reqs


def _q_of(req, name="q"):
    p = req.get("params") or {}
    return str(p.get(name) or "")


def test_real_payload_embeds_canary_identity():
    """真实 payload 主值必须携带 canary 身份段（值级通道可比对的前提）。"""
    payload = "foo' OR 1=1--"
    spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": MARKER,
            "family": "sql_injection", "attack_payloads": [payload]}
    reqs = _replay_requests(spec)
    assert any(payload in _q_of(r) and IDENT in _q_of(r) for r in reqs), (
        "主载荷未携带 canary 身份段 —— 值级通道将被饿死（r73 根因复发）")


def test_deserialization_via_category_key_not_embedded():
    """族名只写在 category（没有 family 键）时也必须识别为反序列化、不追加。

    2026-10-11 踩坑：守卫原先只看 `family`，而 test_d1_replay / test_sca_forge 的 spec
    只带 `category=deserialization` ⇒ 守卫整个漏掉，把 base64 gadget 字节串尾部改坏
    （readObject 直接失败、sink 不触发，比不追加更差）。族名须三键全看。
    """
    payload = "rO0ABXNy-gadget-chain"
    spec = {"target_endpoint": "/debug/import", "http_method": "POST", "param_name": "data",
            "param_location": "body", "taint_marker": MARKER,
            "category": "deserialization", "attack_payloads": [payload]}
    reqs = _replay_requests(spec)
    for r in reqs:
        body = r.get("json") or {}
        if isinstance(body, dict) and str(body.get("data") or "").startswith("rO0AB"):
            assert body["data"] == payload, (
                "反序列化 gadget 字节串被篡改：%r（readObject 会直接失败）" % body["data"])


def test_real_payload_embeds_full_marker_not_just_identity():
    """追加的必须是**完整 taint_marker**，不能只有身份段。

    2026-10-11 修正：线上 `compute_value_hit` 比对用的是完整 marker（形如
    `s4st41<16hex>PAYLOAD<8hex>`，spec 级确定性生成），而不是 find_identity 提取的
    身份段。只追加身份段时完整 marker 依然匹配不上 —— r74 实测值级命中仅 14→26，
    远低于预期。本锁防止再退回「只追加 ident」的错误形态。
    """
    full_marker = "s4st41deadbeef00112345PAYLOAD775a7bce"
    payload = "foo' OR 1=1--"
    spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": full_marker,
            "family": "sql_injection", "attack_payloads": [payload]}
    reqs = _replay_requests(spec)
    assert any(payload in _q_of(r) and full_marker in _q_of(r) for r in reqs), (
        "主载荷未携带完整 taint_marker —— 与 compute_value_hit 的比对串不一致，"
        "值级通道仍会被饿死（r74 实证：只追加身份段无效）")


def test_degraded_canary_probe_not_double_appended():
    """退化模式（无真实 payload）：参数位本就是 canary，绝不能出现身份段重复拼接。"""
    spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": MARKER,
            "family": "sql_injection"}
    reqs = _replay_requests(spec)
    for r in reqs:
        assert _q_of(r).count(IDENT) <= 1


def test_sleep_payload_not_embedded():
    """A2 产的 sleep 主载荷不追加身份段：时延盲注通道的 SQL 语法优先。"""
    sleep_p = "' AND SLEEP(3)-- "
    spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": MARKER,
            "family": "sql_injection", "attack_payloads": [sleep_p]}
    reqs = _replay_requests(spec)
    assert any("SLEEP(3)" in _q_of(r) for r in reqs)
    for r in reqs:
        if "SLEEP(3)" in _q_of(r) and _q_of(r).startswith(sleep_p.strip()[:4]):
            assert IDENT not in _q_of(r), "A2 sleep 主载荷被追加身份段会破坏时延 SQL 语法"


def test_numeric_param_not_embedded():
    """数值型参数不追加：追加会让 Spring 类型绑定失败（400）→ 比不追加更差。"""
    spec = {"target_endpoint": "/api/order/1", "http_method": "GET", "param_name": "id",
            "param_location": "query", "taint_marker": MARKER,
            "param_type": "numeric_id", "family": "sql_injection",
            "attack_payloads": ["1 OR 1=1"]}
    reqs = _replay_requests(spec)
    # 主载荷保持数值可绑定形态：任何请求都不得出现 "1 OR 1=1"+身份段的拼接
    for r in reqs:
        q = _q_of(r, "id")
        # 主载荷请求（以 payload 打头）绝不能带身份段；退化探针请求（纯 canary）不受影响
        if q.startswith("1 OR 1=1"):
            assert IDENT not in q, (
                "数值型参数被追加身份段会破坏类型绑定：%r" % q)


def test_url_param_not_embedded():
    """URL 语义参数（SSRF）不追加：会把 host 变成非法主机导致 new URL() 抛错。"""
    spec = {"target_endpoint": "/ssrf/fetch", "http_method": "GET", "param_name": "url",
            "param_location": "query", "taint_marker": MARKER,
            "family": "ssrf", "attack_payloads": ["http://169.254.169.254/latest/meta-data/"]}
    reqs = _replay_requests(spec)
    assert any("169.254.169.254" in _q_of(r, "url") for r in reqs), "SSRF 主载荷未发出，用例失真"
    for r in reqs:
        q = _q_of(r, "url")
        if "169.254.169.254" in q:
            assert IDENT not in q, (
                "URL 语义参数被追加身份段会破坏 URL 解析：%r" % q)


def test_deserialization_payload_not_embedded():
    """反序列化族不追加：payload 是 base64 gadget 字节串，追加会破坏编码使 readObject 失败。"""
    gadget = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
    spec = {"target_endpoint": "/deser/read", "http_method": "POST", "param_name": "data",
            "param_location": "body", "taint_marker": MARKER,
            "family": "deserialization", "attack_payloads": [gadget]}
    reqs = _replay_requests(spec)
    for r in reqs:
        v = str((r.get("json") or {}).get("data") or "")
        if gadget in v:
            assert IDENT not in v, (
                "反序列化 base64 载荷被追加身份段会破坏编码：%r" % v)


def test_value_chain_hit_live_admits_confirm_gate():
    """全链路正向：值级 hit_live → B1 通道 definitive 阳性 → B6 门 runtime_arrival 准入。"""
    vh = {"hit": True, "form": "hit_live", "where": "source_value",
          "sink_file": "java.sql.Statement.executeQuery", "snippet": "...OR 1=1--" + IDENT,
          "matched_len": len(IDENT), "definitive": True, "harmful": True, "sanitizer": ""}
    ch = _ch_value_level_sink_arg({"iast": {"value_hits": [vh]}, "family": "sql_injection"})
    assert ch["definitive"] is True and ch["harmful"] is True
    ok, code, _ = _confirm_gate_decide(
        "sink-reached-probe", {"value_hit": vh, "matched_event_ids": [1]},
        {"impact_observed": False}, {})
    assert ok is True and code == "runtime_arrival"


def test_value_chain_hit_sanitized_is_definitive_negative():
    """消毒命中：B1 通道出 definitive 阴性；确认门不放行（合法阴性，非证据缺失）。"""
    vh = {"hit": True, "form": "hit_sanitized", "where": "source_value",
          "sink_file": "java.sql.Statement.executeQuery", "snippet": IDENT + "...",
          "matched_len": len(IDENT), "definitive": True, "harmful": False,
          "sanitizer": "ESAPI.encoder().encodeForSQL"}
    ch = _ch_value_level_sink_arg({"iast": {"value_hits": [vh]}, "family": "sql_injection"})
    assert ch["definitive"] is True and ch["harmful"] is False
    ok, code, _ = _confirm_gate_decide(
        "sink-reached-probe", {"value_hit": vh, "matched_event_ids": [1]},
        {"impact_observed": False}, {})
    assert ok is False and code == "arrival_without_semantics"


def test_value_chain_miss_stays_evidence_missing():
    """未命中：绝不 出阴性裁决（r250 教训），确认门 fail-open 到 unconfirmed。"""
    vh = {"hit": False, "form": "miss", "where": "", "sink_file": "", "snippet": "",
          "matched_len": 0, "definitive": False, "harmful": False, "sanitizer": ""}
    ch = _ch_value_level_sink_arg({"iast": {"value_hits": [vh]}, "family": "sql_injection"})
    assert ch["definitive"] is False
    ok, code, _ = _confirm_gate_decide(
        "sink-reached-probe", {"value_hit": vh, "matched_event_ids": [1]},
        {"impact_observed": False}, {})
    assert ok is False and code == "arrival_without_semantics"


def test_compute_value_hit_four_states_on_embedded_value():
    """值级四态在嵌入形态上的行为：原文命中 live / 消毒命中 sanitized / 不出现 miss。"""
    ev_live = {"source_value": "[SELECT * FROM u WHERE n='' OR 1=1--" + IDENT + "']",
               "sink_file": "java.sql.Statement.executeQuery",
               "evidence": {"payload": "", "sink_sanitizer": ""}}
    assert compute_value_hit(IDENT, ev_live)["form"] == "hit_live"
    ev_san = dict(ev_live, evidence={"payload": "", "sink_sanitizer": "encodeForSQL"})
    assert compute_value_hit(IDENT, ev_san)["form"] == "hit_sanitized"
    ev_miss = {"source_value": "[SELECT * FROM u WHERE n='static']", "evidence": {}}
    assert compute_value_hit(IDENT, ev_miss)["form"] == "miss"
