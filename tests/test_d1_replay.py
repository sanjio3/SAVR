"""D1 重放契约（重构文档 §3.17）单测 + 注入 verify_via_iast_trigger 集成测试。

用 unittest.mock 把 requests.request / time.sleep 替掉，使重放不真正打网络、
不真正退避，可快速、确定性运行。验证点：
- canary 注入各 param_location（query/header/cookie/body/path）；
- service_url 与 endpoint 正确拼接；
- 瞬态异常 → D1 自重试 3 次 → 仍失败标 provisional 交 I2；
- 瞬态 5xx → 重试后成功（retried 计数正确）；
- multi-match：representative_request_params 全参数带标一次回放 + slices；
- 集成：把真实 IdorService 作为 dast_operator 注入 facade，全链路跑通。
"""
import json
import time
from unittest.mock import patch

import re

import pytest

from src.application.d1_service import D1Service
from src.agents.d2_facade import D2Agent
from src.iast.orchestrator import DastImpact


def _is_canary(v) -> bool:
    """参数位是否携带平台规范 canary（身份段 s4st41 + 十六进制）。

    历史：本文件早期直接断言参数位等于 spec.taint_marker 的字面量（'CANARY123' /
    's4st41abcd' / 'CANARY_MAIN'）。现行实现改为「参数位由 D1 生成规范 canary，请求头
    X-SASTAI-Trace 承载 spec 的 taint_marker」，旧断言因此全部失效。现改为校验 canary 形态
    而非具体字面量，既保住「canary 注入到正确位置」这一契约，又不再绑定实现细节。
    """
    return isinstance(v, str) and re.match(r"^s4st41[0-9a-f]+$", v) is not None


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        # 2026-09-28（测试桩对齐）：真实 requests.Response 恒有 headers，
        # 补上以消除桩与产物失配导致的 AttributeError（非产物回归）。
        self.headers = {}


def _svc():
    return D1Service()


def test_replay_injects_canary_into_query():
    captured = {}

    def fake_request(method, url, params=None, headers=None, cookies=None, json=None, data=None, **kw):
        captured.update(method=method, url=url, params=params, headers=headers or {}, cookies=cookies or {}, json=json, data=data)
        return FakeResponse(200, "ok")

    spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": "s4st41deadbeef00"}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)

    assert isinstance(imp, DastImpact)
    assert imp.reached is True
    assert imp.status_code == 200
    assert imp.provisional is False
    assert captured["url"] == "http://app.local/api/search"
    assert captured["params"]["q"] == "s4st41deadbeef00"


@pytest.mark.parametrize("loc,getter", [
    ("header", lambda c: c["headers"].get("id")),
    ("cookie", lambda c: c["cookies"].get("id")),
    ("body", lambda c: (c["json"] or {}).get("id")),
    ("path", lambda c: c["url"]),
])
def test_replay_injects_into_locations(loc, getter):
    captured = {}

    def fake_request(method, url, params=None, headers=None, cookies=None, json=None, data=None, **kw):
        captured.update(method=method, url=url, params=params, headers=headers or {}, cookies=cookies or {}, json=json, data=data)
        return FakeResponse(200, "ok")

    spec = {"target_endpoint": "/api/{id}", "http_method": "POST", "param_name": "id",
            "param_location": loc, "taint_marker": "CANARY123"}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)

    assert imp.reached is True
    # 参数位只需落在正确位置且是规范 canary；具体字面量由 D1 生成，不再断言 spec 里的 marker。
    if loc == "path":
        assert re.match(r"^http://app\.local/api/s4st41[0-9a-f]+$", captured["url"]), captured["url"]
    else:
        _v = getter(captured)
        assert _is_canary(_v), (loc, _v)
    # 请求头始终承载 spec 的 taint_marker（身份溯源锚点）
    assert captured["headers"].get("X-SASTAI-Trace") == "CANARY123"


def test_replay_retry_three_times_then_provisional():
    calls = {"n": 0}

    def fake_request(*a, **k):
        calls["n"] += 1
        raise RuntimeError("connection refused")

    spec = {"target_endpoint": "/x", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": "C"}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)

    assert calls["n"] == 3
    assert imp.provisional is True
    assert imp.reached is False
    assert "connection refused" in imp.error


def test_replay_retries_on_5xx_then_succeeds():
    seq = [FakeResponse(503, "busy"), FakeResponse(503, "busy"), FakeResponse(200, "ok")]
    calls = {"n": 0}

    def fake_request(*a, **k):
        i = calls["n"]
        calls["n"] += 1
        return seq[min(i, len(seq) - 1)]

    spec = {"target_endpoint": "/x", "http_method": "GET", "param_name": "q",
            "param_location": "query", "taint_marker": "C"}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)

    assert calls["n"] == 3
    assert imp.reached is True
    assert imp.status_code == 200
    assert imp.retried == 2
    assert imp.provisional is False


def test_replay_multi_match_representative_params():
    captured = {}

    def fake_request(method, url, params=None, headers=None, cookies=None, json=None, data=None, **kw):
        captured.update(params=params or {}, json=json, headers=headers or {}, cookies=cookies or {})
        return FakeResponse(200, "ok")

    spec = {
        "target_endpoint": "/api/item",
        "http_method": "POST",
        "param_name": "id",
        "param_location": "query",
        "taint_marker": "CANARY_MAIN",
        "representative_request_params": [
            {"param_name": "id", "param_location": "query", "taint_marker": "CANARY_MAIN"},
            {"param_name": "name", "param_location": "body", "taint_marker": "CANARY_NAME"},
            {"param_name": "XTrace", "param_location": "header", "taint_marker": "CANARY_TRACE"},
        ],
    }
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)

    # 主参数（与 spec.param_name 同名）由 D1 投放规范 canary；其余 representative 参数保留原 marker。
    assert _is_canary(captured["params"]["id"]), captured["params"]
    assert (captured["json"] or {})["name"] == "CANARY_NAME"
    assert captured["headers"]["XTrace"] == "CANARY_TRACE"
    assert captured["headers"]["X-SASTAI-Trace"] == "CANARY_MAIN"
    assert set(imp.slices.keys()) == {"id", "name", "XTrace"}


def test_facade_wires_real_d1_operator():
    """把真实 IdorService 作为 dast_operator 注入 facade.verify_via_iast_trigger，验证全链路。"""

    captured = {}

    def fake_request(method, url, params=None, headers=None, cookies=None, json=None, data=None, **kw):
        captured["called"] = True
        captured["url"] = url
        return FakeResponse(200, "some body")

    class FakeIast:
        def poll_events_by_canary(self, canary, since_id=0, limit=50,
                                 app_name=None, agent_id=None, trace_id=None):
            # 让编排器早停：返回一条 sink-reached 事件（§4.2 隔离形参兼容）。
            # 富化：携带完整链路字段（taint_path / sink / stack_trace / source_value），
            # 使 I1 逐节点链路符合性按「方案 B 真实探针事件」判 conforms=True，
            # 而非退化成「缺 source / 不可证伪」（旧桩只有一个 canary_state 字段）。
            return [{
                "id": 1,
                "canary_state": "sink-reached",
                "canary": canary,
                "stack_trace": "at com.demo.SearchController.query(SearchController.java:42)",
                # v2 A3/值级通道（2026-10-10）：sink_file 必须落在本族真实危险函数画像上
                # （sqli → java.sql.Statement.execute），写源码文件名会被
                # is_family_relevant_sink 身份校验剔除，值级命中退化为证据缺失。
                "sink_method": "java.sql.Statement.execute",
                "sink_file": "java.sql.Statement.execute",
                "sink_line": 42,
                # v2 A3/A5（2026-10-10）：exploitable 确认需要语义层证据 —— sink 实参值里必须
                # 真的看得见 spec 的投放数据（taint_marker）。旧 fixture 写的是完整 canary，
                # 与 taint_marker("s4st41abc") 不同串，值级比对不命中 ⇒ 只剩探针断言（证明力 2）
                # ⇒ 被「到达≠可利用」闸门正确降级。现让 sink 实参带上 taint_marker 构成
                # hit_live，测试继续锁「全链路到 confirmed_exploitable」。
                "source_value": "SELECT * FROM users WHERE name='s4st41abc'",
                "taint_path_json": json.dumps([
                    {"role": "source", "origin": "GET /api/search#q(query)"},
                    {"role": "transform", "origin": "java.sql.Statement.execute"},
                    {"role": "sink", "origin": "java.sql.Statement.execute"},
                ]),
            }]

    svc = _svc()
    facade = D2Agent()
    vuln = {"id": "v1", "type": "SQLI"}
    external_target = {"service_url": "http://app.local", "app_name": "demo",
                       "agent_id": "a1", "probe_mode": "monitor"}
    # 富化 spec：带真实攻击 payload（family/category/attack_payloads）→ D1 回放非降级，
    # 全链路才能走到 confirmed_attributable（降级探针到达 sink 按设计只判 ambiguous）。
    trigger_spec = {"target_endpoint": "/api/search", "http_method": "GET", "param_name": "q",
                    "param_location": "query", "taint_marker": "s4st41abc",
                    "vulnerability_hash_v2": "h1",
                    "family": "sql-injection", "category": "sql-injection",
                    "attack_payloads": ["' OR '1'='1"]}

    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        vr = facade.verify(vuln, {}, external_target=external_target, trigger_spec=trigger_spec,
                           iast_service=FakeIast(), dast_operator=svc)

    assert captured.get("called") is True, "真实 D1 操作器 replay 应被调用"
    assert vr.iast_evidence.get("state") == "sink-reached"
    assert vr.final_state in ("confirmed_attributable", "runtime_confirmed")
    # 2026-10-10（v2 证据分层）：exploitable=True 现由**值级 hit_live**（sink 实参值里
    # 比对到 taint_marker，证明力 4）支撑，不再是裸 200 响应 —— A5 铁律：reached(L1)
    # 不再派生 impact_observed(L4)。降级只发生在「只有探针断言、无任何语义证据」时 ——
    # 回归锁见 tests/test_d2_arrival_only_downgrade.py（14 条）。
    assert vr.exploitable is True
    vd = vr.verification_decision
    assert vd["verification_status"] == "confirmed_exploitable"
    assert vd["arrival_only_downgraded"] is False


def test_phase2_default_off_no_impact_request():
    """§7.10：默认 phase2_enabled=False → 不发 impact_payload 请求。"""
    captured = {"phase1": 0, "phase2": 0}

    def fake_request(method, url, **kw):
        if kw.get("json") and kw["json"].get("payload") == "rm -rf /":
            captured["phase2"] += 1
        else:
            captured["phase1"] += 1
        return FakeResponse(200, "ok")

    spec = {
        "target_endpoint": "/api/cmd", "http_method": "POST", "param_name": "cmd",
        "param_location": "body", "taint_marker": "CANARY",
        "impact_payloads": ["rm -rf /"], "phase2_override": True,
    }
    target = {"service_url": "http://app.local"}  # 无 phase2_enabled
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        _svc().replay(spec, target)
    assert captured["phase1"] == 1
    assert captured["phase2"] == 0


def test_phase2_enabled_with_whitelist_sends_impact_request():
    """§7.10：phase2_enabled=True + target 在白名单 + spec.phase2_override → 打 Phase 2。"""
    captured = {"phase1": 0, "phase2": 0}

    def fake_request(method, url, **kw):
        if kw.get("json") and kw["json"].get("payload") in ("rm -rf /", "DROP TABLE x;"):
            captured["phase2"] += 1
        else:
            captured["phase1"] += 1
        return FakeResponse(200, "ok")

    spec = {
        "target_endpoint": "/api/cmd", "http_method": "POST", "param_name": "cmd",
        "param_location": "body", "taint_marker": "CANARY",
        "impact_payloads": ["rm -rf /", "DROP TABLE x;"], "phase2_override": True,
    }
    target = {
        "service_url": "http://app.local",
        "settings": {"phase2_enabled": True, "phase2_whitelist": ["http://app.local"]},
    }
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)
    assert captured["phase1"] == 1
    assert captured["phase2"] == 2
    assert "phase2:0" in imp.slices
    assert "phase2:1" in imp.slices


def test_phase2_enabled_target_not_in_whitelist_blocked():
    """§7.10：phase2_enabled=True 但目标不在白名单 → 阻断。"""
    captured = {"phase2": 0}

    def fake_request(method, url, **kw):
        if kw.get("json") and kw["json"].get("payload") == "rm -rf /":
            captured["phase2"] += 1
        return FakeResponse(200, "ok")

    spec = {
        "target_endpoint": "/api/cmd", "http_method": "POST", "param_name": "cmd",
        "param_location": "body", "taint_marker": "CANARY",
        "impact_payloads": ["rm -rf /"], "phase2_override": True,
    }
    target = {
        "service_url": "http://other.local",
        "settings": {"phase2_enabled": True, "phase2_whitelist": ["http://app.local"]},
    }
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        _svc().replay(spec, target)
    assert captured["phase2"] == 0


def test_replay_injects_trace_header():
    """§7.1 平台侧：每次 replay 自动注入 X-SASTAI-Trace 头供探针透传关联。

    2026-08-29 契约变更（评审）：头里携带的必须是 canary 身份段本身，而不是随机 UUID。
    这样 I1 关联的是「这次请求的身份」而非「payload 的值」—— payload 后续加绕过、变形、
    编码、混淆都不会让 I1 丢失监听（这正是 canary 融合方案的死穴）。
    """
    captured = {}

    def fake_request(method, url, params=None, headers=None, **kw):
        captured["headers"] = headers or {}
        return FakeResponse(200, "ok")

    spec = {"target_endpoint": "/api/x", "http_method": "GET", "param_name": "id",
            "param_location": "query", "taint_marker": "CANARY"}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        _svc().replay(spec, target)
    assert "X-SASTAI-Trace" in captured["headers"]
    # 头里就是 canary 本身 —— I1 按此做请求级关联，与 payload 形态解耦
    assert captured["headers"]["X-SASTAI-Trace"] == "CANARY"


def test_replay_uses_a2_attack_payload_not_canary():
    """通道B：参数位投放 A2 构造的真实 payload，canary 只留请求头。

    payload 构造是 A2 的职责；D1 绝不硬编码最小威力探测串。
    """
    captured = {}

    def fake_request(method, url, params=None, headers=None, json=None, data=None, **kw):
        captured.update(params=params or {}, headers=headers or {}, json=json, data=data)
        return FakeResponse(200, "ok")

    spec = {"target_endpoint": "/debug/import", "http_method": "POST", "param_name": "data",
            "param_location": "body", "taint_marker": "s4st41abcd",
            "category": "deserialization",
            "attack_payloads": ["rO0ABXNy-gadget-chain"]}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)
    # 参数位是 A2 的真 payload（不是 canary）—— body 位置走 json=
    assert (captured["json"] or {}).get("data") == "rO0ABXNy-gadget-chain"
    # 头里才是 canary
    assert captured["headers"].get("X-SASTAI-Trace") == "s4st41abcd"
    # 未被标记降级，且记录了实际投放的 payload
    assert imp.attack_degraded is False
    assert imp.attack_payload_used == "rO0ABXNy-gadget-chain"


def test_replay_degrades_to_canary_when_a2_has_no_payload():
    """A2 没造出真 payload 时退化为纯 canary 探针，但必须显式标记 attack_degraded。

    不允许拿最小威力探测串冒充攻击，也不允许把可达性弱证据伪装成攻击证据。
    """
    captured = {}

    def fake_request(method, url, params=None, headers=None, **kw):
        captured.update(params=params or {}, headers=headers or {})
        return FakeResponse(200, "ok")

    spec = {"target_endpoint": "/api/x", "http_method": "GET", "param_name": "id",
            "param_location": "query", "taint_marker": "s4st41abcd",
            "category": "sql-injection", "attack_payloads": []}
    target = {"service_url": "http://app.local"}
    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        imp = _svc().replay(spec, target)
    # 回落到 canary 探针：参数位是规范 canary（具体身份由 D1 生成），头里保留 spec 的 marker
    assert _is_canary(captured["params"].get("id")), captured["params"]
    assert captured["headers"].get("X-SASTAI-Trace") == "s4st41abcd"
    assert imp.attack_degraded is True
    assert imp.attack_payload_used == ""
