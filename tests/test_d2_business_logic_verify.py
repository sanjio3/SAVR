"""业务逻辑漏洞统一 verify() 路由（#2/#5）回归测试。

验证：
- D2Agent.verify() 在收到 business_logic trigger_spec 时透明路由到 business_logic.verify
  （差分重放），返回与 canary 路径同构的 VerificationResult；
- 确认结论被折叠进 verification_decision.verification_status = confirmed_exploitable，
  使攻击计划命中指标能计入业务逻辑命中（消除「0 命中」错觉）；
- 非业务逻辑且无 trigger_spec 仍走 no_evidence 基线，行为不退化。
"""
from unittest import mock

from src.agents.d2_facade import D2Agent
from src.agents.d2_types import VerificationResult


def _bl_vuln():
    return {
        "type": "BOLA",
        "a1_evidence": {
            "business_logic": True,
            "category": "bola",
            "target_endpoint": "/api/order/{id}",
            "http_method": "GET",
            "vulnerable_param": "id",
        },
    }


def test_resolve_business_logic_category_from_spec():
    agent = D2Agent()
    assert agent._resolve_business_logic_category(
        {"business_logic_category": "bola"}, None) == "bola"
    # 别名归一
    assert agent._resolve_business_logic_category(
        {"category": "IDOR"}, None) == "bola"
    # 非业务类返回 None
    assert agent._resolve_business_logic_category(
        {"category": "injection"}, None) is None
    # 从 vulnerability.a1_evidence 回退
    assert agent._resolve_business_logic_category(
        None, {"a1_evidence": {"business_logic": True, "category": "vertical_privesc"}}) == "vertical_privesc"


def test_verify_routes_to_business_logic_and_confirms():
    fake = {
        "confirmed": True,
        "data_leak_confirmed": True,
        "authz_hook_confirmed": True,
        "confidence": "high",
        "category": "bola",
        "reason": "attacker accessed victim resource",
    }
    with mock.patch("src.iast.business_logic.verify", return_value=fake) as m:
        agent = D2Agent()
        spec = {
            "business_logic_category": "bola",
            "target_endpoint": "/api/order/{id}",
            "http_method": "GET",
            "param_name": "id",
            "accounts": {"attacker": {"auth_headers": {}}, "victim": {"auth_headers": {}}},
        }
        result = agent.verify(_bl_vuln(), {}, {"service_url": "http://x"}, trigger_spec=spec)
        assert isinstance(result, VerificationResult)
        assert result.exploitable is True
        assert result.final_state == "confirmed"
        # 差分重放结论必须折叠进统一裁决，使攻击计划命中指标能计入
        assert result.verification_decision.get("verification_status") == "confirmed_exploitable"
        assert result.dast_impact_evidence.get("business_logic", {}).get("confirmed") is True
        # 确实调用了 business_logic.verify 且传了正确类目
        m.assert_called_once()
        assert m.call_args.args[0] == "bola"


def test_verify_business_logic_unconfirmed_no_evidence():
    fake = {
        "confirmed": False,
        "data_leak_confirmed": False,
        "authz_hook_confirmed": False,
        "confidence": "low",
        "category": "bola",
    }
    with mock.patch("src.iast.business_logic.verify", return_value=fake):
        agent = D2Agent()
        spec = {"business_logic_category": "bola", "target_endpoint": "/x", "accounts": None}
        result = agent.verify(_bl_vuln(), {}, {"service_url": "http://x"}, trigger_spec=spec)
        assert result.exploitable is False
        assert result.final_state == "no_evidence"
        assert result.verification_decision.get("verification_status") == "unconfirmed"


def test_technical_vuln_no_spec_still_no_evidence():
    agent = D2Agent()
    result = agent.verify({"type": "injection"}, {}, {"service_url": "http://x"}, trigger_spec=None)
    assert result.final_state == "no_evidence"
    assert result.exploitable is False


class _FakeIastService:
    """模拟探针侧 IAST 服务：按 canary 回带业务型可达性/授权 hook 事件。"""

    def __init__(self, events=None, blindspots=None):
        self._events = events or []
        self._blindspots = blindspots or []
        self.poll_calls = []

    def poll_events_by_canary(self, canary, since_id=0, limit=50, app_name=None, agent_id=None, trace_id=None):
        self.poll_calls.append(("events", canary, app_name, agent_id))
        return [dict(e, canary=canary) for e in self._events]

    def poll_authz_blindspots(self, canary, app_name=None, agent_id=None, limit=20):
        self.poll_calls.append(("blindspots", canary, app_name, agent_id))
        return [dict(b, canary=canary) for b in self._blindspots]


def _bl_spec_with_canary():
    return {
        "business_logic_category": "bola",
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "param_name": "id",
        "taint_marker": "s4st41deadbeef00000001",
        "victim_resource_id": "victim-1",
        "accounts": {"attacker": {"auth_headers": {}}, "victim": {"auth_headers": {}}},
    }


def test_verify_business_logic_iast_authz_confirmed():
    """差分未确认，但探针产出 BOLA_SUSPECT 授权 hook 事件 → 消费可达性确认 exploitable。"""
    diff = {
        "confirmed": False,
        "data_leak_confirmed": False,
        "authz_hook_confirmed": False,
        "confidence": "low",
        "category": "bola",
    }
    fake_iast = _FakeIastService(
        events=[{"id": 1, "event_type": "BOLA_SUSPECT", "canary_state": "arrived",
                 "sink_method": "OrderController.getOrder", "source_value": "victim-1"}],
        blindspots=[{"id": 1, "event_type": "BOLA_SUSPECT", "principal": "attacker",
                     "source_value": "victim-1", "sink_method": "OrderController.getOrder"}],
    )
    with mock.patch("src.iast.business_logic.verify", return_value=diff):
        agent = D2Agent()
        result = agent.verify(
            _bl_vuln(), {}, {"service_url": "http://x", "app_name": "mall", "agent_id": "a1"},
            trigger_spec=_bl_spec_with_canary(), iast_service=fake_iast,
        )
    assert result.exploitable is True
    assert result.final_state == "confirmed"
    ie = result.iast_evidence
    assert ie["iast_authz_confirmed"] is True
    assert ie["iast_reached"] is True
    assert ie["authz_event_count"] == 1
    assert ie["confirmed_via"] == "iast-authz"
    assert "iast-authz-confirmed" == ie["state"]
    assert result.verification_decision.get("verification_status") == "confirmed_exploitable"


def test_verify_business_logic_iast_reach_only_confirmed():
    """差分未确认，探针仅观测到请求到达预测操作（无 authz hook）→ 不确认（v2 B4 闸门）。

    v2 证据分层（2026-10-10）：「仅到达应用」不构成有害判定（L1 传输层 ≠ L4 裁决层），
    确认必须来自差分 / 副作用 / authz hook 机制级证据。本用例锁定：
    exploitable=False、iast_reached 事实保留、且带 C 批诚实声明元数据。
    """
    diff = {
        "confirmed": False,
        "data_leak_confirmed": False,
        "authz_hook_confirmed": False,
        "confidence": "low",
        "category": "bola",
    }
    fake_iast = _FakeIastService(
        events=[{"id": 2, "event_type": "request_observed", "canary_state": "arrived",
                 "sink_method": "OrderController.getOrder"}],
        blindspots=[],
    )
    with mock.patch("src.iast.business_logic.verify", return_value=diff):
        agent = D2Agent()
        result = agent.verify(
            _bl_vuln(), {}, {"service_url": "http://x", "app_name": "mall", "agent_id": "a1"},
            trigger_spec=_bl_spec_with_canary(), iast_service=fake_iast,
        )
    assert result.exploitable is False
    assert result.iast_evidence["iast_reached"] is True
    assert result.iast_evidence["iast_authz_confirmed"] is False
    assert result.iast_evidence["confirmed_via"] == "iast-reach"
    assert result.iast_evidence["state"] == "iast-reached"
    # C 批诚实声明：差分三态落 verdict 与 decision，且「仅到达」绝不冒充 confirmed
    assert result.d2_verdict["differential_state"] in ("no_difference", "ambiguous")
    assert result.verification_decision["differential_state"] == result.d2_verdict["differential_state"]
    assert result.verification_decision["verification_status"] == "unconfirmed"


def test_verify_business_logic_no_iast_falls_back_to_diff():
    """未注入 iast_service（探针未联网）→ fail-open，仅依赖差分结论，不污染结果。"""
    diff = {
        "confirmed": False,
        "data_leak_confirmed": False,
        "authz_hook_confirmed": False,
        "confidence": "low",
        "category": "bola",
    }
    with mock.patch("src.iast.business_logic.verify", return_value=diff):
        agent = D2Agent()
        result = agent.verify(
            _bl_vuln(), {}, {"service_url": "http://x"},
            trigger_spec=_bl_spec_with_canary(), iast_service=None,
        )
    assert result.exploitable is False
    assert result.final_state == "no_evidence"
    ie = result.iast_evidence
    assert ie["iast_reached"] is False
    assert ie["iast_authz_confirmed"] is False
    assert ie["state"] == "no-iast-evidence"
