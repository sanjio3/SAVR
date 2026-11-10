"""Q2 回归：业务逻辑/BOLA finding 经 a1_evidence 携带的 HTTP 端点必须能被 resolver 解析，
从而经 auto_register_from_a2 登记为可重放的 trigger_spec、最终到达 D1。

此前 resolver 只读 exploit_spec.entry / top-level entry_route / entry_point，完全忽略
a1_evidence.target_endpoint / http_method / vulnerable_param——导致融合后的业务逻辑 finding
全部 skipped_unresolved、永远到不了 D1。本测试锁死该闭环。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.param_resolver import resolve_trigger_endpoint  # noqa: E402


def test_business_logic_a1_evidence_endpoint_resolves():
    """LLM 业务逻辑假说只挂 a1_evidence.target_endpoint，无 exploit_spec → 必须解析出路由+参数。"""
    vuln = {"type": "BOLA", "entry_point": "app/OrderController.java:42"}  # file:line，非 HTTP
    a1_ev = {
        "business_logic": True,
        "category": "bola",
        "family": "IDOR",
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "vulnerable_param": "id",
    }
    res = resolve_trigger_endpoint(vuln, a1_evidence=a1_ev)
    assert res["route"] == "/api/order/{id}", res
    assert res["method"] == "GET", res
    assert res["param_name"] == "id", res
    assert res["resolvable"] is True, res
    assert res["param_name_source"] == "a1-business-logic", res


def test_business_logic_matches_discovered_route():
    """a1_evidence 端点命中 entry_discovery 真实路由 → Tier0 精确匹配，参数取真实请求参数。"""
    vuln = {"type": "BOLA", "entry_point": "app/X.java:1"}
    a1_ev = {
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "vulnerable_param": "id",
    }
    discovered = [{
        "route": "/api/order/{id}",
        "method": "GET",
        "params": [{"param_name": "id", "param_location": "path"}],
    }]
    res = resolve_trigger_endpoint(
        vuln, a1_evidence=a1_ev, discovered_routes=discovered
    )
    assert res["route"] == "/api/order/{id}", res
    assert res["param_name"] == "id", res
    assert res["resolvable"] is True, res


def test_no_endpoint_stays_unresolved_no_garbage():
    """无任何端点信息时，不得编造路由/参数（不静默注入无效 spec）。"""
    vuln = {"type": "BOLA", "entry_point": "app/X.java:1"}
    a1_ev = {"business_logic": True}
    res = resolve_trigger_endpoint(vuln, a1_evidence=a1_ev)
    assert res["route"] == "", res
    assert res["param_name"] == "", res
    assert res["resolvable"] is False, res


def test_offline_bola_file_line_not_injected_as_route():
    """离线 BOLA 把 entry_point 设为 file:line，绝不能把它当 HTTP 路由注入。"""
    vuln = {
        "type": "BOLA",
        "entry_point": "app/OrderController.java:42",
        "function": "getOrder",
        "param": "orderId",
    }
    a1_ev = {"business_logic": True, "family": "IDOR"}
    res = resolve_trigger_endpoint(vuln, a1_evidence=a1_ev)
    # file:line 不是合法路由，不应被解析为可重放端点
    assert res["route"] != "app/OrderController.java:42", res
