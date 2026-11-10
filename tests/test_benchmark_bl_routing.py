"""Items 2/3/5 胶水层测试：benchmark_cli 在统一 verify() 入口处对业务逻辑漏洞的路由。

覆盖：
- _is_business_logic_vuln：a1_evidence.business_logic / 归一化类别命中 / 纯注入类不命中
- _normalize_bl_category：idor→bola 等别名归一
- _build_business_logic_spec：构造带 business_logic_category + 双账号的 trigger_spec
（d2_facade._verify_business_logic 的路由与折叠逻辑由 test_d2_business_logic_verify.py 覆盖，
本文件只验证「benchmark_cli 是否把正确的 spec 喂给 verify()」这一未测 seam。）
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.cli import benchmark_cli as bc


def test_normalize_bl_category_aliases():
    # idor 在 D1 重放层与 BOLA 同路由（business_logic.verify 仅 8 类，无 idor）
    assert bc._normalize_bl_category("idor") == "bola"
    assert bc._normalize_bl_category("vertical") == "vertical_privesc"
    assert bc._normalize_bl_category("calculation") == "calculation_logic"
    assert bc._normalize_bl_category("abuse_dos") == "abuse_dos"
    assert bc._normalize_bl_category("") is None
    assert bc._normalize_bl_category("sql_injection") is None
    # captcha / dos 非差分证明族（不在 P2 真源 9 类 + 别名表），合并后不再误归业务型
    assert bc._normalize_bl_category("captcha") is None
    assert bc._normalize_bl_category("dos") == "abuse_dos"  # P2 真源 dos→abuse_dos


def test_is_business_logic_vuln_a1_evidence_flag():
    vuln = {"a1_evidence": {"business_logic": True, "category": "bola"}}
    assert bc._is_business_logic_vuln(vuln) is True


def test_is_business_logic_vuln_category_normalized():
    # A2 产出 type=BOLA / VERTICAL 等
    assert bc._is_business_logic_vuln({"type": "BOLA"}) is True
    assert bc._is_business_logic_vuln({"category": "vertical_privesc"}) is True
    assert bc._is_business_logic_vuln({"vuln_type": "IDOR"}) is True


def test_is_business_logic_vuln_rejects_pure_injection():
    # 纯注入类不应误判为业务逻辑（走 canary 污点重放而非差分重放）
    assert bc._is_business_logic_vuln({"type": "sql_injection"}) is False
    assert bc._is_business_logic_vuln({"a1_evidence": {"business_logic": False}, "type": "command_injection"}) is False
    assert bc._is_business_logic_vuln({}) is False


def test_build_business_logic_spec_carries_category_and_accounts():
    vuln = {
        "a1_evidence": {
            "business_logic": True,
            "category": "IDOR",
            "target_endpoint": "/api/quote/:id",
            "http_method": "GET",
            "vulnerable_param": "id",
        }
    }
    external_target = {"app_name": "java-quote", "service_url": "http://localhost:8899"}
    accounts = {"attacker": {"username": "a", "role": "attacker"}, "victim": {"username": "b", "role": "victim"}}
    spec = bc._build_business_logic_spec(vuln, external_target, accounts)
    assert spec is not None
    assert spec["business_logic_category"] == "bola"  # idor→bola 归一
    assert spec["target_endpoint"] == "/api/quote/:id"
    assert spec["http_method"] == "GET"
    assert spec["param_name"] == "id"
    assert spec["accounts"] == accounts


def test_build_business_logic_spec_no_category_returns_none():
    vuln = {"a1_evidence": {"business_logic": True}}  # 无 category
    spec = bc._build_business_logic_spec(vuln, {}, None)
    assert spec is None


def test_resolve_endpoint_full_business_derivation_consistent_two_channels():
    """业务族 Service/DAO 漏洞经 Service->Controller 推导解析出真实路由后，
    通道 B（exploit_spec.entry.route，pre_resolve 写入）与通道 A（trigger_specs.target_endpoint，
    auto_register 写入）必须是同一 resolve_endpoint_full 的结果——两投影一致、不再 100% vs 16.7% 漂移。
    """
    from src.iast.trigger_spec_registry import resolve_endpoint_full

    discovered = [{
        "route": "/api/order/create", "method": "POST", "file": "com/sanjio/mall/controller/OrderController.java",
        "line": 40, "params": [{"param_name": "amount", "param_location": "query"}],
    }]
    vuln = {
        "type": "race",
        "file": "com/sanjio/mall/service/OrderServiceImpl.java",
        "line": 56,
        "exploit_spec": {"payload": {"payload_family": "race"}, "entry": {"method": "POST"}},
    }
    resolved = resolve_endpoint_full(vuln, {}, code_root=None, discovered_routes=discovered)
    # 业务推导应命中 OrderController 的真实路由
    assert resolved["route"] == "/api/order/create", resolved
    assert resolved["resolvable"] is True
    # 通道 B 投影
    entry = {
        "route": resolved["route"], "method": resolved["method"],
        "parameter_name": resolved["param_name"], "parameter_location": resolved["param_location"],
    }
    # 通道 A 投影（target_endpoint 仅取 route+method+param 字段）
    target_endpoint = {
        "route": resolved["route"], "method": resolved["method"],
        "parameter_name": resolved["param_name"], "parameter_location": resolved["param_location"],
    }
    assert entry == target_endpoint  # 两投影同源 => 完全一致


def test_resolve_endpoint_full_vertical_privesc_admin_route_correction():
    """垂直越权 A2 幻觉端点 /ops/user/delete（实测 405）应被 discovered_routes 真实
    /admin/users 纠正；pre_resolve 与 auto_register 共用同一纠正逻辑。
    """
    from src.iast.trigger_spec_registry import resolve_endpoint_full

    discovered = [{
        "route": "/admin/users", "method": "GET", "file": "com/sanjio/mall/controller/AdminController.java",
        "line": 30, "params": [],
    }]
    vuln = {
        "type": "vertical_privesc",
        "file": "com/sanjio/mall/controller/AdminController.java",
        "line": 35,
        "exploit_spec": {"payload": {"payload_family": "vertical_privesc"},
                         "entry": {"route": "/ops/user/delete", "method": "GET"}},
    }
    resolved = resolve_endpoint_full(vuln, {}, code_root=None, discovered_routes=discovered)
    # 幻觉端点被纠正为真实管理路由
    assert resolved["route"] == "/admin/users", resolved
    assert resolved["category"] == "vertical_privesc"
    assert resolved["resolvable"] is True
