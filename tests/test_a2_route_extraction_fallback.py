"""回归守卫：A2 路由"提取层"兜底（file:line -> discovered_routes）。

覆盖 #8 SSTI /marketing/preview、#21 JWT垂直 /admin/* 等此前 route 恒为空、
无法登记 trigger_spec 的问题。直接用真实 target-mall 入口发现产物验证。
"""

import os

import pytest

LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")
pytestmark = [
    pytest.mark.external,
    pytest.mark.skipif(
        not LOCAL_ROOT,
        reason="external target sources required: set SAST_AI_SDL_ROOT to your local targets root",
    ),
]

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.application.entry_discovery_service import EntryDiscoveryService
from src.agents.a2_intelligent_agent import A2SemanticAgent


def _discovered_routes():
    srv = EntryDiscoveryService()
    res = srv.discover(os.path.join(LOCAL_ROOT, "target-mall"), framework="spring")
    return [e for e in res["entries"] if e.get("entry_type") == "web_route"]


def _fake_vuln(file, line, **kw):
    attrs = dict(
        file=file, line=line, entry_point="", data_flow="", description="",
        type="", callers="", code_snippet="", sink="", a1_evidence={}, llm_route="",
        llm_params=[], finding_family="", display_family="", business_logic_category="",
        chain_id="", canonical_group_key="", has_http_entry=False, has_call_chain=False,
    )
    attrs.update(kw)
    return types.SimpleNamespace(**attrs)


def test_sanitize_admin_trailing_slash():
    # /admin/ 去尾斜杠保留为类级前缀（不再硬拒）
    assert A2SemanticAgent._sanitize_llm_route("/admin/") == "/admin"
    # 含逗号残缺仍拒
    assert A2SemanticAgent._sanitize_llm_route("/admin/,") == "/admin"
    assert A2SemanticAgent._sanitize_llm_route("/") == ""
    # 具体子路由正常
    assert A2SemanticAgent._sanitize_llm_route("/admin/users") == "/admin/users"


def test_pick_admin_route_prefers_concrete():
    routes = [
        {"route": "/admin", "file": "x", "line": 1},
        {"route": "/admin/,", "file": "x", "line": 2},
        {"route": "/admin/users", "file": "x", "line": 3},
    ]
    assert A2SemanticAgent._pick_admin_route(routes) == "/admin/users"


def test_match_discovered_route_by_location_ssti():
    dr = _discovered_routes()
    # #8 SSTI: MarketingController.java L25 -> /marketing/preview
    v = _fake_vuln("src/main/java/com/sanjio/mall/web/MarketingController.java", 25, type="模板注入")
    hit = A2SemanticAgent({})._match_discovered_route_by_location(v, dr)
    assert hit is not None, "SSTI 应匹配到 /marketing/preview"
    assert hit["route"] == "/marketing/preview", hit
    # 实体类（User.java）无对应路由 -> 不匹配
    v2 = _fake_vuln("src/main/java/com/sanjio/mall/entity/User.java", 13)
    assert A2SemanticAgent({})._match_discovered_route_by_location(v2, dr) is None


def test_match_discovered_route_by_location_admin_vertical():
    dr = _discovered_routes()
    # #21 JWT垂直：AdminController 内某方法（行号取 /admin/users 之后）应匹配到 /admin/users
    v = _fake_vuln("src/main/java/com/sanjio/mall/web/AdminController.java", 70,
                   display_family="基础设施层-垂直越权")
    hit = A2SemanticAgent({})._match_discovered_route_by_location(v, dr)
    assert hit is not None, "垂直越权应匹配到 admin 子路由"
    assert "/admin/" in hit["route"], hit


def test_build_exploit_spec_fallback_populates_route():
    dr = _discovered_routes()
    agent = A2SemanticAgent({})
    # SSTI 用例：llm_route 为空，entry_point 为空 -> 兜底拿 /marketing/preview
    v = _fake_vuln("src/main/java/com/sanjio/mall/web/MarketingController.java", 25, type="模板注入")
    spec = agent._build_exploit_spec(v, discovered_routes=dr)
    assert spec["entry"]["route"] == "/marketing/preview", spec["entry"]["route"]
    # 垂直越权用例：应落到具体 /admin/users
    v2 = _fake_vuln("src/main/java/com/sanjio/mall/web/AdminController.java", 70,
                    display_family="基础设施层-垂直越权", type="垂直越权")
    spec2 = agent._build_exploit_spec(v2, discovered_routes=dr)
    assert "/admin/" in spec2["entry"]["route"], spec2["entry"]["route"]
