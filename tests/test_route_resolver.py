"""静态路由解析回归守卫（Q2，2026-09-10）。

背景：
    findings 必须绑到**真实 HTTP 路由**才转得成 trigger_spec。历史上靠 A2 LLM 顺带
    猜 route，产出 "/"、"/admin/"、"/admin/," 这类残缺路由，或 LLM 一挂业务族归零。
    Q2 改为纯静态解析 Spring 注解，A1 阶段前置绑定。本文件用 target-mall 真实
    controller 断言解析结果，防回归。
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

from src.core.route_resolver import (
    RouteIndex,
    build_route_index,
    build_route_index_from_dir,
    is_plausible_route,
    join_route,
    parse_java_routes,
    resolve_route_for_finding,
)

TARGET_MALL = os.path.join(LOCAL_ROOT, "target-mall")
WEB = TARGET_MALL + "/src/main/java/com/sanjio/mall/web"
PRODUCT_CTRL = WEB + "/ProductController.java"
ORDER_CTRL = WEB + "/OrderController.java"
ADMIN_CTRL = WEB + "/AdminController.java"


def _index():
    return build_route_index_from_dir(TARGET_MALL)


def _one(entries, route, method=None):
    hits = [e for e in entries if e.route == route and (method is None or e.method == method)]
    assert hits, f"未解析出路由 {route}（共 {len(entries)} 条）"
    return hits[0]


# ---------------------------------------------------------------------------
# 真实工程：路由解析
# ---------------------------------------------------------------------------

def test_target_mall_routes_parsed():
    """target-mall 应解析出全部 controller 路由（数量与关键路由双重断言）。"""
    idx = _index()
    routes = {e.route for e in idx.entries}
    for expected in (
        "/products", "/product/{id}", "/api/products/sort", "/api/products/by-category",
        "/profile", "/api/profile/{id}", "/profile/update", "/profile/password",
        "/order/{id}", "/order/{id}/pay", "/order/{id}/ship", "/order/{id}/refund",
        "/order/buy", "/order/checkout", "/order/invoice", "/order/import-xml",
        "/admin", "/admin/ping", "/admin/fetch", "/admin/report", "/admin/users",
        "/comment", "/comment/delete/{id}", "/api/comment/moderate",
        "/login", "/api/internal/users", "/api/internal/config",
        "/wallet/transfer", "/upload", "/seckill",
    ):
        assert expected in routes, f"缺失路由 {expected}"
    # 全量 59 条（2026-09-10 基线）；允许新增路由，但不允许解析能力退化
    assert len(idx.entries) >= 59, f"解析条数退化：{len(idx.entries)}"


def test_class_prefix_with_empty_method_path_maps_to_prefix():
    """/admin 类前缀 + @GetMapping({"", "/"}) 应映射到 /admin，不是 /admin/。"""
    idx = _index()
    entry = _one(idx.entries, "/admin", "GET")
    assert entry.class_name == "AdminController"
    assert entry.method_name == "dashboard"
    assert entry.class_routes == ["/admin"]
    assert entry.view_name == "admin"


def test_class_prefix_join():
    """@RestController + 类级 /api/internal + 方法级 /users → /api/internal/users。"""
    idx = _index()
    entry = _one(idx.entries, "/api/internal/users")
    assert entry.class_name == "InternalApiController"
    assert entry.json_response is True  # @RestController


def test_http_method_from_mapping_annotation():
    """@GetMapping/@PostMapping 的方法识别。"""
    idx = _index()
    assert _one(idx.entries, "/products").method == "GET"
    assert _one(idx.entries, "/order/buy").method == "POST"
    assert _one(idx.entries, "/order/buy").methods == ["POST"]


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------

def test_path_variable_param():
    """@PathVariable Long id → location=path。"""
    idx = _index()
    entry = _one(idx.entries, "/order/{id}")
    idp = [p for p in entry.params if p.name == "id"]
    assert idp and idp[0].location == "path"
    assert idp[0].type == "Long"
    assert entry.path_variables == ["id"]


def test_request_param_optional_with_default():
    """@RequestParam(required=false, defaultValue="") 不得把 "false" 解析成参数名。"""
    idx = _index()
    entry = _one(idx.entries, "/products")
    kw = [p for p in entry.params if p.name == "keyword"]
    assert kw, f"/products 参数解析错误：{[p.name for p in entry.params]}"
    assert kw[0].location == "query"
    assert kw[0].required is False
    assert kw[0].default == ""


def test_request_param_explicit_name():
    """@RequestParam("key") String key → 参数名取注解值而非类型名。"""
    idx = _index()
    entry = _one(idx.entries, "/api/fw/redis")
    assert [p.name for p in entry.params if p.location != "infra"] == ["key"]


def test_request_body_param_location():
    """@RequestBody → location=body。"""
    idx = _index()
    entry = _one(idx.entries, "/order/import-xml")
    xml = [p for p in entry.params if p.name == "xml"]
    assert xml and xml[0].location == "body"


def test_generic_map_param_keeps_variable_name():
    """@RequestParam Map<String, String> params 不得把 "String>" 解析成参数名。"""
    idx = _index()
    entry = _one(idx.entries, "/profile/update")
    names = [p.name for p in entry.params if p.location != "infra"]
    assert names == ["params"], f"泛型参数名解析错误：{names}"


def test_infra_params_marked_and_excluded_from_binding():
    """Model / HttpServletRequest 等框架入参标 infra，绑定结果里不出现。"""
    idx = _index()
    entry = _one(idx.entries, "/products")
    assert any(p.location == "infra" for p in entry.params)  # Model model
    hit = resolve_route_for_finding(idx, file=PRODUCT_CTRL, line=34)
    assert [p["name"] for p in hit["params"]] == ["keyword"]


# ---------------------------------------------------------------------------
# 视图 / 模板映射
# ---------------------------------------------------------------------------

def test_view_name_resolved_to_template_file():
    """@Controller 返回的视图名应解析到 templates/*.html。"""
    idx = _index()
    entry = _one(idx.entries, "/products")
    assert entry.view_name == "products"
    assert entry.view_template.endswith("/templates/products.html")


def test_json_response_method_has_no_view():
    """@ResponseBody 方法里的 `return "ERROR: " + ...` 不得被当成视图名。"""
    idx = _index()
    entry = _one(idx.entries, "/order/invoice")
    assert entry.json_response is True
    assert entry.view_name == ""


# ---------------------------------------------------------------------------
# finding → route 归属
# ---------------------------------------------------------------------------

def test_lookup_by_file_and_line():
    """按源码行号归属到正确的 handler（方法体区间）。"""
    idx = _index()
    assert resolve_route_for_finding(idx, file=PRODUCT_CTRL, line=34)["route"] == "/products"
    assert resolve_route_for_finding(idx, file=PRODUCT_CTRL, line=42)["route"] == "/product/{id}"
    assert resolve_route_for_finding(idx, file=ORDER_CTRL, line=102)["route"] == "/order/{id}/ship"


def test_lookup_supports_relative_path_dual_track():
    """A1 绝对路径 / A2 相对路径都要能命中（路径双轨制）。"""
    idx = _index()
    rel = "src/main/java/com/sanjio/mall/web/ProductController.java"
    hit = resolve_route_for_finding(idx, file=rel, line=34)
    assert hit and hit["route"] == "/products"


def test_lookup_by_method_name():
    idx = _index()
    hit = resolve_route_for_finding(idx, file=ORDER_CTRL, method_name="refund")
    assert hit and hit["route"] == "/order/{id}/refund"
    assert hit["qualified_name"] == "OrderController#refund"


def test_lookup_unknown_file_returns_none():
    idx = _index()
    assert resolve_route_for_finding(idx, file="D:/nope/Foo.java", line=1) is None
    assert resolve_route_for_finding(None, file=PRODUCT_CTRL, line=34) is None


def test_resolve_marks_static_status():
    idx = _index()
    hit = resolve_route_for_finding(idx, file=PRODUCT_CTRL, line=34)
    assert hit["route_status"] == "static"
    assert hit["class_name"] == "ProductController"


# ---------------------------------------------------------------------------
# 纯函数 / 合成用例（覆盖 target-mall 里没有的注解形态）
# ---------------------------------------------------------------------------

def test_join_route_rules():
    assert join_route("/admin", "") == "/admin"
    assert join_route("/admin", "/") == "/admin"
    assert join_route("/admin", "/ping") == "/admin/ping"
    assert join_route("", "/products") == "/products"
    assert join_route("/api", "users") == "/api/users"


def test_is_plausible_route_rejects_stub_routes():
    """与 A2._sanitize_llm_route 同口径："/"、"/admin/"、多值污染一律拒收。"""
    assert not is_plausible_route("/")
    assert not is_plausible_route("")
    assert not is_plausible_route("/admin/, /users")
    assert not is_plausible_route("products")
    assert is_plausible_route("/order/{id}")
    assert is_plausible_route("/admin")


def test_request_mapping_with_explicit_method():
    """@RequestMapping(value="/x", method=RequestMethod.POST) 识别 POST。"""
    src = '''
package com.demo.web;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @RequestMapping(value = "/create", method = RequestMethod.POST)
    public Object create(@RequestBody String body) {
        return body;
    }

    @RequestMapping(value = "/multi", method = {RequestMethod.GET, RequestMethod.POST})
    public Object multi(@RequestParam String q) {
        return q;
    }

    @RequestMapping("/any")
    public Object any() {
        return "ok";
    }
}
'''
    entries = parse_java_routes("DemoController.java", src)
    routes = {e.route: e for e in entries}
    assert routes["/api/demo/create"].method == "POST"
    assert routes["/api/demo/create"].params[0].location == "body"
    assert set(routes["/api/demo/multi"].methods) == {"GET", "POST"}
    assert routes["/api/demo/any"].method_explicit is False  # 未声明 method


def test_non_controller_java_file_returns_empty():
    src = "package com.demo.dao;\npublic class ReportDao { public void run() {} }\n"
    assert parse_java_routes("ReportDao.java", src) == []


def test_guard_annotations_collected():
    """@PreAuthorize 等权限注解要收集（Q1 业务族结构特征判据要用）。"""
    src = '''
package com.demo.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class SecureController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/secure/users")
    public Object users() {
        return null;
    }

    @GetMapping("/secure/open")
    public Object open() {
        return null;
    }
}
'''
    entries = {e.route: e for e in parse_java_routes("SecureController.java", src)}
    assert entries["/secure/users"].has_guard is True
    assert entries["/secure/users"].guards[0].startswith("@PreAuthorize")
    assert entries["/secure/open"].has_guard is False


def test_build_route_index_from_files_skips_non_java():
    idx = build_route_index([
        {"path": "src/main/resources/templates/products.html", "content": "<div th:utext='${keyword}'></div>"},
        {"path": "src/main/java/com/demo/Demo.java", "content": "class Demo { }"},
    ])
    assert len(idx) == 0
    assert idx.template_map.get("products", "").endswith("templates/products.html")


# ── 权限守卫必须覆盖 Shiro + URL 级全局兜底（2026-11-02）───────────────────────
#
# 事故：若依首扫产出 105 条 vertical_privesc，**0 条确认**。逐条核对发现：
#   1. `_GUARD_ANNOTATIONS` 只有 Spring Security 的 8 个注解，**没有 Shiro 的
#      `@RequiresPermissions`**。若依全站 Shiro，实测 112 处，全被当成「无权限注解」。
#      反例：`SysRoleController#list` 第 53 行就有 `@RequiresPermissions("system:role:list")`。
#   2. 更根本的是「没注解 ≠ 没鉴权」：若依 ShiroConfig 有
#      `filterChainDefinitionMap.put("/**", "user,kickout,...")` —— 全站要求认证。
#      58 个无注解的管理端点全在认证之后，判成越权是错的。
#
# 修完实测（若依真源码）：管理前缀 139 个，有 guard 81，无 guard 但全站认证 58，
# **仍会被报越权 0**（修前 105）。

def _idx(*files):
    from src.core.route_resolver import build_route_index
    return build_route_index([{"path": p, "content": c} for p, c in files])


SHIRO_CTRL = '''package d;
@RestController
@RequestMapping("/system/role")
public class SysRoleController {
    @RequiresPermissions("system:role:list")
    @PostMapping("/list")
    public String list(String role) { return ""; }
}
'''

SHIRO_CONFIG = '''package d;
public class ShiroConfig {
    public Object filter() {
        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/**", "user,kickout,onlineSession,syncOnlineSession");
        return null;
    }
}
'''


def test_shiro_requires_permissions_counts_as_guard():
    idx = _idx(("a/SysRoleController.java", SHIRO_CTRL))
    e = idx.routes()[0]
    assert e.guards, "Shiro 的 @RequiresPermissions 必须算 guard"
    assert e.has_guard


def test_global_url_auth_guard_is_detected():
    idx = _idx(("a/SysRoleController.java", SHIRO_CTRL), ("a/ShiroConfig.java", SHIRO_CONFIG))
    e = idx.routes()[0]
    assert e.app_requires_auth is True, e.app_auth_evidence
    assert "/**" in e.app_auth_evidence


def test_anon_only_chain_is_not_auth_guard():
    """`/**` → `anon` 不算认证兜底（否则会把「全站开放」误判成「全站受保护」）。"""
    cfg = SHIRO_CONFIG.replace('"user,kickout,onlineSession,syncOnlineSession"', '"anon"')
    idx = _idx(("a/SysRoleController.java", SHIRO_CTRL), ("a/ShiroConfig.java", cfg))
    assert idx.routes()[0].app_requires_auth is False


def test_spring_security_anyrequest_authenticated_is_detected():
    sec = '''package d;
public class SecConfig {
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();
    }
}
'''
    idx = _idx(("a/SysRoleController.java", SHIRO_CTRL), ("a/SecConfig.java", sec))
    assert idx.routes()[0].app_requires_auth is True
