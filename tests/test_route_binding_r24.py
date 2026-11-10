"""R24 路由绑定两处修复的回归守卫（2026-09-11）。

背景（两处都是「检测到但确认不了」的漏报根因，均用 target-mall 真实源码实证）：

1. 注解数组污染路由
   AdminController.dashboard 写作 ``@GetMapping({"", "/"})``（类前缀 /admin 本身就是入口）。
   旧实现 ``_spring_mapping_path_and_method`` 用「窗口里第一个非空字符串」的正则取路径，
   空串 "" 因量词要求至少 1 字符被跳过，正则改从第二个引号起匹配，把 ``"", "/"`` 之间的
   ``", "``（逗号 + 空格）当成路径 → 与类前缀拼成 ``/admin/,``。触发 spec 1718 记录该
   残缺路由，D1 重放直接 404，垂直越权族整体判 no_evidence。

2. 行号归属错绑（注解行 vs 方法声明行）
   SAST finding 的 line 是**方法级映射注解所在行**：``@PostMapping("/order/{id}/refund")``
   在第 107 行、方法声明 ``public String refund(...)`` 在第 108 行。
   旧 ``RouteIndex.lookup`` 用 ``[方法声明行, end_line]`` 判区间，107 落在 ship 的
   end_line(104) 之后、refund 的声明行(108) 之前 → 两侧都不命中 → 兜底取「不晚于 line 的
   最后一个 handler」= ship。于是退款滥用（abuse-dos）spec 被绑到 /order/{id}/ship，
   真值 #33 期望 /refund → 判 finding-only。

断言基线为 target-mall 真实源码，防解析能力回归。
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

from types import SimpleNamespace as NS

from src.core.param_resolver import (
    resolve_endpoint_from_source,
    is_valid_route,
)
from src.core.route_resolver import (
    build_route_index_from_dir,
    resolve_route_for_finding,
)

TARGET_MALL = os.path.join(LOCAL_ROOT, "target-mall")
WEB = TARGET_MALL + "/src/main/java/com/sanjio/mall/web"
ADMIN_CTRL = WEB + "/AdminController.java"
ORDER_CTRL = WEB + "/OrderController.java"


# ---------------------------------------------------------------------------
# 修复 1：注解数组写法不得产出逗号污染路由
# ---------------------------------------------------------------------------

def test_is_valid_route_rejects_comma_residue():
    """逗号是注解数组解析的残留，Spring 映射路径不会含逗号 —— 一律拒收。"""
    assert is_valid_route("/admin/,") is False
    assert is_valid_route("/admin/, ") is False
    assert is_valid_route("/a,b") is False
    assert is_valid_route("/admin") is True
    assert is_valid_route("/admin/") is True


def test_admin_dashboard_resolves_to_admin_not_comma():
    """@GetMapping({"", "/"}) + 类前缀 /admin → /admin，绝不能是 /admin/,。"""
    r = resolve_endpoint_from_source(NS(file=ADMIN_CTRL, line=31), TARGET_MALL)
    assert r is not None, "AdminController 第 31 行应解析出路由"
    assert r["route"] == "/admin", f"期望 /admin，实际 {r['route']!r}"
    assert "," not in r["route"]
    assert r["method"] == "GET"


def test_synthetic_mapping_array_no_comma():
    """合成源码：@GetMapping({"", "/"}) 与 @GetMapping({"/a", "/b"}) 均不得带逗号。"""
    import os
    import tempfile

    code = (
        "package com.t;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "@RequestMapping(\"/x\")\n"
        "public class X {\n"
        "    @GetMapping({\"\", \"/\"})\n"
        "    public String dash() { return \"d\"; }\n"
        "    @GetMapping({\"/a\", \"/b\"})\n"
        "    public String ab() { return \"r\"; }\n"
        "}\n"
    )
    d = tempfile.mkdtemp(prefix="r24_route_")
    p = os.path.join(d, "X.java")
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)

    r1 = resolve_endpoint_from_source(NS(file=p, line=6), d)  # @GetMapping 在第 6 行
    assert r1 is not None and r1["route"] == "/x", f"数组空串写法应拼成 /x，实际 {r1}"
    r2 = resolve_endpoint_from_source(NS(file=p, line=8), d)
    assert r2 is not None and r2["route"] == "/x/a", f"数组取首个路径应为 /x/a，实际 {r2}"
    assert "," not in r2["route"]


# ---------------------------------------------------------------------------
# 修复 2：注解行归属（findings.line 落在注解行）
# ---------------------------------------------------------------------------

def test_annotation_line_is_populated_and_precedes_method_line():
    """解析出的 RouteEntry 必须带 annotation_line，且不晚于方法声明行。"""
    idx = build_route_index_from_dir(TARGET_MALL)
    hits = [e for e in idx.entries if e.route == "/order/{id}/refund"]
    assert hits, "未解析出 /order/{id}/refund"
    e = hits[0]
    assert e.annotation_line > 0, "annotation_line 未落库"
    # refund 注解行 107、方法声明行 108；注解行应严格早于声明行
    assert e.annotation_line < e.line, f"annotation_line={e.annotation_line} line={e.line}"


def test_finding_on_annotation_line_binds_to_refund_not_ship():
    """退款 finding 报在注解行 107，必须绑到 /order/{id}/refund，不得错绑 ship。"""
    idx = build_route_index_from_dir(TARGET_MALL)
    hit = resolve_route_for_finding(idx, file=ORDER_CTRL, line=107)
    assert hit is not None
    assert hit["route"] == "/order/{id}/refund", f"错绑：{hit['route']}"
    assert hit["method_name"] == "refund"


def test_method_decl_line_still_binds_correctly():
    """方法声明行 108 同样应绑到 refund（注解行/声明行双保险）。"""
    idx = build_route_index_from_dir(TARGET_MALL)
    hit = resolve_route_for_finding(idx, file=ORDER_CTRL, line=108)
    assert hit is not None and hit["route"] == "/order/{id}/refund"


def test_adjacent_handlers_not_swapped():
    """相邻 handler 不得互相串绑：ship(100) → ship，invoice(117) → invoice。"""
    idx = build_route_index_from_dir(TARGET_MALL)
    assert resolve_route_for_finding(idx, file=ORDER_CTRL, line=100)["route"] == "/order/{id}/ship"
    assert resolve_route_for_finding(idx, file=ORDER_CTRL, line=117)["route"] == "/order/invoice"


# ---------------------------------------------------------------------------
# 修复 3：验收对账口径（check_r23_acceptance._match_specs）
# ---------------------------------------------------------------------------

from scripts.check_r23_acceptance import (  # noqa: E402
    _match_specs,
    _norm_route_key,
    _expand_tokens,
)


def _spec(family, endpoint, status="confirmed_exploitable"):
    return {"family": family, "target_endpoint": endpoint, "verification_status": status,
            "business_logic_confirmed": 0, "iast_state": ""}


def test_route_key_norm_strips_query_and_trailing_slash():
    assert _norm_route_key("/products?keyword") == "/products"
    assert _norm_route_key("/admin/") == "/admin"
    assert _norm_route_key("/api/internal/") == "/api/internal"


def test_token_alias_ssti_matches_template_injection():
    assert "template-injection" in _expand_tokens(["ssti"])
    ms = _match_specs(["ssti"], ["/marketing/preview"],
                      [_spec("template-injection", "/marketing/preview")])
    assert len(ms) == 1


def test_bare_slash_spec_must_not_match_any_truth():
    """端点记成裸 '/' 的残缺 spec 不得冒充命中任意真值（'/' 是任何路由的子串）。"""
    specs = [_spec("jwt-forgery", "/"), _spec("authentication-bypass", "/"),
             _spec("auth_session", "/")]
    assert _match_specs(["vertical", "jwt"], ["/admin/"], specs) == []
    assert _match_specs(["idor", "auth", "password"], ["/profile/password"], specs) == []


def test_reverse_containment_must_not_cross_contaminate():
    """spec /profile（idor/bola）不得冒充命中真值 /profile/password（越权改密）。"""
    specs = [_spec("idor", "/profile"), _spec("auth_session", "/profile/password", "unconfirmed")]
    ms = _match_specs(["idor", "auth", "password"], ["/profile/password"], specs)
    eps = {s["target_endpoint"] for s in ms}
    assert "/profile" not in eps, "反向包含导致跨漏洞假命中"
    assert eps == {"/profile/password"}


def test_forward_containment_still_matches_subpaths():
    """真值 /refund 应命中 spec /order/{id}/refund（正向包含，修复 #33 的前提）。"""
    ms = _match_specs(["abuse_dos"], ["/refund"],
                      [_spec("abuse-dos", "/order/{id}/refund")])
    assert len(ms) == 1

