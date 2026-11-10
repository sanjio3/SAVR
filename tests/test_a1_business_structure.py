"""A1 业务族结构特征确定性检测回归守卫（Q1，2026-09-10）。

背景：
    业务逻辑类 findings 此前**只能靠 LLM 产出**（A1BusinessLogicAIAgent + A2 LLM）。
    A2 一挂（如 audit_prompts 里 `/order/{id}` 触发 str.format KeyError 被吞），
    垂直越权/状态机/金额篡改类 findings 全部消失，任务仍报 completed。
    Q1 补一层**纯静态、不调 LLM** 的结构特征检测：handler 收资源 id + 按 id 直查 +
    无归属校验 → IDOR；流转端点无状态前置 → 状态机跳步；管理端点无权限注解 → 垂直越权；
    金额入参直传下单/支付且服务端未取价重算 → 金额篡改。

    本文件同时守卫两条误报红线（都是实测踩出来的）：
    - "/marketing/preview" 不得因 `mark\\w*` 被判状态机；
    - "/payment/sign" 不得因路由前缀里的 "pay" 被判状态机。
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

from src.agents.a1_business_structure_analyzer import (
    RULE_IDS,
    analyze_files,
    analyze_route,
)
from src.core.route_resolver import build_route_index_from_dir
from src.pipeline.a1.service import A1PipelineService, _dedup_hypos

TARGET_MALL = os.path.join(LOCAL_ROOT, "target-mall")


def _target_index():
    return build_route_index_from_dir(TARGET_MALL)


def _hypos():
    idx = _target_index()
    import os
    files = []
    for dp, dn, fn in os.walk(TARGET_MALL):
        dn[:] = [d for d in dn if d not in {"target", "build", ".git"}]
        for n in fn:
            if n.endswith((".java", ".html")):
                p = os.path.join(dp, n).replace("\\", "/")
                files.append({"path": p, "content": open(p, encoding="utf-8", errors="ignore").read()})
    return analyze_files(files, route_index=idx)


def _routes(hypos, rule):
    return {h["target_endpoint"] for h in hypos if h["rule_name"] == rule}


# ---------------------------------------------------------------------------
# 真实靶场：召回
# ---------------------------------------------------------------------------

def test_idor_structure_recalled():
    """真实 IDOR 端点（凭 id 直查、无归属校验）应被结构规则召回。"""
    hit = _routes(_hypos(), "IDOR_STRUCTURE")
    for expected in ("/order/{id}", "/profile", "/api/profile/{id}", "/comment/delete/{id}"):
        assert expected in hit, f"IDOR 结构未召回 {expected}"


def test_state_machine_skip_recalled():
    """未付款可发货 / 退款无约束 这类流转端点应被召回。"""
    hit = _routes(_hypos(), "STATE_MACHINE_SKIP")
    assert hit == {"/order/{id}/pay", "/order/{id}/ship", "/order/{id}/refund"}, hit


def test_admin_route_unguarded_recalled():
    """/admin/** 与 /ops/** 无任何权限注解 → 垂直越权结构。"""
    hit = _routes(_hypos(), "ADMIN_ROUTE_UNGUARDED")
    assert "/admin" in hit and "/admin/users" in hit
    assert "/ops/user/delete" in hit


def test_amount_tampering_recalled():
    """采信客户端 amount 的下单/支付端点应被召回。"""
    hit = _routes(_hypos(), "AMOUNT_TAMPERING")
    assert "/order/checkout" in hit
    assert "/wallet/withdraw" in hit


def test_vuln_type_normalizes_to_canonical_family():
    """vuln_type 经 _norm_family 归一后必须落在规范业务族上。

    否则两处会坏：①不在 DIFFERENTIAL_PROOF_FAMILIES → 被判成注入族，业务族差分门禁失效；
    ②与 A2 侧同一漏洞的 vhash 不一致 → 重复 finding + 孤儿 spec。
    实测踩坑：vuln_type 曾用 "STATE_MACHINE_BYPASS"，归一成 state_machine_bypass 两者皆错。
    """
    from src.core.exploit_spec import DIFFERENTIAL_PROOF_FAMILIES
    from src.core.vuln_hash import _norm_family

    for h in _hypos():
        item = {
            "type": h["vuln_type"],
            "description": h.get("evidence", ""),
            "file": h["file"],
            "sink": h.get("target_endpoint", ""),
        }
        fam = _norm_family(item)
        assert fam in DIFFERENTIAL_PROOF_FAMILIES, (h["rule_name"], h["vuln_type"], fam)
        assert fam == h["family"], (h["rule_name"], fam, h["family"])


def test_hypotheses_carry_real_route_and_param():
    """结构假说必须自带真实路由与参数（否则转不成 trigger_spec）。"""
    for h in _hypos():
        assert h["target_endpoint"].startswith("/"), h
        assert h["http_method"] in ("GET", "POST", "PUT", "DELETE", "PATCH"), h
        assert h["family"] in RULE_IDS.values(), h
        assert h["confidence"] in ("medium", "low"), h


# ---------------------------------------------------------------------------
# 误报红线
# ---------------------------------------------------------------------------

def test_marketing_preview_not_state_machine():
    """/marketing/preview 不得被 `mark\\w*` 命中为状态流转端点（实测误报）。"""
    assert "/marketing/preview" not in _routes(_hypos(), "STATE_MACHINE_SKIP")


def test_payment_sign_not_state_machine():
    """/payment/sign 不得因路由前缀含 "pay" 被判状态机（实测误报）。"""
    assert "/payment/sign" not in _routes(_hypos(), "STATE_MACHINE_SKIP")


def test_public_product_list_not_idor():
    """/products（无资源 id 入参）不得被判 IDOR。"""
    assert "/products" not in _routes(_hypos(), "IDOR_STRUCTURE")


def test_guarded_admin_route_not_flagged():
    """带 @PreAuthorize 的管理端点不算「无守卫」，不得报垂直越权。"""
    src = '''
package com.demo.web;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class SecureAdminController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public Object users(@RequestParam Long id) { return null; }
}
'''
    idx = __import__("src.core.route_resolver", fromlist=["x"]).build_route_index(
        [{"path": "SecureAdminController.java", "content": src}]
    )
    hypos = []
    for e in idx.entries:
        hypos.extend(analyze_route(e, src))
    assert [h for h in hypos if h["rule_name"] == "ADMIN_ROUTE_UNGUARDED"] == []


def test_ownership_check_suppresses_idor():
    """方法体内有归属校验（CurrentUser / owner 比对）时不报 IDOR。"""
    src = '''
package com.demo.web;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @GetMapping("/order/{id}")
    public Object detail(@PathVariable Long id) {
        Long uid = CurrentUser.of(request).uid();
        if (!order.getUserId().equals(uid)) { throw new AccessDeniedException(); }
        return orderService.findById(id);
    }
}
'''
    idx = __import__("src.core.route_resolver", fromlist=["x"]).build_route_index(
        [{"path": "OrderController.java", "content": src}]
    )
    hypos = []
    for e in idx.entries:
        hypos.extend(analyze_route(e, src))
    assert [h for h in hypos if h["rule_name"] == "IDOR_STRUCTURE"] == []


def test_status_guard_suppresses_state_machine():
    """有 getStatus() 前置判断的流转端点不报状态机跳步。"""
    src = '''
package com.demo.web;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @PostMapping("/order/{id}/ship")
    public Object ship(@PathVariable Long id) {
        Order o = orderService.find(id);
        if (!"PAID".equals(o.getStatus())) { throw new IllegalStateException(); }
        return orderService.ship(id);
    }
}
'''
    idx = __import__("src.core.route_resolver", fromlist=["x"]).build_route_index(
        [{"path": "OrderController.java", "content": src}]
    )
    hypos = []
    for e in idx.entries:
        hypos.extend(analyze_route(e, src))
    assert [h for h in hypos if h["rule_name"] == "STATE_MACHINE_SKIP"] == []


def test_server_side_recompute_suppresses_amount_tampering():
    """服务端取价重算时不报金额篡改。"""
    src = '''
package com.demo.web;
import org.springframework.web.bind.annotation.*;

@RestController
public class CartController {
    @PostMapping("/cart/checkout")
    public Object checkout(@RequestParam BigDecimal amount) {
        BigDecimal real = productMapper.findById(pid).getPrice();
        return orderService.checkout(real);
    }
}
'''
    idx = __import__("src.core.route_resolver", fromlist=["x"]).build_route_index(
        [{"path": "CartController.java", "content": src}]
    )
    hypos = []
    for e in idx.entries:
        hypos.extend(analyze_route(e, src))
    assert [h for h in hypos if h["rule_name"] == "AMOUNT_TAMPERING"] == []


# ---------------------------------------------------------------------------
# 去重与开关
# ---------------------------------------------------------------------------

def test_dedup_merges_three_paths_same_finding():
    """同一 handler + 同族 + 同参数的三路假说只保留一条。"""
    base = {"file": "D:/p/OrderController.java", "line": 81, "family": "idor",
            "vulnerable_param": "id"}
    bl = dict(base, target_endpoint="/order/{id}", rule_name="LLM")
    bola = dict(base, entry_point="D:/p/OrderController.java:81", rule_name="BOLA")
    struct = dict(base, target_endpoint="/order/{id}", rule_name="IDOR_STRUCTURE")
    assert len(_dedup_hypos([bl, bola, struct])) == 1


def test_dedup_keeps_different_families_on_same_method():
    """同一方法的 IDOR 与金额篡改属不同族，都要保留。"""
    base = {"file": "D:/p/OrderController.java", "line": 94}
    a = dict(base, family="idor", vulnerable_param="id")
    b = dict(base, family="calculation_logic", vulnerable_param="payAmount")
    assert len(_dedup_hypos([a, b])) == 2


def test_structure_analyzer_switch_off():
    """a1_business_structure=false 时不产出结构假说（便于 A/B 对照）。"""
    svc = A1PipelineService({"a1_business_structure": False})
    assert svc.analyze_business_structure([{"path": "A.java", "content": "class A{}"}]) == []


def test_non_java_project_yields_nothing():
    assert analyze_files([{"path": "a.py", "content": "def f(): pass"}]) == []
