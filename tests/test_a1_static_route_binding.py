"""A1 阶段静态路由前置绑定回归守卫（Q2，2026-09-10）。

背景：
    路由此前只能靠 A2 LLM 在语义分析时"顺便"猜。LLM 一挂（如 audit_prompts 里
    `/order/{id}` 触发 str.format KeyError）业务族 findings 直接归零；LLM 敷衍输出
    "/"、"／admin/" 之类残缺路由写进 exploit_spec 后 D2 构造请求必失败。
    Q2 改为 A1 阶段用静态解析的 Spring 路由前置绑定，LLM 只做兜底。

    本文件守卫两条铁律：
    1. 命中静态路由 → a1_evidence.target_endpoint / exploit_spec.entry.route 被填上真实路由；
    2. 未命中 → 标 route_status='static-failed' 且**绝不回填任何猜测值**（宁缺毋滥）。
"""
from src.core.models import ScanResult, Vulnerability
from src.pipeline.a1.service import A1PipelineService

PRODUCT_CTRL = "D:/proj/src/main/java/com/demo/web/ProductController.java"
DAO_FILE = "D:/proj/src/main/java/com/demo/dao/ReportDao.java"

CONTROLLER_SRC = '''
package com.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/shop")
public class ProductController {

    @GetMapping("/products")
    public String search(@RequestParam(required = false, defaultValue = "") String keyword, Model model) {
        model.addAttribute("keyword", keyword);
        return "products";
    }

    @GetMapping("/product/{id}")
    public String detail(@PathVariable Long id, Model model) {
        return "product";
    }
}
'''

DAO_SRC = '''
package com.demo.dao;
public class ReportDao {
    public void run(String sql) { }
}
'''


def _files():
    return [
        {"path": PRODUCT_CTRL, "content": CONTROLLER_SRC, "language": "java"},
        {"path": DAO_FILE, "content": DAO_SRC, "language": "java"},
        {"path": "src/main/resources/templates/products.html", "content": "<div th:utext='${keyword}'></div>"},
    ]


def _vuln(file, line, **kw):
    v = Vulnerability(
        type=kw.pop("type", "BUSINESS_LOGIC"),
        severity="medium",
        line=line,
        description=kw.pop("description", ""),
        file=file,
        source="a1",
        confidence=kw.pop("confidence", "medium"),
        **kw
    )
    v.a1_evidence = {"business_logic": True, "category": "idor", "family": "idor"}
    return v


def _bind(vulns):
    svc = A1PipelineService({})
    results = [ScanResult(file=PRODUCT_CTRL, vulnerabilities=vulns, agent="a1")]
    return svc.bind_static_routes(results, _files())


# ---------------------------------------------------------------------------
# 命中
# ---------------------------------------------------------------------------

def test_static_route_bound_to_a1_evidence():
    """controller 内的 finding 应被绑上类前缀拼接后的真实路由。"""
    results = _bind([_vuln(PRODUCT_CTRL, 14)])
    v = results[0].vulnerabilities[0]
    ev = v.a1_evidence
    assert ev["route_status"] == "static"
    assert ev["target_endpoint"] == "/shop/products"
    assert ev["http_method"] == "GET"
    assert ev["route_handler"] == "ProductController#search"
    # 唯一候选入参时补位 vulnerable_param；Model 属 infra 不得计入
    assert ev["vulnerable_param"] == "keyword"
    assert [p["name"] for p in ev["static_route_params"]] == ["keyword"]


def test_exploit_spec_entry_filled_for_a2_outage():
    """即便 A2 整体失败，finding 也已携带可达入口（消除 A2 单点故障的前置条件）。"""
    results = _bind([_vuln(PRODUCT_CTRL, 19)])
    v = results[0].vulnerabilities[0]
    assert v.exploit_spec["entry"]["route"] == "/shop/product/{id}"
    assert v.exploit_spec["entry"]["method"] == "GET"
    assert v.exploit_spec["entry"]["resolved_by"] == "a1-static-route"
    assert v.has_http_entry is True


def test_existing_entry_route_not_overwritten():
    """已有 entry.route（A2 ground truth）时不得被覆盖。"""
    v = _vuln(PRODUCT_CTRL, 14)
    v.exploit_spec = {"entry": {"route": "/legacy", "method": "POST"}}
    results = _bind([v])
    entry = results[0].vulnerabilities[0].exploit_spec["entry"]
    assert entry["route"] == "/legacy"
    assert entry["method"] == "POST"


def test_view_template_carried():
    results = _bind([_vuln(PRODUCT_CTRL, 14)])
    ev = results[0].vulnerabilities[0].a1_evidence
    assert ev["view_template"].endswith("/templates/products.html")


def test_multi_param_route_does_not_guess_param():
    """多候选入参时不得猜测 vulnerable_param，只留参数清单给下游选。"""
    src = CONTROLLER_SRC.replace(
        '@GetMapping("/products")\n    public String search(@RequestParam(required = false, defaultValue = "") String keyword, Model model) {',
        '@GetMapping("/products")\n    public String search(@RequestParam String keyword, @RequestParam String sort, Model model) {',
    )
    files = [
        {"path": PRODUCT_CTRL, "content": src},
        {"path": DAO_FILE, "content": DAO_SRC},
    ]
    svc = A1PipelineService({})
    results = svc.bind_static_routes(
        [ScanResult(file=PRODUCT_CTRL, vulnerabilities=[_vuln(PRODUCT_CTRL, 13)], agent="a1")],
        files,
    )
    ev = results[0].vulnerabilities[0].a1_evidence
    assert ev["route_status"] == "static"
    assert ev["target_endpoint"] == "/shop/products"
    assert "vulnerable_param" not in ev or not ev.get("vulnerable_param")
    assert [p["name"] for p in ev["static_route_params"]] == ["keyword", "sort"]


# ---------------------------------------------------------------------------
# 未命中：绝不编造
# ---------------------------------------------------------------------------

def test_non_controller_file_marked_static_failed_without_fabrication():
    svc = A1PipelineService({})
    results = svc.bind_static_routes(
        [ScanResult(file=DAO_FILE, vulnerabilities=[_vuln(DAO_FILE, 3)], agent="a1")],
        _files(),
    )
    v = results[0].vulnerabilities[0]
    assert v.a1_evidence["route_status"] == "static-failed"
    assert v.a1_evidence.get("target_endpoint", "") == ""
    assert v.exploit_spec.get("entry", {}).get("route", "") == ""
    assert v.has_http_entry is False


def test_source_path_in_target_endpoint_is_cleared():
    """源码路径当 HTTP 端点的污染必须清掉（entry_point 属代码定位，保持原样）。

    离线 BOLA 分析器的 entry_point 形如 ``.../OrderService.java:118``，会被
    _hypo_to_vulnerability 一并写进 a1_evidence.target_endpoint；该字段是
    resolve_endpoint_full 的一等候选，留着会让下游拿源码路径当真实路由
    （task-4 实锤：spec 550/551 的 target_endpoint 即 orderservice.java:118）。
    """
    v = _vuln(DAO_FILE, 3)
    v.a1_evidence["target_endpoint"] = "D:/proj/src/main/java/com/demo/service/OrderService.java:118"
    v.entry_point = "D:/proj/src/main/java/com/demo/service/OrderService.java:118"
    svc = A1PipelineService({})
    results = svc.bind_static_routes(
        [ScanResult(file=DAO_FILE, vulnerabilities=[v], agent="a1")], _files()
    )
    out = results[0].vulnerabilities[0]
    assert out.a1_evidence["target_endpoint"] == ""
    assert out.a1_evidence["route_status"] == "static-failed-source-path-cleared"
    # 代码定位字段不受影响
    assert out.entry_point.endswith("OrderService.java:118")


def test_real_route_not_cleared_when_already_present():
    """已是真实路由（非源码路径）时不得被清理逻辑误伤。"""
    v = _vuln(DAO_FILE, 3)
    v.a1_evidence["target_endpoint"] = "/order/{id}"
    svc = A1PipelineService({})
    results = svc.bind_static_routes(
        [ScanResult(file=DAO_FILE, vulnerabilities=[v], agent="a1")], _files()
    )
    assert results[0].vulnerabilities[0].a1_evidence["target_endpoint"] == "/order/{id}"


def test_missing_file_skipped():
    v = _vuln("", 1)
    results = _bind([v])
    assert results[0].vulnerabilities[0].a1_evidence.get("route_status") is None


def test_bind_meta_recorded():
    svc = A1PipelineService({})
    svc.bind_static_routes(
        [ScanResult(file=PRODUCT_CTRL, vulnerabilities=[_vuln(PRODUCT_CTRL, 14)], agent="a1")],
        _files(),
    )
    meta = getattr(svc, "_last_route_bind_meta", {})
    assert meta.get("routes") == 2
    assert meta.get("bound") == 1
