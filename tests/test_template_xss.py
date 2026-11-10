"""3.3 模板层 XSS analyzer 闭环回归守卫。

验证链：scanner 收 .html（模板内容闸门）→ a1_template_xss_analyzer 跨文件关联出假说 →
A1PipelineService.merge_template_xss_findings 转成注入族 Vulnerability（entry_point=真实路由，
供 A2 绑定 route → D2 验证）。target-mall 实测 3 条：/products 反射(keyword)、
/product/{id} 存储(content)、/profile 存储(signature)。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.a1_template_xss_analyzer import analyze_files
from src.pipeline.a1.service import A1PipelineService

_CONTROLLER = '''
package com.demo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class DemoController {

    @GetMapping("/search")
    public String search(@RequestParam String keyword, Model model) {
        model.addAttribute("keyword", keyword);
        return "search";
    }

    @GetMapping("/item/{id}")
    public String item(@PathVariable Long id, Model model) {
        model.addAttribute("item", service.get(id));
        return "item";
    }

    @PostMapping("/item/comment")
    public String addComment(@RequestParam String content) {
        commentMapper.insert(content);
        return "redirect:/item";
    }
}
'''

# 反射型：${keyword} root_var=keyword → model_key=keyword 直传
_SEARCH_TPL = '''<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body><span th:utext="${keyword}">kw</span></body>
</html>
'''

# 存储型：${item.content} → root_var=item=model_key，field=content 且有写接口 /item/comment
_ITEM_TPL = '''<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body><p th:utext="${item.content}">c</p></body>
</html>
'''


def _files():
    root = "proj/src/main"
    return [
        {"path": f"{root}/java/com/demo/DemoController.java", "rel_path": "DemoController.java",
         "content": _CONTROLLER, "language": "java"},
        {"path": f"{root}/resources/templates/search.html", "rel_path": "templates/search.html",
         "content": _SEARCH_TPL, "language": "template"},
        {"path": f"{root}/resources/templates/item.html", "rel_path": "templates/item.html",
         "content": _ITEM_TPL, "language": "template"},
    ]


def test_analyzer_detects_reflected_and_stored():
    hyps = analyze_files(_files())
    subtypes = {h["subtype"]: h for h in hyps}
    assert "reflected" in subtypes, f"应检出反射型，实际={[h['subtype'] for h in hyps]}"
    assert "stored" in subtypes, f"应检出存储型，实际={[h['subtype'] for h in hyps]}"
    r = subtypes["reflected"]
    assert r["target_endpoint"] == "/search"
    assert r["vulnerable_param"] == "keyword"
    s = subtypes["stored"]
    assert s["target_endpoint"] == "/item/{id}"
    assert s["vulnerable_param"] == "content"
    assert s["write_endpoint"] == "/item/comment"


def test_merge_produces_injection_family_vulnerabilities():
    svc = A1PipelineService.__new__(A1PipelineService)  # 不跑 __init__（避免依赖配置）
    merged = svc.merge_template_xss_findings([], _files())
    vulns = []
    for r in merged:
        vulns.extend(getattr(r, "vulnerabilities", []) or [])
    assert vulns, "merge 应产出模板层 XSS Vulnerability"
    routes = {v.entry_point for v in vulns}
    assert "/search" in routes and "/item/{id}" in routes, f"entry_point 应为真实路由，实际={routes}"
    for v in vulns:
        ae = getattr(v, "a1_evidence", {}) or {}
        assert ae.get("family") == "xss"
        assert ae.get("business_logic") is False, "xss 属注入族，不得标 business_logic"
        assert v.source == "a1-template-xss"
