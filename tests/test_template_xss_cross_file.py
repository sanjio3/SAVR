"""模板层 XSS 跨文件关联单元测试（块4 #17/#18）。

用贴近 target-mall 的夹具验证 a1_template_xss_analyzer 的跨文件关联：
1. 反射型 #17：GET /products 的 keyword 经 th:utext 原样回显。
2. 存储型 #16：POST /comment 写入 content，GET /product/{id} 用 th:utext 渲染 ${c.content}。
3. 存储型 #18：POST /profile/update 写入 signature，GET /profile 用 th:utext 渲染 ${user.signature}。

同时校验：开发数据（products.html 的 ${p.description}）因无写接口被正确跳过，不误报。
"""
import os
import sys

import pytest

# 让 src 可导入（与项目 pytest 一致）
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.agents.a1_template_xss_analyzer import analyze_files  # noqa: E402


_PRODUCT_CONTROLLER = """package com.sanjio.mall.web;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProductController {
    @GetMapping("/products")
    public String search(@RequestParam(required = false, defaultValue = "") String keyword, Model model) {
        model.addAttribute("products", list);
        model.addAttribute("keyword", keyword);
        return "products";
    }

    @GetMapping("/product/{id}")
    public String detail(@PathVariable Long id, Model model) {
        model.addAttribute("product", p);
        model.addAttribute("comments", comments);
        return "product";
    }
}
"""

_PROFILE_CONTROLLER = """package com.sanjio.mall.web;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProfileController {
    @GetMapping("/profile")
    public String profile(@RequestParam(required = false) Long id, Model model) {
        model.addAttribute("user", userMapper.findById(target));
        return "profile";
    }

    @PostMapping("/profile/update")
    public String update(@RequestParam Map<String, String> params, HttpServletRequest request) {
        User u = userMapper.findById(id);
        BeanWrapper bw = new BeanWrapperImpl(u);
        params.forEach((k, v) -> { if (bw.isWritableProperty(k)) bw.setPropertyValue(k, v); });
        userMapper.updateFull(u);
        return "redirect:/profile";
    }
}
"""

_COMMENT_CONTROLLER = """package com.sanjio.mall.web;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class CommentController {
    @PostMapping("/comment")
    public String add(@RequestParam Long productId, @RequestParam String content,
                      @RequestParam(required = false) String author, HttpServletRequest request) {
        c.setContent(content);
        commentMapper.insert(c);
        return "redirect:/product/" + productId;
    }
}
"""

_PRODUCTS_HTML = """<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<form method="get" action="/products">
  <input type="text" name="keyword" th:value="${keyword}"/>
</form>
<p th:utext="${keyword}">kw</p>
<p th:utext="${p.description}">desc</p>
</body>
</html>
"""

_PRODUCT_HTML = """<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<div th:each="c : ${comments}">
  <span class="xss-box" th:utext="${c.content}">评论内容</span>
</div>
</body>
</html>
"""

_PROFILE_HTML = """<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
<table>
  <tr><th>个性签名</th><td class="xss-box" th:utext="${user.signature}">sig</td></tr>
</table>
<form method="post" action="/profile/update">
  <input type="text" name="signature" placeholder="个性签名（支持 HTML）"/>
  <input type="text" name="role"/>
</form>
</body>
</html>
"""


def _files():
    return [
        {"path": "src/main/java/com/sanjio/mall/web/ProductController.java",
         "content": _PRODUCT_CONTROLLER, "language": "java"},
        {"path": "src/main/java/com/sanjio/mall/web/ProfileController.java",
         "content": _PROFILE_CONTROLLER, "language": "java"},
        {"path": "src/main/java/com/sanjio/mall/web/CommentController.java",
         "content": _COMMENT_CONTROLLER, "language": "java"},
        {"path": "src/main/resources/templates/products.html",
         "content": _PRODUCTS_HTML, "language": "template"},
        {"path": "src/main/resources/templates/product.html",
         "content": _PRODUCT_HTML, "language": "template"},
        {"path": "src/main/resources/templates/profile.html",
         "content": _PROFILE_HTML, "language": "template"},
    ]


def test_cross_file_xss_finds_three_sinks():
    hypos = analyze_files(_files())
    by_key = {(h["subtype"], h["target_endpoint"], h["vulnerable_param"]): h for h in hypos}

    # #17 反射型：/products 的 keyword
    reflected = by_key.get(("reflected", "/products", "keyword"))
    assert reflected is not None, f"未检出反射型 #17 /products keyword，实际：{hypos}"
    assert reflected["family"] == "xss"
    assert reflected["write_endpoint"] == ""

    # #16 存储型：/product/{id} 渲染 content，写接口 /comment
    stored_comment = by_key.get(("stored", "/product/{id}", "content"))
    assert stored_comment is not None, f"未检出存储型 #16 /product/{{id}} content，实际：{hypos}"
    assert stored_comment["write_endpoint"] == "/comment"

    # #18 存储型：/profile 渲染 signature，写接口 /profile/update
    stored_profile = by_key.get(("stored", "/profile", "signature"))
    assert stored_profile is not None, f"未检出存储型 #18 /profile signature，实际：{hypos}"
    assert stored_profile["write_endpoint"] == "/profile/update"


def test_cross_file_xss_skips_dev_data_without_write_endpoint():
    hypos = analyze_files(_files())
    # products.html 的 ${p.description} 无写接口 → 不应产出 stored 假说
    dev_data = [h for h in hypos if h["vulnerable_param"] == "description"]
    assert dev_data == [], f"开发数据 ${p.description} 不应被报为 XSS：{dev_data}"


def test_cross_file_xss_is_injection_family_not_business_logic():
    hypos = analyze_files(_files())
    for h in hypos:
        assert h["family"] == "xss"
        assert h["category"] == "xss"
        assert h["subtype"] in ("reflected", "stored")
