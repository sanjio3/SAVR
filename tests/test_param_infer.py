"""param_infer 单测（2026-11-01，阶段 2）。

锁死三件事：
  1. 六条通道各自能推出参数（header/cookie 是新增的两条，治 cors 的 Origin 与 shiro 的 rememberMe）；
  2. 工具类 sink 走调用图回溯到 Controller；
  3. **路径三种写法都要能对上**（绝对 Windows 路径 / 相对正斜杠 / 相对反斜杠）——
     本轮实测库里三种同时存在，不归一就「有索引查不到」。
"""
from __future__ import annotations

import json
import os

from src.core.param_infer import (
    infer_for_spec,
    infer_param_from_method,
    rel_path,
    resolve_source_file,
)


JAVA_CTRL = """package demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class DemoController {

    @GetMapping("/ssrf")
    public String ssrf(@RequestParam String url) {
        return HttpUtil.fetch(url);
    }

    @GetMapping("/cors")
    public String cors(@RequestHeader("Origin") String origin) {
        return origin;
    }

    @GetMapping("/remember")
    public String remember(@CookieValue("rememberMe") String token) {
        return token;
    }

    @PostMapping("/body")
    public String body(@RequestBody String payload) {
        return payload;
    }

    @GetMapping("/plain")
    public String plain(HttpServletRequest req) {
        String ip = req.getParameter("ip");
        return ip;
    }
}
"""

JAVA_UTIL = """package demo;

public class HttpUtil {
    public static String fetch(String url) {
        return url;
    }
}
"""


def _write_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "DemoController.java").write_text(JAVA_CTRL, encoding="utf-8")
    (tmp_path / "src" / "HttpUtil.java").write_text(JAVA_UTIL, encoding="utf-8")
    idx = {
        "src/DemoController.java:ssrf": {
            "file": "src/DemoController.java", "line": 8,
            "parameters": "String url", "callers": [],
            "http_entry": {"route": "/ssrf", "method": "GET"},
        },
        "src/DemoController.java:cors": {
            "file": "src/DemoController.java", "line": 13,
            "parameters": "String origin", "callers": [],
            "http_entry": {"route": "/cors", "method": "GET"},
        },
        "src/DemoController.java:remember": {
            "file": "src/DemoController.java", "line": 18,
            "parameters": "String token", "callers": [],
            "http_entry": {"route": "/remember", "method": "GET"},
        },
        "src/DemoController.java:body": {
            "file": "src/DemoController.java", "line": 23,
            "parameters": "String payload", "callers": [],
            "http_entry": {"route": "/body", "method": "POST"},
        },
        "src/DemoController.java:plain": {
            "file": "src/DemoController.java", "line": 28,
            "parameters": "HttpServletRequest req", "callers": [],
            "http_entry": {"route": "/plain", "method": "GET"},
        },
        # 工具类：没有 http_entry，callers 指向 Controller
        "src/HttpUtil.java:fetch": {
            "file": "src/HttpUtil.java", "line": 4,
            "parameters": "String url",
            "callers": ["src/DemoController.java:ssrf"],
            "http_entry": None,
        },
    }
    return idx


def test_channels_query_header_cookie_body(tmp_path):
    idx = _write_tree(tmp_path)
    root = str(tmp_path)
    assert infer_for_spec(root, idx, "src/DemoController.java", 8).name == "url"
    g = infer_for_spec(root, idx, "src/DemoController.java", 13)
    assert (g.name, g.location) == ("Origin", "header")
    g = infer_for_spec(root, idx, "src/DemoController.java", 18)
    assert (g.name, g.location) == ("rememberMe", "cookie")
    g = infer_for_spec(root, idx, "src/DemoController.java", 23)
    assert (g.name, g.location) == ("payload", "body")
    # 方法体里的 getParameter("ip") 字面量
    assert infer_for_spec(root, idx, "src/DemoController.java", 28).name == "ip"


def test_util_sink_backtraces_to_controller(tmp_path):
    """工具类 sink（HttpUtil.fetch）必须回溯到 Controller 的 @RequestParam。"""
    idx = _write_tree(tmp_path)
    g = infer_for_spec(str(tmp_path), idx, "src/HttpUtil.java", 5)
    assert g.name == "url", g.as_dict()
    assert g.confidence != "low"


def test_path_forms_all_resolve(tmp_path):
    """三种路径写法（绝对 / 相对正斜杠 / 相对反斜杠）都要能定位到同一个文件。"""
    idx = _write_tree(tmp_path)
    root = str(tmp_path)
    abs_path = os.path.join(root, "src", "HttpUtil.java")
    for form in (abs_path, "src/HttpUtil.java", "src\\HttpUtil.java"):
        rel = rel_path(form, root)
        assert rel == "src/httputil.java", (form, rel)
        assert resolve_source_file(root, form, idx), form
        assert infer_for_spec(root, idx, form, 5).name == "url", form


def test_unknown_sink_returns_low_not_guess(tmp_path):
    """回溯不到就返回 low —— 绝不硬填一个名字（硬填比留空更糟）。"""
    idx = _write_tree(tmp_path)
    g = infer_for_spec(str(tmp_path), idx, "src/NotExists.java", 10)
    assert not g
    assert g.confidence == "low"


# ── sink 所在方法即入口（2026-11-02）──────────────────────────────────────────
#
# 事故：`infer_for_spec` 判断「sink 所在方法是不是入口」用的是 `line == sink_line`
# （**等号**），而 sink 是方法体里的语句，行号几乎永远不等于方法声明行
# ⇒ 这条通道恒不命中，全部掉进 backtrace；而 backtrace 对一个「自己就是入口」的方法
# 只能返回 `no_http_entry_caller`（它没有 caller）。
# 实测 35 条 param 空里 30 条卡在这，修完可补 3 → 10 条。

CTRL_WITH_SINK_INSIDE = """package d;
@RestController
public class Cors {
    @GetMapping("/cors/vuln/origin")
    public String vuls1(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        response.setHeader("Access-Control-Allow-Origin", origin);
        return "";
    }
}
"""


def test_sink_inside_entry_method_uses_that_method(tmp_path):
    """sink 在方法体内（行号 > 声明行）也要认出「所在方法就是入口」。"""
    from src.core.param_infer import infer_for_spec

    f = tmp_path / "Cors.java"
    f.write_text(CTRL_WITH_SINK_INSIDE, encoding="utf-8")
    index = {"Cors.java:vuls1": {
        "file": "Cors.java", "line": 4,
        "http_entry": "GET /cors/vuln/origin", "callers": [],
    }}
    g = infer_for_spec(str(tmp_path), index, "Cors.java", 6)
    assert g.name.lower() == "origin", g.as_dict()
    assert g.location == "header"
    assert g.source.startswith("sink_is_entry")


def test_entry_method_without_any_param_reports_no_channel(tmp_path):
    """方法本身没有可取参数（如只有 response）⇒ 返回 no_channel，不硬编一个名字。"""
    from src.core.param_infer import infer_for_spec

    f = tmp_path / "Logout.java"
    f.write_text("""package d;
@RestController
public class Logout {
    @GetMapping("/logout")
    public String logoutPage(HttpServletResponse response) {
        response.addCookie(new Cookie("a", "b"));
        return "";
    }
}
""", encoding="utf-8")
    index = {"Logout.java:logoutPage": {
        "file": "Logout.java", "line": 4,
        "http_entry": "GET /logout", "callers": [],
    }}
    g = infer_for_spec(str(tmp_path), index, "Logout.java", 6)
    assert g.name == "", g.as_dict()
    assert g.confidence == "low"


# ── sink 所在方法即入口（2026-11-02）──────────────────────────────────────────
#
# 事故：`infer_for_spec` 判断「sink 所在方法是不是入口」用的是 `line == sink_line`
# （**等号**），而 sink 是方法体里的语句，行号几乎永远不等于方法声明行
# ⇒ 这条通道恒不命中，全部掉进 backtrace；而 backtrace 对一个「自己就是入口」的方法
# 只能返回 `no_http_entry_caller`（它没有 caller）。
# 实测 35 条 param 空里 30 条卡在这，修完可补 3 → 10 条。

CTRL_WITH_SINK_INSIDE = """package d;
@RestController
public class Cors {
    @GetMapping("/cors/vuln/origin")
    public String vuls1(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        response.setHeader("Access-Control-Allow-Origin", origin);
        return "";
    }
}
"""


def test_sink_inside_entry_method_uses_that_method(tmp_path):
    """sink 在方法体内（行号 > 声明行）也要认出「所在方法就是入口」。"""
    from src.core.param_infer import infer_for_spec

    f = tmp_path / "Cors.java"
    f.write_text(CTRL_WITH_SINK_INSIDE, encoding="utf-8")
    index = {"Cors.java:vuls1": {
        "file": "Cors.java", "line": 4,
        "http_entry": "GET /cors/vuln/origin", "callers": [],
    }}
    g = infer_for_spec(str(tmp_path), index, "Cors.java", 6)
    assert g.name.lower() == "origin", g.as_dict()
    assert g.location == "header"
    assert g.source.startswith("sink_is_entry")


def test_entry_method_without_any_param_reports_no_channel(tmp_path):
    """方法本身没有可取参数（如只有 response）⇒ 返回 no_channel，不硬编一个名字。"""
    from src.core.param_infer import infer_for_spec

    f = tmp_path / "Logout.java"
    f.write_text("""package d;
@RestController
public class Logout {
    @GetMapping("/logout")
    public String logoutPage(HttpServletResponse response) {
        response.addCookie(new Cookie("a", "b"));
        return "";
    }
}
""", encoding="utf-8")
    index = {"Logout.java:logoutPage": {
        "file": "Logout.java", "line": 4,
        "http_entry": "GET /logout", "callers": [],
    }}
    g = infer_for_spec(str(tmp_path), index, "Logout.java", 6)
    assert g.name == "", g.as_dict()
    assert g.confidence == "low"
