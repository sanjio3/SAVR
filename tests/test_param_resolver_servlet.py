"""纯 Servlet/JSP 工程（OWASP Benchmark）入口解析回归测试。

背景：OWASP Benchmark 无 Spring 注解，漏洞类自身即 @WebServlet 入口类。param_resolver
原有 tier 只认 @RequestMapping / @RestController / @Controller，导致该类工程全部 finding
落到 missing_route（task-8 实锤 a2_poc 跳过 344 条）。本测试锁定 servlet_self_endpoint
与 resolve_trigger_endpoint 的 servlet 通道。
"""
from src.core.param_resolver import servlet_self_endpoint, resolve_trigger_endpoint


def _write_java(tmp_path, name: str, body: str):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_self_route_from_value_annotation(tmp_path):
    f = _write_java(tmp_path, "BenchmarkTest00008.java", '''
@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest00008");
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["route"] == "/sqli-00/BenchmarkTest00008"
    assert r["param_name"] == "BenchmarkTest00008"
    assert r["param_location"] == "header"
    assert r["method"] == "GET"


def test_self_route_query_param_and_urlpatterns(tmp_path):
    f = _write_java(tmp_path, "FooServlet.java", '''
@WebServlet(urlPatterns = {"/api/foo", "/api/foo2"})
public class FooServlet extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String p = request.getParameter("username");
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["route"] == "/api/foo"
    assert r["param_name"] == "username"
    assert r["param_location"] == "query"
    assert r["method"] == "POST"


def test_dynamic_enumeration_falls_back_to_class_name(tmp_path):
    """getParameterNames 遍历全部输入：接受任意参数名，故回落到类名而非放弃。"""
    f = _write_java(tmp_path, "BenchmarkTest00028.java", '''
@WebServlet("/pathtraver-00/BenchmarkTest00028")
public class BenchmarkTest00028 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        java.util.Enumeration<String> names = request.getParameterNames();
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["route"] == "/pathtraver-00/BenchmarkTest00028"
    assert r["param_name"] == "BenchmarkTest00028"
    assert r["param_location"] == "query"


def test_cookie_name_equals_is_recognized(tmp_path):
    f = _write_java(tmp_path, "BenchmarkTest00060.java", '''
@WebServlet("/pathtraver-00/BenchmarkTest00060")
public class BenchmarkTest00060 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        for (Cookie c : request.getCookies()) {
            if (c.getName().equals("BenchmarkTest00060")) { param = c.getValue(); }
        }
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["param_name"] == "BenchmarkTest00060"
    assert r["param_location"] == "cookie"


def test_dual_method_non_delegating_is_post(tmp_path):
    """2026-10-14 回归锁：doGet 与 doPost 并存且 doGet 不委托 doPost 时判 POST。

    实测背景：OWASP Benchmark 里 216/2740 的 servlet 属「非委托型」——doGet 只做
    rememberMe cookie 样板，真正的取参与 sink 都在 doPost（如 trustbound 的
    BenchmarkTest00004）。旧逻辑「两者都有即 GET」对这类永远打不到 sink ⇒ no-arrival。
    实测 216/216 非委托型取参在 doPost。
    """
    f = _write_java(tmp_path, "BenchmarkTest00004.java", '''
@WebServlet(value = "/trustbound-00/BenchmarkTest00004")
public class BenchmarkTest00004 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        Cookie c = new Cookie("rememberMe", "x");
        response.addCookie(c);
    }
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cs = request.getCookies();
        request.getSession().setAttribute(param, "10340");
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["method"] == "POST", r


def test_dual_method_delegating_stays_get(tmp_path):
    """doGet 委托 doPost（GET 最终仍进 doPost）时保持 GET，不误改。"""
    f = _write_java(tmp_path, "BenchmarkTest00321.java", '''
@WebServlet(value = "/trustbound-00/BenchmarkTest00321")
public class BenchmarkTest00321 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        doPost(request, response);
    }
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("BenchmarkTest00321");
    }
}
''')
    r = servlet_self_endpoint(f)
    assert r is not None
    assert r["method"] == "GET", r


def test_non_servlet_file_returns_none(tmp_path):
    """Spring 工程无 @WebServlet：必须返回 None，保证对既有靶场零回归。"""
    f = _write_java(tmp_path, "OrderController.java", '''
@RestController
@RequestMapping("/orders")
public class OrderController {
    @GetMapping("/list")
    public String list(@RequestParam("id") String id) { return id; }
}
''')
    assert servlet_self_endpoint(f) is None


def test_resolve_trigger_endpoint_uses_servlet_channel(tmp_path):
    """端到端：A2 不给任何 route 的 servlet finding 也应被判定为可解析。"""
    f = _write_java(tmp_path, "BenchmarkTest00008.java", '''
@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest00008");
    }
}
''')
    vuln = {
        "file": f,
        "line": 45,
        "vulnerability_type": "sql_injection",
        "family": "sql_injection",
    }
    out = resolve_trigger_endpoint(vuln, a1_evidence={}, code_root=str(tmp_path), discovered_routes=None)
    assert out["route"] == "/sqli-00/BenchmarkTest00008", out
    assert out["param_name"] == "BenchmarkTest00008", out
    assert out["resolvable"] is True, out
    # 关键回归点：不能再是 missing_route
    assert out.get("resolution_failure") != "missing_route", out
