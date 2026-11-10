from src.core.code_indexer import CodeIndexer


def test_code_indexer_binds_decompiled_spring_http_entry_and_call_chain():
    files = [
        {
            "rel_path": "com/ctf/gateway/controller/GatewayController.java",
            "language": "java",
            "content": """
@RestController
public class GatewayController {
    @GetMapping(value={"/check"})
    public String checkRule(@RequestParam String rule) {
        return evaluationService.evaluate(rule);
    }
}
""",
        },
        {
            "rel_path": "com/ctf/gateway/service/EvaluationService.java",
            "language": "java",
            "content": """
public class EvaluationService {
    public String evaluate(String expression) {
        return this.parser.parseExpression(expression, new TemplateParserContext()).getValue(String.class);
    }
}
""",
        },
    ]

    index = CodeIndexer().index_project(files)

    gateway = index["functions"]["com/ctf/gateway/controller/GatewayController.java:checkRule"]
    service = index["functions"]["com/ctf/gateway/service/EvaluationService.java:evaluate"]

    assert gateway["http_entry"] == "GET /check"
    assert gateway["parameters"] == "@RequestParam String rule"
    assert "com/ctf/gateway/service/EvaluationService.java:evaluate" in gateway["callees"]
    assert "com/ctf/gateway/controller/GatewayController.java:checkRule" in service["callers"]
    assert index["stats"]["http_entries"] >= 1


def test_code_indexer_records_hono_inline_route_as_http_entry():
    files = [
        {
            "rel_path": "app.tsx",
            "language": "typescript",
            "content": """
import { Hono } from 'hono'
const app = new Hono()
app.post('/eval', async (c) => {
  const code = await c.req.text()
  return c.json({ code })
})
""",
        }
    ]

    index = CodeIndexer().index_project(files)

    assert index["stats"]["http_entries"] >= 1
    assert any(info["http_entry"] == "POST /eval" for info in index["functions"].values())


def test_code_indexer_records_wordpress_rest_route_as_http_entry():
    files = [
        {
            "rel_path": "src/API/Endpoints/Logs/FlushLogs.php",
            "language": "php",
            "content": """
class FlushLogs {
    protected $endpoint = 'logs/flush-logs';
    public function registerRoute()
    {
        register_rest_route(
            'give-api/v2',
            $this->endpoint,
            [
                [
                    'methods' => 'DELETE',
                    'callback' => [$this, 'handleRequest'],
                ],
            ]
        );
    }
}
""",
        }
    ]

    index = CodeIndexer().index_project(files)

    assert index["stats"]["http_entries"] >= 1
    assert any(
        info["http_entry"] == "DELETE /wp-json/give-api/v2/logs/flush-logs"
        for info in index["functions"].values()
    )


def test_variable_receiver_ambiguous_method_name_makes_no_edge():
    """变量接收者 + 方法名在全项目不唯一 ⇒ 不连边（防「doGet 连全部 doPost」爆炸）。"""
    files = [
        {"rel_path": "a/Ctrl.java", "language": "java", "content": """
public class Ctrl {
    public void doGet() {
        helper.run();
    }
}
"""},
        {"rel_path": "b/Svc1.java", "language": "java", "content": """
public class Svc1 {
    public void run() {
    }
}
"""},
        {"rel_path": "c/Svc2.java", "language": "java", "content": """
public class Svc2 {
    public void run() {
    }
}
"""},
    ]
    index = CodeIndexer().index_project(files)
    ctrl = index["functions"]["a/Ctrl.java:doGet"]
    assert ctrl["callees"] == []


# ── 源码语义消费（2026-11-02）──────────────────────────────────────────────
#
# 三个守卫，对应三个实测缺陷：
#   1. 形参正则遇注解的 `)` 截断 ⇒ 类型丢失（`MultipartFile` 变成 `@RequestParam("file"`）；
#   2. 类上没有 @Controller 却因方法有 @RequestMapping 被当入口（Spring 不注册 ⇒ 404）；
#   3. 跨类同名调用被「自递归保护」误跳过 ⇒ 工具类 sink 的 callers 恒为空。


def _index(tmp_path, files: dict):
    from src.core.code_indexer import CodeIndexer
    payload = [{"rel_path": k, "content": v, "language": "java"} for k, v in files.items()]
    return CodeIndexer().index_project(payload)


def test_typed_params_are_not_truncated_by_annotation_parens(tmp_path):
    out = _index(tmp_path, {"A.java": '''package d;
@RestController
public class A {
    @PostMapping("/up")
    public String up(@RequestParam("file") MultipartFile file, String note) { return "x"; }
}'''})
    fn = out["functions"]["A.java:up"]
    types = {p["name"]: p["type"] for p in fn["params_typed"]}
    assert types.get("file") == "MultipartFile", fn["params_typed"]
    assert types.get("note") == "String"


def test_method_without_controller_class_is_not_an_entry(tmp_path):
    """类上没有 @Controller/@RestController ⇒ 不是 HTTP 入口（Spring 不会注册该路由）。"""
    out = _index(tmp_path, {"Plain.java": '''package d;
public class Plain {
    @RequestMapping("/x")
    public void x(String p) { }
}'''})
    assert out["functions"]["Plain.java:x"]["http_entry"] is None
    assert out["stats"]["http_entries"] == 0


def test_comment_containing_class_does_not_reset_controller_flag(tmp_path):
    """注释里的 "class ..." 不能被当成类声明，否则后续方法的入口全丢。"""
    out = _index(tmp_path, {"C.java": '''package d;
@RestController
public class C {
    /**
     * Check this class using black list.
     */
    @RequestMapping("/a")
    public void a(String p) { }
}'''})
    assert out["functions"]["C.java:a"]["http_entry"], out["functions"]["C.java:a"]


def test_cross_class_same_name_call_is_linked(tmp_path):
    """`Ssrf.request()` 调 `HttpUtils.request(url)` —— 同名也要连边（否则 param 回溯断链）。"""
    out = _index(tmp_path, {
        "Ssrf.java": '''package d;
@RestController
public class Ssrf {
    @GetMapping("/s")
    public String request(String url) { return HttpUtils.request(url); }
}''',
        "HttpUtils.java": '''package d;
public class HttpUtils {
    public static String request(String url) { return url; }
}''',
    })
    assert out["functions"]["HttpUtils.java:request"]["callers"] == ["Ssrf.java:request"]


# ── 源码语义消费（2026-11-02）──────────────────────────────────────────────
#
# 三个守卫，对应三个实测缺陷：
#   1. 形参正则遇注解的 `)` 截断 ⇒ 类型丢失（`MultipartFile` 变成 `@RequestParam("file"`）；
#   2. 类上没有 @Controller 却因方法有 @RequestMapping 被当入口（Spring 不注册 ⇒ 404）；
#   3. 跨类同名调用被「自递归保护」误跳过 ⇒ 工具类 sink 的 callers 恒为空。


def _index(tmp_path, files: dict):
    from src.core.code_indexer import CodeIndexer
    payload = [{"rel_path": k, "content": v, "language": "java"} for k, v in files.items()]
    return CodeIndexer().index_project(payload)


def test_typed_params_are_not_truncated_by_annotation_parens(tmp_path):
    out = _index(tmp_path, {"A.java": '''package d;
@RestController
public class A {
    @PostMapping("/up")
    public String up(@RequestParam("file") MultipartFile file, String note) { return "x"; }
}'''})
    fn = out["functions"]["A.java:up"]
    types = {p["name"]: p["type"] for p in fn["params_typed"]}
    assert types.get("file") == "MultipartFile", fn["params_typed"]
    assert types.get("note") == "String"


def test_method_without_controller_class_is_not_an_entry(tmp_path):
    """类上没有 @Controller/@RestController ⇒ 不是 HTTP 入口（Spring 不会注册该路由）。"""
    out = _index(tmp_path, {"Plain.java": '''package d;
public class Plain {
    @RequestMapping("/x")
    public void x(String p) { }
}'''})
    assert out["functions"]["Plain.java:x"]["http_entry"] is None
    assert out["stats"]["http_entries"] == 0


def test_comment_containing_class_does_not_reset_controller_flag(tmp_path):
    """注释里的 "class ..." 不能被当成类声明，否则后续方法的入口全丢。"""
    out = _index(tmp_path, {"C.java": '''package d;
@RestController
public class C {
    /**
     * Check this class using black list.
     */
    @RequestMapping("/a")
    public void a(String p) { }
}'''})
    assert out["functions"]["C.java:a"]["http_entry"], out["functions"]["C.java:a"]


def test_cross_class_same_name_call_is_linked(tmp_path):
    """`Ssrf.request()` 调 `HttpUtils.request(url)` —— 同名也要连边（否则 param 回溯断链）。"""
    out = _index(tmp_path, {
        "Ssrf.java": '''package d;
@RestController
public class Ssrf {
    @GetMapping("/s")
    public String request(String url) { return HttpUtils.request(url); }
}''',
        "HttpUtils.java": '''package d;
public class HttpUtils {
    public static String request(String url) { return url; }
}''',
    })
    assert out["functions"]["HttpUtils.java:request"]["callers"] == ["Ssrf.java:request"]


def test_webfilter_doFilter_is_an_http_entry(tmp_path):
    """`@WebFilter` + `doFilter` 是真实 HTTP 入口（每个匹配请求都过它）。

    此前只建模 `@WebServlet` 的 doGet/doPost，过滤器里的 sink 因此拿不到入口，
    param 推断也恒失败 —— 明明 `request.getHeader("Origin")` 是确定性可推的。
    """
    out = _index(tmp_path, {"F.java": '''package d;
@WebFilter(filterName = "F", urlPatterns = "/api/filter")
public class F implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        String o = ((HttpServletRequest) req).getHeader("Origin");
    }
}'''})
    fn = out["functions"]["F.java:doFilter"]
    assert fn["http_entry"] == "ANY /api/filter", fn["http_entry"]


def test_webfilter_with_wildcard_route_is_not_an_entry(tmp_path):
    """`@WebFilter("/*")` 是通配符路由，拿 `/*` 去发请求没有意义 ⇒ 不入入口。"""
    out = _index(tmp_path, {"W.java": '''package d;
@WebFilter("/*")
public class W implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain c) { }
}'''})
    assert out["functions"]["W.java:doFilter"]["http_entry"] is None
    assert out["stats"]["http_entries"] == 0
