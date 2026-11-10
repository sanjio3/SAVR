"""框架惯用 sink 规则包的单元测试（src/iast/framework_sinks.py）。

覆盖三件最容易回归的事：
1. 每条规则「该报的报、不该报的不报」（含安全写法必须放过）；
2. 解析器不能死循环 —— 曾经因为 `import ...RequestMapping;` 这类行不以 @ 开头、
   注解收集循环一步不走，导致 i 不前进、整进程卡死（实测 SIGTERM）；
3. 类级路由不能被方法级注解污染（Log4j 曾拼出 /log4j/log4j）。
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.iast import framework_sinks as fs  # noqa: E402


def _families(code: str) -> set:
    return {h.family for h in fs.detect_source(code, "T.java")}


# ── 解析器健壮性 ────────────────────────────────────────────────────────

def test_import_line_does_not_hang():
    """import 行含 Mapping 但不以 @ 开头 —— 历史死循环点。"""
    code = (
        "package a;\n"
        "import org.springframework.web.bind.annotation.RequestMapping;\n"
        "import org.springframework.web.bind.annotation.ResponseBody;\n"
        "@RestController\n"
        "public class T {\n"
        "    @RequestMapping(\"/x\")\n"
        "    @ResponseBody\n"
        "    public String x(String p) { return p; }\n"
        "}\n"
    )
    hits = fs.detect_source(code, "T.java")
    assert any(h.family == fs.FAMILY_XSS for h in hits)


def test_class_route_not_polluted_by_method_annotation():
    """类上无 @RequestMapping、路径写在方法上时，不能拼成 /log4j/log4j。"""
    code = (
        "import org.apache.logging.log4j.LogManager;\n"
        "@RestController\n"
        "public class Log4j {\n"
        "    private static final Logger logger = LogManager.getLogger(\"x\");\n"
        "    @RequestMapping(value = \"/log4j\")\n"
        "    public String log4j(String token) {\n"
        "        logger.error(token);\n"
        "        return token;\n"
        "    }\n"
        "}\n"
    )
    hits = fs.detect_source(code, "Log4j.java")
    routes = {h.route for h in hits if h.family == fs.FAMILY_XSS}
    assert routes == {"/log4j"}


# ── 规则 1：Spring 反射返回 → xss ───────────────────────────────────────

def test_spring_reflected_return_positive():
    code = (
        "@RestController\n"
        "public class X {\n"
        "    @RequestMapping(\"/reflect\")\n"
        "    @ResponseBody\n"
        "    public String reflect(String xss) { return xss; }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "X.java") if h.family == fs.FAMILY_XSS]
    assert len(hits) == 1
    assert hits[0].param == "xss"
    assert hits[0].route == "/reflect"
    assert hits[0].confidence == "high"


def test_spring_reflected_return_ignores_encoded():
    """经过函数调用（可能已净化）必须放过 —— 不猜净化器，那是 CodeQL 的活。"""
    code = (
        "@RestController\n"
        "public class X {\n"
        "    @RequestMapping(\"/safe\")\n"
        "    @ResponseBody\n"
        "    public String safe(String xss) { return encode(xss); }\n"
        "}\n"
    )
    assert fs.FAMILY_XSS not in _families(code)


def test_spring_reflected_return_ignores_literal():
    code = (
        "@RestController\n"
        "public class X {\n"
        "    @RequestMapping(\"/ok\")\n"
        "    @ResponseBody\n"
        "    public String ok(String xss) { return \"hello\"; }\n"
        "}\n"
    )
    assert fs.FAMILY_XSS not in _families(code)


# ── 规则 2：CORS ────────────────────────────────────────────────────────

def test_cors_reflected_origin_high():
    code = (
        "@RequestMapping(\"/cors\")\n"
        "public class C {\n"
        "    @GetMapping(\"/vuln/origin\")\n"
        "    public String v(HttpServletRequest request, HttpServletResponse response) {\n"
        "        String origin = request.getHeader(\"origin\");\n"
        "        response.setHeader(\"Access-Control-Allow-Origin\", origin);\n"
        "        response.setHeader(\"Access-Control-Allow-Credentials\", \"true\");\n"
        "        return info;\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_CORS]
    assert hits and hits[0].confidence == "high"
    assert "Allow-Credentials=true" in hits[0].reason


def test_cors_fixed_origin_not_reported():
    code = (
        "public class C {\n"
        "    public String v(HttpServletResponse response) {\n"
        "        response.setHeader(\"Access-Control-Allow-Origin\", \"https://a.example\");\n"
        "        return info;\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_CORS not in _families(code)


# ── 规则 3：log4j2 → jndi ───────────────────────────────────────────────

def test_log4j2_nonliteral_is_jndi():
    code = (
        "import org.apache.logging.log4j.LogManager;\n"
        "public class L {\n"
        "    private static final Logger logger = LogManager.getLogger(\"L\");\n"
        "    @RequestMapping(\"/log4j\")\n"
        "    public String log4j(String token) { logger.error(token); return token; }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "L.java") if h.family == fs.FAMILY_JNDI]
    assert len(hits) == 1
    assert hits[0].confidence == "high"


def test_log4j2_literal_not_reported():
    code = (
        "import org.apache.logging.log4j.LogManager;\n"
        "public class L {\n"
        "    public void a() { logger.error(\"static message\"); }\n"
        "}\n"
    )
    assert fs.FAMILY_JNDI not in _families(code)


def test_non_log4j2_not_reported():
    """没有 log4j2 依赖时不能报 jndi（slf4j/logback 无 ${jndi:} 替换）。"""
    code = (
        "import org.slf4j.Logger;\n"
        "public class L {\n"
        "    public void a(String token) { logger.error(token); }\n"
        "}\n"
    )
    assert fs.FAMILY_JNDI not in _families(code)


# ── 规则 4：表达式引擎 ──────────────────────────────────────────────────

def test_qlexpress_execute_nonliteral():
    code = (
        "@RestController\n"
        "public class Q {\n"
        "    @RequestMapping(\"/vuln1\")\n"
        "    public String vuln1(HttpServletRequest req) throws Exception {\n"
        "        String express = WebUtils.getRequestBody(req);\n"
        "        ExpressRunner runner = new ExpressRunner();\n"
        "        return runner.execute(express, context, null, true, false).toString();\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "Q.java") if h.family == fs.FAMILY_EXPRESSION]
    assert hits and hits[0].route == "/vuln1"


def test_qlexpress_hardened_method_skipped():
    """开了 forbidInvokeSecurityRiskMethods 的安全方法必须放过（曾误报 L40）。"""
    code = (
        "@RestController\n"
        "public class Q {\n"
        "    @RequestMapping(\"/sec\")\n"
        "    public String sec(HttpServletRequest req) throws Exception {\n"
        "        String express = WebUtils.getRequestBody(req);\n"
        "        ExpressRunner runner = new ExpressRunner();\n"
        "        QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true);\n"
        "        return runner.execute(express, context, null, true, false).toString();\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_EXPRESSION not in _families(code)


def test_spel_literal_skipped():
    code = (
        "public class S {\n"
        "    public void a() { parser.parseExpression(\"'abc'\").getValue(); }\n"
        "}\n"
    )
    assert fs.FAMILY_EXPRESSION not in _families(code)


# ── 规则 5：RMI ─────────────────────────────────────────────────────────

def test_rmi_registry_reported():
    code = (
        "public class Server {\n"
        "    public static void main(String[] a) throws Exception {\n"
        "        LocateRegistry.createRegistry(1099);\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_RMI in _families(code)


# ── 规则 6：Cookie 标志位 ───────────────────────────────────────────────

def test_cookie_without_secure():
    code = (
        "public class C {\n"
        "    public void a(HttpServletResponse r) { r.addCookie(new Cookie(\"k\", \"v\")); }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_SECURE_COOKIE]
    assert hits and hits[0].confidence == "medium"


def test_cookie_with_secure_true_not_reported():
    code = (
        "public class C {\n"
        "    public void a(HttpServletResponse r) {\n"
        "        Cookie c = new Cookie(\"k\", \"v\");\n"
        "        c.setSecure(true);\n"
        "        r.addCookie(c);\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_SECURE_COOKIE not in _families(code)


# ── 规则 7/8/9 ──────────────────────────────────────────────────────────

def test_csrf_disabled_reported():
    code = (
        "public class S {\n"
        "    protected void configure(HttpSecurity http) throws Exception {\n"
        "        http.csrf().disable();\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_CSRF in _families(code)


def test_csrf_missing_token_alone_not_reported():
    """只是「没看到 token 校验」不报 —— 缺失推断 FP 太高。"""
    code = (
        "@RestController\n"
        "public class C {\n"
        "    @PostMapping(\"/post\")\n"
        "    public String post() { return \"ok\"; }\n"
        "}\n"
    )
    assert fs.FAMILY_CSRF not in _families(code)


def test_jsonp_callback_controlled():
    code = (
        "@RequestMapping(\"/jsonp\")\n"
        "public class J {\n"
        "    @GetMapping(\"/vuln\")\n"
        "    public void v(String callback, HttpServletResponse resp) {\n"
        "        resp.setContentType(\"application/javascript\");\n"
        "        resp.getWriter().write(callback + \"(\" + info + \")\");\n"
        "    }\n"
        "}\n"
    )
    assert fs.FAMILY_JSONP in _families(code)


def test_deserialization_entry_reported_as_medium():
    code = (
        "public class D {\n"
        "    public Object a(InputStream in) throws Exception {\n"
        "        return new ObjectInputStream(in).readObject();\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "D.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].confidence == "medium"


# ── 注释与作用域 ────────────────────────────────────────────────────────

def test_commented_payload_not_matched():
    """注释里写着 PoC 不能当代码匹配（java-sec-code 的注释里就有）。"""
    code = (
        "public class Q {\n"
        "    // url = 'http://sb.dog:8888/';\n"
        "    // classLoader = new java.net.URLClassLoader(...);\n"
        "    public void a() { }\n"
        "}\n"
    )
    assert fs.detect_source(code, "Q.java") == []


def test_switch_off_returns_empty(monkeypatch):
    monkeypatch.setenv("SAST_AI_FW_RULES", "0")
    code = (
        "@RestController\n"
        "public class X {\n"
        "    @RequestMapping(\"/r\")\n"
        "    @ResponseBody\n"
        "    public String r(String p) { return p; }\n"
        "}\n"
    )
    assert fs.detect_source(code, "X.java") == []


def test_test_sources_excluded(tmp_path):
    """src/test 下的控制器样例不是部署面，必须跳过。"""
    src = tmp_path / "src" / "test" / "java"
    src.mkdir(parents=True)
    (src / "T.java").write_text(
        "@RestController\npublic class T {\n"
        "  @RequestMapping(\"/r\")\n  @ResponseBody\n"
        "  public String r(String p) { return p; }\n}\n",
        encoding="utf-8",
    )
    assert fs.detect_path(str(tmp_path)) == []


# ── 参数推断（登记环节要求 (route, param) 可解析，否则整条丢弃）──────────

def test_param_from_request_body_annotation():
    """`@RequestBody String params` 要取 params，不能取类型名 String。"""
    code = (
        "@RestController\n"
        "public class F {\n"
        "    @RequestMapping(\"/deserialize\")\n"
        "    @ResponseBody\n"
        "    public String Deserialize(@RequestBody String params) {\n"
        "        JSONObject ob = JSON.parseObject(params);\n"
        "        return ob.get(\"name\").toString();\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "F.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "params" and hits[0].location == "body"


def test_param_from_get_parameter_literal():
    """无入参方法：参数名写在 getParameter("classData") 里。"""
    code = (
        "public class C {\n"
        "    @RequestMapping(\"/classloader\")\n"
        "    public void classData() {\n"
        "        String classData = request.getParameter(\"classData\");\n"
        "        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(null));\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "classData" and hits[0].route == "/classloader"


def test_param_from_cookie_constant():
    """`getCookie(request, Constants.REMEMBER_ME_COOKIE)` → rememberMe / cookie。"""
    code = (
        "public class D {\n"
        "    @RequestMapping(\"/deserialize/rememberMe/vuln\")\n"
        "    public String vuln(HttpServletRequest request) throws Exception {\n"
        "        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);\n"
        "        byte[] decoded = Base64.getDecoder().decode(cookie.getValue());\n"
        "        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(decoded));\n"
        "        in.readObject();\n"
        "        return \"ok\";\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "D.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "rememberMe" and hits[0].location == "cookie"


def test_param_from_body_stream_uses_sentinel():
    """直接读流的端点没有参数名，用 __body__ 哨兵（location=body）。"""
    code = (
        "public class X {\n"
        "    @PostMapping(\"/xstream\")\n"
        "    public String parseXml(HttpServletRequest request) throws Exception {\n"
        "        String xml = WebUtils.getRequestBody(request);\n"
        "        XStream xstream = new XStream(new DomDriver());\n"
        "        xstream.fromXML(xml);\n"
        "        return \"xstream\";\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "X.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "__body__" and hits[0].location == "body"


def test_const_to_camel_strips_suffix():
    assert fs._const_to_camel("REMEMBER_ME_COOKIE") == "rememberMe"
    assert fs._const_to_camel("SESSION_KEY") == "session"
    assert fs._const_to_camel("") == ""


# ── 参数推断（登记环节要求 (route, param) 可解析，否则整条丢弃）──────────

def test_param_from_request_body_annotation():
    """`@RequestBody String params` 要取 params，不能取类型名 String。"""
    code = (
        "@RestController\n"
        "public class F {\n"
        "    @RequestMapping(\"/deserialize\")\n"
        "    @ResponseBody\n"
        "    public String Deserialize(@RequestBody String params) {\n"
        "        JSONObject ob = JSON.parseObject(params);\n"
        "        return ob.get(\"name\").toString();\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "F.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "params" and hits[0].location == "body"


def test_param_from_get_parameter_literal():
    """无入参方法：参数名写在 getParameter("classData") 里。"""
    code = (
        "public class C {\n"
        "    @RequestMapping(\"/classloader\")\n"
        "    public void classData() {\n"
        "        String classData = request.getParameter(\"classData\");\n"
        "        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(null));\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "classData" and hits[0].route == "/classloader"


def test_param_from_cookie_constant():
    """`getCookie(request, Constants.REMEMBER_ME_COOKIE)` → rememberMe / cookie。"""
    code = (
        "public class D {\n"
        "    @RequestMapping(\"/deserialize/rememberMe/vuln\")\n"
        "    public String vuln(HttpServletRequest request) throws Exception {\n"
        "        Cookie cookie = getCookie(request, Constants.REMEMBER_ME_COOKIE);\n"
        "        byte[] decoded = Base64.getDecoder().decode(cookie.getValue());\n"
        "        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(decoded));\n"
        "        in.readObject();\n"
        "        return \"ok\";\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "D.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "rememberMe" and hits[0].location == "cookie"


def test_param_from_body_stream_uses_sentinel():
    """直接读流的端点没有参数名，用 __body__ 哨兵（location=body）。"""
    code = (
        "public class X {\n"
        "    @PostMapping(\"/xstream\")\n"
        "    public String parseXml(HttpServletRequest request) throws Exception {\n"
        "        String xml = WebUtils.getRequestBody(request);\n"
        "        XStream xstream = new XStream(new DomDriver());\n"
        "        xstream.fromXML(xml);\n"
        "        return \"xstream\";\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "X.java") if h.family == fs.FAMILY_DESERIALIZE]
    assert hits and hits[0].param == "__body__" and hits[0].location == "body"


def test_const_to_camel_strips_suffix():
    assert fs._const_to_camel("REMEMBER_ME_COOKIE") == "rememberMe"
    assert fs._const_to_camel("SESSION_KEY") == "session"
    assert fs._const_to_camel("") == ""


# ── 2026-10-31 Batch：族判错 3 个 + 未检出 2 个的规则补齐 ─────────────────
# 这一组用例锁的都是「改错了就退回原状」的点，不是覆盖率装饰。


def test_crlf_header_write_from_parameter():
    """响应头 value 直接来自 getParameter → crlf_injection。"""
    code = (
        "public class C {\n"
        "    @RequestMapping(\"/crlf/safecode\")\n"
        "    public void crlf(HttpServletRequest request, HttpServletResponse response) {\n"
        "        response.addHeader(\"test1\", request.getParameter(\"test1\"));\n"
        "        response.setHeader(\"test2\", request.getParameter(\"test2\"));\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_CRLF]
    assert len(hits) == 2
    assert all(h.route == "/crlf/safecode" for h in hits)
    assert hits[0].param == "test1"


def test_crlf_header_write_from_local_var():
    """先落到局部变量再写头（`String a = request.getParameter(..)`）也要认。"""
    code = (
        "public class C {\n"
        "    @GetMapping(\"/h\")\n"
        "    public void h(HttpServletRequest request, HttpServletResponse response) {\n"
        "        String author = request.getParameter(\"test3\");\n"
        "        response.setHeader(\"X-Author\", author);\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "C.java") if h.family == fs.FAMILY_CRLF]
    assert hits and hits[0].param == "test3"


def test_crlf_suppresses_secure_cookie_in_same_file():
    """同文件既写头又建 Cookie：族仲裁必须留下 crlf、丢掉 secure_cookie。

    CRLFInjection.java 的真值族是 crlf_injection；两条都登记会让族判定选错。
    """
    code = (
        "public class C {\n"
        "    @RequestMapping(\"/crlf/safecode\")\n"
        "    public void crlf(HttpServletRequest request, HttpServletResponse response) {\n"
        "        response.addHeader(\"test1\", request.getParameter(\"test1\"));\n"
        "        String author = request.getParameter(\"test3\");\n"
        "        Cookie cookie = new Cookie(\"test3\", author);\n"
        "        response.addCookie(cookie);\n"
        "    }\n"
        "}\n"
    )
    fams = {h.family for h in fs.detect_source(code, "C.java")}
    assert fs.FAMILY_CRLF in fams
    assert fs.FAMILY_SECURE_COOKIE not in fams


def test_ssti_velocity_evaluate():
    """Velocity.evaluate 的第 4 参就是模板源码 → ssti。"""
    code = (
        "public class S {\n"
        "    @GetMapping(\"/velocity\")\n"
        "    public void velocity(String template) {\n"
        "        VelocityContext context = new VelocityContext();\n"
        "        Velocity.evaluate(context, swOut, \"test\", template);\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "S.java") if h.family == fs.FAMILY_SSTI]
    assert hits and hits[0].param == "template" and hits[0].route == "/velocity"


def test_ssti_requires_velocity_context():
    """只有 evaluate 没有 VelocityContext ⇒ 不报（避免误伤别的 evaluate）。"""
    code = (
        "public class S {\n"
        "    @GetMapping(\"/v\")\n"
        "    public void v(String template) {\n"
        "        engine.evaluate(context, \"test\", template);\n"
        "    }\n"
        "}\n"
    )
    assert not [h for h in fs.detect_source(code, "S.java") if h.family == fs.FAMILY_SSTI]


def test_file_upload_original_filename():
    """MultipartFile + getOriginalFilename + 落盘 → file_upload。

    同时锁住解析器坑：形参带 `@RequestParam("file")` 时，签名解析不能提前截断。
    """
    code = (
        "public class F {\n"
        "    @PostMapping(\"/upload\")\n"
        "    public String singleFileUpload(@RequestParam(\"file\") MultipartFile file,\n"
        "                                   RedirectAttributes ra) throws Exception {\n"
        "        byte[] bytes = file.getBytes();\n"
        "        Path path = Paths.get(UPLOADED_FOLDER + file.getOriginalFilename());\n"
        "        Files.write(path, bytes);\n"
        "        return \"ok\";\n"
        "    }\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "F.java") if h.family == fs.FAMILY_FILE_UPLOAD]
    assert hits and hits[0].route == "/upload" and hits[0].confidence == "high"


def test_file_upload_requires_disk_write():
    """只解析内容不落盘（上传 xlsx 后解析）不能报 file_upload。"""
    code = (
        "public class F {\n"
        "    @PostMapping(\"/readxlsx\")\n"
        "    public String read(@RequestParam(\"file\") MultipartFile file) throws Exception {\n"
        "        Workbook wb = new XSSFWorkbook(file.getInputStream());\n"
        "        return file.getOriginalFilename();\n"
        "    }\n"
        "}\n"
    )
    assert not [h for h in fs.detect_source(code, "F.java")
                if h.family == fs.FAMILY_FILE_UPLOAD]


def test_csrf_flag_default_off():
    """开关式 CSRF（`Boolean csrfEnabled = false`）也要能被识别成项目级关闭。"""
    code = (
        "public class W {\n"
        "    @Value(\"${joychou.security.csrf.enabled}\")\n"
        "    private Boolean csrfEnabled = false;\n"
        "}\n"
    )
    hits = [h for h in fs.detect_source(code, "W.java") if h.family == fs.FAMILY_CSRF]
    assert hits and hits[0].rule == "csrf_flag_default_off"


def test_csrf_flag_true_does_not_fire():
    """默认 true（保护开着）不能报。"""
    code = "public class W {\n    private Boolean csrfEnabled = true;\n}\n"
    assert not [h for h in fs.detect_source(code, "W.java") if h.family == fs.FAMILY_CSRF]


# ── 2026-10-31 Batch 2：MyBatis XML ${} 拼接（若依 P4）────────────────────

def test_mybatis_dollar_substitution_in_dml():
    """<select> 里的 ${} 是字符串替换 → sql_injection。"""
    xml = (
        '<mapper namespace="com.x.UserMapper">\n'
        '  <select id="selectUserList" resultType="User">\n'
        '    select * from sys_user where 1=1\n'
        '    ${params.dataScope}\n'
        '  </select>\n'
        '</mapper>\n'
    )
    hits = [h for h in fs.detect_source(xml, "UserMapper.xml") if h.family == fs.FAMILY_SQLI]
    assert len(hits) == 1
    assert hits[0].rule == "mybatis_dollar_substitution"
    assert hits[0].confidence == "high"


def test_mybatis_dollar_requires_mapper_root():
    """没有 <mapper namespace=> 的 XML（pom/logback/mybatis-config）一律不报。"""
    xml = '<project><properties><x>${project.artifactId}</x></properties></project>'
    assert not [h for h in fs.detect_source(xml, "pom.xml") if h.family == fs.FAMILY_SQLI]


def test_mybatis_dollar_outside_dml_ignored():
    """${} 落在 <resultMap>/<property> 里不是 SQL 拼接面。"""
    xml = (
        '<mapper namespace="com.x.M">\n'
        '  <resultMap id="r"><result property="a" column="${col}"/></resultMap>\n'
        '</mapper>\n'
    )
    assert not [h for h in fs.detect_source(xml, "M.xml") if h.family == fs.FAMILY_SQLI]


def test_mybatis_dollar_whitelist():
    """databaseId / log.* / project.* 这类不是注入面。"""
    xml = (
        '<mapper namespace="com.x.M">\n'
        '  <select id="s">select * from t where d=${databaseId}</select>\n'
        '  <sql id="log">${log.path}</sql>\n'
        '</mapper>\n'
    )
    assert not [h for h in fs.detect_source(xml, "M.xml") if h.family == fs.FAMILY_SQLI]


def test_mybatis_dollar_ignores_xml_comments():
    """注释掉的 ${} 不能报（真实项目里注释常留着旧写法）。"""
    xml = (
        '<mapper namespace="com.x.M">\n'
        '  <select id="s">\n'
        '    <!-- 旧写法 ${params.dataScope} 已废弃 -->\n'
        '    select 1\n'
        '  </select>\n'
        '</mapper>\n'
    )
    assert not [h for h in fs.detect_source(xml, "M.xml") if h.family == fs.FAMILY_SQLI]


# ── 族仲裁（2026-11-01）：优先级表取代写死特例 ────────────────────────────
# 背景：本轮实测某文件真值 xss，但被 D2 确认出来的是 secure_cookie，
# 于是在「文件+族对」口径里算族错。根因是属性族顶替了注入族。

def test_injection_family_drops_property_family_same_file():
    """同文件有注入族 ⇒ 属性族让位（不同行也成立）。"""
    from src.iast.framework_sinks import FrameworkHit

    hits = [
        FrameworkHit(family="xss", rule="r", file="M.java", line=4, sink="print"),
        FrameworkHit(family=fs.FAMILY_SECURE_COOKIE, rule="c", file="M.java", line=5, sink="new Cookie"),
    ]
    out = fs._arbitrate_families(hits)
    assert {h.family for h in out} == {"xss"}


def test_property_family_survives_when_no_injection():
    """没有注入族的文件里，属性族必须保留（不能一刀切删）。"""
    from src.iast.framework_sinks import FrameworkHit

    hits = [
        FrameworkHit(family=fs.FAMILY_SECURE_COOKIE, rule="c", file="C.java", line=4, sink="new Cookie"),
        FrameworkHit(family="cors", rule="o", file="C.java", line=6, sink="ACAO"),
    ]
    out = fs._arbitrate_families(hits)
    assert {h.family for h in out} == {fs.FAMILY_SECURE_COOKIE, "cors"}


def test_root_cause_beats_consequence_same_line():
    """同一行 file_upload 与 path_traversal 并存 ⇒ 留根因（上传）。"""
    from src.iast.framework_sinks import FrameworkHit

    hits = [
        FrameworkHit(family=fs.FAMILY_FILE_UPLOAD, rule="u", file="F.java", line=10, sink="s"),
        FrameworkHit(family="path_traversal", rule="p", file="F.java", line=10, sink="s"),
    ]
    out = fs._arbitrate_families(hits)
    assert [h.family for h in out] == [fs.FAMILY_FILE_UPLOAD]


def test_arbitration_is_line_scoped_for_same_class():
    """两个注入族在不同行 ⇒ 都保留（跨行压掉会把两个真实缺陷合并成一个）。"""
    from src.iast.framework_sinks import FrameworkHit

    hits = [
        FrameworkHit(family=fs.FAMILY_FILE_UPLOAD, rule="u", file="F.java", line=10, sink="s"),
        FrameworkHit(family="path_traversal", rule="p", file="F.java", line=20, sink="s"),
    ]
    out = fs._arbitrate_families(hits)
    assert {h.family for h in out} == {fs.FAMILY_FILE_UPLOAD, "path_traversal"}
