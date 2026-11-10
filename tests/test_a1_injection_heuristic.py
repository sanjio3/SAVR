"""注入类确定性兜底 + CodeQL 状态区分 回归测试（改进清单 P0#2/#5、P1#1）。

覆盖：
- 轻量 sink 匹配能检出 Java 高危 sink（反序列化 / 命令注入 / 路径穿越），且不依赖 Maven/CodeQL/网络。
- A1PipelineService.scan_files 在 CodeQL 不可用 / 构建失败（空结果）时回退到兜底，且标记 engine。
- CodeQL 适配器 scan 返回 status 字段，区分 unavailable / build_failed / analyze_failed / ok / no_vuln。
- _bl_common.has_token 剥离注释，避免「注释里写无 @decimalmin/clamp 校验」被误判为已校验（漏报）。
"""
import unittest
from unittest import mock

from src.agents.a1_injection_heuristic import analyze_content, analyze_files, scan_path
from src.core.models import Vulnerability
from src.pipeline.a1.service import A1PipelineService


JAVA_DESERIAL = """
import java.io.*;
public class DebugController {
    public void importData(String b64) throws Exception {
        byte[] data = Base64.getDecoder().decode(b64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
    }
}
"""

JAVA_CMDEXEC = """
import java.lang.*;
public class SystemUtils {
    public String run(String cmd) {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
        return "ran";
    }
}
"""

JAVA_PATH_TRAVERSAL = """
public class QuoteController {
    public String read(String name) throws Exception {
        return new String(Files.readAllBytes(java.nio.file.Paths.get(name)));
    }
}
"""

PY_EVAL = """
import os
def run(user_input):
    return eval(user_input)
"""

# 2026-09-17（文档《漏洞检测能力现状》§2.1 Nashorn/ScriptEngine 漏检）：
# 真实写法是「先取引擎、隔几行再 eval」，旧规则要求 ScriptEngine 与 eval 同一行，
# 跨行即永不命中（实测 Rce.java：L97 取引擎、L100 eval，静态动态双双 0 命中）。
JAVA_SCRIPT_ENGINE_RCE = """
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.Bindings;
import javax.script.ScriptContext;

@GetMapping("/jscmd")
public void jsEngine(String jsurl) throws Exception{
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
    Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
    String cmd = String.format("load(\\"%s\\")", jsurl);
    engine.eval(cmd, bindings);
}
"""

PY_PICKLE = """
import pickle
def load(b):
    return pickle.loads(b)
"""


def _vulns_to_types(vulns):
    return {v.type for v in vulns}


class TestInjectionHeuristic(unittest.TestCase):
    def test_java_deserialization_detected(self):
        vs = analyze_content("DebugController.java", JAVA_DESERIAL, "java")
        types = _vulns_to_types(vs)
        self.assertIn("Deserialization", types)
        # 危险 sink 名称应出现在结果中
        self.assertTrue(any(v.sink == "ObjectInputStream" for v in vs)
                        or any(v.sink == "readObject" for v in vs))

    def test_java_command_injection_detected(self):
        vs = analyze_content("SystemUtils.java", JAVA_CMDEXEC, "java")
        types = _vulns_to_types(vs)
        self.assertIn("Command Injection", types)
        self.assertTrue(any(v.sink == "ProcessBuilder" for v in vs))

    def test_java_path_traversal_detected(self):
        vs = analyze_content("QuoteController.java", JAVA_PATH_TRAVERSAL, "java")
        self.assertIn("Path Traversal", _vulns_to_types(vs))

    def test_python_eval_and_pickle_detected(self):
        vs = analyze_files([
            {"path": "a.py", "content": PY_EVAL, "language": "python"},
            {"path": "b.py", "content": PY_PICKLE, "language": "python"},
        ])
        types = _vulns_to_types(vs)
        self.assertIn("Code Injection", types)
        self.assertIn("Deserialization", types)

    def test_unsupported_or_empty_skipped(self):
        self.assertEqual(analyze_content("x.txt", "anything", "txt"), [])
        self.assertEqual(analyze_content("x.go", "", "go"), [])

    def test_scan_path_ignores_nonexistent(self):
        self.assertEqual(scan_path("D:/no/such/path", "java"), [])


class TestScanFilesFallback(unittest.TestCase):
    def _make_svc(self, codeql_available: bool):
        svc = A1PipelineService({"a1_use_codeql": True, "codeql": {"bin_path": "C:/codeql/codeql.exe"}})
        svc._codeql.is_available = lambda: codeql_available  # type: ignore[assignment]
        svc._semantic._codeql.is_available = lambda: codeql_available  # type: ignore[assignment]
        return svc

    def _sink_files(self):
        return [
            {"path": "D:/app/DebugController.java", "content": JAVA_DESERIAL, "language": "java"},
            {"path": "D:/app/SystemUtils.java", "content": JAVA_CMDEXEC, "language": "java"},
        ]

    def test_fallback_when_codeql_unavailable(self):
        svc = self._make_svc(codeql_available=False)
        results = svc.scan_files(self._sink_files())
        vulns = [v for r in results for v in r.vulnerabilities]
        types = _vulns_to_types(vulns)
        self.assertIn("Deserialization", types)
        self.assertIn("Command Injection", types)
        self.assertEqual(svc._last_scan_meta["engine"], "heuristic-only")

    def test_fallback_when_codeql_returns_empty(self):
        # CodeQL 可用但主链路返回空（模拟构建失败 / 0 告警）→ 应回退兜底
        svc = self._make_svc(codeql_available=True)
        with mock.patch.object(svc._semantic, "scan_project", return_value=[]):
            results = svc.scan_files(self._sink_files())
        vulns = [v for r in results for v in r.vulnerabilities]
        types = _vulns_to_types(vulns)
        self.assertIn("Deserialization", types)
        self.assertEqual(svc._last_scan_meta["engine"], "heuristic-fallback")

    def test_direct_echo_xss_flows_through_pipeline(self):
        """新规则经 A1 服务链路（兜底）产出，且必须带 rule 命中的展示字段。

        只测 analyze_content 不够：从 Vulnerability → ScanResult → findings 这条链路上
        detection_method / rule_name 决定前端显示「XX规则命中」，缺了会显示成空。
        """
        svc = self._make_svc(codeql_available=False)
        results = svc.scan_files([
            {"path": "D:/app/XSS.java", "content": JAVA_REFLECTED_XSS_ECHO, "language": "java"},
        ])
        vulns = [v for r in results for v in r.vulnerabilities]
        xss = [v for v in vulns if v.type == "XSS"]
        self.assertTrue(xss, "反射型 XSS 直出未产出 finding")
        self.assertEqual(xss[0].detection_method, "rule")
        self.assertTrue(xss[0].rule_name)
        self.assertEqual(xss[0].source, "a1-injection-heuristic")


class TestCodeQLStatusField(unittest.TestCase):
    def test_scan_returns_status_field(self):
        from src.agents.a1_codeql_adapter import CodeQLAdapter
        # 无可执行文件：unavailable
        a = CodeQLAdapter(codeql_bin="D:/no/codeql.exe")
        r = a.scan("D:/x", language="java")
        self.assertFalse(r["available"])
        self.assertEqual(r["status"], "unavailable")

    def test_build_failed_status_distinct(self):
        from src.agents.a1_codeql_adapter import CodeQLAdapter
        # 伪造一个「可用但 create 失败」的适配器，验证 status=build_failed 而非静默 0
        a = CodeQLAdapter(codeql_bin="C:/codeql/codeql.exe")
        a.is_available = lambda: True  # type: ignore[assignment]
        with mock.patch.object(a, "create_database",
                              return_value={"status": "error", "reason": "autobuild exit 1"}):
            with mock.patch.object(a, "analyze", return_value={"status": "ok", "sarif": ""}):
                r = a.scan("D:/x", language="java")
        self.assertTrue(r["available"])
        self.assertEqual(r["status"], "build_failed")
        self.assertEqual(r["alerts"], [])


class TestCommentStrip(unittest.TestCase):
    def test_comment_does_not_fake_validation(self):
        # 注释里写「无 @decimalmin / clamp 校验」不应被 has_token 当作已校验
        from src.agents._bl_common import has_token
        body = "BigDecimal p = new BigDecimal(price);\n" \
               "// 客户端可控参数直接参与金额运算，无 @decimalmin / clamp / 非负校验\n" \
               "BigDecimal total = p.multiply(new BigDecimal(quantity));"
        # @decimalmin / clamp 在注释中，剥离后不应命中
        self.assertFalse(has_token(body, ("@decimalmin", "clamp", "@min", "@max")))
        # 真实代码里的校验 token 仍应命中
        self.assertTrue(has_token("if (qty <= 0) throw new RuntimeException();", ("qty <= 0",)))


class TestNewSinkCoverage449(unittest.TestCase):
    """sink 覆盖率补强回归：MyBatis 注解 ${} / SpEL 求值 / SSRF 客户端 / XXE / XSS。"""

    def test_mybatis_annotation_sqli_with_single_quotes(self):
        # 登录查询：SQL 文本内带单引号 '${username}' —— 旧规则会因单引号提前终止匹配而漏报
        src = '''
@Select("SELECT * FROM t_user WHERE username = '${username}' AND password = '${password}'")
User findByLogin(String username, String password);
'''
        vs = analyze_content("UserMapper.java", src, "java")
        sql = [v for v in vs if v.type == "SQL Injection"]
        sinks = {v.sink for v in sql}
        self.assertTrue(sql, "MyBatis 注解 ${} SQL 注入未被检出")
        self.assertIn("MyBatis 注解 ${} 拼接", sinks)

    def test_mybatis_annotation_sqli_order_by(self):
        # ORDER BY ${sort} 无单引号
        src = '''
@Select("SELECT * FROM t_product ORDER BY ${sort}")
List<Product> list(String sort);
'''
        vs = analyze_content("ProductMapper.java", src, "java")
        self.assertTrue(any(v.type == "SQL Injection" for v in vs))

    def test_spel_getvalue_detected(self):
        src = '''
Expression expr = parser.parseExpression(input);
Object val = expr.getValue(context);
'''
        vs = analyze_content("SpelRuleEngine.java", src, "java")
        self.assertTrue(any(v.type == "SpEL Injection" for v in vs))

    def test_ssrf_resttemplate_detected(self):
        src = '''
ResponseEntity<String> r = restTemplate.getForObject(url, String.class);
'''
        vs = analyze_content("HttpFetcher.java", src, "java")
        self.assertTrue(any(v.type == "SSRF" for v in vs))

    def test_xxe_documentbuilder_detected(self):
        src = '''
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
'''
        vs = analyze_content("XmlImporter.java", src, "java")
        self.assertTrue(any(v.type == "XXE" for v in vs))

    def test_xss_getwriter_detected(self):
        # 2026-09-24：getWriter 直出规则加了污点门控，实参须引用外部输入才报。
        # 原用例是孤立的 `print(userContent)`（无污点来源），按新语义正确地不报，
        # 故补上 request 参数来源，还原它真正想验证的场景。
        src = '''
String userContent = request.getParameter("c");
response.getWriter().print(userContent);
'''
        vs = analyze_content("HomeController.java", src, "java")
        self.assertTrue(any(v.type == "XSS" for v in vs))

    def test_xss_getwriter_requires_taint(self):
        # 门控的另一半：输出静态文案/服务端自造数据不报
        # （OWASP Benchmark 上这类无差别命中占全部 finding 的 91.5%）
        src = '''
response.getWriter().print(userContent);
response.getWriter().write("403 forbidden.");
'''
        vs = analyze_content("HomeController.java", src, "java")
        self.assertFalse(any(v.type == "XSS" and "直出" in (v.sink or "") for v in vs))

    def test_pom_xml_guard_no_false_positive(self):
        # pom.xml 是 Maven 配置，含 ${spring-boot.version} 等属性占位符，不可误报为 SQL 注入
        from src.agents.a1_injection_heuristic import _is_mapper_xml
        pom = '<project>\n  <version>${revision}</version>\n</project>'
        self.assertFalse(_is_mapper_xml(pom))
        self.assertEqual(analyze_content("pom.xml", pom, "mybatis-xml"), [])

    def test_mybatis_mapper_xml_detected(self):
        # 真正的 MyBatis Mapper XML 内 ${} 必须命中
        from src.agents.a1_injection_heuristic import _is_mapper_xml
        mapper = '''<?xml version="1.0"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.x.M">
  <select id="find" resultType="User">SELECT * FROM t_user WHERE name = '${name}'</select>
</mapper>'''
        self.assertTrue(_is_mapper_xml(mapper))
        vs = analyze_content("UserMapper.xml", mapper, "mybatis-xml")
        self.assertTrue(any(v.type == "SQL Injection" for v in vs))


class TestScriptEngineRceCrossLine(unittest.TestCase):
    """Nashorn / ScriptEngine RCE：引擎获取与 eval 跨行也必须命中。"""

    def test_script_engine_rce_detected_across_lines(self):
        vs = analyze_content("Rce.java", JAVA_SCRIPT_ENGINE_RCE, "java")
        self.assertIn("Code Injection", _vulns_to_types(vs))

    def test_hit_line_is_engine_acquisition_line(self):
        """行号应落在「取引擎」那一行（对应真实漏检点 Rce.java L97），而不是 eval 行。"""
        vs = analyze_content("Rce.java", JAVA_SCRIPT_ENGINE_RCE, "java")
        lines = [v.line for v in vs if v.type == "Code Injection"]
        self.assertTrue(lines, "未命中任何 Code Injection")
        # 期望行号从夹具现算，避免夹具改动就脆断
        src_lines = JAVA_SCRIPT_ENGINE_RCE.splitlines()
        engine_line = next(i + 1 for i, s in enumerate(src_lines) if "getEngineByName" in s)
        eval_line = next(i + 1 for i, s in enumerate(src_lines) if "engine.eval" in s)
        self.assertLess(engine_line, eval_line)  # 前提：二者确实跨行
        self.assertEqual(min(lines), engine_line)

    def test_no_double_report_for_single_vuln(self):
        """一条漏洞只报一次（去重键含 sink 名，重复登记规则会造成双份噪声）。"""
        vs = analyze_content("Rce.java", JAVA_SCRIPT_ENGINE_RCE, "java")
        self.assertEqual(len([v for v in vs if v.type == "Code Injection"]), 1)

    def test_engine_without_eval_not_reported(self):
        """只创建引擎不执行不算漏洞，避免误报膨胀。"""
        src = """
import javax.script.ScriptEngineManager;
public class A {
    public void f() {
        ScriptEngineManager manager = new ScriptEngineManager();
        System.out.println(manager.getEngineFactories().size());
    }
}
"""
        vs = analyze_content("A.java", src, "java")
        self.assertNotIn("Code Injection", _vulns_to_types(vs))


# README 独立条目 XSS 的反射直出形态（java-sec-code controller/XSS.java）：
# @ResponseBody 处理函数把 String 形参原样 return，无任何转义。
JAVA_REFLECTED_XSS_ECHO = """
package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/xss")
public class XSS {

    @RequestMapping("/reflect")
    @ResponseBody
    public static String reflect(String xss) {
        return xss;
    }

    @RequestMapping("/stored/show")
    @ResponseBody
    public String show(@CookieValue("xss") String xss) {
        return xss;
    }

    @RequestMapping("/safe")
    @ResponseBody
    public static String safe(String xss) {
        return encode(xss);
    }

    private static String encode(String origin) {
        origin = StringUtils.replace(origin, "<", "&lt;");
        return origin;
    }
}
"""


class TestReflectedXssDirectEcho(unittest.TestCase):
    """反射型 XSS 直出：形参原样 return 才算，经过转义函数的不算。"""

    def test_direct_echo_detected(self):
        vs = analyze_content("XSS.java", JAVA_REFLECTED_XSS_ECHO, "java")
        self.assertIn("XSS", _vulns_to_types(vs))

    def test_hit_line_is_the_return_statement(self):
        """行号必须是真正的输出点（`return xss;`），不是注解行或方法声明行。

        XSS.java 是两个 `return xss;`：裸形参与 @CookieValue 注解形参各一。
        """
        vs = analyze_content("XSS.java", JAVA_REFLECTED_XSS_ECHO, "java")
        lines = sorted(v.line for v in vs if v.type == "XSS")
        src_lines = JAVA_REFLECTED_XSS_ECHO.splitlines()
        expect = sorted(
            i + 1 for i, s in enumerate(src_lines)
            if s.strip() in ("return xss;",)
        )
        self.assertEqual(len(expect), 2, "夹具应含两个直出点")
        self.assertEqual(lines, expect)

    def test_sanitized_return_not_reported(self):
        """`return encode(xss);` 经过转义，不得报为直出（safe 端点是反例）。"""
        vs = analyze_content("XSS.java", JAVA_REFLECTED_XSS_ECHO, "java")
        src_lines = JAVA_REFLECTED_XSS_ECHO.splitlines()
        safe_line = next(i + 1 for i, s in enumerate(src_lines) if "encode(xss)" in s)
        self.assertNotIn(safe_line, [v.line for v in vs if v.type == "XSS"])

    def test_class_level_annotation_alone_not_enough(self):
        """只有类级注解、方法体没有 return 形参时不报，避免把整个类体当一次命中。"""
        src = """
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Plain {
    private String cache = "";

    public String fetch(String key) {
        this.cache = key;
        return "ok";
    }
}
"""
        vs = analyze_content("Plain.java", src, "java")
        self.assertNotIn("XSS", _vulns_to_types(vs))

    def test_returned_param_must_be_string_param_of_same_method(self):
        """返回局部变量（非形参）不报——否则常量转发类代码会大面积误报。"""
        src = """
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

public class Echo {
    @RequestMapping("/echo")
    @ResponseBody
    public String echo(String ignored) {
        String rendered = "static-content";
        return rendered;
    }
}
"""
        vs = analyze_content("Echo.java", src, "java")
        self.assertNotIn("XSS", _vulns_to_types(vs))


# README 独立条目 ooxmlXXE：POI/OOXML（xlsx/docx）解析入口。
JAVA_POI_OOXML = """
package org.joychou.controller.othervulns;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.multipart.MultipartFile;

public class ooxmlXXE {

    @PostMapping("/readxlsx")
    public String ooxml_xxe(MultipartFile file) throws IOException {
        XSSFWorkbook wb = new XSSFWorkbook(file.getInputStream()); // xxe vuln
        return wb.getSheetAt(0).toString();
    }
}
"""


class TestPoiOoxmlXxe(unittest.TestCase):
    """POI/OOXML 解析：库自身版本决定是否解析外部实体，属 README 独立条目。"""

    def test_xssfworkbook_detected(self):
        vs = analyze_content("ooxmlXXE.java", JAVA_POI_OOXML, "java")
        self.assertIn("XXE", _vulns_to_types(vs))

    def test_no_hit_when_no_poi_entry(self):
        src = """
public class Plain {
    public String handle(String name) {
        return name.trim();
    }
}
"""
        vs = analyze_content("Plain.java", src, "java")
        self.assertNotIn("XXE", _vulns_to_types(vs))


# ===== 配置类检测通道（2026-09-18，评审方案二）=====
# 覆盖 README 的 Actuators to RCE：application.properties 关掉 actuator 安全校验、
# logback-online.xml 挂 <jmxConfigurator/>。两类此前完全落在检测之外：
# .properties 无扩展名映射（analyze_content 首行直接返回空）；
# 非 mapper 的 .xml 被 _is_mapper_xml 闸门拒掉。
PROP_ACTUATOR = """
# Spring Boot Actuator Config
management.security.enabled=false
management.endpoints.web.exposure.include=*
management.endpoint.shutdown.enabled=true
"""

LOGBACK_XML_JMX = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <jmxConfigurator/>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender"/>
</configuration>
"""

MYBATIS_MAPPER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.x.UserMapper">
    <select id="q">SELECT * FROM t WHERE name = '${name}'</select>
</mapper>
"""

POM_LIKE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<project><properties><spring-boot.version>${spring-boot.version}</spring-boot.version></properties></project>
"""


class TestConfigSecurityRules(unittest.TestCase):
    """配置类静态检测：actuator 暴露与 logback JMX，族归 config-security（暴露轴）。"""

    def test_properties_language_is_recognized(self):
        """扩展名闸门：.properties 此前无映射，analyze_content 会直接返回空。"""
        from src.agents.a1_injection_heuristic import _detect_language

        self.assertEqual(_detect_language("src/main/resources/application.properties"), "properties")

    def test_actuator_security_disabled_detected(self):
        vs = analyze_content("application.properties", PROP_ACTUATOR)
        self.assertIn("Security Misconfiguration", _vulns_to_types(vs))

    def test_actuator_hits_land_on_expected_lines(self):
        vs = analyze_content("application.properties", PROP_ACTUATOR)
        hits = {(v.line, v.sink) for v in vs if v.type == "Security Misconfiguration"}
        self.assertIn((3, "actuator 安全校验被关闭"), hits)
        self.assertIn((4, "actuator 端点全量暴露"), hits)
        self.assertIn((5, "actuator 端点被单独开启"), hits)

    def test_logback_jmx_in_non_mapper_xml(self):
        """关键：非 mapper 的 xml 此前被一概丢弃，现在必须走配置规则组。"""
        vs = analyze_content("logback-online.xml", LOGBACK_XML_JMX)
        self.assertIn("Security Misconfiguration", _vulns_to_types(vs))

    def test_mapper_xml_still_takes_sql_route(self):
        """门控未被破坏：MyBatis Mapper 仍走 SQL 规则，不进配置组。"""
        vs = analyze_content("UserMapper.xml", MYBATIS_MAPPER_XML)
        types = _vulns_to_types(vs)
        self.assertIn("SQL Injection", types)
        self.assertNotIn("Security Misconfiguration", types)

    def test_non_mapper_xml_no_false_positive(self):
        """pom.xml 的 Maven 属性占位符不得被误报（配置组不含 SQL 规则）。"""
        vs = analyze_content("pom.xml", POM_LIKE_XML)
        self.assertFalse(_vulns_to_types(vs))

    def test_plain_properties_no_hit(self):
        vs = analyze_content("application.properties", "server.port=8080\nlogging.level.root=INFO\n")
        self.assertFalse(_vulns_to_types(vs))

    def test_config_types_map_to_exposure_axis(self):
        """族轴：配置类与凭据类必须落在暴露轴（不进重放 / 差分 / 召回）。"""
        from src.core.exploit_spec import derive_flow_type

        self.assertEqual(derive_flow_type("Security Misconfiguration"), "exposure")
        self.assertEqual(derive_flow_type("Sensitive Data Exposure"), "exposure")
        vs = analyze_content("application.properties", PROP_ACTUATOR)
        self.assertTrue(vs)
        for v in vs:
            self.assertEqual(derive_flow_type(v.type), "exposure")
            self.assertTrue(v.rule_name)


class TestCredentialRules(unittest.TestCase):
    """明文凭据：单列、只检出、不计入召回（2026-09-18 决议，观察一轮再定）。"""

    def test_plaintext_password_detected(self):
        vs = analyze_content("application.properties", "spring.datasource.password=root123\n")
        self.assertIn("Sensitive Data Exposure", _vulns_to_types(vs))

    def test_plaintext_aksk_detected(self):
        vs = analyze_content("application.properties", "accessKeySecret=AKIDabcdef123456\n")
        self.assertIn("Sensitive Data Exposure", _vulns_to_types(vs))

    def test_placeholders_are_not_reported(self):
        """配置里大量模板值，占位符一律不报，否则会把示例值误判成真实凭据。"""
        for line in (
            "spring.datasource.password=${DB_PASSWORD}",
            "spring.datasource.password=your_password",
            "spring.datasource.password=changeme",
            "spring.datasource.password=<password>",
            "spring.datasource.password=password",
        ):
            vs = analyze_content("application.properties", line + "\n")
            self.assertFalse(_vulns_to_types(vs), line)

    def test_switch_can_disable_credential_rules(self):
        import src.agents.a1_injection_heuristic as mod

        src = "spring.datasource.password=root123\n"
        old = mod._CREDENTIAL_RULES_ENABLED
        try:
            mod._CREDENTIAL_RULES_ENABLED = False
            vs = analyze_content("application.properties", src)
            self.assertNotIn("Sensitive Data Exposure", _vulns_to_types(vs))
        finally:
            mod._CREDENTIAL_RULES_ENABLED = old


if __name__ == "__main__":
    unittest.main()
