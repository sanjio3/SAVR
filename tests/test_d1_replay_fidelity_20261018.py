"""D1 重放保真度 + 判据覆盖修复（2026-10-18，r106 实证）。

三个根因各自的回归锁：
  1. sqli/xpathi sink token 覆盖缺口（prepareCall / prepareStatement / addBatch / 类级 sink /
     XPathExpressionImpl）→ no_event 假阴性；
  2. DB 列 representative_request_params_json 未映射到 D1 读取的内存键 → rep 注入空转；
  3. 名注入源 servlet（getHeaderNames 等）判定。
"""
from src.core.sink_value_gate import judge_sink_value
from src.core.source_location import detect_name_source
from src.iast.trigger_spec_registry import attach_rep_params

IDENT = "s4st41d3c6c8df3965f3e0"
MK = f"{IDENT}PAYLOAD663f6c06"


def _ev(sink_file, src):
    return [{"sink_file": sink_file, "source_value": src, "evidence_json": "{}"}]


class TestSqliSinkTokenCoverage:
    def test_preparecall_at_sink(self):
        # r106 实录：org.hsqldb.jdbc.JDBCConnection.prepareCall（58 条）
        v = judge_sink_value(
            _ev("org.hsqldb.jdbc.JDBCConnection.prepareCall",
                f"{{call {{? = call foo('{MK}')}}}}"),
            MK, "sql_injection")
        assert v["verdict"] == "at_sink"

    def test_preparestatement_method_form_at_sink(self):
        # 实录是小写方法名 prepareStatement，旧 token PreparedStatement（接口名）匹配不到
        v = judge_sink_value(
            _ev("org.hsqldb.jdbc.JDBCConnection.prepareStatement",
                f"SELECT * FROM t WHERE x='{MK}'"),
            MK, "sql_injection")
        assert v["verdict"] == "at_sink"

    def test_jdbcstatement_class_level_at_sink(self):
        v = judge_sink_value(
            _ev("org.hsqldb.jdbc.JDBCStatement", f"SELECT * FROM t WHERE x='{MK}'"),
            MK, "sql_injection")
        assert v["verdict"] == "at_sink"

    def test_addbatch_at_sink(self):
        v = judge_sink_value(
            _ev("org.apache.commons.dbcp.DelegatingStatement.addBatch",
                f"INSERT INTO t VALUES ('{MK}')"),
            MK, "sql_injection")
        assert v["verdict"] == "at_sink"

    def test_sqli_expanded_token_still_absent_on_clean_sql(self):
        v = judge_sink_value(
            _ev("org.hsqldb.jdbc.JDBCConnection.prepareCall", "{call foo('bar')}"),
            MK, "sql_injection")
        assert v["verdict"] == "absent"


class TestXPathSinkTokenCoverage:
    def test_xpath_expression_impl_at_sink(self):
        # 实录 com.sun...jaxp.XPathExpressionImpl.evaluate（122 条）；旧 token 因 Impl 断开漏匹配
        v = judge_sink_value(
            _ev("com.sun.org.apache.xpath.internal.jaxp.XPathExpressionImpl.evaluate",
                f"/root[contains(.,'{MK}')]"),
            MK, "xpath_injection")
        assert v["verdict"] == "at_sink"


class TestAttachRepParams:
    def test_maps_json_column_to_memory_key(self):
        sd = {"representative_request_params_json":
              '[{"name": "BenchmarkTest00668", "location": "query", "value": "s4st41xx"}]'}
        attach_rep_params(sd)
        assert sd["representative_request_params"] == [
            {"name": "BenchmarkTest00668", "location": "query", "value": "s4st41xx"}]

    def test_keeps_existing_memory_key(self):
        sd = {"representative_request_params": [{"name": "a"}],
              "representative_request_params_json": '[{"name": "b"}]'}
        attach_rep_params(sd)
        assert sd["representative_request_params"] == [{"name": "a"}]

    def test_bad_json_is_noop(self):
        sd = {"representative_request_params_json": "not-json"}
        attach_rep_params(sd)
        assert "representative_request_params" not in sd


class TestDetectNameSource:
    def test_header_names_loop(self):
        code = """
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) { String name = names.nextElement();
          if (Utils.commonHeaders.contains(name)) continue; param = name; }
        """
        assert detect_name_source(code=code) == "header_name"

    def test_param_names_loop(self):
        code = "Enumeration<String> e = request.getParameterNames(); param = e.nextElement();"
        assert detect_name_source(code=code) == "param_name"

    def test_cookie_names(self):
        code = """
        Cookie[] cookies = request.getCookies();
        for (Cookie c : cookies) { if (c.getName().equals("foo")) { v = c.getValue(); } }
        """
        assert detect_name_source(code=code) == "cookie_name"

    def test_value_read_servlet_is_not_name_source(self):
        code = 'String param = request.getParameter("BenchmarkTest00668");'
        assert detect_name_source(code=code) is None

    def test_comment_is_stripped(self):
        code = '// request.getHeaderNames()\nString p = request.getParameter("x");'
        assert detect_name_source(code=code) is None
