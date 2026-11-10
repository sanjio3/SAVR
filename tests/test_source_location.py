"""Phase 0a：源位置判定回归测试。"""
from src.core.source_location import detect_source_location, strip_java_comments


def test_header_via_getheader():
    code = 'param = request.getHeader("BenchmarkTest00008");'
    assert detect_source_location(code=code, case_name="BenchmarkTest00008") == "header"


def test_header_via_getheaders_enumeration():
    code = 'Enumeration<String> h = request.getHeaders("BenchmarkTest00015");'
    assert detect_source_location(code=code, case_name="BenchmarkTest00015") == "header"


def test_query_via_getparameter():
    code = 'param = request.getParameter("BenchmarkTest00006");'
    assert detect_source_location(code=code, case_name="BenchmarkTest00006") == "query"


def test_query_via_getparametermap():
    code = 'Map<String, String[]> map = request.getParameterMap();'
    assert detect_source_location(code=code, case_name="BenchmarkTest00032") == "query"


def test_cookie_via_getcookies_and_name():
    code = (
        'Cookie[] cs = request.getCookies();\n'
        'if (c.getName().equals("BenchmarkTest00001")) { param = c.getValue(); }'
    )
    assert detect_source_location(code=code, case_name="BenchmarkTest00001") == "cookie"


def test_body_via_inputstream():
    code = 'byte[] b = request.getInputStream().readAllBytes();'
    assert detect_source_location(code=code, case_name="BenchmarkTest00099") == "body"


def test_comment_must_not_pollute():
    # 注释里的 getParameters 文字不得把 header 源判成 query
    code = (
        'Enumeration<String> h = request.getHeaders("BenchmarkTest00015");\n'
        '// Unlike req.getParameters(), getHeaders() does not decode.'
    )
    assert detect_source_location(code=code, case_name="BenchmarkTest00015") == "header"


def test_ambiguous_returns_none():
    code = 'request.getHeader("X"); request.getParameter("Y"); request.getCookies();'
    assert detect_source_location(code=code, case_name="BenchmarkTest09999") is None


def test_strip_comments():
    assert "getParameter" not in strip_java_comments('// getParameter\n/* getParameter */x=1;')
