"""A1 污点门控单测（2026-09-24，OWASP Benchmark 对账驱动）。

覆盖三件事:
  1. XSS `getWriter 直出` 规则加了门控后，静态文案/自造数据不再报
  2. 门控不误杀真污点直出（含容器 HashMap/List 中转形态）
  3. 新增的「文件读写 sink」路径穿越规则能认出 `new FileOutputStream(fileName)`
"""

import os

import pytest

LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")
pytestmark = [
    pytest.mark.external,
    pytest.mark.skipif(
        not LOCAL_ROOT,
        reason="external target sources required: set SAST_AI_SDL_ROOT to your local targets root",
    ),
]

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.a1_injection_heuristic import analyze_content  # noqa: E402

SAMPLE = os.path.join(LOCAL_ROOT, "owasp-code", "benchmark-sample-200",
                            "src", "main", "java", "org", "owasp", "benchmark", "testcode")
JSC = os.path.join(LOCAL_ROOT, "java-sec-code")


def types_of(content, path="T.java"):
    return sorted({(v.type, v.sink) for v in analyze_content(path, content, "java")})


def real_file(name):
    p = os.path.join(SAMPLE, name + ".java")
    if not os.path.isfile(p):
        return None
    return open(p, encoding="utf-8", errors="ignore").read()


def test_static_echo_is_not_xss():
    """输出纯静态文案不应报 XSS（Benchmark FPR 94.95% 的主因）。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().println("Welcome back: " + user + "<br/>");
        response.getWriter().write("403 forbidden by JoyChou.");
    }
}
"""
    assert ("XSS", "response.getWriter 直出") not in types_of(src)


def test_tainted_echo_is_xss():
    """实参引用 request 参数才是 XSS——门控不得误杀真污点。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("x");
        response.getWriter().println("hello " + param);
    }
}
"""
    assert ("XSS", "response.getWriter 直出") in types_of(src)


def test_taint_through_container_is_xss():
    """污点经 HashMap 中转再取出后直出，仍须报——OWASP Benchmark 的刻意设计。

    只做「RHS 含污点变量名」会在此断链，实测会漏掉全部 7 个此类 xss 真漏洞。
    """
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("x");
        java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
        m.put("keyB", param);
        String bar = (String) m.get("keyB");
        response.getWriter().print(bar);
    }
}
"""
    assert ("XSS", "response.getWriter 直出") in types_of(src)


def test_taint_through_list_is_xss():
    """污点经 List 中转（add → get(0)）同样须报。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("x");
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add(param);
        String bar = valuesList.get(0);
        response.getWriter().print(bar);
    }
}
"""
    assert ("XSS", "response.getWriter 直出") in types_of(src)


def test_sanitized_echo_is_not_xss():
    """经 htmlEscape / encodeForHTML 转义后直出不报 XSS。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("x");
        String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
        response.getWriter().println(bar);
    }
}
"""
    assert ("XSS", "response.getWriter 直出") not in types_of(src)


def test_file_output_stream_is_path_traversal():
    """先拼路径再传 FileOutputStream——旧规则认不出，新规则须认出。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("BenchmarkTest00028");
        String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
        java.io.FileOutputStream fos = null;
        fos = new java.io.FileOutputStream(fileName, false);
    }
}
"""
    assert ("Path Traversal", "文件读写 sink") in types_of(src)


def test_file_stream_with_static_path_is_not_reported():
    """文件流参数不含污点（固定路径）不应报路径穿越。"""
    src = """
public class T {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        java.io.FileOutputStream fos = new java.io.FileOutputStream("/tmp/safe.txt", false);
    }
}
"""
    assert ("Path Traversal", "文件读写 sink") not in types_of(src)


def test_legacy_path_rule_still_works():
    """原有 `new File(a+b)` 规则保留，不得被新规则顶掉。"""
    src = """
public class T {
    void f(HttpServletRequest request) {
        String p = request.getParameter("f");
        String base = "/base/";
        java.io.File f = new java.io.File(base + p);
    }
}
"""
    assert ("Path Traversal", "文件路径拼接") in types_of(src)


def test_benchmark_pathtraver_true_positive():
    """真实样本：00028 是 pathtraver 真漏洞，须报出路径穿越。"""
    c = real_file("BenchmarkTest00028")
    if c is None:
        return
    assert ("Path Traversal", "文件读写 sink") in types_of(c)


def test_benchmark_false_positive_no_longer_xss():
    """真实样本：00178（weakrand 假阳性）与 00277（xss 假阳性）不应再被报 XSS。

    这两个用例的输出点全部输出静态文案或经 htmlEscape 转义的内容。
    """
    for name in ("BenchmarkTest00178", "BenchmarkTest00277"):
        c = real_file(name)
        if c is None:
            continue
        assert ("XSS", "response.getWriter 直出") not in types_of(c), name


def test_java_sec_code_static_handlers_not_xss():
    """java-sec-code 的 7 条 getWriter 命中经源码核验 100% 是静态文案，门控后须消失。"""
    rel = [
        "src/main/java/org/joychou/controller/URLRedirect.java",
        "src/main/java/org/joychou/filter/OriginFilter.java",
        "src/main/java/org/joychou/filter/ReferFilter.java",
        "src/main/java/org/joychou/security/CsrfAccessDeniedHandler.java",
        "src/main/java/org/joychou/security/LoginFailureHandler.java",
    ]
    checked = 0
    for r in rel:
        p = os.path.join(JSC, r.replace("/", os.sep))
        if not os.path.isfile(p):
            continue
        checked += 1
        c = open(p, encoding="utf-8", errors="ignore").read()
        assert ("XSS", "response.getWriter 直出") not in types_of(c, p), r
    assert checked >= 3, f"样本文件不足，仅校验 {checked} 个"


if __name__ == "__main__":
    import traceback
    fns = [(n, o) for n, o in sorted(globals().items()) if n.startswith("test_") and callable(o)]
    failed = 0
    for n, fn in fns:
        try:
            fn()
            print(f"  PASS  {n}")
        except Exception:
            failed += 1
            print(f"  FAIL  {n}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
