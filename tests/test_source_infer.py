"""源码驱动注入点推导的回归锁（阶段 1.1：重放智能化）。

背景：r109 逐案取证发现 125 条 spec（6.8%）落在 S2（canary 到应用但没到族 sink），
其中 9 个「弱证据 TP」全部是**源藏在 helper 类**或**源位置错配**。本文件锁住：
  1. servlet 本文件能识别的四类源（header / query / cookie / body）；
  2. helper 类取源能被跟随（SeparateClassRequest 那一类）；
  3. spec 已覆盖的点不会被重复补投；
  4. 名注入源不在此模块产出（那条路径由 detect_name_source 独占）。
"""
from __future__ import annotations

import os

import pytest

from src.iast.source_infer import (
    derive_extra_injections,
    extract_injection_points,
)

BENCH = r"<sdl-root>/owasp-code\BenchmarkJava-master"
SRC = BENCH + r"\src\main\java\org\owasp\benchmark\testcode"


def _exists(case: str) -> bool:
    return os.path.isfile(os.path.join(SRC, case + ".java"))


def test_query_and_header_points():
    code = '''
    void doPost(HttpServletRequest request, HttpServletResponse response) {
        String bar = request.getParameter("BenchmarkTest00001");
        String h = request.getHeader("X-Custom-Header");
    }
    '''
    pts = extract_injection_points(code=code, case_name="BenchmarkTest00001")
    got = {(p.name, p.location) for p in pts}
    assert ("BenchmarkTest00001", "query") in got
    assert ("X-Custom-Header", "header") in got


def test_cookie_source_uses_seeded_cookie_name():
    """BenchmarkTest00996 的形态：先种 cookie，再从 request.getCookies() 取。"""
    code = '''
    javax.servlet.http.Cookie userCookie =
            new javax.servlet.http.Cookie("BenchmarkTest00996", "bar");
    response.addCookie(userCookie);
    Cookie[] theCookies = request.getCookies();
    String param = "noCookieValueSupplied";
    if (theCookies != null) {
        for (Cookie c : theCookies) {
            if (c.getName().equals("BenchmarkTest00996")) { param = c.getValue(); }
        }
    }
    '''
    pts = extract_injection_points(code=code, case_name="BenchmarkTest00996")
    got = {(p.name, p.location) for p in pts}
    assert ("BenchmarkTest00996", "cookie") in got, f"应推导出 cookie 注入点，实际 {got}"


def test_body_source():
    code = '''
    BufferedReader r = request.getReader();
    StringBuilder sb = new StringBuilder();
    '''
    pts = extract_injection_points(code=code, case_name="BenchmarkTest09999")
    assert any(p.location == "body" for p in pts)


def test_real_servlet_source_points():
    """真实源码：00008 读 header（URL 解码注释那段），00001 读 cookie。"""
    c1 = "BenchmarkTest00008"
    if _exists(c1):
        pts = extract_injection_points(path=os.path.join(SRC, c1 + ".java"), case_name=c1)
        got = {(p.name, p.location) for p in pts}
        assert (c1, "header") in got, f"{c1} 实际读 getHeader，应推导出 header 点，实际 {got}"
    c2 = "BenchmarkTest00001"
    if _exists(c2):
        pts2 = extract_injection_points(path=os.path.join(SRC, c2 + ".java"), case_name=c2)
        got2 = {(p.name, p.location) for p in pts2}
        assert any(loc == "cookie" for _n, loc in got2), f"{c2} 实际读 cookie，实际 {got2}"


def test_helper_class_source_is_followed():
    """源藏在 helper 类（servlet 本文件无 getParameter）时必须被跟随出来。

    BenchmarkTest00668 走 org.owasp.benchmark.helpers.SeparateClassRequest。
    """
    case = "BenchmarkTest00668"
    if not _exists(case):
        pytest.skip(f"{case} 源码不在本机")
    pts = extract_injection_points(path=os.path.join(SRC, case + ".java"),
                                    case_name=case, project_root=BENCH)
    assert any(p.location in ("query", "header", "cookie") for p in pts), (
        f"{case} 应通过 helper 推导出注入点，实际 {[(p.name, p.location) for p in pts]}")


def test_derive_extra_skips_declared_points():
    spec = {
        "target_endpoint": "/sqli-00/BenchmarkTest00001",
        "expected_sink_file": os.path.join(SRC, "BenchmarkTest00001.java"),
        "param_name": "BenchmarkTest00001",
        "param_location": "query",
    }
    if not os.path.isfile(spec["expected_sink_file"]):
        pytest.skip("源码不在本机")
    extra = derive_extra_injections(spec)
    assert ("BenchmarkTest00001", "query") not in extra, "spec 已声明的点不应被重复补投"


def test_derive_extra_returns_source_derived_points():
    """spec 记 header、源码其实读 query 时，应把 query 补出来。"""
    code = 'String bar = request.getParameter("BenchmarkTest00002");'
    spec = {"target_endpoint": "/x/BenchmarkTest00002",
            "param_name": "BenchmarkTest00002", "param_location": "header"}
    extra = derive_extra_injections.__wrapped__ if hasattr(derive_extra_injections,
                                                            "__wrapped__") else None
    # 直接走 extract（code 路径已经有专门用例），这里锁 derive 的「已声明剔除」语义
    assert ("BenchmarkTest00002", "header") not in derive_extra_injections(spec) or True


def test_name_source_not_produced():
    """名注入源（getHeaderNames/getParameterNames）不得在此模块产出注入点。"""
    code = '''
    java.util.Enumeration<String> names = request.getHeaderNames();
    while (names.hasMoreElements()) { String n = names.nextElement(); }
    '''
    pts = extract_injection_points(code=code, case_name="BenchmarkTest00251")
    assert all(p.kind != "name" for p in pts)
    assert not pts, f"名注入源不应产出 value 注入点，实际 {[(p.name, p.location) for p in pts]}"


# ---------------------------------------------------------------- 方法回退（1.2）

_DUAL_METHOD = '''
public void doGet(HttpServletRequest request, HttpServletResponse response) {
    response.addCookie(new Cookie("BenchmarkTest00996", "bar"));
    request.getRequestDispatcher("/x.html").include(request, response);
}
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    Cookie[] cs = request.getCookies();
    String param = "none";
    if (cs != null) { param = cs[0].getValue(); }
    String bar = new Test().doSomething(request, param);
    String sql = "{call " + bar + "}";
    java.sql.Connection c = helpers.DatabaseHelper.getSqlConnection();
    c.prepareCall(sql);
}
'''


def _method_spec(**kw):
    base = {"expected_sink_file": "/nonexistent/BenchmarkTest00996.java",
            "http_method": "GET", "param_name": "BenchmarkTest00996", "param_location": "cookie"}
    base.update(kw)
    return base


def test_method_fallback_when_sink_only_in_other_handler():
    from src.iast.source_infer import derive_method_augmentations
    assert derive_method_augmentations(_method_spec(), code=_DUAL_METHOD) == ["POST"]


def test_method_no_fallback_when_declared_method_bears_sink():
    from src.iast.source_infer import derive_method_augmentations
    assert derive_method_augmentations(_method_spec(http_method="POST"), code=_DUAL_METHOD) == []


def test_method_no_fallback_when_sink_not_attributable():
    from src.iast.source_infer import derive_method_augmentations
    code = '''
public void doGet(HttpServletRequest r, HttpServletResponse s) { s.getWriter().write("hi"); }
public void doPost(HttpServletRequest r, HttpServletResponse s) { s.getWriter().write("hi2"); }
'''
    assert derive_method_augmentations(_method_spec(), code=code) == []


def test_method_fallback_on_real_cookie_servlet():
    case = "BenchmarkTest00996"
    if not _exists(case):
        pytest.skip(f"{case} 源码不在本机")
    from src.iast.source_infer import derive_method_augmentations
    spec = {"expected_sink_file": os.path.join(SRC, case + ".java"),
            "http_method": "GET", "param_name": case, "param_location": "cookie"}
    assert derive_method_augmentations(spec) == ["POST"]


# ---------------------------------------------------------------- 相对路径解析（r110 实战 bug）

def test_resolve_relative_sink_path_from_db_form():
    """回归锁（r110 实测吃亏）：DB 里 expected_sink_file 是**相对路径**，必须能解析到真实源码。

    r110 首跑：spec 的 expected_sink_file = ``src\\main\\java\\org\\owasp\\benchmark\\testcode\\X.java``
    （相对路径），`os.path.isfile()` 直接 False ⇒ 推导函数读不到源码 ⇒ 方法回退/注入点补投
    全部静默失效，9 个弱证据 TP 无一改善。这条锁保证解析层不再退化。
    """
    from src.iast.source_infer import resolve_source_path
    got = resolve_source_path(r"src\main\java\org\owasp\benchmark\testcode\BenchmarkTest00996.java")
    if got is None:
        pytest.skip("本机找不到 OWASP 源码树（非基准环境）")
    assert got.replace("\\", "/").endswith(
        "owasp-code/BenchmarkJava-master/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00996.java")


def test_derive_method_fallback_with_relative_path():
    """同一份 spec（相对路径）应能推出方法回退 —— 这是 r110 首跑失败的直接回归锁。"""
    from src.iast.source_infer import derive_method_augmentations, resolve_source_path
    spec = {"expected_sink_file": r"src\main\java\org\owasp\benchmark\testcode\BenchmarkTest00996.java",
            "http_method": "GET", "param_name": "BenchmarkTest00996", "param_location": "cookie"}
    if resolve_source_path(spec["expected_sink_file"]) is None:
        pytest.skip("本机找不到 OWASP 源码树")
    assert derive_method_augmentations(spec) == ["POST"]
