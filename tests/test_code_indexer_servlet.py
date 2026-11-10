"""P0-1：@WebServlet 接入通用入口发现的回归守卫。

背景（2026-09-25 task-5/6 复盘）：code_indexer 只认 Spring 注解，OWASP Benchmark
205 个 @WebServlet 类索引出 0 个 HTTP 入口，下游 252/253 候选 no_trigger_spec。
"""
import pytest

from src.core.code_indexer import CodeIndexer


SERVLET_JAVA = """package org.owasp.benchmark.testcode;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00001")
public class BenchmarkTest00001 extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String param = request.getParameter("foo");
        String sql = "INSERT INTO users VALUES('" + param + "')";
        try {
            java.sql.Statement statement = connection.createStatement();
            statement.execute(sql);
        } catch (Exception e) { }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }

    private String helper(String x) {
        return x;
    }
}
"""

FILTER_JAVA = """package org.owasp.benchmark.testcode;

import javax.servlet.annotation.WebFilter;

@WebFilter("/*")
public class BenchmarkFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) { }
}
"""

SPRING_JAVA = """package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/api")
public class UserController {
    @RequestMapping("/users")
    public String list() { return "ok"; }
}
"""


def _index(*file_pairs):
    idx = CodeIndexer()
    payload = [
        {"rel_path": name, "content": content, "language": "java"}
        for name, content in file_pairs
    ]
    return idx.index_project(payload)


def test_webservlet_route_attached_to_do_methods():
    result = _index(("a/BenchmarkTest00001.java", SERVLET_JAVA))
    assert result["stats"]["http_entries"] == 2  # doGet + doPost
    post = result["functions"]["a/BenchmarkTest00001.java:doPost"]
    get = result["functions"]["a/BenchmarkTest00001.java:doGet"]
    assert post["http_entry"] == "POST /sqli-00/BenchmarkTest00001"
    assert get["http_entry"] == "GET /sqli-00/BenchmarkTest00001"


def test_servlet_helper_methods_not_marked_as_entries():
    result = _index(("a/BenchmarkTest00001.java", SERVLET_JAVA))
    helper = result["functions"]["a/BenchmarkTest00001.java:helper"]
    assert helper["http_entry"] is None


def test_servlet_class_annotation_recorded():
    result = _index(("a/BenchmarkTest00001.java", SERVLET_JAVA))
    assert "servlet" in result["classes"]["BenchmarkTest00001"]["annotations"]


def test_webservlet_annotation_variants():
    f = CodeIndexer._extract_servlet_route
    assert f('@WebServlet(value = "/sqli-00/BenchmarkTest00001")') == "/sqli-00/BenchmarkTest00001"
    assert f('@WebServlet("/xss-05/T")') == "/xss-05/T"
    assert f('@WebServlet(urlPatterns = "/cmd-00/T")') == "/cmd-00/T"
    assert f('@WebServlet(value = { "/a/T", "/b/T" })') == "/a/T"
    assert f('@RequestMapping("/not/servlet")') == ""
    assert f("") == ""


def test_webfilter_not_treated_as_servlet_entry():
    result = _index(("a/BenchmarkFilter.java", FILTER_JAVA))
    assert result["stats"]["http_entries"] == 0
    assert "servlet" not in result["classes"]["BenchmarkFilter"]["annotations"]


def test_spring_controller_still_works_alongside():
    result = _index(("a/BenchmarkTest00001.java", SERVLET_JAVA), ("b/UserController.java", SPRING_JAVA))
    assert result["stats"]["http_entries"] == 3
    assert result["functions"]["b/UserController.java:list"]["http_entry"] == "GET /api/users"


def test_real_benchmark_sample_counts_205_entries():
    """真源码冒烟：OWASP Benchmark 205 个 @WebServlet 类必须全部索引出入口。"""
    from pathlib import Path

    root = Path("<sdl-root>/owasp-code/benchmark-sample-200/src")
    if not root.is_dir():
        pytest.skip("benchmark source not present on this machine")
    files = []
    for p in root.rglob("*.java"):
        files.append((str(p.relative_to(root)), p.read_text(encoding="utf-8", errors="replace")))
    result = _index(*files)
    assert result["stats"]["http_entries"] >= 400  # 每类 doGet+doPost 双入口
