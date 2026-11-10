"""过滤器前置 header 抽取的回归锁（2026-11-02）。

背景：有些应用在 `Filter` 里校验 `Referer` / `Origin`，缺了就直接 `return` 或 403。
这时参数、编码、HTTP 方法全对，请求也**进不到业务代码** —— jsc 的 `ReferFilter`
就是这一类（jsonp 族曾整族 no-arrival）。

本文件锁四件事：能抽到 header、能识别「校验型」、urlPattern 匹配正确、
以及**跨类校验（jsc 的 WebConfig.getReferUris）也要带同源默认值**——
那是「读」型，但静态抽不出「哪些路由要校验」，只能按「读过就带」兜底。
"""
from __future__ import annotations

from src.core.filter_requirements import (
    extract_requirements, headers_for_route, summarize, _pattern_matches,
)

FILTER_CHECK = '''package d;
@WebFilter(urlPatterns = "/jsonp/*")
public class ReferFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        HttpServletRequest request = (HttpServletRequest) req;
        String refer = request.getHeader("referer");
        if (!refer.contains("example.com")) { return; }
        chain.doFilter(req, res);
    }
}
'''

FILTER_READ_ONLY = '''package d;
public class OriginFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        String origin = ((HttpServletRequest) req).getHeader("Origin");
        chain.doFilter(req, res);
    }
}
'''

NOT_A_FILTER = '''package d;
@RestController
public class C {
    @GetMapping("/x")
    public String x(HttpServletRequest r) { return r.getHeader("Referer"); }
}
'''


def test_extracts_header_from_filter_only():
    reqs = extract_requirements([
        {"path": "ReferFilter.java", "content": FILTER_CHECK},
        {"path": "C.java", "content": NOT_A_FILTER},
    ])
    headers = {r.header for r in reqs}
    assert "referer" in headers
    assert "Referer" not in headers, "非 Filter 类里的 getHeader 不算过滤器要求"


def test_check_kind_captures_value_domain():
    reqs = [r for r in extract_requirements([{"path": "F.java", "content": FILTER_CHECK}])
            if r.header == "referer"]
    assert reqs and reqs[0].kind == "check"
    assert "example.com" in reqs[0].values


def test_read_only_filter_still_produces_headers():
    """跨类校验（真正的判定在别的类里）时，静态只能判成「读」——但仍要带值。"""
    reqs = extract_requirements([{"path": "F.java", "content": FILTER_READ_ONLY}])
    assert any(r.header == "Origin" for r in reqs)
    got = headers_for_route(reqs, "/cors/vuln/origin", "http://127.0.0.1:8080")
    assert got.get("Origin") == "http://127.0.0.1:8080"


def test_url_pattern_matching():
    assert _pattern_matches("/*", "/a/b")
    assert _pattern_matches("/**", "/a/b")
    assert _pattern_matches("/jsonp/*", "/jsonp/object2jsonp")
    assert _pattern_matches("/api/**", "/api/v1/x")
    assert _pattern_matches("/cors/sec/originFilter", "/cors/sec/originFilter")
    assert not _pattern_matches("/jsonp/*", "/sqli/jdbc/vuln")


def test_headers_only_for_matching_routes():
    reqs = extract_requirements([{"path": "F.java", "content": FILTER_CHECK}])
    assert headers_for_route(reqs, "/jsonp/object2jsonp", "http://h:8080").get("referer")
    assert headers_for_route(reqs, "/sqli/jdbc/vuln", "http://h:8080") == {}


def test_default_referer_is_same_origin():
    """值域里没有 http 前缀时，要补成合法 URL（浏览器 Referer 不会只有域名）。"""
    reqs = extract_requirements([{"path": "F.java", "content": FILTER_CHECK}])
    got = headers_for_route(reqs, "/jsonp/x", "http://127.0.0.1:8080")
    assert got["referer"].startswith("http://")
    assert "example.com" in got["referer"]


def test_summarize_counts_by_header():
    reqs = extract_requirements([{"path": "F.java", "content": FILTER_CHECK},
                                 {"path": "G.java", "content": FILTER_READ_ONLY}])
    s = summarize(reqs)
    assert s.get("referer") and s.get("Origin")


# ── 配置感知：只读源码不准（2026-11-02 用户指出）─────────────────────────────
#
# jsc 的真实配置：
#   joychou.security.referer.enabled = false        ← 全局关
#   joychou.security.referer.host = joychou.org, joychou.com
#   joychou.security.referer.uri = /jsonp/**        ← 校验范围
#   joychou.security.jsonp.referer.check.enabled = true   ← 专用开
# 只读源码只能得出「ReferFilter 读了 referer」，于是给**所有路由**塞
# `Referer: http://<target>/` —— 而那个值**过不了 host 白名单**，
# 反而让本来能过的 jsonp 端点失败。必须把配置一起读。

JSC_PROPS = """joychou.security.referer.enabled = false
joychou.security.referer.host = joychou.org, joychou.com
joychou.security.referer.uri = /jsonp/**
joychou.security.jsonp.referer.check.enabled = true
"""

FILTER_SIMPLE = '''package d;
@WebFilter("/*")
public class ReferFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        String refer = ((HttpServletRequest) req).getHeader("referer");
        chain.doFilter(req, res);
    }
}
'''


def test_config_supplies_scope_and_value_domain():
    reqs = extract_requirements([
        {"path": "ReferFilter.java", "content": FILTER_SIMPLE},
        {"path": "application.properties", "content": JSC_PROPS},
    ])
    assert headers_for_route(reqs, "/jsonp/object2jsonp", "http://h:8080") == {
        "referer": "http://joychou.org/"}


def test_config_scope_excludes_other_routes():
    """校验范围是 /jsonp/** ⇒ 其他路由不该被塞 Referer（否则污染请求）。"""
    reqs = extract_requirements([
        {"path": "ReferFilter.java", "content": FILTER_SIMPLE},
        {"path": "application.properties", "content": JSC_PROPS},
    ])
    assert headers_for_route(reqs, "/sqli/jdbc/vuln", "http://h:8080") == {}


def test_specific_enabled_overrides_global_disabled():
    """全局 `referer.enabled=false` + 专用 `jsonp.referer.check.enabled=true` ⇒ 仍要求。"""
    reqs = extract_requirements([
        {"path": "ReferFilter.java", "content": FILTER_SIMPLE},
        {"path": "application.properties", "content": JSC_PROPS},
    ])
    assert reqs, "专用开关为 true 时不能因为全局开关 false 就整体关掉"


def test_all_disabled_means_no_requirement():
    props = """app.referer.enabled = false
app.referer.host = a.com
app.referer.uri = /x/**
"""
    reqs = extract_requirements([
        {"path": "ReferFilter.java", "content": FILTER_SIMPLE},
        {"path": "application.properties", "content": props},
    ])
    assert headers_for_route(reqs, "/x/y", "http://h") == {}
