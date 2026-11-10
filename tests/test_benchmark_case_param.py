"""OWASP Benchmark「反射参数名 == 用例类名」候选补全回归锁（2026-10-12 r81 实证）。

背景：/xss-00/BenchmarkTest00047 真正读的是 ``getParameter("BenchmarkTest00047")``。
抽参器抽错时会给出 'param' / 'name' / '' 之类的兜底名（r81 实测 321 条 xss spec 里
36 条：param 20 / name 10 / 空 6）。只带错名字重放 ⇒ servlet 走「找不到参数」的提前
返回分支（响应体原文 ``getQueryString() couldn't find expected parameter
'BenchmarkTest00047' in query string.``）⇒ 不写响应体、不碰 sink ⇒ 零事件。

修复：**追加**用例名候选，绝不替换 —— 替换会弄坏 Referer 类用例（00013/00144 走 header
注入，参数名 'Referer' 本就是对的、实测可正常反射）。
"""
from src.iast.trigger_spec_registry import append_benchmark_case_param


def test_wrong_query_param_gets_case_name_candidate():
    """抽错成 'param' 时，追加用例名候选，且原参数保留（不是替换）。"""
    out = append_benchmark_case_param(
        [{"name": "param", "location": "query", "value": "s4st41abc"}],
        "param", "query", "/xss-00/BenchmarkTest00047", "s4st41abc")
    names = [p["name"] for p in out]
    assert names == ["param", "BenchmarkTest00047"], out


def test_empty_param_name_still_gets_case_candidate():
    """抽参失败（pname 为空）时，params 原来一条都没有，现在必须补上用例名。"""
    out = append_benchmark_case_param([], "", "query", "/xss-00/BenchmarkTest00048", "s4st41abc")
    assert [p["name"] for p in out] == ["BenchmarkTest00048"], out


def test_correct_param_name_not_duplicated():
    """参数名本来就对时不得重复追加（否则多带一个同名参数、还可能触发别的分支）。"""
    out = append_benchmark_case_param(
        [{"name": "BenchmarkTest00030", "location": "query", "value": "s4st41abc"}],
        "BenchmarkTest00030", "query", "/xss-00/BenchmarkTest00030", "s4st41abc")
    assert [p["name"] for p in out] == ["BenchmarkTest00030"], out


def test_referer_header_case_is_untouched():
    """Referer 类用例是 header 注入，参数名 'Referer' 是对的 —— 绝不能被用例名顶掉。

    实测：00013/00144 走 Referer 正常反射，若把 query 参数改成用例名反而失去注入点。
    """
    base = [{"name": "Referer", "location": "header", "value": "s4st41abc"}]
    out = append_benchmark_case_param(base, "Referer", "header",
                                      "/xss-00/BenchmarkTest00013", "s4st41abc")
    assert out == base, out


def test_cookie_location_is_untouched():
    base = [{"name": "JSESSIONID", "location": "cookie", "value": "s4st41abc"}]
    out = append_benchmark_case_param(base, "JSESSIONID", "cookie",
                                      "/xss-00/BenchmarkTest00099", "s4st41abc")
    assert out == base, out


def test_non_benchmark_route_is_untouched():
    """非 Benchmark 路由必须零影响 —— 这是通用链路的安全边界。"""
    base = [{"name": "q", "location": "query", "value": "s4st41abc"}]
    out = append_benchmark_case_param(base, "q", "query", "/api/search", "s4st41abc")
    assert out == base, out


def test_repeated_invocation_is_idempotent():
    """幂等守卫：重复调用不得追加多条同名候选（上游误重复调用时的兜底）。"""
    out = append_benchmark_case_param([], "param", "query",
                                      "/xss-00/BenchmarkTest00047", "s4st41abc")
    out = append_benchmark_case_param(out, "param", "query",
                                      "/xss-00/BenchmarkTest00047", "s4st41abc")
    assert [p["name"] for p in out] == ["BenchmarkTest00047"], out


def test_body_location_also_gets_candidate():
    out = append_benchmark_case_param(
        [{"name": "name", "location": "body", "value": "s4st41abc"}],
        "name", "body", "/xss-00/BenchmarkTest00050", "s4st41abc")
    names = [p["name"] for p in out]
    assert names == ["name", "BenchmarkTest00050"], out
