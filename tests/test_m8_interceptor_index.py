"""M8 拦截器挖掘（正向全局索引）测试（2026-10-03）。

核心断言是 M8 的硬要求：**Filter 必须按 urlPatterns 匹配后才参与求交**。
把 /admin 下的过滤算到 /public 路由上，会凭空判死漏洞——所以这条比"能扫出来"更重要。

另外两条实测踩出来的坑也各有守卫：
  1. addPathPatterns 写在 WebMvcConfigurer 配置类里，不在拦截器自己的类里。
     只在拦截器类里找 → 路径恒空 → 该拦截器被误判成 global，对所有路由都生效。
  2. addPathPatterns 用 Spring Ant 的 `/admin/**`，不是 servlet 的 `/admin/*`。
     只实现 servlet 语义 → `/admin/**` 退化成精确匹配 → 永不生效 → 约束被漏算。
"""
from src.core import interceptor_index as ix

_FILTER_JAVA = '''
@WebFilter(urlPatterns = {"/api/*"})
public class SqlFilter implements Filter {
  public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
      String v = req.getParameter("q");
      if (v.contains("<script>")) { resp.getWriter().write("bad"); return; }
      chain.doFilter(req, resp);
  }
}
'''

_INTERCEPTOR_JAVA = '''
public class AuthInterceptor implements HandlerInterceptor {
  public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object h) {
      String role = req.getParameter("role");
      if (role.equals("admin")) return false;
      return true;
  }
}
'''

_REG_JAVA = '''
public class WebCfg implements WebMvcConfigurer {
  public void addInterceptors(InterceptorRegistry r) {
     r.addInterceptor(new AuthInterceptor()).addPathPatterns("/admin/**");
  }
}
'''

_ASPECT_JAVA = '''
@Aspect
@Component
public class XssGuard {
  @Before("execution(* com.demo.web..*.*(..))")
  public void guard(String p) {
      if (p.contains("'")) { throw new RuntimeException("bad"); }
  }
}
'''


def _files(*pairs):
    return [{"path": p, "language": "java", "content": c} for p, c in pairs]


def test_filter_is_indexed_with_url_patterns():
    idx = ix.collect_interceptors(_files(("SqlFilter.java", _FILTER_JAVA)))
    assert len(idx) == 1
    it = idx[0]
    assert it["kind"] == ix.KIND_FILTER
    assert it["path_patterns"] == ["/api/*"]
    assert it["path_source"] == "annotation"
    assert it["filter_spec"]["kind"] == "deny"


def test_filter_only_applies_to_matched_routes():
    """M8 硬要求：urlPatterns 不匹配的路由，Filter 不参与求交。"""
    idx = ix.collect_interceptors(_files(("SqlFilter.java", _FILTER_JAVA)))
    it = idx[0]
    assert ix.applies_to_route(it, "/api/x") is True
    assert ix.applies_to_route(it, "/public/x") is False
    assert ix.applies_to_route(it, "/admin/x") is False


def test_interceptor_paths_come_from_registration_in_other_file():
    """注册语句在 WebMvcConfigurer 里 —— 必须在全库范围找，不能只看拦截器自己的类。"""
    idx = ix.collect_interceptors(_files(
        ("AuthInterceptor.java", _INTERCEPTOR_JAVA),
        ("WebCfg.java", _REG_JAVA)))
    it = [x for x in idx if x["kind"] == ix.KIND_INTERCEPTOR][0]
    assert it["path_patterns"] == ["/admin/**"]
    assert it["path_source"] == "registration"
    # 对 /public 不生效（若这里错判生效，会凭空判死 /public 上的漏洞）
    assert ix.applies_to_route(it, "/admin/y") is True
    assert ix.applies_to_route(it, "/public/y") is False


def test_spring_ant_double_star_is_understood():
    """addPathPatterns 是 Spring Ant 语义，`/admin/**` 跨层级，不是精确匹配。"""
    assert ix.path_matches("/admin/**", "/admin/y") is True
    assert ix.path_matches("/admin/**", "/admin/a/b") is True
    assert ix.path_matches("/admin/**", "/admin") is True
    assert ix.path_matches("/admin/**", "/public/y") is False
    # servlet 语义仍要成立
    assert ix.path_matches("/api/*", "/api/x") is True
    assert ix.path_matches("/api/*", "/other") is False
    assert ix.path_matches("/*", "/anything") is True


def test_unregistered_interceptor_is_global_but_flagged():
    """没有注册信息的拦截器按全局生效处理（fail-open），但 path_source 要写明。"""
    idx = ix.collect_interceptors(_files(("AuthInterceptor.java", _INTERCEPTOR_JAVA)))
    it = idx[0]
    assert it["path_patterns"] == []
    assert it["path_source"] == "global"
    assert ix.applies_to_route(it, "/anything") is True


def test_aspect_is_indexed():
    idx = ix.collect_interceptors(_files(("XssGuard.java", _ASPECT_JAVA)))
    assert any(x["kind"] == ix.KIND_ASPECT for x in idx)


def test_non_sanitizing_interceptor_is_not_indexed():
    """只做鉴权不做净化的拦截器不进索引 —— 空约束进索引只会污染求交。"""
    files = _files(("AuthOnly.java", '''
    public class AuthOnly implements HandlerInterceptor {
      public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object o) {
          return req.getSession() != null;
      }
    }
    '''))
    assert ix.collect_interceptors(files) == []


def test_intersect_merges_dataflow_and_interceptor_specs():
    """数据流侧净化器 + 全局索引命中的拦截器，一起送 intersect 求交。"""
    from src.core.sanitizer_miner import FilterSpec
    idx = ix.collect_interceptors(_files(("SqlFilter.java", _FILTER_JAVA)))
    dataflow = FilterSpec(FilterSpec.KIND_DENY, tokens=["--"])
    merged, prov = ix.intersect_for_route(idx, "/api/x", [dataflow])
    assert merged is not None and merged.is_known()
    assert "--" in merged.tokens and "<script>" in merged.tokens
    assert len(prov) == 2


def test_intersect_excludes_interceptor_for_other_route():
    """路由不匹配时，拦截器约束不得进入求交（数据流侧约束仍保留）。"""
    from src.core.sanitizer_miner import FilterSpec
    idx = ix.collect_interceptors(_files(("SqlFilter.java", _FILTER_JAVA)))
    dataflow = FilterSpec(FilterSpec.KIND_DENY, tokens=["--"])
    merged, prov = ix.intersect_for_route(idx, "/public/x", [dataflow])
    assert merged is not None
    assert "<script>" not in merged.tokens
    assert merged.tokens == ["--"]
    assert len(prov) == 1


def test_provenance_carries_source_for_audit():
    """判「不可绕过」时要能说出是哪个拦截器按哪条 urlPattern 拦的。"""
    idx = ix.collect_interceptors(_files(("SqlFilter.java", _FILTER_JAVA)))
    specs = ix.filter_specs_for_route(idx, "/api/x")
    assert len(specs) == 1
    assert "SqlFilter" in specs[0].source
    assert "/api/*" in (specs[0].note or "")
