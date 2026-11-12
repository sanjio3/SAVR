"""拦截器/过滤器/切面的正向全局索引。

背景（为什么从「反向数据流」改成「正向全局索引」）：
    原先的净化器挖掘是**反向**的：沿着污点数据流回溯（source → sink），只在数据流经过的
    代码里找净化调用。缺陷有三：
      1. 漏：净化发生在**数据流之外**的位置就找不到 —— 比如 HandlerInterceptor 的
         preHandle、Servlet Filter 的 doFilter、@Aspect 通知，这些都在 MVC 链上、在
         「参数 → sink」这条数据流之外，但它们确实对请求做了净化/拦截。
      2. 每条 spec 各扫一遍，重复劳动，且不同 spec 对同一拦截器可能给出不同结论
         （扫到多少取决于那条 spec 恰好经过哪些代码）。
      3. 无法审计：判「不可绕过」时说不清是哪个拦截器拦的。

    正向索引的做法：启动时把整个代码库里三类**全局生效点**扫一遍建索引，之后每条 spec
    判定时按路由取出生效的拦截器，与数据流侧挖到的净化器一起送
    ``mechanism_library.intersect`` 求交。好处是：全量只扫一次、每条 spec 结论一致、
    结论带拦截器来源可审计。

三类生效点与路由匹配口径：
    1. HandlerInterceptor.preHandle        —— WebMvcConfigurer 注册时通常 addPathPatterns，
                                             未注册路径 = 全局生效（fail-open 记来源）。
    2. javax.servlet.Filter / OncePerRequestFilter —— **必须按 urlPatterns 匹配后才参与
       求交**，否则会把 /admin 下的过滤算到 /public 路由上，凭空判死漏洞（这条是硬要求，
       不是优化）。@WebFilter(urlPatterns=...) 与 FilterRegistrationBean(urlPatterns=...)
       两种登记方式都认。
    3. @Aspect 通知（@Before/@Around/@Pointcut）—— 带切点表达式时按 @Pointcut 里的路径
       模式匹配；不带路径（如 ``@Before("execution(* com.x..*.*(..))")``）视为全局生效。

设计红线：
    1. **不确定就 fail-open**：匹配不上的、语法认不出的，都记为「不参与求交」并留来源，
       绝不用「可能生效」去判不可绕过。判死漏洞的代价高于漏判。
    2. 索引是**只读快照**，进程内构建一次即复用；不随 spec 变动（全局生效点不随 spec 变）。
    3. 每个 InterceptorSpec 都要带 ``path_patterns``，让对账能回答「这条结论是哪个拦截器
       按哪条 urlPattern 算出来的」。
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 三类生效点的 kind
KIND_INTERCEPTOR = "interceptor"   # HandlerInterceptor.preHandle
KIND_FILTER = "filter"             # javax.servlet.Filter.doFilter
KIND_ASPECT = "aspect"             # @Aspect 通知

# ── 类/方法识别 ──
_RE_INTERCEPTOR_CLS = re.compile(
    r"\bclass\s+(\w+)[^{]*\{", re.MULTILINE)
_RE_IMPL_INTERCEPTOR = re.compile(
    r"\bimplements\s+[^{]*\bHandlerInterceptor\b|\bextends\s+HandlerInterceptorAdapter\b")
_RE_IMPL_FILTER = re.compile(
    r"\bimplements\s+[^{]*\b(javax\.servlet\.)?Filter\b|\bextends\s+(OncePerRequestFilter|GenericFilterBean)\b")
_RE_ASPECT_CLS = re.compile(r"@Aspect\b")
_RE_WEBFILTER = re.compile(
    r"@WebFilter\s*\(\s*(?:value|urlPatterns)\s*=\s*\{?\s*([^)]*?)\}?\s*\)", re.DOTALL)
_RE_FILTER_REG = re.compile(
    r"FilterRegistrationBean[^;]{0,400}?setUrlPatterns\s*\(\s*([^)]*?)\)", re.DOTALL)
_RE_ADD_INTERCEPTOR = re.compile(
    r"addInterceptor\s*\(\s*new\s+(\w+)\s*\([^)]*\)\s*\)"
    r"(?:\s*\.\s*addPathPatterns\s*\(\s*([^)]*?)\s*\))?",
    re.DOTALL)
_RE_ADD_PATH_PATTERNS = re.compile(
    r"addPathPatterns\s*\(\s*([^)]*?)\)", re.DOTALL)
_RE_PREHANDLE = re.compile(
    r"\b(?:public|protected)\s+boolean\s+preHandle\s*\([^)]*\)\s*\{", re.MULTILINE)
_RE_DOFILTER = re.compile(
    r"\b(?:public|protected)\s+void\s+doFilter\s*\([^)]*\)\s*\{", re.MULTILINE)
_RE_ADVICE = re.compile(
    r"@(Before|Around|After|AfterReturning|AfterThrowing)\s*\(\s*([^)]*?)\)\s*",
    re.DOTALL)
_RE_POINTCUT_PATH = re.compile(
    r"@Pointcut\s*\(\s*(?:value\s*=\s*)?\"([^\"]*)\"")
_RE_PATH_IN_EXPR = re.compile(r"/[A-Za-z0-9_\-*/]+")


def _java_files(files: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for f in files or []:
        p = str(f.get("path") or f.get("file_path") or "")
        lang = str(f.get("language") or "").lower()
        if lang == "java" or p.rsplit(".", 1)[-1].lower() in ("java", "kt", "scala"):
            out.append(f)
    return out


def _split_methods(content: str, decl_re: re.Pattern) -> List[str]:
    """按方法声明正则切出各方法的方法体（大括号配平，字符串内的括号不算）。

    不用完整 Java 解析器：拦截器方法体都很短，且我们要的只是「这段代码里有没有净化」，
    精确到注释/字符串的边界差异不影响结论（判定本身还有 simulate_filter 兜底）。
    """
    out: List[str] = []
    for m in decl_re.finditer(content or ""):
        start = content.find("{", m.end() - 1)
        if start < 0:
            continue
        depth = 0
        i = start
        n = len(content)
        while i < n:
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append(content[start:i + 1] if i > start else content[m.start():i])
    return out


def _class_body_for(content: str, header_match: re.Match) -> str:
    """取某个 class 声明之后的大括号体（用于把注解/方法限定在该类内）。"""
    start = content.find("{", header_match.end() - 1)
    if start < 0:
        return ""
    depth = 0
    i = start
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start:i + 1]
        i += 1
    return content[start:]


def _str_list(raw: str) -> List[str]:
    """从 ``"/a/*", "/b"`` 这种源码字面量片段里取出字符串项。"""
    return [m.group(1) for m in re.finditer(r'"([^"]*)"', raw or "") if m.group(1).strip()]


def _to_filter_spec(body: str, source: str):
    """把方法体交给既有净化器抽取器（单一真相源：sanitizer_miner.extract_filter_spec）。"""
    try:
        from src.core.sanitizer_miner import extract_filter_spec
    except Exception as exc:
        logger.debug("[interceptor-index] 无法导入 extract_filter_spec：%s", exc)
        return None
    try:
        return extract_filter_spec(body or "")
    except Exception as exc:
        logger.debug("[interceptor-index] extract_filter_spec 抛错（跳过该生效点）：%s", exc)
        return None


def _make(kind: str, spec, path_patterns: List[str], evidence: str,
          path_source: str) -> Optional[Dict[str, Any]]:
    """统一构造索引条目。判不出净化规则的（spec 非 known）直接丢，不进索引。"""
    if spec is None or not spec.is_known():
        return None
    return {
        "kind": kind,
        "path_patterns": list(path_patterns or []),
        "path_source": path_source,   # annotation / registration / global / pointcut
        "filter_spec": spec.to_dict(),
        "evidence": (evidence or "")[:400],
    }


def collect_interceptors(files: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """扫全代码库建拦截器/过滤器/切面的正向索引。返回索引条目列表。"""
    jf = _java_files(files)
    # 先建「拦截器类名 → 注册路径」映射：注册语句写在 WebMvcConfigurer 配置类里，
    # 不在拦截器自己的类里（实测踩过：只看拦截器类 → addPathPatterns("/admin/**")
    # 永远找不到 → 该拦截器被误判成 global，对所有路由都参与求交，凭空判死 /public 的漏洞）。
    reg_map = _interceptor_registrations(jf)
    out: List[Dict[str, Any]] = []
    for f in jf:
        content = f.get("content") or ""
        path = str(f.get("path") or f.get("file_path") or "")
        if not content:
            continue

        # ① HandlerInterceptor
        for cm in _RE_INTERCEPTOR_CLS.finditer(content):
            header_start = max(0, cm.start() - 400)
            content[header_start:cm.end()]
            if not _RE_IMPL_INTERCEPTOR.search(content[header_start:cm.end() + 200]):
                continue
            body = _class_body_for(content, cm)
            for mb in _split_methods(body, _RE_PREHANDLE):
                spec = _to_filter_spec(mb, "interceptor")
                pats, src = _interceptor_paths(reg_map, cm.group(1), content)
                item = _make(KIND_INTERCEPTOR, spec, pats, "%s:%s" % (path, cm.group(1)), src)
                if item:
                    item["class"] = cm.group(1)
                    item["file"] = path
                    out.append(item)

        # ② Servlet Filter
        for cm in _RE_INTERCEPTOR_CLS.finditer(content):
            region = content[max(0, cm.start() - 600): cm.end() + 400]
            if not _RE_IMPL_FILTER.search(region):
                continue
            body = _class_body_for(content, cm)
            for mb in _split_methods(body, _RE_DOFILTER):
                spec = _to_filter_spec(mb, "filter")
                pats, src = _filter_paths(content, cm, path)
                item = _make(KIND_FILTER, spec, pats, "%s:%s" % (path, cm.group(1)), src)
                if item:
                    item["class"] = cm.group(1)
                    item["file"] = path
                    out.append(item)

        # ③ @Aspect 通知
        if _RE_ASPECT_CLS.search(content):
            for cm in _RE_INTERCEPTOR_CLS.finditer(content):
                body = _class_body_for(content, cm)
                for am in _RE_ADVICE.finditer(body):
                    expr = am.group(2) or ""
                    spec = _to_filter_spec(body, "aspect")
                    pats, src = _aspect_paths(expr, body)
                    item = _make(KIND_ASPECT, spec, pats,
                                 "%s:%s@%s" % (path, cm.group(1), am.group(1)), src)
                    if item:
                        item["class"] = cm.group(1)
                        item["file"] = path
                        item["advice"] = am.group(1)
                        out.append(item)
    return out


def _interceptor_registrations(jf: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """扫全库建 {拦截器类名: 注册路径列表}。

    ``r.addInterceptor(new AuthInterceptor).addPathPatterns("/admin/**")`` 与
    ``r.addInterceptor(new AuthInterceptor)``（无 addPathPatterns = 全局）都要认。
    """
    out: Dict[str, List[str]] = {}
    for f in jf:
        content = f.get("content") or ""
        for m in _RE_ADD_INTERCEPTOR.finditer(content or ""):
            name = m.group(1)
            pats = _str_list(m.group(2) or "")
            if pats:
                out.setdefault(name, [])
                for p in pats:
                    if p not in out[name]:
                        out[name].append(p)
            else:
                out.setdefault(name, [])   # 显式注册但没给路径 = 全局，存空列表
    return out


def _interceptor_paths(reg_map: Dict[str, List[str]], class_name: str,
                       content: str) -> Tuple[List[str], str]:
    """HandlerInterceptor 的生效路径：优先取全库注册表里的 addPathPatterns。

    注册表命中即按注册路径判；注册表里显式存了空列表（注册了但没给路径）→ global；
    完全没注册（如直接 new 出来没用、或由第三方 starter 注册）→ 退回在本类里找
    addPathPatterns，再没有才 global（fail-open，理由见模块头红线 1）。
    """
    name = str(class_name or "")
    if name and name in reg_map:
        pats = reg_map[name]
        return (pats, "registration") if pats else ([], "global")
    m = _RE_ADD_PATH_PATTERNS.search(content or "")
    if m:
        pats = _str_list(m.group(1))
        if pats:
            return pats, "registration"
    return [], "global"


def _filter_paths(content: str, cls_match: re.Match, file_path: str) -> Tuple[List[str], str]:
    """Filter 的生效路径：@WebFilter(urlPatterns=...) 或 FilterRegistrationBean。

    认不到路径时**返回空 + global**（fail-open，理由见模块头红线 1）。
    """
    m = _RE_WEBFILTER.search(content or "")
    if m:
        pats = _str_list(m.group(1))
        if pats:
            return pats, "annotation"
    m2 = _RE_FILTER_REG.search(content or "")
    if m2:
        pats = _str_list(m2.group(1))
        if pats:
            return pats, "registration"
    return [], "global"


def _aspect_paths(expr: str, body: str) -> Tuple[List[str], str]:
    """@Aspect 通知的生效路径：通知表达式或 @Pointcut 里的路径模式。

    切点是 ``execution(* com.x..*.*(..))`` 这种纯方法匹配时，取不出路径 → 视为全局生效。
    """
    pools = [expr or "", body or ""]
    for pool in pools:
        m = _RE_POINTCUT_PATH.search(pool)
        if m:
            raw = (m.group(1) or "")
            pats = _str_list(raw) or _RE_PATH_IN_EXPR.findall(raw)
            if pats:
                return pats, "pointcut"
    for pool in pools:
        pats = _RE_PATH_IN_EXPR.findall(pool or "")
        if pats:
            return pats, "pointcut"
    return [], "global"


# ── 路由匹配（servlet urlPatterns 语义 + Spring Ant 语义）─────────────────
def path_matches(pattern: str, route: str) -> bool:
    """路径模式匹配，同时认 servlet urlPattern 与 Spring Ant 两套语义。

    两套都收，是因为登记方式不同：Filter 走 ``@WebFilter(urlPatterns=...)``（servlet 语义），
    而 ``addPathPatterns("/admin/**")`` 是 Spring Ant 语义（``**`` 跨层级、``*`` 单层级）。
    历史上只实现 servlet 语义时，``/admin/**`` 会退化成精确匹配 ``/admin/**`` 字符串，
    结果是**永不生效** → 约束被漏算。

    认不出的 pattern 判 **不匹配**（fail-closed 于「这条约束生效」这个方向）——
    因为误判生效会凭空判死漏洞，而漏判只是少一条约束。
    """
    p = str(pattern or "").strip()
    r = str(route or "").strip()
    if not p:
        return False
    if p in ("/*", "/*/*", "*", "/**", "**"):
        return True
    if p == "/":
        return r.startswith("/")
    if "**" in p:
        # Spring Ant：/admin/** 匹配 /admin 及其任意层级子路径
        prefix = p[:p.index("**")].rstrip("/")
        if not prefix:
            return True
        return r == prefix or r.startswith(prefix + "/")
    if p.endswith("/*"):
        prefix = p[:-2]
        if r == prefix or r.startswith(prefix + "/"):
            return True
        # /admin/* 只跨单层级；再深（/admin/a/b）只在 Ant 语义下由上面的 ** 分支覆盖，
        # 这里保持 servlet 语义（单层）判定即可，不额外放宽。
        return False
    return p == r


def applies_to_route(item: Dict[str, Any], route: str) -> bool:
    """该索引条目对本路由是否生效。

    path_source=global（全局生效点：addPathPatterns 没配、@Aspect 切点无路径、
    Filter 认不到登记）→ 恒生效。
    有 path_patterns → 必须有一条匹配上，否则**不参与求交**（M8 的硬要求：
    把 /admin 下的过滤算到 /public 上会凭空判死漏洞）。
    """
    pats = item.get("path_patterns") or []
    if not pats:
        return str(item.get("path_source") or "") == "global"
    return any(path_matches(p, route) for p in pats)


# ── 生产侧：按 code_root 建索引（带进程内缓存）──────────────────────────
# 全局生效点不随 spec 变，同一个 code_root 只扫一次即可。
# 缓存 key 用 code_root 绝对路径；目录内容变了不自动失效（那属于重新扫描的范畴，
# 跨轮复用同一 workspace 源码时内容本来就不变）。
_INDEX_CACHE: Dict[str, List[Dict[str, Any]]] = {}

# 是少数派，且都集中在 web/config 层。这里按「先扫全量、超上限按修改时间取最近」处理，
# 保证不会因为上限把 web 层排除在外（web 层通常是最近改动的）。
_INDEX_MAX_FILES = 4000


def _java_source_files(code_root: str, max_files: int = _INDEX_MAX_FILES) -> List[Dict[str, Any]]:
    import os
    root = str(code_root or "")
    if not root or not os.path.isdir(root):
        return []
    paths: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # 排除构建产物与 CodeQL 库（含源码副本，会让文件数精确翻倍）
        dirnames[:] = [d for d in dirnames
                       if d not in ("target", "build", "node_modules", ".git")
                       and not d.startswith(".codeql-db")]
        for fn in filenames:
            if fn.endswith((".java", ".kt", ".scala")):
                paths.append(os.path.join(dirpath, fn))
    if len(paths) > max_files:
        try:
            paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        except Exception:
            pass
        paths = paths[:max_files]
    out: List[Dict[str, Any]] = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception:
            continue
        if not content:
            continue
        out.append({"path": p, "language": "java", "content": content})
    return out


def build_index(code_root: str, refresh: bool = False) -> List[Dict[str, Any]]:
    """按 code_root 建拦截器索引（进程内缓存，同 root 只扫一次）。"""
    root = str(code_root or "").strip()
    if not root:
        return []
    if not refresh and root in _INDEX_CACHE:
        return _INDEX_CACHE[root]
    try:
        idx = collect_interceptors(_java_source_files(root))
    except Exception as exc:
        logger.warning("[interceptor-index] 建索引失败（fail-open，按无拦截器约束处理）：%s", exc)
        idx = []
    _INDEX_CACHE[root] = idx
    logger.info("[interceptor-index] %s 建索引：%d 条全局生效点（%s）",
                root, len(idx), ", ".join(sorted({i["kind"] for i in idx})) or "none")
    return idx


def index_stats(index: List[Dict[str, Any]]) -> Dict[str, Any]:
    """索引概览（挂 raw 供对账：能回答「本轮判不可绕过时，全局生效点扫到了几个」）。"""
    by_kind: Dict[str, int] = {}
    for it in index or []:
        by_kind[str(it.get("kind"))] = by_kind.get(str(it.get("kind")), 0) + 1
    return {"total": len(index or []), "by_kind": by_kind,
            "classes": sorted({str(it.get("class") or "") for it in (index or []) if it.get("class")})}


def filter_specs_for_route(index: List[Dict[str, Any]], route: str) -> List[Any]:
    """取出对指定路由生效的 FilterSpec 对象（交给 intersect 求交）。"""
    from src.core.sanitizer_miner import FilterSpec as _FS
    out = []
    for item in index or []:
        if not applies_to_route(item, route):
            continue
        spec = _FS.from_dict(item.get("filter_spec"))
        if spec is None or not spec.is_known():
            continue
        # 留来源：判「不可绕过」时能说出是哪个拦截器按哪条 urlPattern 拦的
        spec.source = "%s/%s(%s)" % (item.get("kind"), item.get("class") or "?",
                                     item.get("path_source") or "global")
        spec.note = (spec.note or "") + " [path_patterns=%s]" % (
            ",".join(item.get("path_patterns") or []) or "global")
        out.append(spec)
    return out


def intersect_for_route(index: List[Dict[str, Any]], route: str,
                        dataflow_specs: Optional[List[Any]] = None):
    """把「全局索引命中的拦截器约束」与「数据流侧挖到的净化器约束」一起求交。

    返回 (merged_spec, provenance)：merged_spec 可能为 None（无任何已知约束），
    provenance 是每条约束的来源列表，供审计与报告引用。
    """
    try:
        from src.core.mechanism_library import intersect as _intersect
    except Exception as exc:
        logger.warning("[interceptor-index] 机制库不可用，拦截器约束不参与求交：%s", exc)
        return None, []
    specs = list(dataflow_specs or []) + filter_specs_for_route(index, route)
    provenance = [
        {"kind": "interceptor", "source": getattr(s, "source", "?"),
         "note": getattr(s, "note", "")}
        for s in specs
    ]
    try:
        merged = _intersect(specs)
    except Exception as exc:
        logger.warning("[interceptor-index] 约束求交抛错（fail-open，按无约束处理）：%s", exc)
        return None, provenance
    return merged, provenance
