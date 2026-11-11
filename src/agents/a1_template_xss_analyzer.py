"""模板层 XSS 跨文件静态分析（块4 #17/#18：Thymeleaf th:utext 非转义输出）。

反射型 / 存储型 XSS 的 sink 常常不在 Java 里，而在 Thymeleaf 模板的 ``th:utext`` 上。
Java 侧只看到 ``model.addAttribute("keyword", keyword)``，看不到它最终有没有被 HTML 转义；
模板侧只看到 ``th:utext="${keyword}"``，看不到值从哪来。单看任何一侧都判不出来，必须跨文件关联。

此前 ``scanner.py`` 的 ``LANGUAGE_EXTENSIONS`` 不含 ``.html``，模板从不进扫描集，
``java_rules.yaml`` 里写了 ``th:utext`` pattern 的 SSTI004/SSTI005 也永不命中。
现已放开模板组 + 内容闸门（见 scanner.py），并新增 ``src/core/template_taint.py`` 抽取模板侧 sink。

本分析器负责 **Java 侧的四元组关联**：
- 抽取每个 Controller 方法的四元组（路由 / 视图名 / model key / 入参）；
- 视图名 → 模板文件（Thymeleaf 前缀后缀解析，见 template_taint.view_name_to_template_rel）；
- 模板侧 sink 的 ``model_key`` 与 Controller 的 ``model key`` 比对（root_var == model_key）；
- 反射型 = 入参直传（model key 的 source 是 @RequestParam，且无 DB 写入）；
- 存储型 = 实体字段且存在写接口（全局扫描 POST 方法 + 表单字段，命中同名字段且确实落库）；
- 产物写成 A1 findings（族 xss，细分 reflected/stored），**由 A1 确定性检出，不依赖 A2 LLM 发现**。

口径对齐 ``a1_vertical_privesc_analyzer.py``：产出与业务逻假说同形状的 dict，
由 ``A1PipelineService.merge_template_xss_findings`` 转成 ``Vulnerability`` 并入 A1 findings。
因 xss 属注入族（exploit_spec._INJECTION_FAMILIES），并入时 **不** 标 business_logic=True，
走注入族链路（A2 绑定 entry.route → D2 验证）。

定位：注入类离线确定性兜底的一部分（IS_PRIMARY_PATH=False）；CodeQL 主链路不覆盖模板层，
故本分析器是唯一能稳定检出模板层 XSS 的来源。
"""
# 模板层 XSS 跨文件确定性兜底：Controller 四元组 × 视图名→模板映射 × root_var==model_key 关联。
IS_PRIMARY_PATH = False

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.agents._bl_common import scan_spring_endpoints
from src.core.template_taint import (
    parse_templates,
    resolve_thymeleaf_config,
    view_name_to_template_rel,
)

logger = logging.getLogger(__name__)

# model.addAttribute("key", expr) / model.addObject("key", expr)
_MODEL_ADD_RE = re.compile(
    r"\bmodel\.\w*[Aa]dd(?:Attribute|Object)\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*(.+?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
# return "viewname";
_RETURN_VIEW_RE = re.compile(r"return\s+[\"']([^\"']+)[\"']\s*;", re.IGNORECASE)
# @RequestParam(...) Type name / @PathVariable(...) Type name / @RequestParam Map<String,String> params
# 单一捕获组：只取参数名。参数名是注解后、紧邻 `,` / `)` / `=` 的最后一个标识符。
# 注意：类型部分（如 Map<String,String>）可能含逗号，故不能把逗号放进类型字符类后用「贪婪」吞掉参数名；
# 这里用最小匹配 .*? 定位到「注解之后、首个 ,/) /= 之前的标识符」即为参数名。
_REQ_PARAM_RE = re.compile(
    r"@(?:RequestParam|PathVariable)(?:\([^)]*\))?\s+.*?(\b\w+)\s*(?:[,)=])"
)
# 表单 action + 输入字段名（用于把模板表单字段关联到写接口）
_FORM_RE = re.compile(r"<form\b[^>]*\baction=[\"']([^\"']+)[\"']", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"\bmethod=[\"']([^\"']+)[\"']", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"\bname=[\"']([^\"']+)[\"']", re.IGNORECASE)
_FORM_CLOSE_RE = re.compile(r"</form>", re.IGNORECASE)
# DB 落库信号（判定 POST 方法是否真的持久化，避免把纯查询/转发当成写接口）
_DB_WRITE_TOKENS = (
    "insert", "update", "save", "delete", "mapper", "repository",
    "setpropertvalue", "beanwrapper", "writedb", "persist",
)
_POST_METHODS = {"POST", "PUT", "PATCH"}


def _java_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for f in files or []:
        p = str(f.get("path") or f.get("file_path") or "")
        lang = str(f.get("language") or "").lower()
        if lang == "java" or p.rsplit(".", 1)[-1].lower() in ("java", "kt", "scala"):
            out.append(f)
    return out


def _template_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for f in files or []:
        p = str(f.get("path") or f.get("file_path") or "")
        lang = str(f.get("language") or "").lower()
        if lang == "template" or p.rsplit(".", 1)[-1].lower() in ("html", "htm", "ftl", "vm"):
            out.append(f)
    return out


def _extract_model_keys(block: str) -> Dict[str, str]:
    """方法体内 model.addAttribute("key", expr) → {key: source_expr}。"""
    out: Dict[str, str] = {}
    for m in _MODEL_ADD_RE.finditer(block or ""):
        key = m.group(1)
        src = (m.group(2) or "").strip()
        if src.endswith(";"):
            src = src[:-1].strip()
        out.setdefault(key, src)
    return out


def _extract_return_view(block: str) -> str:
    m = _RETURN_VIEW_RE.search(block or "")
    return m.group(1) if m else ""


def _field_of(root_var: str, expr: str) -> Optional[str]:
    """从 sink 表达式推字段名。${user.signature} → signature；${keyword} → None（反射直传）。"""
    inner = (expr or "").strip()
    if inner.startswith("${") and inner.endswith("}"):
        inner = inner[2:-1].strip()
    elif inner.startswith("[(") and inner.endswith(")]"):
        inner = inner[2:-1].strip()
        if inner.startswith("$"):
            inner = inner[1:]
    if not inner:
        return None
    if inner == root_var:
        return None
    if inner.startswith(root_var + "."):
        return inner[len(root_var) + 1:].split(".")[0].split("[")[0]
    # 退化：整个表达式是 root_var（如 ${keyword}）→ 反射
    return None


def _reflected_param(block: str, model_keys: Dict[str, str], mk: str) -> str:
    """反射型：model key 的 source 是 @RequestParam 名，或存在同名 @RequestParam。"""
    source = (model_keys.get(mk) or "").strip()
    params = set(_REQ_PARAM_RE.findall(block or ""))
    if source and source in params:
        return source
    if mk in params:
        return mk
    return ""


def _parse_form_fields(templates: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """模板表单 → {endpoint_path: {field_name, ...}}（仅取 POST 表单）。"""
    out: Dict[str, Set[str]] = {}
    for t in templates:
        content = t.get("content") or ""
        for fm in _FORM_RE.finditer(content):
            action = (fm.group(1) or "").strip()
            low = action.lower()
            if low.startswith(("redirect:", "forward:")):
                continue
            # 取该 form 块内的字段名
            start = fm.end()
            end = _FORM_CLOSE_RE.search(content, start)
            end_pos = end.start() if end else min(start + 4000, len(content))
            seg = content[start:end_pos]
            method_m = _FORM_METHOD_RE.search(content[fm.start():start])
            method = (method_m.group(1) if method_m else "get").upper()
            if method not in _POST_METHODS:
                continue
            fields = {g for g in _INPUT_NAME_RE.findall(seg)}
            out.setdefault(action, set()).update(fields)
    return out


def _collect_write_endpoints(java_files: List[Dict[str, Any]],
                             form_fields: Dict[str, Set[str]]) -> List[Dict[str, Any]]:
    """收集所有会落库的写接口：{route, method, fields:set, db_write:bool}。

    字段来源 = Java @RequestParam/@PathVariable 名 ∪ 模板表单字段（关联同 action 的 POST 表单）。
    仅当方法体含 DB 落库信号（insert/update/mapper/BeanWrapper…）才视为真写接口。
    """
    eps: List[Dict[str, Any]] = []
    for f in java_files:
        content = f.get("content") or ""
        for route, http_method, block, mname, line in scan_spring_endpoints(content):
            if http_method not in _POST_METHODS:
                continue
            low = (block or "").lower()
            db_write = any(tok in low for tok in _DB_WRITE_TOKENS)
            if not db_write:
                continue
            fields: Set[str] = set(_REQ_PARAM_RE.findall(block or ""))
            fields.update(form_fields.get(route, set()))
            if not fields:
                continue
            eps.append({
                "route": route,
                "method": http_method,
                "fields": fields,
                "db_write": True,
            })
    return eps


def _match_write_endpoint(write_eps: List[Dict[str, Any]], field: str) -> Optional[str]:
    """为存储型字段找写接口路由（优先 POST）。"""
    candidates = [e for e in write_eps if field in e["fields"] and e["db_write"]]
    if not candidates:
        return None
    for e in candidates:
        if e["method"] == "POST":
            return e["route"]
    return candidates[0]["route"]


# ── M7：读接口判定（写接口判定的对称面，两步重放第一步写进去、第二步要读回来）──
_DB_READ_TOKENS = (
    "select", "query", "getbyid", "getone", "findby", "mapper", "repository",
    "jdbctemplate", "hibernate", "entitymanager", "dao", "findall", "getby",
    "sqlsession",
)


def _collect_read_endpoints(java_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """收集所有会对外读出实体字段的 GET 端点：{route, method, fields:set}。

    与 _collect_write_endpoints 严格对称：
      写端 = GET/POST/PUT/PATCH + **库写信号**（insert/update/save/mapper…）
      读端 = GET + **库读信号**（select/query/getById/findBy/mapper…）
    必须同时满足「读库信号」+「方法体里带出该字段」，否则 /login、/error 这类
    纯页面端点会被全算成读端点（标记反查时要真发请求，算多了会烧预算）。
    """
    eps: List[Dict[str, Any]] = []
    for f in java_files:
        content = f.get("content") or ""
        for route, http_method, block, mname, line in scan_spring_endpoints(content):
            if str(http_method or "").upper() != "GET":
                continue
            low = (block or "").lower()
            if not any(tok in low for tok in _DB_READ_TOKENS):
                continue
            fields: Set[str] = set(_REQ_PARAM_RE.findall(block or ""))
            for m in _MODEL_ADD_RE.finditer(block or ""):
                fields.add(m.group(1))
            if not fields:
                continue
            eps.append({
                "route": route,
                "method": "GET",
                "fields": fields,
                "db_read": True,
                "function": mname or "",
                "line": line,
            })
    return eps


def _match_read_endpoint(read_eps: List[Dict[str, Any]], field: str,
                         write_route: str = "",
                         aliases: Optional[Set[str]] = None) -> Optional[str]:
    """为存储型字段找读接口路由（M7 两级定位里的第一级：静态）。

    先试「写路由同路径的 GET」（写 /comment 就读 GET /comment，零成本且命中不少），
    再退回按字段匹配。注意不把 /comments 这类集合路由当同路径——那不是长页，
    标记反查扫它纯属白跑一趟。

    **aliases 为什么必须传**：
      读接口侧登记的是 model key（``model.addAttribute("content", o)`` 里的 content），
      写接口侧登记的是模板表达式里的实体字段（``${content.signature}`` 里的 signature）。
      两者不在同一个命名空间，只按字段名匹配时**永远对不上**——静态定位会恒为空，
      两条兜底（LLM / 标记反查）全白搭，存储型只读侧永远拿不到回显证据。
      所以匹配集 = {实体字段} ∪ {model key} ∪ {root_var}，任何一个命中都算数。
    """
    wr = str(write_route or "").strip().lstrip("/")
    if wr:
        for e in read_eps:
            if str(e["route"]).strip().lstrip("/") == wr and e["method"] == "GET":
                return e["route"]
    wanted = {str(field or "").lower()}
    wanted.update(str(a or "").lower() for a in (aliases or set()) if a)
    wanted.discard("")
    if wanted:
        for e in read_eps:
            if wanted & {str(x).lower() for x in (e.get("fields") or [])}:
                return e["route"]
    return None


def analyze_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """跨文件关联分析模板层 XSS，返回假说 dict 列表（形状对齐业务逻假说）。

    输入：[{path, content, language?}]。无 Java 或 无模板则返回空。
    """
    java_files = _java_files(files)
    templates = _template_files(files)
    if not java_files or not templates:
        return []

    prefix, suffix = resolve_thymeleaf_config(files)
    template_sinks = parse_templates(templates)
    if not template_sinks:
        return []
    template_paths = list(template_sinks.keys())
    form_fields = _parse_form_fields(templates)
    write_eps = _collect_write_endpoints(java_files, form_fields)
    # M7：读接口判定的对称面 —— 两步重放第二步要读回写进去的字段
    read_eps = _collect_read_endpoints(java_files)
    # M10：静态识别模板引擎（import / class 路径，不需要 LLM）。
    # 结果挂在每条假说上，D1 透传到 DastImpact.ssti_engines，D2 的结果点比对按桶
    # 派发求值对 —— 同一组表达式打所有引擎会同时漏报（语法不匹配）与误报（碰巧算出 49）。
    try:
        from src.core.ssti_engines import detect_engines as _detect_engines
        engines = _detect_engines(files)
    except Exception:
        engines = []

    hypotheses: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, int, str]] = set()

    for f in java_files:
        path = str(f.get("path") or f.get("file_path") or "")
        content = f.get("content") or ""
        for route, http_method, block, mname, line in scan_spring_endpoints(content):
            model_keys = _extract_model_keys(block)
            if not model_keys:
                continue
            view = _extract_return_view(block)
            if not view:
                continue
            if view.lower().startswith(("redirect:", "forward:")):
                continue
            tpl = view_name_to_template_rel(view, prefix, suffix, template_paths)
            if not tpl:
                continue
            for s in template_sinks.get(tpl, []):
                mk = s["model_key"]
                if mk not in model_keys:
                    continue
                root_var = s["root_var"]
                field = _field_of(root_var, s["expr"])
                key = (route, tpl, s["line"], field or "")
                if key in seen:
                    continue
                seen.add(key)

                if field is None:
                    # 反射型：入参直传且未落库
                    param = _reflected_param(block, model_keys, mk)
                    if not param:
                        continue
                    hypotheses.append(_make_hypo(
                        "reflected", route, http_method, path, line, mname, s,
                        vulnerable_param=param, write_endpoint="",
                        engines=engines,
                    ))
                else:
                    # 存储型：实体字段且存在写接口（无写接口视为开发数据，非用户可控，跳过以免误报）
                    wep = _match_write_endpoint(write_eps, field)
                    if not wep:
                        continue
                    # M7：读端点静态定位（三级里的第一级）。给不出也不算漏检——
                    # 还有 LLM 补候选与标记反查两级兜底，这里只是「能静态给就先给」。
                    # aliases 把 model key 与 root_var 带进去：读侧登记的是 model key、
                    # 写侧登记的是实体字段，只认字段名会永远对不上（见该函数注释）。
                    rep = _match_read_endpoint(read_eps, field, wep,
                                               aliases={mk, root_var})
                    hypotheses.append(_make_hypo(
                        "stored", route, http_method, path, line, mname, s,
                        vulnerable_param=field, write_endpoint=wep,
                        read_endpoint=rep or "",
                        read_endpoint_source="static" if rep else "none",
                        engines=engines,
                    ))
    return hypotheses


def _make_hypo(subtype: str, route: str, http_method: str, path: str, line: int,
               mname: str, sink: Dict[str, Any], vulnerable_param: str,
               write_endpoint: str, read_endpoint: str = "",
               read_endpoint_source: str = "none",
               engines: Optional[List[str]] = None) -> Dict[str, Any]:
    tpl = sink["path"]
    sline = sink["line"]
    if subtype == "reflected":
        vuln_type = "reflected_xss"
        evidence = (
            f"反射型 XSS：请求参数 '{vulnerable_param}' 经 Controller 直传到模板 "
            f"{tpl}:{sline} 的 th:utext（非转义）输出，无 HTML 转义。入口 {http_method} {route}。"
        )
    else:
        vuln_type = "stored_xss"
        evidence = (
            f"存储型 XSS：字段 '{vulnerable_param}' 经写接口 {write_endpoint} 入库后，"
            f"在 {route} 渲染模板 {tpl}:{sline} 的 th:utext（非转义）输出。入口 {http_method} {route}。"
        )
    return {
        "vuln_type": vuln_type,
        "category": "xss",
        "family": "xss",
        "subtype": subtype,
        "target_endpoint": route,
        "http_method": http_method,
        "vulnerable_param": vulnerable_param,
        "entry_point": f"{path}:{line}",
        "template_sink": f"{tpl}:{sline}",
        "write_endpoint": write_endpoint,
        # M7：两步重放的写→读配对。空值表示静态侧给不出（还有 LLM 与标记反查两级兜底）
        "read_endpoint": read_endpoint,
        "read_endpoint_source": read_endpoint_source,
        # M10：模板引擎桶（静态识别，下游按桶派发求值对）
        "ssti_engines": list(engines or []),
        "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
        "confidence": "high",
        "evidence": evidence,
        "detection_method": "rule",
        "rule_name": "模板层XSS(th:utext)",
        "source": "a1-template-xss",
    }
