"""模板层不安全输出点（sink）抽取与 Thymeleaf 视图解析。

反射型/存储型 XSS 的 sink 常常不在 Java 里，而在 Thymeleaf 模板的 ``th:utext`` 上。
Java 侧只看到 ``model.addAttribute("keyword", keyword)``，看不到它最终有没有被转义；
模板侧只看到 ``th:utext="${keyword}"``，看不到值从哪来。单看任何一侧都判不出来，
必须跨文件关联 —— 本模块负责**模板侧**，Java 侧由 ``a1_template_xss_analyzer`` 负责。

此前 ``java_rules.yaml`` 里 SSTI004/SSTI005 明明写了 ``th:utext`` 的 pattern 却永不命中，
根因是规则跑在 Java 文件上、而 ``th:utext`` 只存在于 HTML 里（且 .html 压根没进扫描集，
见 src/core/scanner.py 的 LANGUAGE_EXTENSIONS）。本模块把模板侧做成确定性解析，不依赖 LLM。

口径：
- 只报**不转义**的输出：``th:utext``、``[(...)]`` 内联非转义、``th:attr`` 拼 innerHTML/事件属性。
- ``th:text`` 默认 HTML 转义，**不报**（与 java_rules.yaml SSTI004 把 th:text 列入
  false_positive 的口径保持一致）。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------- 模板侧 sink ----------------

# th:utext="..." / data-th-utext="..."（Thymeleaf 的非转义输出属性）
_UNSAFE_ATTR_RE = re.compile(
    r"(?:th:utext|data-th-utext)\s*=\s*([\"'])(.*?)\1",
    re.IGNORECASE | re.DOTALL,
)
# 内联非转义 [( ${expr} )]（对应 th:utext；[[ ]] 是转义的 th:text，不报）
_INLINE_UNESCAPED_RE = re.compile(r"\[\s*\((.*?)\)\s*\]", re.DOTALL)
# th:attr / th:attrappend 里拼接危险属性名
_ATTR_RE = re.compile(r"th:attr\w*\s*=\s*([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL)
_UNSAFE_ATTR_NAME_RE = re.compile(r"(?i)\b(innerHTML|outerHTML|srcdoc|formaction|on[a-z]{3,})\b")
# 表达式根变量：${user.signature} → user；${keyword} → keyword
_ROOT_VAR_RE = re.compile(r"\$\{\s*([A-Za-z_$][A-Za-z0-9_$]*)")
# 循环别名：th:each="c : ${comments}" → 别名 c 指向模型键 comments
_EACH_RE = re.compile(
    r"th:each\s*=\s*([\"'])\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(.*?)\1",
    re.IGNORECASE | re.DOTALL,
)
# 模板片段引用 th:replace="~{fragments :: navbar}" —— 不是 sink，但需识别以免误判
_FRAGMENT_RE = re.compile(r"~\s*\{[^}]*\}")

_DEFAULT_TH_PREFIX = "classpath:/templates/"
_DEFAULT_TH_SUFFIX = ".html"


def _line_of(text: str, offset: int) -> int:
    """字符偏移 → 1-based 行号。"""
    return text.count("\n", 0, offset) + 1


def _collect_each_scopes(content: str) -> List[Tuple[int, str, str]]:
    """收集所有 th:each 别名作用域起点：[(行号, 别名, 目标表达式根变量), ...]。

    作用域判定采用「最近前驱」近似：sink 行号 L 的别名 = 行号小于 L 的最后一个 th:each。
    不做 HTML 闭合解析（成本高且对这类模板收益有限），代价是循环结束后、下一个 th:each
    之前的 sink 可能被误挂到上一个别名 —— 但只有当它恰好引用了别名变量时才会误报，
    而引用了别名变量本身就说明它在循环体内，故实际误报极低。文档化此近似，便于后续替换。
    """
    scopes: List[Tuple[int, str, str]] = []
    for m in _EACH_RE.finditer(content):
        alias = m.group(2)
        target_expr = m.group(3) or ""
        vm = _ROOT_VAR_RE.search(target_expr)
        if not vm:
            continue
        scopes.append((_line_of(content, m.start()), alias, vm.group(1)))
    scopes.sort(key=lambda t: t[0])
    return scopes


def _alias_for_line(scopes: List[Tuple[int, str, str]], line: int) -> Tuple[str, str]:
    """返回该行生效的 (别名, 目标模型键)；不在任何循环内则返回 ("", "")）。"""
    alias, target = "", ""
    for lno, a, t in scopes:
        if lno < line:
            alias, target = a, t
        else:
            break
    return alias, target


def parse_template_sinks(rel_path: str, content: str) -> List[Dict[str, Any]]:
    """抽取单个模板文件里的不安全输出点。

    返回 [{path, line, attr, expr, root_var, alias_of, model_key, raw}]。
    ``model_key`` 是解析别名后、应当与 ``model.addAttribute`` 的第一个实参比对的名字。
    """
    if not isinstance(content, str):
        if isinstance(content, (bytes, bytearray)):
            content = content.decode("utf-8", "ignore")
        else:
            content = str(content)

    scopes = _collect_each_scopes(content)
    sinks: List[Dict[str, Any]] = []
    seen = set()

    def _add(line: int, attr: str, expr: str, raw: str) -> None:
        expr = (expr or "").strip()
        if not expr or _FRAGMENT_RE.search(expr):
            return
        vm = _ROOT_VAR_RE.search(expr)
        if not vm:
            return
        root_var = vm.group(1)
        alias, alias_target = _alias_for_line(scopes, line)
        model_key = alias_target if (alias and root_var == alias) else root_var
        key = (line, attr, expr)
        if key in seen:
            return
        seen.add(key)
        sinks.append({
            "path": rel_path,
            "line": line,
            "attr": attr,
            "expr": expr,
            "root_var": root_var,
            "alias_of": alias_target if (alias and root_var == alias) else "",
            "model_key": model_key,
            "raw": raw[:300],
        })

    for m in _UNSAFE_ATTR_RE.finditer(content):
        _add(_line_of(content, m.start()), "th:utext", m.group(2), m.group(0))

    for m in _INLINE_UNESCAPED_RE.finditer(content):
        _add(_line_of(content, m.start()), "inline-unescaped", m.group(1), m.group(0))

    for m in _ATTR_RE.finditer(content):
        body = m.group(2) or ""
        if _UNSAFE_ATTR_NAME_RE.search(body):
            _add(_line_of(content, m.start()), "th:attr", body, m.group(0))

    sinks.sort(key=lambda s: s["line"])
    return sinks


def parse_templates(files: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """批量解析模板文件，返回 {模板相对路径: [sink, ...]}。

    输入形状与 A1 scan_files 对齐：[{path, content, language?}]。
    只处理 language=='template' 或扩展名为 .html/.htm 的文件；逐文件容错。
    """
    out: Dict[str, List[Dict[str, Any]]] = {}
    for f in files or []:
        path = f.get("path") or f.get("file_path") or f.get("rel_path") or ""
        lang = str(f.get("language") or "").lower()
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if lang != "template" and ext not in ("html", "htm"):
            continue
        content = f.get("content") or f.get("source") or ""
        try:
            sinks = parse_template_sinks(path, content)
        except Exception:
            continue
        if sinks:
            out[path] = sinks
    return out


# ---------------- Thymeleaf 视图名 → 模板文件 ----------------

def resolve_thymeleaf_config(files: List[Dict[str, Any]]) -> Tuple[str, str]:
    """从扫描文件里的 application.properties / .yml 读取 Thymeleaf 前缀后缀。

    读不到则用 Spring Boot 缺省（classpath:/templates/ + .html）。
    只做轻量文本匹配，不做完整 properties/yaml 解析 —— 配置缺失时缺省值即可满足绝大多数项目。
    """
    prefix, suffix = _DEFAULT_TH_PREFIX, _DEFAULT_TH_SUFFIX
    for f in files or []:
        path = str(f.get("path") or "")
        if not (path.endswith(".properties") or path.endswith(".yml") or path.endswith(".yaml")):
            continue
        content = f.get("content") or ""
        for line in content.splitlines():
            s = line.strip()
            if s.startswith("#") or s.startswith("//"):
                continue
            if "thymeleaf" in s and ("prefix" in s or "suffix" in s):
                if "=" in s:
                    k, _, v = s.partition("=")
                elif ":" in s:
                    k, _, v = s.partition(":")
                else:
                    continue
                k, v = k.strip(), v.strip().strip("\"'")
                if k.endswith("prefix"):
                    prefix = v
                elif k.endswith("suffix"):
                    suffix = v
    if not prefix.endswith("/"):
        prefix += "/"
    if suffix and not suffix.startswith("."):
        suffix = "." + suffix
    return prefix, suffix


def view_name_to_template_rel(view: str, prefix: str, suffix: str,
                              template_paths: List[str]) -> Optional[str]:
    """视图名 → 模板文件相对路径。

    视图名先剥 redirect:/forward: 前缀（这类不渲染模板），再按 prefix/suffix 拼出逻辑路径，
    最后在已知模板路径里做「以逻辑路径结尾」的匹配（容忍扫描到的绝对路径/target 前缀差异）。
    """
    if not view:
        return None
    v = view.strip()
    low = v.lower()
    if low.startswith("redirect:") or low.startswith("forward:"):
        return None
    # 去掉前缀中的 classpath:/ 等协议与开头的 /
    logical = prefix.replace("classpath:/", "").lstrip("/") + v + suffix
    for p in template_paths:
        norm = str(p).replace("\\", "/")
        if norm.endswith("/" + logical) or norm == logical or norm.endswith(logical):
            return p
    # 兜底：仅按文件名匹配（视图名 + 后缀），容忍非标准目录
    fname = v + suffix
    for p in template_paths:
        norm = str(p).replace("\\", "/")
        if norm.endswith("/" + fname):
            return p
    return None
