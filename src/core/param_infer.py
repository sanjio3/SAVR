#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""请求参数名推断（2026-11-01，阶段 2）。

## 为什么需要

`trigger_specs.param_name` 为空 ⇒ D1 不知道该往哪个参数投弹 ⇒ 只能打一条空请求
⇒ sink 永远到不了 ⇒ `no-arrival`。本轮实测：156 条 spec 里 **40 条（26%）param 为空**，
其中 ssrf 一族占 11 条（22 条里一半）。

其中真正「能补但没补」的是**工具类 sink**：sink 落 `HttpUtils.request(String url)` 这种
工具方法上，参数名只在**调用方**的 Controller 签名里。这类必须靠调用图回溯，猜不出来。

## 与 `framework_sinks._infer_param` 的关系

后者是同一类推断的早期实现，但：
  - 只认 `@RequestBody` / 标量入参 / `getParameter` / body 哨兵，**不认 header 和 cookie 注解**
    ⇒ cors（Origin 头）和 shiro（rememberMe cookie）永远推不出参数；
  - 它是规则模块的内部函数，A2 的 spec 构造路径用不到。
本模块是它的**超集**（多两条通道），先只供「登记后、重放前」的后处理使用，
不动 framework_sinks 的既有行为（那 34 条命中与 OWASP 零命中的不变量不能被顺手改掉）。

## 纪律

- 只推**能从源码确定性读出来**的名字，不猜、不用 LLM；
- 推不出就返回空，由调用方标 `param_confidence=low`，**不许硬填**；
- 置信度 low 的 spec 不计入动态分母（见 `spec_state_normalize`）。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# 标量类型：只有这些才可能直接对应一个请求参数（排除对象/集合）
_SCALAR_TYPES = {
    "String", "int", "Integer", "long", "Long", "short", "Short", "byte", "Byte",
    "boolean", "Boolean", "double", "Double", "float", "Float", "char", "Character",
    "BigDecimal", "BigInteger", "Date", "LocalDate", "LocalDateTime", "Timestamp",
}

_REQ_BODY_ANN_RE = re.compile(r"@RequestBody\s+(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_REQ_PARAM_ANN_RE = re.compile(r"@RequestParam\s*\(([^)]*)\)\s*(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_REQ_PARAM_BARE_RE = re.compile(r"@RequestParam\s+(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_REQ_HEADER_ANN_RE = re.compile(r"@RequestHeader\s*\(([^)]*)\)\s*(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_COOKIE_VALUE_ANN_RE = re.compile(r"@CookieValue\s*\(([^)]*)\)\s*(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_PATH_VAR_ANN_RE = re.compile(r"@PathVariable\s*\(([^)]*)\)\s*(?:final\s+)?([\w$.<>\[\]]+)\s+(\w+)")
_GET_PARAM_RE = re.compile(r"""getParameter\s*\(\s*"([^"]+)"\s*\)""")
_GET_HEADER_RE = re.compile(r"""getHeader\s*\(\s*"([^"]+)"\s*\)""")
_STR_LITERAL_RE = re.compile(r'"([^"]+)"')

# 方法签名探测：找到最近的、带访问修饰符的方法声明
_METHOD_SIG_RE = re.compile(
    r"(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?[\w$.<>\[\],\s?]+\s+(\w+)\s*\("
)


@dataclass
class ParamGuess:
    """一个参数推断结果。``confidence`` 为 low 时调用方必须排除出动态分母。"""

    name: str = ""
    location: str = "query"
    confidence: str = "low"
    source: str = ""          # 哪条通道推出来的，便于审计

    def __bool__(self) -> bool:
        return bool(self.name)

    def as_dict(self) -> Dict[str, str]:
        return {"name": self.name, "location": self.location,
                "confidence": self.confidence, "source": self.source}


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def rel_path(p: Any, code_root: Optional[str] = None) -> str:
    """把任意形态的路径统一成**仓库相对、正斜杠、小写**的形式，用于比较。

    为什么必须统一：`trigger_specs.expected_sink_file` 实测有**三种写法**同时存在
    ：
      - 绝对 Windows 路径 `D:\\...\\java-sec-code\\src\\main\\...\\Cors.java`
      - 相对正斜杠 `src/main/java/org/joychou/util/HttpUtils.java`
      - 相对反斜杠 `src\\main\\java\\org\\joychou\\controller\\CSRF.java`
    而 `code_index.json` 里的 key 又是另一种大小写（`SSRF.java` vs DB 的 `Ssrf.java`）。
    不做归一就会「明明有索引却查不到」，表现为 `sink_func_not_indexed`。
    """
    s = str(p or "").replace("\\", "/").strip()
    if not s:
        return ""
    root = str(code_root or "").replace("\\", "/").rstrip("/")
    if root and s.lower().startswith(root.lower() + "/"):
        s = s[len(root) + 1:]
    else:
        # 绝对路径但不在当前 code_root 下：从 /src/ 开始截，尽量还原仓库相对路径
        low = s.lower()
        i = low.find("/src/")
        if i >= 0:
            s = s[i + 1:]
        else:
            s = re.sub(r"^[A-Za-z]:/", "", s)
    return s.lstrip("./").lower()


def resolve_source_file(code_root: Optional[str], sink_file: Any,
                        code_index: Optional[Dict[str, Any]] = None) -> str:
    """把 spec 里的 sink 文件解析成**磁盘上真实存在**的路径（大小写不敏感兜底）。"""
    if not code_root:
        return ""
    rel = rel_path(sink_file, code_root)
    if not rel:
        return ""
    cand = os.path.join(str(code_root), rel.replace("/", os.sep))
    if os.path.isfile(cand):
        return cand
    # 大小写不敏感兜底：拿索引里同名文件的真实写法
    for meta in (code_index or {}).values():
        if not isinstance(meta, dict):
            continue
        f = str(meta.get("file") or "")
        if f and rel_path(f, code_root) == rel:
            c2 = os.path.join(str(code_root), f.replace("/", os.sep))
            if os.path.isfile(c2):
                return c2
    return ""


def _enclosing_signature(code: str, line: int) -> Tuple[str, str]:
    """返回 (方法签名文本, 方法体文本)。签名取到配平的 `)` 为止。"""
    lines = code.splitlines()
    if not lines:
        return "", ""
    idx = max(0, min(len(lines) - 1, int(line) - 1))
    # 向前取 40 行找方法声明（注解/多行形参），向后取 40 行拿方法体
    # （只取 +2 行会让 body 为空 ⇒ getParameter 通道整条失效）。
    start = max(0, idx - 40)
    head = "\n".join(lines[start: min(len(lines), idx + 40)])
    # 选出**声明行号 ≤ 目标行**且离目标行最近的那个方法（不能取窗口里最后一个：
    # 向后多取 40 行后，窗口里会出现目标行之后的方法，取最后一个就张冠李戴）。
    sig = ""
    # sink 行正好落在注解行上（`@GetMapping("/x")` 比方法声明早一行）时，注解属于**下面**那个方法。
    # 直接看该行内容判断，比"往前找最近的声明"可靠：后者会把注解误判成上一个方法的。
    _line_txt = lines[idx].strip() if 0 <= idx < len(lines) else ""
    _want_next = _line_txt.startswith("@")
    best_line = -1
    next_sig, next_line = "", 10 ** 9
    for m in _METHOD_SIG_RE.finditer(head):
        decl_line = start + head[: m.start()].count("\n") + 1
        if decl_line <= int(line):
            if decl_line > best_line:
                best_line = decl_line
                sig = head[m.start():]
        elif decl_line < next_line:
            next_line = decl_line
            next_sig = head[m.start():]
    if _want_next and next_sig:
        sig = next_sig
    if not sig:
        return "", ""
    # 括号配平：形参里可能嵌注解的 ()，不能见 ')' 就收工
    depth = 0
    end = -1
    for i, ch in enumerate(sig):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return sig, ""
    sig_text = sig[: end + 1]
    body = sig[end + 1: end + 1 + 4000]
    return sig_text, body


def _ann_arg_name(ann_args: str) -> str:
    """从注解参数里取参数名：`value="x"` / `"x"` / `name="x"`。"""
    m = re.search(r'(?:value|name)\s*=\s*"([^"]+)"', ann_args)
    if m:
        return m.group(1)
    m = _STR_LITERAL_RE.search(ann_args)
    return m.group(1) if m else ""


def infer_param_from_method(code: str, line: int) -> ParamGuess:
    """在 `line` 所在方法里推断请求参数（六条通道，按确定性从高到低）。"""
    sig, body = _enclosing_signature(code, line)
    if not sig:
        return ParamGuess(source="no_method")

    # 1) @RequestHeader("X-Forwarded-For") String ip → header
    m = _REQ_HEADER_ANN_RE.search(sig)
    if m:
        name = _ann_arg_name(m.group(1)) or m.group(3)
        return ParamGuess(name, "header", "high", "request_header_ann")

    # 2) @CookieValue("rememberMe") String v → cookie
    m = _COOKIE_VALUE_ANN_RE.search(sig)
    if m:
        name = _ann_arg_name(m.group(1)) or m.group(3)
        return ParamGuess(name, "cookie", "high", "cookie_value_ann")

    # 3) @RequestBody X x → body
    m = _REQ_BODY_ANN_RE.search(sig)
    if m:
        return ParamGuess(m.group(2), "body", "high", "request_body_ann")

    # 4) @RequestParam("x") / @RequestParam String x → query
    m = _REQ_PARAM_ANN_RE.search(sig)
    if m:
        name = _ann_arg_name(m.group(1)) or m.group(3)
        return ParamGuess(name, "query", "high", "request_param_ann")
    m = _REQ_PARAM_BARE_RE.search(sig)
    if m:
        return ParamGuess(m.group(2), "query", "high", "request_param_bare")

    # 5) @PathVariable("id") → query（路径变量用 query 注入对多数框架无效，
    #    但至少给出名字，由调用方按 confidence 决定是否用）
    m = _PATH_VAR_ANN_RE.search(sig)
    if m:
        name = _ann_arg_name(m.group(1)) or m.group(3)
        return ParamGuess(name, "query", "medium", "path_variable_ann")

    # 6) 方法体里 getParameter("lit") / getHeader("lit")
    m = _GET_PARAM_RE.search(body)
    if m:
        return ParamGuess(m.group(1), "query", "high", "get_parameter_literal")
    m = _GET_HEADER_RE.search(body)
    if m:
        return ParamGuess(m.group(1), "header", "high", "get_header_literal")

    # 7) 兜底：第一个标量形参（无注解，Spring 也按同名参数绑定）
    for typ, nm in _parse_scalar_args(sig):
        return ParamGuess(nm, "query", "medium", "scalar_arg")
    return ParamGuess(source="no_channel")


def _parse_scalar_args(sig: str) -> List[Tuple[str, str]]:
    """从方法签名里抽 (类型, 名字) 对，只保留标量。"""
    m = re.search(r"\((.*)\)", sig, re.S)
    if not m:
        return []
    out: List[Tuple[str, str]] = []
    for part in m.group(1).split(","):
        # 去掉注解（含带括号的）
        p = re.sub(r"@\w+\s*(?:\([^)]*\))?", " ", part).strip()
        toks = p.replace("final ", "").split()
        if len(toks) < 2:
            continue
        typ, nm = toks[-2], toks[-1]
        if typ in _SCALAR_TYPES and re.match(r"^\w+$", nm):
            out.append((typ, nm))
    return out


def backtrace_param(code_root: Optional[str], code_index: Dict[str, Any],
                    sink_file: str, sink_line: int,
                    max_depth: int = 2) -> ParamGuess:
    """工具类 sink 的参数回溯：顺着 `callers` 往上找到有 HTTP 入口的那一层。

    `code_index` 是 `code_index.json` 的 `functions` 段：
    `{"<rel_file>:<func>": {"line":..., "parameters":..., "callers":[...], "http_entry": {...}}}`

    三条置信度闸门（缺一即返回 low / 空，宁可漏不可投错位置）：
      1. 回溯层数 > ``max_depth`` → 放弃
      2. 多个 caller 推出的参数名不一致 → 放弃
      3. 推出来的名字与 sink 形参名不一致，且不是同名直传 → 降 medium
    """
    if not code_root or not code_index or not sink_file:
        return ParamGuess(source="no_input")

    norm_sink = rel_path(sink_file, code_root)
    # 找到 sink 所在函数（同文件、行号最接近且不超过 sink_line）
    best_key, best_line = "", -1
    for key, meta in code_index.items():
        if not isinstance(meta, dict):
            continue
        kf = rel_path(meta.get("file") or key.rsplit(":", 1)[0], code_root)
        if kf != norm_sink:
            continue
        try:
            ln = int(meta.get("line") or 0)
        except Exception:
            continue
        if ln <= int(sink_line) and ln > best_line:
            best_key, best_line = key, ln
    if not best_key:
        return ParamGuess(source="sink_func_not_indexed")

    frontier = [best_key]
    visited = {best_key}
    # 大小写不敏感索引：`callers` 里的 key 与 `functions` 的 key 可能只差大小写
    # （DB 写 `SSRF.java`、索引写 `Ssrf.java`），直接 dict.get 会查不到，
    # 表现为「明明调用方有入口却报 no_http_entry_caller」。
    lower_index = {str(k).lower(): k for k in code_index}
    for depth in range(1, int(max_depth) + 1):
        nxt: List[str] = []
        for key in frontier:
            meta = code_index.get(key) or {}
            for caller in (meta.get("callers") or []):
                _ck = caller if caller in code_index else lower_index.get(str(caller).lower())
                if not _ck or _ck in visited:
                    continue
                visited.add(_ck)
                cmeta = code_index.get(_ck) or {}
                entry = cmeta.get("http_entry") or None
                if entry:
                    cfile = str(cmeta.get("file") or caller.rsplit(":", 1)[0])
                    cline = int(cmeta.get("line") or 1)
                    path = resolve_source_file(code_root, cfile, code_index)
                    guess = infer_param_from_method(_read(path), cline)
                    if guess:
                        # 闸门 3：与 sink 形参名不一致时降一级
                        sink_params = str(meta.get("parameters") or "")
                        if guess.name and guess.name not in sink_params:
                            guess.confidence = "medium"
                            guess.source += "+name_differs_from_sink"
                        return guess
                nxt.append(_ck)
        if not nxt:
            break
        frontier = nxt
    return ParamGuess(source="no_http_entry_caller")


def infer_for_spec(code_root: Optional[str], code_index: Dict[str, Any],
                   sink_file: str, sink_line: int) -> ParamGuess:
    """spec 级入口：先看 sink 本身是不是 Controller 方法，不是再回溯调用方。"""
    if not code_root or not sink_file:
        return ParamGuess(source="no_input")
    path = resolve_source_file(code_root, sink_file, code_index)
    code = _read(path)
    if not code:
        return ParamGuess(source="sink_file_unreadable")

    norm = rel_path(sink_file, code_root)
    # 找 **包含** sink 行的方法（行号 ≤ sink_line 里最大的那个），不是「行号相等」。
    # 2026-11-02 实杀：这里原本写的是 `int(meta["line"]) == int(sink_line)`，
    # 而 sink 是方法体里的语句，行号几乎永远不等于方法声明行 ⇒ 这条通道恒不命中，
    # 全部掉进 backtrace；backtrace 对一个「自己就是入口」的方法只能返回
    # `no_http_entry_caller`（它没有 caller）。实测 35 条 param 空里 30 条卡在这。
    own_meta = None
    own_line = -1
    for key, meta in (code_index or {}).items():
        if not isinstance(meta, dict):
            continue
        kf = rel_path(meta.get("file") or key.rsplit(":", 1)[0], code_root)
        if kf != norm:
            continue
        try:
            ln = int(meta.get("line") or 0)
        except Exception:
            continue
        if ln <= int(sink_line or 0) and ln > own_line:
            own_meta, own_line = meta, ln
    if own_meta and own_meta.get("http_entry"):
        g = infer_param_from_method(code, int(sink_line or 0))
        if g and g.name:
            g.source = "sink_is_entry+" + g.source
            return g
    return backtrace_param(code_root, code_index, sink_file, sink_line)


# ── 类型驱动的请求形态（2026-11-02）──────────────────────────────────────────
#
# 为什么要它：`content_type` 现在由 A2 按 **payload_family（族字符串）** 推断
# （a2_contract_planner.py:931）。族一错，编码方式就跟着错 —— 实测 `/file/upload`
# 的参数是 `@RequestParam("file") MultipartFile`，必须 multipart 编码，但 spec 的
# content_type 是空、param_location 落 `query` ⇒ Spring 的 MultipartFile 永远绑不上
# ⇒ sink 不执行 ⇒ 白打 12 条。
#
# 类型是**源码里客观写着的**，不需要猜：MultipartFile→multipart、byte[]→二进制、
# @RequestBody→body、@CookieValue→cookie、@RequestHeader→header。
# 判据优先级：注解 > 类型 > 默认 query。

_MULTIPART_TYPES = {"multipartfile", "list<multipartfile>", "multipartfile[]"}
_BINARY_TYPES = {"byte[]", "inputstream", "bytebuffer", "file"}


def infer_binding(typed_params: List[Dict[str, Any]], param_name: str = "") -> Dict[str, str]:
    """从结构化形参推出 (location, content_type)。推不出返回空 dict（调用方保持原样）。"""
    params = [p for p in (typed_params or []) if isinstance(p, dict)]
    if not params:
        return {}

    target = None
    if param_name:
        for p in params:
            if str(p.get("name") or "") == param_name:
                target = p
                break
    if target is None and len(params) == 1:
        target = params[0]
    if target is None:
        # 多个形参又对不上名字：只认「唯一一个决定性类型」的那种，避免乱改
        decisive = [p for p in params
                    if str(p.get("type") or "").strip().lower() in (_MULTIPART_TYPES | _BINARY_TYPES)]
        if len(decisive) != 1:
            return {}
        target = decisive[0]

    anns = " ".join(str(a or "") for a in (target.get("annotations") or [])).lower()
    typ = str(target.get("type") or "").strip().lower()

    # 1) 注解优先
    if "@requestheader" in anns:
        return {"location": "header", "content_type": "", "reason": "annotation:@RequestHeader"}
    if "@cookievalue" in anns:
        return {"location": "cookie", "content_type": "", "reason": "annotation:@CookieValue"}
    if "@requestpart" in anns:
        return {"location": "form", "content_type": "multipart/form-data",
                "reason": "annotation:@RequestPart"}
    if "@requestbody" in anns:
        return {"location": "body",
                "content_type": "application/json" if typ not in ("string", "byte[]") else "",
                "reason": "annotation:@RequestBody"}

    # 2) 类型
    if typ in _MULTIPART_TYPES:
        return {"location": "form", "content_type": "multipart/form-data",
                "reason": "type:MultipartFile"}
    if typ in _BINARY_TYPES:
        return {"location": "body", "content_type": "application/octet-stream",
                "reason": "type:%s" % typ}
    return {}


def infer_binding_for_spec(code_root: Optional[str], code_index: Dict[str, Any],
                           sink_file: str, sink_line: int,
                           param_name: str = "") -> Dict[str, str]:
    """按 sink 所在函数（或回溯到的入口函数）的形参类型，推出请求形态。"""
    if not code_root or not code_index:
        return {}
    norm = rel_path(sink_file, code_root)
    if not norm:
        return {}

    def _meta_at(line_no: int):
        best, best_line = None, -1
        for key, meta in code_index.items():
            if not isinstance(meta, dict):
                continue
            if rel_path(meta.get("file") or key.rsplit(":", 1)[0], code_root) != norm:
                continue
            try:
                ln = int(meta.get("line") or 0)
            except Exception:
                continue
            if ln <= line_no and ln > best_line:
                best, best_line = meta, ln
        return best

    own = _meta_at(int(sink_line or 0))
    if own and own.get("http_entry"):
        return infer_binding(own.get("params_typed") or [], param_name)

    # 回溯到入口函数
    if own:
        lower_index = {str(k).lower(): k for k in code_index}
        frontier = [(k, m) for k, m in code_index.items() if m is own]
        visited = set()
        for _depth in range(2):
            nxt = []
            for _k, meta in frontier:
                for caller in (meta.get("callers") or []):
                    ck = caller if caller in code_index else lower_index.get(str(caller).lower())
                    if not ck or ck in visited:
                        continue
                    visited.add(ck)
                    cmeta = code_index.get(ck) or {}
                    if cmeta.get("http_entry"):
                        return infer_binding(cmeta.get("params_typed") or [], param_name)
                    nxt.append((ck, cmeta))
            if not nxt:
                break
            frontier = nxt
    return {}
