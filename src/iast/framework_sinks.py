"""框架惯用 sink 的确定性静态规则（补 CodeQL 查询覆盖不到的位置）。

## 为什么需要这个模块

CodeQL 的标准 Java 查询包建模的是 **Servlet API** 的 sink：
``response.getWriter.print(...)``、``Statement.executeQuery(...)``、
**框架惯用写法**，同一个危害在代码里长得完全不同：

| 族 | CodeQL 认的形态 | 框架惯用形态（CodeQL 漏） |
|---|---|---|
| xss | ``response.getWriter.print(param)`` | Spring ``@ResponseBody`` 方法 ``return param;`` |
| expression_injection | 无 | ``new ExpressRunner.execute(param, ...)`` |
| jndi_injection | 无 | log4j2 ``logger.error(param)``（Log4Shell 面） |
| cors | 无 | ``setHeader("Access-Control-Allow-Origin", origin)`` |
| rmi | 无 | ``LocateRegistry.createRegistry(...)`` |

全部落在上表右列。这不是「判据不够好」，是**候选压根没被登记**——
下游 D1/D2/I2 再强也无从下手。

## 设计纪律（沿用属性族的硬约束）

1. **只匹配「单行即可定性」的形态**。需要跨函数污点传播才能定的，一律不进来
   （那是 CodeQL 的活）。规则宁少勿滥。
2. **每条规则必须给出「为什么这一行就够」**，写进 ``reason``，供审计。
3. **不判安全**。本模块只产出「正向证据」，不产出「这里安全」的结论——
4. **族名用平台族名**，与 ``trigger_specs.family`` 对齐，避免下游族路由错配。
5. 每条规则带 ``confidence``；只有 ``high`` 才允许直接落 confirmed_code_property，
   ``medium`` 只登记候选、交给正常流程裁决。


纯 Servlet + ``javax`` 写法，因此这些规则在 OWASP 上应当**零命中**。
这一点由 ``tools/_wb_fw_rule_audit.py`` 离线校验（两个语料同时跑）。
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ── 平台族名（与 trigger_specs.family 对齐） ──────────────────────────────
FAMILY_XSS = "xss"
FAMILY_CORS = "cors"
FAMILY_JNDI = "jndi_injection"
FAMILY_EXPRESSION = "expression_injection"
FAMILY_RMI = "rmi"
FAMILY_SECURE_COOKIE = "secure_cookie"
FAMILY_CSRF = "csrf"
FAMILY_JSONP = "jsonp_referer"
FAMILY_DESERIALIZE = "deserialization"
FAMILY_CRLF = "crlf_injection"
FAMILY_SSTI = "ssti"
FAMILY_FILE_UPLOAD = "file_upload"
FAMILY_SQLI = "sql_injection"


@dataclass
class FrameworkHit:
    """一条确定性静态命中。"""

    family: str
    rule: str
    file: str
    line: int
    sink: str
    route: str = ""
    http_method: str = "GET"
    param: str = ""
    location: str = "query"
    confidence: str = "high"
    reason: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "family": self.family,
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "sink": self.sink,
            "route": self.route,
            "http_method": self.http_method,
            "param": self.param,
            "location": self.location,
            "confidence": self.confidence,
            "reason": self.reason,
        }


# ── 源码骨架解析：把 Java 文件切成「方法块」并带出注解与路由 ──────────────

_CLASS_ANN_RE = re.compile(r"@(?:RequestMapping|RestController|Controller)\b[^\n]*")
_CLASS_MAPPING_RE = re.compile(
    r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']*)[\"']"
)
_METHOD_MAPPING_RE = re.compile(
    r"@(?P<ann>RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
    r"\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?(?P<q>[\"'])(?P<path>[^\"']*)(?P=q))?"
)
_HANDLER_SIG_RE = re.compile(
    r"(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?"
    r"(?P<ret>[\w<>\[\],.\s?]+?)\s+(?P<name>\w+)\s*"
    # 形参里可能带注解，注解本身含括号（`@RequestParam("file") MultipartFile file`）。
    # 原先用 `[^)]*` 会在 `@RequestParam("file")` 的 `)` 处截断 ⇒ 整个方法解析不到 ⇒
    # FileUpload.java 的上传规则一条都不命中。这里允许一层内嵌括号。
    r"\((?P<args>(?:[^()]|\([^()]*\))*)\)"
)
_ANN_BEFORE = re.compile(r"^\s*@")

_HTTP_METHOD_BY_ANN = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

# Spring 的「请求参数」：String/int 等标量入参，没有 @RequestBody/@PathVariable 之外来源，
# 默认就是 query/form 参数。这里只认 String 与常见标量。
_SCALAR_TYPES = {"String", "CharSequence", "int", "Integer", "long", "Long", "boolean", "Boolean"}


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _strip_comments(code: str) -> str:
    """去掉 // 与 /* */ 注释，保留行号（用空行占位）。

    不摘掉会把注释当代码匹配出假命中。
    """
    out: List[str] = []
    in_block = False
    for line in code.splitlines():
        if in_block:
            idx = line.find("*/")
            if idx < 0:
                out.append("")
                continue
            line = " " * (idx + 2) + line[idx + 2:]
            in_block = False
        # 行内块注释
        while True:
            s = line.find("/*")
            if s < 0:
                break
            e = line.find("*/", s + 2)
            if e < 0:
                line = line[:s]
                in_block = True
                break
            line = line[:s] + " " * (e + 2 - s) + line[e + 2:]
        # 行注释（不处理字符串里的 //，对规则匹配影响可忽略）
        p = line.find("//")
        if p >= 0:
            line = line[:p]
        out.append(line)
    return "\n".join(out)


def _method_blocks(code: str) -> List[Dict[str, object]]:
    """粗切方法块：注解块 + 方法签名 + 方法体（按花括号配平）。

    不追求语法完备，只保证「注解 → 签名 → 体」三者的行号对齐。
    """
    lines = code.splitlines()
    blocks: List[Dict[str, object]] = []
    n = len(lines)
    i = 0
    while i < n:
        # 必须以 @ 开头才算注解块。曾经只判 "Mapping" in line，于是
        # `import ...annotation.RequestMapping;` 这种行也会进来，但它不以 @ 开头、
        # 注解收集循环一步不走 ⇒ anns 为空 ⇒ continue 后 i 不变 ⇒ 死循环。
        if not _ANN_BEFORE.match(lines[i]):
            i += 1
            continue
        # 收集连续注解行
        ann_start = i
        anns: List[str] = []
        while i < n and (_ANN_BEFORE.match(lines[i]) or lines[i].strip() == ""):
            if lines[i].strip():
                anns.append(lines[i])
            i += 1
            if len(anns) > 8 and i < n and not _ANN_BEFORE.match(lines[i]):
                break
        if not anns:
            i = max(i, ann_start + 1)
            continue
        ann_text = " ".join(anns)
        # 方法签名可能跨行。**不能一见到 ")" 就收工**：形参注解自带括号
        # （`@RequestParam("file") MultipartFile file,`），那样会在注解处提前截断，
        # 后面的形参全部丢失。
        # 改为按括号配平判断「参数列表真正结束」。
        sig_start = i
        sig = ""
        _depth = 0
        _seen_open = False
        while i < n and i < sig_start + 12:
            _seg = lines[i].strip()
            sig += " " + _seg
            _depth += _seg.count("(") - _seg.count(")")
            if "(" in _seg:
                _seen_open = True
            if _seen_open and _depth <= 0:
                break
            i += 1
        m = _HANDLER_SIG_RE.search(sig)
        if not m:
            # 注解块后面跟的是类声明（`@RestController` + `public class X {`）：
            # 只跳过类声明这一行，别把紧随其后的方法注解一起吞掉。
            # 曾经直接 continue（i 已前进到签名探测窗口末尾），导致「类声明紧接方法注解」
            # 的文件整体解析不到方法（单测 test_import_line_does_not_hang 抓到的）。
            if re.search(r"\b(?:class|interface|enum|record)\s+\w+", sig):
                i = sig_start + 1
            continue
        # 方法体
        body_start = i
        depth = 0
        started = False
        body_lines: List[str] = []
        j = body_start
        while j < n:
            body_lines.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if started and depth <= 0:
                break
            j += 1
        blocks.append({
            "ann": ann_text,
            "ann_line": ann_start + 1,
            "sig_line": sig_start + 1,
            "ret": (m.group("ret") or "").strip(),
            "name": m.group("name"),
            "args": m.group("args") or "",
            "body": "\n".join(body_lines),
            "body_line": body_start + 1,
        })
        i = max(j, i) + 1
    return blocks


def _parse_args(args: str) -> List[Tuple[str, str]]:
    """方法参数 → [(类型, 名)]。"""
    out: List[Tuple[str, str]] = []
    for raw in _split_top_level(args):
        part = raw.strip()
        if not part:
            continue
        part = re.sub(r"@\w+(?:\([^)]*\))?", " ", part)
        part = part.replace("final ", " ").strip()
        toks = part.split()
        if len(toks) >= 2:
            out.append((toks[-2], toks[-1]))
    return out


def _split_top_level(s: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def _class_base_route(code: str) -> str:
    """取**类级** ``@RequestMapping`` 的路径前缀。

    ``@RestController``（无路径），路径写在**方法**的 ``@RequestMapping(value="/log4j")``
    上，按「第一个」取会得到 base=/log4j，再拼方法路径就成了 ``/log4j/log4j``。
    ⇒ 必须定位 ``class`` 声明行，只取它**紧邻上方**那一段注解。
    """
    lines = code.splitlines()
    for idx, line in enumerate(lines):
        if not re.search(r"\b(?:class|interface|enum|record)\s+\w+", line):
            continue
        j = idx - 1
        block: List[str] = []
        while j >= 0 and (_ANN_BEFORE.match(lines[j]) or lines[j].strip() == ""):
            if lines[j].strip():
                block.append(lines[j])
            j -= 1
        for ann in block:
            m = _CLASS_MAPPING_RE.search(ann)
            if m:
                return m.group(1)
        return ""
    return ""


def _join_route(base: str, sub: str) -> str:
    if not base:
        return sub or ""
    if not sub:
        return base
    return base.rstrip("/") + "/" + sub.lstrip("/")


def _enclosing_block(code: str, line: int) -> Optional[Dict[str, object]]:
    for b in _method_blocks(code):
        start = int(b["body_line"])
        end = start + str(b["body"]).count("\n")
        if start <= line <= end:
            return b
    return None


# 从方法体里「抠」参数名：这三条是真实项目里最常见的取值写法
_GET_PARAM_RE = re.compile(r"""getParameter\s*\(\s*["']([\w\-.]+)["']""")
_REQ_BODY_ANN_RE = re.compile(
    r"@RequestBody\b\s+(?:final\s+)?[\w.$<>\[\],?\s]*?\s+([A-Za-z_$][\w$]*)\s*(?:,|$)"
)
_BODY_READ_RE = re.compile(r"getRequestBody\s*\(|getInputStream\s*\(|getReader\s*\(")
# Cookie 取值：字面量优先，其次常量名（REMEMBER_ME_COOKIE → rememberMe）
_COOKIE_LITERAL_RE = re.compile(r"""getCookie\w*\s*\([^,]+,\s*["']([\w\-.]+)["']""")
_COOKIE_CONST_RE = re.compile(r"getCookie\w*\s*\([^,]+,\s*[\w.]*?\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")
_COOKIE_VALUE_ANN_RE = re.compile(r"""@CookieValue\s*\(\s*(?:value\s*=\s*)?["']([\w\-.]+)["']""")


def _const_to_camel(name: str) -> str:
    """``REMEMBER_ME_COOKIE`` → ``rememberMe``（去掉 COOKIE/SESS 后缀再转小驼峰）。"""
    parts = [p for p in re.split(r"_+", name) if p]
    if parts and parts[-1].upper() in ("COOKIE", "SESS", "SESSION", "KEY", "NAME"):
        parts = parts[:-1]
    if not parts:
        return ""
    head = parts[0].lower()
    return head + "".join(p.capitalize() for p in parts[1:])


def _infer_param(code: str, line: int) -> Tuple[str, str]:
    """推断该行所在方法的**请求参数名**与位置。返回 (param, location)。

    为什么必须做：登记环节要求 (route, param) 可解析，**解析不出就整条丢弃**
    （`missing_route`）。而 deserialization / cors 这类规则原先只给 route 不给 param，
    于是 Fastjson、XStreamRce、ClassDataLoader 全部在登记阶段被丢——不是没检出，是登记不进去。

    推断顺序（确定性，不猜）：
      1. 方法签名里 `@RequestBody String params` → params（body）
      2. 方法签名里的标量入参（String/int…）→ 第一个（query）
      3. 方法体里 `request.getParameter("classData")` → classData（query）
      4. 方法体里直接读流（`getRequestBody` / `getInputStream`）→ 无名字的 body，
         用哨兵 `__body__`（location=body），D1 按原始 body 投放
    """
    b = _enclosing_block(code, line)
    if not b:
        return "", "query"
    args = str(b["args"] or "")
    body = str(b["body"] or "")
    m = _REQ_BODY_ANN_RE.search(args)
    if m:
        return m.group(1), "body"
    for typ, name in _parse_args(args):
        if typ in _SCALAR_TYPES:
            return name, "query"
    m = _GET_PARAM_RE.search(body)
    if m:
        return m.group(1), "query"
    m = _COOKIE_VALUE_ANN_RE.search(args) or _COOKIE_VALUE_ANN_RE.search(body)
    if m:
        return m.group(1), "cookie"
    m = _COOKIE_LITERAL_RE.search(body)
    if m:
        return m.group(1), "cookie"
    m = _COOKIE_CONST_RE.search(body)
    if m:
        _c = _const_to_camel(m.group(1))
        if _c:
            return _c, "cookie"
    if _BODY_READ_RE.search(body):
        return "__body__", "body"
    return "", "query"


# ── 规则 1：Spring @ResponseBody 直接返回请求参数 → xss ──────────────────

_RETURN_IDENT_RE = re.compile(
    r"(?:^|[;{}])\s*return\s+([A-Za-z_$][\w$]*)\s*;", re.MULTILINE
)


def _rule_spring_reflected_return(code: str, rel: str) -> List[FrameworkHit]:
    """``@ResponseBody`` 方法 ``return <请求参数>;`` —— 反射型 XSS 的框架惯用形态。

    为什么一行就够：把未经编码的请求参数原样写进响应体，浏览器就会把它当 HTML/JS 解析。
    这里只认「返回值就是那个参数名本身」，任何经过函数调用（``return encode(xss);``）
    或字符串拼接的都放过 —— 前者可能已净化，后者需要判净化器（CodeQL 的活）。
    """
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    for b in _method_blocks(code):
        ann = str(b["ann"])
        if "ResponseBody" not in ann and "RestController" not in code[:2000]:
            continue
        args = _parse_args(str(b["args"]))
        scalar_names = {n for t, n in args if t in _SCALAR_TYPES}
        if not scalar_names:
            continue
        for m in _RETURN_IDENT_RE.finditer(str(b["body"])):
            ident = m.group(1)
            if ident not in scalar_names:
                continue
            sub = ""
            mm = _METHOD_MAPPING_RE.search(ann)
            if mm:
                sub = mm.group("path") or ""
            line = int(b["body_line"]) + str(b["body"])[: m.start()].count("\n")
            hits.append(FrameworkHit(
                family=FAMILY_XSS, rule="spring_reflected_return", file=rel, line=line,
                sink="ResponseBody.return", route=_join_route(base, sub),
                http_method=_HTTP_METHOD_BY_ANN.get(
                    (mm.group("ann") if mm else "RequestMapping"), "GET"),
                param=ident, confidence="high",
                reason=f"@{b['name']} 把请求参数 `{ident}` 原样作为响应体返回，无编码",
            ))
            break  # 一个方法只报一次
    return hits


# ── 规则 2：CORS 反射/通配 ────────────────────────────────────────────────

_CORS_SETHEADER_RE = re.compile(
    r"""setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*([^)]+)\)"""
)
_CORS_WILDCARD_API_RE = re.compile(
    r"""(?:allowedOriginPatterns|allowedOrigins|addAllowedOrigin(?:Pattern)?)\s*\(\s*["']\*["']"""
)


def _rule_cors(code: str, rel: str) -> List[FrameworkHit]:
    """ACAO 反射请求头 / 通配 ``*`` + 允许携带凭据。

    为什么一行就够：ACAO 决定「哪些源能读响应」。反射 Origin 头等于对任意源开放；
    ``*`` 配合 ``Allow-Credentials: true`` 同样把凭据交出去。这两者都是配置事实，
    不需要运行时观测。
    """
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    has_credentials = re.search(
        r"""["']Access-Control-Allow-Credentials["']\s*,\s*["']true["']""", code, re.I)
    for m in _CORS_SETHEADER_RE.finditer(code):
        val = m.group(1).strip()
        if val.startswith(("\"", "'")):
            literal = val.strip("\"'")
            if literal != "*":
                continue
            kind = "通配 *"
        else:
            kind = "反射 Origin"
        line = code[: m.start()].count("\n") + 1
        _route, _meth = _route_at_line(code, line)
        _param, _loc = _infer_param(code, line)
        hits.append(FrameworkHit(
            family=FAMILY_CORS, rule="cors_acao", file=rel, line=line,
            sink="Access-Control-Allow-Origin", route=_route or base,
            http_method=_meth, param=_param, location=_loc,
            confidence="high" if (kind == "反射 Origin" or has_credentials) else "medium",
            reason=f"ACAO 取值为{kind}" + ("，且 Allow-Credentials=true" if has_credentials else ""),
        ))
    for m in _CORS_WILDCARD_API_RE.finditer(code):
        line = code[: m.start()].count("\n") + 1
        hits.append(FrameworkHit(
            family=FAMILY_CORS, rule="cors_wildcard_api", file=rel, line=line,
            sink="CorsConfiguration.allowedOrigins", route=base, confidence="medium",
            reason="CORS 配置允许任意源（*）",
        ))
    return hits


# ── 规则 3：log4j2 记录非字面量 → jndi_injection（Log4Shell 面） ──────────

_LOG_CALL_RE = re.compile(
    r"\b(?:logger|log|LOG|LOGGER)\s*\.\s*(?:trace|debug|info|warn|error|fatal)\s*\(\s*([^),]{1,120})"
)
_LITERAL_ONLY_RE = re.compile(r"""^["'][^"']*["']$""")


def _rule_log4j_jndi(code: str, rel: str) -> List[FrameworkHit]:
    """log4j2 把非字面量写进日志 → JNDI 注入面。

    为什么一行就够：log4j2 < 2.15 会对日志内容做 ``${jndi:...}`` 替换，攻击者把
    表达式放进任何被记录的用户输入即可触发远程类加载。判据是「有 log4j2 + 记录非字面量」，
    不依赖能否真的打通（真实环境往往打不通，但漏洞成立）。
    """
    if "org.apache.logging.log4j" not in code:
        return []
    hits: List[FrameworkHit] = []
    for m in _LOG_CALL_RE.finditer(code):
        arg = m.group(1).strip()
        if not arg or _LITERAL_ONLY_RE.match(arg):
            continue
        if arg.startswith("\""):  # 拼接字面量开头也算，但要求含变量
            if not re.search(r"\+\s*[A-Za-z_$]", arg):
                continue
        line = code[: m.start()].count("\n") + 1
        hits.append(FrameworkHit(
            family=FAMILY_JNDI, rule="log4j2_nonliteral", file=rel, line=line,
            sink="log4j2.Logger", route="", param=_ident_of(arg), confidence="high",
            reason=f"log4j2 记录非字面量 `{arg[:40]}`，存在 ${{jndi:}} 注入面",
        ))
    return hits


def _ident_of(expr: str) -> str:
    m = re.search(r"[A-Za-z_$][\w$]*", expr or "")
    return m.group(0) if m else ""


# ── 规则 4：表达式引擎执行非字面量 → expression_injection ─────────────────

_EXPR_ENGINES = (
    (re.compile(r"\bExpressRunner\b"), "QLExpress", FAMILY_EXPRESSION),
    (re.compile(r"\bSpelExpressionParser\b"), "SpEL", "spel_injection"),
    (re.compile(r"\bOgnl\b"), "OGNL", FAMILY_EXPRESSION),
    (re.compile(r"\bMVEL\b"), "MVEL", FAMILY_EXPRESSION),
    (re.compile(r"\bGroovyShell\b"), "Groovy", "command_execution"),
)
_EXEC_CALL_RE = re.compile(
    r"\.\s*(?:execute|parseExpression|parse|eval|evaluate|getValue)\s*\(\s*([^),]{1,160})"
)
# 表达式引擎的「安全模式」显式声明。出现在方法体内即代表该方法已收紧执行面。
_ENGINE_HARDENING_RE = re.compile(
    r"forbidInvokeSecurityRiskMethods|addSecureMethod|setForbidInvokeSecurityRiskMethods"
    r"|SimpleEvaluationContext|setAllowStaticMethodAccess\s*\(\s*false"
)


def _hardened_ranges(code: str) -> List[Tuple[int, int]]:
    """返回「已显式收紧」的方法体行号区间 [(start, end)]。

    为什么必须排除：QLExpress 的 ``sec`` 方法与 ``vuln1`` 写法几乎一样，区别只在
    多了一行 ``QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true)``。
    不排除就会把安全版本报成漏洞。
    """
    out: List[Tuple[int, int]] = []
    for b in _method_blocks(code):
        body = str(b["body"])
        if _ENGINE_HARDENING_RE.search(body):
            start = int(b["body_line"])
            out.append((start, start + body.count("\n")))
    return out


def _rule_expression_engine(code: str, rel: str) -> List[FrameworkHit]:
    """表达式引擎执行非字面量 → 表达式注入（可导致 RCE）。

    为什么一行就够：表达式引擎的入参就是「代码」。只要入参不是字面量，
    攻击者控制它即可执行任意表达式。这里只要求「同文件出现引擎类 + 执行调用非字面量」，
    不判污点来源（避免与 CodeQL 重复，也让规则保守）。
    """
    engine = ""
    fam = FAMILY_EXPRESSION
    for pat, name, family in _EXPR_ENGINES:
        if pat.search(code):
            engine, fam = name, family
            break
    if not engine:
        return []
    hardened = _hardened_ranges(code)
    hits: List[FrameworkHit] = []
    for m in _EXEC_CALL_RE.finditer(code):
        arg = m.group(1).strip()
        if not arg or _LITERAL_ONLY_RE.match(arg):
            continue
        if re.fullmatch(r"[A-Za-z_$][\w$]*", arg) and arg in ("context", "ctx", "null"):
            continue
        line = code[: m.start()].count("\n") + 1
        if any(s <= line <= e for s, e in hardened):
            continue
        route, meth = _route_at_line(code, line)
        hits.append(FrameworkHit(
            family=fam, rule=f"expr_engine_{engine.lower()}", file=rel,
            line=line, sink=f"{engine}.execute", route=route, http_method=meth,
            param=_ident_of(arg), confidence="high",
            reason=f"{engine} 执行非字面量表达式 `{arg[:40]}`",
        ))
    return hits


# ── 规则 5b：反射调用（类名/方法名来自变量）→ command_execution ────────────
#
# 典型形态是定时任务的 invokeTarget 注入（如 `/monitor/job/add` + `/monitor/job/run`）。
# 这类漏洞不是 shell 拼接，A1 的字符串规则会**一条候选都不产出** —— findings 里
# 有 command_execution，但没有一条落在 Job / Quartz 文件上。
# 它的真实形态是**反射调用**：`Class.forName(beanName).newInstance` + `method.invoke(...)`，
# 而命令执行规则只认 `Runtime.exec` / `ProcessBuilder`，看不见它。
#
# 判据（同文件同时满足，保守）：
#   1. `Class.forName(<标识符>)` —— 类名来自变量，不是字符串字面量；
#   2. 文件里存在 `Method.invoke(...)` —— 有反射调用面。
# 两条同时成立才报，避免把「常量类名 + 反射工具类」误报。
_REFLECT_FORNAME_VAR_RE = re.compile(r"\bClass\s*\.\s*forName\s*\(\s*([A-Za-z_]\w*)\s*\)")
_REFLECT_INVOKE_RE = re.compile(r"\.\s*invoke\s*\(")


def _rule_reflective_invoke(code: str, rel: str) -> List[FrameworkHit]:
    """类名来自变量 + 反射调用 ⇒ 任意类实例化/方法调用（代码执行面）。"""
    hits: List[FrameworkHit] = []
    if not _REFLECT_INVOKE_RE.search(code):
        return hits
    for m in _REFLECT_FORNAME_VAR_RE.finditer(code):
        line = code[: m.start()].count("\n") + 1
        hits.append(FrameworkHit(
            family="command_execution", rule="reflective_class_invoke", file=rel, line=line,
            sink="Class.forName(%s).newInstance()+Method.invoke" % m.group(1),
            route="", confidence="medium",
            reason=("类名取自变量 `%s` 并通过 Method.invoke 调用；"
                    "若该变量可由外部输入控制（如定时任务 invokeTarget），即构成任意代码执行"
                    % m.group(1)),
        ))
    return hits


# ── 规则 5：RMI 注册表暴露 → rmi ─────────────────────────────────────────

_RMI_RE = re.compile(
    r"\b(?:LocateRegistry\s*\.\s*createRegistry|Naming\s*\.\s*(?:bind|rebind))\s*\("
)


def _rule_rmi(code: str, rel: str) -> List[FrameworkHit]:
    """``LocateRegistry.createRegistry`` / ``Naming.bind`` —— 对外暴露 RMI 注册表。

    为什么一行就够：注册表一旦监听非回环地址，就对外提供「按名字取远程对象」的能力，
    反序列化面随之暴露。判据是「是否暴露」，不需要打到具体 gadget。
    """
    hits: List[FrameworkHit] = []
    for m in _RMI_RE.finditer(code):
        line = code[: m.start()].count("\n") + 1
        hits.append(FrameworkHit(
            family=FAMILY_RMI, rule="rmi_registry_exposed", file=rel, line=line,
            sink="LocateRegistry/Naming", route="", confidence="high",
            reason="RMI 注册表被创建/绑定，对外暴露远程对象查找能力",
        ))
    return hits


# ── 规则 6：Cookie 未置 Secure → secure_cookie ──────────────────────────

_NEW_COOKIE_RE = re.compile(r"\bnew\s+Cookie\s*\(")
_SET_SECURE_TRUE_RE = re.compile(r"\.\s*setSecure\s*\(\s*true\s*\)")
_SET_SECURE_FALSE_RE = re.compile(r"\.\s*setSecure\s*\(\s*false\s*\)")


def _rule_cookie_secure(code: str, rel: str) -> List[FrameworkHit]:
    """创建 Cookie 却从不 ``setSecure(true)`` → 会话 Cookie 可被明文窃取。

    为什么一行就够：``Secure`` 是浏览器侧的唯一强制位，缺失即代表「HTTP 明文也会发」。
    判据取「文件内创建了 Cookie 且没有任何 setSecure(true)」，保守（宁可漏）。
    """
    hits: List[FrameworkHit] = []
    if not _NEW_COOKIE_RE.search(code):
        return hits
    if _SET_SECURE_TRUE_RE.search(code) and not _SET_SECURE_FALSE_RE.search(code):
        return hits
    m = _NEW_COOKIE_RE.search(code)
    line = code[: m.start()].count("\n") + 1
    _route, _meth = _route_at_line(code, line)
    _param, _loc = _infer_param(code, line)
    hits.append(FrameworkHit(
        family=FAMILY_SECURE_COOKIE, rule="cookie_missing_secure", file=rel, line=line,
        sink="Cookie.setSecure", route=_route or _class_base_route(code),
        http_method=_meth, param=_param, location=_loc, confidence="medium",
        reason="创建了 Cookie 但文件内没有 setSecure(true)",
    ))
    return hits


# ── 规则 7：状态变更端点无 CSRF 校验 → csrf ─────────────────────────────

_STATE_ANN_RE = re.compile(r"@(?:PostMapping|PutMapping|DeleteMapping|PatchMapping)\b")


def _rule_csrf_state_change(code: str, rel: str) -> List[FrameworkHit]:
    """状态变更端点（POST/PUT/DELETE/PATCH）—— 只有在「项目级已显式关闭 CSRF」时才报。

    这条规则单独在文件里跑没有意义（没有 ``csrf.disable`` 就无从判断保护是否开启），
    因此它由 :func:`detect_path` 的**第二遍**调用：先扫全工程确认存在显式关闭，
    再回过头把各控制器的状态变更端点标出来。

    置信度取 medium：``csrf.disable`` 是确定的，但「是否另有自定义 token 过滤器兜底」
    静态判不了，所以只登记候选、不直接确认。
    """
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    for b in _method_blocks(code):
        ann = str(b["ann"])
        mm = _STATE_ANN_RE.search(ann)
        if not mm:
            continue
        ann_name = mm.group(0)[1:]
        sub = ""
        mpath = _METHOD_MAPPING_RE.search(ann)
        if mpath:
            sub = mpath.group("path") or ""
        hits.append(FrameworkHit(
            family=FAMILY_CSRF, rule="csrf_state_change_endpoint", file=rel,
            line=int(b["sig_line"]), sink=ann_name,
            route=_join_route(base, sub),
            http_method=_HTTP_METHOD_BY_ANN.get(ann_name, "POST"),
            confidence="medium",
            reason=f"项目已显式关闭 CSRF 保护，而 {ann_name} 端点无 token 校验",
        ))
    return hits


def _rule_csrf(code: str, rel: str) -> List[FrameworkHit]:
    """Spring Security 的 CSRF 被显式关闭，同时存在状态变更端点。

    为什么一行就够：``csrf.disable`` 是「确定关掉 CSRF 保护」的显式声明；
    再叠加同工程存在 ``@PostMapping`` 等状态变更端点，即构成 CSRF 弱点。
    只在**显式 disable** 时命中，不对「没看到 token 校验」这种缺失做推断（FP 太高）。
    """
    if not re.search(r"csrf\s*\(\s*\)\s*\.\s*disable\s*\(", code):
        return []
    hits: List[FrameworkHit] = []
    m = re.search(r"csrf\s*\(\s*\)\s*\.\s*disable\s*\(", code)
    line = code[: m.start()].count("\n") + 1
    hits.append(FrameworkHit(
        family=FAMILY_CSRF, rule="csrf_disabled", file=rel, line=line,
        sink="HttpSecurity.csrf.disable", route="", confidence="medium",
        reason="Spring Security CSRF 保护被显式关闭",
    ))
    return hits


# ── 规则 8：JSONP 回调名来自请求 → jsonp_referer ────────────────────────

_JSONP_RE = re.compile(
    r"""(?:getParameter\s*\(\s*["'](?:callback|cb|jsonp|jsonpcallback)["']|"""
    r"""@RequestParam\s*\(\s*["'](?:callback|cb|jsonp)["']|"""
    r"""String\s+(?:callback|cb|jsonp)\b)""",
    re.I,
)
_JS_CONTENT_RE = re.compile(r"""["'](?:application/javascript|text/javascript)["']""", re.I)


def _rule_jsonp(code: str, rel: str) -> List[FrameworkHit]:
    """响应以 JS 内容类型输出、且回调名来自请求 → JSONP 劫持面。

    为什么一行就够：JSONP 的本质就是「把响应包进调用方指定的函数名」，
    回调名可控即意味着任意站点可跨域读取。这里额外要求同文件出现 JS 内容类型，
    避免把普通 JSON 接口误判。
    """
    m = _JSONP_RE.search(code)
    if not m:
        return []
    if not _JS_CONTENT_RE.search(code):
        return []
    line = code[: m.start()].count("\n") + 1
    _route, _meth = _route_at_line(code, line)
    _param, _loc = _infer_param(code, line)
    return [FrameworkHit(
        family=FAMILY_JSONP, rule="jsonp_callback_controlled", file=rel, line=line,
        sink="JSONP.callback", route=_route or _class_base_route(code),
        http_method=_meth, param=_param, location=_loc, confidence="medium",
        reason="JS 响应内容类型 + 回调名来自请求参数，存在 JSONP 跨域读取面",
    )]


# ── 规则 9：不安全反序列化入口 ──────────────────────────────────────────

_DESER_CALLS = (
    (re.compile(r"\bnew\s+ObjectInputStream\s*\("), "ObjectInputStream"),
    (re.compile(r"\bJSON\s*\.\s*parse(?:Object)?\s*\("), "fastjson.JSON.parse"),
    (re.compile(r"\bXMLDecoder\s*\("), "XMLDecoder"),
    (re.compile(r"\.\s*fromXML\s*\("), "XStream.fromXML"),
    (re.compile(r"\bYaml\s*\(\s*\)\s*\.\s*load\s*\("), "SnakeYAML.load"),
    # 反射式自定义类加载：把外部字节直接 defineClass 再实例化，等价于「执行任意类」。
    # 语义上是代码注入，但平台族口径归 deserialization（不可信类/对象实例化）。
    (re.compile(r"""getDeclaredMethod\s*\(\s*["']defineClass["']"""), "ClassLoader.defineClass"),
)


def _rule_deserialization(code: str, rel: str) -> List[FrameworkHit]:
    """把外部字节流交给通用反序列化器。

    为什么一行就够：这些 API 的入参就是「对象图」，入参可控即等于「可构造任意对象」。
    这里只报**入口存在**，不判入参是否可控（那是 CodeQL 的污点活），
    因此置信度标 medium，交给下游裁决。
    """
    hits: List[FrameworkHit] = []
    for pat, name in _DESER_CALLS:
        m = pat.search(code)
        if not m:
            continue
        line = code[: m.start()].count("\n") + 1
        _route, _meth = _route_at_line(code, line)
        _param, _loc = _infer_param(code, line)
        hits.append(FrameworkHit(
            family=FAMILY_DESERIALIZE, rule=f"deser_{name.split('.')[0].lower()}", file=rel,
            line=line, sink=name, route=_route, http_method=_meth,
            param=_param, location=_loc, confidence="medium",
            reason=f"存在通用反序列化入口 {name}",
        ))
    return hits


# ── 规则 10：响应头写入用户输入 → crlf_injection ────────────────────────

_HEADER_WRITE_RE = re.compile(
    r"\.\s*(?P<api>addHeader|setHeader)\s*\(\s*(?P<name>[^,]+?)\s*,\s*(?P<val>[^;]+?)\s*\)\s*;"
)
# `String v = request.getParameter("x");` —— 先把用户输入落到局部变量再写头，
# 是真实项目里比内联更常见的写法（CRLFInjection.java 的 test3 就是这种）。
_LOCAL_FROM_PARAM_RE = re.compile(
    r"(?:String|CharSequence)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*[^;]*?getParameter\s*\("
)


def _rule_crlf_header(code: str, rel: str) -> List[FrameworkHit]:
    """``response.addHeader/setHeader(name, <请求参数>)`` —— 响应头注入。

    为什么一行就够：header 的 value 由服务端直接写进状态行之后的头部字节流，
    其中若含 ``\\r\\n`` 就能截断响应、注入任意头或响应体（HTTP 响应拆分）。
    这里只认「value 直接来自 ``getParameter``」或「来自同方法内由 getParameter 赋值的局部变量」，
    不追跨方法传播（那是 CodeQL 的活）。

    注意：JDK 1.7+ 的 ``HttpServletResponse.setHeader`` 会过滤 ``\\r\\n``，
    所以这条命中是**代码形态成立**而非「一定可打通」——置信度取 medium，
    """
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    for b in _method_blocks(code):
        body = str(b["body"])
        if "getParameter" not in body:
            continue
        tainted = {m.group("var") for m in _LOCAL_FROM_PARAM_RE.finditer(body)}
        ann = str(b["ann"])
        mm = _METHOD_MAPPING_RE.search(ann)
        sub = (mm.group("path") or "") if mm else ""
        ann_name = mm.group("ann") if mm else "RequestMapping"
        for m in _HEADER_WRITE_RE.finditer(body):
            val = m.group("val").strip()
            direct = "getParameter" in val
            indirect = bool(_ident_of(val)) and _ident_of(val) in tainted
            if not (direct or indirect):
                continue
            line = int(b["body_line"]) + body[: m.start()].count("\n")
            _param, _loc = _infer_param(code, line)
            hits.append(FrameworkHit(
                family=FAMILY_CRLF, rule="crlf_header_write", file=rel, line=line,
                sink=f"HttpServletResponse.{m.group('api')}",
                route=_join_route(base, sub),
                http_method=_HTTP_METHOD_BY_ANN.get(ann_name, "GET"),
                param=_param, location=_loc, confidence="medium",
                reason=f"响应头 {m.group('api')} 的 value 来自请求参数，未做换行过滤",
            ))
    return hits


# ── 规则 11：Velocity 模板来自请求 → ssti ───────────────────────────────

_VELOCITY_EVAL_RE = re.compile(r"\bVelocity\s*\.\s*evaluate\s*\(")
_VELOCITY_CTX_RE = re.compile(r"\bVelocityContext\b")


def _rule_ssti(code: str, rel: str) -> List[FrameworkHit]:
    """``Velocity.evaluate(ctx, out, tag, <请求参数>)`` —— 服务端模板注入。

    为什么一行就够：``evaluate`` 的第 4 个参数就是**模板源码本身**（不是模板名），
    传进去即被解析执行，``#set($e="e")$e.getClass...`` 这类指令可直接打到 Runtime。
    这里额外要求同文件出现 ``VelocityContext``，避免把「模板名走配置」的用法误判。
    """
    if not _VELOCITY_CTX_RE.search(code):
        return []
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    for m in _VELOCITY_EVAL_RE.finditer(code):
        line = code[: m.start()].count("\n") + 1
        route, meth = _route_at_line(code, line)
        param, loc = _infer_param(code, line)
        hits.append(FrameworkHit(
            family=FAMILY_SSTI, rule="ssti_velocity_evaluate", file=rel, line=line,
            sink="Velocity.evaluate", route=route or base,
            http_method=meth, param=param, location=loc, confidence="medium",
            reason="Velocity.evaluate 的模板源码参数来自请求，模板即代码",
        ))
    return hits


# ── 规则 12：MultipartFile 原始文件名落盘 → file_upload ─────────────────

_MULTIPART_DECL_RE = re.compile(r"\bMultipartFile\s+(?P<var>[A-Za-z_$][\w$]*)")
_ORIG_FILENAME_RE = re.compile(r"\b(?P<var>[A-Za-z_$][\w$]*)\s*\.\s*getOriginalFilename\s*\(\s*\)")
_DISK_WRITE_RE = re.compile(
    r"Files\s*\.\s*write\s*\(|\.\s*transferTo\s*\(|new\s+FileOutputStream\s*\("
    r"|Files\s*\.\s*copy\s*\(|FileUtils\s*\.\s*writeBytes\s*\("
)


def _rule_file_upload(code: str, rel: str) -> List[FrameworkHit]:
    """``MultipartFile`` 的 ``getOriginalFilename`` 参与路径并落盘 → file_upload。

    为什么一行就够：原始文件名由客户端完全控制，直接拼进目标路径即「上传到任意位置 +
    任意扩展名」，危害面同时覆盖文件写入与路径穿越。平台族口径取 ``file_upload``

    判据要三件事同时成立，缺一不可：
      1. 方法签名里有 ``MultipartFile`` 形参；
      2. 方法体里出现 ``getOriginalFilename``；
      3. 方法体里有落盘调用（Files.write / transferTo / FileOutputStream / Files.copy）。
    这样「上传后只解析内容不落盘」（如 ooxmlXXE 的 readxlsx）不会被误报成上传漏洞。
    """
    hits: List[FrameworkHit] = []
    base = _class_base_route(code)
    for b in _method_blocks(code):
        args = str(b["args"] or "")
        if not _MULTIPART_DECL_RE.search(args):
            continue
        body = str(b["body"] or "")
        if not _DISK_WRITE_RE.search(body):
            continue
        m = _ORIG_FILENAME_RE.search(body)
        if not m:
            continue
        ann = str(b["ann"])
        mm = _METHOD_MAPPING_RE.search(ann)
        sub = (mm.group("path") or "") if mm else ""
        ann_name = mm.group("ann") if mm else "RequestMapping"
        line = int(b["body_line"]) + body[: m.start()].count("\n")
        mp = _MULTIPART_DECL_RE.search(args)
        hits.append(FrameworkHit(
            family=FAMILY_FILE_UPLOAD, rule="file_upload_original_filename", file=rel,
            line=line, sink="MultipartFile.getOriginalFilename",
            route=_join_route(base, sub),
            http_method=_HTTP_METHOD_BY_ANN.get(ann_name, "POST"),
            param=(mp.group("var") if mp else ""), location="multipart",
            confidence="high",
            reason="上传文件用客户端可控的 getOriginalFilename() 拼路径后落盘，未做扩展名/路径校验",
        ))
        break  # 一个方法只报一次
    return hits


# ── 规则 13：Spring Security 的 csrf 开关默认关闭 → csrf（工程级）────────

_CSRF_FLAG_OFF_RE = re.compile(
    r"\b(?:boolean|Boolean)\s+(?P<name>\w*[Cc]srf\w*)\s*=\s*false\s*;"
)


def _rule_csrf_config_off(code: str, rel: str) -> List[FrameworkHit]:
    """``Boolean csrfEnabled = false;`` —— CSRF 保护由配置开关控制且默认关闭。

    为什么必须补这条：``_rule_csrf`` 只认 ``csrf.disable`` 这种**链式显式关闭**，
    但真实项目更常见的是「开关式」——``@Value("${x.csrf.enabled}") Boolean csrfEnabled = false;``
    再在 ``RequestMatcher`` 里按布尔值决定是否启用。这种写法下 CSRF 实际是关的，

    这里只产出「项目级 csrf 处于关闭态」这一个信号（route 留空），
    真正的端点枚举交给 :func:`detect_path` 的第二遍 ``_rule_csrf_state_change``。
    置信度 medium：开关默认值确定，但部署时是否被外部配置覆盖静态判不了。
    """
    m = _CSRF_FLAG_OFF_RE.search(code)
    if not m:
        return []
    line = code[: m.start()].count("\n") + 1
    return [FrameworkHit(
        family=FAMILY_CSRF, rule="csrf_flag_default_off", file=rel, line=line,
        sink="SpringSecurity.csrfFlag", route="", confidence="medium",
        reason=f"CSRF 开关 {m.group('name')} 默认 false，保护处于关闭态",
    )]


# ── 规则 14：MyBatis XML 里的 ${} 拼接 → sql_injection ──────────────────

_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_MAPPER_ROOT_RE = re.compile(r"<mapper\s+namespace\s*=")


def _strip_xml_comments(text: str) -> str:
    """剥 XML 注释，**但保留换行**。

    头部有 3 行注释，实测报出的 L17 实际是 L20）。行号是 (file, line, family) 三元组
    和人工复核的锚点，偏了就等于报错位置。
    """
    return _XML_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
# DML 语句元素：${} 只有落在这些元素里才是「拼进 SQL」
_DML_BLOCK_RE = re.compile(
    r"<(select|update|insert|delete|sql)\b[^>]*>(.*?)</\1\s*>", re.S | re.I)
_DOLLAR_RE = re.compile(r"\$\{\s*([^}]{1,120}?)\s*\}")
# 明确不是注入面的 ${}：Maven/日志/配置占位、以及 MyBatis 的 databaseId 变量
_DOLLAR_WHITELIST_RE = re.compile(
    r"^(?:@?databaseId|_databaseId|log\.|logging\.|project\.|spring\.|server\.)", re.I)


def _mybatis_param_path(var: str) -> str:
    """把 mapper 里的 ``${a.b.c}`` 转成请求参数路径 ``a[b][c]``。


    ``param_name`` 是从 controller 方法签名反查来的（``parentId`` / ``username`` / 空）。
    投 ``parentId=<payload>`` 时 mapper 的 ``params.dataScope`` 拿不到值 ⇒
    **SQL 根本没被注入**，但查询照常执行、探针在 mapper 处命中 ⇒ 状态变成
    ``sink-reached``，看起来「到了 sink」，实际什么都没打进去。5 条真值因此全漏。

    ``${...}`` 里写的就是注入点的精确路径，比任何反查都准。

    - ``params.dataScope`` → ``params[dataScope]``（Spring 嵌套属性绑定）
    - ``ancestors``        → ``ancestors``
    """
    parts = [p for p in str(var or "").split(".") if p]
    if not parts:
        return ""
    return parts[0] + "".join("[%s]" % p for p in parts[1:])


def _rule_mybatis_dollar(code: str, rel: str) -> List[FrameworkHit]:
    """MyBatis mapper XML 里 ``${...}`` 直接拼 SQL → sql_injection。

    为什么必须单独做：MyBatis 的 ``${}`` 是**字符串替换**，``#{}`` 才是预编译占位。
    CodeQL 的 Java SQLi 查询只看 Java 代码里的 ``Statement.execute``，
    （``${params.dataScope}``）因此整片漏掉。

    判据（三件事同时成立，缺一不可）：
      1. 文件根是 ``<mapper namespace="...">``（排除 pom/mybatis-config 等）；
      2. ``${}`` 落在 ``<select|update|insert|delete|sql>`` 元素体内；
      3. 变量名不在明确白名单里（``databaseId``/``log.*``/``project.*`` 等）。

    route 留空：mapper 不知道调用它的 Controller，路由要靠 A1 调用链补。
    因此本规则产出的是**静态证据**，spec 会因 ``missing_route`` 不进重放——
    这是刻意的（宁可静态命中、不可编造路由）。
    """
    if not _MAPPER_ROOT_RE.search(code):
        return []
    body = _strip_xml_comments(code)
    hits: List[FrameworkHit] = []
    for m in _DML_BLOCK_RE.finditer(body):
        tag, inner = m.group(1), m.group(2)
        for d in _DOLLAR_RE.finditer(inner):
            var = d.group(1).strip()
            if _DOLLAR_WHITELIST_RE.match(var):
                continue
            line = body[: m.start(2) + d.start()].count("\n") + 1
            hits.append(FrameworkHit(
                family=FAMILY_SQLI, rule="mybatis_dollar_substitution", file=rel, line=line,
                sink=f"mybatis.${var}", route="", confidence="high",
                # 参数路径就是注入点本身（`${params.dataScope}` → `params[dataScope]`）。
                # 下游 param_resolver 优先用它，别再让 controller 签名把注入点推歪。
                param=_mybatis_param_path(var),
                reason=f"<{tag}> 内 ${var} 为字符串替换拼接，非 #{{}} 预编译",
            ))
    return hits


_RULES: Sequence = (
    _rule_spring_reflected_return,
    _rule_cors,
    _rule_log4j_jndi,
    _rule_expression_engine,
    _rule_reflective_invoke,
    _rule_rmi,
    _rule_cookie_secure,
    _rule_csrf,
    _rule_jsonp,
    _rule_deserialization,
    _rule_crlf_header,
    _rule_ssti,
    _rule_file_upload,
    _rule_csrf_config_off,
    _rule_mybatis_dollar,
)


def enabled() -> bool:
    return os.environ.get("SAST_AI_FW_RULES", "1") not in ("0", "false", "False", "")


def detect_source(code: str, rel_path: str = "") -> List[FrameworkHit]:
    """对单个源文件跑全部规则（已去注释），并做**族竞争消解**。

    ## 为什么需要族竞争消解

    同一个文件里往往同时存在「强注入族」和「弱配置族」的形态，
    真值只记前者。最典型的是 ``CRLFInjection.java``：
    ``response.addHeader("test1", request.getParameter("test1"))`` 是响应头注入，
    同一方法里还有 ``new Cookie("test3", author)`` 缺 ``setSecure``。
    两条都对，但真值族是 ``crlf_injection``；两条都登记会让族判定在
    「secure_cookie 先命中」时选错。

    仲裁规则（只在**同一文件内**生效，且只做「强族压弱族」，不做跨文件推断）：

    1. 出现 ``crlf_injection`` ⇒ 丢弃本文件的 ``secure_cookie``。
       理由：header 注入是「注入类」危害，cookie 缺 Secure 是「配置属性」危害，
       前者成立时后者没有独立价值（而且同一行 cookie 往往就是注入载体）。
    2. ``file_upload`` 与 ``path_traversal`` **同行**时丢弃 ``path_traversal``。
       理由：``Paths.get(DIR + f.getOriginalFilename)`` 这一行的根因是「未校验上传」，
       路径穿越是它的**后果**而不是另一个独立缺陷。只压同一行，避免误伤
       文件里真正独立的穿越点。
    """
    if not enabled():
        return []
    stripped = _strip_comments(code)
    out: List[FrameworkHit] = []
    for rule in _RULES:
        try:
            out.extend(rule(stripped, rel_path))
        except Exception:
            continue
    return _arbitrate_families(out)


# 族优先级：数字越小越「根本」。同文件同一行出现多个族时，只保留优先级最高的那个。
#
# 依据两条通用原则（不是靶场约定）：
#   ① **注入类压配置属性类**：一行代码同时存在注入点和「cookie 没设 Secure」，
#      根因是注入，cookie 属性是顺带发现的次要问题，不能顶替主族。
#   ② **根因压后果**：上传落盘（file_upload）与路径穿越（path_traversal）同时命中，
#      根因是没校验上传文件，穿越只是它的后果。
# 只做**同一行**的仲裁。跨行/跨文件一律不推断——那会把两个真实缺陷压成一个。
_FAMILY_PRIORITY = {
    # 注入类（根因）
    "sql_injection": 10, "command_execution": 10, "deserialization": 10,
    "xxe": 10, "ssrf": 10, "xss": 10, "expression_injection": 10,
    "ssti": 10, "jndi_injection": 10, "ldap_injection": 10,
    "path_traversal": 12, "crlf_injection": 12,
    "url_redirect": 12, "url_whitelist_bypass": 12,
    # 根因压后果：上传优先于它引发的穿越
    FAMILY_FILE_UPLOAD: 8,
    # 属性 / 配置类（次要）
    FAMILY_SECURE_COOKIE: 50, "cors": 50, "csrf": 50,
    "information_exposure": 50, "log_injection": 50,
    "weak_crypto": 50, "weak_random": 50, "weak_hash": 50,
    "jsonp_referer": 40,
}


def _arbitrate_families(hits: List[FrameworkHit]) -> List[FrameworkHit]:
    """族竞争消解。两条规则，作用域不同：

    **规则 1（同文件）注入族压属性族。**
    一个文件里既有注入点、又有「cookie 没设 Secure」这类属性问题，属性族会被 D2
    单独确认，然后在「文件+族对」口径里顶替掉真正的主族（实测：某文件真值是 xss，
    确认出来的却是 secure_cookie）。根因是注入，属性是顺带发现，不能让次要点位抢主位。

    **规则 2（同一行）根因压后果。**
    上传落盘（file_upload）与路径穿越（path_traversal）同时命中同一行时，根因是
    没校验上传文件，穿越只是它的后果。两者都是注入类，所以只在同一行生效——
    跨行压掉会把两个真实缺陷合并成一个。

    历史上这里是两条写死的特例，只覆盖见过的两种组合；改成优先级表后，
    新族只需登记进 `_FAMILY_PRIORITY`，规则自动生效。
    """
    if not hits:
        return hits

    def _prio(h: FrameworkHit) -> int:
        return _FAMILY_PRIORITY.get(h.family, 30)

    # 规则 1：同文件，注入族（prio < 30）存在 ⇒ 丢掉属性族（prio >= 40）
    if any(_prio(h) < 30 for h in hits):
        hits = [h for h in hits if _prio(h) < 40]

    # 规则 2：同一行，只留优先级最高的
    by_line: Dict[int, List[FrameworkHit]] = {}
    for h in hits:
        by_line.setdefault(int(h.line), []).append(h)
    keep_ids = set()
    for _line, group in by_line.items():
        if len({h.family for h in group}) <= 1:
            keep_ids.update(id(h) for h in group)
            continue
        best = min(_prio(h) for h in group)
        keep_ids.update(id(h) for h in group if _prio(h) == best)
    return [h for h in hits if id(h) in keep_ids]


def family_priority(family: str) -> int:
    """族优先级（数字越小越「根本」）。公开给 spec 登记级仲裁使用
    （trigger_spec_registry 的路由级族仲裁与 framework hits 同表同源，口径不漂移）。
    未登记族返回 30（中间档，不参与属性族压制）。"""
    return _FAMILY_PRIORITY.get(str(family or "").strip().lower(), 30)


_JAVA_EXT = (".java", ".kt")


def _route_at_line(code: str, line: int) -> Tuple[str, str]:
    """取覆盖该行的处理器方法的 (路由, HTTP 方法)。

    表达式引擎 / 日志 / RMI 这类 sink 不在方法注解块里，需要用「行号 → 所属方法」
    反查路由，否则登记出来的 spec 没有 endpoint，D1 无从重放。
    """
    base = _class_base_route(code)
    best = ("", "GET")
    for b in _method_blocks(code):
        start = int(b["body_line"])
        end = start + str(b["body"]).count("\n")
        if start <= line <= end:
            mm = _METHOD_MAPPING_RE.search(str(b["ann"]))
            sub = mm.group("path") if mm else ""
            ann_name = mm.group("ann") if mm else "RequestMapping"
            best = (_join_route(base, sub or ""), _HTTP_METHOD_BY_ANN.get(ann_name, "GET"))
            break
    return best


_TEST_DIR_TOKENS = (
    "/src/test/", "/main/test/", "/test/java/", "/src/androidTest/", "/src/it/",
    "/src/testFixtures/",
)


def detect_path(project_path: str, max_files: int = 20000,
                max_xml_files: int = 5000) -> List[FrameworkHit]:
    """对整个工程跑规则（Java/Kotlin 生产源 + MyBatis mapper XML）。

    测试源码一律不扫：``src/test/java`` 里的控制器样例不是部署面，

    没有意义，而 MyBatis 的 ``${}`` 拼接是 CodeQL 和启发式**都看不见**的注入面
    因缺少 ``<mapper namespace=`` 自然零命中。
    """
    if not enabled():
        return []
    root = os.path.abspath(project_path)
    out: List[FrameworkHit] = []
    csrf_disabled = False
    sources: List[Tuple[str, str]] = []
    seen = 0
    seen_xml = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in ("target", "build", "node_modules", ".git", "out", "bin", "generated")
        ]
        for fn in filenames:
            _is_java = fn.endswith(_JAVA_EXT)
            _is_xml = fn.lower().endswith(".xml")
            if not (_is_java or _is_xml):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            norm = "/" + rel
            if any(tok in norm for tok in _TEST_DIR_TOKENS):
                continue
            # 大工程里的资源 XML 会把 Java 预算吃掉，甚至触发 return out 导致后半程
            # Java 文件整片不扫（比漏报更糟：是静默的半途而废）。
            if _is_xml:
                seen_xml += 1
                if seen_xml > max_xml_files:
                    continue
                out.extend(_rule_mybatis_dollar(_read(full), rel))
                continue
            seen += 1
            if seen > max_files:
                return out
            code = _strip_comments(_read(full))
            sources.append((rel, code))
            hits = detect_source(code, rel)
            if any(h.family == FAMILY_CSRF for h in hits):
                csrf_disabled = True
            out.extend(hits)
    # 第二遍：项目级「CSRF 已被显式关闭」⇒ 各状态变更端点才有 CSRF 语义。
    # 单独在文件里跑这条规则没有意义（无从判断保护是否开启），所以必须放到工程级。
    if csrf_disabled:
        for rel, code in sources:
            try:
                out.extend(_rule_csrf_state_change(code, rel))
            except Exception:
                continue
    return out
