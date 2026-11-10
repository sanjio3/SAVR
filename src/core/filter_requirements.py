"""过滤器前置 header 抽取（2026-11-02）。

## 为什么需要

很多应用在 `Filter` 里**校验请求头**，缺了就直接拒绝或走另一条分支：

    if (!referer.contains("joychou.com")) { response.sendError(403); return; }
    if (!allowedOrigins.contains(request.getHeader("Origin"))) { return; }

这类端点即使参数、编码、方法全对，也会因为「没带 Referer / Origin」而**进不到业务代码**。
实测 jsc 的 `RefererFilter` 就属于这一类（jsonp 族曾因此整族 no-arrival）。

## 做法（全确定性，不需要 LLM）

1. 找 `implements Filter` / `extends OncePerRequestFilter` 的类；
2. 从 `doFilter` 方法体抽 `request.getHeader("X")` / `getHeaders("X")` 的**字面量**；
3. 判定「读」还是「校验」：该 header 的变量出现在
   `if (...)` / `.equals(` / `.contains(` / `.matches(` / `.startsWith(` / `.indexOf(` 里 ⇒ 校验；
4. 校验时把条件里的字符串字面量当**值域**（`contains("joychou.com")` ⇒ 用 `http://joychou.com/`）；
5. 结合 filter 的 urlPatterns（`@WebFilter` / `addUrlPatterns`）把要求归到路由上。

跨方法/跨类的复杂校验（`ReferrerPolicy.validate(req)`）静态抽不出来，留给 A2 兜底 ——
但那是少数，绝大多数就是一行 `getHeader("X").contains("...")`。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

_HEADER_READ_RE = re.compile(
    r"\.\s*getHeader\s*\(\s*\"([A-Za-z0-9\-_]+)\"\s*\)|"
    r"\.\s*getHeaders\s*\(\s*\"([A-Za-z0-9\-_]+)\"\s*\)"
)
_FILTER_CLASS_RE = re.compile(r"implements\s+[^{]*\bFilter\b|extends\s+OncePerRequestFilter")
_WEBFILTER_RE = re.compile(r"@WebFilter\s*\(([^)]*)\)", re.S)
_URLPATTERN_ARG_RE = re.compile(r"urlPatterns?\s*=\s*\{?\s*\"([^\"]+)\"")
_ADD_PATTERN_RE = re.compile(r"addUrlPatterns?\s*\(\s*\"([^\"]+)\"")
_STRING_LIT_RE = re.compile(r"\"([^\"\\]{2,80})\"")

# 「校验」的判据：header 变量出现在这些上下文里
_CHECK_CTX = (".equals(", ".contains(", ".matches(", ".startsWith(", ".indexOf(", "equalsIgnoreCase(")
# 校验时常见的「负向」写法：!x.contains / x == null 后 return —— 我们只取值域，不判方向
_NEGATIVE_HINT = ("!=", "!", "== null", "isEmpty()")

# ── 配置感知（2026-11-02）─────────────────────────────────────────────────
#
# 只从过滤器源码抽是不够的：jsc 的 ReferFilter 只写
#     String refer = request.getHeader("referer");
#     for (String uri : WebConfig.getReferUris()) { ... }
# 真正的「校验哪些路由 / 允许哪些 host」全在配置里：
#     joychou.security.referer.host = joychou.org, joychou.com
#     joychou.security.referer.uri  = /jsonp/**
#     joychou.security.referer.enabled = false
# 不读配置就只能「给所有路由塞同源 Referer」——而那个值**过不了 host 白名单**，
# 反而让本来能过的 jsonp 端点失败。所以必须把配置一起读进来。

_PROP_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:]\s*(.*?)\s*$")
_YML_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*:\s*(.+?)\s*$")
_DISABLED_VALUES = ("false", "0", "off", "no")
_VALUE_KEYS = ("host", "hosts", "domain", "domains", "whitelist", "allow", "allowed", "origin", "origins")
_SCOPE_KEYS = ("uri", "uris", "path", "paths", "url", "urls", "pattern", "patterns")
_ENABLED_KEYS = ("enabled", "enable", "check.enabled")


def load_app_config(files: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """把项目里的 `application*.properties` / `*.yml` 读成扁平 kv（key 原样保留小写）。"""
    cfg: Dict[str, str] = {}
    for f in files or []:
        name = str((f or {}).get("path") or (f or {}).get("rel_path") or "").lower()
        if not (name.endswith(".properties") or name.endswith(".yml") or name.endswith(".yaml")):
            continue
        for raw in str((f or {}).get("content") or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            m = _PROP_LINE_RE.match(line) or _YML_LINE_RE.match(line)
            if not m:
                continue
            key, val = m.group(1).strip().lower(), m.group(2).strip().strip('"').strip("'")
            if key and val:
                cfg[key] = val
    return cfg


def _split_values(raw: str) -> List[str]:
    return [x.strip() for x in re.split(r"[,;\s]+", str(raw or "")) if x.strip()]


def _config_disabled(cfg: Dict[str, str], header: str) -> bool:
    """配置是否明确「关闭」了该 header 的校验（所有相关开关都是 false）。"""
    h = str(header or "").lower()
    if not h:
        return False
    flags: List[bool] = []
    for key, val in (cfg or {}).items():
        if h not in key and not (h == "referer" and "refer" in key):
            continue
        if key.rsplit(".", 1)[-1] in _ENABLED_KEYS:
            flags.append(str(val).strip().lower() not in _DISABLED_VALUES)
    return bool(flags) and not any(flags)


def _config_requirements(cfg: Dict[str, str], header: str, pattern: str,
                         file: str = "") -> List[FilterRequirement]:
    """按配置补齐「该 header 的值域与作用范围」。

    匹配规则（通用，不写死某个项目的 key）：
      · key 里含该 header 名（referer/origin/...）
      · 以 host/domain/whitelist 结尾 → 值域
      · 以 uri/url/pattern 结尾 → 作用范围
      · 以 enabled 结尾且值为 false → 该 header 的校验关闭，直接不要求
    """
    h = str(header or "").lower()
    if not h:
        return []
    values: List[str] = []
    scopes: List[str] = []
    _flags: List[bool] = []
    for key, val in (cfg or {}).items():
        if h not in key and not (h == "referer" and "refer" in key):
            continue
        tail = key.rsplit(".", 1)[-1]
        if tail in _ENABLED_KEYS:
            _flags.append(str(val).strip().lower() not in _DISABLED_VALUES)
            continue
        if tail in _VALUE_KEYS:
            values.extend(_split_values(val))
        elif tail in _SCOPE_KEYS:
            scopes.extend(_split_values(val))
    # 同一个 header 可能有多个开关（全局 `referer.enabled=false` + 专用
    # `jsonp.referer.check.enabled=true`）。任一为 true 即视为开启 ——
    # jsc 正是这种：全局关、jsonp 专用开。
    if _flags and not any(_flags):
        return []
    if not values and not scopes:
        return []
    out: List[FilterRequirement] = []
    for sc in (scopes or [pattern or "/*"]):
        out.append(FilterRequirement(pattern=sc, header=header, kind="check",
                                     values=values[:5], file=file, line=0))
    return out


@dataclass
class FilterRequirement:
    """一条「路由 → 需要的请求头」要求。"""
    pattern: str = ""          # urlPattern（如 /jsonp/*、/*、/api/**）
    header: str = ""           # Referer / Origin / X-Requested-With
    kind: str = "read"         # read | check
    values: List[str] = field(default_factory=list)   # 校验用到的字面量（值域提示）
    file: str = ""
    line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"pattern": self.pattern, "header": self.header, "kind": self.kind,
                "values": list(self.values), "file": self.file, "line": self.line}


def _line_of(text: str, idx: int) -> int:
    return text[:idx].count("\n") + 1


def _patterns_of(code: str) -> List[str]:
    """取该 filter 的 urlPatterns（@WebFilter 优先，其次 addUrlPatterns）。"""
    pats: List[str] = []
    m = _WEBFILTER_RE.search(code)
    if m:
        arg = _URLPATTERN_ARG_RE.search(m.group(1))
        if arg:
            pats.append(arg.group(1))
        else:
            # @WebFilter("/x") 裸串形态
            bare = _STRING_LIT_RE.search(m.group(1))
            if bare:
                pats.append(bare.group(1))
    for mm in _ADD_PATTERN_RE.finditer(code):
        pats.append(mm.group(1))
    # 去重保序
    out: List[str] = []
    for p in pats:
        p = p.strip()
        if p and p not in out:
            out.append(p)
    return out


def extract_requirements(files: Sequence[Dict[str, Any]]) -> List[FilterRequirement]:
    """从项目源文件 + 配置里抽「过滤器要求的请求头」。

    两步：
      1. 源码：找 Filter 类、抽 `getHeader("X")` 字面量；
      2. **配置优先**：若 `application*.properties/yml` 里有该 header 的值域/作用范围，
         用配置覆盖源码推断（源码只能看出「读了这个头」，看不出「校验哪些路由、允许哪些值」）。
    """
    cfg = load_app_config(files)
    reqs: List[FilterRequirement] = []
    seen_headers: List[str] = []
    for f in files or []:
        code = str((f or {}).get("content") or "")
        path = str((f or {}).get("path") or (f or {}).get("rel_path") or "")
        if not code or not _FILTER_CLASS_RE.search(code):
            continue
        patterns = _patterns_of(code) or ["/*"]
        lines = code.splitlines()
        for m in _HEADER_READ_RE.finditer(code):
            header = m.group(1) or m.group(2)
            if not header:
                continue
            if header not in seen_headers:
                seen_headers.append(header)
            line_no = _line_of(code, m.start())
            # 取该行往后 12 行做「是否被校验」的判定（条件判断通常紧跟读取）
            window = "\n".join(lines[max(0, line_no - 1): line_no + 12])
            is_check = any(ctx in window for ctx in _CHECK_CTX)
            values: List[str] = []
            if is_check:
                for lit in _STRING_LIT_RE.findall(window):
                    lit = lit.strip()
                    if lit and lit != header and lit not in values:
                        values.append(lit)
            for p in patterns:
                reqs.append(FilterRequirement(pattern=p, header=header,
                                              kind="check" if is_check else "read",
                                              values=values[:5], file=path, line=line_no))

    # 配置覆盖：对每个出现过的 header，若能配出「值域 + 范围」，就用它替换源码推断
    for header in seen_headers:
        src_patterns = [r.pattern for r in reqs if r.header == header] or ["/*"]
        if _config_disabled(cfg, header):
            # 配置明确关闭 ⇒ 该 header 不再要求（源码只能看出「读了」，
            # 而配置才是「到底校不校验」的权威）。
            reqs = [r for r in reqs if r.header != header]
            continue
        cfg_reqs = _config_requirements(cfg, header, src_patterns[0])
        if not cfg_reqs:
            continue
        reqs = [r for r in reqs if r.header != header] + cfg_reqs
    return reqs


def _pattern_matches(pattern: str, route: str) -> bool:
    """把 filter 的 urlPattern 与具体 route 做匹配（支持 /*、/**、前缀、精确）。"""
    p = str(pattern or "").strip()
    r = str(route or "").strip()
    if not p or not r:
        return False
    if p in ("/*", "/**"):
        return True
    if p.endswith("/**"):
        return r.startswith(p[:-3].rstrip("/") + "/") or r == p[:-3].rstrip("/")
    if p.endswith("/*"):
        return r.startswith(p[:-2].rstrip("/") + "/")
    return p == r or r.startswith(p.rstrip("/") + "/")


def _default_value(header: str, values: List[str], base_url: str) -> str:
    """给一个「能过校验」的默认值。"""
    h = str(header or "").lower()
    base = str(base_url or "").rstrip("/")
    if values:
        v = values[0]
        if h in ("referer", "referrer"):
            return v if v.lower().startswith("http") else "http://%s/" % v.strip("/")
        return v
    if h in ("referer", "referrer"):
        return (base + "/") if base else "http://127.0.0.1/"
    if h == "origin":
        return base or "http://127.0.0.1"
    if h == "x-requested-with":
        return "XMLHttpRequest"
    return "1"


def headers_for_route(reqs: Iterable[FilterRequirement], route: str,
                      base_url: str = "") -> Dict[str, str]:
    """算出某路由需要携带的请求头。

    ## 为什么 `read` 型也要带

    「读」和「校验」的边界常常跨类：jsc 的 `ReferFilter` 只是
    `String refer = request.getHeader("referer")`，真正的判定在
    `WebConfig.getReferUris()` / `getReferSecEnabled()` 里 —— 静态抽不出「哪些路由要校验」。

    这类情况下，「应用读过这个头」就是足够强的信号：带一个**同源的合法值**
    （`Referer: <target>/`、`Origin: <target>`）不会破坏任何东西，
    但如果那个 filter 确实在校验，缺了它请求就进不到业务代码。

    所以：`check` 型用抽到的值域；`read` 型用同源默认值。两条都是「宁可多带」。
    """
    out: Dict[str, str] = {}
    for req in reqs or []:
        if not _pattern_matches(req.pattern, route):
            continue
        if req.header in out:
            continue
        out[req.header] = _default_value(req.header, req.values, base_url)
    return out


def summarize(reqs: Sequence[FilterRequirement]) -> Dict[str, int]:
    """诊断用：按 header 统计条数。"""
    out: Dict[str, int] = {}
    for r in reqs or []:
        out[r.header] = out.get(r.header, 0) + 1
    return out
