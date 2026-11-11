"""静态路由解析：Spring 注解 → controller → route 索引。

    findings 必须绑到**真实 HTTP 路由**才转得成 trigger_spec。历史上这一步靠
    A2 LLM 在语义分析时"顺便"猜一个 route/entry_method/params，结果是：

    - LLM 一挂（或 KeyError 被吞），业务族 findings 直接归零；
    - LLM 敷衍输出 "/"、"/admin/"、"/admin/," 这类残缺路由，写进 exploit_spec
      后 D2 构造请求必失败，整批 findings 被丢弃；
    - 同一条路由在不同轮次被猜成不同形态，vhash 不稳定。

    Q2 的修法：路由是**源码里的确定性事实**（@RestController/@Controller +
    类级 @RequestMapping + 方法级 @GetMapping/@PostMapping/...），不该交给 LLM 猜。
    本模块做纯静态解析（不调 LLM、不需要构建工具、不依赖 CodeQL），产出
    route 索引供 A1 阶段**前置绑定**，LLM 只做兜底。

设计要点：
    - 解析基于"去注释 + 逐行括号深度"的轻量扫描，不引入 Java 语法解析器。
      解析不了的情况一律返回空（宁缺毋滥），由调用方回落 LLM 并标记
      ``route_status='static-failed'``。
    - 文件路径跨阶段比较一律走 :mod:`src.core.path_norm`（路径双轨制：
      A1 产绝对路径、A2 产相对路径）。

典型用法::

    from src.core.route_resolver import build_route_index, resolve_route_for_finding

    index = build_route_index(files)                      # files = [{path, content}, ...]
    hit = resolve_route_for_finding(index, file=v.file, line=v.line)
    if hit:
        entry.route = hit["route"]
        entry.method = hit["method"]
        entry.params = hit["params"]
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from src.core.path_norm import normalize_path_key

__all__ = [
    "RouteParam",
    "RouteEntry",
    "RouteIndex",
    "parse_java_routes",
    "build_route_index",
    "build_route_index_from_dir",
    "resolve_route_for_finding",
    "join_route",
    "is_plausible_route",
]

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 类级：识别为 HTTP controller 的注解
_CONTROLLER_ANNOTATIONS = ("Controller", "RestController")

# 方法级：HTTP 映射注解 → HTTP 方法
_MAPPING_METHODS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
}

# 参数注解 → 参数位置（与 exploit_spec / DB 列的 param_location 口径一致）
_PARAM_LOCATION = {
    "RequestParam": "query",
    "PathVariable": "path",
    "RequestBody": "body",
    "RequestHeader": "header",
    "CookieValue": "cookie",
    "RequestPart": "form",
    "ModelAttribute": "query",
}

# 框架注入参数：不是攻击者可控输入，解析时标为 infra 且默认不进 params
_INFRA_TYPES = frozenset({
    "HttpServletRequest", "HttpServletResponse", "HttpSession", "ServletRequest",
    "ServletResponse", "Model", "ModelMap", "ModelAndView", "RedirectAttributes",
    "HttpMethod", "Principal", "Authentication", "BindingResult", "Errors",
    "WebRequest", "NativeWebRequest", "UriComponentsBuilder", "Locale",
    "HttpHeaders", "MultipartFile", "ServletContext", "SessionStatus",
})

# 权限守卫注解
_GUARD_ANNOTATIONS = ("PreAuthorize", "PostAuthorize", "PreFilter", "PostFilter",
                      "Secured", "RolesAllowed", "DenyAll", "PermitAll",
                      # 是最主要的鉴权方式，却不被识别 ⇒ 105 条管理端点
                      # 全被判成「未标注任何权限注解」的垂直越权（0 条确认）。
                      # 实测反例：SysRoleController#list 第 53 行就有 @RequiresPermissions，
                      # 方法在第 56 行。Shiro 的三种注解必须与 Spring 的同等对待。
                      "RequiresPermissions", "RequiresRoles", "RequiresAuthentication",
                      "RequiresUser", "RequiresGuest")

# Java 控制关键字：防止 `} else if (x) {` 之类被当成方法声明
_JAVA_CONTROL_WORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "catch", "try",
    "return", "new", "throw", "synchronized", "assert", "instanceof",
})

_CLASS_RE = re.compile(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")

_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native|strictfp)\s+)*"
    r"(?:<[^>]*>\s*)?"
    r"([A-Za-z_$][\w$.<>\[\],?\s]*?)\s+([A-Za-z_$][\w$]*)\s*\("
)

_ANN_RE = re.compile(r"^@([A-Za-z_$][\w$.]*)\s*(\(.*\))?\s*$", re.S)

_VIEW_RETURN_RE = re.compile(r"\breturn\s+\"([^\"]+)\"")

_TEMPLATE_RE = re.compile(r"(?:^|/)templates/(.+)\.html$", re.I)


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class RouteParam:
    """一个 HTTP 入参。"""
    name: str = ""                 # 对外参数名（@RequestParam("key") 的 key，否则 java 变量名）
    java_name: str = ""            # java 形参名
    type: str = ""                 # java 类型（Long/String/BigDecimal/...）
    location: str = ""             # query/path/body/header/cookie/form/infra
    annotation: str = ""           # RequestParam/PathVariable/.../""（无注解）
    required: bool = True
    default: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RouteEntry:
    """一条 HTTP 路由（controller 的一个 handler 方法 × 一个具体路径）。"""
    file: str = ""
    line: int = 0                  # 方法声明所在行（1-based）
    annotation_line: int = 0       # 方法级映射注解（@GetMapping 等）所在行；0 = 未解析到
    end_line: int = 0              # 方法体结束行（用于按行号归属 finding；0 = 未解析到）
    class_name: str = ""
    method_name: str = ""
    route: str = ""                # 完整路由，路径变量保留 {id} 形态
    method: str = "GET"            # 主 HTTP 方法
    methods: List[str] = field(default_factory=list)
    method_explicit: bool = True   # False = @RequestMapping 未声明 method（Spring 接受全部）
    params: List[RouteParam] = field(default_factory=list)
    path_variables: List[str] = field(default_factory=list)
    json_response: bool = False    # @RestController 或方法上有 @ResponseBody
    view_name: str = ""            # 返回的视图名（Thymeleaf 逻辑名）
    view_template: str = ""        # 视图名解析出的模板文件路径（若文件清单里能找到）
    redirect_to: str = ""          # "redirect:/xxx" 的目标
    guards: List[str] = field(default_factory=list)   # 方法/类级权限注解原文
    class_routes: List[str] = field(default_factory=list)  # 类级 @RequestMapping 前缀
    source: str = "static"         # 固定标记，区别于 LLM 推断
    # 例如 Shiro 的 `filterChainDefinitionMap.put("/**", "user,...")`、
    # Spring Security 的 `anyRequest.authenticated`。
    # 为什么要落到每个 entry 上：`has_guard` 只看方法/类注解，而**「没注解」不等于「没鉴权」**
    # ——应用可能由全局过滤器兜底认证，此时管理端点缺注解不等于缺鉴权。
    app_requires_auth: bool = False
    app_auth_evidence: str = ""

    @property
    def qualified_name(self) -> str:
        return f"{self.class_name}#{self.method_name}" if self.class_name else self.method_name

    @property
    def has_guard(self) -> bool:
        return bool(self.guards)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["qualified_name"] = self.qualified_name
        d["has_guard"] = self.has_guard
        return d


@dataclass
class RouteIndex:
    """路由索引：按文件/行号、路由、类名三向检索。"""
    entries: List[RouteEntry] = field(default_factory=list)
    template_map: Dict[str, str] = field(default_factory=dict)  # 视图逻辑名 → 模板文件路径

    # ---- 基础检索 ----
    def routes(self) -> List[RouteEntry]:
        return list(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def find(self, route: str, method: Optional[str] = None) -> List[RouteEntry]:
        """按路由（等价归一后）检索；method 为空则不过滤。"""
        target = _canon_route(route)
        if not target:
            return []
        out = []
        for e in self.entries:
            if _canon_route(e.route) != target:
                continue
            if method and method.upper() not in {m.upper() for m in (e.methods or [e.method])}:
                continue
            out.append(e)
        return out

    def by_class(self, class_name: str) -> List[RouteEntry]:
        return [e for e in self.entries if e.class_name == class_name]

    def by_file(self, file: str) -> List[RouteEntry]:
        key = normalize_path_key(file)
        return [e for e in self.entries if normalize_path_key(e.file) == key]

    # ---- 按源码位置归属（finding → handler）----
    def lookup(
        self,
        file: Optional[str],
        line: Optional[int] = None,
        method_name: Optional[str] = None,
    ) -> Optional[RouteEntry]:
        """找出「包含该源码位置」的 handler 方法。

        优先级：file+method_name 精确 → file+line 落在方法体区间 → file+line 取最近的
        上一个 handler（end_line 未解析到时的兜底）。
        """
        if not file:
            return None
        candidates = self._file_candidates(file)
        if not candidates:
            return None

        if method_name:
            for e in candidates:
                if e.method_name == method_name:
                    return e

        if line is None:
            return None
        try:
            line = int(line)
        except (TypeError, ValueError):
            return None

        # 方法体区间命中（最可靠）。
        # 是**注解行**（如 ``@PostMapping("/order/{id}/refund")`` 在 107 行、方法声明在 108 行），
        # 旧实现只认 [方法声明行, end_line]，107 落在 ship 的 end_line(104) 之后、refund 的
        # 声明行(108) 之前 → 两侧都不命中，兜底取「不晚于 line 的最后一个 handler」→ 错绑 ship。
        # 这正是 #33 退款滥用 finding 被绑到 /order/{id}/ship 的根因。annotation_line 缺省回退 line。
        for e in candidates:
            _lo = e.annotation_line or e.line
            if _lo <= line and (not e.end_line or line <= e.end_line):
                return e
        # 兜底：取不晚于 line 的最后一个 handler
        earlier = [e for e in candidates if (e.annotation_line or e.line) <= line]
        if earlier:
            return max(earlier, key=lambda e: (e.annotation_line or e.line))
        return None

    def _file_candidates(self, file: str) -> List[RouteEntry]:
        """按路径取候选，兼容 A1 绝对路径 / A2 相对路径（路径双轨制）。"""
        q = normalize_path_key(file)
        if not q:
            return []
        hits = []
        for e in self.entries:
            k = normalize_path_key(e.file)
            if k == q or (k and (k.endswith("/" + q) or q.endswith("/" + k))):
                hits.append(e)
        return hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
            "template_map": dict(self.template_map),
        }


# ---------------------------------------------------------------------------
# 源码扫描：去注释 + 括号深度
# ---------------------------------------------------------------------------

def _strip_comments_and_track_depth(src: str):
    """去掉注释（保留换行与列位置）并逐行记录括号深度。

    Returns:
        (cleaned, depth_start, depth_end)：三个长度一致于行数的结构；
        ``depth_start[i]`` / ``depth_end[i]`` 是第 i 行（0-based）起止时的 ``{}`` 深度。
    """
    chars: List[str] = []
    depth_starts: List[int] = [0]
    depth_ends: List[int] = []
    depth = 0
    i = 0
    n = len(src)
    state = None  # None | 'line' | 'block' | 'str' | 'char'

    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if state is None:
            if ch == "/" and nxt == "/":
                state = "line"
                chars.append("  ")
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block"
                chars.append("  ")
                i += 2
                continue
            if ch == '"':
                state = "str"
                chars.append(ch)
                i += 1
                continue
            if ch == "'":
                state = "char"
                chars.append(ch)
                i += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
            if ch == "\n":
                depth_ends.append(depth)
                depth_starts.append(depth)
            chars.append(ch)
            i += 1
            continue

        if state == "line":
            if ch == "\n":
                state = None
                depth_ends.append(depth)
                depth_starts.append(depth)
                chars.append(ch)
            else:
                chars.append(" ")
            i += 1
            continue

        if state == "block":
            if ch == "*" and nxt == "/":
                chars.append("  ")
                i += 2
                state = None
                continue
            if ch == "\n":
                depth_ends.append(depth)
                depth_starts.append(depth)
                chars.append(ch)
            else:
                chars.append(" ")
            i += 1
            continue

        # 字符串 / 字符字面量内部：原样保留（其中的括号不参与深度计算）
        chars.append(ch)
        if ch == "\\" and i + 1 < n:
            chars.append(src[i + 1])
            i += 2
            continue
        if (state == "str" and ch == '"') or (state == "char" and ch == "'"):
            state = None
        i += 1

    depth_ends.append(depth)
    return "".join(chars), depth_starts, depth_ends


def _split_top_level(text: str, sep: str = ",") -> List[str]:
    """按顶层分隔符切分（忽略 <> 与  内部的 sep）。"""
    out: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            out.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


# ---------------------------------------------------------------------------
# 注解解析
# ---------------------------------------------------------------------------

def _parse_annotation(text: str):
    """``@GetMapping("/x")`` → ``("GetMapping", '("/x")')``；解析不出返回 None。"""
    m = _ANN_RE.match(text.strip())
    if not m:
        return None
    name = m.group(1).split(".")[-1]
    args = (m.group(2) or "").strip()
    return name, args


def _extract_paths(args: str) -> List[str]:
    """从注解参数里取路径（支持 value=/path= 具名、位置参数、字符串数组）。"""
    if not args:
        return []
    inner = args.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]

    raw = None
    m = re.search(r"\b(?:value|path)\s*=\s*(\{[^{}]*\}|'[^']*'|\"[^\"]*\")", inner)
    if m:
        raw = m.group(1)
    if raw is None:
        m = re.match(r"\s*(\{[^{}]*\}|\"[^\"]*\")", inner)
        if m:
            raw = m.group(1)
    if raw is None:
        return []

    raw = raw.strip()
    if raw.startswith("{"):
        parts = _split_top_level(raw[1:-1])
    else:
        parts = [raw]
    out = []
    for p in parts:
        p = p.strip().strip('"').strip("'").strip()
        if p:
            out.append(p)
    return out


def _extract_methods(args: str) -> List[str]:
    """从 ``method = RequestMethod.GET`` / ``method = {GET, POST}`` 取 HTTP 方法。"""
    if not args:
        return []
    m = re.search(r"\bmethod\s*=\s*(\{[^{}]*\}|[^,)]+)", args)
    if not m:
        return []
    out: List[str] = []
    for rm, bare in re.findall(
        r"RequestMethod\.(\w+)|\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\b", m.group(1)
    ):
        val = (rm or bare or "").upper()
        if val and val not in out:
            out.append(val)
    return out


def _annotation_named(args: str, key: str) -> str:
    """取注解的字符串型具名属性（如 value/name/defaultValue）。

    用 ``(?<![A-Za-z_$])`` 而非 ``\\b`` 做左边界：``defaultValue = "PAID"`` 里的
    "Value" 与 ``username = "x"`` 里的 "name" 都不能被当成 value/name 属性命中。
    """
    if not args:
        return ""
    m = re.search(r"(?<![A-Za-z_$])" + re.escape(key) + r"\s*=\s*\"([^\"]*)\"", args)
    return m.group(1) if m else ""


def _annotation_has(args: str, key: str, default: bool = True) -> bool:
    if not args:
        return default
    m = re.search(r"\b" + re.escape(key) + r"\s*=\s*(true|false)", args, re.I)
    if m:
        return m.group(1).lower() == "true"
    return default


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------

def _parse_params(sig: str) -> List[RouteParam]:
    """解析方法形参列表（已去掉外层括号）→ RouteParam 列表。"""
    out: List[RouteParam] = []
    for part in _split_top_level(sig or ""):
        part = part.strip()
        if not part:
            continue
        anns = re.findall(r"@([A-Za-z_$][\w$]*)\s*(?:\(([^)]*)\))?", part)
        body = re.sub(r"@[A-Za-z_$][\w$]*\s*(?:\([^)]*\))?", "", part).strip()
        body = re.sub(r"\s+", " ", body)
        if not body:
            continue
        # 形参名取**最后一个**标识符：泛型 ``Map<String, String> params`` 内部有空格和逗号，
        tokens = body.split(" ")
        if len(tokens) < 2:
            continue
        pname = tokens[-1].split("=")[0].strip()
        ptype = " ".join(tokens[:-1]).strip()
        if not re.match(r"^[A-Za-z_$][\w$]*$", pname):
            continue

        ann_name = ""
        ann_args = ""
        for a, ar in anns:
            a_short = a.split(".")[-1]
            if a_short in _PARAM_LOCATION:
                ann_name = a_short
                ann_args = ar or ""
                break

        location = _PARAM_LOCATION.get(ann_name, "")
        if not location:
            location = "infra" if ptype.split("<")[0] in _INFRA_TYPES or ptype in _INFRA_TYPES else "query"

        name = _annotation_named(ann_args, "value") or _annotation_named(ann_args, "name") or pname
        out.append(RouteParam(
            name=name,
            java_name=pname,
            type=ptype,
            location=location,
            annotation=ann_name,
            required=_annotation_has(ann_args, "required", default=True) if ann_name else True,
            default=_annotation_named(ann_args, "defaultValue") or _annotation_named(ann_args, "default"),
        ))
    return out


# ---------------------------------------------------------------------------
# 路由拼接 / 校验
# ---------------------------------------------------------------------------

def join_route(prefix: str, path: str) -> str:
    """拼接类级前缀与方法级路径（Spring 规则：都补斜杠、去重复斜杠）。"""
    prefix = (prefix or "").strip()
    path = (path or "").strip()
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix
    if path and not path.startswith("/"):
        path = "/" + path
    if not path or path == "/":
        # Spring 规则：类前缀 /admin + 方法路径 ""/"/" 都映射到 /admin（不是 /admin/）
        return prefix.rstrip("/") or "/"
    combined = (prefix.rstrip("/") + "/" + path.lstrip("/")) if prefix else path
    while "//" in combined:
        combined = combined.replace("//", "/")
    return combined


def _canon_route(route: str) -> str:
    """路由等价归一（比较用）：去尾部斜杠、路径变量保留占位、小写。"""
    r = (route or "").strip()
    if not r:
        return ""
    if not r.startswith("/"):
        r = "/" + r
    r = r.rstrip("/") or "/"
    while "//" in r:
        r = r.replace("//", "/")
    return r.lower()


def is_plausible_route(route: str) -> bool:
    """路由是否可信（与 A2._sanitize_llm_route 同口径，挡掉 "/" 一类残缺值）。"""
    r = (route or "").strip()
    if not r.startswith("/") or r == "/":
        return False
    if "," in r:
        return False
    return bool(re.match(r"^/[A-Za-z0-9_\-/{}.]*$", r))


# ---------------------------------------------------------------------------
# 单文件解析
# ---------------------------------------------------------------------------

def parse_java_routes(file: str, content: str) -> List[RouteEntry]:
    """解析单个 Java 文件的 Spring 路由。非 controller / 解析不出时返回空列表。"""
    if not content or "Mapping" not in content:
        return []
    if "class " not in content:
        return []

    cleaned, depth_starts, depth_ends = _strip_comments_and_track_depth(content)
    lines = cleaned.split("\n")

    entries: List[RouteEntry] = []
    pending: List[str] = []
    pending_lines: List[int] = []   # 与 pending 一一对应：每条注解的起始行号
    ann_buf = ""
    ann_depth = 0
    ann_start_line = 0

    class_name = ""
    class_routes: List[str] = []
    class_guards: List[str] = []
    class_rest = False
    class_depth = None  # 类体所在深度

    open_method: Optional[RouteEntry] = None

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        line = raw.strip()

        # --- 收集注解（支持跨行）---
        if ann_buf:
            ann_buf += " " + line
            ann_depth += line.count("(") - line.count(")")
            if ann_depth <= 0:
                pending.append(ann_buf.strip())
                pending_lines.append(ann_start_line)
                ann_buf = ""
                ann_depth = 0
                ann_start_line = 0
            continue
        if line.startswith("@"):
            d = line.count("(") - line.count(")")
            if d > 0:
                ann_buf = line
                ann_depth = d
                ann_start_line = lineno
            else:
                pending.append(line)
                pending_lines.append(lineno)
            continue

        # --- 类声明 ---
        m_cls = _CLASS_RE.search(line)
        if m_cls and (class_depth is None or depth_starts[idx] <= (class_depth or 0)):
            class_name = m_cls.group(1)
            class_routes = []
            class_guards = []
            class_rest = False
            for text in pending:
                ann = _parse_annotation(text)
                if not ann:
                    continue
                name, args = ann
                if name in _CONTROLLER_ANNOTATIONS:
                    class_rest = class_rest or name == "RestController"
                    class_routes.extend(_extract_paths(args))
                elif name == "RequestMapping":
                    class_routes.extend(_extract_paths(args))
                elif name in _GUARD_ANNOTATIONS:
                    class_guards.append(text.strip())
            class_depth = depth_starts[idx]
            pending = []
            pending_lines = []
            continue

        # --- 方法声明 ---
        m = _METHOD_RE.match(raw)
        if m and class_depth is not None and depth_starts[idx] == class_depth + 1:
            rtype = m.group(1).strip().split(".")[-1].strip()
            mname = m.group(2)
            if mname in _JAVA_CONTROL_WORDS or rtype in _JAVA_CONTROL_WORDS or mname == class_name:
                pending = []
                pending_lines = []
                continue

            method_routes: List[str] = []
            methods: List[str] = []
            method_explicit = True
            method_rest = class_rest
            guards = list(class_guards)
            sig = ""
            mapping_ann_line = 0   # 方法级映射注解所在行（供按行号归属 finding）

            for _pi, text in enumerate(pending):
                ann = _parse_annotation(text)
                if not ann:
                    continue
                name, args = ann
                _aln = pending_lines[_pi] if _pi < len(pending_lines) else 0
                if name in _MAPPING_METHODS:
                    method_routes.extend(_extract_paths(args))
                    methods.append(_MAPPING_METHODS[name])
                    if not mapping_ann_line:
                        mapping_ann_line = _aln
                elif name == "RequestMapping":
                    method_routes.extend(_extract_paths(args))
                    if not mapping_ann_line:
                        mapping_ann_line = _aln
                    m_methods = _extract_methods(args)
                    if m_methods:
                        methods.extend(m_methods)
                    else:
                        method_explicit = False
                elif name == "ResponseBody":
                    method_rest = True
                elif name in _GUARD_ANNOTATIONS:
                    guards.append(text.strip())

            pending = []
            pending_lines = []

            if not method_routes:
                continue

            # 形参列表：从方法声明行起拼到遇到 '{' 或 ';' 为止（支持跨行签名）
            sig, _ = _collect_signature(lines, idx)

            for c_route in (class_routes or [""]):
                for m_route in method_routes:
                    full = join_route(c_route, m_route)
                    if not is_plausible_route(full):
                        continue
                    params = _parse_params(sig)
                    path_vars = re.findall(r"\{([A-Za-z_$][\w$]*)\}", full)
                    entry = RouteEntry(
                        file=file,
                        line=lineno,
                        annotation_line=mapping_ann_line,
                        end_line=0,
                        class_name=class_name,
                        method_name=mname,
                        route=full,
                        method=(methods[0] if methods else "GET"),
                        methods=sorted(set(methods)) if methods else [],
                        method_explicit=method_explicit and bool(methods),
                        params=params,
                        path_variables=path_vars,
                        json_response=method_rest,
                        guards=guards,
                        class_routes=list(class_routes),
                    )
                    entries.append(entry)
                    open_method = entry
            continue

        # --- 方法体结束 / 视图名 ---
        if open_method is not None and class_depth is not None:
            if depth_ends[idx] == class_depth + 1:
                open_method.end_line = lineno
                open_method = None
            elif not open_method.view_name and not open_method.json_response:
                # 只有非 JSON 响应（@Controller 且无 @ResponseBody）的 return 才是视图名。
                # 否则会把 `return "ERROR: " + e.getMessage` 这类字符串字面量误当视图。
                mv = _VIEW_RETURN_RE.search(raw)
                if mv:
                    val = mv.group(1)
                    if val.startswith("redirect:"):
                        open_method.redirect_to = val[len("redirect:"):]
                    elif re.match(r"^[A-Za-z0-9_\-/.]+$", val):
                        open_method.view_name = val

        if line:
            pending = []
            pending_lines = []

    return entries


def _collect_signature(lines: List[str], start_idx: int):
    """从方法声明行开始收集形参列表，返回 (参数串, 签名结束行号)。"""
    buf: List[str] = []
    depth = 0
    started = False
    for i in range(start_idx, min(start_idx + 12, len(lines))):
        for ch in lines[i]:
            if not started:
                if ch == "(":
                    started = True
                    depth = 1
                continue
            # 内层括号（@RequestParam(...) / 泛型）必须原样保留，否则
            # ``@RequestParam(required = false, defaultValue = "") String keyword``
            # 的注解括号丢失后，其内部的逗号会被当成形参分隔符，把 "false"
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return "".join(buf), i
            buf.append(ch)
        if started:
            buf.append(" ")
    return "".join(buf), start_idx


# ---------------------------------------------------------------------------
# 索引构建
# ---------------------------------------------------------------------------

def _build_template_map(files: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """从文件清单里建「视图逻辑名 → 模板文件路径」映射（Thymeleaf 默认 templates/ 目录）。"""
    out: Dict[str, str] = {}
    for f in files or []:
        path = str((f or {}).get("path") or "")
        if not path:
            continue
        key = normalize_path_key(path)
        m = _TEMPLATE_RE.search(key)
        if not m:
            continue
        logical = m.group(1).strip("/")
        out.setdefault(logical, path)
        out.setdefault(logical.split("/")[-1], path)
    return out


def build_route_index(
    files: Sequence[Dict[str, Any]],
    template_map: Optional[Dict[str, str]] = None,
) -> RouteIndex:
    """从文件清单构建路由索引。

    Args:
        files: ``[{"path": ..., "content": ...}, ...]``，与 A1 ``scan_files`` 同构。
              只有 ``.java`` 且内容含 Mapping/controller 的文件会被解析。
        template_map: 外部已算好的视图→模板映射；不给则内部从 files 推。

    Returns:
        RouteIndex（解析不到任何路由时为空索引，不抛异常）。
    """
    entries: List[RouteEntry] = []
    for f in files or []:
        if not f:
            continue
        path = str(f.get("path") or "")
        if not path.lower().endswith(".java"):
            continue
        content = f.get("content")
        if content is None:
            content = _read_text(path)
            if content is None:
                continue
        try:
            entries.extend(parse_java_routes(path, content))
        except Exception:  # 单文件解析失败绝不拖垮整轮扫描
            continue

    tmaps = _build_template_map(files) if template_map is None else dict(template_map or {})
    index = RouteIndex(entries=entries, template_map=tmaps)
    # URL 级全局守卫：先判定整个应用是否「全站要求认证」，再落到每个 entry。
    _auth_guard, _auth_ev = _detect_global_auth_guard(files)
    for e in index.entries:
        e.app_requires_auth = _auth_guard
        e.app_auth_evidence = _auth_ev
        if e.view_name and not e.view_template:
            e.view_template = tmaps.get(e.view_name, "") or tmaps.get(e.view_name.split("/")[-1], "")
    return index


# 覆盖三种主流写法，都是「一条配置管全站」：
#   Shiro:      filterChainDefinitionMap.put("/**", "user" | "authc" | "kickout,...")
#   Spring Sec: .anyRequest.authenticated / .hasRole(...) / .access(...)
#   Spring Sec: http.authorizeRequests.antMatchers("/**").authenticated
_AUTH_FILTER_TOKENS = ("user", "authc", "kickout", "onlineSession", "syncOnlineSession",
                       "jwt", "token", "oauth2", "bearer")
_ANON_TOKENS = ("anon",)


def _detect_global_auth_guard(files: Sequence[Dict[str, Any]]) -> tuple:
    """判定应用是否有「全站要求认证」的 URL 级守卫，返回 (bool, 证据原文)。

    只看「catch-all 模式」（`/**` 或 `anyRequest`），不看具体路径规则——
    具体路径规则不影响「这个端点是否在认证之后」这个判断。
    """
    for f in files or []:
        content = (f or {}).get("content")
        if not content:
            continue
        text = str(content)
        if "filterChainDefinitionMap" in text:
            for m in re.finditer(
                    r'filterChainDefinitionMap\.put\(\s*"(/\*\*[^"]*)"\s*,\s*"([^"]*)"\s*\)', text):
                pattern, chain = m.group(1), m.group(2)
                tokens = [t.strip() for t in chain.split(",") if t.strip()]
                if tokens and not all(t in _ANON_TOKENS for t in tokens):
                    if any(t in _AUTH_FILTER_TOKENS or t.startswith("perms") for t in tokens):
                        return True, 'filterChainDefinitionMap.put("%s", "%s")' % (pattern, chain)
        if "anyRequest()" in text:
            m = re.search(r"anyRequest\(\)\s*\.\s*(authenticated|hasRole|hasAuthority|access)\s*\(", text)
            if m:
                return True, "anyRequest().%s(...)" % m.group(1)
        if "antMatchers(\"/**\")" in text or "requestMatchers(\"/**\")" in text:
            m = re.search(r'(?:antMatchers|requestMatchers)\(\s*"/\*\*"\s*\)\s*\.\s*(\w+)\s*\(', text)
            if m and m.group(1) in ("authenticated", "hasRole", "hasAuthority", "access"):
                return True, 'antMatchers("/**").%s(...)' % m.group(1)
    return False, ""


def build_route_index_from_dir(root: str) -> RouteIndex:
    """从项目根目录构建路由索引（遍历 .java，跳过 target/build 与测试目录）。"""
    import os

    skip_dirs = {"target", "build", "out", ".git", "node_modules", ".idea", ".venv", "venv"}
    files: List[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            if not name.endswith(".java") and not name.endswith(".html"):
                continue
            # 统一成正斜杠：流水线里 A1 用绝对正斜杠路径、A2 用相对路径，
            # 目录遍历产出的是 Windows 反斜杠，混用会让下游字符串断言与展示不一致。
            full = os.path.join(dirpath, name).replace("\\", "/")
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    files.append({"path": full, "content": fh.read()})
            except OSError:
                continue
    return build_route_index(files)


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# finding → route 绑定（A1 阶段接线用）
# ---------------------------------------------------------------------------

def resolve_route_for_finding(
    index: Optional[RouteIndex],
    file: Optional[str] = None,
    line: Optional[int] = None,
    method_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """把一条 finding 静态绑定到真实 HTTP 路由。

    Returns:
        ``{"route", "method", "params", "class_name", "method_name", "file", "line",
        "route_status", "path_variables", "guards", "view_template"}``；
        绑定不到返回 None（调用方应回落 LLM 并标 ``route_status='static-failed'``）。
    """
    if index is None:
        return None
    entry = index.lookup(file, line=line, method_name=method_name)
    if entry is None:
        return None
    return {
        "route": entry.route,
        "method": entry.method,
        "methods": list(entry.methods or [entry.method]),
        "params": [
            {
                "name": p.name,
                "location": p.location,
                "type": p.type,
                "required": p.required,
                "default": p.default,
                "annotation": p.annotation,
            }
            for p in entry.params
            if p.location != "infra"
        ],
        "class_name": entry.class_name,
        "method_name": entry.method_name,
        "file": entry.file,
        "line": entry.line,
        "route_status": "static",
        "path_variables": list(entry.path_variables),
        "guards": list(entry.guards),
        "view_template": entry.view_template,
        "json_response": entry.json_response,
        "qualified_name": entry.qualified_name,
    }
