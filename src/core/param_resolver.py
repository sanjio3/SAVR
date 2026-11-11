"""真实请求参数名解析：从漏洞元信息（代码/路由/数据流）正则提取 HTTP 入口的真实参数名。

A2 语义分析有时会把 Java 类型签名（如 ``String, Object``）或类型名误当成参数名，
导致 D1 重放把 canary 注入到应用根本不读取的位置，I1 监听器自然读不到。本模块提供
独立于 LLM 的、确定性的参数名兜底提取，供 A2 登记阶段在被污染的名字上抢救出真名。

兼容两种输入：``Vulnerability`` 对象（属性访问）或普通 ``dict``（to_dict 后的产物）。
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from src.core.exploit_spec import (
    is_injection_family,
    canonical_business_logic_family,
    DIFFERENTIAL_PROOF_FAMILIES,
)
from src.core import workspace_runtime


def _field(src: Any, key: str) -> str:
    if isinstance(src, dict):
        value = src.get(key)
    else:
        value = getattr(src, key, None)
    return str(value or "")


# 真实参数名必须满足的强约束：ASCII 标识符，不含空格/逗号/点/引号等。
# 类型签名（``String, Object``）、``@RequestParam String`` 整段、``data,body`` 等一律判非法。
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# 嵌套参数路径（Spring `@ModelAttribute` / MyBatis `${params.dataScope}`）：
# `params[dataScope]`、`filter[user][id]`。**只允许标识符段**，不含引号/空格/点，
# 因此不会变成注入脏值；长度另限 80，防止整段签名被塞进来。
_NESTED_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[A-Za-z_][A-Za-z0-9_]*\])+$")

# 常见 Java 类型词：出现在参数名里即判定为「把类型签名当名字」的污染值。
_TYPE_SIGNATURE_TOKENS = (
    "string", "object", "int", "integer", "long", "boolean", "float", "double",
    "list", "map", "set", "array", "void", "char", "byte", "short",
)


def is_valid_param_name(name: str) -> bool:
    """判断 A2 给出的参数名是否为可安全注入的合法 HTTP 参数名。

    就是这种形态（Spring `@ModelAttribute` 的 Map 字段），此前被 `_PARAM_NAME_RE`
    也会被登记层以 `invalid_param_name` 跳过。嵌套形态只允许标识符段，
    不含引号/空格/点，不会引入注入脏值。
    """
    name = str(name or "").strip()
    if not name:
        return False
    if _NESTED_PARAM_RE.match(name):
        return len(name) <= 80
    if "," in name or " " in name or "." in name or "\"" in name or "'" in name:
        return False
    if not _PARAM_NAME_RE.match(name):
        return False
    lowered = name.lower()
    if lowered in _TYPE_SIGNATURE_TOKENS:
        return False
    # 长度异常（>40）通常意味着整段签名被塞进来了
    if len(name) > 40:
        return False
    return True


def is_valid_route(route: str) -> bool:
    """判断候选路由是否为真实 HTTP 路由（而非源码路径）。

    A2 的 entry_point / chain_id 经常是 Java 源码路径（如 ``D:\\...\\OrderService.java:118``），
    若被当作 route 候选锁进 TriggerSpec，D1 会向不存在的端点发请求 → 永远 not_hit，且污染命中率统计。
    此函数把源码文件后缀 / Windows 盘符 / 反斜杠路径 / 包路径 / ``file:line`` 形态拒掉，
    只放行形如 ``/api/order/{id}`` 的 HTTP 路由。
    """
    r = (route or "").strip()
    if not r:
        return False
    if " " in r or "\n" in r or "\t" in r:
        return False
    # Spring 映射路径不会含逗号，含逗号一律判非路由（防线：即使上游解析器回归也拦得住）。
    if "," in r:
        return False
    # 通配/尖括号残片（如 "/*"、">"、">/"），这些不是真实路由，必须挡在登记之前，
    # 否则会和 "/" 一起污染 D1 重放命中率统计。
    if "*" in r or ">" in r or "<" in r:
        return False
    # 源码文件后缀（OrderService.java:118 这类 file:line 也会被此处及下行拦截）
    if re.search(r"\.(java|py|go|js|ts|tsx|jsx|rb|php|kt|cs)\b", r, re.I):
        return False
    # Windows 盘符（C:\ / D:\）或任意反斜杠路径都不是 HTTP 路由
    if re.search(r"[a-zA-Z]:[\\/]", r) or "\\" in r:
        return False
    # 包路径（com/sanjio/...、src/main/java/...）
    if re.search(r"(^|/)(com|org|net|io)/[a-z]", r) or "src/main" in r:
        return False
    # 至少得像路由：以 / 开头或含字母
    if not (r.startswith("/") or re.search(r"[a-zA-Z]", r)):
        return False
    # 拒绝「根路径 only / 无任何真实路径段」的残片（"/"、"/"、模板 leftover）。
    # 这类没有可重放的端点，登记只会浪费 canary 预算并拉低命中率。
    _segs = [s for s in r.split("/") if s]
    if not _segs:
        return False
    return True


# Spring 映射注解调用（类级 @RequestMapping / 方法级 @Get|Post|...Mapping），用于定位参数列表
_SPRING_MAPPING_CALL_RE = re.compile(
    r"@\s*(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\("
)


def _spring_mapping_path(window: str) -> str:
    """从（可能跨多行的）Spring 映射注解窗口里取**第一个** path（无则返回空串）。

    ``@GetMapping({"", "/"})`` 时，空串因量词要求至少 1 个字符而被跳过，正则改从第二个引号
    起匹配，把 ``"", "/"`` 之间的 ``, ``（逗号 + 空格）当成路径 → 与类前缀拼成 ``/admin/,``

    现改为：先定位注解调用 ``@XxxMapping(``，按括号配平截出参数，再交给
    ``route_resolver._extract_paths`` 解析（支持 value= / path= / 位置参数 / 字符串数组，
    全项目唯一真相源）；只在注解调用定位失败时才回落到旧的「首个字符串」行为。
    """
    m = _SPRING_MAPPING_CALL_RE.search(window or "")
    if m:
        start = m.end() - 1  # 指向 '('
        depth = 0
        end = -1
        for i in range(start, len(window)):
            ch = window[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > start:
            try:
                from src.core.route_resolver import _extract_paths
                paths = _extract_paths(window[start:end])
            except Exception:
                paths = []
            return paths[0] if paths else ""
        # 注解调用未闭合（窗口被截断）：不猜，返回空串交由类级前缀兜底
        return ""
    # 未识别出注解调用：保底沿用旧行为（首个非空字符串）
    pm = re.search(r'["\']([^"\']+)["\']', window)
    return pm.group(1) if pm else ""


def _spring_mapping_path_and_method(window: str, default_http: str):
    """从（可能跨多行的）Spring 映射注解文本里取 (http_method, path)。

    修复单行长正则漏解析：真实代码常把 ``@RequestMapping`` 写成多行，路径在下一行；
    且 ``@RequestMapping(value=\"/x\", method=RequestMethod.POST)`` 的 HTTP 方法在 ``method``
    属性里，不能默认 GET。
    """
    path = _spring_mapping_path(window)
    http = default_http
    rm = re.search(r'RequestMethod\.([A-Z]+)', window)
    if rm:
        http = rm.group(1).upper()
    sm = re.search(r'method\s*=\s*["\'](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\']', window, re.I)
    if sm:
        http = sm.group(1).upper()
    return http, path


# Spring MVC 方法级映射注解
_METHOD_MAPPING_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch|Request)\s*Mapping\s*\('
)
_HTTP_BY_ANNOTATION = {
    "Get": "GET", "Post": "POST", "Put": "PUT",
    "Delete": "DELETE", "Patch": "PATCH", "Request": "GET",
}
# 方法声明行识别：容忍 throws 子句（如 `... (String filepath) throws IOException {`）。
# 旧正则要求 `)` 后紧跟 `{` 或行尾，导致带 throws 的方法（命令注入等靶场几乎全是）无法被识别为
# 方法声明 → method_decl 恒为 None → 兜底②.5 读不到签名 → 参数名解析失败。
# group(1) = 参数列表（不含括号）。
_METHOD_DECL_RE = re.compile(
    r'\s*(public|private|protected|static)\s+\S.*?\(([^)]*)\)'
    r'(?:\s+throws\s+[A-Za-z0-9_,\s.<>]+)?\s*\{?'
)
# 方法签名里的参数提取（@RequestParam / @PathVariable 都可能无括号或有括号+value=）
_PARAM_RE = re.compile(
    r'@(?:RequestParam|PathVariable|CookieValue|RequestHeader|Header)\s*'
    r'(?:\([^)]*?name\s*=\s*["\']([^"\']+)["\'])?'   # name="x" / name='x'
    r'(?:\([^)]*\))?'                                  # 任意 (...) 或无括号
    r'\s+\w+\s+(\w+)'                                  # 类型 名
)
# 绑定在 **cookie / header** 通道，不是 query。旧实现把它们一律当 query
# （`_PARAM_RE` 只含 RequestParam/PathVariable，@CookieValue 落不到兜底②，
# 而兜底②把签名里的 `String xss` 当 query）⇒ D1 把 canary 投到 query，
# 而 `/xss/stored/show` 只从 Cookie 读 ⇒ 响应恒空 ⇒ 该真值点恒漏。
#
# 位置必须由**注解**决定（Spring 的绑定规则），不能由签名兜底猜。
_PARAM_LOCATION_BY_ANNOTATION = (
    ("PathVariable", "path"),
    ("CookieValue", "cookie"),
    ("RequestHeader", "header"),
    ("Header", "header"),
    ("RequestParam", "query"),
)
_CLASS_REQUEST_MAPPING_RE = re.compile(r'@RequestMapping\s*\(')


def _resolve_java_class_path(code_root: str, fqn: str) -> Optional[str]:
    """把 Java 全限定类名（org.joychou.config.Constants）还原为源码文件路径。

    但 Maven/Gradle 标准布局下源码在 ``code_root/src/main/java/<fqn>.java``
    ⇒ 恒返回 None ⇒ 常量解析失效 ⇒ cookie 名解析不出 ⇒ Shiro 的 rememberMe
    被登记成 body（应用只从 Cookie 读）⇒ D1 投错通道 ⇒ 端点永久 no-arrival。

    现在按**常见源码根前缀**依次探测（不猜内容，只认布局）。
    """
    if not code_root or not fqn:
        return None
    rel = fqn.replace(".", "/") + ".java"
    roots = (
        "",                       # 源码根本身就是包根（部分工程）
        "src/main/java",          # Maven 标准
        "src/main/kotlin",
        "src/java",
        "src",
        "java",
    )
    for pre in roots:
        p = Path(code_root) / pre / rel if pre else Path(code_root) / rel
        try:
            if p.exists():
                return str(p)
        except OSError:
            continue
    # 兜底：按文件名在源码根下找（同名类可能不在标准包里）
    try:
        simple = fqn.rsplit(".", 1)[-1] + ".java"
        for dirpath, dirnames, filenames in os.walk(code_root):
            dirnames[:] = [d for d in dirnames
                           if d not in ("target", "build", "node_modules", ".git",
                                        "out", "bin", "generated")
                           and not d.startswith(".codeql-db")]
            if simple in filenames:
                return os.path.join(dirpath, simple)
    except OSError:
        pass
    return None


def _resolve_const_string(code_root: str, src_lines: List[str], ref: str) -> Optional[str]:
    """把常量引用（Constants.REMEMBER_ME_COOKIE / FOO）解析为字符串字面量。

    先在同文件找 ``NAME = "..."``；找不到再按 import 映射 simple class → fqn，
    读常量类源码找定义。解析不出返回 None（绝不编造）。
    """
    if not ref:
        return None
    if "." in ref:
        _fqn, _const = ref.rsplit(".", 1)
    else:
        _fqn, _const = None, ref
    _const_pat = re.compile(
        r'(?:static\s+final\s+String\s+|final\s+String\s+|String\s+)'
        + re.escape(_const) + r'\s*=\s*["\']([^"\']+)["\']'
    )
    for ln in src_lines:
        m = _const_pat.search(ln)
        if m:
            return m.group(1)
    if _fqn:
        # （`Constants.REMEMBER_ME_COOKIE`），而 import 语句是**包路径**
        # （`import org.joychou.config.Constants;`）。旧实现只匹配静态 import
        # （`import static a.b.Constants;`），普通包 import 完全匹配不上 ⇒
        # 常量解析返回 None ⇒ cookie 名解析不出 ⇒ Shiro 的 rememberMe 参数
        # 被登记成 body/query（应用只从 Cookie 读）⇒ D1 投错通道 ⇒
        # 端点永久 no-arrival（617 的 237706/237707/237725/237784 四条）。
        #
        # 修法：同时支持两种 import 形态——按 import 的**最后一段**匹配类名，
        # 再用 import 给出的完整包路径定位常量类源码。
        for ln in src_lines:
            im = re.search(r'^\s*import\s+(?:static\s+)?([\w.]+)\s*;', ln)
            if not im:
                continue
            _full = im.group(1)
            if _full.rsplit(".", 1)[-1] != _fqn.rsplit(".", 1)[-1]:
                continue
            _p = _resolve_java_class_path(code_root, _full)
            if _p:
                try:
                    for ln2 in Path(_p).read_text(encoding="utf-8", errors="ignore").splitlines():
                        m = _const_pat.search(ln2)
                        if m:
                            return m.group(1)
                except Exception:
                    pass
            # 静态 import 时 _full 已是完整类名；若上面没找到，尝试把包前缀剥掉再试
            if "." in _full:
                _tail = _full.rsplit(".", 1)[-1]
                for ln2 in src_lines:
                    if re.search(r'^\s*import\s+' + re.escape(_full) + r'\s*;', ln2):
                        _p2 = _resolve_java_class_path(code_root, _tail)
                        if _p2:
                            try:
                                for ln3 in Path(_p2).read_text(encoding="utf-8", errors="ignore").splitlines():
                                    m = _const_pat.search(ln3)
                                    if m:
                                        return m.group(1)
                            except Exception:
                                pass
            break
    return None


def _resolve_cookie_name(body: str, code_root: str, src_lines: List[str]) -> Optional[str]:
    """从方法体提取被读取的 Cookie 名（如 rememberMe），供 param_location=cookie 回填。

    覆盖：getCookie(req, "literal") 直接字面量、getCookies 循环里 getName.equals("X")、
    getCookie(req, CONST) / WebUtils.getCookieValueByName(req, CONST)
    （CONST 经 _resolve_const_string 解析为字面量）。无法解析时返回 None（不编造 cookie 名，
    避免 D1 把 canary 注入到应用根本不读取的字段）。
    """
    for m in re.finditer(r'getCookie\(\s*\w+\s*,\s*["\']([^"\']+)["\']', body):
        return m.group(1)
    m = re.search(r'\.getName\(\)\s*\.equals\(\s*["\']([^"\']+)["\']', body)
    if m:
        return m.group(1)
    rm = re.search(r'getCookie\(\s*\w+\s*,\s*([A-Za-z_][\w.]*)\s*\)', body)
    if rm:
        return _resolve_const_string(code_root, src_lines, rm.group(1))
    rm = re.search(r'getCookieValueByName\(\s*\w+\s*,\s*([A-Za-z_][\w.]*)\s*\)', body)
    if rm:
        return _resolve_const_string(code_root, src_lines, rm.group(1))
    return None


def _join_class_base(base: str, method_route: str) -> str:
    """类级 base + 方法级路由拼接（防 /api/api 叠加、归一尾斜杠）。供
    resolve_endpoint_from_source 尾部与路由定向再归因共用同一拼接口径。"""
    route = method_route
    if base and method_route:
        # 防 /api/api：类级 base 与方法级 method_route 已含同一前缀时（如 base="/api"、
        # method_route="/api/users/delete"），不再叠加，否则拼出 /api/api 这种错误路由。
        _base = base.rstrip("/")
        if method_route == _base or method_route.startswith(_base + "/"):
            route = method_route
        else:
            route = _base + "/" + method_route.lstrip("/")
        # 方法级映射为 "/" 或 ""（Spring 的 @GetMapping({"", "/"}) 把类前缀本身作为入口）时，
        # 拼出的是 "/admin/"。Spring 6 默认关闭尾斜杠匹配，"/admin/" 对部分端点会 404，
        # 与 route_resolver.join_route 的口径保持一致，统一归一为 "/admin"。
        if route.rstrip("/") == _base:
            route = _base or "/"
    elif base and not method_route:
        route = base
    return route


def resolve_endpoint_from_source(vuln: Any, code_root: str, route_hint: str = "") -> Optional[Dict[str, str]]:
    """读真实 Java 源码，从 Spring 注解解析 (route, method, param_name, param_location)。

    当 A2 没给出 exploit_spec.entry.route / parameter_name 时（常见：route=''、param 为类型签名），
    用漏洞的 file+line 定位到具体 controller 方法，从 class/method 的 @RequestMapping、
    @PostMapping 与 @RequestParam/@PathVariable 抢救出真实 HTTP 入口与参数名。

    A2 LLM 的 line 常落错方法（实测：FileUpload.java 文件类型绕过 finding 标 line=35，真实逻辑
    在 L82 的 /upload/picture 方法，行归因解析出 /file），导致源码注解权威（multipart/cookie
    纠偏）因「路由相等才覆盖」守卫无法生效，低精度位置被登记持久化 → D1 注入应用不读取的
    位置 → no-arrival。行归因与 hint 不一致时，在同文件内寻找完整路由与 hint 精确相等的
    映射并改选之（路由是比行号更强的归因信号；仅同文件内纠偏，不跨文件猜测）。

    返回 None 表示源码不可达或解析不出路由。
    """
    if not code_root:
        return None
    file = _field(vuln, "file")
    if not file:
        return None
    try:
        line = int(_field(vuln, "line") or 0)
    except Exception:
        line = 0

    root = Path(code_root)
    candidates = [root / file, root / file.replace("\\", "/")]
    src = next((p for p in candidates if p.exists()), None)
    if src is None:
        try:
            hits = [p for p in root.rglob(Path(file).name) if p.is_file()]
            if hits:
                src = hits[0]
        except Exception:
            src = None
    if src is None or not src.exists():
        return None
    try:
        lines = src.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    if not lines:
        return None

    # class 级 base path：找紧随 class 声明前的 @RequestMapping(...)（支持多行写法）
    base = ""
    for i, l in enumerate(lines):
        if "@RequestMapping" not in l:
            continue
        window = "\n".join(lines[i:min(i + 6, len(lines))])
        if not re.search(r'\bclass\s+\w+', window):
            continue
        _, bp = _spring_mapping_path_and_method(window, "GET")
        if bp:
            base = bp
            break

    # 收集方法级映射（注解行号、HTTP 方法、路径），支持多行注解与 method=RequestMethod.X
    method_maps: list = []
    for i, l in enumerate(lines):
        mm = _METHOD_MAPPING_RE.search(l)
        if not mm:
            continue
        window = "\n".join(lines[i:min(i + 5, len(lines))])
        # _METHOD_MAPPING_RE 的 (Get|Post|...|Request) 分支同样能匹配它，若不排除，它会以
        # 「方法级映射」身份进入 method_maps；当 vuln.line 落在所有方法映射之前时
        # （SAST 行号漂移、或漏洞在字段/工具区），chosen 退化取 method_maps[0] 正好就是它
        # → 解析出的 route 是类级基路径（/ssrf、/cors、/jwt …），spec 锁到不可调用的路径上。
        if re.search(r"\bclass\s+\w+", window):
            continue
        http, path = _spring_mapping_path_and_method(window, _HTTP_BY_ANNOTATION.get(mm.group(1), "GET"))
        method_maps.append((i, http, path))
    if not method_maps:
        return None

    # 选包含 vuln.line 的那个方法（映射注解行号 < line 且最大）
    chosen = None
    for mm in method_maps:
        if mm[0] < line:
            chosen = mm
    if chosen is None:
        # 行号漂移兜底：vuln.line 落在所有映射之前（SAST 分析器行号与当前源码不一致，
        # 如 ProductController 的 SQLi finding 标 line=20 但 @GetMapping 实际在 line=32），
        # 退化选第一个映射（控制器首个 HTTP 入口），避免整控制器 SQLi 因行号错位全部 skipped。
        chosen = method_maps[0]

    # hint 与行归因选出的完整路由不一致时，在同文件内改选与 hint 精确相等的映射。
    # 仅同文件内纠偏：找不到相等路由则维持行归因结果（不猜）。
    _hint = str(route_hint or "").strip()
    if _hint:
        try:
            _hint_key = normalize_route_key(_hint)
            if _hint_key and normalize_route_key(_join_class_base(base, chosen[2])) != _hint_key:
                for _mm in method_maps:
                    if normalize_route_key(_join_class_base(base, _mm[2])) == _hint_key:
                        logger.info(
                            "[resolve_endpoint_from_source] 路由定向再归因：行归因选 %s（line=%s），"
                            "与假设路由 %s 不一致，同文件改选 %s（注解行 %d）。",
                            _join_class_base(base, chosen[2]), line, _hint,
                            _join_class_base(base, _mm[2]), _mm[0] + 1,
                        )
                        chosen = _mm
                        break
        except Exception as _e:
            logger.debug("[resolve_endpoint_from_source] 路由定向再归因失败（维持行归因）：%s", _e)
    method_route, method_http = chosen[2], chosen[1]

    # 参数名 + 位置：扫描整个方法体（映射注解后到下一个方法声明为止，最多 80 行），
    # 覆盖 @RequestParam/@PathVariable 之外的 request.getParameter("x") 等真实取参写法，
    # 否则 SQLi/SSRF/命令注入等控制器只解析出路由、参数名为空 → 整类被 skipped（Point B 主因）。
    # 先定位 chosen 映射所属方法的声明行，再以此为界截到下一个方法声明。
    method_decl = None
    for j in range(chosen[0] + 1, len(lines)):
        if _METHOD_DECL_RE.match(lines[j]):
            method_decl = j
            break
    body_end = min(len(lines), (method_decl + 80) if method_decl is not None else chosen[0] + 80)
    if method_decl is not None:
        for j in range(method_decl + 1, len(lines)):
            if (_METHOD_MAPPING_RE.search(lines[j])
                    or re.match(r'\s*(public|private|protected|static)\s+\S.*\([^)]*\)\s*\{?$', lines[j])):
                body_end = j
                break
    body = "\n".join(lines[chosen[0]:body_end])
    param_name = None
    param_location = None
    pm = _PARAM_RE.search(body)
    if pm:
        # 第 1 组是 name="x"（可能为空），第 2 组是变量名
        param_name = (pm.group(1) or pm.group(2) or "").strip()
        # 位置由**注解**决定（Spring 的绑定规则）：@CookieValue → cookie、
        # @RequestHeader → header、@PathVariable → path、@RequestParam → query。
        # 导致 @CookieValue 参数被登记成 query ⇒ D1 投错通道 ⇒ 端点恒漏。
        _ann = pm.group(0)
        param_location = "query"
        for _tok, _loc2 in _PARAM_LOCATION_BY_ANNOTATION:
            if _tok in _ann:
                param_location = _loc2
                break
        if not param_name:
            # 注解没写 name= 时，CookieValue/RequestHeader 的**第一个字符串字面量**
            # 就是参数名（`@CookieValue("xss") String xss` ⇒ xss）。
            _lit = re.search(r'["\']([^"\']+)["\']', _ann)
            if _lit:
                param_name = _lit.group(1).strip()
    if not param_name:
        # 兜底①：方法体内 request.getParameter("x") 取参（SQLi/SSRF/命令注入常见写法）
        gp = re.search(r'getParameter\s*\(\s*["\']([^"\']+)["\']\s*\)', body)
        if gp:
            param_name = gp.group(1).strip()
            param_location = "query"
    if not param_name:
        # —— 与 getParameter 同为「方法体内取参」，但绑定在 **header** 通道。
        # 旧实现只认 getParameter ⇒ header 参数落到兜底②（签名里的 `String origin`
        # 被当成 query）⇒ D1 把 canary 投到 query，而应用只从 Origin 头读
        # ⇒ 端点恒 no-arrival（CORS 的 /cors/vuln/origin 就是这个形态）。
        gh = re.search(r'getHeader\s*\(\s*["\']([^"\']+)["\']\s*\)', body)
        if gh:
            param_name = gh.group(1).strip()
            param_location = "header"
    if not param_name:
        # 兜底②：签名里第一个「类型 名」
        sm = re.search(r'\(([^)]*)\)\s*\{', body)
        if sm:
            pm2 = re.search(
                r'\b(?:String|int|long|Integer|Long|Object|Map|List|Set|boolean|'
                r'float|double|byte|char|short)\b\s+(\w+)',
                sm.group(1),
            )
            if pm2:
                param_name = pm2.group(1)
                param_location = "query"
    if not param_name:
        # （public String foo(String filepath)）。这类端点的参数名在「方法签名」而非方法体内
        # （无 @RequestParam / request.getParameter 调用），旧逻辑只看方法体 → param_name 恒空，
        # 甚至被下方 _body 兜底③误判（方法体含 process.getInputStream 等进程输出流读取）。
        # 这里从签名抽取首个白名单类型参数名（跳过 request/response/session/model 等非入参）。
        # 直接扫描方法体前若干行找「方法声明行」（用 _METHOD_DECL_RE，容忍 throws 子句），
        # 不依赖 method_decl 索引，避免带 throws 的方法被漏判（命令注入等靶场几乎全是）。
        _sig_line = None
        for _bl in body.splitlines():
            if _METHOD_DECL_RE.match(_bl):
                _sig_line = _bl
                break
        if not _sig_line and method_decl is not None and 0 <= method_decl < len(lines):
            _sig_line = lines[method_decl]
        if _sig_line:
            _sm = re.search(r'\(([^)]*)\)', _sig_line)
            if _sm:
                _pm = re.search(
                    r'\b(?:String|int|long|Integer|Long|Object|Map|List|Set|boolean|'
                    r'float|double|byte|char|short)\b\s+(\w+)',
                    _sm.group(1),
                )
                if _pm and _pm.group(1) not in ("request", "response", "session", "model") \
                        and is_valid_param_name(_pm.group(1)):
                    param_name = _pm.group(1)
                    param_location = "query"

    if not param_name:
        # 兜底③：HTTP 请求体全文读取（WebUtils.getRequestBody(req) / request.getReader /
        # request.getInputStream / @RequestBody）。须锚定到「请求对象」或 @RequestBody，
        # 否则会把 process.getInputStream（进程输出流，如 convertStreamToString(process.getInputStream)）
        # 误判成请求体 → 参数被回退成 _body（实测 /codeinject/sec 即因此被误判，导致 D1 注入到
        # 应用不读取的 body 位置 → 端点永久 no-arrival、waf_blocked 永不被求值）。
        if (re.search(r'getRequestBody\s*\(', body)
                or re.search(r'\b(?:request|req|servletRequest|httpRequest|httpServletRequest)\w*\s*\.\s*getReader\s*\(', body)
                or re.search(r'\b(?:request|req|servletRequest|httpRequest|httpServletRequest)\w*\s*\.\s*getInputStream\s*\(', body)
                or "@RequestBody" in body):
            param_name = "_body"
            param_location = "body"

    # C：源感知位置纠偏（Cookie / Multipart）。上面兜底把 MultipartFile 参数或 Cookie 入参误判成
    # query（甚至 extract 出无意义的 request 变量名），导致 D1 把 canary 注入到应用根本不读取的
    # 位置（/file/upload、/deserialize/rememberMe/vuln 永久 no-arrival）。这里基于真实方法体做位置
    # 纠偏：multipart 优先（文件上传族 always）；cookie 仅在尚未解析出参数名时回填，避免覆盖已
    # 正确解析的 query 参数。
    _multipart_m = re.search(r'MultipartFile\s+(\w+)', body)
    if _multipart_m:
        _mname = _multipart_m.group(1)
        _rp_m = re.search(r'@RequestParam\s*\(\s*["\']([^"\']+)["\']\s*\)\s+MultipartFile', body)
        if _rp_m and is_valid_param_name(_rp_m.group(1)):
            _mname = _rp_m.group(1)
        if is_valid_param_name(_mname):
            param_name = _mname
            param_location = "multipart"
    elif param_name is None or param_name == "":
        _cookie_name = _resolve_cookie_name(body, code_root, lines)
        if _cookie_name:
            param_name = _cookie_name
            param_location = "cookie"

    if not method_route and not param_name:
        return None
    route = _join_class_base(base, method_route)
    if not route:
        return None
    return {
        "param_name": param_name or "",
        "route": route,
        "method": method_http,
        "param_location": param_location or "query",
    }


# 例如 AdminController 的 SSRF finding，description 明写「fetch 方法…url 参数…」，
# 但 line 落在相邻 ping 方法的 javadoc 收尾行，按 line 解析会回落到更早的 dashboard 路由 `/admin`
# （`resolve_endpoint_from_source` 取「最近的前置映射」），于是 ssrf 族永远没有 `/admin/fetch` 的 spec。
# 这不是类级兜底吃掉方法级路由，而是 Line 归因错误；下面按「漏洞文本点名的方法名」在同文件内纠偏。
_METHOD_HINT_CN_RE = re.compile(r"([A-Za-z_$][\w$]{2,})\s*方法")
_METHOD_HINT_EN_RE = re.compile(r"\b([A-Za-z_$][\w$]{2,})\s+method\b", re.IGNORECASE)
_METHOD_HINT_HASH_RE = re.compile(r"#([A-Za-z_$][\w$]{2,})")


def _method_name_hints(vuln_dict: Any) -> List[str]:
    """从漏洞文本提取「被点名的方法名」（"fetch 方法" / "fetch method" / "#fetch"）。"""
    if not isinstance(vuln_dict, dict):
        return []
    text = " ".join(
        str(vuln_dict.get(k) or "")
        for k in ("description", "display_title", "title", "sink", "code_snippet")
    )
    hints: List[str] = []
    for rx in (_METHOD_HINT_CN_RE, _METHOD_HINT_EN_RE, _METHOD_HINT_HASH_RE):
        hints.extend(m.group(1) for m in rx.finditer(text))
    seen: set = set()
    out: List[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def resolve_endpoint_by_method_hint(vuln: Any, code_root: str,
                                    vuln_dict: Any = None) -> Optional[Dict[str, str]]:
    """按「漏洞文本点名的方法名」在同文件内纠偏真实 HTTP 路由。

    仅在**同文件确有该方法的 Spring 映射**时生效 —— 属代码级事实，不是猜测。
    返回结构与 `resolve_endpoint_from_source` 一致（多带 function）。
    """
    if not code_root:
        return None
    hints = _method_name_hints(vuln_dict if vuln_dict is not None else vuln)
    if not hints:
        return None
    file = _field(vuln, "file")
    if not file:
        return None
    root = Path(code_root)
    src = next((p for p in (root / file, root / file.replace("\\", "/")) if p.exists()), None)
    if src is None:
        try:
            hits = [p for p in root.rglob(Path(file).name) if p.is_file()]
            src = hits[0] if hits else None
        except Exception:  # noqa: BLE001
            src = None
    if src is None or not src.exists():
        return None
    try:
        content = src.read_text(encoding="utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        return None
    try:
        from src.core.route_resolver import parse_java_routes
        entries = parse_java_routes(str(src), content)
    except Exception:  # noqa: BLE001
        return None
    if not entries:
        return None
    by_name: Dict[str, Any] = {}
    for e in entries:
        if getattr(e, "method_name", "") and getattr(e, "route", ""):
            by_name.setdefault(e.method_name, e)
    for h in hints:
        e = by_name.get(h)
        if e is None:
            continue
        _ln = int(getattr(e, "line", 0) or 0) or (int(getattr(e, "annotation_line", 0) or 0) + 1)
        _v2 = dict(vuln_dict) if isinstance(vuln_dict, dict) else {}
        _v2["file"] = file
        _v2["line"] = _ln
        res = resolve_endpoint_from_source(_v2, code_root)
        if res and res.get("route"):
            res["function"] = h
            return res
    return None


# 缓存：code_root → 已发现的 Web 控制器文件列表（避免每个漏洞重复扫描全量源码）。
_controller_cache: Dict[str, List[str]] = {}


def _discover_web_controllers(code_root: str) -> List[str]:
    """发现 code_root 下的 Spring Web 控制器源码文件列表，供调用链反查兜底使用。

    两通道：
       ``rglob("*Controller.java")`` 完全一致——对这类目标零回归。
    2) 兜底（注解识别）：当主通道为空（靶场把控制器命名为 ``SSRF.java`` / ``XSS.java`` /
       ``CommandInject.java``，完全没有 ``*Controller.java`` 后缀）时，按类级注解
       ``@RestController`` / ``@Controller``（排除 ``@ControllerAdvice`` / ``@RestControllerAdvice``）
       扫描全量 ``*.java`` 识别真实控制器。否则原 glob 直接返回空，util/service 类 sink
       （如 ``HttpUtils`` 被 ``SSRF.java`` 引用）永远 missing_route，90 条漏斗的主因即此。
    结果按 code_root 缓存，调用链反查只在路由解析失败时才触发，扫描成本可控。
    """
    cached = _controller_cache.get(code_root)
    if cached is not None:
        return cached
    root = Path(code_root)
    try:
        primary = [p for p in root.rglob("*Controller.java") if p.is_file()]
    except Exception:
        primary = []
    if primary:
        _controller_cache[code_root] = primary
        return primary
    out: List[Any] = []
    pat = re.compile(r"@(Rest)?Controller\b")
    try:
        files = [p for p in root.rglob("*.java") if p.is_file()]
    except Exception:
        _controller_cache[code_root] = out
        return out
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if pat.search(text) and "@ControllerAdvice" not in text and "@RestControllerAdvice" not in text:
            out.append(p)
    _controller_cache[code_root] = out
    return out


def _resolve_controller_route_by_entity(vuln: Any, code_root: str) -> Optional[Dict[str, str]]:
    """ 业务类二次源码注解：漏洞 file 指向 Mapper/Service/DAO（无 @RequestMapping）时，
    用类名推导实体（OrderMapper/OrderService → Order），在 code_root 找同名 ``<Entity>Controller.java``，
    从其 @RequestMapping 取真实 HTTP 入口。业务越权/bola 多为按 id 查询，优先取含 ``{id}`` 的端点。

    仅返回 HTTP 路由（绝不返回源码路径）；找不到对应 Controller 时返回 None（不静默编造）。
    这是 (file,line)→源码注解通道的延伸：仍读真实源码，只是多跳一层到同名 Controller。
    """
    file = _field(vuln, "file")
    if not file:
        return None
    base = Path(file).stem  # e.g. OrderMapper / OrderService / CommentMapper
    # 去掉常见后缀得实体名；无法推导（如 CurrentUser 跨控制器复用）则放弃，绝不编造
    m = re.match(r"^([A-Za-z][A-Za-z0-9]*?)(Mapper|Service|Dao|Repository|Entity|Impl|BO|Biz|Manager)?$", base)
    entity = m.group(1) if (m and m.group(1) and m.group(1) != base) else ""
    if not entity:
        return None
    root = Path(code_root)
    try:
        ctrls = [p for p in root.rglob(f"{entity}Controller.java") if p.is_file()]
    except Exception:
        return None
    if not ctrls:
        return None
    ctrl = ctrls[0]
    try:
        lines = ctrl.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    # class 级 base path
    base_path = ""
    for i, l in enumerate(lines):
        if "@RequestMapping" not in l:
            continue
        window = "\n".join(lines[i:i + 6])
        if not re.search(r'\bclass\s+\w+', window):
            continue
        _, bp = _spring_mapping_path_and_method(window, "GET")
        if bp:
            base_path = bp
            break
    # 方法级映射；优先含 {id}（业务按 id 越权/bola 最常见），否则取首个
    method_maps: list = []
    for i, l in enumerate(lines):
        mm = _METHOD_MAPPING_RE.search(l)
        if not mm:
            continue
        window = "\n".join(lines[i:i + 5])
        http, path = _spring_mapping_path_and_method(window, _HTTP_BY_ANNOTATION.get(mm.group(1), "GET"))
        method_maps.append((http, path))
    if not method_maps:
        return None
    chosen = next(((h, p) for h, p in method_maps if p and "{id}" in p), method_maps[0])
    http, path = chosen
    if not path:
        return None
    route = path
    if base_path and path:
        _b = base_path.rstrip("/")
        if path == _b or path.startswith(_b + "/"):
            route = path
        else:
            route = _b + "/" + path.lstrip("/")
    elif base_path and not path:
        route = base_path
    if not route or not is_valid_route(route):
        return None
    param = "id" if "{id}" in route else ""
    loc = "path" if "{id}" in route else "query"
    return {
        "route": route,
        "method": http or "GET",
        "param_name": param,
        "param_location": loc,
        "param_name_source": "entity-controller-inferred",
    }


def _resolve_controller_route_by_reference(vuln: Any, code_root: str) -> Optional[Dict[str, str]]:
    """调用链反查（sound 优先 / 宁可误报也不漏报）。

    _resolve_controller_route_by_entity 只按「类名剥后缀 → 同名 <Entity>Controller」推导，
    对工具类 / 配置类（HttpFetcher / SecurityConfig / JwtUtil / SpEL 引擎等）推不出实体名便直接
    放弃 → route 为空 → 该 finding 被 resolvable 门禁刷掉，永远进不了重放（覆盖率泄漏主因之一）。

    本函数改为「引用反查」：漏洞所在类（或其去后缀别名）被哪些 Controller 调用 / 注入，就取那些
    Controller 的真实 HTTP 入口。判据全部来自真实源码文本（类型声明 / 字段注入 / 方法调用），
    绝不编造路由；下游 D1 / I1 / D2 负责确认正确性（SAST 保证 sound 而非 truth）。
    优先返回含 {id} 的端点（业务越权 / bola 多为按 id 查询）。
    """
    file = _field(vuln, "file")
    if not file or not code_root:
        return None
    cls = Path(str(file)).stem  # e.g. HttpFetcher / OrderService / JwtUtil
    if not cls:
        return None
    ref_pat = re.compile(r"\b" + re.escape(cls) + r"\b")
    # 去后缀别名：OrderServiceImpl → Order，使引用它的 OrderController 也能命中
    m = re.match(
        r"^([A-Za-z][A-Za-z0-9]*?)(Mapper|Service|Dao|Repository|Impl|BO|Biz|"
        r"Manager|Util|Utils|Helper|Client|Engine|Config)$",
        cls,
    )
    alias = m.group(1) if (m and m.group(1) and m.group(1) != cls) else ""
    alias_pat = re.compile(r"\b" + re.escape(alias) + r"\w*\b") if alias else None

    Path(code_root)
    # 改用注解感知的控制器发现：主通道 *Controller.java（零回归），兜底按 @RestController/@Controller
    ctrls = _discover_web_controllers(code_root)
    if not ctrls:
        return None

    # 两优先级：先按「完整类名」精确引用（如 HttpUtils 被 SSRF.java 引用）择控制器；
    # 仅当无精确命中时，才回退到「去后缀别名」（如 OrderServiceImpl → Order）匹配。
    # 否则别名 \bHttp\w*\b 会误中 HttpURLConnection（CommandInject.java 等），把 SSRF/HttpUtils
    # 类漏洞错挂到命令注入控制器——这是早期「首个命中即锁 best」逻辑的假阳性根因。
    # 同优先级内若多个控制器都引用该类（WebUtils 被 9 个控制器共用），用「控制器名 ↔ 漏洞族」
    # 上下文打分择优，避免把 XSS/WebUtils 错挂到 /codeinject。
    exact_cands: List[Tuple[int, Dict[str, str]]] = []
    alias_cands: List[Tuple[int, Dict[str, str]]] = []
    for ctrl in ctrls:
        try:
            text = ctrl.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        hit_exact = bool(ref_pat.search(text))
        hit_alias = (not hit_exact) and (alias_pat is not None) and bool(alias_pat.search(text))
        if not (hit_exact or hit_alias):
            continue
        ctrl_stem = Path(str(ctrl)).stem
        lines = text.splitlines()
        base_path = ""
        for i, l in enumerate(lines):
            if "@RequestMapping" not in l:
                continue
            window = "\n".join(lines[i:i + 6])
            if not re.search(r"\bclass\s+\w+", window):
                continue
            _, bp = _spring_mapping_path_and_method(window, "GET")
            if bp:
                base_path = bp
                break
        method_cands: list = []
        for i, l in enumerate(lines):
            mm = _METHOD_MAPPING_RE.search(l)
            if not mm:
                continue
            window = "\n".join(lines[i:i + 5])
            # 它原本会作为 method_cands[0] 被选中（位于文件最靠前）→ 本函数直接返回
            # 锁在这种路径上且 param_name 全空，其中 40 条来自本通道
            # （param_name_source=caller-controller-reverse-lookup）。排除后，只有类级注解的
            # 控制器会因 method_cands 为空而跳过（下方 `if not method_cands: continue`），
            # 判为「路由不可靠」留空，不再产出不可调用的 spec。
            if re.search(r"\bclass\s+\w+", window):
                continue
            http, path = _spring_mapping_path_and_method(
                window, _HTTP_BY_ANNOTATION.get(mm.group(1), "GET")
            )
            if not path:
                continue
            # 提取该方法签名上的 @RequestParam / @PathVariable 参数名，供注入族回填 param_name。
            # sound 优先：注入族即便 param 空也放行（D1 全参注入兜底）；但若能从真实签名取到参数名，
            # 优先回填，提高 D1 注入精度而非纯误报。绝不编造不存在的参数名。
            sig_window = "\n".join(lines[i:i + 18])
            params = _extract_spring_params(sig_window)
            method_cands.append((http, path, params))
        if not method_cands:
            continue
        chosen = next(((h, p, ps) for h, p, ps in method_cands if "{id}" in p), method_cands[0])
        http, path, params = chosen
        route = path
        if base_path and path:
            _b = base_path.rstrip("/")
            route = path if (path == _b or path.startswith(_b + "/")) else _b + "/" + path.lstrip("/")
        elif base_path and not path:
            route = base_path
        # 保真归一：本函数是本文件里的「源码注解 → 真实路由」通道，其返回值会被 _lock_route
        # 直接锁进 trigger_specs.target_endpoint，必须保留注解原始大小写（Spring 大小写敏感）。
        route = _norm_route_case(route)
        if not is_valid_route(route):
            continue
        # 参数回填：{id} 路由优先用 id/path；否则取方法首个真实参数（注入族据此注入 canary）
        _pname = "id" if "{id}" in route else ""
        _ploc = "path" if "{id}" in route else "query"
        if not _pname and params:
            _pname = params[0][0]
            _ploc = params[0][1]
        cand = {
            "route": route,
            "method": (http or "GET").upper(),
            "param_name": _pname,
            "param_location": _ploc,
            "param_name_source": "caller-controller-reverse-lookup",
        }
        _score = _controller_match_score(ctrl_stem, vuln)
        if hit_exact:
            # 精确类名引用最可靠，入 exact 候选池按上下文打分择优（不再对 {id} 提前返回，
            # 否则首个匹配的控制器（如 CommandInject 字母序先于 XSS）会抢走 XSS/WebUtils 的归属）。
            exact_cands.append((_score, cand))
        else:
            # 别名命中仅作最后兜底，不抢精确命中。
            alias_cands.append((_score, cand))
    # 择优：同池内按上下文打分降序、其次按出现顺序（稳定）。
    # 歧义守卫：同一工具类被多个控制器共用、且无任一控制器名与漏洞族匹配（如 WebUtils 被 9 个
    # 不相关控制器共用、XSS/WebUtils 无法可靠归属到某个真实入口）时，返回 None 保持 missing_route，
    # 宁可漏报也不把漏洞错挂到错误端点（否则会污染 D1/D2 命中率统计并生成假阳性 spec）。
    if exact_cands:
        exact_cands.sort(key=lambda x: (-x[0],))
        _best_score = exact_cands[0][0]
        if len(exact_cands) > 1 and _best_score <= 0:
            return None
        return exact_cands[0][1]
    if alias_cands:
        alias_cands.sort(key=lambda x: (-x[0],))
        _best_score = alias_cands[0][0]
        if len(alias_cands) > 1 and _best_score <= 0:
            return None
        return alias_cands[0][1]
    return None


def _controller_match_score(ctrl_stem: str, vuln: Any) -> int:
    """调用链反查时，多个控制器都引用同一工具类（WebUtils 被 9 个控制器共用）时，
    用「控制器名 ↔ 漏洞上下文」打分择优，把 XSS/WebUtils 导向 XSS.java 而非 /codeinject。

    上下文取自漏洞族 / 原始类型 / 漏洞文件名 stem；命中控制器名（去 controller/java 后缀）
    即 +1。精确相等额外加权。绝不编造路由，仅在候选间排序。
    """
    stem = (ctrl_stem or "").lower()
    stem_base = re.sub(r"(controller|java)$", "", stem)
    vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else (vuln if isinstance(vuln, dict) else {})
    ctx: set = set()
    for _k in ("finding_family", "display_family", "original_type", "type"):
        _v = vuln_dict.get(_k) if isinstance(vuln_dict, dict) else getattr(vuln, _k, None)
        if _v:
            for _t in re.split(r"[^a-z0-9]+", str(_v).lower()):
                if _t:
                    ctx.add(_t)
    _vf = vuln_dict.get("file") if isinstance(vuln_dict, dict) else getattr(vuln, "file", None)
    if _vf:
        ctx.add(Path(str(_vf)).stem.lower())
    _score = 0
    for _t in ctx:
        if not _t:
            continue
        if _t in stem or _t in stem_base or stem in _t or stem_base in _t:
            _score += 1
    # 控制器名与漏洞族精确相等（ssrf↔ssrf / xss↔xss）强信号
    if stem in ctx or stem_base in ctx:
        _score += 2
    return _score


def _extract_spring_params(text: str) -> List[Tuple[str, str]]:
    """从 Spring 方法签名窗口提取 @RequestParam / @PathVariable 参数名与位置。

    仅取注解显式声明的参数名（value="x" 或 "x"），不编造；下游 D1 全参注入兜底时
    若无真实参数名仍可工作（sound 优先）。返回 [(name, location), ...]，location=query/path。
    """
    out: List[Tuple[str, str]] = []
    for m in re.finditer(r'@RequestParam\s*\(([^)]*)\)', text):
        arg = m.group(1)
        vm = re.search(r'(?:value\s*=\s*)?"([^"]+)"', arg)
        name = vm.group(1) if vm else None
        if name and is_valid_param_name(name):
            out.append((name, "query"))
    for m in re.finditer(r'@PathVariable\s*\(([^)]*)\)', text):
        arg = m.group(1)
        vm = re.search(r'(?:value\s*=\s*)?"([^"]+)"', arg)
        name = vm.group(1) if vm else None
        if name and is_valid_param_name(name):
            out.append((name, "path"))
    return out


def _norm_route(route: str) -> str:
    r = (route or "").strip().lower()
    if r and not r.startswith("/"):
        r = "/" + r
    return r.rstrip("/") or "/"


def _norm_route_case(route: str) -> str:
    """路由归一（**保真**）：只补前导斜杠、去尾斜杠，保留原始大小写。

    存在的理由：Spring 的 PathPattern 匹配大小写敏感，``/rce/ProcessBuilder`` 与
    ``/rce/processbuilder`` 是两个不同端点。``_norm_route`` 的 ``.lower`` 只能用于
    「比较两个路由是否同一端点」，一旦把它的返回值当作真实 HTTP 路径回写
    （trigger_specs.target_endpoint / exploit_spec.entry.route），D1 重放就会打到
    应用上不存在的路径 → 404 → 该 spec 永久 no-arrival。

    （/deserialize/rememberme/vuln 真实为 /deserialize/rememberMe/vuln、
    /rce/processbuilder 真实为 /rce/ProcessBuilder、
    /xxe/saxparser/vuln 真实为 /xxe/SAXParser/vuln 等），这 8 条在 D1 全部 404。
    """
    r = (route or "").strip()
    if r and not r.startswith("/"):
        r = "/" + r
    return r.rstrip("/") or "/"


def normalize_route_key(route: str) -> str:
    """公开的路由匹配键（小写归一）。跨模块做「大小写不敏感」路由比对时用本函数，
    不要直接 lower 拼字符串，以免与 ``_norm_route`` 的前导斜杠 / 尾斜杠规则漂移。"""
    return _norm_route(route)


def _norm_route_loose(route: str) -> str:
    """宽松归一化——去掉前导 ``/api``（及 ``/api/vN``）段，使 ``/api/status`` 与 ``/status``
    在匹配时视为同一端点。Spring 类级 ``@RequestMapping("/api")`` + 方法级 ``@GetMapping("/status")``
    拼出 ``/api/status``，而 entry_discovery 常记录为 ``/status``，二者必须对得上，否则 A2 假说路由
    永远匹配不到真实路由 → skipped_unresolved。"""
    r = _norm_route(route)
    parts = [p for p in r.split("/") if p]
    if not parts:
        return r
    if parts[0] == "api":
        parts = parts[1:]
        if parts and parts[0].lower().startswith("v") and parts[0][1:].replace(".", "").isdigit():
            parts = parts[1:]
    return ("/" + "/".join(parts)).rstrip("/") or "/"


def normalize_payload_family(family: str) -> str:
    """族名归一：把同义 / 分裂的 payload_family 合并到唯一规范名。

    解决「同一漏洞被 A2 标成 spel / ognl / template-injection / ssti 等多个族，
    导致被拆成多条 selected spec、D2 重复验证」的问题。

    - 模板/表达式注入类 → ``template-injection``
    - 越权类（IDOR/BOLA/BFLA/对象级/功能级）→ ``idor``
    其余原样返回（不改 sql-injection / command-execution 等已有规范名）。
    """
    f = (family or "").strip().lower()
    if not f or f == "generic":
        return f
    _template = ("spel", "ognl", "ssti", "template-injection", "templateinjection",
                 "expression-injection", "el-injection", "freemarker", "velocity",
                 "thymeleaf", "jinjava", "jexl")
    _idor = ("idor", "bola", "bfla", "broken-access-control", "broken-object-level",
             "object-level", "function-level", "authz", "insecure-direct-object")
    if any(k in f for k in _template):
        return "template-injection"
    if any(k in f for k in _idor):
        return "idor"
    return f


# ----------------------------------------------------------------------------
# 第二点 A：探针/诊断控制器路由过滤
# FrameworkProbeController 暴露 /api/fw/redis、/api/fw/dubbo、/api/fw/es 等
# 诊断端点，被 entry_discovery 扫进 discovered_routes。若不剔除，_match_disc 的
# 模糊/子串匹配会把反序列化/XXE/SSRF 的 spec 错指到这些端点 → 404 / 永远 not_hit。
# 这是杠杆最高的一刀：凡 probe controller 路由直接不参与 Tier0 匹配。
# ----------------------------------------------------------------------------
def _is_probe_route(file: str, route: str) -> bool:
    """判断一条 web_route 是否应被剔除（探针/诊断端点，非应用真实漏洞入口）。

    判据（仅路由本身命中即剔除）：路由以探针前缀开头（如 /api/fw/redis）。

    真实业务漏洞（如 SSRF ProfileController 的 /profile/avatar-from-url）归因到
    FrameworkProbeController 时，该真实业务路由被一併误杀。修正为仅按路由前缀判定——
    路由不属探针前缀即保留，无论其归属文件是否为探针类。这样真实业务端点不再被误剔。
    探针类标记 / 路由前缀均来自 workspace_runtime（第 7 类耦合外置）。

    路径**本身（如 ``/api/fw``，无尾段）同样命中探针控制器。原先仅 ``startswith(prefix)`` 会放过
    ``/api/fw``，导致 SSRF(HttpFetcher) 经调用链反查落到 FrameworkProbeController 的 ``/api/fw``
    base，路由等于 base 或以其为前缀即剔除，杜绝裸挂载漏网。
    """
    _r = str(route or "").lower()
    for _p in workspace_runtime.probe_route_prefixes():
        _base = _p.rstrip("/")
        if _r == _base or (_base and _r.startswith(_base + "/")):
            return True
    return False


# ----------------------------------------------------------------------------
# 第二点 D：sink 类 → 真实业务入口 兜底映射表
# 当 LLM/发现都给不出路由时，用漏洞的 sink 文件反查其真实 HTTP 入口，硬覆盖，
# 保证经典 sink 永远落到正确业务端点（而非落到探针/错误端点）。
# 反序列化 → /profile/import；XXE → /order/import-xml；SSRF(HttpFetcher) →
# /profile/avatar-from-url 与 /admin/fetch。每条带真实参数名兜底。
# ----------------------------------------------------------------------------
# 第二点 D / D-2 的 sink 类 → 真实业务入口兜底表已外置到 workspace_runtime
# （src/core/workspace_runtime.py: sink_file_route_overrides / sink_family_route_overrides）。



def _is_probe_file(file: str) -> bool:
    """判断 sink 文件是否属于 IAST 探针自身的调试控制器（/api/fw/* 那类），
    这类归因的 finding 本质是探针噪声而非应用真实漏洞。探针类标记来自 workspace_runtime（第 7 类耦合外置）。"""
    _f = str(file or "")
    return any(frag in _f for frag in workspace_runtime.probe_class_names())


def _norm_family(vuln_dict: Dict[str, Any]) -> str:
    """从 exploit_spec.payload.payload_family 或 type 归一化漏洞族名。"""
    _es = (vuln_dict or {}).get("exploit_spec") or {}
    _pl = _es.get("payload") or {}
    _f = _pl.get("payload_family") or _es.get("family") or (vuln_dict or {}).get("type") or ""
    return str(_f).strip().lower()


def _is_business_vuln(vuln_dict: Dict[str, Any]) -> bool:
    """综合多源族名判定业务型（越权/竞态/状态机/批量赋值/认证/滥用等）。

    修复 ③（fid360 根因）：``resolve_trigger_endpoint`` 的 ``_biz`` 门禁原只用
    ``_norm_family``（优先读 ``exploit_spec.payload.payload_family``）。A2 在
    ``plan_pocs`` 归一化之前，会把该字段写成 ``generic``/raw 等非业务 token，
    导致 ``_norm_family`` 返回非业务串、``is_business_logic_family`` 判 False、
    实体→Controller 回落被整体跳过——Mapper/Service/DAO 类越权 finding 因此解析不到
    路由。但同一 vuln 的 ``type``（如 ``水平越权``→bola）
    或 ``business_logic_category`` 已可靠携带业务族。本函数对全部族名承载字段逐一
    归一判定，任一命中 ``DIFFERENTIAL_PROOF_FAMILIES`` 即判业务型，使回落不再被单一
    未归一字段遮蔽。注入型族（sql/ssrf/xss…）归一后不在业务集合内，行为不变。
    """
    _es = (vuln_dict or {}).get("exploit_spec") or {}
    _pl = _es.get("payload") or {}
    _cands = [
        _pl.get("payload_family"),
        _es.get("family"),
        _es.get("business_logic_category"),
        (vuln_dict or {}).get("type"),
        (vuln_dict or {}).get("category"),
        (vuln_dict or {}).get("business_logic_category"),
        (vuln_dict or {}).get("vuln_type"),
    ]
    for _c in _cands:
        _c = str(_c or "").strip()
        if not _c:
            continue
        if canonical_business_logic_family(_c) in DIFFERENTIAL_PROOF_FAMILIES:
            return True
    return False


def _sink_class_route_overrides(vuln_dict: Any, vuln: Any) -> List[Dict[str, str]]:
    """按漏洞的 sink 文件（vuln.file）反查已知 sink 类的真实业务入口。

    仅当 sink 文件命中 _SINK_FILE_ROUTE_OVERRIDE 的键（如 DeserializeUtil.java）
    才返回兜底路由，避免对普通漏洞注入错误路由。返回多条时（如 SSRF 两个入口）
    全部作为低优先级候选追加，使 canary 能覆盖所有真实入口。
    """
    _f = str((vuln_dict or {}).get("file") or _field(vuln, "file") or "")
    if not _f:
        return []
    base = Path(_f).name
    out: List[Dict[str, str]] = []
    # 第二点 D：sink 类 → 真实业务入口兜底表已外置到 workspace_runtime（第 6 类耦合）。
    for key, routes in workspace_runtime.sink_file_route_overrides().items():
        if key in base:
            out.extend(routes)
    return out


def _resolve_sink_override(
    vuln_dict: Any, vuln: Any, discovered: Optional[List[Dict[str, Any]]]
) -> Optional[Dict[str, str]]:
    """第二点 D：sink 类兜底解析。仅当漏洞 sink 命中已知 sink 类且尚未解析出路由时调用。

    对每条兜底路由：优先在 discovered 真实路由里取真实参数名/位置；取不到则用兜底表自带参数。
    返回首个「有参数名」的兜底结果；全部无参数名则返回 None。
    """
    overrides = _sink_class_route_overrides(vuln_dict, vuln)
    if not overrides:
        # 第二点 D-2：file 类兜底查不到时（典型：A2 把 xxe/ssrf/cmd 误归到探针控制器），
        # 若漏洞 file 确属探针噪声且 family 是 well-known sink 族，按 family 回退真实业务入口，
        # 回收真实覆盖，使 D1 仍能量到真端点而非被探针噪声吞掉。
        if _is_probe_file(str((vuln_dict or {}).get("file") or _field(vuln, "file") or "")):
            fam = _norm_family(vuln_dict)
            # 第二点 D-2：family → 真实业务入口兜底表已外置到 workspace_runtime（第 6 类耦合）。
            overrides = workspace_runtime.sink_family_route_overrides().get(fam, [])
    if not overrides:
        return None
    # 建 (route_key -> params) 索引，供优先取真实参数名（键小写，大小写不敏感匹配）
    _disc_by_route: Dict[str, List[Dict[str, Any]]] = {}
    for _d in (discovered or []):
        _disc_by_route.setdefault(_d.get("route_key") or _norm_route(_d["route"]), []).append(_d)

    for _ov in overrides:
        # 保真回写：兜底表里的路由来自源码，必须保留原始大小写；匹配用小写键。
        _oroute = _norm_route_case(_ov["route"])
        _omethod = str(_ov.get("method", "POST")).upper()
        _oparam = str(_ov.get("param") or "")
        _oloc = str(_ov.get("location") or "query")
        _cs = _disc_by_route.get(_norm_route(_oroute))
        if _cs:
            _dparams = _cs[0].get("params") or []
            if _dparams:
                _oparam = _dparams[0].get("param_name", _oparam)
                _oloc = _dparams[0].get("param_location", _oloc)
        if _oparam:
            return {
                "route": _oroute,
                "method": _omethod,
                "param_name": _oparam,
                "param_location": _oloc,
                "param_name_source": "sink-class-override",
                "resolvable": True,
            }
    return None


def build_discovered_route_index(entries: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """把 entry_discovery 的 web_route 实体（含 request_params）规整为路由索引，
    供 resolve_trigger_endpoint 作为 Tier0（SAST 确认的 ground truth）与 A2 假说
    做精确（归一化）校验。

    返回 [{route, route_key, method, params:[{param_name, param_location}], file, line}]。
    - ``route``     ：保真路由（保留源码注解原始大小写），可直接作为 HTTP 路径使用；
    - ``route_key`` ：小写匹配键，仅用于大小写不敏感的路由比对。

    两者分离是必需的：Spring PathPattern 大小写敏感，route 必须保真；但匹配又必须
    大小写不敏感（历史数据与 A2 假说的大小写不可信赖）。曾把两者合并成一个小写 route，
    导致 8/22 个登记端点因大小写错误在 D1 全部 404（见 _norm_route_case 说明）。
    """
    out: List[Dict[str, Any]] = []
    if not entries:
        return out
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("entry_type") != "web_route":
            continue
        if e.get("is_class_level") or (e.get("metadata") or {}).get("is_class_level"):
            # 类级 @RequestMapping 仅作 base path，本身不可调用，不作为可重放端点登记。
            continue
        sig = e.get("signature") or ""
        route = _route_from_signature(sig)
        if not route:
            continue
        # 第二点 A：剔除探针/诊断控制器路由（/api/fw/redis 等），不参与 Tier0 匹配。
        if _is_probe_route(e.get("file", ""), route):
            continue
        method = _method_from_signature(sig)
        params: List[Dict[str, Any]] = []
        for p in (e.get("request_params") or e.get("metadata", {}).get("request_params") or []):
            if isinstance(p, dict) and p.get("param_name"):
                params.append({
                    "param_name": str(p["param_name"]),
                    "param_location": str(p.get("param_location") or "query"),
                })
        out.append({
            "route": route, "route_key": _norm_route(route), "method": method, "params": params,
            "file": e.get("file", ""), "line": e.get("line"),
        })
    return out


def ensure_route_index(entries: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """把 discovered_routes 统一成路由索引，并兼容两种入参形态。

    必须在同一函数里兼容两种形态，因为真实链路上两种都存在：

    - 原始形态：entry_discovery 的条目，字段为 signature / request_params / entry_type，
      没有 route / method / params。经 build_discovered_route_index 转换。
    - 索引形态：已经规整过的条目（带 route / method / params），例如 resolve_endpoint_full
      的内部构造与单元测试直接喂的输入。此时不能用 build_discovered_route_index 再过一遍——
      该函数按 entry_type == "web_route" 过滤，索引形态没有该字段，会被整批丢弃成空索引，

    返回的每条都保证有 route_key（匹配键），route 保持原大小写（保真）。
    """
    if not entries:
        return []
    _dicts = [e for e in entries if isinstance(e, dict)]
    if any("route" in e for e in _dicts):
        out: List[Dict[str, Any]] = []
        for e in _dicts:
            if e.get("is_class_level") or (e.get("metadata") or {}).get("is_class_level"):
                # 类级 @RequestMapping 仅作 base path，不作为可重放端点。
                continue
            _r = str(e.get("route") or "")
            if not _r:
                continue
            d = dict(e)
            d["route"] = _norm_route_case(_r)
            d["route_key"] = e.get("route_key") or _norm_route(_r)
            if not isinstance(d.get("params"), list):
                d["params"] = []
            out.append(d)
        return out
    return build_discovered_route_index(_dicts)


def _route_from_signature(sig: str) -> str:
    s = str(sig or "").strip()
    if not s:
        return ""
    m = re.search(r'["\']([^"\']+)["\']', s)
    raw = m.group(1) if m else s
    # Flask <conv:name>/<name> → Spring 风格 {name}，与 A2 假说路由对齐
    raw = re.sub(r"<(?:[a-zA-Z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>", r"{\1}", raw)
    # 保真归一：这里的 route 会经 Tier0 直接写进 trigger_specs.target_endpoint，
    # 必须保留源码注解里的原始大小写（曾用 _norm_route 全小写化，致 8/22 端点 404）。
    return _norm_route_case(raw)


def _method_from_signature(sig: str) -> str:
    s = str(sig or "")
    mm = re.search(r'@(Get|Post|Put|Delete|Patch|Request)\s*Mapping', s)
    if mm:
        verb = mm.group(1).lower()
        if verb == "request":
            rm = re.search(r"RequestMethod\.([A-Z]+)", s)
            return rm.group(1).upper() if rm else "GET"
        return verb.upper()
    fm = re.search(r"@(?:\w+)\.(get|post|put|delete|patch|options|head)\b", s)
    if fm:
        return fm.group(1).upper()
    if "methods" in s:
        mm2 = re.search(r"methods\s*=\s*\[?\s*[\"'](GET|POST|PUT|DELETE|PATCH)[\"']", s)
        if mm2:
            return mm2.group(1)
    if "@route" in s or "add_url_rule" in s:
        return "GET"
    return ""


_WEBSERVLET_ANNO_RE = re.compile(r"@WebServlet\s*\(([^)]*)\)", re.S)
# Servlet 取参写法分散（OWASP 205 个测试类实测：getCookies 51 / getParameter 27 /
# getHeader 21 / getQueryString 21 / getParameterValues 20），按「可注入位置」分派：
# query→query、getHeader→header、cookie getName.equals→cookie。
_SERVLET_PARAM_PATTERNS = (
    (re.compile(r"\.getParameter\s*\(\s*\"([^\"]+)\""), "query"),
    (re.compile(r"\.getParameterValues\s*\(\s*\"([^\"]+)\""), "query"),
    (re.compile(r"\.getHeader\s*\(\s*\"([^\"]+)\""), "header"),
    (re.compile(r"\.getName\(\)\s*\.equals(?:IgnoreCase)?\s*\(\s*\"([^\"]+)\""), "cookie"),
)


def _servlet_method_body(text: str, name: str) -> str:
    """截取 servlet 某个 doXxx 方法的方法体文本（从方法签名到下一个 doXxx 或文件末尾）。

    用于判定 doGet 是否委托 doPost：只取 doGet 体，避免把 doPost 体内的 doPost( 误判为委托。
    """
    m = re.search(r"void\s+" + re.escape(name) + r"\s*\(", text)
    if not m:
        return ""
    rest = text[m.start():]
    nxt = re.search(r"\n\s*(?:@Override\s*)?(?:protected|public|private)\s+void\s+do(?:Get|Post)\s*\(", rest[12:])
    return rest[: nxt.start() + 12] if nxt else rest


def servlet_self_endpoint(file_path: str) -> Optional[Dict[str, str]]:
    """从 Java 文件自身的 @WebServlet 注解解析入口路由与请求参数名。

    ``request.getParameter("username")`` 进入。而 param_resolver 的既有 tier 只认
    @RequestMapping / @RestController / @Controller，对这类工程一条路由都解不出，
    全部落到 missing_route（task-8 实锤：a2_poc 跳过 344 条）。

    与其它通道的分工：路由取自类级注解（代码级 ground truth），参数名取 doGet/doPost 方法体内
    首个 request.getParameter 实参名；Spring 工程无 @WebServlet，本函数直接返回 None，零回归。
    """
    if not file_path:
        return None
    try:
        text = Path(str(file_path)).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    if "@WebServlet" not in text:
        return None
    m = _WEBSERVLET_ANNO_RE.search(text)
    if not m:
        return None
    route = ""
    for cand in re.findall(r'"([^"]*)"', m.group(1)):
        if cand.startswith("/"):
            route = cand
            break
    if not route or not is_valid_route(route):
        return None
    # - 只有 doPost → POST。
    # - 只有 doGet → GET。
    #   （GET 请求最终仍进 doPost），但另有 216 个「非委托型」servlet——doGet 只做
    #   rememberMe cookie 之类的样板动作，真正的取参与 sink 都在 doPost。对这类用 GET
    #   判据：doGet 方法体内是否出现 doPost( 调用（委托）。实测 216/216 非委托型取参在 doPost。
    _has_get = bool(re.search(r"\bdoGet\b", text))
    _has_post = bool(re.search(r"\bdoPost\b", text))
    if _has_post and not _has_get:
        method = "POST"
    elif _has_get and _has_post:
        _get_body = _servlet_method_body(text, "doGet")
        method = "GET" if re.search(r"\bdoPost\s*\(", _get_body) else "POST"
    else:
        method = "GET"
    param_name = ""
    param_location = "query"
    for _pat, _loc in _SERVLET_PARAM_PATTERNS:
        _m2 = _pat.search(text)
        if _m2:
            param_name = _m2.group(1)
            param_location = _loc
            break
    if not param_name:
        # 动态枚举型取参（getParameterMap / getParameterNames / getHeaderNames / getQueryString / 裸 getCookies）：
        # 这类 servlet 遍历全部输入、接受任意名称（源码注释常写 "Grabs the name of the first
        # 作为注入位。这不是编造参数名——它们确实读取任意名称的输入，只是没有写死常量。
        _cls = Path(str(file_path)).stem
        if re.search(r"\.getParameterMap\s*\(|\.getParameterNames\s*\(", text):
            param_name, param_location = _cls, "query"
        elif re.search(r"\.getHeaderNames\s*\(|\.getHeaders\s*\(", text):
            param_name, param_location = _cls, "header"
        elif re.search(r"\.getQueryString\s*\(", text):
            param_name, param_location = _cls, "query"
        elif re.search(r"\.getCookies\s*\(", text):
            param_name, param_location = _cls, "cookie"
    return {
        "route": _norm_route_case(route),
        "method": method,
        "param_name": param_name,
        "param_location": param_location,
        "param_name_source": "servlet-self-annotation",
    }


def resolve_trigger_endpoint(
    vuln: Any,
    a1_evidence: Optional[Dict[str, Any]] = None,
    code_root: Optional[str] = None,
    discovered_routes: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, str]:
    """结合 A2 假说 + entry_discovery 真实路由 + A1 静态调用链证据 + 源码注解解析
    (route, method, param_name, location)，取代 guess_parameter_name 正则猜测。

    解析优先级（纯 SAST 静态，无运行时观测输入）：
    0. entry_discovery 真实路由（SAST ground truth，项目级全量 web_route + request_params）：
       与 A2 假说路由做归一化精确校验，命中即取真实路由/方法/参数名——这是「真实请求参数名」的
       最高权威来源。
    1. 源码注解解析 resolve_endpoint_from_source（路由/方法属代码级 ground truth）。
    2. A2 结构化 entry（AI 假说，无其它来源时的兜底）。
    匹配不到则返回空字段，由调用方跳过登记（不静默注入无效 spec）。
    """
    a1_evidence = a1_evidence or {}
    vuln_dict = vuln.to_dict() if hasattr(vuln, "to_dict") else (vuln if isinstance(vuln, dict) else {})
    exploit_spec = vuln_dict.get("exploit_spec") or {}
    entry = exploit_spec.get("entry") or {}
    # 故用文件自身注解兜底。此处只解析一次，供候选阶段与 Tier 0.5 复用，避免重复读文件。
    _servlet_self = servlet_self_endpoint(_field(vuln, "file"))

    # 8→5→3 退化的根因之一正是：exploit_spec.entry.route 为空，但 top-level entry_route /
    # trigger_route / entry_point（形如 "METHOD /path"）里确有真实入口却被忽略 → 全部回落到
    # Tier1/Tier2 仍解析不出 → skipped_unresolved。候选来源（按 SAST ground truth 优先级合并、去重）：
    #   ① exploit_spec.entry.route / trigger_route
    #   ② top-level entry_route / trigger_route
    #   ③ top-level entry_point（"METHOD /path" → 解析出 method + route）
    candidate_routes: List[Tuple[str, Optional[str]]] = []
    _seen_routes: set = set()

    def _add_candidate(_r: str, _m: Optional[str]) -> None:
        _r = _norm_route(_r)
        if not _r or _r in _seen_routes:
            return
        # 1.1 守门：拒绝源码路径（D:\...\X.java:118 等）进入候选，避免被当成 route 锁进 spec
        if not is_valid_route(_r):
            return
        # 第二点 A 守门：拒绝探针/诊断控制器路由（/api/fw/dubbo、/api/fw/redis 等）作为候选。
        # 否则 A2 的 entry.route 落到探针调试路由、Tier0 匹配不到真实路由后回落 Tier2 直接锁成 spec，
        # 导致 SSRF/XSS/命令注入等被错误登记到探针端点、D1 重放 404（技术类漏洞漏掉的根因之一）。
        # 拒绝后，这些漏洞会回落到 sink 类兜底（HttpFetcher → /profile/avatar-from-url 等真实业务入口），
        # 从而被回收为可按真实路由重放的 spec。
        if _is_probe_route(_field(vuln, "file"), _r):
            return
        _seen_routes.add(_r)
        candidate_routes.append((_r, str(_m).upper() if _m else None))

    # ⓪ 静态路由索引（A1 阶段 bind_static_routes 写入的**确定性事实**）：
    # 设计约定是「路由绑定优先走静态 resolver，
    # 仅歧义情形回落 LLM 推断」。落地前候选顺序恰好相反（① LLM 写的 exploit_spec.entry.route
    # 排在 ⑤ a1_evidence.target_endpoint 之前），LLM 猜错的路由会盖掉静态正确路由。
    # 仅在 route_status=='static' 时提权：该标记只由 bind_static_routes 写入；历史数据里
    # 由 LLM 写进 a1_evidence.target_endpoint 的值不带此标记，优先级不变。
    if str(a1_evidence.get("route_status") or "") == "static":
        _static_ep = str(a1_evidence.get("target_endpoint") or "").strip()
        if _static_ep:
            _add_candidate(_static_ep, str(a1_evidence.get("http_method") or "").strip().upper() or None)

    # ① exploit_spec.entry 的入口路由（D1 重放应把 canary 注入 HTTP 入口点，而非污点汇聚的触发点）
    if entry.get("route"):
        _add_candidate(str(entry.get("route")), entry.get("method"))
    # ② top-level entry_route（HTTP 入口点；如反序列化链 POST /debug/import 才是注入点）
    if vuln_dict.get("entry_route"):
        _add_candidate(str(vuln_dict.get("entry_route")), entry.get("method") or vuln_dict.get("entry_method"))
    # ③ trigger_route（污点触发/汇聚点，如反序列化链末端 GET /api/quote/random）——入口解析失败时的回退
    if entry.get("trigger_route"):
        _add_candidate(str(entry.get("trigger_route")), entry.get("method"))
    if vuln_dict.get("trigger_route"):
        _add_candidate(str(vuln_dict.get("trigger_route")), entry.get("method") or vuln_dict.get("trigger_method"))
    # ③ top-level entry_point（"METHOD /path"）
    _ep = str(vuln_dict.get("entry_point") or "").strip()
    if _ep:
        _m: Optional[str] = None
        _rest = _ep
        _parts = _ep.split(None, 1)
        if len(_parts) == 2 and _parts[0].upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            _m, _rest = _parts[0].upper(), _parts[1].strip()
        _add_candidate(_rest, _m)
    # ④ 兜底：top-level 直接带 route / entry_point_route 的极少数 A2 格式
    for _k in ("route", "entry_point_route"):
        if vuln_dict.get(_k):
            _add_candidate(str(vuln_dict.get(_k)), entry.get("method"))
    # ④-2 自身 @WebServlet 路由（纯 Servlet/JSP 工程专属）：纳入候选后，Tier 0 能用
    # entry_discovery 产出的真实 request_params 补全参数名（比源码正则取到的更权威）。
    if _servlet_self:
        _add_candidate(_servlet_self["route"], _servlet_self.get("method"))
    # ⑤ A1 业务逻辑/BOLA 假说的端点（a1_evidence.target_endpoint / http_method）：
    # 由 A1 离线分析器或 A1BusinessLogicAIAgent(LLM) 在 SAST 阶段产出，其真实 HTTP 入口只挂在
    # a1_evidence 上，不进入 exploit_spec.entry（那是 A2 的 AI 假说字段）。若不纳入候选，融合后的
    # 业务逻辑 finding 会在所有 tier 解析不出路由 → skipped_unresolved → 永远到不了 D1 重放。
    # 纳入候选后参与 Tier0(真实路由)/Tier1(观测面) 精确匹配；匹配不到再回落 Tier2(源码)/Tier3(A2)。
    _a1_ep = str(a1_evidence.get("target_endpoint") or "").strip()
    if _a1_ep:
        _a1_method = str(a1_evidence.get("http_method") or "").strip().upper() or None
        _add_candidate(_a1_ep, _a1_method)

    # 第二点 D：sink 类 → 真实业务入口兜底。仅当漏洞 sink 命中已知 sink 类
    # （DeserializeUtil/XmlImporter/HttpFetcher）时追加其真实路由为低优先级候选，
    # 保证经典 sink 永远落到正确业务端点（如反序列化 → /profile/import），不被解析失败
    # 逼到探针/错误端点。追加在最后，仅当其它候选都匹配不到时才被采用。
    for _ov in _sink_class_route_overrides(vuln_dict, vuln):
        _add_candidate(_ov["route"], _ov.get("method", "POST"))

    # ===== Tier 0：entry_discovery 真实路由（SAST ground truth，最高优先级）=====
    # entry_discovery 在 Phase 0.7 产出项目级真实 web_route 实体（含 request_params），
    # 这是 SAST 确认的入口 ground truth，应优先与 A2 假说做精确校验。匹配不到才回退
    # Tier1(源码注解)/Tier2(A2 结构化 entry)/Tier3(业务逻辑端点)。
    discovered = ensure_route_index(discovered_routes)
    if discovered:
        # 索引键用 route_key（小写），值仍是保真 route——匹配大小写不敏感，回写保真。
        _disc_by_route: Dict[str, List[Dict[str, Any]]] = {}
        for _d in discovered:
            _disc_by_route.setdefault(_d.get("route_key") or _norm_route(_d["route"]), []).append(_d)

        def _match_disc(cand_route: str, cand_method: Optional[str]) -> Optional[Dict[str, Any]]:
            """第二点 B：收紧匹配——仅「归一化精确相等」或「去 /api 前缀后的宽松相等」，
            且强制 method 一致（discovered method 为空时视为通配）。删除原先的 endswith
            子串匹配，避免候选 /profile/import 被错指到 /redis 之类的长尾误映射。

            大小写不敏感（键均经 _norm_route 小写化）：A2 假说与历史库数据的大小写不可信赖，
            但命中的 route 必须回写保真大小写，否则 D1 打到不存在的路径 → 404。
            """
            _ck = _norm_route(cand_route)
            _lc = _norm_route_loose(cand_route)
            # 1) 精确归一化相等（优先 method 一致；discovered method 为空视为通配）
            if _ck in _disc_by_route:
                _cs = _disc_by_route[_ck]
                if cand_method:
                    for _c in _cs:
                        _m = (_c.get("method") or "").upper()
                        if not _m or _m == cand_method.upper():
                            return _c
                    return None  # method 给定但全不匹配 → 不匹配（避免 GET 当 POST 注入）
                return _cs[0]
            # 2) 宽松（去 /api 前缀）相等（对齐 A2 假说 /api/x 与真实路由 /x）
            for _r, _cs in _disc_by_route.items():
                if _norm_route_loose(_r) == _lc:
                    if cand_method:
                        for _c in _cs:
                            _m = (_c.get("method") or "").upper()
                            if not _m or _m == cand_method.upper():
                                return _c
                        return None
                    return _cs[0]
            return None

        for _cr, _cm in candidate_routes:
            _m = _match_disc(_cr, _cm)
            if not _m:
                continue
            _droute = _m["route"]
            _dmethod = (_m.get("method") or str(entry.get("method") or "GET")).upper()
            _dparams = _m.get("params") or []
            _a2_pname = str(entry.get("parameter_name") or "")
            if is_valid_param_name(_a2_pname) and any(p.get("param_name") == _a2_pname for p in _dparams):
                _pname = _a2_pname
                _loc = next((p.get("param_location") for p in _dparams if p.get("param_name") == _a2_pname), "query")
                _src = "a2+discovered"
            elif _dparams:
                _p0 = _dparams[0]
                _pname = _p0.get("param_name", "")
                _loc = _p0.get("param_location") or "query"
                _src = "discovered"
            elif is_valid_param_name(_a2_pname):
                _pname = _a2_pname
                _loc = entry.get("parameter_location") or "query"
                _src = "a2+discovered"
            else:
                # 命中路由但无可用参数名：本 tier 无效，落到更低 tier 继续解析
                continue
            if not _pname:
                continue
            return {
                "route": _droute,
                "method": _dmethod,
                "param_name": _pname,
                "param_location": _loc,
                "param_name_source": _src,
                "resolvable": True,
            }

        # 2. 类级模糊匹配（回收 A2 给源码路径而非真实路由的 BOLA/IDOR finding）：
        # 当 A2 的 entry_route 是 file:line（已被 is_valid_route 在 _add_candidate 拒掉、candidate 里
        # 没有真实路由）时，用漏洞 file 的 basename 对齐 entry_discovery 的 web_route.file（同文件），
        # 把漏洞挂到该控制器已确认的真实 web_route 上，从而把「永远 not_hit 的垃圾 spec」回收为
        # 「可按真实路由重放的 spec」。优先选与 A2 method 一致、且 line 最接近（<= vuln.line 且最大）的 web_route。
        _vuln_file = _field(vuln, "file")
        if _vuln_file:
            _vuln_base = Path(_vuln_file).name
            if _vuln_base:
                _disc_by_file: Dict[str, List[Dict[str, Any]]] = {}
                for _d in discovered:
                    _df = _d.get("file", "")
                    if _df:
                        _disc_by_file.setdefault(Path(_df).name, []).append(_d)
                _file_matches = _disc_by_file.get(_vuln_base)
                # 注：类级 @RequestMapping 的 base path（如 /urlRedirect）已在 entry_discovery
                # 阶段标记为 is_class_level、并在 build_discovered_route_index / ensure_route_index
                # 中剔除，不会进入 _file_matches；故此处无需再做前缀过滤，避免误删带参数的兄弟
                # 真实端点（如 /api/address 与 /api/address/{id} 共存时）。
                if _file_matches:
                    try:
                        _vuln_line = int(_field(vuln, "line") or 0)
                    except Exception:
                        _vuln_line = 0
                    _a2_method = str(entry.get("method") or vuln_dict.get("entry_method") or "").upper() or None

                    def _score_disc(_dm: Dict[str, Any]) -> int:
                        _s = 0
                        if _a2_method and (_dm.get("method") or "").upper() == _a2_method:
                            _s += 2
                        _dl = int(_dm.get("line") or 0)
                        if _vuln_line and _dl and _dl <= _vuln_line:
                            _s += 1
                        return _s

                    _chosen = max(_file_matches, key=_score_disc)
                    _droute = _chosen["route"]
                    _dmethod = (_chosen.get("method") or str(entry.get("method") or "GET")).upper()
                    _dparams = _chosen.get("params") or []
                    _a2_pname = str(entry.get("parameter_name") or "")
                    if is_valid_param_name(_a2_pname) and any(p.get("param_name") == _a2_pname for p in _dparams):
                        _pname = _a2_pname
                        _loc = next((p.get("param_location") for p in _dparams if p.get("param_name") == _a2_pname), "query")
                        _src = "a2+discovered-file"
                    elif _dparams:
                        _p0 = _dparams[0]
                        _pname = _p0.get("param_name", "")
                        _loc = _p0.get("param_location") or "query"
                        _src = "discovered-file"
                    elif is_valid_param_name(_a2_pname):
                        _pname = _a2_pname
                        _loc = entry.get("parameter_location") or "query"
                        _src = "a2+discovered-file"
                    else:
                        _pname = ""
                        _loc = "query"
                        _src = "discovered-file"
                    # 探针调试路由（/api/fw/*）即便通过 file 匹配也不得作为真实入口返回——
                    # A2 把 xxe/ssrf/cmd 误归到 FrameworkProbeController 时该 file 确在 discovered 里，
                    # 若不拦会被锁到探针端点。拦下后回落到 sink family 兜底拿真实业务入口。
                    if _pname and not _is_probe_route(_chosen.get("file", ""), _droute):
                        return {
                            "route": _droute,
                            "method": _dmethod,
                            "param_name": _pname,
                            "param_location": _loc,
                            "param_name_source": _src,
                            "resolvable": True,
                        }

    result: Dict[str, Any] = {
        "route": "", "method": "", "param_name": "", "param_location": "",
        "param_name_source": "", "resolvable": False, "resolution_failure": "",
    }

    # 文件自身注解是唯一的代码级 ground truth。放在 sink 兜底表之前：
    # 注解事实优先于硬编码兜底表。Spring 工程无 @WebServlet，_servlet_self 为 None，零回归。
    if not result["route"] and _servlet_self:
        _sv_route = _norm_route_case(_servlet_self["route"])
        if is_valid_route(_sv_route):
            result["route"] = _sv_route
            result["method"] = _servlet_self.get("method") or "GET"
            if not result["param_name"] and _servlet_self.get("param_name"):
                result["param_name"] = _servlet_self["param_name"]
                result["param_location"] = _servlet_self.get("param_location") or "query"
                result["param_name_source"] = _servlet_self.get("param_name_source") or "servlet-self-annotation"

    # 第二点 D：sink 类兜底——若上面所有候选都没解析出路由，但漏洞 sink 命中已知 sink 类
    # （DeserializeUtil/XmlImporter/HttpFetcher/UserMapper/ProductMapper/CouponMapper/JdbcReportDao），
    # 直接用兜底表构造 (route, param, location)，不再回落到探针/错误端点。优先用 discovered 里该
    # 路由的真实参数名；没有则用兜底表自带参数。仍无参数名则跳过。
    if not result["route"]:
        _sink_override = _resolve_sink_override(vuln_dict, vuln, discovered)
        if _sink_override:
            return _sink_override

    # route 一旦被某 tier 确认即锁定：低优先级 tier 只补 param，不再回退/覆盖已确认的路由，
    def _lock_route(_r: str, _m: str) -> None:
        if not result["route"]:
            _nr = _norm_route(_r)
            # 1.1 守门：Tier2 的 a2_route 若是源码路径（OrderService.java:118 之类）不能锁成 route
            if not is_valid_route(_nr):
                return
            # 第二点 A 守门（Tier1/2 补漏）：A2 把 entry.route 写成探针调试路由时，
            # _add_candidate 已在 Tier0 候选阶段拒绝，但 Tier1/2 直接走 _lock_route 不经过
            # _add_candidate，故此处必须再挡一次——否则 xxe/ssrf/command-execution 等会被锁进
            if _is_probe_route(_field(vuln, "file"), _nr):
                return
            # 锁进 spec 的路由必须保真大小写：_nr（小写）只作守门判定，回写用 _norm_route_case。
            result["route"] = _norm_route_case(_r)
            result["method"] = str(_m or "GET").upper()

    # —— Tier 1：源码注解解析（@RequestMapping 等，路由/方法属代码级 ground truth）——
    # 用户 point 4：源码注解置于 A2 之上（路由/方法以代码声明为准）；但参数名推断弱于 A2 的
    # 结构化结论，故 param 优先用 A2 合法 param，缺则回退源码提取。不再有 A1 独立回退层。
    # 业务类（bola/idor/垂直越权等无 sink）强制走源码注解通道：即便 A2 已给 param_name 也
    # 必须由其 file:line 重算真实 HTTP 入口，否则会回落到错误/幻觉端点。
    _biz = _is_business_vuln(vuln_dict)
    # 的技术型漏洞（SQL 注入 / SSRF 等，落在 Mapper/Util 类）整块跳过，导致实体名→Controller 与
    # 调用链反查两条路由兜底通道（_resolve_controller_route_by_entity / _resolve_controller_route_by_reference）
    # SQLi#2 / SSRF#11 有 findings 但 0 spec）。参数名与路由是独立维度：路由缺失时必须给兜底通道一次机会，
    # 与 param_name 是否已解析无关。故改为只要 code_root 可用即进入本通道；内部各分支自守门
    # （by_entity 仍需 _biz；by_reference 仍需 route 为空）。源码注解仍优先采用 A2 合法 param_name，不回退覆盖。
    if code_root:
        _src = resolve_endpoint_from_source(vuln, code_root)
        # 仅当纠偏结果与按 line 解析不同、且同文件确有该方法映射时才覆盖（代码级事实）。
        _hint = resolve_endpoint_by_method_hint(vuln, code_root, vuln_dict)
        if _hint and _hint.get("route") and (_src is None or _hint.get("route") != _src.get("route")):
            logger.warning(
                "[route-fix] 方法名纠偏 %s：按 line 解析=%s → 文本点名 %s 对应 %s",
                vuln_dict.get("file"), (_src or {}).get("route"), _hint.get("function"), _hint.get("route"),
            )
            _src = _hint
        if _src and _src.get("route"):
            _lock_route(_src.get("route", ""), str(_src.get("method") or "GET"))
            a2_pname = str(entry.get("parameter_name") or "")
            src_pname = _src.get("param_name") or ""
            if is_valid_param_name(a2_pname):
                result["param_name"] = a2_pname
                result["param_name_source"] = "a2"
                # 旧实现在 A2 param_name 有效时保留 A2 的 location ⇒ 出现
                # 「名字来自 A2、位置也来自 A2，但两者错配」的契约：
                #   /xss/reflect 源码是 `reflect(String xss)`（**query** 绑定），
                #   A2 却给了 cookie ⇒ D1 把 canary 投到 Cookie，
                #   而该端点只读 query 参数 ⇒ 响应恒空 ⇒ 该真值点恒漏。
                #
                # 纪律：参数名与位置是**同一个契约的两半**，源码解析出的位置是
                # **代码级 ground truth**（Spring 的绑定规则由签名决定，不由 LLM 决定）。
                # A2 的 location 只在源码**解析不出**位置时才作为兜底。
                _src_loc = str(_src.get("param_location") or "").strip().lower()
                if _src_loc:
                    result["param_location"] = _src_loc
                elif not result["param_location"]:
                    result["param_location"] = "query"
            elif is_valid_param_name(src_pname):
                result["param_name"] = src_pname
                result["param_name_source"] = "source-recovered"
                # 采信源码**。旧实现把 location 的采信放在「A2 param_name 有效」的分支之前，
                # 于是只要 A2 填了 location（哪怕是错的），源码解析出的正确定位就被丢弃 ——
                # 实测 /rce/jscmd：源码签名是 `jsEngine(String jsurl)`（query 绑定），
                # A2 却给了 body ⇒ spec 登记成 body ⇒ D1 把 canary 投到 body，
                # servlet 根本不读那里 ⇒ 端点永久 no-arrival（237721 恒 payload_unavailable）。
                #
                # 参数名与参数位置是**同一个契约的两半**，来源必须一致，
                # 否则会出现「名字来自源码、位置来自 LLM」的拼接契约。
                result["param_location"] = _src.get("param_location") or "query"
            if result["param_name"]:
                result["resolvable"] = True
                return result
        # 业务类 file 指向 Mapper/Service/DAO（无 @RequestMapping）时，源码注解通道落空；
        # 改由「实体名→同名 *Controller」二次源码注解取真实 HTTP 入口（业务型多为按 id 查询，
        # 优先取含 {id} 端点）。仅业务族、且 route 仍为空时触发；绝不把源码路径当路由，也不覆盖已确认路由。
        if _biz and not result["route"]:
            _ctrl = _resolve_controller_route_by_entity(vuln, code_root)
            if _ctrl and _ctrl.get("route"):
                _lock_route(_ctrl.get("route", ""), str(_ctrl.get("method") or "GET"))
                if not result["param_location"]:
                    result["param_location"] = _ctrl.get("param_location") or "query"
                if not result["param_name"] and _ctrl.get("param_name"):
                    result["param_name"] = _ctrl["param_name"]
                    result["param_name_source"] = _ctrl.get("param_name_source", "entity-controller-inferred")
                result["resolvable"] = True
                return result
        # sound 优先（宁可误报也不漏报）：调用链反查兜底。
        # 实体名推导对工具类/配置类失效时，改按「哪些 Controller 引用了漏洞所在类」反查真实 HTTP 入口。
        # 不区分业务族 / 注入族——路由来自真实源码注解，正确性由下游 D1/I1/D2 确认；
        # 注入族即便 param 仍空也放行，交由 D1 全参 canary 注入兜底（SAST 保证 sound 而非 truth）。
        if not result["route"]:
            _ref = _resolve_controller_route_by_reference(vuln, code_root)
            if _ref and _ref.get("route"):
                _lock_route(_ref.get("route", ""), str(_ref.get("method") or "GET"))
                if not result["param_location"]:
                    result["param_location"] = _ref.get("param_location") or "query"
                if not result["param_name"] and _ref.get("param_name"):
                    result["param_name"] = _ref["param_name"]
                # 调用链反查来源始终记录：即便 param 为空（控制器方法无 @RequestParam，由 D1 全参
                # canary 注入兜底），路由确实来自反向引用，必须留痕便于追溯与审计，不放空。
                result["param_name_source"] = _ref.get(
                    "param_name_source", "caller-controller-reverse-lookup"
                )
                result["resolvable"] = True
                return result

    # —— 静态路由优先锁（先于 Tier 2 的 A2 LLM 假说）——
    # 设计约定：「路由绑定优先走静态 resolver，
    # 仅歧义情形回落 LLM 推断」。落地前 Tier 2 会先用 A2 假说的 entry.route 锁住路由
    # （_lock_route 只认首次锁定），静态事实只能退到 Tier 3.5 兜底 → LLM 猜错即盖掉静态正确值。
    # 此处把 A1 阶段 bind_static_routes 写入的静态路由（route_status=='static'）提前锁定。
    # 放在 Tier 1 源码注解解析之后是刻意的：两者同属代码级事实且对同一 controller 结论一致，
    # 而 Tier 1 还带 Service→Controller 反查（静态绑定失败的场景恰恰靠它兜底）。
    if not result["route"] and str(a1_evidence.get("route_status") or "") == "static":
        _static_ep = str(a1_evidence.get("target_endpoint") or "").strip()
        if _static_ep:
            _lock_route(_static_ep, str(a1_evidence.get("http_method") or "GET"))

    # —— Tier 2：A2 结构化 entry（AI 假说，无源码时的兜底；同时纳入 top-level entry_route/trigger_route）——
    # a2_route_raw 保留原始大小写供回写；a2_route 小写仅供「是否为空」判定与守门。
    a2_route_raw = (
        entry.get("route") or entry.get("trigger_route")
        or vuln_dict.get("entry_route") or vuln_dict.get("trigger_route") or ""
    )
    a2_route = _norm_route(a2_route_raw)
    a2_pname = str(entry.get("parameter_name") or "")
    if is_valid_param_name(a2_pname) and a2_route:
        _lock_route(a2_route_raw, str(entry.get("method") or "GET"))
        result["param_name"] = a2_pname
        result["param_location"] = entry.get("parameter_location") or "query"
        result["param_name_source"] = "a2"
        result["resolvable"] = True
        return result

    # 仍无：不退化到任何静态猜测（已删除 A1 独立回退层；也不再构造 /api/api 之类垃圾值）。
    # 调用方 auto_register_from_a2 检测到 route/param_name 为空即跳过登记，并在日志中归因于
    # 「空 code_root + 无 entry_discovery 真实路由 + A2 未产出合法结构化入口」，而非静默登记无效 spec 把 canary
    # 注入到应用根本不读取的位置（这正是此前 I1 永远读不到、I1/I2 全 0 的根因之一）。

    # —— Tier 3.5：业务逻辑路由兜底（a1_evidence.target_endpoint）——
    # 前序 tier 都未解析出路由时（无 entry_discovery 真实路由命中、无观测面、无源码注解、A2 未给
    # 结构化 entry），直接用 A1 分析器/LLM 在 SAST 阶段产出的真实 HTTP 入口（a1_evidence.target_endpoint）
    # 作为路由锁定。该端点是 SAST 静态 ground truth（分析器读的是真实代码），与 Tier3 直接锁 A2 entry
    # 的风险同级；调用方 auto_register_from_a2 仍会对解析结果做 is_valid_param_name/路由非空校验。
    # 绝不为 file:line 形式的 entry_point 编造路由——只认 a1_evidence.target_endpoint 这一显式 HTTP 端点。
    if not result["route"]:
        _a1_ep = str(a1_evidence.get("target_endpoint") or "").strip()
        if _a1_ep:
            _a1_method = str(a1_evidence.get("http_method") or "").strip().upper() or "GET"
            # 1.1 守门：a1 业务逻辑端点是 SAST 静态 ground truth，但必须确为 HTTP 路由；
            # 若为 Java 源码路径（OrderService.java:118 之类）则拒绝，绝不作为 route 锁进 spec，
            # 而是回落 Tier1 源码注解（类级 @RequestMapping 前缀拼接）继续尝试真实路由。这止血了
            # BOLA/IDOR 把源码路经当路由登记、D1 向不存在端点发请求永远 not_hit 的污染
            if is_valid_route(_a1_ep):
                # 保真回写：A1 静态端点的路由来自源码，必须保留原始大小写。
                result["route"] = _norm_route_case(_a1_ep)
                result["method"] = _a1_method
                result["param_name_source"] = "a1-business-logic"

    # —— Tier 3.6：业务逻辑 param 兜底（a1_evidence.vulnerable_param）——
    # route 已锁定（⑤ 候选命中 / Tier2 源码 / Tier3.5 直接锁）但 param 仍空时，用 A1 分析器给出的
    # 真实参数名（vulnerable_param）补位，使业务逻辑 finding 可登记为可重放 spec。
    # 仅在 route 已解析时才允许填 param，绝不为无路由的 finding 编造 param（否则会注入到不存在的端点）。
    if result["route"] and not result["param_name"]:
        _a1_pname = str(a1_evidence.get("vulnerable_param") or "").strip()
        if is_valid_param_name(_a1_pname):
            result["param_name"] = _a1_pname
            result["param_name_source"] = "a1-business-logic"
    # sink 落在**工具类**里时（`HttpUtils.request` / `SecurityUtil.checkSSRF` /
    # 都解析不出路由 ⇒ 该漏洞永远登记不到 spec ⇒ 永久 no-arrival。
    # 这里顺着 code_index 的 callers 往上找**最近的 HTTP 入口**，且只在
    # 「同深度只有一个不同路由」时采用（工具方法常被多个端点复用，有歧义就不猜）。
    if not result["route"] and code_root:
        try:
            from src.core.callgraph_route import route_via_callers
            _cg = route_via_callers(code_root, _field(vuln, "file"), _field(vuln, "line"))
            if _cg.get("route"):
                result["route"] = _cg["route"]
                if _cg.get("method") and str(_cg["method"]).upper() not in ("ANY", ""):
                    result["http_method"] = str(_cg["method"]).upper()
                result["route_source"] = "callgraph:%dhop" % int(_cg.get("hops") or 0)
                result["route_status"] = "static"
            else:
                # Tier 3.8：**两步桥**（写入口 → 存储 → 调度器执行）。
                # 定时任务/消息队列这类 sink 不是由请求直接触发的，调用图里没有 HTTP 入口
                # 这里从 sink 读的字段反查「谁把用户输入写进这个实体」，拿那个写入口当路由，
                # 并在 prerequisites 里标明这是两步攻击。
                from src.core.callgraph_route import route_via_writer
                _wr = route_via_writer(code_root, _field(vuln, "file"), _field(vuln, "line"))
                if _wr.get("route"):
                    result["route"] = _wr["route"]
                    if _wr.get("method") and str(_wr["method"]).upper() not in ("ANY", ""):
                        result["http_method"] = str(_wr["method"]).upper()
                    result["route_source"] = "writer-bridge:%s" % (_wr.get("bridge") or "")
                    result["route_status"] = "static"
                    result["two_step_bridge"] = True
                    # 两步桥的 getter 名（`getInvokeTarget` → `invokeTarget`）就是
                    # 用户可控的那个字段，直接当参数名。否则注入族因缺 param_name
                    # 仍判不可解析（`resolvable=False`），spec 依旧登记不上。
                    _br = str(_wr.get("bridge") or "")
                    _fld = _br.split(":", 1)[1] if ":" in _br else ""
                    if _fld.startswith("get") and len(_fld) > 3:
                        _fld = _fld[3].lower() + _fld[4:]
                    if _fld and not result["param_name"]:
                        result["param_name"] = _fld
                        result["param_name_source"] = "writer-bridge"
        except Exception as _cg_e:  # noqa: BLE001
            logger.debug("[resolve] 调用图反查路由失败（忽略）：%s", _cg_e)

    if not result["param_location"]:
        result["param_location"] = "query"
    # resolvable 按族分级。注入型仍要求 route 且 param_name 双非空（参数名是注入点定位依据）；
    # 非注入型（业务/认证/状态机：越权换身份重放、竞态并发重复、状态机跳步、批量赋值加字段）
    # 不依赖「参数名」概念，只要 route 非空即可 resolvable，param 允许为空交由重放策略决定。
    _norm = _norm_family(vuln_dict)
    if result["route"] and (result["param_name"] or not is_injection_family(_norm)):
        result["resolvable"] = True
        return result

    # 记录解析失败原因（不在此清空 ground truth；调用方据 resolved 决定是否写回 entry）。
    if not result["route"]:
        result["resolution_failure"] = "missing_route"
    elif is_injection_family(_norm) and not result["param_name"]:
        result["resolution_failure"] = "missing_param_injection"
    else:
        result["resolution_failure"] = "unresolved"
    return result
