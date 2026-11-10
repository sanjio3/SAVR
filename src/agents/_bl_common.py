"""业务逻辑静态分析公共件（§2.2 业务逻辑策略分析体系共享）。

提供多语言函数抽取、token 命中判定等启发式基础件，供 a1_*_analyzer 各分类复用，
避免每个分析器重复实现括号匹配 / 函数体扫描。首版为启发式（正则 + 轻量结构感知），
后续可统一升级为 CodeQL 查询或 AI 语义分析，对外接口保持稳定。
"""
import re
from typing import Any, Dict, List, Optional, Tuple


def _annotation_prefix(lines: List[str], i: int) -> List[str]:
    """方法签名上方可能附有安全注解/装饰器（Java @PreAuthorize、Python @decorator、注释），
    这些在括号匹配抽取时位于 body 之外，需一并纳入 token 扫描，否则角色/限流校验会被漏看。"""
    prefix: List[str] = []
    j = i - 1
    while j >= 0:
        s = lines[j].strip()
        if s.startswith("@") or s.startswith("//") or s.startswith("*"):
            prefix.insert(0, lines[j])
            j -= 1
        else:
            break
    return prefix


def extract_functions(content: str, lang: str) -> List[Dict[str, Any]]:
    """按语言抽取函数/方法块（启发式，够 analyzer 用）。返回 [{name, params, body, start}]。

    body 含方法签名上方的安全注解/装饰器前缀，确保 @PreAuthorize/@RateLimit 等校验可见。
    """
    funcs: List[Dict[str, Any]] = []
    lines = content.splitlines()
    lang = (lang or "").lower()

    if lang in ("py", "python"):
        for i, line in enumerate(lines):
            m = re.match(r"^(\s*)def\s+(\w+)\s*\((.*?)\)\s*:", line)
            if not m:
                continue
            indent = len(m.group(1))
            body: List[str] = []
            for j in range(i + 1, len(lines)):
                cur = lines[j]
                if cur.strip() == "" or (len(cur) - len(cur.lstrip())) > indent:
                    body.append(cur)
                else:
                    break
            funcs.append({"name": m.group(2), "params": m.group(3), "body": "\n".join(_annotation_prefix(lines, i) + body), "start": i + 1})
        return funcs

    # java / js / ts / php / go：括号匹配
    for i, line in enumerate(lines):
        m = re.search(r"\b(\w+)\s*\(([^)]*)\)\s*\{", line)
        if not m or line.strip().startswith(("if", "for", "while", "switch", "catch", "do", "else")):
            continue
        depth = 0
        started = False
        body = []
        for j in range(i, len(lines)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            body.append(lines[j])
            if started and depth == 0:
                break
        funcs.append({"name": m.group(1), "params": m.group(2), "body": "\n".join(_annotation_prefix(lines, i) + body), "start": i + 1})
    return funcs


_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def _strip_comments(text: str) -> str:
    """去除 // 行注释与 /* */ 块注释（含 javadoc），保留注解（@xxx）与真实代码。

    避免注释文本被当作代码 token 参与判定——例如注释里写「无 @decimalmin / clamp 校验」
    会被子串匹配误判为「已做服务端校验」，造成漏报。
    """
    return _COMMENT_RE.sub(" ", text)


def has_token(body: str, tokens: Tuple[str, ...]) -> bool:
    """方法体（小写）中出现任一 token 即命中。匹配前先剥离注释，避免注释文本误判。"""
    low = _strip_comments(body).lower()
    return any(tok in low for tok in tokens)


def safe_text(content: Any) -> str:
    """把任意来源的内容规整为字符串，避免正则/分行走到 bytes 上崩溃。"""
    if isinstance(content, str):
        return content
    if isinstance(content, (bytes, bytearray)):
        return content.decode("utf-8", "ignore")
    if content is None:
        return ""
    return str(content)


# ---- Spring MVC 路由抽取（让业务逻假说带上真实 HTTP 端点，才能落入 trigger_spec 路由门禁）----
_SPRING_METHOD_RE = re.compile(
    r"@((?:Get|Post|Put|Delete|Patch|Request)Mapping)\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_SPRING_METHOD_HTTP = {
    "getmapping": "GET", "postmapping": "POST", "putmapping": "PUT",
    "deletemapping": "DELETE", "patchmapping": "PATCH", "requestmapping": None,
}
_REQUEST_METHOD_RE = re.compile(r"method\s*=\s*RequestMethod\.(GET|POST|PUT|DELETE|PATCH)", re.IGNORECASE)
_CLASS_REQ_RE = re.compile(r"@RequestMapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']+)[\"']", re.IGNORECASE)

_SKIP_ANNOT_NAMES = {"PostMapping", "GetMapping", "PutMapping", "DeleteMapping",
                     "PatchMapping", "RequestMapping", "RequestParam", "RequestHeader",
                     "RequestBody", "PathVariable", "PreAuthorize", "Secured", "Override"}


def _next_sig_line(lines, idx):
    for k in range(idx + 1, min(idx + 4, len(lines))):
        s = lines[k].strip()
        if s == "" or s.startswith("@") or s.startswith("//") or s.startswith("*"):
            continue
        return lines[k]
    return None


def _class_base_route(content: str):
    """抽取类级 @RequestMapping 前缀（其下一有效行是 class 声明 / '{'）。"""
    lines = content.splitlines()
    for i, line in enumerate(lines):
        m = _CLASS_REQ_RE.search(line)
        if not m:
            continue
        nxt = _next_sig_line(lines, i)
        if nxt is not None and (nxt.strip().startswith("public class") or nxt.strip().startswith("class") or nxt.strip() == "{"):
            return m.group(1)
    return ""


def extract_spring_route(content: str, fn_start: int, fn_body: str):
    """从文件 + 函数体中抽取 Spring MVC 路由（类级前缀 + 方法级 @XMapping）。

    返回 (target_endpoint, http_method)。抽不到则返回 ("", "POST")。
    fn_body 已含方法签名上方的注解前缀，故方法级映射多在其中；类级需回看文件确定。
    """
    class_base = _class_base_route(content)
    method_path = ""
    http_method = None
    for mm in _SPRING_METHOD_RE.finditer(fn_body):
        annot = mm.group(1).lower()
        method_path = mm.group(2)
        if annot == "requestmapping":
            rm = _REQUEST_METHOD_RE.search(mm.group(0))
            http_method = rm.group(1).upper() if rm else "POST"
        else:
            http_method = _SPRING_METHOD_HTTP.get(annot, "POST")
        break
    base = (class_base or "").rstrip("/")
    mp = (method_path or "").lstrip("/")
    if base and mp:
        full = base + "/" + mp
    elif base:
        full = base
    elif mp:
        full = "/" + mp
    else:
        full = ""
    full = re.sub(r"/+", "/", full)
    return full, (http_method or "POST")


def _extract_method_block(content: str, from_idx: int) -> str:
    """从注解行 from_idx 起向下做花括号配平，返回方法体（含注解行）。

    不依赖签名括号配平，故对 @RequestParam(defaultValue="PAID") 这类嵌套圆括号签名也能
    正确抽取方法体（简易正则会被嵌套 '(' 截断，漏掉 reviewOrder/ship/refund 等方法）。

    关键修正：字符串字面量内的花括号（如 @GetMapping("/product/{id}") 的 {id}）不参与配平，
    否则含路径变量的端点会在注解行即误判「方法体结束」，导致方法体被截断、return 视图名丢失。
    用引号状态机跳过字符串内部字符。
    """
    lines = content.splitlines()
    depth = 0
    started = False
    body: List[str] = []
    in_str: Optional[str] = None
    for j in range(from_idx, len(lines)):
        line = lines[j]
        for ch in line:
            if in_str is not None:
                if ch == in_str:
                    in_str = None
                continue
            if ch in ('"', "'"):
                in_str = ch
                continue
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        body.append(line)
        if started and depth == 0:
            break
    return "\n".join(body)


def scan_spring_endpoints(content: str):
    """返回 [(route, http_method, block, method_name, line_no), ...]：每个 Spring MVC 映射方法一块。

    类级 @RequestMapping 作前缀；方法级 @XMapping 提供路径与 HTTP 方法。跳过类级映射本身。
    用于各业务逻分析器在「按函数体抽取失配」时补扫真实端点（带路由），避免漏检。
    """
    lines = content.splitlines()
    class_base = _class_base_route(content)
    out = []
    for i, line in enumerate(lines):
        m = _SPRING_METHOD_RE.search(line)
        if not m:
            continue
        nxt = _next_sig_line(lines, i)
        if nxt is not None and (nxt.strip().startswith("public class") or nxt.strip().startswith("class") or nxt.strip() == "{"):
            continue  # 类级 @RequestMapping，非方法端点
        annot = m.group(1).lower()
        path = m.group(2)
        http = _SPRING_METHOD_HTTP.get(annot)
        if annot == "requestmapping":
            rm = _REQUEST_METHOD_RE.search(line)
            http = rm.group(1).upper() if rm else "POST"
        blk = _extract_method_block(content, i)
        base = (class_base or "").rstrip("/")
        mp = (path or "").lstrip("/")
        if base and mp:
            full = base + "/" + mp
        elif base:
            full = base
        elif mp:
            full = "/" + mp
        else:
            full = ""
        full = re.sub(r"/+", "/", full)
        mname = full.rsplit("/", 1)[-1]
        try:
            sig = blk[:blk.index("{")]
            cands = [c.group(1) for c in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", sig)]
            cands = [c for c in cands if c not in _SKIP_ANNOT_NAMES]
            if cands:
                mname = cands[-1]
        except Exception:
            pass
        out.append((full, http or "POST", blk, mname, i + 1))
    return out


def find_id_param(params: str) -> Optional[str]:
    m = re.search(r"(?i)\b(\w*id\w*)\b", params or "")
    return m.group(1) if m else None


def sink_has_id_arg(sink_text: str) -> bool:
    return bool(re.search(r"(?i)\b(\w*id\w*)\b", sink_text or ""))
