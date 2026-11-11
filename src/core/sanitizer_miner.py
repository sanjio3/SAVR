"""净化器挖掘。

取代旧的「按名字猜净化器」路线（a1_injection_heuristic 里只有
`secCheck(filepath)` 都匹配不到）。新路线是**行为判定 + 跨文件跳转 + 规则抽取**：

1. 守卫发现不看名字，只看行为：方法体里是否对污点值「条件返回/抛出」，或是否做
   「替换、编码、转义、归一化、模式匹配」。这样 secCheck / cmdFilter / 各种自定义校验
   一律能抓到。
2. 跨文件跳转：沿数据流路径走（不是只看 sink 附近）——同文件、项目内其他文件（FQN→路径）、
   父类重写（沿 extends 上溯）、接口实现（找实现类）。
3. 规则抽取产出结构化 FilterSpec（拒绝 token / 允许字符集 / 转义变换 / 是否先解码），
   确定性解析优先，判不出才把「有边界的方法体」交给 LLM（读得懂、可校验，不是凭空造弹）。
4. simulate_filter 提供**确定性闸门**：发之前先在 Python 里对候选求值，凡会被拦的直接丢弃。
   这一步把「猜完再试」变成「证完再验」。
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---- 行为判定：条件拦截 ------------------------------------------------------
_RE_IF = re.compile(r"\b(if|switch|while)\b|\?\s*[^:]+:")
_RE_ABORT = re.compile(r"\b(return|throw|break|continue)\b")
_RE_REJECT_WORD = re.compile(r"(非法|禁止|不允许|invalid|illegal|forbidden|denied|block|reject|bad)", re.I)

# ---- 行为判定：值变换 --------------------------------------------------------
_RE_TRANSFORM = re.compile(
    r"\b(replace|replaceAll|replaceFirst|escape|encode|decode|normalize|strip|trim"
    r"|toLowerCase|toUpperCase|escaper|sanitize|clean|filter|validate|check|verify|match(?:es)?)\s*\("
)
_RE_DENY_CALL = re.compile(r"\b(contains|startsWith|endsWith|indexOf|equals|equalsIgnoreCase|matches)\s*\(")
_RE_ALLOW_CALL = re.compile(r"\b(matches|pattern\s*\.\s*matcher|Pattern\s*\.\s*compile)\s*\(")

# ---- 规则抽取：字面量与正则 --------------------------------------------------
_RE_STR_LIT = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")
_RE_VAR_REF = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*(?:contains|matches|equals|indexOf|startsWith|endsWith)\s*\(")
_RE_ESCAPE_CALL = re.compile(
    r"\b(replace|replaceAll|escapeHtml|escapeJavaScript|encodeForHTML|encodeForJavaScript"
    r"|StringEscapeUtils|URLEncoder\s*\.\s*encode|HtmlPolicyBuilder|Jsoup\s*\.\s*clean)\s*\(")
_RE_DECODE_FIRST = re.compile(r"\b(URLDecoder\s*\.\s*decode|Base64\s*\.\s*getDecoder|decode\s*\()")
# Q1 归一化感知：守卫在匹配前做 Normalizer.normalize / 双重归一化，会让允许集外的危险字符
# 在匹配前变成允许集内字符，静态字符集推理无法覆盖 → 不得判 non_bypassable。
_RE_NORMALIZE = re.compile(r"\b(Normalizer\s*\.\s*normalize|java\.text\.Normalizer|normaliz\w*\(|NFKD|NFC|NFD|NFKC)\b")


def _split_top_plus(expr: str) -> List[str]:
    """按引号感知的方式切分顶层 '+'：正则字面量内部的 '+'（如 "^[a-z]+$"）不切分。"""
    parts: List[str] = []
    buf: List[str] = []
    in_q = False
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_q:
            if c == "\\" and i + 1 < len(expr):
                buf.append(expr[i:i + 2])
                i += 2
                continue
            if c == '"':
                in_q = False
            buf.append(c)
            i += 1
            continue
        if c == '"':
            in_q = True
            buf.append(c)
            i += 1
            continue
        if c == "+":
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


# 若每次新建 SourceNavigator，则文件缓存与类索引无法跨 spec 复用，140+ 条 spec 会
# 重复读盘、重复 os.walk 建索引。改为按 code_root 复用同一实例。
# 同一 code_root 以「相对/绝对/大小写不同/软链」四种写法传入会得到 4 个键、4 次全量建索引。
# 改为 realpath + normcase（Windows 大小写不敏感归一），四种写法收敛到同一缓存项；
# 淘汰策略由「满即清全表」改为 LRU（OrderedDict move_to_end + 淘汰最久未用），
# 避免多靶场并行时一次 clear 抖掉全部热索引。
_NAV_CACHE: "Dict[str, SourceNavigator]" = __import__("collections").OrderedDict()
_NAV_CACHE_MAX = 8


def get_navigator(code_root: str) -> "SourceNavigator":
    """取（或建）该源码根共用的导航器。"""
    key = os.path.normcase(os.path.realpath(os.path.abspath(str(code_root or ""))))
    nav = _NAV_CACHE.get(key)
    if nav is not None:
        _NAV_CACHE.move_to_end(key)
        return nav
    nav = SourceNavigator(key)
    if len(_NAV_CACHE) >= _NAV_CACHE_MAX:
        _NAV_CACHE.popitem(last=False)  # LRU：淘汰最久未用，不全清
    _NAV_CACHE[key] = nav
    return nav


class SourceNavigator:
    """跨文件跳转：FQN → 文件 → 方法体（带缓存）。"""

    def __init__(self, code_root: str = ""):
        self.code_root = str(code_root or "")
        self._file_cache: Dict[str, List[str]] = {}
        self._class_index: Optional[Dict[str, str]] = None

    # ---- 文件定位 ----
    def resolve_fqn(self, fqn: str) -> Optional[str]:
        if not self.code_root or not fqn:
            return None
        rel = fqn.replace(".", os.sep) + ".java"
        p = os.path.join(self.code_root, rel)
        if os.path.isfile(p):
            return p
        # 短路 FQN（只给了类名）或包路径对不上 → 全局按类名找
        return self.find_by_class(fqn.split(".")[-1])

    def find_by_class(self, class_name: str) -> Optional[str]:
        if not self.code_root or not class_name:
            return None
        if self._class_index is None:
            idx: Dict[str, str] = {}
            for root, _dirs, files in os.walk(self.code_root):
                if os.sep + "target" + os.sep in root or os.sep + ".codeql-db" in root:
                    continue
                for fn in files:
                    if fn.endswith(".java"):
                        idx.setdefault(fn[:-5], os.path.join(root, fn))
            self._class_index = idx
        return self._class_index.get(class_name)

    # ---- 源码读取 ----
    def _lines(self, path: str) -> List[str]:
        if path in self._file_cache:
            return self._file_cache[path]
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
        except Exception:
            lines = []
        self._file_cache[path] = lines
        return lines

    def method_body(self, path: str, method: str) -> str:
        """按花括号配对抽取方法体；找不到返回空串。"""
        if not path or not method:
            return ""
        lines = self._lines(path)
        start = -1
        for i, ln in enumerate(lines):
            if re.search(r"\b" + re.escape(method) + r"\s*\(", ln):
                start = i
                break
        if start < 0:
            return ""
        buf: List[str] = []
        depth = 0
        seen_open = False
        for ln in lines[start:]:
            buf.append(ln)
            depth += ln.count("{") - ln.count("}")
            if "{" in ln:
                seen_open = True
            if seen_open and depth <= 0:
                break
        return "\n".join(buf)

    def resolve_const(self, path: str, name: str, _depth: int = 0) -> Optional[str]:
        """解析类常量里的正则字符串（如 FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+$")）。

        `FILTER_PATTERN.matcher(input).matches` —— 不解析常量就抽不出任何规则。

          1) 字面量（含 "a" + "b" 字符串拼接合并）；
          2) 变量间接（NAME = OTHER_CONST → 递归解析 OTHER_CONST，深度限 3）；
          3) 配置注入（NAME 由 @Value("${key}") / getProperty("key") 填充 → 读 application.properties/yml）。
        """
        if not path or not name or _depth > 3:
            return None
        assign_re = re.compile(r"\b" + re.escape(name) + r"\s*=\s*([^;]+);")
        for ln in self._lines(path):
            m = assign_re.search(ln)
            if not m:
                continue
            val = self._resolve_const_expr(path, m.group(1).strip(), _depth)
            if val:
                return val
        return None

    def _resolve_const_expr(self, path: str, expr: str, depth: int) -> Optional[str]:
        expr = str(expr or "").strip()
        m = re.match(r"Pattern\s*\.\s*compile\s*\((.*)\)\s*$", expr, re.S)
        if m:
            expr = m.group(1).strip()
        # 逐段求解（支持字面量、变量、及其任意混合拼接）："^" + ALLOWED + "$"
        # 注意：不能对 expr 直接 split("+")——正则字面量内部常含 '+'（如 "^[a-z]+$"），
        # 必须按引号感知切分（_split_top_plus）。
        parts = _split_top_plus(expr)
        vals: List[str] = []
        solvable = True
        for p in parts:
            m = re.match(r"^\"((?:[^\"\\]|\\.)*)\"$", p)
            if m:
                vals.append(m.group(1))
                continue
            if re.match(r"^[A-Za-z_$][\w$]*$", p):
                v = self.resolve_const(path, p, depth + 1)
                if v is None:
                    solvable = False
                    break
                vals.append(v)
                continue
            solvable = False
            break
        if solvable and vals:
            return "".join(vals)
        # 逐段求解失败 → 落到配置注入兜底（@Value("${key}") / getProperty("key")），
        # 不提前 return None，否则 env.getProperty(...) 形态永远解析不出。
        m = re.search(r"(?:\$\{([^}]+)\}|getProperty\s*\(\s*\"([^\"]+)\"\s*)", expr)
        if m:
            key = m.group(1) or m.group(2)
            return self._config_value(path, key)
        return None

    def _config_value(self, path: str, key: str) -> Optional[str]:
        """从 path 向上找 src/main/resources/application.properties|yml 取 key 的值。"""
        d = os.path.dirname(os.path.abspath(path or ""))
        for _ in range(8):
            for cand in (
                os.path.join(d, "src", "main", "resources", "application.properties"),
                os.path.join(d, "src", "main", "resources", "application.yml"),
                os.path.join(d, "src", "main", "resources", "application.yaml"),
            ):
                if not os.path.isfile(cand):
                    continue
                try:
                    with open(cand, "r", encoding="utf-8", errors="ignore") as fh:
                        for ln in fh.read().splitlines():
                            ln = ln.strip()
                            if not ln or ln.startswith("#"):
                                continue
                            for sep in ("=", ":"):
                                if sep not in ln:
                                    continue
                                k, _, v = ln.partition(sep)
                                ks = k.strip()
                                if ks == key or ks.endswith("." + key):
                                    return v.strip().strip('"').strip("'")
                                break
                except Exception:
                    continue
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        return None

    def imports_of(self, path: str) -> Dict[str, str]:
        """解析 import 行 → {简单类名: 全限定名}，供跨类调用跳转使用。

        只收显式单类导入；通配符（import a.b.*;）与同包隐式由 import_context /
        """
        return self.import_context(path)["explicit"]

    def import_context(self, path: str) -> Dict[str, Any]:
        """解析 import 上下文：显式单类映射、通配符包列表、本文件所属包。"""
        explicit: Dict[str, str] = {}
        wildcard_pkgs: List[str] = []
        package = ""
        for ln in self._lines(path or ""):
            m = re.match(r"\s*package\s+([\w\.]+)\s*;", ln)
            if m and not package:
                package = m.group(1)
                continue
            m = re.match(r"\s*import\s+(?:static\s+)?([\w\.]+)\.\*\s*;", ln)
            if m:
                if m.group(1) not in wildcard_pkgs:
                    wildcard_pkgs.append(m.group(1))
                continue
            m = re.match(r"\s*import\s+(?:static\s+)?([\w\.]+)\s*;", ln)
            if m:
                fqn = m.group(1)
                explicit.setdefault(fqn.split(".")[-1], fqn)
        return {"explicit": explicit, "wildcards": wildcard_pkgs, "package": package}

    def same_package_classes(self, path: str) -> Dict[str, str]:
        """同包隐式可见（Java 语义：同包类无需 import）：返回 {简单类名: 文件路径}。"""
        pkg = self.import_context(path)["package"]
        if not pkg:
            return {}
        return self.expand_wildcard(pkg)

    def expand_wildcard(self, pkg: str) -> Dict[str, str]:
        """展开 import a.b.* / 同包目录：把该包目录下的 .java 收进 {简单类名: 路径}（带缓存）。"""
        cache = getattr(self, "_wildcard_cache", None)
        if cache is None:
            cache = self._wildcard_cache = {}
        if pkg in cache:
            return cache[pkg]
        out: Dict[str, str] = {}
        pdir = os.path.join(self.code_root, str(pkg or "").replace(".", os.sep))
        if os.path.isdir(pdir):
            for fn in os.listdir(pdir):
                if fn.endswith(".java"):
                    out.setdefault(fn[:-5], os.path.join(pdir, fn))
        cache[pkg] = out
        return out

    def resolve_call(self, target: str, method: str, from_path: str) -> Tuple[str, str]:
        """跟随跨类调用：SecurityUtil.cmdFilter(...) → 定位 SecurityUtil 文件并取 cmdFilter 方法体。

        显式单类 import > 同包隐式 > 通配符 import 展开 > 全局按类名兜底。
        """
        if not target or not method:
            return "", ""
        ctx = self.import_context(from_path)
        candidates: List[str] = []
        fqn = ctx["explicit"].get(target)
        if fqn:
            candidates.append(self.resolve_fqn(fqn) or "")
        candidates.append(self.same_package_classes(from_path).get(target) or "")
        for pkg in ctx["wildcards"]:
            candidates.append(self.expand_wildcard(pkg).get(target) or "")
        candidates.append(self.find_by_class(target) or "")
        path = next((p for p in candidates if p), "")
        if not path:
            return "", ""
        body = self.method_body(path, method)
        return (body, path) if body else ("", "")

    def superclass_of(self, path: str) -> Optional[str]:
        """取 extends 的父类名（用于上溯父类重写）。

        「全限定/内部类父类 extends com.foo.Outer.Inner」会截在 com —— 上溯直接断链。
        现抓完整限定名（允许点号）并剥离泛型实参（extends Base<String> → Base）。
        """
        for ln in self._lines(path or "")[:80]:
            m = re.search(r"\bextends\s+([\w$]+(?:\.[\w$]+)*)(?:\s*<[^{;]*>)?", ln)
            if m:
                return m.group(1)
        return None

    def lombok_fields(self, path: str) -> List[Tuple[str, str]]:
        """识别 lombok 注解类并返回字段 [(字段名, 类型)]；无 lombok 注解返回 []。

        守卫判定会因「方法体取不到」而漏掉挂在访问器上的约束。这里按注解预扫识别。
        """
        lines = self._lines(path or "")
        head = "\n".join(lines[:60])
        if not re.search(r"@(?:Getter|Setter|Data|Accessors)\b", head):
            return []
        out: List[Tuple[str, str]] = []
        in_class = False
        for ln in lines:
            if re.search(r"\bclass\s+[A-Za-z_$][\w$]*", ln):
                in_class = True
                continue
            if not in_class:
                continue
            m = re.match(
                r"^\s*(?:private|protected|public)\s+(?:static\s+)?(?:final\s+)?"
                r"([\w<>\[\],\.\?]+)\s+([A-Za-z_$][\w$]*)\s*(?:=|;)", ln)
            if m:
                out.append((m.group(2), m.group(1)))
        return out

    def lombok_accessor_body(self, path: str, method: str) -> str:
        """为 lombok 生成的 getX/setX/isX 合成等价方法体（源码不存在，编译期生成）。"""
        fields = self.lombok_fields(path)
        if not fields:
            return ""
        m = re.match(r"^(?:get|set|is)([A-Z][\w$]*)$", method or "")
        if not m:
            return ""
        cap = m.group(1)
        prefix = (method or "")[:3]
        for fname, ftype in fields:
            if (fname[:1].upper() + fname[1:]) != cap:
                continue
            if prefix == "set":
                return "public void %s(Object v) { this.%s = v; }" % (method, fname)
            if str(ftype).strip().lower() == "boolean":
                return "public boolean %s() { return this.%s; }" % (method, fname)
            return "public Object %s() { return this.%s; }" % (method, fname)
        return ""

    def body_for(self, ref: Dict[str, Any], _depth: int = 0) -> Tuple[str, str]:
        """给定一个节点引用，返回 (方法体, 实际文件路径)。跨文件 / 上溯父类。"""
        if not ref or _depth > 3:
            return "", ""
        path = str(ref.get("file") or "")
        method = str(ref.get("method") or "")
        if not path:
            fqn = str(ref.get("class") or ref.get("fqn") or "")
            path = self.resolve_fqn(fqn) or ""
        if not path:
            return "", ""
        body = self.method_body(path, method)
        if body:
            return body, path
        # 编译期才存在，源码 method_body 取不到；这里合成等价方法体再参与守卫判定。
        body = self.lombok_accessor_body(path, method)
        if body:
            return body, path
        # 方法不在本文件 → 上溯父类（superclass_of 已支持泛型剥离与限定/内部类父类名）
        sup = self.superclass_of(path)
        if sup:
            spath = self.find_by_class(sup.split(".")[-1]) or self.find_by_class(sup)
            if spath:
                return self.body_for({"file": spath, "method": method}, _depth + 1)
        return "", ""


# ---- 守卫发现（行为判定，不按名字） -------------------------------------------
def is_guard(body: str) -> bool:
    """方法体是否表现为「守卫」：条件拦截 或 值变换。"""
    if not body:
        return False
    cond_intercept = bool(_RE_IF.search(body)) and bool(_RE_ABORT.search(body))
    transforms = bool(_RE_TRANSFORM.search(body))
    deny_checks = bool(_RE_DENY_CALL.search(body))
    return bool(cond_intercept or transforms or deny_checks)


def harvest_guards(nodes: List[Dict[str, Any]], nav: SourceNavigator) -> List[Dict[str, Any]]:
    """沿数据流路径逐节点取方法体并判定守卫。nodes 至少含 method（最好含 file/class）。"""
    out: List[Dict[str, Any]] = []
    for n in nodes or []:
        if not isinstance(n, dict):
            continue
        body, path = nav.body_for(n)
        if not body:
            continue
        if not is_guard(body):
            continue
        # sink 节点自身不算守卫（它是终点）
        if str(n.get("role") or "") == "sink":
            continue
        out.append({
            "method": str(n.get("method") or ""),
            "class": str(n.get("class") or n.get("fqn") or ""),
            "file": path,
            "body": body,
        })
    return out


# ---- 规则抽取 ---------------------------------------------------------------
class FilterSpec:
    """净化器约束的结构化表示。"""

    KIND_DENY = "deny"
    KIND_ALLOW = "allow"
    KIND_ESCAPE = "escape"
    KIND_PATH_PREFIX = "path_prefix"   # M9：目录白名单（路径前缀类）
    KIND_UNKNOWN = "unknown"

    def __init__(self, kind: str = KIND_UNKNOWN, tokens: Optional[List[str]] = None,
                 patterns: Optional[List[str]] = None, transforms: Optional[List[str]] = None,
                 case_sensitive: bool = True, decode_first: bool = False,
                 has_normalization: bool = False,
                 source: str = "unknown", note: str = ""):
        self.kind = kind
        self.tokens = list(tokens or [])
        self.patterns = list(patterns or [])
        self.transforms = list(transforms or [])
        self.case_sensitive = bool(case_sensitive)
        self.decode_first = bool(decode_first)
        # 归一化感知：守卫在匹配前对污点做 Normalizer.normalize / 双重解码，
        # 会让「允许集外的危险字符」在匹配前变成「允许集内字符」，静态字符集无法覆盖
        # → 含归一化的 spec 不得判 non_bypassable（fail-open 到 undetermined）。
        self.has_normalization = bool(has_normalization)
        self.source = source
        self.note = note

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "tokens": self.tokens, "patterns": self.patterns,
                "transforms": self.transforms, "case_sensitive": self.case_sensitive,
                "decode_first": self.decode_first, "has_normalization": self.has_normalization,
                "source": self.source, "note": self.note}

    @staticmethod
    def from_dict(d: Any) -> Optional["FilterSpec"]:
        if not isinstance(d, dict):
            return None
        try:
            return FilterSpec(
                kind=str(d.get("kind") or FilterSpec.KIND_UNKNOWN),
                tokens=list(d.get("tokens") or []),
                patterns=list(d.get("patterns") or []),
                transforms=list(d.get("transforms") or []),
                case_sensitive=bool(d.get("case_sensitive", True)),
                decode_first=bool(d.get("decode_first", False)),
                has_normalization=bool(d.get("has_normalization", False)),
                source=str(d.get("source") or "unknown"),
                note=str(d.get("note") or ""),
            )
        except Exception:
            return None

    def is_known(self) -> bool:
        return self.kind != self.KIND_UNKNOWN and bool(self.tokens or self.patterns or self.transforms)


def extract_filter_spec(body: str, llm_complete: Optional[Callable[[str], str]] = None) -> FilterSpec:
    """抽取净化器规则。确定性解析优先；判不出再让 LLM 读这段有边界的源码。"""
    if not body:
        return FilterSpec(note="empty body")

    # M9 目录白名单优先：路径前缀类是「基址字面量 + 逃逸校验」的强信号，
    # 放到字符集判定之前 —— 否则 Paths.get("/var/www").resolve(name) 里的
    # "/var/www" 会被当成普通字符串字面量混进黑名单 token，判出一堆无意义的约束。
    _pp = extract_path_prefix_spec(body)
    if _pp.is_known():
        return _pp

    literals = [x for x in _RE_STR_LIT.findall(body) if x.strip()]
    transforms = sorted({m.group(1) for m in _RE_ESCAPE_CALL.finditer(body)})
    decode_first = bool(_RE_DECODE_FIRST.search(body))
    has_normalization = bool(_RE_NORMALIZE.search(body))

    # 允许名单特征：正向全量匹配（^[...]+$ / ^\\w+$ 一类）
    allow_pat = None
    for lit in literals:
        if lit.startswith("^") and lit.endswith("$"):
            allow_pat = lit
            break
    if allow_pat is None:
        for lit in literals:
            if re.match(r"^\^?\[[^\]]+\][+*]?\$?$", lit):
                allow_pat = lit
                break

    deny_tokens = [l for l in literals if l and not l.startswith("^")]
    # 单字符/符号类字面量最像黑名单项；长句子多半是提示文案，降权排除
    deny_tokens = [t for t in deny_tokens if len(t) <= 12 and not re.match(r"^[\w\u4e00-\u9fa5 ]{6,}$", t)]

    if allow_pat:
        return FilterSpec(FilterSpec.KIND_ALLOW, patterns=[allow_pat], transforms=transforms,
                          decode_first=decode_first, has_normalization=has_normalization,
                          source="deterministic",
                          note="正向字符集合匹配 → 载荷必须整体落在允许集内")
    # 拒绝类必须真的存在「对值做判定」的调用（contains/matches/equals/indexOf/startsWith）。
    # 只凭 if+return+拒绝字样会把漏洞自身的处理函数也当成过滤器（实测它抽出 'ls ' 这种
    # 命令串当拒绝 token，纯噪声），故这里收紧为必须含判定调用。
    if deny_tokens and _RE_DENY_CALL.search(body):
        return FilterSpec(FilterSpec.KIND_DENY, tokens=deny_tokens, transforms=transforms,
                          decode_first=decode_first, has_normalization=has_normalization,
                          source="deterministic",
                          note="黑名单 token → 载荷必须不含这些片段")
    if transforms:
        return FilterSpec(FilterSpec.KIND_ESCAPE, transforms=transforms,
                          decode_first=decode_first, has_normalization=has_normalization,
                          source="deterministic",
                          note="仅转义/编码 → 载荷需绕开被转义的字符")

    # 判不出 → LLM 读这段有边界的源码（不是凭空造弹）
    if llm_complete is not None:
        try:
            raw = llm_complete(body[:4000])
            import json as _json
            m = re.search(r"\{[\s\S]*\}", raw or "")
            if m:
                d = _json.loads(m.group(0))
                spec = FilterSpec.from_dict(d)
                if spec is not None:
                    spec.source = "llm"
                    return spec
        except Exception:
            pass
    return FilterSpec(note="规则未能抽取（既非黑名单也非白名单且无变换）")


_RE_METHOD_DECL = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|abstract|native)?"
    r"[\w\s<>\[\],\.\?]*\s+([A-Za-z_$][\w$]*)\s*\([^;{]*\)\s*(?:throws\s+[\w\s,\.]+)?\s*\{"
)
_SKIP_METHOD_NAMES = {"if", "for", "while", "switch", "catch", "try", "return", "new",
                      "synchronized", "do", "else"}


def iter_method_bodies(path: str) -> List[Tuple[str, str]]:
    """抽出文件里所有方法体：[(方法名, 方法体)]。

    真实 spec 里的沿路径节点常常是空的（实测 supporting_nodes=[]、taint_path=[]、sink.method="")，
    只靠"按方法名跳转"会一无所获。所以补一条按文件扫描的兜底：把整个文件的方法都抽出来逐个判定。
    """
    try:
        with open(path or "", "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().splitlines()
    except Exception:
        return []
    out: List[Tuple[str, str]] = []
    for i, ln in enumerate(lines):
        m = _RE_METHOD_DECL.match(ln)
        if not m:
            continue
        name = m.group(1)
        if name in _SKIP_METHOD_NAMES:
            continue
        buf: List[str] = []
        depth = 0
        opened = False
        for l2 in lines[i:]:
            buf.append(l2)
            depth += l2.count("{") - l2.count("}")
            if "{" in l2:
                opened = True
            if opened and depth <= 0:
                break
        body = "\n".join(buf)
        if body:
            out.append((name, body))
    return out


_RE_CROSS_CALL = re.compile(r"\b([A-Z][\w$]*)\s*\.\s*([a-zA-Z_$][\w$]*)\s*\(")
_RE_CONST_USE = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*\.\s*(?:matcher|matches|compile|test)\s*\(")


def expand_constants(body: str, path: str, nav: Optional["SourceNavigator"]) -> str:
    """把方法体引用的类常量（如 FILTER_PATTERN）解析成字面量追加到待分析文本里。

    这样 extract_filter_spec 的确定性解析就能看到真实正则，而不用改解析逻辑。
    """
    if not body or not nav or not path:
        return body
    extra: List[str] = []
    for name in sorted({m.group(1) for m in _RE_CONST_USE.finditer(body)}):
        val = nav.resolve_const(path, name)
        if val:
            extra.append('"%s"' % val)
    if not extra:
        return body
    return body + "\n// expanded constants\n" + "\n".join(extra)


def harvest_guards_in_file(path: str, max_guards: int = 8) -> List[Dict[str, Any]]:
    """在单个文件里扫描所有方法，返回表现为守卫的那些（含方法体）。"""
    out: List[Dict[str, Any]] = []
    for name, body in iter_method_bodies(path):
        if is_guard(body):
            out.append({"method": name, "file": path, "body": body})
        if len(out) >= max_guards:
            break
    return out


# ---- 生产侧：沿路径抓守卫 → 抽 FilterSpec → 回填 ----
def _candidate_files(raw: Dict[str, Any]) -> List[str]:
    """从 vuln 的 raw 里收集候选文件：自身 file、sink.file、supporting_nodes、callers。"""
    out: List[str] = []
    f = str(raw.get("file") or "")
    if f:
        out.append(f)
    sink = raw.get("sink")
    if isinstance(sink, dict) and sink.get("file"):
        out.append(str(sink.get("file")))
    for n in (raw.get("supporting_nodes") or []):
        if isinstance(n, dict) and n.get("file"):
            out.append(str(n.get("file")))
    for n in (raw.get("data_flow", {}) or {}).get("taint_path") or []:
        if isinstance(n, dict) and n.get("file"):
            out.append(str(n.get("file")))
    callers = raw.get("callers")
    if isinstance(callers, str) and callers:
        # 形如 "src\...\Foo.java:行101"
        out.append(callers.split(":")[0].strip())
    elif isinstance(callers, (list, tuple)):
        for c in callers:
            if isinstance(c, dict) and c.get("file"):
                out.append(str(c.get("file")))
            elif isinstance(c, str):
                out.append(c.split(":")[0].strip())
    seen = set()
    uniq: List[str] = []
    for p in out:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def attach_filter_spec(payload: Dict[str, Any], code_root: Optional[str] = None,
                       db: Any = None, llm_complete: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:
    """生产侧入口：沿路径抓守卫 → 抽 FilterSpec → 回填 payload["raw"]。

    回填两个字段，供消费侧（d1_service._sanitizer_aware_synth / benchmark_cli 升变体）使用：
      - raw["filter_spec"]：结构化约束（FilterSpec.to_dict）
      - raw["sanitizer_candidates"]：命中的守卫（含方法体），便于复核与后续复用
    环境开关 SAST_AI_SANITIZER_MINER=0 可整体关闭。fail-open：任何异常都不影响登记。
    """
    if str(os.environ.get("SAST_AI_SANITIZER_MINER", "1")).strip() == "0":
        return {}
    if not isinstance(payload, dict):
        return {}
    raw = payload.get("raw")
    if not isinstance(raw, dict):
        raw = {}
    if raw.get("filter_spec"):
        return {}  # 已有，不重复挖

    root = str(code_root or payload.get("code_root") or "").strip()
    if not root and db is not None:
        try:
            row = db.execute("SELECT target_path FROM workspaces WHERE id = ?",
                             (payload.get("workspace_id"),), fetchone=True)
            if row:
                root = str((row.get("target_path") if isinstance(row, dict) else row[0]) or "").strip()
        except Exception:
            root = ""
    if not root or not os.path.isdir(root):
        return {}

    nav = get_navigator(root)  # 跨 spec 复用（文件缓存 + 类索引）
    guards: List[Dict[str, Any]] = []
    seen = set()

    # 1) 沿路径节点跳转（有 method 信息时最准）
    for n in (raw.get("supporting_nodes") or []):
        if not isinstance(n, dict):
            continue
        body, path = nav.body_for(n)
        if body and (path, str(n.get("method") or "")) not in seen:
            seen.add((path, str(n.get("method") or "")))
            guards.append({"method": str(n.get("method") or ""), "file": path, "body": body})

    # 2) 按候选文件扫描（method 缺失时的兜底，覆盖跨文件净化器）
    for rel in _candidate_files(raw):
        path = rel if os.path.isabs(rel) and os.path.isfile(rel) else nav.resolve_fqn(
            rel.replace("\\", "/").replace("/", ".").removesuffix(".java")) or os.path.join(root, rel)
        if not path or not os.path.isfile(path):
            continue
        for g in harvest_guards_in_file(path):
            key = (g.get("file"), g.get("method"))
            if key not in seen:
                seen.add(key)
                guards.append(g)

    if not guards:
        raw["sanitizer_miner"] = {"guards": 0, "filter_spec": None, "reason": "no_guard_found"}
        payload["raw"] = raw
        return raw["sanitizer_miner"]

    # 3) 跟随跨类调用：真实靶场把过滤器放在另一个类里
    #    不跟这条调用就永远只能看到处理函数本身，抽不出规则。
    _follow_seeds: List[Tuple[str, str]] = []
    for g in list(guards):
        _follow_seeds.append((str(g.get("file") or ""), str(g.get("body") or "")))
    for rel in _candidate_files(raw):
        path = rel if os.path.isabs(rel) and os.path.isfile(rel) else os.path.join(root, rel)
        if os.path.isfile(path):
            for _name, _body in iter_method_bodies(path):
                _follow_seeds.append((path, _body))
    for _from, _body in _follow_seeds:
        if not _from or not _body:
            continue
        for m in _RE_CROSS_CALL.finditer(_body):
            _cls, _meth = m.group(1), m.group(2)
            if _cls in ("String", "System", "Pattern", "Runtime", "ProcessBuilder", "Objects"):
                continue
            _cb, _cp = nav.resolve_call(_cls, _meth, _from)
            if _cb and is_guard(_cb) and (_cp, _meth) not in seen:
                seen.add((_cp, _meth))
                guards.append({"method": _meth, "file": _cp, "body": _cb,
                               "via": f"{_cls}.{_meth}"})
        if len(guards) >= 24:
            break

    # 排序：真正做「值判定/白名单」的方法优先（漏洞自身的处理函数常有 if+return 但无判定调用，
    # 会被 is_guard 命中却抽不出有效规则，让它排后面当兜底）。
    def _rank(g: Dict[str, Any]) -> int:
        b = str(g.get("body") or "")
        return 0 if (_RE_DENY_CALL.search(b) or _RE_ALLOW_CALL.search(b)) else 1
    guards.sort(key=_rank)

    spec = None
    for g in guards:
        # 常量里藏正则的情况（FILTER_PATTERN）先展开再抽
        _body = expand_constants(str(g.get("body") or ""), str(g.get("file") or ""), nav)
        cand = extract_filter_spec(_body, llm_complete=llm_complete)
        if cand is not None and cand.is_known():
            spec = cand
            break

    # 4) 并上「库内置闸门」约束（自写层之外还有库内拒绝名单）：
    #    自写净化器判断"能不能绕"，库内置闸门判断"绕过去还有没有用"，两者必须同时满足。
    #    明确不满足的条目跳过并落原因；事实未知 fail-open 放行，绝不因事实缺失误杀链路。
    _mech_specs: List[FilterSpec] = []
    _mech_depends: Dict[str, List[str]] = {}
    try:
        from src.core.mechanism_library import lookup as _mlookup, to_filter_spec as _m2fs
        from src.core.runtime_facts import collect_facts as _rf_collect, check_depends as _rf_check
        _facts = _rf_collect()
        for _m in _mlookup(str(payload.get("package") or ""), str(payload.get("version") or "")):
            try:
                _ok, _why = _rf_check(_m, _facts)
            except Exception:
                _ok, _why = True, ["check_depends_error"]
            _mid = str(_m.get("id") or "")
            if _why:
                _mech_depends[_mid] = list(_why)
            if not _ok:
                continue
            _ms = _m2fs(_m)
            if _ms is not None and _ms.is_known():
                _mech_specs.append(_ms)
    except Exception:
        _mech_specs = []
    if _mech_specs:
        try:
            from src.core.mechanism_library import intersect as _mintersect
            _merged = _mintersect([s for s in [spec] + _mech_specs if s is not None])
            if _merged is not None:
                spec = _merged
        except Exception:
            pass
    raw["mechanism_specs"] = [m.to_dict() for m in _mech_specs]
    raw["mechanism_depends"] = _mech_depends

    # 5) M8：并上「全局生效点」的拦截器约束（HandlerInterceptor / Servlet Filter / @Aspect）。
    #    这一层是**正向**索引出来的，不在「source → sink」这条数据流上——原实现只沿数据流
    #    回溯，净化发生在 MVC 链上（preHandle / doFilter / 切面）时永远找不到。
    #    路由不匹配（Filter 的 urlPatterns / Interceptor 的 addPathPatterns）的条目不参与求交，
    #    否则会把 /admin 下的过滤算到 /public 上，凭空判死漏洞。
    _icp_specs: List[FilterSpec] = []
    try:
        from src.core import interceptor_index as _ix
        _icp_index = _ix.build_index(root)
        _route = str(payload.get("target_endpoint") or raw.get("target_endpoint")
                     or raw.get("entry_route") or "")
        if not _route:
            # 路由取不到 → 保守不并（错并会凭空判死；不并只是少一层约束）
            raw["interceptor_index"] = {"total": len(_icp_index), "by_kind": {},
                                        "applied": 0, "reason": "no_route_for_match"}
        else:
            _icp_specs = _ix.filter_specs_for_route(_icp_index, _route)
            _stats = _ix.index_stats(_icp_index)
            _stats["applied"] = len(_icp_specs)
            _stats["route"] = _route
            raw["interceptor_index"] = _stats
    except Exception as exc:
        raw["interceptor_index"] = {"error": str(exc)}
    if _icp_specs:
        try:
            from src.core.mechanism_library import intersect as _icp_intersect
            _merged_icp = _icp_intersect([s for s in [spec] + _icp_specs if s is not None])
            if _merged_icp is not None:
                spec = _merged_icp
        except Exception:
            pass

    raw["sanitizer_candidates"] = [
        {"method": g.get("method"), "file": g.get("file"), "body": (g.get("body") or "")[:4000]}
        for g in guards[:5]
    ]
    raw["filter_spec"] = spec.to_dict() if spec is not None else None
    # 一等公民判定：可绕过 / 不可绕过 / 未定（按族所需语法字符集 × 约束求交）。
    # 不可绕过 = 真净化器 = 终态，消费侧据此停止造弹与重试，不再死磕。
    try:
        from src.core.filter_verdict import classify as _classify
        raw["filter_verdict"] = _classify(spec, str(payload.get("family") or ""), candidates=None)
    except Exception:
        raw["filter_verdict"] = None
    raw["sanitizer_miner"] = {
        "guards": len(guards),
        "filter_spec": (spec.kind if spec is not None else None),
        "verdict": ((raw.get("filter_verdict") or {}).get("verdict")),
        "source": (spec.source if spec is not None else None),
        "code_root": root,
    }
    payload["raw"] = raw
    return raw["sanitizer_miner"]


# ── M9：目录白名单（路径前缀类）判定 ─────────────────────────────────────────
# 载荷形态是「路径」，不是「字符集」，所以这一类不能用正则判，走路径归一 + 前缀包含。
# 设计约束（定稿本轮第十项）：复用 FilterSpec.patterns 存 base_dir，不新增字段。
def _normalize_path(p: Any) -> str:
    """把载荷/基址归一到可比较的规范形态。

    做四件事：剥 file:// 前缀、反斜杠转正斜杠、URL 解码、点点消解（. 与 ..）。
    Windows 上 Java 代码常写 "..\\..\\etc"，不转正斜杠就会漏掉 ../.. 逃逸。
    """
    s = str(p or "").strip().strip('"').strip("'")
    if s.lower().startswith("file://"):
        s = s[7:]
        # file:///C:/x → /C:/x；file://C:/x → /C:/x
        if len(s) > 2 and s[0] != "/" and s[1] == ":":
            s = "/" + s
    s = s.replace("\\", "/")
    # URL 解码（%2e%2e%2f 这类双重编码逃逸的常见形态）；解码失败就用原串
    for _ in range(2):      # 最多两轮，覆盖单层与 %252e 双重编码
        try:
            from urllib.parse import unquote
            dec = unquote(s)
        except Exception:
            break
        if dec == s:
            break
        s = dec.replace("\\", "/")
    # 点点消解
    absolute = s.startswith("/")
    out: List[str] = []
    for seg in s.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not absolute:
                out.append("..")
            # absolute 时 .. 在根之上，继续吃掉（与 Java 语义一致：/.. == /）
            continue
        out.append(seg)
    joined = "/".join(out)
    if absolute:
        return "/" + joined
    return joined


def path_escapes_base(payload: str, base_dir: str) -> bool:
    """载荷归一后是否逃出 base_dir（True=逃出=会被目录白名单拦住）。

    相对路径先按 ``base.resolve(name)`` 语义拼到 base 之下再判——这是 Java 侧
    ``Paths.get(base).resolve(userInput)`` 的真实行为。不做这一步的话，``a.txt``
    这种最普通不过的合法文件名会因为「不以 / 开头」被误判成逃逸而被提前丢掉，
    那是实打实的漏报（真漏洞的载荷被自己的白名单守卫挡在门外）。

    其余判据刻意保守：只在**能确定逃出**时返回 True。判不出（base 非法、空载荷）
    一律返回 False（放行），因为误判逃出会把真漏洞的载荷提前丢掉；反之只是多发一发。
    """
    base = _normalize_path(base_dir)
    target = _normalize_path(payload)
    if not base or not target:
        return False
    if not target.startswith("/"):
        # 相对路径：按 resolve 语义落到 base 之下
        prefix = base if base.endswith("/") else base + "/"
        target = _normalize_path(prefix + target)
        if not target:
            return False
    if target == base:
        return False
    prefix = base if base.endswith("/") else base + "/"
    return not target.startswith(prefix)


def extract_path_prefix_spec(body: str) -> FilterSpec:
    """从源码抽「目录白名单」约束：patterns 存 base_dir，kind=path_prefix。

    识别两类信号（两者都要有才认，否则宁可判不出）：
      1. 基址字面量：new File("/var/www", name) / Paths.get("/var/www").resolve(...)
      2. 逃逸校验：getCanonicalPath/toRealPath + startsWith(base)

    **has_normalization 恒置 True**（关键设计）：Java 的 getCanonicalPath 会解析符号链接，
    Python 侧模拟不了——base_dir 下挂一个指向 /etc 的软链，静态判定必然漏。
    置 True 后 filter_verdict.classify 不得据此判 non_bypassable（fail-open 交运行时），
    这是「模拟不可信时宁可不判死」的正确姿势。
    """
    if not body:
        return FilterSpec(note="empty body")
    bases: List[str] = []
    for m in re.finditer(
            r"(?:new\s+File|Paths\s*\.\s*get)\s*\(\s*\"([^\"]+)\"", body):
        cand = m.group(1).strip()
        if cand and ("/" in cand or "\\" in cand) and cand not in bases:
            bases.append(cand)
    for m in re.finditer(r"\b(?:getCanonicalPath|toRealPath)\s*\(", body):
        # 形如 BASE_DIR 常量 + startsWith 校验：取常量的字符串定义
        for c in re.finditer(r"\"(/[^\"]+)\"", body):
            if c.group(1) not in bases:
                bases.append(c.group(1))
        break
    if not bases:
        return FilterSpec(note="未识别到目录白名单基址")
    has_canonical = bool(_RE_CANONICAL.search(body))
    return FilterSpec(
        FilterSpec.KIND_PATH_PREFIX, patterns=bases[:4],
        has_normalization=True,   # getCanonicalPath 解析符号链接 → Python 模拟不可信
        source="deterministic",
        note=("目录白名单：载荷归一后必须落在 %s 之内"
              % ", ".join(bases[:4])
              + ("（源码含 getCanonicalPath/toRealPath，会解析符号链接 → 静态判定 fail-open 交运行时）"
                 if has_canonical else "")))


_RE_CANONICAL = re.compile(r"\b(?:getCanonicalPath|toRealPath|getRealPath)\s*\(")


def simulate_filter(spec: Optional[FilterSpec], payload: str) -> bool:
    """确定性闸门：模拟净化器对候选载荷的判定。True=预计可放行（可发），False=必被拦（丢弃）。"""
    if spec is None or not isinstance(spec, FilterSpec) or not spec.is_known():
        return True  # 无约束 → 不拦
    text = str(payload or "")
    probe = text if spec.case_sensitive else text.lower()

    if spec.kind == FilterSpec.KIND_PATH_PREFIX:
        for t in spec.tokens:          # 与 deny 合并时 tokens 承载黑名单
            if t and (t if spec.case_sensitive else t.lower()) in probe:
                return False
        for base in spec.patterns:     # patterns 复用存 base_dir（不新增字段）
            if path_escapes_base(text, base):
                return False
        return True

    if spec.kind == FilterSpec.KIND_DENY:
        for t in spec.tokens:
            if not t:
                continue
            needle = t if spec.case_sensitive else t.lower()
            if needle and needle in probe:
                return False
        for p in spec.patterns:
            try:
                if re.search(p, text, 0 if spec.case_sensitive else re.I):
                    return False
            except re.error:
                continue
        return True

    if spec.kind == FilterSpec.KIND_ALLOW:
        for p in spec.patterns:
            try:
                return bool(re.fullmatch(p, text, 0 if spec.case_sensitive else re.I))
            except re.error:
                continue
        return True

    if spec.kind == FilterSpec.KIND_ESCAPE:
        # 仅转义：不直接丢弃（转义后可能仍能触发），但记录由运行时裁决
        return True

    return True


# ── Q4：simulate_filter 语义精确与可靠性 ──────────────────────────────────────
#
# simulate_filter 是「Python re 对 Java 正则的近似」。Java/Python 真实语义差异会误判：
#   1. 占有量词 X*+ / X++ / 原子组 (?>...)：Java 支持，Python re 不支持 → re.error →
#      原分支误把「带占有量词的强过滤器」当无过滤器放行（漏报真净化器）；
#   2. \p{...} Unicode 属性：Java 支持，Python re 不支持；
#   3. 嵌套量词 (a+)+ / (a*)* 类灾难性回溯（ReDoS）：两边都可能卡死，Python re 无超时；
#   4. 内联标志 (?s)(?m)(?u) 改变匹配语义（点是否跨行、\w 是否 Unicode）。
# 这些情况下 Python 近似不可信 → 标记「不支持」，调用方不得据此判 non_bypassable。
#
# TODO：对最关键族（命令注入白名单等）接 JVM 真 Pattern 互校——
# 用靶场同 JDK 起最小校验子进程跑 Pattern.matches，与 Python 近似分歧时以 JVM 为准并记告警。
# 本仓库侧已具备 : 三态 simulate_filter_safe（None=不支持）+ 超时保护 + filter_regex_supported 静态预筛，
# 调用方（filter_verdict / sanitizer_forge）已对 None fail-open，不据此判 non_bypassable。

_RE_POSSESSIVE = re.compile(r"[*+?]\+|\{\d+(?:,\d*)?\}\+")     # 占有量词 X*+ / X{2,5}+
_RE_ATOMIC = re.compile(r"\(\?>")                                # 原子组 (?>...)
_RE_UNICODE_PROP = re.compile(r"\\p\{")                          # \p{L} 等 Unicode 属性
_RE_NAMED_GROUP = re.compile(r"\(\?P<")                          # Python 命名组 (?P<name>)，Java 无
# 灾难性回溯启发式：一个「含量词的分组」本身又被量词修饰，如 (a+)+ / ([a-z]+)+ / ((a+)+)+。
# 这类在恶意输入下会指数级回溯，两边都可能卡死；标为不可信（fail-open）优先于运行时裁决。
# 误判为「不支持」是保守且安全的（只是 fail-open，不丢有效弹、不漏报净化器）。
_RE_CATASTROPHIC = re.compile(r"\((?:[^()]|\([^()]*\))*[+*?][^()]*\)[+*?]")


def filter_regex_supported(pattern: str) -> bool:
    """判断 Python re 能否安全等价 Java Pattern。含不支持语法 → False（调用方 fail-open）。"""
    if not pattern:
        return True
    if _RE_POSSESSIVE.search(pattern) or _RE_ATOMIC.search(pattern) \
            or _RE_UNICODE_PROP.search(pattern) or _RE_NAMED_GROUP.search(pattern):
        return False
    # 灾难性回溯：含嵌套量词结构 → 标为不可信（避免 ReDoS 拖死分析进程）
    if _RE_CATASTROPHIC.search(pattern):
        return False
    return True


def _patterns_supported(spec: "FilterSpec") -> bool:
    return all(filter_regex_supported(p) for p in (spec.patterns or []))


# ReDoS 求值超时（秒），可用环境变量覆盖。
_RE_EVAL_TIMEOUT = float(os.environ.get("SAST_AI_REGEX_TIMEOUT", "1.0"))


def _safe_match(fn) -> Optional[bool]:
    """在带超时的保护下执行一次正则求值；超时或 re.error 一律返回 None（fail-open）。

    - Unix：SIGALRM 可在主线程中断正在执行的 re 求值；
    - Windows：signal 不支持 alarm，此处直接同步执行——灾难性回溯已被 filter_regex_supported
      的静态启发式预先判 None，故良性 pattern 不会在此挂死，可接受的工程取舍。
    返回 None 表示「判不出」，调用方必须 fail-open 而非当作放行。
    """
    if os.name == "posix":
        import signal

        def _handler(signum, frame):
            raise TimeoutError("regex eval timeout")

        try:
            old = signal.signal(signal.SIGALRM, _handler)
            signal.setitimer(signal.ITIMER_REAL, _RE_EVAL_TIMEOUT)
            try:
                return bool(fn())
            except (re.error, TimeoutError):
                return None
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old)
        except (ValueError, OSError):
            # 非主线程无 SIGALRM，退化为同步执行
            try:
                return bool(fn())
            except re.error:
                return None
    try:
        return bool(fn())
    except re.error:
        return None


def simulate_filter_safe(spec: Optional[FilterSpec], payload: str) -> Optional[bool]:
    """与 simulate_filter 同义，但返回三态：True=放行 / False=必拦 / None=正则不支持（无法判定）。

    None 表示 Python 近似不可信：调用方应 fail-open（不当 non_bypassable，交运行时裁决），
    而非把「带占有量词的强过滤器」当无过滤器放行。

    ReDoS 防护：正则求值带超时。Unix 用 SIGALRM 可在主线程中断；Windows 无可靠可中断
    超时，故直接依赖 `filter_regex_supported` 的静态灾难性回溯启发式（嵌套量词已判 None）。
    若超时（Unix）或求值抛 re.error，一律返回 None（fail-open），绝不把「判不出」当「放行」。
    """
    if spec is None or not isinstance(spec, FilterSpec) or not spec.is_known():
        return True
    if not _patterns_supported(spec):
        return None
    text = str(payload or "")
    probe = text if spec.case_sensitive else text.lower()

    if spec.kind == FilterSpec.KIND_PATH_PREFIX:
        for t in spec.tokens:
            if t and (t if spec.case_sensitive else t.lower()) in probe:
                return False
        for base in spec.patterns:
            if path_escapes_base(text, base):
                return False
        return True

    if spec.kind == FilterSpec.KIND_DENY:
        for t in spec.tokens:
            if not t:
                continue
            needle = t if spec.case_sensitive else t.lower()
            if needle and needle in probe:
                return False
        for p in spec.patterns:
            _hit = _safe_match(lambda: re.search(p, text, 0 if spec.case_sensitive else re.I))
            if _hit is None:
                return None
            if _hit:
                return False
        return True

    if spec.kind == FilterSpec.KIND_ALLOW:
        for p in spec.patterns:
            _hit = _safe_match(lambda: re.fullmatch(p, text, 0 if spec.case_sensitive else re.I))
            if _hit is None:
                return None
            if _hit:
                return True
            return False
        return True

    if spec.kind == FilterSpec.KIND_ESCAPE:
        return True

    return True
