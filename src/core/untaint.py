"""通用判据：判断「流到 sink 的值是否可能被攻击者控制」。

## 要解决的问题

静态扫描最大的误报源之一是：**代码看起来读了外部输入，实际那个值是常量**。
典型形态有两类，都是真实项目里也会出现的写法：

    ① 常量返回的 helper
        Scr scr = new Scr(request);
        String param = scr.getTheValue("x");   // 该方法体只有 return "bar";
        → param 恒为常量，注入类漏洞不成立

    ② 列表索引偏移
        List<String> v = new ArrayList<>();
        v.add("safe"); v.add(param); v.add("moresafe");
        v.remove(0);
        String bar = v.get(1);                 // 实际取到 "moresafe"，不是 param
        → bar 恒为常量

r60 之前这两条是用**具体类名**写死的（`\\.getTheValue\\(`、规则名 `bench_safe_list_index`），
换个项目必然零命中。本模块把它们换成**机制**：

    ① → 解析接收者变量的类，到代码库里找到该类源码，检查被调用方法的
        **每一个 return 是否都返回字面量**。是 ⇒ 该方法与入参、与外部状态无关 ⇒ 常量。
    ② → 对 `List` 做一次浅求值，跟踪 add / remove(int) / get(int) 序列，
        **所有 get 都取到字面量**才算常量；取到 UNKNOWN 一律判不安全。

两条都是**跨框架、跨项目**成立的语义判据，不认识任何具体类名。

## 硬约束：只对「输入驱动族」生效

「值不可控 ⇒ 安全」这个推理**只在漏洞成立需要攻击者可控输入时才成立**。
`weak_hash` / `weak_crypto` / `weak_random` / `secure_cookie` 这类族，
漏洞只看「用了什么 API / 算法」—— 用 MD5 哈希一个常量仍然是漏洞。

r60 实测：不区分族语义直接放开，会误杀 44 个 TP（TPR 降 3.11pp，超 3pp 门限）；
按族语义收窄后掉 TP 归零，精确率反而从 58.59% 涨到 62.62%。

族是否需要外部输入由 `corpus_profile` 的画像决定，未知族一律不启用（fail-open）。

## 另一条硬约束：类里存在外部输入 API 时不判常量

`constant_call_source` 要求整个类里**没有**任何读外部输入的调用。因为类级窗口做不了
过程内数据流，只有「压根没读外部输入」这个条件能安全地推出「类里的值都是常量」。
保守但不会误杀：读不到证据就不抑制。

用法：
    from src.core.untaint import untainted_value
    ok, rule = untainted_value(window_text, family="sql_injection", code_root=root)
"""
from __future__ import annotations

import logging
import os
import re
from typing import Dict, FrozenSet, Iterable, List, Optional, Tuple

from src.core.corpus_profile import StackProfile, active_profile

logger = logging.getLogger("untaint")

# ── 语法要素（都是 Java 通用语法，不含任何具体类名）─────────────────────
_METHOD_DECL = re.compile(
    r"(?:public|private|protected|static|final|synchronized|abstract|\s)+"
    r"[\w<>\[\],\.\s]+?\s+(\w+)\s*\(([^)]*)\)\s*\{")
_RET_LITERAL = re.compile(
    r"return\s+(-?\d+(?:\.\d+)?[lLfFdD]?|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)?'|"
    r"null|true|false)\s*;")
_RET_ANY = re.compile(r"\breturn\b")
# Type var = new Type2(...)
_DECL_NEW = re.compile(r"(?:^|[\s;{(])([\w\.]+)\s+(\w+)\s*=\s*new\s+([\w\.]+)\s*\(")
# Type var = <非 new 表达式>
_DECL_ANY = re.compile(r"(?:^|[\s;{(])([\w\.]+)\s+(\w+)\s*=\s*(?!new\b)([^;=]{1,120}?)\s*;")

_LIST_DECL = re.compile(
    r"List\s*<\s*String\s*>\s*(\w+)\s*=\s*new\s+(?:java\s*\.\s*util\s*\.\s*)?ArrayList", re.I)
_STR_LITERAL = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
_ASSIGN_GET = re.compile(r"(\w+)\s*=\s*[^;]{0,160}?\.\s*get\s*\(\s*\d+\s*\)")

UNKNOWN = object()

# 扫描上限：单次裁决最多读多少个候选类文件 / 索引多少个类，防止大仓库拖垮裁决
_MAX_INDEX_FILES = 20000
_MAX_CLASS_CANDIDATES = 3
_SKIP_DIR_PARTS = ("/target/", "/build/", "/.git/", "/node_modules/", "/.codeql-db/",
                   "\\target\\", "\\build\\", "\\.git\\", "\\node_modules\\", "\\.codeql-db\\")


def _strip_comments(src: str) -> str:
    out: List[str] = []
    i, n, in_block = 0, len(src), False
    while i < n:
        if in_block:
            j = src.find("*/", i)
            if j < 0:
                break
            in_block = False
            i = j + 2
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            in_block = True
            i += 2
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def _method_body(text: str, brace_idx: int) -> Optional[str]:
    depth = 0
    for j in range(brace_idx, len(text)):
        depth += text[j].count("{") - text[j].count("}")
        if depth <= 0:
            return text[brace_idx:j]
    return None


def constant_returning_methods(src: str, profile: Optional[StackProfile] = None) -> FrozenSet[str]:
    """返回该文件里「**所有 return 都返回字面量**」的方法名集合。

    判据刻意严格（三条同时满足才算）：
      1. 方法体里至少有一个 `return`；
      2. **每一个** `return` 后面都是字面量（字符串 / 数字 / 字符 / null / 布尔）；
      3. 方法体里**没有**任何读外部输入的调用。

    第 2 条保证「返回值与入参无关」：`return request.getParameter(p);` 不是字面量，
    所以透传外部输入的方法不会被误判成常量返回（这是 r60 之前必须靠
    `deny getTheParameter|getTheCookie` 白名单才能保住的语义，现在由机制本身保证）。
    """
    prof = profile or active_profile()
    text = _strip_comments(src)
    names = set()
    for m in _METHOD_DECL.finditer(text):
        body = _method_body(text, m.end() - 1)
        if not body:
            continue
        n_ret = len(_RET_ANY.findall(body))
        if n_ret == 0:
            continue
        if len(_RET_LITERAL.findall(body)) != n_ret:
            continue
        if prof.has_external_input(body):
            continue
        names.add(m.group(1))
    return frozenset(names)


# ── 类文件索引（按简单类名 → 候选文件），按 code_root 缓存 ────────────────
_CLASS_INDEX: Dict[str, Dict[str, List[str]]] = {}
_CONST_METHOD_CACHE: Dict[str, FrozenSet[str]] = {}


def _build_class_index(code_root: str) -> Dict[str, List[str]]:
    idx: Dict[str, List[str]] = {}
    if not code_root or not os.path.isdir(code_root):
        return idx
    count = 0
    for dirpath, dirnames, filenames in os.walk(code_root):
        dirnames[:] = [d for d in dirnames
                       if not d.startswith(".")
                       and d not in ("target", "build", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".java"):
                continue
            full = os.path.join(dirpath, fn)
            low = full.replace("\\", "/").lower()
            if any(p in low for p in _SKIP_DIR_PARTS):
                continue
            idx.setdefault(fn[:-5], []).append(full)
            count += 1
            if count >= _MAX_INDEX_FILES:
                return idx
    return idx


def class_index_of(code_root: str) -> Dict[str, List[str]]:
    if not code_root:
        return {}
    idx = _CLASS_INDEX.get(code_root)
    if idx is None:
        idx = _build_class_index(code_root)
        if len(_CLASS_INDEX) > 8:  # 多任务轮转时防止无限增长
            _CLASS_INDEX.clear()
        _CLASS_INDEX[code_root] = idx
    return idx


def _const_methods_of(path: str, profile: StackProfile) -> FrozenSet[str]:
    got = _CONST_METHOD_CACHE.get(path)
    if got is None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                got = constant_returning_methods(f.read(), profile)
        except OSError:
            got = frozenset()
        if len(_CONST_METHOD_CACHE) > 2000:
            _CONST_METHOD_CACHE.clear()
        _CONST_METHOD_CACHE[path] = got
    return got


def constant_call_source(window: str, code_root: str = "",
                         profile: Optional[StackProfile] = None,
                         class_index: Optional[Dict[str, List[str]]] = None) -> bool:
    """① 常量返回 helper：解析接收者类型 → 找到类源码 → 被调方法是常量返回。

    返回 True 的含义：这个类里存在一个调用，它的返回值**在编译期就是常量**，
    且整个类没有任何读外部输入的调用 ⇒ 类里的取值不可能被攻击者控制。
    """
    if not window:
        return False
    prof = profile or active_profile()
    text = _strip_comments(window)
    # 硬约束：类里只要有一处读外部输入，类级窗口就推不出「值都是常量」
    if prof.has_external_input(text):
        return False
    idx = class_index if class_index is not None else class_index_of(code_root)
    if not idx:
        return False

    candidates: Dict[str, set] = {}
    for m in _DECL_NEW.finditer(text):
        var = m.group(2)
        candidates.setdefault(var, set()).update(
            (m.group(1).split(".")[-1], m.group(3).split(".")[-1]))
    for m in _DECL_ANY.finditer(text):
        candidates.setdefault(m.group(2), set()).add(m.group(1).split(".")[-1])

    for var, types in candidates.items():
        for simple in types:
            if not simple or simple[0].islower():  # 基本类型 / 关键字，不是类
                continue
            for path in (idx.get(simple) or [])[:_MAX_CLASS_CANDIDATES]:
                for nm in _const_methods_of(path, prof):
                    if re.search(re.escape(var) + r"\s*\.\s*" + re.escape(nm) + r"\s*\(", text):
                        return True
    return False


def _arg_value(expr: str) -> object:
    m = _STR_LITERAL.match(expr.strip())
    return m.group(1) if m else UNKNOWN


def literal_list_index(window: str, require_assign: bool = True) -> bool:
    """② 列表索引求值：`list.get(i)` 取到的**是否恒为字符串字面量**。

    安全性设计（宁可少抑制）：
      - add 的实参不是字面量 → 该位置记 UNKNOWN；
      - **任何一次** get 取到 UNKNOWN 或越界 → 整段判不安全（直接返回 False）；
      - 只有**所有** get 都取到字面量、且至少有一次取到，才判常量；
      - `require_assign`：要求 get 的结果被赋给变量（`bar = v.get(1)`），
        否则「算出来是常量」和「代码真的用了它」之间没有联系。
    """
    if not window or "ArrayList" not in window:
        return False
    text = _strip_comments(window)
    hit = False
    for decl in _LIST_DECL.finditer(text):
        name = decl.group(1)
        tail = text[decl.end():]
        events: List[Tuple[int, str, object]] = []
        add_rx = re.compile(re.escape(name) + r"\s*\.\s*add\s*\(\s*([^;]{0,150}?)\s*\)\s*;")
        rm_rx = re.compile(re.escape(name) + r"\s*\.\s*remove\s*\(\s*(\d+)\s*\)\s*;")
        get_rx = re.compile(re.escape(name) + r"\s*\.\s*get\s*\(\s*(\d+)\s*\)")
        for m in add_rx.finditer(tail):
            events.append((m.start(), "add", _arg_value(m.group(1))))
        for m in rm_rx.finditer(tail):
            events.append((m.start(), "remove", int(m.group(1))))
        for m in get_rx.finditer(tail):
            events.append((m.start(), "get", int(m.group(1))))
        if not events:
            continue
        events.sort(key=lambda e: e[0])
        items: List[object] = []
        for _pos, kind, payload in events:
            if kind == "add":
                items.append(payload)
            elif kind == "remove":
                idx = int(payload)  # type: ignore[arg-type]
                if 0 <= idx < len(items):
                    items.pop(idx)
            else:
                idx = int(payload)  # type: ignore[arg-type]
                if not (0 <= idx < len(items)) or not isinstance(items[idx], str):
                    return False          # 取到 UNKNOWN / 越界 → 保守不抑制
                hit = True
    if not hit:
        return False
    if require_assign and not _ASSIGN_GET.search(text):
        return False
    return True


def untainted_value(window: str, family: str = "", code_root: str = "",
                    profile: Optional[StackProfile] = None,
                    class_index: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, str]:
    """裁决入口：窗口里的值是否可能被攻击者控制。

    返回 (是否可判「不可控」, 命中的判据名)。**fail-open**：任何异常/证据不足
    都返回 (False, "")，即不抑制。
    """
    if not window or not family:
        return False, ""
    prof = profile or active_profile()
    if not prof.is_input_driven(family):
        return False, ""
    try:
        if constant_call_source(window, code_root=code_root, profile=prof,
                                class_index=class_index):
            return True, "untaint_constant_call"
        if literal_list_index(window):
            return True, "untaint_literal_index"
    except Exception as exc:  # pragma: no cover
        logger.warning("[untaint] 判定异常（不抑制）：%s", exc)
        return False, ""
    return False, ""
