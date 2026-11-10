"""轻量常量求值：识别「代码看起来读了外部输入，实际值是常量」这类语义等价变异。

## 要治的病（r58 全族归因方案 4）

OWASP Benchmark 的「安全变体」大量使用**索引偏移变异**，xss 族最典型
（BenchmarkTest00151，真值 FP）：

    String bar = "alsosafe";
    if (param != null) {
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("safe");        // ← 垫底常量
        valuesList.add(param);          // ← 攻击者输入
        valuesList.add("moresafe");
        valuesList.remove(0);           // ← 移除垫底
        bar = valuesList.get(1);        // ← 实际取到 "moresafe"，不是 param
    }
    response.getWriter().printf(bar, obj);

纯语法特征抓不到（`"safe"` 字面量纯度 45% = 噪声），**必须做一次列表状态求值**。
方案 1 已用 `bench_safe_list_index` 语法规则捞到 22 个（零 TP 损失），
本模块负责把剩下那批「结构更绕、语法规则够不着」的也吃掉。

## 设计边界（刻意做得浅）

只做**字面量级**求值，不做符号执行、不做别名分析、不做跨方法传播：

    - 跟踪 `List<String> x = new ArrayList<>()` 的 add / remove(int) / get(int) 序列；
    - add 的实参是字符串字面量 → 记为该字面量；
    - add 的实参是变量/表达式 → 记为 UNKNOWN（保守，不当常量）；
    - remove(i) 按下标删除；get(i) 取出当前值。

**只在 get(i) 取到「确定的字符串字面量」时才算安全。** 取到 UNKNOWN 一律判不安全，
即默认 fail-safe：宁可少抑制也不误杀真漏洞。

绝不做的事：把 UNKNOWN 当常量、把多个同名 list 混在一起算、跨方法跟踪。
OWASP 一个用例一个类，类内求值已经够用；真实项目里形态复杂，浅求值会不准，
那种场景应该靠 D2 运行时验证而不是静态抑制。

用法：
    from src.core.const_prop import list_index_value_is_literal
    ok, literal = list_index_value_is_literal(source_text)
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

UNKNOWN = object()  # 哨兵：表示该位置的值不可静态确定

_LIST_DECL = re.compile(
    r"List\s*<\s*String\s*>\s*(\w+)\s*=\s*new\s+(?:java\s*\.\s*util\s*\.\s*)?ArrayList", re.I)
_STR_LITERAL = re.compile(r'^"((?:[^"\\]|\\.)*)"$')


def _strip_comments(src: str) -> str:
    """去块注释与行注释，避免注释里的 add/remove/get 干扰求值。"""
    out = []
    i, n = 0, len(src)
    in_block = False
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


def _arg_value(expr: str) -> object:
    """实参求值：字符串字面量 → 该字面量；其余 → UNKNOWN（保守）。"""
    m = _STR_LITERAL.match(expr.strip())
    if m:
        return m.group(1)
    return UNKNOWN


def list_index_value_is_literal(src: str) -> Tuple[bool, Optional[str]]:
    """判断「某个 List 的 get(非字面量来源)」取到的是否为确定字面量。

    返回 (True, 字面量内容) 表示取到确定常量（⇒ 可判安全）；
        (False, None) 表示取到不可确定的值、或根本不是这种模式（⇒ 不予抑制）。

    只识别单个列表对象；同名列表的后续声明会重新开一个新状态，
    这样即使一个文件里出现两段独立代码也不会串味。
    """
    if not src or "ArrayList" not in src:
        return False, None
    text = _strip_comments(src)

    for decl in _LIST_DECL.finditer(text):
        name = decl.group(1)
        # 只在该声明之后、且限定在该 list 名字上扫描操作序列
        tail = text[decl.end():]
        add_rx = re.compile(re.escape(name) + r"\s*\.\s*add\s*\(\s*([^;]{0,150}?)\s*\)\s*;")
        remove_rx = re.compile(re.escape(name) + r"\s*\.\s*remove\s*\(\s*(\d+)\s*\)\s*;")
        get_rx = re.compile(re.escape(name) + r"\s*\.\s*get\s*\(\s*(\d+)\s*\)")

        events: List[Tuple[int, str, object]] = []
        for m in add_rx.finditer(tail):
            events.append((m.start(), "add", _arg_value(m.group(1))))
        for m in remove_rx.finditer(tail):
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
                idx = int(payload)
                if 0 <= idx < len(items):
                    items.pop(idx)
            else:  # get —— 第一次取到确定字面量即返回
                idx = int(payload)
                if 0 <= idx < len(items):
                    val = items[idx]
                    if isinstance(val, str):
                        return True, val
                # 取到 UNKNOWN 或越界：不抑制，交给后续判定
                return False, None
    return False, None
