"""语义 safe-pattern 判定（P3：cmdi 精确率）。

背景
----
OWASP cmdi 的 safe 用例与真漏洞用例，**源码形状几乎相同**，唯一区别是「条件是否恒真」：

  safe   : bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;   # num=106 → 232>200 恒真 → 取常量
  vuln   : bar = (7 * 42) - num > 200 ? "This should never happen" : param;     # num=106 → 188<200 恒假 → 取 param

实测：按「形状正则」补匹配会把 49/126 条真漏洞误杀（tern 14、switch 18、constcmd 22）；
对条件做**数值求值**后，可达 64/102 FP 命中、0/126 TP 误伤。

本模块只做「纯源码、确定性」的安全判定，不依赖运行时/IAST，因此可脱离 D2 门控。
"""
from __future__ import annotations

import re
from typing import Dict, Optional

# —— if_const：死分支常量（与 benchmark_cli 现有规则一致，0 TP 误伤）——
_IF_CONST = re.compile(
    r'if\s*\([^;{}]*[+*%-][^;{}]*\)\s*(?:\{\s*)?(\w+)\s*=\s*"[^"]*"\s*;\s*'
    r'(?:\}\s*)?else\s*(?:\{\s*)?\1\s*=\s*(\w+)', re.S)

# —— ternary 常量：x = <expr> <op> <num> ? "const" : var; ——
_TERN = re.compile(r'(\w+)\s*=\s*([^;?=]+?)\s*([<>]=?)\s*(\d+)\s*\?\s*"([^"]*)"\s*:\s*(\w+)\s*;')
_INTD = re.compile(r'\bint\s+(\w+)\s*=\s*(\d+)\s*;')

# —— map 覆盖：var = (String) m.get("k"); ... ——
_GET = re.compile(r'(\w+)\s*=\s*\(String\)\s*(\w+)\.get\("([^"]+)"\)\s*;')
_PUT = re.compile(r'(\w+)\.put\("([^"]+)"\s*,\s*([^)]+)\)\s*;')

# —— switch 常量：String g="ABC"; char t=g.charAt(1); switch(t){case 'B': x="const";} ——
_SW_STR = re.compile(r'String\s+(\w+)\s*=\s*"([^"]*)"\s*;')
_SW_CHAR = re.compile(r'char\s+(\w+)\s*=\s*(\w+)\.charAt\(\s*(\d+)\s*\)\s*;')


def _eval_num(expr: str, variables: Dict[str, int]) -> Optional[float]:
    """只对「数字 + 已知 int 变量 + +-*()」求值，其余一律放弃（fail-safe）。"""
    e = expr
    for name, val in variables.items():
        e = re.sub(rf'\b{re.escape(name)}\b', str(val), e)
    if not re.fullmatch(r'[\d\s+\-*()]+', e):
        return None
    try:
        return eval(e, {"__builtins__": {}}, {})  # noqa: S307 — 已用白名单正则约束
    except Exception:
        return None


def if_const_safe(src: str) -> Optional[str]:
    if _IF_CONST.search(src):
        return "if_const"
    return None


def ternary_const_safe(src: str) -> Optional[str]:
    """条件恒真 → 取常量分支 → 安全；条件恒假 → 取 param 分支 → 不安全（不误杀）。"""
    variables = {m.group(1): int(m.group(2)) for m in _INTD.finditer(src)}
    for m in _TERN.finditer(src):
        _lhs, expr, op, rhs, _const, _falsevar = m.groups()
        val = _eval_num(expr, variables)
        if val is None:
            continue
        r = int(rhs)
        cond = {">": val > r, ">=": val >= r, "<": val < r, "<=": val <= r}[op]
        if cond:
            return f"ternary:{expr.strip()}{op}{rhs}→const"
    return None


def map_overwrite_safe(src: str) -> Optional[str]:
    """同一变量先 get 污点、再 get 常量（后者覆盖前者）→ 安全。"""
    puts = {m.group(2): m.group(3).strip() for m in _PUT.finditer(src)}
    seq: Dict[str, list] = {}
    for m in _GET.finditer(src):
        var, _obj, key = m.groups()
        seq.setdefault(var, []).append(key)
    for var, keys in seq.items():
        if len(keys) >= 2 and keys[-1] != keys[0]:
            last_val = puts.get(keys[-1], "")
            if last_val.startswith('"'):
                return f"map_overwrite:{var}"
    return None


def switch_const_safe(src: str) -> Optional[str]:
    """switch 目标由「常量字符串.charAt(n)」决定，且取到的 case 赋常量 → 安全。"""
    ms = _SW_STR.search(src)
    if not ms:
        return None
    gname, gval = ms.group(1), ms.group(2)
    mc = _SW_CHAR.search(src)
    if not mc or mc.group(2) != gname:
        return None
    idx = int(mc.group(3))
    if idx >= len(gval):
        return None
    target = gval[idx]
    mm = re.search(rf"case\s+'{re.escape(target)}'\s*:\s*(\w+)\s*=\s*([^;]+);", src)
    if mm and mm.group(2).strip().startswith('"'):
        return f"switch:{gname}[{idx}]={target}"
    return None


_ORDER = (if_const_safe, ternary_const_safe, map_overwrite_safe, switch_const_safe)


def safe_pattern_type(src: str) -> Optional[str]:
    """返回命中的安全写法类型（字符串）或 None。命中即「该用例为安全实现」。"""
    if not src:
        return None
    for fn in _ORDER:
        try:
            hit = fn(src)
        except Exception:
            hit = None
        if hit:
            return hit
    return None


# —— safe RNG：weak_random 族静态安全实现（2026-10-19 r111 weakrand 实测）——
# 数据（weakrand-1/2 检测集合，r89 真值）：
#   FP 94+86 中 73+66 = 139 个「源码只用 java.security.SecureRandom」；
#   TP 112+106 **全部**「只用 java.util.Random / Math.random」——零交叉。
# 与 P2（运行时 safe_impl）互补：random_source 路由没有运行时正证据
# （观测不到 Random ≠ 用了 SecureRandom），但源码正证据是确定性的。
# 纪律：只认正证据（显式 SecureRandom）且**无**弱随机调用（BOTH 情形 fail-open 不抑制）。
_SEC_RNG = re.compile(r'\bSecureRandom\b')
_WEAK_RNG = re.compile(r'java\.util\.Random|new\s+Random\s*\(|\bMath\.random\s*\(')


def _code_lines_only(src: str) -> list:
    """去掉注释行与打印语句（Benchmark 的安全用例会把 "Weak Randomness" 打进 println）。"""
    out = []
    for line in str(src or '').splitlines():
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('*') or s.startswith('/*'):
            continue
        if 'println' in s or 'System.out' in s:
            continue
        out.append(s)
    return out


def safe_rng_static(src: str) -> Optional[str]:
    """weak_random 族：源码只用 SecureRandom（且无弱随机调用）→ 返回 'SecureRandom'。"""
    code = _code_lines_only(src)
    if not code:
        return None
    has_sec = any(_SEC_RNG.search(l) for l in code)
    has_weak = any(_WEAK_RNG.search(l) for l in code)
    if has_sec and not has_weak:
        return 'SecureRandom'
    return None


def weak_rng_static(src: str) -> Optional[str]:
    """weak_random 族**正证据**（2026-10-27，E11 消融后续）：源码使用不安全随机源
    （且无 SecureRandom 混用）→ 返回首个命中的证据标记。

    与 safe_rng_static 互为镜像。为什么需要：474（blind 布局）实证，A2 无 case# 先验时
    spec 变薄 ⇒ canary 未流经 Random sink（00066 事件 78/6 → 4/0）⇒ 运行时判据饿死，
    6 条 weak_random TP 丢失。但「源码用了不安全随机源」是**纯代码属性主张**，
    源码本身就是充分证据——不需要运行时事件，更不需要 case# 布局先验。

    语义护栏：has_weak 且 **无** SecureRandom 混用才算干净正证据；两者混用属歧义
    （可能是安全降级样板/死代码），fail-open 返回 None 维持 unconfirmed。
    """
    code = _code_lines_only(src)
    if not code:
        return None
    if any(_SEC_RNG.search(l) for l in code):
        return None
    for line in code:
        m = _WEAK_RNG.search(line)
        if m:
            return (m.group(0) or 'weak-rng')[:40]
    return None
