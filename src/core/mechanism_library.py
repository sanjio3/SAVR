"""机制表：库内置闸门的加载、匹配与约束求交。

设计动机：之前提到"要不要给每个库补一张版本→绕过表"，答案是**不该**。绕过列表会无限膨胀，
而"门"是稳定的：每个库就那么一两个闸门，跨版本基本不变，变的是默认值（safeMode、trustURLCodebase
这类）与黑名单细节。

所以本模块做三件事：
1. 从 config/mechanism_library.yaml 加载各库的「闸门」条目（gate / kind / default / disable_by / depends）。
2. 按 SCA 给出的 package + version 匹配生效条目（支持 >=/<= 区间与 *）。
3. 把「自写净化器约束」与「库内置闸门约束」**求交**，得到最终可投放载荷的约束。

新漏洞怎么跟进：条目里的版本区间与默认值尽量来自机器可读数据源（OSV / GitHub Advisory / NVD，
本项目 SCA 已跑 osv 与 trivy，产物里有 osv 报告），数据源更新即自动生效；
只有出现全新「机制」时才需要人工补一条。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.sanitizer_miner import FilterSpec

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))
DEFAULT_LIBRARY_PATH = os.path.join(_PROJECT_ROOT, "config", "mechanism_library.yaml")

_MECH_CACHE: Optional[List[Dict[str, Any]]] = None


def load_mechanisms(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """加载机制表；文件缺失或解析失败返回空表（fail-open）。"""
    global _MECH_CACHE
    if path is None and _MECH_CACHE is not None:
        return _MECH_CACHE
    p = path or DEFAULT_LIBRARY_PATH
    try:
        import yaml
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        out = [m for m in (data.get("mechanisms") or []) if isinstance(m, dict)]
    except Exception:
        out = []
    if path is None:
        _MECH_CACHE = out
    return out


def _cmp(v: str, op: str, ref: str) -> bool:
    """简化版本比较：按点分数字逐段比较，非数字按字符串。"""
    def _parts(s):
        out = []
        for seg in str(s or "").split("."):
            m = re.match(r"^(\d+)", seg)
            out.append((int(m.group(1)), seg) if m else (0, seg))
        return out
    a, b = _parts(v), _parts(ref)
    n = max(len(a), len(b))
    for i in range(n):
        x = a[i] if i < len(a) else (0, "")
    y = b[i] if i < len(b) else (0, "")
    if x[0] != y[0]:
        return x[0] < y[0] if op == "<" else (x[0] <= y[0] if op == "<=" else (x[0] > y[0] if op == ">" else x[0] >= y[0]))
    if x[1] != y[1]:
        return x[1] < y[1] if op == "<" else (x[1] <= y[1] if op == "<=" else (x[1] > y[1] if op == ">" else x[1] >= y[1]))
    return op in ("<=", ">=")


def _in_range(version: str, rng: str) -> bool:
    v = str(version or "").strip()
    r = str(rng or "").strip()
    if not r or r == "*":
        return True
    for clause in r.split(","):
        clause = clause.strip()
        m = re.match(r"^(>=|<=|>|<)?\s*(.+)$", clause)
        if not m:
            continue
        op = m.group(1) or "=="
        ref = (m.group(2) or "").strip()
        if op == "==":
            if v != ref:
                return False
        elif not _cmp(v, op, ref):
            return False
    return True


def lookup(package: str, version: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    """按包 + 版本返回生效的机制条目。"""
    pkg = str(package or "").strip()
    hits = []
    for m in load_mechanisms(path):
        if str(m.get("package") or "").strip() != pkg:
            continue
        if _in_range(version, str(m.get("version_range") or "*")):
            hits.append(m)
    return hits


def to_filter_spec(mech: Dict[str, Any]) -> Optional[FilterSpec]:
    """把机制条目转成 FilterSpec，供造弹与闸门复用同一套约束表示。"""
    if not isinstance(mech, dict):
        return None
    kind = str(mech.get("kind") or "").strip().lower()
    if kind not in ("allow", "deny", "escape", "regex"):
        return None
    tokens: List[str] = []
    patterns: List[str] = []
    if kind == "deny":
        for t in (mech.get("deny_tokens") or []):
            if str(t):
                tokens.append(str(t))
        for p in (mech.get("deny_patterns") or []):
            if str(p):
                patterns.append(str(p))
    else:
        for p in (mech.get("allow_patterns") or []):
            if str(p):
                patterns.append(str(p))
    transforms = [str(t) for t in (mech.get("transforms") or []) if str(t)]
    return FilterSpec(
        kind=kind, tokens=tokens, patterns=patterns, transforms=transforms,
        case_sensitive=bool(mech.get("case_sensitive", True)),
        decode_first=bool(mech.get("decode_first", False)),
        source="mechanism_library",
        note=str(mech.get("notes") or ""),
    )


def intersect(specs: List[FilterSpec]) -> Optional[FilterSpec]:
    """多条约束求交（自写净化器 + 库内置闸门 + 拦截器 + 目录白名单）。

    规则（保守，宁可少发也不误判为可绕过）：
      - 任一 deny：拒绝 token / 模式取并集（更严格）。
      - 任一 allow：允许集取交集；无法求交则保留最严格的一条（字符数更少的允许集）。
      - deny 与 allow 同时存在：两者都要满足（先过 allow，再过 deny）。
      - M9 目录白名单（path_prefix）：base_dir **全部保留**而非取其一——
        多个目录白名单同时生效时，载荷必须同时落在每个 base 之内，这本身就是交集语义。
        tokens 槽位留给 deny 并集，于是「目录白名单 + 黑名单」能落在单条 spec 里表达，
        由 simulate_filter 的 KIND_PATH_PREFIX 分支先判 token 再判目录。
    """
    real = [s for s in specs or [] if isinstance(s, FilterSpec) and s.is_known()]
    if not real:
        return None
    denies = [s for s in real if s.kind == FilterSpec.KIND_DENY]
    allows = [s for s in real if s.kind == FilterSpec.KIND_ALLOW]
    path_specs = [s for s in real if s.kind == FilterSpec.KIND_PATH_PREFIX]

    tokens: List[str] = []
    for s in denies:
        for t in s.tokens:
            if t not in tokens:
                tokens.append(t)
    deny_patterns: List[str] = []
    for s in denies:
        for p in s.patterns:
            if p not in deny_patterns:
                deny_patterns.append(p)

    allow_patterns: List[str] = []
    if allows:
        # 取最严格的允许集（字符集最小的那条）
        strictest = min(allows, key=lambda s: len(s.patterns[0]) if s.patterns else 0)
        allow_patterns = list(strictest.patterns)

    # M9：目录白名单参与时，合并结果以 path_prefix 为主 kind 承载
    if path_specs:
        bases: List[str] = []
        has_norm = False
        for s in path_specs:
            for p in s.patterns:
                if p and p not in bases:
                    bases.append(p)
            has_norm = has_norm or bool(s.has_normalization)
        if bases:
            return FilterSpec(
                kind=FilterSpec.KIND_PATH_PREFIX, tokens=tokens, patterns=bases,
                transforms=[], case_sensitive=True, decode_first=False,
                has_normalization=has_norm,      # 符号链接不可模拟 → 不得判 non_bypassable
                source="mechanism_library.merged",
                note=("目录白名单 base 取交集(%d 个)，拒绝集取并集" % len(bases)
                      + ("；allow 字符集约束需同时满足" if allow_patterns else "")),
            )

    # 冲突时优先 allow（更严格），并带上 deny 并集
    if allow_patterns:
        return FilterSpec(
            kind=FilterSpec.KIND_ALLOW, tokens=tokens, patterns=allow_patterns,
            transforms=[], case_sensitive=True, decode_first=False,
            source="mechanism_library.merged",
            note="允许集取交集(最严格)，拒绝集取并集",
        )
    if tokens or deny_patterns:
        return FilterSpec(
            kind=FilterSpec.KIND_DENY, tokens=tokens, patterns=deny_patterns,
            transforms=[], case_sensitive=True, decode_first=False,
            source="mechanism_library.merged",
            note="拒绝集取并集",
        )
    return None
