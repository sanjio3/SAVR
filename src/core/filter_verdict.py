"""净化器可绕过性判定（2026-10-02 落地）：可绕过 / 不可绕过 / 未定，一等公民判定。

背景（用户指正，认同）：白名单命中就是真净化器，**不该继续死磕**。此前造不出载荷就笼统走
degraded_no_synthesis，既浪费重试轮次，又把"过滤器有效、不可利用"这个**真阴性**结论丢掉了
（而精确率正是本项目瓶颈）。

判定思路：把「这一族完成注入所必须的语法字符」与净化器约束求交。
  - 允许集装不下任何必需语法 → 不可绕过（真净化器）：终止，不再重试。
  - 能装下 / 黑名单有漏网构造 → 可绕过：附上可用载荷。
  - 静态字符级推理判不了（语义级、解析器级，如 fastjson autoType 语义链）→ 未定：
    有界探索后诚实记 unknown，绝不谎报干净。

**同一过滤器对不同族结论不同**，必须按族判：java-sec-code 允许集 `[a-zA-Z0-9_/.-]`
对命令注入（需 ; | & $）是不可绕过，对路径穿越（需 . 和 /）仍是可绕过。
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

from src.core.sanitizer_miner import FilterSpec, simulate_filter_safe, _patterns_supported

VERDICT_BYPASSABLE = "bypassable"
VERDICT_NON_BYPASSABLE = "non_bypassable"
VERDICT_UNDETERMINED = "undetermined"

# 各族完成注入所必需的语法（多选项，满足任一即可）。用于与允许集求交。
# 注意（Q2）：空格(" ")不再是 sqli 的独立可满足 token——空格单独不构成 SQLi，它只是陪衬，
# 只有与引号/`--` 同现时才有意义。把裸空格列为必需语法是建模错误，会让「允许集含空格但拦了引号」
# 的过滤器被误判可绕过（假阳性）。空格降级为组合修饰符，不再单独计入。
FAMILY_REQUIRED: Dict[str, List[str]] = {
    "command_execution": [";", "|", "&", "$", "`", "\n"],
    "sqli": ["'", '"', "--", ";"],
    "xss": ["<", ">", '"', "'"],
    "path_traversal": ["../", "..\\"],
    "ssti": ["${", "#{", "{{"],
    "ldap_injection": ["*", "(", ")"],
    "xpathi": ["'", "[", "]"],
    "crlf_injection": ["\r", "\n", "%0d", "%0a"],
    "ssrf": [":", "/"],
}

# Q1：每族「最小完整利用串」。non_bypassable 必须由「对真实利用串跑 simulate_filter 全失败」
# 推出，而不是靠抽象字符集（parse_allowed_chars 只看字符并集，看不见正则结构与归一化）。
# 用整串过 simulate_filter，杜绝字符并集假阳性；缺利用串的族回退到字符集推理（更保守）。
FAMILY_EXPLOIT: Dict[str, List[str]] = {
    "command_execution": [";id", "|id", "$(id)", "`id`", "&&id"],
    "sqli": ["' OR 1=1-- ", "' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT 1,2,3--"],
    "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"],
    "path_traversal": ["../../etc/passwd", "..\\..\\windows\\win.ini", "....//etc/passwd"],
    "ssti": ["${7*7}", "#{7*7}", "{{7*7}}"],
    "ldap_injection": ["*)(uid=*", "*)(|(uid=*", "admin*"],
    "xpathi": ["' or '1'='1", "'] | //user["],
    "crlf_injection": ["%0d%0aX-SastAI-Injected: 1", "\r\nX-SastAI-Injected: 1"],
    "ssrf": ["http://127.0.0.1:8080/", "file:///etc/passwd"],
}

# 大小写不敏感的 sink 上下文（黑名单若大小写敏感，则改大小写即可绕过）
_CASE_INSENSITIVE_SINK_HINT = ("html", "xss", "template", "ssti", "sql")

_RE_CHARCLASS = re.compile(r"\[(.*?)\]", re.S)


def _norm_family(family: str) -> str:
    return str(family or "").strip().lower().replace("-", "_")


def parse_allowed_chars(pattern: str) -> Optional[Set[str]]:
    """把允许集正则解析成字符集合；解析不了返回 None（交回"未定"）。"""
    if not pattern:
        return None
    p = pattern.strip()
    base: Set[str] = set()
    if "\\w" in p or "\\d" in p:
        base |= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    m = _RE_CHARCLASS.search(p)
    if m:
        inner = m.group(1)
        i = 0
        while i < len(inner):
            c = inner[i]
            if c == "\\":
                if i + 1 < len(inner):
                    base.add(inner[i + 1])
                    i += 2
                    continue
                i += 1
                continue
            if i + 2 < len(inner) and inner[i + 1] == "-":
                lo, hi = inner[i], inner[i + 2]
                try:
                    for o in range(ord(lo), ord(hi) + 1):
                        base.add(chr(o))
                except ValueError:
                    pass
                i += 3
                continue
            base.add(c)
            i += 1
    for ch in re.sub(r"[\^\$\+\*\?]|\\w|\\d|\(\)", "", p):
        if ch not in "[]":
            base.add(ch)
    return base or None


def _token_blocked_by_deny(token: str, deny: List[str]) -> bool:
    """该必需语法是否被黑名单覆盖（含任一拒绝 token，或拒绝 token 含它）。"""
    for d in deny or []:
        if not d:
            continue
        if d in token or token in d:
            return True
    return False


def classify(spec: Optional[FilterSpec], family: str, candidates: Optional[List[str]] = None,
             sink_context: str = "") -> Dict[str, Any]:
    """三分类判定。返回 {verdict, reason, payloads, signals}。"""
    fam = _norm_family(family)
    cands = [c for c in (candidates or []) if c]
    signals: List[str] = []

    if spec is None or not isinstance(spec, FilterSpec) or not spec.is_known():
        return {"verdict": VERDICT_UNDETERMINED, "reason": "未拿到净化器约束，无法判定",
                "payloads": cands, "signals": signals}

    # 明确的可绕过信号（"假净化器"特征）
    if spec.decode_first:
        signals.append("先解码后检查：编码后即可绕过")
    if spec.case_sensitive and any(k in fam or k in (sink_context or "").lower()
                                   for k in _CASE_INSENSITIVE_SINK_HINT):
        signals.append("校验大小写敏感而 sink 不敏感：改大小写即可绕过")
    if spec.kind == FilterSpec.KIND_ALLOW and spec.patterns:
        pat = spec.patterns[0]
        if not pat.startswith("^") or not pat.endswith("$"):
            signals.append("允许集正则未锚定：可嵌入绕过")
    if signals and cands:
        return {"verdict": VERDICT_BYPASSABLE, "reason": "；".join(signals),
                "payloads": cands, "signals": signals}

    required = FAMILY_REQUIRED.get(fam)
    exploit_strings = FAMILY_EXPLOIT.get(fam, [])

    if spec.kind == FilterSpec.KIND_ALLOW:
        allowed = parse_allowed_chars(spec.patterns[0] if spec.patterns else "")
        if allowed is None:
            return {"verdict": VERDICT_UNDETERMINED,
                    "reason": "允许集正则无法解析为字符集", "payloads": cands, "signals": signals}
        _anchored = spec.patterns[0].startswith("^") and spec.patterns[0].endswith("$") if spec.patterns else False
        # Q1 安全闸：含先解码 / 归一化 / Python 不支持的正则 → 静态字符集无法覆盖，
        # 不得判 non_bypassable（fail-open 到 undetermined，交运行时裁决）。
        if spec.decode_first or spec.has_normalization or not _patterns_supported(spec):
            return {"verdict": VERDICT_UNDETERMINED, "confidence": "low",
                    "reason": "允许集守卫含先解码/归一化或正则含 Python 不支持语法，"
                              "静态无法证明不可绕过，交运行时复核",
                    "payloads": [], "signals": signals}
        if not _anchored:
            return {"verdict": VERDICT_UNDETERMINED, "confidence": "low",
                    "reason": "允许集正则未锚定，存在绕过空间，不敢判不可绕过",
                    "payloads": [], "signals": signals}
        # Q1 实证：用每族最小完整利用串过 simulate_filter_safe。有三态结果：
        #   - None：含不支持正则，无法实证 → undetermined；
        #   - 任一 True：有利用串可落在允许集内（白名单过宽）→ 不判终态；
        #   - 全 False：利用串全被拦 → 真净化器，可判 non_bypassable。
        if exploit_strings:
            _res = [simulate_filter_safe(spec, e) for e in exploit_strings]
            if any(r is None for r in _res):
                return {"verdict": VERDICT_UNDETERMINED, "confidence": "low",
                        "reason": "利用串含 Python 不支持的正则，无法实证不可绕过",
                        "payloads": [], "signals": signals}
            if any(r is True for r in _res):
                if cands:
                    return {"verdict": VERDICT_BYPASSABLE,
                            "reason": "利用串可落在允许集内，已造出 %d 发载荷" % len(cands),
                            "payloads": cands, "signals": signals}
                return {"verdict": VERDICT_UNDETERMINED,
                        "reason": "有利用串可过白名单（白名单过宽），但当前候选池未构造出载荷",
                        "payloads": [], "signals": signals}
            return {"verdict": VERDICT_NON_BYPASSABLE, "confidence": "high",
                    "reason": ("允许集 %s 拦下该族全部最小利用串（%s 例）→ 真净化器，判定不可利用"
                               % (spec.patterns[0], len(exploit_strings))),
                    "payloads": [], "signals": signals}
        # 无利用串族（语义级）：回退到字符集推理，但更保守——只在「字符集也装不下」且锚定时判终态。
        if required is None:
            return {"verdict": VERDICT_UNDETERMINED,
                    "reason": "该族绕过属语义/解析器级（非字符级），静态判定不了",
                    "payloads": cands, "signals": signals}
        expressible = [t for t in required if all(ch in allowed for ch in t)]
        if not expressible:
            return {"verdict": VERDICT_NON_BYPASSABLE, "confidence": "high",
                    "reason": ("允许集 %s 装不下该族所需的任何注入语法（%s）→ 真净化器，判定不可利用"
                               % (spec.patterns[0], "/".join(required))),
                    "payloads": [], "signals": signals}
        if cands:
            return {"verdict": VERDICT_BYPASSABLE,
                    "reason": "必需语法 %s 可落在允许集内，已造出 %d 发载荷"
                              % ("/".join(expressible), len(cands)),
                    "payloads": cands, "signals": signals}
        return {"verdict": VERDICT_UNDETERMINED,
                "reason": "必需语法可表达但当前候选池未构造出载荷", "payloads": [], "signals": signals}

    if spec.kind == FilterSpec.KIND_DENY:
        if cands:
            return {"verdict": VERDICT_BYPASSABLE,
                    "reason": "黑名单有漏网构造，已造出 %d 发载荷" % len(cands),
                    "payloads": cands, "signals": signals}
        if required is None:
            return {"verdict": VERDICT_UNDETERMINED,
                    "reason": "该族绕过属语义级，且当前未构造出载荷", "payloads": [], "signals": signals}
        # Q1 实证升级：黑名单 non_bypassable 不能只靠「必需语法字符都被 deny token 覆盖」
        # （字符并集盲点：token 是 '<script>' 但 onerror= 变体不含它 → 仍可能绕过）。
        # 必须「该族最小完整利用串全被 simulate_filter 拦」才算真净化器。
        if exploit_strings:
            _res = [simulate_filter_safe(spec, e) for e in exploit_strings]
            if any(r is None for r in _res):
                return {"verdict": VERDICT_UNDETERMINED, "confidence": "low",
                        "reason": "利用串含 Python 不支持的正则，无法实证不可绕过",
                        "payloads": [], "signals": signals}
            if all(r is False for r in _res):
                return {"verdict": VERDICT_NON_BYPASSABLE, "confidence": "high",
                        "reason": "该族全部最小利用串（%s 例）均被黑名单拦下 → 判定不可利用"
                                  % len(exploit_strings),
                        "payloads": [], "signals": signals}
            return {"verdict": VERDICT_UNDETERMINED,
                    "reason": "黑名单未覆盖全部利用串（有变体可绕过），但当前未构造出可用载荷",
                    "payloads": [], "signals": signals}
        all_blocked = all(_token_blocked_by_deny(t, spec.tokens) for t in required)
        if all_blocked:
            return {"verdict": VERDICT_NON_BYPASSABLE, "confidence": "high",
                    "reason": "该族全部必需注入语法（%s）均被黑名单覆盖 → 判定不可利用"
                              % "/".join(required),
                    "payloads": [], "signals": signals}
        return {"verdict": VERDICT_UNDETERMINED,
                "reason": "黑名单未覆盖全部必需语法，但当前未构造出可用载荷",
                "payloads": [], "signals": signals}

    if spec.kind == FilterSpec.KIND_ESCAPE:
        ctx = (sink_context or "").lower()
        if not ctx:
            return {"verdict": VERDICT_UNDETERMINED,
                    "reason": "仅转义型净化器，但 sink 上下文未知，无法判断转义是否完整",
                    "payloads": cands, "signals": signals}
        if cands:
            return {"verdict": VERDICT_BYPASSABLE,
                    "reason": "转义未覆盖当前 sink 上下文（%s）" % ctx,
                    "payloads": cands, "signals": signals}
        return {"verdict": VERDICT_NON_BYPASSABLE,
                "reason": "转义覆盖当前 sink 上下文（%s）" % ctx, "payloads": [], "signals": signals}

    return {"verdict": VERDICT_UNDETERMINED, "reason": "约束类型未识别", "payloads": cands, "signals": signals}


def is_terminal(verdict: Optional[Dict[str, Any]]) -> bool:
    """不可绕过 = 终态：不再进重试环、不再升变体（"判完就停"）。

    安全设计（防误判掐掉真漏洞，三重保险）：
      1. 必须 confidence=high（例如未锚定的允许集一律判未定，不当终态）；
      2. 开关 SAST_AI_VERDICT_TERMINAL=0 可整体关闭"判死"，退回可重试；
      3. 终态**不删发现**：只是停止烧轮次，并把结论落成显式状态
         filtered_not_exploitable（可审计、可回溯），绝不静默消失。
    """
    if not verdict or verdict.get("verdict") != VERDICT_NON_BYPASSABLE:
        return False
    if str(os.environ.get("SAST_AI_VERDICT_TERMINAL", "1")).strip() == "0":
        return False
    return verdict.get("confidence") == "high"


def terminal_diagnostic_canary(family: str, spec: Optional[FilterSpec] = None) -> str:
    """Q5：终态 non_bypassable 仍应发的一发**无害**诊断 canary（非破坏性），
    拿 IAST 到达信号，化解「判死=零运行时证据」。

    canary 本身不触发利用，只证明「探针看没看到这次请求」；净化器拦了 canary →
    arrival-sanitized，是「过滤器有效」的正向证据，正确落成 filtered_not_exploitable，不是死局。
    """
    try:
        from src.iast.attack_context import family_minimal_payload
        cand = family_minimal_payload(family)
        if cand:
            return cand
    except Exception:
        pass
    return "sastai-diagnostic-canary"
