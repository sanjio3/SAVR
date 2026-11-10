"""黄金集条目的「环境前提」（env_premise）—— 真值两层记账的判定层（2026-10-03 M1）。

背景（Part2修复方案-定稿本轮 §1 决策一）
------------------------------------------
真值必须分两层看，否则「运行时打不通」会被误记成「检测失败」：

    L_code（代码缺陷层）  = 静态侧能看到的东西 —— 代码里确实存在缺陷写
                           法，不受中间件/JDK/数据库/出网能力约束。
    L_exploit（可利用层） = 运行时侧能证明的东西 —— 在当前靶场环境里真
                           的能打通。它是 L_code 的子集。

差集（L_code 有、L_exploit 没有）**不是检测失败**，而是 ``env_unsupported``：
环境不支持，代码缺陷仍在。旧口径把这个差集一起算进召回分母，于是「Tomcat
高版本 sanitize 响应头导致 CRLF 打不通」这类条目永久拉低召回率，逼着人去
改根本不该改的判据。

env_premise 的两种写法
----------------------
1) **可机检**（首选）：键是环境事实名（见 ``runtime_facts.collect_facts``），
   值是允许取值列表（小写子串匹配，任一命中即满足）::

       {"db_type": ["mysql", "mariadb"]}
       {"mw_type": ["tomcat"], "jdk_version": [">=9"]}

   事实缺失时 **fail-open**（判 ``unknown``，不缩小分母）—— 与既有的
   ``check_depends`` 语义一致：绝不因事实未知误杀链路。

2) **仅声明**（``_note``）：已知存在环境依赖，但当前没有可机检的事实项
   （典型：Tomcat 响应头 sanitize 的版本阈值尚未实测确定）。此时判
   ``unknown`` 并把 note 透出到报告，绝不当成不满足。

   这样设计是为了**不伪造阈值**：宁可让该条目同时留在两层分母里并在报告
   里标出「前提未实测」，也不能拍一个版本号出来静默缩小分母。

判定结果三态
------------
``satisfied`` / ``unsatisfied`` / ``unknown``。只有 ``unsatisfied`` 会把条目
从 L_exploit 分母里摘出去；``unknown`` 留在两层分母里并计入 ``env_premise_unverified``
清单，等 M2 把事实采上来后自然转为可机检。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# 判定三态
SATISFIED = "satisfied"
UNSATISFIED = "unsatisfied"
UNKNOWN = "unknown"

# 仅声明（不可机检）的保留键
NOTE_KEY = "_note"

# 允许出现在 env_premise 里、且由 runtime_facts.collect_facts() 提供的事实名。
# 未列入的键一律按 unknown 处理（不报错、不静默放行），避免拼错键名造成
# 「前提恒不满足」这种最坏情况。
KNOWN_FACT_KEYS = frozenset({
    "jdk_version",
    "db_type",
    "db_version",
    "mw_type",
    "mw_version",
    "egress",
    # M2 补：XML 解析器配置（XXE 族能不能真读出外部实体，看解析器怎么配而不看
    # 有没有 XXE.java）。取值：xml_dtd=disallowed/allowed、xml_external_entities
    # =enabled/disabled、xml_secure_processing=on/off。未知即键缺席 → fail-open。
    "xml_dtd",
    "xml_external_entities",
    "xml_external_parameter_entities",
    "xml_load_external_dtd",
    "xml_external_stylesheets",
    "xml_secure_processing",
    "xml_external_dtd_access",
    "xml_external_schema_access",
    "xml_xinclude",
    "xml_expand_entity_refs",
    "xml_validation",
})

# 版本型事实：值可写成范围表达式（">=9" / "1.2.68" / "<=1.2.83"），走区间比较
# 而非子串匹配。其余事实一律子串匹配。
_VERSION_FACTS = frozenset({"jdk_version", "db_version", "mw_version"})


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def _match_value(fact_key: str, actual: str, allowed: Any) -> Optional[bool]:
    """单条前提 vs 单个事实值比较。

    返回 True/False 表示可判定；返回 None 表示无法判定（事实为空 / 形态不认识），
    交给上层按 fail-open 处理。
    """
    act = _norm(actual)
    if not act:
        return None
    vals = allowed if isinstance(allowed, (list, tuple, set)) else [allowed]
    vals = [_norm(v) for v in vals if _norm(v)]
    if not vals:
        return None
    if fact_key in _VERSION_FACTS:
        from src.core.runtime_facts import jdk_in_range
        # 区间表达式：任一命中即满足。jdk_in_range 本身对不可解析版本 fail-open。
        return any(jdk_in_range(act, v) for v in vals)
    return any(v in act for v in vals)


def check_premise(
    premise: Optional[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """判定一条黄金集条目的环境前提是否满足。

    返回 ``(state, reason)``：
      - ``("satisfied", "")``        前提为空或全部事实满足
      - ``("unsatisfied", reason)``  有事实明确不满足（该条目应从 L_exploit 分母摘出）
      - ``("unknown", reason)``      事实缺失或前提不可机检（fail-open，留在分母）

    绝不在事实未知时返回 unsatisfied —— 那会让分母随采集能力的波动而抖动，
    把「没采到事实」读成「漏洞打不通」。
    """
    p = premise if isinstance(premise, dict) else {}
    if not p:
        return SATISFIED, ""
    facts = facts if isinstance(facts, dict) else {}

    note = str(p.get(NOTE_KEY) or "").strip()
    machine_keys = [k for k in p if str(k) != NOTE_KEY and str(p.get(k) or "")]
    unknown_reasons: List[str] = []

    for key in machine_keys:
        fk = str(key)
        if fk not in KNOWN_FACT_KEYS:
            unknown_reasons.append(f"{fk}:unknown_fact_key")
            continue
        actual = facts.get(fk)
        res = _match_value(fk, actual, p.get(fk))
        if res is True:
            continue
        if res is False:
            return UNSATISFIED, f"{fk}: actual={_norm(actual)!r} not in {p.get(fk)!r}"
        unknown_reasons.append(f"{fk}:fact_missing")

    if unknown_reasons:
        _r = ",".join(unknown_reasons)
        if note:
            _r = f"{_r};note={note}"
        return UNKNOWN, _r
    if note and not machine_keys:
        return UNKNOWN, f"note_only: {note}"
    return SATISFIED, ""


def is_exploit_layer(premise: Optional[Dict[str, Any]], facts: Optional[Dict[str, Any]] = None) -> bool:
    """该条目是否计入 L_exploit（可利用层）分母。

    只有明确 ``unsatisfied`` 才剔除；``unknown`` 保留（fail-open）。
    """
    return check_premise(premise, facts)[0] != UNSATISFIED


def describe(premise: Optional[Dict[str, Any]]) -> str:
    """给报告/前端用的可读描述（不参与判定）。"""
    p = premise if isinstance(premise, dict) else {}
    if not p:
        return ""
    note = str(p.get(NOTE_KEY) or "").strip()
    parts = [f"{k}={p.get(k)}" for k in p if str(k) != NOTE_KEY]
    out = " & ".join(parts)
    if note:
        out = f"{out}（{note}）" if out else note
    return out


# ---------------------------------------------------------------------------
# L_code / L_exploit 两层记账
# ---------------------------------------------------------------------------
def two_layer_counts(
    entries: List[Dict[str, Any]],
    facts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """对一批「已判定 applicable 的黄金条目」做两层计数。

    入参每项至少含 ``env_premise`` 键（可缺省）；返回：
      - ``code_total``      L_code 分母（全部适用条目）
      - ``exploit_total``   L_exploit 分母（前提明确不满足者已剔除）
      - ``env_unsupported`` 差集条数
      - ``env_unverified``  前提不可机检/事实缺失、按 fail-open 留在分母的条数
      - ``unsupported_types`` / ``unverified_types`` 明细（按条目 type）
    """
    code_total = 0
    exploit_total = 0
    unsupported: List[str] = []
    unverified: List[str] = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        code_total += 1
        state, _reason = check_premise(e.get("env_premise"), facts)
        if state == UNSATISFIED:
            unsupported.append(str(e.get("type") or e.get("id") or ""))
            continue
        exploit_total += 1
        if state == UNKNOWN:
            unverified.append(str(e.get("type") or e.get("id") or ""))
    return {
        "code_total": code_total,
        "exploit_total": exploit_total,
        "env_unsupported": len(unsupported),
        "env_unverified": len(unverified),
        "unsupported_types": unsupported,
        "unverified_types": unverified,
    }
