"""I2 → A2 / 重放侧 的反馈分流与闭环控制。

背景：
- I2 产出 feedback_to_a2=60、rollback_to_a2=30，二次回灌确实触发，但确认数纹丝不动。
- 失败原因分布：**60/60 首因都是「IAST 未观测到匹配 canary」**，端点幻觉/参数缺失/族误判 = 0。
  即回灌给 A2 的全是「运行时观测失败」，而 A2 是静态分析器，重跑只能产出同一条假说 → 空转。
- 反馈重复约 2.3 倍（60 条对应唯一 hypothesis_id 仅 26 个）：同一 verification 同时从
  next_action 与 verification_decision 两处 extend，同一假设被多次验证再叠加。

本模块解决三件事：
1. 反馈分流：给每条反馈打 failure_class，只有 hypothesis_defect 才回灌 A2；
   runtime_observation / probe_not_instrumented 改走重放侧或探针侧，不再浪费 A2 一轮。
2. 去重聚合：按 hypothesis_id 去重合并，避免重复内容吃掉回灌预算与 prompt。
3. 真循环：带迭代上限、attempt history、增益收敛判据的闭环控制器。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from src.iast.spec_projection import sync_entry_projection

logger = logging.getLogger(__name__)

# 失败类别
HYPOTHESIS_DEFECT = "hypothesis_defect"        # A2 假说本身有缺陷：端点幻觉/参数缺失/族误判 → 回灌 A2
RUNTIME_OBSERVATION = "runtime_observation"    # 运行时没观测到：canary 未到 sink / 等待窗口不足 → 改重放侧
PROBE_NOT_INSTRUMENTED = "probe_not_instrumented"  # 探针未插桩该 sink → 探针侧，本轮不可修
JUDGE_MISCLASSIFY = "judge_misclassify"        # D2 裁决误判 → 裁决侧
# （value_level_sanitized / hit_sanitized），即「静态侧声称漏洞、运行时确证无害」——
# 这是**有判据的 definitive 阴性**，是改进静态分析器（消减 over-claim）的最高价值样本，
# 与「证据缺失」彻底区分。它**不**进 A2（A2 是静态分析器，重跑只产同一条假说），而是
# 单独成桶，供静态侧消费。
RUNTIME_REFUTATION = "runtime_refutation"

# 只回灌 A2 的类别
A2_ACTIONABLE = (HYPOTHESIS_DEFECT,)

# 「重放侧变体梯子」决策表（_FIVE_CLASS_ACTIONS）。它们保留具体类名（如 arrived_unconfirmed），
# 但在 route_feedbacks 时归入 RUNTIME_OBSERVATION 桶，使 plan_replay_adjustments 能走五类决策表，
# 同时不进入 a2_actionable（A2_ACTIONABLE 仅含 hypothesis_defect），故不触发 A2 静态重写。
RUNTIME_FIVE_CLASS = (
    "blocked",            # 攻击被 WAF/防护策略拦截
    "route_unreachable",  # 路由不可达（404/410/400）
    "param_not_arrived",  # 参数未到达 sink（200/3xx/5xx 但 canary 未观测）
    "arrived_unconfirmed",# 探针确证到达 sink 但 D2 未确认有害
    "window_missed",      # 等待窗口错过事件（I1 窗口无事件但后续确认）
    # 鉴权墙下**良性请求也进不去**， offshore 补上会话即可； block 是「良性能进、带 Payload 被拒」。
    "auth_missing",
)

# 结构化字段里「假说门禁仍悬置」的四项语义（D2 裁决 residual_gaps.still_open 取值）。
# 这四项表示：假说声称「可达 / 攻击者可控 / 可绕门禁 / 载荷形状成立」，但运行时四项一个都没闭合。
# 属假说链路本身的问题（族误判、端点幻觉、参数位错），不是「等待窗口不足」。
_CHAIN_GATE_TOKENS = (
    "reachable", "attacker_control_proven", "gate_bypass_or_satisfaction_proven",
    "payload_shape_proven", "still_open",
)

# 分流关键词（按优先级匹配；命中即返回）
# 闭环退化成「只调重放参数、从不修假说」。链路不符按定义属假说缺陷，已迁入 hypothesis_defect。
_CLS_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (PROBE_NOT_INSTRUMENTED, ("探针未插桩", "未插桩", "no instrumentation", "instrumentation missing")),
    (HYPOTHESIS_DEFECT, (
        "端点幻觉", "参数缺失", "缺失参数", "受害者资源 id 缺失", "victim_resource_id 缺失",
        "族误判", "family mismatch", "路由不存在", "route not found", "endpoint hallucination",
        "参数名错误", "parameter mismatch", "方法不匹配", "method mismatch",
        "I1 链路不符", "链路不符", "确凿缺失节点", "chain mismatch", "missing chain node",
        "attacker_control_proven", "gate_bypass_or_satisfaction_proven", "payload_shape_proven",
    )),
    (JUDGE_MISCLASSIFY, ("裁决误判", "judge misclassify", "误判", "misclassified")),
    (RUNTIME_OBSERVATION, (
        "未观测到匹配 canary", "窗口内无", "no canary", "canary 未到达",
        "sink_reached=0", "DAST 未证影响", "no-iast-evidence", "no_iast_evidence", "未证影响",
    )),
)


def _structured_class(item: Dict[str, Any]) -> str:
    """结构化优先判定：显式 failure_class / residual_gaps.still_open 优先于自然语言关键词。

    历史缺陷：分类完全依赖关键词，而失败原因的措辞由 D2 裁决器生成，词表永远追不上，
    于是分类结果随措辞漂移。改为「结构字段优先、文本兜底」后，分类不再受文案影响。
    """
    explicit = str(item.get("failure_class") or "").strip()
    if explicit in (HYPOTHESIS_DEFECT, RUNTIME_OBSERVATION, PROBE_NOT_INSTRUMENTED, JUDGE_MISCLASSIFY, RUNTIME_REFUTATION, *RUNTIME_FIVE_CLASS):
        return explicit

    def _collect_gaps(obj: Any) -> List[str]:
        out: List[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("still_open", "claimed_gaps") and isinstance(v, (list, tuple)):
                    out.extend(str(x) for x in v if x)
                else:
                    out.extend(_collect_gaps(v))
        elif isinstance(obj, (list, tuple)):
            for x in obj:
                out.extend(_collect_gaps(x))
        return out

    gaps = {g.strip().lower() for g in _collect_gaps(item)}
    if gaps and any(t in gaps for t in _CHAIN_GATE_TOKENS):
        return HYPOTHESIS_DEFECT
    return ""


def _evidence_value_hit_form(item: Dict[str, Any]) -> str:
    """从反馈项抽取值级命中形态（hit_live / hit_sanitized / hit_opaque / miss）。

    反馈项可能携带三种形状：显式 ``value_hit_form`` 字段（由 _build_feedback_to_a2 透传）、
    扁平 ``value_hit`` dict（含 ``form``）、或嵌套 ``iast_evidence.value_hit`` /
    ``iast_evidence.value_hits`` 列表。统一归一为本函数返回值。无证据返回 ""。
    """
    if not isinstance(item, dict):
        return ""
    explicit = item.get("value_hit_form")
    if isinstance(explicit, str) and explicit:
        return explicit
    # 扁平 value_hit
    vh = item.get("value_hit")
    if isinstance(vh, dict) and str(vh.get("form") or ""):
        return str(vh["form"])
    # 嵌套 iast_evidence
    ie = item.get("iast_evidence")
    if isinstance(ie, dict):
        _vh = ie.get("value_hit")
        if isinstance(_vh, dict) and str(_vh.get("form") or ""):
            return str(_vh["form"])
        _vhs = ie.get("value_hits")
        if isinstance(_vhs, (list, tuple)):
            for h in _vhs:
                if isinstance(h, dict) and str(h.get("form") or ""):
                    return str(h["form"])
    return ""


def _is_runtime_refutation(item: Dict[str, Any]) -> bool:
    """E1：运行时证否黄金样本判定。

    命中条件（任一即可）：显式 failure_class=RUNTIME_REFUTATION、显式 runtime_refutation 标记、
    value_level_sanitized 为真、或值级命中形态为 hit_sanitized（数据到了 sink 但被针对本族净化）。
    这代表「静态侧声称漏洞、运行时确证无害」的 definitive 阴性，是改进静态分析器（消减
    over-claim）的最高价值样本，与「证据缺失（miss / no_evidence）」彻底区分。
    """
    if not isinstance(item, dict):
        return False
    if str(item.get("failure_class") or "") == RUNTIME_REFUTATION:
        return True
    if item.get("runtime_refutation"):
        return True
    if item.get("value_level_sanitized"):
        return True
    return _evidence_value_hit_form(item) == "hit_sanitized"


def _is_threw(item: Dict[str, Any]) -> bool:
    """E1：A2 生成/执行异常判定。

    A2 产出的 PoC/payload 在合成期或重放期抛异常（语法错误、生成失败）属**假说缺陷**——
    回灌 A2 重生成 payload，而不是当成运行时观测失败。命中条件：显式 threw/generation_error/
    syntax_error 字段、final_state 落入生成异常态、或 reason 含 SyntaxError/生成失败/抛异常关键词。
    """
    if not isinstance(item, dict):
        return False
    for key in ("threw", "generation_error", "syntax_error"):
        v = item.get(key)
        if v in (True, "true", "True", 1) or (isinstance(v, str) and v.strip()):
            return True
    fs = str(item.get("final_state") or "")
    if fs in ("threw", "generation_error", "syntax_error"):
        return True
    blob = str(item.get("reason") or item.get("message") or "").lower()
    return any(p in blob for p in ("syntaxerror", "syntax error", "生成失败", "payload 生成", "抛异常", "threw an exception", "生成异常"))


def classify_feedback(item: Dict[str, Any]) -> str:
    """给单条 I2 反馈判定 failure_class。

    0. 结构化/显式 failure_class（含 RUNTIME_REFUTATION）；
    1. E1 值级证否：hit_sanitized / value_level_sanitized → RUNTIME_REFUTATION（不进 A2）；
    2. E1 生成异常：threw / 语法错误 → HYPOTHESIS_DEFECT（回灌 A2 重生成）；
    3. residual_gaps.still_open 命中假说门禁四项 → hypothesis_defect；
    4. 关键词表（含 canary/观测语义 → runtime_observation）；
    5. 兜底：含 canary/iast 字样 → runtime_observation，否则 hypothesis_defect。
    """
    sc = _structured_class(item)
    if sc:
        return sc

    # E1 层：值级证否黄金样本优先于一切关键词，确保「到且已净化」不被误吞成 no_evidence。
    if _is_runtime_refutation(item):
        return RUNTIME_REFUTATION
    # E1 层：A2 payload 生成/执行异常 → 假说缺陷（回灌 A2），与「运行时观测失败」严格区分。
    if _is_threw(item):
        return HYPOTHESIS_DEFECT

    reason = str(item.get("reason") or item.get("message") or "")
    iast_state = str(item.get("iast_state") or "").lower()
    blob = (reason + " " + iast_state).lower()

    for cls, needles in _CLS_RULES:
        for n in needles:
            if n.lower() in blob:
                return cls

    # 兜底：明确无 canary 证据 → 运行时观测失败
    if "canary" in blob or "iast" in blob:
        return RUNTIME_OBSERVATION
    return HYPOTHESIS_DEFECT


def dedup_feedbacks(feedbacks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按 hypothesis_id 去重合并（保留首次出现顺序，合并 reason 与计数）。"""
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for fb in feedbacks or []:
        if not isinstance(fb, dict):
            continue
        key = str(fb.get("hypothesis_id") or fb.get("vulnerability_hash_v2") or "")
        if not key:
            # 无身份的反馈按内容去重，避免完全相同的句子反复进 prompt
            key = "raw:" + str(fb.get("reason") or "")[:120]
        if key not in merged:
            merged[key] = dict(fb)
            merged[key]["_dup_count"] = 1
            order.append(key)
        else:
            merged[key]["_dup_count"] = int(merged[key].get("_dup_count") or 1) + 1
    out = [merged[k] for k in order]
    if feedbacks and len(feedbacks) != len(out):
        logger.info("[i2_feedback] 反馈去重：%d 条 → %d 条唯一假设", len(feedbacks), len(out))
    return out


def route_feedbacks(feedbacks: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """分流：打 failure_class 并按类别分组。返回按类别分组的有序字典。"""
    routed: Dict[str, List[Dict[str, Any]]] = {
        HYPOTHESIS_DEFECT: [],
        RUNTIME_OBSERVATION: [],
        PROBE_NOT_INSTRUMENTED: [],
        JUDGE_MISCLASSIFY: [],
        # 由 a2_actionable 显式排除（A2_ACTIONABLE 仅含 hypothesis_defect），供静态侧消费。
        RUNTIME_REFUTATION: [],
    }
    for fb in dedup_feedbacks(feedbacks):
        cls = classify_feedback(fb)
        fb = dict(fb)
        if cls in RUNTIME_FIVE_CLASS:
            # 五类运行时细分：保留具体 failure_class（如 arrived_unconfirmed）作为决策子类，
            # 同时归入 RUNTIME_OBSERVATION 桶，供 plan_replay_adjustments 走五类决策表；
            # 不进入 a2_actionable（仅含 hypothesis_defect），故不触发 A2 重写。
            if not fb.get("failure_class"):
                fb["failure_class"] = cls
            routed.setdefault(RUNTIME_OBSERVATION, []).append(fb)
        else:
            fb["failure_class"] = cls
            routed.setdefault(cls, []).append(fb)
    logger.info(
        "[i2_feedback] 分流结果：%s",
        {k: len(v) for k, v in routed.items() if v},
    )
    return routed


def _feedback_hid(fb: Dict[str, Any]) -> str:
    """反馈项的唯一定位键：hypothesis_id 优先，回落 vulnerability_hash_v2。

    收口：此前 plan_replay_adjustments 用「hypothesis_id or vulnerability_hash_v2」，
    而 attach_directives 只认 hypothesis_id，两处口径不同 ⇒ 只带 hash 的反馈项
    （迟到证据补捞、无 spec 回灌等路径）必然匹配不上指令，静默丢弃。统一到本函数。
    """
    if not isinstance(fb, dict):
        return ""
    return str(fb.get("hypothesis_id") or fb.get("vulnerability_hash_v2") or "")


def attach_directives(routed: Dict[str, List[Dict[str, Any]]],
                      adjustments: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """把具体改进指令并入送 A2 的反馈项。

    此前指令只挂在 plan_replay_adjustments 产出的 adjustments 上，而 A2 消费的是
    feedback_to_a2（经 route_feedbacks → a2_actionable 透传），两条路不相通 ——
    于是"根据失败原因给 A2 改进思路"实际没送到 A2（实读：directive 仅存在于本模块）。

    这里按 hypothesis_id 把指令并回反馈项，并把 instruction 追加进 reason：
    即便下游只透传 reason 文本进 prompt，指令也一定带得过去。

    1) **埋点**：此前按 hid 精确匹配，匹配不上就静默跳过，无任何计数可查——指令到底
       有没有并进去、丢了多少，外部无从判断（真值只能靠读本模块源码确认）。
       现返回统计写入 ``routed["_directive_stats"]``，由调用方落进 stage_results.i2。
    2) **五类也拿指令**：arrived_unconfirmed（探针确证到达但结果点未确证有害）是
       最需要"怎么改弹"指导的一类，但它归 RUNTIME_OBSERVATION 桶、不进 a2_actionable，
       于是 directive 永远送不出去。现额外挂 ``replay_directive``，由重放侧
       （apply_replay_adjustments / 下一轮合成）消费，不依赖 A2 静态重写。
    """
    by_hid: Dict[str, Dict[str, Any]] = {}
    for a in (adjustments or []):
        if isinstance(a, dict) and a.get("directive") and a.get("hypothesis_id"):
            by_hid[str(a.get("hypothesis_id"))] = a["directive"]
    stats = {"adjustments": len(adjustments or []), "with_directive": len(by_hid),
             "matched": 0, "unmatched": 0, "matched_ids": [], "unmatched_ids": [],
             "replay_directive_attached": 0}
    if not isinstance(routed, dict):
        return routed
    if not by_hid:
        # 无指令可并：也要落统计，否则调用方无法区分「没生成指令」与「生成了但全丢」。
        if isinstance(routed, dict):
            routed["_directive_stats"] = stats
        return routed
    for _cls, items in routed.items():
        if _cls == "_directive_stats":
            continue
        for fb in (items or []):
            if not isinstance(fb, dict):
                continue
            # 残留 2 收口：hid 统一按「hypothesis_id 优先、回落 vulnerability_hash_v2」取，
            # 与 plan_replay_adjustments:919 的口径完全一致。此前本函数只认 hypothesis_id，
            # 而反馈项常只带 vulnerability_hash_v2（如迟到证据补捞、无 spec 回灌路径），
            # 于是指令全部静默失配——这正是「指令根本没进去」的第二重成因。
            _hid = _feedback_hid(fb)
            d = by_hid.get(_hid)
            if not d:
                # 统计失配：hypothesis_id 为空或与 adjustments 不同源。
                stats["unmatched"] += 1
                if len(stats["unmatched_ids"]) < 20:
                    stats["unmatched_ids"].append(_hid or "<empty>")
                continue
            stats["matched"] += 1
            if len(stats["matched_ids"]) < 20:
                stats["matched_ids"].append(_hid)
            fb["directive"] = d
            instr = str(d.get("instruction") or "").strip()
            if instr and instr not in str(fb.get("reason") or ""):
                fb["reason"] = (str(fb.get("reason") or "").strip() + " | 改进指令：" + instr).strip(" |")
            # 残留 1：五类不进 a2_actionable，但重放侧同样需要具体改弹要求。
            # 挂 replay_directive 供重放侧消费（不进 A2 prompt，避免诱导静态重写）。
            fb["replay_directive"] = d
            stats["replay_directive_attached"] += 1
    if stats["matched"]:
        logger.info("[i2_feedback] 已把 %d 条改进指令并入送 A2 的反馈（失配 %d 条）",
                    stats["matched"], stats["unmatched"])
    if stats["unmatched"]:
        logger.warning("[i2_feedback] 指令并入失配 %d 条（hypothesis_id 不同源或为空）：%s",
                       stats["unmatched"], stats["unmatched_ids"][:5])
    routed["_directive_stats"] = stats
    return routed


def a2_actionable(routed: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """取「值得回灌 A2」的反馈：只有假说缺陷。

    跳过 ``_directive_stats``（attach_directives 写入的统计 dict，非反馈项）。
    """
    out: List[Dict[str, Any]] = []
    for cls in A2_ACTIONABLE:
        out.extend(routed.get(cls) or [])
    return [x for x in out if isinstance(x, dict)]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
#   而 gain = 0（iterations=1、228 条 feedback、LLM 判因仅 4 次调用/1 次重分类）。
#   同一轮里**确定性重试**只用 192.4s 就拿到 +9 确认 —— 效率差 23 倍。
#   根因：反馈里 95%+ 是 runtime_observation（"canary 未观测到"），而其中绝大多数
#   属**结构性/环境性**（WAF 拦截、路由不可达、参数没到 sink、探针未插桩、鉴权墙），
#   静态侧重跑 A2 改不动它们 —— 属于「拿 A2 去修重放侧/环境侧的问题」。
#
# 定向口径（可救 = A2 重跑真能改善）：
#   - hypothesis_defect：假说本身错了（端点幻觉/参数缺失/族误判）⇒ A2 重跑有意义
#   - runtime_observation 且 failure_class == arrived_unconfirmed
#     （探针确证到达 sink，但 D2 未确认有害）⇒ 弹不够强/判定不足，A2 重跑可换弹
# 不可救（本轮白花 LLM 调用）：
#   - probe_not_instrumented（探针侧）、runtime_refutation（运行时已证否）、
#     judge_misclassify（裁决侧）
#   - runtime_observation 的其余子类：blocked / route_unreachable / param_not_arrived /
#     window_missed / auth_missing
RECOVERABLE_RUNTIME_CLASSES = ("arrived_unconfirmed",)


def filter_recoverable(feedbacks: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """按「A2 重跑真能改善」筛出可救反馈。返回 (可救列表, 统计)。

    统计里给出各桶的保留/丢弃条数 —— 闭环收益判定的依据（可救子集为空 ⇒ 直接 no_action）。
    """
    routed = route_feedbacks(feedbacks or [])
    keep: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {"kept": 0, "dropped": 0, "by_bucket": {}}
    for cls, items in (routed or {}).items():
        if not items:
            continue
        kept_here = 0
        for fb in items:
            if not isinstance(fb, dict):
                continue
            sub = str(fb.get("failure_class") or "")
            if cls == HYPOTHESIS_DEFECT:
                keep.append(fb)
                kept_here += 1
            elif cls == RUNTIME_OBSERVATION and sub in RECOVERABLE_RUNTIME_CLASSES:
                keep.append(fb)
                kept_here += 1
        stats["by_bucket"][cls] = {"total": len(items), "kept": kept_here}
    stats["kept"] = len(keep)
    stats["dropped"] = max(0, len([f for f in (feedbacks or []) if isinstance(f, dict)]) - len(keep))
    return keep, stats


def a2_rerun_budget_ok(n_files: int, remaining_s: float,
                       per_file_s: float = 25.0) -> Tuple[bool, str]:
    """D10 预算预检：文件级 a2_rerun 能否在剩余预算内完成。

    背景：预算闸只在闭环轮次间生效，拦不住单轮内的 A2 重跑——473 实测 51 条
    hypothesis_defect 触发数十文件重跑，单轮 2237.8s / gain=0；471 全量 4528.9s /
    超出剩余预算即建议跳过（只做重放侧调整，秒级）。

    返回 (是否放行, 说明)。remaining_s<=0 直接不放行。
    """
    try:
        n = max(0, int(n_files))
    except (TypeError, ValueError):
        n = 0
    try:
        remain = float(remaining_s)
        per = float(per_file_s)
    except (TypeError, ValueError):
        return False, "预算参数非法"
    if remain <= 0:
        return False, "预算已用尽（remaining<=0）"
    est = n * per
    if est > remain:
        return False, ("估计 a2_rerun %.0fs（%d 文件×%.0fs）> 剩余 %.0fs"
                       % (est, n, per, remain))
    return True, "估计 %.0fs ≤ 剩余 %.0fs" % (est, remain)


# ---------------------------------------------------------------------------
# 各类绑定定向动作或仅记录——不再全挤一类、也不再有「151 条同类触发全量 rerun」的盲动。
# ---------------------------------------------------------------------------
DEFECT_SUBCLASSES = (
    "endpoint_hallucination",
    "missing_parameter",        # 参数缺失 → a2_rerun（白名单内）
    "family_mislabel",          # 族误判 → a2_rerun（白名单内）
    "chain_mismatch",           # 链路不符 → replay_adjust + 记录（重放侧调整优先）
    "insufficient_evidence",    # 证据不足 → 仅记录（静态重跑产不出运行时证明）
)

DEFECT_ACTIONS = {
    "endpoint_hallucination": "a2_rerun",
    "missing_parameter": "a2_rerun",
    "family_mislabel": "a2_rerun",
    "chain_mismatch": "replay_adjust",
    "insufficient_evidence": "record_only",
}

_DEFECT_SUBCLASS_RULES = [
    ("endpoint_hallucination", ("端点幻觉", "路由不存在", "endpoint hallucination", "路由不存在或不可达")),
    ("missing_parameter", ("参数缺失", "缺失参数", "参数名错误", "parameter mismatch", "missing parameter")),
    ("family_mislabel", ("族误判", "family mismatch", "误归因", "wrong family")),
    ("chain_mismatch", ("链路不符", "确凿缺失节点", "missing chain node", "chain mismatch")),
]


def classify_defect(fb: Dict[str, Any]) -> str:
    """单条 hypothesis_defect 反馈的子类判定（关键词保守匹配，兜底=证据不足）。"""
    blob = " ".join(
        str(fb.get(k) or "") for k in ("reason", "message", "correction_hint", "failure_class")
    ).lower()
    for subclass, tokens in _DEFECT_SUBCLASS_RULES:
        if any(t.lower() in blob for t in tokens):
            return subclass
    return "insufficient_evidence"


def defect_subclass_counts(feedbacks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """五类计数 + 各类绑定动作。空输入返回空 dict。"""
    counts: Dict[str, int] = {}
    actions: Dict[str, str] = {}
    for fb in (feedbacks or []):
        if not isinstance(fb, dict):
            continue
        sc = classify_defect(fb)
        counts[sc] = counts.get(sc, 0) + 1
        actions[sc] = DEFECT_ACTIONS.get(sc, "record_only")
    if not counts:
        return {}
    return {"counts": counts, "bound_actions": actions}


# 「静态可修」信号：A2 重跑能真正改善的缺陷——端点/参数/族猜错了，重看源码能改对。
_STATIC_FIXABLE_TOKENS = (
    "端点幻觉", "参数缺失", "缺失参数", "族误判", "路由不存在", "参数名错误",
    "方法不匹配", "victim_resource_id 缺失", "endpoint hallucination",
    "parameter mismatch", "method mismatch", "链路不符", "确凿缺失节点",
    "missing chain node",
)


def a2_rerun_actionable(feedbacks: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """止损预检：这批 hypothesis_defect 反馈，A2 重跑真的修得好吗？

    烧掉 47 分钟，gain = **-7**（可利用数反而少了 7 条）。根因是这些反馈的语义并非
    「假说猜错了」，而是 residual_gaps.still_open = [reachable, attacker_control_proven,
    gate_bypass_or_satisfaction_proven, payload_shape_proven] —— 即假说声称可达/可控/
    可绕门禁/载荷成立，但运行时四项一个都没闭合。**A2 是静态分析器，无法产出运行时证明**，
    重跑只会得到同一条假说，必然空转且因抖动丢分。

    判据（保守，宁可多跑一次也不误砍）：
    1. 任一反馈含「静态可修」信号（端点/参数/族/链路猜错）→ 可修，照跑；
    2. 否则若反馈普遍带门禁悬置四项 → 判定不可修，跳过 a2_rerun；
    3. 无任何明确信号 → 保守判可修，维持旧行为。
    """
    items = [f for f in (feedbacks or []) if isinstance(f, dict)]
    if not items:
        return False, "无反馈"

    # 仅当「值级命中为 hit_live（数据确证到达 sink 且未净化，路径真实）+ threw（A2 生成的
    # payload 抛异常/语法错误）」才放行 A2 重生成 payload——这是唯一 A2 重跑能修好的情况：
    # 路径已证真实，只差 payload 质量（语法/执行）。其余情况（miss / hit_sanitized /
    # hit_opaque 或无 threw）A2 静态重跑产不出运行时证明，保持既有止损闸门不动。
    _regen = 0
    for fb in items:
        if _is_threw(fb) and _evidence_value_hit_form(fb) == "hit_live":
            _regen += 1
    if _regen:
        return True, (
            f"{_regen}/{len(items)} 条命中 A2 payload 重生成条件（value_hit=hit_live 且 threw），"
            f"放行定向重生成（路径真实、仅 payload 质量缺陷）"
        )

    # 旧实现把所有运行时失败一律挡在 A2 之外（省钱但学习信号也断了），
    # 现在只要能给出可执行指令（净化器约束 / 必须避开什么 / 已试过什么），就放行——
    # A2 不再是"被同一句话重复提示"，而是拿到明确的改写要求。
    _directed = 0
    for fb in items:
        d = fb.get("directive") if isinstance(fb, dict) else None
        if isinstance(d, dict) and d.get("target") in ("payload_synthesis", "a2_rerun") and d.get("instruction"):
            _directed += 1
    if _directed and _directed == len(items):
        return True, f"全部 {_directed} 条均带具体改进指令，放行定向 A2 重跑"

    static_hits = 0
    gate_hits = 0
    for fb in items:
        blob = " ".join(
            str(fb.get(k) or "")
            for k in ("reason", "message", "failure_class", "final_state", "correction_hint")
        )
        gaps = fb.get("residual_gaps") if isinstance(fb.get("residual_gaps"), dict) else {}
        still = [str(x) for x in (gaps.get("still_open") or [])]
        blob = (blob + " " + " ".join(still)).lower()

        if any(t.lower() in blob for t in _STATIC_FIXABLE_TOKENS):
            static_hits += 1
        # 门禁悬置四项：只在 still_open 里出现才算数（reason 里的措辞不可靠）。
        if any(g in ("reachable", "attacker_control_proven",
                     "gate_bypass_or_satisfaction_proven", "payload_shape_proven") for g in still):
            gate_hits += 1

    if static_hits:
        return True, f"含静态可修缺陷 {static_hits}/{len(items)} 条，重跑 A2"
    if gate_hits == len(items):
        return False, (
            f"全部 {len(items)} 条均为假说门禁悬置（reachable/attacker_control/gate_bypass/payload_shape "
            f"未闭合）——属运行时证明缺失，A2 静态重跑无法产出，跳过以避免空转与负增益"
        )
    if gate_hits:
        return False, (
            f"{gate_hits}/{len(items)} 条为门禁悬置且无静态可修信号，跳过 a2_rerun"
        )
    return False, "无静态可修信号（触发白名单外），跳过 a2_rerun"


# ---------------------------------------------------------------------------
# 阈值可经环境变量覆盖：SAST_AI_A2_RERUN_GATE_TOTAL（默认 0.10）、
# SAST_AI_A2_RERUN_GATE_ENDPOINT（默认 0.10，相对）、SAST_AI_A2_RERUN_GATE_INJECTION（默认 0.20）。
# ---------------------------------------------------------------------------
INJECTION_FAMILY_TOKENS = ("sql", "cmd", "command", "xss", "path_traversal", "path-traversal",
                           "xxe", "ldap", "xpath", "ssti", "template", "deserialization")

_GATE_ENV = {
    "total": float(os.environ.get("SAST_AI_A2_RERUN_GATE_TOTAL", "0.10") or 0.10),
    "endpoint": float(os.environ.get("SAST_AI_A2_RERUN_GATE_ENDPOINT", "0.10") or 0.10),
    "injection": float(os.environ.get("SAST_AI_A2_RERUN_GATE_INJECTION", "0.20") or 0.20),
}


def _q(db, sql: str, params: tuple, one: bool = True):
    """兼容两种执行器：平台 Database.execute（fetchone/fetchall 关键字）与裸 sqlite3（返回 cursor）。
    统一转 dict（sqlite3.Row 无 .get）。"""
    try:
        res = db.execute(sql, params, fetchone=True) if one else db.execute(sql, params, fetchall=True)
    except TypeError:
        cur = db.execute(sql, params)
        res = cur.fetchone() if one else cur.fetchall()
    if res is None:
        return None
    if one:
        return dict(res) if not isinstance(res, dict) else res
    return [dict(r) if not isinstance(r, dict) else r for r in res]


def spec_health_snapshot(db, task_id: int) -> Dict[str, Any]:
    """rerun 产物健康度快照：spec 总数 / 端点解析率 / 注入类 spec 数。任何异常返回 None（闸门 fail-open）。"""
    try:
        rows = _q(db, "SELECT family, target_endpoint FROM trigger_specs WHERE task_id=?",
                  (task_id,), one=False) or []
        total = len(rows)
        with_endpoint = sum(1 for r in rows if str(r.get("target_endpoint") or "").strip())
        injection = sum(
            1 for r in rows
            if any(t in str(r.get("family") or "").lower() for t in INJECTION_FAMILY_TOKENS)
        )
        return {
            "total": total,
            "endpoint_resolved": with_endpoint,
            "endpoint_rate": (with_endpoint / total) if total else 0.0,
            "injection": injection,
        }
    except Exception as _e:
        logger.warning("[i2_feedback] spec 健康度快照失败（闸门 fail-open）：%s", _e)
        return None


def spec_health_gate(before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """对比 rerun 前后健康度。返回 (ok, reason)。ok=False 表示产物退化须回滚。快照缺失 fail-open。"""
    if not before or not after:
        return True, "健康度快照缺失，闸门放行（fail-open）"
    reasons = []
    tb, ta = before.get("total") or 0, after.get("total") or 0
    if tb and ta < tb * (1 - _GATE_ENV["total"]):
        reasons.append(f"spec 总数 {tb}->{ta}（退化 {1 - ta / tb:.0%} > {_GATE_ENV['total']:.0%}）")
    rb, ra = before.get("endpoint_rate") or 0.0, after.get("endpoint_rate") or 0.0
    if rb and ra < rb * (1 - _GATE_ENV["endpoint"]):
        reasons.append(f"端点解析率 {rb:.1%}->{ra:.1%}（超阈值 {_GATE_ENV['endpoint']:.0%}）")
    ib, ia = before.get("injection") or 0, after.get("injection") or 0
    if ib and ia < ib * (1 - _GATE_ENV["injection"]):
        reasons.append(f"注入类 spec {ib}->{ia}（退化超 {_GATE_ENV['injection']:.0%}）")
    if reasons:
        return False, "；".join(reasons)
    return True, "rerun 产物健康度达标"


# 此前这类只能落 unconfirmed / no_evidence，把"过滤器有效、不可利用"这个**真阴性**
# 混进"没打到"里 —— 既丢结论又污染对账（精确率是本项目瓶颈）。
FILTERED_NOT_EXPLOITABLE = "filtered_not_exploitable"

# M5：结果点三态里「确实到了结果点、但被过滤掉」的那几态。
# 与 src/core/result_point.py 的常量同源，不在此另立一套。
_RESULT_POINT_FILTERED_STATES = (
    "reflected_escaped",   # XSS：回显被 HTML 转义
    "reflected_encoded",   # XSS：回显被 URL/实体编码
    "echo_only",           # SSTI：表达式原样回显、模板未求值
)


def mark_filtered_not_exploitable(db, task_id: int) -> int:
    """把判定为不可绕过的 spec 标成显式状态（可审计、可回溯，不删发现）。

    两条独立证据都可落 filtered_not_exploitable（真阴性，进对账，不污染精确率）：
    1) 静态终态（confidence=high 的 non_bypassable）—— 一等公民口径；
    2) 运行时观测到 arrival-sanitized（探针证明污点抵达 sink 但被净化）
       —— 这是「过滤器有效」的**正向**证据，与静态 non_bypassable 等价，直接落 filtered_not_exploitable，
       解耦「破坏性闸门降级（不 fire 破坏性弹，安全）」与「无害探针发送（仍发、仍收证据，智能）」。
       否则 arrival-sanitized 会被当 unconfirmed 空转成死局（既不能真打、净化器又拦了，闭环无结论）。

    已是 confirmed_exploitable 的不动（真确认优先于过滤器判定）。返回更新条数。fail-open：异常返回 0。
    """
    try:
        from src.core.filter_verdict import is_terminal as _is_terminal
        rows = db.execute(
            "SELECT id, verification_status, raw_json, iast_state FROM trigger_specs WHERE task_id=?",
            (int(task_id),), fetchall=True,
        ) or []
    except Exception as _e:
        logger.warning("[i2_feedback] 读取 spec 失败（跳过过滤器口径标记）：%s", _e)
        return 0
    n = 0
    for r in rows:
        if not isinstance(r, dict):
            continue
        _cur_status = str(r.get("verification_status") or "")
        if _cur_status == "confirmed_exploitable":
            continue
        meta = {}
        try:
            import json as _json
            meta = _json.loads(r.get("raw_json") or "{}") or {}
        except Exception:
            meta = {}
        if not isinstance(meta, dict):
            meta = {}

        _terminal = _is_terminal(meta.get("filter_verdict"))
        _runtime_sanitized = str(r.get("iast_state") or "") == "arrival-sanitized"
        # M5 结果点三态：投放值到了结果点但被转义/编码，或模板表达式没被求值
        # —— 这是「输出侧过滤器有效」的**正向**证据，与静态 non_bypassable 等价。
        # 漏掉它，XSS/SSTI 的安全用例就只能落 unconfirmed，既丢结论又污染精确率。
        _rp_state = str((meta.get("d2_evidence") or {}).get("result_point_state") or "")
        _runtime_filtered = _rp_state in _RESULT_POINT_FILTERED_STATES
        if not _terminal and not _runtime_sanitized and not _runtime_filtered:
            continue

        # 静态终态 → 用静态 filter_verdict 文本作证据。
        # 运行时 arrival-sanitized → 用探针的净化观测作证据（即便静态 verdict 未判终态也成立）。
        # M5：结果点转义/未求值 → 用结果点比对观测作证据。
        if _terminal:
            _fv = meta.get("filter_verdict") or {}
            _fs = meta.get("filter_spec") or {}
            _bypass_state = _fv.get("verdict") or "non_bypassable"
            _bypass_reason = _fv.get("reason") or "净化器不可绕过（真净化器）"
        elif _runtime_filtered:
            _fv = meta.get("filter_verdict") or {}
            _fs = meta.get("filter_spec") or {}
            _bypass_state = _fv.get("verdict") or "non_bypassable"
            _bypass_reason = (
                "结果点比对：投放值到达结果点但被%s，输出侧过滤器有效，不可利用（真阴性）"
                % ("HTML 转义/URL 编码" if _rp_state.startswith("reflected") else "模板引擎原样回显未求值")
            )
        else:
            _fv = meta.get("filter_verdict") or {}
            _fs = meta.get("filter_spec") or {}
            _bypass_state = _fv.get("verdict") or "non_bypassable"
            _bypass_reason = ("运行时观测到污点抵达 sink 但被净化（arrival-sanitized），"
                              "过滤器有效，不可利用（真阴性）")
        try:
            import json as _json
            _filter_spec_json = _json.dumps(_fs, ensure_ascii=False)
        except Exception:
            _filter_spec_json = "{}"
        try:
            db.execute(
                "UPDATE trigger_specs SET verification_status=?, bypass_state=?, "
                "bypass_reason=?, filter_spec_json=? WHERE id=?",
                (FILTERED_NOT_EXPLOITABLE, _bypass_state, _bypass_reason, _filter_spec_json,
                 int(r.get("id"))),
            )
            n += 1
        except Exception as _e:
            logger.warning("[i2_feedback] 标记过滤器口径失败 spec=%s：%s", r.get("id"), _e)
    if n:
        logger.info("[i2_feedback] 过滤器有效（不可绕过/运行时净化）标记 %d 条 → %s", n, FILTERED_NOT_EXPLOITABLE)
    return n


def reopen_terminal_on_runtime_evidence(db, task_id: int) -> int:
    """终态可重开（单调只升不降，但允许「新证据推翻静态结论」这一例外）。

    non_bypassable 的 spec 若已有运行时**到达并利用**信号（sink-reached / sink-reached-probe），
    说明静态字符集推理被运行时推翻（例如归一化/编码让危险字符在匹配前变形，或白名单过宽未覆盖），
    单调重开为待复核，而非静默丢弃真漏洞。

    注意：arrival-sanitized（到但被净化）是「过滤器有效」的正向证据，与 non_bypassable 一致，
    **不**重开；只有「污点真正抵达 sink 利用成功」才推翻静态结论。
    """
    try:
        rows = db.execute(
            "SELECT id, iast_state FROM trigger_specs WHERE task_id=? AND bypass_state='non_bypassable'",
            (int(task_id),), fetchall=True,
        ) or []
    except Exception as _e:
        logger.warning("[i2_feedback] 读取终态 spec 失败（跳过重开）：%s", _e)
        return 0
    _REACHED = ("sink-reached", "sink-reached-probe")
    n = 0
    for r in rows:
        st = str(r.get("iast_state") or "")
        if st not in _REACHED:
            continue
        try:
            db.execute(
                "UPDATE trigger_specs SET bypass_state='undetermined', "
                "bypass_reason=?, verification_status='' WHERE id=?",
                ("运行时观测到 %s，静态 non_bypassable 被推翻，重开待复核" % st, int(r.get("id"))),
            )
            n += 1
        except Exception as _e:
            logger.warning("[i2_feedback] 重开终态 spec=%s 失败：%s", r.get("id"), _e)
    if n:
        logger.info("[i2_feedback] 运行时证据推翻静态 non_bypassable，重开 %d 条 → undetermined", n)
    return n


def confirmed_case_count(db, task_id: int) -> int:
    """B-3 gain 对账口径：确认层（confirmed_exploitable）去重 endpoint 用例数。

    与对账脚本 L2 同源（spec 级、按 endpoint 去重），替代原「D2 内部 exploitable_count」口径
    ——后者会把 rerun 产物收缩误读成正增益（产物少了，分母也小了）。
    """
    try:
        row = _q(db,
                 "SELECT COUNT(DISTINCT target_endpoint) AS n FROM trigger_specs"
                 " WHERE task_id=? AND verification_status='confirmed_exploitable'"
                 " AND target_endpoint IS NOT NULL AND target_endpoint != ''",
                 (task_id,), one=True)
        return int((row or {}).get("n") or 0)
    except Exception as _e:
        logger.warning("[i2_feedback] 确认层用例计数失败（返回 0）：%s", _e)
        return 0


# 单条 spec 的定向重放封顶轮次（超过即判「真不可达」，不再重试）
_RETRY_MAX_ROUNDS = int(os.environ.get("SAST_AI_RETRY_MAX_ROUNDS", "2") or 2)


def plan_retryable_replay(db, task_id: int, max_rounds: int = 0) -> Dict[str, Any]:
    """可重试 no_evidence 的定向重放清单。

    背景：纪律规定 verdict=clean 且靶场停机窗口为空 ⇒ 属**可重试** no_evidence，
    原地重放同一发请求，永远捞不回来。

    这里只做「该不该再放一次」的判定，**不替代**重放执行：
      - 窗口错过：本 task 事件流里有 invalidated/downtime 类事件（靶场重启或不健康窗口），
        证据缺失是时序问题 → 可重试；
      - 真不可达：无停机记录且已重试 ≥max_rounds 轮仍 0 事件 → 封顶，保持终态 no_evidence，
        绝不无限重试（无限重试会把「打不通」伪装成「还没打到」）。
    """
    import json as _json
    _max = int(max_rounds or _RETRY_MAX_ROUNDS)
    # 第 2 轮原样重放对这些 spec 是纯窗口开销）。零到达 spec 重试封顶
    # SAST_AI_RETRY_ZERO_ARRIVAL_ROUNDS（默认 1 轮）；有到达迹象（sink-reached-*）或任务发生过
    # 靶场停机（downtime，证据缺失可能是时序问题）不受此限。设为 2 恢复旧行为。
    # 同样只给 1 轮机会。
    try:
        _zero_cap = int(os.environ.get("SAST_AI_RETRY_ZERO_ARRIVAL_ROUNDS", "1") or 1)
    except Exception:
        _zero_cap = 1
    out: Dict[str, Any] = {"retryable": [], "exhausted": [], "downtime_affected": False, "max_rounds": _max}
    try:
        rows = db.execute(
            "SELECT id, vulnerability_hash_v2, family, target_endpoint, verification_status, iast_state, raw_json"
            " FROM trigger_specs WHERE task_id=? AND verification_status IN ('no_evidence','unconfirmed')",
            (task_id,), fetchall=True,
        ) or []
    except Exception as _e:
        logger.warning("[i2_feedback] 可重试清单查询失败：%s", _e)
        return out
    try:
        ev = db.execute(
            "SELECT id FROM scan_task_events WHERE task_id=?"
            " AND event_type IN ('task_invalidated','downtime','epoch_invalidated') LIMIT 1",
            (task_id,), fetchall=True,
        ) or []
        out["downtime_affected"] = bool(ev)
    except Exception:
        pass
    for r in rows:
        if not isinstance(r, dict):
            continue
        _round = 0
        try:
            _meta = _json.loads(r.get("raw_json") or "{}") or {}
            _round = int(((_meta.get("replay_adjust") or {}).get("round") or 0))
        except Exception:
            _round = 0
        item = {
            "spec_id": r.get("id"),
            "vhash": r.get("vulnerability_hash_v2"),
            "family": r.get("family"),
            "endpoint": r.get("target_endpoint"),
            "round": _round,
        }
        # 真净化器前死磕只会烧轮次与 LLM，且会把"不可利用"的真阴性结论搅浑。
        try:
            from src.core.filter_verdict import is_terminal as _is_terminal
            if _is_terminal(_meta.get("filter_verdict")):
                item["terminal_reason"] = (_meta.get("filter_verdict") or {}).get("reason", "")
                out["exhausted"].append(item)
                continue
        except Exception:
            pass
        # 零到达封顶：IAST 从未观测到 canary（no-arrival / no-iast-evidence / 无状态）的 spec，
        # 只给 _zero_cap 轮机会；有过到达（sink-reached-*）或靶场停机过的不受限。
        # safe-pattern-veto 同样封顶：静态安全裁决不是重放能翻案的。
        _cap = _max
        _zero_arrival = str(r.get("iast_state") or "") in (
            "", "no-arrival", "no-iast-evidence", "safe-pattern-veto")
        if _zero_arrival and not out["downtime_affected"]:
            _cap = min(_cap, _zero_cap)
        if out["downtime_affected"] or _round < _cap:
            out["retryable"].append(item)
        else:
            if _zero_arrival:
                item["exhaust_reason"] = "zero_arrival_rounds"
            out["exhausted"].append(item)
    if out["retryable"]:
        logger.info(
            "[i2_feedback] 可重试 no_evidence %d 条（另有 %d 条已达封顶，判真不可达）",
            len(out["retryable"]), len(out["exhausted"]),
        )
    return out


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 基线 → URL 编码 → 双重编码 → 大小写/空白混淆 → 替代语法。
#
# ① 默认宿主原为 ``127.0.0.1:8088``，而真实回执端点是后端 ``/api/oob/{token}``
#    （端口 8000）—— 端口对不上，靶场就算出网了请求也打到没人监听的端口，
#    回执恒为零且**看不出错**（payload 生成了、投出去了、就是没人接）。
#    现在宿主与路径统一由 oob_monitor 给出（单一真相源），此处只保留兼容读取。
# ② 带外**不再是梯子的末阶**。原来是「前面全失败才爬到 OOB」，但 OOB 证明的是
#    「服务端真的发起了出网请求」，与「响应里有没有回显」是**正交**的两件事 ——
#    等回显判据全输光才投它，等于白扔最强的证据通道。现改为伴随通道：
#    对「服务端会主动出网」的族，在基线投放时**同时**投一枚带外弹
#    （见 oob_companion_payload），主判据仍按响应侧走，带外只是多一路证据。
_OOB_HOST = os.environ.get("SAST_AI_OOB_HTTP_HOST", "127.0.0.1:8000")

# 每族变体梯子：有序「变换名」列表（baseline 为原始 payload，不变换）。仅覆盖 OWASP 主族；
# 未知族返回空梯子（只基线），绝不瞎投。
_VARIANT_LADDER: Dict[str, List[str]] = {
    "sqli": ["baseline", "url_encode", "double_encode", "case_obfuscation", "alt_syntax", "oob"],
    "xss": ["baseline", "url_encode", "case_obfuscation", "alt_syntax"],
    "ssti": ["baseline", "alt_syntax", "url_encode"],
    "command_execution": ["baseline", "url_encode", "alt_syntax", "oob"],
    "path_traversal": ["baseline", "url_encode", "double_encode", "alt_syntax"],
    "ldap_injection": ["baseline", "url_encode", "alt_syntax"],
    "xpathi": ["baseline", "url_encode", "alt_syntax"],
    "trust_boundary_violation": ["baseline", "url_encode"],
    "crypto": ["baseline", "url_encode"],
}

# 替代语法映射（族 → (原片段, 替代片段)），只替换首个命中，避免瞎改导致 payload 失效。
_ALT_SYNTAX: Dict[str, List[tuple]] = {
    "sqli": [("' OR '1'='1", "'||'1'='1"), (" OR ", "|| "), ("1=1", "1=1)-- ")],
    "xss": [("<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"),
            ("<script", "<ScRiPt"), ("alert(1)", "prompt(1)")],
    "ssti": [("${7*7}", "#{7*7}"), ("${", "<!--${"), ("7*7}", "7*7}-->")],
    "command_execution": [(";", "|"), ("&&", "||"), ("cat ", "more ")],
    "path_traversal": [("../", "..%2f"), ("..\\", "..%5c"), ("/etc/passwd", "\\windows\\win.ini")],
    "ldap_injection": [("*)(uid=*", "*)(|(uid=*"), ("*", "*)(uid=*")],
    "xpathi": [("' or '1'='1", "' or '1'='1' or '"), ("1=1", "1=1]*)")],
}


def _family_of(fam: str) -> str:
    return str(fam or "").lower().replace("-", "_")


def variant_ladder_for(family: str) -> List[str]:
    """返回某族的变体梯子（含 baseline）。未知族返回空梯子。"""
    return list(_VARIANT_LADDER.get(_family_of(family), []))


def apply_variant_transform(transform: str, base: str, family: str) -> str:
    """对基线 payload 施加一种变体变换，返回新 payload。未知变换 / 异常 fail-open 返回原串。"""
    try:
        import urllib.parse as _up
        if transform == "url_encode":
            return _up.quote(base, safe="")
        if transform == "double_encode":
            return _up.quote(_up.quote(base, safe=""), safe="")
        if transform == "case_obfuscation":
            return "".join((c.upper() if (i % 2 == 0) else c.lower()) for i, c in enumerate(base)) if base else base
        if transform == "alt_syntax":
            for old, new in _ALT_SYNTAX.get(_family_of(family), []):
                if old in base:
                    return base.replace(old, new, 1)
            return base  # 无匹配片段不瞎改
        if transform == "oob":
            return _oob_payload(family, base)
    except Exception:
        return base
    return base


def _oob_payload(family: str, base: str) -> str:
    """OOB 确认弹：让靶场在服务端执行出网请求，把「执行了」变成带外事实。

    形态表与宿主/路径统一由 oob_monitor 提供（单一真相源，修的就是原先两边对不上的
    那个口子）。只有「服务端会主动出网」的族才有形态 —— XSS 的 OOB 依赖浏览器上下文、
    headless 重放不会触发，LDAP/XPath 走的是目录协议接不到 HTTP 回执，SQL 的
    出网需要额外前提且定稿已定优先时间盲注，这些一律不生成，避免白扔重放预算。
    """
    try:
        from src.iast.oob_monitor import payload_for_family
    except Exception:
        return base
    token = "sastai-%016x" % (abs(hash(base)) & 0xFFFFFFFFFFFFFFFF)
    fam = _family_of(family)
    variants = payload_for_family(fam, base, token)
    # HTTP 形态优先：平台自己就是接收端，开箱可用；DNS 形态要等公网域名配好
    return variants.get("http") or variants.get("dns") or base


def oob_companion_payload(family: str, base: str, token: str = "") -> str:
    """带外**伴随**弹：与基线同时投放，而不是等梯子爬到末阶。

    与 _oob_payload（梯子末阶的确认弹）的区别：
      - 末阶弹 = 前面都失败了才投，用于「还能不能救回来」；
      - 伴随弹 = 第一次重放就带上，用于「这次请求到底有没有让服务端出网」。
    它证明的是「服务端发起了外部请求」，与响应侧判据（回显/差分/时延）正交，
    因此**不占用梯子的层级**，也不应该等到最后才用。

    token 必须外部传入且与登记行一致（此前由 base 派生 hash，无法与 oob_monitor
    的登记 token 对上 → 回执到了也对不上号；现在由调用方统一发号）。
    返回空串表示该族没有伴随弹（不该投，不要硬凑）。
    """
    if not token:
        return ""
    try:
        from src.iast.oob_monitor import payload_for_family
    except Exception:
        return ""
    variants = payload_for_family(_family_of(family), base, token)
    return variants.get("http") or variants.get("dns") or ""


def oob_available(family: str) -> bool:
    """该族是否具备带外弹形态。

    投给一个根本不会出网的族，得到的只是「投了但没回」，既浪费重放预算，又把真阴性
    伪装成「带外也没打通」的假阴性 —— 所以先问再做。
    """
    try:
        from src.iast.oob_monitor import _OOB_MORPHOLOGY, oob_mode
        if oob_mode() == "disabled":
            return False
        fam = _family_of(family)
        morph = _OOB_MORPHOLOGY.get(fam) or {}
        mode = oob_mode()
        return bool(morph.get("http") and mode in ("http", "both")) or \
            bool(morph.get("dns") and mode in ("dns", "both"))
    except Exception:
        return False


def next_variant_payload(base: str, family: str, current_level: int) -> tuple:
    """给定基线与当前层级（0=baseline 已投），返回 (下一层变换名, 变换后 payload, 是否还有下一层)。

    层级越界返回 (None, base, False)。OOB 是梯队的最后一阶（终极弹），越过后即封顶。
    """
    ladder = variant_ladder_for(family)
    if not ladder or current_level < 0 or current_level >= len(ladder) - 1:
        return (None, base, False)
    nxt = ladder[current_level + 1]
    if nxt == "baseline":
        return (nxt, base, True)
    return (nxt, apply_variant_transform(nxt, base, family), True)


# 路由不可达 / 参数未达 / 到达未确认 / 窗口错过 / 被拦截。
_FIVE_CLASS_ACTIONS: Dict[str, List[str]] = {
    "route_unreachable": ["repush_endpoint", "switch_param_location"],
    "param_not_arrived": ["inject_all_params", "switch_param_location"],
    "arrived_unconfirmed": ["escalate_variant", "extend_wait_window"],
    "window_missed": ["extend_wait_window"],
    "blocked": ["escalate_variant"],
    "auth_missing": ["repush_endpoint"],
}



# ---------------------------------------------------------------------------
#
# 背景：两者在「结果终点」上都表现为没到 sink，但成因完全不同——一个是放错位置（错放），
# 一个是路对了被拦（拦截）。此前 `_infer_failure_class` 拿 D2 的 reason 自然语言做关键词
# 匹配，且第一条分支含 "endpoint"/"no-arrival" 这类极泛的词，导致 reason 里只要出现这些词、
# 哪怕同时写了 waf/blocked，也会被抢先判成 route_unreachable —— 五类信号因此长期失真，
# blocked→escalate_variant 分支实际不可达。
#
# 修法：改以「一组确定的可观测事实」分层——状态码 + 响应摘要（拒绝签名）+ 到达事实 +
# 是否被确证有害。同一条 spec 的重放天然只有一组这样的事实，判据是确定的、不再漂移。
# ---------------------------------------------------------------------------
AUTH_MISSING = "auth_missing"

# 路由缺席类状态码：端点根本不存在或方法不被允许，请求压根没进 controller。
_ROUTE_MISS_STATUS = (404, 405, 410)
# 拒绝类状态码（与 d1_service._is_waf_blocked 的 _WAF_BLOCK_STATUS 同源口径）。
_DENY_STATUS = (401, 403, 405, 406, 407, 429)
# 鉴权墙状态码：跳登录 / 无凭据。
_AUTH_REDIRECT_STATUS = (301, 302)

# 拒绝短语（镜像 src/application/d1_service.py 的 _FILTER_REJECT_PHRASES，单一真相源在那里；
# 此处为免循环 import 做本地镜像，改动请两边同步）。
_REJECT_PHRASES = (
    "bad boy", "i got u", "request blocked", "access denied", "forbidden",
    "blocked by", "waf", "firewall", "not allowed", "rejected",
    "拦截", "已被过滤", "请求被拒绝", "禁止访问",
)


def _ev_field(evidence: Any, *keys: str) -> Any:
    """从扁平或嵌套的 D2 证据里取值，兼容 dast_impact_evidence / iast_evidence / d2_verdict 三种形状。"""
    if not isinstance(evidence, dict):
        return None
    for k in keys:
        v = evidence.get(k)
        if v not in (None, "", [], {}):
            return v
    for container in ("dast_impact_evidence", "iast_evidence", "d2_verdict", "d2_output"):
        sub = evidence.get(container)
        if isinstance(sub, dict):
            for k in keys:
                v = sub.get(k)
                if v not in (None, "", [], {}):
                    return v
    return None


def _has_reject_signature(blob: str) -> bool:
    return any(p in blob for p in _REJECT_PHRASES)


def classify_runtime_evidence(evidence: Any) -> str:
    """按可观测事实把运行时失败分层，返回五类之一；证据不足返回 ""（调用方回落到关键词）。

    分层次序（由粗到细、先礼让不可达，再问是否被拦）：
      1. 404/405/410                → route_unreachable（错放：路由不存在/方法不对）
      2. 302/301 跳登录、401 无凭据 → auth_missing（先补会话，不是拦截也不是错放）
      3. 403/406/407/429 或 200+拒绝短语 → blocked（拦截：路由活着但 payload 被拒）
      4. 已到达 sink 但未被确证有害  → arrived_unconfirmed
      5. 200 但 canary 未抵达 sink    → param_not_arrived
      6. 都没有                       → ""（证据不足）

    第 3 条优先于第 4 条的理由：攻击 payload 被拒、只剩canary 到达噪声 sink 时，
    「到达」不代表可利用，必须判 blocked 才能走到 escalate_variant 去试绕过变体。
    """
    if not isinstance(evidence, dict):
        return ""

    raw_status = _ev_field(evidence, "status_code", "status", "http_status")
    status = None
    try:
        if raw_status is not None and str(raw_status).strip() != "":
            status = int(raw_status)
    except (TypeError, ValueError):
        status = None

    # 响应摘要只读「机器产出的事实」，绝不把 reason 自然语言放进来（那正是旧判据漂移的根源）。
    body = " ".join(
        str(_ev_field(evidence, k) or "")
        for k in ("response_summary", "body", "d2_evidence", "response_body", "value")
    ).lower()

    reached = bool(_ev_field(evidence, "reached", "dast_reached", "impact_observed"))
    harmful = bool(_ev_field(evidence, "harmful", "d2_harmful"))
    iast_state = str(_ev_field(evidence, "iast_state", "state") or "").lower()
    arrived_sink = "sink-reached" in iast_state or "arrived" in iast_state or bool(
        _ev_field(evidence, "sink_reached", "canary_arrived")
    )

    # 1) 路由本身不在
    if status in _ROUTE_MISS_STATUS:
        return "route_unreachable"

    # 2) 鉴权墙
    if status in _AUTH_REDIRECT_STATUS:
        return AUTH_MISSING
    # 401 + 标准鉴权挑战头 WWW-Authenticate → 鉴权墙（缺凭证），
    # 优先于「被拦截」判据，确保走「带会话/双账户重放」而非 escalate_variant。
    _hdr_blob = " ".join(
        str(_ev_field(evidence, k) or "") for k in ("headers", "response_headers")
    ).lower()
    if status == 401 and ("www-authenticate" in _hdr_blob or not _has_reject_signature(body)):
        return AUTH_MISSING

    if status in _DENY_STATUS or (status == 200 and _has_reject_signature(body)):
        if _has_reject_signature(body) or status in (403, 406, 407, 429):
            # 攻击 payload 确实被拒 且没被确证有害 → 判 blocked（走进重试环升变体）
            if not harmful:
                return "blocked"

    # 4) 到了 sink 但没确证有害
    if (reached or arrived_sink) and not harmful:
        return "arrived_unconfirmed"

    # 5) 200 但数据没到 sink
    if status == 200 and not (reached or arrived_sink):
        return "param_not_arrived"

    return ""


def _infer_failure_class(reason: str) -> str:
    """无结构化事实时，从 reason 关键词反推五类之一（best-effort，用于记录）。

    "endpoint" / "no-arrival" 这类极泛的词 —— 结果 reason 里只要出现这些词，哪怕同时
    写了 waf/blocked，也会被抢判成 route_unreachable，blocked→escalate_variant 分支
    因此长期不可达。

    新次序：**先判具体成因（鉴权 / 拦截），再判泛化的到达类失败**，并踢掉会劫持的泛词。
    """
    r = (reason or "").lower()
    # 1) 鉴权墙（最具体）
    if any(k in r for k in ("请登录", "未登录", "未授权", "unauthorized", "302", "login", "鉴权")):
        return AUTH_MISSING
    # 2) 被拦截：必须在路由/参数之前判，否则 reason 提到 endpoint 就被误吞
    if any(k in r for k in ("拦截", "403", "waf", "blocked", "防火墙", "过滤", "拒绝", "禁止")):
        return "blocked"
    # 3) 路由缺席：只留真正描述路由不存在的词，踢掉 "endpoint" / "no-arrival" 泛词
    if any(k in r for k in ("路由不存在", "404", "路由不可达", "找不到路由", "未找到该路由")):
        return "route_unreachable"
    if any(k in r for k in ("参数", "parameter", "未达", "未命中")):
        return "param_not_arrived"
    if any(k in r for k in ("窗口", "未观测", "迟到", "wait", "超时")):
        return "window_missed"
    return "param_not_arrived"  # 默认按「参数/到达」处理，与旧回退一致


# ---------------------------------------------------------------------------
# 重放侧调整（闭环不只让 A2 重写假说）
# ---------------------------------------------------------------------------
def plan_replay_adjustments(routed: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """把「运行时观测失败」翻译成重放侧可执行的调整动作。

    当前 A2 重写假说改不了 D1 实际发出的请求；真正影响重放的是 trigger_spec 上的
    param_location / representative_request_params / 等待窗口。这里产出具体调整：
    - switch_param_location：换参数注入位置（query→json/body/form）
    - inject_all_params：全参注入（不再只打单一参数）
    - extend_wait_window：延长 I1 事件等待窗口
    """
    adjustments: List[Dict[str, Any]] = []
    seen = set()
    for fb in (routed.get(RUNTIME_OBSERVATION) or []) + (routed.get(PROBE_NOT_INSTRUMENTED) or []):
        hid = _feedback_hid(fb)
        if not hid or hid in seen:
            continue
        seen.add(hid)
        reason = str(fb.get("reason") or "")
        fb_class = str(fb.get("failure_class") or "")
        # 响应摘要 / 到达事实 / 是否确证有害）判定，判不出来才回落到自然语言关键词。
        # 这一步是 blocked 与 route_unreachable 能可靠分离的关键。
        if not fb_class:
            fb_class = classify_runtime_evidence(fb)
        actions: List[str] = []
        if fb_class in _FIVE_CLASS_ACTIONS:
            actions = list(_FIVE_CLASS_ACTIONS[fb_class])
        else:
            if "参数" in reason or "parameter" in reason.lower():
                actions.append("switch_param_location")
            if "确凿缺失节点" in reason or "链路不符" in reason:
                actions.append("inject_all_params")
            if "窗口" in reason or "未观测到" in reason:
                actions.append("extend_wait_window")
            if any(k in reason or k in reason.lower() for k in ("路由", "404", "不可达", "no-arrival", "endpoint")):
                actions.append("repush_endpoint")
                if "switch_param_location" not in actions:
                    actions.append("switch_param_location")
            if any(k in reason.lower() for k in ("拦截", "403", "waf", "blocked", "防火墙", "过滤")):
                actions.append("escalate_variant")
            if not actions:
                actions = ["inject_all_params", "extend_wait_window"]
            fb_class = fb_class or _infer_failure_class(reason)
        # 指令里带净化器约束(FilterSpec)、必须避开的片段、以及轨迹记忆里已试过且无效的载荷，
        # 让下一轮合成/重放不再重复无效打法——这是"Agent 式自主学习"所缺的那一环。
        _directive: Dict[str, Any] = {}
        try:
            from src.core.sanitizer_miner import FilterSpec as _FS
            from src.iast.replay_intel import ReplayMemory as _RM, build_directive as _bd
            _mem = _RM.from_dict(fb.get("replay_intel")) if isinstance(fb.get("replay_intel"), dict) else _RM()
            _fspec = _FS.from_dict(fb.get("filter_spec"))
            _directive = _bd(
                fb_class, fb, spec=_fspec, memory=_mem,
                family=str(fb.get("family") or ""),
                endpoint=str(fb.get("target_endpoint") or fb.get("endpoint") or ""),
                sink=str(fb.get("sink") or fb.get("expected_sink_file") or ""),
            )
        except Exception as _de:
            logger.warning("[i2_feedback] 改进指令生成失败（不影响既有动作）：%s", _de)

        adjustments.append({
            "hypothesis_id": hid,
            "failure_class": fb_class,
            "actions": actions,
            "reason": reason[:200],
            "directive": _directive,
        })
    if adjustments:
        logger.info("[i2_feedback] 重放侧调整计划：%d 条", len(adjustments))
    return adjustments


def apply_replay_adjustments(db, task_id: int, adjustments: List[Dict[str, Any]], *, bump_round: bool = True) -> int:
    """把重放侧调整落到 trigger_specs（D1 重放的实际输入），返回调整条数。

    只改「请求怎么发」，不改漏洞假说本身——这是与 A2 回灌的本质区别。

    adjustments **补写**。补写时必须 bump_round=False，
    否则 round 被推到 2 会让 plan_retryable_replay 误判封顶、重试环整体失效。
    """
    if not adjustments:
        return 0
    n = 0
    for adj in adjustments:
        hid = str(adj.get("hypothesis_id") or "")
        if not hid:
            continue
        try:
            row = db.execute(
                "SELECT id, param_location, representative_request_params_json, param_name, raw_json"
                " FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=? LIMIT 1",
                (task_id, hid), fetchone=True,
            )
        except Exception:
            row = None
        if not row:
            continue
        actions = adj.get("actions") or []
        new_loc = row["param_location"] or "query"
        if "switch_param_location" in actions:
            # 一次只换一档，避免连续回灌把位置抖成循环
            ladder = {"query": "json", "json": "form", "form": "body", "body": "query"}
            new_loc = ladder.get(new_loc, "json")
        try:
            db.execute(
                "UPDATE trigger_specs SET param_location=? WHERE id=?", (new_loc, int(row["id"]))
            )
            sync_entry_projection(db, int(row["id"]), param_location=new_loc)
            n += 1
        except Exception as _e:
            logger.warning("[i2_feedback] 应用重放调整失败 spec=%s：%s", row["id"], _e)
        # inject_all_params / extend_wait_window **只进 plan、不改任何字段**——闭环看起来
        # 「做了重放侧调整」，实际仍按原样重放同一发请求，0 事件的 spec 永远捞不回来。
        # 这里把三个动作全部落到 spec.raw_json.replay_adjust（累计轮次 + 动作集合），
        # 供重放侧读取与事后审计；未被读取前不改变任何既有重放行为（零回归）。
        try:
            import json as _json
            _raw = row["raw_json"] if "raw_json" in row.keys() else ""
            _meta = {}
            if _raw:
                try:
                    _meta = _json.loads(_raw) or {}
                except Exception:
                    _meta = {}
            if not isinstance(_meta, dict):
                _meta = {}
            _adj = dict(_meta.get("replay_adjust") or {})
            _acts = sorted(set(list(_adj.get("actions") or []) + list(actions)))
            _adj["actions"] = _acts
            if bump_round:
                _adj["round"] = int(_adj.get("round") or 0) + 1
            # 残留 1 收口：把具体改弹指令（directive）一并落到 spec，使重放侧 /
            # 下一轮合成真正读得到「该改什么」——此前指令只活在 adjustments 的内存对象里，
            # apply 阶段只搬了 actions（动作名），指令正文（避开片段/净化器约束/已试无效载荷）
            # 从未进 DB，故「改进要求」实际永远到不了执行端。
            _dir = adj.get("directive") or {}
            if isinstance(_dir, dict) and _dir:
                _prev = _adj.get("directive") if isinstance(_adj.get("directive"), dict) else {}
                _merged = dict(_prev)
                _merged.update(_dir)
                _adj["directive"] = _merged
                _adj["failure_class"] = str(adj.get("failure_class") or "") or str(
                    _merged.get("failure_class") or "")
            _meta["replay_adjust"] = _adj
            db.execute(
                "UPDATE trigger_specs SET raw_json=? WHERE id=?",
                (_json.dumps(_meta, ensure_ascii=False), int(row["id"])),
            )
        except Exception as _e:
            logger.warning("[i2_feedback] 记录重放调整元字段失败 spec=%s：%s", row["id"], _e)
    if n:
        logger.info("[i2_feedback] 已应用 %d 条重放侧调整（task=%s）", n, task_id)
    return n


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def difference_set_feedbacks(db, task_id: int, limit: int = 200) -> List[Dict[str, Any]]:
    """把「假说集 ⊖ 观测集」的差集条目转成结构化回灌项。

    差集 = state=open 的假说（重放跑了但四个门禁一个都没闭合，既未证实也未证伪）。
    与旧的「回灌自然语言 reason」不同：这里回灌结构化字段（vulnerability_hash_v2 /
    family / endpoint / gates），并显式标 failure_class=hypothesis_defect，
    保证该条必然进入 a2_actionable，不再靠关键词分类去猜。

    依赖 src.core.hypotheses 的差集载体（hypotheses 表）。任何异常都 fail-open 返回空表，
    不影响闭环主流程。
    """
    try:
        from src.core import hypotheses as _hyp
        diff = _hyp.difference_set(db, task_id, limit=limit)
    except Exception as _e:  # noqa: BLE001
        logger.warning("[i2_feedback] 差集导出失败（不阻断闭环）：%s", _e)
        return []

    out: List[Dict[str, Any]] = []
    for it in (diff.get("items") or []):
        vh = it.get("vulnerability_hash_v2")
        out.append({
            "hypothesis_id": vh or f"{it.get('family')}@{it.get('endpoint')}",
            "vulnerability_hash_v2": vh,
            "family": it.get("family"),
            "endpoint": it.get("endpoint"),
            "method": it.get("method"),
            "reason": it.get("reason") or "假说 state=open：观测既未证实也未证伪",
            # 显式结构化分类：差集条目按定义就是假说链路缺陷
            "failure_class": HYPOTHESIS_DEFECT,
            "residual_gaps": {"still_open": it.get("gates") or []},
            "claimed_chain": it.get("claimed_chain") or {},
            "source": "difference_set",
        })
    if out:
        logger.info("[i2_feedback] 差集结构化回灌项：%d 条（state=open 假说）", len(out))
    return out


# ---------------------------------------------------------------------------
# 闭环控制器（真循环）
# ---------------------------------------------------------------------------
class ClosedLoopController:
    """带迭代上限、attempt history、增益收敛判据的闭环控制器。

    与旧实现的差别：
    - 旧：固定回灌 1 次、绝不递归、无历史、无判据 → 不是 loop，是一次 retry。
    - 新：最多 max_iterations 轮；每轮记录 (iteration, 分流结果, 采取动作, 增益)；
      以「新增 confirmed/verified 数」为增益判据，连续无增益即停并标记 exhausted。

    「调用被阻塞」**。round-15 死在 i2_rerun（iteration=1、replay_adjustments=0），
    因 canary 重放被双 runner 并发踩踏永久阻塞，却无超时能把循环拽出。新增：
    - stall_timeout：距上次 note_progress 超过该秒数即判 stalled（覆盖「阻塞」非仅 gain）。
    - note_progress：编排侧每完成一次有效进展（迭代结束 / 阶段心跳）调用，刷新时间戳。
    - failure_class=replay_stall：stall 终止时写入 summary，便于前端/报告定位。
    """

    def __init__(self, max_iterations: int = 3, min_gain: int = 1, stall_timeout: int = 1200):
        self.max_iterations = max(1, int(max_iterations))
        self.min_gain = max(0, int(min_gain))
        # stall_timeout 默认 20 分钟：低于项目「scan_progress.json >45min 判卡死」阈值，
        # 但高于单轮 D2 重验正常耗时，避免误杀正常轮。
        self.stall_timeout = max(60, int(stall_timeout))
        self.history: List[Dict[str, Any]] = []
        self._last_progress = time.time()
        self.stalled = False

    def note_progress(self) -> None:
        """编排侧每完成一次有效进展调用，刷新 stall 时间戳。"""
        self._last_progress = time.time()

    def seconds_since_progress(self) -> float:
        return time.time() - self._last_progress

    def should_continue(self, iteration: int, gain: int) -> bool:
        if iteration >= self.max_iterations:
            logger.info("[closed_loop] 达迭代上限 %d，停止", self.max_iterations)
            return False
        if gain < self.min_gain:
            logger.info("[closed_loop] 本轮增益 %d < 阈值 %d，判定收敛/无效，停止", gain, self.min_gain)
            return False
        if self.seconds_since_progress() > self.stall_timeout:
            self.stalled = True
            logger.warning(
                "[closed_loop] 距上次进展 %.0fs 超 stall_timeout %ds，判定重放/调用阻塞，强制停止",
                self.seconds_since_progress(), self.stall_timeout,
            )
            return False
        return True

    def record(self, iteration: int, routed_counts: Dict[str, int],
               action: str, gain: int, detail: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "iteration": iteration,
            "routed": routed_counts,
            "action": action,
            "gain": gain,
        }
        if detail:
            entry.update(detail)
        if self.stalled:
            entry["failure_class"] = "replay_stall"
            entry["stalled"] = True
        self.history.append(entry)
        logger.info("[closed_loop] #%d action=%s gain=%s routed=%s",
                    iteration, action, gain, routed_counts)

    def summary(self) -> Dict[str, Any]:
        return {
            "iterations": len(self.history),
            "max_iterations": self.max_iterations,
            "history": self.history,
            "exhausted": len(self.history) >= self.max_iterations,
        }
