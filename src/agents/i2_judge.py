"""I2 判因：把「LLM 当安全人员用」落到闭环里。

## 为什么需要它
此前的判因是关键词规则表（`src/iast/replay_intel.py` 的 `decide_next_action`）：
能区分「被拦 / 无证据」，但区分不了「payload 有问题（被净化/语法错）」和「打法错了
（方法/参数/编码/流程不对）」——这两类需要判断力，正是 LLM 该占的位置。
人拿到重放结果会做四态判断：漏洞不成立 / 漏洞成立 / payload 有问题 / 打法错了，
然后决定下一步。本模块把这四态 + 8 个受限动作变成结构化输出。

## 两级决策（控成本）
1. 规则先判 obvious：无 payload、属性族、oracle 已给出正向结论 —— 这些不需要判断力；
2. 只有「到达但未确认 / 被拦 / 过滤」这类 ambiguous 才交 LLM。
目标：LLM 调用 ≤ 20% 的 spec。

## 受限动作空间（禁止自由文本）
change_payload / change_encoding / change_location / change_content_type /
add_header / change_method / adjust_window / give_up。

## 纪律
- 只输出 JSON，字段全部枚举校验；不合格重试一次，再不合格降级为规则结论（绝不静默吞掉）。
- LLM 只「提议」，落地动作仍由确定性执行器（D1/D2）执行 —— 与项目整体定位一致。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 四态（人工判因的口径）
VERDICTS = ("confirmed", "false_positive", "payload_problem", "approach_problem")

# 受限动作空间
ACTIONS = (
    "change_payload", "change_encoding", "change_location", "change_content_type",
    "add_header", "change_method", "adjust_window", "give_up",
)

# 规则先判 obvious 的动作（不走 LLM）
_PROPERTY_FAMILIES = ("weak_hash", "weak_crypto", "weak_random", "insecure crypto algorithm",
                      "secure_cookie")

_SYSTEM_PROMPT = """你是渗透测试闭环里的「判因」环节。给你一条漏洞的静态线索 + 运行时重放观察包，
你只做判断并选择**一个**受限动作，不解释、不扩展、不输出多余字段。

四态口径（必须四选一）：
- confirmed：**运行时证据**表明漏洞成立（payload 已产生预期效果）。
- false_positive：证据表明这不是漏洞（安全实现/不可达/判据不适用）。
- payload_problem：漏洞可能存在，但当前 payload 没打出效果（被净化、编码不对、语法错）。
- approach_problem：漏洞可能存在，但当前打法不对（参数位置/方法/Content-Type/流程/头）。

判定纪律（**最重要，违反即判错**）：
- 判 confirmed 的硬条件：观察包里必须存在「payload 产生了预期效果」的**直接证据**——
  oracle 正向信号（boolean_diff / time_delay / file_signature / reflection_raw），
  或 read_state 显示值被读取，或明确的响应差异。**没有这些证据时，即使 payload
  看起来完全正确，也只能判 payload_problem 或 approach_problem，绝不能判 confirmed。**
- 「spec 里写了 payload」不等于「payload 有效」；「payload 设计合理」不等于「打通了」。
- 观察包里出现「canary 未观测到」「oracle 未跑」「状态码 200 但无差异」时，默认是**未打通**。

八个受限动作（必须八选一）：
- change_payload：换一个 payload（必须给出新 payload）
- change_encoding：换编码方式（必须给出新 payload）
- change_location：换参数位置（query/header/cookie/body）
- change_content_type：换请求体格式
- add_header：补请求头（必须给出头名与值）
- change_method：换 HTTP 方法
- adjust_window：延长等待窗口（延迟处理型 sink）
- give_up：放弃（仅在 false_positive 或已充分尝试时选）

输出严格 JSON（不要 markdown 代码块、不要注释）：
{"verdict":"<四态之一>","action":"<八选一>","payload":"<新payload；仅 change_payload/change_encoding 必填>",
 "reason":"<=80字的人类可读理由>","confidence":0.0}
"""


@dataclass
class ObservationPacket:
    """一条 spec 的判因观察包（结构化、小体积，可直接进 prompt）。"""

    spec_id: int = 0
    task_id: int = 0
    family: str = ""
    endpoint: str = ""
    http_method: str = "GET"
    param_name: str = ""
    param_location: str = "query"
    content_type: str = ""
    payloads: List[str] = field(default_factory=list)
    filter_spec: Dict[str, Any] = field(default_factory=dict)
    sanitizer: str = ""                    # 净化器片段（A2 摘要）
    attempts: List[Dict[str, Any]] = field(default_factory=list)
    oracle: Dict[str, Any] = field(default_factory=dict)
    read_state: str = ""                   # raw / escaped / absent（backfill 回填）
    verification_status: str = ""
    round_no: int = 1

    def to_prompt_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "endpoint": "%s %s" % (self.http_method, self.endpoint),
            "param": "%s(%s)" % (self.param_name or "?", self.param_location),
            "content_type": self.content_type or "(none)",
            "payloads_tried": self.payloads[:5],
            "sanitizer": self.filter_spec or self.sanitizer or "(未知)",
            "attempts": self.attempts[-6:],
            "oracle": {k: self.oracle.get(k) for k in ("verdict", "signal", "reason")} or "(未跑)",
            "probe_read_state": self.read_state or "(未回填)",
            "current_status": self.verification_status or "(未确认)",
            "round": self.round_no,
        }


def build_packet(*, spec: Dict[str, Any], attempts: List[Dict[str, Any]],
                 round_no: int = 1) -> ObservationPacket:
    """从 DB 行构造观察包。`attempts` 取该 spec 的 replay_attempts（新的在前或旧的在前都行）。"""
    def _json(v: Any, default: Any) -> Any:
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.strip():
            try:
                return json.loads(v)
            except Exception:  # noqa: BLE001
                return default
        return default

    pk = ObservationPacket(
        spec_id=int(spec.get("id") or 0),
        task_id=int(spec.get("task_id") or 0),
        family=str(spec.get("family") or ""),
        endpoint=str(spec.get("target_endpoint") or ""),
        http_method=str(spec.get("http_method") or "GET").upper(),
        param_name=str(spec.get("param_name") or ""),
        param_location=str(spec.get("param_location") or "query"),
        content_type=str(spec.get("content_type") or ""),
        payloads=[str(p) for p in (_json(spec.get("attack_payloads_json"), []) or [])],
        filter_spec=_json(spec.get("filter_spec_json"), {}),
        attempts=list(attempts or []),
        oracle={
            "verdict": str(spec.get("oracle_state") or ""),
            "signal": str(spec.get("oracle_signal") or ""),
        },
        read_state=str(spec.get("read_state") or ""),
        verification_status=str(spec.get("verification_status") or ""),
        round_no=int(round_no or 1),
    )
    return pk


# ─────────────────────────── 第一级：规则判 obvious ───────────────────────────

def rule_decide(packet: ObservationPacket) -> Optional[Dict[str, Any]]:
    """不需要判断力的 obvious 情形直接给结论；返回 None 表示交给 LLM。

    覆盖三类（都是确定性事实，不需要语义判断）：
    1. 无 payload 可投（A2 没产出 / 全被判废）→ change_payload（合成族内弹）
    2. 属性族（hash/crypto/random/cookie flag）→ give_up（运行时无 payload 可判，
       结论来自静态代码属性，重放再多也不产生新信息）
    3. oracle 已给出结论 → 直接采信（behavioral 正向/主动净化证据都比规则强）
    """
    fam = (packet.family or "").lower()
    oracle = (packet.oracle or {}).get("verdict") or ""

    if oracle == "exploitable":
        return {"verdict": "confirmed", "action": "give_up", "payload": "",
                "reason": "行为 oracle 正向信号（%s）" % ((packet.oracle or {}).get("signal") or "?"),
                "confidence": 0.9, "source": "rule"}
    if oracle == "not_exploitable":
        return {"verdict": "false_positive", "action": "give_up", "payload": "",
                "reason": "行为 oracle 主动净化证据（%s）" % ((packet.oracle or {}).get("signal") or "?"),
                "confidence": 0.7, "source": "rule"}
    if not packet.payloads:
        return {"verdict": "payload_problem", "action": "change_payload", "payload": "",
                "reason": "无可用 payload（A2 未产出或被自检判废）", "confidence": 0.5,
                "source": "rule"}
    if any(fam == p or p in fam for p in _PROPERTY_FAMILIES):
        return {"verdict": "false_positive", "action": "give_up", "payload": "",
                "reason": "属性族：运行时无 payload 可判，结论应由静态代码属性给出",
                "confidence": 0.5, "source": "rule"}
    return None


# ─────────────────────────── 第二级：LLM 判因 ───────────────────────────

def _validate(decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(decision, dict):
        return None
    verdict = str(decision.get("verdict") or "").strip().lower()
    action = str(decision.get("action") or "").strip().lower()
    if verdict not in VERDICTS or action not in ACTIONS:
        return None
    payload = str(decision.get("payload") or "")
    try:
        conf = float(decision.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    conf = min(max(conf, 0.0), 1.0)
    # 其余动作（换位置/换编码/换方法/加头/延长窗口）本来就不需要新弹，
    # 早期对它们也强制 payload ⇒ 有价值的判因被判"不合格"、两次后降级成 adjust_window，
    # 等于把「LLM 明确说该换 cookie 位置」这类最有用的信息丢掉。
    if action == "change_payload" and not payload.strip():
        return None
    return {"verdict": verdict, "action": action, "payload": payload[:2000],
            "reason": str(decision.get("reason") or "")[:120], "confidence": conf,
            "source": "llm"}


def llm_decide(packet: ObservationPacket, gateway: Any = None) -> Dict[str, Any]:
    """调用 LLM 判因；失败/不合格时降级为保守结论（绝不静默吞掉）。"""
    fallback = {"verdict": "approach_problem", "action": "adjust_window", "payload": "",
                "reason": "LLM 判因不可用，保守重试", "confidence": 0.0, "source": "fallback"}
    try:
        from src.agents.a2_integrated_analyst import ollama_chat
    except Exception as exc:  # noqa: BLE001
        logger.debug("[i2_judge] ollama_chat 不可用：%s", exc)
        return fallback
    user = json.dumps({
        "task": "判因并选择下一步动作",
        "observation": packet.to_prompt_dict(),
        "output_schema": {"verdict": "|".join(VERDICTS), "action": "|".join(ACTIONS),
                          "payload": "str", "reason": "str<=80", "confidence": "0..1"},
    }, ensure_ascii=False)
    messages = [{"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user}]
    for attempt in (1, 2):
        raw = ""
        try:
            raw = ollama_chat(messages, timeout=120.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[i2_judge] LLM 调用失败（第 %d 次）：%s", attempt, exc)
        parsed = None
        if isinstance(raw, dict):
            parsed = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except Exception:  # noqa: BLE001
                import re
                m = re.search(r"\{.*\}", raw, re.S)
                if m:
                    try:
                        parsed = json.loads(m.group(0))
                    except Exception:  # noqa: BLE001
                        parsed = None
        ok = _validate(parsed or {})
        if ok:
            return ok
        if attempt == 1:
            # 第一次不合格：把错误回灌重试一次
            messages.append({"role": "user",
                             "content": "上一次输出不合格（字段越界或缺 payload），"
                                        "请严格按 output_schema 重试。"})
    logger.info("[i2_judge] LLM 判因两次均不合格，降级保守结论（spec=%s）", packet.spec_id)
    return fallback


def payload_vhash_set(db: Any, task_id: int) -> set:
    """返回本任务里「带 payload」的 spec vhash 集合（一次查询，供候选过滤）。

    为什么需要：真实闭环里 95% 以上的反馈被规则分流进 runtime_observation
    （reason 是「canary 未观测到」），hypothesis_defect 桶几乎总是空的 ⇒ 只挂在那桶上的
    真正值得判的是「有弹但打不通」的那一小撮（468 实测 148 条未确认里 23 条带 payload，
    其中 sql_injection 21 条）——是弹的问题还是打法的问题，这正是判因该回答的。
    """
    if db is None or not task_id:
        return set()
    try:
        rows = db.execute(
            "SELECT vulnerability_hash_v2, attack_payloads_json FROM trigger_specs"
            " WHERE task_id=?", (int(task_id),), fetchall=True) or []
    except Exception:  # noqa: BLE001
        return set()
    out = set()
    for r in rows:
        d = dict(r)
        try:
            if json.loads(d.get("attack_payloads_json") or "[]"):
                out.add(str(d.get("vulnerability_hash_v2") or ""))
        except Exception:  # noqa: BLE001
            continue
    out.discard("")
    return out


def apply_reclassification(routed: Dict[str, List[Dict[str, Any]]],
                           verdicts: Dict[str, Any],
                           defect_class: str = "hypothesis_defect",
                           source_classes: Optional[List[str]] = None) -> Dict[str, Any]:
    """把 LLM 判因结果应用到 routed 桶（纯函数，可单测）。

    只移动「判出的 failure_class 与源桶不同」的条目；**未被重分类的条目必须留在原桶**——
    结果把整桶清空，a2_actionable 拿不到任何反馈，闭环误判「无可执行反馈」直接空转。

    runtime_observation 里「有弹但打不通」的条目。对后者有一条额外纪律：
    **approach_problem 不移动**（打法问题该由重放侧改位置/编码，不该触发 A2 重跑），
    只标注 llm_action 供 replay 调整消费。

    返回 {"moved": n, "kept": n, "annotated": n}，就地修改 routed。
    """
    sources = list(source_classes or [defect_class])
    moved: set = set()
    annotated = 0
    for cls in sources:
        for fb in list(routed.get(cls) or []):
            if not isinstance(fb, dict):
                continue
            hid = str(fb.get("hypothesis_id") or fb.get("vulnerability_hash_v2") or "")
            d = (verdicts.get("classified") or {}).get(hid)
            if not d:
                continue
            annotated += 1
            fb["llm_verdict"] = d.get("verdict")
            fb["llm_source"] = d.get("source")
            fb["llm_confidence"] = d.get("confidence")
            fb["llm_action"] = d.get("action")
            fb["llm_reason"] = d.get("reason")
            new_cls = d.get("failure_class")
            if not new_cls or new_cls == cls:
                continue
            if cls == "runtime_observation" and d.get("verdict") == "approach_problem":
                # 打法问题留在运行时桶：重放侧改位置/编码比 A2 静态重写更对症。
                continue
            routed.setdefault(new_cls, []).append(fb)
            moved.add((cls, id(fb)))
    for cls in sources:
        if any(c == cls for c, _ in moved):
            routed[cls] = [f for f in (routed.get(cls) or [])
                           if (cls, id(f)) not in moved]
    return {"moved": len(moved),
            "kept": sum(len(routed.get(c) or []) for c in sources),
            "annotated": annotated}


def attach_llm_directives(routed: Dict[str, List[Dict[str, Any]]],
                          defect_class: str = "hypothesis_defect",
                          source_classes: Optional[List[str]] = None) -> Dict[str, Any]:
    """把 LLM 判因给出的**具体动作**追加进反馈的 reason（纯函数，可单测）。

    为什么必须走 reason：A2 二次分析消费的是 feedback_to_a2 的 reason 文本，
    挂在自定义字段上的 llm_action 它读不到（与 i2_feedback.attach_directives 同一个
    false_positive，所以「重新分桶」收益有限；真正有价值的是它给出的动作建议
    （换弹 / 换位置 / 换方法 / 延长窗口）——必须让 A2 看见。

    尤其 approach_problem 留在该桶时，靠这条 reason 让重放侧/下一轮知道该怎么改。

    give_up 不追加：那是「别再试了」，不该变成一条改进要求。
    返回 {"attached": n}，就地修改。
    """
    n = 0
    classes = list(source_classes or [defect_class])
    for cls in classes:
        for fb in (routed.get(cls) or []):
            if not isinstance(fb, dict):
                continue
            act = str(fb.get("llm_action") or "")
            if not act or act == "give_up":
                continue
            reason = str(fb.get("reason") or "").strip()
            hint = "LLM 判因建议：%s" % act
            if fb.get("llm_reason"):
                hint += "（%s）" % str(fb.get("llm_reason"))[:80]
            if hint in reason:
                continue
            fb["reason"] = (reason + "｜" + hint) if reason else hint
            fb["llm_directive_attached"] = True
            n += 1
    return {"attached": n}


def decide(packet: ObservationPacket, gateway: Any = None,
           llm_enabled: bool = True) -> Dict[str, Any]:
    """两级决策入口：规则先判 obvious，ambiguous 才交 LLM。"""
    rule = rule_decide(packet)
    if rule is not None:
        return rule
    if not llm_enabled:
        return {"verdict": "approach_problem", "action": "adjust_window", "payload": "",
                "reason": "LLM 判因关闭，保守重试", "confidence": 0.0, "source": "rule"}
    return llm_decide(packet, gateway=gateway)


# ───────────────────────── 闭环接线：对 I2 反馈做 LLM 二级判因 ─────────────────────────

# 判因四态 → i2_feedback 的 failure_class 映射（**按来源分表**）。
#
# 规则判定（source=rule）有硬证据，结论可信：
#   oracle 正向 ⇒ confirmed 可信；oracle 主动净化 ⇒ false_positive 可信。
#   confirmed 判出 5/10 条「运行时证据表明漏洞成立」，但对应 spec 的 oracle 全是
#   inconclusive/boolean_same（零直接证据）⇒ 采信会把未打通的白送进 A2 重跑烧时间；
#   false_positive 同理不可采信（黑盒无否定能力）。
#   因此 LLM 的 confirmed / false_positive 一律不移动（映射为空），只保留在条目上供审计；
#   真正落地的只有 payload_problem / approach_problem 的动作建议（换弹/换位置/换编码）。
_RULE_VERDICT_TO_CLASS = {
    "confirmed": "hypothesis_defect",        # 证据说成立却走到这里 ⇒ 假说有瑕疵，回灌重造
    "false_positive": "runtime_refutation",  # 判否：不进 A2 回灌
    "payload_problem": "hypothesis_defect",
    "approach_problem": "hypothesis_defect",
}
_LLM_VERDICT_TO_CLASS = {
    "confirmed": "",
    "false_positive": "",       # 不采信（黑盒无否定能力）
    "payload_problem": "hypothesis_defect",   # 该换弹 ⇒ 回灌 A2
    "approach_problem": "hypothesis_defect",  # 该换打法 ⇒ 回灌 A2（runtime 桶里则留原地）
}


def _load_spec_row(db: Any, task_id: int, hypothesis_id: str) -> Dict[str, Any]:
    """按 hypothesis_id（= vhash）取本任务的 trigger_spec 行；取不到返回空字典。"""
    if db is None or not hypothesis_id:
        return {}
    try:
        row = db.execute(
            "SELECT * FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=? "
            "ORDER BY id DESC LIMIT 1", (int(task_id), str(hypothesis_id)), fetchone=True)
        return dict(row) if row else {}
    except Exception as exc:  # noqa: BLE001
        logger.debug("[i2_judge] spec 查询失败（%s）：%s", hypothesis_id[:12], exc)
        return {}


def _load_attempts(db: Any, spec_id: Any, limit: int = 6) -> List[Dict[str, Any]]:
    """取该 spec 最近的 replay_attempts（摘要，不喂原文）。"""
    if db is None or not spec_id:
        return []
    try:
        rows = db.execute(
            "SELECT attempt_no, payload, param_location, encoding, status_code, elapsed_ms,"
            " waf_blocked, read_state, verdict FROM replay_attempts WHERE spec_id=?"
            " ORDER BY id DESC LIMIT ?", (int(spec_id), int(limit)), fetchall=True) or []
        out = []
        for r in rows:
            d = dict(r)
            d.pop("resp_body_head", None)  # 纪律：只喂摘要，不喂响应原文
            out.append(d)
        return out
    except Exception:  # noqa: BLE001
        return []


def adjudicate_feedbacks(feedbacks: List[Dict[str, Any]], db: Any = None,
                         task_id: Optional[int] = None,
                         llm_enabled: bool = True,
                         max_llm_calls: int = 20) -> Dict[str, Any]:
    """对一批 I2 反馈做 LLM 二级判因（闭环接线入口）。

    只处理调用方传来的「模糊桶」（benchmark_cli 只传 hypothesis_defect 兜底项），
    规则能明确分桶的在调用方已处理。返回：
      {"classified": {hypothesis_id: {"failure_class","action","payload","reason",
                                       "verdict","source","confidence"}},
       "llm_calls": n, "llm_budget": max_llm_calls}
    LLM 调用数有硬上限（默认 20/轮），超预算的退回规则结论，控成本。
    """
    out: Dict[str, Any] = {"classified": {}, "llm_calls": 0, "llm_budget": max_llm_calls}
    for fb in feedbacks or []:
        if not isinstance(fb, dict):
            continue
        hid = str(fb.get("hypothesis_id") or fb.get("vulnerability_hash_v2") or "")
        if not hid:
            continue
        spec = _load_spec_row(db, task_id, hid) if task_id else {}
        packet = build_packet(
            spec=spec,
            attempts=_load_attempts(db, spec.get("id")),
            round_no=int(fb.get("round") or 1),
        )
        # feedback 自带的可观测事实补进 packet（status_code/read_state 等），
        # 让判因看到的是「运行时观测」而不是只有静态线索。
        for k in ("status_code", "iast_state", "read_state"):
            if fb.get(k) and not getattr(packet, k, ""):
                try:
                    setattr(packet, k, str(fb.get(k)))
                except Exception:  # noqa: BLE001
                    pass
        if str(fb.get("reason") or ""):
            packet.filter_spec = packet.filter_spec or {}
        allow_llm = llm_enabled and out["llm_calls"] < max_llm_calls
        d = decide(packet, llm_enabled=allow_llm)
        _src = d.get("source")
        if _src == "llm":
            out["llm_calls"] += 1
        # 按来源选映射表：规则有硬证据（oracle 正向/主动净化）⇒ 结论可信；
        # LLM 只采信「未打通的细分」，不采信结论翻转（见映射表注释）。
        _table = _RULE_VERDICT_TO_CLASS if _src == "rule" else _LLM_VERDICT_TO_CLASS
        out["classified"][hid] = {
            "failure_class": _table.get(d.get("verdict"), "hypothesis_defect"),
            "action": d.get("action"),
            "payload": d.get("payload") or "",
            "reason": d.get("reason") or "",
            "verdict": d.get("verdict"),
            "source": _src,
            "confidence": d.get("confidence"),
        }
    return out
