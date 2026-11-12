"""I2 裁决器。

职责：综合 A2 假说（findings）+ I1 观测（iast_events）+ D2 裁定，做覆盖率差集审计，
产出差集分类与反哺候选（净化器 + 新规则种子）。所有反哺动作走 RuleFeedback 人工 confirm
闸门（第三门），本模块只产出候选、绝不自动 confirm（禁止把运行时假象固化成永久规则）。

 差集语义：
1. 假说有、观测无（hypothesis_only）→ SAST 假阳性嫌疑；跨多次扫描稳定才降级 likely-false-positive
   或触发净化器白名单候选。
2. 观测有、假说无（observed_only）→ SAST 漏报；IAST 真实命中但无法对齐任何 SAST finding，
   即 SAST 规则未覆盖该 source→sink 路径，作为"新增规则"反哺种子。

 净化器反哺三门门槛（缺一不可）：
1. 同一净化器多次独立观测一致；
2. stackTrace 能定位到明确方法（类+方法+行号）；
3. RuleFeedback 人工 confirm 闸门（禁止自动入库）。
"""
import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.model_gateway import gateway_from_config
from src.core.proof_obligations import (
    apply_runtime_evidence,
    empty_taint_flow_hypothesis,
    residual_proof_gaps,
)
from src.core.exploit_spec import derive_flow_type, is_injection_family
from src.iast.canary import CanaryMatcher
from src.iast.orchestrator import (
    IastVerdict,
    STATE_ARRIVAL_SANITIZED,
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED,
    STATE_SINK_REACHED_PROBE,
    is_sink_reached,
)
from src.iast.sink_identity import iast_evidence_sink_reached_genuine
from src.infrastructure.db import Database

logger = logging.getLogger(__name__)


# 观测态强弱（与 correlation.py 一致）。
# 收口：必须含 sink-reached-probe —— 探针在 sink 现场的显式断言是最强证据，
# 历史实现漏掉它，导致 I2 覆盖率审计把 29 条已抵达事件判成「未观测」，
# hypothesis_only 虚高 → 大量「IAST 未观测到匹配 canary」的假反馈回灌 A2（闭环空转）。
_OBSERVED_STATES = ("arrived", "arrival-sanitized", "sink-reached", "sink-reached-probe")

# 五态 final_state
FINAL_CONFIRMED_ATTRIBUTABLE = "confirmed_attributable"
FINAL_RUNTIME_CONFIRMED = "runtime_confirmed"
FINAL_AMBIGUOUS = "ambiguous"
FINAL_NO_EVIDENCE = "no_evidence"
FINAL_FALSE_POSITIVE_SAST_ONLY = "false_positive_sast_only"
# 靶场不健康（可重试）：D1 重放因靶场 5xx/连接异常/环境探针未就绪而未能取得有效响应，
# 与 no_evidence（永久非漏洞）严格区分。闭环应把它当作「本轮未测出、可重试」，而非「无漏洞」。
FINAL_TARGET_UNHEALTHY = "target_unhealthy"
# 被防护拦截（WAF/拦截器/参数截断）：请求未到达漏洞点即被安全设备/过滤器阻断。
# 与 no_evidence 严格区分——它不代表「无漏洞」，而是「本次未能有效验证」，应重试或人工确认。
# rank 0（非正），不污染确认口径；只是把「被挡」从「干净」里摘出来。
FINAL_WAF_BLOCKED = "waf_blocked"


# 五态强弱序（强→弱），用于多 spec 裁决的合并取最强态。
# target_unhealthy 与 no_evidence 同列最弱（rank 0），但语义不同（可重试 vs 永久非漏洞）。
_FINAL_STATE_RANK = {
    FINAL_CONFIRMED_ATTRIBUTABLE: 4,
    FINAL_RUNTIME_CONFIRMED: 3,
    FINAL_AMBIGUOUS: 2,
    FINAL_FALSE_POSITIVE_SAST_ONLY: 1,
    FINAL_NO_EVIDENCE: 0,
    FINAL_TARGET_UNHEALTHY: 0,
    FINAL_WAF_BLOCKED: 0,
}


def _safe_str(obj: Any, limit: int = 2000) -> str:
    """把上下文对象安全地压成字符串（截断），避免把巨型上下文塞进 LLM prompt。"""
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    if len(s) > limit:
        s = s[:limit] + "...(truncated)"
    return s


def _cfg_flag(cfg: Any, dotted_key: str, default: bool) -> bool:
    """从 dict 里读一个布尔开关，兼容「点分键」与「嵌套字典」两种写法。

    I2 的 config 在两条构造路径上分别是根配置快照（嵌套）与局部投影（可能扁平），
    用点分键直接 ``cfg.get('agents.i2.x')`` 在嵌套形态下恒取不到（返 default），
    会静默把开关当成默认值 —— 这类「开关配了不生效」的坑本项目已踩过多次。
    """
    if not isinstance(cfg, dict):
        return default
    if dotted_key in cfg:
        value = cfg.get(dotted_key)
        return default if value is None else bool(value)
    node: Any = cfg
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return default if node is None else bool(node)


# ------------------------------------------------------------------ 纯法官（I1 / D2）#
# I1 监听器与 D2 校验器只做「这条 spec 是否符合要求」的判断（不论成败），
# 把结果全部交给 I2 裁决器；二者不做任何裁决动作。

@dataclass
class I1Verdict:
    """I1 监听器对单条 spec 的符合性判断（纯法官输出，不裁决可利用性）。"""
    hypothesis_id: str
    requirement_met: bool          # 污点是否按 A2 预测链到达 sink / 链路符合
    state: str
    chain_conforms: bool
    chain_conformance: Dict[str, Any] = field(default_factory=dict)
    matched_event_ids: List[int] = field(default_factory=list)
    confidence: str = "low"
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    flow_type: str = ""


@dataclass
class D2Verdict:
    """D2 校验器对单条 spec 结果点的有害性判断（纯法官输出，不裁决可利用性）。"""
    hypothesis_id: str
    requirement_met: bool          # 结果点是否确证有害（sink 到达 + D1 影响观测）
    harmful: bool
    sink_reached: bool
    confidence: str = "low"
    reason: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    # 离线 DAST 影响观测（D1 重放 reached/impact_observed），独立于 sink_reached。
    # 注入族（sql/ssrf/command...）本靶场 IAST 永不观测到 sink，确认只能来自离线 DAST 影响，
    # 故必须单独携带该信号，否则 _evidence_bundle 只认 d2.harmful（=sink_reached and reached=恒 False）
    # 会把真实 D1 影响丢掉，导致 Fix B 注入族离线确认分支（adjudicate_final_state:493）永不触发。
    dast_impact_observed: bool = False


@dataclass
class I2Decision:
    """I2 LLM 裁决器对单条 spec 的裁决。"""
    hypothesis_id: str
    final_state: str
    action: str                    # pass / re_correct / re_send / rollback_to_a2
    confirmed: bool
    confidence: str
    reason: str
    feedback_to_a2: Dict[str, Any] = field(default_factory=dict)
    # I2 把 IAST/DAST 运行时证据映射到 A2 同一组证明义务的结果
    proof_resolution: Dict[str, Any] = field(default_factory=dict)


class I1Judge:
    """I1 纯法官：只判断每条 spec 的污点传播是否符合 A2 预测链，结果全交 I2。"""

    def judge(self, per_hypothesis: Dict[str, "IastVerdict"]) -> List[I1Verdict]:
        verdicts: List[I1Verdict] = []
        for hid, v in (per_hypothesis or {}).items():
            state = getattr(v, "state", STATE_NO_ARRIVAL) or STATE_NO_ARRIVAL
            chain = getattr(v, "chain_conformance", None) or {}
            conforms = bool(chain.get("conforms"))
            # 历史实现 `state == STATE_SINK_REACHED` 漏掉探针显式断言态 sink-reached-probe，导致 I1 对
            # 「经 probe 抵达 sink」的假说误判 reached=False，仅依赖 I1 链路符合性兜底。
            reached = is_sink_reached(state)
            requirement_met = reached or conforms
            if conforms:
                chain_reason = "；I1 逐节点链路符合 A2 poc 链"
            elif chain:
                chain_reason = "；I1 链路不符 A2 poc 链"
            else:
                chain_reason = "；无逐节点链路证据"
            verdicts.append(I1Verdict(
                hypothesis_id=str(hid),
                requirement_met=requirement_met,
                state=state,
                chain_conforms=conforms,
                chain_conformance=dict(chain),
                matched_event_ids=list(getattr(v, "matched_event_ids", []) or []),
                confidence=getattr(v, "confidence", "low") or "low",
                reason=f"I1 监听：state={state}{chain_reason}",
                detail={"canary_state": getattr(v, "canary_state", ""), "degraded": getattr(v, "degraded", False)},
            ))
        return verdicts


class D2Judge:
    """D2 纯法官：只判断每条 spec 的结果点是否确证有害，结果全交 I2。"""

    def judge(self, per_hypothesis: Dict[str, "IastVerdict"], raw_dast_impact: Optional[Dict[str, Any]] = None) -> List[D2Verdict]:
        raw = raw_dast_impact or {}
        slices = raw.get("slices") or {}
        # attack_degraded=全部回放仅发 canary 探针；attack_degraded_any=至少一条降级。
        attack_degraded = bool(raw.get("attack_degraded"))
        attack_degraded_any = bool(raw.get("attack_degraded_any"))
        biz = raw.get("business_logic") or {}
        biz_confirmed = bool(biz.get("confirmed")) if isinstance(biz, dict) else False
        # 任务4 IAST 校验函数 hook：探针在 AccessDecisionManager.decide 处观测到「访问域对象但无
        # 对象级授权决策」= 授权机制缺失的语义确认（比响应差分更强）。
        authz_hook_confirmed = bool(biz.get("authz_hook_confirmed")) if isinstance(biz, dict) else False
        verdicts: List[D2Verdict] = []
        for hid, v in (per_hypothesis or {}).items():
            state = getattr(v, "state", STATE_NO_ARRIVAL) or STATE_NO_ARRIVAL
            # 取该 spec 的 D1 影响切片，无切片（单 spec 场景）则退回整段 D1 影响
            d1 = slices.get(str(hid)) or slices.get(hid) or raw
            reached = bool(d1.get("reached")) if isinstance(d1, dict) else False
            # 离线 DAST 影响观测：本靶场 IAST 永不到 sink（sink_reached=0），注入族确认只能来自
            # D1 重放「外部可观测影响」（reached / impact_observed）。该信号独立于 sink_reached，
            # 必须单独携带到 D2Verdict，供 _evidence_bundle 喂给 Fix B 注入族离线确认分支。
            impact_observed = bool((d1.get("impact_observed") or d1.get("reached"))) if isinstance(d1, dict) else False
            # 单一真相源：sink_reached 判定收口到 is_sink_reached（含探针显式断言态
            # sink-reached-probe）。历史实现用 `state == STATE_SINK_REACHED` 漏掉 probe 态，
            # 导致 D2 的 sink_reached_count 恒 0。
            sink_reached = is_sink_reached(state)
            harmful = sink_reached and reached

            # 降级门控：canary 只是身份串，它能到 sink 仅证明「可达」，不证明「有害」。
            # 业务族差分确认是例外——它没有走 canary 通道，差分/授权 hook 结果本身就是攻击证据。
            if harmful and attack_degraded and not biz_confirmed:
                harmful = False
                conf = "low"
                reason = (
                    "D2 结果点核实：sink 到达且请求被处理，但本次回放为降级攻击"
                    "（A2 未产出真实 payload，D1 仅投放 canary 探针）。"
                    "canary 到达 sink 仅证明可达性，不构成有害性证据，不得判 harmful。"
                )
            elif harmful and attack_degraded_any and not biz_confirmed:
                conf = "medium"
                reason = (
                    f"D2 结果点核实：sink 到达且请求被处理（status={d1.get('status_code')}），"
                    "但部分 spec 为降级攻击（仅 canary 探针），证据强度降级为 medium。"
                )
            elif biz_confirmed:
                # 业务族（BOLA/BFLA/RACE...）不走 canary→sink，其确认来自差分/授权 hook，
                # 因此 biz_confirmed 本身即攻击证据，独立于 sink 可达性 → 直接判 harmful。
                harmful = True
                conf = str(biz.get("confidence") or "high")
                if authz_hook_confirmed:
                    reason = (
                        f"D2 结果点核实：业务差分 + 探针授权 hook 语义确认（{biz.get('category', 'business')}）——"
                        f"访问域对象 {biz.get('authz_hook_objects') or '该域对象'} 时未执行对象级归属校验，"
                        "鉴权机制缺失，结果点有害（机制级证据，强于响应差分）。"
                    )
                else:
                    reason = (
                        f"D2 结果点核实：业务差分确认（{biz.get('category', 'business')}），"
                        "攻击者账户成功访问受害者资源，结果点有害。"
                    )
            elif harmful:
                conf = "high"
                reason = f"D2 结果点核实：sink 到达且请求被处理（status={d1.get('status_code')}），真实攻击 payload 已投放，结果点被打中/有害"
            elif sink_reached and not reached:
                conf = "medium"
                reason = "D2 结果点核实：sink 到达但 D1 未证 reached（传输中断/超时），结果点仍视为打中"
            else:
                conf = "low"
                reason = f"D2 结果点核实：I1 state={state}，结果点未确证有害"
            detail = {"dast_status_code": d1.get("status_code"), "dast_body": (d1.get("body") or "")[:500]}
            detail["attack_degraded"] = attack_degraded
            detail["attack_degraded_any"] = attack_degraded_any
            detail["attack_payload_used"] = raw.get("attack_payload_used", "")
            detail["business_logic_confirmed"] = biz_confirmed
            detail["authz_hook_confirmed"] = authz_hook_confirmed
            if authz_hook_confirmed:
                detail["authz_hook_objects"] = biz.get("authz_hook_objects") or []
            if isinstance(biz, dict) and biz:
                detail["business_logic"] = biz
            verdicts.append(D2Verdict(
                hypothesis_id=str(hid),
                requirement_met=harmful,
                harmful=harmful,
                sink_reached=sink_reached,
                confidence=conf,
                reason=reason,
                detail=detail,
                dast_impact_observed=impact_observed,
            ))
        return verdicts


def _i2_final_state_reason(iast_state: str, dast_impact: bool) -> str:
    base = {
        STATE_SINK_REACHED: "IAST SINK_HIT：canary 身份段+元字符段均到达 sink（保真+可达）",
        STATE_ARRIVAL_SANITIZED: "IAST：canary 身份段到达 sink 但元字符被净化（仅部分可达）",
        STATE_NO_ARRIVAL: "IAST：窗口内未观测到匹配 canary 的事件",
    }.get(iast_state, f"IAST state={iast_state}")
    if dast_impact:
        return base + "；DAST 观察到影响证据"
    return base + "；DAST 未证影响"


def _chain_reason_suffix(chain: Dict[str, Any]) -> str:
    """把 I1 逐节点链路符合性追加进裁决理由。"""
    if not chain:
        return ""
    if chain.get("conforms"):
        unv = chain.get("unverifiable") or 0
        if unv:
            return f"；I1 链路符合 A2 poc（{unv} 个 transform 节点因探针未上报路径而不可证伪）"
        return "；I1 逐节点链路符合 A2 poc 链"
    missing = chain.get("missing") or []
    if missing:
        return f"；I1 链路不符：确凿缺失节点 {missing}"
    return "；I1 链路符合性未知"


def parse_stack_frames(stack_trace: str) -> List[Dict[str, Any]]:
    """从 stack trace 文本解析方法帧，返回 [{class, method, file, line}]。

    兼容 Java 风格 `at com.foo.Bar.method(Bar.java:42)` 与 Python 风格
    `File "x.py", line 42, in method`。
    """
    frames: List[Dict[str, Any]] = []
    for m in re.finditer(r"at\s+([\w.$]+)\.(\w+)\(([\w.$]+\.\w+):(\d+)\)", stack_trace or ""):
        frames.append({"class": m.group(1), "method": m.group(2), "file": m.group(3), "line": int(m.group(4))})
    for m in re.finditer(r'File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(\w+)', stack_trace or ""):
        frames.append({"class": "", "method": m.group(3), "file": m.group(1), "line": int(m.group(2))})
    return frames


class I2Adjudicator:
    """I2 裁决器：覆盖率差集审计 + 反哺候选。

    rule_feedback：可选 RuleFeedbackService，提供 record_candidate 落库候选（第三门人工 confirm
    不在此调用）。缺省 None 时 harvest_feedback 只返回候选清单、不落库（便于离线测试）。
    min_observations：净化器反哺门1 的"多次独立观测一致"阈值（默认 2）。
    stability_threshold： 跨扫描稳定阈值——同一 hypothesis_only 跨该数量任务仍无观测 → likely-false-positive（默认 2）。
    """

    def __init__(
        self,
        db: Optional[Database] = None,
        rule_feedback: Any = None,
        min_observations: int = 2,
        stability_threshold: int = 2,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        self.rule_feedback = rule_feedback
        self.min_observations = max(1, int(min_observations or 2))
        self.stability_threshold = max(1, int(stability_threshold or 2))
        self.config = config or {}
        self._gateway = None

    # ------------------------------------------------------------------ 覆盖率审计 #
    def audit_coverage(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> Dict[str, Any]:
        """ 覆盖率审计：SAST 假说集 ⊖ IAST 观测集 → matched / hypothesis_only / observed_only。

        §用户需求④：I2 只审计「有对应 trigger_spec、即真正经 D1 发放过攻击流量的 A2 假说」，
        不把全部 findings
        计入 hypotheses——那些从没被 D1 验证过，判为 false-positive 是误判、纯属浪费。
        trigger_specs 就是 D1 的发放清单；以「本任务 findings 中、且存在 trigger_spec 的哈希」
        作为 I2 审计对象（与 spec 取交集可顺带排除跨任务污染的孤儿 spec）。
        """
        findings = self._load_findings(workspace_id, task_id)
        all_finding_hashes = {f["vulnerability_hash_v2"] for f in findings if f.get("vulnerability_hash_v2")}

        specs = self._load_specs(workspace_id, task_id)
        hash_to_family = {
            (s.get("vulnerability_hash_v2") or ""): (s.get("family") or s.get("category") or "")
            for s in specs
        }
        canary_to_hash: Dict[str, str] = {}
        hash_to_canary: Dict[str, str] = {}
        for s in specs:
            # 用身份段（s4st41<16hex>）做键，与 correlation.py / iast_events.canary 对齐；
            # taint_marker 形如「身份段 + 元字符段」，事件上报的 canary 仅含身份段，故不能拿整串做键。
            ident = CanaryMatcher.find_identity(s.get("taint_marker") or "")
            if ident:
                canary_to_hash[ident] = s.get("vulnerability_hash_v2") or ""
                hash_to_canary[s.get("vulnerability_hash_v2") or ""] = ident

        # I2 审计对象 = 本任务 findings 中存在 trigger_spec 的哈希（即 D1 实际发放过攻击流量的假说）。
        # 排除：70 条 SCA（无 spec）+ 未解析出可路由端点的 SAST 命中（无 spec）+ 跨任务污染的孤儿 spec。
        hypothesis_hashes = set(hash_to_canary.keys()) & all_finding_hashes
        excluded_no_trigger_spec = len(all_finding_hashes - hypothesis_hashes)

        events = self._load_observed_events(workspace_id, task_id)
        observed_hashes: set = set()
        observed_only: List[Dict[str, Any]] = []
        for e in events:
            h = canary_to_hash.get(e.get("canary") or "")
            if h and h in hypothesis_hashes:
                observed_hashes.add(h)
            else:
                observed_only.append(self._event_summary(e))

        matched = sorted(hypothesis_hashes & observed_hashes)
        hypothesis_only = sorted(hypothesis_hashes - observed_hashes)

        #  跨扫描稳定性：hypothesis_only 跨多次扫描稳定 → likely-false-positive
        stability = self._stability_map(hypothesis_only, workspace_id)
        hypothesis_only_detail = [
            {
                "vulnerability_hash_v2": h,
                "stability_count": stability.get(h, 1),
                "status": "likely-false-positive" if stability.get(h, 0) >= self.stability_threshold else "pending",
            }
            for h in hypothesis_only
        ]

        #  完整 schema：每假说的 evidence_chain（SAST→DAST→IAST→D2）+ included_in_report
        per_hypothesis = []
        for h in matched + hypothesis_only:
            per_hypothesis.append({
                "vulnerability_hash_v2": h,
                "flow_type": derive_flow_type(hash_to_family.get(h, "")),
                "taint_marker": hash_to_canary.get(h, ""),
                "evidence_chain": self._evidence_chain(h, workspace_id),
                "included_in_report": h in matched,  # 仅 matched 进入报告
                "sast_hypothesis": {"vulnerability_hash_v2": h},
                "d2_verdict": "sink-reached" if h in matched else "no-arrival",
            })
        feedback = {
            "sanitizer_candidate_count": 0,  # harvest_feedback 时填充
            "coverage_diff": {
                "matched": matched,
                "hypothesis_only": hypothesis_only,
                "observed_only": observed_only,
            },
        }

        # 源=scan_tasks.summary_json.stage_results.a2_poc.missing_route_watch（benchmark_cli 落盘）。
        try:
            _mrow = self.db.execute(
                "SELECT summary_json FROM scan_tasks WHERE id=?", (task_id,), fetchone=True
            ) if task_id is not None else None
            _watch = {}
            if _mrow and _mrow.get("summary_json"):
                import json as _json
                _stages = (_json.loads(_mrow["summary_json"]) or {}).get("stage_results") or {}
                _watch = ((_stages.get("a2_poc") or {}).get("missing_route_watch")) or {}
        except Exception:
            _watch = {}
        return {
            "workspace_id": workspace_id,
            "task_id": task_id,
            "stats": {
                "spec_count": len(specs),
                "total_hypotheses": len(hypothesis_hashes),
                "excluded_no_trigger_spec": excluded_no_trigger_spec,
                "matched": len(matched),
                "hypothesis_only": len(hypothesis_only),
                "observed_only": len(observed_only),
                "likely_false_positive": sum(1 for x in hypothesis_only_detail if x["status"] == "likely-false-positive"),
            },
            "matched": matched,
            "hypothesis_only": hypothesis_only,
            "hypothesis_only_detail": hypothesis_only_detail,
            "observed_only": observed_only,
            "per_hypothesis": per_hypothesis,
            "feedback": feedback,
            "missing_route_watch": _watch,
        }

    # ------------------------------------------------------------------ 反哺候选 #
    def harvest_feedback(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> Dict[str, Any]:
        """从差集提炼反哺候选，过前两门门槛；record_candidate 落库（第三门人工 confirm 不在此自动执行）。"""
        sanitizer_candidates = self._sanitizer_candidates(workspace_id)
        rule_seeds = self._rule_seed_candidates(workspace_id, task_id)

        recorded: List[Dict[str, Any]] = []
        if self.rule_feedback is not None:
            for c in sanitizer_candidates + rule_seeds:
                recorded.append(self.rule_feedback.record_candidate(
                    kind=c["kind"],
                    pattern=c["pattern"],
                    language=c.get("language", ""),
                    family=c.get("family", ""),
                    confidence="candidate",
                    workspace_id=workspace_id,
                ))
        return {
            "sanitizer_candidates": sanitizer_candidates,
            "rule_seed_candidates": rule_seeds,
            "recorded": recorded,
        }

    def summarize_closed_loop(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> Dict[str, Any]:
        """I2 闭环裁决汇总：覆盖率差集 + 反哺候选 +  完整 schema。"""
        audit = self.audit_coverage(workspace_id, task_id)
        feedback = self.harvest_feedback(workspace_id, task_id)
        audit["feedback"]["sanitizer_candidate_count"] = len(feedback["sanitizer_candidates"])
        return {
            "audit": audit,
            "feedback": feedback,
            "final_state_summary": self._final_state_summary(audit),
        }

    # ------------------------------------------------------------------ 五态综合裁定#
    @staticmethod
    def adjudicate_final_state(*, iast_evidence: Optional[Dict[str, Any]], dast_impact_evidence: Optional[Dict[str, Any]], d2_verdict: Optional[Dict[str, Any]] = None, family: Optional[str] = None, attempts: Optional[List[Dict[str, Any]]] = None, endpoint: str = "") -> Dict[str, Any]:
        """ I2 综合裁定：综合 I1 监听（iast_evidence.state + chain_conformance）+ D2 结果点核实
        （d2_verdict.harmful）+ D1 影响侧（dast_impact_evidence），出五态 final_state（3.18）。

        I2 作为总开关收集 I1 与 D2 的结论：D2 结果点有害(d2_verdict.harmful) 与 D1 影响观测
        （dast_impact）任一为真且 I1 到 sink → 最强态 confirmed_attributable。
        纯逻辑、不碰 DB。"""
        iast_evidence = iast_evidence or {}
        dast_impact_evidence = dast_impact_evidence or {}
        d2_verdict = d2_verdict or {}
        iast_state = iast_evidence.get("state", "")
        # 靶场不健康（可重试）标记：来自 D1 重放实际观测（5xx/连接异常/环境探针未就绪）。
        # 与 no_evidence（永久非漏洞）严格区分——有该标记且无其他证据时，结论应为
        # target_unhealthy 而非 no_evidence，使闭环可重试而非误判「无漏洞」。
        target_unhealthy = bool(dast_impact_evidence.get("target_unhealthy"))
        # waf_blocked 与 target_unhealthy 并列 rank 0，但语义不同（靶场健康但请求被安全策略拦截）。
        # 优先于 target_unhealthy 与 no_evidence——只要观测到拦截特征，结论即 waf_blocked（可重试/人工确认）。
        waf_blocked = bool(dast_impact_evidence.get("waf_blocked"))
        no_ev = FINAL_WAF_BLOCKED if waf_blocked else (FINAL_TARGET_UNHEALTHY if target_unhealthy else FINAL_NO_EVIDENCE)
        iast_conf = iast_evidence.get("confidence", "low")
        dast_impact = bool(dast_impact_evidence.get("impact_observed"))
        d2_harmful = bool(d2_verdict.get("harmful"))
        chain = iast_evidence.get("chain_conformance") or {}
        stable_disproof = bool(dast_impact_evidence.get("stable_disproof"))
        # 它到达 sink 只证明「可达」，不证明「可利用」。此前本函数完全不感知该字段，
        # 导致降级攻击照走 dast_impact=True → 直接落到最强态 confirmed_attributable（假阳性）。
        attack_degraded = bool(dast_impact_evidence.get("attack_degraded"))
        attack_degraded_any = bool(dast_impact_evidence.get("attack_degraded_any"))
        biz = dast_impact_evidence.get("business_logic") or {}
        biz_confirmed = bool(biz.get("confirmed")) if isinstance(biz, dict) else False
        # 任务4 IAST 校验函数 hook：探针授权盲点语义确认（比响应差分更强的机制级证据）。
        authz_hook_confirmed = bool(biz.get("authz_hook_confirmed")) if isinstance(biz, dict) else False
        # 设计一①：探针在 sink 现场显式断言 SINK_REACHED（sink-reached-probe）= canary 确证位于危险函数
        # 实参，即「攻击者可控数据抵达 sink」的强证据。即便 attack_degraded（D1 仅投 canary 探针）也判有害，
        # 不降级回滚 A2。仅当「降级且非业务确认且非探针显式断言」时才降级。
        probe_asserted = (iast_state == STATE_SINK_REACHED_PROBE)
        degraded_no_attack = attack_degraded and not biz_confirmed and not probe_asserted

        # §注入族离线裁决（本靶场 iast_observed=0，确认只能来自离线 DAST 影响）：
        # 对注入型 sink（sql/ssrf/command/path/deserialization...），D1 离线重放观测到「外部可观测影响」
        # （impact_observed=True，如 SQL 报错 / 时间差 / 命令回显 / 文件读出 / 反序列化异常）即等价于
        # 「攻击者可控数据抵达 sink 并产生可利用效果」，即便 IAST 探针未观测到 canary 到 sink（本靶场
        # iast_observed=0）甚至 D1 仅投 canary（attack_degraded），该可观测影响本身就是可利用的强证据。
        # 故注入族 + 离线 DAST 影响 + 未到 sink → 直接判 confirmed_attributable（有真实可观测影响），
        # 不走 ambiguous 兜底，也不因降级而回滚 A2。仅当 stable_disproof 为真时判误报（优先于确认）。
        # 注意：仅在 impact_observed（有可观测影响）时确认；若仅 reached 无影响仍走 ambiguous（证据不足）。
        # 此分支仅覆盖注入族——业务逻辑族走 biz_confirmed 分支、暴露/其它族不享受此离线确认，保持判定口径单一。
        is_inj = is_injection_family(family or "")
        # sink 身份校验下沉到 I2 终态准入（此前本函数只判 is_sink_reached(iast_state)
        # 这个纯状态串，而 D2 的 _verify_sink_result 走 iast_evidence_sink_reached_genuine
        # 会剔除框架噪声 sink）。两条判据不一致 ⇒ 同一 spec 出现
        # 「运行时未确证有害（噪声 sink）」却「spec 层 confirmed_exploitable」的打架。
        # 本函数签名早已接收 family 但一直未消费，这里补上，令 I2 与 D2/correlation 三处同源。
        # fail-open：证据里无 sink_file 时该函数返回 True（视为真实），不误杀迟到升级。
        genuine_sink = iast_evidence_sink_reached_genuine(iast_evidence, family or "")
        # 仅当「确实到了 sink」且「落点被判非真 sink」时才是矛盾态（噪声 sink 逃逸）。
        noise_sink_reached = is_sink_reached(iast_state) and not genuine_sink
        if is_inj and dast_impact and not is_sink_reached(iast_state):
            if stable_disproof:
                return {
                    "final_state": FINAL_FALSE_POSITIVE_SAST_ONLY,
                    "confirmed": False,
                    "confidence": "low",
                    "judge_reason": (
                        "注入族离线 DAST 观测到影响，但存在稳定反证（stable_disproof），判误报。"
                    ),
                    "matched_outcomes": [],
                    "iast_evidence": iast_evidence,
                    "dast_impact_evidence": dast_impact_evidence,
                    "d2_verdict": d2_verdict,
                    "chain_conformance": chain,
                    "attack_degraded": attack_degraded,
                }
            # 此前「注入族 + 离线 DAST 影响 + 未到 sink」直接判 confirmed_attributable，
            # 该分支沦为精确率杀手：降级攻击（仅 canary 探针）+ 404 响应上的「影响」也升确认。
            # 收紧后：降级攻击且探针无 sink 证据 → 最多 ambiguous（进 suspicious 档，
            # 交 rollback_to_a2 补真实 payload），不再计 confirmed；仅「真实 payload 攻击
            # （非降级）+ 可观测影响」才保留离线确认通道。
            # （d2_harmful=True，动态确认强证据），即便本次为降级攻击（D1 仅投 canary），
            # 也确认可利用——降级是 payload 质量限制，不是漏洞存在性限制；D2 有害判定
            # 不依赖 404 上的弱影响，故不会重新打开「404 伪影响」这个精确率漏洞。
            # 落入此 carve-out 的假说走下方 FINAL_CONFIRMED_ATTRIBUTABLE 分支（保留降级标注）。
            if attack_degraded and not d2_harmful:
                return {
                    "final_state": FINAL_AMBIGUOUS,
                    "confirmed": False,
                    "confidence": "low",
                    "judge_reason": (
                        "注入族离线 DAST 观测到影响，但本次为降级攻击（D1 仅投 canary 探针）"
                        "且 I1 未观测到污点到达 sink——影响证据不足以支撑可利用确认"
                        "（D2 收紧：confirmed 需 IAST sink 证据或真实 payload 攻击影响），"
                        "降级为可疑待补证，交 A2 补造真实 payload 重放。"
                    ),
                    "matched_outcomes": [],
                    "iast_evidence": iast_evidence,
                    "dast_impact_evidence": dast_impact_evidence,
                    "d2_verdict": d2_verdict,
                    "chain_conformance": chain,
                    "attack_degraded": attack_degraded,
                }
            reason = (
                "注入族离线 DAST 重放观测到外部可观测影响（impact_observed），该影响本身即攻击者可控数据"
                "抵达 sink 并产生可利用效果的证据（本靶场 IAST 运行时观测为 0），故确认可利用。"
            )
            if attack_degraded:
                reason += (
                    "；本次为降级攻击（D1 仅投 canary 探针），但离线 DAST 影响已独立构成利用证据，不回滚 A2。"
                )
            return {
                "final_state": FINAL_CONFIRMED_ATTRIBUTABLE,
                "confirmed": True,
                "confidence": "medium",
                "judge_reason": reason,
                "matched_outcomes": [],
                "iast_evidence": iast_evidence,
                "dast_impact_evidence": dast_impact_evidence,
                "d2_verdict": d2_verdict,
                "chain_conformance": chain,
                "attack_degraded": attack_degraded,
            }

        if degraded_no_attack:
            # 降级攻击：保留「确实到达 sink」的运行时价值，但不确认可利用，
            # 交由 A2 补造真实 payload 后重跑（见 decide_next_action 的 rollback_to_a2）。
            if is_sink_reached(iast_state) or dast_impact or d2_harmful:
                final_state = FINAL_AMBIGUOUS
            elif stable_disproof:
                final_state = FINAL_FALSE_POSITIVE_SAST_ONLY
            else:
                final_state = no_ev
            return {
                "final_state": final_state,
                "confirmed": False,
                "confidence": "low",
                "judge_reason": (
                    _i2_final_state_reason(iast_state, dast_impact or d2_harmful)
                    + "；但本次为降级攻击（A2 未产出真实 payload，D1 仅投放 canary 探针），"
                    "canary 到达 sink 仅证可达性，不足以确认可利用，按不明确处理并回灌 A2 补造 payload。"
                ),
                "matched_outcomes": [],
                "iast_evidence": iast_evidence,
                "dast_impact_evidence": dast_impact_evidence,
                "d2_verdict": d2_verdict,
                "chain_conformance": chain,
                "attack_degraded": True,
            }

        if biz_confirmed:
            # 业务族（BOLA/BFLA/RACE...）不走 canary→sink，其确认来自响应差分 / 探针授权 hook
            # 语义确认，本身就是攻击证据，独立于 sink 可达性 → 直接判最强态。
            # 任务4 IAST 校验函数 hook：authz_hook_confirmed 是机制级证据（探针在
            # AccessDecisionManager.decide 字节码处证明「访问域对象但无对象级归属校验」）。
            final_state = FINAL_CONFIRMED_ATTRIBUTABLE
            confirmed = True
            reason = _i2_final_state_reason(iast_state, dast_impact or d2_harmful) + _chain_reason_suffix(chain)
            if authz_hook_confirmed:
                reason += (
                    f"；业务差分 + 探针授权 hook 语义确认（{biz.get('category', 'business')}）："
                    f"访问域对象 {biz.get('authz_hook_objects') or '该域对象'} 时未执行对象级归属校验，"
                    "鉴权机制缺失（机制级证据，强于响应差分）→ confirmed_attributable。"
                )
            else:
                reason += (
                    f"；业务差分确认（{biz.get('category', 'business')}）："
                    "攻击者账户成功访问受害者资源 → confirmed_attributable。"
                )
            if attack_degraded_any:
                reason += "；注意：部分 spec 为降级攻击（仅 canary 探针），但业务族确认已独立构成攻击证据。"
            return {
                "final_state": final_state,
                "confirmed": confirmed,
                "confidence": "high" if authz_hook_confirmed else (biz.get("confidence") or "high"),
                "judge_reason": reason,
                "matched_outcomes": [],
                "iast_evidence": iast_evidence,
                "dast_impact_evidence": dast_impact_evidence,
                "d2_verdict": d2_verdict,
                "chain_conformance": chain,
                "attack_degraded": attack_degraded,
                "attack_degraded_any": attack_degraded_any,
                "authz_hook_confirmed": authz_hook_confirmed,
                "business_logic_confirmed": biz_confirmed,
            }

        if noise_sink_reached and not biz_confirmed:
            # canary 抵达的只是框架噪声 sink（响应写入 / 序列化 / 模板渲染，且非 XSS/SSTI 族），
            # 该「抵达」不构成本族真实漏洞证据。降为不明确并落明确 reason，绝不确认可利用——
            # 与 _verify_sink_result 的 harmful=False 保持同源，消除两层打架。
            return {
                "final_state": FINAL_AMBIGUOUS,
                "confirmed": False,
                "confidence": "low",
                "judge_reason": (
                    f"canary 抵达 sink 态（{iast_state}），但落点被判为框架噪声 sink"
                    f"（非本族真实危险函数，且非 XSS/SSTI 族——该族响应写入本身即 sink），"
                    f"「抵达」不构成本族漏洞证据，降为不明确待补证；"
                    f"与 D2 结果点核实（harmful=False）口径一致。"
                ),
                "matched_outcomes": [],
                "iast_evidence": iast_evidence,
                "dast_impact_evidence": dast_impact_evidence,
                "d2_verdict": d2_verdict,
                "chain_conformance": chain,
                "attack_degraded": attack_degraded,
                "attack_degraded_any": attack_degraded_any,
                "noise_sink_rejected": True,
            }

        # 注意：_harm_note 必须在分支**外**初始化——此前只在 is_sink_reached 分支里赋值，
        # 导致所有「非 sink-reached」路径（arrival_sanitized / no_arrival，占多数）走到
        # 下面的 reason 拼接时抛 UnboundLocalError，直接崩掉整个裁定（被全量单测抓出）。
        _harm_note = ""
        # 必须与 d2_harmful / dast_impact 同级参与准入 —— 否则它永远进不了下面的
        # harm_evidence 评估分支（原实现只在「已有影响证据」时才调 evaluate，
        # 而 oracle 恰恰是用来**产生**影响证据的，形成死循环）。
        # 实测 本轮/urlRedirect/redirect（location_reflect）与
        # /path_traversal/vul（file_signature）两条 oracle=exploitable 都因此落到
        # FINAL_RUNTIME_CONFIRMED（仅到达），随后被 D2 的「到达≠可利用」降级砍掉。
        _oracle_positive = (
            str(iast_evidence.get("oracle_state") or "") == "exploitable"
            and bool(str(iast_evidence.get("oracle_signal") or "").strip())
        )
        if is_sink_reached(iast_state):
            # I1 到 sink +（D2 结果点有害 或 D1 影响观测 或 行为 oracle 正向）→ 最强态
            # 只有 harm_absent 才降级；harm_unknown（证据不足/族未覆盖）保持原判据，避免误伤
            # 靠 canary 到达确认的真漏洞（462 的 TP 78 里仅 16 个有 oracle 正向信号）。
            if d2_harmful or dast_impact or _oracle_positive:
                try:
                    from src.iast import harm_evidence as _he
                    _harm = _he.evaluate(
                        family, iast_evidence=iast_evidence,
                        dast_impact_evidence=dast_impact_evidence, d2_verdict=d2_verdict,
                        attempts=attempts,
                        oracle_state=str(iast_evidence.get("oracle_state") or ""),
                        oracle_signal=str(iast_evidence.get("oracle_signal") or ""),
                        endpoint=str(endpoint or ""))
                except Exception:  # noqa: BLE001  fail-open：判据增强失败绝不改判
                    _harm = {"verdict": "harm_unknown", "kind": "evaluator_error", "detail": ""}
                if _harm.get("verdict") == "harm_absent":
                    final_state = FINAL_AMBIGUOUS
                    _harm_note = (
                        "；但族特有有害证据缺失（%s）：%s ⇒ 可达不等于有害，降级为不明确待补证"
                        % (_harm.get("kind"), _harm.get("detail"))
                    )
                else:
                    final_state = FINAL_CONFIRMED_ATTRIBUTABLE
            else:
                final_state = FINAL_RUNTIME_CONFIRMED
        elif iast_state == STATE_ARRIVAL_SANITIZED:
            final_state = FINAL_AMBIGUOUS if (dast_impact or d2_harmful) else no_ev
        elif dast_impact or d2_harmful:
            final_state = FINAL_AMBIGUOUS
        elif stable_disproof:
            final_state = FINAL_FALSE_POSITIVE_SAST_ONLY
        else:
            final_state = no_ev

        confirmed = final_state in (FINAL_CONFIRMED_ATTRIBUTABLE, FINAL_RUNTIME_CONFIRMED)
        reason = _i2_final_state_reason(iast_state, dast_impact or d2_harmful) + _chain_reason_suffix(chain) + _harm_note
        # 部分降级：确有真 payload 投放（故可确认），但混有仅 canary 的弱证据 spec，需显式标注，
        # 避免调用方把「部分真打」与「全部真打」当成同一证据强度。
        if attack_degraded_any and not biz_confirmed:
            reason += "；注意：部分 spec 为降级攻击（仅 canary 探针），该部分证据强度较弱"
        return {
            "final_state": final_state,
            "confirmed": confirmed,
            "confidence": iast_conf if is_sink_reached(iast_state) else "low",
            "judge_reason": reason,
            "matched_outcomes": [],
            "iast_evidence": iast_evidence,
            "dast_impact_evidence": dast_impact_evidence,
            "d2_verdict": d2_verdict,
            "chain_conformance": chain,
            "attack_degraded": False,
            "attack_degraded_any": attack_degraded_any,
        }

    @staticmethod
    def decide_next_action(*, iast_evidence: Optional[Dict[str, Any]], d2_verdict: Optional[Dict[str, Any]], dast_impact_evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """I2 控制回路（总开关）：根据 I1/I2/D2 结论决定下一步。

        - pass：I1 逐节点链路符合 A2 poc 且 D2 确认结果点有害 → 通过，无需动作。
        - re_correct：I1 到 sink 但 poc 链有节点未命中 → A2 猜测链路与实际不符，产出修正提示供 A2 修正 poc 再跑。
        - re_send：D1 重放到达目标但 I1 未观测到 canary（编码/位置/时机问题）→ 重发修正参数。
        """
        iast_evidence = iast_evidence or {}
        d2_verdict = d2_verdict or {}
        dast = dast_impact_evidence or {}
        iast_state = iast_evidence.get("state", "")
        # 设计一①：探针显式断言 SINK_REACHED 即强证据，降级攻击不回滚 A2。
        probe_asserted = (iast_state == STATE_SINK_REACHED_PROBE)
        chain = iast_evidence.get("chain_conformance") or {}
        conforms = bool(chain.get("conforms"))
        missing = chain.get("missing") or []
        d1_reached = bool(dast.get("reached"))

        if is_sink_reached(iast_state) and missing:
            # 确有「确凿缺失」节点（非 unverifiable）→ A2 猜测链路与实际不符，需修正 poc
            return {
                "action": "re_correct",
                "reason": "I1 到达 sink 但 poc 链存在确凿缺失节点，A2 猜测链路与实际不符，需修正 poc 后重跑",
                "correction_hint": {
                    "missing_nodes": missing,
                    "observed_frames": chain.get("observed_frames", []),
                    "per_node": chain.get("per_node", []),
                },
                "retry": False,
            }
        if d1_reached and iast_state in (STATE_NO_ARRIVAL,):
            return {
                "action": "re_send",
                "failure_class": "param_not_arrived",
                "reason": "D1 重放到达目标但 I1 未观测到 canary（可能编码/位置/时机问题），建议重发修正参数",
                "correction_hint": {
                    "dast_status": dast.get("status_code"),
                    "dast_body": (dast.get("body", "") or "")[:300],
                },
                "retry": True,
            }
        # 这不是 D1 发得不对，重发同一条 canary 毫无意义——必须回灌 A2 补造真实攻击 payload 再跑。
        attack_degraded = bool(dast.get("attack_degraded"))
        biz = dast.get("business_logic") or {}
        biz_confirmed = bool(biz.get("confirmed")) if isinstance(biz, dict) else False
        # 设计一①：探针显式断言 SINK_REACHED（sink-reached-probe）= canary 确证位于 sink 实参，
        # 即便降级攻击也确认有害，不回滚 A2。
        if attack_degraded and not biz_confirmed and not probe_asserted:
            return {
                "action": "rollback_to_a2",
                "reason": (
                    "D1 本次为降级攻击（A2 未产出真实 payload，D1 仅投放 canary 探针），"
                    "需 A2 补造真实攻击 payload 后重跑；重发同一条 canary 无法提升证据强度。"
                ),
                "correction_hint": {
                    "degraded": True,
                    "need_real_payload": True,
                    "dast_status": dast.get("status_code"),
                },
                "retry": False,
            }
        # 攻击被 WAF / 防护策略拦截：sink 可能根本没收到攻击，
        # 须升级 payload 变体（编码/替代语法）绕过，而非回滚 A2 重写假说。归入运行时观测失败，
        # 由重放侧 decision 表（_FIVE_CLASS_ACTIONS.blocked → escalate_variant）处理。
        waf_blocked = bool(dast.get("waf_blocked"))
        if waf_blocked and not (probe_asserted and bool(d2_verdict.get("harmful"))):
            return {
                "action": "re_send",
                "failure_class": "blocked",
                "reason": "攻击请求被 WAF/防护策略拦截（dast.waf_blocked=True），需升级 payload 变体（URL 编码/替代语法/双重编码）绕过拦截",
                "correction_hint": {"waf_blocked": True, "dast_status": dast.get("status_code")},
                "retry": True,
            }
        if conforms and d2_verdict.get("harmful"):
            return {"action": "pass", "reason": "I1 逐节点链路符合 A2 poc 且 D2 确认结果点有害，统一链路通过", "correction_hint": {}, "retry": False}
        if iast_state in (STATE_NO_ARRIVAL,) and not (bool(dast.get("impact_observed")) or bool(dast.get("business_logic_confirmed"))):
            # 窗口内 I1 从未观测到 canary 到达 sink、且 D1 也未证 reached、且无任何离线 DAST 影响——
            # A2 假说的路由/参数/调用链与实际不符，属于「假说不符合」，按 回灌 A2 重新推导，
            # 而非无脑重发同一条重放。
            # 即注入族 Fix B 分支确认的已利用漏洞），则不应再回灌 A2 重推——否则已确认的漏洞会被
            # 丢进闭环二次回灌，稀释 rollback 信号、造成「闭环空转」。降级攻击（attack_degraded）
            # 仍需 rollback（A2 未造真实 payload），其分支在上方已先行返回，不受此处影响。
            # 供重放侧 decision 表走不同动作（repush_endpoint / inject_all_params）。
            _code = dast.get("status_code")
            _fc = "route_unreachable" if _code in (404, 410, 400) else "param_not_arrived"
            return {
                "action": "rollback_to_a2",
                "failure_class": _fc,
                "reason": "I1 窗口内未观测到 canary 到达 sink（D1 未证 reached、无离线 DAST 影响），A2 假说可能与实际不符，回灌 A2 重新推导",
                "correction_hint": {"http_status": _code},
                "retry": False,
            }
        # （sink-reached-probe 强证据），但 D2 未确认结果点有害。此时「到达」已成立，问题在确认力度，
        # 应升级 payload 变体 + 延长等待窗口重验，而非回滚 A2 重写假说（探针已证到达，说明假说路由正确）。
        # 注：XSS-7 反射类（探针未织 reflection sink）先归 param_not_arrived（见上方 NO_ARRIVAL 分支），
        # 待探针 XSS sink 覆盖后迁移至本类。
        if probe_asserted and not (conforms and bool(d2_verdict.get("harmful"))):
            return {
                "action": "re_send",
                "failure_class": "arrived_unconfirmed",
                "reason": "探针确证 canary 到达 sink 实参，但 D2 未确认结果点有害（到达未确认），建议升级变体/延长窗口重验",
                "correction_hint": {"probe_asserted": True, "d2_harmful": bool(d2_verdict.get("harmful"))},
                "retry": True,
            }
        return {"action": "pass", "reason": "默认通过（未触发明确修正条件）", "correction_hint": {}, "retry": False}

    # ------------------------------------------------------------------  I2 LLM 裁决器（AI 检测 review 制度）#
    def _get_gateway(self):
        if self._gateway is None:
            try:
                # self.config 在两条构造路径上都是局部投影 —— D2 facade 路径传的是
                # benchmark_cli 的 d2 agent_config（只有 api 子表）、API 路径
                # （api/dependencies.py）干脆不传 —— 直接喂给 gateway_from_config
                # 会取不到 llm.provider，判成 offline-heuristic，于是这条
                # i2-adjudication AI review 链路**从未真正跑过**。
                from src.core.model_gateway import resolve_llm_config
                self._gateway = gateway_from_config(resolve_llm_config(self.config))
            except Exception as _e:
                logger.warning("[I2] LLM 网关构造失败，回退规则式裁决：%s", _e)
                self._gateway = None
        return self._gateway

    def adjudicate(
        self,
        i1_verdicts: List["I1Verdict"],
        d2_verdicts: List["D2Verdict"],
        specs: Optional[List[Dict[str, Any]]] = None,
        vulnerability_context: Optional[Dict[str, Any]] = None,
        taint_flow_hypothesis: Optional[Dict[str, Any]] = None,
        dast_impact_evidence: Optional[Dict[str, Any]] = None,
    ) -> List["I2Decision"]:
        """ I2 LLM 裁决器（AI 检测 review 制度）：综合 I1 + D2 双重证据，以「条」为颗粒度裁定
        pass / re_correct / re_send / rollback_to_a2，并把不符合的假说回灌 A2 的修正提示写入
        feedback_to_a2。无可用 LLM（离线）或解析失败时回退 _adjudicate_rule_based，保证闭环不中断。

        taint_flow_hypothesis 为 A2 侧声称的污点流假说（source/sink/reachable/barrier_free +
        五个证明义务），I2 用它和运行时证据对账，产出结构化 proof_resolution 与残差 diff。
        """
        specs = specs or []
        #
        # 时间线：行为 oracle 的探测在 D1 完成（`d1_service._run_family_oracle`）并写
        # `trigger_specs.oracle_state/oracle_signal`；而这里收到的 `specs` 是上游传入的
        # **内存快照**（可能不含该列，也可能干脆是 A2 产出对象而非 DB 行）。
        #
        # 实测代价：连续 4 轮里 `oracle_state='exploitable'` 的 11 条只有 2~4 条参与裁决，
        # path_traversal(file_signature) / url_redirect(location_reflect) / ssrf(error_reflect)
        # 全部停在 sink_reached。前三次我改的都是「判据条件」（adjudicator 准入、d2_facade
        # 降级豁免、D2 重读），都没解决「数据压根没到判据手里」这一层。
        #
        # 这里用 self.db 在**最靠近裁决**的位置补齐，优先级：id（精确）> vhash（兜底）。
        # fail-open：查不到就按原快照判，绝不因补齐失败改判。
        if self.db is not None and specs:
            try:
                _by_id_map: Dict[str, Dict[str, Any]] = {}
                _ids = []
                for _s in specs:
                    try:
                        if _s.get("id"):
                            _ids.append(int(_s["id"]))
                    except Exception:
                        continue
                if _ids:
                    _ph = ",".join("?" * len(_ids))
                    for _r in (self.db.execute(
                            "SELECT id, oracle_state, oracle_signal FROM trigger_specs "
                            "WHERE id IN (%s)" % _ph, _ids, fetchall=True) or []):
                        _d = dict(_r)
                        _by_id_map[str(_d.get("id"))] = _d
                else:
                    # specs 不带 DB id 时按 vhash 兜底；同 vhash 可能跨任务重复，
                    # 取 id 最大（最新）的一条，避免读到历史任务的陈旧观测。
                    _vhs = [str(_s.get("vulnerability_hash_v2") or "") for _s in specs]
                    _vhs = [v for v in _vhs if v]
                    if _vhs:
                        _ph = ",".join("?" * len(_vhs))
                        for _r in (self.db.execute(
                                "SELECT id, vulnerability_hash_v2, oracle_state, oracle_signal "
                                "FROM trigger_specs WHERE vulnerability_hash_v2 IN (%s) "
                                "ORDER BY id ASC" % _ph, _vhs, fetchall=True) or []):
                            _d = dict(_r)
                            _by_id_map[str(_d.get("vulnerability_hash_v2"))] = _d
                _n = 0
                for _s in specs:
                    _d = (_by_id_map.get(str(_s.get("id"))) if _s.get("id")
                          else _by_id_map.get(str(_s.get("vulnerability_hash_v2") or "")))
                    if _d:
                        _s["oracle_state"] = _d.get("oracle_state") or ""
                        _s["oracle_signal"] = _d.get("oracle_signal") or ""
                        if _s["oracle_state"]:
                            _n += 1
                if _n:
                    logger.info("[I2] 从 DB 补齐 oracle 观测：%d/%d 条带信号", _n, len(specs))
                    print("[I2][oracle-fill] %d/%d 条带信号" % (_n, len(specs)), flush=True)
            except Exception as _oe:  # noqa: BLE001
                logger.warning("[I2] oracle 观测补齐失败（按原快照继续）：%s", _oe)
        spec_by_h = {str(s.get("vulnerability_hash_v2") or s.get("hypothesis_id")): s for s in specs}
        hypothesis = taint_flow_hypothesis
        if hypothesis is None:
            hypothesis = dict(vulnerability_context or {}).get("taint_flow_hypothesis") or None
        if hypothesis is None:
            hypothesis = empty_taint_flow_hypothesis()
        try:
            if _cfg_flag(self.config, "agents.i2.enable_llm_adjudication", True):
                gw = self._get_gateway()
                if gw is not None and not gw.is_offline:
                    decisions = self._adjudicate_llm(i1_verdicts, d2_verdicts, spec_by_h, vulnerability_context)
                    if decisions:
                        return [self._attach_proof_resolution(d, hypothesis, i1_verdicts, d2_verdicts) for d in decisions]
        except Exception as _e:
            logger.warning("[I2] LLM 裁决异常，回退规则式：%s", _e)
        return self._adjudicate_rule_based(i1_verdicts, d2_verdicts, spec_by_h, hypothesis, dast_impact_evidence)

    @staticmethod
    def _evidence_bundle(i1, d2) -> Dict[str, Dict[str, Any]]:
        """把 I1 / D2 裁决整理成 proof_obligations 可消费的证据三元组。

        关键映射：
          - iast state == sink-reached 且 canary 命中 ⇒ 证出 source→sink 真实传播；
          - iast state == arrival-sanitized ⇒ 运行时观测到净化/归一化，barrier 确实存在。
        """
        iast_evidence = {
            "state": (getattr(i1, "state", STATE_NO_ARRIVAL) if i1 else STATE_NO_ARRIVAL),
            "confidence": (getattr(i1, "confidence", "low") if i1 else "low"),
            "chain_conformance": (getattr(i1, "chain_conformance", None) if i1 else None),
            "matched_event_ids": list(getattr(i1, "matched_event_ids", []) or []) if i1 else [],
            "sanitizer_observed": bool(i1 and getattr(i1, "state", "") == STATE_ARRIVAL_SANITIZED),
        }
        dast_impact_evidence = {
            # 单一真相源（与 proof_obligations.py:715 对齐）：impact_observed = D1 离线影响 OR D2 结果点有害。
            # 此前只认 d2.harmful（= sink_reached and reached），注入族 sink_reached 恒 False → 真实 D1 影响被丢，
            # Fix B 注入族离线确认分支（adjudicate_final_state:493）永不触发。现补 d2.dast_impact_observed。
            "impact_observed": bool(d2 and (d2.harmful or d2.dast_impact_observed)),
            "reached": bool(d2 and d2.sink_reached),
            "status_code": (d2.detail or {}).get("dast_status_code") if d2 else None,
            "body": (d2.detail or {}).get("dast_body", "") if d2 else "",
            # business_logic / authz_hook_confirmed 等语义信号，但本 bundle 此前只透传 impact/reached，
            # 导致 adjudicate_final_state / decide_next_action 里读取 attack_degraded、business_logic 的分支
            # 全部是死代码 —— 降级攻击的「不回滚、补造 payload」语义与业务族「差分确认」语义从未真正生效。
            # 现把 D2Verdict.detail 里的语义信号一并透传，使 I2 决策逻辑与其注释口径一致。
            "attack_degraded": bool(d2 and (d2.detail or {}).get("attack_degraded")),
            "attack_degraded_any": bool(d2 and (d2.detail or {}).get("attack_degraded_any")),
            "business_logic": (d2.detail or {}).get("business_logic") or {} if d2 else {},
            "business_logic_confirmed": bool(d2 and (d2.detail or {}).get("business_logic_confirmed")),
            "authz_hook_confirmed": bool(d2 and (d2.detail or {}).get("authz_hook_confirmed")),
        }
        d2_verdict = {
            "harmful": bool(d2 and d2.harmful),
            "sink_reached": bool(d2 and d2.sink_reached),
            "confidence": (d2.confidence if d2 else "low"),
            "reason": (d2.reason if d2 else ""),
        }
        return {
            "iast_evidence": iast_evidence,
            "dast_impact_evidence": dast_impact_evidence,
            "d2_verdict": d2_verdict,
        }

    def _resolve_proof(self, hypothesis: Optional[Dict[str, Any]], i1, d2) -> Dict[str, Any]:
        """把运行时证据映射到 A2 同一组证明义务，产出逐条 resolution + 残差 diff。"""
        bundle = self._evidence_bundle(i1, d2)
        resolution = apply_runtime_evidence(
            hypothesis,
            bundle["iast_evidence"],
            bundle["dast_impact_evidence"],
            bundle["d2_verdict"],
        )
        # 闭环信号：A2 声称的 flow ⊖ I2 解析后的 flow
        resolution["residual"] = residual_proof_gaps(hypothesis, resolution)
        return resolution

    def _attach_proof_resolution(self, decision: "I2Decision", hypothesis, i1_verdicts, d2_verdicts) -> "I2Decision":
        """给单条裁决补上 proof_resolution，并把结构化 diff 写进 feedback_to_a2 供 A2 回灌消费。"""
        i1_by_h = {v.hypothesis_id: v for v in (i1_verdicts or [])}
        d2_by_h = {v.hypothesis_id: v for v in (d2_verdicts or [])}
        decision.proof_resolution = self._resolve_proof(
            hypothesis,
            i1_by_h.get(decision.hypothesis_id),
            d2_by_h.get(decision.hypothesis_id),
        )
        residual = dict(decision.proof_resolution.get("residual") or {})
        still_open = list(residual.get("still_open") or [])
        refuted = list(residual.get("refuted") or [])
        # 回灌只在「需要修正」时产生：已被反驳（如确实存在 sanitizer），或尚未确认且有缺口。
        # pass 且已确认、又无反驳 → 无需回灌，保持 feedback 为空（proof_resolution 仍记录在裁决上）。
        needs_feedback = bool(decision.feedback_to_a2) or bool(refuted) or (not decision.confirmed and bool(still_open))
        if needs_feedback:
            feedback = dict(decision.feedback_to_a2 or {})
            feedback.setdefault("hypothesis_id", decision.hypothesis_id)
            feedback["proof_resolution"] = decision.proof_resolution
            feedback["residual_gaps"] = residual
            decision.feedback_to_a2 = feedback
        return decision

    def _adjudicate_rule_based(self, i1_verdicts, d2_verdicts, spec_by_h, hypothesis=None, dast_impact_evidence=None) -> List["I2Decision"]:
        _outer_dast = dast_impact_evidence or {}
        """规则式兜底：复用 adjudicate_final_state + decide_next_action 的既有五态/控制回路逻辑，
        逐条产出 I2Decision，并把 re_correct（A2 poc 链与实际不符）→ rollback_to_a2 的修正提示汇入
        feedback_to_a2；同时把运行时证据对账结果写入 proof_resolution（闭环反思消费）。
        """
        i1_by_h = {v.hypothesis_id: v for v in i1_verdicts}
        d2_by_h = {v.hypothesis_id: v for v in d2_verdicts}
        # 批量查而非逐条查：349 spec 逐条查会让 I2 多出数百次 DB 往返。
        # fail-open：查不到就传空，判据退化为原逻辑，绝不因取证据失败而改判。
        _attempts_by_spec: Dict[int, List[Dict[str, Any]]] = {}
        try:
            _tid = None
            for _s in (spec_by_h or {}).values():
                _tid = (_s or {}).get("task_id") or _tid
                if _tid:
                    break
            if _tid:
                for _r in (self.db.execute(
                        "SELECT spec_id, family, resp_body_head, resp_headers_digest"
                        " FROM replay_attempts WHERE task_id=?",
                        (int(_tid),), fetchall=True) or []):
                    _d = dict(_r)
                    _attempts_by_spec.setdefault(int(_d.get("spec_id") or 0), []).append(_d)
        except Exception as _ae:  # noqa: BLE001
            logger.debug("[I2] 取重放响应摘要失败（有害证据判定退化为 unknown）：%s", _ae)
            _attempts_by_spec = {}
        decisions: List["I2Decision"] = []
        for hid in i1_by_h:
            i1 = i1_by_h[hid]
            d2 = d2_by_h.get(hid)
            bundle = self._evidence_bundle(i1, d2)
            iast_evidence = bundle["iast_evidence"]
            dast_impact_evidence = bundle["dast_impact_evidence"]
            d2_verdict = bundle["d2_verdict"]
            # 把 D1 聚合层标记的靶场不健康信号透传到 final_state 裁定（与 no_evidence 区分）。
            if dast_impact_evidence is not None:
                dast_impact_evidence = dict(dast_impact_evidence)
                dast_impact_evidence["target_unhealthy"] = bool(
                    dast_impact_evidence.get("target_unhealthy") or _outer_dast.get("target_unhealthy")
                )
                # （与 no_evidence / target_unhealthy 区分，三者并列 rank 0 但语义不同）。
                dast_impact_evidence["waf_blocked"] = bool(
                    dast_impact_evidence.get("waf_blocked") or _outer_dast.get("waf_blocked")
                )
                # 透传上游 D1 离线重放的 impact_observed（_outer_dast 来自 D1 replay 结果），
                # 与 d2.dast_impact_observed 形成双保险，确保注入族 Fix B 分支能拿到真实 DAST 影响。
                dast_impact_evidence["impact_observed"] = bool(
                    dast_impact_evidence.get("impact_observed") or _outer_dast.get("impact_observed")
                )
            _spec_row = spec_by_h.get(hid) or {}
            # 把 spec 的 oracle 结论塞进 iast_evidence（adjudicate_final_state 从那里读），
            # 供 harm_evidence 判定「行为 oracle 正向 ⇒ 有害档证据」。
            #
            # `_evidence_bundle` 产出的 iast_evidence 里通常已经带着 `oracle_state: ""`
            # （空串占位），而 `setdefault` 只在键**不存在**时才写入 ⇒ 真值永远进不去。
            # 实测：本轮日志已确认 `[I2][oracle-fill] 1/1 条带信号`，
            # 但 oracle 转化仍只有 3/11，就是卡在这一行。
            # 语义上也没问题：spec 里的非空值才是权威观测，空串不构成「已有强信号」。
            if _spec_row.get("oracle_state") or _spec_row.get("oracle_signal"):
                iast_evidence = dict(iast_evidence or {})
                if _spec_row.get("oracle_state"):
                    iast_evidence["oracle_state"] = _spec_row.get("oracle_state")
                if _spec_row.get("oracle_signal"):
                    iast_evidence["oracle_signal"] = _spec_row.get("oracle_signal")
            verdict = I2Adjudicator.adjudicate_final_state(
                iast_evidence=iast_evidence, dast_impact_evidence=dast_impact_evidence, d2_verdict=d2_verdict,
                family=(spec_by_h.get(hid) or {}).get("family"),
                attempts=_attempts_by_spec.get(int(_spec_row.get("id") or 0), []),
                # 传 endpoint 让 harm_evidence 按路由前缀纠正族（00016/00121 的族误标就靠它）
                endpoint=(spec_by_h.get(hid) or {}).get("target_endpoint") or "",
            )
            action = I2Adjudicator.decide_next_action(
                iast_evidence=iast_evidence, d2_verdict=d2_verdict, dast_impact_evidence=dast_impact_evidence,
            )
            feedback = self._build_feedback_to_a2(hid, verdict, action, spec_by_h.get(hid))
            decision = I2Decision(
                hypothesis_id=hid,
                final_state=verdict.get("final_state", FINAL_NO_EVIDENCE),
                action=self._normalize_action(action.get("action", "pass"), verdict),
                confirmed=bool(verdict.get("confirmed")),
                confidence=verdict.get("confidence", "low"),
                reason=verdict.get("judge_reason", ""),
                feedback_to_a2=feedback,
            )
            decisions.append(self._attach_proof_resolution(decision, hypothesis, i1_verdicts, d2_verdicts))
        return decisions

    @staticmethod
    def _normalize_action(raw_action: str, verdict: Dict[str, Any]) -> str:
        """把既有控制回路 action 归一到 I2 口径：re_correct（A2 poc 链与实际不符）→ 回灌 A2 的
        rollback_to_a2；re_send 仍是 D1 控制回路动作，保留；pass 不变。"""
        if raw_action == "re_correct":
            return "rollback_to_a2"
        return raw_action

    def _build_feedback_to_a2(self, hid, verdict, action, spec) -> Dict[str, Any]:
        """把不符合的假说整理成 A2 可消费的回灌提示（闭环反思用）。

        导致注入族（I2 判 confirmed=true / action=pass 的典型结局）的 feedback_to_a2 恒为空，
        闭环退化成「只调重放参数、从不修假说」，a2_feedback 三轮恒为 0。

        修正：即便整体确认通过，只要链路仍有「确凿缺失节点」（chain_conformance.missing 非空，
        属假说链路本身缺陷：族误判 / 端点幻觉 / 参数位错），仍回灌 A2 使其收敛。
        仅当链路完全闭合（无 missing）才返回空，避免对确证且无缺口的假说产生噪声反馈；
        conforms=True 但 unverifiable（探针未上报路径、仅不可证伪而非缺失）亦不回灌。
        """
        chain = verdict.get("chain_conformance") or {}
        missing = chain.get("missing") or []
        # 整体确认通过且无任何「确凿缺失节点」→ 无需回灌（保留原语义，避免噪声）
        if action.get("action") == "pass" and verdict.get("confirmed") and not missing:
            return {}
        return {
            "hypothesis_id": hid,
            "final_state": verdict.get("final_state"),
            "reason": verdict.get("judge_reason", ""),
            "correction_hint": action.get("correction_hint", {}),
            "missing_chain_nodes": missing,
            "residual_gaps": {"still_open": missing},
            # 未闭合门禁属假说链路缺陷，显式标类保证进入 a2_actionable（不依赖关键词漂移）
            "failure_class": "hypothesis_defect" if missing else (action.get("failure_class") or ""),
            # 供 I2 classify_feedback 识别 RUNTIME_REFUTATION（运行时证否黄金样本）。
            # verdict 由 adjudicate_final_state 透传 iast_evidence，其 value_hit.form 即值级形态。
            "value_hit_form": str(
                ((verdict.get("iast_evidence") or {}).get("value_hit") or {}).get("form") or ""
            ),
            "current_spec": {
                "family": (spec or {}).get("family"),
                "target_endpoint": (spec or {}).get("target_endpoint"),
                "param_name": (spec or {}).get("param_name"),
                "poc_chain": (spec or {}).get("poc_chain"),
            },
        }

    def _adjudicate_llm(self, i1_verdicts, d2_verdicts, spec_by_h, vulnerability_context) -> List["I2Decision"]:
        """LLM 裁决主路径：把 I1 + D2 双重证据 + A2 假说上下文喂给 LLM，要求逐条 JSON 裁决。"""
        gw = self._get_gateway()
        if gw is None or gw.is_offline:
            return []
        prompt, context = self._build_i2_prompt(i1_verdicts, d2_verdicts, spec_by_h, vulnerability_context)
        resp = gw.complete(purpose="i2-adjudication", prompt=prompt, context=context)
        return self._parse_i2_llm(resp.text, i1_verdicts, spec_by_h)

    def _build_i2_prompt(self, i1_verdicts, d2_verdicts, spec_by_h, vulnerability_context):
        payload = {
            "vulnerability_context": _safe_str(vulnerability_context),
            "specs": [
                {
                    "hypothesis_id": hid,
                    "family": (s or {}).get("family"),
                    "target_endpoint": (s or {}).get("target_endpoint"),
                    "param_name": (s or {}).get("param_name"),
                    "poc_chain": (s or {}).get("poc_chain"),
                }
                for hid, s in spec_by_h.items()
            ],
            "i1_verdicts": [vars(v) for v in i1_verdicts],
            "d2_verdicts": [vars(v) for v in d2_verdicts],
        }
        context = {"i2_adjudication": payload}
        prompt = (
            "你是应用安全验证链路的 I2 裁决器（AI 检测 review 制度）。\n"
            "综合 I1 监听器（污点是否按 A2 预测链到达 sink / 链路符合）与 D2 校验器（结果点是否确证有害）"
            "的双重证据，以「条（hypothesis）」为颗粒度独立裁决每条 spec：\n"
            "- action 取值：pass（符合可利用，放行）/ rollback_to_a2（不符合，需回灌 A2 重新推导 poc 与 entry）/ "
            "re_send（D1 重放到达目标但 I1 未观测到 canary，建议重发修正触发参数）。\n"
            "对 action != pass 的条目，必须在 feedback_to_a2 给出 A2 可直接消费的修正提示"
            "（缺失的链路节点、推测错误的参数位置/路由、建议的重新推导方向）。\n"
            "【注入族离线裁决口径——必须与规则式路径一致】\n"
            "对 sql-injection / ssrf / command-execution / xss / path-traversal / template-injection / "
            "deserialization / xxe 等注入型族：本靶场 IAST 运行时恒未观测到 canary 到达 sink"
            "（i1_verdicts.state 多为 no-arrival、sink_reached=false），此时确认只能来自离线 DAST 影响。"
            "若该条 d2_verdicts 中 dast_impact_observed=true（D1 重放已观测到外部可观测影响，"
            "如 SQL 报错 / 时间差 / 命令回显 / 文件读出 / 反序列化异常），即便 I1 未到 sink，"
            "也应判 final_state=confirmed_attributable、confirmed=true、action=pass。"
            "仅当存在稳定反证（stable_disproof）时才判 false_positive_sast_only。\n"
            "只输出一个 JSON 数组，每个元素形如：\n"
            '[{"hypothesis_id":"...","final_state":"confirmed_attributable|runtime_confirmed|ambiguous|no_evidence|false_positive_sast_only|target_unhealthy|waf_blocked",'
            '"action":"pass|rollback_to_a2|re_send","confirmed":true,"confidence":"high|medium|low",'
            '"reason":"...","feedback_to_a2":{}}]\n'
            "不要输出任何 Markdown 代码块围栏或额外文字。"
        )
        return prompt, context

    @staticmethod
    def _parse_i2_llm(text, i1_verdicts, spec_by_h) -> List["I2Decision"]:
        if not text:
            return []
        raw = text.strip()
        # 剥离可能的 ```json 围栏
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
            raw = raw.strip()
        try:
            data = json.loads(raw)
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        i1_by_h = {v.hypothesis_id: v for v in i1_verdicts}
        decisions: List["I2Decision"] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            hid = str(item.get("hypothesis_id", ""))
            if hid not in i1_by_h:
                continue
            decisions.append(I2Decision(
                hypothesis_id=hid,
                final_state=str(item.get("final_state", FINAL_NO_EVIDENCE)),
                action=str(item.get("action", "pass")),
                confirmed=bool(item.get("confirmed")),
                confidence=str(item.get("confidence", "low")),
                reason=str(item.get("reason", "")),
                feedback_to_a2=dict(item.get("feedback_to_a2") or {}),
            ))
        return decisions

    # ------------------------------------------------------------------ 内部 #
    def _sanitizer_candidates(self, workspace_id: Optional[int]) -> List[Dict[str, Any]]:
        """ 净化器反哺候选：arrival-sanitized 事件 → 解析 stack_trace 定位方法，
        门1（多次独立观测一致 ≥ min_observations）+ 门2（明确方法）过滤。"""
        sql = ("SELECT sink_method, stack_trace FROM iast_events WHERE canary_state = 'arrival-sanitized'")
        params: List[Any] = []
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        rows = self.db.execute(sql, params, fetchall=True) or []

        observations: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "file": "", "line": 0})
        for r in rows:
            row = dict(r)
            sink_method = row.get("sink_method") or ""
            seen: set = set()
            for fr in parse_stack_frames(row.get("stack_trace") or ""):
                key = f"{fr['class']}.{fr['method']}" if fr["class"] else fr["method"]
                if not key or key == sink_method:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                observations[key]["count"] += 1
                observations[key]["file"] = fr.get("file", "")
                observations[key]["line"] = fr.get("line", 0)

        candidates: List[Dict[str, Any]] = []
        for key, ob in sorted(observations.items()):
            if ob["count"] >= self.min_observations:
                candidates.append({
                    "kind": "sanitizer",
                    "pattern": key,
                    "language": "",
                    "family": "",
                    "occurrences": ob["count"],
                    "file": ob["file"],
                    "line": ob["line"],
                })
        return candidates

    def _rule_seed_candidates(self, workspace_id: Optional[int], task_id: Optional[int]) -> List[Dict[str, Any]]:
        """ 观测有、假说无 → 新增 sink 规则种子（从观测 sink 方法提炼）。"""
        audit = self.audit_coverage(workspace_id, task_id)
        seeds: List[Dict[str, Any]] = []
        seen: set = set()
        for e in audit["observed_only"]:
            method = e.get("sink_method") or ""
            if not method or method in seen:
                continue
            seen.add(method)
            seeds.append({
                "kind": "sink",
                "pattern": method,
                "language": _language_from_file(e.get("sink_file") or ""),
                "family": "",
                "sink_file": e.get("sink_file", ""),
                "sink_line": e.get("sink_line", 0),
            })
        return seeds

    @staticmethod
    def _event_summary(e: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "canary": e.get("canary", ""),
            "canary_state": e.get("canary_state", ""),
            "sink_method": e.get("sink_method", ""),
            "sink_file": e.get("sink_file", ""),
            "sink_line": e.get("sink_line", 0),
            "app_name": e.get("app_name", ""),
            "agent_id": e.get("agent_id", ""),
        }

    def _load_findings(self, workspace_id, task_id) -> List[Dict[str, Any]]:
        # §SCA 隔离：SCA findings 只走 SCA 软件成分分析模块，不参与 I2 裁决。
        sql = "SELECT vulnerability_hash_v2 FROM findings WHERE COALESCE(source, '') != 'sca'"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _load_specs(self, workspace_id, task_id=None) -> List[Dict[str, Any]]:
        sql = "SELECT vulnerability_hash_v2, taint_marker FROM trigger_specs"
        clauses: List[str] = []
        params: List[Any] = []
        # 不参与裁决——裁决器读 taint_marker 的目的是「这个假说有没有被运行时证实」，
        # 而这些 spec 静态层已判安全，不该再被判成 confirmed。数据卫生类函数
        # （reconcile_orphan_specs / purge）**故意不过滤**，否则被抑制的 spec 会永远残留。
        clauses.append("COALESCE(suppressed_by_safe_verdict, 0) = 0")
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _load_observed_events(self, workspace_id, task_id=None) -> List[Dict[str, Any]]:
        # 占位符随 _OBSERVED_STATES 长度动态生成：历史实现硬编码 3 个 ?，
        # 一旦新增观测态（如 sink-reached-probe）就会 binding 数量不匹配而整段查询静默失败。
        _ph = ", ".join("?" for _ in _OBSERVED_STATES)
        sql = ("SELECT canary, canary_state, sink_method, sink_file, sink_line, app_name, agent_id "
               f"FROM iast_events WHERE canary_state IN ({_ph})")
        params: List[Any] = list(_OBSERVED_STATES)
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _stability_map(self, hypothesis_only: List[str], workspace_id: Optional[int]) -> Dict[str, int]:
        """ 跨扫描稳定性：同一 hash 在多少个独立 task 中持续 hypothesis_only。
        简化实现：直接统计该 hash 在 findings 中出现的不同 task_id 数量（≥1 即本轮 + 历史）。
        """
        if not hypothesis_only:
            return {}
        result: Dict[str, int] = {}
        for h in hypothesis_only:
            sql = "SELECT COUNT(DISTINCT task_id) AS n FROM findings WHERE vulnerability_hash_v2 = ? AND COALESCE(source, '') != 'sca'"
            params: List[Any] = [h]
            if workspace_id is not None:
                sql += " AND workspace_id = ?"
                params.append(workspace_id)
            row = self.db.execute(sql, params, fetchone=True)
            result[h] = int(row["n"] or 0) if row else 0
        return result

    def _evidence_chain(self, vulnerability_hash_v2: str, workspace_id: Optional[int]) -> List[Dict[str, str]]:
        """ evidence_chain：SAST 种子 → DAST 触发 → IAST 观测 → D2 校验。"""
        chain = []
        # SAST 种子
        sql = "SELECT id, file_path, line FROM findings WHERE vulnerability_hash_v2 = ? AND COALESCE(source, '') != 'sca'"
        params: List[Any] = [vulnerability_hash_v2]
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        row = self.db.execute(sql, params, fetchone=True)
        if row:
            chain.append({"stage": "SAST", "id": str(row["id"]), "file": str(row["file_path"]), "line": str(row["line"])})
        # DAST 触发 + IAST 观测 + D2 校验（从 trigger_specs + iast_events 派生）
        sql = "SELECT id FROM trigger_specs WHERE vulnerability_hash_v2 = ?"
        params = [vulnerability_hash_v2]
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        spec_row = self.db.execute(sql, params, fetchone=True)
        if spec_row:
            chain.append({"stage": "DAST", "id": str(spec_row["id"]), "trigger_spec_id": str(spec_row["id"])})
        sql = ("SELECT id, canary_state FROM iast_events WHERE "
               "canary IN (SELECT substr(taint_marker, 1, 22) FROM trigger_specs WHERE vulnerability_hash_v2 = ?) "
               "OR canary IN (SELECT taint_marker FROM trigger_specs WHERE vulnerability_hash_v2 = ?)")
        params = [vulnerability_hash_v2, vulnerability_hash_v2]
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        ev_row = self.db.execute(sql, params, fetchone=True)
        if ev_row:
            chain.append({"stage": "IAST", "id": str(ev_row["id"]), "canary_state": str(ev_row["canary_state"])})
            chain.append({"stage": "D2", "id": str(ev_row["id"]), "verdict": "sink-reached" if str(ev_row["canary_state"]) == "sink-reached" else "ambiguous"})
        return chain

    @staticmethod
    def _final_state_summary(audit: Dict[str, Any]) -> Dict[str, int]:
        return {
            "confirmed_runtime": audit["stats"]["matched"],
            "no_evidence": audit["stats"]["hypothesis_only"],
            "likely_false_positive": audit["stats"].get("likely_false_positive", 0),
            "rule_seed_candidates": audit["stats"]["observed_only"],
        }


def _language_from_file(file_path: str) -> str:
    suffix = (file_path or "").rsplit(".", 1)[-1].lower()
    return {
        "java": "java", "py": "python", "js": "javascript", "ts": "typescript",
        "tsx": "typescript", "jsx": "javascript", "php": "php", "go": "go",
    }.get(suffix, "")
