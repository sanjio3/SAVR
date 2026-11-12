"""
Shared D2 result types.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from src.core.exploit_spec import empty_exploit_spec, failure_classification
from .d2_judge import empty_execution_evidence


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class VerificationResult:
    exploitable: bool = False
    confidence: str = "low"
    reason: str = ""
    evidence: List[str] = field(default_factory=list)
    poc_type: str = ""
    poc_code: str = ""
    fix_suggestion: str = ""
    steps_executed: int = 0
    execution_time: float = 0.0
    raw_output: str = ""
    attack_plan: Dict[str, Any] = field(default_factory=dict)
    exploit_spec: Dict[str, Any] = field(default_factory=empty_exploit_spec)
    failure_classification: Dict[str, Any] = field(default_factory=failure_classification)
    contract_completeness: Dict[str, Any] = field(default_factory=dict)
    execution_evidence: Dict[str, Any] = field(default_factory=empty_execution_evidence)
    verification_decision: Dict[str, Any] = field(default_factory=dict)
    # IAST 闭环扩展
    iast_evidence: Dict[str, Any] = field(default_factory=dict)
    dast_impact_evidence: Dict[str, Any] = field(default_factory=dict)
    final_state: str = ""  # 六态：confirmed_attributable / runtime_confirmed / ambiguous / no_evidence / false_positive_sast_only / target_unhealthy / waf_blocked
    # target_unhealthy：靶场 5xx/连接异常/探针未就绪导致本轮未测出（可重试，与 no_evidence 严格区分）。
    # waf_blocked：被 WAF/拦截器/参数截断拦截（请求未到漏洞点即被安全策略阻断，可重试/人工确认，与 no_evidence 严格区分）。
    # 统一链路扩展（D2 结果点核实 + I2 控制回路）
    d2_verdict: Dict[str, Any] = field(default_factory=dict)   # D2 站在 sink 立场判结果点是否有害（看结果点，不重发）
    next_action: Dict[str, Any] = field(default_factory=dict)  # I2 总开关：pass / re_send / re_correct 及修正提示
    # 设计二②：业务逻辑「可观测副作用确认」独立标记（区别于差分确认与 IAST 可达性确认）。
    # replay_race 返回 business_confirmed / observed_side_effect 经 d2_facade 聚合后落到此字段，
    # 供 attack_plan_service 把运行时命中态升为 business_confirmed（最高置信）。
    business_confirmed: bool = False

    def to_dict(self):
        return {
            "exploitable": self.exploitable,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": self.evidence,
            "poc_type": self.poc_type,
            "poc_code": self.poc_code,
            "fix_suggestion": self.fix_suggestion,
            "steps_executed": self.steps_executed,
            "execution_time": self.execution_time,
            "attack_plan": self.attack_plan,
            "exploit_spec": self.exploit_spec,
            "failure_classification": self.failure_classification,
            "contract_completeness": self.contract_completeness,
            "execution_evidence": self.execution_evidence,
            "verification_decision": self.verification_decision,
            "iast_evidence": self.iast_evidence,
            "dast_impact_evidence": self.dast_impact_evidence,
            "final_state": self.final_state,
            "d2_verdict": self.d2_verdict,
            "next_action": self.next_action,
            "business_confirmed": self.business_confirmed,
        }
