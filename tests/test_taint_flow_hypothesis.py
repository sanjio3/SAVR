"""污点流假说 / severity 由 proof 推导 / 运行时证据闭合义务 的回归测试。

语义基线：sink 本身不等于危险。只有 source（攻击者可控输入）→ sink 可达、且中间
没有 barrier（净化器）截断，才算一条完整 flow，此时「危险」才可断言。
"""

from src.core.proof_obligations import (
    TAINT_FLOW_OBLIGATIONS,
    apply_runtime_evidence,
    build_taint_flow_hypothesis,
    derive_finding_gate,
    derive_severity_from_proof,
    empty_chain_proof,
    empty_taint_flow_hypothesis,
    residual_proof_gaps,
)
from src.core.models import Vulnerability


def _proof(**overrides):
    proof = empty_chain_proof()
    proof.update({
        "reachable": True,
        "attacker_control_proven": True,
        "gate_bypass_or_satisfaction_proven": True,
        "payload_shape_proven": True,
        "success_signal_anchor_proven": True,
    })
    proof.update(overrides)
    proof["proof_gaps"] = [
        k for k in (
            "reachable",
            "attacker_control_proven",
            "gate_bypass_or_satisfaction_proven",
            "payload_shape_proven",
            "success_signal_anchor_proven",
        )
        if not proof.get(k)
    ]
    return proof


# ------------------------------------------------------------------ 假说构造 #

def test_full_flow_is_complete():
    vuln = Vulnerability(type="SQL Injection", severity="HIGH", sink="Statement.execute")
    flow = build_taint_flow_hypothesis(vuln, _proof(), None)
    assert flow["sink_present"] is True
    assert flow["source_present"] is True
    assert flow["reachable"] is True
    assert flow["barrier_free"] is True
    assert flow["flow_complete"] is True
    assert flow["proof_gaps"] == []


def test_sink_alone_is_not_dangerous():
    """只有 sink、没有 source/可达性 ⇒ flow 不完整，不可断言危险。"""
    vuln = Vulnerability(type="Command Injection", severity="HIGH", sink="Runtime.exec")
    flow = build_taint_flow_hypothesis(
        vuln,
        _proof(attacker_control_proven=False, reachable=False,
               gate_bypass_or_satisfaction_proven=False, payload_shape_proven=False,
               success_signal_anchor_proven=False),
        None,
    )
    assert flow["sink_present"] is True          # 识别到 sink
    assert flow["source_present"] is False       # 但没有 source
    assert flow["flow_complete"] is False        # 因此 flow 不完整
    assert len(flow["proof_gaps"]) >= 3


def test_barrier_present_breaks_flow():
    """source→sink 可达，但中间有 barrier（未证明绕过）⇒ flow 仍不完整。"""
    vuln = Vulnerability(type="Path Traversal", severity="HIGH", sink="new FileInputStream")
    flow = build_taint_flow_hypothesis(vuln, _proof(gate_bypass_or_satisfaction_proven=False), None)
    assert flow["reachable"] is True
    assert flow["barrier_free"] is False
    assert flow["flow_complete"] is False
    assert "gate_bypass_or_satisfaction_proven" in flow["proof_gaps"]


# ------------------------------------------------------------------ severity 推导 #

def test_severity_kept_when_chain_proven():
    assert derive_severity_from_proof("HIGH", "chain_proven", []) == "HIGH"
    assert derive_severity_from_proof("CRITICAL", "chain_proven", []) == "CRITICAL"


def test_severity_downgraded_when_gaps_exist():
    # 缺口 ≤2 降一级
    assert derive_severity_from_proof("HIGH", "broad_static", ["reachable"]) == "MEDIUM"
    assert derive_severity_from_proof("HIGH", "broad_static", ["reachable", "payload_shape_proven"]) == "MEDIUM"
    # 缺口 >2 降两级
    assert derive_severity_from_proof("HIGH", "broad_static", ["reachable", "payload_shape_proven", "success_signal_anchor_proven"]) == "LOW"


def test_no_high_without_full_flow():
    """核心断言：没证出完整 flow 的候选 sink 不能顶着 HIGH。"""
    gaps = ["reachable", "attacker_control_proven", "gate_bypass_or_satisfaction_proven",
            "payload_shape_proven", "success_signal_anchor_proven"]
    assert derive_severity_from_proof("HIGH", "broad_static", gaps) == "LOW"


def test_severity_floor_is_low_not_unknown():
    """降级下限是 LOW：完全未证成的候选 sink 仍是待查线索，不该被 UNKNOWN 淹没。"""
    gaps = ["reachable", "attacker_control_proven", "gate_bypass_or_satisfaction_proven",
            "payload_shape_proven", "success_signal_anchor_proven"]
    assert derive_severity_from_proof("MEDIUM", "broad_static", gaps) == "LOW"
    # UNKNOWN 已在底部，不再下探
    assert derive_severity_from_proof("UNKNOWN", "broad_static", gaps) == "UNKNOWN"


# ------------------------------------------------------------------ 统一门禁 #

def test_gate_false_positive_verdict_forces_low():
    """A2 自己判为假漏洞 ⇒ 强制压到 LOW 且不算确认，消掉「HIGH + ❌假漏洞」矛盾。"""
    gate = derive_finding_gate(
        claimed_severity="HIGH",
        proof_tier="chain_proven",
        proof_gaps=[],
        obligations={k: True for k in TAINT_FLOW_OBLIGATIONS},
        flow_complete=True,
        verdict="❌ A2:假漏洞-无调用点",
    )
    assert gate["severity"] == "LOW"
    assert gate["confirmed"] is False
    assert gate["reason"] == "verdict_false_positive"


def test_gate_broad_static_with_empty_gaps_is_not_confirmed():
    """tier=broad_static 但 gaps 恰好为空 ⇒ 补标记缺口，不能当成已证成。"""
    gate = derive_finding_gate(
        claimed_severity="HIGH",
        proof_tier="broad_static",
        proof_gaps=[],
        obligations={k: True for k in TAINT_FLOW_OBLIGATIONS},
        flow_complete=False,
    )
    assert gate["confirmed"] is False
    assert gate["effective_gaps"] == ["proof_tier_not_chain_proven"]
    assert gate["severity"] == "MEDIUM"


def test_gate_chain_proven_keeps_claim():
    gate = derive_finding_gate(
        claimed_severity="HIGH",
        proof_tier="chain_proven",
        proof_gaps=[],
        obligations={k: True for k in TAINT_FLOW_OBLIGATIONS},
        flow_complete=True,
        verdict="✅ A2:真漏洞-HTTP入口可触发",
    )
    assert gate["confirmed"] is True
    assert gate["severity"] == "HIGH"


def test_gate_recovers_gaps_from_empty_shell_chain_proof():
    """chain_proof 空壳（booleans 全假、gaps 为空）⇒ 从 obligations 反推真实缺口。"""
    gate = derive_finding_gate(
        claimed_severity="HIGH",
        proof_tier="broad_static",
        proof_gaps=[],
        obligations={k: False for k in TAINT_FLOW_OBLIGATIONS},
    )
    assert len(gate["effective_gaps"]) == len(TAINT_FLOW_OBLIGATIONS)
    assert gate["confirmed"] is False
    assert gate["severity"] == "LOW"


# ------------------------------------------------------------------ 运行时证据闭合 #

class _I1:
    def __init__(self, state, matched):
        self.state = state
        self.confidence = "high"
        self.chain_conformance = {"conforms": True}
        self.matched_event_ids = matched


class _D2:
    def __init__(self, harmful=False, sink_reached=False):
        self.harmful = harmful
        self.sink_reached = sink_reached
        self.confidence = "high"
        self.reason = ""
        self.detail = {}


def test_runtime_canary_closes_reachable_and_source():
    """探针 sink-reached + canary 命中 ⇒ 证出 source→sink 真实传播。"""
    flow = build_taint_flow_hypothesis(
        Vulnerability(type="SQL Injection", severity="HIGH", sink="Statement.execute"),
        _proof(reachable=False, attacker_control_proven=False),
        None,
    )
    resolution = apply_runtime_evidence(flow, {"state": "sink-reached", "matched_event_ids": [1, 2]}, {}, {})
    assert resolution["resolution"]["reachable"] == "closed"
    assert resolution["resolution"]["attacker_control_proven"] == "closed"
    assert resolution["runtime_evidence"]["canary_matched"] is True


def test_runtime_sanitizer_refutes_barrier_free():
    """运行时观测到净化 ⇒ barrier 确实存在，反驳 gate_bypass。"""
    flow = build_taint_flow_hypothesis(
        Vulnerability(type="XSS", severity="HIGH", sink="response.getWriter().print"),
        _proof(),
        None,
    )
    resolution = apply_runtime_evidence(flow, {"state": "arrival-sanitized", "matched_event_ids": [3]}, {}, {})
    assert resolution["resolution"]["gate_bypass_or_satisfaction_proven"] == "refuted"
    assert resolution["runtime_evidence"]["sanitizer_observed"] is True
    assert "gate_bypass_or_satisfaction_proven" in resolution["refuted"]


def test_dast_impact_closes_success_signal():
    flow = build_taint_flow_hypothesis(
        Vulnerability(type="Command Injection", severity="HIGH", sink="Runtime.exec"),
        _proof(success_signal_anchor_proven=False, payload_shape_proven=False),
        None,
    )
    resolution = apply_runtime_evidence(flow, {"state": "sink-reached", "matched_event_ids": [1]},
                                        {"impact_observed": True}, {"harmful": True})
    assert resolution["resolution"]["success_signal_anchor_proven"] == "closed"
    assert resolution["runtime_evidence"]["impact_observed"] is True


# ------------------------------------------------------------------ 闭环残差 diff #

def test_residual_diff_reports_newly_closed_and_refuted():
    """闭环信号 = A2 声称的 flow ⊖ I2 解析后的 flow。"""
    flow = build_taint_flow_hypothesis(
        Vulnerability(type="SSRF", severity="HIGH", sink="URL.openConnection"),
        _proof(reachable=False, attacker_control_proven=False),
        None,
    )
    assert "reachable" in flow["proof_gaps"]
    resolution = apply_runtime_evidence(flow, {"state": "sink-reached", "matched_event_ids": [7]}, {}, {})
    residual = residual_proof_gaps(flow, resolution)
    # 运行时新闭合的
    assert "reachable" in residual["newly_closed"]
    assert "attacker_control_proven" in residual["newly_closed"]
    # 仍未闭合的
    assert set(residual["still_open"]) == set()


def test_residual_keeps_unclosed_gaps():
    flow = empty_taint_flow_hypothesis()
    resolution = apply_runtime_evidence(flow, {"state": "no-arrival", "matched_event_ids": []}, {}, {})
    residual = residual_proof_gaps(flow, resolution)
    assert len(residual["still_open"]) == 5
    assert residual["newly_closed"] == []
