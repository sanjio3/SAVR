"""⑤ D2 闸门（接入活跃链路）单元测试。

覆盖 decide_hitl_gate 决策大脑 + D2Agent.verify() 在不可逆动作上短接返回 approval_required，
且不实际执行破坏性重放（orchestrator.run_transaction 不被调用）。
"""
import sys
import os
import types

import pytest

# 让 src 可被导入
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.d2_strategy import decide_hitl_gate
from src.agents.d2_facade import D2Agent, _hitl_gate_for_spec


# ── decide_hitl_gate：决策大脑 ──────────────────────────────────────────────
def test_off_mode_never_gates():
    ctx = {"hitl": {"approval_mode": "off"}}
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")  # money_out 不可逆
    assert act["category"] == "money_out"
    assert act["irreversible"] is True
    assert act["gate"] is False
    assert act["approval_mode"] == "off"
    assert act["hitl_configured"] is True


def test_ask_on_risky_tools_gates_irreversible():
    ctx = {"hitl": {"approval_mode": "ask_on_risky_tools"}}
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")
    assert act["category"] == "money_out"
    assert act["gate"] is True


def test_ask_on_risky_tools_does_not_gate_reversible():
    ctx = {"hitl": {"approval_mode": "ask_on_risky_tools"}}
    act = decide_hitl_gate(ctx, "GET", "/api/products")
    assert act["category"] is None
    assert act["irreversible"] is False
    assert act["gate"] is False


def test_strict_gates_irreversible():
    ctx = {"hitl": {"approval_mode": "strict"}}
    act = decide_hitl_gate(ctx, "POST", "/api/users/1/delete")
    assert act["category"] == "data_destroy"
    assert act["gate"] is True


def test_act_allowlist_overrides_gate():
    ctx = {"hitl": {"approval_mode": "strict", "act_allowlist": ["money_out"]}}
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")
    assert act["category"] == "money_out"
    assert act["gate"] is False


def test_no_hitl_config_means_no_gate_and_no_audit_hint():
    ctx = {}  # 未配置 hitl
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")
    assert act["gate"] is False
    assert act["hitl_configured"] is False


# M14：破坏性闸门持续全批准（2026-10-03 决议）。缺省与未知值都必须 fail-open 到放行，
# 否则「hitl 键写了但漏填 approval_mode」会静默把闸门打开，整轮 D2 卡成 approval_required
# （真实库历史累计 19 条 approval_required 全是这么来的）。
def test_default_approval_mode_is_off_per_destructive_gate_policy():
    act = decide_hitl_gate({"hitl": {}}, "POST", "/api/transfer")
    assert act["approval_mode"] == "off"
    assert act["gate"] is False


def test_empty_approval_mode_is_treated_as_off():
    ctx = {"hitl": {"approval_mode": ""}}
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")
    assert act["approval_mode"] == "off"
    assert act["irreversible"] is True
    assert act["gate"] is False


def test_unknown_approval_mode_fails_open_to_off():
    ctx = {"hitl": {"approval_mode": "ask_the_human_please"}}
    act = decide_hitl_gate(ctx, "POST", "/api/transfer")
    assert act["approval_mode"] == "off"
    assert act["gate"] is False


def test_explicit_ask_on_risky_tools_still_gates():
    # 显式收紧的语义没有被动到 —— 只有缺省/未知才 fail-open。
    act = decide_hitl_gate({"hitl": {"approval_mode": "ask_on_risky_tools"}}, "POST", "/api/transfer")
    assert act["approval_mode"] == "ask_on_risky_tools"
    assert act["gate"] is True


# ── _hitl_gate_for_spec：trigger_spec 字段归一 ──────────────────────────────
def test_gate_for_spec_reads_target_endpoint_and_method():
    ctx = {"hitl": {"approval_mode": "ask_on_risky_tools"}}
    spec = {"target_endpoint": "/api/transfer", "method": "POST"}
    act = _hitl_gate_for_spec(ctx, spec)
    assert act["category"] == "money_out"
    assert act["gate"] is True


def test_gate_for_spec_http_method_alias():
    ctx = {"hitl": {"approval_mode": "ask_on_risky_tools"}}
    spec = {"route": "/api/users/1", "http_method": "DELETE"}
    act = _hitl_gate_for_spec(ctx, spec)
    assert act["category"] == "data_destroy"
    assert act["gate"] is True


# ── D2Agent.verify() 短接：不可逆动作返回 approval_required，不执行重放 ─────────
class _FakeIast:
    pass


class _FakeD1:
    pass


def _make_agent():
    return D2Agent({})


def test_verify_gates_destructive_and_short_circuits():
    agent = _make_agent()
    vuln = {"family": "ssrf", "finding_type": "ssrf", "file": "a.java", "line": 1, "type": "ssrf"}
    project_context = {"hitl": {"approval_mode": "ask_on_risky_tools"}}
    external_target = {
        "service_url": "http://127.0.0.1:8092",
        "app_name": "target-mall",
        "agent_id": "agent-x",
    }
    trigger_spec = {
        "target_endpoint": "/api/transfer",
        "method": "POST",
        "category": "money_out",
        "task_id": 99,
        "workspace_id": 3,
        "vulnerability_hash_v2": "h1",
        "taint_marker": "",
    }
    vr = agent.verify(
        vuln, project_context, external_target,
        trigger_spec=trigger_spec,
        iast_service=_FakeIast(), dast_operator=_FakeD1(),
    )
    # gate 短接：不进入 orchestrator.run_transaction（破坏性重放），直接回 approval_required
    assert vr.verification_decision.get("verification_status") == "approval_required"
    assert vr.exploit_spec.get("entry", {}).get("route") == "/api/transfer"
    assert vr.failure_classification.get("category") == "money_out"


def test_verify_off_mode_does_not_gate():
    agent = _make_agent()
    vuln = {"family": "ssrf", "finding_type": "ssrf", "file": "a.java", "line": 1, "type": "ssrf"}
    project_context = {"hitl": {"approval_mode": "off"}}
    external_target = {
        "service_url": "http://127.0.0.1:8092",
        "app_name": "target-mall",
        "agent_id": "agent-x",
    }
    trigger_spec = {
        "target_endpoint": "/api/transfer",
        "method": "POST",
        "category": "money_out",
        "task_id": 99,
        "workspace_id": 3,
        "vulnerability_hash_v2": "h1",
        "taint_marker": "",
    }
    # off：即便不可逆也不 gate（由靶场验收执行路径；此处仅断言决策不影响短接返回）
    act = _hitl_gate_for_spec(project_context, trigger_spec)
    assert act["gate"] is False
    assert act["irreversible"] is True
