"""
Execution-mode inference for contract-driven D2 verification.
"""

from typing import Any, Dict

from src.core.exploit_spec import normalize_exploit_spec


def infer_execution_mode(exploit_spec: Dict[str, Any], *, iast_trigger: bool = False) -> str:
    spec = normalize_exploit_spec(exploit_spec)
    execution = spec.get("execution", {}) or {}
    shape = str(execution.get("shape", "") or "")
    if shape:
        return shape
    # 重构文档 3.5：验证走 TriggerSpec / 外部目标时，执行形态为 iast_trigger_observation
    # （发请求让探针观测，而非自验影响）。由调用方在 IAST 模式下显式传入 iast_trigger=True
    # （normalize_exploit_spec 会丢弃 execution 内的未知标记键，故不依赖 spec 内标记）。
    if iast_trigger:
        return "iast_trigger_observation"
    entry = spec.get("entry", {})
    prerequisites = spec.get("prerequisites", {})
    family = str((spec.get("payload", {}) or {}).get("payload_family", "") or "")
    if prerequisites.get("ordered_steps") or entry.get("trigger_route"):
        return "multi_step_trigger_chain"
    if family == "idor" or any("different user" in str(item).lower() or "different tenant" in str(item).lower() for item in prerequisites.get("dependent_data", []) or []):
        return "cross_owner_resource_action"
    if prerequisites.get("auth_required") == "required" or prerequisites.get("token_requirements") or prerequisites.get("session_requirements"):
        return "authenticated_stateful_action"
    if family == "ssrf":
        return "server_side_fetch"
    return "single_request_reflection"


def annotate_strategy_with_execution_mode(strategy: Dict[str, Any], exploit_spec: Dict[str, Any]) -> Dict[str, Any]:
    annotated = dict(strategy or {})
    annotated["execution_mode"] = infer_execution_mode(exploit_spec)
    return annotated

