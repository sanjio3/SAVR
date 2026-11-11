"""
Shared contract-compiler helpers for A2.1.
"""

from typing import Any, Dict, List

from src.core.exploit_spec import exploit_spec_completeness, normalize_exploit_spec


def infer_execution_shape(exploit_spec: Dict[str, Any]) -> str:
    spec = normalize_exploit_spec(exploit_spec)
    entry = spec.get("entry", {})
    prerequisites = spec.get("prerequisites", {})
    payload = spec.get("payload", {})
    family = str(payload.get("payload_family", "") or "")
    if prerequisites.get("ordered_steps") or entry.get("trigger_route"):
        return "multi_step_trigger_chain"
    if family == "idor" or any("different user" in str(item).lower() or "different tenant" in str(item).lower() for item in prerequisites.get("dependent_data", []) or []):
        return "cross_owner_resource_action"
    if (
        prerequisites.get("auth_required") == "required"
        or prerequisites.get("token_requirements")
        or prerequisites.get("session_requirements")
    ):
        return "authenticated_stateful_action"
    if family == "ssrf":
        return "server_side_fetch"
    return "single_request_reflection"


def infer_required_runtime_setup(exploit_spec: Dict[str, Any]) -> List[str]:
    spec = normalize_exploit_spec(exploit_spec)
    shape = infer_execution_shape(spec)
    prerequisites = spec.get("prerequisites", {})
    setup: List[str] = []
    if shape == "authenticated_stateful_action":
        setup.append("obtain_authenticated_session")
    if shape == "cross_owner_resource_action":
        setup.extend(["provision_owner_identity", "provision_attacker_identity", "provision_cross_owner_resource"])
    if shape == "server_side_fetch":
        setup.append("prepare_observable_server_side_fetch_target")
    if shape == "multi_step_trigger_chain":
        setup.append("prepare_trigger_sequence")
    if prerequisites.get("dependent_data"):
        setup.append("provision_dependent_data")
    deduped: List[str] = []
    for item in setup:
        if item not in deduped:
            deduped.append(item)
    return deduped


def attach_contract_execution_metadata(exploit_spec: Dict[str, Any]) -> Dict[str, Any]:
    spec = normalize_exploit_spec(exploit_spec)
    execution_group = spec.setdefault("execution", {})
    execution_group["shape"] = execution_group.get("shape") or infer_execution_shape(spec)
    required_runtime_setup = execution_group.get("required_runtime_setup") or []
    if not required_runtime_setup:
        execution_group["required_runtime_setup"] = infer_required_runtime_setup(spec)
    return spec


def derive_contract_gaps(proof_tier: str, exploit_spec: Dict[str, Any]) -> List[str]:
    gaps: List[str] = []
    if str(proof_tier or "broad_static") != "chain_proven":
        gaps.append("proof_tier!=chain_proven")
    completeness = exploit_spec_completeness(exploit_spec)
    gaps.extend(list(completeness.get("missing_required", []) or []))
    return gaps

