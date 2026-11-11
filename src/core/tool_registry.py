"""
Curated runtime / exploit tool registry used by D2 and HITL.
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional


TOOL_SPECS: List[Dict[str, Any]] = [
    {
        "id": "docker_build",
        "name": "Docker Build",
        "category": "runtime/bootstrap",
        "risk_level": "medium",
        "language_scope": ["java", "python", "node", "php"],
        "vuln_families": [],
        "execution_modes": [],
        "requires_runtime": False,
        "description": "Build project-specific runtime images for dynamic verification.",
    },
    {
        "id": "generated_runtime",
        "name": "Generated Runtime",
        "category": "runtime/bootstrap",
        "risk_level": "medium",
        "language_scope": ["java", "python", "node", "php"],
        "vuln_families": [],
        "execution_modes": [],
        "requires_runtime": False,
        "description": "Generate temporary runtime assets when a project lacks startup files.",
    },
    {
        "id": "local_java_runtime",
        "name": "Local Java Runtime",
        "category": "runtime/bootstrap",
        "risk_level": "medium",
        "language_scope": ["java"],
        "vuln_families": [],
        "execution_modes": [],
        "requires_runtime": False,
        "description": "Launch local java -jar runtime for jar-only projects.",
    },
    {
        "id": "java_expression_probe",
        "name": "Java Expression Probe",
        "category": "exploit/verification",
        "risk_level": "high",
        "language_scope": ["java"],
        "vuln_families": ["template-injection", "expression-chain"],
        "execution_modes": ["single_request_reflection"],
        "requires_runtime": True,
        "description": "Exercise Java expression/template injection sinks with verification and high-impact payloads.",
    },
    {
        "id": "generic_idor_probe",
        "name": "Generic IDOR Probe",
        "category": "exploit/verification",
        "risk_level": "high",
        "language_scope": ["python", "java", "node", "php"],
        "vuln_families": ["idor", "auth-bypass"],
        "execution_modes": ["cross_owner_resource_action", "authenticated_stateful_action"],
        "requires_runtime": True,
        "description": "Exercise cross-owner resource actions and ownership checks.",
    },
    {
        "id": "python_ssrf_probe",
        "name": "Python SSRF Probe",
        "category": "exploit/verification",
        "risk_level": "high",
        "language_scope": ["python"],
        "vuln_families": ["ssrf"],
        "execution_modes": ["server_side_fetch"],
        "requires_runtime": True,
        "description": "Exercise server-side request forgery chains with source-aware payloads.",
    },
    {
        "id": "python_file_upload_probe",
        "name": "Python File Upload Probe",
        "category": "exploit/verification",
        "risk_level": "high",
        "language_scope": ["python"],
        "vuln_families": ["file-upload"],
        "execution_modes": ["authenticated_stateful_action"],
        "requires_runtime": True,
        "description": "Exercise file upload chains with high-impact payload acceptance checks.",
    },
    {
        "id": "auth_state_setup",
        "name": "Auth State Setup",
        "category": "support/auth-state",
        "risk_level": "medium",
        "language_scope": ["java", "python", "node", "php"],
        "vuln_families": ["idor", "auth-bypass", "workflow"],
        "execution_modes": ["authenticated_stateful_action", "cross_owner_resource_action"],
        "requires_runtime": True,
        "description": "Prepare login sessions, dual-user state, and victim/attacker resources.",
    },
    {
        "id": "default_credentials_probe",
        "name": "Default Credentials Probe",
        "category": "exploit/verification",
        "risk_level": "high",
        "language_scope": ["shell", "java", "python", "node", "php"],
        "vuln_families": ["default-credentials"],
        "execution_modes": ["authenticated_stateful_action"],
        "requires_runtime": True,
        "description": "Authenticate with exposed default credentials and verify privileged API access or state change.",
    },
    {
        "id": "forensics_state_diff",
        "name": "State Diff Forensics",
        "category": "evidence/forensics",
        "risk_level": "low",
        "language_scope": ["java", "python", "node", "php"],
        "vuln_families": [],
        "execution_modes": ["multi_step_trigger_chain", "cross_owner_resource_action", "authenticated_stateful_action"],
        "requires_runtime": True,
        "description": "Observe before/after state changes, artifacts, or follow-up verification paths.",
    },
]


class ToolRegistry:
    @staticmethod
    def list_tools() -> List[Dict[str, Any]]:
        return deepcopy(TOOL_SPECS)

    @staticmethod
    def get(tool_id: str) -> Optional[Dict[str, Any]]:
        for item in TOOL_SPECS:
            if item["id"] == tool_id:
                return deepcopy(item)
        return None


def tool_id_for_contract(language: str, family: str, execution_shape: str = "") -> str:
    family = str(family or "").strip().lower()
    language = str(language or "").strip().lower()
    execution_shape = str(execution_shape or "").strip().lower()

    if language == "java" and family in {"template-injection", "expression-chain"}:
        return "java_expression_probe"
    if family == "idor":
        return "generic_idor_probe"
    if family == "default-credentials":
        return "default_credentials_probe"
    if language == "python" and family == "ssrf":
        return "python_ssrf_probe"
    if language == "python" and family == "file-upload":
        return "python_file_upload_probe"
    if execution_shape in {"authenticated_stateful_action", "cross_owner_resource_action"}:
        return "auth_state_setup"
    if execution_shape in {"multi_step_trigger_chain", "server_side_fetch"}:
        return "forensics_state_diff"
    return "forensics_state_diff"
