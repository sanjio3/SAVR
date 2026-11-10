"""
Node-specific D2 deterministic strategy helpers.
"""
import logging
import re
from pathlib import Path
from typing import Dict, Optional

from .d2_types import VerificationResult

logger = logging.getLogger(__name__)


class D2NodeStrategiesMixin:
    def _detect_node_template_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'(ejs\.render|res\.render|handlebars\.compile|pug\.compile|nunjucks\.renderString)', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx)
                if not route_info or not param_info.get("name"):
                    continue
                payload_info = self._pick_node_template_payload(line)
                return {
                    "exploit_family": "node_template_injection",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "render_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": payload_info["payload"],
                    "expected": payload_info["expected"],
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_deserialization_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'(node-serialize|serialize\.unserialize|v8\.deserialize)', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["body", "query", "params"])
                if not route_info:
                    continue
                return {
                    "exploit_family": "node_insecure_deserialization",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "data",
                    "method": route_info["method"],
                    "payload": '{"rce":"_$$ND_FUNC$$_function(){return 7*7}()"}',
                    "expected": "49",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_command_injection_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'(child_process\.exec|execSync\(|spawn\(|\bexec\()', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx)
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "node_command_injection",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "test;id",
                    "expected": "uid=",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_prototype_pollution_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'(__proto__|constructor\.prototype|Object\.assign|\.merge\(|\bmerge\(|defaultsDeep\(|\bset\()', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                if not route_info:
                    continue
                verify_route = route_info
                for verify_idx, verify_line in enumerate(lines, 1):
                    if re.search(r'(a3_polluted|Object\.prototype|{}\.[A-Za-z_][A-Za-z0-9_]*)', verify_line):
                        maybe_route = self._find_node_route_for_line(lines, verify_idx)
                        if maybe_route:
                            verify_route = maybe_route
                            break
                return {
                    "exploit_family": "node_prototype_pollution",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "pollute_path": route_info["path"],
                    "method": route_info["method"],
                    "verify_path": verify_route["path"],
                    "verify_method": verify_route["method"],
                    "query_key": "__proto__.a3_polluted",
                    "verify_key": "a3_polluted",
                    "payload_value": "polluted-by-a3",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_jwt_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'jwt\.(verify|decode)\(', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["headers", "query", "body", "params"])
                if not route_info:
                    continue
                return {
                    "exploit_family": "node_jwt",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "token",
                    "method": route_info["method"],
                    "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0.",
                    "expected": "admin",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_open_redirect_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if "res.redirect" not in line:
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["query", "body", "params"])
                if not route_info:
                    continue
                semantics = self._infer_business_semantics(
                    "node_open_redirect",
                    target_path=route_info["path"],
                    parameter=param_info.get("name") or "next",
                    method=route_info["method"],
                    source_file=str(script_file.relative_to(project_path)).replace("/", "\\"),
                    line_context="\n".join(lines[max(0, idx - 3):min(len(lines), idx + 3)]),
                )
                return {
                    "exploit_family": "node_open_redirect",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "next",
                    "method": route_info["method"],
                    "payload": "https://example.com/a3",
                    "expected": "https://example.com/a3",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                    **semantics,
                }
        return None

    def _detect_node_file_delete_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 8 or idx > selected_line + 8:
                    continue
                if not re.search(r'fs\.(unlink|unlinkSync|rm|rmSync)\(', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["body", "query", "params"])
                if not route_info:
                    continue
                return {
                    "exploit_family": "node_file_delete",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "name",
                    "method": route_info["method"],
                    "payload": "../../../../tmp/a3-delete-me.txt",
                    "expected": "deleted",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_nosql_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(findOne|find|aggregate|updateOne|updateMany|findOneAndUpdate|findById|findByIdAndUpdate|countDocuments|exists)\(', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["body", "query", "params"])
                if not route_info:
                    continue
                return {
                    "exploit_family": "node_nosql_injection",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info.get("name") or "username",
                    "method": route_info["method"],
                    "transport": "json" if route_info["method"] in {"POST", "PUT", "PATCH"} else "param",
                    "baseline": "guest",
                    "payload": '{"$ne": null}',
                    "expected": "",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_ssrf_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'(axios\.(get|post|request)|fetch\(|http\.get\(|https\.get\(|request\(|got\()', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["query", "body", "params"])
                if not route_info or not param_info.get("name"):
                    continue
                semantics = self._infer_business_semantics(
                    "node_ssrf",
                    target_path=route_info["path"],
                    parameter=param_info["name"],
                    method=route_info["method"],
                    source_file=str(script_file.relative_to(project_path)).replace("/", "\\"),
                    line_context="\n".join(lines[max(0, idx - 3):min(len(lines), idx + 3)]),
                )
                return {
                    "exploit_family": "node_ssrf",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "http://127.0.0.1:80",
                    "expected": "127.0.0.1",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                    **semantics,
                }
        return None

    def _detect_node_path_traversal_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 6 or idx > selected_line + 6:
                    continue
                if not re.search(r'(fs\.readFile|fs\.readFileSync|fs\.createReadStream|res\.sendFile|path\.join|path\.resolve)', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                param_info = self._extract_node_request_param(lines, idx, preferred_sources=["query", "params", "body"])
                if not route_info or not param_info.get("name"):
                    continue
                return {
                    "exploit_family": "node_path_traversal",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "parameter": param_info["name"],
                    "method": route_info["method"],
                    "payload": "../../../../etc/passwd",
                    "expected": "root:",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _detect_node_file_upload_strategy(self, project_path: Path, vulnerability: Dict) -> Optional[Dict[str, str]]:
        selected_line = int(vulnerability.get("line", 0) or 0)
        selected_image = self._select_project_image(project_path, "sast-target:latest")
        for script_file in self._find_target_script_files(project_path, vulnerability):
            lines = script_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(lines, 1):
                if idx < selected_line - 10 or idx > selected_line + 10:
                    continue
                if not re.search(r'(multer\(|upload\.single\(|upload\.array\(|req\.files|req\.file|\.mv\()', line):
                    continue
                route_info = self._find_node_route_for_line(lines, idx)
                if not route_info:
                    continue
                field_match = re.search(r'upload\.(?:single|array)\((?:\"([^\"]+)\"|\'([^\']+)\')', "\n".join(lines[max(0, idx - 5):min(len(lines), idx + 5)]))
                field_name = field_match.group(1) or field_match.group(2) if field_match else "file"
                return {
                    "exploit_family": "node_file_upload",
                    "image": selected_image,
                    "container_port": str(self._guess_node_container_port(selected_image)),
                    "target_path": route_info["path"],
                    "field_name": field_name,
                    "filename": "a3-test.php",
                    "content": "<?php echo 7*7; ?>",
                    "expected": "upload",
                    "source_file": str(script_file.relative_to(project_path)).replace("/", "\\"),
                    "source_line": str(selected_line),
                }
        return None

    def _verify_node_template_injection_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_template_injection_probe.py",
            poc_type="node-template-injection",
            script_args=[
                "--render-path", strategy.get("render_path", "/"),
                "--parameter", strategy.get("parameter", "tpl"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "<%= 7 * 7 %>"),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="已通过 Node 模板注入探测脚本观察到服务端模板表达式执行结果",
            fail_reason="Node 模板注入探测已执行，但未观察到预期模板执行结果",
            fix_suggestion="避免将不可信输入直接作为服务端模板内容、模板名或渲染上下文的一部分；对 EJS/Nunjucks/Handlebars/Pug 使用固定模板并隔离用户输入",
        )

    def _verify_node_deserialization_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_deserialization_probe.py",
            poc_type="node-insecure-deserialization",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "data"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", '{"rce":"_$$ND_FUNC$$_function(){return 7*7}()"}'),
                "--expected", strategy.get("expected", "49"),
            ],
            success_reason="已通过 Node 不安全反序列化探测脚本观察到可控反序列化结果",
            fail_reason="Node 反序列化探测已执行，但未观察到预期结果或服务异常",
            fix_suggestion="避免对不可信输入使用 node-serialize、serialize.unserialize 或 v8.deserialize；改用安全数据格式并做严格模式校验",
        )

    def _verify_node_command_injection_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_command_injection_probe.py",
            poc_type="node-command-injection",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "cmd"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "test;id"),
                "--expected", strategy.get("expected", "uid="),
                "--transport", strategy.get("transport", "query"),
                "--fallback-payload", strategy.get("fallback_payload", ""),
                "--fallback-expected", strategy.get("fallback_expected", ""),
            ],
            success_reason="已通过 Node 命令注入探测脚本观察到系统命令执行回显",
            fail_reason="Node 命令注入探测已执行，但未观察到预期命令执行回显",
            fix_suggestion="避免将 HTTP 输入直接拼接到 exec/execSync/spawn 命令中；优先使用参数数组调用并建立白名单",
        )

    def _verify_node_prototype_pollution_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_prototype_pollution_probe.py",
            poc_type="node-prototype-pollution",
            script_args=[
                "--pollute-path", strategy.get("pollute_path", "/"),
                "--verify-path", strategy.get("verify_path", "/"),
                "--method", strategy.get("method", "POST"),
                "--verify-method", strategy.get("verify_method", "GET"),
                "--query-key", strategy.get("query_key", "__proto__.a3_polluted"),
                "--verify-key", strategy.get("verify_key", "a3_polluted"),
                "--payload-value", strategy.get("payload_value", "polluted-by-a3"),
            ],
            success_reason="已通过 Node 原型链污染探测脚本观察到污染键生效",
            fail_reason="Node 原型链污染探测已执行，但未观察到污染键生效",
            fix_suggestion="禁止将不可信输入直接交给 Object.assign/merge/defaultsDeep/set 等对象合并函数；显式过滤 __proto__、constructor、prototype",
        )

    def _verify_node_ssrf_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_ssrf_probe.py",
            poc_type="node-ssrf",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "url"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "http://127.0.0.1:80"),
                "--expected", strategy.get("expected", "127.0.0.1"),
            ],
            success_reason="已通过 Node SSRF 探测脚本观察到服务端请求结果",
            fail_reason="Node SSRF 探测已执行，但未观察到预期服务端请求结果",
            fix_suggestion="禁止将 HTTP 输入直接作为目标 URL 传给 axios/fetch/request/http.get；对目标地址做白名单和协议限制",
        )

    def _verify_node_path_traversal_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_path_traversal_probe.py",
            poc_type="node-path-traversal",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "path"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "../../../../etc/passwd"),
                "--expected", strategy.get("expected", "root:"),
            ],
            success_reason="已通过 Node 路径穿越探测脚本观察到敏感文件内容",
            fail_reason="Node 路径穿越探测已执行，但未观察到预期文件读取结果",
            fix_suggestion="禁止将 HTTP 输入直接拼接到 fs.readFile/res.sendFile/path.join/path.resolve；对路径做规范化并限制在固定基目录",
        )

    def _verify_node_file_upload_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_file_upload_probe.py",
            poc_type="node-file-upload",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--field-name", strategy.get("field_name", "file"),
                "--filename", strategy.get("filename", "a3-test.php"),
                "--content", strategy.get("content", "<?php echo 7*7; ?>"),
                "--expected", strategy.get("expected", "upload"),
            ],
            success_reason="已通过 Node 文件上传探测脚本观察到上传请求被服务端接收",
            fail_reason="Node 文件上传探测已执行，但未观察到预期上传结果",
            fix_suggestion="限制上传目录、扩展名、MIME、文件大小和可执行权限；不要直接使用原始文件名落地",
        )

    def _verify_node_jwt_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_jwt_probe.py",
            poc_type="node-jwt",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "token"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0."),
                "--expected", strategy.get("expected", "admin"),
            ],
            success_reason="Node JWT 探测脚本已观察到弱 JWT 被服务端接受",
            fail_reason="Node JWT 探测已执行，但未观察到预期 JWT 绕过结果",
            fix_suggestion="禁止 alg=none 和弱算法，强制校验签名与允许算法列表",
        )

    def _verify_node_open_redirect_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_open_redirect_probe.py",
            poc_type="node-open-redirect",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "next"),
                "--method", strategy.get("method", "GET"),
                "--payload", strategy.get("payload", "https://example.com/a3"),
                "--expected", strategy.get("expected", "https://example.com/a3"),
            ],
            success_reason="Node 开放重定向探测脚本已观察到 Location 被用户输入控制",
            fail_reason="Node 开放重定向探测已执行，但未观察到预期跳转结果",
            fix_suggestion="对 redirect 目标使用固定路径或白名单，禁止用户输入原样进入 res.redirect",
        )

    def _verify_node_file_delete_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_file_delete_probe.py",
            poc_type="node-file-delete",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "name"),
                "--method", strategy.get("method", "POST"),
                "--payload", strategy.get("payload", "../../../../tmp/a3-delete-me.txt"),
                "--expected", strategy.get("expected", "deleted"),
            ],
            success_reason="Node 文件删除探测脚本已观察到删除操作生效",
            fail_reason="Node 文件删除探测已执行，但未观察到预期删除结果",
            fix_suggestion="对可删除路径增加基准目录和 realpath 校验，禁止用户可控路径直接进入 fs.unlink/rm",
        )

    def _verify_node_nosql_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        return self._run_node_probe_script(
            project_path=project_path,
            strategy=strategy,
            script_name="node_nosql_injection_probe.py",
            poc_type="node-nosql-injection",
            script_args=[
                "--target-path", strategy.get("target_path", "/"),
                "--parameter", strategy.get("parameter", "username"),
                "--method", strategy.get("method", "GET"),
                "--transport", strategy.get("transport", "param"),
                "--baseline", strategy.get("baseline", "guest"),
                "--payload", strategy.get("payload", '{"$ne": null}'),
                "--expected", strategy.get("expected", ""),
            ],
            success_reason="Node NoSQL injection probe observed a meaningful difference between baseline and injected responses",
            fail_reason="Node NoSQL injection probe ran but did not confirm query manipulation",
            fix_suggestion="Reject operator objects from request input, enforce schema validation, and avoid passing raw request data into Mongo/Mongoose query filters",
        )


