"""
Shared D2 execution helpers for deterministic verification.
"""
import base64
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from .d2_bundle import D2BundleMixin
from .d2_types import VerificationResult
from ..core.tool_paths import get_exploits_dir, get_java_tools_dir
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class D2ExecutionMixin(D2BundleMixin):
    def _wait_for_http_service(self, base_url: str, timeout_seconds: int = 30, candidate_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        deadline = time.time() + timeout_seconds
        last_error = ""
        paths = []
        for path in candidate_paths or []:
            if path and path not in paths:
                paths.append(path)
        for fallback_path in ["/", "/docs", "/openapi.json"]:
            if fallback_path not in paths:
                paths.append(fallback_path)
        while time.time() < deadline:
            for path in paths:
                target = base_url.rstrip("/") + (path if path.startswith("/") else f"/{path}")
                try:
                    response = requests.get(target, timeout=5)
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "body": response.text[:200],
                        "ready_url": target,
                    }
                except Exception as exc:
                    last_error = str(exc)
                    continue
            time.sleep(1)
        return {"success": False, "error": last_error}

    @staticmethod
    def _result_has_probe_evidence(exploit_result: Dict[str, Any], strategy: Dict[str, str], poc_type: str) -> bool:
        attack_result = exploit_result.get("attack_result", {}) or {}
        verify_result = exploit_result.get("verify_result", {}) or {}
        attack_body = str(attack_result.get("body", ""))
        verify_body = str(verify_result.get("body", ""))
        expected = str(exploit_result.get("expected") or strategy.get("expected") or "")
        payload = str(exploit_result.get("payload") or strategy.get("payload") or "")
        attack_status = int(attack_result.get("status_code") or 0)
        verify_status = int(verify_result.get("status_code") or 0)

        if expected and (expected in attack_body or expected in verify_body):
            return True
        if poc_type in {"python-reflected-xss", "java-reflected-xss", "php-reflected-xss", "node-template-injection"} and payload and payload in attack_body:
            return True
        if poc_type in {"python-sqli", "java-sqli", "php-sqli", "java-xpath", "python-xpath", "php-xpath", "node-nosql-injection", "java-ldap", "python-ldap"} and attack_status == 200 and verify_body and attack_body != verify_body:
            return True
        if poc_type in {"java-hpp", "java-mongo", "java-redis"} and attack_status == 200 and verify_body and attack_body != verify_body:
            return True
        if poc_type == "csrf" and attack_status in (200, 201, 202, 204):
            lowered = attack_body.lower()
            return not any(token in lowered for token in ("csrf", "forbidden", "invalid token"))
        if poc_type in {"python-path-traversal", "node-path-traversal", "java-path-traversal", "php-path-traversal"}:
            return attack_status == 200 and ("root:" in attack_body or expected and expected in attack_body)
        if poc_type in {"python-ssrf", "node-ssrf", "java-ssrf", "php-ssrf"}:
            return attack_status == 200 and (expected in attack_body if expected else bool(attack_body))
        if poc_type in {"java-open-redirect", "php-open-redirect", "node-open-redirect"}:
            location = str(attack_result.get("headers", {}).get("Location", ""))
            return attack_status in (301, 302, 303, 307, 308) and (expected in location if expected else bool(location))
        if poc_type == "java-cors":
            allowed_origin = str(attack_result.get("headers", {}).get("Access-Control-Allow-Origin", ""))
            return attack_status in (200, 204) and bool(allowed_origin)
        if poc_type == "java-cookie":
            set_cookie = str(attack_result.get("headers", {}).get("Set-Cookie", ""))
            lowered = set_cookie.lower()
            return attack_status in (200, 302) and bool(set_cookie) and ("secure" not in lowered or "httponly" not in lowered)
        if poc_type == "java-auth-bypass":
            return attack_status not in (401, 403)
        if poc_type in {"java-xxe", "python-xxe", "php-xxe"}:
            return attack_status == 200 and ("root:" in attack_body or expected and expected in attack_body)
        if poc_type == "python-debug":
            lowered = attack_body.lower()
            return attack_status == 200 and any(token in lowered for token in ("werkzeug", "traceback", "debugger", "__debugger__"))
        if verify_status in (200, 201, 202, 204) and verify_body:
            return True
        return False

    def _get_prepared_runtime(self, strategy: Dict[str, str]) -> Optional[Dict[str, Any]]:
        service_url = str(self.tools.runtime_context.get("service_url", "") or "").strip()
        ready_url = str(self.tools.runtime_context.get("ready_url", "") or "").strip()
        container_id = str(self.tools.runtime_context.get("container_id", "") or "").strip()
        runtime_type = str(self.tools.runtime_context.get("runtime_type", "") or "").strip()
        runtime_source = str(self.tools.runtime_context.get("runtime_source", "") or "").strip()
        process_id = str(self.tools.runtime_context.get("process_id", "") or "").strip()
        if not service_url:
            return None

        candidate_paths = []
        if ready_url:
            parsed = urlparse(ready_url)
            ready_path = parsed.path or "/"
            if parsed.query:
                ready_path = f"{ready_path}?{parsed.query}"
            candidate_paths.append(ready_path)
        candidate_paths.extend([
            strategy.get("target_path", ""),
            strategy.get("render_path", ""),
            strategy.get("probe_path", ""),
            strategy.get("verify_path", ""),
            strategy.get("trigger_path", ""),
            "/",
        ])
        probe_result = self._wait_for_http_service(service_url, timeout_seconds=8, candidate_paths=candidate_paths)
        if not probe_result.get("success"):
            return None
        return {
            "service_url": service_url,
            "ready_url": ready_url,
            "container_id": container_id,
            "runtime_type": runtime_type,
            "runtime_source": runtime_source,
            "process_id": process_id,
            "probe_result": probe_result,
        }

    def _run_node_probe_script(
        self,
        project_path: Path,
        strategy: Dict[str, str],
        script_name: str,
        poc_type: str,
        script_args: List[str],
        success_reason: str,
        fail_reason: str,
        fix_suggestion: str,
    ) -> VerificationResult:
        strategy = self._ensure_strategy_semantics(strategy)
        for key, value in self._derive_project_specific_semantics(project_path, strategy).items():
            if value:
                strategy[key] = value
        script_path = get_exploits_dir() / script_name
        if not script_path.exists():
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason=f"缺少 {script_name} 利用器",
                evidence=[str(script_path)],
                poc_type=poc_type,
                poc_code="",
                steps_executed=0,
                raw_output=self._build_raw_output({"semantic_context": self._build_semantic_context_from_strategy(strategy)}),
            )

        raw_steps: List[Dict[str, Any]] = []
        prepared_runtime = self._get_prepared_runtime(strategy)
        if prepared_runtime:
            container_id = prepared_runtime.get("container_id", "")
            base_url = prepared_runtime.get("service_url", "")
            probe_result = prepared_runtime.get("probe_result", {})
            raw_steps.append({"step": "reuse_prepared_runtime", "service_url": base_url, "container_id": container_id})
        else:
            host_port = self._get_available_host_port(13000)
            run_result = self.tools.execute(
                "docker_run",
                image=strategy.get("image", "sast-target:latest"),
                ports={str(strategy.get("container_port", "3000")): host_port},
                timeout=120,
            )
            raw_steps.append({"step": "docker_run", "result": run_result})
            if not run_result.get("success"):
                return VerificationResult(
                    exploitable=False,
                    confidence="low",
                    reason="确定性验证启动容器失败",
                    evidence=[run_result.get("error", "")],
                    poc_type=poc_type,
                    poc_code="",
                    steps_executed=1,
                    raw_output=self._build_raw_output({"steps": raw_steps, "semantic_context": self._build_semantic_context_from_strategy(strategy)}),
                )

            container_id = run_result.get("container_id", "")
            base_url = f"http://127.0.0.1:{host_port}"
            self.tools.set_runtime_context(container_id=container_id, service_url=base_url, project_path=str(project_path))

            candidate_paths = [
                strategy.get("target_path", ""),
                strategy.get("render_path", ""),
                strategy.get("probe_path", ""),
                strategy.get("verify_path", ""),
            ]
            probe_result = self._wait_for_http_service(base_url, timeout_seconds=30, candidate_paths=candidate_paths)
        raw_steps.append({"step": "probe_service", "result": probe_result})
        if not probe_result.get("success"):
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason="确定性验证中服务未就绪",
                evidence=[probe_result.get("error", "")],
                poc_type=poc_type,
                poc_code="",
                steps_executed=len(raw_steps),
                raw_output=self._build_raw_output({"steps": raw_steps, "service_url": base_url, "container_id": container_id, "semantic_context": self._build_semantic_context_from_strategy(strategy)}),
            )

        cmd = [sys.executable, str(script_path), "--base-url", base_url] + script_args
        raw_steps.append({"step": "run_exploit_script", "command": cmd})
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                cwd=str(Path.cwd()),
                env=os.environ.copy(),
            )
        except Exception as exc:
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason=f"执行 {script_name} 失败",
                evidence=[str(exc)],
                poc_type=poc_type,
                poc_code="",
                steps_executed=len(raw_steps),
                raw_output=self._build_raw_output({"steps": raw_steps, "service_url": base_url, "container_id": container_id, "error": str(exc), "semantic_context": self._build_semantic_context_from_strategy(strategy)}),
            )

        stdout = proc.stdout.decode("utf-8", errors="ignore").strip()
        stderr = proc.stderr.decode("utf-8", errors="ignore").strip()
        raw_steps.append({"step": "script_output", "stdout": stdout, "stderr": stderr, "returncode": proc.returncode})

        try:
            exploit_result = json.loads(stdout) if stdout else {}
        except Exception:
            exploit_result = {}
        result_file = Path(str(exploit_result.get("result_file", "") or ""))
        file_result = self._load_exploit_result_file(result_file)
        if file_result:
            exploit_result = {**file_result, **exploit_result}

        success = proc.returncode == 0 and bool(exploit_result.get("success"))
        attack_request = exploit_result.get("attack_request", {})
        attack_result = exploit_result.get("attack_result", {})
        verify_result = exploit_result.get("verify_result", {})
        if not success:
            success = self._result_has_probe_evidence(exploit_result, strategy, poc_type)

        evidence = [
            f"D2 服务地址: {base_url}",
            f"D2 容器: {container_id}",
            f"服务就绪URL: {probe_result.get('ready_url', '')}",
            f"攻击路径: {attack_request.get('url', '')}",
            f"攻击响应码: {attack_result.get('status_code', '')}",
            f"攻击响应片段: {str(attack_result.get('body', ''))[:200]}",
        ]
        if verify_result:
            evidence.append(f"验证响应码: {verify_result.get('status_code', '')}")
            evidence.append(f"验证响应片段: {str(verify_result.get('body', ''))[:200]}")

        poc_lines = [
            f"1. 启动镜像 {strategy.get('image', 'sast-target:latest')}",
            f"2. 向 {attack_request.get('url', '')} 发起 {attack_request.get('method', strategy.get('method', 'GET'))} 请求",
        ]
        if strategy.get("parameter"):
            poc_lines.append(f"3. 参数 {strategy.get('parameter', '')} 注入 {strategy.get('payload', strategy.get('payload_value', ''))}")
        elif strategy.get("query_key"):
            poc_lines.append(f"3. 污染键 {strategy.get('query_key', '')} 写入 {strategy.get('payload_value', '')}")
        if strategy.get("expected"):
            poc_lines.append(f"4. 检查响应中是否出现 {strategy.get('expected', '')}")
        elif strategy.get("verify_key"):
            poc_lines.append(f"4. 检查攻击响应或验证响应中是否出现 {strategy.get('verify_key', '')}")

        return VerificationResult(
            exploitable=success,
            confidence="high" if success else "medium",
            reason=success_reason if success else fail_reason,
            evidence=evidence,
            poc_type=poc_type,
            poc_code="\n".join(poc_lines),
            fix_suggestion=fix_suggestion,
            steps_executed=len(raw_steps),
            raw_output=self._build_raw_output(
                {
                    "steps": raw_steps,
                    "service_url": base_url,
                    "container_id": container_id,
                    "result_file": str(result_file) if result_file else "",
                    "exploit_result": exploit_result,
                    "attack_request": attack_request,
                    "attack_result": attack_result,
                    "verify_result": verify_result,
                    "semantic_context": self._build_semantic_context_from_strategy(strategy),
                }
            ),
        )

    def _build_map_deserialization_payload(self, command: str, jar_relative_path: str) -> Dict[str, Any]:
        container_id = str(self.tools.runtime_context.get('container_id', '') or '').strip() or "default"
        safe_container = re.sub(r'[^a-zA-Z0-9._-]+', '_', container_id)
        runtime_dir = self.tools.runtime_dir / f"map_deser_{safe_container}"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        app_jar = runtime_dir / "app.jar"
        helper_java = get_java_tools_dir() / "MapDeserializationPayloadGenerator.java"
        helper_class = runtime_dir / "MapDeserializationPayloadGenerator.class"
        commons_jar = runtime_dir / jar_relative_path
        payload_ser = runtime_dir / "verified_map_payload.ser"

        try:
            if app_jar.exists():
                app_jar.unlink()
            proc = subprocess.run(
                ["docker", "cp", f"{container_id}:/app.jar", str(app_jar)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                env=self._docker_env(),
            )
            if proc.returncode != 0:
                return {"success": False, "error": proc.stderr.decode("utf-8", errors="ignore")}

            if commons_jar.exists():
                commons_jar.unlink()
            commons_jar.parent.mkdir(parents=True, exist_ok=True)
            proc = subprocess.run(
                ["jar", "xf", "app.jar", jar_relative_path],
                cwd=str(runtime_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            if proc.returncode != 0:
                return {"success": False, "error": proc.stderr.decode("utf-8", errors="ignore")}

            if not helper_class.exists() or helper_class.stat().st_mtime < helper_java.stat().st_mtime:
                proc = subprocess.run(
                    ["javac", "-cp", str(commons_jar), "-d", str(runtime_dir), str(helper_java)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120,
                )
                if proc.returncode != 0:
                    return {"success": False, "error": proc.stderr.decode("utf-8", errors="ignore")}

            proc = subprocess.run(
                ["java", "-cp", "{};{}".format(runtime_dir, commons_jar), "MapDeserializationPayloadGenerator", command, str(payload_ser)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
            if proc.returncode != 0 or not payload_ser.exists():
                return {"success": False, "error": proc.stderr.decode("utf-8", errors="ignore")}

            payload_b64 = base64.b64encode(payload_ser.read_bytes()).decode("ascii")
            return {
                "success": True,
                "payload_file": str(payload_ser),
                "payload_b64": payload_b64,
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}



