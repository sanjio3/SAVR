"""
LLM planning, fallback execution, and conclusion helpers for D2.
"""
import json
import logging
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.core import workspace_runtime

logger = logging.getLogger(__name__)


class D2PlanningMixin:
    def _understand(self, vuln: Dict, context: Dict) -> Dict:
        """理解漏洞"""
        prompt = f"""
# 漏洞信息分析

## 漏洞详情
- 类型: {vuln.get('type', 'Unknown')}
- 文件: {vuln.get('file', 'Unknown')}
- 行号: {vuln.get('line', 'Unknown')}
- 代码: {vuln.get('code_snippet', 'N/A')}
- 描述: {vuln.get('description', 'N/A')}
- 入口点: {vuln.get('entry_point', 'N/A')}
- 调用链: {vuln.get('callers', 'N/A')}
- 数据流: {vuln.get('data_flow', 'N/A')}
- 危险函数: {vuln.get('sink', 'N/A')}
- 是否存在HTTP入口: {vuln.get('has_http_entry', False)}
- A1/A2真假判定: {vuln.get('verdict', 'N/A')}

## 项目信息
- 语言: {context.get('language', 'Unknown')}
- 框架: {context.get('framework', 'Unknown')}

## 分析要求

请分析以下内容，以JSON格式输出:

{{
    "trigger_condition": "触发漏洞需要的条件",
    "required_input": "需要什么样的输入才能触发",
    "attack_impact": "攻击成功的影响",
    "verification_approach": "推荐的验证方法",
    "difficulty": "验证难度 (简单/中等/困难)",
    "false_positive_risk": "误报风险评估"
}}

只输出JSON，不要其他内容。
"""

        response = self.llm.chat(prompt, self.SYSTEM_PROMPT)

        try:
            # 尝试提取JSON
            result = self._extract_json(response)
            return result
        except:
            logger.warning(f"[D2] Failed to parse understanding response: {response[:200]}")
            return {
                "trigger_condition": "Unknown",
                "required_input": "Unknown",
                "attack_impact": "Unknown",
                "verification_approach": "Unknown",
                "difficulty": "中等",
                "false_positive_risk": "中"
            }

    def _plan(self, understanding: Dict, project_context: Dict = None) -> Dict:
        """制定验证计划"""
        # 获取项目信息
        project_path = project_context.get('project_path', '') if project_context else ''
        language = project_context.get('language', '') if project_context else ''
        framework = project_context.get('framework', '') if project_context else ''

        # 检查本地镜像和运行中的容器
        local_images = self._check_local_docker()
        preferred_project_image = self._select_project_image(Path(project_path), "sast-target:latest") if project_path else "sast-target:latest"
        logger.info(f"[D2] Local Docker info: {local_images}")

        # 读取Dockerfile内容作为上下文
        dockerfile_content = ""
        dockerfile_path = ""
        possible_paths = [
            f"{project_path}/Dockerfile",
            f"{project_path}/Dockerfile.generated",
            f"{project_path}/Dockerfile.generated"
        ]

        for df_path in possible_paths:
            try:
                with open(df_path, 'r', encoding='utf-8', errors='ignore') as f:
                    dockerfile_content = f.read()
                    dockerfile_path = df_path
                    break
            except:
                continue

        # 查找项目中的API端点
        api_endpoints = self._find_api_endpoints(project_path)

        # 准备本地Docker信息
        local_docker_info = f"""
## 本地Docker镜像 (必须优先使用!)
可用镜像: {local_images.get('images', [])}
运行中的容器: {local_images.get('running_containers', [])}
当前项目优先镜像: {preferred_project_image}
"""
        # 如果有本地镜像，强制使用，不允许docker_build
        use_local_only = False
        local_image = preferred_project_image if local_images.get('images') else '无'
        if local_images.get('images'):
            local_docker_info += f"\n**强制要求**: 必须使用当前项目绑定的本地镜像 `{preferred_project_image}` 进行 docker_run！禁止使用 docker_build！"
            use_local_only = True

        prompt = f"""
# 漏洞验证计划制定 - 你是一个专业的安全研究员

你需要为以下漏洞制定详细的验证计划，包括环境启动、POC构造和验证步骤。

## 漏洞分析结果
{json.dumps(understanding, ensure_ascii=False, indent=2)}

## 项目信息
- 项目路径: {project_path}
- 编程语言: {language}
- 框架: {framework}
- 暴露端口: 8888

## 本地Docker状态 (优先使用!)
{local_docker_info}

## 项目API端点 (用于构造URL)
{api_endpoints[:1000] if api_endpoints else "未找到API端点信息"}

## 你必须遵守的规则

### 1. 镜像使用优先级
- 优先: 直接使用本地已有的镜像进行 docker_run
- 备选: 如果没有本地镜像，再尝试 docker_build

### 2. 工具使用规则
- docker_build: 仅当本地没有可用镜像时才使用
- docker_run: 启动容器
  - 使用本地镜像: {local_image}
  - ports: 端口映射，如 {{"8888": 8888}}
- http_request: 发送HTTP请求
  - url: 完整URL，如 "http://localhost:8888/api/user/1"
  - method: GET/POST
  - body: 请求体 (用于POST)

### 2. 关键约束
- 禁止使用变量如 ${{TARGET_API}}、${{URL}}，必须写死实际URL
- 必须先用read_file读取Dockerfile了解如何构建
- 必须先用docker_build构建镜像，再用docker_run运行
- docker_run启动后必须等待15秒让服务启动
- 端口映射格式：{{"容器端口": 主机端口}}
- `poc_code` 不能只给单一 payload，必须优先给“多组候选 payload / 绕过变体 + 成功判据 + 失败判据 + 需要的工具”
- 如果 A1/A2 已提供调用链、入口点、sink、真假判定，必须利用这些信息生成更贴近真实入口的 payload
- 如果怀疑存在过滤、编码、黑名单或部分 bypass，需要在 `poc_code` 中体现至少 2 种绕过变体

### 3. 正确的步骤示例
```json
{{
    "steps": [
        {{
            "step": 1,
            "description": "读取Dockerfile了解构建方式",
            "tool": "read_file",
            "params": {{"path": "data/samples/test-project/ctf-java-quote/Dockerfile"}},
            "expected": "Dockerfile内容"
        }},
        {{
            "step": 2,
            "description": "构建Docker镜像",
            "tool": "docker_build",
            "params": {{"path": "data/samples/test-project/ctf-java-quote", "tag": "vuln-app:latest"}},
            "expected": "镜像构建成功"
        }},
        {{
            "step": 3,
            "description": "启动应用容器",
            "tool": "docker_run",
            "params": {{"image": "vuln-app:latest", "ports": {{"8888": 8888}}}},
            "expected": "容器启动成功"
        }},
        {{
            "step": 4,
            "description": "等待服务启动",
            "tool": "shell_exec",
            "params": {{"command": "sleep 15"}},
            "expected": "等待完成"
        }},
        {{
            "step": 5,
            "description": "发送正常请求验证服务",
            "tool": "http_request",
            "params": {{"method": "GET", "url": "http://localhost:8888/"}},
            "expected": "200 OK"
        }},
        {{
            "step": 6,
            "description": "发送恶意POC测试漏洞",
            "tool": "http_request",
            "params": {{"method": "POST", "url": "http://localhost:8888/api/user/1", "body": "1 OR 1=1"}},
            "expected": "SQL注入响应"
        }}
    ]
}}
```

## 输出要求

请以JSON格式输出验证计划，包含:
1. poc_type: POC类型 (http/shell/docker)
2. poc_code: 具体的POC代码
3. steps: 详细步骤，每步必须包含 step, description, tool, params, expected

**重要**: 所有URL必须使用 http://localhost:8888 格式，不要使用变量!
"""
        logger.info(f"[D2] Generating plan with context: project={project_path}, dockerfile={bool(dockerfile_content)}")

        response = self.llm.chat(prompt, self.SYSTEM_PROMPT)

        try:
            result = self._extract_json(response)
            logger.info(f"[D2] Plan generated successfully")
            return result
        except Exception as e:
            logger.warning(f"[D2] Failed to parse planning response: {e}")
            return self._build_fallback_plan(
                project_path,
                local_images,
                dockerfile_path,
                project_context.get('vulnerability_file', '') if project_context else ''
            )

    def _build_fallback_plan(self, project_path: str, local_images: Dict, dockerfile_path: str,
                             vulnerability_file_hint: str = "") -> Dict:
        """Fallback plan when LLM planning is unavailable."""
        image_name = "sast-target:latest"
        local_image = self._select_project_image(Path(project_path), image_name) if local_images.get('images') else ""

        pom_path = ""
        for candidate in (
            Path(project_path) / "pom.xml",
            Path(project_path) / "build.gradle",
            Path(project_path) / "build.gradle.kts",
        ):
            if candidate.exists():
                pom_path = str(candidate)
                break

        vulnerability_file = self._resolve_project_file(
            project_path,
            vulnerability_file_hint
        )

        steps = []
        step_no = 1

        if dockerfile_path:
            steps.append({
                "step": step_no,
                "description": "Read Dockerfile for fallback validation",
                "tool": "read_file",
                "params": {"path": dockerfile_path},
                "expected": "Dockerfile content"
            })
            step_no += 1

        if pom_path:
            steps.append({
                "step": step_no,
                "description": "Read project dependency manifest for fallback validation",
                "tool": "read_file",
                "params": {"path": pom_path},
                "expected": "Dependency metadata"
            })
            step_no += 1

        if vulnerability_file:
            steps.append({
                "step": step_no,
                "description": "Read vulnerable source file for fallback validation",
                "tool": "read_file",
                "params": {"path": vulnerability_file},
                "expected": "Source code around vulnerability"
            })
            step_no += 1

        if local_image:
            image_name = local_image
        else:
            steps.append({
                "step": step_no,
                "description": "Build Docker image using deterministic fallback",
                "tool": "docker_build",
                "params": {"path": project_path, "tag": image_name},
                "expected": "Docker image built"
            })
            step_no += 1

        steps.append({
            "step": step_no,
            "description": "Run target service in Docker using deterministic fallback",
            "tool": "docker_run",
            "params": {"image": image_name, "ports": {"8080": 8888}},
            "expected": "Container started"
        })
        step_no += 1

        steps.append({
            "step": step_no,
            "description": "Probe service root endpoint",
            "tool": "http_request",
            "params": {"method": "GET", "url": "http://localhost:8888/", "timeout": 10},
            "expected": "HTTP response from target"
        })

        return {
            "poc_type": "",
            "poc_code": "",
            "steps": steps,
            "success_indicators": ["docker_run success", "service responds on localhost:8888"],
            "failure_indicators": ["docker build failed", "docker run failed", "service probe failed"]
        }

    def _resolve_project_file(self, project_path: str, file_hint: str) -> str:
        """Resolve a project-local file path for fallback reads."""
        if not file_hint:
            return ""

        candidates = []
        hint_path = Path(file_hint)
        if hint_path.exists():
            candidates.append(hint_path)
        if project_path:
            candidates.append(Path(project_path) / file_hint)
            candidates.append(Path(project_path) / hint_path.name)

        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        if project_path:
            for candidate in Path(project_path).rglob(hint_path.name):
                if candidate.is_file():
                    return str(candidate)
        return ""

    def _get_available_host_port(self, preferred: int = 8888) -> int:
        """Return a usable local TCP port, preferring the requested one."""
        for port in (preferred,):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _rewrite_service_url(self, original_url: str, service_url: str) -> str:
        """Rewrite localhost URLs to the active service URL while preserving the path."""
        if not original_url or not service_url:
            return original_url
        if not original_url.startswith("http://localhost:"):
            return original_url

        suffix = ""
        match = re.match(r"^http://localhost:\d+(.*)$", original_url)
        if match:
            suffix = match.group(1) or ""
        return f"{service_url}{suffix}"

    def _find_api_endpoints(self, project_path: str) -> str:
        """查找项目中的API端点"""
        endpoints = []
        import os
        from pathlib import Path

        # 查找Java控制器文件
        java_path = Path(project_path)
        if not java_path.exists():
            return ""

        # 查找所有Java文件
        for java_file in java_path.rglob("*.java"):
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                # 查找Spring MVC注解
                import re
                patterns = [
                    r'@(Get|Post|Put|Delete|RequestMapping)\(["\']*/([^"\']+)',
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    for method, path in matches:
                        endpoints.append(f"{method.upper()} /{path}")
            except:
                continue

        return "\n".join(endpoints[:20])  # 限制数量

    def _check_local_docker(self) -> Dict:
        """检查本地Docker镜像和运行中的容器"""
        cache_ttl_seconds = 120
        now = time.time()
        cached = self._docker_info_cache.get("value")
        cached_ts = float(self._docker_info_cache.get("timestamp", 0.0) or 0.0)
        if cached is not None and now - cached_ts < cache_ttl_seconds:
            return dict(cached)
        result = {
            'images': [],
            'running_containers': [],
            'available': False
        }

        try:
            # 检查本地镜像
            proc = subprocess.Popen(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._docker_env()
            )
            try:
                stdout, _ = proc.communicate(timeout=25)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
                raise TimeoutError("docker images timed out")
            images = stdout.decode('utf-8', errors='ignore').strip().split('\n')
            result['images'] = self._prioritize_images([i for i in images if i])

            # 检查运行中的容器
            proc = subprocess.Popen(
                ['docker', 'ps', '--format', '{{.Names}}|{{.Ports}}|{{.Image}}'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._docker_env()
            )
            try:
                stdout, _ = proc.communicate(timeout=25)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
                raise TimeoutError("docker ps timed out")
            containers = stdout.decode('utf-8', errors='ignore').strip().split('\n')
            for c in containers:
                if c:
                    parts = c.split('|')
                    result['running_containers'].append({
                        'name': parts[0] if len(parts) > 0 else '',
                        'ports': parts[1] if len(parts) > 1 else '',
                        'image': parts[2] if len(parts) > 2 else ''
                    })

            result['available'] = len(result['images']) > 0 or len(result['running_containers']) > 0
            self._docker_info_cache = {"value": dict(result), "timestamp": now}

        except Exception as e:
            logger.warning(f"[D2] Failed to check Docker: {e}")
            if cached is not None:
                return dict(cached)

        return result

    def _prioritize_images(self, images: List[str]) -> List[str]:
        preferred = dict(workspace_runtime.image_priority())
        return sorted(images, key=lambda image: (preferred.get(image, 100), image))

    def _execute(self, plan: Dict, context: Dict) -> Dict:
        """执行验证计划。"""
        steps_executed = 0
        raw_outputs = []
        all_success = True
        container_id = None  # 容器 ID
        service_url = None   # 服务 URL
        service_ready = False

        poc_code = plan.get('poc_code', '')
        if poc_code:
            poc_preview = poc_code if isinstance(poc_code, str) else json.dumps(poc_code, ensure_ascii=False)
            logger.info(f"[D2] POC generated:\n{poc_preview[:500]}")

        self.tools.set_runtime_context(
            container_id="",
            service_url="",
            project_path=context.get('project_path', '') if context else '',
        )

        for step_info in plan.get('steps', []):
            step_num = step_info.get('step', 0)
            tool = step_info.get('tool', '')
            params = step_info.get('params', {})

            logger.info(f"[D2] Executing step {step_num}: {tool} with params: {params}")

            mapped_params = self._map_tool_params(tool, params)

            if tool == "docker_run":
                ports = self.tools._normalize_container_ports(
                    mapped_params.get('image', ''),
                    mapped_params.get('ports', {}) or {}
                )
                adjusted_ports = {}
                for container_port, host_port in ports.items():
                    try:
                        preferred_port = int(host_port)
                    except (TypeError, ValueError):
                        preferred_port = 8888
                    adjusted_ports[str(container_port)] = self._get_available_host_port(preferred_port)
                if adjusted_ports:
                    mapped_params['ports'] = adjusted_ports

            if tool == "http_request" and service_url:
                url = mapped_params.get('url', '')
                if '${TARGET_API}' in url or '${TARGET_URL}' in url or 'TARGET_API' in url:
                    mapped_params['url'] = url.replace('${TARGET_API}', service_url).replace('${TARGET_URL}', service_url).replace('TARGET_API', service_url)
                else:
                    mapped_params['url'] = self._rewrite_service_url(url, service_url)
                mapped_params['body'] = self._rewrite_http_body(mapped_params.get('body', ''), service_url)

            try:
                result = self.tools.execute(tool, **mapped_params)

                if tool == "docker_run" and result.get('success'):
                    container_id = result.get('container_id', '')
                    ports = mapped_params.get('ports', {})
                    for _, host_port in ports.items():
                        service_url = f"http://localhost:{host_port}"
                        logger.info(f"[D2] Container started: {container_id}, URL: {service_url}")
                    self.tools.set_runtime_context(container_id=container_id, service_url=service_url)

                    logger.info("[D2] Waiting for service to start (15 seconds)...")
                    time.sleep(15)

                    test_result = self.tools.execute(
                        'http_request',
                        method='GET',
                        url=service_url,
                        timeout=10
                    )
                    if test_result.get('success'):
                        logger.info(f"[D2] Service is UP: {test_result.get('status_code')}")
                        service_ready = True
                    else:
                        logger.warning(f"[D2] Service might not be ready: {test_result.get('error', 'Unknown')}")
                        all_success = False

            except TypeError as e:
                logger.warning(f"[D2] Tool params mismatch: {e}, skipping step")
                result = {"success": False, "error": str(e)}

            steps_executed += 1
            raw_outputs.append({
                'step': step_num,
                'tool': tool,
                'result': result
            })

            if not result.get('success', False):
                all_success = False
                logger.warning(f"[D2] Step {step_num} failed: {result.get('error', 'Unknown error')}")

        if container_id:
            logger.info(f"[D2] Keeping container running for follow-up testing: {container_id}")

        self.memory.record_action({
            'type': 'execution',
            'steps': steps_executed,
            'success': all_success
        })

        raw_output_payload = {
            'steps': raw_outputs,
            'container_id': container_id,
            'service_url': service_url,
            'container_kept_running': bool(container_id),
            'service_ready': service_ready,
            'all_success': all_success,
        }

        return {
            'steps_executed': steps_executed,
            'raw_output': json.dumps(raw_output_payload, ensure_ascii=False),
            'results': raw_outputs,
            'all_success': all_success,
            'container_id': container_id,
            'service_url': service_url,
            'container_kept_running': bool(container_id),
            'service_ready': service_ready,
        }

    def _rewrite_http_body(self, body: str, service_url: str) -> str:
        if not isinstance(body, str) or not body:
            return body

        rewritten = (
            body
            .replace("${TARGET_API}", service_url)
            .replace("${TARGET_URL}", service_url)
            .replace("TARGET_API", service_url)
        )

        def replace_cat(match) -> str:
            raw_path = match.group(1).strip().strip('"').strip("'")
            try:
                resolved_path = self.tools._resolve_local_path(raw_path, prefer_runtime=True)
                return resolved_path.read_text(encoding='utf-8', errors='ignore').strip()
            except Exception:
                return match.group(0)

        return re.sub(r"\$\(\s*cat\s+(.+?)(?:\s*\)|$)", replace_cat, rewritten)

    def _conclude(self, understanding: Dict, execution: Dict) -> Dict:
        """根据理解与执行结果生成最终结论。"""
        prompt = f"""
# 最终结论任务

## 漏洞理解
{json.dumps(understanding, ensure_ascii=False, indent=2)}

## 执行结果
{json.dumps(execution, ensure_ascii=False, indent=2)}

## 输出要求

请综合漏洞理解与执行结果，判断漏洞是否真实可利用，并给出简洁、可审计的结论。

请只输出 JSON，格式如下：

{{
    "exploitable": true/false,
    "confidence": "high/medium/low",
    "reason": "结论原因",
    "evidence": ["证据1", "证据2"],
    "fix_suggestion": "修复建议"
}}

不要输出 JSON 之外的任何解释。
"""

        response = self.llm.chat(prompt, self.SYSTEM_PROMPT)

        try:
            result = self._extract_json(response)

            exploitable = result.get('exploitable', False)
            if isinstance(exploitable, str):
                exploitable = 'true' in exploitable.lower()

            return {
                'exploitable': exploitable,
                'confidence': result.get('confidence', 'low'),
                'reason': result.get('reason', ''),
                'evidence': result.get('evidence', []),
                'fix_suggestion': result.get('fix_suggestion', '')
            }
        except:
            logger.warning(f"[D2] Failed to parse conclusion: {response[:200]}")
            step_errors = []
            for item in execution.get('results', []):
                result = item.get('result', {}) or {}
                if not result.get('success', False):
                    error = result.get('error')
                    if error:
                        step_errors.append(f"{item.get('tool', 'step')}: {error}")

            reason = 'Unable to analyze execution results'
            if step_errors:
                reason = '; '.join(step_errors[:3])
            elif execution.get('steps_executed', 0) == 0:
                reason = 'D2 did not execute any verification steps'

            return {
                'exploitable': False,
                'confidence': 'low',
                'reason': reason,
                'evidence': step_errors[:3],
                'fix_suggestion': 'Please review manually'
            }

    def _map_tool_params(self, tool: str, params: Dict) -> Dict:
        """映射工具参数，处理LLM生成的不匹配参数"""
        mapped = {}

        if tool == "docker_build":
            # 映射 docker_build 参数
            mapped['path'] = params.get('path') or params.get('context') or params.get('dockerfile_path', '.')
            mapped['tag'] = params.get('tag') or params.get('image_name', 'test-image:latest')
        elif tool == "docker_run":
            # 映射 docker_run 参数
            mapped['image'] = params.get('image') or params.get('image_name', 'test-image:latest')
            mapped['ports'] = params.get('ports') or params.get('port_mappings', {})
            mapped['command'] = params.get('command', '')
            mapped['timeout'] = params.get('timeout', 120)
        elif tool == "http_request":
            # 映射 http_request 参数
            mapped['method'] = params.get('method', 'GET')
            mapped['url'] = params.get('url') or params.get('endpoint', '')
            mapped['headers'] = params.get('headers', {})
            mapped['body'] = params.get('body', '')
            mapped['timeout'] = params.get('timeout', 10)
        elif tool == "shell_exec":
            # 映射 shell_exec 参数
            mapped['command'] = params.get('command') or params.get('cmd', '')
            mapped['timeout'] = params.get('timeout', 30)
            mapped['cwd'] = params.get('cwd')
        elif tool == "read_file":
            # 映射 read_file 参数
            mapped['path'] = params.get('path') or params.get('file_path', '')
        else:
            # 其他工具直接传递参数
            mapped = params

        return mapped

    def _extract_json(self, text: str) -> Dict:
        """从文本中提取JSON"""
        # 尝试找到JSON块
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            json_str = json_match.group(0)
            # 尝试修复常见的JSON问题
            # 移除尾随逗号
            json_str = re.sub(r',(\s*[\]\}])', r'\1', json_str)
            return json.loads(json_str)

        # 尝试直接解析
        return json.loads(text)
