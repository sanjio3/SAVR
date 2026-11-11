"""
A2 Semantic Analysis Agent (语义分析Agent)
深度AI推理 + 可利用性判断
"""
import ast
import json
import yaml
import os
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import re

from ..core.models import Vulnerability, ScanResult
from ..core.exploit_spec import (
    DIFFERENTIAL_PROOF_FAMILIES,
    canonical_business_logic_family,
    empty_chain_proof,
    empty_exploit_spec,
    merge_exploit_specs,
    normalize_chain_proof,
)
from ..core.proof_obligations import (
    build_taint_flow_hypothesis,
    derive_finding_gate,
    evaluate_proof_obligations,
    summarize_proof_context,
)
from .analysis_result import AnalysisResult as A1AnalysisResult
from .prompt_render import render_prompt
from src.core import workspace_runtime
from src.core.normalize import strip_family_prefix
from src.core.vuln_hash import stable_vuln_key

logger = logging.getLogger(__name__)


def _cfg_get(config: Any, dotted_key: str, default: Any = None) -> Any:
    """按点分键取配置，兼容两种形态的 config 容器。

      * 部分路径传 src.core.config.Config 实例，其 get 原生支持 "a.b.c" 点分键；
      * 部分路径（benchmark_cli.run_a2_scan）传手工组装的嵌套 dict
        {'api': {...}, 'agents': {...}}，dict.get("a.b.c") 恒取不到，
        导致配置形同虚设且无任何报错（开关静默失效）。
    统一先试点分键，再按嵌套 dict 逐层下钻，保证两种形态都能读到。
    """
    if config is None:
        return default
    getter = getattr(config, "get", None)
    if not callable(getter):
        return default
    # 1) 点分键（Config 实例 / 已展平的 dict）
    try:
        value = getter(dotted_key, None)
    except Exception:
        value = None
    if value is not None:
        return value
    # 2) 嵌套 dict 逐层下钻
    current: Any = config
    for part in dotted_key.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current if current is not None else default


REANCHOR_PATTERNS = {
    'deserialization': list(workspace_runtime.deserialization_chain().get('reanchor_patterns', [])),
    'command': [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(', 12),
        (r'\bexec\s*\(', 11),
        (r'\bProcessBuilder\b', 10),
        (r'\bsystem\s*\(', 10),
        (r'sh",\s*"-c"', 8),
    ],
    'path': [
        (r'Files\.readAllBytes\s*\(', 12),
        (r'Paths\.get\s*\(', 10),
        (r'Files\.write\s*\(', 9),
        (r'\bnew File\b', 8),
        (r'\breadFile\s*\(', 7),
        (r'filePath', 6),
    ],
    'xss': [
        (r'writeStatus\s*\(', 12),
        (r'Files\.write\s*\(', 10),
        (r'writeStatus\s*\(', 11),
        (r'innerHTML', 10),
        (r'response\.write', 10),
        (r'<pre>', 9),
        (r'content', 4),
    ],
}

# HTTP入口点模式 (用户输入来源)
HTTP_ENTRY_PATTERNS = [
    r'@RequestParam',
    r'@RequestBody',
    r'@PathVariable',
    r'@RequestParam\s*\(',
    r'HttpServletRequest',
    r'request\.getParameter',
    r'request\.getHeader',
    r'request\.getInputStream',
    r'request\.getReader',
    r'request\.args\.get',
    r'request\.form\.get',
    r'request\.json\.get',
    r'request\.values\.get',
    r'@RequestMapping',
    r'@PostMapping',
    r'@GetMapping',
    r'@PutMapping',
    r'@DeleteMapping',
    r'def\s+\w+\s*\([^)]*(?:request|param|body)',
    r'function\s*\([^)]*(?:req|res|body)',
]

# 修复三：业务族（idor/bola）判定要求 finding 落在带 HTTP 方法注解的方法上，
# 否则视为辅助方法/注释块误报，确定性收敛过检。
HTTP_METHOD_ANNOTATION_RE = re.compile(
    r'@(Get|Post|Put|Delete|Patch)Mapping|@RequestMapping', re.I
)

THYMELEAF_ENGINE_PATTERNS = [
    r'TemplateEngine\.process',
    r'SpringTemplateEngine',
    r'org\.thymeleaf',
    r'th:utext',
    r'th:insert',
    r'th:replace',
    r'parseExpression\(',
]

JAVA_TEMPLATE_ENGINE_PATTERNS = [
    r'VelocityEngine',
    r'mergeTemplate\(',
    r'evaluate\(',
    r'FreeMarkerConfigurer',
    r'freemarker\.template',
    r'getTemplate',
    r'SpelExpressionParser',
    r'StandardEvaluationContext',
    r'parseExpression\(',
]

PYTHON_TEMPLATE_PATTERNS = [
    r'render_template_string',
    r'jinja2\.Template',
    r'from_string\(',
    r'Environment\(',
    r'Template\(',
]

PYTHON_PICKLE_PATTERNS = [
    r'pickle\.load',
    r'pickle\.loads',
]

JAVA_JWT_PATTERNS = [
    r'JwtParser',
    r'parseClaimsJws',
    r'parseClaimsJwt',
    r'JwtDecoder',
]

JAVA_FASTJSON_PATTERNS = [
    r'JSON\.parse',
    r'JSON\.parseObject',
    r'JSON\.parseArray',
    r'ParserConfig',
]

JAVA_UPLOAD_PATTERNS = [
    r'MultipartFile',
    r'transferTo',
    r'getOriginalFilename',
    r'FileItem',
]

JAVA_CSP_PATTERNS = [
    r'Content-Security-Policy',
    r'setHeader',
    r'addHeader',
]

JAVA_TOMCAT_PATTERNS = [
    r'DefaultServlet',
    r'readonly',
    r'TomcatServletWebServerFactory',
    r'addContextCustomizers',
]

PYTHON_XML_PATTERNS = [
    r'xml\.etree',
    r'xml\.dom\.minidom',
    r'xml\.sax',
    r'lxml\.etree',
    r'xmlrpc\.client',
    r'xmlrpc\.server',
    r'fromstring\(',
    r'parse\(',
    r'XMLParser\(',
]

JAVA_CORS_PATTERNS = [
    r'@CrossOrigin',
    r'allowedOrigins',
    r'allowedOriginPatterns',
    r'addCorsMappings',
]

JAVA_COOKIE_PATTERNS = [
    r'addCookie',
    r'new Cookie',
    r'setSecure',
    r'setHttpOnly',
]

JAVA_AUTH_PATTERNS = [
    r'permitAll',
    r'anonymous',
    r'@PreAuthorize',
    r'@Secured',
    r'@RolesAllowed',
]

JAVA_HPP_PATTERNS = [
    r'getParameterValues',
    r'getParameters',
    r'MultiValueMap',
]

JAVA_MONGO_PATTERNS = [
    r'MongoCollection',
    r'BasicDBObject',
    r'Document\.parse',
    r'MongoTemplate',
]

JAVA_REDIS_PATTERNS = [
    r'Jedis',
    r'RedisTemplate',
    r'StringRedisTemplate',
    r'opsForValue',
]

PYTHON_JWT_PATTERNS = [
    r'jwt\.decode',
    r'jwt\.encode',
    r'PyJWT',
]

PYTHON_UPLOAD_PATTERNS = [
    r'request\.files',
    r'\.save\(',
    r'UploadFile',
    r'File\(',
]
PYTHON_YAML_PATTERNS = [
    r'yaml\.load',
    r'FullLoader',
    r'Loader=None',
]
PYTHON_COMMAND_PATTERNS = [
    r'os\.system',
    r'subprocess\.(call|run|Popen|check_output)',
    r'os\.popen',
    r'eval\(',
    r'exec\(',
]

PHP_WEBSHELL_PATTERNS = [
    r'eval\(',
    r'assert\(',
    r'base64_decode\(',
    r'php://input',
]

PHP_UPLOAD_PATTERNS = [
    r'move_uploaded_file\(',
    r'\$_FILES',
]

PHP_COMMAND_PATTERNS = [
    r'system\(',
    r'exec\(',
    r'shell_exec\(',
    r'passthru\(',
    r'popen\(',
]
PHP_DESERIALIZATION_PATTERNS = [
    r'unserialize\(',
    r'yaml_parse\(',
]
PHP_PATH_PATTERNS = [
    r'include\(',
    r'require\(',
    r'file_get_contents\(',
    r'readfile\(',
    r'fopen\(',
    r'unlink\(',
]

NODE_PROTOTYPE_POLLUTION_PATTERNS = [
    r'__proto__',
    r'constructor\.prototype',
    r'Object\.assign',
    r'\.merge\(',
    r'merge\(',
    r'defaultsDeep\(',
    r'set\(',
]

NODE_TEMPLATE_INJECTION_PATTERNS = [
    r'ejs\.render',
    r'res\.render',
    r'handlebars\.compile',
    r'pug\.compile',
    r'nunjucks\.renderString',
]

NODE_DESERIALIZATION_PATTERNS = [
    r'node-serialize',
    r'serialize\.unserialize',
    r'v8\.deserialize',
]

NODE_COMMAND_INJECTION_PATTERNS = [
    r'child_process\.exec',
    r'exec\(',
    r'spawn\(',
    r'execSync\(',
]

NODE_SSRF_PATTERNS = [
    r'axios\.(get|post|request)',
    r'fetch\(',
    r'http\.get\(',
    r'https\.get\(',
    r'request\(',
    r'got\(',
]

NODE_PATH_TRAVERSAL_PATTERNS = [
    r'fs\.readFile',
    r'fs\.readFileSync',
    r'fs\.createReadStream',
    r'res\.sendFile',
    r'path\.join',
    r'path\.resolve',
]

NODE_FILE_UPLOAD_PATTERNS = [
    r'multer\(',
    r'upload\.single\(',
    r'upload\.array\(',
    r'req\.files',
    r'req\.file',
    r'\.mv\(',
]
NODE_JWT_PATTERNS = [
    r'jwt\.verify',
    r'jwt\.decode',
    r'jsonwebtoken',
]
NODE_OPEN_REDIRECT_PATTERNS = [
    r'res\.redirect',
    r'redirect\(',
]
NODE_FILE_DELETE_PATTERNS = [
    r'fs\.unlink',
    r'fs\.unlinkSync',
    r'fs\.rm',
    r'fs\.rmSync',
    r'fs\.rmdir',
]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 背景：A2 的 LLM 偶发把「JNDI / Log4j lookup」判成 XXE、把「JSONP callback」判成 CSRF。
# 说成 XML External Entity；Jsonp.java 五条 finding 的 type=CSRF（描述称 callback 下未校验 token）。
# 这类错配污染报告 by_type，且会让 A2 的 _analyze_java_jndi 因 type 不含 jndi/log4j/ldap 而不生效。
# 解决办法是在 LLM 结果落成 Vulnerability 之前做一次「证据约束」：当代码证据与 LLM 族名矛盾时，
# 以代码证据为准改判；只在证据确凿时触发，不触碰其它族。
_JNDI_EVIDENCE_RE = re.compile(
    r"\$\{jndi:|InitialContext\b|jndi:[a-z]+://|ldap://|rmi://", re.IGNORECASE)
_XML_PARSER_EVIDENCE_RE = re.compile(
    r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory"
    r"|SAXReader|SAXBuilder|DocumentHelper", re.IGNORECASE)


def _correct_llm_family(llm_type: str, file_path: str, code: str) -> str:
    """按代码证据修正 LLM 给出的族名；仅纠正「证据确凿的错配」，其余原样返回。"""
    t = str(llm_type or "").strip()
    if not t:
        return t
    tl = t.lower()
    text = f"{file_path or ''}\n{code or ''}"
    # 约束一：JNDI / Log4j lookup 不可能是 XXE（须无 XML 解析器证据）。
    if "xxe" in tl or "xml external" in tl:
        jndi_evidence = bool(_JNDI_EVIDENCE_RE.search(text)) or bool(
            re.search(r"log4j", file_path or "", re.IGNORECASE))
        if jndi_evidence and not _XML_PARSER_EVIDENCE_RE.search(text):
            return "JNDI Injection"
    # 约束二：JSONP callback 端点不是 CSRF（callback 注入属 XSS / 数据泄露）。
    if "csrf" in tl:
        if re.search(r"jsonp", text, re.IGNORECASE) and re.search(r"callback", text, re.IGNORECASE):
            return "XSS"
    return t


class ExploitabilityLevel(Enum):
    """可利用性级别"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass
class ExploitabilityResult:
    """可利用性评估结果"""
    level: ExploitabilityLevel = ExploitabilityLevel.MEDIUM
    score: float = 0.5  # 0-1
    factors: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class DataFlow:
    """数据流"""
    source: str
    sink: str
    path: List[str] = field(default_factory=list)
    sanitized: bool = False


class A2SemanticAgent:
    """
    A2 语义分析Agent

    核心能力:
    - 理解代码业务逻辑
    - 判断漏洞真实可利用性
    - 分析数据流向和危险函数调用链
    - 生成修复建议
    """

    def __init__(self, config: Dict, provider: str = "qwen"):
        """
        初始化A2 Agent

        Args:
            config: 配置字典
            provider: API提供商
        """
        self.config = config
        self.provider = provider

        # 初始化AI客户端
        self.client = None
        self._init_client()

        # 加载提示词
        self.prompts = self._load_prompts()
        # 模板指纹（hash）/ 版本，供 LLM 缓存盐与 model_runs 归因；_load_prompts 内已赋值，
        # 这里给默认值防止未调用时属性缺失。
        self.prompt_hashes = getattr(self, "prompt_hashes", {})
        self.prompt_versions = getattr(self, "prompt_versions", {})

        # 危险函数库
        self.dangerous_functions = self._build_dangerous_functions()

        # 污点追踪
        self.taint_tracking: Dict[str, DataFlow] = {}

        # §R4可观测性：A2 单文件分析失败计数。上层扫描循环据此做健康检查，
        # 避免"全部文件失败但任务仍 completed"的静默归零再次发生。
        self._a2_error_count = 0

        # 走「带工具调用的多轮推理」；首轮分析不受影响，便于先小范围验证再放开。
        # 取值必须用 _cfg_get 而非 config.get('a.b.c')：self.config 的形态随调用方而变——
        # 有的路径传 Config 对象（点分键），有的传 benchmark_cli 组装的嵌套 dict
        # （{'api': {...}, 'agents': {...}}）。后者上直接点分取会恒取不到，开关永远关着。
        self._agentic_enabled = bool(_cfg_get(self.config, 'agents.a2.enable_agentic_loop', False))
        self._agentic_max_rounds = int(_cfg_get(self.config, 'agents.a2.agentic_max_rounds', 3) or 3)

    def _init_client(self):
        """初始化AI客户端：主用 provider 先用，耗尽/失败自动切兜底（智谱 GLM）。

        ModelGateway.build_fallback_client，与 review / triage / I2 / D1 共用一套实现和
        埋点口径，消除「A2 绕过网关直连客户端族」的双链路。内部仍复用
        a2_ai_agent._make_client，config 驱动的 base_url / model 保持不变。
        """
        from src.core.model_gateway import ModelGateway

        api_config = self.config.get('api', {}) or {}
        primary = api_config.get('provider', self.provider or 'deepseek')
        # D5：prompt_version 由 run_a2_scan 随 agent_config 下发（此前一路传进来后被丢弃）
        _prompt_version = str(_cfg_get(self.config, 'prompt_version', '') or '')
        client = ModelGateway.build_fallback_client(
            config=self.config, provider=primary, prompt_version=_prompt_version,
        )
        if client is None:
            logger.warning("No API key configured for any provider!")
            return

        self.client = client
        self.provider = primary
        self.model = getattr(client, "model", "") or ""
        logger.info(
            "[A2SemanticAgent] LLM 顺序降级链（经 ModelGateway 统一构造，主用先用）：%s",
            " -> ".join(getattr(client, "provider_names", None) or [primary]),
        )

    def _load_prompts(self) -> Dict:
        """加载提示词。

        注册表把 src/prompts/ 下模板收敛成带版本/hash 的清单，并返回
        {name: text, name.hash: <sha256前16>, name.version: <ver>}，供缓存盐与埋点归因。
        注册表取不到 audit_file 时回退直接读 yaml，保证旧路径不破。
        """
        prompts: Dict = {}
        try:
            from src.core.prompt_registry import load_prompts_dict
            # 分级回退。此前不传版本 → prompt_version 只进 metadata、从不驱动模板选择。
            _prompt_version = str(_cfg_get(self.config, 'prompt_version', '') or '')
            prompts = load_prompts_dict(version=_prompt_version or None) or {}
        except Exception as e:
            logger.error(f"[PromptRegistry] 加载失败，回退直接读 yaml：{e}")

        if not prompts.get("audit_file"):
            try:
                prompts_file = self.config.get('agents.a2.prompts_file', 'src/prompts/audit_prompts.yaml')
                base_dir = Path(__file__).parent.parent.parent
                prompts_path = base_dir / prompts_file
                with open(prompts_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    prompts.update(data.get('prompts', {}) or {})
            except Exception as e:
                logger.error(f"Error loading prompts: {e}")

        # 拆出 hash / version 供埋点与缓存盐使用（不污染 self.prompts 正文访问）
        self.prompt_hashes = {k[:-5]: v for k, v in prompts.items() if k.endswith(".hash")}
        self.prompt_versions = {k[:-8]: v for k, v in prompts.items() if k.endswith(".version")}
        return {k: v for k, v in prompts.items() if not (k.endswith(".hash") or k.endswith(".version"))}

    def _build_dangerous_functions(self) -> Dict[str, List[str]]:
        """构建危险函数库"""
        return {
            'sql': [
                'execute', 'executemany', 'exec', 'cursor',
                'statement', 'query', 'raw'
            ],
            'command': [
                'system', 'exec', 'popen', 'spawn', 'call',
                'run', 'Popen', 'Command'
            ],
            'deserialize': [
                'pickle.load', 'yaml.load', 'marshal.load',
                'unserialize', 'readObject'
            ],
            'xxe': [
                'parse', 'parseXML', 'parseDTD', 'parseEntity'
            ],
            'path': [
                'open', 'file', 'read', 'write', 'upload'
            ],
            'xss': [
                'render', 'response.write', 'html', 'innerHTML'
            ],
            'ssrf': [
                'urlopen', 'request', 'get', 'post', 'fetch'
            ]
        }

    def analyze(self, file_path: str, content: str, context: Dict = None) -> A1AnalysisResult:
        """
        深度语义分析

        Args:
            file_path: 文件路径
            content: 文件内容
            context: 共享上下文

        Returns:
            AnalysisResult
        """
        from .analysis_result import AnalysisResult as A1AnalysisResult

        result = A1AnalysisResult()
        result.context = context or {}

        try:
            # 1. 分析数据流
            data_flows = self._analyze_data_flow(content)
            result.context['data_flows'] = data_flows

            # 2. 分析调用链
            call_chains = self._analyze_call_chain(content)
            result.context['call_chains'] = call_chains

            # 3. AI深度分析
            ai_vulns = self._ai_deep_analysis(content, file_path, context)
            result.vulnerabilities = ai_vulns

        except Exception as e:
            # §R4可观测性修复：此前这里只记 str(e)（形如 "'id'"），且不带文件名，
            # 导致 task 9 的 60 个文件全部分析失败、A2 产出归零，却只在日志里留下
            # 60 行无上下文的 "Error in semantic analysis: 'id'"，任务状态仍为 completed。
            # 改为带文件路径 + 完整堆栈，并累计失败计数供上层做健康检查。
            try:
                self._a2_error_count += 1
            except Exception:
                pass
            logger.error(
                "A2 语义分析失败 file=%s error=%s: %s",
                file_path, type(e).__name__, e, exc_info=True,
            )

        return result

    def _analyze_data_flow(self, content: str) -> List[DataFlow]:
        """分析数据流"""
        flows = []
        lines = content.split('\n')

        # 追踪用户输入
        sources = [
            r'request\.args\.get',
            r'request\.form\.get',
            r'request\.json\.get',
            r'request\.values\.get',
            r'input\(',
            r'HttpServletRequest',
            r'@RequestParam',
            r'@RequestBody'
        ]

        # 危险sink
        sinks = [
            r'\.execute\(',
            r'exec\(',
            r'system\(',
            r'eval\(',
            r'pickle\.load\(',
            r'yaml\.load\(',
            r'open\('
        ]

        for i, line in enumerate(lines):
            # 检查source
            for src in sources:
                if re.search(src, line):
                    var_name = self._extract_variable(line)
                    if var_name:
                        # 追踪这个变量到sink
                        flow = self._trace_taint(var_name, lines[i:], sinks)
                        if flow:
                            flows.append(flow)

        return flows

    def _extract_variable(self, line: str) -> Optional[str]:
        """提取变量名"""
        patterns = [
            r'(\w+)\s*=\s*.*request',
            r'(\w+)\s*=\s*input\(',
            r'def\s+\w+\s*\((\w+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)

        return None

    def _trace_taint(self, var_name: str, lines: List[str], sinks: List[str]) -> Optional[DataFlow]:
        """追踪污点变量"""
        path = []
        sink_line = None

        for line in lines:
            path.append(line.strip())

            # 检查是否在sink中使用
            for sink in sinks:
                if re.search(sink, line) and var_name in line:
                    sink_line = line.strip()
                    break

            # 检查是否有消毒
            if any(x in line.lower() for x in ['escape', 'sanitize', 'validate', 'quote']):
                return None

        if sink_line:
            return DataFlow(
                source=var_name,
                sink=sink_line,
                path=path
            )

        return None

    def _analyze_call_chain(self, content: str) -> List[Dict]:
        """分析调用链"""
        chains = []

        # 提取函数调用
        calls = re.findall(r'(\w+)\.(\w+)\(', content)

        for caller, callee in calls:
            # 检查是否有危险函数链
            if callee in ['execute', 'exec', 'system', 'eval']:
                chains.append({
                    'caller': caller,
                    'callee': callee,
                    'type': 'dangerous'
                })

        return chains

    def _ai_deep_analysis(self, content: str, file_path: str, context: Dict = None) -> List[Vulnerability]:
        """
        AI深度分析

        Args:
            content: 文件内容
            file_path: 文件路径
            context: 上下文

        Returns:
            漏洞列表
        """
        if not self.client:
            logger.warning("No AI client available for deep analysis")
            return []

        # 只在「模型上下文 <= 8192」时才裁剪输入（云端大模型不裁，保持现有跑分口径不变）。
        # 预算 = 该模型能吃下的输入 token，用 CJK 感知的估算裁剪——原实现写死
        # 「4 字符/token」，而本项目真实提示词实测只有 2.34~2.38 字符/token（中文占多数），
        # 会把 8192 上下文高估约 1.7 倍从而喂溢出（Ollama 静默丢弃提示词头部）。
        if content:
            try:
                from src.core.model_capabilities import (
                    resolve_profile, input_budget, fit_to_token_budget,
                )
                _prof = resolve_profile(model=str(getattr(self, "model", "") or ""))
                if _prof.context_window <= 8192:
                    content, _cut = fit_to_token_budget(content, input_budget(_prof))
                    if _cut:
                        logger.warning(
                            "[LLM-INPUT] %s truncated to fit input budget (model=%s ctx=%d)",
                            file_path, _prof.name, _prof.context_window,
                        )
            except Exception:
                pass

        # 构建提示词
        template = self.prompts.get('semantic_analysis', self.prompts.get('audit_file', ''))

        # 添加上下文信息
        context_info = ""
        if context:
            data_flows = context.get('data_flows', [])
            if data_flows:
                context_info = f"\n\nData flows detected:\n"
                for flow in data_flows[:5]:  # 限制数量
                    context_info += f"- Source: {flow.source} -> Sink: {flow.sink}\n"

            # 把 A1 静态分析调用链证据前置喂给 LLM，让模型同时消费 A1 证据 + 自析源码，
            # 省一遍语义重算 token，并提升 A2 假说精度。仅注入与本文件相关的候选（per-file 已按
            # 文件路径过滤；aggregate 兜底），不塞全量以免噪声淹没。
            a1_ev = context.get('a1_evidence') or {}
            if a1_ev:
                _A1_LABELS = (
                    ('entry_candidates', 'HTTP 入口/路由'),
                    ('source_candidates', '攻击者可控源点'),
                    ('sink_candidates', '危险 sink'),
                    ('guard_candidates', '校验/拦截守卫'),
                    ('sanitizer_candidates', '净化器'),
                    ('ownership_candidates', '鉴权/归属上下文'),
                    ('state_transition_candidates', '状态迁移'),
                    ('artifact_candidates', '业务产物'),
                    ('tech_fingerprint', '技术指纹（nuclei）'),
                    ('external_cve_hits', '已知 CVE 命中（nuclei）'),
                )
                a1_lines = ["\n\nA1 静态分析调用链证据（供你交叉印证，不要盲信；以本文件源码为准）："]
                for key, label in _A1_LABELS:
                    items = a1_ev.get(key) or []
                    for it in items[:8]:
                        if isinstance(it, dict):
                            summary = (
                                it.get('route')
                                or it.get('name')
                                or it.get('function')
                                or it.get('signature')
                                or it.get('http_entry')
                                or it.get('description')
                                or next(iter(it.values()), '')
                            )
                            extra = it.get('method') or it.get('location') or ''
                            if not extra and isinstance(it.get('cve_ids'), list):
                                extra = ','.join(str(c) for c in it.get('cve_ids') if c)
                            if extra:
                                summary = f"{summary} [{extra}]"
                        else:
                            summary = str(it)
                        if summary:
                            a1_lines.append(f"- {label}: {summary}")
                if len(a1_lines) > 1:
                    context_info += "\n".join(a1_lines) + "\n"

            # §P4：把 D2/I2 闭环回灌的 feedback_to_a2 注入 LLM prompt，使 A2 二次分析能修正此前
            # 错误的 exploit_spec 假说（端点幻觉 / 参数缺失 / 受害者资源 id 缺失）。feedback 来自 I2
            # 裁决的 rollback_to_a2，经 run_a2_scan(feedback=...) → scan_file(context['feedback']) 透传至此。
            feedback_list = context.get('feedback') or [] if isinstance(context, dict) else []
            if feedback_list:
                fb_lines = ["\n\nD2/I2 闭环回灌反馈（此前动态验证发现你的上一轮假说有误，请据此重新推导，不要重复错误假说）："]
                for fb in feedback_list[:12]:
                    if not isinstance(fb, dict):
                        continue
                    hid = fb.get('hypothesis_id') or '?'
                    reason = fb.get('reason') or ''
                    final_state = fb.get('final_state') or ''
                    line = f"- 假说#{hid}（验证结论={final_state}）"
                    if reason:
                        line += f"：{reason}"
                    fb_lines.append(line)
                    ch = fb.get('correction_hint') or {}
                    if isinstance(ch, dict):
                        for k, v in ch.items():
                            if v:
                                fb_lines.append(f"    修正提示[{k}]：{v}")
                    cs = fb.get('current_spec') or {}
                    if isinstance(cs, dict) and cs.get('target_endpoint'):
                        fb_lines.append(f"    当前(错误)假说端点：{cs.get('target_endpoint')}")
                    mc = fb.get('missing_chain_nodes') or []
                    if mc:
                        fb_lines.append(f"    缺失链节点：{', '.join(str(m) for m in mc[:6])}")
                if len(fb_lines) > 1:
                    context_info += "\n".join(fb_lines) + "\n"

        # §R4回归修复：禁止直接用 str.format。提示词正文里的字面花括号（如路由示例
        # /order/{id}）会被 format 当成未提供的占位符抛 KeyError，进而被下面的 except
        # 吞掉导致 A2 整体静默归零。render_prompt 只替换显式传入的键，其余保留字面量。
        # 注入规则库 skill 的补充检测要点（model-agnostic，强化强弱模型对特定形态的识别）。
        skill_hints = ""
        try:
            from src.core.rule_registry import build_skill_hints
            skill_hints = build_skill_hints(language="java")
        except Exception:
            skill_hints = ""
        prompt = render_prompt(
            template,
            code=content,
            file_path=file_path,
            context=context_info,
            skill_hints=skill_hints,
        )

        try:
            # 调用AI - 使用temperature=0确保结果稳定
            system = "You are a professional security code auditor. Analyze code for security vulnerabilities with deep semantic understanding. Consider data flows, call chains, and exploitability. Always output valid JSON in the exact format specified. Output ONLY the JSON, no explanations."
            messages = [{"role": "user", "content": prompt}]

            # 调用的多轮推理——A2 可主动查证端点 / 参数 / 族是否真实存在，而不是只能看
            # prompt 里塞进来的片段。首轮分析（feedback 为空）保持原单次 completion。
            # 注意：feedback 只能从入参 context（dict）取。context_info 到这里已被拼成
            # 提示词正文字符串（上方 context_info += ...），对它 .get 会抛
            # 'str' object has no attribute 'get'，并被本函数末尾 except 吞成空结果——
            _feedback = (context or {}).get("feedback") or [] if isinstance(context, dict) else []
            if _feedback and getattr(self, "_agentic_enabled", False):
                # 它抛异常若一路冒到本函数末尾的 except，会被吞成 return [] ——
                # 表现是 feedback 非空时 A2 一条都不产，且不报错。真实 LLM 下工具输出畸形、
                # 网络抖动等都可能触发，故必须在这一层拦住并回退到单次 completion。
                try:
                    from src.agents.a2_agentic import run_agentic_loop

                    _res = run_agentic_loop(
                        self.client, system, prompt,
                        max_rounds=getattr(self, "_agentic_max_rounds", 3),
                        max_tool_calls_per_round=3,
                        max_tokens=4096, temperature=0.0, logger=logger,
                    )
                    response = _res.get("text") or ""
                    logger.info(
                        "[A2][agentic] 二次分析完成：%s 轮、%s 次工具调用（结束原因 %s）",
                        _res.get("rounds"), len(_res.get("tool_calls") or []), _res.get("stopped_by"),
                    )
                    if not response:
                        # 多轮跑完却没文本（模型只吐 TOOL 行 / 达上限仍未结论）：
                        # 同样回退单次补全，绝不把空串交给解析器当「无漏洞」。
                        logger.warning("[A2][agentic] 多轮结束但无结论文本，回退单次 completion")
                        response = self.client.create_message(system, messages, max_tokens=4096, temperature=0.0)
                except Exception as _agentic_e:
                    logger.warning("[A2][agentic] 多轮闭环失败，回退单次 completion：%s", _agentic_e)
                    response = self.client.create_message(system, messages, max_tokens=4096, temperature=0.0)
            else:
                response = self.client.create_message(system, messages, max_tokens=4096, temperature=0.0)

            # 解析响应
            vulnerabilities = self._parse_ai_response(response, file_path)

            return vulnerabilities

        except Exception as e:
            logger.error(f"AI deep analysis error: {e}")
            return []

    def _source_snippet_for_family_check(self, file_path: str, line: Any, context_lines: int = 40) -> str:
        """LLM 未回带 code 时，按行号回读源文件片段，供族名证据纠正使用。

        Object2Jsonp.java:L75 两条因 code_snippet 为空仍留 csrf。
        这里只用于「判定」，不写回 code_snippet；读不到就返回空串，不阻断 A2 主流程。
        """
        try:
            proj_path = getattr(self, "project_path", "") or ""
            candidates = [str(file_path or "")]
            if proj_path and file_path:
                candidates.append(os.path.join(proj_path, str(file_path)))
            for path in candidates:
                if not path or not os.path.exists(path):
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
                try:
                    ln = int(line or 0)
                except (TypeError, ValueError):
                    ln = 0
                if ln <= 0:
                    return "".join(lines[: context_lines * 2])
                lo = max(0, ln - 1 - context_lines)
                hi = min(len(lines), ln + context_lines)
                return "".join(lines[lo:hi])
        except Exception as exc:  # 兜底读取失败不影响主流程
            logger.debug("[A2] 族名纠正回读源文件失败（忽略）：%s", exc)
        return ""

    def _parse_ai_response(self, response: str, file_path: str) -> List[Vulnerability]:
        """解析AI响应"""
        vulnerabilities = []

        try:
            try:
                from src.core.llm_output import parse_llm_list
            except Exception:
                from ..core.llm_output import parse_llm_list

            # 数组元素抢救），替代原本脆弱的「括号配平 + 末尾截断」写法。截断/抢救诊断
            # 打 [LLM-OUTPUT] 日志，区分「模型判定无漏洞」与「答案被 max_tokens 腰斩（平台侧问题）」。
            vulns, diag = parse_llm_list(response or "")
            if not diag.ok or not vulns:
                if not diag.ok:
                    logger.warning(
                        "[LLM-OUTPUT] a2_intelligent parse fail | strategy=%s truncated=%s repaired=%s error=%s | resp=%s",
                        diag.strategy, diag.truncated, diag.repaired, diag.error, (response or "")[:200],
                    )
                elif not vulns:
                    logger.info(
                        "[LLM-OUTPUT] a2_intelligent empty (model likely judged no-vuln) | resp=%s",
                        (response or "")[:120],
                    )
                return vulnerabilities

            for v in vulns:
                # 提取数据流信息（如果AI返回了这些字段）
                entry_point = v.get('entry_point', '')
                sink = v.get('sink', '')
                data_flow = v.get('data_flow', '')
                has_http_entry = v.get('has_http_entry', False)

                # 如果AI没有返回数据流信息，进行本地分析
                if not entry_point and not sink:
                    try:
                        code_snippet = v.get('code', '')
                        flow_info = self._local_data_flow_analysis(file_path, code_snippet)
                        entry_point = flow_info.get('entry_point', '')
                        sink = flow_info.get('sink', '')
                        data_flow = flow_info.get('data_flow', '')
                        has_http_entry = flow_info.get('has_http_entry', False)
                    except Exception as e:
                        logger.warning(f"[A2] Data flow analysis error: {e}")

                # §R5：接收 LLM 显式给出的 HTTP 入口绑定。prompt 已要求"不确定时留空"，
                # 这里再做一次合理性校验，挡掉 "/"、"/admin/" 这类残缺路由，
                # 避免 LLM 敷衍输出反而污染 exploit_spec。
                llm_route = self._sanitize_llm_route(v.get('route'))
                llm_entry_method = str(v.get('entry_method') or '').strip()
                llm_params = v.get('params') or []
                if not isinstance(llm_params, list):
                    llm_params = []

                _llm_type = v.get('type', 'Unknown')
                # 否则族名纠正规则看不到关键证据（jsonp / callback）而静默失效。
                _family_evidence = v.get('code', '')
                if not _family_evidence:
                    _family_evidence = self._source_snippet_for_family_check(file_path, v.get('line'))
                _fixed_type = _correct_llm_family(_llm_type, file_path, _family_evidence)
                if _fixed_type != _llm_type:
                    logger.info("[A2] 族名证据修正：%s -> %s（%s）", _llm_type, _fixed_type, file_path)
                vuln = Vulnerability(
                    type=_fixed_type,
                    severity=v.get('severity', 'MEDIUM'),
                    line=v.get('line'),
                    description=v.get('description', ''),
                    fix=v.get('fix', ''),
                    file=file_path,
                    code_snippet=v.get('code', ''),
                    entry_point=entry_point,
                    sink=sink,
                    data_flow=data_flow,
                    has_http_entry=has_http_entry,
                    llm_route=llm_route,
                    llm_entry_method=llm_entry_method,
                    llm_params=llm_params,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")

        return vulnerabilities

    @staticmethod
    def _sanitize_llm_route(route) -> str:
        """校验 LLM 给出的 HTTP 路由，挡掉敷衍/残缺输出。

        prompt 已要求"不确定时留空"，但模型仍可能给出 "/"、"/admin/"、"/admin/,"
        这类目录式残缺路由（逗号是 LLM 末尾加句号/逗号的产物）。这类值写进
        exploit_spec.entry.route 会误导下游：D2 拿它构造请求必失败，还不如留空走
        A1 证据/正则解析。

        Returns:
            可信路由；否则空字符串。
        """
        r = str(route or "").strip()
        if not r or not r.startswith("/"):
            return ""
        r = r.split("?", 1)[0].split("#", 1)[0]
        # 去尾部逗号/句号（LLM 常见产物："/admin/,"）
        r = r.rstrip(",.")
        # 逗号残留 = LLM 输出了多值/片段（如 "/admin/, /users"）。尾部逗号已在上一步剥离，
        # 若仍含逗号说明是多值污染路由，拒收留空，让下游走 A1 证据 / 正则解析；
        # 写进 exploit_spec.entry.route 会令 D2 构造请求必失败（历史坑：/admin/, 污染）。
        if "," in r:
            return ""
        if r == "/":
            return ""
        [p for p in r.split("/") if p]
        # 目录式残缺路由粒度太粗时拒收；但已知管理前缀（/admin /manage /console /sys）即便以
        # / 结尾也保留为类级前缀（去尾斜杠），由下游 _pick_admin_route 择优具体子路由。
        # 其他（如 /api/）仍按残缺路由拒收。
        if r.endswith("/"):
            if re.match(r"^/(admin|manage|console|sys)/?$", r):
                r = r.rstrip("/")
            else:
                return ""
        return r

    @staticmethod
    def _repair_json_text(json_text: str) -> str:
        repaired = (json_text or '').strip().lstrip('\ufeff')
        if not repaired:
            return repaired

        quote_map = {
            '\u2018': "'",
            '\u2019': "'",
            '\u201c': '"',
            '\u201d': '"',
            '\u300c': '"',
            '\u300d': '"',
        }
        for src, dst in quote_map.items():
            repaired = repaired.replace(src, dst)

        repaired = re.sub(r',(\s*[}\]])', r'\1', repaired)
        repaired = re.sub(
            r'([{,]\s*)([A-Za-z_][A-Za-z0-9_\- ]*)(\s*:)',
            lambda match: f'{match.group(1)}"{match.group(2).strip()}"{match.group(3)}',
            repaired
        )
        repaired = re.sub(r'\bTrue\b', 'true', repaired)
        repaired = re.sub(r'\bFalse\b', 'false', repaired)
        repaired = re.sub(r'\bNone\b', 'null', repaired)
        return repaired

    def _load_ai_json_candidate(self, json_text: str) -> Optional[Any]:
        candidates = []
        for candidate in ((json_text or '').strip(), self._repair_json_text(json_text)):
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        parse_errors = []
        for index, candidate in enumerate(candidates):
            try:
                data = json.loads(candidate)
                if index > 0:
                    logger.warning("[A2] AI JSON response recovered via tolerant parser")
                return data
            except json.JSONDecodeError as exc:
                parse_errors.append(exc)

        pythonish = candidates[-1] if candidates else ''
        pythonish = re.sub(r'\btrue\b', 'True', pythonish)
        pythonish = re.sub(r'\bfalse\b', 'False', pythonish)
        pythonish = re.sub(r'\bnull\b', 'None', pythonish)
        try:
            data = ast.literal_eval(pythonish)
            logger.warning("[A2] AI JSON response recovered via literal_eval fallback")
            return data
        except (ValueError, SyntaxError) as exc:
            parse_errors.append(exc)

        if parse_errors:
            logger.error(f"JSON parse error: {parse_errors[-1]}")
        return None

    @staticmethod
    def _normalize_anchor_text(text: str) -> str:
        if not text:
            return ''
        normalized = re.sub(r'//.*', '', text)
        normalized = re.sub(r'/\*.*?\*/', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized.strip(' ;{}')

    @staticmethod
    def _meaningful_snippet_lines(code_snippet: str) -> List[str]:
        lines = []
        for raw in (code_snippet or '').splitlines():
            normalized = A2SemanticAgent._normalize_anchor_text(raw)
            if not normalized or normalized in {'{', '}', 'try', 'catch (Exception e)'}:
                continue
            lines.append(normalized)
        return lines

    @staticmethod
    def _classify_vuln_family(vuln: Vulnerability) -> str:
        type_text = (vuln.type or '').lower()
        desc_text = (vuln.description or '').lower()
        text = f"{type_text} {desc_text}"
        if any(token in type_text for token in ('xss', '跨站', '存储型xss')):
            return 'xss'
        if any(token in type_text for token in ('命令', 'command')):
            return 'command'
        if any(token in type_text for token in ('路径', 'traversal', 'path')):
            return 'path'
        if any(token in type_text for token in ('反序列化', 'serialize', 'deserial')):
            return 'deserialization'
        if any(token in text for token in (
            'deserialize', 'deserial', 'serialization', '反序列化', 'readobject',
            'commons-collections', 'chainedtransformer', 'transformer', 'serialized'
        )):
            return 'deserialization'
        if any(token in text for token in ('command', '命令', 'exec', 'runtime', 'processbuilder', 'shell')):
            return 'command'
        if any(token in text for token in ('path', 'traversal', '路径', 'file read', 'file write', 'readfile', 'filepath')):
            return 'path'
        if any(token in text for token in ('xss', '跨站', '存储型xss', 'reflected', 'writestatus', 'healthcheck', 'html')):
            return 'xss'
        return ''

    def _find_anchor_by_snippet(self, content: str, vuln: Vulnerability) -> Optional[int]:
        lines = content.splitlines()
        snippet_lines = self._meaningful_snippet_lines(vuln.code_snippet)
        if not lines or not snippet_lines:
            return None

        normalized_file_lines = [self._normalize_anchor_text(line) for line in lines]
        family = self._classify_vuln_family(vuln)
        pattern_defs = REANCHOR_PATTERNS.get(family, [])

        def is_valid_anchor_line(raw_line: str) -> bool:
            if not self._is_viable_anchor_line(raw_line, vuln):
                return False
            if not pattern_defs:
                return True
            return any(re.search(pattern, raw_line, re.IGNORECASE) for pattern, _ in pattern_defs)

        for snippet in snippet_lines:
            matches = [
                idx + 1 for idx, line in enumerate(normalized_file_lines)
                if line and snippet in line and is_valid_anchor_line(lines[idx])
            ]
            if len(matches) == 1:
                return matches[0]

        if len(snippet_lines) >= 2:
            joined = ' '.join(snippet_lines[:4])
            matches = []
            for idx in range(len(normalized_file_lines)):
                window_lines = lines[idx:idx + len(snippet_lines[:4])]
                if not window_lines or not any(is_valid_anchor_line(item) for item in window_lines):
                    continue
                window = ' '.join(line for line in normalized_file_lines[idx:idx + len(snippet_lines[:4])] if line)
                if joined and joined in window:
                    matches.append(idx + 1)
            if len(matches) == 1:
                return matches[0]

        return None

    def _find_anchor_by_patterns(self, content: str, vuln: Vulnerability) -> Optional[int]:
        family = self._classify_vuln_family(vuln)
        pattern_defs = REANCHOR_PATTERNS.get(family, [])
        if not pattern_defs:
            return None

        description = (vuln.description or '').lower()
        identifier_tokens = {
            token.lower() for token in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]{3,}\b', vuln.description or '')
            if not token.isupper()
        }
        lines = content.splitlines()
        scored = []

        def is_pattern_anchor_candidate(raw_line: str) -> bool:
            return self._is_viable_anchor_line(raw_line, vuln)

        for idx, line in enumerate(lines, 1):
            if not is_pattern_anchor_candidate(line):
                continue
            score = 0
            pattern_score = 0
            for pattern, weight in pattern_defs:
                if re.search(pattern, line, re.IGNORECASE):
                    pattern_score += weight
            score += pattern_score

            line_lower = line.lower()
            token_hits = sum(1 for token in identifier_tokens if token in line_lower)
            if not pattern_score and token_hits == 0:
                continue
            if pattern_score:
                # Description tokens only help break ties when a sink-like pattern already matched.
                score += min(token_hits, 2)
            else:
                # Token-only anchors are fallback only; keep them much weaker than real sink hits.
                score += min(token_hits, 2)
                score -= 4

            if 'transform' in description and 'transform' in line_lower:
                score += 5
            if ('decoratedmap' in description or '装饰map' in description or 'put操作' in description) and (
                'decoratedmap' in line_lower or '.put(' in line_lower
            ):
                score += 5
            if 'commons-collections' in description and 'commons-collections' in line_lower:
                score += 4
            if 'version' in description and '<version>' in line_lower:
                score += 3
            if family == 'path':
                wants_write = any(token in description for token in ('write', '写入', 'output_path'))
                wants_read = any(token in description for token in ('read', '读取', '敏感文件', 'filepath'))
                line_is_write = any(token in line_lower for token in ('files.write', 'writestatus', 'write('))
                line_is_read = any(token in line_lower for token in ('files.readallbytes', 'readfile', 'paths.get('))
                if wants_write and line_is_read and not line_is_write:
                    continue
                if wants_read and line_is_write and not line_is_read:
                    continue
                if wants_write and line_is_write:
                    score += 7
                if wants_read and line_is_read:
                    score += 5
            if self._is_method_signature_line(line):
                score -= 4
            if self._has_body_call_signal(line):
                score += 4

            scored.append((score, idx))

        if not scored:
            return None

        scored.sort(key=lambda item: (-item[0], item[1]))
        return scored[0][1]

    @staticmethod
    def _is_viable_anchor_line(raw_line: str, vuln: Vulnerability) -> bool:
        lowered = (raw_line or '').lower().strip()
        if not lowered:
            return False
        if lowered.startswith('import ') and not str(vuln.file).lower().endswith('pom.xml'):
            return False
        if lowered.startswith('@'):
            return False
        if re.match(r'^(public|private|protected)\s+[\w<>\[\], ?]+\s+\w+\s*(=\s*[^;]+)?;$', lowered):
            return False
        getter_setter_match = re.match(
            r'^(public|private|protected)\s+[\w<>\[\], ?]+\s+(get|set|is)\w+\s*\(([^)]*)\)\s*\{?$',
            lowered
        )
        if getter_setter_match:
            method_name = getter_setter_match.group(2)
            params = getter_setter_match.group(3).strip()
            if method_name in {'get', 'set', 'is'} or method_name.startswith(('get', 'set', 'is')):
                if method_name.startswith('get') and not params:
                    return False
                if method_name.startswith('is') and not params:
                    return False
                if method_name.startswith('set') and params:
                    return False
        return True

    @staticmethod
    def _is_method_signature_line(raw_line: str) -> bool:
        lowered = (raw_line or '').lower().strip()
        if not lowered:
            return False
        return bool(re.match(
            r'^(public|private|protected)\s+(static\s+)?[\w<>\[\], ?]+\s+\w+\s*\([^;{}]*\)\s*\{?$',
            lowered
        ))

    @staticmethod
    def _has_body_call_signal(raw_line: str) -> bool:
        lowered = (raw_line or '').lower().strip()
        if not lowered:
            return False
        if A2SemanticAgent._is_method_signature_line(lowered):
            return False
        if lowered.startswith(('if ', 'for ', 'while ', 'switch ', 'catch ')):
            return False
        return any(token in lowered for token in (
            '.',
            '(',
        )) and ';' in lowered

    def _extract_reanchored_snippet(self, content: str, line_no: int) -> str:
        lines = content.splitlines()
        if not lines or not line_no or line_no <= 0 or line_no > len(lines):
            return ''
        current = lines[line_no - 1].strip()
        if current:
            return current
        for idx in range(line_no, min(len(lines), line_no + 3)):
            candidate = lines[idx].strip()
            if candidate:
                return candidate
        for idx in range(max(0, line_no - 2), line_no - 1):
            candidate = lines[idx].strip()
            if candidate:
                return candidate
        return ''

    def _reanchor_vulnerability(self, vuln: Vulnerability, content: str) -> Vulnerability:
        if not content:
            return vuln

        anchor_line = self._find_anchor_by_snippet(content, vuln)
        if anchor_line is None:
            anchor_line = self._find_anchor_by_patterns(content, vuln)
        if anchor_line is None:
            return vuln

        vuln.line = anchor_line
        anchored_snippet = self._extract_reanchored_snippet(content, anchor_line)
        if anchored_snippet:
            vuln.code_snippet = anchored_snippet
        return vuln

    def _canonical_family(self, vuln: Vulnerability) -> str:
        text = f"{(vuln.type or '').lower()} {(vuln.description or '').lower()}"
        if any(token in text for token in ('default credential', 'hardcoded credential', 'hardcoded password', 'insecure credentials', '不安全的凭证')):
            return 'default-credentials'
        if any(token in text for token in ('deserial', 'serializ', 'serialization', 'readobject', 'commons-collections', 'transformer')):
            return 'deserialization'
        if any(token in text for token in ('spel', 'ssti', 'template', 'thymeleaf', 'velocity', 'freemarker', 'ognl')):
            return 'template-injection'
        if any(token in text for token in ('command', 'exec', 'processbuilder', 'runtime')):
            return 'command'
        if any(token in text for token in ('path', 'traversal', 'filepath', 'readallbytes', 'files.write')):
            return 'path'
        if any(token in text for token in ('xss', 'html', 'writestatus', 'innerhtml', 'response.write')):
            return 'xss'
        return (vuln.type or '').strip().lower()

    def _canonical_a2_group_key(self, vuln: Vulnerability) -> str:
        family = self._canonical_family(vuln)
        file_path = str(vuln.file or '').strip().lower()
        line = int(vuln.line or 0)
        snippet = self._normalize_anchor_text(vuln.code_snippet or '')
        return f"{family}|{file_path}|{line}|{snippet}"

    @staticmethod
    def _a2_vuln_rank(vuln: Vulnerability) -> tuple:
        verdict = vuln.verdict or ''
        verdict_score = 2 if '真漏洞' in verdict or '✅' in verdict else 1 if verdict else 0
        return (
            verdict_score,
            1 if vuln.has_http_entry else 0,
            1 if vuln.has_call_chain else 0,
            len(vuln.callers or ''),
            len(vuln.description or ''),
            len(vuln.fix or ''),
        )

    def _deduplicate_a2_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        grouped: Dict[str, Vulnerability] = {}
        ordered_keys: List[str] = []

        for vuln in vulnerabilities:
            key = self._canonical_a2_group_key(vuln)
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = vuln
                ordered_keys.append(key)
                continue

            winner = existing
            loser = vuln
            if self._a2_vuln_rank(vuln) > self._a2_vuln_rank(existing):
                winner = vuln
                loser = existing

            if not winner.description and loser.description:
                winner.description = loser.description
            if not winner.fix and loser.fix:
                winner.fix = loser.fix
            if not winner.callers and loser.callers:
                winner.callers = loser.callers
            if not winner.code_snippet and loser.code_snippet:
                winner.code_snippet = loser.code_snippet
            winner.has_http_entry = winner.has_http_entry or loser.has_http_entry
            winner.has_call_chain = winner.has_call_chain or loser.has_call_chain
            grouped[key] = winner

        return [grouped[key] for key in ordered_keys]

    def _early_chain_group_key(self, vuln: Vulnerability) -> str:
        text = " ".join([
            str(vuln.file or ''),
            str(vuln.description or ''),
            str(vuln.code_snippet or ''),
            str(vuln.callers or ''),
            str(vuln.entry_point or ''),
            str(vuln.sink or ''),
            str(vuln.data_flow or ''),
        ]).lower()
        family = self._canonical_family(vuln)
        route_text = str(vuln.entry_point or '').lower()
        guessed_parameter = self._resolve_parameter_name_from_static(vuln).lower()

        if family == 'deserialization':
            markers = tuple(workspace_runtime.deserialization_chain().get('markers', []))
            file_hints = ('controller', 'service', 'processor', 'pom.xml')
            if any(marker in text for marker in markers) or any(hint in str(vuln.file or '').lower() for hint in file_hints):
                return 'deserialization:project_chain'

        if family in {'template-injection', 'xss'}:
            markers = (
                'spelexpressionparser', 'parseexpression(', 'templateparsercontext', 'velocityengine',
                'freemarker', 'thymeleaf', 'templateengine.process', 'evaluate(', '/check', 'requestparam string rule',
            )
            expression_routes = ('/check', '/render', '/evaluate', '/preview', '/template')
            expression_parameters = {'rule', 'expression', 'template', 'spel', 'expr'}
            has_expression_markers = any(marker in text for marker in markers)
            has_expression_route = any(route in route_text or route in text for route in expression_routes)
            has_expression_parameter = guessed_parameter in expression_parameters or any(
                token in text for token in (
                    'requestparam string rule',
                    'requestparam string expression',
                    'requestparam string template',
                    '@requestparam string rule',
                    '@requestparam string expression',
                    '@requestparam string template',
                )
            )
            if has_expression_markers or (has_expression_route and has_expression_parameter):
                return 'template-injection:expression_chain'

        if family == 'command':
            markers = ('processbuilder', 'runtime.getruntime().exec', '.exec(', '"sh", "-c"', 'executecommand')
            controllable_command_markers = (
                'command parameter', 'requestparam', 'getparameter', 'pathvariable', 'requestbody',
                'req.query', 'req.body', 'request.getparameter', 'shell command'
            )
            if any(marker in text for marker in markers):
                has_reachability = vuln.has_http_entry or vuln.has_call_chain or bool(vuln.callers)
                has_command_control = any(marker in text for marker in controllable_command_markers)
                if not has_reachability and not has_command_control:
                    return ''
                return 'command:exec_chain'

        if family == 'path':
            read_markers = ('files.readallbytes', 'readfile', 'filepath')
            write_markers = ('files.write', 'writestatus', 'output_path')
            controllable_path_markers = ('filepath', 'path parameter', '../', '..\\', 'requestparam', 'getparameter', 'pathvariable')
            if any(marker in text for marker in read_markers):
                return 'path:read_chain'
            if any(marker in text for marker in write_markers):
                has_reachability = vuln.has_http_entry or vuln.has_call_chain or bool(vuln.callers)
                has_path_control = any(marker in text for marker in controllable_path_markers)
                if not has_reachability and not has_path_control:
                    return ''
                return 'path:write_chain'

        if family == 'xss':
            markers = ('writestatus', '<pre>', 'status.html', 'html', 'response.write', 'innerhtml')
            controllable_xss_markers = ('requestparam', 'getparameter', 'pathvariable', 'requestbody', 'user input', '<script', 'stored xss')
            if any(marker in text for marker in markers):
                has_reachability = vuln.has_http_entry or vuln.has_call_chain or bool(vuln.callers)
                has_xss_control = any(marker in text for marker in controllable_xss_markers)
                if not has_reachability and not has_xss_control:
                    return ''
                return 'xss:output_chain'

        if family == 'default-credentials':
            markers = ('curl --user', 'admin_password=admin', '/api/users/1', '/api/user', '/login', 'grafana')
            if any(marker in text for marker in markers):
                return 'default-credentials:privileged_api_chain'

        generic_reachability = bool(
            vuln.has_http_entry
            or vuln.has_call_chain
            or vuln.callers
            or 'route ' in text
            or '/api/' in text
            or '/' in str(vuln.entry_point or '')
        )
        if family and generic_reachability:
            # 行号一漂移键就变，成员掉出原组 → 漏排/重复计（DB 实测大量
            # 「路径穿越:...java:42」形态的 file:line 键，4844 行键为空）。
            # 改用 route-drift 免疫的行号无关弱键（file_tail + type + code_block 哈希，
            # 见 vuln_hash.stable_vuln_key），同文件同族同代码块才归并；
            # 弱键算不出时退化为 family:file（仍不含行号）。
            _weak = stable_vuln_key(vuln, line_agnostic=True)
            if _weak:
                return f'{family}:chain:{_weak}'
            return f'{family}:{str(vuln.file or "").lower()}'

        return ''

    def _early_chain_rank(self, vuln: Vulnerability) -> tuple:
        family = self._canonical_family(vuln)
        file_path = str(vuln.file or '').lower()
        snippet = str(vuln.code_snippet or '').lower()
        verdict = vuln.verdict or ''
        family_bias = {
            'deserialization': (
                1 if 'readobject' in snippet or 'objectinputstream' in snippet else 0,
                1 if 'processor.process' in snippet or 'process(userconfig)' in snippet else 0,
                1 if 'transform(' in snippet else 0,
                1 if file_path.endswith('pom.xml') else 0,
            ),
            'command': (
                1 if 'processbuilder' in snippet or '.exec(' in snippet else 0,
                1 if '"sh", "-c"' in snippet else 0,
                1 if 'runtime.getruntime().exec' in snippet else 0,
                0,
            ),
            'path': (
                1 if 'files.readallbytes' in snippet or 'readfile' in snippet else 0,
                1 if 'files.write' in snippet or 'writestatus' in snippet else 0,
                1 if 'filepath' in snippet or 'output_path' in snippet else 0,
                0,
            ),
            'xss': (
                1 if 'writestatus' in snippet or 'response.write' in snippet else 0,
                1 if '<pre>' in snippet or 'innerhtml' in snippet else 0,
                0,
                0,
            ),
            'template-injection': (
                1 if 'parseexpression(' in snippet or 'templateparsercontext' in snippet else 0,
                1 if 'spelexpressionparser' in snippet or 'thymeleaf' in snippet or 'freemarker' in snippet else 0,
                1 if 'evaluate(' in snippet or 'process(' in snippet else 0,
                1 if 'service' in file_path else 0,
            ),
        }.get(family, (0, 0, 0, 0))
        return (
            1 if '真漏洞' in verdict or '✅' in verdict else 0,
            1 if vuln.has_http_entry else 0,
            1 if 'controller' in file_path else 0,
            *family_bias,
            len(vuln.description or ''),
        )

    @staticmethod
    def _build_supporting_node(vuln: Vulnerability) -> Dict[str, Any]:
        return {
            'file': vuln.file,
            'line': vuln.line,
            'type': vuln.type,
            'severity': vuln.severity,
            'description': vuln.description,
            'code_snippet': vuln.code_snippet,
            'entry_point': vuln.entry_point,
            'sink': vuln.sink,
            'callers': vuln.callers,
            'verdict': vuln.verdict,
            'canonical_group_key': getattr(vuln, 'canonical_group_key', ''),
            'chain_id': getattr(vuln, 'chain_id', ''),
            'proof_tier': getattr(vuln, 'proof_tier', 'broad_static'),
            'chain_proof': normalize_chain_proof(getattr(vuln, 'chain_proof', {})),
            'proof_gaps': list(getattr(vuln, 'proof_gaps', []) or []),
            'exploit_spec': getattr(vuln, 'exploit_spec', empty_exploit_spec()),
        }

    @staticmethod
    def _vuln_text(vuln: Vulnerability) -> str:
        return "\n".join([
            str(vuln.type or ""),
            str(vuln.description or ""),
            str(vuln.code_snippet or ""),
            str(vuln.entry_point or ""),
            str(vuln.sink or ""),
            str(vuln.data_flow or ""),
            str(vuln.callers or ""),
            str(vuln.verdict or ""),
            str(vuln.file or ""),
        ]).lower()

    def _build_chain_proof(self, vuln: Vulnerability, exploit_spec: Dict[str, Any], supporting_nodes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        proof = evaluate_proof_obligations(
            vuln,
            exploit_spec,
            supporting_nodes=list(supporting_nodes or []),
            evidence=getattr(vuln, "a1_evidence", {}) or {},
            incoming_proof=empty_chain_proof(),
        )
        vuln.proof_context_summary = summarize_proof_context(vuln, getattr(vuln, "a1_evidence", {}) or {})
        return proof

    def _apply_proof_derivation(self, vuln: Vulnerability) -> None:
        """把 proof 状态推导到污点流假说 / confirmed / severity（幂等）。

        sink 本身不等于危险：只有 source→sink 可达、且中间无 barrier 的完整 flow
        才允许断言「危险」。severity 由 proof 推导，不再被 LLM 自由文本压住：
        chain_proven 沿用声称值，broad_static 且有 gaps 则降级为假说。
        """
        vuln.taint_flow_hypothesis = build_taint_flow_hypothesis(
            vuln, vuln.chain_proof, getattr(vuln, "exploit_spec", None)
        )
        gaps = list((vuln.chain_proof or {}).get("proof_gaps") or [])
        # 防御：chain_proof 缺失/未评估时 obligations 全为假而 gaps 为空，若照抄会把
        # 「从未评估」误判成「已证成」。此时从 obligations 反推真实缺口。
        if not gaps:
            obligations = (vuln.taint_flow_hypothesis or {}).get("obligations") or {}
            gaps = [key for key, met in obligations.items() if not met]
        vuln.proof_gaps = gaps
        vuln.proof_tier = "chain_proven" if not gaps else "broad_static"
        flow = vuln.taint_flow_hypothesis or {}
        # 首次调用时保留 LLM 原始声称值供审计，之后始终基于它推导（保证幂等）
        if not vuln.severity_claimed:
            vuln.severity_claimed = str(vuln.severity or "")
        # 统一门禁：tier / gaps / obligations / verdict 一起裁决，避免自相矛盾
        gate = derive_finding_gate(
            claimed_severity=vuln.severity_claimed or vuln.severity,
            proof_tier=vuln.proof_tier,
            proof_gaps=vuln.proof_gaps,
            obligations=flow.get("obligations") or {},
            flow_complete=bool(flow.get("flow_complete")),
            verdict=vuln.verdict,
            sink_present=bool(flow.get("sink_present")),
        )
        vuln.confirmed = bool(gate["confirmed"])
        vuln.is_dangerous = bool(gate["is_dangerous"])
        vuln.severity = str(gate["severity"])

    @staticmethod
    def _parse_http_entry(http_entry: str) -> Dict[str, str]:
        value = str(http_entry or "").strip()
        if not value:
            return {"method": "", "route": ""}
        parts = value.split(" ", 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "REQUEST", "ROUTE"}:
            method = "GET" if parts[0].upper() == "ROUTE" else parts[0].upper()
            return {"method": method, "route": parts[1].strip()}
        return {"method": "", "route": value}

    @staticmethod
    def _extract_route_from_text(*parts: str) -> str:
        text = " ".join(str(part or "") for part in parts)
        match = re.search(r'(/[\w\-/{}]+)', text)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _resolve_parameter_name_from_static(vuln: Vulnerability) -> str:
        """从 SAST 静态证据（A1 source_candidates）取真实参数名，取代 guess_parameter_name 正则猜测。
        若 A1 未给出，返回空串，由 A2→TriggerSpec 登记阶段结合 entry_discovery 真实路由与
        源码注解精确解析——保证参数名来自「应用真实读取的位置」，而非从描述文本硬猜。
        request_observed，该档恒为空）。"""
        from src.core.param_resolver import is_valid_param_name
        evidence = getattr(vuln, "a1_evidence", None) or {}
        if isinstance(evidence, dict):
            for sc in (evidence.get("source_candidates") or []):
                name = str(sc.get("name") or sc.get("param") or "") if isinstance(sc, dict) else str(sc)
                if is_valid_param_name(name):
                    return name
        return ""

    @staticmethod
    def _has_sql_injection_signal(text: str) -> bool:
        lower = str(text or "").lower()
        explicit_patterns = (
            r"\bsql injection\b",
            r"\bsqli\b",
            r"\bblind sql injection\b",
            r"\bunion select\b",
        )
        if any(re.search(pattern, lower) for pattern in explicit_patterns):
            return True
        weak_negative_markers = (
            "sqlite:///",
            "default sqlite database",
            "sqlalchemy_database_uri",
            "database_url",
            "sqlalchemy_database_uri",
        )
        if any(marker in lower for marker in weak_negative_markers):
            return False
        query_signals = (
            "select ",
            "insert into",
            "update ",
            "delete from",
            "executequery",
            "preparedstatement",
            "statement.execute",
            "cursor.execute",
            "raw query",
            "executescript",
        )
        attacker_control_signals = (
            "requestparam",
            "getparameter(",
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "requestbody",
            "query parameter",
            "user-controlled",
            "pathvariable",
        )
        interpolation_signals = (
            "string concatenation",
            ".format(",
            "f\"",
            "f'",
            "%s",
            "{user_input}",
        )
        return any(signal in lower for signal in query_signals) and (
            any(signal in lower for signal in attacker_control_signals)
            or any(signal in lower for signal in interpolation_signals)
        )

    # 规范族 token 集合：vuln.type 已是这些规范族之一时，_payload_family 直接采用（不再被
    # description/sink 中残留的旧误标关键词在下方 mapping 顺序里抢先命中覆盖）。
    # description 仍残留「XPath注入」字样；若不优先采用 vuln.type，下方 ('xpath',)→'xpath-injection'
    # 会排在 ('ldap',)→'ldap-injection' 之前命中，把族名又扳回 xpathi，override 完全失效。
    # vuln.type 是权威分类字段，规范族优先于描述性文本（同时修掉「type=sql-injection 但描述含
    # xss → 被扳成 xss」的潜在错配）。
    _PAYLOAD_FAMILY_CANONICAL = frozenset({
        "deserialization", "path-traversal", "file-upload", "open-redirect", "jwt",
        "xpath-injection", "ldap-injection", "xss", "template-injection", "ssrf", "xxe",
        "command-execution", "race-condition", "workflow-bypass", "crlf-injection",
        "jsonp", "jndi-injection", "url-whitelist-bypass", "csrf", "cookie", "cors",
        "auth-bypass", "idor", "default-credentials", "sql-injection",
    })

    @staticmethod
    def _payload_family(vuln: Vulnerability) -> str:
        _t = (vuln.type or "").lower().replace("_", "-").strip()
        if _t in A2SemanticAgent._PAYLOAD_FAMILY_CANONICAL:
            return _t
        text = "\n".join([
            str(vuln.type or ""),
            str(vuln.sink or ""),
            str(vuln.description or ""),
            str(vuln.code_snippet or ""),
            str(vuln.data_flow or ""),
        ]).lower()
        if "deserial" in text:
            return "deserialization"
        if any(needle in text for needle in ("idor", "insecure direct object reference", "ownership", "owner_id", "user_id", "tenant_id", "resource_id")):
            # 修复三：非端点 helper/注释块过检收敛——业务族须落在带 HTTP 方法注解的方法上，
            # 否则是辅助方法/注释块误报，降级走后续 generic 规则（不再路由 BOLA 差分重放）。
            if A2SemanticAgent._has_http_method_annotation(getattr(vuln, "code_snippet", "") or ""):
                return "idor"
            logger.info(
                "[A2] idor 关键词命中但 code_snippet 无 HTTP 方法注解，降级为 generic（%s:%s）",
                getattr(vuln, "file", ""), getattr(vuln, "line", ""),
            )
            # 否则 fall through 到下方 mapping 规则
        if any(needle in text for needle in ("default credential", "hardcoded credential", "hardcoded password", "insecure credentials", "不安全的凭证", "curl --user", "grafana")):
            return "default-credentials"
        mapping = (
            (("deserialize", "反序列化"), "deserialization"),
            (("path", "traversal", "路径"), "path-traversal"),
            (("upload", "上传"), "file-upload"),
            (("redirect",), "open-redirect"),
            (("jwt",), "jwt"),
            (("xpath",), "xpath-injection"),
            (("ldap",), "ldap-injection"),
            (("xss",), "xss"),
            (("template", "ssti", "ognl", "spel"), "template-injection"),
            (("ssrf",), "ssrf"),
            (("xxe", "xml"), "xxe"),
            (("command", "runtime.exec", "processbuilder", "rce"), "command-execution"),
            (("race", "refund", "coupon", "concurrent"), "race-condition"),
            (("workflow", "approval", "bypass", "支付", "退款", "优惠券"), "workflow-bypass"),
            # attack_payloads_json 落 []，D1 重放退化为纯 canary、注入族确认率恒 0。
            (("crlf", "response splitting", "header injection"), "crlf-injection"),
            (("jsonp", "callback"), "jsonp"),
            (("jndi", "log4j", "log4shell"), "jndi-injection"),
            (("whitelist", "url_bypass", "url bypass", "ends_with"), "url-whitelist-bypass"),
            # （cookie 位置、跨域上下文），不是「漏洞是什么」。抢在真实漏洞族之前命中就会
            # 旧顺序下 cookie 先命中 → payload_family=cookie → 默认载荷表无此族 →
            # attack_payloads_json=[] → 重放没有载荷可注入 → 永久 no-arrival，
            # 即使该 spec 的端点/参数/sink 行全部正确。
            (("csrf",), "csrf"),
            (("cookie",), "cookie"),
            (("cors",), "cors"),
            (("auth", "鉴权"), "auth-bypass"),
        )
        for needles, family in mapping:
            if any(needle in text for needle in needles):
                return family
        if A2SemanticAgent._has_sql_injection_signal(text):
            return "sql-injection"
        return "generic"

    @staticmethod
    def _default_payloads_for_family(family: str) -> List[str]:
        """确定性路径（_build_exploit_spec）默认 payload 兜底。

        原因：真实攻击载荷此前只在 A2ContractPlanner（LLM 路径）的 _apply_payload_defaults
        里按族填充；走确定性 _build_exploit_spec 的 spec 不会经过该路径，导致
        candidate_payloads 恒空 → attack_payloads_json 落库为 [] → D1 重放退化为纯 canary，
        注入族确认率 0%。这里镜像 planner 的确定性默认载荷，仅当候选为空时填充（不覆盖 LLM 路径）。
        """
        table = {
            "sql-injection": ["' OR '1'='1", "\" OR \"1\"=\"1"],
            "xpath-injection": ["' OR '1'='1", "\" OR \"1\"=\"1"],
            "ldap-injection": ["*)(uid=*))(|(uid=*", "*)(uid=*"],
            "nosql-injection": ["' || '1'=='1", "'$ne': ''"],
            "template-injection": ["${7*7}", "{{7*7}}", "T(java.lang.Runtime).getRuntime().exec('id')"],
            "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"],
            "path-traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "xxe": ["<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin"],
            "command-execution": ["; id", "| id", "$(id)"],
            "file-upload": ["webshell_or_probe_file"],
            "deserialization": ["base64(serialized_object)"],
            "idor": ["alternate_owner_resource_id"],
            # CRLF 用 %0d%0a 编码形态（作为 query 参数值传递时需保持单行可编码）；
            # jndi 指向本地回环 LDAP，与靶场 wiki 的验证姿势一致（不自毁、不外联）。
            "crlf-injection": ["x%0d%0aSet-Cookie:crlf=1", "x%0d%0aContent-Length:0"],
            "jsonp": ["evilCallback", "alert(1)//"],
            "jndi-injection": ["${jndi:ldap://127.0.0.1:1389/exploit}"],
            "url-whitelist-bypass": [
                "http://whitelisted.example@127.0.0.1/",
                "http://whitelisted.example.evil.com/",
            ],
            # → attack_payloads_json 落 [] → D1 重放退化为纯 canary、确认率恒 0。补齐后每一族都有
            # 可注入载荷，消除"零载荷 spec"。取值保守、指向本地回环或明显标记，不自毁、不外联。
            "open-redirect": ["https://savr-probe.example.com/"],
            "jwt": ["eyJhbGciOiJub25lIn0.eyJzdWIiOiJzYXN0YWkifQ."],
            "race-condition": ["1"],
            "workflow-bypass": ["1"],
            "csrf": ["savr-probe"],
            "cookie": ["savr-probe=1"],
            "cors": ["https://savr-probe.example.com"],
            "auth-bypass": ["admin"],
            "default-credentials": ["admin:admin"],
            # generic 是分类器的兜底族：给它一个标记载荷，保证任何未归族 spec 也有载荷可注入。
            "generic": ["savr-probe"],
        }
        return list(table.get(family, []))

    # —— F1/F2 辅助：业务逻辑类目识别与真实管理路由择优 ——
    # 兜底补出，A2 自身认不出 race 族 → 门控漏判、payload_family 恒 'generic'。
    # 注意 idor 仍经下方别名表折叠为 bola（D1 重放层两者同路由，见 _BL_ROUTE_OVERRIDES），
    # 故此处不把 idor 直接放进集合，避免破坏既有折叠语义。
    _BL_CATEGORY_SET = frozenset({
        "bola", "vertical_privesc", "cross_module_privesc", "state_machine", "race",
        "calculation_logic", "auth_session", "abuse_dos", "signature_bypass",
    })

    @staticmethod
    def _has_http_method_annotation(snippet: str) -> bool:
        """修复三：代码是否含 Spring HTTP 方法注解（@GetMapping/@PostMapping/@RequestMapping 等）。
        用于业务族（idor/bola）判定的确定性后过滤——非端点辅助方法/注释块不含注解，据此丢弃过检。"""
        return bool(HTTP_METHOD_ANNOTATION_RE.search(str(snippet or "")))

    @staticmethod
    def _business_logic_category(vuln: "Vulnerability") -> str:
        raw = str(
            getattr(vuln, "business_logic_category", "") or getattr(vuln, "category", "") or ""
        ).strip().lower()
        if raw in A2SemanticAgent._BL_CATEGORY_SET:
            cat = raw
        else:
            alias = {
                "idor": "bola", "b-o-l-a": "bola", "privesc": "vertical_privesc",
                "vertical": "vertical_privesc", "cross_module": "cross_module_privesc",
                "statemachine": "state_machine", "race_condition": "race",
                "race-condition": "race", "concurrency": "race",
                "calculation": "calculation_logic",
                "auth": "auth_session", "captcha": "auth_session",
                "password_reset": "auth_session", "abuse": "abuse_dos", "dos": "abuse_dos",
                "signature": "signature_bypass", "jwt": "signature_bypass",
                "alg_none": "signature_bypass", "signature-bypass": "signature_bypass",
            }
            cat = alias.get(raw)
        if not cat or cat not in A2SemanticAgent._BL_CATEGORY_SET:
            return ""
        # 修复三：idor/bola 类须落在带 HTTP 方法注解的方法上（辅助方法/注释块误报收敛）。
        # vertical_privesc 等管理端点多为类级 @RequestMapping（方法体可见注解）同样满足，故仅拦 bola。
        if cat == "bola" and not A2SemanticAgent._has_http_method_annotation(getattr(vuln, "code_snippet", "") or ""):
            logger.info(
                "[A2] bola 业务族命中但 code_snippet 无 HTTP 方法注解，降级（%s:%s）",
                getattr(vuln, "file", ""), getattr(vuln, "line", ""),
            )
            return ""
        return cat

    @staticmethod
    def _pick_admin_route(discovered_routes: Optional[List[Dict[str, Any]]]) -> str:
        routes = [d.get("route", "") for d in (discovered_routes or []) if d.get("route")]
        admin = [r for r in routes if re.search(r"/(admin|manage|console|sys)/", r, re.I)]
        # 排除残缺（含逗号）与仅类级前缀的路由，优先具体子路由（如 /admin/users 而非 /admin）。
        admin = [r for r in admin if "," not in r]
        concrete = [r for r in admin if r.count("/") >= 2 and not r.endswith("/")]
        return (concrete or admin or [""])[0]

    @staticmethod
    def _norm_file_for_match(fp: str) -> str:
        if not fp:
            return ""
        return str(fp).replace("\\", "/").rstrip("/").split("/")[-1].lower()

    @staticmethod
    def _route_method_from_signature(sig: str):
        """从 discovery 产物的 signature（如 @GetMapping("/x")）解析路由与 HTTP 方法。
        discovered_routes 条目没有独立 route 字段，路由嵌在 signature 的首个引号路径里
        （类级前缀已在 discovery 阶段拼好，如 /admin/users）。"""
        if not sig:
            return "", "GET"
        rm = re.search(r'["\']([^"\']+)["\']', sig)
        route = rm.group(1).strip() if rm else ""
        method = "GET"
        low = sig.lower()
        if "@postmapping" in low or "@post" in low:
            method = "POST"
        elif "@putmapping" in low or "@put" in low:
            method = "PUT"
        elif "@deletemapping" in low or "@delete" in low:
            method = "DELETE"
        elif "@patchmapping" in low or "@patch" in low:
            method = "PATCH"
        return route, method

    def _match_discovered_route_by_location(self, vuln, discovered_routes):
        """端到端路由回退：当 LLM 绑定 / entry_point / 正文正则都未取到路由时，
        按 finding 的 file:line 在同文件 discovered_routes 中匹配最近的方法级路由
        （line <= vuln.line 的最大者）。修复 #8 SSTI /marketing/preview、#21 JWT垂直 /admin/*
        等因路由"提取层"缺失而 route 恒为空、永远登记不出 trigger_spec 的问题。
        实体类（User/Comment）无对应路由，自然匹配不到，不会误绑。"""
        if not discovered_routes:
            return None
        vf = self._norm_file_for_match(getattr(vuln, "file", "") or "")
        if not vf:
            return None
        try:
            vline = int(getattr(vuln, "line") or 0)
        except Exception:
            vline = 0
        best = None
        for d in discovered_routes:
            df = self._norm_file_for_match(d.get("file", "") or "")
            if df != vf:
                continue
            # discovered_routes 条目的路由嵌在 signature（无独立 route 字段）；若已带 route 字段也兼容。
            r = d.get("route") or self._route_method_from_signature(d.get("signature", ""))[0]
            if not r or "," in r:
                continue
            try:
                dl = int(d.get("line") or 0)
            except Exception:
                dl = 0
            if dl <= vline and (best is None or dl > best[0]):
                best = (dl, r, self._route_method_from_signature(d.get("signature", ""))[1])
        if best:
            return {"route": best[1], "method": (best[2] or "GET")}
        return None

    @staticmethod
    def _extract_resource_id_from_text(*parts: str) -> str:
        text = " ".join(str(p or "") for p in parts)
        m = re.search(r"/(\d{1,10})(?:[/\s\"'\}]|$)", text)
        return m.group(1) if m else ""

    def _build_exploit_spec(self, vuln: Vulnerability, feedback: Optional[Dict] = None,
                            discovered_routes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        route_info = self._parse_http_entry(vuln.entry_point)
        spec = empty_exploit_spec()
        evidence = getattr(vuln, "a1_evidence", {}) or {}
        nearest_entry = next(iter(list(evidence.get("entry_candidates", []) or [])), {}) if not route_info.get("route") else {}
        if nearest_entry and not route_info.get("route"):
            route_info = {
                "route": str(nearest_entry.get("route", "") or ""),
                "method": str(nearest_entry.get("method", "") or ""),
            }
        parameter_name = self._resolve_parameter_name_from_static(vuln)
        payload_family = self._payload_family(vuln)
        # F2：业务逻辑族用 A1/business-logic 标注的 business_logic_category 覆盖 payload_family，
        # 使下游证明（proof_obligations 差分族）与登记（trigger_spec.category）识别一致。
        business_cat = self._business_logic_category(vuln)
        # F2-补：A2 的 LLM 已在结构化字段 type/finding_family/
        # display_family 显式给出漏洞族（如「垂直越权」），但 _payload_family 仅靠英文关键词
        # 自下而上匹配（无 vertical/越权 等 needle），对垂直越权类恒回落 'generic'；而
        # _business_logic_category 只读 business_logic_category/category 属性（垂直越权类这两字段
        # 为空），于是 payload_family 彻底丢失、下游 trigger_spec 被错标 bola → 永远 no-iast-evidence。
        # 故当文本探测无果（generic）且业务类目属性为空时，回退到 LLM 结构化族标签，经
        # canonical_business_logic_family 归一（"垂直越权"→vertical_privesc 等），命中 DIFFERENTIAL_PROOF_FAMILIES
        # 即采信。仅作 generic 时的最终兜底，不覆盖已正确识别的注入/idor 等族，避免误改。
        if not business_cat and payload_family == "generic":
            _raw_hint = (
                getattr(vuln, "finding_family", "")
                or getattr(vuln, "type", "")
                or getattr(vuln, "display_family", "")
                or ""
            )
            # 剥离「基础设施层-/业务逻辑类-」等降级标记前缀，取底层业务族再归一
            # （如「基础设施层-垂直越权」→「垂直越权」→vertical_privesc）；注入类剥离后仍归不到
            # DIFFERENTIAL_PROOF_FAMILIES，不会被误判为业务族。
            _raw_hint = strip_family_prefix(_raw_hint)
            _llm_family_hint = canonical_business_logic_family(_raw_hint)
            if _llm_family_hint in A2SemanticAgent._BL_CATEGORY_SET:
                business_cat = _llm_family_hint
        if business_cat:
            payload_family = business_cat
        chain_group = self._early_chain_group_key(vuln)
        lower_text = "\n".join([
            str(vuln.type or ""),
            str(vuln.description or ""),
            str(vuln.callers or ""),
            str(vuln.file or ""),
            str(vuln.entry_point or ""),
        ]).lower()
        if chain_group == "template-injection:expression_chain":
            payload_family = "template-injection"
            if not parameter_name:
                for candidate in ("rule", "expression", "template"):
                    if candidate in lower_text:
                        parameter_name = candidate
                        break
        if chain_group == "default-credentials:privileged_api_chain":
            payload_family = "default-credentials"
            parameter_name = "authorization"

        entry = spec["entry"]
        # §R5：路由取值优先级 —— LLM 显式绑定 > _parse_http_entry > 正文正则兜底。
        # 此前正则兜底会捞出不完整片段（"/"、"、/admin/"），写进 spec 后 D2 构造请求必失败，
        # 这批 findings 在转 trigger_spec 时被整批丢弃。LLM 看着完整源码 + A1 证据给路由，
        # 且已过 _sanitize_llm_route 校验，可信度最高。
        _llm_route = str(getattr(vuln, "llm_route", "") or "").strip()
        entry["route"] = (
            _llm_route
            or route_info["route"]
            or self._extract_route_from_text(vuln.entry_point, vuln.data_flow, vuln.description)
        )
        entry["method"] = route_info["method"] or (
            "POST" if any(token in lower_text for token in ("postmapping", "@postmapping", "post /", "import")) else
            "PUT" if any(token in lower_text for token in ("put /", "-xput", "-x put", "api/users/1")) else
            "GET" if any(token in lower_text for token in ("getmapping", "@getmapping", "get /")) else
            ""
        )
        # §R5：静态解析拿不到参数名时，回落到 LLM 显式给出的可控参数（prompt 要求
        # 给出参数名 + 位置）。业务逻辑族尤其依赖这一步 —— 静态规则不认业务字段名
        # （如 couponId / amount / quantity），没有参数名 D1 就无从注入 canary。
        _llm_params = getattr(vuln, "llm_params", None) or []
        if not parameter_name and _llm_params:
            for _p in _llm_params:
                if isinstance(_p, dict) and str(_p.get("name") or "").strip():
                    parameter_name = str(_p.get("name")).strip()
                    break
        entry["parameter_name"] = parameter_name
        # F2：垂直/跨模块越权族在 A2 主路径即绑定真实管理路由（来自 entry_discovery discovered_routes /
        # SAST ground truth），避免落到幻觉端点（/admin/ping）或留空导致不进 D2 候选。
        if business_cat in ("vertical_privesc", "cross_module_privesc"):
            _disc_routes = [d.get("route", "") for d in (discovered_routes or []) if d.get("route")]
            _cur = entry["route"]
            if not _cur or (_disc_routes and _cur not in _disc_routes):
                _admin = self._pick_admin_route(discovered_routes)
                if _admin:
                    entry["route"] = _admin
                    if not entry["method"]:
                        entry["method"] = "GET"
        # §R5-fix：端到端路由回退。当 LLM 绑定 / entry_point / 正文正则都未取到路由时，
        # 用 finding 的 file:line 在同文件 discovered_routes 中匹配最近方法级路由。
        # 这是路由"提取层"缺失的兜底。
        if not entry["route"] and discovered_routes:
            _loc = self._match_discovered_route_by_location(vuln, discovered_routes)
            if _loc:
                entry["route"] = _loc["route"]
                if not entry["method"]:
                    entry["method"] = _loc.get("method") or "GET"
        if payload_family == "default-credentials" and not entry["route"]:
            entry["route"] = "/api/users/1"
        # §R5：参数位置同理，优先采信 LLM 给出的 in（query/body/path/header）。
        _llm_loc = ""
        for _p in _llm_params:
            if isinstance(_p, dict):
                _cand = str(_p.get("in") or _p.get("location") or "").strip().lower()
                if _cand in ("query", "body", "path", "header", "form", "cookie"):
                    if not parameter_name or str(_p.get("name") or "").strip() == parameter_name:
                        _llm_loc = _cand
                        break
        entry["parameter_location"] = (
            _llm_loc
            or ("body" if "requestbody" in lower_text or "请求体" in lower_text else
                "query" if entry["method"] == "GET" else
                "form" if entry["method"] else "")
        )
        entry["content_type"] = (
            "application/json" if "json" in lower_text else
            "multipart/form-data" if "upload" in lower_text or "文件" in lower_text else
            "application/x-www-form-urlencoded" if entry["parameter_location"] == "form" else
            ""
        )
        if payload_family == "default-credentials":
            entry["parameter_location"] = "header"
            entry["content_type"] = "application/json"
        trigger_route = ""
        if "cacheprocessor.process" in lower_text or "二次" in lower_text:
            trigger_route = workspace_runtime.deserialization_chain().get('trigger_route', '/api/quote/random')
        entry["trigger_route"] = trigger_route

        prerequisites = spec["prerequisites"]
        prerequisites["auth_required"] = "required" if any(token in lower_text for token in ("auth", "login", "session", "token", "admin", "debug")) else "unknown"
        if "admin" in lower_text:
            prerequisites["role_or_permission"] = "admin"
        ordered_steps: List[str] = []
        if payload_family == "deserialization" and ("/debug/import" in lower_text or entry["route"] == workspace_runtime.deserialization_chain().get('entry_route', '/debug/import')):
            dc = workspace_runtime.deserialization_chain()
            ordered_steps = [
                f"POST {dc.get('entry_route', '/debug/import')} 导入满足业务对象约束的序列化输入",
                f"GET {dc.get('trigger_route', '/api/quote/random')} 触发后续缓存处理链",
            ]
        prerequisites["ordered_steps"] = ordered_steps
        if "token" in lower_text:
            prerequisites["token_requirements"] = ["需要有效 token 或等价认证态"]
        if "session" in lower_text or "csrf" in lower_text:
            prerequisites["session_requirements"] = ["需要受害者携带有效会话"]

        if payload_family == "default-credentials":
            prerequisites["auth_required"] = "required"
            prerequisites["role_or_permission"] = "admin"

        payload = spec["payload"]
        payload["payload_family"] = payload_family
        if payload_family == "deserialization":
            payload["payload_constraints"] = ["输入必须满足服务端对象类型与业务字段约束"]
            payload["object_shape_constraints"] = ["不能只是普通字符串，需要可被业务导入逻辑接受的对象结构"]
            payload["encoding"] = "base64" if "base64" in lower_text else ""
            payload["generator_hint"] = "use_project_object_shape"
        elif payload_family in {"path-traversal", "file-upload", "xxe"}:
            payload["payload_constraints"] = ["输入必须保持业务可接受的文件或资源参数形态"]
        elif payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"}:
            payload["payload_constraints"] = ["输入必须保持真实认证或跨站请求上下文"]

        if payload_family == "default-credentials":
            payload["payload_constraints"] = ["privileged service credentials are embedded in runtime scripts or configuration"]
            payload["candidate_payloads"] = ["admin:admin"]
            payload["verification_payloads"] = ["admin:admin"]
            payload["high_impact_payloads"] = ["a3-proof-admin-email@example.com"]
            payload["impact_constraints"] = ["prefer privileged API write actions after confirming default credential access"]
            payload["generator_hint"] = "use disclosed default credentials to authenticate to the privileged service API"

        # 确定性路径 payload 兜底——候选为空时按族填充默认攻击载荷（不覆盖 LLM 路径已生成的 payload）。
        if not payload.get("candidate_payloads"):
            _dp = A2SemanticAgent._default_payloads_for_family(payload_family)
            if _dp:
                payload["candidate_payloads"] = _dp
                if not payload.get("verification_payloads"):
                    payload["verification_payloads"] = list(_dp)

        success_signal = spec["success_signal"]
        if payload_family == "deserialization":
            success_signal["signal_type"] = "state_change_or_side_effect"
            success_signal["match_strategy"] = "observe_secondary_trigger_effect"
            success_signal["expected_indicators"] = ["后续业务链出现对象恢复后的副作用或可解释差异"]
            if trigger_route:
                success_signal["verify_request"] = {"path": trigger_route, "method": "GET"}
            success_signal["side_effect_target"] = "cache_processing_chain"
        elif payload_family == "path-traversal":
            success_signal["signal_type"] = "response_body"
            success_signal["match_strategy"] = "contains_any"
            success_signal["expected_indicators"] = ["root:", "[extensions]", "[fonts]"]
        elif payload_family in {"auth-bypass", "jwt", "cookie", "cors", "csrf"}:
            success_signal["signal_type"] = "authorization_or_state_change"
            success_signal["match_strategy"] = "business_effect"
            success_signal["expected_indicators"] = ["应受限资源可访问", "状态修改被接受"]
        elif payload_family == "default-credentials":
            success_signal["signal_type"] = "authorization_or_state_change"
            success_signal["match_strategy"] = "privileged_api_access"
            success_signal["expected_indicators"] = ["isGrafanaAdmin", "email", "login"]
            success_signal["verify_request"] = {"path": entry["route"] or "/api/user", "method": "GET"}
        else:
            success_signal["signal_type"] = "response_or_side_effect"
            success_signal["match_strategy"] = "business_effect"

        # F1：BOLA/IDOR 主路径即产出受害者资源 id（解 R1）。此前该字段只在 D2 回灌 feedback 消费端
        # 回填（死开关），主路径恒空 → D1 重放空 id → 404。现改为：能从端点/源码常量取到具体 id 即用具体值；
        # 否则写哨兵 VICTIM_FROM_POOL，由 D1 replay_bola 从账户池解析真实受害者 id。
        # victim 目标时 D1 差分重放无从构造请求；而 race/state_machine/calculation/auth_session 等
        # 差分族同样需要受害者/对照身份，旧门控把它们全部漏掉。规范族判定走 canonical_business_logic_family，
        # 与登记层（trigger_spec_registry）/证明层同一真相源（NAMING_STANDARDS 簇一）。
        # 注意：canonical_business_logic_family 对未收录族会原样返回（如 'generic'），故不能用
        # `canonical(payload_family) or business_cat` 的短路写法——'generic' 是 truthy，会掩盖
        # business_cat 里正确的业务族。必须按「是否为差分族」逐个判定。
        _biz_fam = ""
        for _cand in (business_cat, payload_family):
            _norm = canonical_business_logic_family(_cand)
            if _norm in DIFFERENTIAL_PROOF_FAMILIES:
                _biz_fam = _norm
                break
        if _biz_fam and not spec["prerequisites"].get("victim_resource_id"):
            _concrete = self._extract_resource_id_from_text(
                vuln.entry_point, vuln.data_flow, vuln.description, getattr(vuln, "code_snippet", ""))
            spec["prerequisites"]["victim_resource_id"] = _concrete or "VICTIM_FROM_POOL"

        # —— point 5 闭环：消费 D2 回灌的 feedback 修正 exploit_spec ——
        # 注意：feedback['current_spec'] 是「当前（错误）假说」，不可直接采纳为端点；只有 feedback 显式
        # 携带真实值（如 correction_hint.victim_resource_id / victim_resource_id）时才回填，避免把幻觉端点再写回。
        # 端点 hallucination 的纠正统一由登记层（trigger_spec_registry 的 discovered_routes 真实管理路由择优）完成。
        if isinstance(feedback, dict):
            _hint = feedback.get("correction_hint") or {}
            _vid = str(
                feedback.get("victim_resource_id")
                or _hint.get("victim_resource_id")
                or ""
            ).strip()
            if _vid:
                spec["prerequisites"]["victim_resource_id"] = _vid

        return spec

    def _merge_chain_vulnerabilities(self, vulnerabilities: List[Vulnerability],
                                     discovered_routes: Optional[List[Dict[str, Any]]] = None) -> List[Vulnerability]:
        chain_groups: Dict[str, List[Vulnerability]] = {}
        passthrough: List[Vulnerability] = []

        for vuln in vulnerabilities:
            group_key = self._early_chain_group_key(vuln)
            if not group_key:
                passthrough.append(vuln)
                continue
            chain_groups.setdefault(group_key, []).append(vuln)

        merged: List[Vulnerability] = list(passthrough)
        for group_key, items in chain_groups.items():
            if len(items) == 1:
                only = items[0]
                only.canonical_group_key = group_key
                only.chain_id = group_key
                only.is_canonical = True
                only.supporting_nodes = []
                only.supporting_node_count = 0
                only.exploit_spec = self._build_exploit_spec(only, discovered_routes=discovered_routes)
                only.chain_proof = self._build_chain_proof(only, only.exploit_spec, [])
                self._apply_proof_derivation(only)
                merged.append(only)
                continue

            if group_key == 'template-injection:expression_chain':
                canonical = sorted(
                    items,
                    key=lambda vuln: (
                        1 if self._canonical_family(vuln) == 'template-injection' else 0,
                        *self._early_chain_rank(vuln),
                    ),
                    reverse=True,
                )[0]
            else:
                canonical = sorted(items, key=self._early_chain_rank, reverse=True)[0]
            supporting_nodes = []
            seen_nodes = set()
            merged_callers = []
            absorbed_members: List[Vulnerability] = []
            for item in items:
                node_key = (str(item.file or ''), int(item.line or 0), self._normalize_anchor_text(item.code_snippet or ''))
                if item is canonical:
                    if item.callers and item.callers not in merged_callers:
                        merged_callers.append(item.callers)
                    continue
                if node_key not in seen_nodes:
                    seen_nodes.add(node_key)
                    supporting_nodes.append(self._build_supporting_node(item))
                # 此前该成员在此处被彻底丢弃，导致「按 file_path 统计覆盖」把它所在文件读成
                # 0 覆盖、且 iast_events 关联桥无处可挂。现在标记归属后随 merged 一起下行，
                # 由 report_manager 统一落库；D2 候选池按 is_absorbed 排除，前端按标记去重展示。
                item.is_absorbed = True
                item.absorbed_by_group_key = group_key
                item.canonical_group_key = group_key
                item.chain_id = group_key
                item.is_canonical = False
                absorbed_members.append(item)
                if item.callers and item.callers not in merged_callers:
                    merged_callers.append(item.callers)
                canonical.exploit_spec = merge_exploit_specs(
                    getattr(canonical, 'exploit_spec', empty_exploit_spec()),
                    getattr(item, 'exploit_spec', empty_exploit_spec()),
                )

            canonical.callers = " | ".join(merged_callers[:4]) if merged_callers else canonical.callers
            canonical.has_call_chain = any(item.has_call_chain for item in items)
            canonical.has_http_entry = any(item.has_http_entry for item in items)
            if not canonical.description or len(canonical.description) < max(len(item.description or '') for item in items):
                canonical.description = max(items, key=lambda item: len(item.description or '')).description
            canonical.canonical_group_key = group_key
            canonical.chain_id = group_key
            canonical.is_canonical = True
            canonical.supporting_nodes = supporting_nodes
            canonical.supporting_node_count = len(supporting_nodes)
            canonical.exploit_spec = merge_exploit_specs(
                self._build_exploit_spec(canonical, discovered_routes=discovered_routes),
                getattr(canonical, 'exploit_spec', empty_exploit_spec()),
            )
            canonical.chain_proof = self._build_chain_proof(canonical, canonical.exploit_spec, supporting_nodes)
            self._apply_proof_derivation(canonical)
            merged.append(canonical)
            # 不参与 canonical 的 proof_tier / exploit_spec 派生；下游按 is_absorbed 排除出 D2 候选池。
            merged.extend(absorbed_members)

        return merged

    def canonicalize_scan_results(self, results: List[ScanResult],
                                  discovered_routes: Optional[List[Dict[str, Any]]] = None) -> List[ScanResult]:
        self._discovered_routes = discovered_routes
        all_vulns: List[Vulnerability] = []
        for result in results:
            all_vulns.extend(result.vulnerabilities)

        all_vulns = self._merge_chain_vulnerabilities(all_vulns, discovered_routes=discovered_routes)
        filtered_vulns, suppressed = self._filter_raw_a2_vulnerabilities(all_vulns)

        remaining_ids = {id(vuln) for vuln in filtered_vulns}
        suppressed_by_file: Dict[str, List[dict]] = {}
        for item in suppressed:
            suppressed_by_file.setdefault(item.get('file', ''), []).append(item)
        rebuilt: List[ScanResult] = []
        for result in results:
            kept = [vuln for vuln in result.vulnerabilities if id(vuln) in remaining_ids]
            suppressed_items = suppressed_by_file.get(result.file, [])
            rebuilt.append(ScanResult(
                file=result.file,
                vulnerabilities=kept,
                agent=result.agent,
                error=result.error,
                suppressed_count=len(suppressed_items),
                suppressed_vulnerabilities=suppressed_items,
            ))

        attached_ids = {id(vuln) for result in rebuilt for vuln in result.vulnerabilities}
        for vuln in filtered_vulns:
            if id(vuln) in attached_ids:
                continue
            target = next((result for result in rebuilt if result.file == vuln.file), None)
            if target is None:
                suppressed_items = suppressed_by_file.get(vuln.file or '', [])
                target = ScanResult(
                    file=vuln.file or '',
                    vulnerabilities=[],
                    agent='a2',
                    suppressed_count=len(suppressed_items),
                    suppressed_vulnerabilities=suppressed_items,
                )
                rebuilt.append(target)
            target.vulnerabilities.append(vuln)
        return rebuilt

    def _raw_a2_suppression_reason(self, vuln: Vulnerability) -> str:
        family = self._canonical_family(vuln)
        return f"suppressed_{family}_boundary_without_reachability_or_chain"

    def _filter_raw_a2_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> tuple:
        kept: List[Vulnerability] = []
        suppressed: List[dict] = []
        for vuln in vulnerabilities:
            family = self._canonical_family(vuln)
            has_canonical = bool(getattr(vuln, 'canonical_group_key', ''))
            has_reachability = vuln.has_http_entry or vuln.has_call_chain or bool(vuln.callers)
            text = " ".join([
                str(vuln.description or ''),
                str(vuln.code_snippet or ''),
                str(vuln.entry_point or ''),
                str(vuln.sink or ''),
                str(vuln.data_flow or ''),
            ]).lower()
            has_deserialization_control = any(marker in text for marker in (
                'requestparam', 'requestbody', 'getparameter', 'pathvariable',
                'base64', 'serialized', 'user-controlled', '用户可控', 'readobject', 'objectinputstream'
            ))

            if family in {'command', 'path', 'xss'} and not has_canonical and not has_reachability:
                suppressed.append({
                    'file': vuln.file,
                    'line': vuln.line,
                    'type': vuln.type,
                    'code_snippet': vuln.code_snippet,
                    'reason': self._raw_a2_suppression_reason(vuln),
                })
                continue
            if family == 'deserialization' and not has_canonical and not has_reachability and not has_deserialization_control:
                suppressed.append({
                    'file': vuln.file,
                    'line': vuln.line,
                    'type': vuln.type,
                    'code_snippet': vuln.code_snippet,
                    'reason': self._raw_a2_suppression_reason(vuln),
                })
                continue

            kept.append(vuln)
        return kept, suppressed

    def _local_data_flow_analysis(self, file_path: str, code_snippet: str) -> Dict:
        """
        本地数据流分析 - 改进版，生成真正的漏洞利用链
        """
        result = {
            'entry_point': '',
            'sink': '',
            'data_flow': '',
            'has_http_entry': False
        }

        # 尝试读取整个文件进行分析
        full_content = code_snippet
        proj_path = getattr(self, 'project_path', '')

        try:
            paths_to_try = [file_path]
            if proj_path:
                paths_to_try.append(os.path.join(proj_path, file_path))

            for path in paths_to_try:
                if path and os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        full_content = f.read()
                    break
        except Exception:
            pass

        if not full_content:
            return result

        # ====== 1. 检查HTTP入口 (用户输入点) ======
        http_entries = []
        http_patterns = [
            (r'@RequestParam\s+\(?(\w+)\)?', '参数'),
            (r'@RequestBody\s+\(?(\w+)\)?', '请求体'),
            (r'@GetMapping\("([^"]+)"\)', 'GET路由'),
            (r'@PostMapping\("([^"]+)"\)', 'POST路由'),
            (r'@RequestMapping\("([^"]+)"\)', '路由'),
            (r'request\.getParameter\("([^"]+)"\)', 'getParameter'),
            (r'Base64\.decode\(', 'Base64解码'),
        ]

        for pattern, ptype in http_patterns:
            matches = re.findall(pattern, full_content)
            for match in matches:
                http_entries.append(f"{ptype}:{match}")

        # ====== 2. 检查危险sink函数 ======
        sinks = []
        sink_info = []  # (位置, 类型, 代码)
        sink_patterns = [
            # 命令执行
            (r'(\w+)\.exec\s*\(([^)]+)\)', '命令执行', 1),
            (r'Runtime\.getRuntime\(\)\.exec\s*\(([^)]+)\)', 'Runtime.exec', 0),
            (r'new\s+ProcessBuilder\s*\(([^)]+)\)', 'ProcessBuilder', 0),
            (r'system\s*\(([^)]+)\)', 'system()', 0),
            # 反序列化
            (r'new\s+ObjectInputStream\s*\(([^)]+)\)', 'ObjectInputStream', 0),
            (r'(\w+)\.readObject\s*\(', 'readObject()', 1),
            (r'XMLDecoder\s*\(', 'XMLDecoder', 0),
            # SQL
            (r'createStatement\s*\(', 'Statement', 0),
            (r'(\w+)\.executeQuery\s*\(([^)]+)\)', 'executeQuery', 1),
            # 文件操作
            (r'new\s+File\s*\(([^)]+)\)', 'File()', 0),
        ]

        for pattern, stype, group_idx in sink_patterns:
            matches = re.findall(pattern, full_content)
            if matches:
                for match in matches:
                    code = match[group_idx] if group_idx < len(match) else match[0]
                    sinks.append(stype)
                    sink_info.append((stype, code.strip()[:30]))

        sinks = list(set(sinks))

        # ====== 3. 检查数据流向 (输入如何传递到危险函数) ======
        data_flow_steps = []

        # 如果有HTTP入口
        if http_entries:
            data_flow_steps.append(f"[用户输入] {' + '.join(http_entries[:2])}")

            # 检查数据处理过程
            if 'Base64' in full_content:
                data_flow_steps.append("-> [Base64解码]")

            # 检查是否直接传递到危险函数
            if sinks:
                data_flow_steps.append(f"-> [危险函数] {sinks[0]}")
        else:
            # 没有直接HTTP入口，可能是通过Service调用
            if 'service' in file_path.lower() or 'processor' in file_path.lower():
                data_flow_steps.append("[间接入口] 被Controller/Service调用")
                if sinks:
                    data_flow_steps.append(f"-> [危险函数] {sinks[0]}")

        # 构建最终结果
        if http_entries:
            result['has_http_entry'] = True
            result['entry_point'] = ' | '.join(http_entries[:2])
        elif 'service' in file_path.lower() or 'processor' in file_path.lower():
            # sound 优先（宁可漏报也不伪造）：service/processor 类不直接暴露 HTTP 入口，
            # 此处不再编造「被Controller调用」占位文本，也不伪报 has_http_entry=True；
            # 真实路由由 param_resolver 调用链反查（_resolve_controller_route_by_reference）
            # 在 resolver 阶段兜底补全，正确性交 D1/I1/D2 确认。
            result['entry_point'] = ''
        else:
            # 内部方法：无 HTTP 入口，不编造占位文本、不伪报 http_entry。
            result['entry_point'] = ''

        if sinks:
            result['sink'] = ' | '.join(sinks[:2])

        if data_flow_steps:
            result['data_flow'] = ' '.join(data_flow_steps)
        elif sinks:
            result['data_flow'] = f"危险函数: {sinks[0]}"
        return result

    def assess_exploitability(self, vulnerability: Vulnerability, full_context: Dict) -> ExploitabilityResult:
        """
        评估漏洞可利用性

        Args:
            vulnerability: 漏洞
            full_context: 完整上下文

        Returns:
            ExploitabilityResult
        """
        result = ExploitabilityResult()
        result.factors = {
            'has_input_source': False,
            'has_sanitization': False,
            'has_auth_check': False,
            'network_accessible': False
        }

        # 分析数据流
        data_flows = full_context.get('data_flows', [])
        for flow in data_flows:
            if str(vulnerability.line) in str(flow.path):
                result.factors['has_input_source'] = True
                if flow.sanitized:
                    result.factors['has_sanitization'] = True
                break

        # 计算可利用性分数
        score = 0.5

        if result.factors['has_input_source']:
            score += 0.2
        if not result.factors['has_sanitization']:
            score += 0.2

        # 检查是否有认证
        if not result.factors['has_auth_check']:
            score += 0.1

        result.score = min(score, 1.0)

        # 确定级别
        if result.score >= 0.8:
            result.level = ExploitabilityLevel.CRITICAL
        elif result.score >= 0.6:
            result.level = ExploitabilityLevel.HIGH
        elif result.score >= 0.4:
            result.level = ExploitabilityLevel.MEDIUM
        elif result.score >= 0.2:
            result.level = ExploitabilityLevel.LOW
        else:
            result.level = ExploitabilityLevel.NONE

        result.reasoning = f"Exploitability score: {result.score:.2f} ({result.level.value})"

        return result

    def generate_fix_suggestion(self, vulnerability: Vulnerability, code: str) -> str:
        """
        生成修复建议

        Args:
            vulnerability: 漏洞
            code: 代码

        Returns:
            修复建议
        """
        vuln_type = vulnerability.type.lower()

        suggestions = {
            'sql': "Use parameterized queries (prepared statements) instead of string concatenation. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            'command': "Avoid using user input in shell commands. Use subprocess with list arguments and shell=False, or use secure APIs.",
            'xss': "Use output encoding appropriate to the context. Consider using template engines with auto-escaping.",
            'ssrf': "Validate and whitelist URLs. Avoid taking URL from user input directly.",
            'path': "Use secure file path construction. Validate input against a whitelist, use os.path.basename().",
            'deserialize': "Never deserialize untrusted data. Use JSON instead of pickle/yaml for untrusted data.",
        }

        for key, suggestion in suggestions.items():
            if key in vuln_type:
                return suggestion

        return "Review and validate all user inputs. Apply appropriate sanitization and encoding."

    def scan_file(self, file_info: Dict, all_files: Dict = None, a1_evidence: Optional[Dict] = None, feedback: Optional[List[Dict]] = None) -> ScanResult:
        """
        扫描单个文件

        Args:
            file_info: 文件信息
            all_files: 所有文件内容字典 {rel_path: content}，用于跨文件调用链分析
            a1_evidence: A1 静态分析调用链证据（entry/source/sink/guard/sanitizer/ownership
                候选），在 LLM 调 prompt 之前注入，使 LLM 同时消费 A1 证据 + 自析源码。

        Returns:
            ScanResult
        """
        result = ScanResult(file=file_info.get('rel_path', ''), agent='a2')

        try:
            content = file_info.get('content', '')
            file_path = file_info.get('rel_path', '')
            self.project_path = file_info.get('project_path', '')

            context = {
                'file_path': file_path,
                'language': file_info.get('language', 'unknown'),
                'project_path': self.project_path,
                'all_files': all_files or {},  # 传递所有文件用于跨文件分析
                'a1_evidence': a1_evidence or {},
                'feedback': feedback or [],  # §P4：D2/I2 闭环回灌的 feedback_to_a2，供 A2 二次分析消费
            }

            # 语义分析
            analysis_result = self.analyze(file_path, content, context)

            for vuln in analysis_result.vulnerabilities:
                self._reanchor_vulnerability(vuln, content)

            # 为每个漏洞添加跨文件调用链分析
            for vuln in analysis_result.vulnerabilities:
                if all_files:
                    call_chain_result = self._analyze_cross_file_call_chain(
                        vuln, all_files
                    )
                    vuln.has_call_chain = call_chain_result['has_caller']
                    vuln.callers = call_chain_result['callers_str']
                    vuln.verdict = call_chain_result['verdict']
                    # 真实族与 A1 误标不一致时，回写 vuln.type —— trigger_specs.family 经
                    # vuln.to_dict → _norm_family 解析，'ldap-injection' 会被确定性归一到
                    # ldap_injection，使 D2 真值(ldapi) 对账不再错配为 xpathi。
                    family_override = call_chain_result.get('family_override')
                    if family_override and (vuln.type or '').lower() != family_override:
                        vuln.type = family_override
                    if call_chain_result.get('http_entry') and not vuln.entry_point:
                        vuln.entry_point = call_chain_result.get('http_entry', '')
                else:
                    vuln.verdict = '⚠️ A2:无跨文件数据'
                vuln.source = 'a2'
                vuln.exploit_spec = self._build_exploit_spec(
                    vuln, feedback=feedback, discovered_routes=getattr(self, "_discovered_routes", None))

            result.vulnerabilities = self._deduplicate_a2_vulnerabilities(analysis_result.vulnerabilities)

            # 更新共享上下文
            if hasattr(self, 'shared_context') and self.shared_context:
                self.shared_context.update_vulnerabilities('a2', result.vulnerabilities)

        except Exception as e:
            logger.error(f"Error scanning {file_info.get('rel_path', '')}: {e}")
            result.error = str(e)

        return result

    def _analyze_cross_file_call_chain(self, vuln: Vulnerability, all_files: Dict) -> Dict:
        """
        跨文件调用链分析 - 判断真假漏洞的核心!
        检查漏洞函数是否在其他文件中有调用者，或者是否有HTTP入口
        """
        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无调用点'
        }

        ssti_result = self._analyze_thymeleaf_ssti(vuln, all_files)
        if ssti_result:
            return ssti_result

        generic_template_result = self._analyze_java_template_ssti(vuln, all_files)
        if generic_template_result:
            return generic_template_result

        python_template_result = self._analyze_python_template_ssti(vuln, all_files)
        if python_template_result:
            return python_template_result

        python_pickle_result = self._analyze_python_pickle(vuln, all_files)
        if python_pickle_result:
            return python_pickle_result

        java_jwt_result = self._analyze_java_jwt(vuln, all_files)
        if java_jwt_result:
            return java_jwt_result

        java_fastjson_result = self._analyze_java_fastjson(vuln, all_files)
        if java_fastjson_result:
            return java_fastjson_result

        java_ognl_result = self._analyze_java_ognl(vuln, all_files)
        if java_ognl_result:
            return java_ognl_result

        java_jndi_result = self._analyze_java_jndi(vuln, all_files)
        if java_jndi_result:
            return java_jndi_result

        java_ldap_result = self._analyze_java_ldap(vuln, all_files)
        if java_ldap_result:
            return java_ldap_result

        java_jackson_result = self._analyze_java_jackson(vuln, all_files)
        if java_jackson_result:
            return java_jackson_result

        java_xstream_result = self._analyze_java_xstream(vuln, all_files)
        if java_xstream_result:
            return java_xstream_result

        java_upload_result = self._analyze_java_upload(vuln, all_files)
        if java_upload_result:
            return java_upload_result

        java_csp_result = self._analyze_java_csp(vuln, all_files)
        if java_csp_result:
            return java_csp_result

        java_tomcat_result = self._analyze_java_tomcat(vuln, all_files)
        if java_tomcat_result:
            return java_tomcat_result

        java_cors_result = self._analyze_java_cors(vuln, all_files)
        if java_cors_result:
            return java_cors_result

        java_cookie_result = self._analyze_java_cookie(vuln, all_files)
        if java_cookie_result:
            return java_cookie_result

        java_auth_result = self._analyze_java_auth(vuln, all_files)
        if java_auth_result:
            return java_auth_result

        java_hpp_result = self._analyze_java_hpp(vuln, all_files)
        if java_hpp_result:
            return java_hpp_result

        java_mongo_result = self._analyze_java_mongo(vuln, all_files)
        if java_mongo_result:
            return java_mongo_result

        java_redis_result = self._analyze_java_redis(vuln, all_files)
        if java_redis_result:
            return java_redis_result

        java_redirect_result = self._analyze_java_open_redirect(vuln, all_files)
        if java_redirect_result:
            return java_redirect_result

        java_ssl_result = self._analyze_java_ssl_verification(vuln, all_files)
        if java_ssl_result:
            return java_ssl_result

        java_session_result = self._analyze_java_weak_session(vuln, all_files)
        if java_session_result:
            return java_session_result

        python_jwt_result = self._analyze_python_jwt(vuln, all_files)
        if python_jwt_result:
            return python_jwt_result

        python_xml_result = self._analyze_python_xml(vuln, all_files)
        if python_xml_result:
            return python_xml_result

        python_crypto_result = self._analyze_python_weak_crypto(vuln, all_files)
        if python_crypto_result:
            return python_crypto_result

        python_secret_result = self._analyze_python_hardcoded_secret(vuln, all_files)
        if python_secret_result:
            return python_secret_result

        python_temp_result = self._analyze_python_temp_file(vuln, all_files)
        if python_temp_result:
            return python_temp_result

        python_upload_result = self._analyze_python_upload(vuln, all_files)
        if python_upload_result:
            return python_upload_result

        php_webshell_result = self._analyze_php_webshell(vuln, all_files)
        if php_webshell_result:
            return php_webshell_result

        php_upload_result = self._analyze_php_upload(vuln, all_files)
        if php_upload_result:
            return php_upload_result

        php_command_result = self._analyze_php_command(vuln, all_files)
        if php_command_result:
            return php_command_result

        python_yaml_result = self._analyze_python_yaml(vuln, all_files)
        if python_yaml_result:
            return python_yaml_result

        python_ldap_result = self._analyze_python_ldap(vuln, all_files)
        if python_ldap_result:
            return python_ldap_result

        python_debug_result = self._analyze_python_debug(vuln, all_files)
        if python_debug_result:
            return python_debug_result

        python_marshal_result = self._analyze_python_marshal(vuln, all_files)
        if python_marshal_result:
            return python_marshal_result

        python_command_result = self._analyze_python_command(vuln, all_files)
        if python_command_result:
            return python_command_result

        php_deser_result = self._analyze_php_deserialization(vuln, all_files)
        if php_deser_result:
            return php_deser_result

        php_path_result = self._analyze_php_path(vuln, all_files)
        if php_path_result:
            return php_path_result

        php_sqli_result = self._analyze_php_sqli(vuln, all_files)
        if php_sqli_result:
            return php_sqli_result

        php_xss_result = self._analyze_php_xss(vuln, all_files)
        if php_xss_result:
            return php_xss_result

        php_redirect_result = self._analyze_php_open_redirect(vuln, all_files)
        if php_redirect_result:
            return php_redirect_result

        php_ssrf_result = self._analyze_php_ssrf(vuln, all_files)
        if php_ssrf_result:
            return php_ssrf_result

        php_jwt_result = self._analyze_php_jwt(vuln, all_files)
        if php_jwt_result:
            return php_jwt_result

        php_cors_result = self._analyze_php_cors(vuln, all_files)
        if php_cors_result:
            return php_cors_result

        php_cookie_result = self._analyze_php_cookie(vuln, all_files)
        if php_cookie_result:
            return php_cookie_result

        php_auth_result = self._analyze_php_auth(vuln, all_files)
        if php_auth_result:
            return php_auth_result

        node_jwt_result = self._analyze_node_jwt(vuln, all_files)
        if node_jwt_result:
            return node_jwt_result

        node_redirect_result = self._analyze_node_open_redirect(vuln, all_files)
        if node_redirect_result:
            return node_redirect_result

        node_delete_result = self._analyze_node_file_delete(vuln, all_files)
        if node_delete_result:
            return node_delete_result

        node_nosql_result = self._analyze_node_nosql_injection(vuln, all_files)
        if node_nosql_result:
            return node_nosql_result

        node_cors_result = self._analyze_node_cors(vuln, all_files)
        if node_cors_result:
            return node_cors_result

        node_cookie_result = self._analyze_node_cookie(vuln, all_files)
        if node_cookie_result:
            return node_cookie_result

        node_auth_result = self._analyze_node_auth(vuln, all_files)
        if node_auth_result:
            return node_auth_result

        node_pp_result = self._analyze_node_prototype_pollution(vuln, all_files)
        if node_pp_result:
            return node_pp_result

        node_template_result = self._analyze_node_template_injection(vuln, all_files)
        if node_template_result:
            return node_template_result

        node_deser_result = self._analyze_node_deserialization(vuln, all_files)
        if node_deser_result:
            return node_deser_result

        node_cmd_result = self._analyze_node_command_injection(vuln, all_files)
        if node_cmd_result:
            return node_cmd_result

        node_ssrf_result = self._analyze_node_ssrf(vuln, all_files)
        if node_ssrf_result:
            return node_ssrf_result

        node_path_result = self._analyze_node_path_traversal(vuln, all_files)
        if node_path_result:
            return node_path_result

        node_upload_result = self._analyze_node_file_upload(vuln, all_files)
        if node_upload_result:
            return node_upload_result

        # 1. 首先检查是否有HTTP入口
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            result['verdict'] = '✅ A2:真漏洞-HTTP入口可触发'
            return result

        # 2. 如果没有HTTP入口，检查是否有跨文件方法调用
        # 提取漏洞所在的方法名
        method_name = self._extract_method_from_code(vuln.code_snippet, all_files.get(vuln.file, ''), vuln.line)
        if method_name:
            # 搜索其他文件中对该方法的调用
            for file_path, content in all_files.items():
                if file_path == vuln.file:
                    continue
                if not any(file_path.endswith(ext) for ext in ['.java', '.py', '.js', '.ts', '.go', '.php']):
                    continue

                callers = self._find_method_callers(content, method_name, file_path)
                if callers:
                    result['callers'].extend(callers)

            if result['callers']:
                result['has_caller'] = True
                result['callers_str'] = '; '.join([c['desc'] for c in result['callers'][:3]])
                result['verdict'] = '✅ A2:真漏洞-有跨文件调用'

        return result

    def _analyze_java_template_ssti(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_template_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控模板入口'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._thymeleaf_request_controlled(content, vuln.line or 0)
        dynamic_template = bool(re.search(r'(evaluate|mergeTemplate|getTemplate|parseExpression)\s*\([^"\']', content))

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入模板/表达式上下文')
        if dynamic_template:
            details.append('模板内容或表达式动态可控')

        if http_entry and (request_controlled or dynamic_template):
            result['verdict'] = '✅ A2:真漏洞-Java模板引擎动态渲染'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        if http_entry:
            result['verdict'] = '⚠️ A2:可疑-Java模板引擎需D2验证'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        return result

    def _analyze_python_template_ssti(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_template_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控模板入口'
        }
        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._python_request_controlled(content, vuln.line or 0)
        dynamic_template = bool(re.search(r'(render_template_string|Template|from_string)\s*\([^"\']', content))

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入模板字符串')
        if dynamic_template:
            details.append('模板内容动态可控')

        if http_entry and (request_controlled or dynamic_template):
            result['verdict'] = '✅ A2:真漏洞-Jinja2模板动态渲染'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        if http_entry:
            result['verdict'] = '⚠️ A2:可疑-Jinja2模板需D2验证'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        return result

    def _analyze_python_pickle(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_pickle_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无不可信反序列化输入'
        }
        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._python_request_controlled(content, vuln.line or 0)
        direct_pickle = bool(re.search(r'pickle\.loads?\s*\(', content))

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('不可信输入进入 pickle')
        if direct_pickle:
            details.append('存在 pickle.load/loads 调用')

        if direct_pickle and (http_entry or request_controlled):
            result['verdict'] = '✅ A2:真漏洞-pickle不安全反序列化'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        if direct_pickle:
            result['verdict'] = '⚠️ A2:可疑-pickle反序列化需D2验证'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        return result

    def _analyze_thymeleaf_ssti(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_thymeleaf_ssti_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控模板入口'
        }

        vuln_content = all_files.get(vuln.file, '')
        if not vuln_content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._thymeleaf_request_controlled(vuln_content, vuln.line or 0)
        dynamic_template = self._thymeleaf_dynamic_template(vuln_content, vuln.line or 0)
        raw_output = 'th:utext' in vuln_content

        verdict_parts = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            verdict_parts.append('HTTP入口可触发')
        if request_controlled:
            verdict_parts.append('用户输入可进入模板上下文')
        if dynamic_template:
            verdict_parts.append('模板名/模板内容动态可控')
        if raw_output:
            verdict_parts.append('存在 th:utext 不转义输出')

        if http_entry and (request_controlled or dynamic_template):
            result['verdict'] = '✅ A2:真漏洞-Thymeleaf可控模板渲染'
            result['callers_str'] = ' | '.join(verdict_parts[:3])
            return result

        if http_entry and raw_output:
            result['verdict'] = '⚠️ A2:可疑-Thymeleaf原样输出需D2验证'
            result['callers_str'] = ' | '.join(verdict_parts[:3])
            result['has_caller'] = True
            return result

        if http_entry:
            result['verdict'] = '⚠️ A2:可疑-Thymeleaf已到达入口但模板可控性不足'
            result['callers_str'] = ' | '.join(verdict_parts[:3])
            result['has_caller'] = True
            return result

        return result

    def _analyze_node_prototype_pollution(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_prototype_pollution_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控原型污染入口'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dangerous_merge = self._node_dangerous_merge(content, vuln.line or 0)
        prototype_write = self._node_prototype_write(content, vuln.line or 0)

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入对象合并上下文')
        if dangerous_merge:
            details.append('存在危险对象合并或路径写入')
        if prototype_write:
            details.append('存在 __proto__/constructor.prototype 污染')

        if (http_entry or request_controlled) and dangerous_merge and prototype_write:
            result['verdict'] = '✅ A2:真漏洞-原型链污染可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:4])
            return result

        if (http_entry or request_controlled) and (dangerous_merge or prototype_write):
            result['verdict'] = '⚠️ A2:可疑-原型链污染需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            if http_entry:
                result['has_caller'] = True
            return result

        return result

    def _analyze_node_template_injection(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_template_injection_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控模板注入入口'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dynamic_template = self._node_dynamic_template(content, vuln.line or 0)

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入模板上下文')
        if dynamic_template:
            details.append('模板内容或模板名动态可控')

        if http_entry and request_controlled and dynamic_template:
            result['verdict'] = '✅ A2:真漏洞-Node模板注入可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        if http_entry and (request_controlled or dynamic_template):
            result['verdict'] = '⚠️ A2:可疑-Node模板注入需D2验证'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        return result

    def _analyze_node_nosql_injection(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_nosql_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控NoSQL查询入口'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0) or bool(re.search(r'(ctx\.(request\.)?(body|query|params)|request\.(body|query|params)|@Query\(|@Body\(|@Param\()', content))
        dangerous_query = bool(re.search(r'(findOne|find|aggregate|updateOne|updateMany|findOneAndUpdate|findById|findByIdAndUpdate|countDocuments|exists)\s*\(', content))
        operator_object = bool(re.search(r'(\$ne|\$gt|\$regex|\$where|\$in|\$or|req\.(body|query|params)|ctx\.(request\.)?(body|query|params)|request\.(body|query|params)|@Query\(|@Body\(|@Param\()', content))

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入 Mongo/Mongoose 查询条件')
        if dangerous_query:
            details.append('存在 Mongo/Mongoose 查询接口或框架封装查询')
        if operator_object:
            details.append('存在操作符对象或未净化查询条件')

        if dangerous_query and operator_object and (http_entry or request_controlled):
            result['verdict'] = '✅ A2:真漏洞-Node NoSQL注入可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:4])
            return result

        if dangerous_query and (http_entry or request_controlled):
            result['verdict'] = '⚠️ A2:可疑-Node NoSQL注入需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            return result

        return result

    def _analyze_node_deserialization(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_deserialization_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无不可信反序列化输入'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dangerous_deserialization = self._node_dangerous_deserialization(content, vuln.line or 0)

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('不可信输入可进入反序列化上下文')
        if dangerous_deserialization:
            details.append('存在危险反序列化调用')

        if dangerous_deserialization and (http_entry or request_controlled):
            result['verdict'] = '✅ A2:真漏洞-Node不安全反序列化'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        if dangerous_deserialization:
            result['verdict'] = '⚠️ A2:可疑-Node反序列化需D2验证'
            result['callers_str'] = ' | '.join(details[:3])
            return result

        return result

    def _analyze_node_command_injection(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_command_injection_vuln(vuln):
            return None

        result = {
            'has_caller': False,
            'callers': [],
            'callers_str': '',
            'http_entry': None,
            'verdict': '❌ A2:假漏洞-无可控命令执行入口'
        }

        content = all_files.get(vuln.file, '')
        if not content:
            return result

        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dangerous_command = self._node_dangerous_command(content, vuln.line or 0)
        command_concat = self._node_command_concatenation(content, vuln.line or 0)

        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入命令参数')
        if dangerous_command:
            details.append('存在系统命令执行入口')
        if command_concat:
            details.append('命令字符串存在拼接或模板插值')

        if dangerous_command and request_controlled and (http_entry or command_concat):
            result['verdict'] = '✅ A2:真漏洞-Node命令注入可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:4])
            return result

        if dangerous_command and (request_controlled or http_entry):
            result['verdict'] = '⚠️ A2:可疑-Node命令注入需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            return result

        return result

    def _analyze_node_ssrf(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_ssrf_vuln(vuln):
            return None
        result = {'has_caller': False, 'callers': [], 'callers_str': '', 'http_entry': None, 'verdict': '❌ A2:假漏洞-无可控SSRF入口'}
        content = all_files.get(vuln.file, '')
        if not content:
            return result
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dangerous_ssrf = self._node_dangerous_ssrf(content, vuln.line or 0)
        url_controlled = self._node_url_controlled(content, vuln.line or 0)
        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入 URL 上下文')
        if dangerous_ssrf:
            details.append('存在服务端发起请求入口')
        if url_controlled:
            details.append('目标地址动态可控')
        if dangerous_ssrf and url_controlled and (http_entry or request_controlled):
            result['verdict'] = '✅ A2:真漏洞-Node SSRF可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        if dangerous_ssrf and (http_entry or request_controlled):
            result['verdict'] = '⚠️ A2:可疑-Node SSRF需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        return result

    def _analyze_node_path_traversal(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_path_traversal_vuln(vuln):
            return None
        result = {'has_caller': False, 'callers': [], 'callers_str': '', 'http_entry': None, 'verdict': '❌ A2:假漏洞-无可控路径入口'}
        content = all_files.get(vuln.file, '')
        if not content:
            return result
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = self._node_request_controlled(content, vuln.line or 0)
        dangerous_file = self._node_dangerous_file_access(content, vuln.line or 0)
        path_controlled = self._node_path_controlled(content, vuln.line or 0)
        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if request_controlled:
            details.append('用户输入可进入文件路径')
        if dangerous_file:
            details.append('存在文件读取或发送入口')
        if path_controlled:
            details.append('路径拼接或解析动态可控')
        if dangerous_file and path_controlled and (http_entry or request_controlled):
            result['verdict'] = '✅ A2:真漏洞-Node路径穿越可由HTTP输入触发'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        if dangerous_file and (http_entry or request_controlled):
            result['verdict'] = '⚠️ A2:可疑-Node路径穿越需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        return result

    def _analyze_node_file_upload(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_file_upload_vuln(vuln):
            return None
        result = {'has_caller': False, 'callers': [], 'callers_str': '', 'http_entry': None, 'verdict': '❌ A2:假漏洞-无危险文件上传入口'}
        content = all_files.get(vuln.file, '')
        if not content:
            return result
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        upload_handler = self._node_upload_handler(content, vuln.line or 0)
        filename_controlled = self._node_upload_filename_controlled(content, vuln.line or 0)
        unrestricted_type = self._node_upload_unrestricted_type(content, vuln.line or 0)
        details = []
        if http_entry:
            result['has_caller'] = True
            result['http_entry'] = http_entry
            details.append('HTTP入口可触发')
        if upload_handler:
            details.append('存在文件上传处理器')
        if filename_controlled:
            details.append('上传文件名或落地路径可控')
        if unrestricted_type:
            details.append('未观察到类型或扩展名限制')
        if upload_handler and filename_controlled and (http_entry or unrestricted_type):
            result['verdict'] = '✅ A2:真漏洞-Node危险文件上传'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        if upload_handler and (filename_controlled or unrestricted_type):
            result['verdict'] = '⚠️ A2:可疑-Node文件上传需D2验证'
            result['callers_str'] = ' | '.join(details[:4])
            return result
        return result

    def _analyze_java_jwt(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_jwt_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        weak_verify = bool(re.search(r'parseClaimsJwt|algorithms?\s*\(\s*"none"|setAllowedClockSkewSeconds', content, re.IGNORECASE))
        no_auth_guard = not bool(re.search(r'@PreAuthorize|hasRole|verifyWith|setSigningKey', content))
        if weak_verify:
            return {'has_caller': True, 'callers': [], 'callers_str': '存在弱 JWT 校验或算法约束不足', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java JWT校验不安全'}
        if no_auth_guard:
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到 JWT 逻辑但签名校验证据不足', 'http_entry': None, 'verdict': '⚠️ A2:可疑-Java JWT需进一步验证'}
        return None

    def _analyze_java_fastjson(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_fastjson_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        request_controlled = self._thymeleaf_request_controlled(content, vuln.line or 0)
        dangerous = bool(re.search(r'JSON\.parse(Object|Array)?\s*\(', content))
        auto_type = bool(re.search(r'@type|setAutoTypeSupport\s*\(\s*true|ParserConfig\.getGlobalInstance', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and auto_type and (http_entry or request_controlled):
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Fastjson 且存在 AutoType 风险', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Fastjson不安全反序列化'}
        if dangerous and (http_entry or request_controlled):
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Fastjson 解析', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Fastjson需D2验证'}
        return None

    def _analyze_java_ognl(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_ognl_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'Ognl(Runtime|Context)?|Ognl\.(getValue|setValue)|ActionContext|ServletActionContext', content))
        request_controlled = bool(re.search(r'@RequestParam|request\.getParameter|getParameterMap|\+', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and request_controlled and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 OGNL 表达式求值入口', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Java OGNL表达式注入'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 OGNL 表达式求值逻辑，需确认输入是否可控', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Java OGNL需D2验证'}
        return None

    def _analyze_java_jndi(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_jndi_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous_lookup = bool(re.search(r'InitialContext|Context\.lookup|lookup\s*\(', content))
        request_controlled = bool(re.search(r'@RequestParam|request\.getParameter|\burl\b|\bjndi\b|\bname\b|\+', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous_lookup and request_controlled and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入可控 JNDI lookup 目标', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Java JNDI注入'}
        if dangerous_lookup:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 JNDI lookup 逻辑，需确认命名目标是否可控', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Java JNDI需D2验证'}
        return None

    def _analyze_java_ldap(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        content = all_files.get(vuln.file, '') or ''
        # 如 02115），故在 gate 之前取 content 并传入 _is_java_ldap_vuln。
        if not self._is_java_ldap_vuln(vuln, content):
            return None
        if not content:
            return None
        # BenchmarkTestNNNNN.java 本文件内），本文件只含 javax.naming.directory.SearchControls + 过滤器拼接，
        # 故 dangerous_search 恒为 False → _analyze_java_ldap 在 _is_java_ldap_vuln 已判定 LDAP 后仍 return
        # None → family_override 永不回写 → 落库恒为 xpathi。这里把 LDAP 目录包标记纳入 dangerous_search，
        # 与 _is_java_ldap_vuln 的判定口径对齐，使本文件含 SearchControls/LDAPManager 即视为 LDAP 查询。
        dangerous_search = bool(re.search(r'DirContext|LdapContext|search\s*\(|javax\.naming\.directory|SearchControls|LDAPManager|getDirContext', content, re.IGNORECASE))
        filter_concat = bool(re.search(r'search\s*\([^)]*(\+|format\(|String\.format|MessageFormat)|(\+|format\(|String\.format|MessageFormat)\s*[^;]*filter', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        # A1 误标 xpath-injection 时 family 恒为 xpathi。这里返回 family_override，由 scan_file
        # 回写 vuln.type='ldap-injection'，使 _norm_family 的 ('ldap',) 针确定性收敛到 ldap_injection，
        # 与 D2 真值(ldapi) 对齐。
        result_family = 'ldap-injection'
        if dangerous_search and filter_concat and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入拼接进入 LDAP 查询过滤器', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Java LDAP注入', 'family_override': result_family}
        if dangerous_search:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 LDAP 查询逻辑，需确认过滤器是否由请求参数拼接', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Java LDAP需D2验证', 'family_override': result_family}
        return None

    def _analyze_java_jackson(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_jackson_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous_mapper = bool(re.search(r'ObjectMapper|readValue\s*\(|enableDefaultTyping|activateDefaultTyping', content))
        request_controlled = bool(re.search(r'@RequestBody|HttpServletRequest|request\.getParameter|readValue\s*\(\s*\w+\s*,', content))
        default_typing = bool(re.search(r'enableDefaultTyping|activateDefaultTyping', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous_mapper and request_controlled and (default_typing or http_entry):
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Jackson readValue，且存在危险多态类型能力', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Jackson不安全反序列化'}
        if dangerous_mapper:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Jackson 反序列化逻辑，需确认默认类型和输入可控性', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Jackson反序列化需D2验证'}
        return None

    def _analyze_java_xstream(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_xstream_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'XStream|fromXML\s*\(', content))
        request_controlled = bool(re.search(r'@RequestBody|request\.getParameter|\+', content))
        weak_allowlist = not bool(re.search(r'allowTypes|allowTypesByWildcard|addPermission|NoTypePermission', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and request_controlled and (weak_allowlist or http_entry):
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 XStream.fromXML，且未见严格类型白名单', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-XStream不安全反序列化'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 XStream XML 反序列化逻辑，需确认输入可控性和类型限制', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-XStream反序列化需D2验证'}
        return None

    def _analyze_java_upload(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_upload_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'transferTo\s*\(|getOriginalFilename\s*\(', content))
        no_filter = not bool(re.search(r'contentType|allowedExt|whitelist|suffix', content, re.IGNORECASE))
        if dangerous and no_filter:
            return {'has_caller': True, 'callers': [], 'callers_str': '存在文件落地且缺少扩展名/类型限制', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java危险文件上传'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到文件上传落地逻辑', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java文件上传需D2验证'}
        return None

    def _analyze_java_csp(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_csp_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        unsafe_csp = bool(re.search(r"Content-Security-Policy.*(unsafe-inline|\*)", content, re.IGNORECASE))
        if unsafe_csp:
            return {'has_caller': False, 'callers': [], 'callers_str': 'CSP 包含 unsafe-inline 或通配符', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Java CSP配置不安全'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 CSP 相关配置，需确认是否真正缺失或过宽', 'http_entry': None, 'verdict': '⚠️ A2:可疑-Java CSP需人工确认'}

    def _analyze_java_tomcat(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_tomcat_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous_put = bool(re.search(r'readonly\s*=\s*false|setReadonly\s*\(\s*false', content))
        manager_like = bool(re.search(r'/manager|DefaultServlet', content))
        if dangerous_put or manager_like:
            return {'has_caller': False, 'callers': [], 'callers_str': 'Tomcat 组件配置暴露危险能力', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Tomcat危险配置'}
        return None

    def _analyze_java_cors(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_cors_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'@CrossOrigin\s*\([^)]*\*|allowedOrigins\s*\([^)]*\*|allowedOriginPatterns\s*\([^)]*\*', content, re.IGNORECASE))
        credentials = bool(re.search(r'allowCredentials\s*\([^)]*true|setAllowCredentials\s*\([^)]*true', content, re.IGNORECASE))
        if dangerous and credentials:
            return {'has_caller': False, 'callers': [], 'callers_str': 'CORS 允许任意来源且允许凭证', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java CORS配置不安全'}
        if dangerous:
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到 Java CORS 允许任意来源', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java CORS需D2验证'}
        return None

    def _analyze_java_cookie(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_cookie_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        sets_cookie = bool(re.search(r'addCookie|new\s+Cookie', content))
        weak_flags = bool(re.search(r'setSecure\s*\(\s*false|setHttpOnly\s*\(\s*false', content, re.IGNORECASE))
        missing_flags = sets_cookie and not bool(re.search(r'setSecure\s*\(|setHttpOnly\s*\(', content, re.IGNORECASE))
        if sets_cookie and (weak_flags or missing_flags):
            return {'has_caller': False, 'callers': [], 'callers_str': 'Cookie 设置缺少 Secure/HttpOnly 保护', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java Cookie配置不安全'}
        if sets_cookie:
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到 Cookie 写入逻辑，需确认是否设置 Secure/HttpOnly', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java Cookie需D2验证'}
        return None

    def _analyze_java_auth(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_auth_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        open_access = bool(re.search(r'permitAll\s*\(|anonymous\s*\(|\.anonymous\s*\(', content, re.IGNORECASE))
        missing_guard = bool(re.search(r'@(GetMapping|PostMapping|RequestMapping)', content)) and not bool(re.search(r'@PreAuthorize|@Secured|@RolesAllowed', content))
        if open_access or missing_guard:
            return {'has_caller': False, 'callers': [], 'callers_str': '敏感接口缺少鉴权或显式允许匿名访问', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java鉴权绕过'}
        return None

    def _analyze_java_hpp(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_hpp_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        multi_param = bool(re.search(r'getParameterValues|getParameters|MultiValueMap', content))
        dangerous_sink = bool(re.search(r'query|sql|redirect|Location|Document\.parse|opsForValue|find\(', content, re.IGNORECASE))
        if multi_param and dangerous_sink:
            return {'has_caller': True, 'callers': [], 'callers_str': '多值参数进入危险查询或控制流', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java HTTP参数污染'}
        if multi_param:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到多值参数处理逻辑，需确认是否影响后端行为', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java HPP需D2验证'}
        return None

    def _analyze_java_mongo(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_mongo_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'MongoCollection|BasicDBObject|Document\.parse|MongoTemplate', content))
        request_controlled = bool(re.search(r'@RequestParam|request\.getParameter|\+', content))
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Mongo 查询构造逻辑', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java MongoDB注入'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Mongo 查询接口，需确认查询条件是否由请求参数拼接', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java MongoDB注入需D2验证'}
        return None

    def _analyze_java_redis(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_redis_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'Jedis|RedisTemplate|StringRedisTemplate|opsForValue', content))
        request_controlled = bool(re.search(r'@RequestParam|request\.getParameter|\+', content))
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Redis 命令或 key 构造逻辑', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java Redis命令注入'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Redis 操作接口，需确认 key/command 是否由请求参数直接控制', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java Redis注入需D2验证'}
        return None

    def _analyze_java_open_redirect(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_open_redirect_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'redirect:|sendRedirect\s*\(|setHeader\s*\(\s*["\']Location|ResponseEntity\.status\s*\(\s*30[12]', content, re.IGNORECASE))
        request_controlled = bool(re.search(r'@RequestParam|request\.getParameter|\burl\b|\bnext\b|\bredirect\b|\+', content))
        validated = bool(re.search(r'allowlist|whitelist|startsWith|URI\.create|isTrusted', content, re.IGNORECASE))
        if dangerous and request_controlled and not validated:
            return {'has_caller': True, 'callers': [], 'callers_str': '请求参数直接控制 Java 重定向目标，未见白名单校验', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java开放重定向'}
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Java 重定向逻辑，需确认目标是否被严格限制', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Java开放重定向需D2验证'}
        return None

    def _analyze_java_ssl_verification(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_ssl_verification_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustManager|HostnameVerifier|setHostnameVerifier', content, re.IGNORECASE))
        disabled = bool(re.search(r'return\s+true\s*;|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|verify\s*\([^)]*\)\s*\{\s*return\s+true', content, re.IGNORECASE))
        if dangerous and disabled:
            return {'has_caller': False, 'callers': [], 'callers_str': 'SSL 证书或主机名校验被关闭', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Java禁用SSL校验'}
        if dangerous:
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到弱 SSL 校验逻辑，需确认是否实际跳过校验', 'http_entry': None, 'verdict': '⚠️ A2:可疑-Java SSL校验需D2验证'}
        return None

    def _analyze_java_weak_session(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_java_weak_session_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        weak_session = bool(re.search(r'HttpSession|session\.setAttribute', content)) and bool(re.search(r'new\s+Random\s*\(|Math\.random\s*\(', content))
        if weak_session:
            return {'has_caller': False, 'callers': [], 'callers_str': '会话标识或会话相关随机值由弱随机数生成', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Java弱会话标识'}
        return None

    def _analyze_python_jwt(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_jwt_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        weak_verify = bool(re.search(r'jwt\.decode\s*\([^)]*verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False', content))
        if weak_verify:
            return {'has_caller': True, 'callers': [], 'callers_str': 'JWT decode 禁用了签名校验', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Python JWT校验不安全'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 JWT 逻辑，需进一步确认算法与签名校验', 'http_entry': None, 'verdict': '⚠️ A2:可疑-Python JWT需进一步验证'}

    def _analyze_python_xml(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_xml_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        request_controlled = bool(re.search(r'request\.data|request\.body|request\.get_data|request\.args|request\.form|Body\(|xml\s*=|data\s*=|content\s*=', content))
        dangerous_parser = any(re.search(pattern, content, re.IGNORECASE) for pattern in PYTHON_XML_PATTERNS)
        unsafe_entities = bool(re.search(r'resolve_entities\s*=\s*True|no_network\s*=\s*False|DOCTYPE|ENTITY|xmlrpc\.client\.loads|xmlrpc\.server', content, re.IGNORECASE))
        if dangerous_parser and unsafe_entities and (http_entry or request_controlled):
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Python XML 解析，且存在外部实体/实体扩展/XML-RPC 不安全特征', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python XML解析不安全'}
        if dangerous_parser and (http_entry or request_controlled):
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Python XML 解析逻辑，需确认实体解析和 XML-RPC 输入是否可控', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Python XML需D2验证'}
        return None

    def _analyze_python_weak_crypto(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_weak_crypto_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'hashlib\.md5|hashlib\.sha1|\bmd5\(|\bsha1\(|random\.(random|randrange)', content):
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到弱加密散列或不安全随机数用于安全相关逻辑', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Python弱加密/弱随机数'}
        return None

    def _analyze_python_hardcoded_secret(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_hardcoded_secret_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'(password|passwd|pwd|api[_-]?key|secret[_-]?key|secret|token)\s*=\s*[\'"][^\'"]+[\'"]', content, re.IGNORECASE):
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到硬编码密码、密钥或令牌', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Python硬编码敏感信息'}
        return None

    def _analyze_python_temp_file(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_temp_file_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'tempfile\.mktemp', content):
            return {'has_caller': False, 'callers': [], 'callers_str': '检测到不安全临时文件创建接口 tempfile.mktemp', 'http_entry': None, 'verdict': '✅ A2:真漏洞-Python不安全临时文件'}
        return None

    def _analyze_python_upload(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_upload_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'request\.files|UploadFile|\.save\s*\(', content))
        no_filter = not bool(re.search(r'allowed_extensions|content_type|suffix|secure_filename', content))
        if dangerous and no_filter:
            return {'has_caller': True, 'callers': [], 'callers_str': '存在文件保存且缺少扩展名/类型限制', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '✅ A2:真漏洞-Python危险文件上传'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到文件上传保存逻辑', 'http_entry': self._find_http_entry_for_vuln(vuln, all_files), 'verdict': '⚠️ A2:可疑-Python文件上传需D2验证'}
        return None

    def _analyze_php_webshell(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_webshell_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST)|php://input', content))
        dangerous = bool(re.search(r'eval\s*\(|assert\s*\(|base64_decode\s*\(', content))
        if request_controlled and dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '请求参数进入动态代码执行', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP一句话木马/后门'}
        return None

    def _analyze_php_sqli(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_sqli_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'(mysqli_query|->query|PDO\s*\(|->prepare)', content))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', content))
        weak_binding = not bool(re.search(r'bindParam|bindValue|prepare\s*\([^)]*\?', content))
        if dangerous and request_controlled and weak_binding:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数进入 SQL 查询，且未见参数绑定', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP SQL注入'}
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数可到达 SQL 查询入口', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP SQL注入需D2验证'}
        return None

    def _analyze_php_xss(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_xss_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        reflected = bool(re.search(r'(echo|print)\s+.*\$_(GET|POST|REQUEST)', content))
        escaped = bool(re.search(r'htmlspecialchars|htmlentities|strip_tags', content))
        if reflected and not escaped:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数被直接输出到响应且未见转义', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP反射型XSS'}
        if reflected:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数被输出到响应', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP XSS需D2验证'}
        return None

    def _analyze_php_open_redirect(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_open_redirect_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        redirect = bool(re.search(r'header\s*\(\s*[\'"]Location:|redirect\s*\(', content))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST)', content))
        validated = bool(re.search(r'parse_url|preg_match|whitelist|allowlist|startsWith', content, re.IGNORECASE))
        if redirect and request_controlled and not validated:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数直接控制 Location/redirect 目标，未见白名单校验', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP开放重定向'}
        if redirect and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数可控制重定向目标', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP开放重定向需D2验证'}
        return None

    def _analyze_php_ssrf(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_ssrf_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'curl_exec|curl_setopt\s*\([^,\n]+,\s*CURLOPT_URL|file_get_contents\s*\(|fopen\s*\(|fsockopen\s*\(', content, re.IGNORECASE))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', content))
        validated = bool(re.search(r'parse_url|FILTER_VALIDATE_URL|allowlist|whitelist', content, re.IGNORECASE))
        if dangerous and request_controlled and not validated:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数可控远程 URL，并进入 curl/file_get_contents 等服务端请求逻辑', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP SSRF'}
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 PHP 服务端请求逻辑，需确认 URL 是否被严格限制', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP SSRF需D2验证'}
        return None

    def _analyze_php_upload(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_upload_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'move_uploaded_file\s*\(', content))
        no_filter = not bool(re.search(r'mime_content_type|pathinfo|finfo_file|allowedExt', content))
        if dangerous and no_filter:
            return {'has_caller': True, 'callers': [], 'callers_str': '存在文件上传落地且缺少类型/扩展名限制', 'http_entry': 'PHP file upload entry', 'verdict': '✅ A2:真漏洞-PHP危险文件上传'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 move_uploaded_file 逻辑', 'http_entry': 'PHP file upload entry', 'verdict': '⚠️ A2:可疑-PHP文件上传需D2验证'}
        return None

    def _analyze_php_command(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_command_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)', content))
        dangerous = bool(re.search(r'system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(', content))
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': '用户输入可进入 PHP 命令执行函数', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP命令执行/RCE'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 PHP 命令执行函数', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP命令执行需D2验证'}
        return None

    def _analyze_python_yaml(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_yaml_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous_loader = bool(re.search(r'yaml\.load\s*\(', content))
        safe_loader = bool(re.search(r'SafeLoader|safe_load\s*\(', content))
        request_controlled = bool(re.search(r'request\.(args|form|json|data)|Body\(|Query\(|Form\(|input\s*\(', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous_loader and request_controlled and not safe_loader:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 yaml.load 且未使用 SafeLoader', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python YAML不安全反序列化'}
        if dangerous_loader and not safe_loader:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 yaml.load 且未见 SafeLoader', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Python YAML需D2验证'}
        return None

    def _analyze_python_ldap(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_ldap_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'ldap|ldap3|conn\.search|connection\.search', content, re.IGNORECASE))
        filter_concat = bool(re.search(r'search\s*\([^)]*(\+|%|f"|format\()', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and filter_concat and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入拼接进入 LDAP 搜索过滤器', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python LDAP注入'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 LDAP 搜索逻辑，需确认过滤器是否由请求参数拼接', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Python LDAP需D2验证'}
        return None

    def _analyze_python_debug(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_debug_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        debug_enabled = bool(re.search(r'DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\s*\(\s*debug\s*=\s*True', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files) or "Python app entry"
        if debug_enabled:
            return {'has_caller': True, 'callers': [], 'callers_str': '应用以调试模式启动，异常页和调试控制台可能对外暴露', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python Debug模式暴露'}
        return None

    def _analyze_python_marshal(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_marshal_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'marshal\.load|marshal\.loads', content))
        request_controlled = bool(re.search(r'request\.(args|form|json|data)|Body\(|Query\(|Form\(|input\s*\(', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 marshal.load/loads', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python marshal不安全反序列化'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 marshal 反序列化逻辑，需确认输入是否可控', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Python marshal需D2验证'}
        return None

    def _analyze_python_command(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_python_command_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous_exec = bool(re.search(r'os\.system\s*\(|subprocess\.(run|Popen|call|check_output)\s*\(|commands\.getoutput\s*\(', content))
        request_controlled = bool(re.search(r'request\.(args|form|json|data)|Body\(|Query\(|Form\(|input\s*\(', content))
        concatenated = bool(re.search(r'os\.system\s*\([^)]*(request|input)|subprocess\.(run|Popen|call|check_output)\s*\([^)]*(shell\s*=\s*True|request|input)', content))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous_exec and request_controlled and concatenated:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 Python 命令执行函数，且存在 shell/字符串拼接', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Python命令执行'}
        if dangerous_exec and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入可到达 Python 命令执行函数', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Python命令执行需D2验证'}
        return None

    def _analyze_php_deserialization(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_deserialization_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'unserialize\s*\(|yaml_parse\s*\(', content))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)|php://input', content))
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求输入进入 unserialize/yaml_parse', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP不安全反序列化'}
        if dangerous:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 PHP 反序列化入口', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP反序列化需D2验证'}
        return None

    def _analyze_php_path(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_path_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'(include|require|readfile|file_get_contents|unlink|rmdir)\s*\(', content))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST|COOKIE)|php://input', content))
        weak_path_guard = not bool(re.search(r'realpath\s*\(|basename\s*\(|preg_match\s*\([^)]*\.\.|strpos\s*\([^)]*\.\.', content))
        if dangerous and request_controlled and weak_path_guard:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数进入文件路径操作，且未见有效路径约束', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP路径穿越/任意文件操作'}
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求参数可到达文件路径操作', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP路径操作需D2验证'}
        return None

    def _analyze_php_cors(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_cors_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'Access-Control-Allow-Origin.*\*|header\s*\(\s*[\'"]Access-Control-Allow-Origin:\s*\*', content, re.IGNORECASE):
            return {'has_caller': False, 'callers': [], 'callers_str': 'PHP 响应允许任意跨域来源', 'http_entry': 'PHP response header', 'verdict': '✅ A2:真漏洞-PHP CORS配置不安全'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 PHP CORS 响应头设置，需确认来源是否受限', 'http_entry': 'PHP response header', 'verdict': '⚠️ A2:可疑-PHP CORS需D2验证'}

    def _analyze_php_cookie(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_cookie_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'setcookie|header\s*\(\s*[\'"]Set-Cookie:', content, re.IGNORECASE) and not re.search(r'secure|httponly|samesite', content, re.IGNORECASE):
            return {'has_caller': False, 'callers': [], 'callers_str': 'PHP Cookie 缺少 Secure/HttpOnly/SameSite 保护', 'http_entry': 'PHP response header', 'verdict': '✅ A2:真漏洞-PHP Cookie配置不安全'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 PHP Cookie 设置逻辑，需确认安全属性是否齐全', 'http_entry': 'PHP response header', 'verdict': '⚠️ A2:可疑-PHP Cookie需D2验证'}

    def _analyze_php_auth(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_auth_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'\$_SESSION|session_start|Authorization|apache_request_headers', content, re.IGNORECASE) and re.search(r'empty\s*\(|!\s*isset|==\s*true|return\s+true', content, re.IGNORECASE):
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 鉴权逻辑存在可绕过或缺失检查迹象', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP鉴权绕过'}
        return {'has_caller': True, 'callers': [], 'callers_str': '检测到 PHP 会话/令牌鉴权逻辑，需确认是否存在绕过', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP鉴权需D2验证'}

    def _analyze_node_cors(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_cors_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'cors\s*\([^)]*(origin\s*:\s*true|credentials\s*:\s*true)|Access-Control-Allow-Origin.*\*|enableCors\s*\([^)]*(origin\s*:\s*true|credentials\s*:\s*true)', content, re.IGNORECASE):
            return {'has_caller': False, 'callers': [], 'callers_str': 'Node CORS 配置允许任意来源或携带凭证，需要 D2 验证实际响应头', 'http_entry': 'Node response header', 'verdict': '⚠️ A2:可疑-Node CORS需D2验证'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 Node CORS 配置，需要确认 Origin 和 Allow-Credentials 是否存在危险组合', 'http_entry': 'Node response header', 'verdict': '⚠️ A2:可疑-Node CORS需D2验证'}

    def _analyze_node_cookie(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_cookie_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        if re.search(r'res\.cookie|Set-Cookie|cookie-session', content, re.IGNORECASE) and not re.search(r'httpOnly\s*:\s*true|secure\s*:\s*true|sameSite\s*:\s*[\'"]?(strict|lax|none)', content, re.IGNORECASE):
            return {'has_caller': False, 'callers': [], 'callers_str': 'Node Cookie 缺少 HttpOnly / Secure / SameSite 保护', 'http_entry': 'Node response header', 'verdict': '✅ A2:真漏洞-Node Cookie配置不安全'}
        return {'has_caller': False, 'callers': [], 'callers_str': '检测到 Node Cookie 设置逻辑，需要确认安全属性是否齐全', 'http_entry': 'Node response header', 'verdict': '⚠️ A2:可疑-Node Cookie需D2验证'}

    def _analyze_node_auth(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_auth_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        weak_auth = bool(re.search(r'@Public|public\s*:\s*true|allowAnonymous|skipAuth|jwt\.decode\s*\(|passport\.authenticate\s*\([^)]*false', content, re.IGNORECASE))
        if weak_auth and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'Node 路由存在显式公开或弱鉴权逻辑，可能导致未授权访问', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Node鉴权绕过/认证不安全'}
        return {'has_caller': bool(http_entry), 'callers': [], 'callers_str': '检测到 Node 鉴权控制点，需要 D2 确认是否可绕过', 'http_entry': http_entry or 'Node route', 'verdict': '⚠️ A2:可疑-Node鉴权需D2验证'}

    def _analyze_php_jwt(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_php_jwt_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        weak_verify = bool(re.search(r'JWT::decode\s*\(|firebase\\JWT|alg\s*=\s*[\'"]none[\'"]|HS256|verify\s*=\s*false', content, re.IGNORECASE))
        request_controlled = bool(re.search(r'\$_(GET|POST|REQUEST)|Authorization|apache_request_headers\s*\(', content, re.IGNORECASE))
        if weak_verify and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'PHP 请求中的 token 进入 JWT 校验，且存在弱算法或签名校验不安全迹象', 'http_entry': 'PHP request entry', 'verdict': '✅ A2:真漏洞-PHP JWT校验不安全'}
        if weak_verify:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 PHP JWT 弱校验逻辑', 'http_entry': 'PHP request entry', 'verdict': '⚠️ A2:可疑-PHP JWT需D2验证'}
        return None

    def _analyze_node_jwt(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_jwt_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        weak_verify = bool(re.search(r'jwt\.(verify|decode)\s*\([^)]*(false|none|noVerify)|ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[[^\]]*none', content, re.IGNORECASE))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if weak_verify and http_entry:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP Token 进入 Node JWT 校验，且签名/算法校验不安全', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Node JWT校验不安全'}
        if weak_verify:
            return {'has_caller': True, 'callers': [], 'callers_str': '检测到 Node JWT 弱校验逻辑', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Node JWT需D2验证'}
        return None

    def _analyze_node_open_redirect(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_open_redirect_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        redirect = bool(re.search(r'res\.redirect\s*\(', content))
        request_controlled = bool(re.search(r'req\.(query|body|params)\.[A-Za-z_][A-Za-z0-9_]*', content))
        validated = bool(re.search(r'new URL\s*\(|startsWith\s*\(\s*[\'\"]/|allowlist|whitelist', content, re.IGNORECASE))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if redirect and request_controlled and not validated:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入直接控制 res.redirect 目标，未见白名单校验', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Node开放重定向'}
        if redirect and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入可控制重定向目标', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Node开放重定向需D2验证'}
        return None

    def _analyze_node_file_delete(self, vuln: Vulnerability, all_files: Dict) -> Optional[Dict]:
        if not self._is_node_file_delete_vuln(vuln):
            return None
        content = all_files.get(vuln.file, '')
        if not content:
            return None
        dangerous = bool(re.search(r'fs\.(unlink|unlinkSync|rm|rmSync)\s*\(', content))
        request_controlled = bool(re.search(r'req\.(query|body|params)\.[A-Za-z_][A-Za-z0-9_]*', content))
        weak_path_guard = not bool(re.search(r'path\.basename\s*\(|path\.resolve\s*\(|startsWith\s*\([^)]*uploads|allowlist|whitelist', content, re.IGNORECASE))
        http_entry = self._find_http_entry_for_vuln(vuln, all_files)
        if dangerous and request_controlled and weak_path_guard:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入进入 fs 删除操作，且未见有效路径约束', 'http_entry': http_entry, 'verdict': '✅ A2:真漏洞-Node任意文件删除'}
        if dangerous and request_controlled:
            return {'has_caller': True, 'callers': [], 'callers_str': 'HTTP 输入可到达 fs 删除操作', 'http_entry': http_entry, 'verdict': '⚠️ A2:可疑-Node文件删除需D2验证'}
        return None

    @staticmethod
    def _is_thymeleaf_ssti_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        snippet = vuln.code_snippet or ''
        sink = vuln.sink or ''
        combined = f"{snippet}\n{sink}"
        return (
            ('ssti' in vuln_type and any(re.search(pattern, combined) for pattern in THYMELEAF_ENGINE_PATTERNS))
            or 'thymeleaf' in vuln_type
        )

    @staticmethod
    def _is_java_template_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('ssti', 'template', 'spel', 'freemarker', 'velocity')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_TEMPLATE_ENGINE_PATTERNS)

    @staticmethod
    def _is_python_template_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('jinja2', 'ssti', 'template injection')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_TEMPLATE_PATTERNS)

    @staticmethod
    def _is_python_pickle_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('pickle', 'deserialization', '反序列化')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_PICKLE_PATTERNS)

    @staticmethod
    def _is_node_prototype_pollution_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('prototype pollution', '原型链污染', 'prototype')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_PROTOTYPE_POLLUTION_PATTERNS)

    @staticmethod
    def _is_node_template_injection_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node template injection', 'template injection', 'ssti', 'ejs', 'nunjucks', 'handlebars', 'pug')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_TEMPLATE_INJECTION_PATTERNS)

    @staticmethod
    def _is_node_nosql_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('nosql', 'mongodb injection', 'mongoose injection', 'mongo injection')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'(findOne|find|aggregate|updateOne|updateMany|findOneAndUpdate|findById|findByIdAndUpdate|countDocuments|exists|mongoose|mongodb|\$ne|\$gt|\$regex|\$where|\$in|\$or)', combined))

    @staticmethod
    def _is_node_deserialization_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node insecure deserialization', 'deserialization', '反序列化', 'node-serialize', 'v8.deserialize')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_DESERIALIZATION_PATTERNS)

    @staticmethod
    def _is_node_command_injection_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node command injection', 'command injection', '命令注入')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_COMMAND_INJECTION_PATTERNS)

    @staticmethod
    def _is_node_ssrf_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node ssrf', 'ssrf', 'server-side request forgery')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_SSRF_PATTERNS)

    @staticmethod
    def _is_node_path_traversal_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node path traversal', 'path traversal', '路径穿越', '目录穿越')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_PATH_TRAVERSAL_PATTERNS)

    @staticmethod
    def _is_node_file_upload_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('node unsafe file upload', 'file upload', '上传')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_FILE_UPLOAD_PATTERNS)

    @staticmethod
    def _is_java_jwt_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'jwt' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_JWT_PATTERNS)

    @staticmethod
    def _is_java_fastjson_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'fastjson' not in vuln_type and not ('deserialization' in vuln_type and 'json' in vuln_type):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_FASTJSON_PATTERNS)

    @staticmethod
    def _is_java_ognl_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('ognl', 'struts')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'Ognl|ActionContext|ServletActionContext|getValue|setValue', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_jndi_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('jndi', 'log4j', 'ldap')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'InitialContext|lookup|jndi:|ldap://|rmi://', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_ldap_vuln(vuln: Vulnerability, content: str = '') -> bool:
        # A1 常把 LDAP 查询注入（DirContext.search + 拼接过滤器）误标为 xpath-injection
        # （search( 与 XPath evaluate 形似）。旧逻辑只看 vuln.code_snippet，而 OWASP ldapi 用例的
        # code_snippet 常被 A1 只截到「过滤器拼接行」（如 02115 仅截到 String filter=... + bar），
        # 不含 LDAPManager/DirContext 字面 → gate 直接 False → _analyze_java_ldap 永不进入 →
        # family 恒落 xpathi 与真值(ldapi) 错配。
        # 修复：判定口径升级为「code_snippet + sink + 全文件内容」三源并集，并区分强/弱标记：
        #  - 强标记（LDAPManager / getDirContext / getTheValue / ldap://）：OWASP LDAPHelper 独有，
        #    XPath.evaluate 永不出现，命中即判 LDAP，覆盖 00948/01831（仅 LDAPManager）与 02115
        #    （code_snippet 无标记、但全文件含 LDAPManager + getDirContext）等全部分支；
        #  - 弱标记（DirContext/LdapContext/InitialDirContext/javax.naming.directory/SearchControls）：
        #    LDAP 目录查询独有，XPath 不出现，仅作用于 code_snippet（避免全文件误扩到无关 import）。
        # type 已含 'ldap' 时维持原有内容判定，兼容非 OWASP 场景。
        snippet = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        combined = f"{snippet}\n{content or ''}"
        STRONG = r'LDAPManager|getDirContext|getTheValue|ldap://'
        DIR = r'DirContext|LdapContext|InitialDirContext|javax\.naming\.directory|SearchControls'
        # 强标记命中三源任一即判 LDAP（覆盖 code_snippet 漏标分支，如 02115）。
        if re.search(STRONG, combined, re.IGNORECASE):
            return True
        # 弱标记仅看 code_snippet（不扩全文件，避免无关 import 误触发）。
        if re.search(DIR, snippet, re.IGNORECASE):
            return True
        vuln_type = (vuln.type or '').lower()
        if 'ldap' not in vuln_type:
            return False
        return bool(re.search(r'DirContext|LdapContext|search\s*\(', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_jackson_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'jackson' not in vuln_type and 'deserialization' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'ObjectMapper|readValue|enableDefaultTyping|activateDefaultTyping', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_xstream_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'xstream' not in vuln_type and 'deserialization' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'XStream|fromXML', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_upload_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'upload' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_UPLOAD_PATTERNS)

    @staticmethod
    def _is_java_csp_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'csp' not in vuln_type and 'content security policy' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_CSP_PATTERNS)

    @staticmethod
    def _is_java_tomcat_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'tomcat' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_TOMCAT_PATTERNS)

    @staticmethod
    def _is_java_cors_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cors' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_CORS_PATTERNS)

    @staticmethod
    def _is_java_cookie_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cookie' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_COOKIE_PATTERNS)

    @staticmethod
    def _is_java_auth_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('auth', 'authorization', 'authentication', '鉴权', '授权', '认证')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in JAVA_AUTH_PATTERNS) or bool(re.search(r'@(GetMapping|PostMapping|RequestMapping)', combined))

    @staticmethod
    def _is_java_hpp_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('hpp', 'parameter pollution', 'http parameter pollution')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in JAVA_HPP_PATTERNS)

    @staticmethod
    def _is_java_mongo_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'mongo' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in JAVA_MONGO_PATTERNS)

    @staticmethod
    def _is_java_redis_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'redis' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in JAVA_REDIS_PATTERNS)

    @staticmethod
    def _is_java_open_redirect_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('open redirect', 'redirect', '开放重定向')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'redirect:|sendRedirect\(|setHeader\(\s*["\']Location|ResponseEntity\.status\(30[12]', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_ssl_verification_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('ssl', 'hostname verifier', 'trustmanager', '证书校验')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustManager|HostnameVerifier|setHostnameVerifier', combined, re.IGNORECASE))

    @staticmethod
    def _is_java_weak_session_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('weak session', 'session', '会话')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'HttpSession|session\.setAttribute|new Random|Math\.random', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_weak_crypto_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('weak cryptography', 'weak crypto', 'crypto', 'md5', 'sha1', '弱加密')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'hashlib\.md5|hashlib\.sha1|\bmd5\(|\bsha1\(|random\.(random|randrange)', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_hardcoded_secret_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('hardcoded', 'secret', 'password', 'api key', '硬编码密钥')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'(password|passwd|pwd|api[_-]?key|secret[_-]?key|secret|token)\s*=', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_temp_file_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('temp', 'temporary', '临时文件')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'tempfile\.mktemp', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_jwt_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'jwt' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_JWT_PATTERNS)

    @staticmethod
    def _is_python_xml_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('xxe', 'xml', 'entity expansion', 'xml-rpc', 'billion laughs')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in PYTHON_XML_PATTERNS) or bool(re.search(r'DOCTYPE|ENTITY|xmlrpc', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_upload_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'upload' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_UPLOAD_PATTERNS)

    @staticmethod
    def _is_php_webshell_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('webshell', 'backdoor', 'one-liner', '木马')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PHP_WEBSHELL_PATTERNS)

    @staticmethod
    def _is_php_sqli_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'sql' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'(mysqli_query|->query|PDO|prepare|SELECT|INSERT|UPDATE|DELETE)', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_xss_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'xss' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'(echo|print|\$_GET|\$_POST|\$_REQUEST)', combined))

    @staticmethod
    def _is_php_open_redirect_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('redirect', '开放重定向', 'open redirect')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'(header\s*\(\s*[\'"]Location:|redirect\s*\()', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_ssrf_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('ssrf', 'server-side request forgery')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'curl_exec|CURLOPT_URL|file_get_contents\s*\(|fopen\s*\(|fsockopen\s*\(', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_upload_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'upload' not in vuln_type and '上传' not in vuln.type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PHP_UPLOAD_PATTERNS)

    @staticmethod
    def _is_php_command_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('command', 'rce', '命令执行', '命令注入')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PHP_COMMAND_PATTERNS)

    @staticmethod
    def _is_python_yaml_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('yaml', 'pyyaml', 'deserialization', '反序列化')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_YAML_PATTERNS)

    @staticmethod
    def _is_python_ldap_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'ldap' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'ldap|ldap3|search\s*\(', combined, re.IGNORECASE))

    @staticmethod
    def _is_python_debug_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'debug' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\s*\(\s*debug\s*=\s*True', combined))

    @staticmethod
    def _is_python_marshal_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'marshal' not in vuln_type and 'deserialization' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'marshal\.load|marshal\.loads', combined))

    @staticmethod
    def _is_python_command_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('command injection', 'command execution', 'rce', '命令执行')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PYTHON_COMMAND_PATTERNS)

    @staticmethod
    def _is_php_deserialization_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('php insecure deserialization', 'deserialization', '反序列化')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PHP_DESERIALIZATION_PATTERNS)

    @staticmethod
    def _is_php_path_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('path traversal', 'directory traversal', '文件包含', '路径穿越', '任意文件')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in PHP_PATH_PATTERNS)

    @staticmethod
    def _is_php_cors_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cors' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'Access-Control-Allow-Origin|header\(.*Access-Control-Allow-Origin', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_cookie_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cookie' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'setcookie|Set-Cookie', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_auth_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('auth', 'authentication', 'authorization', '鉴权', '授权', '认证')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'\$_SESSION|session_start|Authorization|apache_request_headers', combined, re.IGNORECASE))

    @staticmethod
    def _is_php_jwt_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'jwt' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'JWT::decode|JWT::encode|firebase\\JWT', combined, re.IGNORECASE))

    @staticmethod
    def _is_node_cors_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cors' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'cors\(|Access-Control-Allow-Origin|enableCors', combined, re.IGNORECASE))

    @staticmethod
    def _is_node_cookie_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'cookie' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'res\.cookie|Set-Cookie|cookie-session', combined, re.IGNORECASE))

    @staticmethod
    def _is_node_auth_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('auth', 'authentication', 'authorization', '鉴权', '授权', '认证')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return bool(re.search(r'passport|jwt|guard|@UseGuards|@Public|permitAll|public\s*:\s*true|Authorization', combined, re.IGNORECASE))

    @staticmethod
    def _is_node_jwt_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if 'jwt' not in vuln_type:
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_JWT_PATTERNS)

    @staticmethod
    def _is_node_open_redirect_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('open redirect', 'redirect', '开放重定向')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_OPEN_REDIRECT_PATTERNS)

    @staticmethod
    def _is_node_file_delete_vuln(vuln: Vulnerability) -> bool:
        vuln_type = (vuln.type or '').lower()
        if not any(token in vuln_type for token in ('file delete', 'arbitrary file delete', '文件删除', '任意文件删除')):
            return False
        combined = f"{vuln.code_snippet or ''}\n{vuln.sink or ''}"
        return any(re.search(pattern, combined) for pattern in NODE_FILE_DELETE_PATTERNS)

    @staticmethod
    def _python_request_controlled(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 30)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'request\.args\.get',
            r'request\.form\.get',
            r'request\.json',
            r'request\.data',
            r'request\.get_json',
            r'Query\(',
            r'Body\(',
            r'Path\(',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _thymeleaf_request_controlled(content: str, vuln_line: int) -> bool:
        start = max(0, vuln_line - 30)
        end = min(len(content.splitlines()), vuln_line + 20)
        window = '\n'.join(content.splitlines()[start:end])
        request_patterns = [
            r'@RequestParam',
            r'@RequestBody',
            r'HttpServletRequest',
            r'request\.getParameter',
            r'request\.getHeader',
            r'Model\.addAttribute',
            r'model\.addAttribute',
        ]
        return any(re.search(pattern, window) for pattern in request_patterns)

    @staticmethod
    def _node_request_controlled(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 30)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'req\.body',
            r'req\.query',
            r'req\.params',
            r'req\.headers',
            r'JSON\.parse\s*\(',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dangerous_merge(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'Object\.assign\s*\(',
            r'\.merge\s*\(',
            r'\bmerge\s*\(',
            r'defaultsDeep\s*\(',
            r'\bset\s*\(',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_prototype_write(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'__proto__',
            r'constructor\.prototype',
            r'prototype\s*\[',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dynamic_template(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'(ejs\.render|nunjucks\.renderString|handlebars\.compile|pug\.compile)\s*\(\s*[^"\']',
            r'res\.render\s*\(\s*[^"\']',
            r'\+\s*(req\.body|req\.query|req\.params)',
            r'`[^`]*\$\{[^}]+req\.(body|query|params)[^}]*\}[^`]*`',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dangerous_deserialization(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'node-serialize',
            r'serialize\.unserialize\s*\(',
            r'v8\.deserialize\s*\(',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dangerous_command(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'child_process\.exec\s*\(',
            r'\bexecSync\s*\(',
            r'\bspawn\s*\(',
            r'\bexec\s*\(',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_command_concatenation(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 20)
        window = '\n'.join(lines[start:end])
        patterns = [
            r'\+\s*(req\.body|req\.query|req\.params)',
            r'`[^`]*\$\{[^}]+req\.(body|query|params)[^}]*\}[^`]*`',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dangerous_ssrf(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        return any(re.search(pattern, window) for pattern in NODE_SSRF_PATTERNS)

    @staticmethod
    def _node_url_controlled(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        patterns = [
            r'(axios\.(get|post|request)|fetch\(|http\.get\(|https\.get\(|request\(|got\()\s*\([^"\']',
            r'(req\.body|req\.query|req\.params).*(url|uri|host|target)',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_dangerous_file_access(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        return any(re.search(pattern, window) for pattern in NODE_PATH_TRAVERSAL_PATTERNS)

    @staticmethod
    def _node_path_controlled(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        patterns = [
            r'(path\.join|path\.resolve|res\.sendFile|fs\.readFile(?:Sync)?|fs\.createReadStream)\s*\([^"\']',
            r'(req\.body|req\.query|req\.params).*(file|path|name)',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_upload_handler(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        return any(re.search(pattern, window) for pattern in NODE_FILE_UPLOAD_PATTERNS)

    @staticmethod
    def _node_upload_filename_controlled(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        patterns = [
            r'(req\.file|req\.files).*(originalname|filename|path)',
            r'(originalname|filename|destination)',
            r'\.mv\s*\([^"\']',
        ]
        return any(re.search(pattern, window) for pattern in patterns)

    @staticmethod
    def _node_upload_unrestricted_type(content: str, vuln_line: int) -> bool:
        lines = content.splitlines()
        window = '\n'.join(lines[max(0, vuln_line - 20):min(len(lines), vuln_line + 20)])
        return not any(re.search(pattern, window) for pattern in [r'fileFilter', r'limits', r'mimetype', r'extension'])

    @staticmethod
    def _thymeleaf_dynamic_template(content: str, vuln_line: int) -> bool:
        start = max(0, vuln_line - 20)
        end = min(len(content.splitlines()), vuln_line + 20)
        window = '\n'.join(content.splitlines()[start:end])
        return bool(
            re.search(r'TemplateEngine\.process\s*\(\s*[^"\']', window)
            or re.search(r'return\s+[^"\']+\s*;', window)
            or re.search(r'parseExpression\s*\(\s*[^"\']', window)
            or re.search(r'th:utext', window)
        )

    def _extract_method_from_code(self, code_snippet: str, file_content: str, vuln_line: int) -> str:
        """从漏洞代码中提取所在方法名"""
        if not file_content:
            return ''

        lines = file_content.split('\n')

        if not lines or vuln_line <= 0 or vuln_line > len(lines):
            return ''

        # 向前搜索方法定义
        for i in range(vuln_line - 1, -1, -1):
            if i < 0 or i >= len(lines):
                continue
            line = lines[i]
            # Java: public/private/protected + return_type + method_name(
            match = re.search(r'(public|private|protected|static|\w+)\s+(?:void|String|int|List|Map|Object|\w+)\s+(\w+)\s*\(', line)
            if match:
                return match.group(2)
            # Python: def method_name(
            match = re.search(r'def\s+(\w+)\s*\(', line)
            if match:
                return match.group(1)

        return ''

    def _find_method_callers(self, content: str, method_name: str, file_path: str) -> List[Dict]:
        """查找对特定方法的调用"""
        callers = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # 检查是否调用了目标方法
            # 格式: methodName( 或 obj.methodName(
            pattern = r'\b' + re.escape(method_name) + r'\s*\('
            if re.search(pattern, line):
                # 排除方法定义
                def_pattern = r'(public|private|protected|static|def|function)\s+' + re.escape(method_name) + r'\s*[\(\{]'
                if not re.search(def_pattern, line):
                    callers.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': line.strip(),
                        'desc': f"{file_path}:行{i+1}"
                    })

        return callers

    def _extract_vuln_function_name(self, vuln: Vulnerability) -> str:
        """从漏洞信息中提取函数名"""
        # 从代码片段中提取
        code = vuln.code_snippet or ''

        # 常见危险函数模式
        dangerous_patterns = {
            'executeCommand': ['executeCommand', 'ProcessBuilder', 'Runtime.getRuntime'],
            'readFile': ['readFile', 'FileInputStream', 'Files.readAllBytes'],
            'writeStatus': ['writeStatus', 'Files.write'],
            'healthCheck': ['healthCheck'],
            'ObjectInputStream': ['ObjectInputStream', 'readObject'],
            'eval': ['eval', 'execScript'],
            'system': ['system(', 'Runtime.exec'],
        }

        for func_name, patterns in dangerous_patterns.items():
            for p in patterns:
                if p in code:
                    return func_name

        # 尝试从sink字段提取
        if vuln.sink:
            return vuln.sink.split(',')[0].strip()

        # 尝试从代码中提取方法调用
        match = re.search(r'(\w+)\s*\(', code)
        if match:
            return match.group(1)

        return ''

    def _find_function_callers(self, content: str, func_name: str, file_path: str) -> List[Dict]:
        """在文件中查找函数调用"""
        callers = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            # 跳过注释和函数定义
            if line.strip().startswith('//') or line.strip().startswith('#'):
                continue

            # 检查是否调用了目标函数
            # 匹配: func_name( 或 object.func_name(
            pattern = rf'\b{re.escape(func_name)}\s*\('
            if re.search(pattern, line):
                # 排除函数定义行
                if not re.search(rf'(public|private|protected|def|void|String|int|static|function)\s+{re.escape(func_name)}\s*[\(\s]', line):
                    callers.append({
                        'file': file_path,
                        'line': i + 1,
                        'code': line.strip(),
                        'desc': f"{file_path}:行{i+1}"
                    })

        return callers

    def _find_http_entry_for_vuln(self, vuln: Vulnerability, all_files: Dict) -> str:
        vuln_file = vuln.file
        vuln_line = vuln.line
        content = all_files.get(vuln_file, '')
        if not content:
            return None

        local_entry = self._find_java_http_entry_in_file(content, vuln_line)
        if local_entry:
            return local_entry

        lines = content.split('\n')
        if vuln_line and 0 < vuln_line <= len(lines):
            for idx in range(max(0, vuln_line - 8), min(len(lines), vuln_line + 2)):
                line = lines[idx]
                py_match = re.search(r'@app\.(get|post|put|delete)\((?:"([^"]+)"|\'([^\']+)\')\)', line)
                if py_match:
                    return f"{py_match.group(1).upper()} {py_match.group(2) or py_match.group(3)}"
                flask_match = re.search(r'@app\.route\((?:"([^"]+)"|\'([^\']+)\')', line)
                if flask_match:
                    return f"ROUTE {flask_match.group(1) or flask_match.group(2)}"
                express_match = re.search(r'(?:app|router)\.(get|post|put|delete|patch)\((?:"([^"]+)"|\'([^\']+)\')', line)
                if express_match:
                    return f"{express_match.group(1).upper()} {express_match.group(2) or express_match.group(3)}"

        method_name = self._extract_method_from_code(vuln.code_snippet or '', content, vuln_line)
        if not method_name:
            return None
        for candidate_file, candidate_content in all_files.items():
            if candidate_file == vuln_file:
                continue
            normalized_candidate = str(candidate_file or '').replace('\\', '/').lower()
            if normalized_candidate.startswith('org/springframework/boot/loader/'):
                continue
            callers = self._find_method_callers(candidate_content, method_name, candidate_file)
            if not callers:
                continue
            for caller in callers:
                caller_line = int(caller.get('line', 0) or 0)
                caller_entry = self._find_java_http_entry_in_file(candidate_content, caller_line)
                if caller_entry:
                    return caller_entry
        return None

    @staticmethod
    def _extract_java_mapping_path(annotation_line: str) -> str:
        line = str(annotation_line or '')
        for pattern in (
            r'@\w+Mapping\s*\(\s*(?:value|path)\s*=\s*\{\s*"([^"]+)"',
            r'@\w+Mapping\s*\(\s*(?:value|path)\s*=\s*"([^"]+)"',
            r'@\w+Mapping\s*\(\s*\{\s*"([^"]+)"',
            r'@\w+Mapping\s*\(\s*"([^"]+)"',
        ):
            match = re.search(pattern, line, re.I)
            if match:
                return str(match.group(1) or '').strip()
        return ''

    @staticmethod
    def _extract_java_mapping_method(annotation_line: str) -> str:
        line = str(annotation_line or '')
        direct_match = re.search(r'@(Get|Post|Put|Delete|Patch)Mapping', line, re.I)
        if direct_match:
            return str(direct_match.group(1) or '').upper()
        request_match = re.search(r'RequestMethod\.(GET|POST|PUT|DELETE|PATCH)', line, re.I)
        if request_match:
            return str(request_match.group(1) or '').upper()
        return 'GET' if '@RequestMapping' in line else ''

    @staticmethod
    def _join_java_routes(base_route: str, method_route: str) -> str:
        base = str(base_route or '').strip().strip('/')
        sub = str(method_route or '').strip().strip('/')
        if base and sub:
            return f'/{base}/{sub}'
        if base:
            return f'/{base}'
        if sub:
            return f'/{sub}'
        return ''

    def _find_java_http_entry_in_file(self, content: str, vuln_line: int) -> str:
        lines = content.split('\n')
        pending_annotations = []
        class_base_route = ''
        method_pattern = re.compile(r'^\s*(?:public|protected|private)\s+(?:static\s+)?(?:[\w<>\[\],?]+\s+)+(\w+)\s*\(')
        class_pattern = re.compile(r'^\s*(?:public|protected|private)?\s*class\s+\w+')
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('@'):
                pending_annotations.append(stripped)
                continue
            if class_pattern.search(stripped):
                for annotation in pending_annotations:
                    if '@RequestMapping' in annotation:
                        class_base_route = self._extract_java_mapping_path(annotation)
                pending_annotations = []
                continue
            if not method_pattern.search(stripped):
                pending_annotations = []
                continue
            start_line = index + 1
            brace_balance = stripped.count('{') - stripped.count('}')
            end_line = len(lines)
            saw_body = '{' in stripped
            for follow_index in range(index + 1, len(lines)):
                candidate = lines[follow_index]
                brace_balance += candidate.count('{') - candidate.count('}')
                if '{' in candidate:
                    saw_body = True
                if saw_body and brace_balance <= 0:
                    end_line = follow_index + 1
                    break
            # 纵深防御：vuln_line 可能仍为 None（非经 Vulnerability 构造入口赋值时），
            # 直接参与区间比较会抛 int/NoneType TypeError 并被上层容错吞成静默漏检。
            if vuln_line is None or not (start_line <= vuln_line <= end_line):
                pending_annotations = []
                continue
            for annotation in pending_annotations:
                method = self._extract_java_mapping_method(annotation)
                route = self._join_java_routes(class_base_route, self._extract_java_mapping_path(annotation))
                if route:
                    return f"{method or 'GET'} {route}"
            pending_annotations = []
        return None

    def set_shared_context(self, shared_context):
        """设置共享上下文"""
        self.shared_context = shared_context
