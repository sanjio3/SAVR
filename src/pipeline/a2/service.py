import logging
import os
import re
from collections import defaultdict
from concurrent.futures import as_completed
from typing import Any, Dict, List, Optional

from src.core.capability_judge import capability_family_of

from src.agents.a2_agent import A2Agent
from src.core.models import ScanResult
from src.core.model_gateway import _DEFAULT_COST_PER_1K, _PROVIDER_COST_PER_1K, estimate_tokens
from src.core.path_norm import match_path_key
from src.pipeline.a2.manifest import A2_MANIFEST
from src.pipeline.stage_contract import StageService

logger = logging.getLogger(__name__)

# Supported scan modes (see G2 / ). ``filter_first`` keeps the historical
# behaviour (rule pre-filter then AI deep scan); ``pure_ai`` sends every file to
# the AI without pre-filtering; ``hybrid`` always keeps files under key
# directories (pure_ai treatment) and filters the remainder.
SCAN_MODE_FILTER_FIRST = "filter_first"
SCAN_MODE_PURE_AI = "pure_ai"
SCAN_MODE_HYBRID = "hybrid"
VALID_SCAN_MODES = (SCAN_MODE_FILTER_FIRST, SCAN_MODE_PURE_AI, SCAN_MODE_HYBRID)

# Directories treated as "always deep scan" in hybrid mode.
_KEY_DIR_TOKENS = (
    "/controller/", "/controllers/", "/route/", "/routes/", "/endpoint",
    "/api/", "/handler", "/webhook", "/auth",
)

_SINK_PATTERN = re.compile(
    r"eval\s*\(|assert\s*\(|unserialize\s*\(|shell_exec\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|"
    r"proc_open\s*\(|curl_exec\s*\(|file_get_contents\s*\(|move_uploaded_file\s*\(|"
    r"simplexml_load_string\s*\(|DOMDocument|parseExpression\s*\(|SpelExpressionParser|"
    r"Runtime\.getRuntime\(\)\.exec|subprocess\.(?:run|Popen|call)|os\.system|pickle\.loads?|"
    r"render_template_string|jinja2\.Template|requests\.(?:get|post)|axios\.|fetch\s*\(",
    re.I,
)
_SOURCE_PATTERN = re.compile(
    r"\$_GET|\$_POST|\$_REQUEST|\$_FILES|request\.(?:args|form|json|values|files)|"
    r"c\.req\.(?:query|param|header|text|json)|@RequestParam|@PathVariable|@RequestBody|"
    r"req\.(?:query|params|body|headers|cookies)",
    re.I,
)

# 附带修正：非源码文件不进入 A2 LLM 扫描清单（所有 scan_mode 一视同仁）。
# 二进制 + 工具链产物」，保留 .yml/.html 模板/.xml 映射/.properties —— docker-compose.yml
# 实测产出 3 条「基础设施层-安全配置」finding，.html 是 SSTI 面，一刀切会造成漏检回归。
A2_NON_SOURCE_EXTS = (
    ".md", ".csv", ".jar", ".class", ".log", ".iml", ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
)
# 构建/依赖清单文件名（依赖风险已由 SCA 阶段覆盖，A2 再扫一次纯属浪费预算）
A2_NON_SOURCE_NAMES = (
    "pom.xml", "build.gradle", "settings.gradle", "gradlew",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
)
# 工具链产物目录（CodeQL DB 等，非应用源码）
A2_NON_SOURCE_PATH_TOKENS = ("/.codeql-db/", "/target/", "/build/", "/node_modules/", "/.git/")


def _is_non_source_file(file_info: Dict) -> bool:
    rel_path = str(file_info.get("rel_path", "") or "").replace("\\", "/").lower()
    if not rel_path:
        return False
    name = rel_path.rsplit("/", 1)[-1]
    if name in A2_NON_SOURCE_NAMES:
        return True
    if any(tok in ("/" + rel_path) for tok in A2_NON_SOURCE_PATH_TOKENS):
        return True
    return any(rel_path.endswith(ext) for ext in A2_NON_SOURCE_EXTS)


class A2PipelineService(StageService):
    stage_name = "a2"

    def __init__(self, config: Optional[Dict] = None, provider: str = "qwen"):
        self.config = config or {}
        self.provider = provider
        self.scan_mode = self._normalize_mode(self.config.get("scan_mode"))
        super().__init__(manifest=A2_MANIFEST, factory=lambda: A2Agent(self.config, self.provider))

    def scan_files(self, files: List[Dict], scan_mode: Optional[str] = None, a1_evidence_index: Optional[Dict] = None, feedback: Optional[List[Dict]] = None, discovered_routes: Optional[List[Dict[str, Any]]] = None, on_progress: Optional[Any] = None) -> List[ScanResult]:
        mode = self._normalize_mode(scan_mode) if scan_mode is not None else self.scan_mode
        files = self._select_focus_files(files, scan_mode=mode)
        all_files = {
            file_info.get("rel_path", ""): file_info.get("content", "")
            for file_info in files
            if file_info.get("rel_path") and file_info.get("content")
        }
        # 把 A1 调用链证据索引拆成 per-file 证据，注入每个文件的 LLM 扫描 prompt（前置，
        # 而非扫描后富集）。索引结构见 benchmark_cli._build_a1_evidence_index -> {"by_file": {...}, "aggregate": {...}}
        by_file = (a1_evidence_index or {}).get("by_file", {}) or {}
        aggregate = (a1_evidence_index or {}).get("aggregate", {}) or {}
        agent = self.create()
        # §并行化：逐文件 scan_file 原本串行（每个文件一次 LLM 语义分析，是 A2 最重环节）。
        # 改为有界线程池并发：每线程独立 agent 实例（线程局部，避免共享 self.project_path /
        # self.client 的并发竞争），Semaphore 挡 Deepseek 网关 429 限流。结果按文件顺序收集，
        # 最终由主 agent 串行 canonicalize（保持确定性，报告顺序稳定）。
        import threading as _a2_threading
        from concurrent.futures import ThreadPoolExecutor as _A2TPE
        _a2_tls = _a2_threading.local()
        # §R4可观测性：收集各线程 agent 引用，扫描后汇总单文件失败数。
        # A2 内部 except 吞掉，任务照样 completed，A2 产出静默归零却无人发现。
        _a2_agents = []
        _a2_agents_lock = _a2_threading.Lock()
        def _a2_agent():
            if not hasattr(_a2_tls, 'agent'):
                _a2_tls.agent = self.create()
                with _a2_agents_lock:
                    _a2_agents.append(_a2_tls.agent)
            return _a2_tls.agent
        _a2_cfg = (self.config.get('agents', {}) or {})
        _a2_max_workers = int((_a2_cfg.get('a2', {}) or {}).get('max_workers', 12) or 12)
        _a2_llm_conc = int((_a2_cfg.get('a2', {}) or {}).get('llm_concurrency', 8) or 8)
        _a2_sem = _a2_threading.Semaphore(_a2_llm_conc)
        def _scan_one(file_info):
            with _a2_sem:
                # §路径归一修复：A1 证据索引的 key 是 A1 侧路径形态（绝对路径），
                # 而这里拿到的是 A2 侧 rel_path（相对路径），直接 .get 永远 miss，
                # per-file 的 A1 入口/source/sink 证据实际上从未喂进 LLM，只用了 aggregate 兜底。
                # match_path_key 先精确、再尾部匹配，抹平 绝对 vs 相对 的差异。
                _ev = match_path_key(file_info.get("rel_path", ""), by_file, aggregate)
                return _a2_agent().scan_file(
                    file_info,
                    all_files,
                    a1_evidence=_ev,
                    feedback=feedback,
                )
        _n = len(files)
        if _n == 0:
            results = []
        else:
            # on_progress(done, total) 发心跳，使前端在 A2 长耗时（本轮 33.4 分钟）期间能看到
            # 真实文件级进度，不再把 running 误判为卡死。顺序由 canonicalize 重新对齐，结果稳定。
            # on_progress 默认 None（已有调用方不传），且调用一律吞异常，绝不因心跳失败中断扫描。
            results = [None] * _n
            _done = 0
            with _A2TPE(max_workers=min(_n, _a2_max_workers)) as _ex:
                _futs = {_ex.submit(_scan_one, f): i for i, f in enumerate(files)}
                for _fut in as_completed(_futs):
                    _idx = _futs[_fut]
                    results[_idx] = _fut.result()
                    _done += 1
                    if on_progress is not None:
                        try:
                            on_progress(_done, _n)
                        except Exception:
                            pass

        # §R4健康检查：A2 单文件分析失败率。全部/大面积失败说明存在系统性故障
        # （prompt 模板渲染、LLM 客户端、解析契约），此时 A2 产出不可信，必须显式告警，
        # 不能像 task 9 那样静默归零后仍报 completed。
        _a2_err = sum(int(getattr(a, "_a2_error_count", 0) or 0) for a in _a2_agents)
        if _a2_err:
            _a2_ratio = _a2_err / _n
            logger.error(
                "[A2] 单文件语义分析失败 %d/%d（%.0f%%）", _a2_err, _n, _a2_ratio * 100
            )
            if _a2_ratio >= 0.5:
                logger.error(
                    "[A2] 失败率 >=50%%，判定为系统性故障：本次 A2 产出不可信。"
                    "常见原因为提示词模板含未转义花括号（如路由示例 /order/{id}）"
                    "或 LLM 客户端不可用，请检查 A2 日志堆栈。"
                )
        elif files:
            logger.info("[A2] 单文件语义分析全部成功（%d/%d）", _n, _n)
        # F2：把 entry_discovery 的 discovered_routes 透传给 A2 产出层，使垂直/跨模块越权族在
        # _build_exploit_spec 主路径即绑定真实管理路由（SAST ground truth），而非落到幻觉端点。
        return agent.canonicalize_scan_results(results, discovered_routes=discovered_routes)

    # ----  A2 吸收 A2.1（PoC 生成 / TriggerSpec 投影）；review 环节已删除，由 I2 LLM 裁决器接管 ----

    @staticmethod
    def plan_pocs(results: List[ScanResult], llm_client=None, a1_evidence_index: Optional[Dict] = None, code_root: Optional[str] = None, code_index: Optional[Dict] = None, on_progress: Optional[Any] = None) -> List[ScanResult]:
        """A2 的 PoC 猜测 / TriggerSpec 投影子职责（吸收原 A2ContractPlanner，不再独立编号）。

        把 canonical finding 补全为可执行 exploit_spec（entry.route / parameter_name /
        payload / success_signal / expected_outcomes），并给出 a21_selected 筛选结果，
        供 D2 校验器或 DAST 触发使用。

        POC 生成必须使用 LLM——``llm_client`` 为 A2 语义分析共用的 LLM 客户端
        （与 A2SemanticAgent 同 provider），由调用方传入（run_benchmark 经 run_a2_scan
        取回）；为 None 时 A2ContractPlanner 自动回退规则式（降级，不阻断流水线）。
        ``a1_evidence_index`` 把 A1 调用链证据一并喂给 LLM POC 生成（per-file + aggregate）。
        ``code_root`` / ``code_index`` 供 RAG 检索增强（跨文件切片注入 LLM）+ 解析入口回填。
        """
        from src.agents.a2_contract_planner import A2ContractPlanner

        return A2ContractPlanner(llm_client=llm_client).plan_scan_results(
            results, a1_evidence_index, code_root=code_root, code_index=code_index,
            on_progress=on_progress,
        )

    def build_llm_client(self):
        """构造 A2 语义分析共用的 LLM 客户端（与 A2SemanticAgent 同 provider），供 POC 生成复用。"""
        try:
            agent = self.create()
            return getattr(agent, "client", None)
        except Exception as _e:
            logger.warning("[A2PipelineService] 构造 LLM 客户端失败，POC 回退规则式：%s", _e)
            return None

    @staticmethod
    def _normalize_mode(scan_mode: Optional[str]) -> str:
        mode = str(scan_mode or "").strip().lower()
        return mode if mode in VALID_SCAN_MODES else SCAN_MODE_FILTER_FIRST

    @staticmethod
    def _is_key_dir(file_info: Dict) -> bool:
        lowered_path = str(file_info.get("rel_path", "") or "").replace("\\", "/").lower()
        return any(token in lowered_path for token in _KEY_DIR_TOKENS)

    @staticmethod
    def _score_file(file_info: Dict) -> int:
        rel_path = str(file_info.get("rel_path", "") or "")
        lowered_path = rel_path.replace("\\", "/").lower()
        content = str(file_info.get("content", "") or "")
        lowered_content = content.lower()
        total = 0
        if any(token in lowered_path for token in ("/controller/", "/controllers/", "/route/", "/routes/", "/endpoint", "/api/", "/handler", "/service", "/webhook")):
            total += 80
        if any(token in lowered_path for token in ("controller", "route", "endpoint", "api", "handler", "service", "webhook")):
            total += 40
        if any(token in lowered_path for token in ("dockerfile", "entrypoint", "startup", "compose", "grafana", "influx")):
            total += 45
        if _SINK_PATTERN.search(content):
            total += 120
        if _SOURCE_PATTERN.search(content):
            total += 90
        if any(token in lowered_content for token in ("register_rest_route", "@requestmapping", "@getmapping", "@postmapping", "app.get(", "app.post(", "router.get(", "router.post(")):
            total += 100
        if any(token in lowered_content for token in ("curl --user", "admin_password", "grafana", "/api/users/1", "entrypoint", "token ", "login with", "viewer permission")):
            total += 80
        if any(token in lowered_content for token in ("login", "auth", "token", "session", "cookie", "jwt", "owner", "tenant", "user_id", "entry_id", "resource_id")):
            total += 30
        return total

    @classmethod
    def _filter_first(cls, files: List[Dict], max_files: int) -> List[Dict]:
        """遗留全局 top-N（族无关通用分排序）。env SAST_AI_A2_FAMILY_QUOTA=0 时回退到此。"""
        if max_files <= 0:
            return []
        if len(files) <= max_files:
            return files
        scored = [(cls._score_file(file_info), idx, file_info) for idx, file_info in enumerate(files)]
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[2] for item in scored[:max_files]]

    @classmethod
    def _resolve_max_files(cls, total_files: int, explicit: Optional[int] = None) -> int:
        """max_files 解析：显式参数 > env SAST_AI_A2_MAX_FILES > 历史默认 240。

        env 取值：
          - 整数：直接作为预算；
          - "auto"：随源文件数缩放 = min(total, max(240, total//10))（全量测试用）；
          - 空/其它：240（与历史行为一致，不改默认）。
        """
        if explicit is not None and explicit > 0:
            return explicit
        env = (os.environ.get("SAST_AI_A2_MAX_FILES") or "").strip().lower()
        if env == "auto" and total_files > 0:
            return min(total_files, max(240, total_files // 10))
        if env.isdigit() and int(env) > 0:
            return int(env)
        return 240

    @classmethod
    def _classify_file_family(cls, file_info: Dict) -> str:
        """用确定性能力识别（capability_judge）给文件判族——比 A1/A2 的族标签更可靠
        （平台族错标 391 个用例已被能力族纠正）。无能力证据返回 ''（归入通用桶）。"""
        content = str(file_info.get("content", "") or "")
        if not content:
            return ""
        fam, _ = capability_family_of(content)
        return fam or ""

    @classmethod
    def _layered_score(cls, file_info: Dict):
        """分层排序键：sink+source 同现(2) > 仅其一(1) > 均无(0)，同层内按通用分降序。
        预算集中给「最像真漏洞载体」的文件（分层深度项）。"""
        content = str(file_info.get("content", "") or "")
        has_sink = bool(_SINK_PATTERN.search(content))
        has_source = bool(_SOURCE_PATTERN.search(content))
        layer = 2 if (has_sink and has_source) else (1 if (has_sink or has_source) else 0)
        return (layer, cls._score_file(file_info))

    @classmethod
    def _filter_first_family_aware(cls, files: List[Dict], max_files: int) -> List[Dict]:
        """族感知配额选择（本质修复：解决全局 top-N 在同源构文件上退化为按文件序截断、
        约 1.4 族通吃的预算代表性坍缩）。

        算法：
          1. 按 capability_family_of 把文件分族（''=通用桶）；
          2. 每族保底 1 个配额，基础配额 = max_files // 族数，剩余预算按族规模分配到仍有余量的族；
          3. 族内按 _layered_score 降序取该族配额；
          4. 总量硬封顶 max_files。
        效果：同样 240 预算从覆盖 ~1.4 族变成全族各取一块，LLM 总成本不变，只修分配代表性。
        """
        if max_files <= 0:
            return []
        if len(files) <= max_files:
            return list(files)
        groups: Dict[str, List[Dict]] = defaultdict(list)
        for f in files:
            groups[cls._classify_file_family(f)].append(f)
        fams = list(groups.keys())
        if not fams:
            return files[:max_files]
        n_fam = len(fams)
        base = max(1, max_files // n_fam)
        quotas = {fam: base for fam in fams}
        used = sum(min(quotas[fam], len(groups[fam])) for fam in fams)
        remainder = max_files - used
        order = sorted(fams, key=lambda f: -len(groups[f]))
        guard = 0
        while remainder > 0 and guard < 100_000:
            placed = False
            for fam in order:
                if quotas[fam] < len(groups[fam]):
                    quotas[fam] += 1
                    remainder -= 1
                    placed = True
                    if remainder <= 0:
                        break
            if not placed:
                break
            guard += 1
        out: List[Dict] = []
        for fam in fams:
            items = groups[fam]
            q = quotas[fam]
            if len(items) <= q:
                out.extend(items)
            else:
                scored = sorted(items, key=lambda f: cls._layered_score(f), reverse=True)
                out.extend(scored[:q])
        if len(out) > max_files:
            out = out[:max_files]
        return out

    @classmethod
    def _select_focus_files(cls, files: List[Dict], max_files: Optional[int] = None, scan_mode: str = SCAN_MODE_FILTER_FIRST) -> List[Dict]:
        # 非源码文件（pom.xml/构建脚本/配置/文档）在进入任何 scan_mode 分支前剔除，
        # 不占 max_files 预算，也不进 LLM。
        source_files = [f for f in files if not _is_non_source_file(f)]
        excluded = len(files) - len(source_files)
        if excluded:
            logger.info("[A2] 扫描清单剔除非源码文件 %d 个（pom.xml/配置/文档等）", excluded)
        files = source_files
        effective_max = cls._resolve_max_files(len(files), max_files)
        mode = cls._normalize_mode(scan_mode)
        # 族感知配额默认开；env SAST_AI_A2_FAMILY_QUOTA=0 回退遗留全局 top-N。
        use_family = (os.environ.get("SAST_AI_A2_FAMILY_QUOTA", "1") or "1").strip().lower() not in ("0", "false", "no")
        filter_fn = cls._filter_first_family_aware if use_family else cls._filter_first
        if mode == SCAN_MODE_PURE_AI:
            # No pre-filter: every file is sent to the AI deep scan.
            return list(files)
        if mode == SCAN_MODE_HYBRID:
            key_files = [f for f in files if cls._is_key_dir(f)]
            other_files = [f for f in files if not cls._is_key_dir(f)]
            budget = max(0, effective_max - len(key_files))
            return key_files + filter_fn(other_files, budget)
        return filter_fn(files, effective_max)

    @classmethod
    def estimate_cost(
        cls,
        files: List[Dict],
        *,
        scan_mode: str = SCAN_MODE_FILTER_FIRST,
        provider: str = "qwen",
        max_files: int = 240,
    ) -> Dict:
        """Estimate token/cost of a scan for the given mode.

        Cost is derived from focus-file count x per-file token estimate x provider
        unit price, so it varies monotonically with file scale (more files or a
        less aggressive filter => higher estimate).
        """
        mode = cls._normalize_mode(scan_mode)
        mf = cls._resolve_max_files(len(files), max_files)
        focus = cls._select_focus_files(files, max_files=mf, scan_mode=mode)
        total_tokens = sum(estimate_tokens(str(f.get("content", "") or "")) for f in focus)
        family_hits = sum(
            1
            for f in focus
            if _SINK_PATTERN.search(str(f.get("content", "") or "")) or _SOURCE_PATTERN.search(str(f.get("content", "") or ""))
        )
        cost_per_1k = _PROVIDER_COST_PER_1K.get(provider, _DEFAULT_COST_PER_1K)
        estimated_cost = round(total_tokens / 1000 * cost_per_1k, 6)
        return {
            "scan_mode": mode,
            "provider": provider,
            "total_files": len(files),
            "focus_files": len(focus),
            "family_hits": family_hits,
            "estimated_tokens": total_tokens,
            "estimated_cost": estimated_cost,
        }
