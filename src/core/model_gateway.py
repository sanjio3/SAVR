"""Pluggable model gateway for AI review / fix generation.

The gateway decouples *callers* (e.g. ``FindingWorkflowService``) from the concrete
backend. In production it can dispatch to a real LLM provider (keyed by environment
variables); when no key is configured it falls back to a deterministic, offline
provider so the platform stays fully functional and testable without network access.

Every call returns a :class:`ModelResponse` carrying the text plus real usage
telemetry (latency measured with a monotonic clock, token estimate, cost estimate),
which the caller persists into ``model_runs`` — replacing the previous hard-coded zeros.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

# Rough price table (USD per 1K tokens) used to estimate cost for observability.
# Values are advisory; real providers should override via ``cost_per_1k``.
_DEFAULT_COST_PER_1K = 0.0
_PROVIDER_COST_PER_1K = {
    "anthropic": 0.009,
    "qwen": 0.002,
    "doubao": 0.001,
    "minimax": 0.001,
    "glm": 0.001,
    "zhipu": 0.001,
    "anthropic-compatible": 0.001,
    "agnes": 0.0,
    "openai-compatible": 0.0,
    "offline-heuristic": 0.0,
    # 本地 Ollama 无 API 计费概念，置 0（cost_usd 仅作观测口径）。
    "ollama": 0.0,
    "ollama-native": 0.0,
}

# 免鉴权 provider：本地服务默认不校验凭据。这两个名字不出现在 _resolve_api_key 的
# env 表里（= 取不到 key），因此 __init__ 的「无 key 即离线」判定必须对它们放行，
# 否则接本地模型后 A1 语义 / I2 裁决 / 业务逻辑 AI 会整族静默回落离线。
_KEYLESS_PROVIDERS = frozenset({"ollama", "ollama-native"})


def estimate_tokens(text: str) -> int:
    """Cheap, deterministic token estimate (~4 chars/token, min 1 for non-empty).

    仅用于**成本埋点**（cost_usd）口径，不参与「把输入裁进上下文预算」的决策。
    需要按上下文预算裁剪输入时请用 ``src.core.model_capabilities.estimate_tokens``
    —— 那是 CJK 感知版（中文 1 token/字）。两者不可互换：本项目真实提示词实测只有
    2.34~2.38 字符/token，用本函数去算预算会把小模型上下文高估约 1.7 倍，
    导致 Ollama 静默丢弃提示词头部（详见 model_capabilities 内注释）。
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


@dataclass
class ModelResponse:
    text: str
    model: str
    provider: str
    prompt_version: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    status: str = "completed"
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelGateway:
    """Dispatches a prompt to a provider and returns telemetry-rich responses.

    :param provider: explicit provider name; defaults to env ``SAST_AI_MODEL_PROVIDER``
        or ``offline-heuristic`` when no API key is present.
    :param offline_handler: callable ``(purpose, prompt, context) -> str`` used by the
        offline provider to produce deterministic output. Callers inject their existing
        heuristic here, so behaviour is unchanged but telemetry becomes real.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        *,
        model: str = "",
        offline_handler: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
        api_key: str = "",
        base_url: str = "",
    ):
        self.provider = (provider or os.environ.get("SAST_AI_MODEL_PROVIDER") or "").strip().lower()
        # 智谱 GLM 系列统一走 Anthropic-compatible 网关（open.bigmodel.cn/api/anthropic）
        if self.provider in ("glm", "zhipu"):
            self.provider = "anthropic-compatible"
        self.model = model or os.environ.get("SAST_AI_MODEL_NAME", "")
        self.offline_handler = offline_handler
        self._api_key = api_key or self._resolve_api_key(self.provider)
        self._base_url = base_url or os.environ.get("SAST_AI_BASE_URL", "")
        if not self.provider or (not self._api_key and self.provider not in _KEYLESS_PROVIDERS):
            # No usable real provider configured -> deterministic offline mode.
            self.provider = "offline-heuristic"
            self.model = self.model or "local-heuristic-review"

    @property
    def is_offline(self) -> bool:
        return self.provider == "offline-heuristic"

    @staticmethod
    def _resolve_api_key(provider: str) -> str:
        # 支持两个环境变量名——项目前缀 SAST_AI_GLM_API_KEY 优先，兼容历史 GLM_API_KEY。
        # 多个候选按序取第一个非空，避免「配了 key 但因变量名不对静默回落离线」。
        env_names = {
            "anthropic": ["ANTHROPIC_API_KEY"],
            "qwen": ["QWEN_API_KEY"],
            "doubao": ["DOUBAO_API_KEY"],
            "minimax": ["MINIMAX_API_KEY"],
            "glm": ["SAST_AI_GLM_API_KEY", "GLM_API_KEY"],
            "zhipu": ["SAST_AI_GLM_API_KEY", "GLM_API_KEY"],
            "anthropic-compatible": ["SAST_AI_GLM_API_KEY", "GLM_API_KEY"],
            "agnes": ["AGNES_API_KEY"],
            "openai-compatible": ["AGNES_API_KEY"],
        }
        for name in env_names.get(provider, []):
            value = (os.environ.get(name) or "").strip()
            if value:
                return value
        return ""

    def complete(
        self,
        *,
        purpose: str,
        prompt: str,
        context: Optional[Dict[str, Any]] = None,
        prompt_version: str = "",
    ) -> ModelResponse:
        context = context or {}
        started = time.perf_counter()
        status = "completed"
        error_message = ""
        # C2：流式埋点（ttfb_ms / chunk_count / streamed），由远程客户端回传，
        # 用于下轮全量观察「流式是否真的消灭了读超时 fail-open」。
        telemetry: Dict[str, Any] = {}
        try:
            if self.is_offline:
                text = self._offline_complete(purpose, prompt, context)
            else:
                text, telemetry = self._remote_complete(purpose, prompt, context)
        except Exception as exc:  # pragma: no cover - defensive; remote failure path
            status = "error"
            error_message = str(exc)
            # Fail safe: degrade to offline so the platform never hard-stops on a review.
            text = self._offline_complete(purpose, prompt, context)
        latency_ms = int((time.perf_counter() - started) * 1000)
        input_tokens = estimate_tokens(prompt)
        output_tokens = estimate_tokens(text)
        cost_per_1k = _PROVIDER_COST_PER_1K.get(self.provider, _DEFAULT_COST_PER_1K)
        cost_usd = round(((input_tokens + output_tokens) / 1000.0) * cost_per_1k, 6)
        return ModelResponse(
            text=text,
            model=self.model or self.provider,
            provider=self.provider,
            prompt_version=prompt_version,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            status=status,
            error_message=error_message,
            metadata={"purpose": purpose, **telemetry},
        )

    def _offline_complete(self, purpose: str, prompt: str, context: Dict[str, Any]) -> str:
        if self.offline_handler is not None:
            return self.offline_handler(purpose, prompt, context)
        return f"[offline:{purpose}] no handler configured"

    def _remote_complete(self, purpose: str, prompt: str, context: Dict[str, Any]) -> tuple:
        """Dispatch to a real provider client. 返回 (text, telemetry)。

        Real client wiring lives in ``src/agents/a2_ai_agent.py`` (Anthropic/Qwen/
        Doubao/MiniMax). We import lazily so that the offline path never requires the
        provider SDKs, and so this module has no import-time side effects.

        provider 客户端暴露的是 ``create_message``，并没有 ``complete`` 方法 —— 该分支恒抛
        AttributeError，并被 complete 的 fail-open 兜底静默吞掉，表现为「配了 API key
        却永远走离线」。现改为调用真实接口，并回传流式埋点（ttfb_ms / chunk_count）。
        """
        from src.agents import a2_ai_agent  # lazy import; optional dependency surface

        client_factory = getattr(a2_ai_agent, "build_client", None)
        if not callable(client_factory):
            raise RuntimeError("no remote model client factory available")
        client = client_factory(self.provider, self.model, self._api_key, base_url=self._base_url)
        caller = getattr(client, "create_message", None)
        if not callable(caller):
            # 兼容自定义客户端仍提供旧形态 complete(prompt) 的情况
            return str(client.complete(prompt)), {}
        text = str(caller(system="", messages=[{"role": "user", "content": prompt}]))
        telemetry = dict(getattr(client, "last_call_telemetry", {}) or {})
        # 备用文本流（推理模型思维链）不进元数据，避免大文本落库
        telemetry.pop("reasoning_text", None)
        return text, telemetry


    # （a2_intelligent_agent._init_client），与 ModelGateway 形成两套实现、两套埋点。
    # 现在把「provider 归一 + 降级链构造」收敛到网关，A2/AP 只调用本工厂；
    # 内部仍复用 a2_ai_agent._make_client，保留 config 驱动的 base_url / model，行为不变。
    @staticmethod
    def build_fallback_client(
        config: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        fallback: Optional[str] = None,
        prompt_version: str = "",
    ):
        """构造带顺序降级的 LLM 客户端；无任何可用凭据时返回 None（调用方回落离线）。

        ``fallback`` 传 None 表示「跟配置走」，即读 ``api.fallback_provider``；
        该键缺失时保留历史默认 ``anthropic-compatible``（智谱 GLM 网关），行为不变。
        显式传空串则不加兜底 —— 接本地 Ollama 时必须这样，否则本地模型一旦失败
        就会静默把源码发往云端，与「本地扫描」的语义直接冲突。
        """
        from src.agents import a2_ai_agent  # lazy import，离线路径不依赖 provider SDK

        cfg = config or {}
        api_cfg = (cfg.get("api") or {}) if isinstance(cfg, dict) else {}
        primary = (provider or api_cfg.get("provider") or "").strip().lower()
        if fallback is None:
            _fb = api_cfg.get("fallback_provider", "anthropic-compatible")
            fallback = str(_fb or "").strip().lower()
        else:
            fallback = str(fallback or "").strip().lower()
        # 智谱 GLM 系列统一走 anthropic-compatible 网关（open.bigmodel.cn/api/anthropic）
        if primary in ("glm", "zhipu"):
            primary = "anthropic-compatible"
        order = [primary] if primary else []
        if fallback and fallback not in order:
            order.append(fallback)

        clients, names = [], []
        for name in order:
            try:
                client = a2_ai_agent._make_client(name, cfg)
            except Exception:
                client = None
            if client is not None:
                clients.append(client)
                names.append(name)
        if not clients:
            return None
        # D5：prompt_version 随客户端下发，最终写进 model_runs，便于按版本分组观测
        # 重试上限按主用模型画像收窄，避免弱模型空转重试。
        _primary_model = getattr(clients[0], "model", "") or ""
        try:
            from src.core.model_capabilities import resolve_profile
            _max_attempts = resolve_profile(model=_primary_model, provider=primary).max_attempts
        except Exception:
            _max_attempts = None
        client = a2_ai_agent.FallbackLLMClient(
            clients, provider_names=names, prompt_version=prompt_version, max_attempts=_max_attempts
        )
        # 供调用方取模型名展示/埋点；FallbackLLMClient 自身不一定暴露该属性。
        if not getattr(client, "model", ""):
            try:
                client.model = getattr(clients[0], "model", "")
            except Exception:
                pass
        return client

    def complete_batch(
        self,
        tasks: list,
        max_workers: int = 4,
    ) -> list:
        """并发批处理：一批 (purpose, prompt) 并发送出，返回同序结果。

        用线程池而非引入 asyncio/aiohttp：现有 provider 客户端都是同步 requests，
        线程池即可把「N 个文件串行等 LLM」变成并发，不引入新依赖、不改单次调用语义，
        失败沿用 complete 的 fail-open（回落到离线）。
        """
        if not tasks:
            return []
        from concurrent.futures import ThreadPoolExecutor

        workers = max(1, min(int(max_workers or 4), len(tasks)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(
                    self.complete,
                    purpose=str(t.get("purpose") or ""),
                    prompt=str(t.get("prompt") or ""),
                    context=t.get("context"),
                    prompt_version=str(t.get("prompt_version") or ""),
                )
                for t in tasks
            ]
            return [f.result() for f in futures]


def resolve_llm_config(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """补齐 LLM 相关的配置段，返回一份 ``gateway_from_config`` 能吃透的配置。

    为什么需要：项目里流传的 ``config`` 往往是**局部投影**而不是根配置。
    例如 ``benchmark_cli.run_d2_verify`` 传给 ``D2PipelineService`` 的 agent_config
    只有 ``{'api': {...}}``（没有 ``llm`` 段），``api/dependencies.py`` 干脆不传。
    这些形态下 ``gateway_from_config`` 取不到 ``llm.provider`` → 判成
    ``offline-heuristic`` → 该节点的 LLM 通路**恒离线且不报错**。
    都是 offline-heuristic，即这条 AI review 链路从未真正跑过。

    规则：**传入值优先，缺失才回落根配置（config.yaml）**。所以：
    - 显式传了 ``llm`` 段 → 用传入的，不会被根配置覆盖；
    - 只传了 ``api`` 子表或不传 → 从根配置补 ``llm`` 与各 provider 专属段。

    注意本函数不做「无凭据即离线」的判定，那只在 ``ModelGateway.__init__`` 里做；
    这里只解决「配置取不到」的问题，取到之后离线与否交由既有逻辑决定。
    """
    merged: Dict[str, Any] = dict(cfg or {})
    snap: Dict[str, Any] = {}
    try:
        from .config import config as _root  # lazy import，避免与 config 模块循环依赖
        snap = _root.snapshot() or {}
    except Exception:
        snap = {}
    if not snap:
        return merged
    # llm 段：只有传入侧拿不到 provider 才补
    if not (merged.get("llm") or {}).get("provider"):
        _root_llm = snap.get("llm") or {}
        if _root_llm.get("provider"):
            merged["llm"] = dict(_root_llm)
    # provider 专属段：缺哪个补哪个（gateway_from_config 按 provider 名取段）
    for _key in ("anthropic_compatible", "agnes", "qwen", "minimax", "claude",
                 "doubao", "deepseek", "ollama"):
        if not merged.get(_key) and snap.get(_key):
            merged[_key] = snap[_key]
    return merged


def gateway_from_config(cfg: Optional[Dict[str, Any]] = None,
                        *,
                        offline_handler: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
                        ) -> "ModelGateway":
    """从根配置文件（config.yaml）构造 ModelGateway。

    注入类/业务逻辑类的 AI 语义整合统一走此构造器：

    - ``llm.provider`` 决定 provider（glm/zhipu 统一归一到 anthropic-compatible）；
    - 该 provider 的**专属配置段**提供 api_key / base_url / model；
      GLM 族（glm / zhipu / anthropic-compatible / anthropic）沿用
      ``anthropic_compatible`` 段；
    - 若配置里既没有 api_key 也没有对应环境变量，则自动回落离线，
      平台不报错、可测试。``ollama`` 属免鉴权 provider，不计入此判定。

    base_url/api_key/model，于是 ``llm.provider`` 写 agnes / qwen / ollama 时，
    凭据与端点仍是智谱 GLM 的 —— 实测 ``llm.provider: agnes`` 得到
    base_url=https://open.bigmodel.cn/api/anthropic + GLM key，请求必然鉴权失败，
    再被 ``complete`` 的 fail-open 静默降级成离线响应。表现为「配了 key、
    provider 也不是 offline，但 A1 语义/I2 裁决实际一直在用离线兜底」。

    调用方不传 cfg（或 cfg 为空）时，等价于 ``ModelGateway`` -> 离线确定性模式。

    ``offline_handler`` 可选：离线时用它产出确定性文本。传了它之后，本构造器就等价于
    「在线走真实 provider / 离线走既有确定性兜底」的完整形态 —— 这是
    ``FindingWorkflowService``（gray-review）需要的语义：它原先自建 ModelGateway 时
    带了一个离线 handler，换成本构造器时不能把该行为丢掉。
    """
    cfg = cfg or {}
    llm = cfg.get("llm") or {}
    compat = cfg.get("anthropic_compatible") or {}
    provider = (llm.get("provider") or compat.get("source") or "").strip().lower()
    if provider == "config":
        provider = "anthropic-compatible"
    # GLM 族一律从 anthropic_compatible 段取（历史行为，测试已锁定）
    _compat_family = ("glm", "zhipu", "anthropic-compatible", "anthropic")
    sub: Dict[str, Any] = {}
    if provider not in _compat_family:
        for _key in (provider, provider.replace("-", "_")):
            _cand = cfg.get(_key)
            if isinstance(_cand, dict) and _cand:
                sub = _cand
                break
    if not sub:
        sub = compat
    if provider in _KEYLESS_PROVIDERS and sub is compat:
        # 免鉴权 provider 配了名字却没配专属段时，绝不能继承 GLM 的端点与凭据
        sub = {}
    api_key = str(sub.get("api_key") or "").strip()
    base_url = str(sub.get("base_url") or "").strip()
    model = str(sub.get("model") or "").strip()
    # llm 段的显式覆写优先级最高（历史语义：llm.model / llm.base_url 可覆盖 provider 段）
    model = str(llm.get("model") or "").strip() or model
    base_url = str(llm.get("base_url") or "").strip() or base_url
    return ModelGateway(
        provider=provider or None,
        model=model,
        api_key=api_key,
        base_url=base_url,
        offline_handler=offline_handler,
    )
