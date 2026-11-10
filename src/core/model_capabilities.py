"""模型能力画像层（Model Capability Profiles）。

解决的问题：本平台要在「云端大模型（GLM / Claude / qwen-plus）」与「本地小模型
（Ollama qwen3:8b，num_ctx 2048~8192）」之间来回切换，而这两类模型的能力边界差异极大——
上下文窗口差 16 倍、是否支持 function calling 不同、是否支持流式不同、合理并发差一个量级。

如果把这些差异散落在各个 agent 里写成 if/else，每接一个新模型就要改一遍业务代码。
本模块把「模型能干什么、能吃多少」集中成一张可配置的表，其余模块一律按画像取值：

    profile = resolve_profile(model="qwen3:8b", provider="ollama")
    budget  = input_budget(profile)          # 该模型能吃多少输入 token
    if profile.supports_tools: ...           # 用原生 function calling 还是文本注入
    if profile.max_attempts: ...             # 重试次数
    if profile.recommended_concurrency: ...  # 并发闸门宽度

设计原则（回答「怎么适配大部分模型」）：

1. **未知模型不猜能力，但区分云端与本地**。见不到匹配项时，provider 明确是云端的回落到
   CLOUD_FALLBACK（按大模型对待、不裁输入，保持既有跑分口径）；其余回落到 SAFE_FALLBACK
   （context 按 4096 算、不支持 tools、重试 1 次）。**新模型上市远快于我们登记画像的速度**，
   所以「没登记」必须等于「按该 provider 的常态对待」，而不是一律当成小模型——
   否则一个没登记的新云端模型会被按 4096 裁剪输入，白白丢掉大半证据。
2. **配置优先于内置**。config/model_capabilities.yaml 存在则用配置，便于不动代码调参。
   覆盖语义是**按 name 逐项覆盖**，不是整体替换（2026-09-19 修正）：外部 yaml 里只写
   `local-small` 一项时，云端画像（claude-large / glm-large / cloud-medium …）必须保留，
   否则接本地模型的那一刻会把云端档位全部弄丢，回退成 SAFE_FALLBACK。
   新增项默认追加到末尾（最后才参与匹配）；若某项写了 `prepend: true`，则插到表头优先匹配。
3. **同一套 API 适配强弱**：所有差异都收敛成「取一个数值」或「取一个布尔」，
   调用方不需要知道底层是 Ollama 还是 Claude。
4. **本地的上下文要探测，不要硬编码**。本地模型的上下文由 Modelfile / 启动参数决定
   （qwen3:8b 本体 40960，但 num_ctx 被压到 8192），内置表不可能知道用户当前的值。
   因此 provider=ollama 时用 `/api/show` 探测真实 `num_ctx` 覆盖内置值（带 TTL 缓存、
   fail-open、`SAST_AI_OLLAMA_PROBE=0` 可关）。换模型或改 num_ctx 后无需改代码。

注意：`supports_tools` / `supports_json_mode` 目前**只是信息字段**，除本模块外无消费点
（agentic 走的是提示词里的文本 TOOL 协议，不依赖 provider 原生 function calling）。
因此探测/覆盖这两个字段是「让观测如实」，不会改变运行行为。
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

try:
    import yaml
except Exception:  # pragma: no cover - yaml 缺失时纯用内置表也能工作
    yaml = None  # type: ignore


@dataclass
class ModelProfile:
    """单个模型（或一族模型）的能力边界。"""

    name: str = "unknown"
    tier: str = "medium"  # large | medium | small | local | reasoning
    provider: str = ""
    match_patterns: List[str] = field(default_factory=list)

    # 上下文与输出
    context_window: int = 8192
    max_output_tokens: int = 2048
    # 给推理开销、模板展开留的安全余量；实际可用输入 = context_window - max_output - reserve
    input_reserve_tokens: int = 256

    # 能力开关
    supports_stream: bool = True
    supports_tools: bool = False
    supports_json_mode: bool = False
    # 是否默认开启「思维链」（目前只有 Ollama 原生客户端消费此字段）。
    # 默认 False：2026-09-19 实测 8B 上开思考会与正文争抢输出预算，更慢更不稳定且无质量收益。
    use_thinking: bool = False

    # 调度参数
    max_attempts: int = 3
    recommended_concurrency: int = 4

    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "provider": self.provider,
            "context_window": self.context_window,
            "max_output_tokens": self.max_output_tokens,
            "input_reserve_tokens": self.input_reserve_tokens,
            "supports_stream": self.supports_stream,
            "supports_tools": self.supports_tools,
            "supports_json_mode": self.supports_json_mode,
            "use_thinking": self.use_thinking,
            "max_attempts": self.max_attempts,
            "recommended_concurrency": self.recommended_concurrency,
        }


# 未知模型的保守档：宁可按小模型喂，也不要打爆上下文。
# context_window 取 4096 是因为本地小模型常见 num_ctx 就是 2048~4096，
# 按 4096 裁剪输入在 32K 模型上只是「喂少了」，在 2K 模型上则是「能不能跑」的区别。
SAFE_FALLBACK = ModelProfile(
    name="fallback-conservative",
    tier="small",
    context_window=4096,
    max_output_tokens=1024,
    input_reserve_tokens=256,
    supports_stream=True,
    supports_tools=False,
    supports_json_mode=False,
    max_attempts=2,
    recommended_concurrency=2,
    notes="未知模型的保守默认档：按小模型对待，宁可少喂也不要溢出上下文",
)

# 云端兜底档：provider 明确是云端、但模型名没登记时用它，而不是 SAFE_FALLBACK。
# 动机：SAFE_FALLBACK 按 4096 上下文裁剪，对本地小模型是「能不能跑」，对云端大模型则是
# 「白白丢掉大半输入」——本项目对云端的既有约定是「不裁输入、保持跑分口径不变」。
# 新模型上市速度远快于我们登记画像的速度，这条兜底保证「没登记 ≠ 被当成小模型」。
CLOUD_FALLBACK = ModelProfile(
    name="fallback-cloud",
    tier="large",
    provider="",
    context_window=64_000,
    max_output_tokens=4096,
    input_reserve_tokens=512,
    supports_stream=True,
    supports_tools=True,
    supports_json_mode=True,
    max_attempts=3,
    recommended_concurrency=6,
    notes="云端未知模型的兜底档：按大模型对待，不因未登记而裁剪输入",
)

# 已知的云端 provider 名（用于选择兜底档；ollama 不在其中）
CLOUD_PROVIDERS = frozenset({
    "anthropic", "anthropic-compatible", "openai", "openai-compatible", "agnes",
    "qwen", "dashscope", "doubao", "volces", "minimax", "deepseek", "glm", "zhipu",
    "moonshot", "kimi", "gemini", "google", "ernie", "baidu", "spark", "iflytek",
    "hunyuan", "tencent", "baichuan", "siliconflow", "openrouter", "groq", "together",
})

# 内置画像表。命中顺序 = 列表顺序，**先精确后泛化**：
# 1) 推理型（思维链与正文抢输出预算，必须放宽 max_output_tokens）
# 2) 本地模型（上下文是硬约束，且会由 Ollama /api/show 在运行时用真实 num_ctx 覆盖）
# 3) 云端旗舰 4) 云端中档
# 注意：不要把泛化的 `qwen3.*` 之类写进云端档，否则会把本地的 `qwen3:8b` 一并吞掉。
_BUILTIN_PROFILES: List[ModelProfile] = [
    # ---- 1) 推理型：思维链吃输出预算，正文容易被截断 ----
    ModelProfile(
        name="reasoning", tier="reasoning", provider="",
        match_patterns=[r"^o1", r"^o3", r"^o4-mini", r"deepseek-reasoner", r"deepseek-r1$",
                        r"glm-z1", r"^qwq", r".*thinking.*", r"magistral", r"qwen3-.*-thinking"],
        context_window=128_000, max_output_tokens=16_384, input_reserve_tokens=1024,
        supports_stream=True, supports_tools=False, supports_json_mode=False,
        use_thinking=True, max_attempts=2, recommended_concurrency=4,
        notes="推理型模型：思维链会吃掉大量输出预算，正文容易被截断，需放宽 max_output_tokens",
    ),
    # ---- 2) 本地小模型：上下文受显存限制；真实 num_ctx 由 /api/show 运行时覆盖 ----
    # provider 固定填 "ollama"：模型名带 tag（qwen3:8b）时走模式匹配；万一配置里只写了
    # 裸模型名（qwen3）匹配不上，还能靠 provider 回落直接命中本档，不至于掉进保守档
    # 而把 8192 的上下文按 4096 裁掉一半。
    ModelProfile(
        name="local-small", tier="local", provider="ollama",
        match_patterns=[r"qwen3:[0-9]+b", r"qwen2\.5:[0-9]+b", r"qwen2:[0-9]+b",
                        r"llama3\.[0-9]+:[0-9]+b", r"llama3:[0-9]+b", r"llama4:.*",
                        r"deepseek-r1:[0-9]+b", r"deepseek-coder.*:.*", r"codellama:.*",
                        r"mistral.*:.*", r"mixtral.*:.*", r"gemma[0-9]?:.*", r"phi[0-9]?:.*",
                        r"starcoder.*", r"granite.*:.*", r"smollm.*", r"tinyllama.*",
                        r"yi:[0-9]+b", r"glm4:.*", r"^qwen3$", r"^qwen2\.5$", r"^llama3$"],
        context_window=8192, max_output_tokens=2048, input_reserve_tokens=256,
        supports_stream=True, supports_tools=True, supports_json_mode=False,
        use_thinking=False, max_attempts=2, recommended_concurrency=2,
        notes="本地 Ollama 小模型：上下文受显存限制（运行时由 /api/show 的 num_ctx 覆盖）；"
              "关闭思考——2026-09-19 实测 4 个真实样本上 think=false 命中 4/4 且总耗时 31.7s，"
              "think=true 命中 0~3/4 且总耗时 150s+；"
              "max_attempts=2：本地 provider 免鉴权、无配额、不计费，重试不放大成本（只增加时间），"
              "而接本地时通常已把 api.fallback_provider 置空 —— 此时同 provider 重试是唯一的"
              "容错手段（Ollama 冷加载/并发瞬时失败都只能靠它兜），故保留 1 次重试；"
              "历史上给弱模型设 1 是为了消除「重试 3 次 × N 云端 provider」的请求放大，"
              "该顾虑对本地 provider 不成立。",
    ),
    # ---- 3) 云端旗舰 ----
    ModelProfile(
        name="claude-large", tier="large", provider="anthropic",
        match_patterns=[r"claude"],
        context_window=200_000, max_output_tokens=8192, input_reserve_tokens=1024,
        supports_stream=True, supports_tools=True, supports_json_mode=False,
        max_attempts=3, recommended_concurrency=8,
    ),
    ModelProfile(
        name="cloud-openai-large", tier="large", provider="openai-compatible",
        match_patterns=[r"gpt-4", r"gpt-5", r"gpt-4o", r"gpt-4\.1", r"agnes-3.*",
                        r"deepseek-v3", r"deepseek-chat", r"kimi", r"moonshot",
                        r"qwen-max", r"qwen3-max", r"qwen-plus", r"qwen3-[0-9]+b-instruct",
                        r"gemini-2\.5", r"gemini-exp", r"gemini-1\.5-pro"],
        context_window=128_000, max_output_tokens=8192, input_reserve_tokens=512,
        supports_stream=True, supports_tools=True, supports_json_mode=True,
        max_attempts=3, recommended_concurrency=8,
    ),
    ModelProfile(
        name="glm-large", tier="large", provider="anthropic-compatible",
        match_patterns=[r"glm-4\.5", r"glm-4\.6", r"glm-4-plus", r"glm-4-long", r"glm-4-air",
                        r"glm-4$", r"glm-4-flash"],
        context_window=128_000, max_output_tokens=4096, input_reserve_tokens=512,
        supports_stream=True, supports_tools=True, supports_json_mode=False,
        max_attempts=3, recommended_concurrency=6,
    ),
    # ---- 4) 云端中档 / 其他厂商 ----
    ModelProfile(
        name="cloud-medium", tier="medium", provider="",
        match_patterns=[r"qwen-turbo", r"qwen-long", r"qwen2\.5-[0-9]+b-instruct",
                        r"gpt-3\.5", r"gpt-4o-mini", r"gpt-5-mini", r"gpt-5-nano",
                        r"doubao", r"abab[0-9.]*", r"minimax", r"gemini.*flash",
                        r"ernie", r"spark", r"generalv[0-9]", r"hunyuan", r"baichuan",
                        r"Deepseek-V4.*", r"deepseek-.*chat", r"qwen2\.5-coder-[0-9]+b-instruct"],
        context_window=32_000, max_output_tokens=4096, input_reserve_tokens=512,
        supports_stream=True, supports_tools=True, supports_json_mode=True,
        max_attempts=2, recommended_concurrency=6,
    ),
]

_PROFILES_CACHE: Optional[List[ModelProfile]] = None
_CONFIG_PATH_CACHE: Optional[str] = None


def _candidate_config_paths() -> List[str]:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return [
        os.path.join(root, "config", "model_capabilities.yaml"),
        os.path.join(root, "model_capabilities.yaml"),
    ]


def _profile_from_dict(raw: Dict[str, Any]) -> ModelProfile:
    def _get(key: str, default: Any) -> Any:
        value = raw.get(key, default)
        return default if value is None else value

    return ModelProfile(
        name=str(_get("name", "unnamed")),
        tier=str(_get("tier", "medium")),
        provider=str(_get("provider", "") or ""),
        match_patterns=[str(p) for p in (_get("match", []) or [])],
        context_window=int(_get("context_window", 8192)),
        max_output_tokens=int(_get("max_output_tokens", 2048)),
        input_reserve_tokens=int(_get("input_reserve_tokens", 256)),
        supports_stream=bool(_get("supports_stream", True)),
        supports_tools=bool(_get("supports_tools", False)),
        supports_json_mode=bool(_get("supports_json_mode", False)),
        use_thinking=bool(_get("use_thinking", False)),
        max_attempts=int(_get("max_attempts", 3)),
        recommended_concurrency=int(_get("recommended_concurrency", 4)),
        notes=str(_get("notes", "") or ""),
    )


def _normalize_override_kwargs(raw: Dict[str, Any]) -> Dict[str, Any]:
    """把 yaml 键归一成 ModelProfile 字段名（只保留能识别的键）。"""
    valid = {f.name for f in dataclasses.fields(ModelProfile)}
    kwargs: Dict[str, Any] = {}
    for key, value in raw.items():
        name = "match_patterns" if key == "match" else key
        if name not in valid or name == "name" or value is None:
            continue
        if name == "match_patterns":
            kwargs[name] = [str(p) for p in (value or [])]
        elif name in ("context_window", "max_output_tokens", "input_reserve_tokens",
                      "max_attempts", "recommended_concurrency"):
            kwargs[name] = int(value)
        elif name in ("supports_stream", "supports_tools", "supports_json_mode", "use_thinking"):
            kwargs[name] = bool(value)
        else:
            kwargs[name] = str(value)
    return kwargs


def _merge_profiles(base: List[ModelProfile], overrides: List[Dict[str, Any]]) -> List[ModelProfile]:
    """把外部 yaml 的档位按 name 合并到内置表上；同名者原位**字段级覆盖**，新增者按 prepend 决定位置。

    原位覆盖的意义：命中顺序 = 列表顺序，用户改 `local-small` 的并发/上下文时不该顺带
    改变它的匹配优先级；只有显式声明 prepend 的新档位才会被插到表头优先匹配。

    2026-09-19 修正（实测暴露）：同名档位必须**逐字段**覆盖，不能整体替换。
    原实现用 `_profile_from_dict(raw)` 造一个全新档位顶上去，于是 yaml 里没写的键
    会退回 `_profile_from_dict` 的默认值 —— 只想调 `recommended_concurrency` 的
    外部档位会把 `match_patterns` 清空，该档位再也匹配不上任何模型名，只能靠
    provider 回落命中。实测症状：local-small 丢掉 `qwen3:\\d+b` 后，
    `resolve_profile("qwen3:8b", provider="qwen")` 直接掉进 CLOUD_FALLBACK（ctx 64000），
    输入裁剪口径全错。
    """
    merged = list(base)
    index_by_name = {p.name: i for i, p in enumerate(merged)}
    for raw in overrides:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        pos = index_by_name.get(name)
        if pos is not None:
            kwargs = _normalize_override_kwargs(raw)
            merged[pos] = replace(merged[pos], **kwargs) if kwargs else merged[pos]
            continue
        profile = _profile_from_dict(raw)
        if bool(raw.get("prepend")):
            merged.insert(0, profile)
            index_by_name = {p.name: i for i, p in enumerate(merged)}
        else:
            merged.append(profile)
            index_by_name[profile.name] = len(merged) - 1
    return merged


def load_profiles(force_reload: bool = False) -> List[ModelProfile]:
    """加载画像表：外部 yaml（若存在）**按 name 覆盖**内置表，未覆盖的保持内置值。"""
    global _PROFILES_CACHE
    if _PROFILES_CACHE is not None and not force_reload:
        return _PROFILES_CACHE

    profiles: List[ModelProfile] = list(_BUILTIN_PROFILES)
    if yaml is not None:
        for path in _candidate_config_paths():
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw = yaml.safe_load(handle) or {}
                overrides = [item for item in (raw.get("profiles") or []) if isinstance(item, dict)]
                if overrides:
                    profiles = _merge_profiles(profiles, overrides)
            except Exception as exc:
                # 不再静默 continue：宽 except 曾把一个 NameError 吞了整整一轮，
                # 表现为「yaml 改了不生效」却又看不出任何症状（内置值恰好与 yaml 一致时尤甚）。
                _logger.warning("[model_capabilities] %s 加载/合并失败，回退内置画像表：%s", path, exc)
            break

    _PROFILES_CACHE = profiles
    return profiles


def resolve_profile(model: str = "", provider: str = "") -> ModelProfile:
    """按模型名（优先）与 provider 解析画像；无匹配时按 provider 类型选兜底档。

    兜底分两档（2026-09-19 新增）：provider 明确是云端 → CLOUD_FALLBACK（不裁输入），
    其余（本地/未知）→ SAFE_FALLBACK（按小模型保守裁剪）。
    本地 provider(ollama) 额外用 /api/show 的真实 num_ctx 覆盖内置上下文值。
    """
    model_l = (model or "").strip().lower()
    provider_l = (provider or "").strip().lower()

    for profile in load_profiles():
        for pattern in profile.match_patterns:
            try:
                if re.search(pattern, model_l, flags=re.IGNORECASE):
                    return _apply_runtime_overrides(profile, model, provider)
            except re.error:
                continue
    # 模型名没匹配上，再退一步按 provider 找画像
    if provider_l:
        for profile in load_profiles():
            if profile.provider and profile.provider.lower() == provider_l:
                return _apply_runtime_overrides(profile, model, provider)
    # 最后按 provider 类型选兜底：云端不裁输入，本地/未知保守
    if provider_l in CLOUD_PROVIDERS:
        return CLOUD_FALLBACK
    return SAFE_FALLBACK


def _apply_runtime_overrides(profile: ModelProfile, model: str, provider: str) -> ModelProfile:
    """本地模型：用 Ollama /api/show 探测到的真实 num_ctx 覆盖内置上下文值。

    行为效果集中在 context_window（→ input_budget → 输入裁剪量）。为什么必须探测：
    本地模型的上下文不是模型固有属性，而是 Modelfile / 启动参数决定的——qwen3:8b 本体支持
    40960，但 Modelfile 把 num_ctx 压到 8192 以适配 8GB 显存。用户换模型或改 num_ctx 后，
    内置表不可能知道新值；不跟随就会出现「按 8192 裁剪、实际只有 4096」的溢出
    （Ollama 超限会静默丢弃提示词头部，表现为答非所问）。
    探测结果有 TTL 缓存且 fail-open：Ollama 没起或探测失败时，照旧用内置值。
    """
    if (provider or "").strip().lower() not in ("ollama", "ollama-native"):
        return profile
    # 2026-09-20：任务级覆盖优先于探测。前端【设置】里用户可以按模型能力调 ctx，
    # 该值由 run_benchmark 写进 SAST_AI_LLM_CTX_OVERRIDE（子进程内生效、不外溢），
    # 必须比 /api/show 的 Modelfile 值优先 —— 否则「设了 4096 却仍按 8192 裁剪输入」，
    # 请求 num_ctx 小于裁剪预算时 Ollama 会静默丢提示词头部。
    _ov = (os.environ.get("SAST_AI_LLM_CTX_OVERRIDE") or "").strip()
    if _ov:
        try:
            _ctx = int(_ov)
        except (TypeError, ValueError):
            _ctx = 0
        if _ctx >= 1024 and _ctx != profile.context_window:
            return replace(profile, context_window=_ctx)
    probe = probe_ollama_model(model)
    if not probe:
        return profile
    try:
        ctx = int(probe.get("context_window") or 0)
    except (TypeError, ValueError):
        ctx = 0
    if ctx < 1024:
        return profile
    if ctx == profile.context_window:
        return profile
    return replace(profile, context_window=ctx)


# ---------------------------------------------------------------------------
# 本地模型的运行时能力探测（Ollama /api/show）
# ---------------------------------------------------------------------------

_OLLAMA_PROBE_CACHE: Dict[str, Any] = {}   # "base|model" -> (timestamp, result|None)
_OLLAMA_PROBE_TTL = 300.0
_OLLAMA_DEFAULT_BASE = "http://127.0.0.1:11434"


def _probe_enabled() -> bool:
    """探测开关（默认开）。SAST_AI_OLLAMA_PROBE=0 可关闭，避免离线环境反复重试。"""
    return (os.environ.get("SAST_AI_OLLAMA_PROBE", "1") or "1").strip().lower() not in {
        "0", "false", "no", "off", "",
    }


def _parse_num_ctx(parameters: str) -> Optional[int]:
    """从 /api/show 的 parameters 文本里取 num_ctx（Modelfile 的生效值）。"""
    match = re.search(r"^\s*num_ctx\s+(\d+)\s*$", parameters or "", flags=re.MULTILINE)
    if not match:
        return None
    try:
        value = int(match.group(1))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def probe_ollama_model(model: str, base_url: str = "", timeout: float = 5.0,
                       use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """探测本地 Ollama 模型的真实能力；失败返回 None（fail-open）。

    实测 Ollama 0.34.1 的 /api/show 返回（qwen3:8b）：
      capabilities: ['tools', 'thinking', 'completion']
      parameters  : 'num_ctx                        8192'    <- 生效值，优先取这个
      model_info  : {'qwen3.context_length': 40960}          <- 本体上限，仅作兜底
    返回 {"model", "context_window", "capabilities", "supports_tools", "supports_thinking"}。
    """
    if not model:
        return None
    base = (base_url or _OLLAMA_DEFAULT_BASE).rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3].rstrip("/")
    key = f"{base}|{model}"
    now = time.time()
    if use_cache:
        cached = _OLLAMA_PROBE_CACHE.get(key)
        if cached is not None and now - cached[0] < _OLLAMA_PROBE_TTL:
            return cached[1]

    result: Optional[Dict[str, Any]] = None
    if _probe_enabled():
        try:
            import json as _json
            import urllib.request
            request = urllib.request.Request(
                f"{base}/api/show",
                data=_json.dumps({"model": model}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = _json.loads(response.read().decode("utf-8"))
            capabilities = list(payload.get("capabilities") or [])
            ctx = _parse_num_ctx(str(payload.get("parameters") or ""))
            if ctx is None:
                for info_key, info_value in (payload.get("model_info") or {}).items():
                    if str(info_key).endswith("context_length") and isinstance(info_value, int) and info_value > 0:
                        ctx = info_value
                        break
            result = {
                "model": model,
                "context_window": ctx,
                "capabilities": capabilities,
                "supports_tools": ("tools" in capabilities) if capabilities else None,
                "supports_thinking": ("thinking" in capabilities) if capabilities else None,
            }
        except Exception:
            result = None
    _OLLAMA_PROBE_CACHE[key] = (now, result)
    return result


def clear_probe_cache() -> None:
    _OLLAMA_PROBE_CACHE.clear()


def input_budget(profile: ModelProfile, reserve_output: int = 0) -> int:
    """该模型可用的输入 token 预算。

    budget = context_window - max_output_tokens - 安全余量，且不小于 512 的可用下限，
    避免极端配置算出 0 或负数导致什么都不喂。
    """
    out = max(int(reserve_output or 0), int(profile.max_output_tokens or 0))
    budget = int(profile.context_window) - out - int(profile.input_reserve_tokens)
    return max(256, budget)


def clamp_max_tokens(profile: ModelProfile, requested: int) -> int:
    """把调用方请求的 max_tokens 压到模型能力上限内。

    意义：上层写死 4096/8192 也不会把小模型打爆；同时避免本地模型慢生成时无限等待。
    """
    requested = int(requested or 0)
    ceiling = int(profile.max_output_tokens or 0)
    if ceiling <= 0:
        return max(1, requested)
    if requested <= 0:
        return ceiling
    return min(requested, ceiling)


# CJK 及全角标点：这些字符在 Qwen 系 tokenizer 下大致 1 token 一个字。
_CJK_RE = re.compile(r"[\u2e80-\u9fff\u3000-\u303f\uff00-\uffef\u3040-\u30ff\uac00-\ud7af]")

# 非 CJK 字符的字符/token 比。英文实测 4.76，取 4.0 留余量。
_ASCII_CHARS_PER_TOKEN = 4.0


def estimate_tokens(text: str) -> int:
    """CJK 感知的 token 估算（**故意保守**，宁可少喂也不要溢出上下文）。

    为什么不能再用 `len(text) / 4`：2026-09-19 对 qwen3:8b 实测 prompt_eval_count，
    本项目的真实提示词（中文指令 + 英文代码）只有 2.34~2.38 字符/token，
    纯中文低到 1.67 —— 写死 4 字符/token 会把 8192 上下文的小模型高估约 1.7 倍，
    27.6k 字符的输入实际接近 11.6k token，直接超出 8192，Ollama 会静默丢弃提示词头部
    （连同任务指令一起丢），表现为「模型答非所问」而不是报错，极难排查。

    实测依据：
      - 纯中文说明  820 字符 / 492 token = 1.67 字符/token
      - 纯英文说明 1300 字符 / 273 token = 4.76 字符/token
      - audit_file 真实提示词（中文指令 + Java 代码）3647 字符 / 1532 token = 2.38 字符/token
    """
    if not text:
        return 0
    cjk = len(_CJK_RE.findall(text))
    other = len(text) - cjk
    return int(cjk + other / _ASCII_CHARS_PER_TOKEN) + 1


def fit_to_token_budget(text: str, budget_tokens: int) -> tuple:
    """把文本裁进 token 预算内，返回 (文本, 是否被裁)。

    先按估算比例一次切到位，再回头校验两轮——估算本身有误差（CJK 按 1 token/字偏保守），
    所以只可能裁多不可能裁少，不会溢出。
    """
    if not text:
        return text, False
    budget = int(budget_tokens or 0)
    if budget <= 0:
        return "", True
    if estimate_tokens(text) <= budget:
        return text, False
    cut = text
    for _ in range(3):
        est = estimate_tokens(cut)
        if est <= budget:
            break
        ratio = budget / float(est)
        new_len = max(1, int(len(cut) * ratio))
        if new_len >= len(cut):
            new_len = len(cut) - 1
        cut = cut[:new_len]
    return cut, True
