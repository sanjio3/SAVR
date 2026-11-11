"""
A2 AI 语义分析代理
基于 Claude/Qwen/Doubao API 进行智能漏洞分析
"""
import json
import os
import time
import yaml
import requests
from pathlib import Path
from typing import Any, List, Dict, Optional
import logging

from ..core.models import Vulnerability, ScanResult
from ..core.config import config
from .prompt_render import render_prompt

logger = logging.getLogger(__name__)

# LLM 读超时（秒）。
# src/config/base.yaml 的 api.provider 实际是 qwen、model ark-code-latest，运行期
# FallbackLLMClient 走的是 anthropic-compatible（open.bigmodel.cn，GLM-4-Flash，约 14 token/s），
# 把 A2 拖到 30+ 分钟、D1 卡在契约生成。故恢复 180s：GLM 单份契约需 60-120s。
# 前提变化（真正切到 agnes 或同速 provider）后再下调；可用环境变量 SAST_AI_LLM_TIMEOUT 覆盖。
LLM_READ_TIMEOUT = int(os.environ.get("SAST_AI_LLM_TIMEOUT", "300") or "300")

# requests 抛 ReadTimeout -> FallbackLLMClient 判定失败 -> fail-open 回退单次 completion。
# 流式把「读超时」语义从「整个响应体在 N 秒内到齐」改成「相邻 chunk 之间 idle 上限」：
# 只要 provider 持续吐 chunk（GLM 约 14 token/s，间隔远小于 90s），就永不触发整体超时。
# 不做 asyncio：并发由各调用方自己的线程池提供（A2 pipeline/a2/service.py 的
# llm_concurrency 信号量、a2_contract_planner 的 SASTAI_A2_PLANNER_WORKERS 等），
# 切异步要把全部 provider 客户端换成 httpx/aiohttp 并改写三层签名，收益不抵风险
# （详见 C2 文档第四节）。
#
# 这是错的——complete_batch（core/model_gateway.py:241）全项目零调用点，真正的并发
# 来源是各 stage 各自的线程池/信号量。由此暴露一个架构缺口：不存在跨 stage 的全局
# LLM 并发闸门，各 stage 各限各的，瞬时并发会是各 stage 之和。接本地 Ollama
# （OLLAMA_NUM_PARALLEL=2）时会退化为排队，接云端会触发 429。


def _env_int(name: str, default: int, lo: int = 1, hi: int = 7200) -> int:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


# 连接超时：连不上要快速失败（小值），避免线程池被建连慢的 provider 占满。
LLM_CONNECT_TIMEOUT = _env_int("SAST_AI_LLM_CONNECT_TIMEOUT", 15)
# chunk 间 idle 上限：requests 的 read timeout 在 stream=True 下即「两次 socket 读之间的
# 间隔」，天然就是 chunk idle 语义。90s 对 14 token/s 的 GLM 足够宽松。
LLM_IDLE_TIMEOUT = _env_int("SAST_AI_LLM_IDLE_TIMEOUT", 90)
# 整体硬上限：防 provider 以极低速率持续吐字把单次调用无限拖长（此时 idle 永不触发）。
LLM_TOTAL_TIMEOUT = _env_int("SAST_AI_LLM_TOTAL_TIMEOUT", 600)

# 全局并发闸门的排队忍耐上限（秒）：等不到票就当成一次可重试的失败，
# 而不是无限期挂住线程——后者会让上游线程池被慢慢占满且没有任何信号。
# 本地模型（OLLAMA_NUM_PARALLEL=2）建议显式设 SAST_AI_LLM_GATE_CONCURRENCY=2，
# 让「排队」发生在我们的闸门里（可观测），而不是发生在 Ollama 内部（不可见）。
_GATE_WAIT_TIMEOUT = float(_env_int("SAST_AI_LLM_GATE_WAIT", 120, lo=1, hi=3600))

# 高于此采样温度不进缓存：响应本就不可复现，缓存会造成「假确定性」
_CACHEABLE_TEMPERATURE_MAX = 0.2


def _store_cache(
    cache_key: str,
    text: str,
    provider: str,
    model_name: str,
    telemetry: Dict[str, Any],
) -> None:
    """写缓存的小助手：任何异常都不允许冒泡到调用方。"""
    if not cache_key or not (text or "").strip():
        return
    try:
        from ..core import llm_cache
        llm_cache.put(
            cache_key,
            text=text,
            provider=provider,
            model=model_name,
            telemetry=telemetry,
        )
    except Exception as exc:  # fail-open：缓存只加速，不能拖垮主流程
        logger.debug("[LLM] 缓存写入异常（忽略）：%s", exc)


def _llm_stream_enabled() -> bool:
    """流式开关（默认开）。

    排障或遇到不兼容 provider 时用 SAST_AI_LLM_STREAM=0 整体关闭，
    回到「一次性等完整 JSON 响应」的旧语义（超时仍走 LLM_READ_TIMEOUT）。
    """
    return (os.environ.get("SAST_AI_LLM_STREAM", "1") or "1").strip().lower() not in {
        "0", "false", "no", "off", "",
    }


def _sse_text_anthropic(obj: Dict[str, Any]) -> str:
    # {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
    if obj.get("type") != "content_block_delta":
        return ""
    delta = obj.get("delta") or {}
    if delta.get("type") not in (None, "", "text_delta"):
        return ""
    return delta.get("text") or ""


def _sse_done_anthropic(obj: Dict[str, Any]) -> bool:
    return obj.get("type") == "message_stop"


def _sse_text_openai(obj: Dict[str, Any]) -> str:
    choices = obj.get("choices") or []
    if not choices:
        return ""
    first = choices[0] or {}
    delta = first.get("delta") or {}
    if isinstance(delta, dict) and delta.get("content"):
        return delta.get("content") or ""
    message = first.get("message") or {}
    return message.get("content") or ""


def _sse_done_openai(obj: Dict[str, Any]) -> bool:
    choices = obj.get("choices") or []
    if not choices:
        return False
    return bool((choices[0] or {}).get("finish_reason"))


def _sse_text_qwen(obj: Dict[str, Any]) -> str:
    output = obj.get("output") or {}
    choices = output.get("choices") or []
    if not choices:
        return ""
    message = (choices[0] or {}).get("message") or {}
    return message.get("content") or ""


def _sse_done_qwen(obj: Dict[str, Any]) -> bool:
    output = obj.get("output") or {}
    finish = output.get("finish_reason")
    if finish not in (None, "", "null"):
        return True
    choices = output.get("choices") or []
    if choices:
        return (choices[0] or {}).get("finish_reason") not in (None, "", "null")
    return False


def _sse_alt_openai(obj: Dict[str, Any]) -> str:
    """OpenAI 系推理型模型的「思维链」片段（delta.reasoning_content）。

    单独累积、不与正文混拼：DeepSeek 等模型会先流式吐 reasoning、再吐 content，
    若同一路拼接会把思维链当成答案。原非流式实现在 content 为空时才回退
    reasoning_content，流式形态保留同一语义（见 DeepseekClient.create_message）。
    """
    choices = obj.get("choices") or []
    if not choices:
        return ""
    delta = (choices[0] or {}).get("delta") or {}
    if not isinstance(delta, dict):
        return ""
    return delta.get("reasoning_content") or ""


_SSE_FLAVORS = {
    "anthropic": (_sse_text_anthropic, _sse_done_anthropic),
    "openai": (_sse_text_openai, _sse_done_openai),
    "qwen": (_sse_text_qwen, _sse_done_qwen),
}

# 需要「旁路累积」的 flavor：正文之外的备用文本流（如推理模型的思维链）。
def _sse_finish_anthropic(obj: Dict[str, Any]) -> str:
    # {"type":"message_delta","delta":{"stop_reason":"max_tokens"}}
    delta = obj.get("delta") or {}
    return str(delta.get("stop_reason") or obj.get("stop_reason") or "")


def _sse_finish_openai(obj: Dict[str, Any]) -> str:
    choices = obj.get("choices") or []
    if not choices:
        return ""
    return str((choices[0] or {}).get("finish_reason") or "")


def _sse_finish_qwen(obj: Dict[str, Any]) -> str:
    output = obj.get("output") or {}
    finish = output.get("finish_reason")
    if finish:
        return str(finish)
    choices = output.get("choices") or []
    if choices:
        return str((choices[0] or {}).get("finish_reason") or "")
    return ""


def _sse_finish_ollama(obj: Dict[str, Any]) -> str:
    # Ollama 原生端点把停止原因放在顶层 done_reason（stop / length / load / unload）。
    # "length" 等价于 OpenAI 的 finish_reason=length，是「被输出预算腰斩」的唯一可靠信号。
    return str(obj.get("done_reason") or "")


_SSE_FINISH = {
    "anthropic": _sse_finish_anthropic,
    "openai": _sse_finish_openai,
    "qwen": _sse_finish_qwen,
    "ollama": _sse_finish_ollama,
}


def _extract_text(result: Dict[str, Any], flavor: str) -> str:
    """从一次性 JSON 响应里取正文（用于写 P0-3 缓存，不改各客户端的返回契约）。"""
    if not isinstance(result, dict):
        return ""
    try:
        if flavor == "ollama":
            return str((result.get("message") or {}).get("content") or "")
        if flavor == "anthropic":
            blocks = result.get("content") or []
            if blocks and isinstance(blocks[0], dict):
                return str(blocks[0].get("text") or "")
            return ""
        if flavor == "qwen":
            output = result.get("output") or {}
            choices = output.get("choices") or []
            if choices:
                return str((choices[0] or {}).get("message", {}).get("content") or "")
            return str(output.get("text") or "")
        choices = result.get("choices") or []
        if choices:
            return str(((choices[0] or {}).get("message") or {}).get("content") or "")
    except Exception:
        return ""
    return ""


def _extract_finish_reason(result: Dict[str, Any], flavor: str) -> str:
    """从一次性 JSON 响应里取 finish_reason（非流式路径）。"""
    if not isinstance(result, dict):
        return ""
    try:
        return _SSE_FINISH.get(flavor, _sse_finish_openai)(result) or ""
    except Exception:
        return ""


_SSE_ALT = {
    "openai": _sse_alt_openai,
}


def _prepare_stream_payload(flavor: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """按 flavor 补流式所需字段（仅在流式开启时调用，不影响非流式语义）。"""
    body = dict(payload)
    body["stream"] = True
    if flavor == "qwen":
        # 通义千问：增量输出开关位于 parameters 下，缺省为整段一次性返回。
        params = dict(body.get("parameters") or {})
        params["incremental_output"] = True
        body["parameters"] = params
    return body


def _trim_messages_to_budget(payload: Dict[str, Any], budget: int) -> Dict[str, Any]:
    """上下文裁剪：估算 messages 总 token，超出 budget 时优先截断
    最长、非 system 的消息体（保住 system 与首条消息骨架），直到回到预算内或无可裁。

    - 估算用字符数 // 4（粗略、不引入 tiktoken 重依赖）；偏差只在观测侧，不影响「是否裁剪」正确性。
    - 永不裁 system 消息与首条消息（通常是任务/代码骨架，丢了就跑偏）。
    - 不重写任何提示词、不改动 messages 之外的字段，扫描语义零变更。
    - 命中后返回新 dict（不原地改入参），调用方据此把 telemetry["trimmed"] 置 True。
    """
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        return payload

    def _est_tokens(msg: Any) -> int:
        if not isinstance(msg, dict):
            return 0
        parts: List[str] = []
        for key in ("content", "system", "role"):
            val = msg.get(key)
            if isinstance(val, str):
                parts.append(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        parts.append(str(item.get("text") or item.get("content") or ""))
                    elif isinstance(item, str):
                        parts.append(item)
        return max(1, len("\n".join(parts)) // 4)

    if sum(_est_tokens(m) for m in messages) <= budget:
        return payload

    new_messages = [dict(m) if isinstance(m, dict) else m for m in messages]
    # 可裁候选：非 system（且不含 system 键）、非首条
    candidates = [
        i for i, m in enumerate(new_messages)
        if i > 0 and isinstance(m, dict) and m.get("role") != "system" and "system" not in m
    ]
    while True:
        if sum(_est_tokens(m) for m in new_messages) <= budget or not candidates:
            break
        longest = max(candidates, key=lambda i: _est_tokens(new_messages[i]))
        msg = new_messages[longest]
        content = msg.get("content")
        if isinstance(content, str) and len(content) > 1:
            keep = max(1, len(content) // 2)
            msg["content"] = content[:keep] + "\n...[context trimmed]"
        else:
            candidates = [i for i in candidates if i != longest]
    new_payload = dict(payload)
    new_payload["messages"] = new_messages
    return new_payload


def _read_sse_stream(response, flavor: str) -> tuple:
    """逐行读 SSE 并拼接文本，同时采集埋点。返回 (text, telemetry)。

    - ttfb_ms：首个 SSE 行到达耗时，用于区分「排队慢」与「生成慢」；
    - chunk_count：实际贡献文本的 chunk 数，为 0 说明流式没吐出内容。
    """
    extract, is_done = _SSE_FLAVORS.get(flavor) or _SSE_FLAVORS["openai"]
    finish_of = _SSE_FINISH.get(flavor) or _sse_finish_openai
    alt = _SSE_ALT.get(flavor)
    started = time.perf_counter()
    deadline = started + LLM_TOTAL_TIMEOUT
    text = ""
    alt_text = ""
    ttfb_ms = 0
    chunk_count = 0
    finish_reason = ""
    for raw in response.iter_lines():
        if time.perf_counter() > deadline:
            raise TimeoutError(f"LLM stream exceeded total timeout {LLM_TOTAL_TIMEOUT}s")
        if not raw:
            continue
        line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        line = line.strip()
        if not ttfb_ms:
            ttfb_ms = int((time.perf_counter() - started) * 1000)
        if not line.startswith("data:"):
            # event: / 注释行不承载文本
            continue
        body = line[5:].strip()
        if not body:
            continue
        if body == "[DONE]":
            break
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        if is_done(obj):
            # 停止原因必须在这里抓取：一旦 break 就再也拿不到这一帧了。
            finish_reason = finish_of(obj) or ""
            break
        piece = extract(obj) or ""
        if piece:
            chunk_count += 1
            # 兼容两种 provider 语义：增量片段，或每段回传「至今累积全文」。
            if text and piece.startswith(text):
                text = piece
            else:
                text += piece
        if alt is not None:
            alt_piece = alt(obj) or ""
            if alt_piece:
                if alt_text and alt_piece.startswith(alt_text):
                    alt_text = alt_piece
                else:
                    alt_text += alt_piece
    telemetry = {
        "ttfb_ms": ttfb_ms,
        "chunk_count": chunk_count,
        "streamed": True,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        # 上层据此走「修复 / 抢救」而不是当成空结论。
        "finish_reason": finish_reason,
        # 备用文本流（推理模型思维链）；调用方取用后应 pop，避免大文本进埋点/元数据。
        "reasoning_text": alt_text,
    }
    return text, telemetry


def request_chat_completion(
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any],
    flavor: str = "openai",
    *,
    provider: str = "",
    enable_cache: bool = True,
    prompt_version: str = "",
    cache_salt: str = "",
    force_stream: Optional[bool] = None,
) -> tuple:
    """统一 chat completion 入口：优先 SSE 流式，返回 (result_json, text, telemetry)。

    - 流式命中：result_json 为 None、text 为拼接后的完整文本；
    - provider 返回普通 JSON（不支持 stream / 开关关闭）：result_json 为解析后的 dict、
      text 为空串，调用方按原有一次性语义取值。

    所有 provider 客户端共用此入口，保证超时语义与埋点口径一致。


    - 全局并发闸门（P0-1）：无论哪个 stage 发起，都在这里取票，瞬时并发不再叠加；
    - prompt→response 缓存（P0-3）：指纹命中直接返回，反复调试不再重复烧算力；
    - 模型能力适配：按画像把 max_tokens 压到模型上限内，避免把小模型的输出预算打爆。
    """
    started = time.perf_counter()
    telemetry = {
        "ttfb_ms": 0, "chunk_count": 0, "streamed": False, "elapsed_ms": 0, "finish_reason": "",
        "trimmed": False,
    }

    # ---- 模型能力适配：把 max_tokens 压到模型上限内 ----
    model_name = str(payload.get("model") or "")
    try:
        from ..core.model_capabilities import resolve_profile, clamp_max_tokens
        profile = resolve_profile(model=model_name, provider=provider)
        if payload.get("max_tokens") is not None:
            payload = dict(payload)
            payload["max_tokens"] = clamp_max_tokens(profile, payload.get("max_tokens"))
        # Ollama 原生端点真正读的是 options.num_predict，顶层 max_tokens 它不认识（会被忽略）。
        # 只钳顶层会造成「画像以为上限 1024、模型却按 4096 生成」的两套口径，必须一起钳。
        if isinstance(payload.get("options"), dict) and payload["options"].get("num_predict") is not None:
            payload = dict(payload)
            options = dict(payload["options"])
            options["num_predict"] = clamp_max_tokens(profile, options.get("num_predict"))
            payload["options"] = options
        if not profile.supports_stream:
            use_stream = False
        else:
            use_stream = _llm_stream_enabled()
        telemetry["profile"] = profile.name
        telemetry["tier"] = profile.tier
    except Exception:
        use_stream = _llm_stream_enabled()
        profile = None  # type: ignore

    # provider 可以强制关流式：Ollama 原生端点的流式是 NDJSON（每行一个 JSON、无 "data:" 前缀），
    # 与 _read_sse_stream 的 SSE 解析不兼容，必须走一次性响应。
    if force_stream is not None:
        use_stream = bool(force_stream)

    # 最长非系统消息，保住 system + 首条消息（通常是任务上下文骨架）。默认 0 = 关闭，
    # 不裁剪、不改写任何提示词，扫描行为完全不变。命中后只在 telemetry 打 trimmed 标记，便于观测。 ----
    max_input_tokens = int(os.environ.get("SAST_AI_MAX_INPUT_TOKENS", "0") or 0)
    if max_input_tokens > 0 and payload.get("messages") is not None:
        payload = _trim_messages_to_budget(payload, max_input_tokens)
        telemetry["trimmed"] = True

    # ---- 缓存 + 提示词指纹（prompt_hash 进埋点，便于按提示词版本归因） ----
    cache_key = ""
    temperature = payload.get("temperature")
    temperature = 0.0 if temperature is None else float(temperature)
    cacheable = bool(
        enable_cache
        and temperature <= _CACHEABLE_TEMPERATURE_MAX
        and str(payload.get("stream") or "") != "True"
    )
    if enable_cache and payload.get("messages") is not None:
        try:
            from ..core import llm_cache
            cache_key = llm_cache.build_cache_key(
                provider=provider,
                model=model_name,
                messages=payload.get("messages"),
                system=str(payload.get("system") or ""),
                temperature=temperature,
                max_tokens=int(payload.get("max_tokens") or 0),
                prompt_version=prompt_version,
                extra=cache_salt,
            )
            if cacheable:
                cached = llm_cache.get(cache_key)
                if cached is not None:
                    cached_text, cached_tele = cached
                    cached_tele["cached"] = True
                    cached_tele["provider"] = provider
                    cached_tele["prompt_hash"] = cache_key
                    return None, cached_text, cached_tele
        except Exception as exc:  # fail-open：缓存问题绝不能影响主流程
            logger.debug("[LLM] 缓存读取异常（忽略）：%s", exc)

    timeout = (LLM_CONNECT_TIMEOUT, LLM_IDLE_TIMEOUT if use_stream else LLM_READ_TIMEOUT)
    body = _prepare_stream_payload(flavor, payload) if use_stream else payload
    response = None

    # ---- 全局并发闸门（P0-1）：所有 stage 的调用都在这里汇合排队 ----
    try:
        from ..core.llm_gate import get_gate
        gate = get_gate()
        if profile is not None:
            gate.configure_for_concurrency(profile.recommended_concurrency)
        gate_ctx = gate.acquire(timeout=_GATE_WAIT_TIMEOUT)
    except Exception:  # 闸门自身异常不应阻断调用
        import contextlib
        gate_ctx = contextlib.nullcontext(True)

    with gate_ctx as admitted:
        if not admitted:
            raise TimeoutError(
                f"LLM gate busy: no slot within {_GATE_WAIT_TIMEOUT}s "
                f"(queue depth high — lower stage concurrency or raise SAST_AI_LLM_GATE_CONCURRENCY)"
            )
        try:
            response = requests.post(
                url, headers=headers, json=body, timeout=timeout, stream=use_stream
            )
            if response.status_code != 200:
                try:
                    detail = response.text[:500]
                except Exception:
                    detail = ""
                raise RuntimeError(f"API error: {response.status_code} - {detail}")
            ctype = ""
            try:
                ctype = (response.headers.get("content-type") or "").lower()
            except Exception:
                ctype = ""
            if use_stream and "text/event-stream" in ctype:
                text, telemetry = _read_sse_stream(response, flavor)
                if not telemetry.get("finish_reason"):
                    telemetry["finish_reason"] = ""
                telemetry["prompt_hash"] = cache_key
                _store_cache(cache_key, text, provider, model_name, telemetry)
                return None, text, telemetry
            try:
                result = response.json()
            except ValueError as exc:
                raise RuntimeError(f"API error: non-JSON response - {exc}") from exc
            telemetry["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
            telemetry["finish_reason"] = _extract_finish_reason(result, flavor)
            telemetry["prompt_hash"] = cache_key
            # 永远享受不到 P0-3 缓存。这里补写；text 仍按原契约返回空串，调用方零改动。
            _store_cache(cache_key, _extract_text(result, flavor), provider, model_name, telemetry)
            return result, "", telemetry
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass


CLAUDE_SETTINGS_FILE_MAP = {
    "default": "settings.json",
    "qwen": "settings.json.qwen",
    "doubao": "settings.json.doubao",
    "minimax": "settings.json.minimax",
}


def _resolve_claude_settings_dir(settings_dir: Optional[str] = None) -> Path:
    if settings_dir:
        return Path(settings_dir)
    return Path.home() / ".claude"


def _candidate_claude_settings_files(source: str = "auto", settings_dir: Optional[str] = None) -> List[Path]:
    base_dir = _resolve_claude_settings_dir(settings_dir)
    normalized = (source or "auto").strip().lower()

    if normalized in CLAUDE_SETTINGS_FILE_MAP:
        return [base_dir / CLAUDE_SETTINGS_FILE_MAP[normalized]]

    if normalized not in {"", "auto"}:
        candidate = Path(source)
        if not candidate.is_absolute():
            candidate = base_dir / source
        return [candidate]

    ordered = ["qwen", "doubao", "minimax", "default"]
    return [base_dir / CLAUDE_SETTINGS_FILE_MAP[item] for item in ordered]


def load_anthropic_compatible_config(
    configured: Optional[Dict] = None,
    source: str = "auto",
    settings_dir: Optional[str] = None,
) -> Dict[str, str]:
    configured = configured or {}
    direct_key = configured.get("api_key", "") or configured.get("auth_token", "")
    direct_base_url = configured.get("base_url", "")
    direct_model = configured.get("model", "")
    direct_auth_mode = configured.get("auth_mode", "auto")

    if direct_key and direct_base_url:
        return {
            "api_key": direct_key,
            "base_url": direct_base_url,
            "model": direct_model or "claude-3-5-sonnet-20241022",
            "auth_mode": direct_auth_mode or "auto",
            "source": "config",
        }

    chosen_source = configured.get("source", source or "auto")
    chosen_dir = configured.get("settings_dir", settings_dir)
    for candidate in _candidate_claude_settings_files(chosen_source, chosen_dir):
        if not candidate.exists():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        env = data.get("env", {})
        api_key = env.get("ANTHROPIC_AUTH_TOKEN", "")
        base_url = env.get("ANTHROPIC_BASE_URL", "")
        model = env.get("ANTHROPIC_MODEL", "")
        if api_key and base_url:
            return {
                "api_key": api_key,
                "base_url": base_url,
                "model": configured.get("model", "") or model or "claude-3-5-sonnet-20241022",
                "auth_mode": configured.get("auth_mode", "auto") or "auto",
                "source": str(candidate),
            }

    return {}


def build_client(provider: str, model: str, api_key: str, base_url: str = "") -> Any:
    """ModelGateway 远程分发入口：provider → 具体客户端实现。

    供 ``src.core.model_gateway.ModelGateway._remote_complete`` 调用。
    - glm / zhipu / anthropic-compatible：智谱 GLM 系列，走 Anthropic-compatible 网关
      （base_url 默认 ``https://open.bigmodel.cn/api/anthropic``，auth_mode=x-api-key）。
    - 其余 provider 沿用既有客户端实现。
    未知 provider 抛 RuntimeError，由网关降级离线。
    """
    provider = (provider or "").strip().lower()
    if provider in ("glm", "zhipu"):
        provider = "anthropic-compatible"
    if provider == "anthropic":
        return AnthropicClient(api_key=api_key, model=model or "claude-sonnet-4-6")
    if provider == "anthropic-compatible":
        base = base_url or "https://open.bigmodel.cn/api/anthropic"
        return AnthropicCompatibleClient(
            api_key=api_key,
            model=model or "glm-4.5-air",
            base_url=base,
            auth_mode="x-api-key",
        )
    if provider == "qwen":
        return QwenClient(api_key=api_key, model=model or "qwen-plus")
    if provider == "doubao":
        return DoubaoClient(api_key=api_key, model=model or "doubao-pro-32k", base_url=base_url)
    if provider == "minimax":
        return MiniMaxClient(api_key=api_key, model=model or "abab6.5s-chat", base_url=base_url)
    if provider == "deepseek":
        return DeepseekClient(
            api_key=api_key,
            model=model or "Deepseek-V4-Flash",
            base_url=base_url,
            thinking_intensity="medium",
        )
    if provider in ("agnes", "openai-compatible", "openai"):
        # 通用 OpenAI 兼容网关（agnes-ai 等）。base_url 缺省指向 agnes-ai apihub。
        return OpenAIChatClient(
            api_key=api_key,
            model=model or "agnes-3.0-flash",
            base_url=base_url or "https://apihub.agnes-ai.com/v1",
        )
    if provider in ("ollama", "ollama-native"):
        # 本地 Ollama 原生端点（/api/chat）。ModelGateway 远程分发也可用。
        return OllamaNativeClient(
            api_key=api_key or "ollama",
            model=model or "qwen3:8b",
            base_url=base_url or "http://127.0.0.1:11434",
        )
    raise RuntimeError(f"unsupported model provider: {provider}")


def _provider_conf(conf, provider: str) -> Dict:
    """Tolerant provider-subconfig getter.

    兼容两种配置形态：
    - 全局 Config 对象：provider 子配置位于顶层（config.get('deepseek')）。
    - A2 pipeline 传入的 agent_config 字典：provider 子配置位于 'api' 下
      （config.get('api').get('deepseek')）。
    优先取顶层，缺失再回退到 'api' 子层。
    """
    try:
        top = conf.get(provider, {}) or {}
    except Exception:
        top = {}
    if isinstance(top, dict) and top:
        return top
    try:
        api = conf.get("api", {}) or {}
    except Exception:
        api = {}
    if isinstance(api, dict):
        sub = api.get(provider, {}) or {}
        if isinstance(sub, dict):
            return sub
    return {}


def _make_client(provider: str, conf=None):
    """按 provider 名从配置构造单个具体客户端；未配置/缺 key 返回 None。"""
    conf = conf if conf is not None else config
    provider = (provider or "").strip().lower()
    if provider == "anthropic-compatible":
        compat = load_anthropic_compatible_config(configured=_provider_conf(conf, "anthropic_compatible"))
        if not compat:
            return None
        return AnthropicCompatibleClient(
            api_key=compat["api_key"],
            model=compat.get("model", "glm-4.5-air"),
            base_url=compat["base_url"],
            auth_mode=compat.get("auth_mode", "auto"),
        )
    if provider == "deepseek":
        pc = _provider_conf(conf, "deepseek")
        api_key = pc.get("api_key", "")
        base_url = pc.get("base_url", "")
        if not (api_key and base_url):
            return None
        return DeepseekClient(
            api_key=api_key,
            model=pc.get("model", "Deepseek-V4-Flash"),
            base_url=base_url,
            thinking_intensity=pc.get("thinking_intensity", "medium"),
        )
    if provider in ("agnes", "openai-compatible", "openai"):
        pc = _provider_conf(conf, "agnes")
        api_key = pc.get("api_key", "")
        if not api_key:
            return None
        return OpenAIChatClient(
            api_key=api_key,
            model=pc.get("model", "agnes-3.0-flash"),
            base_url=pc.get("base_url", "") or "https://apihub.agnes-ai.com/v1",
        )
    if provider == "qwen":
        pc = _provider_conf(conf, "qwen")
        api_key = pc.get("api_key", "")
        if not api_key:
            return None
        client = QwenClient(api_key=api_key, model=pc.get("model", "qwen-plus"))
        base_url = pc.get("base_url", "")
        if base_url:
            client.base_url = base_url.rstrip("/")
        return client
    if provider == "doubao":
        pc = _provider_conf(conf, "doubao")
        api_key = pc.get("api_key", "")
        base_url = pc.get("base_url", "")
        if not (api_key and base_url):
            return None
        return DoubaoClient(api_key=api_key, model=pc.get("model", "doubao-pro-32k"), base_url=base_url)
    if provider == "minimax":
        pc = _provider_conf(conf, "minimax")
        api_key = pc.get("api_key", "")
        base_url = pc.get("base_url", "")
        if not (api_key and base_url):
            return None
        return MiniMaxClient(api_key=api_key, model=pc.get("model", "abab6.5s-chat"), base_url=base_url)
    if provider in ("ollama", "ollama-native"):
        # 本地 Ollama：不需要 api_key（服务默认无鉴权），走原生 /api/chat。
        pc = _provider_conf(conf, "ollama")
        return OllamaNativeClient(
            api_key=pc.get("api_key", "") or "ollama",
            model=pc.get("model", "qwen3:8b"),
            base_url=pc.get("base_url", "") or "http://127.0.0.1:11434",
            num_ctx=pc.get("num_ctx"),
            keep_alive=pc.get("keep_alive", ""),
            think=pc.get("think"),
        )
    if provider == "claude":
        pc = _provider_conf(conf, "claude")
        api_key = pc.get("api_key", "")
        if not api_key:
            return None
        return AnthropicClient(api_key=api_key, model=pc.get("model", "claude-sonnet-4-6"))
    return None


def _record_model_run(
    *,
    provider: str,
    model: str = "",
    base_url: str = "",
    status: str = "completed",
    latency_ms: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    input_summary: str = "",
    output_summary: str = "",
    error_message: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    stage: str = "",
    prompt_hash: str = "",
) -> None:
    """P2-1：A2 直接持有的 LLM 客户端调用出口埋点，写 model_runs 台账。

    只由 ModelGateway 调用方写入，A2 全部 LLM 调用（含 glm-4-flash 4 条 120s 读超时被
    logger.error 吞掉）对 DB 完全不可见。此处复用 ModelRunRepository.record 补埋点，
    成功与失败都记，provider/base_url 放 metadata。fail-open：写失败仅 debug，不影响主流程。
    """
    # FallbackLLMClient 并调 create_message 时，会往生产库 data/app.db 的 model_runs
    # 写入 provider=deepseek/glm 的假行。这些行虽无网络调用、
    # 无费用，但会破坏「id 水位线判是否有云端混入」的口径。测试置 1 即完全静音。
    if os.environ.get("SAST_AI_DISABLE_MODEL_RUN_LOG", "").strip() not in ("", "0", "false", "False"):
        return
    try:
        from src.infrastructure.db import Database as _DB
        from src.infrastructure.repositories import ModelRunRepository as _MRR
        db = _DB(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        meta = dict(metadata or {})
        meta.setdefault("provider", provider)
        if base_url:
            meta.setdefault("base_url", base_url)
        _MRR(db).record(
            purpose="a2-semantic",
            model=model or provider,
            status=status,
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            latency_ms=int(latency_ms),
            input_summary=str(input_summary or "")[:200],
            output_summary=str(output_summary or "")[:200],
            error_message=str(error_message or "")[:300],
            metadata=meta,
            stage=stage or "a2-semantic",
            prompt_hash=prompt_hash or "",
        )
    except Exception as _e:
        logger.debug("[A2] model_runs 埋点失败（忽略）：%s", _e)


class FallbackLLMClient:
    """调用级顺序降级客户端。

    持有多个具体客户端（按优先级排序）。每次 create_message 先试第一个；
    若抛异常（额度耗尽 429 / 鉴权失败 401,403 / 网络错误等）则自动尝试下一个，
    实现「主用 provider 先用，用完/失败自动切兜底」。全部失败才抛出最后一个异常。

    额度/鉴权类错误触发冷却（默认 300s），期间不再对该 provider 浪费请求；
    冷却结束后周期重试，覆盖额度恢复的情况。
    """

    def __init__(self, clients, provider_names=None, cooldown: float = 300.0, prompt_version: str = "", max_attempts: Optional[int] = None):
        self.clients = list(clients)
        self.provider_names = list(provider_names or ["unknown"] * len(self.clients))
        self._cooldown = float(cooldown)
        # 消除「每 provider 重试 3 次 × N provider」的 6 倍物理请求放大。None 时回落 3。
        self._max_attempts = max_attempts
        self._unhealthy_until = {}
        self.last_used = None
        # D5：prompt 版本标签，写进 model_runs.metadata 便于按版本分组观测
        self.prompt_version = prompt_version or ""
        # C2：最近一次调用的流式埋点（ttfb_ms / chunk_count / streamed / elapsed_ms），
        # 由本次成功的子客户端透传上来，供 A2/AP 与网关观测「流式是否消灭了读超时 fail-open」。
        self.last_call_telemetry = {}

    @staticmethod
    def _is_quota_or_auth(exc) -> bool:
        msg = str(exc).lower()
        return any(tok in msg for tok in (
            "401", "403", "429", "quota", "insufficient", "expired",
            "invalid api", "authentication", "credit", "rate limit",
        ))

    @staticmethod
    def _is_timeout_error(exc) -> bool:
        msg = str(exc).lower()
        return any(tok in msg for tok in (
            "timed out", "timeout", "readtimeout", "connecttimeout",
        ))

    def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
        now = time.time()
        last_error = None
        for idx, client in enumerate(self.clients):
            name = self.provider_names[idx] if idx < len(self.provider_names) else "?"
            until = self._unhealthy_until.get(name, 0.0)
            if until and now < until:
                continue  # 已知额度/鉴权不可用，冷却期跳过，避免浪费请求
            # 修复：timeout 60→90s（5 处 client），重试 2→3 次，重试间退避避开瞬时拥堵。
            _input_chars = len(str(system or ""))
            if isinstance(messages, list):
                _input_chars += sum(
                    len(str(m.get("content") or "")) for m in messages if isinstance(m, dict)
                )
            else:
                _input_chars += len(str(messages))
            _prompt_preview = (
                " ".join(str(m.get("content") or "") for m in messages if isinstance(m, dict))
                if isinstance(messages, list) else str(messages)
            )[:200]
            _input_tokens_est = max(1, (_input_chars + 3) // 4)
            # P1-8：重试上限按画像收窄，弱模型（max_attempts=1）不再做 3 次空转重试。
            _attempts = int(self._max_attempts or 3)
            for _attempt in range(1, _attempts + 1):
                _started = time.perf_counter()
                _telemetry: Dict[str, Any] = {}  # 失败路径也可能读它（prompt_hash），先置空
                try:
                    result = client.create_message(
                        system, messages, max_tokens=max_tokens, temperature=temperature
                    )
                    _latency_ms = int((time.perf_counter() - _started) * 1000)
                    # C2：透传子客户端的流式埋点（去掉备用文本流，避免大文本入埋点）
                    _telemetry = dict(getattr(client, "last_call_telemetry", {}) or {})
                    _telemetry.pop("reasoning_text", None)
                    self.last_call_telemetry = _telemetry
                    if _telemetry.get("streamed"):
                        logger.info(
                            "[FallbackLLMClient][stream] provider=%s ttfb=%sms chunks=%s elapsed=%sms",
                            name, _telemetry.get("ttfb_ms", 0),
                            _telemetry.get("chunk_count", 0), _latency_ms,
                        )
                    # P2-1：成功也记 model_runs（此前 A2 调用对 DB 完全不可见）
                    # 真实计数优先：Ollama 原生端点会给 prompt_eval_count/eval_count（真值），
                    # 其余 provider 没有 usage 透传，只能沿用按字符数 //4 的估算。
                    _real_in = int(_telemetry.get("input_tokens") or 0)
                    _real_out = int(_telemetry.get("output_tokens") or 0)
                    _record_model_run(
                        provider=name,
                        model=str(getattr(client, "model", "") or ""),
                        base_url=str(getattr(client, "base_url", "") or ""),
                        status="completed",
                        latency_ms=_latency_ms,
                        input_tokens=_real_in or _input_tokens_est,
                        output_tokens=_real_out or max(1, (len(str(result or "")) + 3) // 4),
                        input_summary=_prompt_preview,
                        output_summary=str(result or "")[:200],
                        metadata={
                            "attempt": _attempt,
                            "fallback_index": idx,
                            "ttfb_ms": _telemetry.get("ttfb_ms", 0),
                            "chunk_count": _telemetry.get("chunk_count", 0),
                            "streamed": bool(_telemetry.get("streamed", False)),
                            "prompt_version": self.prompt_version or getattr(client, "prompt_version", "") or "",
                            # 落库时丢掉，于是「LLM 变慢了」只能靠延迟分位数反推
                            # 而非 GPU/推理退化）。显式落库后命中率可直接查，不必再猜。
                            "cached": bool(_telemetry.get("cached", False)),
                        },
                        prompt_hash=_telemetry.get("prompt_hash", ""),
                    )
                    self.last_used = name
                    if idx != 0:
                        logger.warning("[FallbackLLMClient] 主用不可用，已由兜底 provider [%s] 提供服务", name)
                    return result
                except Exception as e:
                    _latency_ms = int((time.perf_counter() - _started) * 1000)
                    last_error = e
                    # P2-1：失败也记 model_runs（本轮 4 条读超时仅 logger.error，无痕）
                    _record_model_run(
                        provider=name,
                        model=str(getattr(client, "model", "") or ""),
                        base_url=str(getattr(client, "base_url", "") or ""),
                        status="error",
                        latency_ms=_latency_ms,
                        input_tokens=_input_tokens_est,
                        error_message=str(e),
                        input_summary=_prompt_preview,
                        metadata={"attempt": _attempt, "fallback_index": idx},
                        prompt_hash=_telemetry.get("prompt_hash", ""),
                    )
                    if _attempt < _attempts and self._is_timeout_error(e) and not self._is_quota_or_auth(e):
                        _backoff = 3 * _attempt
                        logger.warning(
                            "[FallbackLLMClient] provider [%s] 读超时（%ds），退避 %ds 后第 %d 次重试：%s",
                            name, _latency_ms // 1000, _backoff, _attempt + 1, e
                        )
                        time.sleep(_backoff)
                        continue
                    break
            if last_error is not None and self._is_quota_or_auth(last_error):
                self._unhealthy_until[name] = now + self._cooldown
                logger.warning(
                    "[FallbackLLMClient] provider [%s] 额度/鉴权失败，冷却 %.0fs：%s", name, self._cooldown, last_error
                )
            else:
                logger.warning("[FallbackLLMClient] provider [%s] 调用异常，尝试下一个：%s", name, last_error)
            continue
        raise last_error or RuntimeError("all LLM providers failed")


class AnthropicClient:
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "anthropic"
    """简单的 Anthropic API 客户端"""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1"

    def _messages_endpoint(self) -> str:
        base_url = self.base_url.rstrip("/")
        if base_url.endswith("/v1"):
            return f"{base_url}/messages"
        return f"{base_url}/v1/messages"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """调用 Claude API。

        C2：内部优先走 SSE 流式（超时语义改为 chunk idle），对外仍返回完整字符串，
        所有调用方零改动。埋点存于 self.last_call_telemetry（ttfb_ms / chunk_count）。
        """
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": messages
        }

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            self._messages_endpoint(), headers, payload, flavor="anthropic",
            provider=self._PROVIDER_NAME,
        )
        self.last_call_telemetry = telemetry
        if text:
            return text
        return result["content"][0]["text"]


class AnthropicCompatibleClient(AnthropicClient):
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "anthropic-compatible"
    """Anthropic-compatible gateway client with flexible auth headers."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        base_url: Optional[str] = None,
        auth_mode: str = "auto",
    ):
        super().__init__(api_key=api_key, model=model)
        self.base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")
        self.auth_mode = (auth_mode or "auto").lower()

    def _headers_for_mode(self, mode: str) -> Dict[str, str]:
        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        if mode == "bearer":
            headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            headers["x-api-key"] = self.api_key
        return headers

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": messages,
        }

        modes = [self.auth_mode] if self.auth_mode in {"bearer", "x-api-key"} else ["bearer", "x-api-key"]
        last_error = None

        self.last_call_telemetry = {}
        for mode in modes:
            try:
                result, text, telemetry = request_chat_completion(
                    self._messages_endpoint(),
                    self._headers_for_mode(mode),
                    payload,
                    flavor="anthropic",
                    provider=self._PROVIDER_NAME,
                )
            except Exception as exc:
                # 仅鉴权类错误（401/403）才换下一种 auth 方式重试，其余按原语义直接失败。
                last_error = str(exc)
                if "API error: 401" in last_error or "API error: 403" in last_error:
                    continue
                raise
            self.last_call_telemetry = telemetry
            if text:
                return text
            return result["content"][0]["text"]

        raise Exception(last_error or "API error: anthropic-compatible request failed")


class QwenClient:
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "qwen"
    """Qwen API 客户端 (阿里云)"""

    def __init__(self, api_key: str, model: str = "qwen-plus"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://dashscope.aliyuncs.com/api/v1"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """调用 Qwen API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # 将 system 转换为 user 消息
        all_messages = [{"role": "system", "content": system}]
        for msg in messages:
            all_messages.append(msg)

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": all_messages
        }

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            f"{self.base_url}/services/aigc/text-generation/generation",
            headers,
            payload,
            flavor="qwen",
            provider=self._PROVIDER_NAME,
        )
        self.last_call_telemetry = telemetry
        if text:
            return text
        return result["output"]["choices"][0]["message"]["content"]


class DoubaoClient:
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "doubao"
    """豆包 API 客户端 (字节跳动/火山引擎)"""

    def __init__(self, api_key: str, model: str = "doubao-pro-32k", base_url: str = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or "https://ark.cn-beijing.volces.com/api/v3"
        # 确保 base_url 包含 /v1
        if "/v1" not in self.base_url:
            self.base_url = self.base_url.rstrip('/') + "/v1"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """调用豆包 API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # 将 system 转换为 user 消息
        all_messages = [{"role": "system", "content": system}]
        for msg in messages:
            all_messages.append(msg)

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": all_messages
        }

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            f"{self.base_url}/chat/completions",
            headers,
            payload,
            flavor="openai",
            provider=self._PROVIDER_NAME,
        )
        self.last_call_telemetry = telemetry
        if text:
            return text
        return result["choices"][0]["message"]["content"]


class MiniMaxClient:
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "minimax"
    """MiniMax API 客户端"""

    def __init__(self, api_key: str, model: str = "abab6.5s-chat", base_url: str = None):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or "https://api.minimax.chat"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        """调用 MiniMax API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        # 将 system 转换为 user 消息
        all_messages = [{"role": "system", "content": system}]
        for msg in messages:
            all_messages.append(msg)

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": all_messages
        }

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            f"{self.base_url}/v1/text/chatcompletion_v2",
            headers,
            payload,
            flavor="openai",
            provider=self._PROVIDER_NAME,
        )
        self.last_call_telemetry = telemetry
        if text:
            return text
        # 检查余额（仅一次性 JSON 响应带 base_resp；流式分块不含该字段）
        if result.get('base_resp', {}).get('status_code') == 1008:
            raise Exception("MiniMax API: Insufficient balance")

        return result["choices"][0]["message"]["content"]


class DeepseekClient:
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "deepseek"
    """Deepseek (OpenAI 兼容) 客户端。

    用于 OpenAI 兼容网关。部分网关的 WAF 会拦截 Python-urllib 默认 UA（HTTP 403），
    但对 requests 默认 UA 及浏览器 UA 放行，故此处强制带浏览器 UA 提升鲁棒性。模型为推理型（响应含 reasoning_content），
    若最终 content 为空则兜底取 reasoning_content，避免 A2 解析到空串导致 0 产出。
    """

    BROWSER_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    def __init__(self, api_key: str, model: str = "Deepseek-V4-Flash", base_url: str = None,
                 thinking_intensity: str = "medium", max_tokens: int = 4096):
        self.api_key = api_key
        self.model = model
        self.thinking_intensity = thinking_intensity
        self.max_tokens = max_tokens
        self.base_url = (base_url or "https://api.deepseek.com/v1").rstrip("/")
        if not self.base_url.endswith("/v1"):
            self.base_url = self.base_url.rstrip("/") + "/v1"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 4096, temperature: float = 0.0) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.BROWSER_HEADERS)

        all_messages = [{"role": "system", "content": system}]
        for msg in messages:
            all_messages.append(msg)

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": all_messages,
        }
        # 思考强度（仅在该网关支持的模型上生效；不支持时网关忽略，不报错）
        if self.thinking_intensity:
            payload["thinking_intensity"] = self.thinking_intensity

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            f"{self.base_url}/chat/completions",
            headers,
            payload,
            flavor="openai",
            provider=self._PROVIDER_NAME,
        )
        # 备用文本流（推理模型思维链）只在此处消费，不进埋点，避免大文本污染元数据
        reasoning = telemetry.pop("reasoning_text", "") or ""
        self.last_call_telemetry = telemetry
        if text:
            return text.strip()
        if result is not None:
            msg = result["choices"][0]["message"]
            content = (msg.get("content") or "").strip()
            # 推理型模型 content 可能为空（reasoning 耗尽 token），兜底取 reasoning_content
            if not content:
                content = (msg.get("reasoning_content") or "").strip()
            return content
        # 流式且正文为空（reasoning 耗尽 token）：沿用原「回退思维链」语义。
        return reasoning.strip()


class OpenAIChatClient(DeepseekClient):
    # provider 标识：进缓存指纹与 model_capabilities 画像解析
    _PROVIDER_NAME = "openai-compatible"
    """通用 OpenAI 兼容客户端（Bearer 鉴权 + /chat/completions）。

    2026-09-14 接入 agnes-ai（https://apihub.agnes-ai.com/v1）：OpenAI 风格接口，文本模型
    agnes-3.0-flash 为当前免费且性能最好的一档（实测 16-41 token/s，支持 system 消息，
    输出 JSON 可能带 ```json 围栏——上游已有剥围栏逻辑）。与 DeepseekClient 的差别仅在
    不发送 thinking_intensity（agnesi 网关无该字段），其余复用。
    """

    def __init__(self, api_key: str, model: str = "agnes-3.0-flash", base_url: str = None,
                 max_tokens: int = 4096):
        super().__init__(api_key=api_key, model=model, base_url=base_url,
                         thinking_intensity="", max_tokens=max_tokens)


def _ollama_usage(result: Any) -> Dict[str, int]:
    """把 Ollama 原生端点的真实 token 计数抬到埋点层。

    原生端点**没有** usage 字段，计数在 prompt_eval_count / eval_count。上游 FallbackLLMClient
    对 tokens 是按字符数 //4 估算的，本地模型上偏差明显；有真实计数时以真实计数为准。
    """
    if not isinstance(result, dict):
        return {}
    usage: Dict[str, int] = {}
    prompt_tokens = result.get("prompt_eval_count")
    completion_tokens = result.get("eval_count")
    if isinstance(prompt_tokens, int) and prompt_tokens > 0:
        usage["input_tokens"] = prompt_tokens
    if isinstance(completion_tokens, int) and completion_tokens > 0:
        usage["output_tokens"] = completion_tokens
    return usage


class OllamaNativeClient:
    """Ollama 原生 ``/api/chat`` 客户端 —— 唯一能让 qwen3 家族稳定吐出正文的调用方式。

    Qwen3 是思考型模型，Ollama 的 OpenAI 兼容层**不认** think:false——请求体里的 think 被忽略、
    Modelfile 的 ``PARAMETER think false`` 直接报 unknown parameter、``chat_template_kwargs.thinking``
    同样无效。于是思维链与正文争抢同一个输出预算，实测同一提示词：

        max_tokens=100 → done/ finish_reason=length, content 长度 0    （思考吃满，正文一个字没有）
        max_tokens=200 → finish_reason=length, content 长度 0
        max_tokens=300 → finish_reason=length, content 长度 0
        max_tokens=600 → finish_reason=stop,   content 长度 79          （思考耗约 360 token 后才轮到正文）

    也就是说「/v1 返回全空 content」不是无条件成立，而是**输出预算不足时的确定性退化**；A2 的审计
    提示词比这个样例长、引发的思考也更长，所以线上更容易撞上。另一个代价是速度：同题 /v1 的
    completion_tokens 约 360，原生端点 think:false 只有约 31，输出量差一个数量级——对并发 2、
    约 53 tok/s 的本地 8B，就是近 10 倍的墙钟差异。

    因此本客户端固定走原生端点并强制：
    - ``think``：默认关闭（``think=False``）。这不是「图省事」，而是实测结论下的一条硬取舍，
      见下节「think 取值的实测依据」；
    - ``stream: false``：原生流式是 NDJSON（每行一个 JSON、无 ``data:`` 前缀），与项目的
      ``_read_sse_stream`` 不兼容；文档实测单条约 3.5s，也没有流式的必要。

    每个样本都刻意混了「漏洞方法 + 白名单校验的安全方法」，所以误报可测）：

        think=false np=1024 : 命中 4/4，漏报 0，总耗时 31.7s， 总输出 790 token
        think=true  np=1024 : 命中 0/4，漏报 4，总耗时 160.5s，总输出 4096 token（预算被思考吃满）
        think=true  np=3072 : 命中 3/4，漏报 1，总耗时 149.1s，总输出 3802 token

    think=true 组的 1024/3072 两组其实被画像钳制成同一档（输出上限 1024），所以 0/4 与 3/4 的
    差异来自逐次波动的思考长度：思考在 818~1024 token 之间浮动，一旦超过预算就出现
    content 长度为 0（SSRF 那次就是全空），答案直接丢失。放开预算后：
    SQL 文件 28.9s / eval=730、XSS 文件 52.0s / eval=1278，约 25 tok/s —— 比 think=false
    慢 4.5~5.3 倍。按全量 1232 次调用、并发 2 估算：think=false 约 1.9h，think=true 约 6.8h。

    结论：本任务（结构化判定 + 严格 JSON 输出）在 8B 上**关闭思考更准、更稳、快 5 倍**，
    且没有任何证据表明思考提升了检出质量。因此默认 false；需要试验时由
    ``ollama.think`` 配置或画像的 ``use_thinking`` 打开，但必须同时把输出上限抬到 3000+，
    否则会退化成本文件开头描述的「content 全空」。
    """

    _PROVIDER_NAME = "ollama"

    def __init__(self, api_key: str = "ollama", model: str = "qwen3:8b",
                 base_url: str = "http://127.0.0.1:11434", num_ctx: Optional[int] = None,
                 keep_alive: str = "", think: Optional[bool] = None):
        self.api_key = api_key or "ollama"
        self.model = model
        base = (base_url or "http://127.0.0.1:11434").rstrip("/")
        # 容忍误把 OpenAI 兼容地址填进来：/v1 结尾会被剥掉，避免拼出 /v1/api/chat
        if base.endswith("/v1"):
            base = base[:-3].rstrip("/")
        self.base_url = base
        self.num_ctx = int(num_ctx) if num_ctx else None
        # 空串会让客户端不发该字段 ⇒ 服务端按 Forever 处理 ⇒ qwen3:8b（7.6GB）永久驻留，
        # 下一次 CodeQL 直接 OOM。实测 /api/ps 的 expires_at 会显示到 2319 年。
        # 默认给 2m（与 config.yaml llm.keep_alive 一致），可用环境变量覆盖。
        self.keep_alive = keep_alive or os.environ.get("SAST_AI_LLM_KEEP_ALIVE", "2m")
        # None = 跟画像走（local-small 的 use_thinking 默认为 False = 关闭思考）
        self.think = think
        self.last_call_telemetry: Dict[str, Any] = {}

    def _resolve_think(self) -> bool:
        if self.think is not None:
            return bool(self.think)
        try:
            from ..core.model_capabilities import resolve_profile
            return bool(resolve_profile(model=self.model, provider=self._PROVIDER_NAME).use_thinking)
        except Exception:
            return False

    def _chat_endpoint(self) -> str:
        return f"{self.base_url}/api/chat"

    def create_message(self, system: str, messages: List[Dict], max_tokens: int = 400,
                       temperature: float = 0.0) -> str:
        all_messages: List[Dict[str, Any]] = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)

        options: Dict[str, Any] = {"temperature": temperature, "num_predict": int(max_tokens)}
        if self.num_ctx:
            options["num_ctx"] = self.num_ctx

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": all_messages,
            "think": self._resolve_think(),
            "stream": False,
            "options": options,
            # 顶层 max_tokens 不是 Ollama 的字段（服务端会忽略），但它是本项目的公共约定：
            # request_chat_completion 靠它做画像钳制、缓存键也把它算进指纹，因此必须带上。
            "max_tokens": int(max_tokens),
        }
        if self.keep_alive:
            payload["keep_alive"] = self.keep_alive

        self.last_call_telemetry = {}
        result, text, telemetry = request_chat_completion(
            self._chat_endpoint(),
            {"Content-Type": "application/json"},
            payload,
            flavor="ollama",
            provider=self._PROVIDER_NAME,
            force_stream=False,
        )
        # 备用文本流（think 被服务端强制开启时的思维链）只在此处消费，不进埋点
        reasoning = telemetry.pop("reasoning_text", "") or ""
        telemetry.update(_ollama_usage(result))
        self.last_call_telemetry = telemetry

        # 缓存命中走这条：request_chat_completion 返回 (None, 缓存正文, tele)。
        # 必须先取 text，否则 result 为 None 会让本方法返回空串，
        # 被上层 _parse_response 当成「模型判定无问题」——正是 P0-2 要防的静默空值。
        if text:
            return text.strip()

        if isinstance(result, dict):
            message = result.get("message") or {}
            content = str(message.get("content") or "").strip()
            if not content:
                # think 被开启（或被服务端强制）时，正文可能被预算耗尽而落空，此时取思维链兜底。
                # 注意字段名：原生端点用 `thinking`，OpenAI 兼容层用 `reasoning`——两者都要认，
                content = str(message.get("thinking") or message.get("reasoning") or "").strip()
            return content
        return reasoning.strip()


class A2AIAgent:
    """A2 AI 语义分析代理"""

    def __init__(self, prompts_file: Optional[str] = None, provider: str = "qwen"):
        """
        初始化 A2 Agent

        Args:
            prompts_file: 提示词文件路径
            provider: API 提供商 ("qwen", "doubao", "minimax", "claude")
        """
        self.prompts = {}
        self.prompts_file = prompts_file or config.get('agents.a2.prompts_file', 'src/prompts/audit_prompts.yaml')
        self._load_prompts()

        self.provider = provider
        self.client = None
        self.max_lines = config.get('agents.a2.max_lines_per_request', 500)
        self.model = ""
        self._init_client()

    def _init_client(self):
        primary = config.get('api.provider', self.provider or 'deepseek')
        # 顺序降级链：主用 provider 先用；耗尽/失败自动切兜底（默认智谱 GLM，anthropic-compatible）。
        # 否则本地模型一失败就会静默把源码发到云端——这在「本地跑」的语义下是不可接受的。
        fallback = config.get('api.fallback_provider', 'anthropic-compatible')
        fallback = (fallback or '').strip()
        order = [primary]
        if fallback and fallback != primary:
            order.append(fallback)

        names, clients = [], []
        for p in order:
            client = _make_client(p, config)
            if client is not None:
                clients.append(client)
                names.append(p)

        if not clients:
            logger.warning("No API key configured for any provider!")
            return

        # P1-8：按主用模型画像确定重试上限，弱模型（local-small: max_attempts=1）不空转。
        _primary_model = getattr(clients[0], "model", "") or ""
        try:
            from src.core.model_capabilities import resolve_profile
            _max_attempts = resolve_profile(model=_primary_model, provider=primary).max_attempts
        except Exception:
            _max_attempts = None
        self.client = FallbackLLMClient(clients, provider_names=names, max_attempts=_max_attempts)
        self.provider = primary
        self.model = _primary_model
        logger.info("[A2AIAgent] LLM 顺序降级链（主用先用，失败自动切兜底）：%s（重试上限=%s）", " -> ".join(names), _max_attempts)

    def _load_prompts(self):
        """加载提示词文件"""
        try:
            from src.core.prompt_registry import load_prompts_dict
            # 此前不传版本 → 只写 metadata、从不影响选中的模板正文。
            merged = load_prompts_dict(version=(getattr(self, "prompt_version", "") or None)) or {}
            if merged.get("audit_file"):
                self.prompts = {k: v for k, v in merged.items()
                                if not (k.endswith(".hash") or k.endswith(".version"))}
                self.prompt_hashes = {k[:-5]: v for k, v in merged.items() if k.endswith(".hash")}
                self.prompt_versions = {k[:-8]: v for k, v in merged.items() if k.endswith(".version")}
                logger.info(f"[PromptRegistry] Loaded {len(self.prompts)} prompt templates")
                return
        except Exception as e:
            logger.error(f"[PromptRegistry] 加载失败，回退直接读 yaml：{e}")

        try:
            base_dir = Path(__file__).parent.parent.parent
            prompts_path = base_dir / self.prompts_file
            with open(prompts_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                self.prompts = data.get('prompts', {})
            self.prompt_hashes = {}
            self.prompt_versions = {}
            logger.info(f"Loaded {len(self.prompts)} prompt templates")
        except Exception as e:
            logger.error(f"Error loading prompts: {e}")
            self.prompts = {}
            self.prompt_hashes = {}
            self.prompt_versions = {}

    def _call_api(self, prompt: str) -> str:
        """调用 AI API"""
        if not self.client:
            raise ValueError("AI client not initialized. Check API key.")

        try:
            system = "You are a professional security code auditor. Analyze Java code for security vulnerabilities. Always output valid JSON."
            messages = [{"role": "user", "content": prompt}]
            return self.client.create_message(system, messages, max_tokens=4096, temperature=0.1)
        except Exception as e:
            logger.error(f"API error: {e}")
            raise

    def _parse_response(self, response: str, finish_reason: str = "") -> List[Vulnerability]:
        """把 LLM 输出解析成漏洞列表——绝不静默返回空。

        ① 不感知字符串内的括号（模型塞进 JSON 的代码片段里若有 `{` 会配平失败），
        ② 输出被 max_tokens 截断时一律 json.loads 抛错 -> 一行 logger.error 后 return []，
           结果是「模型扫出了漏洞，平台拿到 0 条」且没有可观测信号。
        现统一走 src/core/llm_output 的多级降级链：
        直接解析 -> 围栏/裸片段 -> 字符串感知配平 -> 截断修复 -> 数组元素抢救 -> 失败留证。
        截断/修复/抢救的诊断都打 [LLM-OUTPUT] 日志并回传上层。
        """
        vulnerabilities = []

        try:
            from src.core.llm_output import parse_llm_json
        except Exception:
            from ..core.llm_output import parse_llm_json

        data, diag = parse_llm_json(response or "", finish_reason=finish_reason)
        if not diag.ok or data is None:
            # 关键：不再静默。把诊断打到 [LLM-OUTPUT] 日志，便于区分
            # 「模型判定无漏洞」与「答案被截断 / 解析失败（平台侧问题）」。
            logger.warning(
                "[LLM-OUTPUT] parse fail | strategy=%s truncated=%s repaired=%s error=%s | resp=%s",
                diag.strategy, diag.truncated, diag.repaired, diag.error, (response or "")[:200],
            )
            return vulnerabilities

        # 归一化成「漏洞 dict 的扁平列表」，兼容 {vulnerabilities:[]}、{items:[...]}、[[...]] 等外层形态
        vuln_dicts: list = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, list):
                    vuln_dicts.extend(item)
                elif isinstance(item, dict):
                    vuln_dicts.append(item)
        elif isinstance(data, dict):
            top = data.get("vulnerabilities") or data.get("items") or data.get("findings")
            if isinstance(top, list):
                for item in top:
                    if isinstance(item, list):
                        vuln_dicts.extend(item)
                    elif isinstance(item, dict):
                        vuln_dicts.append(item)
            elif isinstance(top, dict):
                vuln_dicts.append(top)
            else:
                # 整条就是一个漏洞对象（{type, severity, line, ...}）
                vuln_dicts.append(data)

        for v in vuln_dicts:
            if not isinstance(v, dict):
                continue
            vulnerabilities.append(Vulnerability(
                type=v.get("type", "Unknown"),
                severity=v.get("severity", "UNKNOWN"),
                line=v.get("line"),
                description=v.get("description", ""),
                fix=v.get("fix", ""),
                file=v.get("file", ""),
            ))

        if diag.repaired or diag.truncated:
            logger.warning(
                "[LLM-OUTPUT] salvaged | strategy=%s truncated=%s repaired=%s items=%d | resp=%s",
                diag.strategy, diag.truncated, diag.repaired, len(vulnerabilities), (response or "")[:200],
            )
        logger.info("[LLM-OUTPUT] parsed=%d finish_reason=%s", len(vulnerabilities), finish_reason)
        return vulnerabilities

    def scan(self, file_content: str, filename: str) -> ScanResult:
        """
        扫描单个文件

        Args:
            file_content: 文件内容
            filename: 文件名

        Returns:
            ScanResult
        """
        result = ScanResult(file=filename, agent='a2')

        if not self.client:
            result.error = "Claude client not initialized"
            return result

        try:
            # 构建提示词
            # §R4回归修复：同 a2_intelligent_agent，禁止裸用 str.format。
            template = self.prompts.get('audit_file', '')
            skill_hints = ""
            try:
                from src.core.rule_registry import build_skill_hints
                skill_hints = build_skill_hints(language="java")
            except Exception:
                skill_hints = ""

            # 截断过长的代码——跟随模型能力画像，不再写死 500 行。
            # 「4 字符/token」的假设。对 qwen3:8b 实测本项目的真实提示词（中文指令 + 代码）
            # 只有 2.34~2.38 字符/token、纯中文低到 1.67，于是 8192 上下文的输入预算
            # 被高估约 1.7 倍：27.6k 字符实为约 11.6k token，超出 8192 后 Ollama 会
            # 静默丢弃提示词头部（连同任务指令），表现为「答非所问」而非报错，极难排查。
            # 现改为 CJK 感知的 token 估算，并把模板/技能提示的占用先扣掉。
            lines = file_content.split('\n')
            if len(lines) > self.max_lines:
                file_content = '\n'.join(lines[:self.max_lines])
                logger.warning(f"File {filename} truncated to {self.max_lines} lines")
            budget_chars = self.max_lines * 80  # 行数约束兜底（画像取不到时用）
            if len(file_content) > budget_chars:
                file_content = file_content[:budget_chars]
            try:
                from src.core.model_capabilities import (
                    resolve_profile, input_budget, estimate_tokens, fit_to_token_budget,
                )
                prof = resolve_profile(model=str(getattr(self, "model", "") or ""),
                                       provider=str(getattr(self, "provider", "") or ""))
                code_budget = input_budget(prof) - estimate_tokens(template) - estimate_tokens(skill_hints)
                file_content, _cut = fit_to_token_budget(file_content, code_budget)
                if _cut:
                    logger.warning(
                        "File %s truncated to fit model input budget "
                        "(profile=%s, code budget ~%d tokens, file=%d chars)",
                        filename, prof.name, code_budget, len(file_content),
                    )
            except Exception:
                pass

            prompt = render_prompt(template, code=file_content, skill_hints=skill_hints)

            # 调用 Claude
            response = self._call_api(prompt)

            # 解析结果（带 finish_reason：区分「判定无漏洞」与「答案被 max_tokens 截断」）
            finish_reason = ""
            client = getattr(self, "client", None)
            if client is not None:
                finish_reason = (getattr(client, "last_call_telemetry", {}) or {}).get("finish_reason", "")
            vulnerabilities = self._parse_response(response, finish_reason=finish_reason)

            # 设置文件名
            for v in vulnerabilities:
                v.file = filename

            result.vulnerabilities = vulnerabilities

        except Exception as e:
            logger.error(f"Error scanning {filename}: {e}")
            result.error = str(e)

        return result

    def scan_files(self, files: List[Dict[str, str]]) -> List[ScanResult]:
        """
        扫描多个文件

        Args:
            files: 文件列表

        Returns:
            扫描结果列表
        """
        results = []

        for file_info in files:
            try:
                result = self.scan(file_info['content'], file_info['rel_path'])
                results.append(result)
                logger.info(f"A2 scanned {file_info['rel_path']}: {len(result.vulnerabilities)} vulnerabilities")
            except Exception as e:
                logger.error(f"Error scanning {file_info['rel_path']}: {e}")
                results.append(ScanResult(
                    file=file_info['rel_path'],
                    agent='a2',
                    error=str(e)
                ))

        return results

    def validate_finding(self, vuln: "Vulnerability", code: str,
                         max_tokens: int = 1024) -> Optional[bool]:
        """问题 5：用 validate_vulnerability 提示词对单条候选漏洞做二次真伪判定。

        设计为 **fail-open** 精度过滤器：
        - 返回 True / False 表示模型判定「真漏洞」/「误报」；
        - 任何异常、解析失败、或 is_true_positive 字段缺失/无法识别，一律返回 None，
          调用方必须「保持原判定」，绝不可因此删改结论或静默丢弃。

        调用方（流水线）应遵守的契约：
        - 只跑在「不确定子集」上（如缺 IAST/D2 佐证、或 low/medium 置信的候选）；
        - 仅用于「升级/降级置信度」或「打 FP 标记」，绝不静默丢弃已确认可利用的漏洞。
        """
        if not self.client:
            logger.warning("[A2.validate] client 未初始化，fail-open 返回 None")
            return None
        template = self.prompts.get("validate_vulnerability")
        if not template:
            logger.warning("[A2.validate] 未加载 validate_vulnerability 模板，fail-open 返回 None")
            return None

        from src.agents.prompt_render import render_prompt
        prompt = render_prompt(
            template,
            vuln_type=getattr(vuln, "type", "") or "",
            line=str(getattr(vuln, "line", "") or ""),
            description=getattr(vuln, "description", "") or "",
            code=code or "",
        )
        try:
            system = ("You are a security expert. Verify whether the specified "
                      "vulnerability is real. Always output valid JSON.")
            text = self.client.create_message(
                system, [{"role": "user", "content": prompt}],
                max_tokens=max_tokens, temperature=0.1,
            )
        except Exception as e:
            logger.error("[A2.validate] API 调用失败，fail-open 返回 None: %s", e)
            return None

        try:
            from src.core.llm_output import parse_llm_json
            data, diag = parse_llm_json(text or "", expect="object")
        except Exception as e:  # pragma: no cover - 防御性分支
            logger.error("[A2.validate] 解析模块加载失败，fail-open 返回 None: %s", e)
            return None

        if not diag.ok or not isinstance(data, dict):
            logger.warning("[A2.validate] 解析失败/非对象，fail-open 返回 None: %s", diag.error)
            return None

        raw = data.get("is_true_positive")
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            s = raw.strip().lower()
            if s in ("true", "1", "yes", "是"):
                return True
            if s in ("false", "0", "no", "否"):
                return False
        if isinstance(raw, int):
            return bool(raw)
        logger.warning("[A2.validate] is_true_positive 缺失/无法识别(%r)，fail-open 返回 None", raw)
        return None
