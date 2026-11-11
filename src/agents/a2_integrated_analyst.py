"""A2 集成分析师。

定位：把"审计 CodeQL 结果"和"构造 payload/spec"作为一个整体，一次 LLM 调用完成——
给(源码 + 该文件的 A1 findings[含 sink 位置/族/净化器候选])，对每条 finding 输出
{真假判定 + 可打通 spec(route/method/param_name/param_location/payload/绕过)}。

与旧 A2 的区别：
- 旧：逐文件 triage 到 canonical + 通用 payload，spec 由确定性 resolve 另行物化。
- 新：审计+构造一体，LLM 直接产出可打通 spec；不设确定性校验器（错路由/打法靠
  D1/D2/I2 重放闭环自纠兜底）。

跨文件：调用方把 finding 的 a1_evidence(sink/source/sanitizer candidates, file+line)
里落在其它文件的片段，作为 extra_context 注入；深层 helper 可按需二次检索。
"""
from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.agents.a2_output_schema import resolve_format_mode

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# 背景：本轮 stderr 出现十几条
#   「[A2->TriggerSpec] spec xxx 无真实 attack_payload（family=…）：
#     D1 将退化为纯 canary 探针，I2 须按弱证据处理」
# 根因：A2 有时只给真假判定、payload 留空或写成占位串（base64(serialized_object) 等）。
# 后果：D1 只能投 canary ⇒ 无语义证明强度 ⇒ 只能拿到弱证据 ⇒ 确认率与重放效率双降。
#
# 为什么在 A2 侧做：「A2 造弹、D1 投弹」的分工不变 —— select_attack_payloads
# （src/iast/attack_context.py）明确「只做挑选，绝不在此生成任何 payload」，
# 所以补弹必须发生在造弹方（A2），不能污染投弹方的挑选逻辑。
#
# 纪律（别越线）：
#  - 属性族（hash/crypto/random）**不合成**：它们按 20.2.2 校准靠「静态强算法门禁」
#    确认，不靠 payload 打到 sink；给它们造弹是自欺。
#  - 业务逻辑族（idor/bola/race/…）**不合成**：走双账户差分证明，不靠 payload。
#  - 合成的是「族典型攻击形态」，不是假弹；D2 的确认门槛（必须正向证据才 confirmed）
#    保持不变 ⇒ 合成不改变确认口径，也就不引入新的 FP 确认。
#  - 合成标记 payload_synthesized=True，便于事后审计「哪些是合成弹」。
_FAMILY_SYNTH_PAYLOAD: Dict[str, str] = {
    "sql_injection": "' OR '1'='1",
    "xss": "<script>alert(1)</script>",
    "path_traversal": "../../../../../../etc/passwd",
    "command_execution": "; id",
    "ldap_injection": "*)(uid=*))(|(uid=*",
    "xpathi": "' or '1'='1",
    "xpath_injection": "' or '1'='1",
    "http_response_splitting": "%0d%0aX-Injected:%20probe",
    "format_string": "%s%s%s%s%n",
    "tainted_format_string": "%s%s%s%s%n",
    "expression_language": "${7*7}",
    "server_side_template_injection": "${7*7}",
    "ssrf": "http://127.0.0.1:9/sast-probe",
    "xxe": "<!DOCTYPE x [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>&x;",
    # 实测 本轮 deserialization 18 条 spec 全空、log_injection 11 条只有 1 条有弹。
    # 注意形态必须与族匹配（下面每条都是该族的真实可用形态，不是占位串）：
    #   deserialization → snakeyaml 的 tag 形态（文本通道可投；二进制 gadget 走 ysoserial，默认关）
    #   jndi            → log4j2 的 lookup 形态
    #   log_injection   → CRLF 注入到日志
    #   jsonp           → callback 参数覆盖
    #   cors            → Origin 头反射探测
    #   url_redirect    → 外部域跳转
    "deserialization": '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1:9/"]]]]',
    "jndi_injection": "${jndi:ldap://127.0.0.1:9/sast-probe}",
    "log_injection": "sast-probe%0d%0aInjected-Log-Line",
    "jsonp_referer": "sastProbeCallback",
    "cors": "http://sast-probe.invalid",
    "url_redirect": "http://sast-probe.invalid/",
}
# 属性族关键词（命中即不合成）
_NO_SYNTH_KEYWORDS = ("hash", "crypto", "random", "certificate", "tls", "cookie_flag")
# 业务逻辑族关键词（命中即不合成）
_NO_SYNTH_BIZ = (
    "idor", "bola", "business", "race", "workflow", "privilege", "escalation",
    "state_machine", "statemachine", "calculation", "abuse", "dos", "captcha",
)
# A2 的占位串（与 src/iast/attack_context._PLACEHOLDER_PAYLOADS 对齐；此处不 import
# 以免与 exploit_spec 形成循环导入）
_A2_PLACEHOLDER_PAYLOADS = frozenset({
    "base64(serialized_object)", "webshell_or_probe_file",
    "alternate_owner_resource_id", "generic_payload", "",
})


def _highrisk_retry_enabled() -> bool:
    """C7 召回兜底开关（默认开；SAST_AI_A2_HIGH_RISK_RETRY=0 可关）。"""
    return str(os.environ.get("SAST_AI_A2_HIGH_RISK_RETRY", "1")).strip().lower() not in (
        "0", "false", "no", "off")


# 注入类高危族（C7 复核触发条件）。注意：属性族（hash/crypto/random）不在此列 ——
# 它们既不该有 payload，也不该靠"再问一次"提升检出（按 20.2.2 走静态强算法门禁）。
_HIGH_RISK_FAMILY_TOKENS = (
    "sql_injection", "sqli", "command_execution", "cmd", "path_traversal", "pathtraver",
    "xss", "ldap_injection", "ldapi", "xpath", "xxe", "ssrf", "expression_language",
    "template_injection", "response_splitting", "format_string",
)


def _is_high_risk_family(family: Any) -> bool:
    """该 finding 的族是否属「注入类高危族」（C7 复核触发用）。"""
    low = str(family or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not low:
        return False
    return any(tok in low for tok in _HIGH_RISK_FAMILY_TOKENS)


def synthesize_payload(family: str, spec: Dict[str, Any]) -> Tuple[bool, str]:
    """A2 没造出真 payload 时，按族补载荷。返回 (是否补了, 首个载荷)。


    1. **写错位置**：原实现 `spec["payload"] = tpl` 写的是**字符串**，而消费方
       `attack_context.select_attack_payloads` 读的是
       `exploit_spec["payload"]["candidate_payloads"]`（**字典里的数组**）
       ⇒ `isinstance(payload, dict)` 为假 ⇒ 直接返回空列表。
       实测 本轮 156 条 spec 里只有 25 条有 payload（16%），
       而库里 `payload_synthesized` 标记**一条都没有**——合成等于没发生。
    2. **族覆盖不全**：`_FAMILY_SYNTH_PAYLOAD` 只有 14 个族，
       csrf / jsonp / cors / url_redirect / log_injection / jndi 也都缺。

    现在的做法：先查族模板，再问**族载荷库**（`payload_library.build_family_payloads`，
    它知道 deser_text / xxe_xml / url_bypass 等需要什么形态），
    统一写进 `payload["candidate_payloads"]`，并保留 `payload_synthesized` 便于审计。
    """
    if not isinstance(spec, dict):
        return False, ""
    fam = str(family or spec.get("family") or "").strip().lower()
    if not fam:
        return False, ""
    low = fam.replace("-", "_").replace(" ", "_")
    if any(tok in low for tok in _NO_SYNTH_KEYWORDS):
        return False, ""
    if any(tok in low for tok in _NO_SYNTH_BIZ):
        return False, ""

    # payload 段有两种形态在流里：
    #   · exploit_spec.payload  → dict（含 candidate_payloads 等契约字段）
    #   · A2 per-file spec.payload → **字符串**（LLM 直接给一个载荷）
    # 不能强行把字符串改成 dict（下游/测试都按字符串读）。字符串形态下把候选数组
    # 写到 `payload_candidates`，由 `select_attack_payloads` 兼容读取。
    payload_block = spec.get("payload")
    legacy_str = ""
    if isinstance(payload_block, dict):
        existing = [str(x).strip() for x in (payload_block.get("candidate_payloads") or [])
                    if str(x or "").strip()]
        existing = [x for x in existing if x not in _A2_PLACEHOLDER_PAYLOADS]
        if existing:
            return False, existing[0]  # A2 已给出真载荷，不干预
    else:
        legacy_str = str(payload_block or "").strip()
        if legacy_str and legacy_str not in _A2_PLACEHOLDER_PAYLOADS:
            return False, legacy_str  # 字符串形态且已是真载荷
        _cand = spec.get("payload_candidates")
        if isinstance(_cand, list) and [x for x in _cand if str(x or "").strip()]:
            return False, str(_cand[0])

    candidates: List[str] = []
    source = ""

    # ① 族载荷库优先：它知道「同族不同形态」（deser 要 JSON/序列化串、xxe 要完整 DOCTYPE）
    try:
        from src.iast.payload_library import build_family_payloads
        entry = spec.get("entry") if isinstance(spec.get("entry"), dict) else {}
        lib_spec = {
            "family": fam,
            "param_name": entry.get("parameter_name") or spec.get("param_name") or "",
            "param_location": entry.get("parameter_location") or "",
            "content_type": entry.get("content_type") or "",
            "target_endpoint": entry.get("route") or "",
        }
        lib_out = build_family_payloads(fam, lib_spec) or {}
        for p in (lib_out.get("payloads") or []):
            t = str(p or "").strip()
            if t and t not in candidates:
                candidates.append(t)
        if candidates:
            source = "payload_library:%s" % (lib_out.get("provider") or fam)
    except Exception as _le:  # noqa: BLE001
        logger.debug("[integrated-a2] 族载荷库调用失败（family=%s）：%s", fam, _le)

    # ② 退回静态模板（覆盖库里没有的简单形态）
    if not candidates:
        tpl = _FAMILY_SYNTH_PAYLOAD.get(low)
        if tpl:
            candidates.append(str(tpl))
            source = "template:%s" % low

    if not candidates:
        return False, ""

    if isinstance(payload_block, dict):
        payload_block["candidate_payloads"] = candidates
        if not payload_block.get("payload_family"):
            payload_block["payload_family"] = low
        payload_block["payload_synthesized"] = True
        payload_block["payload_source"] = source
    else:
        # 字符串形态：不动原字段，候选数组放兄弟键（消费方兼容读取）
        spec["payload_candidates"] = candidates
        spec["payload_source"] = source
    spec["payload_synthesized"] = True
    return True, candidates[0]

OLLAMA = os.environ.get("SAST_AI_OLLAMA_URL", "http://127.0.0.1:11434") + "/api/chat"
DEFAULT_MODEL = os.environ.get("SAST_AI_LLM_MODEL", "qwen3:8b")


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# 背景：本轮（L1b）重放 19/24，比历史 632 掉 2 个真值点。逐文件核对后，
# 掉点文件在 A2 阶段都出现了 socket 读超时。链路是：
#   IntegratedAnalyst(timeout=180) → ollama_chat(stream=False) → urlopen(timeout=180)
#   → 本机 GPU 被其它进程占用时单次推理变慢 / Ollama 排队 → 180s 内一个字节未回
#   → 抛 TimeoutError → benchmark_cli 的 `except Exception: specs = []`
#   → **整个文件的全部 finding 静默消失**，D1/D2 再也拿不到这些点。
#
# 注意（纠正此前的错误归因）：R0b / L1b 走的是 `run_a2_integrated_scan`（顺序逐文件），
# 它**不读** SAST_AI_INTEGRATED_WORKERS；4 并发的 `_run_integrated_analyst` 只在
# stage_cache 命中旧产物时补跑。所以用 `--env SAST_AI_INTEGRATED_WORKERS=2` 绕开
# 对这两轮无效，必须修组件本身。
#
# 修复口径（只动传输层，不动 prompt / temperature / seed / 解码契约 ⇒ 判定零漂移）：
#   1. 超时阈值 env 可配，默认与 a2_ai_agent 的 SAST_AI_LLM_TIMEOUT 对齐到 300s；
#   2. 仅对「请求未拿到完整响应」类异常做有限重试 + 退避；
#   3. 连续多轮重试耗尽即熔断，让整轮快速失败，而不是慢慢产出 95 个空文件；
#   4. 全链路埋点，闸门能直接读到「本轮超时/重试/熔断次数」。
#
# 上面第 2 条把 socket 读超时当成「可重试的传输抖动」，是错的。真根因是
# `stream:False` + `format:json` grammar 下 qwen3:8b 偶发不产 EOS，而 options
# 里没有 num_predict ⇒ 生成无限延伸到 num_ctx(8192) 耗尽 ⇒ 服务端一直不返回
# ⇒ 客户端 300s 读超时。历史 `submit_623~628_full.log` 里 ClassDataLoader /
# Shiro / XXE 的 `timed out` 是同一现象，不是 GPU 被别的进程抢。
# 636 实测 3 组超时（00:30/00:35、01:02/01:08、01:14/01:19），重发同一 prompt
# 全部再次超时，6 次重试零收益，单个卡住文件被拉长到 15 分钟以上，A2 跑 58
# 分钟只到 48/95，且 exhausted!=0 按 Gate 0 本轮无效。
# 正确修法：
#   1. options 增加 num_predict 上限（默认 1024，历史输出 P100=485 的 2 倍余量），
#      从服务端硬截断生成；真实冒烟 256 上限 5.85s 返回 done_reason=length。
#   2. socket 读超时判定为「生成超时」，不重试；只对连接类异常做有限重试，
#      避免重发请求与未结束的旧请求抢 GPU。
#   3. 生成超时计入 exhausted，截断计入 truncated，Gate 0 有效轮判据照常拦截。
# 仍不改 prompt / temperature / seed / format / 输出契约：num_predict 对正常
# 输出（≤485 token）不生效，done_reason 仍为 stop，判定口径零漂移。
# ─────────────────────────────────────────────────────────────────────────────
class A2LLMUnavailable(RuntimeError):
    """Ollama 连续不可用，熔断后快速失败（避免整轮慢慢产出空结果）。"""


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default
    return v if lo <= v <= hi else default


def llm_timeout_default() -> float:
    """单次 /api/chat 的 socket 读超时（秒）。默认 300，与 a2_ai_agent 对齐。"""
    return _env_float("SAST_AI_A2_LLM_TIMEOUT", 300.0, 30.0, 1800.0)


def llm_retries_default() -> int:
    """单次调用在传输异常时的额外重试次数（0 = 不重试）。"""
    return int(_env_float("SAST_AI_A2_LLM_RETRIES", 2.0, 0.0, 5.0))


def llm_circuit_break_default() -> int:
    """连续多少次「重试耗尽」后熔断后续调用。"""
    return int(_env_float("SAST_AI_A2_LLM_CIRCUIT_BREAK", 3.0, 1.0, 20.0))


def llm_num_predict_default() -> int:
    """单次 /api/chat 生成 token 上限（默认 1024）。

    历史 A2 输出 P100 = 485 token（本轮/635 共 191 次调用，最大延迟 18.4s），
    1024 留约 2 倍余量，正常输出完全不受影响。用于防止 grammar 约束下模型不产
    EOS 时无限生成到 num_ctx 耗尽、服务端永不返回。
    """
    return int(_env_float("SAST_AI_A2_LLM_NUM_PREDICT", 1024.0, 128.0, 8192.0))


def prompt_token_budget() -> int:
    """单次 prompt 的 token 预算（默认 7000），低于 num_ctx=8192 以给输出留位。

    token 预算。Ollama 在 `num_ctx=8192` 下超限直接 400：
        request (9486 tokens) exceeds the available context size (8192 tokens)
    26KB 的 HTML 就 9,486 token（HTML/JS/SQL token 密度远高于 Java），于是 10 个
    大文件在调用前就失败、被记成 file_failures，看起来像「LLM 不可用」。

    最大是 XXE.java 6,361（`len(prompt)//3`），无一超过 6,500 ⇒ 预算 7000 时
    """
    return int(_env_float("SAST_AI_A2_PROMPT_TOKENS", 7000.0, 2000.0, 7900.0))


def _est_tokens(text: str) -> int:
    """粗略 token 估算：len//3。对 HTML/JS 实测 9486/28500≈1/3，偏保守。"""
    return len(text or "") // 3


def _is_context_overflow(exc: BaseException) -> bool:
    """服务端 400 且原因是「request 超 num_ctx」——估算偏差时的兜底信号。

    `_est_tokens` 是 len//3 的粗估；HTML/SQL 实测可能到 2.5 字符/token，
    这种情况不能直接判文件失败，应当缩小预算重裁。
    """
    if getattr(exc, "code", None) != 400:
        return False
    try:
        body = exc.read()  # type: ignore[attr-defined]
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    except Exception:  # noqa: BLE001
        return False
    return "context size" in text or "exceeds the available context" in text


def _fit_prompt(code: str, filename: str, findings: List[Dict[str, Any]],
                extra_context: str, intent_hints: str,
                budget: int) -> Tuple[str, str]:
    """按预算构造 prompt；超预算时按疑点行开窗。返回 (prompt, 实际使用的 code)。"""
    prompt = _user_prompt(code, filename, findings, extra_context,
                          intent_hints=intent_hints)
    if _est_tokens(SYSTEM) + _est_tokens(prompt) <= budget:
        return prompt, code
    overhead = max(0, len(prompt) - len(code))
    budget_chars = max(1500, budget * 3 - overhead - 100)
    used_code = code
    for _ in range(3):
        used_code = _trim_code_to_budget(code, findings, budget_chars)
        if not used_code or used_code == code:
            break
        prompt = _user_prompt(used_code, filename, findings, extra_context,
                              intent_hints=intent_hints)
        if _est_tokens(SYSTEM) + _est_tokens(prompt) <= budget:
            break
        budget_chars = max(1500, int(budget_chars * 0.8))
    return prompt, used_code


def _trim_code_to_budget(code: str, findings: List[Dict[str, Any]],
                         budget_chars: int) -> str:
    """按「文件头 + 每条疑点行邻域」开窗裁剪源码，保留可判读的最小上下文。

    只在 prompt 估算超预算时调用；不在预算内时 `analyze` 不会走到这里，
    因此小文件的 prompt 与历史完全一致。
    """
    lines = (code or "").splitlines()
    n = len(lines)
    if n == 0 or budget_chars <= 0:
        return code
    spans = [(0, min(120, n))]
    for f in findings or []:
        try:
            ln = int(f.get("line") or 0)
        except Exception:  # noqa: BLE001
            continue
        if ln > 0:
            spans.append((max(0, ln - 1 - 120), min(n, ln - 1 + 121)))
    spans.sort()
    merged: List[Any] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))

    out: List[str] = []
    used = 0
    kept = 0
    for a, b in merged:
        block = lines[a:b]
        block_chars = sum(len(x) + 1 for x in block)
        if used + block_chars <= budget_chars:
            out.extend(block)
            used += block_chars
            kept += len(block)
            continue
        room = budget_chars - used
        acc = 0
        take = 0
        while take < len(block) and acc + len(block[take]) + 1 <= room:
            acc += len(block[take]) + 1
            take += 1
        if take:
            out.extend(block[:take])
            used += acc
            kept += take
        break

    dropped = n - kept
    body = "\n".join(out)
    if dropped > 0:
        body += "\n... [省略 %d 行：文本过长，已按疑点行开窗] ..." % dropped
    return body


_TRANSPORT_STATS: Dict[str, int] = {
    "timeouts": 0,          # 传输异常总次数（含重试内的每一次）
    "retries": 0,           # 发起的重试次数
    "recovered": 0,         # 重试后成功拿到的调用数
    "exhausted": 0,         # 本调用最终失败数（重试耗尽或生成超时）
    "consecutive_exhausted": 0,
    "circuit_broken": 0,    # 熔断后被直接拒绝的调用数
    "generation_timeouts": 0,  # 生成超时（不可重试，直接判耗尽）
    "truncated": 0,         # done_reason=length，输出被 num_predict 截断
}


def reset_transport_stats() -> None:
    """清空传输层统计并解除熔断（测试与新一轮扫描启动时调用）。"""
    for k in _TRANSPORT_STATS:
        _TRANSPORT_STATS[k] = 0


def transport_stats() -> Dict[str, int]:
    return dict(_TRANSPORT_STATS)


def is_generation_timeout(exc: BaseException) -> bool:
    """socket 读超时 = 服务端未在阈值内结束生成（非流式 /api/chat 特有语义）。

    这类失败重发同一 prompt 不会更快，反而可能与客户端断开后仍在运行的旧请求
    抢 GPU。因此单独识别、不重试。
    """
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    reason = getattr(exc, "reason", None)
    return reason is not None and isinstance(reason, (socket.timeout, TimeoutError))


def is_retryable_transport_error(exc: BaseException) -> bool:
    """只重试「连接层没拿到完整响应」；生成超时/业务错误/解析错误一律不重试。

    HTTPError 是 URLError 的子类，但 4xx/5xx 是服务端明确回拒，重试无意义；
    IncompleteRead / RemoteDisconnected 属于响应中途断开，必须重试。
    生成超时（socket.timeout 及包着它的 URLError）见 is_generation_timeout。
    """
    if isinstance(exc, urllib.error.HTTPError) or is_generation_timeout(exc):
        return False
    if isinstance(exc, (ConnectionError, ConnectionResetError,
                        urllib.error.URLError, http.client.RemoteDisconnected,
                        http.client.IncompleteRead)):
        return True
    # OSError 里带 connection reset 文案的也归到传输错误（timeout 已在上面排除）
    if isinstance(exc, OSError):
        msg = str(exc).lower()
        return any(t in msg for t in ("connection reset", "connection aborted",
                                      "broken pipe"))
    return False

#
# 实测结论（tools/_wb_ab_trim_contract.py，15 个真实 benchmark 文件 A/B）：
#   FULL（保留全部审计字段）  100.3s  real 集合与真值基线一致
#   LEAN（砍 snippet/why_bypassable/sink_reached_explanation/content_type）
#                             60.6s（-40%）但 **掉 3 个 TP（00012/01002/01004）+ 多 1 个 FP（00116）**
#   ⇒ **LEAN 被否决**（违反「TP 不降、FP 不升」硬约束）。
#
# 关键教训（别再犯）：`sanitizer.snippet` **不是**纯审计字段。模型把净化器实现代码
# 「抄一遍」这个动作本身帮助它看清净化器，**直接影响 sanitizer.strength 的判定质量**；
# 砍掉它 strength 就判差 ⇒ verdict 跟着错。同一批被砍的
# `why_bypassable` / `sink_reached_explanation` 同理（后者是模型的自我验证步骤）。
#
# 档位语义：
#   full  = 完整契约（旧行为，默认，判定质量基线）
#   safe  = 只砍**确定零影响**的字段（content_type 恒为空串；reason 限长但不改语义）
#   lean  = 激进裁剪（已否决，仅保留用于复现实验）
SAST_AI_A2_CONTRACT = os.environ.get("SAST_AI_A2_CONTRACT", "full").strip().lower()
if SAST_AI_A2_CONTRACT not in ("full", "safe", "lean"):
    SAST_AI_A2_CONTRACT = "full"

SYSTEM = (
    "你是一名资深 Web 安全分析师。你的工作像人审一样：拿到源码和 SAST(CodeQL) 告警后，"
    "一次性完成两件事——判断这条告警是不是真漏洞，并且如果是真的，直接构造出一条能真正打通的 "
    "HTTP 请求规格(spec)。要读懂源码里的 servlet 路由(@WebServlet / @RequestMapping)、请求入口"
    "(getParameter/getCookies/getHeader 等参数从哪来)、数据流到 sink 的路径、以及中间有没有净化器；"
    "有净化器就判断它是否真有效：真有效(参数化/白名单/按上下文结构化编码)则判 false_positive，"
    "可绕过(黑名单 replace/正则/截断/错上下文编码)则构造能绕过它的 payload。只输出一个 JSON 对象。"
)


def _family_hint(family: str) -> str:
    f = (family or "").lower()
    if "cookie" in f:
        return ("【secure_cookie 判据】看 Cookie 是否调用了 setSecure(true) 且 setHttpOnly(true)："
                "两者都设了=安全(false_positive)；缺任一=real，payload 为空，param_name=该 cookie 名。")
    if "crypto" in f or "hash" in f or "weak" in f:
        return ("【算法族判据】看用的是否弱算法：DES/MD5/SHA1/RC4/ECB 等=real；"
                "AES-GCM/SHA-256/PBKDF2 等强算法=false_positive。param 通常为空，payload 空。")
    if "random" in f:
        return "【弱随机判据】用 java.util.Random 生成安全用途=real；SecureRandom=false_positive。"
    if "sql" in f:
        #    里的 String[] 是「返回自增列名」，**不是绑定参数**；该用例安全是因为拼接进 SQL 的 bar
        #    源自常量（`String g = "barbarians_at_the_gate"`），污点流已断，不是"参数化"。
        #    `"select ... PASSWORD='" + bar + "'"` 拼接，bar 源自 cookie；虽然后面用了
        #    prepareStatement + setString(1,"foo")，但注入发生在 SQL 文本构造阶段 ⇒ 仍是 real。
        #    ⇒ 只看「有没有 prepareStatement / 有没有 setString」会误杀，必须看 SQL 文本怎么拼。
        return ("【SQL 注入判据】不要只看有没有 prepareStatement / 绑定参数，要看 **SQL 文本是怎么来的**：\n"
                "  - 真注入(real)：SQL 字面量被 `+ 变量 +`（或 String.format/concat）打断，"
                "且该变量可追溯到请求输入（getParameter/getCookies/getHeader，含 URLDecoder.decode、"
                "StringBuilder、substring、base64 等传播器）。即使随后用 prepareStatement/execute，"
                "**注入已在 SQL 文本构造阶段发生** ⇒ real。\n"
                "  - 假阳性(false_positive)只有两种：\n"
                "    ① SQL 文本是纯常量或全 `?` 占位符，用户输入只经 setString/setInt 等绑定参数进入；\n"
                "    ② 拼接进 SQL 的变量其实是常量/静态值（如 `String g = \"barbarians_at_the_gate\"; "
                "String bar = thing.doSomething(g);`），污点流已断——"
                "**不要因为中间经过反射/工厂/接口调用就认为有风险，只要入参是常量，就没有污点**。\n"
                "  - **反例**：`statement.execute(sql, new String[]{\"username\",\"password\"})` 里的 String[] "
                "是「返回自增列名」，不是绑定参数，**不能当作参数化证据**。")
    return ""


def _output_contract(include_vuln_type: bool = False) -> str:
    """A2 的 JSON 输出契约（按 SAST_AI_A2_CONTRACT 档位切换）。

      full（默认）= 旧契约，判定质量基线。
      safe        = 只砍 content_type（恒为空串，零影响）+ reason 限长 60 字。
      lean        = 激进裁剪，**已否决**（掉 TP），仅保留用于复现实验。

    模型输出族名。根因：A2 契约原本不含「漏洞类型」，族只能从 A1 finding 继承；A1（CodeQL）
    没有对应规则的文件（Velocity SSTI / QLExpress / CORS / JSONP 等）就只能落成 `type=unknown`，
    下游既无法分族也无法做族级门禁。Benchmark 每条 finding 都有 A1 族，故该字段默认不加——
    **对 Benchmark 路径零影响（提示词不变、解码 token 不变）**。

    为什么 snippet 不能砍（血泪教训）：
    模型输出 sanitizer.snippet 的动作 = 把净化器实现「抄一遍」，这个动作本身
    帮助它看清净化器 ⇒ 直接影响 strength 判定 ⇒ 影响 verdict。A/B 实测砍掉后
    00012/01002/01004 三个真漏洞被判成 false_positive（丢 TP），00116 多一个 FP。
    """
    _vt = ('  "vuln_type": "<从下方族清单里选一个，判不准填 unknown>",\n'
           if include_vuln_type else "")
    if SAST_AI_A2_CONTRACT == "lean":
        return (
            "{\n"
            '  "line": <对应可疑点的行号>,\n'
            + _vt +
            '  "verdict": "real" | "false_positive",\n'
            '  "reason": "为什么真/假(<=30字)",\n'
            '  "spec": {\n'
            '    "route": "HTTP 路由", "method": "GET|POST",\n'
            '    "param_name": "参数名/Cookie名", "param_location": "query|body|cookie|header",\n'
            '    "payload": "首选攻击载荷(能到达 sink)",\n'
            '    "bypass_payloads": ["绕过变体1", "绕过变体2", "绕过变体3"],\n'
            '    "sanitizer": {\n'
            '      "present": true|false,\n'
            '      "type": "parameterized|whitelist|encode_html|encode_sql|blacklist_replace|regex|truncate|cast|none|unknown",\n'
            '      "strength": "strong|weak|unknown"\n'
            "    }\n"
            "  }\n"
            "}"
        )
    if SAST_AI_A2_CONTRACT == "safe":
        # 只砍 content_type；snippet 与两个长文本**全部保留**
        # （它们影响 strength 判定，见上方教训）。
        return (
            "{\n"
            '  "line": <对应可疑点的行号>,\n'
            + _vt +
            '  "verdict": "real" | "false_positive",\n'
            '  "reason": "为什么真/假(<=60字)",\n'
            '  "spec": {\n'
            '    "route": "HTTP 路由", "method": "GET|POST",\n'
            '    "param_name": "参数名/Cookie名", "param_location": "query|body|cookie|header",\n'
            '    "payload": "首选攻击载荷(能到达 sink)",\n'
            '    "bypass_payloads": ["绕过变体1", "绕过变体2", "绕过变体3"],\n'
            '    "sanitizer": {\n'
            '      "present": true|false,\n'
            '      "type": "parameterized|whitelist|encode_html|encode_sql|blacklist_replace|regex|truncate|cast|none|unknown",\n'
            '      "strength": "strong|weak|unknown",\n'
            '      "location": "file:line(无则空)",\n'
            '      "snippet": "净化实现片段(<=200字符，无则空)",\n'
            '      "why_bypassable": "可绕过/不可绕过的具体理由"\n'
            "    },\n"
            '    "sink_reached_explanation": "为何该 payload 会打到 sink"\n'
            "  }\n"
            "}"
        )
    return (
        "{\n"
        '  "line": <对应可疑点的行号>,\n'
        + _vt +
        '  "verdict": "real" | "false_positive",\n'
        '  "reason": "为什么真/假(净化器是否有效、输入是否真到 sink)",\n'
        '  "spec": {\n'
        '    "route": "HTTP 路由", "method": "GET|POST",\n'
        '    "param_name": "参数名/Cookie名", "param_location": "query|body|cookie|header",\n'
        '    "content_type": "或空", "payload": "首选攻击载荷(能到达 sink)",\n'
        '    "bypass_payloads": ["绕过变体1", "绕过变体2", "绕过变体3"],\n'
        '    "sanitizer": {\n'
        '      "present": true|false,\n'
        '      "type": "parameterized|whitelist|encode_html|encode_sql|blacklist_replace|regex|truncate|cast|none|unknown",\n'
        '      "strength": "strong|weak|unknown",\n'
        '      "location": "file:line(无则空)",\n'
        '      "snippet": "净化实现片段(<=200字符，无则空)",\n'
        '      "why_bypassable": "可绕过/不可绕过的具体理由"\n'
        "    },\n"
        '    "sink_reached_explanation": "为何该 payload 会打到 sink"\n'
        "  }\n"
        "}"
    )


def _user_prompt(code: str, filename: str, findings: List[Dict[str, Any]],
                 extra_context: str = "", intent_hints: str = "") -> str:
    lines = []
    for i, f in enumerate(findings):
        lines.append(
            "  #%d 行 %s  族=%s  备注=%s" % (
                i + 1, f.get("line") or "?", f.get("family") or "?", f.get("note") or "")
        )
    flist = "\n".join(lines) if lines else "  (未给出具体 sink 行，请你从源码中定位可疑点)"
    hints = "\n".join(sorted({h for h in (_family_hint(f.get("family", "")) for f in findings) if h}))
    if not hints:
        # 模型只能自由发挥——实测会把参数化的 sqli（01002）判成 false_positive。
        # 这里退化为「全族判据」都给它，等于把专家 checklist 摆在面前，而不是凭感觉。
        _fams = ("sql_injection", "xss", "path_traversal", "command_execution",
                 "ldap_injection", "weak_hash", "weak_crypto", "weak_random", "secure_cookie")
        hints = "\n".join(dict.fromkeys(h for h in (_family_hint(x) for x in _fams) if h))
    hint_block = ("判据提示(按族)：\n" + hints + "\n") if hints else ""
    extra = ("\n跨文件相关片段(污点源/净化器等)：\n" + extra_context + "\n") if extra_context else ""
    # 由 replay_intents 表生成后注入。默认空串 → 不追加任何提示，对常规路径零影响。
    intent_block = (
        "\n【历史探索摘要（状态外置，仅供参考，勿重复已试无效打法）】\n" + intent_hints + "\n"
    ) if intent_hints else ""
    no_anchor_note = ""
    if not findings:
        # 无 A1 锚点：要求模型即使判假也给出 route/param，供登记一条 canary 探针复核。
        # 这是「召回保险」——01002/01003/01004 这类真注入在无锚点时会被判 false_positive，
        # 一旦 spec 为空就整例漏掉（453/457 都发生过）。
        no_anchor_note = (
            "本文件**没有 SAST 告警**，请通读源码自行定位可疑点。\n"
            "注意：即使你判定为 false_positive，也请尽量给出 spec.route 与 spec.param_name"
            "（payload 可留空），我们会登记一条 canary 探针做运行时复核。\n"
        )
    _need_vt = not findings
    _vt_help = (
        "vuln_type 只能从下面这份族清单里选一个（原样输出英文键名）：\n"
        "sql_injection, xss, path_traversal, command_execution, deserialization, ssti,\n"
        "spel_injection, expression_injection, xxe, ssrf, crlf_injection, url_redirect,\n"
        "url_whitelist_bypass, jsonp_referer, cors, csrf, auth_bypass, file_upload,\n"
        "jndi_injection, rmi, ldap_injection, xpathi, weak_hash, weak_crypto, weak_random,\n"
        "secure_cookie, trust_boundary_violation。判不准就填 unknown。\n"
    ) if _need_vt else ""
    return (
        f"文件: {filename}\n"
        f"SAST 在该文件报出以下可疑点：\n{flist}\n"
        f"{no_anchor_note}"
        f"{hint_block}"
        f"{intent_block}"
        f"{extra}\n"
        "源码：\n```\n" + code + "\n```\n\n"
        "对上面每一条可疑点，输出一个 JSON 数组，每项：\n"
        + _output_contract(include_vuln_type=_need_vt)
        + "\n"
        + _vt_help
        +
        "关于净化器与绕过（必须严格执行）：\n"
        "0. 只有「对注入值做安全处理」才算净化器。下列一律不算净化器，必须 present=false、type=none、strength=strong：\n"
        "   URLDecoder.decode / Base64 解码 / String.trim / getValue / toString / 字符串拼接 / 赋值 / 日志输出。\n"
        "   实测误判案例：把 `param = URLDecoder.decode(cookie.getValue(), \"UTF-8\")` 当成参数化强净化 —— 这是错的，\n"
        "   解码不改变注入语义，注入依旧成立。\n"
        "   典型弱净化：黑名单 replace(如 replace(\"..\", \"\"))、单条正则、substring 截断、只在错误上下文编码。\n"
        "   典型强净化：PreparedStatement 参数绑定、白名单枚举、ESAPI/OWASP encoder 按上下文编码、Integer.parseInt 类型强转。\n"
        "1. 若中间存在净化器，必须读它的实现再判定 strength：\n"
        "   strong = 参数化查询/白名单枚举/按上下文的结构化编码/类型强转；\n"
        "   weak = 黑名单 replace、单条正则、长度截断、错上下文编码(如 SQL 注入却做 HTML 编码)、try/catch 吞异常；\n"
        "   unknown = 自定义函数且实现体看不清。\n"
        "2. 只有 strength 为 weak 或 unknown 且 verdict 为 real 时，才必须给出 3 到 5 个 bypass_payloads，\n"
        "   每个都必须是可直接投放的具体字符串，并尽量覆盖不同绕过族：\n"
        "   大小写混写、双重编码、Unicode 变体、注释分割、空字节截断、宽字节、\n"
        "   换 Content-Type(form/json/multipart)、参数污染(重复同名参数)、路径归一化差异。\n"
        "3. strength 为 strong 时 bypass_payloads 必须为空数组，且 verdict 应为 false_positive。\n"
        "4. 无净化器时 sanitizer.present=false、type=none、strength=strong(无需绕过)，bypass_payloads 为空数组。\n"
        "false_positive 时 spec 为 null。只输出 JSON 数组，不要多余文字。"
    )


def _extract_json(text: str):
    """从模型输出里抽出**最外层**的 JSON 值（对象或数组）。

    format=json 的单对象输出会先命中**内层**的 bypass_payloads 数组（`["a","b"]`），
    解析出一堆字符串 ⇒ 契约校验失败 ⇒ 误判 parse_error。改为：
    1) 去掉 markdown 代码围栏后先整体 json.loads；
    2) 失败再用括号深度扫描取第一个完整 JSON 值（识别字符串内的括号与转义）。
    """
    if not text:
        return None
    s = text.strip()
    # 去 ```json ... ``` 围栏
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    start = min([i for i in (s.find("{"), s.find("[")) if i >= 0], default=-1)
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except Exception:
                    return None
    return None


def _parse_json_array(text: str) -> List[Dict[str, Any]]:
    obj = _extract_json(text)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)] or ([] if not obj else obj)
    if isinstance(obj, dict):
        # 有些模型会包一层 {"specs":[...]} / {"results":[...]}
        for k in ("specs", "results", "items", "findings", "vulnerabilities"):
            v = obj.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        return [obj]
    return []


def _validate_specs(specs) -> str:
    """校验 A2 输出契约。返回问题描述（空串=通过）。

    抽到了也不校验字段——8B 模型经常把 verdict 填反（01002 案例：verdict=false_positive
    但 reason 与 spec 都说有注入），只能靠调用侧打补丁。这里把契约前移到模型侧：
    校验失败 → 带错误回灌重试一次，从源头减少脏输出。
    注意：**不要求 payload 非空**（属性族/secure_cookie 等本来就无 payload），只要求
    real 必须有 route + param_name，否则这条 spec 打不出去。
    """
    if not isinstance(specs, list) or not specs:
        return "输出为空或不是 JSON 数组"
    bad = []
    for i, s in enumerate(specs):
        if not isinstance(s, dict):
            bad.append("#%d 不是对象" % i)
            continue
        v = str(s.get("verdict") or "").strip()
        if v not in ("real", "false_positive"):
            bad.append("#%d verdict=%r 非法（只能是 real/false_positive）" % (i, v))
            continue
        if v == "real":
            sp = s.get("spec") or {}
            if not isinstance(sp, dict):
                bad.append("#%d real 但 spec 不是对象" % i)
                continue
            if not str(sp.get("route") or "").strip():
                bad.append("#%d real 但缺 route" % i)
            if not str(sp.get("param_name") or "").strip():
                bad.append("#%d real 但缺 param_name" % i)
    return "; ".join(bad[:4])


_MODEL_RUN_REPO = None


def _get_model_run_repo():
    """懒加载 model_runs 仓储（连接复用，避免每次 LLM 调用都新建连接）。"""
    global _MODEL_RUN_REPO
    if _MODEL_RUN_REPO is None:
        from src.infrastructure.db import Database as _DB
        from src.infrastructure.repositories import ModelRunRepository as _MRR
        _MODEL_RUN_REPO = _MRR(_DB(os.environ.get("SAST_AI_DB_PATH", "data/app.db")))
    return _MODEL_RUN_REPO


def ollama_chat(messages: List[Dict[str, str]], model: str = DEFAULT_MODEL,
                timeout: Optional[float] = None, format_mode: str = "json") -> str:
    if timeout is None:
        timeout = llm_timeout_default()
    # 开启推理会显著拉长单文件耗时，而推理内容最终会被剥掉，因此默认关闭；
    # 可用 SAST_AI_LLM_THINK=1 打开。
    _think = str(os.environ.get("SAST_AI_LLM_THINK", "0")).strip().lower() in ("1", "true", "yes")
    # 采样温度降到 0 + 固定 seed，把「同一份代码两次跑结论不同」的概率压到最低。
    # 需要 A/B 对照时可用 SAST_AI_LLM_TEMPERATURE 覆盖。
    try:
        _temp = float(os.environ.get("SAST_AI_LLM_TEMPERATURE", "0") or 0)
    except Exception:
        _temp = 0.0
    _body = {
        "model": model, "messages": messages, "stream": False,
        "think": _think,
        # 实测（/api/ps）曾出现 expires_at=2319 的永久驻留：A2 结束后模型不卸载，
        # 下一片 A1 的 CodeQL（~4GB heap）与它抢 Commit/VRAM，导致 CodeQL 变慢甚至 OOM。
        # 取 2m：同片内 A2 连续调用间隔远小于 2 分钟（保持热），跨阶段则自动释放。
        "keep_alive": os.environ.get("SAST_AI_LLM_KEEP_ALIVE", "2m"),
        "options": {"temperature": _temp, "num_ctx": 8192, "seed": 42,
                    "num_predict": llm_num_predict_default()},
    }
    # 从源头消除「散文包 JSON / 少括号」导致的 parse_error）。
    # SAST_AI_LLM_FORMAT_JSON=0 可关闭（A/B 对照用）。注意：只在开启时才写该字段，
    # 传 null 会被服务端拒绝。
    # （llama.cpp grammar 约束），从语法层保证输出合规 ⇒ 消灭「格式幻觉 → 回退重试」
    # 这条最贵的浪费。默认仍是 json（历史行为不变）。
    _fmt = resolve_format_mode(format_mode)
    if _fmt == "schema":
        from src.agents.a2_output_schema import a2_output_schema
        _body["format"] = a2_output_schema()
    elif _fmt == "off":
        pass  # 不传 format 字段（服务端默认自由生成）
    elif os.environ.get("SAST_AI_LLM_FORMAT_JSON", "1").strip().lower() not in (
            "0", "false", "no", ""):
        _body["format"] = "json"
    body = json.dumps(_body).encode("utf-8")
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    t0 = time.time()
    _retries = llm_retries_default()
    _break_at = llm_circuit_break_default()
    if _TRANSPORT_STATS["consecutive_exhausted"] >= _break_at:
        _TRANSPORT_STATS["circuit_broken"] += 1
        raise A2LLMUnavailable(
            "Ollama 连续 %d 次调用重试耗尽，A2 传输层已熔断；检查 Ollama / GPU 后重跑整轮"
            % _TRANSPORT_STATS["consecutive_exhausted"])
    _attempt = 0
    while True:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read().decode("utf-8"))
            if _attempt:
                _TRANSPORT_STATS["recovered"] += 1
            _TRANSPORT_STATS["consecutive_exhausted"] = 0
            break
        except Exception as _te:  # noqa: BLE001
            _gen_timeout = is_generation_timeout(_te)
            _retryable = is_retryable_transport_error(_te)
            _TRANSPORT_STATS["timeouts"] += 1 if (_retryable or _gen_timeout) else 0
            if _gen_timeout:
                _TRANSPORT_STATS["generation_timeouts"] += 1
            if not _retryable:
                # 生成超时直接判本调用耗尽（交给 Gate 0 有效轮判据拦截）；
                # HTTPError / 解析错误属业务错误，不计 exhausted、不重试。
                if _gen_timeout:
                    _TRANSPORT_STATS["exhausted"] += 1
                    _TRANSPORT_STATS["consecutive_exhausted"] += 1
                raise
            if _attempt >= _retries:
                _TRANSPORT_STATS["exhausted"] += 1
                _TRANSPORT_STATS["consecutive_exhausted"] += 1
                raise
            _attempt += 1
            _TRANSPORT_STATS["retries"] += 1
            _backoff = min(2.0 ** _attempt, 8.0)
            logger.warning(
                "[integrated-a2][transport] Ollama 传输异常（%s: %s），%.1fs 后第 %d/%d 次重试",
                type(_te).__name__, str(_te)[:120], _backoff, _attempt, _retries)
            time.sleep(_backoff)
    # num_predict 触发的截断不抛异常，但内容不完整；单独计数便于闸门定位。
    if d.get("done_reason") == "length":
        _TRANSPORT_STATS["truncated"] += 1
        logger.warning(
            "[integrated-a2][transport] 生成被 num_predict 截断（eval_count=%s），输出可能不完整",
            d.get("eval_count"))
    wall = time.time() - t0
    # prompt_eval_count / eval_count / prompt_eval_duration / eval_duration。
    # 这四个数是 prefill/decode 成本的真值来源——没有它们，20.3 的任何优化都是猜。
    # 之前这里只取 message.content，把计数全丢了 ⇒ 无法回答「prefill 占多少」。
    _stats = {
        "wall_s": round(wall, 3),
        "prompt_tokens": int(d.get("prompt_eval_count") or 0),
        "completion_tokens": int(d.get("eval_count") or 0),
        "prefill_ms": round(float(d.get("prompt_eval_duration") or 0) / 1e6, 1),
        "decode_ms": round(float(d.get("eval_duration") or 0) / 1e6, 1),
    }
    _LOG_STATS.append(_stats)
    _dump_llm_stats(_stats)
    _content = (d.get("message") or {}).get("content", "")
    # ModelGateway ⇒ model_runs 自 10-21 起断更，按 task 查 LLM 调用数恒为 0。
    # 复用 ModelRunRepository.record，task_id 由 SAST_AI_CURRENT_TASK_ID 自动归因。
    # fail-open：埋点失败绝不影响主流程。
    try:
        _get_model_run_repo().record(
            purpose="a2-integrated",
            model=model,
            status="completed",
            input_tokens=int(_stats.get("prompt_tokens") or 0),
            output_tokens=int(_stats.get("completion_tokens") or 0),
            latency_ms=int(float(_stats.get("wall_s") or 0) * 1000),
            input_summary=str((messages[-1] or {}).get("content", ""))[:200] if messages else "",
            output_summary=str(_content)[:200],
            metadata={"provider": "ollama", "base_url": OLLAMA,
                      "prefill_ms": _stats.get("prefill_ms"),
                      "decode_ms": _stats.get("decode_ms")},
            stage="a2-integrated",
        )
    except Exception:
        pass
    return _content


# ── 20.3.4 LLM 耗时埋点 ────────────────────────────────────────────────
# 目的：把「prefill 占多少 / decode 占多少 / 多少 token」变成可测量的数字。
# 口径：每次 ollama_chat 追加一条到 _LOG_STATS；按环境变量 SAST_AI_LLM_STATS_FILE
# 落成 JSONL（跑批期间可离线汇总，不必在进程内聚合）。
# 关键：只观测，不改行为——埋点失败绝不能影响主流程。
_LOG_STATS: List[Dict[str, Any]] = []
_STATS_FILE_ENV = "SAST_AI_LLM_STATS_FILE"


def _dump_llm_stats(stats: Dict[str, Any]) -> None:
    """把单次调用的耗时/token 计数落盘（best-effort，绝不影响主流程）。"""
    path = os.environ.get(_STATS_FILE_ENV, "").strip()
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(stats, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ── 20.3.3 契约合规率埋点 ────────────────────────────────────────────────
# 验收指标：格式不合格率 < 5%（不合格 = 首次输出没通过 _validate_specs，触发回退重试）。
# 重试是最贵的浪费（一次完整 prefill+decode），所以这个数直接决定 20.3 的收益上限。
_CONTRACT_STATS: Dict[str, int] = {
    "calls": 0,       # A2 输出调用总次数
    "first_pass": 0,  # 首次即合规
    "retried": 0,     # 触发回退重试
    "recovered": 0,   # 重试后合规
    "failed": 0,      # 重试仍不合规
}


def contract_stats() -> Dict[str, Any]:
    """返回契约合规统计（含派生指标 invalid_rate = 不合格次数 / 总调用数）。"""
    calls = int(_CONTRACT_STATS.get("calls") or 0)
    first = int(_CONTRACT_STATS.get("first_pass") or 0)
    bad = int(_CONTRACT_STATS.get("retried") or 0)
    return {
        "calls": calls,
        "first_pass": first,
        "retried": bad,
        "recovered": int(_CONTRACT_STATS.get("recovered") or 0),
        "failed": int(_CONTRACT_STATS.get("failed") or 0),
        "invalid_rate": round(bad / calls, 4) if calls else 0.0,
        "compliance_rate": round(first / calls, 4) if calls else 1.0,
        # C8 源语收口：为 real spec 合成族典型载荷的条数（可观测，便于审计）
        "synthesized_payloads": int(_CONTRACT_STATS.get("synthesized_payloads") or 0),
        # C7 召回兜底：高危族全否触发的复核次数 / 复核后拿到 real 的次数
        "highrisk_retried": int(_CONTRACT_STATS.get("highrisk_retried") or 0),
        "highrisk_recovered": int(_CONTRACT_STATS.get("highrisk_recovered") or 0),
        # 不作硬条件（裁剪后仍走完整 A2 分析，不是跳过文件）。
        "code_trimmed": int(_CONTRACT_STATS.get("code_trimmed") or 0),
        # 否则说明本轮有文件因 LLM 不可用被跳过，重放数字不可信。
        "transport": transport_stats(),
    }


class IntegratedAnalyst:
    """把审计 + 构造合成一次 LLM 调用，逐 finding 产出可打通 spec。"""

    def __init__(self, llm_call: Optional[Callable[[List[Dict[str, str]]], str]] = None,
                 model: str = DEFAULT_MODEL, timeout: Optional[float] = None,
                 format_mode: str = ""):
        self._model = model
        # SAST_AI_A2_LLM_TIMEOUT 控制（默认 300，与 a2_ai_agent 对齐）；
        # 调用方显式传值仍优先，保持既有测试/调用兼容。
        self._timeout = float(timeout) if timeout is not None else llm_timeout_default()
        # schema = 用 A2 专用 JSON Schema 做 grammar 约束解码（消灭回退重试）。
        _fm = resolve_format_mode(format_mode or os.environ.get("SAST_AI_LLM_FORMAT", "json"))
        self._format_mode = _fm
        self._llm = llm_call or (
            lambda msgs: ollama_chat(msgs, model=self._model, timeout=self._timeout,
                                      format_mode=_fm))
        # 原语判别（a2_primitives）要的是「七段定长文本行」，不是 JSON ⇒ 走非 schema 通道。
        # 否则 grammar 会逼模型吐 JSON，判别永远解析不出来。
        self._llm_plain = llm_call or (
            lambda msgs: ollama_chat(msgs, model=self._model, timeout=self._timeout,
                                      format_mode="json" if _fm == "schema" else _fm))

    def analyze(self, code: str, filename: str, findings: List[Dict[str, Any]],
                extra_context: str = "", intent_hints: str = "") -> List[Dict[str, Any]]:
        """返回 spec 列表，每项含 line/verdict/reason/spec。"""
        if not findings:
            findings = [{"line": 0, "family": "?", "note": "请通读源码定位可疑 sink"}]
        _t_start = time.time()
        _budget = prompt_token_budget()
        prompt, _used_code = _fit_prompt(code, filename, findings, extra_context,
                                         intent_hints, _budget)
        _counted = _used_code != code
        if _counted:
            _CONTRACT_STATS["code_trimmed"] = int(
                _CONTRACT_STATS.get("code_trimmed") or 0) + 1
            logger.warning(
                "[integrated-a2] %s prompt 超预算 %d，源码按疑点行开窗 %d→%d 字符",
                filename, _budget, len(code), len(_used_code))
        msgs = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ]
        # 估算偏乐观时，服务端会 400。
        # 收到明确的「request 超出 num_ctx」就砍半预算重裁，最多两次，别让一个文件
        # 白白记成 file_failure。
        for _try in range(3):
            try:
                raw = self._llm(msgs)
                break
            except Exception as _exc:  # noqa: BLE001
                if _try == 2 or not _is_context_overflow(_exc):
                    raise
                _budget = max(1500, int(_budget * 0.5))
                prompt, _used_code = _fit_prompt(code, filename, findings, extra_context,
                                                 intent_hints, _budget)
                if not _counted and _used_code != code:
                    _CONTRACT_STATS["code_trimmed"] = int(
                        _CONTRACT_STATS.get("code_trimmed") or 0) + 1
                    _counted = True
                msgs = [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt},
                ]
                logger.warning(
                    "[integrated-a2] %s 服务端判超上下文，预算降到 %d 重裁 %d→%d 字符",
                    filename, _budget, len(code), len(_used_code))
        # 1632~3885s 的方差无法归因（429 仅 1~4 次/小时，非主因）。
        # 这里记录「单文件耗时 + 输出字符数 + 输入规模」，供后续按轮次聚合分析：
        # 若耗时随输出字符线性增长 ⇒ decode 主导（符合已知 30~36 tok/s）；
        # 若与输出无关而随轮次波动 ⇒ 查模型重载/机器负载。
        _t_done = time.time()
        logger.info(
            "[integrated-a2][timing] file=%s dur=%.1fs out_chars=%d in_chars=%d findings=%d",
            filename, _t_done - _t_start, len(raw or ""), len(code or ""),
            len(findings or []),
        )
        specs = _parse_json_array(raw)
        _problem = _validate_specs(specs)
        _CONTRACT_STATS["calls"] = int(_CONTRACT_STATS.get("calls") or 0) + 1
        if not _problem:
            _CONTRACT_STATS["first_pass"] = int(_CONTRACT_STATS.get("first_pass") or 0) + 1
        if _problem:
            # 只重试一次——重试成本是单文件 2 倍，不能无限重试拖垮整片。
            logger.info("[integrated-a2] 输出契约校验失败（%s），带错误回灌重试一次", _problem[:120])
            repair = msgs + [
                {"role": "assistant", "content": (raw or "")[:4000]},
                {"role": "user", "content": (
                    "上面的输出不满足要求：%s。\n"
                    "请**只输出一个 JSON 数组**，不要任何解释文字；每项形如\n"
                    '{"line":<int>,"verdict":"real"|"false_positive","reason":"...",'
                    '"spec":{"route":"...","method":"GET|POST","param_name":"...",'
                    '"param_location":"query|body|cookie|header","payload":"...",'
                    '"sanitizer":{"present":bool,"type":"...","strength":"strong|weak|unknown|none",'
                    '"location":"...","snippet":"...","why_bypassable":"..."},'
                    '"bypass_payloads":["..."]}}\n'
                    "verdict=real 时 spec.route 与 spec.param_name 必填；verdict=false_positive 时 spec 可为 null。"
                ) % _problem},
            ]
            _CONTRACT_STATS["retried"] = int(_CONTRACT_STATS.get("retried") or 0) + 1
            try:
                raw2 = self._llm(repair)
                specs2 = _parse_json_array(raw2)
                if specs2 and not _validate_specs(specs2):
                    specs = specs2
                    _CONTRACT_STATS["recovered"] = int(_CONTRACT_STATS.get("recovered") or 0) + 1
                    logger.info("[integrated-a2] 重试后契约校验通过（%d 条）", len(specs2))
                else:
                    _CONTRACT_STATS["failed"] = int(_CONTRACT_STATS.get("failed") or 0) + 1
                    logger.warning("[integrated-a2] 重试仍不合契约（%s），保留首次解析结果",
                                   _validate_specs(specs2)[:120])
            except Exception as _re:
                _CONTRACT_STATS["failed"] = int(_CONTRACT_STATS.get("failed") or 0) + 1
                logger.warning("[integrated-a2] 重试调用异常（保留首次结果）：%s", _re)
        # 兜底：解析失败时返回单条原始输出，便于诊断（不静默丢）
        if not specs:
            return [{"line": findings[0].get("line"), "verdict": "parse_error",
                     "reason": (raw or "")[:500], "spec": None}]
        # C8 源语收口：verdict=real 但没造出真 payload 的 spec，按族补一个典型载荷。
        # 不补 ⇒ D1 退化成纯 canary 探针（degraded_no_synthesis）⇒ 只能拿弱证据。
        _synth_n = 0
        for _it in specs:
            if not isinstance(_it, dict):
                continue
            if str(_it.get("verdict") or "") != "real":
                continue
            _sp = _it.get("spec")
            if not isinstance(_sp, dict):
                continue
            _fam = str(_sp.get("family") or "")
            if not _fam:
                # spec 契约里没有 family 字段 ⇒ 按 line 回到 A1 findings 里取
                for _f in (findings or []):
                    if isinstance(_f, dict) and _f.get("line") == _it.get("line"):
                        _fam = str(_f.get("family") or "")
                        break
            if not _fam:
                # `exploit_spec` 契约里没有 `family` 字段，
                # 按 line 回查 findings 也常对不上 ⇒ `_fam` 为空 ⇒ synthesize_payload
                # 立刻 return False ⇒ 165 条 spec 里只有 24 条有载荷（15%），
                # deserialization 0/18、csrf 0/11 全空。
                # 而 A2 其实把族写在了 `payload.payload_family` 里 —— 用它兜底。
                _pl = _sp.get("payload")
                if isinstance(_pl, dict):
                    _fam = str(_pl.get("payload_family") or "")
                if not _fam:
                    _ent = _sp.get("entry")
                    if isinstance(_ent, dict):
                        _fam = str(_ent.get("family") or "")
            _ok, _p = synthesize_payload(_fam, _sp)
            if _ok:
                _synth_n += 1
        if _synth_n:
            _CONTRACT_STATS["synthesized_payloads"] = (
                int(_CONTRACT_STATS.get("synthesized_payloads") or 0) + _synth_n)
            logger.info("[integrated-a2] C8 源语收口：为 %d 条 real spec 合成族典型载荷", _synth_n)

        #   471 里它也是 A2 判出来的（findings.sources=['A2']），A1/CodeQL 从未检出；
        #   472 这次 A2 把它判成了非漏洞 ⇒ 整条链路上它就没了。
        #   即：这条 TP 的存亡**完全取决于 LLM 单次判定**，而 A2 的判定方差是已知的
        #
        # 为什么是「确定性触发」而不是「按概率卡阈值」：
        #   20.2.2 校准结论禁止按概率/严重度开闸门（那类闸门会误杀 TP）。这里的触发条件是
        #   **结构性事实**（该文件的全部 finding 都被判否 + 其中含注入类高危族），
        #   不是分数阈值；重试后仍由 D2 的正向证据门槛决定确认，不改变确认口径。
        #   ⇒ 不违反校准红线，且只对「最可能漏判」的场景多花一次调用。
        if _highrisk_retry_enabled() and specs:
            _real_n = sum(1 for _it in specs
                          if isinstance(_it, dict) and str(_it.get("verdict")) == "real")
            _hr = [f for f in (findings or [])
                   if isinstance(f, dict) and _is_high_risk_family(f.get("family"))]
            if _real_n == 0 and _hr:
                _CONTRACT_STATS["highrisk_retried"] = (
                    int(_CONTRACT_STATS.get("highrisk_retried") or 0) + 1)
                logger.info("[integrated-a2] C7 召回兜底：%d 条 finding 全判否且含高危族 %s，"
                            "触发一次高危复核", len(_hr),
                            sorted({str(f.get('family')) for f in _hr})[:4])
                try:
                    raw2 = self._llm(msgs + [
                        {"role": "user", "content": (
                            "上一轮你把这个文件的全部 finding 都判成了 false_positive。\n"
                            "请**重新逐条审视**下列 %d 条 finding，特别是注入类高危族"
                            "（%s）：\n"
                            "- 注入类要判断「污点是否真的流进了危险操作」，而不是「代码看起来有防护」；\n"
                            "- 若净化器只是转义/黑名单/长度限制，verdict 仍应为 real（净化器弱可绕过）；\n"
                            "- 只有在污点**根本没有到达**危险操作，或输入被完全丢弃时，才判 false_positive。\n"
                            "请只输出 JSON 数组，格式与上一轮完全一致。"
                            % (len(_hr), ", ".join(sorted({str(f.get('family')) for f in _hr}))[:6])
                        )},
                    ])
                    specs2 = _parse_json_array(raw2)
                    if specs2:
                        _real2 = sum(1 for _it in specs2
                                     if isinstance(_it, dict) and str(_it.get("verdict")) == "real")
                        specs = specs2
                        _CONTRACT_STATS["highrisk_recovered"] = (
                            int(_CONTRACT_STATS.get("highrisk_recovered") or 0) + 1)
                        logger.info("[integrated-a2] C7 高危复核完成：复核后 real=%d 条", _real2)
                        # 复核结果同样要走一次 C8 补弹
                        for _it in specs:
                            if not isinstance(_it, dict):
                                continue
                            if str(_it.get("verdict") or "") != "real":
                                continue
                            _sp = _it.get("spec")
                            if not isinstance(_sp, dict):
                                continue
                            _fam = str(_sp.get("family") or "")
                            if not _fam:
                                for _f in (findings or []):
                                    if isinstance(_f, dict) and _f.get("line") == _it.get("line"):
                                        _fam = str(_f.get("family") or "")
                                        break
                            synthesize_payload(_fam, _sp)
                    else:
                        logger.warning("[integrated-a2] C7 高危复核未解析出内容，保留首轮结果")
                except Exception as _he:  # noqa: BLE001
                    logger.warning("[integrated-a2] C7 高危复核异常（保留首轮结果）：%s", _he)
        return specs

    def analyze_file(self, file_path: str, findings: List[Dict[str, Any]],
                     extra_context: str = "") -> List[Dict[str, Any]]:
        code = open(file_path, encoding="utf-8", errors="ignore").read()
        return self.analyze(code, os.path.basename(file_path), findings, extra_context)

    def analyze_two_stage(self, code: str, filename: str,
                          findings: List[Dict[str, Any]],
                          extra_context: str = "") -> tuple:
        """两段式（Jev 理念第一阶段）：先原语判别，高置信判否的 finding 早停，不生成 spec。

        返回 (specs, stats)：
          specs  与 analyze 同结构，顺序与原 findings 对齐（早停项为
                 {"line":..,"verdict":"false_positive","reason":"primitives 高置信判否...",
                  "spec":None,"primitives":{...}}）；
          stats  {"total":N,"early_stopped":M,"generated":K,"by_reason":{...}} 供审计。

        安全边界（第一阶段刻意保守）：
          - 只对 V=0 且 VP>=EARLY_STOP_MIN_VP（默认 0.9）早停；解析失败/低置信一律走完整路径；
          - 早停结论仍然落库可审计，D2 保留翻案权力——早停省的是生成成本，不是最终裁决。
        """
        if not findings:
            return self.analyze(code, filename, findings, extra_context), {
                "total": 0, "early_stopped": 0, "generated": 0}

        try:
            from src.agents.a2_primitives import discriminate
            prims = discriminate(code, filename, findings, extra_context,
                                 llm_call=self._llm_plain)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[integrated-a2][two-stage] %s 判别失败，退回单段路径：%s",
                           filename, exc)
            return self.analyze(code, filename, findings, extra_context), {
                "total": len(findings), "early_stopped": 0,
                "generated": len(findings), "degraded": True}

        # discriminate 内部失败时返回全 fallback（不抛），这里识别出来并标记 degraded：
        # 行为上等于"判别不可用"→ 全部走完整生成路径，与单段路径一致，不丢召回。
        _degraded = bool(prims) and all(p.source == "fallback" for p in prims)

        specs: List[Dict[str, Any]] = []
        keep: List[Dict[str, Any]] = []
        keep_idx: List[int] = []
        stopped = 0
        for i, f in enumerate(findings):
            p = prims[i] if i < len(prims) else None
            if p is not None and p.early_stoppable:
                stopped += 1
                specs.append({
                    "line": f.get("line"),
                    "verdict": "false_positive",
                    "reason": "原语判别高置信判否（VP=%.2f, S=%s, LOC=%s）"
                              % (p.vuln_prob, p.sanitizer, p.location),
                    "spec": None,
                    "primitives": p.to_dict(),
                })
            else:
                keep.append(f)
                keep_idx.append(i)
                specs.append(None)  # 占位，稍后用生成结果回填

        generated = 0
        if keep:
            try:
                sub = self.analyze(code, filename, keep, extra_context) or []
            except Exception as exc:  # noqa: BLE001
                logger.warning("[integrated-a2][two-stage] %s 生成段异常：%s", filename, exc)
                sub = []
            # sub 与 keep 的顺序对齐由 analyze 保证（它按 findings 逐条输出）；
            # 若条数不符（parse_error 等），按序号回填、多余丢弃、缺失补 None。
            for j, idx in enumerate(keep_idx):
                if j < len(sub):
                    item = sub[j]
                    if isinstance(item, dict):
                        item.setdefault("primitives", None)
                        if idx < len(prims):
                            item["primitives"] = prims[idx].to_dict()
                        specs[idx] = item
                        generated += 1
        # 仍为 None 的占位（生成段缺失）→ 补一条 parse_error，避免下游拿到 None 崩溃
        for idx, s in enumerate(specs):
            if s is None:
                specs[idx] = {"line": findings[idx].get("line"), "verdict": "parse_error",
                              "reason": "two-stage 生成段未返回该 finding", "spec": None}
        stats = {"total": len(findings), "early_stopped": stopped, "generated": generated}
        if _degraded:
            stats["degraded"] = True
        logger.info("[integrated-a2][two-stage] %s 判别 %d 条：早停 %d、生成 %d%s",
                    filename, len(findings), stopped, generated,
                    "（判别降级，全量生成）" if _degraded else "")
        return specs, stats


def _gather_cross_file_context(findings: List[Dict[str, Any]], code_root: str,
                               sink_file: str, max_snippets: int = 8,
                               window: int = 6) -> str:
    """从 finding 的 a1_evidence(sink/source/sanitizer candidates) 收集落在其它文件的片段。"""
    out, seen = [], set()
    for f in findings:
        ae = f.get("a1_evidence") or {}
        for key in ("sanitizer_candidates", "source_candidates", "sink_candidates", "entry_candidates"):
            for c in (ae.get(key) or []):
                cf, ln = c.get("file"), c.get("line")
                if not cf or cf == sink_file:
                    continue
                k = (cf, ln)
                if k in seen or len(out) >= max_snippets:
                    continue
                seen.add(k)
                p = os.path.join(code_root, cf) if not os.path.isabs(cf) else cf
                try:
                    ls = open(p, encoding="utf-8", errors="ignore").read().splitlines()
                    lo = max(0, (ln or 1) - 1 - window // 2)
                    snip = "\n".join(ls[lo: lo + window])
                    out.append("// %s:%s (%s)\n%s" % (cf, ln, key.replace("_candidates", ""), snip))
                except Exception:
                    pass
    return "\n\n".join(out)


if __name__ == "__main__":
    # 单文件自测: python a2_integrated_analyst.py <file> [family]
    import sys
    fp = sys.argv[1]
    fam = sys.argv[2] if len(sys.argv) > 2 else "?"
    an = IntegratedAnalyst()
    res = an.analyze_file(fp, [{"line": 0, "family": fam, "note": "定位 sink 并判断"}])
    print(json.dumps(res, ensure_ascii=False, indent=2))
