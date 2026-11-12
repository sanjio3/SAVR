"""路径 C：聚焦提示词二次证明（chain proof second pass）。

------------------------------
``proof_tier`` 由 ``_proof_complete`` 判定：reachable / attacker_control_proven /
gate_bypass_or_satisfaction_proven / payload_shape_proven / success_signal_anchor_proven
五项全真才是 ``chain_proven``，否则 ``broad_static``，并被 ``d2_zero_audit`` 标成

``evaluate_proof_obligations`` 是**纯规则**判定，它只能看结构化 A1 证据里有没有
对应候选；很多族（尤其是业务族与「证据写在代码里但没被抽成候选」的条目）其实
从代码本身就能判成，规则层却取不到，于是被压成 broad_static。

路径 C 的做法：对这类条目追加**一轮极小代价的 LLM 二次证明**——
不是重新扫一遍代码，而是把「已证成项」作为已知前提固定下来，只问模型
**缺口那几项能否由给出的最小上下文直接支撑**，并要求模型为每一个 true
给出一句引用代码的依据。判 true 且给不出依据的一律不接受。

为什么不直接把模型答案写成 True
--------------------------------
``evaluate_proof_obligations`` 里有一批**族级硬降级**（如 ssrf 无 ssrf_source 时
attacker_control/payload_shape 强制 False、auth 族被 sanitizer 净化时强制 False）。
这些规则是防误报的底线，模型不能推翻。所以本模块**不直接改布尔值**，而是把模型
答案作为 ``incoming_proof`` 重新走一遍 ``evaluate_proof_obligations``：
能合并的合并，该被硬降级降掉的照样降掉。模型只能补证据，不能绕过规则。

可观测与诚实性
--------------
每条被处理的漏洞都落 ``vuln.proof_second_pass``（含 model / prompt 版本 /
模型原始回答摘要 / 是否升级），前端与报告可查「这条 chain_proven 是哪来的」。
升级只发生在模型给出具体依据时；解析失败、离线、超时一律 fail-open 保持原状。
"""

from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 提示词版本：进埋点与 vuln.proof_second_pass，便于按版本归因 A/B。
PROMPT_VERSION = "chain-proof-second-pass-v1"

PROOF_KEYS: Tuple[str, ...] = (
    "reachable",
    "attacker_control_proven",
    "gate_bypass_or_satisfaction_proven",
    "payload_shape_proven",
    "success_signal_anchor_proven",
)

# 每一项的判定口径写给模型看。写窄一点，模型才不会什么都判 true。
_KEY_BRIEF: Dict[str, str] = {
    "reachable": "该危险调用能从某个 HTTP 入口或明确调用链到达（能指出具体路由或调用者）",
    "attacker_control_proven": "攻击者能从请求（查询参数/表单/请求体/请求头/Cookie/路径段）控制流入该危险调用的数据",
    "gate_bypass_or_satisfaction_proven": "若存在鉴权/会话/角色/守卫，攻击者可绕过或满足它（端点无守卫、凭据可预测或默认、守卫在该路径上不成立）",
    "payload_shape_proven": "攻击载荷的具体形态可从代码确定（参数名、参数位置、内容约束、候选载荷至少一项明确）",
    "success_signal_anchor_proven": "利用成功后可观测的判定锚点可确定（响应体特征、状态码、状态变化、越权访问、可观测侧效应之一）",
}

_ANSWER_RE = re.compile(r"\{[^{}]*\}", re.DOTALL)

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": True,
    # 单任务最多处理多少条（按缺口数从少到多排序，缺口越少越可能补成）
    "max_items": 120,
    # 并发：本地 8B 物理吞吐有限，超了只是排队（全局闸门还会再限一次）
    "max_workers": 4,
    # 送进提示词的源码片段 token 预算（上下文裁剪，防 Ollama 静默丢提示词头部）
    "snippet_budget_tokens": 1200,
    # 模型给的依据少于这个字数就当作「没依据」，不接受 true
    "min_evidence_chars": 6,
    # 是否只处理「可达 + 攻击者可控」已证成的条目。
    # 而它们本来就是待证项），把门设在这里等于让本阶段空转。故默认 False，
    # 真正的硬门槛是下面这条「必须有真实代码片段」——没有代码就没有判断依据。
    "require_reachable_and_control": False,
    # 缺口数超过这个数就不尝试（缺口太多说明这条本来就没证据，问也是猜）
    "max_gaps": 3,

    # 问题 5：validate_vulnerability 直接真伪判定（TP/FP）。默认关闭，不改动基线计数。
    # 仅跑在「不确定子集」（未 chain_proven、有 code_snippet），fail-open：异常/解析失败/
    # 字段缺失一律保持原判定；判 False 仅打 FP 标记 + 降置信度（判 True 不动，绝不删除已确认漏洞）。
    "validate_enabled": False,
    "validate_max_items": 120,
    "validate_max_workers": 4,
}


def load_config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """读 ``agents.a2.proof_second_pass`` 段，缺失项用 DEFAULT_CONFIG 兜底。"""
    merged = dict(DEFAULT_CONFIG)
    try:
        from .config import config as _cfg
        section = _cfg.get("agents.a2.proof_second_pass", {}) or {}
        if isinstance(section, dict):
            merged.update({k: v for k, v in section.items() if v is not None})
    except Exception:
        pass
    if isinstance(overrides, dict):
        merged.update({k: v for k, v in overrides.items() if v is not None})
    # 环境变量总开关：跑全量时想关掉不用改配置
    env = (os.environ.get("SAST_AI_SECOND_PASS") or "").strip().lower()
    if env in ("0", "false", "off", "no"):
        merged["enabled"] = False
    elif env in ("1", "true", "on", "yes"):
        merged["enabled"] = True
    # 问题 5：validate_vulnerability 真伪判定的环境变量总开关
    venv = (os.environ.get("SAST_AI_VALIDATE") or "").strip().lower()
    if venv in ("0", "false", "off", "no"):
        merged["validate_enabled"] = False
    elif venv in ("1", "true", "on", "yes"):
        merged["validate_enabled"] = True
    try:
        merged["max_items"] = int(merged.get("max_items") or 0)
        merged["max_workers"] = max(1, int(merged.get("max_workers") or 1))
        merged["snippet_budget_tokens"] = int(merged.get("snippet_budget_tokens") or 0)
        merged["min_evidence_chars"] = int(merged.get("min_evidence_chars") or 0)
        merged["max_gaps"] = int(merged.get("max_gaps") or 0)
    except (TypeError, ValueError):
        pass
    return merged


def _text(value: Any) -> str:
    return str(value or "").strip()


def _snippet(vuln: Any, budget_tokens: int) -> str:
    """最小必要上下文：只要漏洞所在片段，不做整文件投喂。"""
    raw = _text(getattr(vuln, "code_snippet", ""))
    if not raw:
        return ""
    try:
        from .model_capabilities import fit_to_token_budget
        clipped, was_cut = fit_to_token_budget(raw, budget_tokens)
    except Exception:
        clipped, was_cut = raw[: max(0, budget_tokens * 2)], len(raw) > budget_tokens * 2
    return clipped + ("\n...[片段已裁剪]" if was_cut else "")


def build_prompt(vuln: Any, missing_keys: List[str], *, budget_tokens: int = 1200) -> str:
    """构造聚焦提示词：已知项固定、只问缺口项、强制给依据。"""
    spec = getattr(vuln, "exploit_spec", {}) or {}
    entry = spec.get("entry", {}) or {}
    payload = spec.get("payload", {}) or {}
    success = spec.get("success_signal", {}) or {}
    pre = spec.get("prerequisites", {}) or {}

    lines: List[str] = []
    lines.append("你是应用安全审计助手，只做一件事：判断下面这条漏洞链的证明缺口能否由给出的代码直接支撑。")
    lines.append("")
    lines.append("严格约束：")
    lines.append("1. 只有在给出的代码或上下文中能直接指出依据时才判 true；")
    lines.append("2. 判 true 必须给出 evidence：一句话引用代码里的具体依据（类名/方法名/参数名/注解/分支条件）；")
    lines.append("3. 判断不了、需要运行时才能确认、或只能靠推测的一律判 false，不要为了补全而猜。")
    lines.append("")
    lines.append("[漏洞]")
    lines.append(f"类型: {_text(getattr(vuln, 'type', ''))}")
    lines.append(f"文件: {_text(getattr(vuln, 'file', ''))}:{getattr(vuln, 'line', '') or '?'}")
    lines.append(f"危险调用(sink): {_text(getattr(vuln, 'sink', '')) or '(未标注)'}")
    lines.append(f"入口: {_text(entry.get('method', '')).upper()} {_text(entry.get('route', '')) or '(未解析)'}")
    lines.append(f"参数: {_text(entry.get('parameter_name', '')) or '(无)'} 位置: {_text(entry.get('parameter_location', '')) or '(未知)'}")
    lines.append(f"载荷族: {_text(payload.get('payload_family', '')) or '(未定)'}")
    if _text(getattr(vuln, "data_flow", "")):
        lines.append(f"数据流: {_text(getattr(vuln, 'data_flow', ''))[:400]}")
    if _text(getattr(vuln, "callers", "")):
        lines.append(f"调用者: {_text(getattr(vuln, 'callers', ''))[:300]}")
    if _text(pre.get("role_or_permission", "")) or _text(pre.get("auth_required", "")):
        lines.append(f"前置条件: auth_required={_text(pre.get('auth_required', '')) or '未知'} role={_text(pre.get('role_or_permission', '')) or '无'}")
    if _text(success.get("signal_type", "")):
        lines.append(f"成功信号类型: {_text(success.get('signal_type', ''))}")
    lines.append("")
    snippet = _snippet(vuln, budget_tokens)
    if snippet:
        lines.append("[代码]")
        lines.append(snippet)
        lines.append("")

    proven_now = [k for k in PROOF_KEYS if k not in missing_keys]
    if proven_now:
        lines.append("[已由静态分析证成，无需再判]")
        for key in proven_now:
            lines.append(f"- {key}: {_KEY_BRIEF.get(key, '')}")
        lines.append("")

    lines.append("[需要你判定的项]")
    for key in missing_keys:
        lines.append(f"- {key}: {_KEY_BRIEF.get(key, '')}")
    lines.append("")
    asked = ", ".join(f'"{k}": {{"proven": true/false, "evidence": "..."}}' for k in missing_keys)
    lines.append("[输出] 只输出一个 JSON 对象，不要任何解释文字：")
    lines.append("{" + f'"answers": {{{asked}}}' + "}")
    return "\n".join(lines)


# 从代码片段里抽取可作为「引用依据」的标识符：长度 >= 4 的单词/成员访问片段。
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{3,}")
# 这些词在提示词里也大量出现，不能作为「引用了代码」的证明
_ECHO_STOPWORDS = {
    "query", "body", "path", "header", "route", "param", "params", "true", "false",
    "unknown", "none", "null", "http", "https", "json", "token", "cookie", "auth",
}


def _code_identifiers(snippet: str) -> set:
    if not snippet:
        return set()
    out = set()
    for token in _IDENT_RE.findall(snippet):
        low = token.lower()
        if low in _ECHO_STOPWORDS:
            continue
        # 去掉纯包名前缀（java.util 之类），避免任何 Java 文件都能对上
        tail = token.split(".")[-1]
        if len(tail) >= 4:
            out.add(tail)
    return out


def _evidence_grounded(evidence: str, tokens: set) -> bool:
    low = (evidence or "").lower()
    return any(tok.lower() in low for tok in tokens)


def parse_answers(text: str, missing_keys: List[str], *, min_evidence_chars: int = 6,
                  snippet: str = "") -> Tuple[Dict[str, str], str]:
    """解析模型回答。返回 (已接受项 -> 依据, 诊断串)。

    只接受「proven 为真且给了像样依据」的项；其余一律丢弃并在诊断里留痕。
    """
    diag = "ok"
    accepted: Dict[str, str] = {}
    raw = _text(text)
    if not raw:
        return {}, "empty"
    data: Any = None
    try:
        from .llm_output import parse_llm_json
        parsed, diag_obj = parse_llm_json(raw)
        data = parsed
        if not diag_obj.ok:
            diag = f"parse-{diag_obj.strategy}"
        else:
            diag = f"parse-{diag_obj.strategy}"
    except Exception as exc:  # pragma: no cover - defensive
        return {}, f"parse-error:{type(exc).__name__}"

    answers: Any = None
    if isinstance(data, dict):
        answers = data.get("answers")
        if answers is None:
            # 模型偶尔直接把 key 铺在顶层
            if any(k in data for k in missing_keys):
                answers = data
    if not isinstance(answers, dict):
        return {}, diag or "no-answers"

    # 8B 会把我提示词里的 "参数: url 位置: query" 原样抄进 evidence，看上去像给了依据，
    # 实际与代码无关（样本 URLWhiteList.java:12 的片段只有 import 行，模型照样判 true）。
    # 硬规则：evidence 必须至少包含一个**片段里真实存在的标识符**，否则判为无依据。
    # 这样既能挡住回显，也不误伤合法引用（如 "url" 确实出现在
    # `String url = request.getRequestURL` 里）。
    tokens = _code_identifiers(snippet) if snippet else set()

    rejected_echo = 0
    for key in missing_keys:
        item = answers.get(key)
        proven = False
        evidence = ""
        if isinstance(item, dict):
            proven = bool(item.get("proven"))
            evidence = _text(item.get("evidence"))
        elif isinstance(item, bool):
            proven = item
        elif isinstance(item, str):
            proven = item.strip().lower() in ("true", "yes", "1")
        if not proven:
            continue
        if len(evidence) < max(1, min_evidence_chars):
            continue
        if tokens and not _evidence_grounded(evidence, tokens):
            rejected_echo += 1
            continue
        accepted[key] = evidence[:300]
    if rejected_echo:
        diag = f"{diag}|echo-rejected:{rejected_echo}"
    return accepted, diag


def _missing_keys(vuln: Any) -> List[str]:
    proof = getattr(vuln, "chain_proof", {}) or {}
    return [k for k in PROOF_KEYS if not proof.get(k)]


def _eligible(vuln: Any, cfg: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """筛选进入二次证明的条目；返回 (是否入选, 缺口键列表)。"""
    if _text(getattr(vuln, "proof_tier", "")) == "chain_proven":
        return False, []
    # 聚合吸收成员不进（它只是组成员，不是独立主张）
    if bool(getattr(vuln, "is_absorbed", False)):
        return False, []
    # 硬门槛：没有真实代码片段就没有判断依据。为空时去问模型等于逼它编造，
    # 这与「全真实数据」的铁律冲突，宁可跳过。
    if not _text(getattr(vuln, "code_snippet", "")):
        return False, []
    missing = _missing_keys(vuln)
    if not missing:
        # 五项都真却被判 broad_static 属不可能态，交给上游修，不在这里兜
        return False, []
    max_gaps = int(cfg.get("max_gaps") or 0)
    if max_gaps and len(missing) > max_gaps:
        return False, missing
    if cfg.get("require_reachable_and_control"):
        proof = getattr(vuln, "chain_proof", {}) or {}
        if not proof.get("reachable") or not proof.get("attacker_control_proven"):
            return False, missing
    return True, missing


def _evaluate(vuln: Any, incoming: Dict[str, Any]) -> Dict[str, Any]:
    """把模型答案作为 incoming_proof 重跑规则层：可合并则合并，硬降级照降。"""
    from .proof_obligations import evaluate_proof_obligations
    return evaluate_proof_obligations(
        vuln,
        getattr(vuln, "exploit_spec", {}) or {},
        evidence=getattr(vuln, "a1_evidence", {}) or {},
        incoming_proof=incoming,
    )


def _build_gateway():
    from .model_gateway import gateway_from_config, resolve_llm_config
    return gateway_from_config(resolve_llm_config({}))


def run_second_pass(
    scan_results: List[Any],
    *,
    gateway: Any = None,
    overrides: Optional[Dict[str, Any]] = None,
    on_progress=None,
    prompt_version: str = "",
) -> Dict[str, Any]:
    """对 broad_static 条目做一轮聚焦提示词二次证明。

    全程 fail-open：任何异常都不改变原有 proof_tier，只记 stats 与单条留痕。
    """
    cfg = load_config(overrides)
    stats: Dict[str, Any] = {
        "enabled": bool(cfg.get("enabled")),
        "candidates": 0,
        "attempted": 0,
        "llm_called": 0,
        "upgraded": 0,
        "accepted_items": 0,
        "offline_skipped": 0,
        "failed": 0,
        "config": {k: cfg.get(k) for k in ("max_items", "max_workers", "max_gaps", "require_reachable_and_control")},
        "prompt_version": prompt_version or PROMPT_VERSION,
        "model": "",
    }
    if not stats["enabled"]:
        return stats

    targets: List[Tuple[Any, List[str]]] = []
    for scan_result in scan_results or []:
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            ok, missing = _eligible(vuln, cfg)
            if not ok:
                continue
            targets.append((vuln, missing))
    if not targets:
        return stats
    # 缺口越少越可能补成，先处理它们
    targets.sort(key=lambda item: len(item[1]))
    max_items = int(cfg.get("max_items") or 0)
    if max_items > 0 and len(targets) > max_items:
        targets = targets[:max_items]
    stats["candidates"] = len(targets)

    gw = gateway
    if gw is None:
        try:
            gw = _build_gateway()
        except Exception as exc:
            logger.warning("[second-pass] 网关构造失败，跳过二次证明：%s", exc)
            stats["failed"] = len(targets)
            return stats
    try:
        stats["model"] = _text(getattr(gw, "model", "") or getattr(gw, "provider", ""))
    except Exception:
        pass
    if bool(getattr(gw, "is_offline", False)):
        # 离线模式没有真实模型判断，绝不能把离线兜底当证据
        stats["offline_skipped"] = len(targets)
        logger.info("[second-pass] LLM 离线，跳过 %d 条二次证明（不伪造判定）", len(targets))
        return stats

    budget = int(cfg.get("snippet_budget_tokens") or 0)
    min_chars = int(cfg.get("min_evidence_chars") or 0)
    version = prompt_version or PROMPT_VERSION

    def _one(item: Tuple[Any, List[str]]) -> None:
        vuln, missing = item
        record: Dict[str, Any] = {
            "prompt_version": version,
            "model": stats.get("model", ""),
            "asked": list(missing),
            "accepted": {},
            "diagnostics": "",
            "upgraded": False,
        }
        try:
            prompt = build_prompt(vuln, missing, budget_tokens=budget)
            response = gw.complete(purpose="a2-chain-proof-second-pass", prompt=prompt, prompt_version=version)
            text = _text(getattr(response, "text", ""))
            if not text:
                record["diagnostics"] = "empty-response"
                vuln.proof_second_pass = record
                return
            accepted, diag = parse_answers(
                text, missing, min_evidence_chars=min_chars,
                snippet=str(getattr(vuln, "code_snippet", "") or ""),
            )
            record["accepted"] = accepted
            record["diagnostics"] = diag
            if not accepted:
                vuln.proof_second_pass = record
                return
            incoming = dict(getattr(vuln, "chain_proof", {}) or {})
            for key in accepted:
                incoming[key] = True
            new_proof = _evaluate(vuln, incoming)
            still_missing = [k for k in PROOF_KEYS if not new_proof.get(k)]
            if not still_missing:
                new_proof["proof_confidence"] = "medium"
                vuln.chain_proof = new_proof
                vuln.proof_gaps = []
                vuln.proof_tier = "chain_proven"
                record["upgraded"] = True
                stats["upgraded"] += 1
                stats["accepted_items"] += len(accepted)
            else:
                # 规则层仍然降级：保留它对账价值（说明模型答案被哪条规则挡下）
                record["rejected_by"] = still_missing
                if len(still_missing) < len(missing):
                    vuln.chain_proof = new_proof
                    vuln.proof_gaps = list(new_proof.get("proof_gaps", []) or [])
        except Exception as exc:
            record["diagnostics"] = f"error:{type(exc).__name__}:{exc}"[:300]
            stats["failed"] += 1
        finally:
            vuln.proof_second_pass = record

    workers = int(cfg.get("max_workers") or 1)
    stats["attempted"] = len(targets)
    stats["llm_called"] = len(targets)
    total = len(targets)
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in pool.map(_one, targets):
                done += 1
                if on_progress and (done % 5 == 0 or done == total):
                    try:
                        on_progress(done, total)
                    except Exception:
                        pass
    except Exception as exc:
        logger.warning("[second-pass] 执行异常（已处理 %d/%d）：%s", done, total, exc)
        stats["failed"] += max(0, total - done)
    stats["done"] = done
    logger.info(
        "[second-pass] 候选 %d / 调用 %d / 升级 %d / 失败 %d",
        stats["candidates"], stats["llm_called"], stats["upgraded"], stats["failed"],
    )
    return stats


# ---------------------------------------------------------------------------
# 问题 5：validate_vulnerability 直接真伪判定（TP/FP）—— fail-open 精度过滤
# ---------------------------------------------------------------------------
VALIDATE_PROMPT_VERSION = "validate-vulnerability-v1"

_VALIDATE_TPL: Optional[str] = None


def _load_validate_template() -> Optional[str]:
    """懒加载 validate_vulnerability 模板（走 PromptRegistry，与 A2 主链路同一套）。"""
    global _VALIDATE_TPL
    if _VALIDATE_TPL is not None:
        return _VALIDATE_TPL or None
    try:
        from .prompt_registry import load_prompts_dict
        _VALIDATE_TPL = (load_prompts_dict() or {}).get("validate_vulnerability") or ""
    except Exception:
        _VALIDATE_TPL = ""
    return _VALIDATE_TPL or None


def _parse_tp_fp(text: str) -> Optional[bool]:
    """解析 validate_vulnerability 的 is_true_positive。返回 True/False/None(fail-open)。"""
    raw = _text(text)
    if not raw:
        return None
    try:
        from .llm_output import parse_llm_json
        data, diag = parse_llm_json(raw, expect="object")
    except Exception:
        return None
    if not diag.ok or not isinstance(data, dict):
        return None
    val = data.get("is_true_positive")
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("true", "1", "yes", "是"):
            return True
        if s in ("false", "0", "no", "否"):
            return False
    if isinstance(val, int):
        return bool(val)
    return None


def _eligible_validate(vuln: Any, cfg: Dict[str, Any]) -> bool:
    """筛选进入 validate 的「不确定子集」。"""
    # 已链证成的不必再验（已是高置信）
    if _text(getattr(vuln, "proof_tier", "")) == "chain_proven":
        return False
    # 聚合吸收成员只是组成员，不是独立主张
    if bool(getattr(vuln, "is_absorbed", False)):
        return False
    # 已确认可利用的（D2 实锤）不降判——与「绝不删除/降级已确认漏洞」底线一致
    if bool(getattr(vuln, "exploitable", False)):
        return False
    # 硬门槛：没有真实代码片段就无判断依据，宁可跳过（同 _eligible 逻辑）
    if not _text(getattr(vuln, "code_snippet", "")):
        return False
    return True


def run_validate_pass(
    scan_results: List[Any],
    *,
    gateway: Any = None,
    overrides: Optional[Dict[str, Any]] = None,
    on_progress=None,
    prompt_version: str = "",
) -> Dict[str, Any]:
    """问题 5：对「不确定子集」跑 validate_vulnerability 直接真伪判定（fail-open 精度过滤）。

    全程 fail-open：任何异常都不改变原有 proof_tier / 不删除任何 finding；判 False 仅打 FP 标记 +
    降置信度，判 True 不动。默认关闭（validate_enabled=False），开启也不改变基线计数口径。
    """
    cfg = load_config(overrides)
    stats: Dict[str, Any] = {
        "enabled": bool(cfg.get("validate_enabled")),
        "candidates": 0,
        "attempted": 0,
        "llm_called": 0,
        "judged_tp": 0,
        "judged_fp": 0,
        "offline_skipped": 0,
        "failed": 0,
        "model": "",
        "prompt_version": prompt_version or VALIDATE_PROMPT_VERSION,
    }
    if not stats["enabled"]:
        return stats

    template = _load_validate_template()
    if not template:
        logger.warning("[validate] 未加载 validate_vulnerability 模板，跳过")
        return stats

    targets: List[Any] = []
    for scan_result in scan_results or []:
        for vuln in getattr(scan_result, "vulnerabilities", []) or []:
            if _eligible_validate(vuln, cfg):
                targets.append(vuln)
    if not targets:
        return stats
    max_items = int(cfg.get("validate_max_items") or 0)
    if max_items > 0 and len(targets) > max_items:
        targets = targets[:max_items]
    stats["candidates"] = len(targets)

    gw = gateway
    if gw is None:
        try:
            gw = _build_gateway()
        except Exception as exc:
            logger.warning("[validate] 网关构造失败，跳过：%s", exc)
            stats["failed"] = len(targets)
            return stats
    try:
        stats["model"] = _text(getattr(gw, "model", "") or getattr(gw, "provider", ""))
    except Exception:
        pass
    if bool(getattr(gw, "is_offline", False)):
        # 离线模式没有真实模型判断，绝不能把离线兜底当证据
        stats["offline_skipped"] = len(targets)
        logger.info("[validate] LLM 离线，跳过 %d 条真伪判定（不伪造判定）", len(targets))
        return stats

    version = prompt_version or VALIDATE_PROMPT_VERSION
    budget = int(cfg.get("snippet_budget_tokens") or 0)

    def _one(vuln: Any) -> None:
        try:
            from src.agents.prompt_render import render_prompt
            code = _snippet(vuln, budget) or _text(getattr(vuln, "code_snippet", ""))
            prompt = render_prompt(
                template,
                vuln_type=_text(getattr(vuln, "type", "")),
                line=str(getattr(vuln, "line", "") or ""),
                description=_text(getattr(vuln, "description", "")),
                code=code,
            )
            response = gw.complete(purpose="a2-validate-vulnerability", prompt=prompt, prompt_version=version)
            text = _text(getattr(response, "text", ""))
            if not text:
                stats["failed"] += 1
                return
            verdict = _parse_tp_fp(text)
            if verdict is None:
                stats["failed"] += 1
                return
            rec = dict(getattr(vuln, "proof_second_pass", {}) or {})
            if verdict:
                stats["judged_tp"] += 1
                rec["validate"] = {"is_true_positive": True}
            else:
                stats["judged_fp"] += 1
                rec["validate"] = {"is_true_positive": False}
                # 仅打 FP 标记 + 降置信度：不删 finding、不改 proof_tier、不碰已确认可利用项
                if _text(getattr(vuln, "verdict", "")) in ("", "待分析"):
                    vuln.verdict = "假漏洞"
                if _text(getattr(vuln, "confidence", "")) in ("", "low"):
                    vuln.confidence = "low"
            vuln.proof_second_pass = rec
        except Exception as exc:
            stats["failed"] += 1
            logger.warning("[validate] 单条判定异常（保持原状）：%s", exc)

    workers = int(cfg.get("validate_max_workers") or 1)
    stats["attempted"] = len(targets)
    stats["llm_called"] = len(targets)
    total = len(targets)
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in pool.map(_one, targets):
                done += 1
                if on_progress and (done % 5 == 0 or done == total):
                    try:
                        on_progress(done, total)
                    except Exception:
                        pass
    except Exception as exc:
        logger.warning("[validate] 执行异常（已处理 %d/%d）：%s", done, total, exc)
        stats["failed"] += max(0, total - done)
    stats["done"] = done
    logger.info(
        "[validate] 候选 %d / 调用 %d / 判真 %d / 判假 %d / 失败 %d",
        stats["candidates"], stats["llm_called"], stats["judged_tp"], stats["judged_fp"], stats["failed"],
    )
    return stats
