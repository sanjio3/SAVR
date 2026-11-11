"""
Hybrid execution-evidence judge for D2 verification.

重构文档 3.5 / 2.1 / 3.18：judge 以两条正交信号做裁定——
- IAST 证据（匹配 vulnType + sink 的 SINK_HIT，代表保真 + 可达）；
- DAST/AI 影响证据（响应 / 副作用代表危害）。
在既有 confirmed_exploitable / confirmed_sink_control / judge_inconclusive 之上，新增
runtime_confirmed（仅 IAST 命中）与 confirmed_attributable（IAST + DAST 双命中）；
最终 final_state 走五态（含 false_positive_sast_only，见 3.18）。
"""
import json
from typing import Any, Dict, Iterable, List, Optional

from src.core.exploit_spec import normalize_exploit_spec
from src.iast.orchestrator import (
    STATE_ARRIVAL_SANITIZED,
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED,
)


def empty_execution_evidence() -> Dict[str, Any]:
    return {
        "requests_made": [],
        "responses_observed": [],
        "side_effects_observed": [],
        "artifacts_created": [],
        "state_changes_observed": [],
        "cleanup_performed": [],
        "raw_signals": [],
        "step_errors": [],
        "impact_attempts": [],
        "impact_blockers_observed": [],
        "matched_impact_step": [],
        "verification_fallback_used": [],
    }


def normalize_execution_evidence(evidence: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    normalized = empty_execution_evidence()
    incoming = evidence or {}
    for key in normalized:
        value = incoming.get(key, [])
        normalized[key] = list(value) if isinstance(value, list) else ([str(value)] if value else [])
    return normalized


def extract_execution_evidence(raw_output: str, exploit_spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    normalized_spec = normalize_exploit_spec(exploit_spec)
    evidence = empty_execution_evidence()
    if not raw_output:
        return evidence
    try:
        payload = json.loads(raw_output)
    except Exception:
        return evidence

    steps = payload.get("steps", []) or []
    entry = normalized_spec.get("entry", {})
    success_signal = normalized_spec.get("success_signal", {})
    payload_family = str((normalized_spec.get("payload", {}) or {}).get("payload_family", "") or "")
    expected_indicators = [str(v) for v in (success_signal.get("expected_indicators", []) or []) if str(v)]
    proof_target = str(success_signal.get("side_effect_target", "") or "")
    verify_request = success_signal.get("verify_request", {}) if isinstance(success_signal.get("verify_request"), dict) else {}
    trigger_path = str(entry.get("trigger_route", "") or verify_request.get("path", "") or "")
    success_mode = str(payload.get("success_mode", "") or "")
    for attempt in payload.get("attempts", []) or []:
        if isinstance(attempt, dict):
            mode = str(attempt.get("mode", "") or "")
            attempt_payload = str(attempt.get("payload", "") or "")
            expected = str(attempt.get("expected", "") or "")
            goal = str(attempt.get("goal", "") or "")
            record = f"{mode}:{goal}:{expected}:{attempt_payload[:120]}"
            evidence["impact_attempts"].append(record)
            if success_mode == "high_impact" and mode == "high_impact":
                evidence["matched_impact_step"].append(goal or expected or attempt_payload[:48])
            if success_mode == "verification" and mode == "verification":
                evidence["verification_fallback_used"].append("true")

    for step in steps:
        step_name = str(step.get("step", "") or "")
        result = step.get("result", {}) if isinstance(step.get("result"), dict) else {}
        stdout = str(result.get("stdout", "") or "")
        stderr = str(result.get("stderr", "") or "")
        body = str(result.get("body", "") or "")
        url = str(result.get("url", "") or "")
        method = str(result.get("method", "") or "")
        if not method and step_name.startswith("post_"):
            method = "POST"
        elif not method and step_name.startswith("trigger_"):
            method = "GET"
        if url:
            evidence["requests_made"].append(f"{method or 'HTTP'} {url}".strip())
        status_code = str(result.get("status_code", "") or "")
        if status_code:
            evidence["responses_observed"].append(f"{step_name or 'step'}:{status_code}")
        if result.get("error"):
            evidence["step_errors"].append(str(result.get("error")))
        if "__A3_FILE_PRESENT__" in stdout or "__A3_FILE_PRESENT__" in stderr:
            evidence["side_effects_observed"].append("proof_file_created")
            evidence["artifacts_created"].append("proof_file_created")
        if step_name.startswith("cleanup") and result.get("success"):
            evidence["cleanup_performed"].append(step_name)
        if trigger_path and trigger_path in url and str(result.get("status_code", "")) == "200":
            evidence["side_effects_observed"].append("trigger_invoked")
        if entry.get("route") and entry.get("route") in url and str(result.get("status_code", "")) in {"200", "201", "202", "204"}:
            evidence["side_effects_observed"].append("primary_delivery_accepted")
            if payload_family == "file-upload":
                evidence["side_effects_observed"].append("uploaded_webshell_accepted")
        for indicator in expected_indicators:
            if indicator and indicator in body:
                evidence["raw_signals"].append(indicator)
        if proof_target and proof_target in stdout:
            evidence["raw_signals"].append(proof_target)

    for result_key in ("attack_result", "verify_result"):
        result = payload.get(result_key, {}) if isinstance(payload.get(result_key), dict) else {}
        body = str(result.get("body", "") or "")
        if str(result.get("url", "") or ""):
            evidence["requests_made"].append(f"HTTP {result.get('url', '')}")
        if str(result.get("status_code", "") or ""):
            evidence["responses_observed"].append(f"{result_key}:{result.get('status_code', '')}")
        if payload_family == "file-upload" and str(result.get("status_code", "")) in {"200", "201", "202", "204"}:
            evidence["side_effects_observed"].append("uploaded_webshell_accepted")
        for indicator in expected_indicators:
            if indicator and indicator in body:
                evidence["raw_signals"].append(indicator)

    if evidence["raw_signals"]:
        evidence["side_effects_observed"].append("response_indicator_observed")
    if payload.get("success_mode") == "high_impact":
        evidence["side_effects_observed"].append("high_impact_indicator_observed")
    elif payload.get("success_mode") == "verification":
        evidence["side_effects_observed"].append("verification_indicator_observed")
        evidence["verification_fallback_used"].append("true")
    if any("authorization" in signal or "state" in signal for signal in evidence["raw_signals"]):
        evidence["side_effects_observed"].append("authorization_or_state_change_observed")
        evidence["state_changes_observed"].append("authorization_or_state_change_observed")

    return normalize_execution_evidence(evidence)


# 五态 final_state
FINAL_CONFIRMED_ATTRIBUTABLE = "confirmed_attributable"
FINAL_RUNTIME_CONFIRMED = "runtime_confirmed"
FINAL_AMBIGUOUS = "ambiguous"
FINAL_NO_EVIDENCE = "no_evidence"
FINAL_FALSE_POSITIVE_SAST_ONLY = "false_positive_sast_only"
# 靶场不健康（可重试）：与 no_evidence（永久非漏洞）严格区分，详见 adjudicator.FINAL_TARGET_UNHEALTHY。
FINAL_TARGET_UNHEALTHY = "target_unhealthy"
# 被防护拦截（WAF/拦截器/参数截断）：请求未到达漏洞点即被安全设备/过滤器阻断。
# 与 no_evidence 严格区分——它不代表「无漏洞」，而是「本次未能有效验证」，应重试或人工确认。
# 详见 adjudicator.FINAL_WAF_BLOCKED（rank 0，非正，不污染确认口径）。
FINAL_WAF_BLOCKED = "waf_blocked"


def _judge_dast_path(
    *,
    spec: Dict[str, Any],
    evidence: Dict[str, Any],
    fallback_exploitable: bool,
    fallback_reason: str,
) -> Dict[str, Any]:
    """既有 DAST/AI 危害裁定路径。"""
    outcomes = spec.get("expected_outcomes", {}) or {}
    contract = spec.get("validation_contract", {}) or {}

    observed = set()
    for key in ("side_effects_observed", "artifacts_created", "raw_signals", "cleanup_performed"):
        observed.update(str(v) for v in evidence.get(key, []) if str(v))

    primary = str(outcomes.get("primary_outcome", "") or "")
    primary_exploit = [str(v) for v in (outcomes.get("primary_exploit_outcomes", []) or []) if str(v)]
    verification_only = [str(v) for v in (outcomes.get("verification_only_outcomes", []) or []) if str(v)]
    secondary = [str(v) for v in (outcomes.get("secondary_outcomes", []) or []) if str(v)]
    confirmed_by = [str(v) for v in (contract.get("confirmed_by", []) or []) if str(v)]
    partial_by = [str(v) for v in (contract.get("partial_by", []) or []) if str(v)]
    failure_by = [str(v) for v in (contract.get("failure_by", []) or []) if str(v)]

    matched_confirmed = [token for token in confirmed_by if token in observed]
    matched_partial = [token for token in partial_by if token in observed]
    matched_failure = [token for token in failure_by if token in observed]
    matched_secondary = [token for token in secondary if token in observed]
    matched_primary = primary if primary and primary in observed else ""
    matched_primary_exploit = [token for token in primary_exploit if token in observed]
    matched_verification_only = [token for token in verification_only if token in observed]
    high_impact_required = primary == "high_impact_indicator_observed"

    if matched_failure:
        return {
            "verification_status": "execution_failed",
            "judge_reason": f"Observed failure evidence: {', '.join(matched_failure)}",
            "matched_outcomes": matched_failure,
            "confidence": "medium",
            "confirmed": False,
        }
    if (fallback_exploitable and not high_impact_required) or matched_primary or matched_confirmed or matched_primary_exploit:
        matches = [matched_primary] if matched_primary else []
        matches.extend(matched_confirmed)
        matches.extend(matched_primary_exploit)
        return {
            "verification_status": "confirmed_exploitable",
            "judge_reason": fallback_reason or "Observed primary or confirmed exploit outcomes",
            "matched_outcomes": [m for m in matches if m],
            "confidence": "high",
            "confirmed": True,
        }
    if matched_verification_only:
        return {
            "verification_status": "confirmed_sink_control",
            "judge_reason": f"Observed verification-only sink control evidence: {', '.join(matched_verification_only)}",
            "matched_outcomes": matched_verification_only,
            "confidence": "medium",
            "confirmed": False,
        }
    if matched_secondary and high_impact_required:
        return {
            "verification_status": "confirmed_sink_control",
            "judge_reason": f"Observed secondary verification evidence only: {', '.join(matched_secondary)}",
            "matched_outcomes": matched_secondary,
            "confidence": "medium",
            "confirmed": False,
        }
    if matched_secondary:
        return {
            "verification_status": "partially_verified",
            "judge_reason": f"Observed secondary exploit evidence: {', '.join(matched_secondary)}",
            "matched_outcomes": matched_secondary,
            "confidence": "medium",
            "confirmed": False,
        }
    if matched_partial and high_impact_required:
        return {
            "verification_status": "confirmed_sink_control",
            "judge_reason": f"Observed verification-only sink control evidence: {', '.join(matched_partial)}",
            "matched_outcomes": matched_partial,
            "confidence": "medium",
            "confirmed": False,
        }
    if matched_partial:
        return {
            "verification_status": "partially_verified",
            "judge_reason": f"Observed partial exploit evidence: {', '.join(matched_partial)}",
            "matched_outcomes": matched_partial,
            "confidence": "medium",
            "confirmed": False,
        }
    if evidence.get("requests_made") or evidence.get("side_effects_observed"):
        return {
            "verification_status": "reached_but_not_triggered",
            "judge_reason": "Exploit path was exercised but no confirmed outcome matched the contract",
            "matched_outcomes": [],
            "confidence": "medium",
            "confirmed": False,
        }
    return {
        "verification_status": "judge_inconclusive",
        "judge_reason": fallback_reason or "Judge could not derive enough evidence from execution output",
        "matched_outcomes": [],
        "confidence": "low",
        "confirmed": False,
    }


def _iast_judge_reason(iast_state: str, dast_impact: bool, dast_reason: str) -> str:
    base = {
        STATE_SINK_REACHED: "IAST SINK_HIT：canary 身份段+元字符段均到达 sink（保真+可达）",
        STATE_ARRIVAL_SANITIZED: "IAST：canary 身份段到达 sink 但元字符被净化（仅部分可达）",
        STATE_NO_ARRIVAL: "IAST：窗口内未观测到匹配 canary 的事件",
    }.get(iast_state, f"IAST state={iast_state}")
    if dast_impact:
        return base + "；DAST 观察到影响证据"
    if dast_reason:
        return base + f"；DAST 未证影响（{dast_reason}）"
    return base + "；DAST 未证影响"


def judge_verification(
    *,
    exploit_spec: Optional[Dict[str, Any]],
    execution_evidence: Optional[Dict[str, Any]],
    fallback_exploitable: bool = False,
    fallback_reason: str = "",
    iast_evidence: Optional[Dict[str, Any]] = None,
    dast_impact_evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """危害裁定。

    以两条正交信号做裁定：IAST 证据（SINK_HIT，保真+可达）与 DAST/AI 影响证据（危害）。
    当传入 iast_evidence（含 state）时走 IAST 感知的五态组合裁定；否则保持既有 DAST/AI
    裁定路径并向后兼容。
    """
    spec = normalize_exploit_spec(exploit_spec)
    evidence = normalize_execution_evidence(execution_evidence)
    legacy = _judge_dast_path(spec=spec, evidence=evidence, fallback_exploitable=fallback_exploitable, fallback_reason=fallback_reason)

    if iast_evidence and iast_evidence.get("state"):
        iast_state = iast_evidence["state"]
        iast_conf = iast_evidence.get("confidence", "low")
        # DAST 影响是否观察到：优先 dast_impact_evidence.impact_observed，其次 legacy 裁定 confirmed_exploitable
        dast_impact = bool(dast_impact_evidence and dast_impact_evidence.get("impact_observed"))
        dast_impact = dast_impact or (legacy.get("confirmed") and legacy.get("verification_status") == "confirmed_exploitable")
        stable_disproof = bool(dast_impact_evidence and dast_impact_evidence.get("stable_disproof"))

        if iast_state == STATE_SINK_REACHED:
            final_state = FINAL_CONFIRMED_ATTRIBUTABLE if dast_impact else FINAL_RUNTIME_CONFIRMED
        elif iast_state == STATE_ARRIVAL_SANITIZED:
            # 值到达 sink 但元字符被净化：有 DAST 影响则歧义，无则视为无证据（净化候选）
            final_state = FINAL_AMBIGUOUS if dast_impact else FINAL_NO_EVIDENCE
        else:  # no-arrival
            if dast_impact:
                final_state = FINAL_AMBIGUOUS
            elif stable_disproof:
                final_state = FINAL_FALSE_POSITIVE_SAST_ONLY
            else:
                final_state = FINAL_NO_EVIDENCE

        confirmed = final_state in (FINAL_CONFIRMED_ATTRIBUTABLE, FINAL_RUNTIME_CONFIRMED)
        return {
            "verification_status": legacy.get("verification_status", "judge_inconclusive"),
            "final_state": final_state,
            "judge_reason": _iast_judge_reason(iast_state, dast_impact, legacy.get("judge_reason", "")),
            "matched_outcomes": legacy.get("matched_outcomes", []),
            "confidence": iast_conf if iast_state == STATE_SINK_REACHED else legacy.get("confidence", "low"),
            "confirmed": confirmed,
            "iast_evidence": iast_evidence,
            "dast_impact_evidence": dast_impact_evidence,
        }

    # 非 IAST 模式：补齐新键，保持向后兼容
    legacy["final_state"] = ""
    legacy["iast_evidence"] = None
    legacy["dast_impact_evidence"] = dast_impact_evidence
    return legacy
