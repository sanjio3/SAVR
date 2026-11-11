"""
Structured root-cause audit for tasks/findings where D2 did not reach confirmed exploitability.
"""

from typing import Any, Dict, Iterable, List


def _text(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> List[Any]:
    return list(value or []) if isinstance(value, list) else []


def _reason_from_gaps(prefix: str, gaps: Iterable[str]) -> str:
    rendered = ", ".join(_text(item) for item in gaps if _text(item))
    return f"{prefix}: {rendered}" if rendered else prefix


def audit_d2_zero_finding(vuln: Dict[str, Any]) -> Dict[str, Any]:
    proof_tier = _text(vuln.get("proof_tier") or "broad_static")
    proof_gaps = [item for item in _list(vuln.get("proof_gaps")) if _text(item)]
    contract_gaps = [item for item in _list(vuln.get("contract_gaps")) if _text(item)]
    completeness = vuln.get("contract_completeness") or {}
    decision = vuln.get("verification_decision") or {}
    evidence = vuln.get("execution_evidence") or {}
    failure = vuln.get("failure_classification") or {}
    runtime_source = _text(vuln.get("runtime_source"))
    runtime_type = _text(vuln.get("runtime_type"))
    step_errors = [item for item in _list(vuln.get("step_errors")) if _text(item)]
    verification_status = _text(decision.get("verification_status"))
    matched_outcomes = [item for item in _list(decision.get("matched_outcomes")) if _text(item)]
    side_effects = [item for item in _list(evidence.get("side_effects_observed")) if _text(item)]
    requests = [item for item in _list(evidence.get("requests_made")) if _text(item)]

    if proof_tier != "chain_proven":
        return {
            "category": "A2_PROOF_FAILURE",
            "summary": _reason_from_gaps("A2 did not prove the exploit chain strongly enough", proof_gaps),
            "next_actions": [
                "Review A1 evidence and handler-bound route/source pairing",
                "Tighten family-specific proof obligations for attacker control, gate, and payload shape",
            ],
        }

    if completeness.get("status") != "ready" or contract_gaps:
        return {
            "category": "A21_CONTRACT_FAILURE",
            "summary": _reason_from_gaps("A2.1 could not compile a contract-ready exploit spec", contract_gaps),
            "next_actions": [
                "Fill missing entry/method/parameter binding",
                "Add family-specific prerequisite and runtime setup steps",
            ],
        }

    if runtime_source == "generic_fallback":
        return {
            "category": "A29_RUNTIME_FAILURE",
            "summary": "D2 used a generic fallback runtime that did not match the target application",
            "next_actions": [
                "Fix runtime bootstrap so the target application starts from project Docker/generated runtime/local runtime",
                "Exclude generic fallback from formal D2 verification",
            ],
        }

    if failure.get("category") == "runtime_unavailable" or step_errors:
        detail = _text(failure.get("explanation")) or "; ".join(step_errors[:3])
        return {
            "category": "A29_RUNTIME_FAILURE",
            "summary": f"Runtime preparation or execution failed: {detail}".strip(),
            "next_actions": [
                "Inspect startup logs, ready probe, and runtime source",
                "Fix generated runtime or local execution bootstrap",
            ],
        }

    if verification_status == "confirmed_sink_control":
        return {
            "category": "JUDGE_ONLY_SINK_CONTROL",
            "summary": "D2 confirmed sink control or expression execution, but high-impact outcomes were not observed",
            "next_actions": [
                "Strengthen high-impact payload ladder for this family/context",
                "Add richer indicators for file read, environment read, command execution, or state change",
            ],
        }

    if verification_status in {"judge_inconclusive", "reached_but_not_triggered", "partially_verified"}:
        return {
            "category": "D2_HIGH_IMPACT_MISS",
            "summary": f"D2 executed the chain ({verification_status}) but did not confirm a high-impact outcome",
            "next_actions": [
                "Improve runtime setup, authentication, victim resource preparation, or trigger ordering",
                "Refine family-specific high-impact payloads and outcome indicators",
            ],
        }

    if requests or side_effects or matched_outcomes:
        return {
            "category": "D2_EXECUTION_MODE_FAILURE",
            "summary": "D2 exercised the chain but execution mode evidence was too weak to confirm exploit success",
            "next_actions": [
                "Review execution mode against required runtime setup and ordered steps",
                "Capture stronger before/after state and side-effect evidence",
            ],
        }

    # 未获 D2 验证的 finding 写入明确的 verification_decision（not_scheduled / no_verification_record
    # + scheduling_reason + final_state），不再留空。审计直接采信该显式原因，不再靠
    # 「无 decision 且无 evidence」反推「疑似未入队」。
    _sched_reason = _text(decision.get("scheduling_reason"))
    if _sched_reason:
        _not_scheduled = verification_status == "not_scheduled"
        return {
            "category": "D2_NOT_SCHEDULED" if _not_scheduled else "D2_RESULT_LOST",
            "summary": (
                ("（★）契约就绪（chain_proven）但未进入 D2 执行队列：" if _not_scheduled
                 else "（★）已进入 D2 候选但无验证记录（上游结果丢失）：") + _sched_reason
            ),
            "next_actions": [
                "按 scheduling_reason 处置：absorbed_member=设计行为；business_logic_not_selected=A2.1 选型未选中；"
                "no_trigger_spec / trigger_spec_without_endpoint=补路由解析与 spec 登记",
                "enqueued_but_no_verification_record 属缺陷（已强制入队却无结果），须查 D2 调度留痕与结果落库",
            ],
        }

    # 「D2 有没有跑过」与「跑了但证据没落库」是两种完全不同的故障，处置动作也不同，
    # 判据：A2.1 已把契约编好（proof_tier=chain_proven 且 contract ready、无 contract_gaps）、
    # 运行时也不是 generic_fallback、更没有 step_errors —— 却**连一条执行痕迹都没有**
    # （decision 为空、evidence 里没有 requests_made / side_effects_observed / matched_outcomes）。
    # 这说明该链路**根本没被排进 D2 执行队列**，而不是「执行了但结构化证据缺失」。
    if not decision and not evidence:
        return {
            "category": "D2_NOT_SCHEDULED",
            "summary": (
                f"（★）Chain is contract-ready (proof_tier=chain_proven) but shows **no D2 execution trace at all**: "
                f"no verification_decision, no requests_made / side_effects_observed / matched_outcomes. "
                f"runtime={runtime_source or runtime_type or 'unknown'}."
            ),
            "next_actions": [
                "chain_proven 已在 _d2_gate_predicate 强制入队（2026-09-22 落地）；此分支仅应作为"
                "「调度留痕缺失」的推断兜底出现，正常不再命中",
                "若仍命中：查 stage_results.d2.scheduling（候选人/入队/未入队+原因），确认是门禁漏排还是结果丢失",
            ],
        }

    return {
        "category": "REPORTING_OR_PIPELINE_MISMATCH",
        "summary": f"No useful D2 evidence was recorded despite proof_tier={proof_tier}, runtime={runtime_source or runtime_type or 'unknown'}",
        "next_actions": [
            "Check D2 scheduling and result persistence",
            "Verify the finding entered formal D2 execution and produced structured evidence",
        ],
    }


def summarize_d2_zero_audit(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    categories: Dict[str, int] = {}
    examples: Dict[str, Dict[str, Any]] = {}
    audited_count = 0
    for vuln in findings or []:
        if _text((vuln.get("verification_decision") or {}).get("verification_status")) == "confirmed_exploitable":
            continue
        if vuln.get("a21_selected") is not True and _text(vuln.get("proof_tier")) != "chain_proven":
            audit = audit_d2_zero_finding(vuln)
        elif _text(vuln.get("proof_tier")) == "chain_proven" or vuln.get("a21_selected") is True:
            audit = audit_d2_zero_finding(vuln)
        else:
            continue
        vuln["d2_zero_audit"] = audit
        category = _text(audit.get("category")) or "UNKNOWN"
        categories[category] = categories.get(category, 0) + 1
        audited_count += 1
        examples.setdefault(category, {
            "type": vuln.get("type", ""),
            "chain_id": vuln.get("chain_id", ""),
            "summary": audit.get("summary", ""),
        })
    primary_category = ""
    if categories:
        primary_category = sorted(categories.items(), key=lambda item: (-item[1], item[0]))[0][0]
    return {
        "audited_count": audited_count,
        "categories": categories,
        "primary_category": primary_category,
        "examples": examples,
        "summary": examples.get(primary_category, {}).get("summary", "") if primary_category else "",
    }
