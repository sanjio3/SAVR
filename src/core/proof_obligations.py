"""
Shared proof-obligation helpers for A1 evidence, A2 proofing, and A2.1 gating.
"""

from typing import Any, Dict, Iterable, List, Optional
import re

from .exploit_spec import (
    empty_chain_proof, merge_exploit_specs, normalize_chain_proof, normalize_exploit_spec,
    DIFFERENTIAL_PROOF_FAMILIES, _BUSINESS_LOGIC_FAMILY_ALIASES, canonical_business_logic_family,
    derive_flow_type,
)


AUTH_FAMILIES = {"auth-bypass", "jwt", "cookie", "cors", "csrf"}
DEFAULT_CREDENTIAL_FAMILIES = {"default-credentials"}

# F3：业务逻辑/状态机/认证会话等「差分证明族」——没有注入型的 gate（鉴权门）/回显信号语义，其
# 「证明」是 D1 运行时差分（换身份取回他人数据 / 状态分歧 / 管理员数据暴露）。SAST 证明阶段只要已
# 声明差分信号类型，即视为 gate 与 success_signal 已满足，避免结构性误判为 broad_static（进而被
# d2_zero_audit 标 A2_PROOF_FAILURE）。注入型族（sql/xss/command/deserialization 等）绝不在此集合内，
# 行为完全不变，保护现有已确认项。
_DIFFERENTIAL_PROOF_FAMILIES = DIFFERENTIAL_PROOF_FAMILIES  # 真源见 src/core/exploit_spec.py（2026-09-03 合并 P1–P5 五套判据）

# 业务/逻辑类家族「显示名 → 规范差分族」别名表。A2 产出的 payload_family 是混用的：既有规范英文
# （idor / race-condition / state-machine）、变体英文（race condition / vertical-privilege-escalation /
# business-logic-bypass / amount-tampering）、也有中文标签（状态机跳步 / 金额篡改 / 并发超发/竞态条件 /
# 水平越权(idor) / 垂直越权 / 批量赋值）。evaluate_proof_obligations 此前直接用原始 payload_family 比对
# _DIFFERENTIAL_PROOF_FAMILIES（仅含规范英文 token），导致几乎所有业务族（尤其中文标签）永远命中不了
# 差分豁免，被结构性误判为 broad_static → A2_PROOF_FAILURE。此表把各类显示名归一为规范差分 token，
# 使 F3 豁免真正连上（「executor 未接」根因）。仅覆盖业务/越权/认证/滥用类；注入型族（sql/ssrf/xss/
# 命令/模板/xxe 等）不在此表，行为不变。
_FAMILY_ALIAS_TO_DIFF = _BUSINESS_LOGIC_FAMILY_ALIASES  # 真源见 src/core/exploit_spec.py；本文件不再维护副本（2026-09-03 合并 P1–P5）


def _canonical_diff_family(raw: str) -> str:
    """兼容旧名：归一逻辑统一走 exploit_spec.canonical_business_logic_family（单一真相源）。"""
    return canonical_business_logic_family(raw)


def _normalize_candidates(items: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            normalized.append(item)
    return normalized


def _semantic_tags(candidate: Dict[str, Any]) -> List[str]:
    raw = (candidate or {}).get("semantic_tags", []) or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(tag or "").strip().lower() for tag in raw if str(tag or "").strip()]


def _align_candidates(candidates: Optional[Iterable[Dict[str, Any]]], route: str = "", handler: str = "") -> List[Dict[str, Any]]:
    pool = _normalize_candidates(candidates)
    route = str(route or "").strip()
    handler = str(handler or "").strip()
    if route:
        route_matches = [item for item in pool if str((item or {}).get("route", "") or "").strip() == route]
        if route_matches:
            return route_matches
    if handler:
        handler_matches = [item for item in pool if str((item or {}).get("function", "") or "").strip() == handler]
        if handler_matches:
            return handler_matches
    return pool


def empty_proof_context_summary() -> Dict[str, Any]:
    return {
        "entry_candidate_count": 0,
        "source_candidate_count": 0,
        "guard_candidate_count": 0,
        "sanitizer_candidate_count": 0,
        "ownership_candidate_count": 0,
        "state_candidate_count": 0,
        "artifact_candidate_count": 0,
        "nearest_entry_route": "",
        "nearest_source_name": "",
        "nearest_guard_snippet": "",
        "bound_handler": "",
        "cross_file_evidence": False,
        "sanitized_inputs": [],
    }


def candidate_line(candidate: Dict[str, Any]) -> int:
    try:
        return int((candidate or {}).get("line", 0) or 0)
    except (TypeError, ValueError):
        return 0


def pick_nearest_candidate(vuln: Any, candidates: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    vuln_file = str(getattr(vuln, "file", "") or "")
    vuln_line = int(getattr(vuln, "line", 0) or 0)
    pool = list(candidates or [])
    if not pool:
        return None

    def sort_key(candidate: Dict[str, Any]):
        file_mismatch = 0 if str((candidate or {}).get("file", "") or "") == vuln_file else 1
        line_distance = abs(candidate_line(candidate) - vuln_line) if vuln_line else 999999
        return (file_mismatch, line_distance)

    return sorted(pool, key=sort_key)[0]


def merge_a1_evidence(per_file: Optional[Dict[str, Any]], aggregate: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    per_file = per_file or {}
    aggregate = aggregate or {}
    merged: Dict[str, Any] = {}
    for key in (
        "entry_candidates",
        "source_candidates",
        "sink_candidates",
        "guard_candidates",
        "sanitizer_candidates",
        "ownership_candidates",
        "state_transition_candidates",
        "artifact_candidates",
        "business_logic_candidates",
    ):
        merged[key] = list(per_file.get(key, []) or []) + list(aggregate.get(key, []) or [])
    return merged


def summarize_proof_context(vuln: Any, evidence: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    evidence = evidence or {}
    summary = empty_proof_context_summary()
    entry_candidates = list(evidence.get("entry_candidates", []) or [])
    source_candidates = list(evidence.get("source_candidates", []) or [])
    guard_candidates = list(evidence.get("guard_candidates", []) or [])
    sanitizer_candidates = list(evidence.get("sanitizer_candidates", []) or [])
    ownership_candidates = list(evidence.get("ownership_candidates", []) or [])
    state_candidates = list(evidence.get("state_transition_candidates", []) or [])
    artifact_candidates = list(evidence.get("artifact_candidates", []) or [])
    business_logic_candidates = list(evidence.get("business_logic_candidates", []) or [])
    summary["entry_candidate_count"] = len(entry_candidates)
    summary["source_candidate_count"] = len(source_candidates)
    summary["guard_candidate_count"] = len(guard_candidates)
    summary["sanitizer_candidate_count"] = len(sanitizer_candidates)
    summary["ownership_candidate_count"] = len(ownership_candidates)
    summary["state_candidate_count"] = len(state_candidates)
    summary["artifact_candidate_count"] = len(artifact_candidates)
    summary["business_logic_candidate_count"] = len(business_logic_candidates)
    nearest_entry = pick_nearest_candidate(vuln, entry_candidates) or {}
    nearest_source = pick_nearest_candidate(vuln, source_candidates) or {}
    nearest_guard = pick_nearest_candidate(vuln, guard_candidates) or {}
    summary["nearest_entry_route"] = str(nearest_entry.get("route", "") or "")
    summary["nearest_source_name"] = str(nearest_source.get("name", "") or "")
    summary["nearest_guard_snippet"] = str(nearest_guard.get("snippet", "") or "")
    summary["bound_handler"] = str(nearest_entry.get("function", "") or nearest_source.get("function", "") or "")
    vuln_file = str(getattr(vuln, "file", "") or "")
    all_candidates = entry_candidates + source_candidates + guard_candidates + sanitizer_candidates + ownership_candidates + state_candidates + artifact_candidates
    summary["cross_file_evidence"] = any(str((item or {}).get("file", "") or "") != vuln_file for item in all_candidates if (item or {}).get("file"))
    summary["sanitized_inputs"] = [
        str((candidate or {}).get("name", "") or "")
        for candidate in sanitizer_candidates
        if str((candidate or {}).get("name", "") or "")
    ]
    return summary


def is_ssrf_source_candidate(candidate: Dict[str, Any]) -> bool:
    tags = _semantic_tags(candidate)
    if "url_like" in tags:
        return True
    name = str((candidate or {}).get("name", "") or "").strip().lower()
    if name in {"url", "uri", "target", "target_url", "endpoint", "dest", "destination", "redirect", "next", "path"}:
        return True
    return any(token in name for token in ("url", "uri", "endpoint", "target", "redirect"))


def has_ssrf_source_evidence(vuln: Any, evidence: Optional[Dict[str, Any]] = None, *, route: str = "", handler: str = "") -> bool:
    evidence = evidence or getattr(vuln, "a1_evidence", {}) or {}
    candidates = _align_candidates(evidence.get("source_candidates", []), route=route, handler=handler)
    return any(is_ssrf_source_candidate(candidate) for candidate in candidates)


def has_idor_source_evidence(vuln: Any, parameter_name: str = "", evidence: Optional[Dict[str, Any]] = None, *, route: str = "", handler: str = "") -> bool:
    evidence = evidence or getattr(vuln, "a1_evidence", {}) or {}
    normalized_parameter = str(parameter_name or "").strip().lower()
    candidates = _align_candidates(evidence.get("source_candidates", []), route=route, handler=handler)
    for candidate in candidates:
        tags = _semantic_tags(candidate)
        name = str((candidate or {}).get("name", "") or "").strip().lower()
        location = str((candidate or {}).get("location", "") or "").strip().lower()
        if normalized_parameter and name == normalized_parameter and location in {"path", "query", "json", "body", "form"}:
            return True
        if "resource_identifier" in tags and location in {"path", "query", "json", "body", "form"}:
            return True
    return False


# SQL 注入「外部可控输入」的文本兜底判据（2026-10-05）。
# 原实现用硬编码 token 子串比对，只认 `getparameter(` 这一个字面形态，于是：
#   getParameterValues( / getParameterNames( / getParameterMap(  → 因后缀不匹配全漏
#   getCookies( / getHeader(                                    → 整类漏
#   scr.getTheParameter(（自定义包装类 getter）                  → 整类漏
# 实测后果：OWASP sample-200 上三个真漏洞（BenchmarkTest00100 cookie 遍历 /
# 00595 getParameterNames / 01552 自定义包装类）A2 已判「真漏洞」，却在 A21 候选
# 评分处被 `missing query-like source evidence` 刷掉，永不生成 spec ⇒ L1 恒漏。
# 改成正则，覆盖「get 开头、含 parameter/header/cookie 的任意取值 API」。
_SQLI_SOURCE_TEXT_RE = re.compile(
    # 注意 `parameter` 两侧都要留 \w*：只留前侧会漏掉 getParameterMap( / 
    # getParameterNames( 这类带后缀的形态（后缀落在 `parameter` 之后，匹配不到 `(`）。
    r"get\s*\w*parameter\w*\s*\("    # getParameter / getParameterValues / getParameterNames
                                     # / getParameterMap / getTheParameter（自定义包装类）
    r"|get\s*\w*header\w*\s*\("      # getHeader / getHeaders
    r"|get\w*cookie\w*\s*\("         # getCookies / getCookieValue
    r"|request\.args|request\.form|request\.values|requestbody|@requestparam",
    re.IGNORECASE,
)


def has_sql_injection_source_evidence(vuln: Any, parameter_name: str = "", evidence: Optional[Dict[str, Any]] = None) -> bool:
    evidence = evidence or getattr(vuln, "a1_evidence", {}) or {}
    lowered_parameter = str(parameter_name or "").strip().lower()
    for candidate in list(evidence.get("source_candidates", []) or []):
        name = str((candidate or {}).get("name", "") or "").strip().lower()
        location = str((candidate or {}).get("location", "") or "").strip().lower()
        if lowered_parameter and name == lowered_parameter:
            return True
        if location in {"query", "form", "body", "json"} and name in {"id", "q", "query", "search", "username", "email", "filter", "sort", "input"}:
            return True
    lower_text = " ".join([
        str(getattr(vuln, "type", "") or ""),
        str(getattr(vuln, "description", "") or ""),
        str(getattr(vuln, "code_snippet", "") or ""),
        str(getattr(vuln, "data_flow", "") or ""),
        str(getattr(vuln, "sink", "") or ""),
    ]).lower()
    if lowered_parameter and _SQLI_SOURCE_TEXT_RE.search(lower_text):
        return True
    return False


def is_auth_header_sanitized(sanitizer_candidates: Iterable[Dict[str, Any]], parameter_name: str) -> bool:
    normalized = str(parameter_name or "").strip().lower()
    if not normalized:
        return False
    for candidate in sanitizer_candidates or []:
        name = str((candidate or {}).get("name", "") or "").strip().lower()
        if name and name == normalized:
            return True
    return False


def has_auth_source_evidence(vuln: Any, parameter_name: str = "", evidence: Optional[Dict[str, Any]] = None, *, route: str = "", handler: str = "") -> bool:
    evidence = evidence or getattr(vuln, "a1_evidence", {}) or {}
    lowered_parameter = str(parameter_name or "").strip().lower()
    auth_names = {"token", "authorization", "cookie", "session", "jwt", "next", "redirect", "x-user"}
    if lowered_parameter and lowered_parameter not in auth_names:
        return False
    for candidate in _align_candidates(evidence.get("source_candidates", []), route=route, handler=handler):
        tags = _semantic_tags(candidate)
        name = str((candidate or {}).get("name", "") or "").strip().lower()
        location = str((candidate or {}).get("location", "") or "").strip().lower()
        if "auth_like" in tags:
            return True
        if name in auth_names:
            return True
        if lowered_parameter and name == lowered_parameter and location in {"header", "cookie", "query", "body", "form"}:
            return True
    lower_text = " ".join([
        str(getattr(vuln, "type", "") or ""),
        str(getattr(vuln, "description", "") or ""),
        str(getattr(vuln, "code_snippet", "") or ""),
        str(getattr(vuln, "data_flow", "") or ""),
        str(getattr(vuln, "sink", "") or ""),
        str(getattr(vuln, "entry_point", "") or ""),
    ]).lower()
    explicit_source_patterns = (
        r"request\.headers\.get\(['\"](?:authorization|x-user|cookie)['\"]",
        r"request\.cookies?\.get\(['\"](?:token|session|jwt|cookie)['\"]",
        r"request\.(?:args|form|values)\.get\(['\"](?:token|next|redirect)['\"]",
    )
    return any(re.search(pattern, lower_text) for pattern in explicit_source_patterns)


def merge_supporting_text(vuln: Any, supporting_nodes: Optional[List[Dict[str, Any]]] = None) -> str:
    text = "\n".join([
        str(getattr(vuln, "type", "") or ""),
        str(getattr(vuln, "description", "") or ""),
        str(getattr(vuln, "code_snippet", "") or ""),
        str(getattr(vuln, "entry_point", "") or ""),
        str(getattr(vuln, "sink", "") or ""),
        str(getattr(vuln, "data_flow", "") or ""),
        str(getattr(vuln, "callers", "") or ""),
        str(getattr(vuln, "verdict", "") or ""),
        str(getattr(vuln, "file", "") or ""),
    ]).lower()
    for node in list(supporting_nodes or []):
        text += "\n" + "\n".join([
            str(node.get("description", "") or ""),
            str(node.get("code_snippet", "") or ""),
            str(node.get("entry_point", "") or ""),
            str(node.get("sink", "") or ""),
            str(node.get("callers", "") or ""),
            str(node.get("verdict", "") or ""),
        ]).lower()
    return text


def evaluate_proof_obligations(
    vuln: Any,
    exploit_spec: Optional[Dict[str, Any]],
    *,
    evidence: Optional[Dict[str, Any]] = None,
    supporting_nodes: Optional[List[Dict[str, Any]]] = None,
    incoming_proof: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    spec = normalize_exploit_spec(exploit_spec)
    proof = normalize_chain_proof(incoming_proof or empty_chain_proof())
    evidence = evidence or getattr(vuln, "a1_evidence", {}) or {}
    entry = spec.get("entry", {})
    payload = spec.get("payload", {})
    prerequisites = spec.get("prerequisites", {})
    success_signal = spec.get("success_signal", {})
    route = str(entry.get("route", "") or "")
    method = str(entry.get("method", "") or "")
    parameter_name = str(entry.get("parameter_name", "") or "")
    payload_family = str(payload.get("payload_family", "") or "")
    lower_text = merge_supporting_text(vuln, supporting_nodes)
    source_candidates = list(evidence.get("source_candidates", []) or [])
    guard_candidates = list(evidence.get("guard_candidates", []) or [])
    sanitizer_candidates = list(evidence.get("sanitizer_candidates", []) or [])
    ownership_candidates = list(evidence.get("ownership_candidates", []) or [])
    handler = str((getattr(vuln, "proof_context_summary", {}) or {}).get("bound_handler", "") or "")
    aligned_sources = _align_candidates(source_candidates, route=route, handler=handler)
    aligned_guards = _align_candidates(guard_candidates, route=route, handler=handler)
    aligned_ownership = _align_candidates(ownership_candidates, route=route, handler=handler)
    ssrf_source = has_ssrf_source_evidence(vuln, evidence, route=route, handler=handler)
    sqli_source = has_sql_injection_source_evidence(vuln, parameter_name, evidence)
    auth_source = has_auth_source_evidence(vuln, parameter_name, evidence, route=route, handler=handler)
    idor_source = has_idor_source_evidence(vuln, parameter_name, evidence, route=route, handler=handler)
    auth_sanitized = bool(entry.get("parameter_location") == "header" and is_auth_header_sanitized(sanitizer_candidates, parameter_name))
    path_source_names = {"file", "path", "filepath", "filename", "location", "resource", "template"}
    path_source = bool(
        parameter_name.strip().lower() in path_source_names
        or any(str((candidate or {}).get("name", "") or "").strip().lower() in path_source_names for candidate in aligned_sources)
        or any(
            "path" in str(tag).lower() or "file" in str(tag).lower()
            for candidate in aligned_sources
            for tag in list((candidate or {}).get("semantic_tags", []) or [])
        )
    )
    implicit_response_families = {
        "sql-injection",
        "xss",
        "template-injection",
        "xpath-injection",
        "open-redirect",
        "file-upload",
        "path-traversal",
        "command-execution",
        "idor",
    }
    implicit_state_families = {
        "workflow-bypass",
        "race-condition",
        "auth-bypass",
        "csrf",
        "jwt",
        "cookie",
        "cors",
        "default-credentials",
    }

    attacker_markers = ("requestparam", "requestbody", "pathvariable", "getparameter", "user-controlled", "http", "query", "form", "json")
    proof["reachable"] = bool(proof.get("reachable") or getattr(vuln, "has_http_entry", False) or getattr(vuln, "has_call_chain", False) or getattr(vuln, "callers", "") or route)
    proof["attacker_control_proven"] = bool(
        proof.get("attacker_control_proven")
        or (
            route
            and (
                parameter_name
                or aligned_sources
                or any(marker in lower_text for marker in attacker_markers)
                or (payload_family == "idor" and aligned_ownership)
                or (payload_family in implicit_state_families and (prerequisites.get("ordered_steps") or prerequisites.get("dependent_data")))
            )
        )
    )
    has_gate_requirements = bool(
        prerequisites.get("role_or_permission")
        or prerequisites.get("token_requirements")
        or prerequisites.get("session_requirements")
        or aligned_guards
    )
    proof["gate_bypass_or_satisfaction_proven"] = bool(
        proof.get("gate_bypass_or_satisfaction_proven")
        or not has_gate_requirements
        or payload_family == "idor"
        or any(marker in lower_text for marker in ("debug", "internal", "test", "admin", "bypass"))
    )
    proof["payload_shape_proven"] = bool(
        proof.get("payload_shape_proven")
        or (
            payload_family
            and payload_family != "generic"
            and (
                payload.get("payload_constraints")
                or payload.get("object_shape_constraints")
                or parameter_name
                or aligned_sources
                or (payload_family == "idor" and aligned_ownership)
                or (payload_family in implicit_state_families and (prerequisites.get("ordered_steps") or prerequisites.get("dependent_data")))
            )
        )
    )
    proof["success_signal_anchor_proven"] = bool(
        proof.get("success_signal_anchor_proven")
        or (
            success_signal.get("signal_type")
            and (
                success_signal.get("verify_request")
                or success_signal.get("expected_indicators")
                or success_signal.get("side_effect_target")
                or entry.get("trigger_route")
                or payload_family in implicit_response_families
                or (
                    payload_family in implicit_state_families
                    and (prerequisites.get("ordered_steps") or prerequisites.get("dependent_data") or route)
                )
            )
        )
    )

    if payload_family == "ssrf" and not ssrf_source:
        proof["attacker_control_proven"] = False
        proof["payload_shape_proven"] = False
    if payload_family == "idor":
        if not idor_source:
            proof["attacker_control_proven"] = False
            proof["payload_shape_proven"] = False
        if not aligned_ownership:
            proof["payload_shape_proven"] = False
        if not aligned_guards and prerequisites.get("auth_required") != "required":
            proof["gate_bypass_or_satisfaction_proven"] = False
    if payload_family == "sql-injection" and not sqli_source:
        proof["attacker_control_proven"] = False
        proof["payload_shape_proven"] = False
    if payload_family == "path-traversal" and not path_source:
        proof["attacker_control_proven"] = False
        proof["payload_shape_proven"] = False
    if payload_family in AUTH_FAMILIES and (not auth_source or auth_sanitized):
        proof["attacker_control_proven"] = False
        proof["payload_shape_proven"] = False
    if payload_family in AUTH_FAMILIES and not aligned_guards:
        proof["gate_bypass_or_satisfaction_proven"] = False
    if payload_family in DEFAULT_CREDENTIAL_FAMILIES:
        has_credential_evidence = bool(
            any("auth_like" in _semantic_tags(candidate) for candidate in aligned_sources)
            or "curl --user" in lower_text
            or "admin_password=admin" in lower_text
            or "admin:admin" in lower_text
            or payload.get("candidate_payloads")
        )
        proof["reachable"] = bool(proof.get("reachable") or route or "/api/user" in lower_text or "/api/users/" in lower_text or "/login" in lower_text)
        proof["attacker_control_proven"] = bool(proof.get("attacker_control_proven") and has_credential_evidence)
        proof["payload_shape_proven"] = bool(
            proof.get("payload_shape_proven")
            and has_credential_evidence
            and (route or success_signal.get("verify_request") or "/api/user" in lower_text or "/api/users/" in lower_text)
        )
        proof["gate_bypass_or_satisfaction_proven"] = bool(
            proof.get("gate_bypass_or_satisfaction_proven")
            and ("admin" in lower_text or aligned_guards or prerequisites.get("role_or_permission"))
        )
        proof["success_signal_anchor_proven"] = bool(
            proof.get("success_signal_anchor_proven")
            and (
                success_signal.get("verify_request")
                or success_signal.get("expected_indicators")
                or "/api/user" in lower_text
                or "/api/users/" in lower_text
            )
        )

    # F3：差分证明族的结构性豁免——业务类漏洞在 SAST 阶段无法满足注入型的 gate/回显门槛，其证据
    # 由 D1 运行时差分收集。只要「已声明差分信号类型」或「已解析出真实 HTTP 路由（route）」即把 gate
    # 与 success_signal 视为已满足（并补齐可达性/攻击者可控/载荷形态这些 SAST 可判的项），使 proof_tier
    # 可达 chain_proven，不再被 d2_zero_audit 误标 A2_PROOF_FAILURE。业务族极少声明 signal_type（其证明
    # 本就在运行时差分收集），故旧门槛（强制 signal_type）结构性把它们误判为 broad_static；放宽为
    # 「有 route 即可」后，凡 SAST 已解析出真实端点的业务族即可达 chain_proven。注入型族不进入此分支，行为不变。
    # 关键修正：「executor 未接」——A2 产出的 payload_family 是混用显示名（规范英文/变体英文/中文标签），
    # 须先经 _canonical_diff_family 归一为规范差分 token，否则差分豁免永远命中不了（见上方 _FAMILY_ALIAS_TO_DIFF）。
    diff_family = _canonical_diff_family(payload_family)
    if diff_family in _DIFFERENTIAL_PROOF_FAMILIES and (success_signal.get("signal_type") or route):
        proof["gate_bypass_or_satisfaction_proven"] = True
        proof["success_signal_anchor_proven"] = True
        # 攻击者可控 = 能发出该请求（有 route 即满足；无参管理端点如 /admin/users 亦同），不要求必有参数名。
        # 但若该族属 AUTH_FAMILIES 且已被净化（auth_sanitized 为 True），净化击败了攻击者对认证头的控制，
        # 不得由差分豁免强行覆盖 line-429 的净化降级，否则跨文件 sanitizer 降级失效 → 误报
        # （见 test_cross_file_auth_header_sanitizer_downgrades_auth_bypass_chain）。净化只击败「攻击者可控」
        # 与「载荷形态」，可达性/门禁/成功信号锚点仍按业务族正常满足。
        _auth_sanitizer_defeats = payload_family in AUTH_FAMILIES and auth_sanitized
        if (parameter_name or route) and not _auth_sanitizer_defeats:
            proof["attacker_control_proven"] = True
        if not _auth_sanitizer_defeats:
            proof["payload_shape_proven"] = bool(proof.get("payload_shape_proven") or parameter_name or route)
        proof["reachable"] = bool(proof.get("reachable") or route)

    proof["proof_gaps"] = [
        key for key in (
            "reachable",
            "attacker_control_proven",
            "gate_bypass_or_satisfaction_proven",
            "payload_shape_proven",
            "success_signal_anchor_proven",
        )
        if not proof.get(key)
    ]
    gap_count = len(proof["proof_gaps"])
    proof["proof_confidence"] = "high" if gap_count == 0 else ("medium" if gap_count <= 2 else "low")
    return normalize_chain_proof(proof)


# --------------------------------------------------------------------------- 污点流假说 #

TAINT_FLOW_OBLIGATIONS = (
    "reachable",
    "attacker_control_proven",
    "gate_bypass_or_satisfaction_proven",
    "payload_shape_proven",
    "success_signal_anchor_proven",
)

SEVERITY_LADDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# IAST 观测态：污点抵达但被净化 ⇒ barrier 确实存在（与 iast/orchestrator 保持一致）
SANITIZED_STATE = "arrival-sanitized"


def empty_taint_flow_hypothesis() -> Dict[str, Any]:
    """结构化污点流假说的空壳。

    sink 本身不等于危险：只有 source（攻击者可控输入）→ sink 可达，且中间没有
    净化器/barrier 截断，才算一条完整 flow。这里把「完整 flow」拆成四个核心维度，
    并保留 A2 的五个证明义务原值供 I2 逐条对账。
    """
    return {
        "source_present": False,
        "sink_present": False,
        "reachable": False,
        "barrier_free": False,
        "flow_complete": False,
        "obligations": {key: False for key in TAINT_FLOW_OBLIGATIONS},
        "proof_gaps": [],
        "proof_confidence": "low",
    }


def _sink_present(vuln: Any, exploit_spec: Optional[Dict[str, Any]]) -> bool:
    """是否识别到 sink（危险函数调用点）。注意：识别到 sink 只是候选，不等于危险。

    2026-10-05（r58 方案 5）补 fallback：原先只看 ``vuln.sink`` 与
    ``exploit_spec.poc_chain`` 两处，但 A2 实际把 sink 位置记在 ``vuln.file`` +
    ``vuln.line`` 上而 ``vuln.sink`` 常留空串 ⇒ ``sink_present`` 在 r58 全 4777 条
    spec 上恒为 False ⇒ ``flow_complete``（= source ∧ sink ∧ reachable ∧
    barrier_free）恒为 False，**整个污点流假说里最严格的那一档从未被点亮过**，
    依赖它的闸门模拟（precision_gate_sim 的 G5）也只能算出 0%。
    这里补的 fallback 读的是同一份 sink 定位信息，不引入新证据、不放宽语义。

    影响面（r58 实测回算）：补齐后 1724 条 flow_complete 变 True，其中 1659 条
    本来就是 chain_proven（``confirmed`` 早已为 True，不受影响），真正因本修复
    改变 confirmed 判定的只有 65 条 broad_static（1.4%）。
    """
    if str(getattr(vuln, "sink", "") or "").strip():
        return True
    # fallback 1：平台已记录 sink 所在文件与行号（vuln.sink 为空时的常态）
    if str(getattr(vuln, "file", "") or "").strip() and (getattr(vuln, "line", None) or 0):
        return True
    spec = normalize_exploit_spec(exploit_spec)
    for node in list(spec.get("poc_chain") or []):
        if isinstance(node, dict) and str(node.get("stage") or "").strip().lower() == "sink":
            return True
    # fallback 2：exploit_spec 里显式给出的 sink 定位
    if str(spec.get("sink") or spec.get("sink_file") or spec.get("sink_location") or "").strip():
        return True
    return False


def build_taint_flow_hypothesis(
    vuln: Any,
    proof: Optional[Dict[str, Any]],
    exploit_spec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """由 A2 的 proof_obligations 结果构造结构化污点流假说。

    四个核心维度：
      source_present  ← attacker_control_proven（有攻击者可控 source 点）
      sink_present    ← 是否识别到 sink 点
      reachable       ← source→sink 可达
      barrier_free    ← gate/barrier 已被绕过或满足（中间无有效净化器）
    flow_complete 为四者全真，只有它为真时「危险」才可断言。
    """
    normalized = normalize_chain_proof(proof or empty_chain_proof())
    hypothesis = empty_taint_flow_hypothesis()
    obligations = {key: bool(normalized.get(key)) for key in TAINT_FLOW_OBLIGATIONS}
    sink = _sink_present(vuln, exploit_spec)
    source = bool(obligations.get("attacker_control_proven"))
    reachable = bool(obligations.get("reachable"))
    barrier_free = bool(obligations.get("gate_bypass_or_satisfaction_proven"))
    hypothesis.update(
        {
            "source_present": source,
            "sink_present": sink,
            "reachable": reachable,
            "barrier_free": barrier_free,
            "flow_complete": bool(source and sink and reachable and barrier_free),
            "obligations": obligations,
            "proof_gaps": list(normalized.get("proof_gaps") or []),
            "proof_confidence": str(normalized.get("proof_confidence") or "low"),
        }
    )
    return hypothesis


def derive_severity_from_proof(
    claimed_severity: Optional[str],
    proof_tier: Optional[str],
    proof_gaps: Optional[List[str]],
) -> str:
    """severity 由 proof 状态推导，而不是让 LLM 自由文本压住。

    - chain_proven（静态已证全 flow）→ 沿用 claimed（可断言高危）；
    - broad_static 且有 gaps → 降级：缺口 ≤2 降一级，>2 降两级，下限为 LOW
      （完全未证成的候选 sink 仍是待查线索，不被 UNKNOWN 淹没）。

    这样「HIGH + ❌假漏洞-无调用点」的自相矛盾不会再出现——没证出完整 flow 的
    候选 sink 不会顶着高危。
    """
    claimed = str(claimed_severity or "UNKNOWN").strip().upper()
    if claimed not in SEVERITY_LADDER:
        claimed = "MEDIUM"
    gaps = list(proof_gaps or [])
    if str(proof_tier or "broad_static") == "chain_proven" and not gaps:
        return claimed
    if not gaps:
        return claimed
    step = 1 if len(gaps) <= 2 else 2
    index = SEVERITY_LADDER.index(claimed)
    if index <= 0:
        return claimed
    # 下限探到 LOW：完全未证成的候选 sink 仍是待查线索，不该被 UNKNOWN 淹没
    return SEVERITY_LADDER[max(1, index - step)]


FALSE_POSITIVE_VERDICT_MARKERS = ("❌", "假漏洞", "false positive", "false-positive")


def verdict_is_false_positive(verdict: Optional[str]) -> bool:
    """A2 自己是否已判定该条为假漏洞（如「无调用点」）。"""
    text = str(verdict or "").lower()
    return any(marker in text for marker in FALSE_POSITIVE_VERDICT_MARKERS)


def derive_finding_gate(
    claimed_severity: Optional[str],
    proof_tier: Optional[str],
    proof_gaps: Optional[List[str]],
    obligations: Optional[Dict[str, bool]] = None,
    flow_complete: bool = False,
    verdict: Optional[str] = None,
    sink_present: bool = True,
) -> Dict[str, Any]:
    """统一推导「这条 finding 能否断言危险」，输出 severity / confirmed / is_dangerous。

    裁决顺序（后者覆盖前者）：
    1. gaps 为空但 obligations 有未满足项时，从 obligations 反推真实缺口
       （历史上 chain_proof 可能是空壳：booleans 全假而 gaps 为空）；
    2. tier 非 chain_proven 却无任何缺口 → 补一个标记缺口，避免「未证成」被当成「已证成」；
    3. 只有 tier==chain_proven 且所有义务满足（或 flow_complete）才 confirmed；
       **且 chain_proven 必须伴随 sink 点识别**——「完整流已证」但 sink:无 自相矛盾，
       缺 sink 时补 sink_not_identified 缺口并降级，confirmed 强制 False；
    4. A2 自己判定为假漏洞 → 强制 confirmed=False 且 severity 压到 LOW，
       彻底消掉「HIGH + ❌假漏洞-无调用点」的自相矛盾。
    """
    obligations = dict(obligations or {})
    gaps = list(proof_gaps or [])
    tier = str(proof_tier or "broad_static")

    if not gaps and obligations:
        gaps = [key for key, met in obligations.items() if not met]
    if tier != "chain_proven" and not gaps:
        gaps = ["proof_tier_not_chain_proven"]

    all_met = bool(obligations) and all(obligations.values())
    # §fix：chain_proven 必须识别到 sink 点，否则「完整流已证」与「sink:无」矛盾。
    # 仍声称已证成却无 sink 的，补缺口并降级，confirmed 强制 False。
    if tier == "chain_proven" and all_met and not sink_present and "sink_not_identified" not in gaps:
        gaps.append("sink_not_identified")
    is_chain_proven = tier == "chain_proven" and not gaps and all_met and sink_present
    confirmed = bool(flow_complete) or is_chain_proven
    severity = derive_severity_from_proof(
        claimed_severity, "chain_proven" if is_chain_proven else "broad_static", gaps
    )
    reason = "chain_proven" if is_chain_proven else ("flow_complete" if flow_complete else "unproven")

    if verdict_is_false_positive(verdict):
        confirmed = False
        severity = "LOW"
        reason = "verdict_false_positive"

    return {
        "severity": severity,
        "confirmed": confirmed,
        "is_dangerous": confirmed,
        "effective_gaps": gaps,
        "reason": reason,
    }


def apply_runtime_evidence(
    hypothesis: Optional[Dict[str, Any]],
    iast_evidence: Optional[Dict[str, Any]] = None,
    dast_impact_evidence: Optional[Dict[str, Any]] = None,
    d2_verdict: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """把 D1(IAST 重放) / D2(DAST) 的运行时证据映射到 A2 同一组证明义务。

    闭合规则：
      - 探针 sink-reached + canary 命中 ⇒ 证出 source→sink 真实传播，
        闭合 reachable 与 attacker_control_proven；
      - 运行时观测到净化/归一化（sanitizer）⇒ barrier 确实存在，
        反驳 gate_bypass_or_satisfaction_proven；
      - DAST 观测到影响 ⇒ 闭合 success_signal_anchor_proven / payload_shape_proven。

    返回逐条 resolution：closed / refuted / open。
    """
    iast = iast_evidence or {}
    dast = dast_impact_evidence or {}
    d2 = d2_verdict or {}
    base = dict(hypothesis or empty_taint_flow_hypothesis())
    claimed_obligations = dict(base.get("obligations") or {})

    resolution: Dict[str, str] = {}
    for key in TAINT_FLOW_OBLIGATIONS:
        resolution[key] = "closed" if claimed_obligations.get(key) else "open"

    state = str(iast.get("state") or "")
    matched = list(iast.get("matched_event_ids") or [])
    sink_reached = bool(
        state == "sink-reached"
        or d2.get("sink_reached")
        or dast.get("reached")
    )
    # 净化信号来源：显式标记，或探针观测态为 arrival-sanitized（污点抵达但被净化）。
    # 注意：sink-reached 但无 canary 命中只说明无法归属，不等于存在净化器，不能据此判净化。
    sanitizer_observed = bool(
        iast.get("sanitizer_observed")
        or d2.get("sanitizer_observed")
        or dast.get("sanitizer_observed")
        or state == SANITIZED_STATE
    )
    impact_observed = bool(dast.get("impact_observed") or d2.get("harmful"))

    if sink_reached and matched:
        resolution["reachable"] = "closed"
        resolution["attacker_control_proven"] = "closed"

    if sanitizer_observed:
        resolution["gate_bypass_or_satisfaction_proven"] = "refuted"
    elif sink_reached and not sanitizer_observed:
        resolution["gate_bypass_or_satisfaction_proven"] = resolution.get(
            "gate_bypass_or_satisfaction_proven"
        ) or "closed"

    if impact_observed:
        resolution["success_signal_anchor_proven"] = "closed"
        resolution["payload_shape_proven"] = resolution.get("payload_shape_proven") or "closed"

    return {
        "obligations": claimed_obligations,
        "resolution": resolution,
        "closed": [k for k, v in resolution.items() if v == "closed"],
        "refuted": [k for k, v in resolution.items() if v == "refuted"],
        "open": [k for k, v in resolution.items() if v == "open"],
        "runtime_evidence": {
            "sink_reached": sink_reached,
            "canary_matched": bool(matched),
            "sanitizer_observed": sanitizer_observed,
            "impact_observed": impact_observed,
        },
    }


def residual_proof_gaps(
    hypothesis: Optional[Dict[str, Any]],
    proof_resolution: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """闭环信号：A2 声称的 flow ⊖ I2 解析后的 flow = 残差 gaps/diff。

    newly_closed 是本轮运行时证据新闭合的义务；still_open 是仍未闭合的；
    refuted 是被运行时证据反驳的（例如确实存在 sanitizer），这些要回灌 A2 重新推导。
    """
    base = dict(hypothesis or empty_taint_flow_hypothesis())
    claimed_gaps = list(base.get("proof_gaps") or [])
    resolution = dict((proof_resolution or {}).get("resolution") or {})
    return {
        "claimed_gaps": claimed_gaps,
        "still_open": [k for k, v in resolution.items() if v != "closed"],
        "refuted": [k for k, v in resolution.items() if v == "refuted"],
        "newly_closed": [k for k in TAINT_FLOW_OBLIGATIONS if k in claimed_gaps and resolution.get(k) == "closed"],
    }
