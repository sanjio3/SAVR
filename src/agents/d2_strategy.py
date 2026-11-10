"""
Deterministic strategy selection for D2 verification.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

from src.core.exploit_spec import (
    exploit_spec_completeness,
    failure_classification,
    has_meaningful_exploit_spec,
    merge_exploit_specs,
    normalize_exploit_spec,
)
from src.core.tool_registry import ToolRegistry, tool_id_for_contract
from .d2_types import VerificationResult
from .d2_judge import extract_execution_evidence, judge_verification
from .d2_execution_modes import annotate_strategy_with_execution_mode


_LANGUAGE_BY_SUFFIX = {
    ".java": "java",
    ".py": "python",
    ".js": "node",
    ".jsx": "node",
    ".ts": "node",
    ".tsx": "node",
    ".php": "php",
    ".sh": "shell",
    ".bash": "shell",
}

_VERIFY_ROUTES = {
    ("java", "sql-injection"): ("_verify_java_sqli_chain", "Java SQL injection"),
    ("java", "xss"): ("_verify_java_reflected_xss_chain", "Java reflected XSS"),
    ("java", "command-execution"): ("_verify_java_command_chain", "Java command execution"),
    ("java", "ssrf"): ("_verify_java_ssrf_chain", "Java SSRF"),
    ("java", "xxe"): ("_verify_java_xxe_chain", "Java XXE"),
    ("java", "xpath-injection"): ("_verify_java_xpath_chain", "Java XPath injection"),
    ("java", "template-injection"): ("_verify_java_template_chain", "Java template injection"),
    ("java", "jwt"): ("_verify_java_jwt_chain", "Java JWT"),
    ("java", "cors"): ("_verify_java_cors_chain", "Java CORS"),
    ("java", "cookie"): ("_verify_java_cookie_chain", "Java cookie"),
    ("java", "auth-bypass"): ("_verify_java_auth_chain", "Java auth bypass"),
    ("java", "open-redirect"): ("_verify_java_open_redirect_chain", "Java open redirect"),
    ("java", "file-upload"): ("_verify_java_file_upload_chain", "Java file upload"),
    ("java", "path-traversal"): ("_verify_java_path_chain", "Java path traversal"),
    ("python", "sql-injection"): ("_verify_python_sqli_chain", "Python SQL injection"),
    ("python", "xss"): ("_verify_python_reflected_xss_chain", "Python reflected XSS"),
    ("python", "template-injection"): ("_verify_python_jinja2_ssti_chain", "Python template injection"),
    ("python", "path-traversal"): ("_verify_python_path_chain", "Python path traversal"),
    ("python", "xxe"): ("_verify_python_xxe_chain", "Python XXE"),
    ("python", "xpath-injection"): ("_verify_python_xpath_chain", "Python XPath injection"),
    ("python", "ssrf"): ("_verify_python_ssrf_chain", "Python SSRF"),
    ("python", "idor"): ("_verify_python_idor_chain", "Python IDOR"),
    ("python", "jwt"): ("_verify_python_jwt_chain", "Python JWT"),
    ("python", "deserialization"): ("_verify_python_pickle_chain", "Python deserialization"),
    ("python", "command-execution"): ("_verify_python_command_chain", "Python command execution"),
    ("python", "file-upload"): ("_verify_python_file_upload_chain", "Python file upload"),
    ("node", "template-injection"): ("_verify_node_template_injection_chain", "Node template injection"),
    ("node", "deserialization"): ("_verify_node_deserialization_chain", "Node deserialization"),
    ("node", "command-execution"): ("_verify_node_command_injection_chain", "Node command execution"),
    ("node", "ssrf"): ("_verify_node_ssrf_chain", "Node SSRF"),
    ("node", "path-traversal"): ("_verify_node_path_traversal_chain", "Node path traversal"),
    ("node", "file-upload"): ("_verify_node_file_upload_chain", "Node file upload"),
    ("node", "jwt"): ("_verify_node_jwt_chain", "Node JWT"),
    ("node", "open-redirect"): ("_verify_node_open_redirect_chain", "Node open redirect"),
    ("node", "nosql-injection"): ("_verify_node_nosql_chain", "Node NoSQL injection"),
    ("php", "command-execution"): ("_verify_php_command_chain", "PHP command execution"),
    ("php", "sql-injection"): ("_verify_php_sqli_chain", "PHP SQL injection"),
    ("php", "xss"): ("_verify_php_xss_chain", "PHP reflected XSS"),
    ("php", "open-redirect"): ("_verify_php_open_redirect_chain", "PHP open redirect"),
    ("php", "ssrf"): ("_verify_php_ssrf_chain", "PHP SSRF"),
    ("php", "jwt"): ("_verify_php_jwt_chain", "PHP JWT"),
    ("php", "xxe"): ("_verify_php_xxe_chain", "PHP XXE"),
    ("php", "xpath-injection"): ("_verify_php_xpath_chain", "PHP XPath injection"),
    ("php", "deserialization"): ("_verify_php_deserialization_chain", "PHP deserialization"),
    ("php", "path-traversal"): ("_verify_php_path_chain", "PHP path traversal"),
    ("php", "file-upload"): ("_verify_php_file_upload_chain", "PHP file upload"),
    ("shell", "default-credentials"): ("_verify_default_credentials_chain", "Default credentials"),
}

_PROFILE_DEFAULTS = {
    "sql-injection": {"parameter": "id", "baseline": "1", "payload": "' OR '1'='1", "expected": ""},
    "xss": {"parameter": "q", "payload": "<svg/onload=alert(1)>", "expected": "<svg/onload=alert(1)>"},
    "command-execution": {"parameter": "cmd", "payload": "id", "expected": "uid="},
    "ssrf": {"parameter": "url", "payload": "http://127.0.0.1:80", "expected": "127.0.0.1"},
    "idor": {"parameter": "id", "payload": "2", "expected": "", "baseline": "1"},
    "xxe": {"parameter": "xml", "transport": "body", "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "expected": "root:"},
    "xpath-injection": {"parameter": "name", "baseline": "guest", "payload": "' or '1'='1", "expected": "", "transport": "param"},
    "template-injection": {"parameter": "name", "payload": "{{7*7}}", "expected": "49"},
    "jwt": {"parameter": "token", "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJhMyI6IjQ5In0.", "expected": "admin"},
    "open-redirect": {"parameter": "next", "payload": "https://example.com/a3", "expected": "https://example.com/a3"},
    "path-traversal": {"parameter": "file", "payload": "../../../../etc/passwd", "expected": "root:"},
    "file-upload": {"parameter": "file", "expected": "ok"},
    "deserialization": {"parameter": "data", "payload": "gASVCQAAAAAAAAB9lIwCYTOUSzFzLg==", "expected": "a3"},
    "nosql-injection": {"parameter": "username", "baseline": "guest", "payload": '{"$ne": null}', "expected": "", "transport": "json"},
    "csrf": {"body": "a3=49", "content_type": "application/x-www-form-urlencoded"},
    "cors": {},
    "cookie": {},
    "auth-bypass": {},
}

_LANGUAGE_PROFILE_OVERRIDES = {
    ("node", "template-injection"): {"parameter": "tpl", "payload": "<%= 7 * 7 %>", "expected": "49"},
    ("java", "template-injection"): {"parameter": "name", "payload": "#{7*7}", "expected": "49"},
    ("python", "template-injection"): {"parameter": "name", "payload": "{{7*7}}", "expected": "49"},
    ("node", "deserialization"): {"parameter": "data", "payload": '{"rce":"_$$ND_FUNC$$_function(){return 7*7}()"}', "expected": "49"},
    ("php", "deserialization"): {"parameter": "data", "payload": 'a:1:{s:2:"a3";s:2:"49";}', "expected": "49"},
    ("python", "deserialization"): {"parameter": "data", "payload": "gASVCQAAAAAAAAB9lIwCYTOUSzFzLg==", "expected": "a3"},
    ("java", "deserialization"): {"parameter": "data"},
}


def _attach_strategy_attack_plan(agent, result: Optional[VerificationResult], vulnerability: Dict, project_context: Dict, strategy: Optional[Dict]):
    if result is None or not strategy:
        return result
    merged_spec = normalize_exploit_spec({})
    for candidate in (
        vulnerability.get("exploit_spec"),
        getattr(result, "attack_plan", {}).get("exploit_spec") if isinstance(getattr(result, "attack_plan", {}), dict) else {},
        getattr(result, "exploit_spec", {}),
    ):
        if has_meaningful_exploit_spec(candidate):
            merged_spec = merge_exploit_specs(merged_spec, candidate)
    result.exploit_spec = normalize_exploit_spec(merged_spec)
    result.execution_evidence = extract_execution_evidence(getattr(result, "raw_output", ""), result.exploit_spec)
    result.verification_decision = judge_verification(
        exploit_spec=result.exploit_spec,
        execution_evidence=result.execution_evidence,
        fallback_exploitable=bool(getattr(result, "exploitable", False)),
        fallback_reason=str(getattr(result, "reason", "") or ""),
    )
    if hasattr(agent, "_apply_ai_mixed_judge"):
        try:
            ai_decision = agent._apply_ai_mixed_judge(
                vulnerability=vulnerability,
                project_context=project_context or {},
                result=result,
            )
            if isinstance(ai_decision, dict) and ai_decision:
                merged_ai_decision = dict(ai_decision)
                merged_ai_decision.setdefault("ai_used", True)
                result.verification_decision = merged_ai_decision
        except Exception:
            pass
    if result.verification_decision.get("confirmed"):
        result.exploitable = True
        result.confidence = result.verification_decision.get("confidence", result.confidence)
        if result.verification_decision.get("judge_reason"):
            result.reason = str(result.verification_decision.get("judge_reason") or result.reason)
    else:
        result.exploitable = False
        if result.verification_decision.get("judge_reason"):
            result.reason = str(result.verification_decision.get("judge_reason") or result.reason)
    # RAG+LLM 攻击计划升级：确定性模板只靠猜的字段（route/parameter/encoding 缺失）
    # 由 LLM 补齐；高完备度仍走纯模板。网关构造失败/离线一律降级模板（不阻断主链路）。
    # A 第三步（2026-09-28 批准）：白名单校验——route 只能命中既有端点集合，parameter 只能来自 spec 参数集合。
    rag_plan = None
    if not getattr(result, "attack_plan", None) and hasattr(agent, "_ensure_attack_plan"):
        try:
            from .d2_plan_rag import generate_attack_plan, record_confirmed_plan
            from src.core.model_gateway import gateway_from_config
            _gw = gateway_from_config(getattr(agent, "config", None) or {})
            _allowed_eps = [
                str(vulnerability.get("entry_point") or ""),
                str(merged_spec.get("entry", {}).get("route") or ""),
                str(merged_spec.get("entry", {}).get("trigger_route") or ""),
                str(strategy.get("target_path") or "") if isinstance(strategy, dict) else "",
            ]
            _allowed_params = [
                str(merged_spec.get("entry", {}).get("parameter_name") or ""),
                str(strategy.get("parameter") or "") if isinstance(strategy, dict) else "",
                str(strategy.get("query_key") or "") if isinstance(strategy, dict) else "",
            ]
            rag_plan = generate_attack_plan(
                vulnerability=vulnerability,
                project_context=project_context or {},
                exploit_spec=merged_spec,
                gateway=_gw,
                allowed_endpoints=[e for e in _allowed_eps if e],
                allowed_params=[p for p in _allowed_params if p],
            )
        except Exception as _e:  # RAG 是增强项，任何异常都不应阻断
            logger.debug("[D2] RAG 攻击计划生成失败（降级模板）：%s", _e)
            rag_plan = None
        result = agent._ensure_attack_plan(result, vulnerability, project_context, strategy=strategy, plan=rag_plan)
        # A 第三步：LLM 补出的 route/parameter（已过白名单）回填 exploit_spec.entry（仅空位），
        # 使 D2 验证与落库产物吃到 LLM 补齐值；resolved_by 留痕可审计。
        # 必须在 _ensure_attack_plan 之后回填 result.exploit_spec——提前改 merged_spec
        # 会被 _ensure_attack_plan 内部的重新归并覆盖。
        if rag_plan:
            try:
                _rspec = getattr(result, "exploit_spec", None)
                if isinstance(_rspec, dict):
                    _entry = _rspec.setdefault("entry", {})
                    _sr = str(rag_plan.get("suggested_route") or "").strip()
                    _sp = str(rag_plan.get("suggested_parameter") or "").strip()
                    _changed = False
                    if _sr and not str(_entry.get("route") or "").strip():
                        _entry["route"] = _sr
                        _entry["resolved_by"] = "llm-rag"
                        _changed = True
                    if _sp and not str(_entry.get("parameter_name") or "").strip():
                        _entry["parameter_name"] = _sp
                        _entry["resolved_by"] = "llm-rag"
                        _changed = True
                    if _changed:
                        result.exploit_spec = normalize_exploit_spec(_rspec)
                        result.contract_completeness = exploit_spec_completeness(result.exploit_spec)
            except Exception:
                pass
        # A 第四步埋点：采纳（source=llm）与采纳后 confirmed 率。
        try:
            from .d2_plan_rag import bump_metric
            if rag_plan is not None and isinstance(getattr(result, "attack_plan", None), dict) \
                    and result.attack_plan.get("source") == "llm":
                bump_metric("adopted")
                if bool(getattr(result, "exploitable", False)):
                    bump_metric("adopted_confirmed")
        except Exception:
            pass
        # 闭环反哺：本条确认可利用 → 把正样本写入 POC 记忆库，供后续同族检索 few-shot。
        if rag_plan is not None and bool(getattr(result, "exploitable", False)):
            try:
                from .d2_plan_rag import record_confirmed_plan
                record_confirmed_plan(
                    vulnerability=vulnerability,
                    project_context=project_context or {},
                    exploit_spec=merged_spec,
                    attack_plan=getattr(result, "attack_plan", None) or rag_plan,
                    observation="verified_exploitable",
                )
            except Exception:
                pass
    return result


def _language_for_vulnerability(vulnerability: Dict) -> str:
    suffix = Path(str(vulnerability.get("file", "") or "")).suffix.lower()
    return _LANGUAGE_BY_SUFFIX.get(suffix, "")


def _default_container_port(agent, image: str, language: str) -> str:
    exposed_ports = []
    try:
        exposed_ports = agent.tools._get_image_exposed_ports(image)
    except Exception:
        exposed_ports = []
    if exposed_ports:
        return str(exposed_ports[0])
    return {
        "java": "8080",
        "python": "5000",
        "node": "3000",
        "php": "80",
    }.get(language, "8080")


def _profile_defaults(language: str, family: str) -> Dict:
    defaults = dict(_PROFILE_DEFAULTS.get(family, {}))
    defaults.update(_LANGUAGE_PROFILE_OVERRIDES.get((language, family), {}))
    return defaults


def _choose_java_template_payload(vulnerability: Dict, exploit_spec: Dict, candidate_payloads) -> str:
    chain_key = str(
        vulnerability.get("chain_id")
        or vulnerability.get("canonical_group_key")
        or ""
    ).lower()
    if chain_key == "template-injection:expression_chain":
        preferred = _prefer_high_impact_payload(candidate_payloads, "java", "template-injection")
        if preferred:
            return preferred
        return "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}"
    text_parts = [
        str(vulnerability.get("type", "") or ""),
        str(vulnerability.get("description", "") or ""),
        str(vulnerability.get("code_snippet", "") or ""),
        str(vulnerability.get("sink", "") or ""),
        str(vulnerability.get("callers", "") or ""),
        json.dumps(vulnerability.get("supporting_nodes", []) or [], ensure_ascii=False),
        json.dumps(exploit_spec, ensure_ascii=False),
    ]
    text = "\n".join(text_parts).lower()
    if any(marker in text for marker in ("spelexpressionparser", "templateparsercontext", "parseexpression(", "spel")):
        return "#{7*7}"
    if any(marker in text for marker in ("thymeleaf", "templateengine.process", "springtemplateengine")):
        return "${7*7}"
    if candidate_payloads:
        return candidate_payloads[0]
    return "#{7*7}"


def _infer_template_verification_expected(payload_text: str, fallback_expected: str) -> str:
    payload_lower = str(payload_text or "").lower()
    if "7*7" in payload_lower:
        return "49"
    return fallback_expected


def _prefer_high_impact_payload(payloads, language: str, family: str) -> str:
    items = [str(item or "") for item in (payloads or []) if str(item or "").strip()]
    if not items:
        return ""
    if language == "java" and family == "template-injection":
        for marker in ("getruntime().exec", "runtime().exec", "/etc/passwd", "system).getproperties", "system).getenv", "/flag", "readstring", "readallbytes"):
            for item in items:
                if marker in item.lower():
                    return item
    if family == "command-execution":
        for marker in ("execsync", "child_process", "runtime().exec", "cat /flag", "id"):
            for item in items:
                if marker in item.lower():
                    return item
    return items[0]


def _ordered_high_impact_payloads(payloads, language: str, family: str):
    items = [str(item or "") for item in (payloads or []) if str(item or "").strip()]
    if not items:
        return []
    if language == "java" and family == "template-injection":
        def _score(item: str) -> int:
            lowered = item.lower()
            if "getruntime().exec" in lowered or "runtime().exec" in lowered:
                return 0
            if "/etc/passwd" in lowered:
                return 1
            if "system).getproperties" in lowered or "system).getenv" in lowered:
                return 2
            if "/flag" in lowered:
                return 3
            return 10
        return sorted(items, key=_score)
    return items


def _expected_for_high_impact_payload(payload_text: str, family: str, language: str, fallback_expected: str = "") -> str:
    lowered = str(payload_text or "").lower()
    if language == "java" and family == "template-injection":
        if "getruntime().exec" in lowered or "runtime().exec" in lowered:
            return "uid="
        if "/etc/passwd" in lowered:
            return "root:"
        if "system).getproperties" in lowered or "system).getenv" in lowered:
            return "java.version"
        if "/flag" in lowered:
            return "flag"
    return fallback_expected


def _flatten_high_impact_ladder(ladder, family: str, language: str, fallback_expected: str = ""):
    payloads = []
    expecteds = []
    goals = []
    for item in ladder or []:
        if not isinstance(item, dict):
            continue
        goal = str(item.get("goal", "") or "")
        indicators = [str(v or "") for v in (item.get("expected_indicators", []) or []) if str(v or "")]
        preferred = indicators[0] if indicators else fallback_expected
        for payload_text in item.get("payloads", []) or []:
            rendered = str(payload_text or "").strip()
            if not rendered:
                continue
            payloads.append(rendered)
            expecteds.append(preferred or _expected_for_high_impact_payload(rendered, family, language, fallback_expected))
            goals.append(goal)
    return payloads, expecteds, goals


def _strategy_from_contract(agent, project_path: Path, vulnerability: Dict, language: str, exploit_spec: Dict) -> Optional[Tuple[str, Dict, str]]:
    entry = exploit_spec.get("entry", {})
    payload = exploit_spec.get("payload", {})
    success_signal = exploit_spec.get("success_signal", {})
    family = str(payload.get("payload_family", "") or "")
    image = agent._select_project_image(project_path, "sast-target:latest")
    container_port = _default_container_port(agent, image, language)
    defaults = _profile_defaults(language, family)
    verify_tuple = _VERIFY_ROUTES.get((language, family))

    if family == "csrf":
        strategy = {
            "exploit_family": family,
            "image": image,
            "container_port": container_port,
            "target_path": entry.get("route", "/"),
            "method": entry.get("method", "POST"),
            "body": defaults.get("body", "a3=49"),
            "content_type": entry.get("content_type") or defaults.get("content_type", "application/x-www-form-urlencoded"),
            "source_file": str(vulnerability.get("file", "") or ""),
            "source_line": str(vulnerability.get("line", 0) or 0),
        }
        strategy = annotate_strategy_with_execution_mode(strategy, exploit_spec)
        return "_verify_csrf_chain", strategy, "CSRF"

    if family == "default-credentials":
        verify_path = ((success_signal.get("verify_request") or {}).get("path") if isinstance(success_signal.get("verify_request"), dict) else "") or entry.get("route", "/api/user")
        creds = list(payload.get("candidate_payloads") or payload.get("verification_payloads") or ["admin:admin"])
        username, password = "admin", "admin"
        if creds and ":" in str(creds[0]):
            username, password = str(creds[0]).split(":", 1)
        high_impact_payloads = list(payload.get("high_impact_payloads") or [])
        strategy = {
            "exploit_family": "default_credentials",
            "image": image,
            "container_port": container_port,
            "target_path": entry.get("route", "/api/users/1"),
            "verify_path": verify_path,
            "method": entry.get("method", "PUT"),
            "username": username,
            "password": password,
            "marker_email": high_impact_payloads[0] if high_impact_payloads else "a3-proof-admin-email@example.com",
            "source_file": str(vulnerability.get("file", "") or ""),
            "source_line": str(vulnerability.get("line", 0) or 0),
        }
        strategy = annotate_strategy_with_execution_mode(strategy, exploit_spec)
        return "_verify_default_credentials_chain", strategy, "Default credentials"

    trigger_route = (
        entry.get("trigger_route")
        or ((success_signal.get("verify_request") or {}).get("path") if isinstance(success_signal.get("verify_request"), dict) else "")
        or _extract_trigger_route(exploit_spec)
    )

    if language == "java" and family == "deserialization" and trigger_route:
        strategy = {
            "exploit_family": "java_map_deserialization",
            "image": image,
            "container_port": container_port,
            "import_path": entry.get("route", "/"),
            "trigger_path": trigger_route,
            "probe_path": trigger_route,
            "proof_file": "/tmp/a3_verified_poc",
            "jar_relative_path": "BOOT-INF/lib/commons-collections-3.1.jar",
            "parameter": entry.get("parameter_name") or defaults.get("parameter", "data"),
            "source_file": str(vulnerability.get("file", "") or ""),
            "source_line": str(vulnerability.get("line", 0) or 0),
        }
        strategy = annotate_strategy_with_execution_mode(strategy, exploit_spec)
        return "_verify_map_deserialization_chain", strategy, "Java map deserialization"

    if not verify_tuple:
        return None

    verify_name, log_label = verify_tuple
    expected = ""
    indicators = success_signal.get("expected_indicators", []) or []
    if indicators:
        expected = indicators[0]

    candidate_payloads = payload.get("candidate_payloads") or []
    verification_payloads = payload.get("verification_payloads") or []
    high_impact_payloads = payload.get("high_impact_payloads") or []
    ladder_payloads, ladder_expecteds, ladder_goals = _flatten_high_impact_ladder(
        payload.get("high_impact_ladder") or [],
        family,
        language,
        expected or defaults.get("expected", ""),
    )
    ladder_meta = {
        str(payload_text): {
            "expected": ladder_expecteds[idx] if idx < len(ladder_expecteds) else "",
            "goal": ladder_goals[idx] if idx < len(ladder_goals) else "",
        }
        for idx, payload_text in enumerate(ladder_payloads)
    }
    ordered_high_impact_payloads = _ordered_high_impact_payloads(
        ladder_payloads or high_impact_payloads,
        language,
        family,
    )
    primary_payloads = list(ordered_high_impact_payloads) or list(candidate_payloads) or list(verification_payloads)
    selected_payload = _prefer_high_impact_payload(primary_payloads, language, family) if primary_payloads else defaults.get("payload", "")
    if language == "java" and family == "template-injection" and not high_impact_payloads:
        selected_payload = _choose_java_template_payload(vulnerability, exploit_spec, list(high_impact_payloads) or list(candidate_payloads))

    strategy = {
        "exploit_family": f"{language}_{family.replace('-', '_')}",
        "image": image,
        "container_port": container_port,
        "target_path": entry.get("route", "/"),
        "method": entry.get("method", "GET"),
        "parameter": entry.get("parameter_name") or defaults.get("parameter", "input"),
        "payload": selected_payload,
        "expected": expected or defaults.get("expected", ""),
        "transport": defaults.get("transport", ""),
        "source_file": str(vulnerability.get("file", "") or ""),
        "source_line": str(vulnerability.get("line", 0) or 0),
    }
    if ordered_high_impact_payloads:
        strategy["high_impact_payload"] = selected_payload
        strategy["high_impact_payloads"] = ordered_high_impact_payloads
        strategy["high_impact_expecteds"] = (
            [ladder_meta.get(item, {}).get("expected", "") for item in ordered_high_impact_payloads]
            if ladder_meta else
            [
                _expected_for_high_impact_payload(item, family, language, expected or defaults.get("expected", ""))
                for item in ordered_high_impact_payloads
            ]
        )
        strategy["high_impact_goals"] = [ladder_meta.get(item, {}).get("goal", "") for item in ordered_high_impact_payloads]
        strategy["expected"] = _expected_for_high_impact_payload(
            selected_payload,
            family,
            language,
            expected or defaults.get("expected", ""),
        )
    if verification_payloads:
        strategy["fallback_payload"] = verification_payloads[0]
        strategy["fallback_expected"] = _infer_template_verification_expected(
            verification_payloads[0],
            defaults.get("expected", ""),
        )

    if entry.get("content_type") == "application/json":
        strategy["transport"] = "json"
    elif entry.get("parameter_location") == "raw_body":
        strategy["transport"] = "raw_body"
    elif entry.get("parameter_location") == "body" and not strategy.get("transport"):
        strategy["transport"] = "body"
    elif entry.get("parameter_location") == "header":
        strategy["header_name"] = entry.get("parameter_name") or defaults.get("parameter", "Authorization")

    if "baseline" in defaults:
        strategy["baseline"] = defaults["baseline"]
    if family == "template-injection":
        strategy["render_path"] = entry.get("route", "/")
        strategy["probe_path"] = entry.get("route", "/")
    if family == "file-upload":
        strategy["field_name"] = entry.get("parameter_name") or defaults.get("parameter", "file")
        strategy["filename"] = "a3-test.jsp" if language == "java" else "a3-test.php" if language in {"node", "php"} else "a3-test.py"
        strategy["content"] = "<% out.print(49); %>" if language == "java" else "<?php echo 49; ?>" if language in {"node", "php"} else "print(49)"
    if family == "nosql-injection" and not strategy.get("transport"):
        strategy["transport"] = "json"
    if family == "idor":
        strategy["resource_path_template"] = entry.get("route", "/")
        if entry.get("parameter_location") == "path":
            strategy["transport"] = "path"
    if (
        language == "node"
        and family == "command-execution"
        and str(entry.get("method", "") or "").upper() == "POST"
        and str(entry.get("parameter_name", "") or "") == "body_text"
    ):
        strategy["transport"] = "raw_body"
        if strategy.get("payload") == "7*7" or "7*7" in list(verification_payloads):
            strategy["expected"] = "49"

    strategy = annotate_strategy_with_execution_mode(strategy, exploit_spec)
    return verify_name, strategy, log_label


def _incomplete_contract_result(exploit_spec: Dict) -> VerificationResult:
    completeness = exploit_spec_completeness(exploit_spec)
    return VerificationResult(
        exploitable=False,
        confidence="low",
        reason="D2 skipped deterministic execution because the exploit contract is incomplete",
        evidence=completeness.get("missing_required", []),
        poc_type="contract_incomplete",
        poc_code="",
        exploit_spec=exploit_spec,
        contract_completeness=completeness,
        failure_classification=failure_classification(
            category="contract_incomplete",
            subtype="missing_required_fields",
            explanation=", ".join(completeness.get("missing_required", [])) or "exploit spec is incomplete",
            retryable=True,
        ),
    )


def _unsupported_contract_result(exploit_spec: Dict, language: str, family: str) -> VerificationResult:
    return VerificationResult(
        exploitable=False,
        confidence="low",
        reason=f"D2 has no deterministic verifier for {language}:{family}",
        evidence=[f"language={language}", f"payload_family={family}"],
        poc_type="verifier_insufficient",
        poc_code="",
        exploit_spec=exploit_spec,
        contract_completeness=exploit_spec_completeness(exploit_spec),
        failure_classification=failure_classification(
            category="verifier_insufficient",
            subtype="unsupported_payload_family",
            explanation=f"no deterministic verifier is registered for {language}:{family}",
            retryable=True,
        ),
    )


def _approval_required_result(exploit_spec: Dict, tool_spec: Dict, approval_mode: str, allowlist,
                              act: Optional[Dict] = None) -> VerificationResult:
    tool_id = str((tool_spec or {}).get("id", "unknown"))
    risk = str((tool_spec or {}).get("risk_level", "unknown"))
    act = act or {}
    act_cat = str(act.get("category") or "unknown")
    act_reason = str(act.get("reason") or "")
    return VerificationResult(
        exploitable=False,
        confidence="low",
        reason=(f"D2 paused: 待人工放行的**不可逆动作**（{act_cat}）"
                f"@ {act.get('method') or '?'} {act.get('route') or '?'}"),
        evidence=[f"approval_mode={approval_mode}", f"tool={tool_id}", f"risk={risk}",
                  f"act_category={act_cat}", f"act_reason={act_reason}",
                  f"allowlist={','.join(list(allowlist) or [])}"],
        poc_type="approval_required",
        poc_code="",
        exploit_spec=exploit_spec,
        contract_completeness=exploit_spec_completeness(exploit_spec),
        failure_classification=failure_classification(
            category="approval_required",
            subtype="irreversible_action",
            explanation=f"不可逆动作 {act_cat} 需人工放行（{act_reason}）",
            retryable=True,
        ),
        verification_decision={
            "verification_status": "approval_required",
            "judge_reason": f"不可逆动作 {act_cat} 未被放行（mode={approval_mode}）。{act_reason}",
            "matched_outcomes": [],
            "confidence": "low",
            "confirmed": False,
            # 2026-09-24：批准链路接通的前提。闸门是「按动作类别」放行的
            # （act_allowlist 比对的正是这里的 category），而 failure_classification.category
            # 恒为字面量 "approval_required" —— 若下游只拿 failure_classification 当类别，
            # 写进白名单的就会是 "approval_required"，与闸门判定时算出的
            # money_out/data_destroy 之类永远不等，批准后重跑依旧被拦。
            # 故在此把闸门判定用的 act 原样带出，供 pending_action 与批准流程取用。
            "act": {
                "irreversible": bool(act.get("irreversible")),
                "category": act_cat,
                "route": act.get("route") or "",
                "method": act.get("method") or "",
                "reason": act_reason,
            },
        },
    )


def _flatten_text(value: object, _depth: int = 0) -> str:
    """递归收集结构里的所有字符串，供 payload 破坏性文本判定用（有深度上限防环）。"""
    if _depth > 6:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten_text(v, _depth + 1) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(v, _depth + 1) for v in value)
    return ""


def _classify_act_risk(exploit_spec: Dict, strategy: Dict) -> Dict:
    """按**将要投放的动作**判定风险（取代旧的「按 tool_id risk_level 拦截」）。

    2026-09-20 重设计。旧语义拦的是「验证器自己用的工具」，等于拦自己的扫描流程：
    粒度是工具、理由说不清危险在哪、一次点击只解一条，且会把流水线卡住。
    新语义只回答一个问题：这个动作**不可逆**吗？

    不可逆判据（复用 src/iast/attack_context 的既有两层，不新增口径）：
      1. 端点语义：`classify_destructive_operation(method, route)` →
         credential_mutation / mass_assignment / data_destroy / money_out / status_overwrite；
      2. payload 文本：`is_destructive_sql_payload`（DROP/TRUNCATE/无 WHERE 的 DELETE·UPDATE）
         与 `is_destructive_command_payload`（rm -rf / mkfs / dd of= / 关机 / fork bomb / curl|sh）。

    只读与追加型动作（GET 读、下单、评论、只读探针、无害命令 whoami）一律判为可逆 → 不问。
    """
    from src.iast.attack_context import (
        classify_destructive_operation,
        is_destructive_command_payload,
        is_destructive_sql_payload,
    )

    entry = exploit_spec.get("entry") or {}
    route = str(entry.get("route") or "").strip() or _extract_trigger_route(exploit_spec)
    method = str(entry.get("method") or "GET").upper()
    category = classify_destructive_operation(method, route)

    blob = _flatten_text(strategy)
    sql_d = is_destructive_sql_payload(blob)
    cmd_d = is_destructive_command_payload(blob)

    reasons = []
    if category:
        reasons.append(f"端点语义={category}")
    if sql_d:
        reasons.append("payload 含破坏性 SQL")
    if cmd_d:
        reasons.append("payload 含破坏性系统命令")
    if not reasons:
        reasons.append("可逆/只读动作")
    return {
        "irreversible": bool(category or sql_d or cmd_d),
        "category": category or ("destructive_payload" if (sql_d or cmd_d) else None),
        "route": route,
        "method": method,
        "reason": "；".join(reasons),
    }


APPROVAL_MODES = ("off", "ask_on_risky_tools", "strict")
# M14：破坏性闸门在后续扫描中**持续全批准**（2026-10-03 决议）。
# 旧缺省是 ask_on_risky_tools —— hitl 键存在但没写 approval_mode 时闸门会默认打开，
# 一条不可逆动作就能把整轮 D2 卡成 approval_required（真实库里历史累计 19 条）。
# 现在缺省一律 off，未知值也当 off（fail-open 到放行）并留痕：宁可放行被记账，
# 也不能因为配置漏写把验证链路静默截断。
DEFAULT_APPROVAL_MODE = "off"


def resolve_approval_mode(hitl: Optional[Dict], logger: Any = None) -> str:
    """approval_mode 唯一解析入口：白名单内原样返回，缺省与未知值一律 off。"""
    hitl = dict(hitl or {})
    raw = str(hitl.get("approval_mode") or "").strip()
    if raw in APPROVAL_MODES:
        return raw
    if raw and raw not in APPROVAL_MODES and logger is not None:
        logger.warning("[D2] 未知 approval_mode=%r，按 %s 处理（破坏性闸门测试期全批准）",
                       raw, DEFAULT_APPROVAL_MODE)
    return DEFAULT_APPROVAL_MODE


def decide_hitl_gate(project_context: Dict, method: Any, route: Any, payload_text: str = "",
                     category_override: Optional[str] = None) -> Dict[str, Any]:
    """HITL 闸门决策（单一真相源，供活跃 D2 链路 D2Agent.verify() 调用）。

    复用 attack_context 的破坏性操作分类，按 project_context['hitl']['approval_mode']
    决定某条「将要投放的不可逆动作」是否需要人放行：
      off                 —— 一律放行（仅审计，记 allowed）；
      ask_on_risky_tools  —— 只拦不可逆动作（可逆/只读即使工具高危也不再问）；
      strict              —— 全部动态动作都需放行（高约束场景）。
    三种模式的语义不变；变的是**缺省**（M14：缺省 off，不再静默打开）。
    不论放行还是拦截都返回完整 act 字典（含 gate 标记），调用方据此写 gated/allowed 审计。
    """
    from src.iast.attack_context import (
        classify_destructive_operation,
        is_destructive_command_payload,
        is_destructive_sql_payload,
    )
    method = str(method or "GET").upper()
    route = str(route or "").strip()
    category = category_override or classify_destructive_operation(method, route)
    blob = payload_text or ""
    sql_d = is_destructive_sql_payload(blob)
    cmd_d = is_destructive_command_payload(blob)
    irreversible = bool(category or sql_d or cmd_d)
    reasons = []
    if category:
        reasons.append(f"端点语义={category}")
    if sql_d:
        reasons.append("payload 含破坏性 SQL")
    if cmd_d:
        reasons.append("payload 含破坏性系统命令")
    if not reasons:
        reasons.append("可逆/只读动作")
    act: Dict[str, Any] = {
        "irreversible": irreversible,
        "category": category or ("destructive_payload" if (sql_d or cmd_d) else None),
        "route": route,
        "method": method,
        "reason": "；".join(reasons),
    }
    hitl = dict((project_context or {}).get("hitl") or {})
    hitl_present = "hitl" in (project_context or {})
    approval_mode = resolve_approval_mode(hitl)
    act_allowlist = set(str(i).strip() for i in (hitl.get("act_allowlist") or []) if str(i).strip())
    act_cat = str(act.get("category") or "")
    act_allowed = act_cat in act_allowlist
    if not hitl_present:
        # HITL 未启用（无 hitl 键）→ 闸门不介入，保留旧行为
        gate = False
    elif approval_mode == "off":
        gate = False
    elif approval_mode == "strict":
        gate = not act_allowed
    else:  # ask_on_risky_tools（默认）：只拦不可逆动作
        gate = bool(act.get("irreversible")) and not act_allowed
    act["gate"] = gate
    act["approval_mode"] = approval_mode
    act["hitl_configured"] = hitl_present
    return act


def _extract_trigger_route(exploit_spec: Dict) -> str:
    prerequisites = exploit_spec.get("prerequisites", {}) or {}
    entry = exploit_spec.get("entry", {}) or {}
    entry_route = str(entry.get("route", "") or "")
    ordered_steps = prerequisites.get("ordered_steps", []) or []
    for step in ordered_steps:
        matches = [token for token in str(step).split() if token.startswith("/")]
        for match in matches:
            if match != entry_route:
                return match
    return ""


def try_deterministic_verification(agent, vulnerability: Dict, project_context: Dict, logger) -> Optional[VerificationResult]:
    project_path_value = str((project_context or {}).get("project_path", "")).strip()
    if not project_path_value:
        return None
    project_path = Path(project_path_value)
    exploit_spec = normalize_exploit_spec(vulnerability.get("exploit_spec") or {})
    language = _language_for_vulnerability(vulnerability)
    if not language:
        return None

    completeness = exploit_spec_completeness(exploit_spec)
    if completeness["status"] != "ready":
        return _incomplete_contract_result(exploit_spec)

    family = str(exploit_spec.get("payload", {}).get("payload_family", "") or "")
    strategy_tuple = _strategy_from_contract(agent, project_path, vulnerability, language, exploit_spec)
    if not strategy_tuple:
        return _unsupported_contract_result(exploit_spec, language, family)

    verify_name, strategy, log_label = strategy_tuple
    execution_shape = str(((strategy or {}).get("execution") or {}).get("shape") or "")
    tool_id = tool_id_for_contract(language, family, execution_shape)
    tool_spec = ToolRegistry.get(tool_id) or {"id": tool_id, "risk_level": "high"}
    hitl = dict((project_context or {}).get("hitl") or {})
    approval_mode = resolve_approval_mode(hitl)
    allowlist = set(str(item).strip() for item in (hitl.get("tool_allowlist") or []) if str(item).strip())
    # 动作级放行名单（可永久放行某个不可逆类别，如 data_destroy），与工具级 allowlist 并存。
    act_allowlist = set(str(item).strip() for item in (hitl.get("act_allowlist") or []) if str(item).strip())

    # ── HITL 闸门（2026-09-20 重设计：按动作判风险，不按工具）────────────────
    # 旧语义按 tool_id 的 risk_level 拦 → 拦的是「验证器自己用的工具」，等于拦自己的扫描；
    # 粒度是工具（一次点击只解一条）、理由说不清危险在哪，且会把流水线卡住。
    # 新语义：
    #   off                 —— 一律放行（仅审计）。
    #   ask_on_risky_tools  —— **只拦不可逆动作**；可逆/只读动作即使工具 risk=high 也不再问。
    #   strict              —— 保留原语义（全部动态工具都需放行），供高约束场景使用。
    # 不论放行还是拦截都写审计（record_destructive_guard_event），
    # 让「人入环」体现在关键决策而非每一步。
    act = _classify_act_risk(exploit_spec, strategy)
    act_cat = str(act.get("category") or "")
    act_allowed = act_cat in act_allowlist
    if not hitl:
        # HITL 未配置 → 闸门不介入（保留旧行为，避免给未启用 HITL 的任务引入新拦截）
        gate = False
    elif approval_mode == "off":
        gate = False
    elif approval_mode == "strict":
        gate = not act_allowed
    else:  # ask_on_risky_tools（默认）：只有不可逆动作需要人
        gate = bool(act.get("irreversible")) and not act_allowed
    # 工具级 allowlist 仍可显式放行（保留兼容）
    if gate and tool_id in allowlist:
        gate = False
    try:
        from src.iast.attack_context import record_destructive_guard_event
        record_destructive_guard_event({
            "action": "gated" if gate else "allowed",
            "category": act_cat or "none",
            "reason": act.get("reason"),
            "route": act.get("route"),
            "method": act.get("method"),
            "tool_id": tool_id,
            "approval_mode": approval_mode,
            "stage": "d2_hitl",
        })
    except Exception:  # 审计失败绝不阻断验证
        pass
    if gate:
        logger.info(
            "[D2] HITL 拦截不可逆动作 mode=%s cat=%s route=%s tool=%s reason=%s",
            approval_mode, act_cat or "?", act.get("route") or "?", tool_id, act.get("reason"),
        )
        return _approval_required_result(exploit_spec, tool_spec, approval_mode, allowlist, act=act)
    if approval_mode != "off" and act.get("irreversible"):
        logger.info("[D2] HITL 放行不可逆动作（已在放行名单）cat=%s route=%s", act_cat, act.get("route"))
    logger.info(f"[D2] Using contract-driven deterministic verification for {log_label}")
    if verify_name == "_verify_csrf_chain":
        result = getattr(agent, verify_name)(project_path, strategy)
    elif verify_name == "_verify_map_deserialization_chain":
        result = getattr(agent, verify_name)(project_path, strategy)
    else:
        result = getattr(agent, verify_name)(project_path, strategy)
    return _attach_strategy_attack_plan(agent, result, vulnerability, project_context, strategy)
