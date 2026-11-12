"""SARIF 2.1.0 导出（Phase 5a）。

把 final_report 的 vulnerabilities 转成 SARIF 2.1.0，供 GitHub Code Scanning /
GitLab SAST / IDE / DefectDojo 消费。纯函数、无副作用，便于单测。

映射：
  ruleId            <- family / type 归一后的 CWE 编号
  level             <- severity（critical/high→error, medium→warning, low/info→note）
  message           <- description / display_title
  locations         <- file / line
  codeFlows         <- data_flow（污点路径，存在时）
  partialFingerprints <- vulnerability_hash_v2（用于去重 / baseline）
"""
from typing import Any, Dict, List, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note", "informational": "note",
}

# family / type 归一 -> (CWE 编号, 人类可读名)
_FAMILY_CWE = {
    "sqli": ("CWE-89", "SQL Injection"),
    "sql": ("CWE-89", "SQL Injection"),
    "sql_injection": ("CWE-89", "SQL Injection"),
    "sql 注入": ("CWE-89", "SQL Injection"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "cmdi": ("CWE-78", "OS Command Injection"),
    "command_execution": ("CWE-78", "OS Command Injection"),
    "pathtraver": ("CWE-22", "Path Traversal"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "ldapi": ("CWE-90", "LDAP Injection"),
    "ldap_injection": ("CWE-90", "LDAP Injection"),
    "xpathi": ("CWE-643", "XPath Injection"),
    "xpath_injection": ("CWE-643", "XPath Injection"),
    "hash": ("CWE-328", "Use of Weak Hash"),
    "weak_hash": ("CWE-328", "Use of Weak Hash"),
    "weakrand": ("CWE-330", "Use of Insufficiently Random Values"),
    "weak_random": ("CWE-330", "Use of Insufficiently Random Values"),
    "crypto": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "securecookie": ("CWE-614", "Sensitive Cookie Without Secure Attribute"),
    "trustbound": ("CWE-501", "Trust Boundary Violation"),
    "xxe": ("CWE-611", "XML External Entity"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "file_upload": ("CWE-434", "Unrestricted File Upload"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "open_redirect": ("CWE-601", "Open Redirect"),
    "crlf_injection": ("CWE-113", "Improper Neutralization of CRLF Sequences"),
    "jndi_injection": ("CWE-74", "Injection"),
    # —— 以下为 DB trigger_specs 中实际落库的规范族名（与短别名并存，避免 CWE-0）——
    "trust_boundary_violation": ("CWE-501", "Trust Boundary Violation"),
    "secure_cookie": ("CWE-614", "Sensitive Cookie Without Secure Attribute"),
    "weak_crypto": ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
    "broken_access_control": ("CWE-284", "Improper Access Control"),
    "business_logic": ("CWE-840", "Business Logic Errors"),
}


def _family_of(vuln: Dict[str, Any]) -> str:
    for k in ("display_family", "finding_family", "family", "original_type", "type"):
        val = vuln.get(k)
        if val:
            return str(val).strip().lower().replace(" ", "_")
    return "unknown"


def _cwe_of(vuln: Dict[str, Any]) -> tuple:
    fam = _family_of(vuln)
    if fam in _FAMILY_CWE:
        return _FAMILY_CWE[fam]
    # 子串兜底
    for key, val in _FAMILY_CWE.items():
        if key in fam or fam in key:
            return val
    return ("CWE-0", fam or "Unknown")


def _level_of(sev: Any) -> str:
    return _SEVERITY_LEVEL.get(str(sev or "").strip().lower(), "warning")


def _uri(path: Any) -> str:
    return str(path or "").replace("\\", "/")


def _int_line(line: Any) -> int:
    try:
        n = int(line)
        return n if n > 0 else 1
    except Exception:
        return 1


def _code_flows(vuln: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """从 data_flow 构造 SARIF codeFlow（存在且形如 [{file,line}] 时）。"""
    flow = vuln.get("data_flow")
    if not isinstance(flow, list) or not flow:
        return None
    locations: List[Dict[str, Any]] = []
    for node in flow:
        if not isinstance(node, dict):
            continue
        f = node.get("file") or node.get("path")
        if not f:
            continue
        locations.append({
            "location": {"physicalLocation": {
                "artifactLocation": {"uri": _uri(f)},
                "region": {"startLine": _int_line(node.get("line"))},
            }}
        })
    if not locations:
        return None
    return [{"threadFlows": [{"locations": locations}]}]


def vuln_to_result(vuln: Dict[str, Any]) -> Dict[str, Any]:
    cwe, _name = _cwe_of(vuln)
    result: Dict[str, Any] = {
        "ruleId": cwe,
        "level": _level_of(vuln.get("severity")),
        "message": {"text": str(vuln.get("description") or vuln.get("display_title") or cwe)},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": _uri(vuln.get("file"))},
            "region": {"startLine": _int_line(vuln.get("line"))},
        }}],
        "partialFingerprints": {
            "vulnerabilityHash/v2": str(vuln.get("vulnerability_hash_v2") or ""),
        },
    }
    cf = _code_flows(vuln)
    if cf:
        result["codeFlows"] = cf
    return result


def to_sarif(
    vulns: List[Dict[str, Any]],
    *,
    tool_name: str = "savr",
    tool_version: str = "1.0",
    info_uri: str = "",
    include_unconfirmed: bool = True,
) -> Dict[str, Any]:
    """把 vulnerabilities 列表转成 SARIF 2.1.0 文档。

    include_unconfirmed=False 时只导出 verification_state == "confirmed" 的项
    （对应 baseline / CI 只报确认项的用法）。
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for vuln in vulns or []:
        if not isinstance(vuln, dict):
            continue
        if not include_unconfirmed and str(vuln.get("verification_state") or "") != "confirmed":
            continue
        cwe, cwe_name = _cwe_of(vuln)
        if cwe not in rules:
            rules[cwe] = {
                "id": cwe,
                "name": cwe_name,
                "shortDescription": {"text": cwe_name},
                "properties": {"tags": [cwe]},
            }
        results.append(vuln_to_result(vuln))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": info_uri,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif(path: str, vulns: List[Dict[str, Any]], **kwargs) -> str:
    """把 SARIF 写到 path，返回 path。"""
    import json
    doc = to_sarif(vulns, **kwargs)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return path
