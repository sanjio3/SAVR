"""-单元测试：CSRF / JWT / JSONP / CVE-2022-22978 四条真实召回路径的代码落地。

不依赖全量扫描，直接对纯函数与规则消费点断言：
- ② round_report CSRF 黄金项纳入 cors（token + route），/cors spec 可对账入环；
- JSONP @ControllerAdvice 重归因 → controller/Jsonp.java 的 /jsonp/* 路由；
- CVE-2022-22978 合成 /black_path%0a/xx 路由 + 证据规则纠回 auth_bypass；
- ① a1 静态规则：csrf().disable() 与 regexMatchers 授权绕过正确产出 finding。
"""
import sys
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.core.normalize import correct_family_by_evidence  # noqa: E402
from src.iast.trigger_spec_registry import (  # noqa: E402
    _no_route_reattribution,
    _jsonp_advice_file,
)
from src.agents.a1_injection_heuristic import analyze_content  # noqa: E402
import src.api.routers.round_report as rr  # noqa: E402


# ---------------------------------------------------------------------------
# ② CSRF 黄金 token / route 纳入 cors，使现有 /cors spec 对账入环
# ---------------------------------------------------------------------------
def test_csrf_golden_includes_cors_token_and_route():
    entry = next(e for e in rr.JAVA_SEC_CODE if e[1] == "CSRF")
    _idx, _name, tokens, routes, _tech, _env_premise = entry
    assert "cors" in tokens, "CSRF 黄金 family token 必须含 cors"
    assert "cors" in routes, "CSRF 黄金 route 必须含 cors（/cors 不含子串 csrf）"


def test_csrf_spec_cors_reconciles():
    # 现有 /cors spec：family=cors，target_endpoint=/cors → 应对账进 CSRF 黄金项
    csrf_entry = next(e for e in rr.JAVA_SEC_CODE if e[1] == "CSRF")
    _idx, _name, tokens, routes, _tech, _env_premise = csrf_entry
    spec = {"family": "cors", "target_endpoint": "/cors",
            "verification_status": "no-iast-evidence", "iast_state": "sink-reached-probe"}
    matched = rr._spec_match(tokens, routes, [spec])
    assert matched is not None, "/cors spec 必须对账进 CSRF 黄金项"
    assert matched[0] == "/cors"


# ---------------------------------------------------------------------------
# JSONP @ControllerAdvice 重归因
# ---------------------------------------------------------------------------
def _disc(routes):
    return [{"route": r, "method": "GET", "file": "src/main/java/org/joychou/controller/Jsonp.java"}
            for r in routes]


def test_jsonp_advice_file_detection():
    assert _jsonp_advice_file("src/main/java/org/joychou/config/Object2Jsonp.java", []) is True
    assert _jsonp_advice_file("src/main/java/org/joychou/controller/Jsonp.java", []) is False


def test_jsonp_reattribution_to_controller_route():
    vuln = {
        "file": "src/main/java/org/joychou/config/Object2Jsonp.java",
        "source": "deserialization",
        "title": "JSONP referer 校验",
        "sink": "jsonp callback",
        "raw_json": "{}",
    }
    disc = _disc(["/jsonp/vuln/emptyReferer", "/jsonp/vuln/referer", "/jsonp/object2jsonp"])
    out = _no_route_reattribution(vuln, disc)
    assert out is not None, "JSONP advice 类必须重归因到 controller 路由"
    assert out["route"].startswith("/jsonp"), out
    assert out["reason"] == "jsonp-controller-advice-reattribution"


def test_jsonp_reattribution_prefers_vuln_endpoint():
    vuln = {
        "file": "src/main/java/org/joychou/config/Object2Jsonp.java",
        "source": "xss", "title": "jsonp", "sink": "callback", "raw_json": "{}",
    }
    disc = _disc(["/jsonp/sec/checkReferer", "/jsonp/vuln/emptyReferer"])
    out = _no_route_reattribution(vuln, disc)
    assert out is not None
    assert "vuln" in out["route"], "应优先选明确漏洞端点 /jsonp/vuln/*"


def test_non_jsonp_advice_not_reattributed():
    vuln = {"file": "src/main/java/org/joychou/controller/Foo.java",
            "source": "sql_injection", "title": "x", "sink": "y", "raw_json": "{}"}
    assert _no_route_reattribution(vuln, _disc(["/jsonp/x"])) is None


# ---------------------------------------------------------------------------
# CVE-2022-22978 合成路由 + 证据规则纠回 auth_bypass
# ---------------------------------------------------------------------------
def test_cve_reattribution_synthetic_route():
    vuln = {
        "file": "src/main/java/org/joychou/security/WebSecurityConfig.java",
        "type": "CVE-2022-22978",
        "source": "a1-injection-heuristic",
        "sink": "Spring regexMatchers 授权绕过(CVE-2022-22978)",
        "raw_json": "{}",
    }
    out = _no_route_reattribution(vuln, [])
    assert out is not None, "CVE 配置类必须合成可重放路由"
    assert out["route"] == "/black_path%0a/xx", out
    assert out["reason"] == "cve-2022-22978-synthetic-route"


def test_cve_family_evidence_correction():
    # 被 A2 误标为 path_traversal 的 CVE finding，合成 /black_path 路由后证据规则应纠回 auth_bypass
    fixed = correct_family_by_evidence("path_traversal", route="/black_path%0a/xx", file="WebSecurityConfig.java")
    assert fixed["corrected"] == "1", fixed
    assert fixed["family"] == "auth_bypass", fixed

    # 即使原始族已是 cve-2022-22978，也应稳定为 auth_bypass（不漂移）
    fixed2 = correct_family_by_evidence("cve-2022-22978", route="/black_path%0a/xx", file="WebSecurityConfig.java")
    assert fixed2["family"] == "auth_bypass", fixed2


def test_cve_spec_reconciles_into_golden():
    cve_entry = next(e for e in rr.JAVA_SEC_CODE if e[1] == "CVE-2022-22978")
    _idx, _name, tokens, routes, _tech, _env_premise = cve_entry
    spec = {"family": "auth_bypass", "target_endpoint": "/black_path%0a/xx",
            "verification_status": "confirmed_exploitable", "iast_state": "business-logic-confirmed"}
    matched = rr._spec_match(tokens, routes, [spec])
    assert matched is not None, "CVE auth_bypass spec 必须对账进 CVE 黄金项"
    assert matched[0] == "/black_path%0a/xx"


# ---------------------------------------------------------------------------
# ① a1 静态规则：csrf().disable() 与 regexMatchers 授权绕过
# ---------------------------------------------------------------------------
def test_a1_detects_regexmatchers_cve():
    content = (
        "http.authorizeRequests()\n"
        "    .regexMatchers(\"/black_path.*\").denyAll();\n"
    )
    findings = analyze_content("src/main/java/org/joychou/security/WebSecurityConfig.java", content, lang="java")
    cve = [f for f in findings if f.type == "CVE-2022-22978"]
    assert cve, "必须检出 CVE-2022-22978（regexMatchers 授权绕过）"
    assert cve[0].severity == "HIGH"
    assert cve[0].has_http_entry is True, "CVE 弱点须标记为 HTTP 可达以便重放"


def test_a1_detects_csrf_disabled():
    content = "http.csrf().disable();\n"
    findings = analyze_content("src/main/java/org/joychou/security/WebSecurityConfig.java", content, lang="java")
    csrf = [f for f in findings if f.type == "CSRF"]
    assert csrf, "必须检出 CSRF（状态变更端点缺 token 校验）"
    assert csrf[0].severity == "HIGH"
