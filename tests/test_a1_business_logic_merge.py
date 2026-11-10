"""Q2 回归测试：run_a1_scan 现在并入业务逻辑/BOLA 假说，并作为 A2 证据基础。

守护点：
- analyze_business_logic（LLM 主链路形状）与 analyze_bola（离线兜底形状）的假说都能并入 A1 findings。
- 并入的假说挂到 ScanResult.evidence["business_logic_candidates"]，可经 _build_a1_evidence_index
  进入 a1_evidence_index，从而成为 A2 的证据基础。
- 任一分析器异常时不阻断注入类结果返回。
"""

from unittest import mock

from src.core.models import ScanResult, Vulnerability
from src.pipeline.a1.service import A1PipelineService


def _make_svc():
    return A1PipelineService({})


def _bl_llm_hypo():
    """A1BusinessLogicAIAgent（LLM 主链路）输出形状。"""
    return [{
        "file": "app/OrderController.java",
        "line": 42,
        "category": "bola",
        "vuln_type": "BOLA",
        "family": "IDOR",
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "vulnerable_param": "id",
        "confidence": "medium",
        "evidence": "敏感操作缺失归属校验",
    }]


def _bola_heuristic_hypo():
    """a1_bola_analyzer（离线兜底）输出形状。"""
    return [{
        "vuln_type": "BOLA",
        "family": "IDOR",
        "entry_point": "app/UserDao.java:88",
        "function": "findById",
        "param": "userId",
        "data_access_sink": "repository.findById(userId)",
        "required_control_point": "归属校验",
        "confidence": "medium",
        "evidence": "按 id 取对象且无归属校验",
    }]


def test_merged_business_logic_appears_in_a1_findings():
    svc = _make_svc()
    svc.analyze_business_logic = mock.MagicMock(return_value=_bl_llm_hypo())
    svc.analyze_bola = mock.MagicMock(return_value=_bola_heuristic_hypo())

    base = [ScanResult(file="app/Main.java", vulnerabilities=[], agent="a1")]
    out = svc.merge_business_logic_findings(base, [{"path": "app/OrderController.java", "content": ""}])

    all_vulns = [v for r in out for v in r.vulnerabilities]
    types = {v.type for v in all_vulns}
    assert "BOLA" in types, all_vulns
    # 两条假说（LLM + 离线）都应并入
    assert len(all_vulns) == 2, all_vulns
    # 离线兜底那条从 entry_point(path:line) 解析出 file/line
    bola_heuristic = next(v for v in all_vulns if v.source == "a1" and v.file == "app/UserDao.java")
    assert bola_heuristic.line == 88, bola_heuristic.line
    # 每条都携带业务逻辑 a1_evidence
    assert getattr(bola_heuristic, "a1_evidence", {}).get("business_logic") is True


def test_business_logic_candidates_in_evidence_index():
    svc = _make_svc()
    svc.analyze_business_logic = mock.MagicMock(return_value=_bl_llm_hypo())
    svc.analyze_bola = mock.MagicMock(return_value=[])

    base = [ScanResult(file="app/OrderController.java", vulnerabilities=[], agent="a1")]
    out = svc.merge_business_logic_findings(base, [{"path": "app/OrderController.java", "content": ""}])

    sr = next(r for r in out if r.file == "app/OrderController.java")
    cand = sr.evidence.get("business_logic_candidates") or []
    assert len(cand) == 1, cand
    assert cand[0]["category"] == "bola"
    assert cand[0]["route"] == "/api/order/{id}"
    assert cand[0]["param"] == "id"


def test_analyzer_failure_is_best_effort():
    svc = _make_svc()
    svc.analyze_business_logic = mock.MagicMock(side_effect=RuntimeError("llm down"))
    svc.analyze_bola = mock.MagicMock(side_effect=RuntimeError("bola down"))

    base = [ScanResult(file="app/Main.java", vulnerabilities=[Vulnerability(type="SQLi", severity="high")], agent="a1")]
    out = svc.merge_business_logic_findings(base, [])
    # 注入类结果不受影响返回
    assert len(out) == 1
    assert out[0].vulnerabilities[0].type == "SQLi"
    # evidence 中不得出现 business_logic_candidates
    assert "business_logic_candidates" not in out[0].evidence


def test_empty_hypos_returns_unchanged():
    svc = _make_svc()
    svc.analyze_business_logic = mock.MagicMock(return_value=[])
    svc.analyze_bola = mock.MagicMock(return_value=[])
    base = [ScanResult(file="app/Main.java", vulnerabilities=[], agent="a1")]
    out = svc.merge_business_logic_findings(base, [])
    assert out == base
