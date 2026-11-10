"""A1/A2 能力整合单测（§8.1 / §9.1）。

覆盖：A2 吸收 A21（plan_pocs PoC 生成）、Q5 POC 必须由 LLM 生成（A2ContractPlanner 经 llm_client）、A1 外接 CodeQL 适配层。
"""
import unittest

from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.agents.a2_contract_planner import A2ContractPlanner
from src.core.models import ScanResult, Vulnerability
from src.pipeline.a1.service import A1PipelineService
from src.pipeline.a2.service import A2PipelineService


class _FakeLlmClient:
    """Q5 回归：模拟 A2 语义分析共用的 LLM 客户端接口（create_message 返回 JSON 字符串）。"""

    def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
        return (
            '{"entry": {"route": "/api/llm", "method": "POST", "parameter_name": "q", '
            '"parameter_location": "query"}, "payload": {"payload_family": "sql-injection", '
            '"candidate_payloads": ["x"]}, "success_signal": {"signal_type": "resp"}, '
            '"poc_chain": [{"stage": "source", "node": "n"}]}'
        )


def _reachable_sql_vuln():
    vuln = Vulnerability(
        type="SQL Injection",
        severity="HIGH",
        file="src\\UserController.java",
        line=18,
        description="HTTP parameter reaches SQL query",
        entry_point="GET route:/users",
        has_http_entry=True,
        has_call_chain=True,
        callers="HTTP parameter flows into repository query",
        verdict="✅ A2:真漏洞-HTTP入口可触发",
    )
    vuln.is_canonical = True
    vuln.exploit_spec["entry"]["route"] = "/users"
    vuln.exploit_spec["entry"]["method"] = "GET"
    vuln.exploit_spec["entry"]["parameter_name"] = "id"
    vuln.exploit_spec["payload"]["payload_family"] = "sql-injection"
    vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"
    vuln.a1_evidence = {"source_candidates": [{"name": "id", "location": "query"}]}
    return vuln


class A2AbsorbsA21Tests(unittest.TestCase):
    def test_plan_pocs_delegates_to_contract_agent(self):
        """§8.1：A2.plan_pocs 吸收 A21，产出带 exploit_spec + a21_selected 的结果。"""
        vuln = _reachable_sql_vuln()
        results = A2PipelineService.plan_pocs([ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")])
        planned = results[0].vulnerabilities[0]
        self.assertTrue(planned.a21_selected)
        self.assertTrue(planned.exploit_spec.get("entry", {}).get("route"))


class A2ContractPlannerLlmPocTests(unittest.TestCase):
    def test_llm_poc_overrides_rule_based(self):
        """Q5：传入 llm_client 时，POC 以 LLM 产出为主覆盖规则式（闭环反思重跑可收敛）。"""
        vuln = _reachable_sql_vuln()
        planner = A2ContractPlanner(llm_client=_FakeLlmClient())
        planned = planner.plan_vulnerability(vuln)
        self.assertEqual(planned.exploit_spec["entry"]["route"], "/api/llm")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_name"], "q")
        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "sql-injection")
        self.assertTrue(planned.exploit_spec.get("poc_chain"))

    def test_no_llm_client_falls_back_to_rule_based(self):
        """无 llm_client 时回退规则式（不阻断流水线）。"""
        vuln = _reachable_sql_vuln()
        planner = A2ContractPlanner(llm_client=None)
        planned = planner.plan_vulnerability(vuln)
        self.assertEqual(planned.exploit_spec["entry"]["route"], "/users")


class A1CodeQLAdapterTests(unittest.TestCase):
    def test_codeql_status_exposes_availability(self):
        """§8.1：A1 外接 CodeQL 能力状态。

        注入类主链路 = CodeQL + AI 语义整合（已删除自写 yaml 正则引擎）。
        fallback = injection-heuristic：当 CodeQL 不可用 / 构建失败 / 空结果时，确定性轻量
        sink 匹配兜底仍能检出明显危险 sink（ObjectInputStream/ProcessBuilder 等），避免 Java
        注入类整体漏报（改进清单 P1#1）。injection_engine 固定为 codeql+ai-semantic。
        """
        status = A1PipelineService().codeql_status()
        self.assertIn("available", status)
        self.assertEqual(status["injection_engine"], "codeql+ai-semantic")
        # 注入类兜底：确定性轻量 sink 匹配（改进清单 P1#1），不再以 0 结果误判安全
        self.assertEqual(status["fallback"], "injection-heuristic")
        # 暴露最近一次扫描实际引擎与 CodeQL 状态，消除「构建失败」与「无漏洞」的状态歧义
        self.assertIn("last_scan_meta", status)
        self.assertIn("engine", status["last_scan_meta"])

    def test_codeql_scan_returns_unavailable_when_disabled(self):
        """CodeQL 未开启（a1_use_codeql 显式为 False）时返回 available=False，调用方回退。

        配置统一（2026-10-20）后：service 未显式给出 a1_use_codeql 时**默认跟随
        config/codeql.yaml**（enabled:true → 默认启用，见用户「CodeQL 默认打开」要求）。
        故「未开启」的路径必须由显式 config 覆盖来触发。
        """
        result = A1PipelineService({"a1_use_codeql": False}).scan_project_with_codeql(
            "/tmp/not-used", language="python")
        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "disabled")

    def test_codeql_enabled_defaults_to_config_file(self):
        """未显式给出 a1_use_codeql 时，默认跟随 config/codeql.yaml 的 enabled。"""
        svc = A1PipelineService()
        # config/codeql.yaml enabled:true ⇒ 默认启用（除非 SAST_AI_DISABLE_CODEQL 置位）。
        import os as _os
        if str(_os.environ.get("SAST_AI_DISABLE_CODEQL", "")).strip().lower() in ("1", "true", "yes", "on"):
            self.assertFalse(svc._codeql_enabled())
        else:
            self.assertTrue(svc._codeql_enabled())

    def test_adapter_scan_short_circuits_when_cli_missing(self):
        """CodeQL CLI 缺失时 scan 短路返回 available=False。"""
        adapter = CodeQLAdapter(codeql_bin="/nonexistent/codeql")
        self.assertFalse(adapter.is_available())
        result = adapter.scan("/tmp/not-used", language="python")
        self.assertFalse(result["available"])


if __name__ == "__main__":
    unittest.main()
