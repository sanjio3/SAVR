"""④ A1/CodeQL → A2 证据稳定输入：Step1 证据发射回归测试。

验证 A1CodeQLSemanticAgent.scan_project 在 CodeQL 产出告警后，会把每条告警转成
a1_evidence（rule_id/message/severity/file/line + entry_candidates/source_candidates/
sink_candidates），并把按文件聚合后的 a1_evidence 挂到 ScanResult.evidence 上——
这是 benchmark_cli._build_a1_evidence_index 抽成 a1_evidence_index、注入 A2 prompt
（Step3）以及 auto_register_from_a2 持久化 findings.a1_evidence（Step2）的数据源头。

此前 A1 的 ScanResult.evidence 永远是 {}，导致整条 A1→A2 证据索引为空、A2 实际收不到
A1 喂入。本测试锁定「A1 必须发射非空 evidence」这一不变量。
"""

import unittest
from unittest.mock import MagicMock

import pytest

from src.agents.a1_codeql_semantic_agent import A1CodeQLSemanticAgent
from src.core.models import Vulnerability


@pytest.fixture(autouse=True)
def _force_offline_gateway(monkeypatch):
    """本测试锁定离线确定性映射（a1_evidence 透传原始 severity="error"）。
    resolve_llm_config 会从磁盘 config.yaml 补 llm 段，Ollama 在线时改走 LLM 语义整合、
    8B 把 severity 归一成 HIGH → 断言失败。强制离线以锁定确定性路径。"""
    import src.core.model_gateway as mg
    monkeypatch.setattr(mg.ModelGateway, "is_offline", property(lambda self: True))


class _FakeCodeQL:
    """替代真实 CodeQL CLI：返回一条带 relatedLocations 的数据流告警。"""

    def is_available(self):
        return True

    def scan(self, project_path, language="java"):
        return {
            "available": True,
            "status": "ok",
            "alerts": [
                {
                    "rule_id": "java/sql-injection",
                    "message": "User-controlled value flows to SQL query",
                    "file": "com/example/Ctrl.java",
                    "line": 42,
                    "severity": "error",
                    "related_locations": [
                        {"kind": "source", "file": "com/example/Ctrl.java", "line": 30,
                         "message": "Tainted value from HTTP request parameter 'id'"},
                        {"kind": "sink", "file": "com/example/Repo.java", "line": 77,
                         "message": "Database query built from tainted value"},
                    ],
                }
            ],
        }


class A1EvidenceEmissionTests(unittest.TestCase):
    def test_scan_project_emits_nonempty_evidence_on_scanresult(self):
        """Step1：CodeQL 告警 → ScanResult.evidence 非空且含 entry/source/sink 候选。"""
        agent = A1CodeQLSemanticAgent({"a1_use_codeql": True})
        agent._codeql = _FakeCodeQL()  # 绕过真实 CLI

        results = agent.scan_project("/tmp/fake-java-proj", language="java")

        self.assertTrue(results, "应至少产出一个 ScanResult")
        sr = results[0]
        ev = sr.evidence
        self.assertTrue(ev, "ScanResult.evidence 不应为空（此前为 {} 导致 A1→A2 索引空）")
        self.assertEqual(ev.get("rule_id"), "java/sql-injection")
        self.assertEqual(ev.get("severity"), "error")
        # 至少应有 sink 候选（主告警位置）
        self.assertTrue(ev.get("sink_candidates"), "sink_candidates 应非空")
        # relatedLocations 含 source 节点 → source_candidates 应非空
        self.assertTrue(ev.get("source_candidates"), "source_candidates 应来自 relatedLocations 的 source 节点")
        # 源节点 message 提到 HTTP request parameter → 应被识别为 entry 候选
        self.assertTrue(ev.get("entry_candidates"), "命中 'HTTP request parameter' 的源应进入 entry_candidates")

    def test_vulnerability_carries_a1_evidence_attr(self):
        """Step1 配套：每个 Vulnerability 自身也带 a1_evidence（供 _merge 与 findings 持久化）。"""
        agent = A1CodeQLSemanticAgent({"a1_use_codeql": True})
        agent._codeql = _FakeCodeQL()
        results = agent.scan_project("/tmp/fake-java-proj", language="java")
        for sr in results:
            for v in sr.vulnerabilities:
                self.assertTrue(getattr(v, "a1_evidence", None), "每个 A1 Vulnerability 应带 a1_evidence")


if __name__ == "__main__":
    unittest.main()
