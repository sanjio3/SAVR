"""A2 方案二：聚合吸收成员补行（2026-09-18 评审）。

背景：聚合（A2 侧 `_merge_chain_vulnerabilities` 与报告侧 `_aggregate_canonical_findings`）
把同族非 canonical 节点并入聚合 finding 的 supporting_nodes 后，该节点原本不再有自己的
findings 行。后果有二：①「按 file_path 统计覆盖」把只有成员资格的文件读成 0 覆盖
（实测 Shiro.java 有两处 sink、兜底引擎单独实测命中 2 条，但 run 17 findings 该文件 0 条）；
②iast_events.correlated_finding_id 关联桥挂不上（证据链只认有行的文件）。

方案二：给被吸收成员补一行（is_canonical=False + absorbed_by_group_key=归属组），
并同时封住两个已知副作用 —— 补行不得进 D2 候选池、不得在前端重复展示。
"""

import tempfile
import unittest

from src.agents.a2_contract_planner import A2ContractPlanner
from src.agents.a2_intelligent_agent import A2SemanticAgent
from src.benchmark.report_manager import ReportManager, is_mainline_d2_item
from src.core.models import ScanResult, Vulnerability


def _deserialization_trio():
    """构造一个必然归入 deserialization:project_chain 的三节点链（同既有测试的夹具口径）。"""
    controller = Vulnerability(
        type="Insecure Deserialization",
        severity="HIGH",
        file="src/main/java/com/quote/controller/DebugController.java",
        line=24,
        description="HTTP import endpoint reaches a deserialization chain",
        code_snippet="public String importConfig(@RequestParam String data)",
        entry_point="/debug/import",
        sink="importConfig",
        has_http_entry=True,
        callers="DebugController#importConfig",
        verdict="⚠️ A2:可疑-Java反序列化需A3验证",
        source="a2",
    )
    shiro = Vulnerability(
        type="JDK Serialization",
        severity="HIGH",
        file="src/main/java/org/joychou/controller/Shiro.java",
        line=37,
        description="new ObjectInputStream(bytes) 由注入类离线兜底分析器检出",
        code_snippet="ObjectInputStream in = new ObjectInputStream(bytes);",
        sink="new ObjectInputStream(bytes)",
        has_call_chain=True,
        callers="Shiro#deserialize",
        verdict="⚠️ A2:可疑-Java反序列化需A3验证",
        source="a2",
    )
    processor = Vulnerability(
        type="Insecure Deserialization",
        severity="HIGH",
        file="src/main/java/com/quote/processor/CacheProcessor.java",
        line=42,
        description="Deserialized object reaches process(userConfig)",
        code_snippet="processor.process(userConfig)",
        sink="processor.process",
        has_call_chain=True,
        callers="CacheProcessor#process",
        verdict="⚠️ A2:可疑-Java反序列化需A3验证",
        source="a2",
    )
    return controller, shiro, processor


class AbsorbedMemberModelTests(unittest.TestCase):
    def test_to_dict_carries_absorbed_markers(self):
        vuln = Vulnerability(type="JDK Serialization", severity="HIGH", file="Shiro.java", line=37)
        self.assertFalse(vuln.is_absorbed)
        self.assertEqual(vuln.absorbed_by_group_key, "")

        vuln.is_absorbed = True
        vuln.absorbed_by_group_key = "deserialization:project_chain"
        payload = vuln.to_dict()

        self.assertTrue(payload["is_absorbed"])
        self.assertEqual(payload["absorbed_by_group_key"], "deserialization:project_chain")


class AbsorbedMemberSurvivesAggregationTests(unittest.TestCase):
    def setUp(self):
        self.agent = A2SemanticAgent.__new__(A2SemanticAgent)

    def test_absorbed_member_keeps_its_own_row_in_its_own_file(self):
        controller, shiro, processor = _deserialization_trio()
        results = [
            ScanResult(file=controller.file, vulnerabilities=[controller], agent="a2"),
            ScanResult(file=shiro.file, vulnerabilities=[shiro], agent="a2"),
            ScanResult(file=processor.file, vulnerabilities=[processor], agent="a2"),
        ]

        rebuilt = self.agent.canonicalize_scan_results(results)
        by_file = {result.file: result.vulnerabilities for result in rebuilt}

        # canonical 落在 controller
        self.assertEqual(len([v for v in by_file[controller.file] if v.is_canonical]), 1)
        # 被吸收成员不再消失：Shiro.java 这个文件恢复有自己的行
        self.assertEqual(len(by_file[shiro.file]), 1)
        self.assertTrue(by_file[shiro.file][0].is_absorbed)
        self.assertFalse(by_file[shiro.file][0].is_canonical)
        self.assertEqual(
            by_file[shiro.file][0].absorbed_by_group_key,
            "deserialization:project_chain",
        )
        # 且它同时仍是 canonical 的 supporting_node（吸收语义不变）
        canonical = next(v for v in by_file[controller.file] if v.is_canonical)
        self.assertIn(
            (shiro.file, shiro.line),
            {(node["file"], node["line"]) for node in canonical.supporting_nodes},
        )

    def test_single_member_group_is_not_marked_absorbed(self):
        only = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=197,
            description="dashboard route reaches outbound request",
            entry_point="ROUTE /dashboard",
            has_call_chain=True,
            source="a2",
        )
        rebuilt = self.agent.canonicalize_scan_results(
            [ScanResult(file=only.file, vulnerabilities=[only], agent="a2")]
        )
        kept = [v for result in rebuilt for v in result.vulnerabilities]
        self.assertEqual(len(kept), 1)
        self.assertTrue(kept[0].is_canonical)
        self.assertFalse(kept[0].is_absorbed)


class AbsorbedMemberNeverEntersD2Tests(unittest.TestCase):
    def _reachable_vuln(self):
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

    def test_absorbed_member_is_blocked_by_hard_gate(self):
        planner = A2ContractPlanner()

        # 基线：同样的结构，未标记吸收时会进 D2
        baseline = self._reachable_vuln()
        score, selected, _ = planner._score_candidate(
            baseline, dict(baseline.exploit_spec or {})
        )
        self.assertTrue(selected)
        self.assertGreater(score, 0)

        absorbed = self._reachable_vuln()
        absorbed.is_absorbed = True
        absorbed.absorbed_by_group_key = "deserialization:project_chain"
        score, selected, reason = planner._score_candidate(
            absorbed, dict(absorbed.exploit_spec or {})
        )
        self.assertFalse(selected)
        self.assertEqual(score, 0)
        self.assertIn("absorbed_member", reason)
        self.assertIn("deserialization:project_chain", reason)

    def test_absorbed_member_is_not_promoted_to_chain_proven(self):
        planner = A2ContractPlanner()
        vuln = self._reachable_vuln()
        vuln.is_absorbed = True
        vuln.absorbed_by_group_key = "deserialization:project_chain"
        spec = dict(vuln.exploit_spec or {})
        spec.setdefault("entry", {})["route"] = "/users"
        spec["entry"]["method"] = "GET"

        proof_tier, _ = planner._backfill_proof_tier(vuln, spec)

        self.assertNotEqual(proof_tier, "chain_proven")


class AbsorbedRowSurvivesReportAggregationTests(unittest.TestCase):
    def _absorbed_row(self):
        return {
            "file": "src/main/java/org/joychou/controller/Shiro.java",
            "line": 37,
            "type": "JDK Serialization",
            "severity": "HIGH",
            "description": "new ObjectInputStream(bytes) 由注入类离线兜底分析器检出",
            "code_snippet": "ObjectInputStream in = new ObjectInputStream(bytes);",
            "sources": ["A2"],
            "canonical_group_key": "deserialization:project_chain",
            "chain_id": "deserialization:project_chain",
            "is_canonical": False,
            "is_absorbed": True,
            "absorbed_by_group_key": "deserialization:project_chain",
            "supporting_nodes": [],
            "supporting_node_count": 0,
            "proof_tier": "broad_static",
        }

    def test_absorbed_row_is_not_reabsorbed_by_report_side_aggregation(self):
        manager = ReportManager()
        canonical = {
            "file": "src/main/java/com/quote/controller/DebugController.java",
            "line": 24,
            "type": "Insecure Deserialization",
            "severity": "HIGH",
            "description": "HTTP import endpoint reaches deserialization",
            "code_snippet": "importConfig(@RequestParam String data)",
            "sources": ["A2"],
            "canonical_group_key": "deserialization:project_chain",
            "chain_id": "deserialization:project_chain",
            "is_canonical": True,
            "supporting_nodes": [
                {"file": "src/main/java/org/joychou/controller/Shiro.java", "line": 37, "type": "JDK Serialization"}
            ],
            "supporting_node_count": 1,
            "proof_tier": "broad_static",
        }

        aggregated = manager._aggregate_canonical_findings([canonical, self._absorbed_row()])

        # 补行必须原样留在输出里，且没有被并入 supporting_nodes 而消失
        absorbed = [v for v in aggregated if v.get("is_absorbed")]
        self.assertEqual(len(absorbed), 1)
        self.assertEqual(absorbed[0]["file"], "src/main/java/org/joychou/controller/Shiro.java")
        self.assertEqual(absorbed[0]["line"], 37)
        # canonical 只有一条，且 supporting_nodes 未被补行二次膨胀
        canonicals = [v for v in aggregated if v.get("is_canonical") and not v.get("is_absorbed")]
        self.assertEqual(len(canonicals), 1)
        self.assertEqual(len(canonicals[0].get("supporting_nodes") or []), 1)

    def test_absorbed_row_is_bool_and_string_tolerant(self):
        manager = ReportManager()
        self.assertTrue(manager._is_absorbed_row({"is_absorbed": True}))
        self.assertTrue(manager._is_absorbed_row({"is_absorbed": "true"}))
        self.assertTrue(manager._is_absorbed_row({"is_absorbed": "1"}))
        self.assertFalse(manager._is_absorbed_row({"is_absorbed": False}))
        self.assertFalse(manager._is_absorbed_row({"is_absorbed": ""}))
        self.assertFalse(manager._is_absorbed_row({}))

    def test_absorbed_row_is_not_mainline_d2_item(self):
        self.assertFalse(is_mainline_d2_item(self._absorbed_row()))


class AbsorbedRowReachesFinalReportTests(unittest.TestCase):
    """端到端：补行必须能走到报告 findings 列表，否则覆盖率与关联桥仍为空。"""

    def test_final_report_keeps_absorbed_row(self):
        controller, shiro, processor = _deserialization_trio()
        agent = A2SemanticAgent.__new__(A2SemanticAgent)
        rebuilt = agent.canonicalize_scan_results([
            ScanResult(file=controller.file, vulnerabilities=[controller], agent="a2"),
            ScanResult(file=shiro.file, vulnerabilities=[shiro], agent="a2"),
            ScanResult(file=processor.file, vulnerabilities=[processor], agent="a2"),
        ])

        manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            manager.output_dir = tempdir
            report = manager.generate_final_report(rebuilt, [], {"verifications": []})

        findings = (report.get("report") or {}).get("vulnerabilities") or []
        shiro_rows = [v for v in findings if "Shiro.java" in str(v.get("file") or "")]
        self.assertTrue(shiro_rows, "被吸收成员补行未出现在最终报告 findings 中")
        self.assertTrue(any(v.get("is_absorbed") for v in shiro_rows))
        self.assertEqual(
            shiro_rows[0].get("absorbed_by_group_key"), "deserialization:project_chain"
        )
        # 补行本身不得是 chain_proven（只有 canonical 可以是）
        self.assertTrue(
            all(str(v.get("proof_tier") or "") != "chain_proven" for v in shiro_rows),
            "被吸收成员补行被误判为 chain_proven，会进 D2 主链",
        )


if __name__ == "__main__":
    unittest.main()
