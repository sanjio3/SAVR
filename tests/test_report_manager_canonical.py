import tempfile
import unittest

from src.benchmark.report_manager import ReportManager
from src.core.models import ScanResult, Vulnerability


class ReportManagerCanonicalTests(unittest.TestCase):
    def test_generate_final_report_matches_a3_results_by_canonical_group_key(self):
        vuln = Vulnerability(
            type="Insecure Deserialization",
            severity="HIGH",
            file="src/main/java/com/quote/controller/DebugController.java",
            line=24,
            description="HTTP import endpoint reaches deserialization",
            code_snippet="importConfig(@RequestParam String data)",
            source="a2",
            canonical_group_key="deserialization:project_chain",
            is_canonical=True,
            supporting_nodes=[
                {
                    "file": "src/main/java/com/quote/service/QuoteService.java",
                    "line": 73,
                    "type": "JDK Serialization",
                    "severity": "HIGH",
                    "description": "Cache hand-off",
                    "entry_point": "",
                    "sink": "setQuoteCache",
                    "callers": "QuoteService#setQuoteCache",
                }
            ],
            supporting_node_count=1,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "deserialization:project_chain",
                            "match_keys": ["canonical:deserialization:project_chain"],
                            "file": "some/other/file.java",
                            "type": "Other",
                            "line": 999,
                            "exploitable": "Yes",
                            "confidence": "high",
                            "test_status": "DONE",
                            "reason": "verified through the canonical chain",
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "",
                            "poc_details": {},
                            "exploit_spec": {
                                "version": "d2.exec.v1",
                                "entry": {
                                    "route": "/debug/import",
                                    "method": "POST",
                                    "parameter_name": "data",
                                    "parameter_location": "form",
                                    "content_type": "application/x-www-form-urlencoded",
                                    "trigger_route": "/api/quote/random",
                                },
                                "prerequisites": {
                                    "auth_required": "unknown",
                                    "role_or_permission": "admin",
                                    "token_requirements": [],
                                    "session_requirements": [],
                                    "dependent_data": [],
                                    "ordered_steps": ["import object", "trigger cache"],
                                },
                                "payload": {
                                    "payload_family": "deserialization",
                                    "payload_constraints": ["must satisfy object shape"],
                                    "object_shape_constraints": [],
                                    "encoding": "base64",
                                    "candidate_payloads": [],
                                    "generator_hint": "",
                                },
                                "success_signal": {
                                    "signal_type": "state_change_or_side_effect",
                                    "match_strategy": "observe_secondary_trigger_effect",
                                    "expected_indicators": ["cache effect"],
                                    "verify_request": {"path": "/api/quote/random", "method": "GET"},
                                    "side_effect_target": "cache",
                                },
                            },
                            "contract_completeness": {"status": "ready", "score": 100, "missing_required": []},
                            "failure_classification": {"category": "signal_not_observed", "subtype": "secondary_effect", "explanation": "n/a", "retryable": False},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 1,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        self.assertEqual(finding["canonical_group_key"], "deserialization:project_chain")
        self.assertEqual(finding["supporting_node_count"], 1)
        self.assertEqual(finding["exploitable"], "Yes")
        self.assertEqual(finding["test_status"], "DONE")
        self.assertEqual(finding["exploit_spec"]["entry"]["route"], "/debug/import")
        self.assertEqual(finding["failure_classification"]["subtype"], "secondary_effect")
        summary = report["report"]["summary"]
        self.assertEqual(summary["broad_static_count"], 1)
        self.assertEqual(summary["chain_proven_count"], 0)
        self.assertEqual(summary["contract_ready_count"], 0)

    def test_generate_final_report_prefers_strongest_verification_with_same_canonical_key(self):
        vuln = Vulnerability(
            type="Java Deserialization Chain",
            severity="HIGH",
            file="src/main/java/com/quote/controller/DebugController.java",
            line=26,
            description="two-step chain",
            code_snippet="readObject()",
            source="a2",
            canonical_group_key="deserialization:project_chain",
            is_canonical=True,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "deserialization:project_chain",
                            "match_keys": ["canonical:deserialization:project_chain"],
                            "file": vuln.file,
                            "type": "Insecure Deserialization",
                            "line": 24,
                            "exploitable": "No",
                            "confidence": "low",
                            "test_status": "DONE",
                            "reason": "structure imported but file not observed",
                            "docker_attempted": True,
                            "docker_used": True,
                            "container_id": "cid-fail",
                            "service_url": "http://127.0.0.1:18080",
                            "container_kept_running": False,
                            "service_ready": True,
                            "poc_generated": True,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "failed poc",
                            "poc_details": {},
                            "exploit_spec": {},
                            "contract_completeness": {"status": "ready", "score": 90, "missing_required": []},
                            "failure_classification": {"category": "signal_not_observed", "subtype": "proof_missing", "explanation": "", "retryable": True},
                            "raw_output": "failed-output",
                            "verified_bundle": {},
                        },
                        {
                            "canonical_group_key": "deserialization:project_chain",
                            "match_keys": [
                                "canonical:deserialization:project_chain",
                                f"raw:{vuln.file}:{vuln.type}:{vuln.line}",
                            ],
                            "file": vuln.file,
                            "type": vuln.type,
                            "line": vuln.line,
                            "exploitable": "Yes",
                            "confidence": "high",
                            "test_status": "DONE",
                            "reason": "verified through proof file",
                            "docker_attempted": True,
                            "docker_used": True,
                            "container_id": "cid-ok",
                            "service_url": "http://127.0.0.1:18080",
                            "container_kept_running": True,
                            "service_ready": True,
                            "poc_generated": True,
                            "poc_verified": True,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "working poc",
                            "poc_details": {"result_json": "output/result.json"},
                            "exploit_spec": {
                                "version": "d2.exec.v1",
                                "entry": {
                                    "route": "/debug/import",
                                    "method": "POST",
                                    "parameter_name": "data",
                                    "parameter_location": "form",
                                    "content_type": "application/x-www-form-urlencoded",
                                    "trigger_route": "/api/quote/random",
                                },
                                "prerequisites": {
                                    "auth_required": "unknown",
                                    "role_or_permission": "",
                                    "token_requirements": [],
                                    "session_requirements": [],
                                    "dependent_data": [],
                                    "ordered_steps": ["import", "trigger"],
                                },
                                "payload": {
                                    "payload_family": "deserialization",
                                    "payload_constraints": [],
                                    "object_shape_constraints": [],
                                    "encoding": "base64",
                                    "candidate_payloads": [],
                                    "generator_hint": "",
                                },
                                "success_signal": {
                                    "signal_type": "state_change_or_side_effect",
                                    "match_strategy": "observe_secondary_trigger_effect",
                                    "expected_indicators": ["proof file"],
                                    "verify_request": {"path": "/api/quote/random", "method": "GET"},
                                    "side_effect_target": "cache",
                                },
                            },
                            "contract_completeness": {"status": "ready", "score": 100, "missing_required": []},
                            "failure_classification": {"category": "", "subtype": "", "explanation": "", "retryable": False},
                            "raw_output": '{"steps": [{"step":"verify_file_1","result":{"stdout":"__A3_FILE_PRESENT__"}}]}',
                            "verified_bundle": {"result_json": "output/result.json"},
                        },
                    ],
                    "pocs": [],
                    "exploitable_count": 1,
                    "verified_poc_count": 1,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        self.assertEqual(finding["exploitable"], "Yes")
        self.assertTrue(finding["poc_verified"])
        self.assertEqual(finding["reason"], "verified through proof file")
        self.assertEqual(finding["container_id"], "cid-ok")
        self.assertTrue("__A3_FILE_PRESENT__" in str(finding["raw_output"]))
        self.assertEqual(finding["verified_bundle"]["result_json"], "output/result.json")

    def test_generate_final_report_counts_chain_proven_and_contract_ready(self):
        vuln = Vulnerability(
            type="SQL Injection",
            severity="HIGH",
            file="src/main/java/com/demo/UserController.java",
            line=18,
            description="Controller parameter reaches query",
            source="a2",
            canonical_group_key="sql:/users:id",
            chain_id="sql:/users:id",
            is_canonical=True,
            proof_tier="chain_proven",
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
                "proof_confidence": "high",
                "proof_gaps": [],
            },
            a21_selected=True,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {"verifications": [], "pocs": [], "exploitable_count": 0, "verified_poc_count": 0},
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )
        summary = report["report"]["summary"]
        self.assertEqual(summary["broad_static_count"], 1)
        self.assertEqual(summary["chain_proven_count"], 1)
        self.assertEqual(summary["contract_ready_count"], 1)

    def test_generate_final_report_preserves_a21_reason_and_contract_gaps_without_a3(self):
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=197,
            description="server-side fetch without proven URL control",
            source="a2",
            proof_tier="broad_static",
            proof_gaps=["attacker_control_proven", "payload_shape_proven"],
            contract_gaps=["proof_tier!=chain_proven"],
            a21_selected=False,
            a21_reason="contract_blocked_by_proof_gap: attacker_control_proven, payload_shape_proven",
            proof_context_summary={"nearest_entry_route": "/dashboard", "nearest_source_name": "username"},
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {"verifications": [], "pocs": [], "exploitable_count": 0, "verified_poc_count": 0},
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        self.assertFalse(finding["a21_selected"])
        self.assertEqual(finding["a21_reason"], "contract_blocked_by_proof_gap: attacker_control_proven, payload_shape_proven")
        self.assertEqual(finding["proof_gaps"], ["attacker_control_proven", "payload_shape_proven"])
        self.assertEqual(finding["contract_gaps"], ["proof_tier!=chain_proven"])
        self.assertEqual(finding["proof_context_summary"]["nearest_entry_route"], "/dashboard")

    def test_single_canonical_finding_promotes_supporting_node_chain_context(self):
        vuln = Vulnerability(
            type="Java 反序列化链",
            severity="HIGH",
            file="src/main/java/com/quote/controller/DebugController.java",
            line=24,
            description="rule hit",
            source="a2",
            canonical_group_key="deserialization:project_chain",
            chain_id="deserialization:project_chain",
            is_canonical=True,
            proof_tier="broad_static",
            chain_proof={
                "reachable": False,
                "attacker_control_proven": False,
                "gate_bypass_or_satisfaction_proven": False,
                "payload_shape_proven": False,
                "success_signal_anchor_proven": False,
                "proof_confidence": "",
                "proof_gaps": [],
            },
            supporting_nodes=[
                {
                    "file": "src/main/java/com/quote/controller/DebugController.java",
                    "line": 26,
                    "type": "反序列化",
                    "description": "Map imported from /debug/import",
                    "chain_id": "deserialization:project_chain",
                    "proof_tier": "chain_proven",
                    "chain_proof": {
                        "reachable": True,
                        "attacker_control_proven": True,
                        "gate_bypass_or_satisfaction_proven": True,
                        "payload_shape_proven": True,
                        "success_signal_anchor_proven": True,
                        "proof_confidence": "high",
                        "proof_gaps": [],
                    },
                    "exploit_spec": {
                        "version": "d2.exec.v1",
                        "entry": {
                            "route": "/debug/import",
                            "method": "POST",
                            "parameter_name": "data",
                            "parameter_location": "form",
                            "content_type": "application/x-www-form-urlencoded",
                            "trigger_route": "/api/quote/random",
                        },
                        "prerequisites": {
                            "auth_required": "unknown",
                            "role_or_permission": "",
                            "token_requirements": [],
                            "session_requirements": [],
                            "dependent_data": [],
                            "ordered_steps": ["import", "trigger"],
                        },
                        "payload": {
                            "payload_family": "deserialization",
                            "payload_constraints": ["business object shape"],
                            "object_shape_constraints": [],
                            "encoding": "base64",
                            "candidate_payloads": [],
                            "generator_hint": "",
                        },
                        "success_signal": {
                            "signal_type": "state_change_or_side_effect",
                            "match_strategy": "observe_secondary_trigger_effect",
                            "expected_indicators": ["proof file"],
                            "verify_request": {"path": "/api/quote/random", "method": "GET"},
                            "side_effect_target": "cache",
                        },
                    },
                    "contract_completeness": {"status": "ready", "score": 100, "missing_required": []},
                    "a21_selected": True,
                    "a21_reason": "selected for contract planning",
                    "a21_candidate_score": 95,
                }
            ],
            supporting_node_count=1,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            generated = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {"verifications": [], "pocs": [], "exploitable_count": 0, "verified_poc_count": 0},
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )
        finding = generated["report"]["vulnerabilities"][0]
        self.assertEqual(finding["proof_tier"], "chain_proven")
        self.assertEqual(finding["exploit_spec"]["entry"]["route"], "/debug/import")
        self.assertEqual(finding["contract_completeness"]["status"], "ready")
        self.assertTrue(finding["a21_selected"])
        self.assertEqual(finding["display_title"], "Java 反序列化链")

    def test_generate_final_report_prefers_verification_failure_reason_in_summary(self):
        vuln = Vulnerability(
            type="Java Deserialization Chain",
            severity="HIGH",
            file="src/main/java/com/quote/controller/DebugController.java",
            line=24,
            description="two-step chain",
            code_snippet="importConfig(@RequestParam String data)",
            source="a2",
            canonical_group_key="deserialization:project_chain",
            is_canonical=True,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            generated = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "deserialization:project_chain",
                            "match_keys": ["canonical:deserialization:project_chain"],
                            "file": vuln.file,
                            "type": vuln.type,
                            "line": vuln.line,
                            "exploitable": "No",
                            "confidence": "medium",
                            "test_status": "DONE",
                            "reason": "结构化 payload 已导入，但未观察到目标文件落地",
                            "docker_attempted": True,
                            "docker_used": True,
                            "container_id": "abc123",
                            "service_url": "http://127.0.0.1:18080",
                            "container_kept_running": False,
                            "service_ready": True,
                            "poc_generated": True,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "demo",
                            "poc_details": {},
                            "is_primary_chain": True,
                            "d2_candidate_ready": True,
                            "exploit_spec": {
                                "version": "d2.exec.v1",
                                "entry": {
                                    "route": "/debug/import",
                                    "method": "POST",
                                    "parameter_name": "data",
                                    "parameter_location": "form",
                                    "content_type": "application/x-www-form-urlencoded",
                                    "trigger_route": "/api/quote/random",
                                },
                                "prerequisites": {
                                    "auth_required": "unknown",
                                    "role_or_permission": "",
                                    "token_requirements": [],
                                    "session_requirements": [],
                                    "dependent_data": [],
                                    "ordered_steps": ["import", "trigger"],
                                },
                                "payload": {
                                    "payload_family": "deserialization",
                                    "payload_constraints": [],
                                    "object_shape_constraints": [],
                                    "encoding": "base64",
                                    "candidate_payloads": [],
                                    "generator_hint": "",
                                },
                                "success_signal": {
                                    "signal_type": "state_change_or_side_effect",
                                    "match_strategy": "observe_secondary_trigger_effect",
                                    "expected_indicators": ["proof file"],
                                    "verify_request": {"path": "/api/quote/random", "method": "GET"},
                                    "side_effect_target": "cache",
                                },
                            },
                            "contract_completeness": {"status": "ready", "score": 100, "missing_required": []},
                            "failure_classification": {"category": "signal_not_observed", "subtype": "proof_file_missing", "explanation": "", "retryable": True},
                        },
                        {
                            "canonical_group_key": "csrf:secondary",
                            "match_keys": ["canonical:csrf:secondary"],
                            "file": "src/main/java/com/quote/controller/AdminController.java",
                            "type": "Missing CSRF",
                            "line": 12,
                            "exploitable": "No",
                            "confidence": "low",
                            "test_status": "NOT_TESTED",
                            "reason": "D2 skipped deterministic execution because the exploit contract is incomplete",
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "D2 skipped deterministic execution because the exploit contract is incomplete",
                            "llm_poc_code": "",
                            "poc_details": {},
                            "exploit_spec": {},
                            "contract_completeness": {"status": "missing", "score": 0, "missing_required": ["entry.route"]},
                            "failure_classification": {"category": "contract_incomplete", "subtype": "missing_required_fields", "explanation": "", "retryable": True},
                        },
                    ],
                    "pocs": [],
                    "exploitable_count": 0,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )
            markdown = open(generated["markdown_file"], "r", encoding="utf-8").read()

        self.assertIn("- POC 未验证成功原因：结构化 payload 已导入，但未观察到目标文件落地", markdown)
        self.assertNotIn("- POC 未生成原因：D2 skipped deterministic execution because the exploit contract is incomplete", markdown)


    def test_generate_final_report_excludes_contract_incomplete_fallback_from_a3_counts(self):
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=197,
            description="dashboard reaches outbound request",
            source="a2",
            canonical_group_key="ssrf:vault/app.py:197",
            chain_id="ssrf:vault/app.py:197",
            is_canonical=True,
            proof_tier="chain_proven",
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
                "proof_confidence": "high",
                "proof_gaps": [],
            },
            a21_selected=True,
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "ssrf:vault/app.py:197",
                            "match_keys": ["canonical:ssrf:vault/app.py:197"],
                            "file": vuln.file,
                            "type": vuln.type,
                            "line": vuln.line,
                            "proof_tier": "chain_proven",
                            "exploitable": "No",
                            "confidence": "medium",
                            "test_status": "NOT_TESTED",
                            "reason": "D2 skipped deterministic execution because the exploit contract is incomplete",
                            "poc_generated": True,
                            "poc_verified": False,
                            "attack_plan": {"source": "deterministic"},
                            "poc_details": {"target_url": "/dashboard"},
                            "contract_completeness": {"status": "missing", "score": 0, "missing_required": ["entry.method"]},
                            "failure_classification": {"category": "contract_incomplete", "subtype": "missing_required_fields", "explanation": "", "retryable": True},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 0,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        summary = report["report"]["summary"]
        self.assertEqual(summary["d2_tested_count"], 0)
        self.assertEqual(summary["d2_poc_generated"], 0)
        self.assertEqual(summary["canonical_poc_count"], 0)
        self.assertEqual(summary["excluded_d2_fallback_count"], 1)


if __name__ == "__main__":
    unittest.main()
