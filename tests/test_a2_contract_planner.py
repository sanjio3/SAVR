import unittest

from src.agents.a2_contract_planner import A2ContractPlanner
from src.core.models import ScanResult, Vulnerability


class A2ContractPlannerTests(unittest.TestCase):
    def test_marks_reachable_canonical_vuln_as_selected(self):
        agent = A2ContractPlanner()
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
        vuln.a1_evidence = {
            "source_candidates": [{"name": "id", "location": "query"}],
        }

        results = agent.plan_scan_results([ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")])
        planned = results[0].vulnerabilities[0]

        self.assertTrue(planned.a21_selected)
        self.assertGreaterEqual(planned.a21_candidate_score, 55)
        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "sql-injection")
        self.assertEqual(planned.proof_tier, "chain_proven")

    def test_enriches_business_workflow_prerequisites(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="Refund workflow bypass",
            severity="HIGH",
            file="src\\RefundController.java",
            line=42,
            description="Refund endpoint can be called twice on the same order",
            entry_point="POST route:/api/refund",
            has_http_entry=True,
            has_call_chain=True,
            callers="refundApply -> refundService.process -> wallet.credit",
            verdict="✅ A2:真漏洞-HTTP入口可触发",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/api/refund"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["success_signal"]["signal_type"] = "business_state_change"

        planned = agent.plan_vulnerability(vuln)

        self.assertIn(planned.exploit_spec["payload"]["payload_family"], {"race-condition", "workflow-bypass"})
        self.assertTrue(planned.exploit_spec["prerequisites"]["ordered_steps"])
        self.assertTrue(planned.exploit_spec["prerequisites"]["dependent_data"])
        self.assertTrue(planned.a21_selected)
        self.assertEqual(planned.proof_tier, "chain_proven")

    def test_backfills_trigger_route_for_project_deserialization_chain(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="Insecure Deserialization",
            severity="HIGH",
            file="src\\main\\java\\com\\quote\\controller\\DebugController.java",
            line=24,
            description="Debug import triggers deferred cache processing via /api/quote/random",
            entry_point="POST route:/debug/import",
            has_http_entry=True,
            has_call_chain=True,
            callers="setQuoteCache -> CacheProcessor.process",
            verdict="✅ A2:真漏洞-HTTP入口可触发",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/debug/import"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["payload"]["payload_family"] = "deserialization"
        vuln.exploit_spec["success_signal"]["signal_type"] = "state_change_or_side_effect"

        planned = agent.plan_vulnerability(vuln)

        self.assertEqual(planned.exploit_spec["entry"]["trigger_route"], "/api/quote/random")
        self.assertEqual(planned.exploit_spec["success_signal"]["verify_request"]["path"], "/api/quote/random")
        self.assertEqual(planned.proof_tier, "chain_proven")
        self.assertEqual(planned.exploit_spec["expected_outcomes"]["primary_outcome"], "proof_file_created")
        self.assertIn("proof_file_created", planned.exploit_spec["validation_contract"]["confirmed_by"])
        self.assertIn("remove_proof_file", planned.exploit_spec["expected_outcomes"]["cleanup_requirements"])

    def test_rejects_candidate_when_chain_is_not_established(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="SQL Injection",
            severity="HIGH",
            file="src\\UserController.java",
            line=18,
            description="Potential query concatenation",
            entry_point="GET route:/users",
            has_http_entry=True,
            has_call_chain=False,
            verdict="⚠️ A2:可疑-需A3验证",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/users"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "id"
        vuln.exploit_spec["payload"]["payload_family"] = "sql-injection"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"

        planned = agent.plan_vulnerability(vuln)

        self.assertFalse(planned.a21_selected)
        self.assertIn("contract_blocked_by_proof_gap", planned.a21_reason)

    def test_rejects_candidate_when_not_reachable(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="Command Injection",
            severity="HIGH",
            file="src\\Util.java",
            line=9,
            description="exec helper exists",
            verdict="✅ A2:真漏洞-有危险sink",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/admin/run"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["payload"]["payload_family"] = "command-execution"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"

        planned = agent.plan_vulnerability(vuln)

        self.assertFalse(planned.a21_selected)
        self.assertIn("contract_blocked_by_proof_gap", planned.a21_reason)

    def test_generates_strong_file_upload_contract(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="File Upload",
            severity="HIGH",
            file="src\\UploadController.java",
            line=33,
            description="upload endpoint stores user-controlled executable file names",
            entry_point="POST route:/upload",
            has_http_entry=True,
            has_call_chain=True,
            callers="multipart upload reaches disk write sink",
            verdict="true positive",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/upload"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["entry"]["parameter_name"] = "file"
        vuln.exploit_spec["payload"]["payload_family"] = "file-upload"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_or_side_effect"

        planned = agent.plan_vulnerability(vuln)

        self.assertTrue(planned.a21_selected)
        self.assertEqual(planned.exploit_spec["expected_outcomes"]["primary_outcome"], "uploaded_webshell_accepted")
        self.assertIn("remove_uploaded_probe_file", planned.exploit_spec["expected_outcomes"]["cleanup_requirements"])
        self.assertIn("uploaded_webshell_accepted", planned.exploit_spec["validation_contract"]["confirmed_by"])

    def test_promotes_full_incoming_chain_proof_and_backfills_route_entry_to_contract_ready(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault\\app.py",
            line=197,
            description="user-controlled outbound request",
            entry_point="GET /fetch",
            has_call_chain=True,
            verdict="鈿狅笍 pending validation",
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
                "proof_confidence": "high",
                "proof_gaps": [],
            },
            proof_tier="broad_static",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/fetch"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "url"
        vuln.exploit_spec["entry"]["parameter_location"] = "query"
        vuln.exploit_spec["payload"]["payload_family"] = "ssrf"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"
        vuln.a1_evidence = {
            "source_candidates": [{"name": "url", "location": "query"}],
        }

        planned = agent.plan_vulnerability(vuln)

        self.assertEqual(planned.proof_tier, "chain_proven")
        self.assertEqual(planned.proof_gaps, [])
        self.assertTrue(planned.chain_proof["attacker_control_proven"])
        self.assertEqual(planned.exploit_spec["entry"]["route"], "/fetch")
        self.assertEqual(planned.exploit_spec["entry"]["method"], "GET")
        self.assertTrue(planned.a21_selected)

    def test_ssrf_without_a1_url_source_evidence_is_not_selected(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault\\app.py",
            line=197,
            description="user-controlled outbound request",
            entry_point="GET /dashboard",
            has_call_chain=True,
            verdict="⚠️ pending validation",
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
                "proof_confidence": "high",
                "proof_gaps": [],
            },
            proof_tier="broad_static",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/dashboard"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "url"
        vuln.exploit_spec["entry"]["parameter_location"] = "query"
        vuln.exploit_spec["payload"]["payload_family"] = "ssrf"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"
        vuln.a1_evidence = {
            "source_candidates": [{"name": "username", "location": "form"}],
        }

        planned = agent.plan_vulnerability(vuln)

        self.assertFalse(planned.a21_selected)
        self.assertEqual(planned.proof_tier, "broad_static")
        # Q5 放宽为「结构可执行即可尝试」：SSRF 有 route/method/family/signal 但 A1 无 URL 类源点，
        # 仍进入细分评分并因缺 URL-like 源证据被拒，reason 应说明缺失的源证据而非笼统 proof_gap。
        self.assertIn("URL-like source evidence", planned.a21_reason)

    def test_default_database_configuration_is_not_promoted_to_sqli_contract(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="Insecure Default Configuration",
            severity="MEDIUM",
            file="vault\\app.py",
            line=15,
            description="The application uses a default SQLite database and creates an admin user if no users exist.",
            entry_point="GET /",
            has_http_entry=True,
            has_call_chain=True,
            callers="authorizer -> index",
            verdict="true positive",
        )
        vuln.is_canonical = True

        planned = agent.plan_vulnerability(vuln)

        self.assertNotEqual(planned.exploit_spec["payload"]["payload_family"], "sql-injection")
        self.assertFalse(planned.a21_selected)
        # callers 含 "authorizer" 被文本启发式归到 auth-bypass 族，结构完整但缺 auth/session 源证据，
        # 进入细分评分后被拒；reason 应说明缺失的源证据（而非笼统 contract_blocked_by_proof_gap）。
        self.assertIn("auth/session source evidence", planned.a21_reason)

    def test_generates_idor_contract_for_chain_proven_business_finding(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            type="Insecure Direct Object Reference",
            severity="HIGH",
            file="vault\\app.py",
            line=233,
            description="resource owner validation is missing for /secret/<id>",
            entry_point="GET /secret/{id}",
            has_http_entry=True,
            has_call_chain=True,
            callers="current_user -> secret lookup by resource_id",
            verdict="true positive",
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
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/secret/{id}"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "id"
        vuln.exploit_spec["entry"]["parameter_location"] = "path"
        vuln.exploit_spec["payload"]["payload_family"] = "idor"
        vuln.exploit_spec["success_signal"]["signal_type"] = "authorization_or_state_change"

        planned = agent.plan_vulnerability(vuln)

        self.assertTrue(planned.a21_selected)
        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "idor")
        self.assertEqual(planned.exploit_spec["expected_outcomes"]["primary_outcome"], "authorization_or_state_change_observed")
        self.assertIn("authorization_or_state_change_observed", planned.exploit_spec["validation_contract"]["confirmed_by"])

    def test_prefers_spel_payloads_for_java_expression_chain(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            file="com\\ctf\\gateway\\service\\EvaluationService.java",
            line=33,
            severity="HIGH",
            type="SPEL003",
            description="SpEL expression evaluation via TemplateParserContext",
            code_snippet="parseExpression(expression, new TemplateParserContext()).getValue(context)",
            has_http_entry=True,
            entry_point="GET /check",
            has_call_chain=True,
            callers="GatewayController.checkRule -> EvaluationService.evaluate",
        )
        vuln.is_canonical = True
        vuln.canonical_group_key = "template-injection:expression_chain"
        vuln.chain_id = "template-injection:expression_chain"
        vuln.proof_tier = "chain_proven"
        vuln.exploit_spec["entry"]["route"] = "/check"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "rule"
        vuln.exploit_spec["entry"]["parameter_location"] = "query"
        vuln.exploit_spec["payload"]["payload_family"] = "template-injection"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"

        planned = agent.plan_vulnerability(vuln)

        self.assertTrue(planned.a21_selected)
        self.assertEqual(planned.exploit_spec["payload"]["candidate_payloads"][0], "#{7*7}")
        self.assertEqual(planned.exploit_spec["payload"]["verification_payloads"][0], "#{7*7}")
        self.assertEqual(planned.exploit_spec["payload"]["high_impact_payloads"][0], "#{T(java.lang.System).getProperties()}")
        self.assertEqual(planned.exploit_spec["expected_outcomes"]["primary_outcome"], "high_impact_indicator_observed")

    def test_spel_expression_chain_ladder_contains_multiple_high_impact_steps(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            file="com\\ctf\\gateway\\service\\EvaluationService.java",
            line=33,
            severity="HIGH",
            type="SPEL003",
            description="SpEL expression evaluation via TemplateParserContext",
            code_snippet="parseExpression(expression, new TemplateParserContext()).getValue(context)",
            has_http_entry=True,
            entry_point="GET /check",
            has_call_chain=True,
            callers="GatewayController.checkRule -> EvaluationService.evaluate",
        )
        vuln.is_canonical = True
        vuln.canonical_group_key = "template-injection:expression_chain"
        vuln.chain_id = "template-injection:expression_chain"
        vuln.proof_tier = "chain_proven"
        vuln.exploit_spec["entry"]["route"] = "/check"
        vuln.exploit_spec["entry"]["method"] = "GET"
        vuln.exploit_spec["entry"]["parameter_name"] = "rule"
        vuln.exploit_spec["entry"]["parameter_location"] = "query"
        vuln.exploit_spec["payload"]["payload_family"] = "template-injection"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"

        planned = agent.plan_vulnerability(vuln)

        ladder = planned.exploit_spec["payload"]["high_impact_ladder"]
        self.assertTrue(any(step.get("goal") == "info_disclosure" for step in ladder))
        self.assertTrue(any(step.get("goal") == "file_read" for step in ladder))
        self.assertTrue(any(step.get("goal") == "command_execution" for step in ladder))
        flattened_payloads = "\n".join("\n".join(step.get("payloads") or []) for step in ladder)
        self.assertIn("readAllBytes", flattened_payloads)
        self.assertIn("exec('id')", flattened_payloads)

    def test_freemarker_context_gets_engine_specific_high_impact_payloads(self):
        agent = A2ContractPlanner()
        vuln = Vulnerability(
            file="com\\demo\\render\\MailRenderer.java",
            line=18,
            severity="HIGH",
            type="SSTI",
            description="Freemarker template rendering with user-supplied template",
            code_snippet="freemarker.template.Template.process(model, writer)",
            has_http_entry=True,
            entry_point="POST /render",
            has_call_chain=True,
            callers="MailController.render -> MailRenderer.process",
        )
        vuln.is_canonical = True
        vuln.canonical_group_key = "template-injection:expression_chain"
        vuln.chain_id = "template-injection:expression_chain"
        vuln.proof_tier = "chain_proven"
        vuln.exploit_spec["entry"]["route"] = "/render"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["entry"]["parameter_name"] = "template"
        vuln.exploit_spec["entry"]["parameter_location"] = "body"
        vuln.exploit_spec["payload"]["payload_family"] = "template-injection"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"

        planned = agent.plan_vulnerability(vuln)

        self.assertIn("${7*7}", planned.exploit_spec["payload"]["verification_payloads"])
        self.assertTrue(any("freemarker.template.utility.Execute" in payload for payload in planned.exploit_spec["payload"]["high_impact_payloads"]))
        self.assertIn("2.3.", planned.exploit_spec["success_signal"]["expected_indicators"])


if __name__ == "__main__":
    unittest.main()
