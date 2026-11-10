import unittest

from src.cli.benchmark_cli import _merge_a1_evidence_into_a2_results
from src.core.models import ScanResult, Vulnerability


class BenchmarkEvidenceTests(unittest.TestCase):
    def test_a1_evidence_promotes_business_chain_into_contract_ready_inputs(self):
        a1_result = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "GET", "route": "/secret/{id}"}],
                "source_candidates": [{"name": "id", "location": "path"}],
                "ownership_candidates": [{"snippet": "owner_id != current_user.id"}],
                "guard_candidates": [{"snippet": "login_required"}],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="Insecure Direct Object Reference",
            severity="HIGH",
            file="vault/app.py",
            line=233,
            description="ownership check is missing",
            proof_tier="broad_static",
            exploit_spec={},
            chain_proof={},
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["entry"]["route"], "/secret/{id}")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_name"], "id")
        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "idor")
        self.assertEqual(planned.proof_tier, "chain_proven")

    def test_flask_path_idor_prefers_path_parameter_and_real_method(self):
        a1_result = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [
                    {"method": "GET", "route": "/", "line": "96", "file": "vault/app.py", "function": "index"},
                    {"method": "DELETE", "route": "/passwords/<int:entry_id>", "line": "227", "file": "vault/app.py", "function": "delete_password"},
                ],
                "source_candidates": [
                    {"name": "X-User", "location": "header", "line": "90", "file": "vault/app.py", "function": "index"},
                    {"name": "entry_id", "location": "path", "line": "227", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>"},
                ],
                "ownership_candidates": [{"snippet": "VaultEntry.query.filter_by(id=entry_id, user_id=user.id)", "line": "229", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>"}],
                "guard_candidates": [{"snippet": "@login_required", "line": "226", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>"}],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="Insecure Direct Object Reference",
            severity="HIGH",
            file="vault/app.py",
            line=237,
            entry_point="ROUTE /passwords/<int:entry_id>",
            proof_tier="broad_static",
            exploit_spec={
                "entry": {
                    "route": "/passwords/<int:entry_id>",
                    "method": "GET",
                    "parameter_name": "X-User",
                    "parameter_location": "header",
                },
                "payload": {"payload_family": "idor"},
                "prerequisites": {},
                "success_signal": {},
            },
            chain_proof={},
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["entry"]["method"], "DELETE")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_name"], "entry_id")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_location"], "path")

    def test_ssrf_without_url_source_does_not_remain_chain_proven(self):
        a1_result = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "POST", "route": "/login"}],
                "source_candidates": [{"name": "username", "location": "form"}],
                "ownership_candidates": [],
                "guard_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=197,
            proof_tier="chain_proven",
            exploit_spec={
                "entry": {"route": "/dashboard", "method": "GET", "parameter_name": "url", "parameter_location": "query"},
                "payload": {"payload_family": "ssrf"},
                "prerequisites": {},
                "success_signal": {"signal_type": "response_body"},
            },
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
            },
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertFalse(planned.chain_proof["attacker_control_proven"])
        self.assertFalse(planned.chain_proof["payload_shape_proven"])
        self.assertEqual(planned.proof_tier, "broad_static")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_name"], "")

    def test_ssrf_prefers_url_like_source_over_generic_query_field(self):
        a1_result = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "GET", "route": "/fetch", "line": "10", "file": "vault/app.py", "function": "fetch"}],
                "source_candidates": [
                    {"name": "label", "location": "query", "line": "11", "file": "vault/app.py", "function": "fetch", "route": "/fetch", "semantic_tags": []},
                    {"name": "target_url", "location": "query", "line": "12", "file": "vault/app.py", "function": "fetch", "route": "/fetch", "semantic_tags": ["url_like"]},
                ],
                "ownership_candidates": [],
                "guard_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=12,
            proof_tier="broad_static",
            exploit_spec={
                "entry": {"route": "/fetch", "method": "GET", "parameter_name": "", "parameter_location": ""},
                "payload": {"payload_family": "ssrf"},
                "prerequisites": {},
                "success_signal": {"signal_type": "response_body"},
            },
            chain_proof={},
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["entry"]["parameter_name"], "target_url")

    def test_idor_with_path_and_ownership_evidence_can_reach_chain_proven(self):
        a1_result = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "DELETE", "route": "/passwords/<int:entry_id>", "line": "227", "file": "vault/app.py", "function": "delete_password"}],
                "source_candidates": [{"name": "entry_id", "location": "path", "line": "227", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>", "semantic_tags": ["resource_identifier"]}],
                "ownership_candidates": [{"snippet": "VaultEntry.query.filter_by(id=entry_id, user_id=user.id)", "line": "229", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>"}],
                "guard_candidates": [{"snippet": "@login_required", "line": "226", "file": "vault/app.py", "function": "delete_password", "route": "/passwords/<int:entry_id>"}],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="Insecure Direct Object Reference",
            severity="HIGH",
            file="vault/app.py",
            line=237,
            proof_tier="broad_static",
            exploit_spec={
                "entry": {"route": "/passwords/<int:entry_id>", "method": "DELETE", "parameter_name": "entry_id", "parameter_location": "path"},
                "payload": {"payload_family": "idor"},
                "prerequisites": {"auth_required": "required"},
                "success_signal": {"signal_type": "authorization_or_state_change"},
            },
            chain_proof={},
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.proof_tier, "chain_proven")

    def test_hono_eval_text_body_uses_raw_body_contract(self):
        a1_result = ScanResult(
            file="app.tsx",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "POST", "route": "/eval", "line": "103", "file": "app.tsx", "function": "route_post_eval_103"}],
                "source_candidates": [{"name": "body_text", "location": "body", "line": "104", "file": "app.tsx", "function": "route_post_eval_103", "route": "/eval", "method": "POST", "semantic_tags": ["raw_body"]}],
                "ownership_candidates": [],
                "guard_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="代码注入",
            severity="HIGH",
            file="app.tsx",
            line=84,
            proof_tier="broad_static",
            exploit_spec={
                "entry": {"route": "/eval", "method": "POST", "parameter_name": "", "parameter_location": ""},
                "payload": {"payload_family": "command-execution"},
                "prerequisites": {},
                "success_signal": {"signal_type": "response_body"},
            },
            chain_proof={},
        )
        a2_result = ScanResult(file="app.tsx", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["entry"]["method"], "POST")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_location"], "raw_body")
        self.assertEqual(planned.exploit_spec["entry"]["content_type"], "text/plain")

    def test_cross_file_auth_header_sanitizer_downgrades_auth_bypass_chain(self):
        app_evidence = ScanResult(
            file="vault/app.py",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "GET", "route": "/"}],
                "source_candidates": [{"name": "X-User", "location": "header"}],
                "ownership_candidates": [],
                "guard_candidates": [{"snippet": "@login_required"}],
                "sanitizer_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        proxy_evidence = ScanResult(
            file="authorizer/main.go",
            agent="a1",
            evidence={
                "entry_candidates": [],
                "source_candidates": [],
                "ownership_candidates": [],
                "guard_candidates": [],
                "sanitizer_candidates": [{"name": "X-User", "snippet": 'req.Header.Del("X-User")'}],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="Insecure Authentication",
            severity="HIGH",
            file="vault/app.py",
            line=175,
            proof_tier="chain_proven",
            exploit_spec={
                "entry": {"route": "/", "method": "GET", "parameter_name": "X-User", "parameter_location": "header"},
                "payload": {"payload_family": "auth-bypass"},
                "prerequisites": {},
                "success_signal": {"signal_type": "authorization_or_state_change"},
            },
            chain_proof={
                "reachable": True,
                "attacker_control_proven": True,
                "gate_bypass_or_satisfaction_proven": True,
                "payload_shape_proven": True,
                "success_signal_anchor_proven": True,
            },
        )
        a2_result = ScanResult(file="vault/app.py", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [app_evidence, proxy_evidence])
        planned = a2_result.vulnerabilities[0]

        self.assertFalse(planned.chain_proof["attacker_control_proven"])
        self.assertFalse(planned.chain_proof["payload_shape_proven"])
        self.assertEqual(planned.proof_tier, "broad_static")

    def test_hono_body_source_can_fill_command_execution_contract(self):
        a1_result = ScanResult(
            file="app.tsx",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "POST", "route": "/eval", "line": "10", "file": "app.tsx"}],
                "source_candidates": [{"name": "body_text", "location": "body", "line": "11", "file": "app.tsx"}],
                "ownership_candidates": [],
                "guard_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="Code Injection",
            severity="HIGH",
            file="app.tsx",
            line=12,
            proof_tier="broad_static",
            exploit_spec={"entry": {}, "payload": {}, "prerequisites": {}, "success_signal": {}},
            chain_proof={},
            code_snippet="const result = eval(code)",
        )
        a2_result = ScanResult(file="app.tsx", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["entry"]["route"], "/eval")
        self.assertEqual(planned.exploit_spec["entry"]["method"], "POST")
        self.assertEqual(planned.exploit_spec["entry"]["parameter_location"], "body")
        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "command-execution")

    def test_shell_default_credentials_chain_becomes_chain_proven(self):
        a1_result = ScanResult(
            file="entrypoint_geekgame.sh",
            agent="a1",
            evidence={
                "entry_candidates": [{"method": "PUT", "route": "/api/users/1", "line": "2", "file": "entrypoint_geekgame.sh"}],
                "source_candidates": [{"name": "authorization", "location": "header", "line": "2", "file": "entrypoint_geekgame.sh", "semantic_tags": ["auth_like"]}],
                "ownership_candidates": [],
                "guard_candidates": [{"snippet": 'curl --user "admin:$ADMIN_PASSWORD" http://127.0.0.1:3000/api/users/1'}],
                "sanitizer_candidates": [],
                "state_transition_candidates": [],
                "sink_candidates": [],
                "artifact_candidates": [],
            },
        )
        vuln = Vulnerability(
            type="不安全的凭证",
            severity="HIGH",
            file="entrypoint_geekgame.sh",
            line=14,
            proof_tier="broad_static",
            exploit_spec={"entry": {}, "payload": {}, "prerequisites": {}, "success_signal": {}},
            chain_proof={},
            code_snippet='curl --user "admin:$ADMIN_PASSWORD" http://127.0.0.1:3000/api/users/1 -XPUT --data "{\\"email\\":\\"x\\"}"',
            description="Grafana admin password is hardcoded in entrypoint and used against /api/users/1",
        )
        a2_result = ScanResult(file="entrypoint_geekgame.sh", vulnerabilities=[vuln], agent="a2")

        _merge_a1_evidence_into_a2_results([a2_result], [a1_result])
        planned = a2_result.vulnerabilities[0]

        self.assertEqual(planned.exploit_spec["payload"]["payload_family"], "default-credentials")
        self.assertEqual(planned.exploit_spec["entry"]["route"], "/api/users/1")
        self.assertEqual(planned.exploit_spec["entry"]["method"], "PUT")
        self.assertEqual(planned.proof_tier, "chain_proven")


if __name__ == "__main__":
    unittest.main()
