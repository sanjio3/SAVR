import unittest
from pathlib import Path

from src.agents.d2_strategy import try_deterministic_verification
from src.agents.d2_types import VerificationResult
from src.core.exploit_spec import empty_exploit_spec
from src.pipeline.d2.resources.tools.exploits.generic_idor_probe import apply_path_payload


class _DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(message)


class _DummyTools:
    @staticmethod
    def _get_image_exposed_ports(image):
        return [3000]


class _DummyAgent:
    def __init__(self):
        self.tools = _DummyTools()
        self.verify_calls = []

    @staticmethod
    def _select_project_image(project_path, fallback):
        return fallback

    def _verify_node_jwt_chain(self, project_path, strategy):
        self.verify_calls.append((project_path, strategy))
        return VerificationResult(reason="verified", poc_type="node-jwt", exploitable=True)

    def _ensure_attack_plan(self, result, vulnerability, project_context, strategy=None, understanding=None, plan=None):
        return result


class D2StrategyTests(unittest.TestCase):
    def test_generic_idor_probe_replaces_flask_typed_path_parameter(self):
        self.assertEqual(
            apply_path_payload("/passwords/<int:entry_id>", "entry_id", "2"),
            "/passwords/2",
        )

    def test_returns_none_when_project_path_missing(self):
        agent = _DummyAgent()
        logger = _DummyLogger()

        result = try_deterministic_verification(
            agent,
            {"type": "JWT", "file": "server.js", "line": 1},
            {},
            logger,
        )

        self.assertIsNone(result)
        self.assertEqual(agent.verify_calls, [])

    def test_uses_contract_driven_verifier_dispatch(self):
        agent = _DummyAgent()
        logger = _DummyLogger()
        exploit_spec = empty_exploit_spec()
        exploit_spec["entry"]["route"] = "/auth"
        exploit_spec["entry"]["method"] = "GET"
        exploit_spec["entry"]["parameter_name"] = "token"
        exploit_spec["payload"]["payload_family"] = "jwt"
        exploit_spec["success_signal"]["signal_type"] = "authorization_or_state_change"
        exploit_spec["success_signal"]["expected_indicators"] = ["admin"]

        result = try_deterministic_verification(
            agent,
            {"type": "JWT", "file": "server.js", "line": 3, "exploit_spec": exploit_spec},
            {"project_path": "demo-app"},
            logger,
        )

        self.assertTrue(result.exploitable)
        self.assertEqual(result.poc_type, "node-jwt")
        self.assertEqual(agent.verify_calls[0][0], Path("demo-app"))
        self.assertEqual(agent.verify_calls[0][1]["target_path"], "/auth")
        self.assertEqual(agent.verify_calls[0][1]["parameter"], "token")
        self.assertEqual(result.verification_decision["verification_status"], "confirmed_exploitable")
        self.assertIn("execution_evidence", result.to_dict())
        self.assertIn("contract-driven deterministic verification", logger.messages[0])

    def test_incomplete_contract_returns_contract_incomplete(self):
        agent = _DummyAgent()
        logger = _DummyLogger()
        exploit_spec = {"entry": {"route": "/auth"}}

        result = try_deterministic_verification(
            agent,
            {"type": "JWT", "file": "server.js", "line": 3, "exploit_spec": exploit_spec},
            {"project_path": "demo-app"},
            logger,
        )

        self.assertFalse(result.exploitable)
        self.assertEqual(result.failure_classification["category"], "contract_incomplete")
        self.assertEqual(agent.verify_calls, [])

    def test_java_deserialization_uses_trigger_from_verify_request(self):
        agent = _DummyAgent()
        logger = _DummyLogger()
        exploit_spec = empty_exploit_spec()
        exploit_spec["entry"]["route"] = "/debug/import"
        exploit_spec["entry"]["method"] = "POST"
        exploit_spec["payload"]["payload_family"] = "deserialization"
        exploit_spec["success_signal"]["signal_type"] = "state_change_or_side_effect"
        exploit_spec["success_signal"]["verify_request"] = {"path": "/api/quote/random", "method": "GET"}

        class _JavaAgent(_DummyAgent):
            def _verify_map_deserialization_chain(self, project_path, strategy):
                self.verify_calls.append((project_path, strategy))
                return VerificationResult(reason="verified", poc_type="java-map-payload", exploitable=True)

        java_agent = _JavaAgent()
        result = try_deterministic_verification(
            java_agent,
            {"type": "Insecure Deserialization", "file": "DebugController.java", "line": 24, "exploit_spec": exploit_spec},
            {"project_path": "demo-app"},
            logger,
        )

        self.assertTrue(result.exploitable)
        self.assertEqual(java_agent.verify_calls[0][1]["trigger_path"], "/api/quote/random")

    def test_java_template_injection_prefers_spel_payload_when_context_indicates_spel(self):
        logger = _DummyLogger()
        exploit_spec = empty_exploit_spec()
        exploit_spec["entry"]["route"] = "/check"
        exploit_spec["entry"]["method"] = "GET"
        exploit_spec["entry"]["parameter_name"] = "rule"
        exploit_spec["payload"]["payload_family"] = "template-injection"
        exploit_spec["payload"]["verification_payloads"] = ["#{7*7}"]
        exploit_spec["payload"]["high_impact_payloads"] = ["#{T(java.lang.System).getProperties()}"]
        exploit_spec["payload"]["candidate_payloads"] = ["#{T(java.lang.System).getProperties()}", "#{7*7}"]
        exploit_spec["success_signal"]["signal_type"] = "response_body"
        exploit_spec["success_signal"]["expected_indicators"] = ["java.version", "49"]

        class _JavaTemplateAgent(_DummyAgent):
            def _verify_java_template_chain(self, project_path, strategy):
                self.verify_calls.append((project_path, strategy))
                return VerificationResult(reason="verified", poc_type="java-template", exploitable=True)

        java_agent = _JavaTemplateAgent()
        result = try_deterministic_verification(
            java_agent,
            {
                "type": "SPEL003",
                "description": "SpEL expression evaluation through TemplateParserContext",
                "code_snippet": "parseExpression(expression, new TemplateParserContext())",
                "file": "EvaluationService.java",
                "line": 33,
                "exploit_spec": exploit_spec,
            },
            {"project_path": "demo-app"},
            logger,
        )

        self.assertTrue(result.exploitable)
        self.assertEqual(java_agent.verify_calls[0][1]["payload"], "#{T(java.lang.System).getProperties()}")
        self.assertEqual(java_agent.verify_calls[0][1]["fallback_payload"], "#{7*7}")

    def test_python_idor_uses_contract_driven_dispatch(self):
        logger = _DummyLogger()
        exploit_spec = empty_exploit_spec()
        exploit_spec["entry"]["route"] = "/secret/{id}"
        exploit_spec["entry"]["method"] = "GET"
        exploit_spec["entry"]["parameter_name"] = "id"
        exploit_spec["entry"]["parameter_location"] = "path"
        exploit_spec["payload"]["payload_family"] = "idor"
        exploit_spec["success_signal"]["signal_type"] = "authorization_or_state_change"

        class _PythonAgent(_DummyAgent):
            def _verify_python_idor_chain(self, project_path, strategy):
                self.verify_calls.append((project_path, strategy))
                return VerificationResult(reason="verified", poc_type="python-idor", exploitable=True)

        python_agent = _PythonAgent()
        result = try_deterministic_verification(
            python_agent,
            {"type": "IDOR", "file": "vault/app.py", "line": 233, "exploit_spec": exploit_spec},
            {"project_path": "demo-app"},
            logger,
        )

        self.assertTrue(result.exploitable)
        self.assertEqual(python_agent.verify_calls[0][1]["transport"], "path")
        self.assertEqual(python_agent.verify_calls[0][1]["resource_path_template"], "/secret/{id}")

    def test_secretvault_project_detection_requires_expected_routes(self):
        from tempfile import TemporaryDirectory
        from src.agents.d2_python_strategies import D2PythonStrategiesMixin

        with TemporaryDirectory() as tmp:
            vault_dir = Path(tmp) / "vault"
            vault_dir.mkdir()
            (vault_dir / "app.py").write_text(
                "\n".join([
                    "@app.route('/register', methods=['GET', 'POST'])",
                    "@app.route('/login', methods=['GET', 'POST'])",
                    "@app.route('/passwords/new', methods=['POST'])",
                    "@app.route('/passwords/<int:entry_id>', methods=['DELETE'])",
                ]),
                encoding="utf-8",
            )
            self.assertTrue(
                D2PythonStrategiesMixin._looks_like_secretvault_project(
                    Path(tmp),
                    {"resource_path_template": "/passwords/<int:entry_id>"},
                )
            )

    def test_ai_mixed_judge_can_override_intermediate_status(self):
        logger = _DummyLogger()
        exploit_spec = empty_exploit_spec()
        exploit_spec["entry"]["route"] = "/secret/{id}"
        exploit_spec["entry"]["method"] = "GET"
        exploit_spec["entry"]["parameter_name"] = "id"
        exploit_spec["entry"]["parameter_location"] = "path"
        exploit_spec["payload"]["payload_family"] = "idor"
        exploit_spec["success_signal"]["signal_type"] = "authorization_or_state_change"

        class _AiAgent(_DummyAgent):
            def _verify_python_idor_chain(self, project_path, strategy):
                self.verify_calls.append((project_path, strategy))
                return VerificationResult(
                    reason="executed",
                    poc_type="python-idor",
                    exploitable=False,
                    raw_output='{"steps":[{"step":"request","result":{"url":"http://127.0.0.1/secret/2","status_code":200,"body":"resource body"}}]}',
                )

            def _apply_ai_mixed_judge(self, **kwargs):
                return {
                    "verification_status": "confirmed_exploitable",
                    "judge_reason": "AI inferred cross-owner access from alternate resource response",
                    "matched_outcomes": ["response_indicator_observed"],
                    "confidence": "high",
                    "confirmed": True,
                }

        agent = _AiAgent()
        result = try_deterministic_verification(
            agent,
            {"type": "IDOR", "file": "vault/app.py", "line": 233, "exploit_spec": exploit_spec},
            {"project_path": "demo-app"},
            logger,
        )

        self.assertTrue(result.exploitable)
        self.assertEqual(result.verification_decision["verification_status"], "confirmed_exploitable")
        self.assertTrue(result.verification_decision["ai_used"])


if __name__ == "__main__":
    unittest.main()
