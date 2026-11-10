import json
import unittest

from src.agents.d2_judge import extract_execution_evidence, judge_verification
from src.core.exploit_spec import empty_exploit_spec


class D2JudgeTests(unittest.TestCase):
    def test_confirms_file_side_effect_for_deserialization_chain(self):
        spec = empty_exploit_spec()
        spec["entry"]["route"] = "/debug/import"
        spec["entry"]["method"] = "POST"
        spec["entry"]["trigger_route"] = "/api/quote/random"
        spec["payload"]["payload_family"] = "deserialization"
        spec["success_signal"]["signal_type"] = "state_change_or_side_effect"
        spec["expected_outcomes"]["primary_outcome"] = "proof_file_created"
        spec["validation_contract"]["confirmed_by"] = ["proof_file_created"]
        raw_output = json.dumps(
            {
                "steps": [
                    {"step": "post_payload", "result": {"url": "http://127.0.0.1/debug/import", "status_code": 200, "body": "imported"}},
                    {"step": "trigger_processing_1", "result": {"url": "http://127.0.0.1/api/quote/random", "status_code": 200, "body": "ok"}},
                    {"step": "verify_file_1", "result": {"stdout": "__A3_FILE_PRESENT__\n-rw-r--r-- /tmp/a3_verified_poc"}},
                ]
            }
        )

        evidence = extract_execution_evidence(raw_output, spec)
        decision = judge_verification(exploit_spec=spec, execution_evidence=evidence)

        self.assertIn("proof_file_created", evidence["side_effects_observed"])
        self.assertEqual(decision["verification_status"], "confirmed_exploitable")
        self.assertTrue(decision["confirmed"])

    def test_confirms_response_indicator_for_response_based_contract(self):
        spec = empty_exploit_spec()
        spec["entry"]["route"] = "/search"
        spec["entry"]["method"] = "GET"
        spec["payload"]["payload_family"] = "path-traversal"
        spec["success_signal"]["signal_type"] = "response_body"
        spec["success_signal"]["expected_indicators"] = ["root:"]
        spec["expected_outcomes"]["primary_outcome"] = "response_indicator_observed"
        spec["validation_contract"]["confirmed_by"] = ["response_indicator_observed"]
        raw_output = json.dumps(
            {
                "attack_result": {"url": "http://127.0.0.1/search?file=../../etc/passwd", "body": "root:x:0:0:root:/root:/bin/bash"}
            }
        )

        evidence = extract_execution_evidence(raw_output, spec)
        decision = judge_verification(exploit_spec=spec, execution_evidence=evidence)

        self.assertIn("response_indicator_observed", evidence["side_effects_observed"])
        self.assertEqual(decision["verification_status"], "confirmed_exploitable")

    def test_confirms_uploaded_webshell_acceptance_for_file_upload_contract(self):
        spec = empty_exploit_spec()
        spec["entry"]["route"] = "/upload"
        spec["entry"]["method"] = "POST"
        spec["payload"]["payload_family"] = "file-upload"
        spec["success_signal"]["signal_type"] = "response_or_side_effect"
        spec["expected_outcomes"]["primary_outcome"] = "uploaded_webshell_accepted"
        spec["validation_contract"]["confirmed_by"] = ["uploaded_webshell_accepted", "response_indicator_observed"]
        raw_output = json.dumps(
            {
                "attack_result": {"url": "http://127.0.0.1/upload", "status_code": 200, "body": "upload ok"}
            }
        )

        evidence = extract_execution_evidence(raw_output, spec)
        decision = judge_verification(exploit_spec=spec, execution_evidence=evidence)

        self.assertIn("uploaded_webshell_accepted", evidence["side_effects_observed"])
        self.assertEqual(decision["verification_status"], "confirmed_exploitable")

    def test_marks_template_verification_only_as_confirmed_sink_control(self):
        spec = empty_exploit_spec()
        spec["entry"]["route"] = "/check"
        spec["entry"]["method"] = "GET"
        spec["payload"]["payload_family"] = "template-injection"
        spec["payload"]["high_impact_ladder"] = [
            {
                "step": 1,
                "goal": "command_execution",
                "payloads": ["#{T(java.lang.Runtime).getRuntime().exec('id')}"],
                "expected_indicators": ["uid="],
            },
            {
                "step": 2,
                "goal": "verification_only",
                "payloads": ["#{7*7}"],
                "expected_indicators": ["49"],
            },
        ]
        spec["success_signal"]["signal_type"] = "response_body"
        spec["success_signal"]["expected_indicators"] = ["java.version", "49"]
        spec["expected_outcomes"]["primary_outcome"] = "high_impact_indicator_observed"
        spec["expected_outcomes"]["primary_exploit_outcomes"] = ["high_impact_indicator_observed"]
        spec["expected_outcomes"]["verification_only_outcomes"] = ["response_indicator_observed", "verification_indicator_observed"]
        spec["validation_contract"]["confirmed_by"] = ["high_impact_indicator_observed"]
        spec["validation_contract"]["partial_by"] = ["response_indicator_observed", "verification_indicator_observed"]
        raw_output = json.dumps(
            {
                "success_mode": "verification",
                "attempts": [
                    {"mode": "high_impact", "goal": "command_execution", "payload": "#{T(java.lang.Runtime).getRuntime().exec('id')}", "expected": "uid=", "status_code": 200},
                    {"mode": "verification", "goal": "verification_only", "payload": "#{7*7}", "expected": "49", "status_code": 200},
                ],
                "attack_result": {"url": "http://127.0.0.1/check?rule=%23%7B7*7%7D", "body": "Result: 49"},
            }
        )

        evidence = extract_execution_evidence(raw_output, spec)
        decision = judge_verification(exploit_spec=spec, execution_evidence=evidence)

        self.assertIn("verification_indicator_observed", evidence["side_effects_observed"])
        self.assertIn("true", evidence["verification_fallback_used"])
        self.assertEqual(decision["verification_status"], "confirmed_sink_control")
        self.assertFalse(decision["confirmed"])


if __name__ == "__main__":
    unittest.main()
