import unittest

from src.agents.d2_planning import D2PlanningMixin


class _DummyLlm:
    def chat(self, prompt, system_prompt=None):
        return "not-json"


class _PlanningHarness(D2PlanningMixin):
    SYSTEM_PROMPT = "test"

    def __init__(self):
        self.llm = _DummyLlm()

    def _extract_json(self, text):
        raise ValueError("bad json")


class D2PlanningTests(unittest.TestCase):
    def test_conclude_falls_back_to_step_errors(self):
        harness = _PlanningHarness()
        result = harness._conclude(
            {"trigger_condition": "x"},
            {
                "steps_executed": 2,
                "results": [
                    {"tool": "docker_run", "result": {"success": False, "error": "daemon unavailable"}},
                    {"tool": "http_request", "result": {"success": False, "error": "connection refused"}},
                ],
            },
        )

        self.assertFalse(result["exploitable"])
        self.assertEqual(result["confidence"], "low")
        self.assertIn("docker_run", result["reason"])
        self.assertTrue(result["evidence"])

    def test_conclude_falls_back_when_nothing_executed(self):
        harness = _PlanningHarness()
        result = harness._conclude(
            {"trigger_condition": "x"},
            {"steps_executed": 0, "results": []},
        )
        self.assertFalse(result["exploitable"])
        self.assertIn("did not execute", result["reason"])


if __name__ == "__main__":
    unittest.main()
