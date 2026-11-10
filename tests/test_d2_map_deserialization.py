import unittest
from pathlib import Path

from src.agents.d2_map_deserialization import D2MapDeserializationMixin


class _DummyTools:
    def __init__(self):
        self.calls = []
        self.runtime_updates = []

    def execute(self, tool, **kwargs):
        self.calls.append((tool, kwargs))
        if tool == "docker_run":
            return {"success": False, "error": "docker daemon unavailable"}
        return {"success": False, "error": "unexpected tool"}

    def set_runtime_context(self, **kwargs):
        self.runtime_updates.append(kwargs)


class _MapHarness(D2MapDeserializationMixin):
    def __init__(self):
        self.tools = _DummyTools()

    def _ensure_strategy_semantics(self, strategy):
        return dict(strategy)

    def _derive_project_specific_semantics(self, project_path, strategy):
        return {}

    def _get_prepared_runtime(self, strategy):
        return None

    def _get_available_host_port(self, preferred=8888):
        return preferred

    def _build_semantic_context_from_strategy(self, strategy):
        return {"family": strategy.get("exploit_family", "")}

    def _infer_business_semantics(self, *args, **kwargs):
        return {"business_goal": "test"}

    def _check_local_docker(self):
        return {"images": [], "running_containers": []}


class D2MapDeserializationTests(unittest.TestCase):
    def test_detect_returns_none_when_chain_incomplete(self):
        harness = _MapHarness()
        result = harness._detect_map_deserialization_strategy(Path("tests"))
        self.assertIsNone(result)

    def test_verify_returns_structured_failure_when_docker_run_fails(self):
        harness = _MapHarness()
        result = harness._verify_map_deserialization_chain(
            Path("demo"),
            {
                "exploit_family": "java_map_deserialization",
                "image": "java-quote-ctf:latest",
            },
        )

        self.assertFalse(result.exploitable)
        self.assertEqual(result.poc_type, "java-map-payload")
        self.assertEqual(result.confidence, "low")
        self.assertIn("docker daemon unavailable", result.evidence[0])


if __name__ == "__main__":
    unittest.main()
