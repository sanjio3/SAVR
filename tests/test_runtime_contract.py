import unittest
from unittest.mock import Mock

from src.agents import A1Agent, A2Agent, D2Agent
from src.agents.d2_bundle import D2BundleMixin
from src.agents.d2_executor import D2ExecutionMixin
from src.agents.d2_java_strategies import D2JavaStrategiesMixin
from src.agents.d2_map_deserialization import D2MapDeserializationMixin
from src.agents.d2_facade import create_d2_agent
from src.agents.d2_node_strategies import D2NodeStrategiesMixin
from src.agents.d2_php_strategies import D2PhpStrategiesMixin
from src.agents.d2_planning import D2PlanningMixin
from src.agents.d2_python_strategies import D2PythonStrategiesMixin
from src.agents.d2_result_normalizer import D2ResultNormalizerMixin
from src.agents.d2_semantics import D2SemanticsMixin
from src.agents.d2_types import VerificationResult
from src.agents.runtime_contract import ExternalTarget, normalize_external_target
from src.iast.orchestrator import DastImpact


class RuntimeContractTests(unittest.TestCase):
    def test_normalize_external_target_produces_canonical_fields(self):
        target = normalize_external_target({
            "service_url": "http://127.0.0.1:11000",
            "app_name": "mall",
            "agent_id": "probe-x",
            "auth_context": {"token": "abc"},
        })
        self.assertEqual(target.service_url, "http://127.0.0.1:11000")
        self.assertEqual(target.app_name, "mall")
        self.assertEqual(target.agent_id, "probe-x")
        self.assertEqual(target.probe_mode, "monitor")
        self.assertTrue(target.is_registered)

    def test_external_target_is_registered_requires_all_fields(self):
        partial = ExternalTarget(service_url="http://x", app_name="", agent_id="")
        self.assertFalse(partial.is_registered)
        full = ExternalTarget(service_url="http://x", app_name="a", agent_id="b")
        self.assertTrue(full.is_registered)

    def test_unified_facade_verify_requires_trigger_spec(self):
        # 统一链路（重构文档 3.5+）：verify 不再有 legacy 回落。缺失 trigger_spec 时不静默跳过，
        # 而是显式返回 no_evidence —— 因为没有重放靶，就无法驱动 D1 → I1 → D2 → I2 验证。
        agent = create_d2_agent({})
        result = agent.verify(
            {"type": "SQL Injection", "file": "demo.py", "line": 1},
            {"project_path": "demo"},
            external_target={"service_url": "http://127.0.0.1:11000", "app_name": "mall", "agent_id": "probe-x"},
        )
        self.assertEqual(result.final_state, "no_evidence")
        self.assertFalse(result.exploitable)
        self.assertIn("trigger_spec", result.reason)

    def test_unified_facade_verify_runs_pipeline_with_injected_deps(self):
        # 统一链路唯一路径：D1 重放(DastImpact) → I1 轮询(假 iast_service.poll_events_by_canary)
        # → D2 结果点核实 → I2 五态裁决。注入假依赖 + 注入编排窗口参数，让测试不真实等待。
        from src.agents.d2_facade import _verify_sink_result
        from src.iast.orchestrator import WindowConfig

        calls = {"replay": 0}

        class FakeIast:
            def poll_events_by_canary(self, canary, since_id, limit, **kwargs):
                # 返回一条 sink-reached 事件
                return [{
                    "id": 1,
                    "canary_state": "sink-reached",
                    "canary": canary,
                    "stack_trace": "at java.util.Base64$Decoder.decode",
                    "sink_method": "readObject",
                    "sink_file": "CacheProcessor.java",
                    "sink_line": 42,
                    "source_value": "demo",
                    "taint_path_json": '[{"role": "source", "origin": "DebugController.java"}, {"role": "sink", "origin": "CacheProcessor.java"}]',
                }]

        class FakeDast:
            def replay(self, spec, target):
                calls["replay"] += 1
                return DastImpact(reached=True, status_code=200, body="import ok")

        # 通过 mock 注入编排窗口参数：默认 W=5s 太慢，这里把时钟推进到超过 t_max。
        # 直接构造 D2Agent，替换其内部 orchestrator 的窗口太繁琐；改为验证编排结果的关键路径：
        # 1) D1 重放被调用  2) 有 trigger_spec 时不会返回 no_evidence
        agent = create_d2_agent({})
        result = agent.verify(
            {"type": "Java Deserialization", "file": "CacheProcessor.java", "line": 42},
            {"project_path": "demo"},
            external_target={"service_url": "http://127.0.0.1:18080", "app_name": "mall", "agent_id": "probe-x"},
            trigger_spec={
                "vulnerability_hash_v2": "h1",
                "target_endpoint": "/debug/import",
                "http_method": "POST",
                "parameter_name": "data",
                "parameter_location": "form",
                "taint_marker": "s4st41abcdef",
            },
            iast_service=FakeIast(),
            dast_operator=FakeDast(),
        )
        self.assertEqual(calls["replay"], 1)
        self.assertNotEqual(result.final_state, "no_evidence")

    def test_public_agent_exports_use_unified_facades(self):
        self.assertEqual(A1Agent.__name__, "A1Agent")
        self.assertEqual(A2Agent.__name__, "A2Agent")
        self.assertEqual(D2Agent.__name__, "D2Agent")

    def test_verification_result_type_is_shared(self):
        result = VerificationResult(reason="ok", poc_type="demo")
        self.assertEqual(result.reason, "ok")
        self.assertEqual(result.poc_type, "demo")

    def test_bundle_helper_handles_missing_result_file(self):
        self.assertEqual(D2BundleMixin._load_exploit_result_file(__import__("pathlib").Path("missing-result.json")), {})


if __name__ == "__main__":
    unittest.main()
