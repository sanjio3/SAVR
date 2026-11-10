"""B（空 payload 告警）与 D（多步重放步骤提取）的单元测试。"""

import json
import logging
import unittest

from src.application.d1_service import D1Service
from src.iast.trigger_spec_registry import _build_attack_context_with_warning


class TestBEmptyPayloadWarning(unittest.TestCase):
    def _assert_warned(self, family, exploit_spec, expect_warning):
        # 捕获日志记录，验证空 payload 是否按族告警（而非静默）。
        recorded = {}
        class _H(logging.Handler):
            def emit(self, rec):
                recorded.setdefault(rec.levelname, []).append(rec.getMessage())
        logger = logging.getLogger("src.iast.trigger_spec_registry")
        h = _H()
        logger.addHandler(h)
        try:
            ctx = _build_attack_context_with_warning(
                {"exploit_spec": exploit_spec}, {}, family, "deadbeef"
            )
        finally:
            logger.removeHandler(h)
        warned = any("无真实 attack_payload" in m for m in recorded.get("WARNING", []))
        self.assertEqual(warned, expect_warning, msg=f"family={family} recorded={recorded}")
        return ctx

    def test_deserialization_info_not_warning(self):
        # 反序列化族：D1 由 SCA/gadget 补弹，属预期降级（info），不应 WARNING。
        self._assert_warned(
            "deserialization",
            {"payload": {"payload_family": "deserialization", "candidate_payloads": ["base64(serialized_object)"]}},
            expect_warning=False,
        )

    def test_idor_info_not_warning(self):
        # IDOR 走差分重放，不依赖 attack_payloads，不应 WARNING。
        self._assert_warned(
            "idor",
            {"payload": {"payload_family": "idor", "candidate_payloads": ["alternate_owner_resource_id"]}},
            expect_warning=False,
        )

    def test_plain_family_with_empty_payload_warns(self):
        # 普通族（如 command-execution）A2 没造出真 payload → 明确 WARNING。
        self._assert_warned(
            "command-execution",
            {"payload": {"payload_family": "command-execution", "candidate_payloads": [""]}},
            expect_warning=True,
        )

    def test_real_payload_no_warning(self):
        self._assert_warned(
            "command-execution",
            {"payload": {"payload_family": "command-execution", "candidate_payloads": ["; id"]}},
            expect_warning=False,
        )


class TestDMultiStepExtraction(unittest.TestCase):
    def test_trigger_route_extracted(self):
        svc = D1Service()
        spec = {
            "raw_json": json.dumps({
                "exploit_spec": {
                    "entry": {"route": "/debug/import", "trigger_route": "/api/quote/random"},
                    "prerequisites": {"ordered_steps": []},
                }
            })
        }
        steps = svc._extract_followup_steps(spec)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["method"], "GET")
        self.assertEqual(steps[0]["route"], "/api/quote/random")

    def test_ordered_steps_extracted_without_duplicate_main(self):
        svc = D1Service()
        spec = {
            "raw_json": json.dumps({
                "exploit_spec": {
                    "entry": {"route": "/api/order"},
                    "prerequisites": {
                        "ordered_steps": [
                            "POST /api/order submit order",
                            "GET /api/order/trigger invoke deferred",
                        ]
                    },
                }
            })
        }
        steps = svc._extract_followup_steps(spec)
        # 主步骤 /api/order 应被去重，只剩触发步。
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["route"], "/api/order/trigger")

    def test_no_steps_returns_empty(self):
        svc = D1Service()
        spec = {"raw_json": json.dumps({"exploit_spec": {"entry": {}, "prerequisites": {}}})}
        self.assertEqual(svc._extract_followup_steps(spec), [])


if __name__ == "__main__":
    unittest.main()
