"""S1/S2/S3 在 A2ContractPlanner 的落地验证：

- S1：plan_vulnerability 用 code_index 调用图确定性回溯拼链；
- S3：回溯命中 http_entry 后，置 proof_tier=chain_proven 并救援 entry_resolution；
- S2：确定性链作为 ground truth 注入 LLM prompt（替换零散 RAG 窗口）。
"""

import json
import unittest

from src.agents.a2_contract_planner import A2ContractPlanner
from src.core.models import Vulnerability


def _code_index():
    return {
        "functions": {
            "app/UserController.java:getAddress": {
                "name": "getAddress", "file": "app/UserController.java", "line": 10,
                "callers": [],
                "http_entry": "GET /api/address/{id}",
            },
            "app/UserService.java:loadAddress": {
                "name": "loadAddress", "file": "app/UserService.java", "line": 30,
                "callers": ["app/UserController.java:getAddress"], "http_entry": "",
            },
            "app/AddressRepo.java:find": {
                "name": "find", "file": "app/AddressRepo.java", "line": 50,
                "callers": ["app/UserService.java:loadAddress"], "http_entry": "",
            },
            "app/AddressRepo.java:vulnSink": {
                "name": "vulnSink", "file": "app/AddressRepo.java", "line": 70,
                "callers": ["app/AddressRepo.java:find"], "http_entry": "",
            },
        }
    }


def _vuln():
    v = Vulnerability(
        type="SQL Injection",
        severity="HIGH",
        file="app/AddressRepo.java",
        line=70,
        description="HTTP parameter reaches SQL query",
        exploit_spec={"payload": {"payload_family": "sql-injection"}},
    )
    return v


class _FakeLLMClient:
    """记录最后一次 prompt，并返回合法 JSON，便于断言 S2 注入了确定性链。"""

    def __init__(self):
        self.last_prompt = ""

    def create_message(self, system, messages, **kwargs):
        self.last_prompt = messages[0]["content"] if messages else ""
        return json.dumps({
            "verdict": {"is_exploitable": True, "confidence": "high", "rationale": "chain proven"},
            "payload": {"payload_family": "sql-injection", "candidate_payloads": ["' OR '1'='1"]},
            "success_signal": {"signal_type": "response_body"},
            "poc_chain": [],
        })


class TestS3ProofTierAndEntryRescue(unittest.TestCase):
    def test_chain_proven_and_entry_rescued(self):
        agent = A2ContractPlanner()  # llm_client=None → 纯规则式，不调 LLM
        v = _vuln()
        out = agent.plan_vulnerability(v, code_index=_code_index())
        self.assertEqual(out.proof_tier, "chain_proven")
        self.assertTrue(out.has_call_chain)
        self.assertTrue(out.has_http_entry)
        # S3 救援：静态解析未给入口时，用确定性链回填 entry_resolution
        self.assertTrue(out.entry_resolution.get("resolvable"))
        self.assertEqual(out.entry_resolution.get("route"), "/api/address/{id}")
        self.assertEqual(out.entry_resolution.get("method"), "GET")

    def test_no_code_index_keeps_broad_static(self):
        agent = A2ContractPlanner()
        v = _vuln()
        out = agent.plan_vulnerability(v, code_index=None)
        self.assertNotEqual(out.proof_tier, "chain_proven")


class TestS2DeterministicChainInPrompt(unittest.TestCase):
    def test_prompt_contains_deterministic_chain(self):
        client = _FakeLLMClient()
        agent = A2ContractPlanner(llm_client=client)
        agent.plan_vulnerability(_vuln(), code_index=_code_index())
        self.assertIn("确定性调用链", client.last_prompt)
        self.assertIn("/api/address/{id}", client.last_prompt)
        self.assertIn("vulnSink", client.last_prompt)

    def test_no_chain_falls_back_to_rag_block_absence(self):
        # 无 code_index → 没有确定性链，prompt 不应包含「确定性调用链」字样。
        client = _FakeLLMClient()
        agent = A2ContractPlanner(llm_client=client)
        agent.plan_vulnerability(_vuln(), code_index=None)
        self.assertNotIn("确定性调用链", client.last_prompt)


if __name__ == "__main__":
    unittest.main()
