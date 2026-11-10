import os
import time
import unittest

from src.agents.a2_contract_planner import A2ContractPlanner
from src.core.models import ScanResult, Vulnerability


def _make_vuln(i):
    v = Vulnerability(
        type="injection",
        severity="high",
        file="X.java",
        line=i,
        entry_point="/api/x",
        callers="a->b",
        code_snippet='String x = req.getParameter("q");',
        proof_tier="broad_static",
        has_call_chain=True,
        supporting_node_count=1,
        is_canonical=True,
    )
    v.exploit_spec = {}
    v.chain_proof = {}
    v.proof_gaps = []
    v.chain_id = ""
    v.a1_evidence = {}
    return v


def _make_result(n):
    return ScanResult(file="X.java", vulnerabilities=[_make_vuln(i) for i in range(n)])


_POC_JSON = (
    '{"entry":{"route":"/api/x","method":"POST","parameter_name":"q"},'
    '"payload":{"payload_family":"command-execution","candidate_payloads":["a"]},'
    '"success_signal":{"signal_type":"response_body"},'
    '"poc_chain":[{"stage":"source","node":"src","role":"source"}]}'
)


class _SlowLLM:
    def __init__(self, latency=0.3):
        self.latency = latency

    def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
        time.sleep(self.latency)
        return _POC_JSON


class _FlakyLLM:
    """First call raises a 429, subsequent calls succeed (simulates transient rate-limit)."""

    def __init__(self):
        self.n = 0

    def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
        self.n += 1
        if self.n == 1:
            raise RuntimeError("API error: 429 - rate limit")
        return (
            '{"entry":{"route":"/ok","method":"GET","parameter_name":"p"},'
            '"payload":{"payload_family":"xss"},"success_signal":{"signal_type":"body"}}'
        )


class A2PlanPocsConcurrencyTests(unittest.TestCase):
    def setUp(self):
        # force a deterministic concurrency level for the speedup test
        self._prev = os.environ.get("SASTAI_A2_PLANNER_WORKERS")
        os.environ["SASTAI_A2_PLANNER_WORKERS"] = "6"

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("SASTAI_A2_PLANNER_WORKERS", None)
        else:
            os.environ["SASTAI_A2_PLANNER_WORKERS"] = self._prev

    def test_concurrent_is_faster_than_serial(self):
        results = [_make_result(12), _make_result(8)]
        planner = A2ContractPlanner(llm_client=_SlowLLM(latency=0.3))

        t0 = time.time()
        out = planner.plan_scan_results(results)
        conc_t = time.time() - t0

        total = sum(len(r.vulnerabilities) for r in out)
        self.assertEqual(total, 20)
        # every vuln must end up with a planned exploit spec
        for r in out:
            for v in r.vulnerabilities:
                self.assertTrue(v.exploit_spec.get("entry", {}).get("route"))

        # serial baseline
        os.environ["SASTAI_A2_PLANNER_WORKERS"] = "1"
        planner2 = A2ContractPlanner(llm_client=_SlowLLM(latency=0.3))
        t0 = time.time()
        planner2.plan_scan_results(results)
        serial_t = time.time() - t0

        # concurrency must yield a meaningful speedup (>=2x) for 20 vulns @ 0.3s
        self.assertGreater(serial_t, conc_t)
        self.assertGreaterEqual(serial_t / max(conc_t, 0.001), 2.0)

    def test_transient_429_retry_recovers(self):
        planner = A2ContractPlanner(llm_client=_FlakyLLM())
        out = planner.plan_scan_results([_make_result(1)])
        v = out[0].vulnerabilities[0]
        # the first 429 must be retried and the POC recovered
        self.assertEqual(v.exploit_spec.get("entry", {}).get("route"), "/ok")
        self.assertEqual(v.exploit_spec.get("payload", {}).get("payload_family"), "xss")

    def test_single_vuln_failure_does_not_kill_batch(self):
        class _BoomLLM:
            def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
                raise RuntimeError("boom")

        planner = A2ContractPlanner(llm_client=_BoomLLM())
        # must not raise; vulns fall back to rule-based planning
        out = planner.plan_scan_results([_make_result(3)])
        self.assertEqual(len(out[0].vulnerabilities), 3)


if __name__ == "__main__":
    unittest.main()
