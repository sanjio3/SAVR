import unittest

from src.core.d2_zero_audit import audit_d2_zero_finding, summarize_d2_zero_audit


class D2ZeroAuditTests(unittest.TestCase):
    def test_classifies_sink_control_only(self):
        vuln = {
            "proof_tier": "chain_proven",
            "contract_completeness": {"status": "ready"},
            "verification_decision": {
                "verification_status": "confirmed_sink_control",
                "matched_outcomes": ["verification_indicator_observed"],
            },
            "execution_evidence": {
                "requests_made": ["GET /check"],
                "side_effects_observed": ["verification_indicator_observed"],
            },
            "a21_selected": True,
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "JUDGE_ONLY_SINK_CONTROL")

    def test_classifies_proof_failure(self):
        vuln = {
            "proof_tier": "broad_static",
            "proof_gaps": ["attacker_control_proven", "payload_shape_proven"],
            "a21_selected": False,
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "A2_PROOF_FAILURE")

    def test_splits_not_scheduled_from_reporting_mismatch(self):
        """2026-09-22：契约已就绪但**一条执行痕迹都没有** ⇒ D2_NOT_SCHEDULED。

        run 31 实测该形态 14 条。两种故障处置动作不同：「没排进队列」要查调度集合，
        「跑了但证据没落库」要查持久化，不能共用一个兜底桶。
        """
        vuln = {
            "proof_tier": "chain_proven",
            "contract_completeness": {"status": "ready"},
            "a21_selected": True,
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "D2_NOT_SCHEDULED")
        self.assertIn("no D2 execution trace", audit["summary"])

    def test_reporting_mismatch_reachable_when_decision_present(self):
        """有 verification_decision（确实跑过）但证据不成形 ⇒ 仍归 REPORTING_OR_PIPELINE_MISMATCH。"""
        vuln = {
            "proof_tier": "chain_proven",
            "contract_completeness": {"status": "ready"},
            "a21_selected": True,
            "verification_decision": {"verification_status": "some_other_status"},
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "REPORTING_OR_PIPELINE_MISMATCH")

    def test_summarize_attaches_audit_to_non_confirmed_findings(self):
        findings = [
            {
                "type": "spel注入",
                "chain_id": "template-injection:expression_chain",
                "proof_tier": "chain_proven",
                "contract_completeness": {"status": "ready"},
                "verification_decision": {"verification_status": "confirmed_sink_control"},
                "execution_evidence": {"requests_made": ["GET /check"], "side_effects_observed": ["verification_indicator_observed"]},
                "a21_selected": True,
            }
        ]
        summary = summarize_d2_zero_audit(findings)
        self.assertEqual(summary["primary_category"], "JUDGE_ONLY_SINK_CONTROL")
        self.assertIn("d2_zero_audit", findings[0])

    def test_explicit_scheduling_reason_not_scheduled(self):
        """§③ 报告层已写出显式原因时，审计直接采信，不再靠「无 decision 无 evidence」反推。"""
        vuln = {
            "proof_tier": "chain_proven",
            "contract_completeness": {"status": "ready"},
            "a21_selected": True,
            "verification_decision": {
                "verification_status": "not_scheduled",
                "scheduling_reason": "no_trigger_spec: 无重放目标",
            },
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "D2_NOT_SCHEDULED")
        self.assertIn("no_trigger_spec", audit["summary"])

    def test_explicit_scheduling_reason_result_lost(self):
        """已强制入队却无验证记录 → D2_RESULT_LOST（区别于 D2_NOT_SCHEDULED）。"""
        vuln = {
            "proof_tier": "chain_proven",
            "contract_completeness": {"status": "ready"},
            "a21_selected": True,
            "verification_decision": {
                "verification_status": "no_verification_record",
                "scheduling_reason": "enqueued_but_no_verification_record",
            },
        }
        audit = audit_d2_zero_finding(vuln)
        self.assertEqual(audit["category"], "D2_RESULT_LOST")
        self.assertIn("enqueued_but_no_verification_record", audit["summary"])


if __name__ == "__main__":
    unittest.main()
