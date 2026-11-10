"""D1 统一重放指标聚合回归测试（#D1-skip 修复）。

历史根因：`benchmark_cli` 的 D1 聚合曾用 ``iast_evidence.get("replayed")`` 计数，
但 `aggregate_iast_evidence` 的返回（IastVerdict.to_dict）根本没有 `replayed` 字段，
导致 `_d1_replayed` 永远为 0、D1 永远被标 `skipped`（"0 条 TriggerSpec 重放"）。

修复后口径见 `_aggregate_d1_replay`：
- replayed 来自 verification 的 `trigger_spec_provided`（verify() 是否被 trigger_spec 驱动）；
- arrivals 来自 `iast_evidence.state == 'sink-reached'`；
- impacts 来自 `dast_impact_evidence.reached`。
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.cli.benchmark_cli import _aggregate_d1_replay


def _v(provided, ie_state=None, de_reached=None):
    return {
        "trigger_spec_provided": provided,
        "iast_evidence": {"state": ie_state} if ie_state else {},
        "dast_impact_evidence": {"reached": de_reached} if de_reached is not None else {},
    }


class AggregateD1ReplayTests(unittest.TestCase):
    def test_no_verifications_is_skipped_zero(self):
        r = _aggregate_d1_replay([])
        self.assertEqual(r["status"], "skipped")
        self.assertEqual(r["candidate_count"], 0)
        # 2026-09-17（待请示 §4.6-2.2）：message 改为「驱动重放 N 条 TriggerSpec」，
        # 并新增 replayed_count 字段（此前缺失，前端读到 0）。
        self.assertEqual(r["replayed_count"], 0)
        self.assertIn("驱动重放 0 条 TriggerSpec", r["message"])

    def test_trigger_spec_provided_flips_to_completed(self):
        # 即使用户之前的 bug：iast_evidence 不带 replayed，只要 trigger_spec 被提供就应当算重放
        r = _aggregate_d1_replay([_v(provided=True)])
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["candidate_count"], 1)
        self.assertEqual(r["replayed_count"], 1)
        self.assertIn("驱动重放 1 条 TriggerSpec", r["message"])

    def test_mixed_counts(self):
        r = _aggregate_d1_replay([
            _v(provided=True, ie_state="sink-reached", de_reached=True),
            _v(provided=True, ie_state="no-arrival", de_reached=False),
            _v(provided=False, ie_state="sink-reached", de_reached=True),  # no_evidence，不计 replayed
        ])
        self.assertEqual(r["status"], "completed")
        self.assertEqual(r["candidate_count"], 2)   # 2 个 trigger_spec_provided
        self.assertEqual(r["iast_arrivals"], 2)     # 2 个 sink-reached
        self.assertEqual(r["finding_count"], 2)      # 2 个 dast reached

    def test_old_bug_would_have_skipped(self):
        # 复现旧逻辑（_ie.get("replayed")）确认它确实会误判 skipped
        verifications = [_v(provided=True, ie_state="sink-reached")]
        old_replayed = sum(
            1 for v in verifications
            if (v.get("iast_evidence") or {}).get("replayed")
        )
        self.assertEqual(old_replayed, 0, "旧口径 replayed 永远为 0 —— 这正是 D1 被误标 skipped 的原因")
        # 新口径应当正确识别
        self.assertEqual(_aggregate_d1_replay(verifications)["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
