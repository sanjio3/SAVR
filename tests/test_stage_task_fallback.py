"""阶段任务清单的「运行中兜底」测试（2026-09-18，run 18 运行态实测缺口）。

D2 / I2 是耗时最长的两个阶段，但明细（verifications_detail / closed_loop.history）
都要等该阶段收尾才写。此前整段 D2 运行期间前端「阶段任务」是 0 条——
状态显示 running、任务却空着。本测试锁死兜底行为：只用阶段自身真实指标摊条目，
没有任何指标时仍然保持空（不伪造）。
"""
import unittest

from src.core.pipeline_view import attach_stage_tasks


class TestStageTaskFallback(unittest.TestCase):

    def test_d2_running_with_metrics_shows_progress_items(self):
        """D2 运行中：无 verifications_detail，但有 replay/verify 指标 → 摊成两条真实进度。"""
        pipeline = {
            "d2": {
                "status": "running",
                "message": "已重放 163/163（confirmed=62, sink_reached=53） · D2 统一验证进行中",
                "metrics": {
                    "replay_total": 163, "replay_replayed": 163,
                    "replay_confirmed": 62, "replay_sink_reached": 53,
                    "d2_verify_iteration": 0, "d2_verify_exploitable_count": 62,
                    "d2_verify_status": "done",
                },
            }
        }
        out = attach_stage_tasks(pipeline, progress={"stage_results": {"d2": {"status": "running"}}})
        items = out["d2"]["tasks"]["items"]
        names = [i["name"] for i in items]
        self.assertIn("重放池排空", names)
        self.assertIn("D2 统一验证 第 0 轮", names)
        replay = next(i for i in items if i["name"] == "重放池排空")
        self.assertIn("163/163", replay["detail"])
        self.assertIn("confirmed=62", replay["detail"])
        verify = next(i for i in items if i["name"] == "D2 统一验证 第 0 轮")
        self.assertIn("已证可利用 62 条", verify["detail"])

    def test_i2_running_waits_shows_one_item(self):
        """I2 运行中：闭环还没有 history，只显示「在等谁」，不自造轮次。"""
        pipeline = {"i2": {"status": "running", "message": "等待 d2 完成", "metrics": {}}}
        out = attach_stage_tasks(pipeline, progress={"stage_results": {}})
        items = out["i2"]["tasks"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "闭环裁决")
        self.assertEqual(items[0]["status"], "running")
        self.assertEqual(items[0]["detail"], "等待 d2 完成")

    def test_no_fabrication_without_metrics(self):
        """既无明细又无指标的阶段，兜底也必须保持空——不造条目。"""
        pipeline = {"d2": {"status": "pending", "message": "", "metrics": {}},
                    "i2": {"status": "pending", "message": "", "metrics": {}}}
        out = attach_stage_tasks(pipeline, progress={"stage_results": {}})
        self.assertEqual(out["d2"]["tasks"]["items"], [])
        self.assertEqual(out["i2"]["tasks"]["items"], [])

    def test_d1_no_candidate_shows_explicit_item(self):
        """D1 无候选是真实结论，不能显示成空卡片（run 18 实测 candidate_count=0）。"""
        pipeline = {"d1": {"status": "completed",
                           "metrics": {"app_id": "workspace-4", "finding_count": 0,
                                       "candidate_count": 0, "replayed_count": 0}}}
        out = attach_stage_tasks(pipeline, progress={"stage_results": {"d1": {"status": "completed"}}})
        items = out["d1"]["tasks"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "重放候选")
        self.assertEqual(items[0]["status"], "pending")
        self.assertIn("候选 0 条", items[0]["detail"])

    def test_real_detail_takes_precedence(self):
        """有真实明细时不得被兜底顶掉。"""
        pipeline = {"d2": {"status": "running", "message": "x",
                           "metrics": {"replay_total": 163, "replay_replayed": 163}}}
        progress = {"stage_results": {"d2": {"status": "completed", "verifications_detail": [
            {"endpoint": "GET /rce/runtime", "family": "command-execution",
             "final_state": "confirmed_exploitable", "d2_harmful": True, "d2_confidence": 0.9},
        ]}}}
        out = attach_stage_tasks(pipeline, progress=progress)
        items = out["d2"]["tasks"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "GET /rce/runtime")
        self.assertNotIn("重放池排空", [i["name"] for i in items])


if __name__ == "__main__":
    unittest.main()
