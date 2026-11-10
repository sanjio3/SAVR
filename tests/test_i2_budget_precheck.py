"""D10 预算预检（a2_rerun_budget_ok）单元测试。

背景：预算闸只能在闭环轮次间打断，拦不住单轮内文件级 A2 重跑（473 实测
2237.8s / gain=0）。执行前用「文件数×单文件耗时」对照剩余预算，超了就跳过
a2_rerun 只做重放侧调整。本测试锁死判定边界，避免回归成"预检形同虚设"。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.i2_feedback import a2_rerun_budget_ok  # noqa: E402


class TestA2RerunBudgetOk:
    def test_within_budget_passes(self):
        ok, why = a2_rerun_budget_ok(8, 300.0, 25.0)  # 200s ≤ 300s
        assert ok is True
        assert "≤" in why

    def test_exceeds_budget_blocks(self):
        ok, why = a2_rerun_budget_ok(30, 300.0, 25.0)  # 750s > 300s
        assert ok is False
        assert "750" in why and "30" in why

    def test_exact_boundary_blocks(self):
        # 估计恰好等于剩余 ⇒ > 判定为 False ⇒ 放行（等于不超）
        ok, _ = a2_rerun_budget_ok(12, 300.0, 25.0)
        assert ok is True
        # 超过 1s 即拦
        ok, _ = a2_rerun_budget_ok(13, 300.0, 25.0)  # 325 > 300
        assert ok is False

    def test_exhausted_budget_blocks(self):
        ok, why = a2_rerun_budget_ok(1, 0.0, 25.0)
        assert ok is False
        assert "用尽" in why
        ok, _ = a2_rerun_budget_ok(1, -5.0, 25.0)
        assert ok is False

    def test_zero_files_passes(self):
        ok, _ = a2_rerun_budget_ok(0, 300.0, 25.0)
        assert ok is True

    def test_invalid_inputs_block(self):
        # 非法文件数按 0 处理仍放行（保守放行空重跑），非法预算参数直接拦
        ok, _ = a2_rerun_budget_ok(None, 300.0, 25.0)
        assert ok is True
        ok, _ = a2_rerun_budget_ok(5, "abc", 25.0)
        assert ok is False

    def test_473_scenario_blocked(self):
        # 473 复盘：51 条 hypothesis_defect ⇒ 数十文件 × 25s ≫ 300s 预算 ⇒ 必须拦
        ok, why = a2_rerun_budget_ok(40, 300.0, 25.0)  # 1000s > 300s
        assert ok is False
        assert "1000" in why
