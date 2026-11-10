"""闭环 A2 重跑结果必须合并回全量后再进 D2（2026-09-18，§4.1 闭环降级修复）。

事故背景：闭环为省 LLM 只重跑「失败 finding 所在文件」，但 run_d2_verify 的候选全集
由传入的 a2_results 构造（``for result in a1_results + a2_results``）。把收窄结果直接
传进去，D2 就只重验那几个文件，与闭环前的全量计数不可比——实测 run 17
baseline 65 → 闭环后 43，gain -22，且**降级后的 43 被写进最终报告**。

收窄只是「少跑 LLM」的优化，绝不能缩小 D2 的验证范围。本测试锁死这一口径。
"""
import unittest

from src.cli.benchmark_cli import _merge_a2_results


class _R:
    """最小 ScanResult 替身：只需要 .file 与一个可比对的版本标记。"""

    def __init__(self, file: str, tag: str):
        self.file = file
        self.tag = tag


class TestClosedLoopA2Merge(unittest.TestCase):
    def test_rerun_replaces_only_its_own_files(self):
        base = [_R("a.java", "old"), _R("b.java", "old"), _R("c.java", "old")]
        rerun = [_R("b.java", "new")]
        out = _merge_a2_results(base, rerun)
        self.assertEqual([(r.file, r.tag) for r in out],
                         [("a.java", "old"), ("b.java", "new"), ("c.java", "old")])

    def test_full_set_is_preserved_not_narrowed(self):
        """合并结果的文件数不得小于全量基数——这是「D2 验证范围被缩小」的直接防线。"""
        base = [_R("a.java", "old"), _R("b.java", "old"), _R("c.java", "old")]
        rerun = [_R("b.java", "new")]
        out = _merge_a2_results(base, rerun)
        self.assertEqual(len(out), len(base))
        self.assertEqual({r.file for r in out}, {r.file for r in base})

    def test_new_file_from_rerun_is_appended(self):
        base = [_R("a.java", "old")]
        out = _merge_a2_results(base, [_R("d.java", "new")])
        self.assertEqual([r.file for r in out], ["a.java", "d.java"])

    def test_empty_rerun_falls_back_to_base(self):
        base = [_R("a.java", "old"), _R("b.java", "old")]
        out = _merge_a2_results(base, [])
        self.assertEqual([r.file for r in out], ["a.java", "b.java"])

    def test_order_is_stable(self):
        """报告顺序必须稳定：以全量集合的文件顺序为骨架。"""
        base = [_R("x.java", "old"), _R("y.java", "old"), _R("z.java", "old")]
        rerun = [_R("z.java", "new"), _R("x.java", "new")]
        out = _merge_a2_results(base, rerun)
        self.assertEqual([r.file for r in out], ["x.java", "y.java", "z.java"])


if __name__ == "__main__":
    unittest.main()
