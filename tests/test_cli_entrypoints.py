import subprocess
import sys
import unittest
from pathlib import Path


class CliEntrypointTests(unittest.TestCase):
    def test_offline_benchmark_cli_is_disabled(self):
        """离线 CLI 直跑入口必须被禁用，并给出统一任务编排路径的指引。

        直接 `python -m src.cli.benchmark_cli` 不带 task_id 会导致 trigger_specs
        永不登记、D1 无靶、I1/D2 全 no-arrival（ws=4 当初 0 条登记的根因），
        故入口应拒绝执行并以非零退出码 + 明确报错收尾，而非静默产出缺数据报告。
        """
        proc = subprocess.run(
            [sys.executable, "-m", "src.cli.benchmark_cli"],
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("禁用", proc.stderr)
        self.assertIn("统一任务编排", proc.stderr)
        self.assertIn("task_id", proc.stderr)


if __name__ == "__main__":
    unittest.main()
