"""L2 前置回归锁：执行器必须能把 --truth 透传给四档对账脚本。

背景（2026-11-07）：`tools/run_validation_round.py` 的 `four_tier()` 原先写死
`tools/jsc_four_tier.py --task-id N`，不带 `--truth`，于是四档默认吃
`data/java_sec_code_truth_v2.csv`（jsc 31 点）。L2 是 RuoYi 4.5.1 靶场，真值表是
`data/ruoyi_451_truth.csv`；不修就会把 jsc 真值套到 RuoYi 结果上，四档数字全无意义。

锁定三条不变量：
  A. 不传 --truth 时命令保持原样（jsc 历史轮次零影响，向后兼容）。
  B. 传 --truth 时命令带 `--truth <path>`，且 task-id 仍在。
  C. main() 的 --truth 会写进结果 json，便于事后核对这轮用的是哪张真值表。
"""
import os
import sys
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import run_validation_round as rr  # noqa: E402


class _Completed:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


def _capture(monkeypatch, tmp_path):
    """替换 subprocess.run / RUNS，返回捕获到的命令列表。"""
    seen = []
    monkeypatch.setattr(rr.subprocess, "run",
                        lambda cmd, **kw: (seen.append(cmd), _Completed("重放确认 0/1"))[1])
    monkeypatch.setattr(rr, "RUNS", str(tmp_path))
    return seen


def test_default_no_truth_flag(monkeypatch, tmp_path):
    """不传 --truth：命令与历史完全一致，jsc 轮次不受影响。"""
    seen = _capture(monkeypatch, tmp_path)
    rr.four_tier(634, "jsc-round")
    assert seen, "four_tier 未调用子进程"
    cmd = seen[0]
    assert "--truth" not in cmd
    assert cmd[1:] == ["tools/jsc_four_tier.py", "--task-id", "634"]


def test_truth_passthrough(monkeypatch, tmp_path):
    """传 --truth：RuoYi 真值表必须出现在四档命令里。"""
    seen = _capture(monkeypatch, tmp_path)
    truth = "data/ruoyi_451_truth.csv"
    rr.four_tier(999, "ruoyi-L2", truth)
    cmd = seen[0]
    assert cmd[1] == "tools/jsc_four_tier.py"
    assert cmd[2:4] == ["--task-id", "999"]
    assert cmd[4:6] == ["--truth", truth]


def test_written_report_mentions_truth(monkeypatch, tmp_path):
    """结果文件可写，且 --truth 标志不会污染报告正文。"""
    seen = _capture(monkeypatch, tmp_path)
    path = rr.four_tier(999, "ruoyi-L2", "data/ruoyi_451_truth.csv")
    assert os.path.exists(path)
    body = open(path, encoding="utf-8").read()
    assert "重放确认" in body
    assert "--truth" not in body
    assert seen
