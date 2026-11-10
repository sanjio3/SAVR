"""ScanTaskRunner 取消能力的回归锁（2026-10-04 落地）。

背景：任务一旦被提交进 ThreadPoolExecutor 的 work_queue，就与 DB 里的 scan_tasks 行脱钩。
REST DELETE / TaskRepository.delete 只删库行，线程池照样在轮到时把任务拉起 ⇒ 出现
「库里任务已消失、磁盘上却还在建 CodeQL 库」的僵尸扫描。2026-10-04 实测：删掉
历史轮次 后它们仍被依次拉起空跑（其中一个跑了 30 分钟、97MB），真正要跑的 本轮
被饿在队尾 20 小时以上。

修复：ScanTaskRunner 登记 future 与子进程，cancel() 同时覆盖「排队中」和「运行中」两种形态，
并在 task_service.delete_task / clear_workspace_tasks 里先取消再删库行。

两条锁：
    1. 排队中的任务被 cancel 后永不起子进程（future.cancel 生效）；
    2. 运行中的任务被 cancel 后子进程必须被 terminate/kill 回收。
"""
from __future__ import annotations

import threading
import time as _real_time
from types import SimpleNamespace

import pytest

from src.infrastructure import task_runner as tr

_real_sleep = _real_time.sleep


class _FakeProcess:
    """只实现 _run_task 用到的 Popen 面：poll / terminate / kill / wait / stdout。"""

    def __init__(self):
        self._alive = True
        self.returncode = None
        self.terminated = False
        self.killed = False
        self.stdout = None

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self.terminated = True
        self._alive = False

    def kill(self):
        self.killed = True
        self._alive = False

    def wait(self, timeout=None):
        return 0


def _task(tid: int, tmp_path, **opts):
    options = {"output_format": "json", "approval_mode": "off",
               "tool_allowlist": [], "act_allowlist": [],
               "enable_a1": True, "enable_a2": True, "enable_verification": True,
               "enable_sca": True, "enable_ai_review": True, "enable_entry_discovery": True,
               "enable_idor": False, "scan_mode": "filter_first", "model_profile": "default",
               "prompt_version": "terminal-first-v1", "sca_tool": "auto",
               "sca_severity_threshold": "LOW"}
    options.update(opts)
    return SimpleNamespace(id=tid, workspace_id=1, name=f"t{tid}", options=options,
                           output_dir=str(tmp_path / f"task-{tid}"))


def _workspace():
    return SimpleNamespace(id=1, name="ws", target_path=".", settings={})


@pytest.fixture
def runner(monkeypatch, tmp_path):
    procs = []
    gate = threading.Event()

    def fake_popen(cmd, **kwargs):
        p = _FakeProcess()
        procs.append(p)
        return p

    monkeypatch.setattr(tr.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(tr, "MAX_SCAN_RUNTIME_SECONDS", 0)
    # 把 _run_task 的 1s 轮询缩到 10ms，让测试快；注意不能直接换成 no-op，
    # 那会让 while 循环空转吃满 CPU，进程会被沙箱按超时杀掉。
    monkeypatch.setattr(tr.time, "sleep", lambda *_a, **_k: _real_sleep(0.01))
    r = tr.ScanTaskRunner(lambda *a, **k: None, lambda *a, **k: None, max_workers=1)
    r._fake_procs = procs
    r._gate = gate
    yield r


def test_cancel_queued_task_never_starts(runner, tmp_path):
    """排队中的任务被取消后，线程池轮到它时不得再拉起子进程。"""
    t1 = _task(1, tmp_path)
    t2 = _task(2, tmp_path)
    ws = _workspace()

    runner.submit(t1, ws)
    # 等第一个任务真正开跑（子进程已被 Popen）
    for _ in range(200):
        if runner._fake_procs:
            break
        _real_sleep(0.02)
    assert len(runner._fake_procs) == 1, "第一个任务应已启动"

    runner.submit(t2, ws)
    assert runner.cancel(2) is True
    assert runner.is_cancelled(2) is True

    # 释放第一个任务让它结束，线程池轮到 task-2
    runner._fake_procs[0].terminate()
    _real_sleep(0.5)

    assert len(runner._fake_procs) == 1, (
        "task-2 已被取消，绝不能再拉起第二个子进程（这是原缺陷：僵尸扫描）")


def test_cancel_running_task_terminates_child(runner, tmp_path):
    """运行中的任务被取消后，扫描子进程必须被终止（不是只改个状态）。"""
    t1 = _task(1, tmp_path)
    runner.submit(t1, _workspace())

    for _ in range(200):
        if runner._fake_procs:
            break
        _real_sleep(0.02)
    proc = runner._fake_procs[0]
    assert proc.poll() is None, "子进程应还在运行"

    runner.cancel(1)

    for _ in range(200):
        if proc.terminated or proc.killed:
            break
        _real_sleep(0.02)
    assert proc.terminated or proc.killed, "取消必须终止扫描子进程"
    assert runner.is_cancelled(1) is True
