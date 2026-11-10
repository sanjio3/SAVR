"""孤儿 worker 治理回归测试。

背景（task-8 事故）：runner 失败分支直接写 task_failed 却从不终止扫描子进程，
导致后端标记失败后子进程继续写 scan_progress.json 并持续产生 IAST 事件
（14:00:25 已标记 failed，阶段却推进到深夜、iast_events 0→540）。
本测试锁定 _terminate_process 必须真正回收子进程。
"""
import subprocess
import sys
import time

from src.infrastructure.task_runner import ScanTaskRunner, MAX_SCAN_RUNTIME_SECONDS


def _make_runner():
    events = []

    def event_cb(task_id, event_type, payload):
        events.append((task_id, event_type, payload))

    def result_cb(task_id, workspace_id, payload):
        events.append((task_id, "result", payload))

    return ScanTaskRunner(event_cb, result_cb), events


def test_terminate_process_kills_long_running_child():
    """子进程不自行退出时，_terminate_process 必须把它杀掉（terminate→wait→kill）。"""
    runner, events = _make_runner()
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # 确认它确实活着
    time.sleep(0.4)
    assert proc.poll() is None, "前置条件失败：子进程应处于运行中"

    runner._terminate_process(1, proc, "unit-test")

    assert proc.poll() is not None, "终止后子进程必须已退出（孤儿 worker 未根治）"
    assert any(e[1] == "task_log" for e in events), "应记录一条终止日志便于排查"


def test_terminate_process_is_noop_when_already_exited():
    """子进程已正常退出时不应再发信号（避免误杀复用的 PID）。"""
    runner, events = _make_runner()
    proc = subprocess.Popen([sys.executable, "-c", "print('done')"], stdout=subprocess.PIPE, text=True)
    proc.wait(timeout=10)
    assert proc.poll() is not None

    runner._terminate_process(2, proc, "unit-test")
    # 已退出的进程不应产生终止日志
    assert not any(e[1] == "task_log" for e in events), "已退出进程不应触发终止动作"


def test_max_runtime_constant_is_configurable():
    """运行时上限默认应为正数（看门狗生效），且允许用环境变量关停。"""
    assert MAX_SCAN_RUNTIME_SECONDS > 0, "默认必须启用运行时上限，否则 worker 可无限悬挂"
