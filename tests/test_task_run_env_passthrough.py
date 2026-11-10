"""REST 提交的任务级环境开关不能丢（2026-11-06 实测回归锁）。

根因：`ScanTaskCreate` 没声明 `run_env`，Pydantic 默认 extra=ignore 静默丢键；
`task_service.create_task()` 的 options 字典也没这一项。结果 REST 提交的 629 / 630
落库 `options_json.run_env` 都是 null，D1 请求 dump 不落盘、ysoserial / Shiro key
等按次能力开关整轮失效，而 628 走本地直提（直接写库）所以带着五项，两轮并非同配置。
`scan_task_runner._apply_task_run_env()` 这一侧本来是正确的，只是拿不到数据。
"""
from __future__ import annotations

import inspect
import json
import os

from src.api.schemas import ScanTaskCreate
from src.application.task_service import TaskService
from src.cli import scan_task_runner as runner


_FIVE = {
    "SAST_AI_DESER_YSOSERIAL": "1",
    "SAST_AI_SHIRO_KEY": "kPH+bIxk5D2deZiIxcaaaA==",
    "YSO_JAVA_HOME": "C:/jdk8",
    "SAST_AI_D1_DUMP_REQ": "1",
    "SAST_AI_D1_DUMP_PATH": "logs/d1_req_dump_R0.jsonl",
}


def test_schema_keeps_run_env_in_model_dump():
    payload = ScanTaskCreate(workspace_id=4, name="R0", run_env=_FIVE).model_dump()
    assert payload["run_env"] == _FIVE, "run_env 被 Pydantic 静默丢弃"


def test_schema_defaults_to_empty_run_env():
    payload = ScanTaskCreate(workspace_id=4, name="R0").model_dump()
    assert payload["run_env"] == {}


def test_task_service_persists_run_env_in_options():
    src = inspect.getsource(TaskService.create_task)
    assert '"run_env"' in src, "options 里必须落 run_env，否则 runner 读不到"
    assert "payload.get(\"run_env\")" in src


def test_runner_injects_run_env_into_process(monkeypatch, capsys):
    """端到端后半段：options_json.run_env 必须真的注入 runner 进程环境。"""

    class _FakeDB:
        def __init__(self, *args, **kwargs):
            pass

        def execute(self, sql, params=(), fetchone=False, **kwargs):
            if fetchone:
                return {"options_json": json.dumps({"run_env": _FIVE})}
            return None

    monkeypatch.setattr(runner, "Database", _FakeDB)
    for key in _FIVE:
        monkeypatch.delenv(key, raising=False)
    runner._apply_task_run_env(630)
    for key, val in _FIVE.items():
        assert os.environ.get(key) == val, key
    out = capsys.readouterr().err
    assert "[run_env] 已应用任务级环境开关" in out
    for key in _FIVE:
        monkeypatch.delenv(key, raising=False)


def test_runner_tolerates_missing_run_env(monkeypatch):
    """历史任务（629/630）没有 run_env 时应静默跳过，不能抛错阻断扫描。"""

    class _FakeDB:
        def __init__(self, *args, **kwargs):
            pass

        def execute(self, sql, params=(), fetchone=False, **kwargs):
            return {"options_json": "{}"} if fetchone else None

    monkeypatch.setattr(runner, "Database", _FakeDB)
    runner._apply_task_run_env(629)
