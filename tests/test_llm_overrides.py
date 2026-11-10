"""任务级 LLM 扫描强度覆盖（前端设置 → 单任务生效）单测。

覆盖三件事：
1. 覆盖只作用在**本进程内**（写 config 单例与环境变量），不外溢到全局配置文件；
2. 越界值被钳回安全边界（ctx 上限 20480 是本机 8GB 卡实测硬边界）；
3. 未知键 / 非法值被忽略且不抛错，绝不静默改变用户没要求改的东西。
"""

import os

import pytest

from src.core import config as config_module
from src.cli.benchmark_cli import _apply_llm_overrides
from src.cli.scan_task_runner import _parse_llm_overrides
from src.api.schemas import ScanTaskCreate


@pytest.fixture(autouse=True)
def _clean_env():
    keys = ["SAST_AI_LLM_CTX_OVERRIDE", "SAST_AI_LLM_GATE_CONCURRENCY", "SAST_AI_LLM_STREAM"]
    saved = {k: os.environ.get(k) for k in keys}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_empty_overrides_is_noop():
    assert _apply_llm_overrides(None) == {}
    assert _apply_llm_overrides({}) == {}


def test_context_window_applied_and_clamped():
    applied = _apply_llm_overrides({"context_window": 16384})
    assert applied["context_window"] == 16384
    assert config_module.get("ollama.num_ctx") == 16384
    # 裁剪预算必须跟随请求 ctx，否则会溢出并被 Ollama 静默丢提示词头部
    assert os.environ["SAST_AI_LLM_CTX_OVERRIDE"] == "16384"

    applied_hi = _apply_llm_overrides({"context_window": 32768})
    assert applied_hi["context_window"] == 20480
    applied_lo = _apply_llm_overrides({"context_window": 16})
    assert applied_lo["context_window"] == 2048


def test_think_and_temperature_applied():
    applied = _apply_llm_overrides({"think": True, "temperature": 0.7})
    assert applied["think"] is True
    assert config_module.get("ollama.think") is True
    assert config_module.get("ollama.temperature") == 0.7


def test_concurrency_and_stream_go_to_env():
    """并发闸门与流式开关是进程级读环境变量的，config 改不到。"""
    applied = _apply_llm_overrides({"concurrency": 4, "stream": True})
    assert applied["concurrency"] == 4
    assert os.environ["SAST_AI_LLM_GATE_CONCURRENCY"] == "4"
    assert os.environ["SAST_AI_LLM_STREAM"] == "1"

    _apply_llm_overrides({"stream": False})
    assert os.environ["SAST_AI_LLM_STREAM"] == "0"


def test_concurrency_clamped():
    assert _apply_llm_overrides({"concurrency": 999})["concurrency"] == 16
    assert _apply_llm_overrides({"concurrency": 0})["concurrency"] == 1


def test_second_pass_toggle():
    assert _apply_llm_overrides({"proof_second_pass": False})["proof_second_pass"] is False
    assert config_module.get("agents.a2.proof_second_pass.enabled") is False
    assert _apply_llm_overrides({"proof_second_pass": True})["proof_second_pass"] is True


def test_unknown_key_ignored():
    applied = _apply_llm_overrides({"not_a_real_key": 1, "context_window": 8192})
    assert "not_a_real_key" not in applied
    assert applied["context_window"] == 8192


def test_invalid_value_skipped_not_raised():
    applied = _apply_llm_overrides({"context_window": "not-a-number"})
    assert applied == {}


def test_parse_llm_overrides_robust():
    assert _parse_llm_overrides("") is None
    assert _parse_llm_overrides("not json") is None
    assert _parse_llm_overrides("[1,2]") is None
    assert _parse_llm_overrides('{"context_window":4096}') == {"context_window": 4096}


def test_task_schema_accepts_llm_overrides():
    payload = ScanTaskCreate(
        workspace_id=1,
        name="t",
        llm_overrides={"context_window": 8192, "think": False, "concurrency": 3},
    )
    assert payload.llm_overrides["concurrency"] == 3
    assert ScanTaskCreate(workspace_id=1, name="t").llm_overrides == {}
