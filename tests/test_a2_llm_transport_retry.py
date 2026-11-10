"""A2 原生 Ollama 传输层健壮性回归锁（2026-11-07 L1b 根因；2026-11-08 修订）。

历史缺陷：IntegratedAnalyst 硬编码 180s socket 读超时 + stream:False 非流式
+ 无重试，超时后 benchmark_cli 用 `except Exception: specs = []` 把整个文件
的 finding 静默丢掉，四档只表现为「掉点」，无法归因。

修订（本轮实测）：真根因是 grammar 约束下模型不产 EOS、而 options
没有 num_predict 上限 ⇒ 生成无限延伸 ⇒ socket 读超时。重发同一 prompt 不会更快，
实测 6 次重试全部再次超时。因此生成超时改为「不重试、直接判耗尽」，只有连接层
异常才重试；同时给生成长度加硬上限。

本组测试锁定：
  1. 生成长度上限进入请求体，且不改 temperature / seed / num_ctx / format；
  2. 连接层异常有限重试且成功后清零熔断计数；
  3. 生成超时不重试、计 exhausted；重试耗尽/熔断仍生效；
  4. 业务错误（HTTPError）不重试、不污染统计；
  5. 超时阈值 env 可配、截断可观测、文件级失败不再静默吞掉。
"""
from __future__ import annotations

import json
import socket
import urllib.error

import pytest

from src.agents import a2_integrated_analyst as A
from src.cli import benchmark_cli as B


class _Resp:
    """最小 urlopen 响应：实现 context manager + read()。"""

    def __init__(self, content: str = "[]"):
        payload = {
            "message": {"content": content},
            "prompt_eval_count": 10,
            "eval_count": 5,
            "prompt_eval_duration": 1000,
            "eval_duration": 2000,
        }
        self._buf = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._buf


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    A.reset_transport_stats()
    B.reset_a2_analysis_errors()
    monkeypatch.setattr(A.time, "sleep", lambda *_: None)
    # 埋点写库要连 data/app.db，测试里不关心，直接短路
    monkeypatch.setattr(A, "_get_model_run_repo", lambda: _NoopRepo())
    monkeypatch.delenv("SAST_AI_A2_LLM_TIMEOUT", raising=False)
    monkeypatch.delenv("SAST_AI_A2_LLM_RETRIES", raising=False)
    monkeypatch.delenv("SAST_AI_A2_LLM_CIRCUIT_BREAK", raising=False)
    monkeypatch.delenv("SAST_AI_A2_LLM_NUM_PREDICT", raising=False)
    monkeypatch.delenv("SAST_AI_LLM_STATS_FILE", raising=False)
    yield
    A.reset_transport_stats()
    B.reset_a2_analysis_errors()


class _NoopRepo:
    def record(self, **kwargs):
        return None


def _call(monkeypatch, outcomes):
    """按顺序给出 urlopen 结果（异常对象或 _Resp），返回 (调用次数, timeout 实参列表)。"""
    seq = list(outcomes)
    seen = {"n": 0, "timeouts": [], "bodies": []}

    def _fake(req, timeout=None):
        seen["n"] += 1
        seen["timeouts"].append(timeout)
        seen["bodies"].append(req.data)
        item = seq.pop(0) if seq else _Resp()
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(A.urllib.request, "urlopen", _fake)
    return seen


# ── 1. 生成长度上限───────────────────────────────────────────────
def test_num_predict_caps_generation_without_changing_decode_contract(monkeypatch):
    seen = _call(monkeypatch, [_Resp("[]")])
    A.ollama_chat([{"role": "user", "content": "x"}])
    body = json.loads(seen["bodies"][0].decode("utf-8"))
    opts = body["options"]
    assert opts["num_predict"] == 1024
    # 判定口径零漂移：解码参数与输出契约一个都不动
    assert opts["temperature"] == 0
    assert opts["seed"] == 42
    assert opts["num_ctx"] == 8192
    assert body["stream"] is False
    assert body["format"] == "json"


def test_num_predict_env_configurable(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_LLM_NUM_PREDICT", "512")
    assert A.llm_num_predict_default() == 512
    seen = _call(monkeypatch, [_Resp("[]")])
    A.ollama_chat([{"role": "user", "content": "x"}])
    body = json.loads(seen["bodies"][0].decode("utf-8"))
    assert body["options"]["num_predict"] == 512


def test_truncated_output_is_counted(monkeypatch):
    class _TruncResp(_Resp):
        def read(self):
            payload = {"message": {"content": "[{"}, "done_reason": "length",
                       "eval_count": 1024, "prompt_eval_count": 10,
                       "prompt_eval_duration": 1000, "eval_duration": 2000}
            return json.dumps(payload).encode("utf-8")

    _call(monkeypatch, [_TruncResp()])
    A.ollama_chat([{"role": "user", "content": "x"}])
    assert A.transport_stats()["truncated"] == 1


# ── 2. 连接层重试成功 ────────────────────────────────────────────────────
def test_transient_connection_error_retries_then_succeeds(monkeypatch):
    seen = _call(monkeypatch, [ConnectionResetError("connection reset"),
                               ConnectionResetError("connection reset"),
                               _Resp('[{"verdict":"false_positive"}]')])
    out = A.ollama_chat([{"role": "user", "content": "x"}])
    assert out.startswith("[{")
    assert seen["n"] == 3
    st = A.transport_stats()
    assert st["retries"] == 2
    assert st["timeouts"] == 2
    assert st["recovered"] == 1
    assert st["exhausted"] == 0
    assert st["consecutive_exhausted"] == 0


def test_connection_reset_is_retryable(monkeypatch):
    seen = _call(monkeypatch, [ConnectionResetError("connection reset"), _Resp("[]")])
    A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 2
    assert A.transport_stats()["recovered"] == 1


# ── 3. 生成超时不重试─────────────────────────────────────────────
def test_generation_timeout_not_retried(monkeypatch):
    seen = _call(monkeypatch, [socket.timeout("timed out")] * 3)
    with pytest.raises((socket.timeout, TimeoutError)):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1, "生成超时不得重发同一 prompt"
    st = A.transport_stats()
    assert st["retries"] == 0
    assert st["generation_timeouts"] == 1
    assert st["exhausted"] == 1
    assert st["consecutive_exhausted"] == 1


def test_urlerror_wrapping_timeout_not_retried(monkeypatch):
    seen = _call(monkeypatch, [urllib.error.URLError(socket.timeout("timed out"))])
    with pytest.raises(urllib.error.URLError):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1
    assert A.transport_stats()["generation_timeouts"] == 1


def test_benchmark_cli_does_not_retry_generation_timeout(monkeypatch):
    calls = {"n": 0}

    def _boom():
        calls["n"] += 1
        raise socket.timeout("timed out")

    monkeypatch.setattr(B.time, "sleep", lambda *_: None)
    with pytest.raises((socket.timeout, TimeoutError)):
        B._a2_analyze_with_retry(_boom, "X.java")
    assert calls["n"] == 1


# ── 4. 连接层重试耗尽与熔断 ──────────────────────────────────────────────
def test_retries_exhausted_raises_and_counts(monkeypatch):
    seen = _call(monkeypatch, [ConnectionResetError("connection reset")] * 10)
    with pytest.raises(ConnectionResetError):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 3  # 首次 + 2 次重试
    st = A.transport_stats()
    assert st["retries"] == 2
    assert st["exhausted"] == 1
    assert st["consecutive_exhausted"] == 1


def test_circuit_break_fails_fast(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_LLM_RETRIES", "0")
    monkeypatch.setenv("SAST_AI_A2_LLM_CIRCUIT_BREAK", "1")
    seen = _call(monkeypatch, [socket.timeout("timed out")] * 10)
    with pytest.raises((socket.timeout, TimeoutError)):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1
    with pytest.raises(A.A2LLMUnavailable):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1, "熔断后不应再发请求"
    st = A.transport_stats()
    assert st["circuit_broken"] == 1
    assert st["exhausted"] == 1


def test_success_clears_consecutive_failures(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_LLM_RETRIES", "0")
    monkeypatch.setenv("SAST_AI_A2_LLM_CIRCUIT_BREAK", "2")
    _call(monkeypatch, [ConnectionResetError("connection reset"), _Resp("[]"),
                        ConnectionResetError("connection reset"), _Resp("[]")])
    with pytest.raises(ConnectionResetError):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert A.transport_stats()["consecutive_exhausted"] == 1
    A.ollama_chat([{"role": "user", "content": "x"}])
    assert A.transport_stats()["consecutive_exhausted"] == 0


# ── 5. 业务错误不重试 ────────────────────────────────────────────────────
def test_http_error_not_retried(monkeypatch):
    err = urllib.error.HTTPError(A.OLLAMA, 400, "bad request", {}, None)
    seen = _call(monkeypatch, [err])
    with pytest.raises(urllib.error.HTTPError):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1
    st = A.transport_stats()
    assert st["retries"] == 0
    assert st["timeouts"] == 0
    assert st["exhausted"] == 0


def test_json_decode_error_not_retried(monkeypatch):
    class _BadResp(_Resp):
        def read(self):
            return b"not-json"

    seen = _call(monkeypatch, [_BadResp()])
    with pytest.raises(ValueError):
        A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["n"] == 1


# ── 6. 阈值可配 ──────────────────────────────────────────────────────────
def test_timeout_env_configurable(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_LLM_TIMEOUT", "420")
    assert A.llm_timeout_default() == 420.0
    assert A.IntegratedAnalyst()._timeout == 420.0
    seen = _call(monkeypatch, [_Resp("[]")])
    A.ollama_chat([{"role": "user", "content": "x"}])
    assert seen["timeouts"] == [420.0]


def test_explicit_timeout_wins(monkeypatch):
    assert A.IntegratedAnalyst(timeout=12.5)._timeout == 12.5
    seen = _call(monkeypatch, [_Resp("[]")])
    A.ollama_chat([{"role": "user", "content": "x"}], timeout=12.5)
    assert seen["timeouts"] == [12.5]


def test_transport_stats_exposed_via_contract_stats():
    st = A.contract_stats()
    assert "transport" in st
    assert set(st["transport"]) == set(A.transport_stats())


# ── 7. 文件级失败不静默 ──────────────────────────────────────────────────
_FILES = [{"rel_path": "src/main/java/X.java", "content": "class X {}"}]


def test_file_level_timeout_recorded_not_silently_dropped(monkeypatch):
    class _Boom:
        def __init__(self, *a, **k):
            pass

        def analyze(self, *a, **k):
            raise socket.timeout("timed out")

    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _Boom)
    monkeypatch.setattr(B.time, "sleep", lambda *_: None)
    results, _ = B.run_a2_integrated_scan(_FILES, [])
    assert len(results) == 1
    assert results[0].vulnerabilities == [], "失败文件不得凭空产出漏洞"
    st = B.a2_analysis_error_stats()
    assert st["failed_files"] == 1
    assert "X.java" in st["files"][0]


def test_analysis_error_placeholder_is_not_false_positive():
    ph = B._a2_failure_placeholder([{"line": 7}], RuntimeError("boom"))
    assert len(ph) == 1
    assert ph[0]["verdict"] == "analysis_error"
    assert ph[0]["analysis_error"] is True
    assert ph[0]["spec"] is None
    assert ph[0]["line"] == 7


def test_circuit_break_aborts_whole_round(monkeypatch):
    class _Broken:
        def __init__(self, *a, **k):
            pass

        def analyze(self, *a, **k):
            raise A.A2LLMUnavailable("circuit broken")

    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _Broken)
    with pytest.raises(A.A2LLMUnavailable):
        B.run_a2_integrated_scan(_FILES, [])
