"""阶段耗时埋点链路单测（20.3.4）。

背景：benchmark_cli 早就算好各阶段耗时并放进返回值（``phase_times``），
但**链路上有两处断点**，导致库里的 summary 查不到任何阶段耗时：
  ① scan_task_runner 构造 task_result.json 的 payload 时没带 phase_times；
  ② task_runner 发 task_completed 事件时没带 phase_times；
  ③ task_service._merge_task_summary 合并时丢掉了 phase_times。

三处都补上后，summary["phase_times"] 才有数据。本测试锁住这条链路。
"""
import json
import os
import tempfile
import unittest.mock as mock

import src.application.task_service as TS


# ── ③ service 层：合并时保留 phase_times ────────────────────────────────

def _svc():
    return TS.TaskService.__new__(TS.TaskService)


def test_merge_keeps_phase_times():
    svc = _svc()
    svc._build_initial_summary = lambda options: {"pipeline": {}}
    svc._stage = lambda name, status: {"label": name, "status": status}
    cur = {"pipeline": {}}
    payload = {"pipeline": {}, "phase_times": {"a1": 12.5, "a2": 300.0, "d2": 2000.0}}
    out = svc._merge_task_summary(cur, payload, {}, "task_completed")
    pt = out.get("phase_times") or {}
    assert pt.get("a1") == 12.5
    assert pt.get("d2") == 2000.0


def test_merge_phase_times_merges_across_events():
    """多轮事件（a1 完成时先来一次、task_completed 再来一次）应累加而不是覆盖。"""
    svc = _svc()
    svc._build_initial_summary = lambda options: {"pipeline": {}}
    svc._stage = lambda name, status: {"label": name, "status": status}
    out = svc._merge_task_summary(
        {"pipeline": {}}, {"pipeline": {}, "phase_times": {"a1": 10.0}}, {}, "task_progress")
    out = svc._merge_task_summary(
        out, {"pipeline": {}, "phase_times": {"a2": 20.0}}, {}, "task_completed")
    pt = out.get("phase_times") or {}
    assert pt.get("a1") == 10.0 and pt.get("a2") == 20.0


def test_merge_ignores_non_numeric_phase_times():
    """脏数据不能把 summary 写坏（非数值一律丢弃）。"""
    svc = _svc()
    svc._build_initial_summary = lambda options: {"pipeline": {}}
    svc._stage = lambda name, status: {"label": name, "status": status}
    out = svc._merge_task_summary(
        {"pipeline": {}}, {"pipeline": {}, "phase_times": {"a1": "x", "a2": 3.0}}, {}, "task_completed")
    pt = out.get("phase_times") or {}
    assert "a1" not in pt
    assert pt.get("a2") == 3.0


# ── ② runner 层：事件带 phase_times ─────────────────────────────────────

def test_runner_event_includes_phase_times():
    """task_completed 事件 payload 必须带 phase_times，否则 service 拿不到。"""
    import inspect
    import src.infrastructure.task_runner as TR
    src = inspect.getsource(TR)
    assert '"phase_times": payload.get("phase_times", {})' in src, \
        "task_runner 的 task_completed 事件未透传 phase_times"
    # 正常路径 + 恢复路径两处都要有
    assert src.count('"phase_times": payload.get("phase_times", {})') >= 2


# ── ① scan_task_runner 层：task_result.json payload 带 phase_times ───────

def test_task_result_payload_includes_phase_times():
    import inspect
    import src.cli.scan_task_runner as SR
    src = inspect.getsource(SR)
    assert '"phase_times": result.get("phase_times") or {}' in src, \
        "task_result.json 的 payload 未带 phase_times"


# ── 埋点产物：ollama_chat 的计数能被消费 ────────────────────────────────

def test_llm_stats_file_roundtrip():
    """A2 埋点落盘 → 能被读回来（prefill/decode/token 三个数都要在）。"""
    import src.agents.a2_integrated_analyst as A
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "llm_stats.jsonl")
        os.environ["SAST_AI_LLM_STATS_FILE"] = path
        try:
            A._dump_llm_stats({"wall_s": 1.5, "prompt_tokens": 1200, "completion_tokens": 220,
                                "prefill_ms": 550.0, "decode_ms": 7000.0})
        finally:
            os.environ.pop("SAST_AI_LLM_STATS_FILE", None)
        rows = [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]
    assert len(rows) == 1
    r = rows[0]
    assert r["prompt_tokens"] == 1200
    assert r["completion_tokens"] == 220
    assert r["prefill_ms"] == 550.0
    assert r["decode_ms"] == 7000.0
    # prefill 占比可算（20.3 的核心判据：prefill 只占 3.5~13%）
    total = r["prefill_ms"] + r["decode_ms"]
    assert 0.0 < r["prefill_ms"] / total < 0.2
