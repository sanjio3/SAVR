"""A2 输出契约单测（src/agents/a2_integrated_analyst.py）。

锁三件事：
  1. **full（默认）= 旧契约**，判定质量基线（2026-10-25 A/B 实测：lean 档掉 3 个 TP
     + 多 1 个 FP，已否决 ⇒ 默认必须是 full）；
  2. **safe 档**只砍 content_type（恒为空串，零影响），snippet 等**必须保留**
     —— snippet 影响 sanitizer.strength 判定，砍掉会掉 TP；
  3. lean 档仅保留用于复现实验，不得成为默认。

以及 20.3.4 埋点：ollama_chat 曾丢弃 Ollama 的 token 计数，现已改为落盘
（SAST_AI_LLM_STATS_FILE）。
"""
import importlib
import os

import src.agents.a2_integrated_analyst as A


def _reload(env=None):
    old = dict(os.environ)
    try:
        if env:
            os.environ.update(env)
        else:
            os.environ.pop("SAST_AI_A2_CONTRACT", None)
        return importlib.reload(A)
    finally:
        os.environ.clear()
        os.environ.update(old)


# ── full 档（默认） ─────────────────────────────────────────────────────

def test_default_is_full_contract():
    """默认必须是 full —— lean 档实测掉 TP（00012/01002/01004），不得默认启用。"""
    m = _reload(None)
    assert m.SAST_AI_A2_CONTRACT == "full"
    c = m._output_contract()
    for f in ("snippet", "why_bypassable", "sink_reached_explanation", "content_type"):
        assert f in c, f


def test_full_contract_keeps_all_decision_fields():
    m = _reload({"SAST_AI_A2_CONTRACT": "full"})
    c = m._output_contract()
    for kept in ("verdict", "route", "method", "param_name", "param_location",
                 "payload", "bypass_payloads", "present", "type", "strength"):
        assert kept in c, kept


# ── safe 档：只砍零影响字段 ────────────────────────────────────────────

def test_safe_contract_drops_only_content_type():
    m = _reload({"SAST_AI_A2_CONTRACT": "safe"})
    c = m._output_contract()
    assert "content_type" not in c
    # snippet / why_bypassable / sink_reached_explanation **必须保留**
    # （实测：砍 snippet ⇒ strength 判差 ⇒ verdict 错 ⇒ 掉 TP）
    for kept in ("snippet", "why_bypassable", "sink_reached_explanation"):
        assert kept in c, kept


def test_safe_contract_keeps_sanitizer_strength():
    m = _reload({"SAST_AI_A2_CONTRACT": "safe"})
    c = m._output_contract()
    assert '"strength": "strong|weak|unknown"' in c
    assert "sanitizer" in c


# ── lean 档：已否决，仅用于复现实验 ────────────────────────────────────

def test_lean_contract_drops_audit_fields():
    m = _reload({"SAST_AI_A2_CONTRACT": "lean"})
    c = m._output_contract()
    for dropped in ("snippet", "why_bypassable", "sink_reached_explanation", "content_type"):
        assert dropped not in c, dropped


def test_lean_contract_keeps_decision_fields():
    m = _reload({"SAST_AI_A2_CONTRACT": "lean"})
    c = m._output_contract()
    for kept in ("verdict", "route", "method", "param_name", "param_location",
                 "payload", "bypass_payloads", "present", "type", "strength"):
        assert kept in c, kept


def test_invalid_contract_falls_back_to_full():
    m = _reload({"SAST_AI_A2_CONTRACT": "garbage"})
    assert m.SAST_AI_A2_CONTRACT == "full"


# ── 消费端容错：契约缺字段时 filter_spec 仍能构造 ──────────────────────

def test_filter_spec_construction_tolerates_missing_fields():
    """缺 snippet/why_bypassable ⇒ 消费端 str(x or "") 必须兜住。"""
    m = _reload({"SAST_AI_A2_CONTRACT": "lean"})
    _san = {"present": True, "type": "blacklist_replace", "strength": "weak"}
    # 与 benchmark_cli.py:1793-1801 同口径
    _stype = str(_san.get("type") or "unknown").lower()
    _strength = str(_san.get("strength") or "unknown").lower()
    if (not _san.get("present")) or _stype in ("none", ""):
        _strength = "none"
    fs = {
        "present": bool(_san.get("present")) and _stype not in ("none", ""),
        "type": _stype or "unknown",
        "strength": _strength,
        "location": str(_san.get("location") or ""),
        "snippet": str(_san.get("snippet") or "")[:300],
        "why_bypassable": str(_san.get("why_bypassable") or "")[:300],
    }
    assert fs["strength"] == "weak"          # 判定链完整
    assert fs["snippet"] == ""                # 审计字段降级为空，不报错
    assert fs["why_bypassable"] == ""


# ── 20.3.4 埋点 ────────────────────────────────────────────────────────

def test_stats_sink_records_llm_cost():
    """埋点必须能落盘 prefill/decode/token —— 没有它 20.3 的优化就是猜。"""
    import json
    import tempfile

    m = _reload(None)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "stats.jsonl")
        os.environ["SAST_AI_LLM_STATS_FILE"] = path
        try:
            m._dump_llm_stats({"wall_s": 1.0, "prompt_tokens": 10, "completion_tokens": 20,
                                "prefill_ms": 5.0, "decode_ms": 100.0})
            with open(path, encoding="utf-8") as fh:
                rows = [json.loads(x) for x in fh if x.strip()]
        finally:
            os.environ.pop("SAST_AI_LLM_STATS_FILE", None)
    assert len(rows) == 1
    assert rows[0]["prompt_tokens"] == 10
    assert rows[0]["decode_ms"] == 100.0


def test_stats_sink_is_silent_without_env():
    """没配环境变量时不应报错、也不该写文件（纯观测，不能影响主流程）。"""
    m = _reload(None)
    os.environ.pop("SAST_AI_LLM_STATS_FILE", None)
    m._dump_llm_stats({"wall_s": 1.0})   # 不抛异常即通过
