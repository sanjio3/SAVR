"""A2 原语判别器（src/agents/a2_primitives.py）+ 两段式拆分单测。

判别与生成都用假 llm_call 注入，按 system 提示词区分两条路径，不碰真实模型。
重点锁定三件事：定长契约解析、早停的保守边界（只停高置信判否）、顺序对齐不丢 finding。
"""
import json

import pytest

from src.agents import a2_primitives as P
from src.agents.a2_integrated_analyst import IntegratedAnalyst


# ───────────────────────── 定长解析 ─────────────────────────

def test_parse_primitives_happy_path():
    text = ("L=42 V=1 VP=0.87 LOC=q LP=0.92 S=w SP=0.61 K=0.78\n"
            "L=57 V=0 VP=0.95 LOC=c LP=0.80 S=s SP=0.90 K=0.10")
    got = P.parse_primitives(text)
    assert len(got) == 2
    assert got[0].vuln is True and got[0].vuln_prob == 0.87
    assert got[0].location == "query" and got[0].sanitizer == "weak"
    assert got[0].exploitability == 0.78
    assert got[1].vuln is False and got[1].location == "cookie"
    assert got[1].sanitizer == "strong"


def test_parse_primitives_skips_garbage_and_pads():
    text = ("这是一行解释文字\n"
            "L=1 V=1 VP=1 LOC=u LP=0.5 S=u SP=0.5 K=0.5\n"
            "L=2 V=9 VP=x LOC=z LP=1 S=q SP=1 K=1")   # 第二行字段越界，必须跳过
    got = P.parse_primitives(text, expect=3)
    assert len(got) == 3
    assert got[0].vuln is True
    assert got[1].source == "fallback" and got[2].source == "fallback"


def test_early_stoppable_boundary():
    # 只有 V=0 且 VP>=0.9 才允许早停；判是的、低置信的、fallback 的一律不早停
    assert P.Primitives(vuln=False, vuln_prob=0.90).early_stoppable is True
    assert P.Primitives(vuln=False, vuln_prob=0.99).early_stoppable is True
    assert P.Primitives(vuln=False, vuln_prob=0.89).early_stoppable is False
    assert P.Primitives(vuln=False, vuln_prob=0.89, source="fallback").early_stoppable is False
    assert P.Primitives(vuln=True, vuln_prob=0.99).early_stoppable is False


def test_primitives_to_dict_roundtrip():
    p = P.Primitives(line=7, vuln=True, vuln_prob=0.8, location="header",
                     location_prob=0.7, sanitizer="none", sanitizer_prob=0.6,
                     exploitability=0.9, raw="x")
    d = p.to_dict()
    assert d["vuln"] is True and d["location"] == "header"
    json.dumps(d)  # 必须可序列化（要落库/落报告）


# ───────────────────────── discriminate ─────────────────────────

def _fake_llm(mapping):
    """按 system 提示词分派：判别返回 mapping['primitive']，生成返回 mapping['generate']。"""
    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            return mapping.get("primitive", "")
        return mapping.get("generate", "[]")
    return _call


_FINDINGS = [
    {"line": 42, "family": "sql_injection", "note": "拼接 SQL"},
    {"line": 57, "family": "xss", "note": "反射输出"},
]


def test_discriminate_parses_all_lines():
    fake = _fake_llm({"primitive": (
        "L=42 V=0 VP=0.95 LOC=q LP=0.9 S=s SP=0.9 K=0.1\n"
        "L=57 V=1 VP=0.8 LOC=h LP=0.9 S=w SP=0.6 K=0.7")})
    got = P.discriminate("code", "T.java", _FINDINGS, llm_call=fake)
    assert len(got) == 2
    assert got[0].early_stoppable and not got[1].early_stoppable


def test_discriminate_repairs_missing_line():
    calls = {"n": 0}

    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            calls["n"] += 1
            if calls["n"] == 1:
                return "L=42 V=0 VP=0.95 LOC=q LP=0.9 S=s SP=0.9 K=0.1"  # 缺第二行
            return ("L=42 V=0 VP=0.95 LOC=q LP=0.9 S=s SP=0.9 K=0.1\n"
                    "L=57 V=1 VP=0.8 LOC=h LP=0.9 S=w SP=0.6 K=0.7")
        return "[]"
    got = P.discriminate("code", "T.java", _FINDINGS, llm_call=_call)
    assert len(got) == 2 and calls["n"] == 2  # 缺行触发一次补齐重试


def test_discriminate_failure_returns_fallback_not_stoppable():
    fake = _fake_llm({"primitive": "完全不合契约的输出"})
    got = P.discriminate("code", "T.java", _FINDINGS, llm_call=fake)
    assert len(got) == 2
    assert all(p.source == "fallback" for p in got)
    assert not any(p.early_stoppable for p in got)  # 失败绝不早停


def test_discriminate_exception_is_contained():
    def _boom(msgs):
        raise RuntimeError("llm down")
    got = P.discriminate("code", "T.java", _FINDINGS, llm_call=_boom)
    assert len(got) == 2 and all(p.source == "fallback" for p in got)


# ───────────────────────── 两段式拆分 ─────────────────────────

def test_analyze_two_stage_early_stops_only_high_conf_negative():
    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            return ("L=42 V=0 VP=0.95 LOC=q LP=0.9 S=s SP=0.9 K=0.1\n"
                    "L=57 V=1 VP=0.8 LOC=h LP=0.9 S=w SP=0.6 K=0.7")
        # 生成段只应看到保留的 finding（第 2 条）
        user = msgs[1]["content"]
        assert "行 57" in user
        assert "行 42" not in user, "早停的 finding 不应进入生成段"
        return json.dumps([{
            "line": 57, "verdict": "real", "reason": "反射",
            "spec": {"route": "/x", "method": "GET", "param_name": "p",
                     "param_location": "header", "payload": "<svg>",
                     "sanitizer": {"present": False}},
        }])
    an = IntegratedAnalyst(llm_call=_call)
    specs, stats = an.analyze_two_stage("code", "T.java", _FINDINGS)
    assert stats == {"total": 2, "early_stopped": 1, "generated": 1}
    # 顺序与原 findings 对齐
    assert specs[0]["line"] == 42 and specs[0]["verdict"] == "false_positive"
    assert specs[0]["spec"] is None and specs[0]["primitives"]["vuln_prob"] == 0.95
    assert specs[1]["line"] == 57 and specs[1]["verdict"] == "real"
    assert specs[1]["spec"]["payload"] == "<svg>"
    assert specs[1]["primitives"]["location"] == "header"


def test_analyze_two_stage_all_stopped_skips_generation():
    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            return ("L=42 V=0 VP=0.99 LOC=q LP=0.9 S=s SP=0.9 K=0.0\n"
                    "L=57 V=0 VP=0.98 LOC=h LP=0.9 S=s SP=0.9 K=0.0")
        raise AssertionError("全部早停时不应调用生成段")
    an = IntegratedAnalyst(llm_call=_call)
    specs, stats = an.analyze_two_stage("code", "T.java", _FINDINGS)
    assert stats["early_stopped"] == 2 and stats["generated"] == 0
    assert all(s["verdict"] == "false_positive" and s["spec"] is None for s in specs)


def test_analyze_two_stage_discriminate_failure_falls_back_to_single_stage():
    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            raise RuntimeError("llm down")
        return json.dumps([{
            "line": 42, "verdict": "real", "reason": "r",
            "spec": {"route": "/x", "method": "GET", "param_name": "p",
                     "param_location": "query", "payload": "' OR 1=1",
                     "sanitizer": {"present": False}},
        }])
    an = IntegratedAnalyst(llm_call=_call)
    specs, stats = an.analyze_two_stage("code", "T.java", [_FINDINGS[0]])
    assert stats.get("degraded") is True and stats["early_stopped"] == 0
    assert specs[0]["verdict"] == "real"  # 判别挂了就按原路径跑，不丢召回


def test_analyze_two_stage_never_emits_none():
    def _call(msgs):
        sys_text = msgs[0]["content"] if msgs else ""
        if "一审判别器" in sys_text:
            return ("L=42 V=1 VP=0.7 LOC=q LP=0.9 S=w SP=0.6 K=0.7\n"
                    "L=57 V=1 VP=0.6 LOC=h LP=0.9 S=w SP=0.6 K=0.7")
        return json.dumps([{"line": 42, "verdict": "real", "reason": "r", "spec": None}])
    an = IntegratedAnalyst(llm_call=_call)
    specs, stats = an.analyze_two_stage("code", "T.java", _FINDINGS)
    assert len(specs) == 2
    assert all(isinstance(s, dict) for s in specs)  # 生成段缺条也不能漏 None 给下游
