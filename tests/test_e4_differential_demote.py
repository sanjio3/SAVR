# -*- coding: utf-8 -*-
"""E4 差分降级权回归锁（2026-10-11，r74 实证后方向反转）。

背景（r74 实测证据）：
  - 282(sqli-1) 的 62 条 `differential_no_impact` 里，**26 条是值级 hit_live 且真值 100% TP**；
    283(ab-mix) 的 40 条里有 9 条同类。合计 35 条真漏洞被「控制/实验 HTTP 响应无差异」
    这条 P1 证据否掉 —— 这是 r250 同型误杀的变体（当年 172 次降级杀掉 33 个真 TP）。
  - 根因是 `_differential_override` 把「已有 L3 证据」当成**解锁**差分降级的钥匙，方向反了：
    值级命中（L3，证明力 4）一出现反而解锁了响应差分（P1）去做阴性，违反证明力序。

反转后的契约（本文件锁定）：
  1. L3 为**正向**（hit_live / sink 异常签名 / OOB / 时延 / 反序列化链路 / 业务差分）
     ⇒ 差分不得做阴性，`_differential_override` 返回 None；
  2. L3 明确为**阴性**（hit_sanitized 且无异常签名）⇒ 差分保留降级权；
  3. **无 L3**（无值级命中、无异常）⇒ fail-open 不降级（绝不零化仅到达 TP，防 r250 复发）；
  4. 未尝试对照 / 对照已判有害 / 开关关闭 ⇒ 一律不降级；
  5. 端到端：到达态 + hit_live 必须走 `runtime_arrival` 准入，不得被差分否成 unconfirmed。
"""
import pytest

import src.agents.d2_facade  # noqa: F401  通道注册前置（memory 铁律）
from src.cli.benchmark_cli import _confirm_gate_decide, _differential_override


def _dast(differential=None, value_level_hit=False, value_hit_form="", **kw):
    d = {"differential": differential, "value_level_hit": value_level_hit,
         "value_hit_form": value_hit_form}
    d.update(kw)
    return d


_NO_HARM = {"attempted": True, "harmful": False}


# ── 1. L3 正向 ⇒ 否决降级 ────────────────────────────────────────────────────

def test_hit_live_blocks_demote():
    """值级 hit_live 是 definitive 正向，差分不得据此做阴性（r74 26 条真 TP 的救回点）。"""
    assert _differential_override(
        _dast(_NO_HARM, True, "hit_live"), {}, False, False) is None


def test_hit_live_without_form_still_blocks():
    """form 缺失时按保守 fail-open 处理：宁可不降级，也不零化可能的 TP。"""
    assert _differential_override(
        _dast(_NO_HARM, True, ""), {}, False, False) is None


def test_sink_exception_blocks_demote():
    """sink 异常签名（注入被解释器处理）是正向证据，否决降级。"""
    assert _differential_override(
        _dast(_NO_HARM, False, ""), {"sink_exception_class": "java.sql.SQLException"},
        False, False) is None


def test_oob_blocks_demote():
    assert _differential_override(_dast(_NO_HARM, True, "hit_live"), {}, True, False) is None


def test_time_blind_blocks_demote():
    assert _differential_override(
        _dast(_NO_HARM, False, "", time_blind_confirmed=True), {}, False, False) is None


def test_deser_chain_blocks_demote():
    assert _differential_override(
        _dast(_NO_HARM, False, ""), {"deserialization_chain_confirmed": True},
        False, False) is None


def test_business_logic_blocks_demote():
    assert _differential_override(_dast(_NO_HARM, False, ""), {}, False, True) is None


# ── 2. L3 明确阴性 ⇒ 保留降级权 ──────────────────────────────────────────────

def test_hit_sanitized_allows_demote():
    """值级命中但实参上录得消毒器 ⇒ definitive 阴性，差分可以降级。"""
    r = _differential_override(_dast(_NO_HARM, True, "hit_sanitized"), {}, False, False)
    assert r is not None and r[0] == "differential_no_impact"


def test_hit_sanitized_with_exception_blocks_demote():
    """命中虽被消毒，但同时有 sink 异常签名 ⇒ 仍属正向，不得降级。"""
    assert _differential_override(
        _dast(_NO_HARM, True, "hit_sanitized"),
        {"sink_exception_class": "java.sql.SQLException"}, False, False) is None


# ── 3. 无 L3 ⇒ fail-open 不降级（防 r250 复发）────────────────────────────────

def test_no_l3_fail_open():
    """没有值级命中也没有异常签名 ⇒ 绝不零化仅到达 TP（r250 事故的正面对照）。"""
    assert _differential_override(_dast(_NO_HARM, False, ""), {}, False, False) is None


def test_no_differential_never_demotes():
    assert _differential_override(_dast(None, True, "hit_sanitized"), {}, False, False) is None


def test_differential_not_attempted_never_demotes():
    assert _differential_override(
        _dast({"attempted": False, "harmful": False}, True, "hit_sanitized"),
        {}, False, False) is None


def test_differential_harmful_never_demotes():
    """对照已确认有害 ⇒ 交给 arrival/impact 路径确认，本函数不否决。"""
    assert _differential_override(
        _dast({"attempted": True, "harmful": True}, True, "hit_sanitized"),
        {}, False, False) is None


def test_switch_off_disables_demote(monkeypatch):
    monkeypatch.setenv("SAST_AI_DIFF_DEMOTE", "0")
    assert _differential_override(
        _dast(_NO_HARM, True, "hit_sanitized"), {}, False, False) is None


# ── 4. 端到端：到达态 + hit_live 必须准入 ────────────────────────────────────

def test_gate_admits_arrival_with_hit_live():
    """回归 r74 主断点：到达态配 hit_live 被差分否掉 ⇒ 282 的 26 条真 TP 全灭。"""
    ok, code, _why = _confirm_gate_decide(
        "sink-reached-probe",
        {"matched_event_ids": [1], "value_hit": {"hit": True, "form": "hit_live"}},
        _dast(_NO_HARM, True, "hit_live"),
        {},
    )
    assert ok is True
    assert code == "runtime_arrival"


def test_gate_still_rejects_arrival_without_semantics():
    """没有任何语义证据的纯到达依旧不得确认（B6 收紧不被本次放宽破坏）。"""
    ok, code, _why = _confirm_gate_decide(
        "sink-reached-probe",
        {"matched_event_ids": [1]},
        _dast(_NO_HARM, False, ""),
        {},
    )
    assert ok is False
    assert code == "arrival_without_semantics"


def test_gate_demotes_sanitized_arrival():
    """到达 + 值级已消毒 ⇒ 差分降级生效，落 unconfirmed（definitive 阴性）。"""
    ok, code, _why = _confirm_gate_decide(
        "sink-reached-probe",
        {"matched_event_ids": [1], "value_hit": {"hit": True, "form": "hit_sanitized"}},
        _dast(_NO_HARM, True, "hit_sanitized"),
        {},
    )
    assert ok is False
    assert code == "differential_no_impact"
