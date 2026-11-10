"""a3_judge IAST 五态裁定 + d2_execution_modes iast 形态测试（重构文档 3.5 / 3.18）。"""
from src.agents.d2_judge import (
    FINAL_AMBIGUOUS,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_FALSE_POSITIVE_SAST_ONLY,
    FINAL_NO_EVIDENCE,
    FINAL_RUNTIME_CONFIRMED,
    judge_verification,
)
from src.agents.d2_execution_modes import infer_execution_mode
from src.iast.orchestrator import STATE_ARRIVAL_SANITIZED, STATE_NO_ARRIVAL, STATE_SINK_REACHED


def _iast(state, confidence="high", provisional=True):
    return {"state": state, "matched_event_ids": [1], "confidence": confidence, "provisional": provisional}


def _dast(impact_observed=False, stable_disproof=False):
    return {"impact_observed": impact_observed, "stable_disproof": stable_disproof}


def test_iast_sink_reached_plus_dast_impact():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_SINK_REACHED), dast_impact_evidence=_dast(impact_observed=True),
    )
    assert r["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is True


def test_iast_sink_reached_no_dast_impact():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_SINK_REACHED), dast_impact_evidence=_dast(impact_observed=False),
    )
    assert r["final_state"] == FINAL_RUNTIME_CONFIRMED
    assert r["confirmed"] is True


def test_iast_no_arrival_plus_dast_impact_ambiguous():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_NO_ARRIVAL), dast_impact_evidence=_dast(impact_observed=True),
    )
    assert r["final_state"] == FINAL_AMBIGUOUS
    assert r["confirmed"] is False


def test_iast_no_arrival_no_dast_no_evidence():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_NO_ARRIVAL), dast_impact_evidence=_dast(impact_observed=False),
    )
    assert r["final_state"] == FINAL_NO_EVIDENCE


def test_iast_no_arrival_stable_disproof_false_positive():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_NO_ARRIVAL), dast_impact_evidence=_dast(impact_observed=False, stable_disproof=True),
    )
    assert r["final_state"] == FINAL_FALSE_POSITIVE_SAST_ONLY


def test_iast_arrival_sanitized_plus_dast_ambiguous():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_ARRIVAL_SANITIZED), dast_impact_evidence=_dast(impact_observed=True),
    )
    assert r["final_state"] == FINAL_AMBIGUOUS


def test_iast_arrival_sanitized_no_dast_no_evidence():
    r = judge_verification(
        exploit_spec={}, execution_evidence={},
        iast_evidence=_iast(STATE_ARRIVAL_SANITIZED), dast_impact_evidence=_dast(impact_observed=False),
    )
    assert r["final_state"] == FINAL_NO_EVIDENCE


def test_backward_compat_no_iast_evidence():
    # 非 IAST 模式：保留既有 DAST/AI 裁定并补齐新键
    r = judge_verification(exploit_spec={}, execution_evidence={})
    assert r["final_state"] == ""
    assert r["iast_evidence"] is None
    assert "dast_impact_evidence" in r


def test_execution_mode_iast_trigger_observation():
    spec = {"entry": {"route": "/x", "method": "GET"}}
    assert infer_execution_mode(spec, iast_trigger=True) == "iast_trigger_observation"


def test_execution_mode_legacy_preserved():
    spec = {"entry": {"route": "/x", "method": "GET"}}
    assert infer_execution_mode(spec, iast_trigger=False) == "single_request_reflection"
