"""回归守卫：D2 裁决全路径必须把探针显式断言态 sink-reached-probe 认作 sink_reached。

历史事故：D2Judge.judge 与 _verify_sink_result 曾用硬编码 `state == "sink-reached"`，
漏掉占多数的 sink-reached-probe 态，导致 D2 的 sink_reached_count 恒 0（task-5 实测 30 条
sink 事件里 26 条是 probe 态）。本测试锁死「单一真相源 is_sink_reached」在 D2 入口被采用。
"""
import types

from src.iast.adjudicator import D2Judge
from src.iast.orchestrator import STATE_SINK_REACHED_PROBE
from src.agents.d2_facade import _verify_sink_result


def _fake_verdict(state: str):
    return types.SimpleNamespace(state=state)


def test_d2_judge_counts_probe_state_as_sink_reached():
    # per_hypothesis 用最小桩对象（D2Judge 只取 getattr(v, "state")）
    per_h = {"h1": _fake_verdict(STATE_SINK_REACHED_PROBE)}
    # reached 通过 raw_dast_impact 透传（slices 缺失时回退 raw）
    raw = {"reached": True}
    verdicts = D2Judge().judge(per_h, raw)
    assert len(verdicts) == 1
    assert verdicts[0].sink_reached is True, "sink-reached-probe 必须被认作 sink_reached"
    assert verdicts[0].harmful is True, "probe 态 + reached 应判有害"


def test_d2_judge_no_arrival_not_sink_reached():
    per_h = {"h1": _fake_verdict("no-arrival")}
    verdicts = D2Judge().judge(per_h, {"reached": True})
    assert verdicts[0].sink_reached is False


def test_verify_sink_result_probe_state_true():
    out = _verify_sink_result(
        {"state": STATE_SINK_REACHED_PROBE},
        {"reached": True, "status_code": 200, "body": "ok"},
    )
    assert out["sink_reached"] is True
    assert out["harmful"] is True


def test_verify_sink_result_non_sink_false():
    out = _verify_sink_result({"state": "no-arrival"}, {"reached": True})
    assert out["sink_reached"] is False
