"""Q2 I2 LLM 裁决器（§8.1 AI 检测 review 制度）回归测试。

验证 Q2 架构：I1 监听器 / D2 校验器只做「单条 spec 是否符合要求」的纯判断（不论成败），
把完整结果交给 I2 裁决器；I2 综合 I1 + D2 双重证据，以「条」为颗粒度裁决
pass / rollback_to_a2，并把不符合的假说整理成回灌 A2 的 feedback_to_a2（闭环反思）。

离线（无 LLM 网关）走规则式兜底 _adjudicate_rule_based，保证闭环不中断。
"""

from src.iast.adjudicator import (
    D2Judge,
    D2Verdict,
    I1Judge,
    I2Adjudicator,
    I2Decision,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_NO_EVIDENCE,
)
from src.iast.orchestrator import IastVerdict, STATE_SINK_REACHED, STATE_NO_ARRIVAL


def _per_hypothesis(hid, state, conforms=False):
    return {hid: IastVerdict(state=state, chain_conformance={"conforms": conforms} if conforms else {})}


def test_i1_judge_is_pure_no_verdict():
    """I1 只判断链路符合性，不决定可利用性。"""
    ph = _per_hypothesis("H1", STATE_SINK_REACHED, conforms=True)
    v = I1Judge().judge(ph)[0]
    assert v.hypothesis_id == "H1"
    assert v.requirement_met is True
    assert v.chain_conforms is True


def test_d2_judge_is_pure_no_verdict():
    """D2 只判断结果点有害性，不决定可利用性。"""
    ph = _per_hypothesis("H1", STATE_SINK_REACHED)
    d2 = D2Judge().judge(ph, {"reached": True, "status_code": 200, "body": "ok"})[0]
    assert d2.requirement_met is True
    assert d2.harmful is True


def test_i2_pass_when_i1_and_d2_agree():
    """I1 链路符合 + D2 结果点有害 → pass / confirmed / 无回灌。"""
    ph = _per_hypothesis("H1", STATE_SINK_REACHED, conforms=True)
    i1 = I1Judge().judge(ph)
    d2 = D2Judge().judge(ph, {"reached": True, "status_code": 200, "body": "ok"})
    spec = [{"vulnerability_hash_v2": "H1", "family": "command-execution", "target_endpoint": "/api/x", "param_name": "q"}]
    decisions = I2Adjudicator(db=None).adjudicate(i1, d2, specs=spec)
    assert len(decisions) == 1
    d = decisions[0]
    assert isinstance(d, I2Decision)
    assert d.final_state == FINAL_CONFIRMED_ATTRIBUTABLE
    assert d.action == "pass"
    assert d.confirmed is True
    assert d.feedback_to_a2 == {}


def test_i2_rollback_when_no_arrival():
    """I1 无到达（no-evidence）→ 不符合假说 → rollback_to_a2（re_correct 归一到回灌），feedback 非空。"""
    ph = _per_hypothesis("H2", STATE_NO_ARRIVAL)
    i1 = I1Judge().judge(ph)
    d2 = D2Judge().judge(ph, {"reached": False})
    spec = [{"vulnerability_hash_v2": "H2", "family": "sql-injection", "target_endpoint": "/api/y", "param_name": "id"}]
    decisions = I2Adjudicator(db=None).adjudicate(i1, d2, specs=spec)
    assert len(decisions) == 1
    d = decisions[0]
    assert d.final_state == FINAL_NO_EVIDENCE
    # re_correct（A2 poc 链与实际不符）→ 归一到 rollback_to_a2，触发 A2 重新推导
    assert d.action == "rollback_to_a2"
    assert d.feedback_to_a2
    assert d.feedback_to_a2["hypothesis_id"] == "H2"
    assert d.feedback_to_a2["current_spec"]["family"] == "sql-injection"


def test_i2_per_spec_granularity_independent():
    """多 spec 以「条」为颗粒度独立裁决：一条 pass，一条 rollback。"""
    ph = {
        "H1": IastVerdict(state=STATE_SINK_REACHED, chain_conformance={"conforms": True}),
        "H2": IastVerdict(state=STATE_NO_ARRIVAL),
    }
    i1 = I1Judge().judge(ph)
    d2 = D2Judge().judge(ph, {
        "H1": {"reached": True, "status_code": 200, "body": "ok"},
        "H2": {"reached": False},
    })
    decisions = I2Adjudicator(db=None).adjudicate(i1, d2, specs=[
        {"vulnerability_hash_v2": "H1"}, {"vulnerability_hash_v2": "H2"},
    ])
    by_h = {d.hypothesis_id: d for d in decisions}
    assert by_h["H1"].action == "pass"
    assert by_h["H2"].action == "rollback_to_a2"
