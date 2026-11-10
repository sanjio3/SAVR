"""I2 证据三元组不得丢弃 D1 离线 DAST 影响（注入族离线确认回归守卫）。

背景（run 17 实测发现）：
本靶场 IAST 永不观测到 sink（sink_reached=0），注入族（sql/ssrf/command...）的确认只能来自
D1 离线重放的「外部可观测影响」——finding raw_json 里 `dast_impact_evidence.impact_observed=True`
（如 SQL 报错 / 400 / 403，payload 真实投放）。但：

1. `D2Judge.judge` 的 `harmful = sink_reached and reached`，注入族 sink_reached 恒 False → harmful 恒 False；
2. `_evidence_bundle` 用 `impact_observed = bool(d2.harmful)` 重建证据三元组，把真实 D1 影响**丢弃**；
3. 于是 `adjudicate_final_state` 的 Fix B 注入族离线确认分支（`is_inj and dast_impact`）因
   `dast_impact=False` **永不触发** —— spec 明明有 D1 影响却恒为 unconfirmed。

修复：给 D2Verdict 加 `dast_impact_observed`（D1 reached/impact_observed，独立于 sink_reached），
_evidence_bundle 改为 `d2.harmful or d2.dast_impact_observed`，与 proof_obligations.py:715 的
`impact_observed = dast OR d2.harmful` 口径对齐。
"""
from src.iast.adjudicator import (
    FINAL_AMBIGUOUS,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_NO_EVIDENCE,
    D2Judge,
    D2Verdict,
    I1Verdict,
    I2Adjudicator,
)
from src.iast.orchestrator import STATE_NO_ARRIVAL, IastVerdict


def _i1(state=STATE_NO_ARRIVAL, hid="h1"):
    return I1Verdict(
        hypothesis_id=hid,
        requirement_met=False,
        state=state,
        chain_conforms=False,
        chain_conformance={},
        matched_event_ids=[],
        confidence="low",
        reason="I1 监听：state=%s" % state,
        detail={},
    )


def _raw(*, reached=True, impact_observed=True):
    return {
        "reached": reached,
        "impact_observed": impact_observed,
        "status_code": 400,
        "body": "SQL syntax error",
    }


def test_d2judge_carries_offline_impact_when_sink_not_reached():
    """D2Judge 必须把 D1 离线影响单独带上，不能只留 harmful（注入族 harmful 恒 False）。"""
    verdicts = D2Judge().judge(
        {"h1": IastVerdict(state=STATE_NO_ARRIVAL, matched_event_ids=[], confidence="low")},
        raw_dast_impact=_raw(reached=True),
    )
    v = verdicts[0]
    # 注入族：IAST 不到 sink → harmful 仍为 False（语义正确，sink 侧没证明）
    assert v.sink_reached is False
    assert v.harmful is False
    # 但 D1 离线影响必须被保留下来供 Fix B 消费
    assert v.dast_impact_observed is True


def test_d2judge_no_impact_when_d1_not_reached():
    """D1 未到达时不得伪造影响（避免反向假阳性）。"""
    verdicts = D2Judge().judge(
        {"h1": IastVerdict(state=STATE_NO_ARRIVAL, matched_event_ids=[], confidence="low")},
        raw_dast_impact=_raw(reached=False, impact_observed=False),
    )
    assert verdicts[0].dast_impact_observed is False


def test_evidence_bundle_keeps_d1_impact():
    """核心回归：证据三元组必须把 d2.dast_impact_observed 带进 impact_observed。"""
    d2 = D2Verdict(
        hypothesis_id="h1",
        requirement_met=False,
        harmful=False,          # 注入族 sink 未达 → harmful=False
        sink_reached=False,
        confidence="low",
        reason="I1 状态=no-arrival，结果点未确证有害",
        detail={},
        dast_impact_observed=True,   # 但 D1 离线重放确有可观测影响
    )
    bundle = I2Adjudicator._evidence_bundle(_i1(), d2)
    assert bundle["dast_impact_evidence"]["impact_observed"] is True


def test_injection_family_offline_dast_impact_is_confirmed():
    """注入族 + D1 离线影响 + IAST 未到 sink → confirmed_attributable（Fix B 真正生效）。"""
    d2 = D2Verdict(
        hypothesis_id="h1", requirement_met=False, harmful=False, sink_reached=False,
        confidence="low", reason="", detail={}, dast_impact_observed=True,
    )
    bundle = I2Adjudicator._evidence_bundle(_i1(), d2)
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence=bundle["iast_evidence"],
        dast_impact_evidence=bundle["dast_impact_evidence"],
        d2_verdict=bundle["d2_verdict"],
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is True


def test_injection_family_without_d1_impact_stays_no_evidence():
    """D1 无影响时注入族不得被误确认（守假阳性）。"""
    d2 = D2Verdict(
        hypothesis_id="h1", requirement_met=False, harmful=False, sink_reached=False,
        confidence="low", reason="", detail={}, dast_impact_observed=False,
    )
    bundle = I2Adjudicator._evidence_bundle(_i1(), d2)
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence=bundle["iast_evidence"],
        dast_impact_evidence=bundle["dast_impact_evidence"],
        d2_verdict=bundle["d2_verdict"],
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_NO_EVIDENCE
    assert r["confirmed"] is False


def test_non_injection_family_not_over_confirmed():
    """非注入族不得因 D1 影响被直接判最强态（口径单一性守卫，避免误伤业务族判定）。"""
    d2 = D2Verdict(
        hypothesis_id="h1", requirement_met=False, harmful=False, sink_reached=False,
        confidence="low", reason="", detail={}, dast_impact_observed=True,
    )
    bundle = I2Adjudicator._evidence_bundle(_i1(), d2)
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence=bundle["iast_evidence"],
        dast_impact_evidence=bundle["dast_impact_evidence"],
        d2_verdict=bundle["d2_verdict"],
        family="bola",
    )
    assert r["final_state"] != FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is False


def test_rule_based_i2_path_confirms_injection_spec():
    """端到端（规则式 I2 路径）：D1 有影响的注入族 spec 必须产出「已确认」裁决。"""
    d2 = D2Verdict(
        hypothesis_id="h1", requirement_met=False, harmful=False, sink_reached=False,
        confidence="low", reason="", detail={}, dast_impact_observed=True,
    )
    spec = {"vulnerability_hash_v2": "h1", "family": "sql-injection", "target_endpoint": "/products"}
    adj = I2Adjudicator()
    decisions = adj._adjudicate_rule_based(
        [_i1()], [d2], {"h1": spec}, None, dast_impact_evidence=_raw(reached=True),
    )
    assert len(decisions) == 1
    assert decisions[0].final_state == FINAL_CONFIRMED_ATTRIBUTABLE
    assert decisions[0].confirmed is True
