"""D2 降级攻击门控回归测试（2026-08-29）。

背景：D1 真实攻击链路落地后，A2 造不出真 payload 时 D1 只投 canary 探针并标 attack_degraded。
但 D2 侧此前完全不消费该字段，导致：

1. `orchestrator._aggregate_dast` 合并多 spec 时把 attack_degraded 静默丢弃（merged 取默认 False），
   D2 永远读到「未降级」；
2. `adjudicator.D2Judge` 判 harmful = sink_reached and reached，canary 到 sink 即判有害；
3. `adjudicator.adjudicate_final_state` 由 impact_observed 直接落到最强态 confirmed_attributable；
4. `adjudicator.decide_next_action` 降级时仍走「默认通过」。

一句话：只发了 canary 探针的降级攻击，被当成真打过来确认可利用。本文件锁死修复后的行为。

注意区分两个「degraded」：
- `IastVerdict.degraded` 是 canary 二态退化（7.2 方向B，探针侧概念）；
- `DastImpact.attack_degraded` 是「本次回放没投真实 payload」（攻击侧概念）。
本文件测的是后者。
"""
from src.iast.adjudicator import (
    FINAL_AMBIGUOUS,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_FALSE_POSITIVE_SAST_ONLY,
    FINAL_NO_EVIDENCE,
    I2Adjudicator,
    D2Judge,
)
from src.iast.orchestrator import (
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED,
    STATE_SINK_REACHED_PROBE,
    DastImpact,
    IastVerdict,
    TriggerTransactionOrchestrator,
)


def _verdicts(state=STATE_SINK_REACHED):
    return {"h1": IastVerdict(state=state, matched_event_ids=[1], confidence="high", provisional=False)}


def _raw(*, degraded=False, degraded_any=False, biz=None, reached=True):
    d = {
        "reached": reached,
        "status_code": 200,
        "body": "ok",
        "impact_observed": reached,
        "slices": {},
        "attack_degraded": degraded,
        "attack_degraded_any": degraded_any,
        "attack_payload_used": "" if degraded else "REAL_PAYLOAD",
    }
    if biz is not None:
        d["business_logic"] = biz
    return d


# ---------------------------------------------------------------- ① 聚合不丢降级标记


def test_aggregate_dast_preserves_all_degraded():
    """全部 spec 降级 → 聚合后 attack_degraded 仍为 True（此前被静默丢弃为 False）。"""
    orch = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orch._aggregate_dast([
        DastImpact(reached=True, status_code=200, attack_degraded=True),
        DastImpact(reached=True, status_code=200, attack_degraded=True),
    ])
    assert merged.attack_degraded is True
    assert merged.attack_degraded_any is True


def test_aggregate_dast_distinguishes_partial_degraded():
    """部分 spec 降级 → attack_degraded=False（有真打），attack_degraded_any=True（混了弱证据）。"""
    orch = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orch._aggregate_dast([
        DastImpact(reached=True, status_code=200, attack_degraded=True),
        DastImpact(reached=True, status_code=200, attack_degraded=False, attack_payload_used="REAL"),
    ])
    assert merged.attack_degraded is False
    assert merged.attack_degraded_any is True
    assert merged.attack_payload_used == "REAL"


def test_aggregate_dast_ignores_blocked_when_judging_degradation():
    """blocked/error 未发流量，既不算攻击也不算降级，不应污染降级判定。"""
    orch = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orch._aggregate_dast([
        DastImpact(blocked=True, error="A0 未就绪"),
        DastImpact(reached=True, status_code=200, attack_degraded=False, attack_payload_used="REAL"),
    ])
    assert merged.attack_degraded is False
    assert merged.attack_degraded_any is False


def test_aggregate_dast_merges_business_logic():
    orch = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orch._aggregate_dast([
        DastImpact(reached=True, business_logic={"confirmed": True, "category": "bola"}),
        DastImpact(reached=True, business_logic={"diff": "attacker_got_victim_data"}),
    ])
    assert merged.business_logic.get("confirmed") is True
    assert merged.business_logic.get("diff") == "attacker_got_victim_data"


# ---------------------------------------------------------------- ② D2Judge 降级门控


def test_d2judge_degraded_attack_is_not_harmful():
    """核心：canary 到 sink 只证可达，不证有害 —— 降级时 harmful 必须为 False。"""
    v = D2Judge().judge(_verdicts(), _raw(degraded=True))
    assert v[0].harmful is False
    assert v[0].sink_reached is True
    assert v[0].confidence == "low"
    assert v[0].detail.get("attack_degraded") is True


def test_d2judge_real_payload_is_harmful():
    """对照：真 payload 投放 + sink 到达 → 判有害（不能被门控误伤）。"""
    v = D2Judge().judge(_verdicts(), _raw(degraded=False))
    assert v[0].harmful is True
    assert v[0].confidence == "high"
    assert v[0].detail.get("attack_payload_used") == "REAL_PAYLOAD"


def test_d2judge_business_logic_diff_bypasses_degradation_gate():
    """例外：业务族没走 canary 通道，差分确认本身就是攻击证据，不受降级门控影响。"""
    v = D2Judge().judge(_verdicts(), _raw(degraded=True, biz={"confirmed": True, "category": "bola"}))
    assert v[0].harmful is True
    assert v[0].confidence == "high"
    assert v[0].detail.get("business_logic_confirmed") is True


def test_d2judge_partial_degraded_lowers_confidence():
    """部分降级：仍可判有害（确有真弹），但置信度降为 medium。"""
    v = D2Judge().judge(_verdicts(), _raw(degraded=False, degraded_any=True))
    assert v[0].harmful is True
    assert v[0].confidence == "medium"


# ---------------------------------------------------------------- ③ 五态裁定降级门控


def test_final_state_degraded_never_confirmed_attributable():
    """核心：降级攻击绝不能落到最强态，也不能被判为「已确认可利用」。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_SINK_REACHED, "confidence": "high", "chain_conformance": {}},
        dast_impact_evidence=_raw(degraded=True),
        d2_verdict={},
    )
    assert r["final_state"] != FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is False
    assert r["attack_degraded"] is True


def test_final_state_real_payload_keeps_confirmed_attributable():
    """对照：真 payload + impact_observed 仍应给出最强态（门控不能反向误伤）。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_SINK_REACHED, "confidence": "high", "chain_conformance": {}},
        dast_impact_evidence=_raw(degraded=False),
        d2_verdict={"harmful": True},
    )
    assert r["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is True


def test_final_state_degraded_no_arrival_is_no_evidence():
    """降级 + 未到 sink → 连可达性证据都没有，只能 no_evidence。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "confidence": "low", "chain_conformance": {}},
        dast_impact_evidence=_raw(degraded=True, reached=False),
        d2_verdict={},
    )
    assert r["final_state"] == FINAL_NO_EVIDENCE
    assert r["confirmed"] is False


def test_final_state_partial_degraded_annotates_reason():
    """部分降级：可确认，但理由里必须显式标注弱证据，避免与「全部真打」混淆。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_SINK_REACHED, "confidence": "high", "chain_conformance": {}},
        dast_impact_evidence=_raw(degraded=False, degraded_any=True),
        d2_verdict={"harmful": True},
    )
    assert r["confirmed"] is True
    assert "部分 spec 为降级攻击" in r["judge_reason"]
    assert r["attack_degraded_any"] is True


# ---------------------------------------------------------------- ④ 控制回路：降级回灌 A2


def test_next_action_degraded_rolls_back_to_a2():
    """降级时重发同一条 canary 毫无意义，必须回灌 A2 补造真实 payload。"""
    a = I2Adjudicator.decide_next_action(
        iast_evidence={"state": STATE_SINK_REACHED, "chain_conformance": {}},
        d2_verdict={"harmful": False},
        dast_impact_evidence=_raw(degraded=True),
    )
    assert a["action"] == "rollback_to_a2"
    assert a["correction_hint"].get("need_real_payload") is True


def test_next_action_real_payload_passes():
    """对照：真 payload 且链路符合 → pass（不能被降级分支误伤）。"""
    a = I2Adjudicator.decide_next_action(
        iast_evidence={"state": STATE_SINK_REACHED, "chain_conformance": {"conforms": True}},
        d2_verdict={"harmful": True},
        dast_impact_evidence=_raw(degraded=False),
    )
    assert a["action"] == "pass"


def test_next_action_business_logic_confirmed_passes_over_degradation():
    """业务差分已确认时不触发补弹回滚。"""
    a = I2Adjudicator.decide_next_action(
        iast_evidence={"state": STATE_SINK_REACHED, "chain_conformance": {"conforms": True}},
        d2_verdict={"harmful": True},
        dast_impact_evidence=_raw(degraded=True, biz={"confirmed": True, "category": "bola"}),
    )
    assert a["action"] == "pass"


# ---------------------------------------------------------------- ⑤ d2_facade 兼容 d2_verdict


def test_verify_sink_result_degraded_not_harmful():
    from src.agents.d2_facade import _verify_sink_result

    r = _verify_sink_result(
        {"state": STATE_SINK_REACHED},
        {"reached": True, "status_code": 200, "body": "ok", "attack_degraded": True},
    )
    assert r["harmful"] is False
    assert r["sink_reached"] is True
    assert r["attack_degraded"] is True


def test_verify_sink_result_real_payload_harmful():
    from src.agents.d2_facade import _verify_sink_result

    r = _verify_sink_result(
        {"state": STATE_SINK_REACHED},
        {"reached": True, "status_code": 200, "body": "ok", "attack_degraded": False},
    )
    assert r["harmful"] is True


def test_verify_sink_result_business_diff_harmful():
    from src.agents.d2_facade import _verify_sink_result

    r = _verify_sink_result(
        {"state": STATE_SINK_REACHED},
        {
            "reached": True,
            "status_code": 200,
            "body": "victim data",
            "attack_degraded": True,
            "business_logic": {"confirmed": True, "category": "bola"},
        },
    )
    assert r["harmful"] is True
    assert r["business_logic_confirmed"] is True


def test_verify_sink_result_probe_asserted_bypasses_degradation():
    """2026-11-03（r17b 验证）推翻旧前提：探针断言 sink-reached-probe 仍不等于可利用。

    旧前提（设计一①）：canary 出现在危险函数实参即视为确认，即便 attack_degraded。
    实证推翻（jsc 609）：FileUpload.java 的 7 条路径穿越、log4j 的 xss 全部由此确认，
    但它们的 replay payload 为空、status_code=302 —— 投的是 D1 的 canary 探针而非攻击载荷，
    canary 到达只证「我方数据可达 sink」，不证「攻击可利用」。真值里 FileUpload 属 file_upload
    族，被判 path_traversal 即跨族误报。

    新语义：降级攻击（无真实 payload）无论探针是否断言，一律 harmful=False（可达但不可利用）。
    """
    from src.agents.d2_facade import _verify_sink_result

    r = _verify_sink_result(
        {"state": STATE_SINK_REACHED_PROBE},
        {"reached": True, "status_code": 200, "body": "ok", "attack_degraded": True},
    )
    assert r["harmful"] is False, "无真实载荷时 canary 到达只证可达，不得判有害"
    assert r["sink_reached"] is True
    assert r.get("attack_degraded") is True, "降级攻击须留痕，供对账识别弱证据"


def test_verify_sink_result_probe_asserted_with_real_payload_still_harmful():
    """正向守卫：有真实攻击载荷（attack_degraded=False）时，探针断言仍判有害，不得误伤真 TP。"""
    from src.agents.d2_facade import _verify_sink_result

    r = _verify_sink_result(
        {"state": STATE_SINK_REACHED_PROBE},
        {"reached": True, "status_code": 200, "body": "ok", "attack_degraded": False},
    )
    assert r["harmful"] is True
    assert r["sink_reached"] is True


def test_final_state_probe_asserted_bypasses_degradation():
    """设计一①：探针显式断言 sink-reached-probe 时，降级攻击不应落入 ambiguous/no_evidence，
    应视为运行时确认（confirmed）。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_SINK_REACHED_PROBE, "confidence": "high", "chain_conformance": {}},
        dast_impact_evidence=_raw(degraded=True, reached=False),
        d2_verdict={},
    )
    assert r["confirmed"] is True
    assert r["final_state"] in (FINAL_CONFIRMED_ATTRIBUTABLE, "runtime_confirmed")


def test_next_action_probe_asserted_no_rollback():
    """设计一①：探针显式断言 sink-reached-probe 时，降级攻击不触发 rollback_to_a2（无需 A2 补弹）。

    注（Q6 五类·arrived_unconfirmed，2026-09-30 激活）：本用例 chain_conformance={}（conforms=False），
    探针虽确证到达 sink，但「逐节点链路符合」不成立，按五类决策表归 arrived_unconfirmed →
    re_send（升级变体/延长窗口重验），而非回滚 A2 重写假说。设计一① 的核心保证是「不回滚 A2」，
    由 re_send 满足；此处断言精确的当前路由，避免把「到达未确认」误当「链路不符」。
    """
    a = I2Adjudicator.decide_next_action(
        iast_evidence={"state": STATE_SINK_REACHED_PROBE, "chain_conformance": {}},
        d2_verdict={"harmful": True},
        dast_impact_evidence=_raw(degraded=True),
    )
    # 设计一① 核心保证：探针显式断言时，降级攻击不回滚 A2。
    assert a["action"] != "rollback_to_a2"
    assert a["action"] == "re_send"
    assert a.get("failure_class") == "arrived_unconfirmed"



# ---------------------------------------------------------------- ⑥ 端到端：DastImpact → to_dict → 裁定


def test_end_to_end_degraded_flow_stays_unconfirmed():
    """端到端：D1 产出降级 DastImpact → 聚合 → to_dict → 五态裁定，全程不确认可利用。"""
    orch = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orch._aggregate_dast([
        DastImpact(reached=True, status_code=200, body="ok", attack_degraded=True),
    ])
    raw = merged.to_dict()
    raw["impact_observed"] = bool(raw.get("reached"))

    verdicts = D2Judge().judge(_verdicts(), raw)
    assert verdicts[0].harmful is False

    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_SINK_REACHED, "confidence": "high", "chain_conformance": {}},
        dast_impact_evidence=raw,
        d2_verdict=verdicts[0].__dict__,
    )
    assert r["confirmed"] is False
    assert r["final_state"] in (FINAL_AMBIGUOUS, FINAL_NO_EVIDENCE)

    a = I2Adjudicator.decide_next_action(
        iast_evidence={"state": STATE_SINK_REACHED, "chain_conformance": {}},
        d2_verdict=verdicts[0].__dict__,
        dast_impact_evidence=raw,
    )
    assert a["action"] == "rollback_to_a2"


# ---------------------------------------------------------------- ⑦ 注入族离线 DAST 确认门禁（让 /products SQLi 在 D2 通过）


def test_final_state_injection_family_offline_dast_confirmed():
    """核心：注入族（sql-injection）+ 离线 DAST 观测到外部可观测影响（impact_observed）+ 未到 sink
    → 确认可利用（confirmed_attributable）。本靶场 iast_observed=0，确认只能来自离线 DAST 影响。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "confidence": "low", "chain_conformance": {}},
        dast_impact_evidence={"impact_observed": True, "reached": True, "status_code": 500},
        d2_verdict={},
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is True


def test_final_state_injection_family_degraded_but_impact_confirmed():
    """2026-09-26 F4 精确率整改③后的口径（本用例随口径同步更新，非产物回归）：

    旧口径「注入族 + 离线 DAST 可观测影响 + 未到 sink ⇒ 直接 confirmed_attributable」已被
    证明是精确率杀手——降级攻击（D1 仅投 canary 探针）在 404 响应上的弱「影响」也会被升确认。
    收紧后：降级攻击且探针无 sink 证据、D2 未独立判有害 ⇒ 最多 ambiguous（进 suspicious 档，
    交 rollback_to_a2 补真实 payload），不再计 confirmed。
    """
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "confidence": "low", "chain_conformance": {}},
        dast_impact_evidence={"impact_observed": True, "reached": True, "attack_degraded": True},
        d2_verdict={},
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_AMBIGUOUS
    assert r["confirmed"] is False


def test_final_state_injection_family_degraded_but_d2_harmful_carveout():
    """carve-out（2026-09-26 round15 召回回收）：降级攻击若 D2 已独立判定结果点有害
    （d2_verdict.harmful=True，动态确认强证据），仍确认可利用——降级是 payload 质量限制，
    不是漏洞存在性限制，且 D2 有害判定不依赖 404 上的弱影响。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "confidence": "low", "chain_conformance": {}},
        dast_impact_evidence={"impact_observed": True, "reached": True, "attack_degraded": True},
        d2_verdict={"harmful": True},
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    assert r["confirmed"] is True


def test_final_state_injection_family_stable_disproof_overrides_confirmation():
    """注入族离线影响若存在稳定反证（stable_disproof），优先判误报，不被 impact_observed 误确认。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "chain_conformance": {}},
        dast_impact_evidence={"impact_observed": True, "reached": True, "stable_disproof": True},
        d2_verdict={},
        family="sql-injection",
    )
    assert r["final_state"] == FINAL_FALSE_POSITIVE_SAST_ONLY
    assert r["confirmed"] is False


def test_final_state_non_injection_offline_dast_stays_ambiguous():
    """回归护栏：非注入族 + 离线 DAST 影响 + 未到 sink → 仍走 ambiguous（不被误确认）。"""
    r = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": STATE_NO_ARRIVAL, "chain_conformance": {}},
        dast_impact_evidence={"impact_observed": True, "reached": True},
        d2_verdict={},
        family="some-unknown-family",
    )
    assert r["final_state"] == FINAL_AMBIGUOUS
    assert r["confirmed"] is False
