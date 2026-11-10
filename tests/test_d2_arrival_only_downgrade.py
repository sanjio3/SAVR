"""回归锁：到达判定不得落 confirmed_exploitable（2026-10-07 方案①）。

## 为什么改

r64c 实测（run 243 pathtraver-1）：105 条 `confirmed_exploitable` 的
`primary_channel` **100% 是 `probe_sink_assert`**（`evidence_strength=2`），
即「探针在危险函数实参里断言到投放的数据」。该通道只证明**污点抵达**，
不证明**利用成功**，而真值口径下 FP 率 35%（真TP 68 / 真FP 37）。

「confirmed_exploitable」在报告/前端会被读成「已证实可利用」，属**误导性标签**。
故：仅靠探针断言支撑时，状态降为 `sink_reached`，并如实说明能力边界。

## 降级范围（必须严格）

只降 `probe_sink_assert`；带外(4)/回显(3)/结果点(3)/语义差分(3)/时间盲注(2 达标)
支撑的确认**一律不动** —— 它们是真正的可利用性证据。
时间盲注虽同为证明力 2，但 harmful 来自「延时差分达标」，与探针断言不同源，
故按**通道名**精确排除，不按 strength 粗暴比较。
"""
import os

import pytest

from src.agents.d2_facade import _build_verification_result


class _Dec:
    """最小 I2Decision 替身：只带 _build_verification_result 真正读到的字段。"""

    def __init__(self, confirmed=True, final_state="confirmed_exploitable"):
        self.confirmed = confirmed
        self.final_state = final_state
        self.confidence = "high"
        self.hypothesis_id = "h1"
        self.reason = "测试"
        self.action = "pass"
        self.feedback_to_a2 = None
        self.proof_resolution = {}

    def __repr__(self):
        return "_Dec(confirmed=%r, final_state=%r)" % (self.confirmed, self.final_state)


def _run(primary_channel, confirmed=True, dast_impact=None):
    d2v = {"primary_channel": primary_channel,
           "harmful": True, "sink_reached": True}
    vr = _build_verification_result([_Dec(confirmed=confirmed)], {}, dast_impact or {}, d2v)
    return vr, vr.verification_decision


class TestArrivalOnlyDowngrade:
    def test_probe_assert_downgraded(self):
        vr, vd = _run("probe_sink_assert")
        assert vd["verification_status"] == "sink_reached", (
            "仅靠探针断言时不得标 confirmed_exploitable")
        assert vr.exploitable is False
        assert vd["arrival_only_downgraded"] is True
        assert vd["confirmed_raw"] is True, "须保留降级前的原始判定供对账"
        assert vd["primary_channel"] == "probe_sink_assert"

    def test_reason_states_capability_boundary(self):
        """降级原因必须对外说明能力边界，不能静默降级。"""
        vr, _ = _run("probe_sink_assert")
        assert "不证明" in vr.reason and "sink_reached" in vr.reason

    @pytest.mark.parametrize("ch", [
        "oob_callback", "echo_marker", "result_point_diff",
        "semantic_diff", "time_blind", "code_property",
    ])
    def test_other_channels_untouched(self, ch):
        """带外/回显/结果点/差分/时间盲注都是真可利用性证据，降级会误伤真阳性。"""
        vr, vd = _run(ch)
        assert vd["verification_status"] == "confirmed_exploitable", (
            "通道 %s 支撑的确认不应被降级" % ch)
        assert vr.exploitable is True
        assert vd["arrival_only_downgraded"] is False

    def test_unconfirmed_stays_unconfirmed(self):
        vr, vd = _run("probe_sink_assert", confirmed=False)
        assert vd["verification_status"] == "unconfirmed"
        assert vr.exploitable is False

    @pytest.mark.parametrize("impact", [
        {"impact_observed": True},
        {"data_leak_confirmed": True},
        {"business_logic": {"confirmed": True}},
    ])
    def test_real_dast_impact_not_downgraded(self, impact):
        """有 DAST 真实影响证据时**不得**降级 —— 那是「攻击真的产生了后果」。

        回归锁来源：tests/test_iast_orchestrator.py（该测试带 impact_observed=True，
        初版判据只看 primary_channel，把它误降级了）。impact 证据优先于抵达证据。
        """
        vr, vd = _run("probe_sink_assert", dast_impact=impact)
        assert vd["verification_status"] == "confirmed_exploitable", (
            "DAST 已观测到真实影响，属可利用性证据，不该降级")
        assert vr.exploitable is True
        assert vd["arrival_only_downgraded"] is False

    def test_env_switch_restores_legacy(self, monkeypatch):
        """开关可恢复旧行为，便于回滚与 A/B 口径对比。"""
        import importlib
        import src.agents.d2_facade as ab
        monkeypatch.setenv("SAST_AI_D2_ARRIVAL_ONLY", "0")
        try:
            importlib.reload(ab)
            vr = ab._build_verification_result(
                [_Dec()], {}, {},
                {"primary_channel": "probe_sink_assert", "harmful": True, "sink_reached": True})
            assert vr.verification_decision["verification_status"] == "confirmed_exploitable"
        finally:
            monkeypatch.delenv("SAST_AI_D2_ARRIVAL_ONLY", raising=False)
            importlib.reload(ab)

    def test_default_is_on(self):
        """默认即降级（诚实优先），只有显式设 0 才回退。"""
        assert os.environ.get("SAST_AI_D2_ARRIVAL_ONLY", "1") not in ("0", "", "false")
