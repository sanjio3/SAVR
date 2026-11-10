"""回归锁：primary_channel='none'（无任何证据通道命中）不得落 confirmed_exploitable。

## 实测来源

r88 早期对账（run 331= shard-sqli-1）发现 6 个误报：
BenchmarkTest00191 / 00329 / 00330 / 00509 / 00672 / 00837 均为**安全用例**（真值 FP），
却被 I2 落 `confirmed_exploitable`。逐条取证：

- `dast_impact_evidence.impact_observed = False`
- `differential = {attempted: True, harmful: False, reason: no_observable_difference}`
- `sink_exception_class = ''`（无异常类证据）
- `iast_evidence.value_hit = {}`（无值级证据）
- `primary_channel = 'none'` —— **没有任何证据通道命中**

即：纯粹的「canary 到达了 sink」被当成了可利用性确认。

## 为什么原门控拦不住

`_ARRIVAL_ONLY_CHANNELS = ("probe_sink_assert",)` 是**白名单式**：只拦探针断言通道。
`primary_channel='none'` 不在白名单内 ⇒ 反而绕过了降级，这是比 arrival-only 更严重的
「无证据却确认」。

## 修复

无证据通道（none/空/unknown）+ 无独立影响证据 + 无值级证据 ⇒ 降级为 sink_reached。
值级/独立影响证据**豁免**（防误伤真阳性：值级可能因迟到证据或通道注册竞态未回填 primary）。
"""
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


def _run(primary_channel, iast_evidence=None, dast_impact=None, confirmed=True):
    d2v = {"primary_channel": primary_channel,
           "harmful": True, "sink_reached": True}
    vr = _build_verification_result(
        [_Dec(confirmed=confirmed)], iast_evidence or {}, dast_impact or {}, d2v)
    return vr, vr.verification_decision


class TestNoEvidenceChannelDowngrade:
    @pytest.mark.parametrize("ch", ["none", "", "unknown", "None"])
    def test_no_evidence_channel_downgraded(self, ch):
        """无任何证据通道命中 ⇒ 只证明到达，不得标 confirmed_exploitable。"""
        vr, vd = _run(ch)
        assert vd["verification_status"] == "sink_reached", (
            "primary_channel=%r 表示无证据通道命中，不得落 confirmed_exploitable" % ch)
        assert vr.exploitable is False
        assert vd["confirmed_raw"] is True, "须保留降级前的原始判定供对账"

    def test_value_level_hit_exempt(self):
        """值级证据（canary 真出现在 sink 实参）是强证据，即便 primary 未回填也不降级。"""
        vr, vd = _run("none", iast_evidence={"value_hit": {"hit": True, "form": "literal"}})
        assert vd["verification_status"] == "confirmed_exploitable", (
            "有值级证据时不得因 primary_channel=none 误伤真阳性")

    def test_real_impact_exempt(self):
        """独立影响证据（OOB/差分有害/时延/异常类）豁免降级。"""
        vr, vd = _run("none", dast_impact={"impact_observed": True})
        assert vd["verification_status"] == "confirmed_exploitable", (
            "有独立影响证据时不得降级")

    def test_unconfirmed_stays_unconfirmed(self):
        vr, vd = _run("none", confirmed=False)
        assert vd["verification_status"] == "unconfirmed"

    def test_kill_switch_restores_old_behaviour(self, monkeypatch):
        """SAST_AI_D2_ARRIVAL_ONLY=0 可回滚（A/B 口径用）。"""
        monkeypatch.setenv("SAST_AI_D2_ARRIVAL_ONLY", "0")
        vr, vd = _run("none")
        assert vd["verification_status"] == "confirmed_exploitable"
