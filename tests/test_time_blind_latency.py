# -*- coding: utf-8 -*-
"""时间盲注时延承接（承接断链①）与竞态 state_query 透传（承接断链②）回归测试。

这些测试锁定 2026-09-07 的两处改造，保证「威力大不破坏」的 sleep 型 payload
（时间盲注 / 命令注入 sleep）在探针未织到 DB sink 时仍能由 D2 时延双阈值门兜底确认，
以及竞态重放能从 raw_json.exploit_spec.state_query 透传获取可观测状态快照配置。

覆盖：
  attack_context.parse_sleep_seconds / first_sleep_payload / neutralize_sleep_payload
  d2_facade._time_blind_confirmed（双阈值确认门）
  d2_facade._verify_sink_result（时延旁证兜底，无 IAST sink-reached 时的端到端承接）
  orchestrator.TriggerTransactionOrchestrator._aggregate_dast（时延三元组「同源配对」聚合）
  d1_service._dig + replay_race 的 state_query 多源解析透传
"""
import pytest

from src.iast import attack_context as ac
from src.agents.d2_facade import _time_blind_confirmed, _verify_sink_result
from src.iast.orchestrator import DastImpact, TriggerTransactionOrchestrator


# ─────────────────────────────────────────────────────────────────────────────
# 1) parse_sleep_seconds —— 从单条 payload 解析预期时延秒数
# ─────────────────────────────────────────────────────────────────────────────
class TestParseSleepSeconds:
    @pytest.mark.parametrize("payload,expected", [
        ("1' AND SLEEP(5)-- -", 5.0),
        ("id=1' OR (SELECT 1 FROM (SELECT SLEEP(8))x)-- -", 8.0),
        ("'; SELECT pg_sleep(3)--", 3.0),
        ("'; WAITFOR DELAY '0:0:5'--", 5.0),
        ("; sleep 4", 4.0),
        ("1' OR 1=1-- -", 0.0),          # 非 sleep 型
        ("' UNION SELECT username FROM users--", 0.0),
    ])
    def test_parse(self, payload, expected):
        assert ac.parse_sleep_seconds(payload) == expected

    def test_multiple_sleep_returns_max(self):
        assert ac.parse_sleep_seconds("SLEEP(2) AND pg_sleep(7)") == 7.0

    def test_non_string_returns_zero(self):
        assert ac.parse_sleep_seconds(None) == 0.0
        assert ac.parse_sleep_seconds(123) == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 2) first_sleep_payload —— 挑预期时延最长的 sleep 型 payload
# ─────────────────────────────────────────────────────────────────────────────
class TestFirstSleepPayload:
    def test_picks_longest(self):
        payloads = ["SLEEP(3)", "1' AND SLEEP(8)-- -", "pg_sleep(2)"]
        assert ac.first_sleep_payload(payloads) == "1' AND SLEEP(8)-- -"

    def test_no_sleep_returns_none(self):
        assert ac.first_sleep_payload(["1 OR 1=1", "drop table x"]) is None

    def test_empty_returns_none(self):
        assert ac.first_sleep_payload([]) is None
        assert ac.first_sleep_payload(None) is None


# ─────────────────────────────────────────────────────────────────────────────
# 3) neutralize_sleep_payload —— 改 sleep 秒数为 0 作无害基线（结构不变）
# ─────────────────────────────────────────────────────────────────────────────
class TestNeutralizeSleepPayload:
    @pytest.mark.parametrize("payload,expected", [
        ("1' AND SLEEP(5)-- -", "1' AND SLEEP(0)-- -"),
        ("'; SELECT pg_sleep(3)--", "'; SELECT pg_sleep(0)--"),
        ("'; WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:0'--"),
        ("; sleep 4", "; sleep 0"),
    ])
    def test_neutralize(self, payload, expected):
        assert ac.neutralize_sleep_payload(payload) == expected

    def test_non_sleep_unchanged(self):
        p = "1' OR 1=1-- -"
        assert ac.neutralize_sleep_payload(p) == p


# ─────────────────────────────────────────────────────────────────────────────
# 4) _time_blind_confirmed（D2 双阈值确认门）—— 承接断链①核心
# ─────────────────────────────────────────────────────────────────────────────
class TestTimeBlindConfirmed:
    def _ev(self, hint, elapsed, baseline=0.0):
        return {"sleep_seconds_hint": hint, "elapsed_ms": elapsed,
                "baseline_elapsed_ms": baseline}

    def test_differential_hit(self):
        # 有基线：净时延差 (6000-200) ≥ 5s*0.7=3500 → high / differential
        v = _time_blind_confirmed(self._ev(5.0, 6000.0, 200.0))
        assert v is not None
        assert v["harmful"] is True
        assert v["sink_reached"] is True
        assert v["confidence"] == "high"
        assert v["time_blind_mode"] == "differential"
        assert v["time_blind_confirmed"] is True

    def test_differential_miss(self):
        # 有基线但净差不足 → 不采信
        assert _time_blind_confirmed(self._ev(5.0, 1000.0, 200.0)) is None

    def test_absolute_hit(self):
        # 无基线：绝对耗时 5000 ≥ 5s*0.8=4000 → medium / absolute
        v = _time_blind_confirmed(self._ev(5.0, 5000.0, 0.0))
        assert v is not None
        assert v["harmful"] is True
        assert v["confidence"] == "medium"
        assert v["time_blind_mode"] == "absolute"

    def test_absolute_miss(self):
        # 无基线且绝对耗时不足 → 不采信
        assert _time_blind_confirmed(self._ev(5.0, 1000.0, 0.0)) is None

    def test_hint_too_small(self):
        # 预期时延 1s < 1.5s：即便净差达标也一律不采信（防普通抖动）
        assert _time_blind_confirmed(self._ev(1.0, 2000.0, 100.0)) is None

    def test_no_sleep_hint(self):
        # 非 sleep 型：hint=0 → 不启用时延门
        assert _time_blind_confirmed(self._ev(0.0, 5000.0, 0.0)) is None

    def test_no_elapsed(self):
        # 已投放 sleep 但主请求未计时（elapsed=0）→ 无法评估
        assert _time_blind_confirmed(self._ev(5.0, 0.0, 0.0)) is None


# ─────────────────────────────────────────────────────────────────────────────
# 5) _verify_sink_result 端到端 —— 时延旁证兜底（探针没织到 sink 时的最后承接）
# ─────────────────────────────────────────────────────────────────────────────
class TestVerifySinkResultTimeBlindFallback:
    def test_no_sink_no_latency_is_not_harmful(self):
        # 对照组：IAST 无 sink-reached，也无时延证据 → 不误判、不回归
        out = _verify_sink_result(
            {"state": "no-arrival"},
            {"reached": True, "status_code": 200, "sleep_seconds_hint": 0.0,
             "elapsed_ms": 0.0, "baseline_elapsed_ms": 0.0},
        )
        assert out["harmful"] is False
        assert out["sink_reached"] is False

    def test_time_blind_fallback_when_no_iast_sink(self):
        # 关键修复：IAST 未报告 sink-reached（探针未织到 DB sink），
        # 但 D1 投放 SLEEP(5) 且时延差分达标 → 时延门独立确认 harmful=True
        out = _verify_sink_result(
            {"state": "no-arrival"},
            {"reached": True, "status_code": 200,
             "sleep_seconds_hint": 5.0, "elapsed_ms": 6000.0,
             "baseline_elapsed_ms": 200.0},
        )
        assert out["harmful"] is True
        assert out["time_blind_confirmed"] is True
        assert out["time_blind_mode"] == "differential"

    def test_iast_sink_reached_still_wins(self):
        # 回归：IAST 主信号 sink-reached 仍正常判有害，时延门不干扰主路径
        out = _verify_sink_result(
            {"state": "sink-reached"},
            {"reached": True, "status_code": 200,
             "sleep_seconds_hint": 0.0, "elapsed_ms": 0.0,
             "baseline_elapsed_ms": 0.0},
        )
        assert out["harmful"] is True
        assert out["sink_reached"] is True
        assert out.get("time_blind_confirmed") is not True


# ─────────────────────────────────────────────────────────────────────────────
# 6) _aggregate_dast 时延三元组「同源配对」聚合
# ─────────────────────────────────────────────────────────────────────────────
class TestAggregateDastLatencyPairing:
    def _orch(self):
        return TriggerTransactionOrchestrator(dast_operator=None)

    def test_picks_sleep_impact_whole_tuple(self):
        orch = self._orch()
        # 非 sleep impact（高 elapsed、无基线）+ sleep impact（配对 elapsed/baseline）
        non_sleep = DastImpact(reached=True, status_code=200, elapsed_ms=9000.0,
                               baseline_elapsed_ms=0.0, sleep_seconds_hint=0.0)
        sleep = DastImpact(reached=True, status_code=200, elapsed_ms=6000.0,
                          baseline_elapsed_ms=200.0, sleep_seconds_hint=5.0)
        merged = orch._aggregate_dast([non_sleep, sleep])
        # 必须整组取自 sleep impact，绝不拿 9000 减 0 污染 delta
        assert merged.sleep_seconds_hint == 5.0
        assert merged.elapsed_ms == 6000.0
        assert merged.baseline_elapsed_ms == 200.0

    def test_no_sleep_keeps_zeros(self):
        orch = self._orch()
        a = DastImpact(reached=True, status_code=200, elapsed_ms=1500.0,
                       baseline_elapsed_ms=0.0, sleep_seconds_hint=0.0)
        b = DastImpact(reached=True, status_code=200, elapsed_ms=900.0,
                       baseline_elapsed_ms=0.0, sleep_seconds_hint=0.0)
        merged = orch._aggregate_dast([a, b])
        assert merged.sleep_seconds_hint == 0.0
        assert merged.elapsed_ms == 0.0  # 没有 sleep 型，三元组保持 0
        assert merged.baseline_elapsed_ms == 0.0

    def test_sleep_impact_picks_highest_elapsed_pair(self):
        orch = self._orch()
        s1 = DastImpact(reached=True, elapsed_ms=3000.0, baseline_elapsed_ms=100.0,
                        sleep_seconds_hint=3.0)
        s2 = DastImpact(reached=True, elapsed_ms=7000.0, baseline_elapsed_ms=300.0,
                        sleep_seconds_hint=7.0)
        merged = orch._aggregate_dast([s1, s2])
        assert merged.sleep_seconds_hint == 7.0
        assert merged.elapsed_ms == 7000.0
        assert merged.baseline_elapsed_ms == 300.0  # 来自 s2 而非 s1


# ─────────────────────────────────────────────────────────────────────────────
# 7) replay_race state_query 多源透传（承接断链②）
#    验证 _dig(raw_json.exploit_spec.state_query) 能解析出 spec 顶层/ target / raw_json 三源
# ─────────────────────────────────────────────────────────────────────────────
class TestRaceStateQueryPassthrough:
    def test_dig_reaches_exploit_spec_state_query(self):
        from src.application.d1_service import _dig
        spec = {
            "raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/api/balance", "field": "amount"}}}',
        }
        cfg = _dig(spec.get("raw_json"), "exploit_spec", "state_query")
        assert cfg is not None
        assert cfg["endpoint"] == "/api/balance"

    def test_snap_cfg_resolution_order(self):
        # 复刻 replay_race L1336 的三源解析表达式：spec → target → raw_json
        from src.application.d1_service import _dig

        def resolve(spec, target):
            return (
                spec.get("state_query")
                or target.get("state_query")
                or _dig(spec.get("raw_json"), "exploit_spec", "state_query")
            )

        # 三源皆空 → None（graceful 降级）
        assert resolve({}, {}) is None
        # 仅 raw_json 有 → 透传成功（承接断链②修复点）
        spec = {"raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/x"}}}'}
        assert resolve(spec, {}) == {"endpoint": "/x"}
        # spec 顶层优先于 raw_json
        spec2 = {"state_query": {"endpoint": "/top"},
                 "raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/x"}}}'}
        assert resolve(spec2, {}) == {"endpoint": "/top"}
        # target 中间优先级
        spec3 = {"raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/x"}}}'}
        assert resolve(spec3, {"state_query": {"endpoint": "/tgt"}}) == {"endpoint": "/tgt"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
