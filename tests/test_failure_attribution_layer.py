"""阶段层归因（failure_attribution_layer）的回归锁。

## 为什么要这一列

四层是串联的（A2 spec → D1 重放 → D2 判据 → I1 观测），任何一层断了，最终症状
都是 `verification_status != confirmed`。旧口径只有 `failure_attribution`
（env/probe/pipeline/true_miss，回答"该谁修"），没有"卡在哪层"，于是 2026-11-04
jsc 615 的 10 个未覆盖点只能逐个人工回查 attempt / iast_state 才能定层。

本列与旧列**并行**，不替代：一次 GROUP BY 就能看到水位在哪层。

## 判定顺序（严格按流水线）

payload 不可用 → 零重放/全非 2xx-3xx → 已到 sink → 未到达 → 兜底观测层
"""
import pytest

from src.core.failure_attribution import (
    ALL_LAYERS,
    LAYER_IAST,
    LAYER_REPLAY,
    LAYER_SPEC,
    LAYER_VERDICT,
    classify_layer,
    classify_layers,
)


def _spec(**kw):
    base = {"id": 1, "family": "sql_injection", "verification_status": "unconfirmed",
            "iast_state": "", "failure_attribution": "", "raw_json": "{}"}
    base.update(kw)
    return base


class TestClassifyLayer:
    def test_confirmed_returns_empty(self):
        for st in ("confirmed_exploitable", "confirmed_code_property",
                   "confirmed_sink_control", "filtered_not_exploitable"):
            layer, _ = classify_layer(_spec(verification_status=st))
            assert layer == "", "已确认的 spec 不应有阶段归因"

    def test_payload_unavailable_is_layer1(self):
        layer, reason = classify_layer(_spec(iast_state="payload_unavailable"))
        assert layer == LAYER_SPEC
        assert "载荷" in reason

    def test_no_payload_attribution_is_layer1(self):
        layer, _ = classify_layer(_spec(failure_attribution="no_payload_synthesized"))
        assert layer == LAYER_SPEC

    def test_zero_attempts_without_payload_is_layer1(self):
        """零重放且无弹药 ⇒ A2 的锅（没弹药所以没发），不是 D1 不发。"""
        layer, _ = classify_layer(_spec(iast_state="no-arrival"), attempts=[])
        assert layer == LAYER_SPEC

    def test_zero_attempts_with_payload_is_layer2(self):
        """零重放但声明了弹药 ⇒ D1 的锅。"""
        layer, reason = classify_layer(
            _spec(iast_state="no-arrival", attack_payloads_json='["probe"]'), attempts=[])
        assert layer == LAYER_REPLAY
        assert "零重放" in reason

    def test_all_404_is_layer2(self):
        atts = [{"status_code": 404, "payload": "probe"}, {"status_code": 404, "payload": "probe"}]
        layer, reason = classify_layer(_spec(iast_state="sink-reached"), attempts=atts)
        assert layer == LAYER_REPLAY, "路由不通应判重放层，即使 iast 到过 sink"
        assert "404" in reason

    def test_200_then_sink_reached_is_layer3(self):
        atts = [{"status_code": 200, "payload": "probe"}]
        layer, reason = classify_layer(_spec(iast_state="sink-reached"), attempts=atts)
        assert layer == LAYER_VERDICT
        assert "判据" in reason

    def test_probe_sink_reached_is_layer3(self):
        layer, _ = classify_layer(_spec(iast_state="sink-reached-probe"), attempts=[{"status_code": 200, "payload": "probe"}])
        assert layer == LAYER_VERDICT

    def test_no_arrival_with_200_is_layer4(self):
        atts = [{"status_code": 200, "payload": "probe"}, {"status_code": 200, "payload": "probe"}]
        layer, reason = classify_layer(_spec(iast_state="no-arrival"), attempts=atts)
        assert layer == LAYER_IAST
        assert "未到" in reason

    def test_attempts_unknown_skips_layer2(self):
        """attempts=None 表示没查，不能误判成「零重放」。"""
        layer, _ = classify_layer(_spec(iast_state="sink-reached"), attempts=None)
        assert layer == LAYER_VERDICT

    def test_empty_iast_state_falls_back_to_iast(self):
        layer, _ = classify_layer(_spec(iast_state=""), attempts=[{"status_code": 200, "payload": "probe"}])
        assert layer == LAYER_IAST, "证据缺失归观测层（最保守）"

    def test_non_dict_returns_empty(self):
        assert classify_layer(None) == ("", "")


class TestClassifyLayers:
    def test_counts_and_rows(self):
        specs = [
            _spec(id=1, iast_state="payload_unavailable"),
            _spec(id=2, iast_state="sink-reached"),
            _spec(id=3, iast_state="no-arrival"),
            _spec(id=4, verification_status="confirmed_exploitable"),
        ]
        att = {2: [{"status_code": 200, "payload": "probe"}], 3: [{"status_code": 200, "payload": "probe"}]}
        res = classify_layers(specs, att)
        assert res["counts"][LAYER_SPEC] == 1
        assert res["counts"][LAYER_VERDICT] == 1
        assert res["counts"][LAYER_IAST] == 1
        assert sum(res["counts"].values()) == 3, "已确认的不计数"
        assert all(set(r) >= {"id", "layer", "reason"} for r in res["rows"])
        assert set(ALL_LAYERS) == {LAYER_SPEC, LAYER_REPLAY, LAYER_VERDICT, LAYER_IAST}
