"""Q9 测试：摄取侧背压告警位 + 闭环重放/摄取差值告警。

Q9 本质：SAVR 摄取侧已是「阻塞不丢」（串行刷盘 + 背压降速），故本仓库只做两件事并
保证不静默——(a) 背压窗口超阈值时置 ingest_throttled 告警位（前端标红）；(b) D2 重验后
核对「发出重放数 vs 收到 IAST 事件数」差值，超容差即记录可见告警，暴露探针侧丢事件。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBackpressureAlertFlag:
    def test_throttled_set_when_windows_exceed_threshold(self):
        from src.iast.ingest_metrics import IngestMetrics
        m = IngestMetrics()
        # 阈值默认 5：连续 6 次超 200ms 刷盘应置位 ingest_throttled。
        for _ in range(6):
            m.record_flush(10, 10, 250.0)
        assert m.backpressure_windows == 6
        assert m.ingest_throttled is True
        snap = m.snapshot()
        assert snap["ingest_throttled"] is True
        assert "backpressure_threshold" in snap

    def test_not_throttled_below_threshold(self):
        from src.iast.ingest_metrics import IngestMetrics
        m = IngestMetrics()
        for _ in range(3):  # 未超阈值
            m.record_flush(10, 10, 250.0)
        assert m.ingest_throttled is False
        assert m.backpressure_windows == 3

    def test_normal_flush_no_backpressure(self):
        from src.iast.ingest_metrics import IngestMetrics
        m = IngestMetrics()
        m.record_flush(10, 10, 5.0)  # 远小于 200ms
        assert m.backpressure_windows == 0
        assert m.ingest_throttled is False

    def test_threshold_env_respected(self, monkeypatch):
        # 把阈值调成 1，1 次背压即告警。
        monkeypatch.setenv("SAST_AI_BACKPRESSURE_ALERT_WINDOWS", "1")
        import importlib
        from src.iast import ingest_metrics
        importlib.reload(ingest_metrics)
        m = ingest_metrics.IngestMetrics()
        m.record_flush(10, 10, 300.0)
        assert m.ingest_throttled is True
        assert m.snapshot()["backpressure_threshold"] == 1.0
        # 复位环境变量，避免污染其它用例（reload 回默认）。
        monkeypatch.setenv("SAST_AI_BACKPRESSURE_ALERT_WINDOWS", "5")
        importlib.reload(ingest_metrics)


class _FakeDB:
    """按 SQL 关键字返回配置好的计数，并记录 INSERT 的告警事件。"""

    def __init__(self, replayed=0, specs=0, events=0, no_arrival=0):
        self.replayed = replayed
        self.specs = specs
        self.events = events
        self.no_arrival = no_arrival
        self.recorded = []

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        s = sql
        if "iast_state IS NULL" in s or "no-arrival" in s:
            return {0: self.no_arrival}
        if "iast_events WHERE task_id" in s:
            return {0: self.events}
        if "FROM trigger_specs WHERE task_id" in s:
            return {0: self.specs}
        if "COALESCE(replayed_count" in s:
            return {"replayed_count": self.replayed}
        if "INSERT INTO scan_task_events" in s:
            self.recorded.append(params)
            return None
        return {}


class TestReplayIngestGap:
    def test_hard_alert_zero_events_after_replays(self):
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        db = _FakeDB(replayed=10, specs=10, events=0, no_arrival=10)
        out = reconcile_replay_ingest_gap(db, 7)
        assert out["alert"] is True
        assert out["severity"] == "hard"
        assert out["replayed_count"] == 10
        assert out["iast_event_count"] == 0
        # 告警落库（不静默）：params = (task_id, payload_json)，event_type 烤进 SQL。
        assert len(db.recorded) == 1
        assert db.recorded[0][0] == 7
        import json as _json
        _payload = _json.loads(db.recorded[0][1])
        assert _payload["severity"] == "hard"

    def test_soft_alert_low_recovery_high_noarrival(self):
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        # 回收率 5/100=0.05 < 0.1，且 no-arrival 80/100 >= 0.5 → 软告警。
        db = _FakeDB(replayed=100, specs=100, events=5, no_arrival=80)
        out = reconcile_replay_ingest_gap(db, 8)
        assert out["alert"] is True
        assert out["severity"] == "soft"
        assert out["recovery_ratio"] == pytest.approx(0.05, abs=1e-6)

    def test_no_alert_healthy_recovery(self):
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        db = _FakeDB(replayed=100, specs=100, events=90, no_arrival=5)
        out = reconcile_replay_ingest_gap(db, 9)
        assert out["alert"] is False
        assert out["severity"] == "ok"
        assert db.recorded == []

    def test_no_alert_low_recovery_but_low_noarrival(self):
        # 事件少但 no-arrival 也少（可能探针侧正常、靶场确实多无到达）→ 不误报。
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        db = _FakeDB(replayed=100, specs=100, events=5, no_arrival=10)
        out = reconcile_replay_ingest_gap(db, 10)
        assert out["alert"] is False

    def test_replayed_fallback_to_specs_when_zero(self):
        # D2 路径未回填 replayed_count 时，用 spec 条数还原发出重放数。
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        db = _FakeDB(replayed=0, specs=40, events=0, no_arrival=40)
        out = reconcile_replay_ingest_gap(db, 11)
        assert out["replayed_count"] == 40
        assert out["alert"] is True  # 40 重放 0 事件 → 硬告警

    def test_zero_replay_no_false_alert(self):
        from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
        db = _FakeDB(replayed=0, specs=0, events=0, no_arrival=0)
        out = reconcile_replay_ingest_gap(db, 12)
        assert out["alert"] is False
        assert out["replayed_count"] == 0
