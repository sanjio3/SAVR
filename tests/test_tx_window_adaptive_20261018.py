"""I1 采集窗口「自适应退出」策略锁（2026-10-18 速度治理）。

背景：r108 实测 D2 阶段占单分片墙钟 78%（11.6min / 15.1min）。原窗口策略是
「只要批内还有假说没到 sink，就把 t_max=60s 等满，再等 6×5s=30s 回填」，
即每个事务最坏 90s；而探针 EventBuffer 的 flush 周期只有 250ms，60s 属于过量。

新策略（全部可用 env 覆盖，置 0 即回到旧行为）：
    t_max          60 → 45
    settle_rounds   6 → 3（30s → 15s）
    quiet_exit     新增 12s：本事务收到过事件后连续静默 12s → 提前收口
    t_max_no_event 新增 25s：本事务一条事件都没收到时，从最后一批重放发出起 25s 即退出
                   （靶场实测首次类加载最坏 13.7s，25s 仍留余量）

这里锁的是「新策略真的提前退出」+「能关掉」+「settle 轮数可配」，
防止后续有人把自适应退出写成恒开、或者把 settle 又写死回 6 轮。
旧窗口语义的回归锁仍在 tests/test_iast_window_late_evidence.py（那边显式关闭自适应）。
"""
from __future__ import annotations

import pytest

from src.iast.canary import CanaryStates
from src.iast.orchestrator import (
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED_PROBE,
    IastVerdict,
    TransactionState,
    TriggerTransactionOrchestrator,
    WindowConfig,
)


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t


def _sleep_advancing(clock: FakeClock):
    def sleep(p: float) -> None:
        clock.t += float(p)
    return sleep


def _tx(canaries: dict, created_at: float = 0.0, dispatch_at: float = 0.0) -> TransactionState:
    """canaries: {hid: canary}"""
    tx = TransactionState(
        transaction_id="tx-adaptive",
        target={},
        trigger_specs=[{"vulnerability_hash_v2": h, "taint_marker": c} for h, c in canaries.items()],
        created_at=created_at,
    )
    tx.canary_by_hypothesis = dict(canaries)
    tx.verdicts = {h: IastVerdict(state=STATE_NO_ARRIVAL, provisional=True) for h in canaries}
    tx.start_watermark = 0
    tx.last_dispatch_at = dispatch_at
    return tx


def _orch(clock: FakeClock, source, **cfg) -> TriggerTransactionOrchestrator:
    base = dict(poll_interval=0.5, t_max=45.0, backfill_ttl=300.0)
    base.update(cfg)
    return TriggerTransactionOrchestrator(
        event_source=source,
        window_cfg=WindowConfig(**base),
        clock=clock,
        sleep=_sleep_advancing(clock),
    )


def _source_at(clock: FakeClock, canary: str, appear_at: float, eid: int = 500):
    """该 canary 的事件在 clock.t >= appear_at 后只"落库"一次（游标推进后不再返回）。"""
    def source(c, since_id, limit):
        if c != canary or clock.t < appear_at:
            return []
        if int(since_id) >= eid:
            return []
        return [{"id": eid, "canary_state": CanaryStates.SINK_REACHED_PROBE,
                 "sink_file": "A.java", "taint_path_json": "[]"}]
    return source


# ---------------------------------------------------------------- 配置层

def test_window_config_new_defaults():
    w = WindowConfig()
    assert w.t_max == 45.0, "t_max 默认应为 45（原 60）"
    assert w.settle_rounds == 3, "settle_rounds 默认应为 3（原硬编码 6）"
    assert w.quiet_exit == 12.0
    assert w.t_max_no_event == 25.0


def test_window_config_env_overrides(monkeypatch):
    monkeypatch.setenv("SAST_AI_TX_TMAX", "30")
    monkeypatch.setenv("SAST_AI_TX_SETTLE_ROUNDS", "1")
    monkeypatch.setenv("SAST_AI_TX_SETTLE_SLEEP", "2.5")
    monkeypatch.setenv("SAST_AI_TX_QUIET_EXIT", "0")
    monkeypatch.setenv("SAST_AI_TX_TMAX_NO_EVENT", "8")
    w = WindowConfig()
    assert (w.t_max, w.settle_rounds, w.settle_sleep, w.quiet_exit, w.t_max_no_event) == (
        30.0, 1, 2.5, 0.0, 8.0)


def test_window_config_env_bad_value_falls_back(monkeypatch):
    monkeypatch.setenv("SAST_AI_TX_TMAX", "not-a-number")
    assert WindowConfig().t_max == 45.0


# ---------------------------------------------------------------- 自适应退出

def test_quiet_exit_fires_when_some_hypothesis_still_missing():
    """一半假说已到达、另一半永远不来 → 静默 12s 即收口，不再等满 t_max=45s。"""
    clock = FakeClock(0.0)
    c1, c2 = "s4st41" + "a" * 16, "s4st41" + "b" * 16
    orch = _orch(clock, _source_at(clock, c1, appear_at=3.0), settle_rounds=0)
    tx = _tx({"h1": c1, "h2": c2})
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE
    assert tx.verdicts["h2"].state == STATE_NO_ARRIVAL
    assert 10.0 <= clock.t <= 20.0, f"应在 ~15s 收口，实际 {clock.t}"


def test_zero_event_cap_fires_when_nothing_arrives():
    """全程零事件（典型的「注入点根本不存在」FP 用例）→ 25s 即退出，不再等满 45s。"""
    clock = FakeClock(0.0)
    c1 = "s4st41" + "c" * 16
    orch = _orch(clock, lambda c, s, l: [], settle_rounds=0)
    tx = _tx({"h1": c1})
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_NO_ARRIVAL
    assert 24.0 <= clock.t <= 26.0, f"应在 ~25s 收口，实际 {clock.t}"


def test_adaptive_exits_disabled_waits_full_tmax():
    """两个自适应退出置 0 → 完全回到旧行为（等满 t_max）。"""
    clock = FakeClock(0.0)
    c1 = "s4st41" + "d" * 16
    orch = _orch(clock, lambda c, s, l: [], settle_rounds=0,
                 quiet_exit=0.0, t_max_no_event=0.0)
    tx = _tx({"h1": c1})
    orch._wait_window(tx)
    assert clock.t >= 44.0, f"关闭自适应后应等满 45s，实际 {clock.t}"


def test_all_arrived_early_exit_still_wins():
    """全部假说到达 sink 时，原有「全到达早停」必须优先于任何自适应逻辑。"""
    clock = FakeClock(0.0)
    c1 = "s4st41" + "e" * 16
    orch = _orch(clock, _source_at(clock, c1, appear_at=2.0), settle_rounds=0)
    tx = _tx({"h1": c1})
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE
    assert clock.t <= 5.0, f"全到达应早停，实际 {clock.t}"


# ---------------------------------------------------------------- settle 可配

def test_settle_rounds_configurable_catches_late_event():
    """3 轮 × 5s = 15s 回填：t=30 落库的事件（主窗口 20s 已过）应被接住。"""
    clock = FakeClock(0.0)
    c1 = "s4st41" + "f" * 16
    orch = _orch(clock, _source_at(clock, c1, appear_at=30.0),
                 t_max=20.0, settle_rounds=3, settle_sleep=5.0,
                 quiet_exit=0.0, t_max_no_event=0.0)
    tx = _tx({"h1": c1})
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE
    assert tx.late_recovered.get("h1") is True


def test_settle_rounds_one_misses_far_late_event():
    """对照组：只有 1 轮回填时，同一迟到事件接不住 —— 证明轮数真的起作用。"""
    clock = FakeClock(0.0)
    c1 = "s4st41" + "9" * 16
    orch = _orch(clock, _source_at(clock, c1, appear_at=30.0),
                 t_max=20.0, settle_rounds=1, settle_sleep=5.0,
                 quiet_exit=0.0, t_max_no_event=0.0)
    tx = _tx({"h1": c1})
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_NO_ARRIVAL


def test_no_event_cap_anchors_on_last_dispatch_not_first():
    """回归锁：零事件 cap 必须锚在**最后一批重放发出**时刻。

    采集线程在发流量之前就启动（run_transaction 先起 collector 再发 replay），
    所以 last_dispatch_at 在采集期间持续前进。若锚点用循环外捕获的初值（created_at=0），
    队尾重放的窗口会被前几批"提前用完"——这是 2026-10-18 修掉的真实缺陷。
    """
    clock = FakeClock(0.0)
    c1 = "sst41" + "7" * 17
    tx = _tx({"h1": c1})

    def sleep_and_dispatch(p: float) -> None:
        clock.t += float(p)
        # 前 10 次睡眠期间持续派发（模拟 28 条重放在线程池里陆续发出）
        if clock.t <= 5.0:
            tx.last_dispatch_at = clock.t

    orch = TriggerTransactionOrchestrator(
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(poll_interval=0.5, t_max=60.0, backfill_ttl=300.0,
                                settle_rounds=0, quiet_exit=0.0, t_max_no_event=25.0),
        clock=clock,
        sleep=sleep_and_dispatch,
    )
    orch._wait_window(tx)
    # 最后一次派发在 t=5，零事件 cap=25 ⇒ 应在 t≈30 退出，而不是 t≈25
    assert clock.t >= 29.0, f"锚点应跟随最后一次派发（期望 ~30s），实际 {clock.t}"
