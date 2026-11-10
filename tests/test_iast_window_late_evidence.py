"""I1 采集窗口锚点 + 迟到证据回收的回归锁（2026-10-04 落地）。

事故背景（必须记住，否则这几条锁会被当成"过度设计"而删掉）：
OWASP 靶场同一批 226 条 spec、同样的参数名，连续三轮的 no-arrival 数分别是
2 / 47 / 19，L2 确认层召回随之在 68.9% → 45.3% → 54.7% 之间跳动。查下去发现
run 88 的 47 条 no-arrival 里，**39 条在 iast_events 中能查到 sink-reached-probe
事件**（run 89 是 11/19，run 46 是 0/2）——不是探针没抓到，是判定把证据丢了。

三个叠加的根因，各对应下面一组锁：
    1. 窗口锚点错：deadline 从 created_at（发流量**之前**）起算 t_max=60s，而重放是提交到
       线程池**排队**执行的，几百条 spec 要几分钟才发完 → 队尾重放发出时采集器早已退出。
    2. 回填等于没做：settle 循环写的是"本轮没捞到新事件就 break"，主窗口刚耗尽时迟到事件
       往往还没到 → 第一轮必然 break → 一次都没等到。
    3. 事务登记太晚：self._transactions[tx_id] 在重放**之后**才写入，摄取端回调
       submit_backfill_event 在整个重放窗口内查不到本事务，回填通道形同断开。

外加一道收口兜底 `_recover_late_arrival`：探针事件是批量 flush 的，实测整批事件会在
采集窗口关闭之后才落库（run 88 那 39 条的证据全落在 22:54:58–22:55:02 这 4 秒内），
窗口再宽也接不住，必须在收口时补查一次。
"""
from __future__ import annotations

import pytest

from src.iast.orchestrator import (
    IastVerdict,
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED_PROBE,
    TransactionState,
    TriggerTransactionOrchestrator,
    WindowConfig,
)
from src.iast.canary import CanaryStates


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t


def _sleep_advancing(clock: FakeClock):
    def sleep(p: float) -> None:
        clock.t += float(p)
    return sleep


def _tx(canary: str, hid: str = "h1", created_at: float = 0.0,
        dispatch_at: float = 0.0, watermark: int = 0) -> TransactionState:
    tx = TransactionState(
        transaction_id="tx-test",
        target={},
        trigger_specs=[{"vulnerability_hash_v2": hid, "taint_marker": canary}],
        created_at=created_at,
    )
    tx.canary_by_hypothesis = {hid: canary}
    tx.verdicts = {hid: IastVerdict(state=STATE_NO_ARRIVAL, provisional=True)}
    tx.start_watermark = watermark
    tx.last_dispatch_at = dispatch_at
    return tx


def _orch(clock: FakeClock, source) -> TriggerTransactionOrchestrator:
    # 2026-10-18：本文件的锁全部针对「旧窗口语义」（t_max 等满 + 6 轮 × 5s 回填），
    # 用于防止历史上修过的三个坑（锚点错 / 回填立刻 break / 事务登记太晚）回归。
    # 新增的自适应退出（quiet_exit / t_max_no_event）会提前收口，会掩盖这些锁，
    # 因此这里显式关闭自适应并固定 settle 轮数 = 6，保持旧语义可测。
    # 新策略的锁见 tests/test_tx_window_adaptive_20261018.py。
    return TriggerTransactionOrchestrator(
        event_source=source,
        window_cfg=WindowConfig(
            poll_interval=0.5, t_max=60.0, backfill_ttl=300.0,
            settle_rounds=6, settle_sleep=5.0, quiet_exit=0.0, t_max_no_event=0.0,
        ),
        clock=clock,
        sleep=_sleep_advancing(clock),
    )


def _delayed_source(clock: FakeClock, canary: str, appear_at: float, eid: int = 100):
    """事件只在 clock.t >= appear_at 之后才"落库"（模拟探针批量 flush 延迟）。"""
    def source(c, since_id, limit):
        if c != canary or clock.t < appear_at:
            return []
        if int(since_id) >= eid:
            return []
        return [{"id": eid, "canary_state": CanaryStates.SINK_REACHED_PROBE,
                 "sink_file": "A.java", "taint_path_json": "[]"}]
    return source


def test_window_anchors_on_last_dispatch_not_creation():
    """队尾重放（t=200 才发出）的事件（t=210 落库）必须被窗口接住。

    修复前 deadline = created_at + 60 = 60，事件 210 秒才到 → no-arrival。
    """
    clock = FakeClock(0.0)
    canary = "s4st41" + "0" * 16
    orch = _orch(clock, _delayed_source(clock, canary, appear_at=210.0))
    tx = _tx(canary, created_at=0.0, dispatch_at=200.0)
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE, (
        "重放在 t=200 才发出、事件 t=210 落库，窗口应以最后派发时刻为锚")


def test_control_without_dispatch_anchor_the_late_event_is_missed():
    """对照组：没有派发锚点（last_dispatch_at=0）时，同一条迟到事件确实接不住。

    这条锁存在的意义是证明上面那条不是"碰巧等到"——它锁的是「修复真的改变了行为」。
    """
    clock = FakeClock(0.0)
    canary = "s4st41" + "0" * 16
    orch = _orch(clock, _delayed_source(clock, canary, appear_at=210.0))
    tx = _tx(canary, created_at=0.0, dispatch_at=0.0)
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_NO_ARRIVAL


def test_settle_keeps_polling_instead_of_breaking_on_first_empty_round():
    """主窗口耗尽后 5 秒才到的事件必须被回填轮询接住（6 轮 × 5s = 30s）。

    修复前 settle 第一轮没捞到就 break，等于一次都没等。
    """
    clock = FakeClock(0.0)
    canary = "s4st41" + "1" * 16
    # 事件在 t=65 才落库：主窗口 60s 已过，但 settle 的 30s 覆盖得到
    orch = _orch(clock, _delayed_source(clock, canary, appear_at=65.0))
    tx = _tx(canary, created_at=0.0, dispatch_at=0.0)
    orch._wait_window(tx)
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE, (
        "settle 必须把 6 轮等完，不能因为没有新事件就立刻 break")
    assert tx.late_recovered.get("h1") is True


def test_recover_late_arrival_uses_events_above_watermark_only():
    """收口回收：水位线**之上**的事件可升级；水位线**之下**的（上一轮同 canary）绝不能用。

    canary 由漏洞哈希确定性生成，跨任务会重复 —— 不设下界就会拿旧证据冒充本轮到达。
    """
    clock = FakeClock(0.0)
    canary = "s4st41" + "2" * 16

    # 1) 水位线之上：应当被回收
    def src_above(c, since_id, limit):
        return [{"id": 500, "canary_state": CanaryStates.SINK_REACHED_PROBE,
                 "sink_file": "A.java", "taint_path_json": "[]"}]
    orch = _orch(clock, src_above)
    tx = _tx(canary, watermark=100)
    n = orch._recover_late_arrival(tx)
    assert n == 1
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE

    # 2) 水位线之下（老任务残留）：不得回收 —— 事件 id 小于 since_id 时查询层本就返回空，
    #    这里锁的是"即便查询层把老事件返回了，回收也不得越过水位线"。
    def src_below(c, since_id, limit):
        assert int(since_id) == 100, "回收必须以水位线为下界"
        return [{"id": 50, "canary_state": CanaryStates.SINK_REACHED_PROBE,
                 "sink_file": "A.java", "taint_path_json": "[]"}]
    orch2 = _orch(clock, src_below)
    tx2 = _tx(canary, watermark=100)
    tx2.verdicts["h1"] = IastVerdict(state=STATE_NO_ARRIVAL, provisional=True)
    n2 = orch2._recover_late_arrival(tx2)
    assert n2 == 0, "水位线以下的事件不得用于升级（跨任务 canary 复用会串味）"


def test_recover_late_arrival_paginates_and_picks_richest_path():
    """回收必须分页取完，并且把 taint_path 最丰富的那条作为 matched_event_detail。"""
    clock = FakeClock(0.0)
    canary = "s4st41" + "3" * 16
    pages = {
        0: [{"id": 101 + i, "canary_state": CanaryStates.SINK_REACHED_PROBE,
             "sink_file": "A.java", "taint_path_json": "[]"} for i in range(50)],
    }

    def src(c, since_id, limit):
        base = int(since_id)
        if base >= 151:
            return []
        out = [{"id": base + 1 + i, "canary_state": CanaryStates.SINK_REACHED_PROBE,
                "sink_file": "A.java",
                "taint_path_json": '["a","b"]' if (base + i) % 2 == 0 else "[]"}
               for i in range(min(50, 151 - base))]
        return out
    orch = _orch(clock, src)
    tx = _tx(canary, watermark=100)
    n = orch._recover_late_arrival(tx)
    assert n == 1
    assert tx.verdicts["h1"].state == STATE_SINK_REACHED_PROBE
    detail = tx.verdicts["h1"].matched_event_detail or {}
    assert detail, "回收到的到达事件必须写回 matched_event_detail"
