"""IAST 事件 ingest 吞吐指标（item 4 方向 5：可观测性）。

进程级单例：ingest_events 是后端唯一写 iast_events 的入口，指标与 IastService 实例
生命周期解耦，确保多 worker / 重启之间持续累计。指标只做只读累加，不参与任何落库契约，
不改变 ingest_events 的同步返回语义（accepted / rejected / session_id / errors）。

指标含义（对应方案文档「方向 5」）：
- total_received / total_accepted / total_rejected：入口接收 / 鉴权通过 / 鉴权失败事件数。
- total_dup_skipped：被幂等去重静默丢弃的事件数（与原语义一致，仍计入 accepted）。
- total_written：实际落库 iast_events 的行数。
- pending_depth：当前正在刷盘的事件数（背压深度的瞬时值）。
- last_batch_size / last_flush_ms：最近一批大小 / 该批「解析+落库」总耗时(ms)。注意计时起点在
  解析之前——只计刷盘会得到虚高排空速率。
- last_drain_rate：排空速率(条/秒)，按进入流水线的事件数计（真实流量去重率极高，故不按写行数）。
- last_write_rate：落库速率(条/秒)，按实际写入 iast_events 的行数计。
- flushes：刷盘次数。
- backpressure_windows：单次刷盘耗时超阈值（后端成为限速点）的窗口数（对应方向 2「背压」信号）。
"""
import os
import threading
import time
from typing import Dict, Any

# 速率计算的计时分辨率下限（ms）。仅用于保证「确实发生了刷盘」时速率有限且非 0，
# 不参与 last_flush_ms 的上报（后者始终是原始测量值）。详见 record_flush 的说明。
_MIN_FLUSH_MS = 0.001

# 背压窗口告警阈值。单次刷盘耗时超 200ms 的窗口累积超过该值即视为「摄取限速」，
# 在前端标红（不静默）。阈值可通过环境变量调整（突发重放调大、常态调小）。
_BACKPRESSURE_ALERT_WINDOWS = float(os.environ.get("SAST_AI_BACKPRESSURE_ALERT_WINDOWS", "5"))


class IngestMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_received = 0
        self.total_accepted = 0
        self.total_rejected = 0
        self.total_dup_skipped = 0
        self.total_written = 0
        self.pending_depth = 0
        self.last_batch_size = 0
        self.last_flush_ms = 0.0
        self.last_drain_rate = 0.0
        self.last_write_rate = 0.0
        self.flushes = 0
        self.backpressure_windows = 0
        # 摄取限速告警位（背压窗口超阈值即置位，快照返回给前端标红，绝不静默）。
        self.ingest_throttled = False
        self.last_flush_at = 0.0

    def record_received(self, n: int) -> None:
        with self._lock:
            self.total_received += n

    def record_accepted(self, n: int) -> None:
        with self._lock:
            self.total_accepted += n

    def record_rejected(self, n: int) -> None:
        with self._lock:
            self.total_rejected += n

    def record_dup_skipped(self, n: int) -> None:
        with self._lock:
            self.total_dup_skipped += n

    def record_written(self, n: int) -> None:
        with self._lock:
            self.total_written += n

    def record_pending(self, depth: int) -> None:
        with self._lock:
            self.pending_depth = depth

    def record_flush(self, batch_size: int, written: int, flush_ms: float) -> None:
        with self._lock:
            self.flushes += 1
            self.last_batch_size = batch_size
            self.last_flush_ms = flush_ms
            self.last_flush_at = time.time()
            # 排空速率必须按「进入流水线处理的事件数」而非「实际写入行数」计算：
            # 运维会误判吞吐崩了。written 单独出 last_write_rate 反映真实落库速率。
            #
            # 触发背景：F2 的连接复用把单次查询开销从 792µs 降到 5µs，小批次真实耗时首次落到
            # 时钟可测范围以下（time.time 在 Windows 粒度约 15.6ms），旧式 `if flush_ms > 0
            # else 0.0` 会输出 0 条/秒 —— 与上面那条已修的「全去重批次显示 0」是同一类误判，
            # 只是触发路径不同。计时器已换 perf_counter（见 service.ingest_events），此处再设
            # 1µs 的下限兜底：低于该值的只有当批条数极少（单测量级）时才可能出现，真实负载批次
            # （数十~数百条）不会命中；且 last_flush_ms 仍上报原始测量值，不掩盖真实耗时。
            effective_ms = flush_ms if flush_ms >= _MIN_FLUSH_MS else _MIN_FLUSH_MS
            self.last_drain_rate = batch_size / effective_ms * 1000.0
            self.last_write_rate = written / effective_ms * 1000.0
            # 背压窗口：单次刷盘耗时超过 200ms 视为后端成为限速点（探针侧会因此变慢，
            # 而非丢失数据——方向 2 的「背压降速」语义：宁可变慢不丢）。
            if flush_ms >= 200.0:
                self.backpressure_windows += 1
                # 背压窗口累积达阈值 → 置摄取限速告警位（前端标红，不静默）。
                if self.backpressure_windows >= _BACKPRESSURE_ALERT_WINDOWS:
                    self.ingest_throttled = True

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_received": self.total_received,
                "total_accepted": self.total_accepted,
                "total_rejected": self.total_rejected,
                "total_dup_skipped": self.total_dup_skipped,
                "total_written": self.total_written,
                "pending_depth": self.pending_depth,
                "last_batch_size": self.last_batch_size,
                "last_flush_ms": round(self.last_flush_ms, 2),
                "last_drain_rate": round(self.last_drain_rate, 1),
                "last_write_rate": round(self.last_write_rate, 1),
                "flushes": self.flushes,
                "backpressure_windows": self.backpressure_windows,
                "backpressure_threshold": _BACKPRESSURE_ALERT_WINDOWS,
                "ingest_throttled": self.ingest_throttled,
                "last_flush_at": self.last_flush_at,
            }


# 进程级单例（与 IastService 实例生命周期解耦）
INGEST_METRICS = IngestMetrics()
