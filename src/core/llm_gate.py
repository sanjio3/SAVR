"""跨 stage 全局 LLM 并发闸门（准入控制）。

问题背景：`ModelGateway.complete_batch` 全项目零调用点，真实并发来自各 stage 各自的线程池——
A2 `llm_concurrency=10`、`a2_contract_planner` 默认 10（上限 16）、D1 自适应闸门 12，
彼此不知道对方存在，瞬时 LLM 并发可以叠到 20+。

后果分两种：
- 云端：撞配额 → 429 → 冷却回落备用 provider（历史故障链就是这样形成的）；
- 本地 Ollama：`OLLAMA_NUM_PARALLEL=2` 时并发再多也不会增加吞吐，只会线性拉长排队，
  再叠加 FallbackLLMClient 的 provider×attempts 放大（单次逻辑调用最多 6 次 HTTP），
  队列会被自己打满。

所以正确的做法不是「提高并发能力」（asyncio 的卖点），而是**准入控制**：
超出后端承载力的请求就排队等着，别把压力转嫁给 provider。

本模块是一个进程内单例同时提供：

1. 并发闸门 `acquire`：所有 provider 客户端在发起请求前取票；
2. 可选的令牌桶限速 `tokens_per_minute`：挡住短时间突发；
3. 排队可观测：等待时长、排队深度、拒绝数——没有这三项，调本地模型时无法判断
   「是模型慢」还是「是我们把队列挤爆了」。

宽度可按 model_capabilities 的 recommended_concurrency 自适应，
也可用环境变量 `SAST_AI_LLM_GATE_CONCURRENCY` 直接指定（本地拉起时常用）。
"""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional


@dataclass
class GateStats:
    """闸门运行指标。用于日志与运维观测。"""

    width: int = 0
    in_flight: int = 0
    acquired_total: int = 0
    timed_out_total: int = 0
    wait_ms_total: int = 0
    peak_wait_ms: int = 0
    peak_in_flight: int = 0

    def as_dict(self) -> Dict[str, Any]:
        avg_wait = 0
        if self.acquired_total:
            avg_wait = self.wait_ms_total // self.acquired_total
        return {
            "width": self.width,
            "in_flight": self.in_flight,
            "acquired_total": self.acquired_total,
            "timed_out_total": self.timed_out_total,
            "avg_wait_ms": avg_wait,
            "peak_wait_ms": self.peak_wait_ms,
            "peak_in_flight": self.peak_in_flight,
        }


class LLMRateGate:
    """进程级 LLM 并发闸门 + 可选令牌桶。

    线程安全；惰性构造（import 无副作用）。所有 provider 客户端统一在
    `request_chat_completion` 入口调用 `acquire`，从而覆盖到每一条调用路径。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._width = self._default_width()
        self._sem = threading.Semaphore(self._width)
        self._tokens_per_minute = int(os.environ.get("SAST_AI_LLM_TPM", "0") or 0)
        self._tokens = float(self._tokens_per_minute or 0)
        self._token_lock = threading.Lock()
        self._token_updated = time.monotonic()
        self._stats = GateStats(width=self._width)

    @staticmethod
    def _default_width() -> int:
        env = (os.environ.get("SAST_AI_LLM_GATE_CONCURRENCY") or "").strip()
        if env:
            try:
                return max(1, int(env))
            except ValueError:
                pass
        # 默认 8：既不至于让云端 429，也够本地小模型的物理并发（再高只是排队）
        return 8

    # ---- 配置 ----
    def configure(self, width: Optional[int] = None, tokens_per_minute: Optional[int] = None) -> None:
        """调整闸门宽度/限速。宽度变更只影响之后新取的票，进行中的请求不受打扰。"""
        with self._lock:
            if width and width > 0:
                delta = width - self._width
                self._width = width
                self._stats.width = width
                if delta > 0:
                    for _ in range(delta):
                        self._sem.release()
                elif delta < 0:
                    for _ in range(-delta):
                        if not self._sem.acquire(blocking=False):
                            break
            if tokens_per_minute is not None:
                self._tokens_per_minute = max(0, int(tokens_per_minute))
                self._tokens = float(self._tokens_per_minute)

    def configure_for_concurrency(self, recommended: int) -> None:
        """按模型画像推荐的并发数收敛闸门宽度（取较小值，绝不把宽度调大）。"""
        try:
            target = max(1, int(recommended or 0))
        except (TypeError, ValueError):
            return
        if target < self._width:
            self.configure(width=target)

    # ---- 令牌桶 ----
    def _take_token(self) -> float:
        """消耗一个令牌，返回需要等待的秒数（0 表示立即可用）。"""
        if self._tokens_per_minute <= 0:
            return 0.0
        with self._token_lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._token_updated)
            refill = elapsed * (self._tokens_per_minute / 60.0)
            self._tokens = min(float(self._tokens_per_minute), self._tokens + refill)
            self._token_updated = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            wait = (1.0 - self._tokens) / (self._tokens_per_minute / 60.0)
            return wait

    # ---- 核心 ----
    @contextmanager
    def acquire(self, timeout: float = 0.0) -> Iterator[bool]:
        """取票进入调用。timeout<=0 表示无限等待（由外层总超时兜住）。

        用法：
            with llm_gate.acquire(timeout=30) as admitted:
                if not admitted:
                    raise TimeoutError(...)
                ...

        注意这里刻意用「超时返回 False」而不是抛异常：调用方（FallbackLLMClient）
        需要把它当成一次可重试的失败来处置。
        """
        wait_started = time.monotonic()
        token_wait = self._take_token()
        if token_wait > 0:
            time.sleep(min(token_wait, 5.0))

        if timeout and timeout > 0:
            got = self._sem.acquire(blocking=True, timeout=timeout)
        else:
            self._sem.acquire()
            got = True

        wait_ms = int((time.monotonic() - wait_started) * 1000)
        if not got:
            with self._lock:
                self._stats.timed_out_total += 1
            yield False
            return

        with self._lock:
            st = self._stats
            st.in_flight += 1
            st.acquired_total += 1
            st.wait_ms_total += wait_ms
            st.peak_wait_ms = max(st.peak_wait_ms, wait_ms)
            st.peak_in_flight = max(st.peak_in_flight, st.in_flight)
        try:
            yield True
        finally:
            self._sem.release()
            with self._lock:
                self._stats.in_flight = max(0, self._stats.in_flight - 1)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return self._stats.as_dict()


_gate: Optional[LLMRateGate] = None
_gate_lock = threading.Lock()


def get_gate() -> LLMRateGate:
    """获取进程级闸门单例。"""
    global _gate
    if _gate is None:
        with _gate_lock:
            if _gate is None:
                _gate = LLMRateGate()
    return _gate


def configure_gate(width: Optional[int] = None, tokens_per_minute: Optional[int] = None) -> None:
    get_gate().configure(width=width, tokens_per_minute=tokens_per_minute)


def gate_stats() -> Dict[str, Any]:
    return get_gate().stats()
