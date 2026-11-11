"""靶场实例纪元（target instance epoch）——D2 批次隔离的判据底座。

--------------------
（16:59:30~17:34:35）的 D1/D2 重放窗口正落在该停机 + 启动区间内 —— 停机窗口内重放的
spec 拿不到任何证据，会被写成 no_evidence（「永久非漏洞」结论）；窗口边缘的结论也不可信。

50→8，整轮数字不可用）。

本模块只回答一个问题：**这一轮 D2 批次是否横跨了靶场实例重建？** 若横跨，则把落在
停机/恢复窗口内的 spec 标 invalidated（可重试），而不是记 confirmed / no_evidence。

判据（不依赖靶场侧任何改动，符合「靶场不能动」铁律）
--------------------------------------------------
① 进程纪元（权威源，psutil 可选）：监听目标端口进程的「创建时间」。
   JVM 重启 → 新进程 → 创建时间必变；同一实例内不受负载影响。
② 探针纪元（降级源，零新依赖）：iast_sessions.agent_phase 回退到 WARMING_UP、
   或 last_heartbeat_at 超期。探针随 JVM 重启会重新挂载并上报 WARMING_UP。

两者都取不到时 epoch 为空 = 「不可判定」——调用方**不得**据「不可判定」清空既有结论
（fail-safe：宁可不标，不可误标）。

纯函数 + 依赖注入（process_probe / http_probe / db / clock 全部可替），便于确定性单测。
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.iast.canary import is_sink_reached

logger = logging.getLogger(__name__)

# 采样间隔（秒）。进程探测是廉价的 psutil 调用，5s 一次对 D2 批次（约 10min）无感。
DEFAULT_INTERVAL = 5.0
# 探针会话「心跳超期」判定阈值（秒）。超过即视为探针不在线（靶场很可能已停）。
DEFAULT_HEARTBEAT_STALE_SEC = 45.0
# 连续 N 个坏样本才开一个停机窗口（防单次瞬时抖动误判）。
DEFAULT_CONFIRM_BAD = 2
# 连续 N 个好样本才关闭窗口（防恢复期抖动来回开关）。
DEFAULT_CONFIRM_GOOD = 2
# 停机窗口起点前推保护带（秒）：紧贴停机前完成的验证同样可疑（请求可能正是在
PRE_DOWN_GUARD_SEC = 15.0

_TARGET_UNHEALTHY_FALLBACK = frozenset({"target_unhealthy"})
_PROBE_BAD_PHASES = frozenset({"WARMING_UP", "STALE"})

# 「运行时已证实」的终态 / 裁决态 / IAST 观测态。三者任一命中即视为本条带正向证据：
# canary 抵达 sink 是**靶场内部探针**上报的，它本身就是「靶场当时存活」的证明，
# 与「靶场不健康」互斥。带正向证据的条目绝不允许落 invalidated。
_POSITIVE_FINAL_STATES = frozenset({
    "confirmed_attributable", "runtime_confirmed", "business_confirmed", "confirmed",
})
_POSITIVE_VERIF_STATES = frozenset({
    "confirmed_exploitable", "confirmed_sink_control", "exploitable", "confirmed",
    "confirmed_code_property",
})
_ARRIVAL_STATES = frozenset({
    "iast-reached", "iast-authz-confirmed", "sink-reached", "sink-reached-probe",
})



def _iso(ts: Optional[float]) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def port_of_url(target_url: str) -> Optional[int]:
    """从 URL 解析端口；无显式端口时按 scheme 取默认值。"""
    try:
        p = urlparse(str(target_url or ""))
        if p.port:
            return int(p.port)
        if p.scheme == "https":
            return 443
        if p.scheme == "http":
            return 80
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 默认探针实现（真实网络 / 真实进程，可注入替换）
# ---------------------------------------------------------------------------
def listening_pid(port: int, *, proc_iter: Optional[Callable[[], Any]] = None) -> Optional[int]:
    """返回监听指定 TCP 端口的进程 PID；查不到返回 None。

    psutil 缺失或权限不足（某些平台 net_connections 需管理员）→ 返回 None，
    由调用方降级到探针纪元，绝不让探测失败影响主流程。
    """
    if not port:
        return None
    try:
        import psutil  # 可选依赖：未安装即降级
    except Exception:
        return None
    try:
        conns = proc_iter() if proc_iter is not None else psutil.net_connections(kind="tcp")
    except Exception as exc:
        logger.debug("[target-epoch] net_connections 不可用（降级）：%s", exc)
        return None
    for c in conns or []:
        try:
            if getattr(c, "status", "") != psutil.CONN_LISTEN:
                continue
            laddr = getattr(c, "laddr", None)
            if not laddr or int(getattr(laddr, "port", 0) or 0) != int(port):
                continue
            pid = getattr(c, "pid", None)
            if pid:
                return int(pid)
        except Exception:
            continue
    return None


def process_instance_epoch(port: int, *, pid_lookup: Optional[Callable[[int], Optional[int]]] = None) -> Tuple[str, bool]:
    """进程纪元 = "pid:<pid>@<create_time>"；取不到返回 ("", False)。"""
    pid = pid_lookup(port) if pid_lookup is not None else listening_pid(port)
    if not pid:
        return "", False
    try:
        import psutil
        p = psutil.Process(int(pid))
        return "pid:%d@%.3f" % (int(pid), float(p.create_time())), True
    except Exception as exc:
        logger.debug("[target-epoch] 进程纪元不可用（降级）：%s", exc)
        return "", False


def http_liveness(target_url: str, *, timeout_ms: float = 2000.0) -> Tuple[Optional[int], bool]:
    """HTTP 存活探测：复用 A0 环境识别的候选路径与宽松判据。

    任一候选返回 2xx/3xx/4xx 即视为「应用已就绪」（4xx 含静态资源缺失，证明进程在
    服务请求）；连接失败 / 全候选持续 5xx → (code, False)。不读 body。
    """
    try:
        from src.iast.env_readiness import EnvCheckConfig, default_http_probe
    except Exception:  # pragma: no cover - 导入失败即视为不可探测
        return None, False
    cfg = EnvCheckConfig()
    base = str(target_url or "").rstrip("/")
    last_code: Optional[int] = None
    for cpath in cfg.probe_paths:
        url = base if cpath in ("", "/") else base + "/" + cpath.lstrip("/")
        try:
            code = int(default_http_probe(url, timeout_ms))
        except Exception:
            continue
        last_code = code
        if code not in cfg.target_down_codes:
            return code, True
    return last_code, False


# ---------------------------------------------------------------------------
# 采样与判定
# ---------------------------------------------------------------------------
@dataclass
class EpochSample:
    at: float
    epoch: str = ""            # 进程纪元；"" = 不可判定
    process_ok: bool = False
    service_ok: bool = False
    http_code: Optional[int] = None
    probe_phase: str = ""      # READY / WARMING_UP / STALE / UNKNOWN / ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at": _iso(self.at),
            "ts": self.at,
            "epoch": self.epoch,
            "process_ok": self.process_ok,
            "service_ok": self.service_ok,
            "http_code": self.http_code,
            "probe_phase": self.probe_phase,
        }


@dataclass
class DowntimeWindow:
    down_at: float
    up_at: Optional[float] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "down_at": _iso(self.down_at),
            "up_at": _iso(self.up_at) if self.up_at else None,
            "seconds": round((self.up_at or self.down_at) - self.down_at, 1),
            "reason": self.reason,
        }


class TargetEpochTracker:
    """D2 批次期间的靶场实例纪元跟踪器。

    用法：
        tr = TargetEpochTracker(service_url, app_name=..., agent_id=..., db=...)
        tr.start            # 批次起点基线（含可选后台采样线程）
        ... 批次执行 ...
        tr.stop
        tr.overlaps(t0, t1)   # 单 spec 是否落在停机/重启窗口内
        tr.report           # 落 summary / task_alert 的整批结论
    """

    def __init__(
        self,
        target_url: str,
        *,
        app_name: str = "",
        agent_id: str = "",
        db: Any = None,
        interval: float = DEFAULT_INTERVAL,
        heartbeat_stale_sec: float = DEFAULT_HEARTBEAT_STALE_SEC,
        confirm_bad: int = DEFAULT_CONFIRM_BAD,
        confirm_good: int = DEFAULT_CONFIRM_GOOD,
        pre_down_guard_sec: float = PRE_DOWN_GUARD_SEC,
        process_probe: Optional[Callable[[int], Tuple[str, bool]]] = None,
        http_probe: Optional[Callable[[str, float], Tuple[Optional[int], bool]]] = None,
        probe_phase_reader: Optional[Callable[[], str]] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.target_url = str(target_url or "")
        self.port = port_of_url(self.target_url)
        self.app_name = str(app_name or "")
        self.agent_id = str(agent_id or "")
        self.db = db
        self.interval = float(interval)
        self.heartbeat_stale_sec = float(heartbeat_stale_sec)
        self.confirm_bad = max(1, int(confirm_bad))
        self.confirm_good = max(1, int(confirm_good))
        self.pre_down_guard_sec = float(pre_down_guard_sec)
        self._process_probe = process_probe or (lambda port: process_instance_epoch(port))
        self._http_probe = http_probe or (lambda url, tms: http_liveness(url, timeout_ms=tms))
        self._probe_phase_reader = probe_phase_reader or self._read_probe_phase
        self._clock = clock

        self.samples: List[EpochSample] = []
        self.windows: List[DowntimeWindow] = []
        # baseline_epoch = 批次首个可用纪元（仅用于报告）；_active_epoch = 当前认定
        # 的「健康基线实例」，窗口关闭时采纳新实例，避免重启后把新实例永久判为坏。
        self.baseline_epoch = ""
        self._active_epoch = ""
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self._open: Optional[DowntimeWindow] = None
        self._bad_streak = 0
        self._bad_since: Optional[float] = None
        self._good_streak = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()

    # ---------------- 采样 ----------------
    def _read_probe_phase(self) -> str:
        if self.db is None or not self.app_name or not self.agent_id:
            return "UNKNOWN"
        try:
            row = self.db.execute(
                "SELECT agent_phase, last_heartbeat_at FROM iast_sessions "
                "WHERE app_name = ? AND agent_id = ? ORDER BY id DESC LIMIT 1",
                (self.app_name, self.agent_id),
                fetchone=True,
            )
        except Exception:
            return "UNKNOWN"
        if not row:
            return "UNKNOWN"
        rec = dict(row)
        phase = str(rec.get("agent_phase") or "").strip().upper()
        hb = str(rec.get("last_heartbeat_at") or "")
        if hb:
            try:
                age = self._clock() - datetime.fromisoformat(hb).replace(tzinfo=timezone.utc).timestamp()
                # iast_sessions 的时间戳由 datetime.utcnow 写入（无时区），按 UTC 解析。
                if age > self.heartbeat_stale_sec:
                    return "STALE"
            except Exception:
                pass
        if phase == "WARMING_UP":
            return "WARMING_UP"
        if phase:
            return phase
        return "UNKNOWN"

    def sample_once(self) -> EpochSample:
        epoch, proc_ok = ("", False)
        if self.port:
            try:
                epoch, proc_ok = self._process_probe(self.port)
            except Exception as exc:
                logger.debug("[target-epoch] 进程探测异常（降级）：%s", exc)
        code, svc_ok = (None, False)
        if self.target_url:
            try:
                code, svc_ok = self._http_probe(self.target_url, 2000.0)
            except Exception as exc:
                logger.debug("[target-epoch] HTTP 探活异常：%s", exc)
        try:
            phase = str(self._probe_phase_reader() or "")
        except Exception:
            phase = "UNKNOWN"
        return EpochSample(at=self._clock(), epoch=epoch, process_ok=proc_ok,
                           service_ok=svc_ok, http_code=code, probe_phase=phase)

    # ---------------- 判定 ----------------
    def _is_bad(self, s: EpochSample, prev: Optional[EpochSample]) -> Tuple[bool, str]:
        """判定单个样本是否「坏」，并给出原因。

        判据顺序（先强后弱）：
        ① 纪元切换：当前实例与健康基线不同 → 靶场被重建。
        ② 进程消失：已知实例（有基线）但本拍端口上查不到进程 → 靶场已停。
           用 _active_epoch 存在性而非上一拍纪元判定，避免「进程消失后连续多拍
           都判不出坏」导致窗口开不起来。
        ③ 应用不再服务请求（连接失败 / 全候选持续 5xx）。
        ④ 纪元整体不可判定时，才用探针阶段兜底（避免探针单独抖动造成误标）。
        """
        if s.epoch and self._active_epoch and s.epoch != self._active_epoch:
            return True, "target_restarted(epoch=%s→%s)" % (self._active_epoch, s.epoch)
        if self.port and self._active_epoch and not s.process_ok:
            return True, "target_process_gone(base=%s)" % self._active_epoch
        if not s.service_ok:
            return True, "target_not_serving(http=%s)" % (s.http_code if s.http_code is not None else "conn_fail")
        if not s.epoch and not s.process_ok and self._active_epoch:
            return True, "target_process_unavailable"
        if not self._active_epoch and s.probe_phase in _PROBE_BAD_PHASES:
            return True, "probe_phase=%s" % s.probe_phase
        return False, ""

    def feed(self, s: EpochSample) -> None:
        """把样本喂入状态机（线程安全）。"""
        with self._lock:
            prev = self.samples[-1] if self.samples else None
            self.samples.append(s)
            if not self.baseline_epoch and s.epoch:
                self.baseline_epoch = s.epoch
            if not self._active_epoch and s.epoch:
                self._active_epoch = s.epoch
            bad, reason = self._is_bad(s, prev)
            if bad:
                self._good_streak = 0
                if self._bad_streak == 0:
                    self._bad_since = s.at
                self._bad_streak += 1
                # 窗口开着时立刻采纳新实例为基线：否则「纪元已变」会永远成立，
                # 窗口再也关不上（新实例被永久判坏）。
                if self._open is not None and s.epoch and s.epoch != self._active_epoch:
                    self._active_epoch = s.epoch
                if self._open is None and self._bad_streak >= self.confirm_bad:
                    self._open = DowntimeWindow(down_at=self._bad_since, reason=reason)
                    logger.warning(
                        "[target-epoch] 靶场停机/重启窗口开启：%s（at=%s）", reason, _iso(self._bad_since)
                    )
            else:
                self._bad_streak = 0
                self._good_streak += 1
                if s.epoch and s.epoch != self._active_epoch:
                    # 已恢复且换了实例 → 采纳为健康基线
                    self._active_epoch = s.epoch
                if self._open is not None and self._good_streak >= self.confirm_good:
                    self._open.up_at = s.at
                    self.windows.append(self._open)
                    logger.warning(
                        "[target-epoch] 靶场恢复，停机窗口关闭：%s（%.1fs）",
                        self._open.reason, self._open.up_at - self._open.down_at,
                    )
                    self._open = None

    def start(self, *, background: bool = True) -> Dict[str, Any]:
        self.started_at = self._clock()
        self.feed(self.sample_once())
        if background:
            self._thread = threading.Thread(target=self._loop, name="target-epoch-watch", daemon=True)
            self._thread.start()
        return self.report()

    def _loop(self) -> None:
        while not self._stop_evt.wait(self.interval):
            try:
                self.feed(self.sample_once())
            except Exception as exc:  # 采样失败不得打断批次
                logger.debug("[target-epoch] 采样循环异常（忽略）：%s", exc)

    def stop(self) -> Dict[str, Any]:
        self._stop_evt.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=max(2.0, self.interval * 2))
        self._thread = None
        self.stopped_at = self._clock()
        # 收尾再采一拍，尽量把「批次结束时仍在停机」的窗口闭合到批次末。
        try:
            self.feed(self.sample_once())
        except Exception:
            pass
        with self._lock:
            if self._open is not None:
                self._open.up_at = self.stopped_at
                self.windows.append(self._open)
                self._open = None
        return self.report()

    # ---------------- 查询 ----------------
    def overlaps(self, t0: Optional[float], t1: Optional[float]) -> Optional[str]:
        """单 spec 的验证窗口 [t0, t1] 是否与停机窗口相交；相交返回原因，否则 None。

        终点前推 pre_down_guard_sec：紧贴停机前完成的验证同样可疑（该请求可能正是在
        """
        if t0 is None or t1 is None:
            return None
        lo = min(float(t0), float(t1))
        hi = max(float(t0), float(t1)) + self.pre_down_guard_sec
        for w in self.windows:
            up = w.up_at if w.up_at is not None else (self.stopped_at or hi)
            if lo <= up and hi >= w.down_at:
                return "%s window=%s~%s" % (w.reason, _iso(w.down_at), _iso(up))
        return None

    def all_window_ranges(self) -> List[Tuple[float, float]]:
        out = []
        for w in self.windows:
            up = w.up_at if w.up_at is not None else (self.stopped_at or w.down_at)
            out.append((w.down_at, up))
        return out

    def report(self) -> Dict[str, Any]:
        with self._lock:
            windows = [w.to_dict() for w in self.windows]
            n_obs = len(self.samples)
            epochs = [s.epoch for s in self.samples if s.epoch]
            epoch_available = bool(epochs)
            restarts = len({e for e in epochs[1:] if e != epochs[0]}) if epochs else 0
            if windows:
                verdict = "target_restarted" if restarts or any("restart" in (w.get("reason") or "") for w in windows) else "target_unavailable"
            elif not epoch_available:
                verdict = "undeterminable"
            else:
                verdict = "clean"
            return {
                "enabled": True,
                "target_url": self.target_url,
                "port": self.port,
                "baseline_epoch": self.baseline_epoch,
                "active_epoch": self._active_epoch,
                "epoch_available": epoch_available,
                "observations": n_obs,
                "restarts": restarts,
                "downtime_windows": windows,
                "verdict": verdict,
                "started_at": _iso(self.started_at),
                "stopped_at": _iso(self.stopped_at),
            }


# ---------------------------------------------------------------------------
# D2 结果侧：单 spec 的失效判定
# ---------------------------------------------------------------------------
def _unhealthy_states() -> frozenset:
    try:
        from src.agents.d2_judge import FINAL_TARGET_UNHEALTHY
        if FINAL_TARGET_UNHEALTHY:
            return frozenset({str(FINAL_TARGET_UNHEALTHY)})
    except Exception:
        pass
    return _TARGET_UNHEALTHY_FALLBACK


def has_positive_runtime_evidence(result: Any, pre_status: str = "") -> bool:
    """本条 D2 结果是否带「运行时已证实」的正向证据。

    判据（任一命中即为真）：
      - final_state ∈ {confirmed_attributable, runtime_confirmed, business_confirmed, confirmed}
      - 裁决态 verification_status ∈ {confirmed_exploitable, confirmed_sink_control, exploitable, confirmed}
      - iast_evidence.state 是 sink 抵达态 / iast 抵达态 / 授权确认态，或 iast_reached 为真

    为什么它能否决失效判定：canary 抵达 sink 由**靶场 JVM 内部**的探针上报，
    没有活着的靶场就不可能有这条证据。因此「有正向证据」与「靶场当时不健康」互斥，
    正向证据必须优先。
    """
    try:
        fs = str(getattr(result, "final_state", "") or "").strip().lower()
    except Exception:
        fs = ""
    if fs and fs in _POSITIVE_FINAL_STATES:
        return True
    if str(pre_status or "").strip().lower() in _POSITIVE_VERIF_STATES:
        return True
    try:
        ev = getattr(result, "iast_evidence", {}) or {}
    except Exception:
        ev = {}
    if isinstance(ev, dict):
        st = str(ev.get("state") or "").strip()
        if st and (st.lower() in _ARRIVAL_STATES or is_sink_reached(st)):
            return True
        if ev.get("iast_reached"):
            return True
    elif ev:
        st = str(getattr(ev, "state", "") or "").strip()
        if st and (st.lower() in _ARRIVAL_STATES or is_sink_reached(st)):
            return True
    return False


def epoch_clears_unavailability(tracker: Optional[TargetEpochTracker]) -> bool:
    """靶场纪元是否**明确证明**本轮全程可用（据此否决「靶场不健康」类失效判定）。

    只认 `verdict == "clean"` 且 `downtime_windows` 为空这一种情形 —— 它有进程身份纪元
    佐证（baseline_epoch == active_epoch、restarts=0），是「靶场全程活着」的硬证据。

    刻意**不认** `undeterminable`（纪元不可用，探针未回报进程身份）：那是「无证据」，
    不能反过来当成「靶场没坏」的证明。同理 `target_unavailable` / `target_restarted`
    自然返回 False。换言之本函数返回 True 时，任何「环境未就绪」信号都只可能来自
    请求级偶发失败，而非靶场不可用。
    """
    if tracker is None:
        return False
    try:
        rep = tracker.report()
    except Exception:
        return False
    if not isinstance(rep, dict):
        return False
    if rep.get("downtime_windows"):
        return False
    return str(rep.get("verdict") or "").strip().lower() == "clean"


def spec_invalidation_reason(
    result: Any,
    tracker: Optional[TargetEpochTracker],
    t0: Optional[float],
    t1: Optional[float],
    *,
    pre_status: str = "",
) -> str:
    """判定单条 D2 结果是否应落 invalidated（可重试）而非 confirmed / no_evidence。

    判据优先级：
       本轮靶场全程可用（verdict=clean、无停机窗口）时，①②③ 三条「靶场不健康」判据一律
       不成立 —— 它们都只是「某次请求疑似打不通」的噪声，与靶场是否可用无关。此情形返回
       空串，保持 D2 原裁决（通常是 no_evidence），不被 invalidated 挤出对账。
       实测根因：target-26/27/28/30/31 的 target_unhealthy 全都伴生 clean + 空窗口，
       注意仅「明确 clean」才否决；`undeterminable`（纪元无数据）沿用旧行为，
       避免把真停机误判成「永久非漏洞」。
    ① 单 spec 权威信号：D2 已判「环境未就绪」（final_state=target_unhealthy）。该分支
       iast_evidence 必然为空、无任何正向证据，是可信的环境态结论，必须失效而非落
       no_evidence（后者会被 finalize_unverified_trigger_specs 清扫成「永久非漏洞」）。
    ② 正向证据否决：只要本条带运行时已证实的证据（见 has_positive_runtime_evidence），
       一律不失效 —— 靶场内部探针能上报抵达，就证明靶场当时活着。
    ③ 噪声标志（仅在无正向证据时采信）：dast_impact_evidence.target_unhealthy。
       注意该字段是**跨步骤粘性 OR**（orchestrator 对同一事务的多条 impact 做
       `merged.target_unhealthy = merged.target_unhealthy or imp.target_unhealthy`，
       且 spec 级阻断也会被标 True），因此单独出现时只是「某一步骤出现过疑似靶场不健康
       被误标的根因。故必须叠加「无正向证据」才采信。
    ④ 批次级信号：该 spec 的验证窗口与靶场停机/重启窗口相交。
    都不命中 → 返回空串（保持原裁决）。
    """
    _epoch_clean = epoch_clears_unavailability(tracker)
    try:
        fs = str(getattr(result, "final_state", "") or "").strip().lower()
    except Exception:
        fs = ""
    if fs and fs in _unhealthy_states():
        if _epoch_clean:
            # 纪元证明靶场全程可用 → 该「环境未就绪」结论不成立，退回原裁决
            return ""
        return "target_unhealthy(final_state)"
    if has_positive_runtime_evidence(result, pre_status):
        return ""
    try:
        dast = getattr(result, "dast_impact_evidence", {}) or {}
    except Exception:
        dast = {}
    if isinstance(dast, dict) and dast.get("target_unhealthy"):
        if _epoch_clean:
            return ""
        return "target_unhealthy(dast_impact):%s" % str(dast.get("reason") or "")
    if tracker is not None:
        hit = tracker.overlaps(t0, t1)
        if hit:
            return "batch_isolation:" + hit
    return ""
