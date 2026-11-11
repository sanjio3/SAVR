"""A0 环境识别。

目标：在 D1 真正发攻击流量前，确认「目标服务起得来 + 探针挂得上 + 三者绑定一致」，
否则阻断，避免 D1 打到半路才发现环境坏了。输入为 iast_sessions 的
target_url + app_name + agent_id（来自 3.10 注册）。

方法论（四步）：
1. 目标可达性（target liveness）：对 target_url 发 HTTP HEAD/GET 探测。连接拒绝 /
   超时 / DNS 失败 → 不可达（阻断）；2xx / 3xx / 4xx → 可达；单次 5xx 仅重试+告警，
   连续 N 次（默认 5，见 EnvCheckConfig.target_down_consecutive）5xx 才判不可达（软判死，
2. 探针在线（probe liveness）：(a) 心跳 last_heartbeat_at 距今 < heartbeat_ttl_sec；
   或 (b) iast_events 中该 (app_name, agent_id) 最近 ingested_at 距今 < event_ttl_sec。
3. 一致性（consistency）：app_name / agent_id 与探针实际上报一致（注册不变量已保）。
4. 产出 EnvironmentReadiness = {target_reachable, probe_online, consistent, checked_at, detail}。

失败处理：任一为 false → 阻断本次扫描（不让 D1 发流量），给出明确错误（非静默）；
不自动降级到其他目标。阈值与判定标准列入配置 env_check。

纯函数 + 依赖注入（db / http_probe 可替），便于确定性单测，不碰真实网络与共享库。
"""
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple


# ---------- 配置----------
@dataclass
class EnvCheckConfig:
    probe_timeout_ms: float = 2000.0          # 探活超时（毫秒）
    target_down_codes: Tuple[int, ...] = tuple(range(500, 600))  # 5xx → 视为不可达的候选
    target_down_consecutive: int = 5          # 连续 N 次 5xx 才判死；单次 5xx 仅重试+告警，
                                              #
    # 避免「探活打到 DB 端点」自毒化——靶场 H2 内存库在重放负载下崩、根路径 5xx，探活本身
    # 也 5xx → 误判靶场不可达、阻断整轮重放。任一候选返回 2xx/3xx/4xx 即视为「进程存活」
    # （4xx 含静态资源不存在，证明进程在线、非 DB 自毒化）；仅当全部候选都连接失败或持续 5xx
    # 才判不可达。DB 无关端点排在根路径之前，确保静态 404 先命中即放行。
    probe_paths: Tuple[str, ...] = (
        "/favicon.ico", "/health", "/actuator/health",
        "/robots.txt", "/index.html", "/",
    )
    # 的 GC 停顿卡死心跳线程 → 心跳过期且事件回探也空窗 → A0 硬门禁把整片任务 kill
    # 。
    # 30s 是按「心跳每 10s 一次」的健康态定的，没考虑重放洪峰下 STW 停顿可达数十秒，
    # 现放宽到 120s（仍远小于「探针真死」的量级，不失门禁意义）。可用环境变量覆盖。
    heartbeat_ttl_sec: float = float(os.environ.get("SAST_AI_ENV_HEARTBEAT_TTL_SEC", "120.0"))
    # 近期事件窗口（心跳缺失时的回探）。原 60s：重放轮次之间的事件空窗常超过 60s，
    # 与心跳过期重叠即误杀，放宽到 180s。
    event_ttl_sec: float = float(os.environ.get("SAST_AI_ENV_EVENT_TTL_SEC", "180.0"))


# ---------- 产出 ----------
@dataclass
class EnvironmentReadiness:
    target_reachable: bool
    probe_online: bool
    consistent: bool
    checked_at: str
    detail: Dict[str, Any] = field(default_factory=dict)
    version_matched: bool = True

    def is_ready(self) -> bool:
        return self.target_reachable and self.probe_online and self.consistent and self.version_matched

    def block_reason(self) -> str:
        problems: list = []
        if not self.target_reachable:
            problems.append(f"目标不可达（{self.detail.get('target_note', '')}）")
        if not self.probe_online:
            problems.append("探针离线（无新鲜心跳 / 无近期事件）")
        if not self.consistent:
            problems.append(self.detail.get("consistent_note", "探针会话未注册"))
        if not self.version_matched:
            problems.append(self.detail.get("version_note", "探针版本与 SAST 分析代码版本不一致（§4.2）"))
        return "；".join(problems) if problems else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_reachable": self.target_reachable,
            "probe_online": self.probe_online,
            "consistent": self.consistent,
            "version_matched": self.version_matched,
            "checked_at": self.checked_at,
            "ready": self.is_ready(),
            "block_reason": self.block_reason(),
            "detail": self.detail,
        }


# ---------- 默认探活（真实网络，可注入替换）----------
def default_http_probe(target_url: str, timeout_ms: float) -> int:
    """返回 HTTP 状态码；连接异常 / 超时 / DNS 失败 → 抛异常（交由调用方判不可达）。

    先 HEAD（轻量），被拒（如 405/403 不允许 HEAD）再回退 GET（仅取状态码，不读 body）。

    失败重试 3 次（指数退避 0.5/1.0s）：D1 回放洪峰可能瞬时占用目标，导致一次性 2.0s
    超时。门禁不应因瞬时抖动直接 abort 整轮扫描——实测 task-5 即因此（D1 回放刚结束、
    """
    import time
    import requests
    from urllib.parse import urlparse

    # localhost 目标必须绕过 HTTP_PROXY（沙箱注入的 127.0.0.1:50621 等），否则探活
    # 请求会被误路由到代理并超时；外部目标仍走代理。
    _host = (urlparse(target_url).hostname or "").lower()
    _proxies = {"http": None, "https": None} if _host in ("127.0.0.1", "localhost", "::1") else None

    def _one(method: str) -> int:
        resp = requests.request(method, target_url, timeout=timeout_ms / 1000.0, allow_redirects=False, proxies=_proxies)
        return int(resp.status_code)

    last_exc = None
    for attempt in range(3):
        try:
            try:
                return _one("HEAD")
            except Exception:
                # HEAD 不被允许时回退 GET（仍只探活、不取完整 body）
                return _one("GET")
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    raise last_exc


def wake_probe(target_url: str, *, settle_sec: float = 3.0) -> bool:
    """主动向目标发一次请求，唤醒探针的心跳 / 事件上报。返回请求是否送达。

    探针心跳是 60s 周期的 HTTP POST 回平台，事件也是 HTTP 上报。后端在 A1/A2 阶段
    繁忙（CodeQL 建库 / LLM 推理 / SQLite 单写者锁）时，这两个请求会排队超时，
    探针进入静默 —— 但**进程一直活着**。此时按「最近有信号」判活就会误判离线：
      - A0 门禁直接把整轮扫描挡死（本轮/554）；
      - D2 每个事务前的廉价复探判 not ready ⇒ 该批 spec 全落 target_unhealthy
        ⇒ invalidated。
    探针 hook 了 HttpServletRequest/Response，所以**请求本身**就会产生新事件并刷新
    心跳。故：判活失败时先敲一下门再判。

    不校验状态码：302/401/404 都证明进程在跑且已进 servlet 链路。
    """
    if not target_url:
        return False
    try:
        default_http_probe(target_url, 5000.0)
    except Exception:  # noqa: BLE001  连不上才是真的不可达
        return False
    try:
        import time as _t

        _t.sleep(max(0.0, float(settle_sec)))
    except Exception:  # noqa: BLE001
        pass
    return True


# ---------- 时间解析工具 ----------
def _parse_iso(s: Any) -> Optional[float]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s)).timestamp()
    except Exception:
        return None


# ---------- 核心检查（纯函数，db / http_probe 可注入）----------
def check_environment_readiness(
    db,
    target_url: str,
    app_name: str,
    agent_id: str,
    *,
    config: Optional[EnvCheckConfig] = None,
    now: Optional[datetime] = None,
    http_probe: Optional[Callable[[str, float], int]] = None,
) -> EnvironmentReadiness:
    config = config or EnvCheckConfig()
    now = now or datetime.utcnow()
    now_ts = now.timestamp()
    detail: Dict[str, Any] = {"target_url": target_url, "app_name": app_name, "agent_id": agent_id}

    # 步骤 1：目标可达性
    # 返回 5xx，但探针心跳/事件正常，此时应重试而非阻断整轮重放。仅当连续 N 次（默认 5）
    # 5xx 才判定目标持续不可用；任意一次 2xx/3xx/4xx 即视为存活。连接拒绝/超时/DNS 失败属
    # 与目标完全不通，仍立即判不可达（非瞬时抖动）。
    target_reachable = True
    if not target_url:
        target_reachable = False
        detail["target_note"] = "target_url 缺失"
    else:
        target_reachable = False  # 默认不可达；任一候选返回 2xx/3xx/4xx 才翻 True（避免 5xx/连接失败误判可达）
        probe = http_probe or default_http_probe
        # 即视为靶场进程存活（4xx 含静态资源缺失，证明在线、非 DB 自毒化）；仅当全部候选
        # 连接失败或持续 5xx 才判不可达。避免「根路径 5xx（DB 崩）」误杀整轮重放。
        _candidates = list(config.probe_paths) or [""]
        _server_listening = False
        _any_5xx = False
        _notes: list = []
        for _cpath in _candidates:
            _c_url = target_url.rstrip("/") + "/" + _cpath.lstrip("/") if _cpath not in ("", "/") else target_url
            _down_streak = 0
            _probed: list = []
            _conn_fail = False
            for _i in range(max(1, config.target_down_consecutive)):
                try:
                    code = int(probe(_c_url, config.probe_timeout_ms))
                except Exception as exc:  # 连接拒绝 / 超时 / DNS 失败
                    _conn_fail = True
                    _notes.append(f"{_cpath or '/'} 探测异常：{exc}")
                    break
                _server_listening = True  # 任意 HTTP 状态码即证明进程在监听
                _probed.append(code)
                detail["target_status"] = code
                if code in config.target_down_codes:
                    _any_5xx = True
                    _down_streak += 1
                    if _down_streak >= config.target_down_consecutive:
                        _notes.append(f"{_cpath or '/'} 连续 {_down_streak} 次 5xx（持续 5xx）")
                        break
                    # 单次 5xx：暂不清算，重试以排除瞬时抖动，并尝试其它候选端点
                    _notes.append(f"{_cpath or '/'} {code} 单次 5xx，重试中（已连续 {_down_streak}/{config.target_down_consecutive}）")
                else:
                    # 任意非 5xx（2xx/3xx/4xx）→ 进程存活，立即可达；优先于根路径 5xx 生效
                    target_reachable = True
                    detail["target_note"] = f"{_cpath or '/'} 返回 {code} 视为可达（进程存活、非 DB 端点自毒化）"
                    break
            detail.setdefault("probed_codes", []).extend(_probed)
            if target_reachable:
                break
        if not target_reachable:
            if not _server_listening:
                detail["target_note"] = "目标不可达（全部候选端点连接失败，靶场进程离线）"
            elif _any_5xx:
                detail["target_note"] = "目标不可达（" + ("；".join(_notes) or "全部候选端点持续 5xx（靶场不健康）") + "）"
            else:
                detail["target_note"] = "目标不可达（" + ("；".join(_notes) or "探活无有效响应") + "）"

    # 步骤 2 + 3：探针在线 + 一致性（依赖 iast_sessions / iast_events）
    probe_online = False
    consistent = False
    version_matched = True
    session_row = None
    if app_name and agent_id:
        session_row = db.execute(
            "SELECT * FROM iast_sessions WHERE app_name = ? AND agent_id = ? ORDER BY id DESC LIMIT 1",
            (app_name, agent_id),
            fetchone=True,
        )
    if session_row:
        session = dict(session_row)
        consistent = True
        detail["session_id"] = session.get("id")
        #  版本钉死：会话注册时已校验探针版本与钉死 SAST 版本，mismatch 硬阻断发流量。
        version_status = (session.get("version_status") or "unknown")
        detail["version_status"] = version_status
        if version_status == "mismatch":
            version_matched = False
            detail["version_note"] = (
                f"探针版本与 SAST 分析代码版本不一致（probe={session.get('probe_version') or '<空>'} "
                f"vs sast={session.get('sast_code_version') or '<未钉死>'}），sink 行号/文件可能错位"
            )
        else:
            detail["version_note"] = "版本校验通过（或为 unverified 软放行）"
        # (a) 心跳新鲜
        hb = _parse_iso(session.get("last_heartbeat_at") or "")
        if hb is not None and (now_ts - hb) <= config.heartbeat_ttl_sec:
            probe_online = True
            detail["probe_liveness"] = "heartbeat_fresh"
        else:
            # (b) 近期事件回探
            ev_row = db.execute(
                "SELECT MAX(ingested_at) AS m FROM iast_events WHERE app_name = ? AND agent_id = ?",
                (app_name, agent_id),
                fetchone=True,
            )
            ev = dict(ev_row) if ev_row else None
            last_ev = (ev or {}).get("m")
            last_ev_ts = _parse_iso(last_ev)
            if last_ev_ts is not None and (now_ts - last_ev_ts) <= config.event_ttl_sec:
                probe_online = True
                detail["probe_liveness"] = "recent_event"
            else:
                detail["probe_liveness"] = "no_recent_signal"
                if last_ev:
                    detail["last_event_at"] = last_ev
    else:
        detail["consistent_note"] = "未找到匹配 app_name/agent_id 的探针会话（须先 POST /api/iast/sessions 注册）"

    return EnvironmentReadiness(
        target_reachable=target_reachable,
        probe_online=probe_online,
        consistent=consistent,
        checked_at=now.isoformat(),
        detail=detail,
        version_matched=version_matched,
    )
