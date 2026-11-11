"""触发事务编排器。

归属独立模块 src/iast/orchestrator.py，不塞进 d2 service。负责协调三件事：
1. DAST 发触发请求（通过注入的 dast_operator）；
2. 等 IAST 事件窗口（通过注入的 event_source 按 canary 精确轮询）；
3. 多假说匹配裁定（含 3.12 回填重裁）。

编排器只产出「IAST 可达性证据 + DAST 影响原始材料」，不裁定 confirmed / attributable；
最终裁定（confirmed_attributable / runtime_confirmed / ambiguous / no_evidence /
false_positive_sast_only，见 2.1 与 3.5 / 3.18）由 d2_judge.judge_verification 负责，
它消费编排器输出的 iast_evidence + dast_impact_evidence。d2_facade.verify_via_iast_trigger
作为两者协调者：调 orchestrator.run_transaction 拿 TransactionResult，再交 d2_judge 出
VerificationResult。这样编排器可独立测试，d2_judge 不依赖任何 IAST 摄取细节。

状态机（3.12 裁定状态机与回填规则）：
- 事务状态：open → provisional → finalized。早停命中与硬超时都只给出 provisional 裁定，不立即 finalize。
- 回填有效期默认 5 分钟；期间摄取端落含 canary 的事件会反查 provisional 事务触发重裁。
- 重裁只允许单向升级置信：no-arrival → arrival-sanitized → sink-reached；反向降级一律禁止。
- 回填有效期结束后事务 finalize，此后同 canary 事件只作历史证据追加，不再改变裁定。
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

import collections
import html
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

_logger = logging.getLogger("iast.orchestrator")

from src.iast.canary import CanaryMatcher, CanaryStates, is_sink_reached, STATE_RANK_STR  # noqa: F401  (is_sink_reached 重导出)
from src.iast.chain_conformance import verify_chain_conformance
from src.iast.sanitizer_trace import is_sanitizer_present

# ---- IastVerdict.state----
STATE_SINK_REACHED = "sink-reached"
# 设计一①：探针在 sink 现场（经 TaintStore 解析出 canary 位于 sink 实参）显式断言的 SINK_REACHED。
# 与被动兜底 sink-reached（Python 在 payload 里扫到 canary）区分：探针断言 = 攻击者可控数据确证抵达危险函数，
# 即便 D1 仅投 canary 探针（attack_degraded）也应判有害，不降级。沿既有 canary_state 通道透传，无需加列。
STATE_SINK_REACHED_PROBE = "sink-reached-probe"
STATE_ARRIVAL_SANITIZED = "arrival-sanitized"
STATE_NO_ARRIVAL = "no-arrival"

# 原 orchestrator 对 dast_operator.replay / replay_multi 的调用无任何墙钟上限，
# 一旦底层 HTTP 线程死锁，整组循环与 i2_rerun 永久冻结。
# 用守护线程 + join(timeout) 给每条重放加硬上限；超时返回哨兵，调用方转为 timeout 标记的 DastImpact，
# 不让单条阻塞拖垮整轮。阈值由 SAST_AI_D1_REPLAY_TIMEOUT 调（默认 120s，远大于单条 HTTP 10s 超时）。
_REPLAY_TIMEOUT_SENTINEL = object()

# SAST_AI_D1_REPLAY_PACE_MS：逐条重放之间的强制间隔（毫秒，默认 0=不限速）。
# 基准靶场建议 ≥4000 并配合 SAST_AI_D1_INIT_WORKERS=1 / SAST_AI_D1_MAX_WORKERS=1。
_D1_REPLAY_PACE_MS = float(os.environ.get("SAST_AI_D1_REPLAY_PACE_MS", "0") or 0)


def _call_with_timeout(fn, timeout: float):
    _result = [None]
    _exc = [None]

    def _runner():
        try:
            _result[0] = fn()
        except Exception as _e:  # noqa: BLE001
            _exc[0] = _e

    _t = threading.Thread(target=_runner, daemon=True)
    _t.start()
    _t.join(timeout)
    if _t.is_alive():
        return _REPLAY_TIMEOUT_SENTINEL
    if _exc[0] is not None:
        raise _exc[0]
    return _result[0]

# ---- 事务状态机 ----
STATUS_OPEN = "open"
STATUS_PROVISIONAL = "provisional"
STATUS_FINALIZED = "finalized"

# canary 状态 → 裁定状态的强度序（用于单向升级判断）。
# v2 证据分层 D1：收敛为 src/iast/canary.py 的 STATE_RANK_STR 单一真相源，
# 不再本地另立副本（旧副本把 sink-reached-probe 错压到与 sink-reached 同档，且漏 arrived）。
_STATE_RANK = STATE_RANK_STR

# 已「到达 sink」的 canary 状态集合：只有这些事件才可作为 I1 链路符合性的命中事件，
# 避免把 no-arrival / 历史空路径事件误选为 matched_event_detail。
_ARRIVAL_STATES = frozenset({
    CanaryStates.SINK_REACHED,
    CanaryStates.SINK_REACHED_PROBE,
    CanaryStates.ARRIVAL_SANITIZED,
    CanaryStates.ARRIVED,
})


# 单一真相源：is_sink_reached 的真身已收口到 src/iast/canary.py（含 sink-reached-probe），
# 此处从 canary 导入后重导出，保持 `from src.iast.orchestrator import is_sink_reached` 旧路径可用。
# 历史本地实现只认 "sink-reached"，漏掉探针显式断言态，是 sink_reached 恒 0 的根因之一。


@dataclass
class WindowConfig:
    """3.12 窗口参数（均可配置）。

    （11.6min/15.1min），是扫描慢的绝对主因。

    三项改动（全部可用 env 覆盖，便于 A/B 回退）：
      ① t_max 60 → 45：探针 EventBuffer 的 flush 周期是 **250ms**（probe-java
         EventBuffer.FLUSH_INTERVAL_MS 默认 250），摄取延迟远小于原假设，60s 属过量。
      ② settle_rounds 6 → 3（30s → 15s）：回填只在「尚有 NO_ARRIVAL 未决」时进入，
         仍保留迟到事件补救能力。
      ③ 新增 quiet_exit / t_max_no_event 两个**自适应退出**：
         - quiet_exit=12：本事务已收到过事件、之后连续 12s 无新事件 → 提前退出
           （剩余未决假说按「未到达」收口，迟到事件由分片级自适应排空 + 迟到补捞兜底）；
         - t_max_no_event=25：本事务**一条事件都没收到**时，从最后一批重放发出起
           25s 即退出（覆盖首次类加载 ~14s 的最坏情况），不再空等 45s。

    全部置 0 即完全回到旧行为（t_max 等满 + 6 轮回填）。
    """
    w_base: float = 5.0            # 基础等待窗口 W_base（秒）
    poll_interval: float = 0.5     # 轮询间隔 P（秒）
    t_max: float = 45.0            # 硬超时 T_max（秒）。原 60s 依据是「探针事件经 HTTP 缓冲+
                                     # 后端摄取有延迟」，但实测 flush 周期仅 250ms；45s 仍留 180 倍余量。
    backfill_ttl: float = 300.0    # 回填有效期（秒，默认 5 分钟）
    settle_rounds: int = 3         # 回填轮数（原硬编码 6 轮 × 5s = 30s）
    settle_sleep: float = 5.0      # 每轮回填间隔（秒）
    quiet_exit: float = 12.0       # 有事件后连续静默 N 秒即提前退出（0=关闭）
    t_max_no_event: float = 25.0   # 全程零事件时的硬超时（0=关闭，回落到 t_max）

    def __post_init__(self):
        """env 覆盖（便于不重启代码做 A/B）：SAST_AI_TX_* 。"""
        import os as _os

        def _f(name: str, cur: float) -> float:
            raw = _os.environ.get(name)
            if raw is None or str(raw).strip() == "":
                return cur
            try:
                return float(raw)
            except Exception:
                return cur

        self.t_max = _f("SAST_AI_TX_TMAX", self.t_max)
        self.settle_rounds = int(_f("SAST_AI_TX_SETTLE_ROUNDS", float(self.settle_rounds)))
        self.settle_sleep = _f("SAST_AI_TX_SETTLE_SLEEP", self.settle_sleep)
        self.quiet_exit = _f("SAST_AI_TX_QUIET_EXIT", self.quiet_exit)
        self.t_max_no_event = _f("SAST_AI_TX_TMAX_NO_EVENT", self.t_max_no_event)



@dataclass
class IastVerdict:
    """单假说可达性裁定。"""
    state: str = STATE_NO_ARRIVAL
    matched_event_ids: List[int] = field(default_factory=list)
    confidence: str = "low"
    provisional: bool = True
    degraded: bool = False          # typed canary 二态退化（7.2 方向B）
    canary_state: str = CanaryStates.NO_ARRIVAL
    chain_conformance: Dict[str, Any] = field(default_factory=dict)  # I1 逐节点链路符合性（§A2 poc 链）
    matched_event_detail: Dict[str, Any] = field(default_factory=dict)  # stash 命中的完整探针事件（含 stack_trace）供链路符合性
    matched_sink_file: str = ""  # 命中事件的 sink_file（JVM 类名.方法），④ sink 身份校验用
    # 与 canary_match 的区别：canary_match 是探针的 trace 级断言（实测 4943/4943 全为 1，
    # 而记录值里真能看到 canary 的只有 129 条 2.6%），值级是**比对出来的**，不是断言出来的。
    value_hit: Dict[str, Any] = field(default_factory=dict)
    # 它是「危险操作真的执行并抛错」的一手事实（如 SQL 注入触发 java.sql.SQLException、
    # 命令注入触发 java.io.IOException），跨过了「污点是否抵达」的不确定性；
    # 与 canary 断言 / 值级命中正交，是独立的 definitive 阳性候选。
    # 空字符串 = 未采集到异常（证据缺失，绝不当阴性；由兜底通道收口）。
    sink_exception_class: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "matched_event_ids": list(self.matched_event_ids),
            "confidence": self.confidence,
            "provisional": self.provisional,
            "degraded": self.degraded,
            "canary_state": self.canary_state,
            "chain_conformance": dict(self.chain_conformance),
            "matched_sink_file": self.matched_sink_file,
            "value_hit": dict(self.value_hit or {}),
            "sink_exception_class": self.sink_exception_class or "",
        }


@dataclass
class DastImpact:
    """D1 重放原始材料，留给 d2_judge 做危害裁定，编排器不解释。"""
    reached: bool = False
    status_code: Optional[int] = None
    body: str = ""
    response_summary: str = ""
    error: str = ""
    retried: int = 0
    provisional: bool = False        # D1 重试 3 次仍失败 → provisional 交 I2 裁定
    blocked: bool = False
    slices: Dict[str, Any] = field(default_factory=dict)  # multi-match 每假说独立切片（仅 per-param 切片，不放元数据）
    attack_degraded: bool = False    # True=本次仅 canary 探针（A2 未产出真 payload），不构成攻击证据
    attack_payload_used: str = ""    # 实际投放的攻击 payload（degraded 时为空）
    business_logic: Dict[str, Any] = field(default_factory=dict)  # 业务差分重放原始结果
    # attack_degraded_any 表示「至少一条降级」（部分没真打）。两者并存才能让 D2 区分
    # 「完全没打过」与「打过但混了弱证据」——只留一个布尔会把这两种截然不同的证据强度混为一谈。
    attack_degraded_any: bool = False
    # ---- D：多步重放（导入→触发）元数据 ----
    multi_step: bool = False            # 本次重放是否触发了后续步骤序列（deserialization 等延迟处理漏洞）
    steps_executed: int = 0            # 实际发出的后续步骤数（不含主请求）
    followup_status_code: Optional[int] = None  # 最后一步后续步骤的 HTTP 状态码
    # ---- M7 两步重放（存储型写→读配对）----
    # {enabled, plan, marker, steps_executed, write_skipped, write, read, read_endpoint_source}。
    # read.state 三态：raw（原样出现=可利用）/ escaped（到 sink 但被转义=真阴性）/ absent。
    # 这条是存储型唯一通用证据——读取侧参数里没有 canary，探针在该侧完全盲区。
    two_step: Dict[str, Any] = field(default_factory=dict)
    # ---- M13 DAST 浏览器扩展（按需起 headless 浏览器取证，用完释放，非常驻）----
    # D1 主重放真实发出的 URL（requests prepare 后含 query 与重定向前的最终地址）。
    # 浏览器取证要还原「同一页面」，用 spec 里那个原始 endpoint 拼出来常常打不开
    # （鉴权跳 302、路径基线不同），故必须留真实地址。
    replay_url: str = ""
    # ---- M10 SSTI 引擎桶 ----
    # A1 静态识别到的模板引擎（velocity/freemarker/thymeleaf/pebble/spel/ognl/mvel）。
    # SSTI 结果点比对按桶派发求值对：不同引擎语法不同，混用一组表达式会同时漏报与误报。
    ssti_engines: List[str] = field(default_factory=list)
    # True 表示本条 D1 重放因靶场 5xx/连接异常/超时/环境探针未就绪而未能取得有效响应——
    # 这不等同于「漏洞不存在」，下游应标记为 target-unhealthy（可重试），而非 no_evidence（永久非漏洞）。
    target_unhealthy: bool = False
    # elapsed_ms：投放攻击 payload 的主请求耗时（毫秒）。任何重放都会填（非 sleep 型也记，便于诊断）。
    # baseline_elapsed_ms：命中 sleep 型 payload 时对同端点发一次无害基线请求的耗时（毫秒）；
    #   无基线（path 位无法安全重建等）时保持 0.0，D2 退回绝对阈值判定。
    # sleep_seconds_hint：本条 payload 解析出的预期时延秒数（来自 attack_context.parse_sleep_seconds）；
    #   0.0 表示非 sleep 型 —— D2 只在 >0 时才启用时延确认门。三者必须同源配对（见 _aggregate_dast）。
    elapsed_ms: float = 0.0
    baseline_elapsed_ms: float = 0.0
    sleep_seconds_hint: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    # 非空时下游须按弱证据处理（absent_id：越权判据保留但零持久化变更；skip：未投放）。
    destructive_guard: Dict[str, Any] = field(default_factory=dict)
    # 投放前被判为「废弹」而被丢弃的载荷及原因（形如 "ssrf_payload_with_shell_metachar"）。
    # 非空表示本次重放**没有**投放 A2 产出的真弹（降级为 canary 或最小兜底弹），下游须按弱证据处理，
    # 且不得把它记成「探针/靶场打不通」——根因在上游载荷形状，不在运行时。
    payload_rejections: List[str] = field(default_factory=list)
    # 本次投放的载荷来源：a2（A2 产出）/ sca_forge（弹药库补位）/ minimal_fallback（族最小可用弹）
    # / none（无弹，纯 canary）。供对账区分「没弹」与「弹形状错」。
    payload_source: str = "none"
    # True 表示本条重放响应明确指示「请求在抵达漏洞点之前被安全基础设施（WAF / 应用拦截器 /
    # 参数截断过滤器）阻断」——它不代表「漏洞不存在」，而是「本次未能有效验证」，应重试或人工确认。
    # 与 target_unhealthy（靶场 5xx/连接异常，可重试）并列 rank 0，但语义不同：
    #   - target_unhealthy：靶场本身不健康；
    #   - waf_blocked：靶场健康，但请求被安全策略拦截。
    # 两者都不应被误判为 no_evidence（永久非漏洞，确认口径的分母）。
    waf_blocked: bool = False
    # 主重放 / oracle 探测臂的实际认证态：
    # anonymous / authenticated / reauthed / reauth_failed。
    # 落 raw_dast_impact 供泛化验证剔除「登录墙 302」这类执行层干扰。
    auth_state: str = ""
    # 由 D1 在 _replay_attack 内对 dataflow 族采集填充；{"attempted","harmful","reason"}。
    # 严格 fail-open：未尝试/歧义时为 attempted=False（闸门口保留现状，绝不零化仅到达 TP）。
    differential: Dict[str, Any] = field(default_factory=dict)
    # 只看 HTTP 响应/时序（布尔对差分 / 时延 / 文件内容签名 / 原样反射），不依赖 IAST 探针。
    # 结构：{family, verdict(exploitable|not_exploitable|inconclusive), signal, confidence,
    #        reason, arms:[{arm,payload,status,body_len,elapsed_ms,error,note}]}。
    # 纪律：**当前只观测不判定**（D2 未采信），确认口径接入前先用 scripts/oracle_report.py
    # 做离线反事实复核（避免把黑盒信号直接变成新的误报通道）。
    oracle: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reached": self.reached,
            "status_code": self.status_code,
            "body": self.body,
            "response_summary": self.response_summary,
            "headers": dict(self.headers),
            "error": self.error,
            "retried": self.retried,
            "provisional": self.provisional,
            "blocked": self.blocked,
            "slices": dict(self.slices),
            "attack_degraded": self.attack_degraded,
            "attack_payload_used": self.attack_payload_used,
            "business_logic": dict(self.business_logic),
            "attack_degraded_any": self.attack_degraded_any,
            "multi_step": self.multi_step,
            "steps_executed": self.steps_executed,
            "followup_status_code": self.followup_status_code,
            "target_unhealthy": self.target_unhealthy,
            "elapsed_ms": self.elapsed_ms,
            "baseline_elapsed_ms": self.baseline_elapsed_ms,
            "sleep_seconds_hint": self.sleep_seconds_hint,
            "destructive_guard": dict(self.destructive_guard),
            "payload_rejections": list(self.payload_rejections),
            "payload_source": self.payload_source,
            "waf_blocked": self.waf_blocked,
            "auth_state": self.auth_state,
            "replay_url": self.replay_url,
            "differential": dict(self.differential),
            "oracle": dict(self.oracle),
        }


# ---------------------------------------------------------------------------
#
# 12 路并发压垮承压弱的靶场（典型如 H2 内存库在并发重放下丢失表 → 500），进而把
# 「靶场不健康」误判成「漏洞无证据」，召回率虚低。
#
# 本闸门：
# - 初始保守并发（initial，默认 4），按实时错误率缓慢爬升（成功累积到阈值 +1，封顶 max_w）。
# - 错误率超阈值（窗口内错误占比 ≥ trip_rate）→ 熔断：挂起后续重放，轮询健康探针
#   直到靶场恢复，再复位为保守并发续跑剩余 spec（而非永久阻断）。
# - 单次并发严格受 max_w 上限约束，且不低于 1；熔断等待有总超时（max_wait），超时强制
#   复位续跑，避免卡死整轮扫描。
# ---------------------------------------------------------------------------

def _looks_like_target_down(msg: str) -> bool:
    """把异常/错误文本判定为「靶场不健康」信号。

    ``"501"`` … 与 ``"探针"`` / ``"environment"`` 这类**子串匹配**，误判面极大 ——
    任何含 "500" 的文本（端口号 5000、请求体里的数字、混淆后的 payload、请求 id）都会命中，
    而 ``"探针"`` 更是把「探针相关提示」当成「靶场不健康」。

    现分两类，且都要求是**结构化短语**而非裸数字：
      - 连接级（靶场没应答）：connection refused / reset / timeout / unreachable / DNS 失败；
      - 就绪级（显式环境阻断）：target_down / not ready / 未就绪 / 探针未就绪。
    即：**错误文本里出现 ``500`` 这类数字**不再算作靶场不健康 —— 那是可重试，不是不可用
    （该口径与 ``d1_service.is_connection_level_failure`` 保持一致）。
    注意与本函数的调用方 ``_is_target_unhealthy_impact`` 区分：那里仍保留
    「状态码就是 5xx」这一支（用于并发闸门退让），本函数只管**文本**判据。
    """
    if not msg:
        return False
    s = msg.lower()
    markers = (
        # ── 连接级：靶场根本没应答 ──
        "connection refused", "connection reset", "connection aborted",
        "remote end closed", "remotedisconnected", "broken pipe",
        "timed out", "timeout", "readtimeout", "connecttimeout",
        "max retries exceeded", "unreachable", "no route to host",
        "name or service not known", "getaddrinfo",
        # ── 就绪级：显式环境阻断（都是结构化短语，不用裸词）──
        "target_down", "target_unavailable", "target not serving",
        "not ready", "not_ready", "未就绪", "探针未就绪", "环境未就绪",
    )
    return any(m in s for m in markers)



def _is_target_unhealthy_impact(imp: "DastImpact") -> bool:
    """DastImpact 是否代表「靶场不健康」（区别于 spec 级阻断 / 真实无证据）。

    该谓词的**唯一消费方**是 ``_AdaptiveConcurrencyGate.record``（降并发 / 熔断复位），
    不是下游的 no_evidence ↔ target_unhealthy 裁定 —— 后者读的是
    ``dast_impact_evidence["target_unhealthy"]`` 标志本身（见 adjudicator.py:495），
    并且还有 ``target_epoch`` 的纪元交叉校验兜底。所以这里的判定只需服务于「该不该退让」。

    三档判据（顺序有意义）：
      1. ``blocked`` 优先返回 False：spec 级阻断（端点非法 / 路由缺失）根本**没发流量**，
         对靶场负载没有任何观测价值，拿它触发退让只会让闸门白降并发。
         注意 orchestrator.py 未就绪分支产出的 ``blocked=True, target_unhealthy=True``
         （见下方 ``if blocked_reason:`` 处）**不会**流经本谓词，故不存在冲突。
      2. 生产者显式标记 ``target_unhealthy``：d1_service 已按「连接级失败才置位」的
    """
    if imp is None:
        return False
    # spec 级阻断（端点非法 / 探针路由）不是靶场问题，不计入靶场不健康
    if imp.blocked:
        return False
    # 生产者已显式判定（d1_service 侧连接级失败 / orchestrator 就绪级阻断）
    if imp.target_unhealthy:
        return True
    if imp.status_code is not None and 500 <= int(imp.status_code) < 600:
        return True
    if imp.error:
        return _looks_like_target_down(imp.error)
    return False


class _AdaptiveConcurrencyGate:
    """D1 重放自适应并发 + 熔断自动复位控制器（线程安全）。"""

    def __init__(self, readiness_probe, target, *, initial=4, min_w=1, max_w=12,
                 trip_rate=0.5, window=24, max_wait=90.0, sleep_fn=None):
        self._probe = readiness_probe
        self._target = target
        self._min = max(1, int(min_w))
        self._max = max(self._min, int(max_w))
        self._workers = max(self._min, min(int(initial), self._max))
        self._trip_rate = float(trip_rate)
        self._window = max(5, int(window))
        self._max_wait = float(max_wait)
        self._sleep = sleep_fn or time.sleep
        self._lock = threading.Lock()
        self._tripped = False
        self._results: "collections.deque" = collections.deque(maxlen=self._window)

    def current_workers(self) -> int:
        with self._lock:
            return self._workers

    @property
    def tripped(self) -> bool:
        with self._lock:
            return self._tripped

    def record(self, success: bool) -> None:
        """记录一次重放成败，调整并发并可能触发熔断。success=False 视为靶场不健康信号。"""
        with self._lock:
            self._results.append(bool(success))
            n = len(self._results)
            if not success:
                if self._workers > self._min:
                    self._workers -= 1
            else:
                # 持续成功后缓慢爬升（避免抖动误升）
                if n >= 10 and all(self._results) and self._workers < self._max:
                    self._workers += 1
            # 错误率超阈值即熔断（每次成败都评估，避免成功记录把窗口填满却不判定）
            errs = sum(1 for r in self._results if not r)
            if n >= 5 and (errs / n) >= self._trip_rate:
                self._tripped = True

    def wait_if_tripped(self) -> None:
        """若已熔断，阻塞直到健康探针恢复（或超时），然后复位续跑剩余 spec。"""
        with self._lock:
            if not self._tripped:
                return
        deadline = time.monotonic() + self._max_wait
        while True:
            with self._lock:
                if not self._tripped:
                    return
            if time.monotonic() > deadline:
                with self._lock:
                    self._tripped = False
                    self._results.clear()
                    self._workers = self._min
                _logger.warning("[orchestrator] 熔断等待超时（%.0fs），强制复位续跑剩余 spec", self._max_wait)
                return
            if self._probe is not None:
                try:
                    probe = self._probe(self._target) or {}
                    ready = bool(probe.get("ready", True))
                except Exception:
                    ready = False
                if ready:
                    with self._lock:
                        self._tripped = False
                        self._results.clear()
                        self._workers = self._min
                    _logger.info("[orchestrator] 熔断复位：靶场健康探针恢复，续跑剩余 spec")
                    return
            self._sleep(3.0)


@dataclass
class TransactionResult:
    """run_transaction 出参。"""
    transaction_id: str = ""
    per_hypothesis: Dict[str, IastVerdict] = field(default_factory=dict)
    multi_match_summary: Dict[str, Any] = field(default_factory=dict)
    raw_dast_impact: Dict[str, Any] = field(default_factory=dict)
    # 按假说的影响证据（to_dict 后的形态），与 raw_dast_impact 同源但按假说切片。
    # 为空表示编排器未登记（旧编排器 / 无重放发生），消费方须回退到 raw_dast_impact。
    dast_impact_by_hypothesis: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    status: str = STATUS_OPEN


@dataclass
class TransactionState:
    """编排器持有的 per-transaction 状态对象（3.12.x 状态持有）。"""
    transaction_id: str
    target: Dict[str, Any]
    trigger_specs: List[Dict[str, Any]]
    canary_by_hypothesis: Dict[str, str] = field(default_factory=dict)
    created_at: float = 0.0
    finalized_at: Optional[float] = None
    status: str = STATUS_OPEN
    verdicts: Dict[str, IastVerdict] = field(default_factory=dict)
    dast_impact: Optional[DastImpact] = None
    # tx.dast_impact 是**事务级聚合**（_aggregate_dast 里 reached = 批内所有重放取 OR），
    # 一个事务合并多个漏洞的假说后，全部成员都会吃到同一个 reached —— 自己没打通的
    # 漏洞也会被判有害（抬 FP）。这里按假说登记「该假说所属 endpoint 组」的影响证据，
    # 供消费方按假说切片，避免跨漏洞串味。粒度为 endpoint 组（replay_multi 的最小单位）：
    # 同端点内多参数仍是 OR，与「单漏洞多 spec」的既有语义一致。
    dast_impact_by_hypothesis: Dict[str, DastImpact] = field(default_factory=dict)
    backfill_eligible: bool = True
    start_watermark: int = 0
    # 当本事务含 extend_wait_window 覆盖的 spec 时，放宽到 t_max × EXTEND_FACTOR，专治
    # 「探针事件因 HTTP 缓冲 / 后端摄取延迟迟到」导致的 no-arrival（与  放宽到 60s 同源思路，
    # 但仅对显式标记的难达 spec 放宽，不放大全量窗口）。
    window_t_max: Optional[float] = None
    # 重放是提交到线程池排队执行的，一批几百条 spec 的重放往往要几分钟才跑完；而窗口原先
    # 从 created_at（= 发流量**之前**）起算 t_max=60s，于是排在队尾的重放还没发出，采集窗口
    # 就已经关闭 → 事件回来时没人接 → 判 no-arrival，而事件明明落进了 iast_events。
    # 窗口必须以「最后一批重放发出」为锚，否则并发度越高、丢证据越多。
    last_dispatch_at: float = 0.0
    # 假说 id → 是否由「收口迟到证据回收」升级而来（对账时用于把回收量单独摘出来，
    # 免得把「回收回来的证据」算成「本轮本来就打中」）。
    late_recovered: Dict[str, bool] = field(default_factory=dict)


def _map_canary_state(canary_state: str) -> Dict[str, Any]:
    """canary 三态/四态 → (verdict.state, confidence, degraded)。"""
    cs = (canary_state or CanaryStates.NO_ARRIVAL)
    if cs in (CanaryStates.SINK_REACHED, CanaryStates.SINK_REACHED_PROBE):
        return {"state": STATE_SINK_REACHED_PROBE if cs == CanaryStates.SINK_REACHED_PROBE else STATE_SINK_REACHED,
                "confidence": "high", "degraded": False}
    if cs == CanaryStates.ARRIVAL_SANITIZED:
        return {"state": STATE_ARRIVAL_SANITIZED, "confidence": "medium", "degraded": False}
    if cs == CanaryStates.ARRIVED:
        # typed canary 二态退化：值到了 sink 但无法判定是否被净化。
        return {"state": STATE_SINK_REACHED, "confidence": "high", "degraded": True}
    return {"state": STATE_NO_ARRIVAL, "confidence": "low", "degraded": False}


def _replay_overrides_of(spec: Dict[str, Any]) -> List[str]:
    """从 spec 解析重放侧覆盖动作。

    优先读 caller 直接放上的 ``replay_overrides`` 列表；缺失时从 ``raw_json.replay_adjust.actions``
    兜底解析（raw_json 可能是字符串或 dict）。涵盖 inject_all_params / extend_wait_window /
    switch_param_location 三类。空列表表示无覆盖（走默认重放行为）。
    """
    raw = spec.get("replay_overrides")
    if isinstance(raw, list):
        return [str(a) for a in raw if a]
    actions: List[str] = []
    rj = spec.get("raw_json")
    if isinstance(rj, str) and rj:
        try:
            rj = json.loads(rj) or {}
        except Exception:
            rj = {}
    if isinstance(rj, dict):
        adj = rj.get("replay_adjust") or {}
        if isinstance(adj, dict):
            actions = [str(a) for a in (adj.get("actions") or []) if a]
    return actions


# extend_wait_window 对 I1 采集窗口的放宽系数（env SAST_AI_I1_WINDOW_EXTEND 可覆盖，默认 3×）。
_WINDOW_EXTEND_FACTOR = float(os.environ.get("SAST_AI_I1_WINDOW_EXTEND", "3.0"))


def _resolve_poc_chain(spec: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """从 trigger_spec 解析 A2 预测的 poc 链（有序节点序列）。

    兼容两种来源：spec 直接带 poc_chain(list)，或 poc_chain_json(json 字符串，来自 DB)。
    若两者皆空，回退到 _derive_poc_chain_from_spec（按 family+endpoint+sink 推导），
    保证 I1 即便在 A2 未登记 poc_chain（旧 spec / 未迁移列）时也能做逐节点符合性。
    """
    if not spec:
        return []
    pc = spec.get("poc_chain")
    if isinstance(pc, list):
        return [n for n in pc if isinstance(n, dict)]
    raw = spec.get("poc_chain_json")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [n for n in parsed if isinstance(n, dict)]
        except Exception:
            return []
    # 回退：spec 未携带 poc_chain（如未迁移 poc_chain_json 列的旧库）→ 即时推导
    return _derive_poc_chain_from_spec(spec)


def _derive_poc_chain_from_spec(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """按 entry(family/route/method/param) + expected_sink 推导 poc 链（I1 逐节点符合性假说）。

    与 benchmark_cli._derive_poc_chain 同源逻辑：A2 预测链优先，缺失时退化为 family 典型传播路径，
    使 I1 不依赖 poc_chain_json 列是否被填充即可端到端跑通。
    """
    family = (spec.get("family") or "")
    route = spec.get("target_endpoint") or ""
    method = (spec.get("http_method") or "GET").upper()
    pname = spec.get("param_name") or ""
    location = spec.get("param_location") or "query"
    chain: List[Dict[str, Any]] = []
    src_label = f"{method} {route}"
    if pname:
        src_label += f"#{pname}({location})"
    chain.append({
        "stage": "source", "role": "source",
        "node": src_label,
        "signature": f"{route}#{pname}" if pname else route,
    })
    fam = (family or "").lower()
    if "deserial" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "Base64.decode", "signature": "java.util.Base64.decode"})
        chain.append({"stage": "transform", "role": "transform", "node": "ObjectInputStream.readObject", "signature": "java.io.ObjectInputStream.readObject"})
    elif "ssrf" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "URL.openStream", "signature": "java.net.URL.openStream"})
    elif "sql" in fam or "inject" in fam:
        chain.append({"stage": "transform", "role": "transform", "node": "Statement.execute", "signature": "java.sql.Statement.execute"})
    sink_file = spec.get("expected_sink_file") or ""
    sink_line = spec.get("expected_sink_line") or 0
    sink_label = f"{sink_file}:{sink_line}" if sink_file else "unknown-sink"
    chain.append({
        "stage": "sink", "role": "sink",
        "node": sink_label,
        "signature": sink_file or "",
    })
    return chain


def _upgrade_verdict(verdict: IastVerdict, new_state: str, event_id: int) -> bool:
    """单向升级置信：no-arrival → arrival-sanitized → sink-reached；反向降级禁止。返回是否发生升级。
    注意 new_state 是 canary 状态（no-arrival/arrived/sink-reached/arrival-sanitized），
    须先 _map_canary_state 映射成裁定状态再取强度序，否则与 _STATE_RANK（按裁定状态键）
    错配导致 new 恒为 0、升级永远被拒（根因④：I1 arrival 恒 0）。"""
    mapped = _map_canary_state(new_state)
    new_rank = _STATE_RANK.get(mapped["state"], 0)
    cur = _STATE_RANK.get(verdict.state, 0)
    if new_rank <= cur:
        return False
    verdict.state = mapped["state"]
    verdict.confidence = mapped["confidence"]
    verdict.degraded = mapped["degraded"]
    verdict.canary_state = new_state
    if event_id and event_id not in verdict.matched_event_ids:
        verdict.matched_event_ids.append(event_id)
    return True


# 探针把 char[] 序列化成 ``[s, 4, s, t, ...]``（逗号分隔单字符）——匹配括号内 ≥4 段的主体。
_CHAR_ARRAY_BODY_RE = re.compile(r"\[([^\[\]]{4,})\]")


def deserialize_char_arrays(text: str) -> List[str]:
    """把探针序列化的 char[]（形如 ``[s, 4, s, t, ...]``，逗号分隔单字符）还原成字符串。

    记成**逐字符数组**（``[[s, 4, s, ...], 0, 36]``）而非连续字符串，于是 ``compute_value_hit``
    01428 的 ``write(char[])`` 事件 reached=1 却确认不了）。本函数在比对前把这种形态还原回
    字符串，作为**额外的 hay 源**，不改既有判定路径。

    判定条件（宁缺勿滥）：括号内 ≥4 段、且除至多 1 段外其余都是 0~1 字符 —— 只对真正的
    ``[MD5]`` 这类正常参数列表不会被误还原（多段长度 >1）。
    """
    out: List[str] = []
    for m in _CHAR_ARRAY_BODY_RE.finditer(text or ""):
        parts = [p.strip() for p in m.group(1).split(",")]
        if len(parts) < 4:
            continue
        single = sum(1 for p in parts if len(p) <= 1)
        if single >= len(parts) - 1:
            out.append("".join(p[0] if p else " " for p in parts))
    return out


def compute_value_hit(canary: str, event: Dict[str, Any], max_snippet: int = 240) -> Dict[str, Any]:
    """值级判据（v2 四态）：我方投放数据是否**真的出现在**探针记录的 sink 实参值里（纯函数）。

    为什么要这条：探针给所有 TAINT_FLOW 事件都打了 canary_match=1（trace 级断言），但实测
    只有 129 条（2.6%）——「数据抵达 sink 实参」长期是**断言**出来的，不是**比对**出来的。
    污点传播对 map 回读、常量分支是值不敏感的（标签没掉就算命中），于是安全版同样被判到达，
    这是误报的根之一。

    v2 四态（L2 事实层，只产出事实，不产出是非结论；是否裁决由 D2 通道决定）：
      - ``hit_live``      canary 原文到达 sink 实参，且实参上无消毒器记录 → 上行即 L3 强化证据
      - ``hit_sanitized`` canary 原文到达 sink 实参，但实参上录得消毒器（针对本族由通道二次校验）
                         → 上行即合法的 definitive 阴性（有判据！）
      - ``hit_html_encoded`` 完整 canary 原文未出现、但 html.unescape 后出现（数据被反射到输出
                         但遭 HTML 转义）→ 事实层「数据到达」成立，但**转义反射=防护生效**，
                         hit=False 绝不据此确认（防 FP）；可利用性由 D2 echo_state 独立裁决
      - ``hit_opaque``    canary 以 base64/hex 等被抽象化形式出现，原文无法比对 → 证据缺失
      - ``miss``          canary 未出现在可读实参里 → 证据缺失（fail-open）

    失败形态（canary 过短 / 非 dict 事件 / 无待查字段）一律返回 miss（definitive=False）。
    返回的 ``definitive`` / ``harmful`` 仅作**提示**，最终裁决权在 D2 通道（B1/B5），
    本函数不越权出结论（证据分层铁律①：下层不得直接产出上层结论）。
    """
    # 事件非 dict（上游坏数据）先归一为空 dict —— miss 模板里要读 sink_file，提前在
    # isinstance 守卫前构造会让失败形态直接抛 AttributeError。
    if not isinstance(event, dict):
        event = {}
    miss = {"hit": False, "form": "miss", "where": "", "sink_file": str(event.get("sink_file") or ""),
            "snippet": "", "matched_len": 0, "definitive": False, "harmful": False, "sanitizer": ""}
    can = str(canary or "").strip()
    if not can or len(can) < 8:
        return miss
    hay: List[tuple] = []
    sv = str(event.get("source_value") or "")
    if sv:
        hay.append(("source_value", sv))
        # 子串比对会 miss；还原成字符串后作为额外 hay 源再比对（不改既有路径，纯增量）。
        for _ds in deserialize_char_arrays(sv):
            hay.append(("source_value:char_array", _ds))
    evidence = event.get("evidence")
    sink_sanitizer: Any = None
    if isinstance(evidence, dict):
        pay = str(evidence.get("payload") or "")
        if pay:
            hay.append(("evidence.payload", pay))
        # L3 语义层：sink 实参上的消毒器记录（探针透传，见 sanitizer_trace 模块说明）。
        ss = evidence.get("sink_sanitizer")
        if ss in (None, ""):
            ctx = evidence.get("context")
            if isinstance(ctx, dict):
                ss = ctx.get("sink_sanitizer")
        if ss in (None, ""):
            ss = event.get("sink_sanitizer")
        sink_sanitizer = ss
    elif isinstance(evidence, str) and evidence:
        hay.append(("evidence", evidence))
    if not hay:
        return miss
    # 精确命中：canary 原文出现在可读实参里
    for where, text in hay:
        idx = text.find(can)
        if idx >= 0:
            lo = max(0, idx - max_snippet // 3)
            snippet = text[lo:lo + max_snippet]
            sanitized = is_sanitizer_present(sink_sanitizer)
            if sanitized:
                return {"hit": True, "form": "hit_sanitized", "where": where,
                        "sink_file": str(event.get("sink_file") or ""),
                        "snippet": snippet, "matched_len": len(can),
                        "definitive": True, "harmful": False,
                        "sanitizer": str(sink_sanitizer or "")}
            return {"hit": True, "form": "hit_live", "where": where,
                    "sink_file": str(event.get("sink_file") or ""),
                    "snippet": snippet, "matched_len": len(can),
                    "definitive": True, "harmful": True,
                    "sanitizer": ""}
    # —— 说明数据确实被反射到了输出，只是被应用/框架 HTML 转义了。这是「数据到达 sink」
    # 的事实（证据层），但**不是**可利用性证据：转义后的反射恰恰是 XSS 防护生效的形态。
    # 因此返回独立的 hit_html_encoded 态且 hit=False —— 确认闸（d2_facade 按 value_hit.hit
    # 门控）不会据此升 confirmed_exploitable，防 FP；可利用性由 D2 echo_state（raw vs
    # escaped）独立裁决。原文命中已在上面 hit_live/hit_sanitized 分支返回，不会走到这里。
    for where, text in hay:
        try:
            unescaped = html.unescape(text)
            if unescaped != text and can in unescaped:
                return {"hit": False, "form": "hit_html_encoded", "where": where + ":html.unescape",
                        "sink_file": str(event.get("sink_file") or ""),
                        "snippet": "", "matched_len": 0,
                        "definitive": False, "harmful": False, "sanitizer": ""}
        except Exception:
            pass
    # 摘要/编码命中：canary 被 base64/hex 包裹（值被抽象化，原文无法比对）→ 证据缺失态
    for where, text in hay:
        try:
            if can.encode("utf-8").hex() in text:
                return {"hit": False, "form": "hit_opaque", "where": where,
                        "sink_file": str(event.get("sink_file") or ""),
                        "snippet": "", "matched_len": 0,
                        "definitive": False, "harmful": False, "sanitizer": ""}
        except Exception:
            pass
        try:
            import base64
            if base64.b64encode(can.encode("utf-8")).decode("ascii") in text:
                return {"hit": False, "form": "hit_opaque", "where": where,
                        "sink_file": str(event.get("sink_file") or ""),
                        "snippet": "", "matched_len": 0,
                        "definitive": False, "harmful": False, "sanitizer": ""}
        except Exception:
            pass
    return miss


class TriggerTransactionOrchestrator:
    """触发事务编排器。

    dast_operator: 可选，对象需提供 replay(trigger_spec, target) -> DastImpact。
                   缺省（None）则跳过 DAST 重放，raw_dast_impact 为空，judge 侧按"无 DAST 影响"处理。
                   重试 3 次 + 退避由 D1 操作器自身负责，编排器只消费其结果。
    event_source: 可选，callable(canary, since_id, limit) -> List[{"id":int, "canary_state":str}]。
                  缺省（None）则不做 IAST 轮询，verdict 保持 no-arrival。
    readiness_probe: 可选，callable(target: dict) -> {"ready": bool, "block_reason": str}。
                     缺省（None）不复探。：run_transaction 真正发流量前做廉价复探（复用 A0
                     环境识别逻辑），避免 A0 预处理结论在扫描中途过期；未就绪则阻断发流量。
    clock: callable -> float（秒）。sleep: callable(seconds)。注入二者使编排器可独立测试。
    """

    def __init__(
        self,
        dast_operator: Any = None,
        event_source: Optional[Callable[[str, int, int], List[Dict[str, Any]]]] = None,
        window_cfg: Optional[WindowConfig] = None,
        clock: Optional[Callable[[], float]] = None,
        sleep: Optional[Callable[[float], None]] = None,
        readiness_probe: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_watermark_provider: Optional[Callable[[], int]] = None,
    ):
        self.dast_operator = dast_operator
        self.event_source = event_source
        self.window = window_cfg or WindowConfig()
        self._clock = clock if clock is not None else _default_clock
        self._sleep = sleep if sleep is not None else _default_sleep
        self.readiness_probe = readiness_probe
        self._watermark = event_watermark_provider
        self._transactions: Dict[str, TransactionState] = {}

    # ---- 公共入口 ----

    def run_transaction(
        self,
        target: Dict[str, Any],
        trigger_specs: List[Dict[str, Any]],
        representative_request_params: Optional[List[Dict[str, Any]]] = None,
        transaction_id: Optional[str] = None,
    ) -> TransactionResult:
        import uuid

        tx_id = transaction_id or ("tx-" + uuid.uuid4().hex[:16])
        now = self._clock()
        specs = list(trigger_specs or [])

        # 黑板阶段二：D1 必读知识（pitfall），best-effort 非致命，作为破坏性闸门日志。
        # 不跳过任何重放（跳过重复重放属阶段三前的预读接线，不在本处），仅日志化载入。
        try:
            from src.core.knowledge_entries import read_for_stage
            read_for_stage(target.get("workspace_id"), "d1")
        except Exception:
            pass

        tx = TransactionState(
            transaction_id=tx_id,
            target=dict(target or {}),
            trigger_specs=specs,
            created_at=now,
            status=STATUS_OPEN,
        )
        # 仅对显式标记的难达 spec 放宽，不放大全量窗口，避免普遍拖慢。fail-safe：无覆盖则保持默认。
        _extend = any("extend_wait_window" in _replay_overrides_of(s) for s in specs)
        if _extend:
            tx.window_t_max = float(self.window.t_max) * _WINDOW_EXTEND_FACTOR
            _logger.info("[orchestrator] 事务 %s 含 extend_wait_window 覆盖，I1 窗口放宽到 %.0fs",
                         tx_id, tx.window_t_max)
        # 重放覆盖动作可见性（inject_all_params 已由 D1 默认全参注入，此处仅观测与可追溯）。
        _ov_seen: Dict[str, int] = {}
        for s in specs:
            for _a in _replay_overrides_of(s):
                _ov_seen[_a] = _ov_seen.get(_a, 0) + 1
        if _ov_seen:
            _logger.info("[orchestrator] 事务 %s 重放覆盖动作：%s", tx_id, _ov_seen)
        hids: List[str] = []
        for i, spec in enumerate(specs):
            hid = spec.get("vulnerability_hash_v2") or spec.get("hypothesis_id") or f"h{i}"
            hids.append(hid)
            canary_raw = spec.get("taint_marker") or ""
            # 收口根因④：bridge 在 iast_events.canary 列只存 22 字符身份段
            #（s4st41<16hex>），而 taint_marker 是「身份段 + 元字符段」完整串。编排器必须用
            # 同一身份段做精确轮询，否则 poll_events_by_canary 的 WHERE canary = <完整 marker>
            # 永远 0 行 → I1 arrival 恒为 0。找不到身份段时回退完整串（向后兼容）。
            canary = CanaryMatcher.find_identity(canary_raw) or canary_raw
            tx.canary_by_hypothesis[hid] = canary
            tx.verdicts[hid] = IastVerdict(state=STATE_NO_ARRIVAL, provisional=True)

        #  廉价复探：真正发流量前复用 A0 环境识别逻辑复探一次，避免预处理结论过期。
        blocked_reason = ""
        if self.readiness_probe is not None:
            try:
                probe = self.readiness_probe(dict(target or {})) or {}
                if not probe.get("ready", True):
                    blocked_reason = probe.get("block_reason") or "A0 复探未就绪"
            except Exception as exc:  # 复探本身异常不静默吞，记入阻断原因
                blocked_reason = f"复探异常：{exc}"

        #  事件隔离：捕获本事务启动前的 iast_events 最大 id 作为水位线（必须在发流量前设置，
        # 使后台采集器只轮询本事务产生的事件，剔除上一轮残留的空路径/陈旧事件）。
        tx.start_watermark = self._watermark() if self._watermark else 0

        # （try/finally 之外的那一行），于是重放期间摄取端回调 submit_backfill_event 根本
        # 查不到本事务 → 回填通道在整个重放窗口内是断开的，只剩下采集器单点兜底。
        self._transactions[tx_id] = tx

        # §I1 后台化：IAST 事件采集改为后台线程，与 D1 重放并发执行，
        # 不再严格串行（先重放完再等窗口）。后台采集器持续轮询 event_source 直到窗口耗尽或
        # 全假说到达 sink；主线程同时把回放请求发出去。事件本身已由摄取端点异步落库到
        # iast_events，后台采集器只负责把命中归类进 verdict（D2 直接读这些已采集事件）。
        _collector = threading.Thread(target=self._wait_window, args=(tx,), daemon=True)
        _collector.start()

        #  multi-match：按 endpoint 分组，同组假说一次回放全参数带标（D1 已有 replay_multi 时用）。
        # 若 dast_operator 不支持 replay_multi，降级为逐假说 replay（兼容旧 D1）。
        raw_impacts: List[DastImpact] = []
        if blocked_reason:
            # 未就绪：阻断发流量，产出 blocked 的 DastImpact 交 I2 裁定（不调用 dast_operator.replay）。
            # 这是靶场级环境门禁（探针未就绪 / 连续 5xx / 不可达）触发，属「靶场不健康」而非
            # 「漏洞无证据」——标记 target_unhealthy 让下游可重试，而非永久判非漏洞。
            raw_impacts.append(DastImpact(blocked=True, error=blocked_reason, target_unhealthy=True))
        elif self.dast_operator is not None:
            groups: Dict[str, List[Dict[str, Any]]] = {}
            group_hids: Dict[str, List[str]] = {}
            order: List[str] = []
            for spec, hid in zip(specs, hids):
                key = f"{spec.get('http_method', 'GET')} {spec.get('target_endpoint', '')}"
                if key not in groups:
                    groups[key] = []
                    group_hids[key] = []
                    order.append(key)
                groups[key].append(spec)
                group_hids[key].append(hid)
            # （H2 内存库在并发重放下丢表 → 500），把「靶场不健康」误判成「漏洞无证据」。
            # 改为自适应闸门：错误率超阈值即熔断，待健康探针恢复后再续跑剩余 spec（非永久阻断）。
            _gate = _AdaptiveConcurrencyGate(
                self.readiness_probe,
                target,
                initial=int((os.environ.get("SAST_AI_D1_INIT_WORKERS") or "4")),
                min_w=1,
                max_w=int((os.environ.get("SAST_AI_D1_MAX_WORKERS") or "12")),
            )
            # #④ 防卡死：每条重放加墙钟硬上限（默认 120s），避免底层 HTTP 线程死锁冻住整组循环。
            # 改为把各组提交到受同一自适应闸门管控的全局线程池，跨 endpoint 并行重放；
            # 组内仍用 replay_multi（per-endpoint 多匹配优化）或逐假说串行（不再组内额外开池，
            # 避免「组数×组内并发」把总并发放大击穿靶场），总并发由外层池大小 = 闸门当前自适应
            # 并发（current_workers，initial→max）限定，只读公开 API、不碰私有 _max。
            # 闸门/raw_impacts 均线程安全（gate 自带锁；raw_impacts 合并加锁）。
            _replay_timeout = float(os.environ.get("SAST_AI_D1_REPLAY_TIMEOUT", "120"))
            _raw_lock = threading.Lock()

            def _process_group(key, group_specs):
                _group_impacts: List[DastImpact] = []
                # 队尾的组可能几分钟后才跑到这里）。I1 采集窗口以此锚定，见 _wait_window。
                try:
                    _now = self._clock()
                    if _now > float(tx.last_dispatch_at or 0.0):
                        tx.last_dispatch_at = _now
                except Exception:
                    pass
                try:
                    if hasattr(self.dast_operator, "replay_multi"):
                        # D1 已支持 multi-match：一次回放全参数带标、返回 per-spec 切片
                        _impacts = _call_with_timeout(
                            lambda: self.dast_operator.replay_multi(group_specs, target) or [],
                            _replay_timeout,
                        )
                        if _impacts is _REPLAY_TIMEOUT_SENTINEL:
                            _logger.warning(
                                "[orchestrator] replay_multi 组 %s 墙钟超时(%.0fs)，标记该组 stalled",
                                key, _replay_timeout,
                            )
                            _group_impacts.append(DastImpact(error="replay_multi wall-clock timeout", provisional=True))
                        else:
                            _group_impacts.extend(_impacts or [])
                    else:
                        # 逐假说 replay：组内串行（并行度交由外层组池 + 闸门统一管控，避免并发放大）。
                        # canary 每 spec 唯一，跨组并发不会串扰 I1 关联；replay 无状态、线程安全。
                        # 覆写——每个 flush tick（~135s）只吐「最近一个请求」的事件，快速连发的
                        # 请求其事件在 flush 前就被覆盖，**永久丢失**（20 连发仅最后 1 条落库；
                        # 4s 间隔 3 条→7 事件全到）。缓解：SAST_AI_D1_REPLAY_PACE_MS 设置逐条
                        # 间隔（建议 ≥4000，与单 worker 配合），让每条重放的事件活到被采集。
                        # 根治需探针侧改为逐事件入队 + 秒级 flush（sec-probe 项目）。
                        for spec in group_specs:
                            _gate.wait_if_tripped()
                            try:
                                _r = _call_with_timeout(
                                    lambda: self.dast_operator.replay(spec, target),
                                    _replay_timeout,
                                )
                            except Exception as exc:
                                _group_impacts.append(DastImpact(
                                    error=str(exc), provisional=True,
                                    target_unhealthy=_looks_like_target_down(str(exc)),
                                ))
                                continue
                            if _r is _REPLAY_TIMEOUT_SENTINEL:
                                _group_impacts.append(DastImpact(
                                    error="replay wall-clock timeout", provisional=True,
                                    target_unhealthy=False,
                                ))
                            else:
                                _group_impacts.append(_r)
                            if _D1_REPLAY_PACE_MS > 0:
                                time.sleep(_D1_REPLAY_PACE_MS / 1000.0)
                except Exception as exc:  # 组级异常视为整组 D1 失败 → 交 I2 裁定
                    for _ in group_specs:
                        _group_impacts.append(DastImpact(
                            error=str(exc), provisional=True,
                            target_unhealthy=_looks_like_target_down(str(exc)),
                        ))
                with _raw_lock:
                    for imp in _group_impacts:
                        if isinstance(imp, DastImpact):
                            raw_impacts.append(imp)
                            _gate.record(not _is_target_unhealthy_impact(imp))
                    # 按假说登记本 endpoint 组的影响证据：使批量合并事务后每个漏洞仍能读到
                    # 属于自己的 reached/status/body，而不是整批事务级 OR 出来的 reached。
                    _group_agg = self._aggregate_dast(_group_impacts) if _group_impacts else DastImpact()
                    for _hid in group_hids.get(key, ()):
                        tx.dast_impact_by_hypothesis[_hid] = _group_agg
                return _group_impacts

            # 必须用闸门公开 API：current_workers（自适应并发，initial→max，线程安全）。
            # 原写 _gate.max_w —— 那是**构造器参数名**而非实例属性（实例只存 self._max），
            # 直接 AttributeError 打挂整个 D2。并发上限
            # 仍受同一闸门管控，想放大并发调 SAST_AI_D1_INIT_WORKERS / SAST_AI_D1_MAX_WORKERS。
            _group_workers = max(1, min(_gate.current_workers(), len(order)))
            with ThreadPoolExecutor(max_workers=_group_workers) as _gp:
                list(_gp.map(lambda k: _process_group(k, groups[k]), order))
            if _gate.tripped:
                _logger.warning("[orchestrator] 事务结束前靶场仍处于熔断态，部分 spec 可能未充分重放")
        tx.dast_impact = self._aggregate_dast(raw_impacts) if raw_impacts else DastImpact()

        self._transactions[tx_id] = tx

        # §I1 后台化：等待后台采集器自然结束（窗口耗尽或全假说到达 sink，含回填 settle 阶段）。
        # join 超时取 t_max + settle(6*5s) + 余量，确保迟到事件回填完毕再继续主流程。
        #
        # join 超时必须同步放宽，否则主线程会先于采集器退出、把还没归类的事件丢在身后。
        # 这里按硬上限（同一公式）放宽，并保留「超时即按末态继续」的 fail-safe。
        _t_max_eff = float(tx.window_t_max or self.window.t_max)
        _hard_cap = max(_t_max_eff * 10.0, 900.0)
        _join_budget = _hard_cap + 6 * 5.0 + 5.0
        _collector.join(timeout=_join_budget)
        if _collector.is_alive():
            _logger.warning("[I1] 后台采集器在 %.0fs 内未退出，按窗口末态继续", _join_budget)

        # iast_events（since_id 仍用水位线，不会捞到上一轮/上一个任务的同 canary 事件）。
        # 这是最后一道兜底——探针事件可能迟到到采集器退出之后才落库，窗口再怎么放宽也接不住，
        # 而事件本身是真实证据，丢掉等于把「打中了」误判成「没打中」。
        _recovered = self._recover_late_arrival(tx)
        if _recovered:
            _logger.info("[I1] 收口回收迟到到达证据：%d 条假说由 no-arrival 升级", _recovered)

        # I1 逐节点链路符合性：对每个假说，用其 A2 poc_chain 与命中的探针事件比对。
        # 这是对「攻击流量流经的每一个节点都符合 A2 猜测 poc 链」的验证（方案 A：复用 sink 调用栈）。
        for hid, v in tx.verdicts.items():
            spec = next((s for s in specs if (s.get("vulnerability_hash_v2") or s.get("hypothesis_id")) == hid), None)
            poc_chain = _resolve_poc_chain(spec)
            v.chain_conformance = verify_chain_conformance(poc_chain, v.matched_event_detail or None)

        tx.status = STATUS_PROVISIONAL
        for v in tx.verdicts.values():
            v.provisional = True

        return TransactionResult(
            transaction_id=tx_id,
            per_hypothesis={k: IastVerdict(**v.to_dict()) for k, v in tx.verdicts.items()},
            multi_match_summary=self._multi_match_summary(tx),
            raw_dast_impact=tx.dast_impact.to_dict(),
            dast_impact_by_hypothesis={
                k: (v.to_dict() if isinstance(v, DastImpact) else dict(v or {}))
                for k, v in tx.dast_impact_by_hypothesis.items()
            },
            status=tx.status,
        )

    def _recover_late_arrival(self, tx: TransactionState) -> int:
        """收口回收：对仍是 NO_ARRIVAL 的假说，按 canary 直接回查一次事件并升级。

        sink-reached-probe 事件全部集中落在 22:54:58–22:55:02 这 4 秒的一次批量落库里）。
        窗口再怎么放宽也接不住「晚于窗口的落库」，必须在收口时补一次回查。

        安全性：
        - since_id 用本事务水位线，绝不捞上一轮/上一个任务的同 canary 事件（canary 是按
          漏洞哈希确定性生成的，跨任务会重复，不设下界就会拿旧证据冒充本轮）；
        - 只升不降（复用 _upgrade_verdict），不会把已达成的结论改差；
        - 分页取完（每页 50，直到取不满），不会只看到前 50 条。
        """
        if self.event_source is None:
            return 0
        pending = [hid for hid, v in tx.verdicts.items() if v.state == STATE_NO_ARRIVAL]
        if not pending:
            return 0
        _base_wm = max(0, int(tx.start_watermark or 0))
        recovered_hids: set = set()
        # 这批事件是「有 state 但没有值」的半证据，D2 值级通道会对它们永久饥饿。
        local_value_hits: Dict[str, Dict[str, Any]] = {}
        # B2 sink 异常：迟到补捞同样要采 L3 异常类名，否则 B2 通道对 late-recover 上来的假说永久饥饿。
        local_sink_exc: Dict[str, str] = {}
        for hid in pending:
            canary = tx.canary_by_hypothesis.get(hid) or ""
            if not canary:
                continue
            cursor = _base_wm
            best: Optional[Dict[str, Any]] = None
            best_score = -1
            for _page in range(20):   # 上限 20 页 × 50 = 1000 条，防异常膨胀打满循环
                try:
                    events = self.event_source(canary, cursor, 50) or []
                except Exception:
                    break
                if not events:
                    break
                for ev in events:
                    eid = int(ev.get("id", 0) or 0)
                    # 纵深防御：即便查询层把水位线以下的老事件返回了，这里也必须跳过。
                    # canary 由漏洞哈希确定性生成、跨任务复用，越过水位线就等于拿上一轮的
                    # 到达证据冒充本轮（会把「以前打中过」误判成「这次打中了」）。
                    if eid <= _base_wm:
                        continue
                    if eid > cursor:
                        cursor = eid
                    cstate = ev.get("canary_state", CanaryStates.NO_ARRIVAL)
                    if _upgrade_verdict(tx.verdicts[hid], cstate, eid):
                        tx.late_recovered[hid] = True
                        recovered_hids.add(hid)
                    if cstate in _ARRIVAL_STATES:
                        _sc = self._event_path_score(ev)
                        self._consider_value_hit(local_value_hits, hid, canary, ev)
                        self._consider_sink_exception(local_sink_exc, hid, ev)
                        if _sc > best_score:
                            best_score = _sc
                            best = ev
                if len(events) < 50:
                    break
            if best is not None:
                tx.verdicts[hid].matched_event_detail = best
                tx.verdicts[hid].matched_sink_file = best.get("sink_file") or ""
        self._flush_value_hits(tx, local_value_hits)
        self._flush_sink_exception(tx, local_sink_exc)
        return len(recovered_hids)

    # ---- 回填重裁（3.12 回填规则）----

    def submit_backfill_event(self, canary: str, canary_state: str, event_id: int = 0) -> List[str]:
        """摄取端落库时反查 provisional 事务（3.12 回填触发点）。返回被升级的假说 id 列表。"""
        if not canary:
            return []
        upgraded: List[str] = []
        now = self._clock()
        for tx in self._transactions.values():
            if tx.status != STATUS_PROVISIONAL or not tx.backfill_eligible:
                continue
            if now - tx.created_at > self.window.backfill_ttl:
                continue
            for hid, c in tx.canary_by_hypothesis.items():
                if c == canary:
                    if _upgrade_verdict(tx.verdicts[hid], canary_state, event_id):
                        upgraded.append(hid)
        return upgraded

    def finalize_expired(self, now: Optional[float] = None) -> List[str]:
        """回填有效期结束后事务 finalize；此后同 canary 事件只作历史证据追加。返回 finalize 的 tx id 列表。"""
        now = now if now is not None else self._clock()
        finalized: List[str] = []
        for tx in self._transactions.values():
            if tx.status == STATUS_PROVISIONAL and tx.backfill_eligible:
                if now - tx.created_at > self.window.backfill_ttl:
                    tx.status = STATUS_FINALIZED
                    tx.finalized_at = now
                    tx.backfill_eligible = False
                    finalized.append(tx.transaction_id)
        return finalized

    def get_transaction(self, transaction_id: str) -> Optional[TransactionState]:
        return self._transactions.get(transaction_id)

    # ---- 内部 ----

    def _wait_window(self, tx: TransactionState) -> None:
        _t_max = tx.window_t_max if tx.window_t_max else self.window.t_max

        # 提交进线程池**排队**执行的——几百条 spec 的重放往往要几分钟才发完。排在队尾的重放
        # 发出时，created_at + t_max 早已过期，采集循环已经退出，于是它的事件回来时没人接，
        # 改为按 `max(created_at, last_dispatch_at)` 动态重算：最后一批重放发出之后仍保有完整
        # t_max 采集窗口。硬上限防止极端排队把窗口拖成无限长（fail-safe：超时按窗口末态继续）。
        _hard_cap = max(float(_t_max) * 10.0, 900.0)

        def _deadline() -> float:
            anchor = max(float(tx.created_at or 0.0), float(tx.last_dispatch_at or 0.0))
            return min(anchor + float(_t_max), float(tx.created_at or 0.0) + _hard_cap)

        # 水位线：只轮询本事务启动后产生的事件，剔除历史遗留空路径事件。
        #
        # 批内多个 canary 的事件在 iast_events 里按 id 交错落库，轮询 canary A 把游标推到
        # 1010 之后，再轮询 canary B 就是「id > 1010」，B 那些 id<=1010 的事件被永久跳过。
        # 单假说事务（逐条 verify）只有一个 canary，游标单调推进恰好不出问题，所以这个坑
        # 一直潜伏；批量合并事务后十几个 canary 共享游标 → 大量假说的到达事件被漏读 →
        # sink_reached 断崖下跌。
        _base_wm = max(0, int(tx.start_watermark or 0))
        last_id_by_canary: Dict[str, int] = {
            c: _base_wm for c in set(tx.canary_by_hypothesis.values()) if c
        }
        # 每个假说维护「路径最丰富的到达事件」：I1 链路符合性优先选 taint_path 节点数最多者，
        # 避免陈旧空路径事件（上一轮残留）被当作 matched_event_detail 导致 conforms=False。
        best_event_by_hid: Dict[str, Dict[str, Any]] = {hid: None for hid in tx.verdicts}
        value_hit_by_hid: Dict[str, Dict[str, Any]] = {}
        # B2 sink 异常：每个假说保留首个 sink 现场异常类名（与值级同生命周期）。
        sink_exc_by_hid: Dict[str, str] = {}
        # 依据 probe-java EventBuffer.FLUSH_INTERVAL_MS=250ms，事件从产生到可被轮询到
        # 通常在秒级，故「有事件后长时间静默」= 剩余假说确实没到，可提前收口。
        _seen_any = False
        _last_event_ts = 0.0
        _quiet_exit = float(getattr(self.window, "quiet_exit", 0.0) or 0.0)
        _t_max_no_event = float(getattr(self.window, "t_max_no_event", 0.0) or 0.0)
        while self._clock() < _deadline():
            for canary in set(tx.canary_by_hypothesis.values()):
                if not canary or self.event_source is None:
                    continue
                try:
                    events = self.event_source(canary, last_id_by_canary.get(canary, _base_wm), 50) or []
                except Exception:
                    events = []
                if events:
                    _seen_any = True
                    _last_event_ts = self._clock()
                for ev in events:
                    eid = int(ev.get("id", 0) or 0)
                    _cur = last_id_by_canary.get(canary, _base_wm)
                    if eid > _cur:
                        last_id_by_canary[canary] = eid
                    cstate = ev.get("canary_state", CanaryStates.NO_ARRIVAL)
                    for hid, c in tx.canary_by_hypothesis.items():
                        if c == canary:
                            _upgrade_verdict(tx.verdicts[hid], cstate, eid)
                            # 仅「已到达 sink」的事件才可作为 I1 命中事件；同组取 taint_path 最丰富者。
                            if cstate in _ARRIVAL_STATES:
                                self._consider_best_event(best_event_by_hid, hid, ev)
                                self._consider_value_hit(value_hit_by_hid, hid, canary, ev)
                                self._consider_sink_exception(sink_exc_by_hid, hid, ev)
            #  multi-match 早停：全部 N 假说至少匹配到 arrival-sanitized/已抵达 sink 才结束；
            # 否则继续等更多事件。窗口耗尽则按现有逻辑退出。
            # (STATE_SINK_REACHED, STATE_ARRIVAL_SANITIZED) —— 探针实际发出的抵达态是
            # 批内假说全部早已抵达 sink，早停分支也永远不触发，窗口白白等满 t_max（≈60s）。
            # 这就是「IAST 几秒就跑通、却静默等满 60 秒」的根因。
            if tx.verdicts and all(
                is_sink_reached(v.state) or v.state == STATE_ARRIVAL_SANITIZED
                for v in tx.verdicts.values()
            ):
                break
            if _quiet_exit > 0 and _seen_any and _last_event_ts and (
                self._clock() - _last_event_ts
            ) >= _quiet_exit:
                _logger.debug(
                    "[orchestrator] 事务 %s 静默 %.1fs 提前退出（seen_any=%s）",
                    tx.transaction_id if hasattr(tx, "transaction_id") else "?", _quiet_exit, _seen_any,
                )
                break
            # 首次类加载最坏约 14s，25s 仍留余量。
            # 注意：采集线程是在**发流量之前**启动的（见 run_transaction），last_dispatch_at 会在
            # 循环期间被主线程持续推进，所以锚点必须每轮重算；用循环外捕获的初值会让队尾重放的
            # 窗口被前几批的派发时刻"提前用完"。
            if _t_max_no_event > 0 and not _seen_any:
                _anchor_now = max(float(tx.created_at or 0.0), float(tx.last_dispatch_at or 0.0))
                if (self._clock() - _anchor_now) >= _t_max_no_event:
                    _logger.debug(
                        "[orchestrator] 事务 %s 全程零事件，%.1fs 提前退出",
                        tx.transaction_id if hasattr(tx, "transaction_id") else "?", _t_max_no_event,
                    )
                    break
            self._sleep(self.window.poll_interval)
        # 这里做有限次「回填轮询」，只升不降——只要迟到事件带 sink-reached / sink-reached-probe，就把
        # 此前误判的 NO_ARRIVAL 升级，避免技术/注入族因时序被错杀为 0 确认。
        # 仅当尚有 NO_ARRIVAL 假说未决时才回填；已全数到达 sink 的事务（早停分支）无需再轮询，避免空转。
        #
        # **还没到**，于是第一轮必然 _any_new=False → 立刻 break → 回填一轮都没等到，等于完全没有
        # 回填。这正是「迟到事件明明落库了却救不回来」的直接原因。改为：只要还有 NO_ARRIVAL 未决
        # 就把 6 轮等完（6×5s = 30s），全部解决才提前退出。
        if any(v.state == STATE_NO_ARRIVAL for v in tx.verdicts.values()):
            # 默认降到 3 轮（15s）：迟到事件的主要来源已由「分片级自适应排空 + 迟到补捞
            # (d2_facade.recover_late_arrival)」兜底，事务内不必再空转 30s。
            _settle_sleep = float(getattr(self.window, "settle_sleep", 5.0) or 5.0)
            _settle_rounds = int(getattr(self.window, "settle_rounds", 6) or 0)
            for _ in range(max(0, _settle_rounds)):
                _any_new = False
                for canary in set(tx.canary_by_hypothesis.values()):
                    if not canary or self.event_source is None:
                        continue
                    try:
                        events = self.event_source(canary, last_id_by_canary.get(canary, _base_wm), 50) or []
                    except Exception:
                        events = []
                    for ev in events:
                        eid = int(ev.get("id", 0) or 0)
                        _cur = last_id_by_canary.get(canary, _base_wm)
                        if eid > _cur:
                            last_id_by_canary[canary] = eid
                        cstate = ev.get("canary_state", CanaryStates.NO_ARRIVAL)
                        for hid, c in tx.canary_by_hypothesis.items():
                            if c == canary:
                                if _upgrade_verdict(tx.verdicts[hid], cstate, eid):
                                    _any_new = True
                                    tx.late_recovered[hid] = True
                                if cstate in _ARRIVAL_STATES:
                                    self._consider_best_event(best_event_by_hid, hid, ev)
                                    self._consider_value_hit(value_hit_by_hid, hid, canary, ev)
                                    self._consider_sink_exception(sink_exc_by_hid, hid, ev)
                # 已无未决的 NO_ARRIVAL 才提前退出；否则把 6 轮等完（见上方注释）。
                if not any(v.state == STATE_NO_ARRIVAL for v in tx.verdicts.values()):
                    break
                self._sleep(_settle_sleep)
        # 窗口结束：把「最丰富路径」的到达事件写回 verdict，覆盖轮询期间可能的首事件（陈旧空路径）。
        for hid, ev in best_event_by_hid.items():
            if ev is not None:
                tx.verdicts[hid].matched_event_detail = ev
                tx.verdicts[hid].matched_sink_file = ev.get("sink_file") or ""
        # 值级证据写回（主窗口 + 回填轮询期间累积的命中）
        self._flush_value_hits(tx, value_hit_by_hid)
        # B2 sink 异常写回（同生命周期）
        self._flush_sink_exception(tx, sink_exc_by_hid)

    @staticmethod
    def _event_path_score(ev: Dict[str, Any]) -> int:
        """taint_path 节点数（方案 B 路径丰富度）。兼容已解析 list 或未解析 JSON 字符串。"""
        tp = ev.get("taint_path")
        if isinstance(tp, str):
            try:
                tp = json.loads(tp)
            except (ValueError, TypeError):
                tp = []
        if not isinstance(tp, list):
            tp = []
        return len(tp)

    @staticmethod
    def _consider_best_event(best_by_hid: Dict[str, Dict[str, Any]], hid: str, ev: Dict[str, Any]) -> None:
        """在已到达 sink 的事件中，保留 taint_path 节点数最多的事件供 I1 链路符合性。"""
        cur = best_by_hid.get(hid)
        if cur is None:
            best_by_hid[hid] = ev
            return
        if TriggerTransactionOrchestrator._event_path_score(ev) > TriggerTransactionOrchestrator._event_path_score(cur):
            best_by_hid[hid] = ev

    @staticmethod
    def _consider_value_hit(hits_by_hid: Dict[str, Dict[str, Any]], hid: str, canary: str,
                            ev: Dict[str, Any]) -> None:
        """记录该假说的**首个**值级命中（命中已足够取证，后续同义事件不必重复计算）。

        只要任何一条探针事件的 sink 实参值里看得见我方投放数据，就留下这条事实；
        没有事件能比对出命中时保持空字典，由上层按「证据缺失」处理，绝不臆断。
        """
        if hits_by_hid.get(hid):
            return
        try:
            vh = compute_value_hit(canary, ev)
        except Exception:
            return
        if vh.get("hit"):
            hits_by_hid[hid] = vh

    @staticmethod
    def _flush_value_hits(tx: TransactionState, hits_by_hid: Dict[str, Dict[str, Any]]) -> None:
        """把采集到的值级命中写回各假说裁定（窗口/回填结束时调用一次）。"""
        for hid, vh in (hits_by_hid or {}).items():
            if not vh or not vh.get("hit"):
                continue
            v = tx.verdicts.get(hid)
            if v is not None:
                v.value_hit = dict(vh)

    @staticmethod
    def _extract_sink_exception(ev: Dict[str, Any]) -> str:
        """从探针事件里提取 sink 现场抛出的异常类名（L3 语义层），取不到返回空串。

        探针把 L3 字段（sink_sanitizer / sink_outcome / sink_exception_class / sink_exception_msg /
        hook_inventory）放进事件 ``context`` 映射；``EventBuffer.eventBody`` 把 ``context`` 嵌套进
        ``ev["context"]`` 并展平 canary/canaryState 到顶层；``agent_bridge`` 已把 L3 提升到返回 dict
        顶层；``service._prepare_event`` 已把 L3 并入 ``evidence`` 落库。故三层（顶层 / evidence /
        evidence.context）都要兜底读，确保迟到事件 / 历史事件都能取到。
        """
        if not isinstance(ev, dict):
            return ""
        exc = ev.get("sink_exception_class")
        if isinstance(exc, str) and exc:
            return exc
        evd = ev.get("evidence")
        if isinstance(evd, dict):
            exc = evd.get("sink_exception_class")
            if isinstance(exc, str) and exc:
                return exc
            ctx = evd.get("context")
            if isinstance(ctx, dict):
                exc = ctx.get("sink_exception_class")
                if isinstance(exc, str) and exc:
                    return exc
        return ""

    @staticmethod
    def _consider_sink_exception(by_hid: Dict[str, str], hid: str, ev: Dict[str, Any]) -> None:
        """记录该假说的首个 sink 异常类名（与值级命中同策略：首个即可取证）。"""
        if by_hid.get(hid):
            return
        _exc = TriggerTransactionOrchestrator._extract_sink_exception(ev)
        if _exc:
            by_hid[hid] = _exc

    @staticmethod
    def _flush_sink_exception(tx: TransactionState, by_hid: Dict[str, str]) -> None:
        """把采集到的 sink 异常类名写回各假说裁定（窗口/回填结束时调用一次）。"""
        for hid, exc in (by_hid or {}).items():
            if not exc:
                continue
            v = tx.verdicts.get(hid)
            if v is not None and not v.sink_exception_class:
                v.sink_exception_class = exc

    # 依赖探针侧已接线的 hook_inventory（A2 L3 字段，经 agent_bridge/service 提到顶层并入 evidence）。
    # 给定一个族与其 sink 画像，判断「本轮没拿到任何探针记录」的根因落在哪一侧：
    #   - "probe_coverage_gap"  ：探针根本没织入本族需要的 sink hook（hook_inventory 里查不到本族关键
    #                             hook）→ 属**组件缺陷**，重放智能化（re-trigger / 重放重规划）无用，须修探针。
    #   - "attack_plan_defect"  ：hook 已就位（本族关键 hook 在 hook_inventory 中），但仍无事件 → 属
    #                             **A2 攻击计划 / D1 重放**问题（canary 没投到正确入口 / 路由大小写 /
    #                             payload 形状），重放智能化**可能**有用，值得回灌 A2 重生成。
    #   - "unknown"            ：无 hook_inventory 可用（探针未上报 / 事件缺失）→ 证据缺失，不臆断。
    # 铁律：证据缺失（unknown）绝不臆断任一侧 —— 与「证据缺失 ≠ 阴性」同源。
    _D5_FAM_HOOK_KEYWORDS: Dict[str, tuple] = {
        "sqli": ("jdbc", "preparedstatement", "statement", "sql"),
        "cmdi": ("runtime", "processbuilder", "exec", "process"),
        "pathtraver": ("fileinputstream", "fileoutputstream", "randomaccessfile", "java.io.file"),
        "ldapi": ("initialdircontext", "dircontext", "namingmanager", "ldap"),
        "xpathi": ("xpath", "xpathexpression"),
        "xxe": ("documentbuilder", "saxparser", "xmlinputfactory", "transformer", "xml"),
    }

    @staticmethod
    def extract_hook_inventory(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """从已轮询到的探针事件里提取 hook_inventory（HOOK_INVENTORY 事件或任意事件的 context）。"""
        inv: Dict[str, Any] = {}
        for ev in (rows or []):
            if not isinstance(ev, dict):
                continue
            # 优先顶层（agent_bridge 已提升），其次 evidence，再次 evidence.context。
            h = ev.get("hook_inventory")
            if isinstance(h, dict) and h:
                inv.update(h)
                continue
            evd = ev.get("evidence")
            if isinstance(evd, dict):
                h = evd.get("hook_inventory")
                if isinstance(h, dict) and h:
                    inv.update(h)
                    continue
                ctx = evd.get("context")
                if isinstance(ctx, dict) and isinstance(ctx.get("hook_inventory"), dict):
                    inv.update(ctx["hook_inventory"])
        return inv

    @staticmethod
    def attribute_no_iast_evidence(family: str, hook_inventory: Optional[Dict[str, Any]]) -> str:
        """no-iast-evidence 归因二分（见 _D5_FAM_HOOK_KEYWORDS 说明）。"""
        if not isinstance(hook_inventory, dict) or not hook_inventory:
            return "unknown"
        fam = (family or "").strip().lower()
        kws = TriggerTransactionOrchestrator._D5_FAM_HOOK_KEYWORDS.get(fam)
        if not kws:
            return "unknown"
        _inv_blob = " ".join(str(k) for k in hook_inventory.keys()) + " " + " ".join(
            str(v) for v in hook_inventory.values())
        if any(kw in _inv_blob.lower() for kw in kws):
            return "attack_plan_defect"   # hook 已就位但无事件 → A2/D1 问题
        return "probe_coverage_gap"      # 关键 hook 未织入 → 探针组件缺陷

    def _aggregate_dast(self, impacts: List[DastImpact]) -> DastImpact:
        merged = DastImpact()
        provisional = False
        for imp in impacts:
            merged.reached = merged.reached or imp.reached
            if imp.status_code is not None:
                merged.status_code = imp.status_code
            if imp.body:
                merged.body = (merged.body + "\n" + imp.body)[:2000]
            if imp.response_summary:
                merged.response_summary = (merged.response_summary + " | " + imp.response_summary)[:500]
            if imp.error:
                merged.error = (merged.error + " | " + imp.error)[:500]
            merged.retried = max(merged.retried, imp.retried)
            provisional = provisional or imp.provisional
            merged.blocked = merged.blocked or imp.blocked
            merged.target_unhealthy = merged.target_unhealthy or imp.target_unhealthy
            merged.waf_blocked = merged.waf_blocked or imp.waf_blocked
            # 认证态聚合：失败态优先，避免多 spec 聚合后被成功的 authenticated 掩盖。
            if imp.auth_state:
                if imp.auth_state in ("reauth_failed", "expired") or not merged.auth_state:
                    merged.auth_state = imp.auth_state
            for k, v in (imp.slices or {}).items():
                merged.slices[k] = v

        # D1 写入的 attack_degraded 在聚合时被静默丢弃（merged 取默认 False），
        # D2/D2Judge 因而永远读到「未降级」，把「只发了 canary 探针」当成真打过来裁决。
        # 只在「实际发起过回放」的 impact 上统计：blocked/error 未发流量，不构成攻击也不算降级。
        replayed = [imp for imp in impacts if not imp.blocked and not imp.error]
        if replayed:
            merged.attack_degraded = all(imp.attack_degraded for imp in replayed)
            merged.attack_degraded_any = any(imp.attack_degraded for imp in replayed)
            for imp in replayed:
                if imp.attack_payload_used and not merged.attack_payload_used:
                    merged.attack_payload_used = imp.attack_payload_used
            # DastImpact，默认 payload_source='none' / payload_rejections=[]，于是多 spec
            # 场景下 D1 明明投了真弹、判废也确实发生，聚合后却一律显示 none / 空
            # 非空自相矛盾）。现按「取最强来源 + 并集留痕」合并。
            _SRC_RANK = {"none": 0, "minimal_fallback": 1, "sca_forge": 2, "a2": 3}
            for imp in replayed:
                if _SRC_RANK.get(imp.payload_source, 0) > _SRC_RANK.get(merged.payload_source, 0):
                    merged.payload_source = imp.payload_source
                for _r in (imp.payload_rejections or []):
                    if _r not in merged.payload_rejections:
                        merged.payload_rejections.append(_r)
        for imp in impacts:
            if isinstance(imp.business_logic, dict) and imp.business_logic:
                merged.business_logic.update(imp.business_logic)

        # 唯独漏了 differential —— 事务级 raw_dast_impact 恒 differential={}，D1 明明产出
        # attempted=True 的对照结论，
        # 到确认闸 _differential_override 却永远读不到，21 个仅到达误报两次全量存活。
        # 合并规则（保守，绝不零化 TP）：
        #   1) 任一 attempted 且 harmful=True → 取该条（有害优先，保护真阳性）；
        #   2) 否则任一 attempted 且 harmful=False → 取该条（高置信无差异，降级误报）；
        #   3) 全部未尝试/缺失 → 保持 {}（fail-open）。
        _diff_harmful = None
        _diff_benign = None
        for imp in impacts:
            _d = getattr(imp, "differential", None)
            if not (isinstance(_d, dict) and _d.get("attempted")):
                continue
            if _d.get("harmful"):
                _diff_harmful = _d
                break
            if _diff_benign is None:
                _diff_benign = _d
        if _diff_harmful is not None:
            merged.differential = dict(_diff_harmful)
        elif _diff_benign is not None:
            merged.differential = dict(_diff_benign)

        # sleep_seconds_hint 必须整组取自同一条 impact，绝不能分别取各字段的极值——否则
        # D2 会拿「A 条的 elapsed」减「B 条的 baseline」，delta 基准被跨请求污染，双阈值门失真。
        # 选取规则：只在投放过 sleep 型 payload（sleep_seconds_hint>0）的 impact 里挑 elapsed_ms
        # 最高的一条整组搬过来（时延最显著、信噪比最高）。没有 sleep 型 impact 则三者保持 0.0，
        # D2 不启用时延确认门（回退到 IAST sink-reached 主信号）。
        sleep_impacts = [imp for imp in impacts if (imp.sleep_seconds_hint or 0.0) > 0.0]
        if sleep_impacts:
            best = max(sleep_impacts, key=lambda imp: (imp.elapsed_ms or 0.0))
            merged.elapsed_ms = best.elapsed_ms
            merged.baseline_elapsed_ms = best.baseline_elapsed_ms
            merged.sleep_seconds_hint = best.sleep_seconds_hint

        merged.provisional = provisional
        return merged

    def _multi_match_summary(self, tx: TransactionState) -> Dict[str, Any]:
        # 抵达态的假说不会计入 sink_reached，与早停分支（已改用 is_sink_reached）口径不一致，
        # 下游据此判断「整批到达」会失真。
        reached = [hid for hid, v in tx.verdicts.items() if is_sink_reached(v.state)]
        sanitized = [hid for hid, v in tx.verdicts.items() if v.state == STATE_ARRIVAL_SANITIZED]
        return {
            "hypotheses": len(tx.verdicts),
            "sink_reached": reached,
            "arrival_sanitized": sanitized,
            "no_arrival": [hid for hid, v in tx.verdicts.items() if v.state == STATE_NO_ARRIVAL],
            # 分开，否则修复前后的召回变化无法归因。
            "late_recovered": sorted(hid for hid, ok in (tx.late_recovered or {}).items() if ok),
        }


def aggregate_iast_evidence(per_hypothesis: Dict[str, IastVerdict]) -> Dict[str, Any]:
    """把 per-hypothesis 裁定聚合成单条 iast_evidence（取最强裁定）。

    ④ sink 身份校验：额外透传 ``reached_sink_files``（所有「已抵达 sink」假说的真实 sink_file 集合），
    供 D2 裁决 / 关联层剔除框架噪声 sink（响应写入 / 序列化类）造成的误确认。
    """
    if not per_hypothesis:
        return {"state": STATE_NO_ARRIVAL, "matched_event_ids": [], "confidence": "low",
                "provisional": True, "degraded": False, "canary_state": CanaryStates.NO_ARRIVAL,
                "chain_conformance": {}, "matched_sink_file": "", "reached_sink_files": [],
                "value_hits": [], "value_hit": {}}
    strongest = None
    strongest_rank = -1
    for v in per_hypothesis.values():
        rank = _STATE_RANK.get(v.state, 0)
        if rank > strongest_rank:
            strongest_rank = rank
            strongest = v
    d = strongest.to_dict()
    d["hypotheses"] = len(per_hypothesis)
    # 所有「已抵达 sink」假说的真实 sink 集合（去重），用于身份校验（fail-open：空集合交由下游判断）
    reached_sink_files = sorted(
        {
            v.matched_sink_file
            for v in per_hypothesis.values()
            if is_sink_reached(v.state) and v.matched_sink_file
        }
    )
    d["reached_sink_files"] = reached_sink_files
    # 只从「已到达 sink」的假说里取，未到达假说上的巧合子串（如同名文件被别的请求打开）
    # 不构成数据流证据。命中可能来自不同假说，族相关性由 D2 侧（拿得到 family）最终把关。
    _vhits = [
        dict(v.value_hit or {})
        for v in per_hypothesis.values()
        if is_sink_reached(v.state) and bool((v.value_hit or {}).get("hit"))
    ]
    d["value_hits"] = _vhits
    d["value_hit"] = _vhits[0] if _vhits else {}
    # B2 L3 异常证据：把「家族真实 sink 现场抛出的异常类名」透传给 D2 _ch_sink_exception。
    # 只从「已到达 sink」的假说里取（未到达假说上的异常不构成本族漏洞证据）；
    # 空串 = 未采集到异常（证据缺失，由兜底通道收口，绝不当阴性）。
    _exc = ""
    for v in per_hypothesis.values():
        if is_sink_reached(v.state) and (v.sink_exception_class or ""):
            _exc = v.sink_exception_class
            break
    d["sink_exception_class"] = _exc
    return d


# ---- 默认时钟 / 睡眠（可被测试替换）----
import time as _time

_default_clock = _time.time
_default_sleep = _time.sleep


# ---- 模块级单例（供摄取端回填 hook 调用）----
_ORCHESTRATOR: Optional[TriggerTransactionOrchestrator] = None


def get_orchestrator() -> TriggerTransactionOrchestrator:
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        _ORCHESTRATOR = TriggerTransactionOrchestrator()
    return _ORCHESTRATOR


def notify_backfill(canary: str, canary_state: str, event_id: int = 0) -> List[str]:
    """摄取端落库后 best-effort 触发回填重裁。异常静默吞掉，绝不阻断摄取。"""
    try:
        return get_orchestrator().submit_backfill_event(canary, canary_state, event_id)
    except Exception:
        return []


def reset_orchestrator() -> None:
    global _ORCHESTRATOR
    _ORCHESTRATOR = None
