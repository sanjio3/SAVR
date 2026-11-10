"""探针兼容桥（agent bridge）：让 sec-probe.jar 真正连上 SAVR 后端。

探针（IAST_RASP/probe-java）的真实协议与后端 IAST 模块（/api/iast/*）不一致：
- 心跳：POST {sec.server.url}/api/agent/heartbeat，鉴权头 X-Agent-Token，仅带 agentId/appName，无 session id。
- 事件：POST {sec.server.url}/api/agent/events，鉴权头 X-Agent-Token，body 为 {agentId, appName, environment, events:[...]}。
- 事件体为 RASP 风格：{eventType, severity, traceId, sink(string), payload(string), context(map)}，
  而非后端的 canary 风格（sink{file,line,method} + canary + vulnType）。

本桥把探针协议翻译进既有 IastService（authenticate_by_token / update_heartbeat_by_token /
ingest_events），使挂载探针后能真正上报心跳与事件，I1/D2/I2 不再静默空跑。
canary 仅取自平台注入的身份段 s4st41<16hex>（平台经 D1 重放注入到 HTTP 参数/请求体）。
命中即与 trigger_specs.taint_marker 前缀一致，关联层据此判定 arrival；未命中即 no-arrival。
本桥不绑定任何 rasp 概念，不会为事件自造合成身份键。
"""
import json
import logging
import os
import threading
from functools import partial
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, Request
from starlette.concurrency import run_in_threadpool

from src.api.dependencies import container
from src.iast.canary import CanaryStates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent-bridge"])

# 鉴权失败此前是静默的 —— 后端返回 HTTP 200 + accepted=0，探针侧
# ProbeHttpClient 不解析响应体，运维要等 D2 才发现 IAST 证据全丢。
# 这里只加可观测性（WARN 日志 + 计数），不改 200 状态码、不改探针协议。
_AUTH_REJECT_LOCK = threading.Lock()
_AUTH_REJECT_COUNT = 0
_AUTH_REJECT_LAST: Dict[str, Any] = {}


def record_auth_reject(app_name: str, agent_id: str, token_prefix: str,
                       path: str, detail: str) -> int:
    """记录一次鉴权拒绝；返回累计次数。只存 token 前缀，不落全量凭据。"""
    global _AUTH_REJECT_COUNT, _AUTH_REJECT_LAST
    with _AUTH_REJECT_LOCK:
        _AUTH_REJECT_COUNT += 1
        _AUTH_REJECT_LAST = {"app_name": app_name, "agent_id": agent_id,
                             "token_prefix": token_prefix, "path": path,
                             "detail": detail}
        count = _AUTH_REJECT_COUNT
    logger.warning(
        "[probe-auth] 拒绝探针请求 #%d path=%s app=%s agent=%s token=%s… ：%s。"
        "探针 token 与 iast_sessions 不对齐，事件会被静默丢弃；"
        "请核对注入侧与 DB 真值（tools/probe_preflight.py）",
        count, path, app_name, agent_id, token_prefix, detail)
    return count


def auth_reject_stats() -> Dict[str, Any]:
    """供诊断端点/单测读取，不参与任何落库契约。"""
    with _AUTH_REJECT_LOCK:
        return {"count": _AUTH_REJECT_COUNT, "last": dict(_AUTH_REJECT_LAST)}


def _now_iso() -> str:
    from datetime import datetime
    return datetime.utcnow().isoformat()


def _translate_probe_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    """把探针事件翻译成后端 ingest_events 期望的 canary 风格事件体。

    canary 必须取自平台注入的身份段，而非自造合成值：
    - 探针上报的 payload / context / traceId 可能携带平台注入的 s4st41<16hex> 身份段
      （平台经 D1 重放注入到 HTTP 参数/请求体）。命中即把 canary 设为该身份段，与
      trigger_specs.taint_marker 前缀一致 → ingest 的 CanaryMatcher(canary).match(sample)
      据此判定 arrival（sink-reached / arrived）。
    - 未命中（canary 没到 sink）：canary 置空、canary_source="none"，关联层判 no-arrival。
      这是诚实的「探针没观测到 canary 抵达 sink」语义，不造任何合成身份键。
    """
    event_type = str(ev.get("eventType") or ev.get("event_type") or "sink_call")
    severity = str(ev.get("severity") or "INFO")
    trace_id = str(ev.get("traceId") or ev.get("trace_id") or "")
    # 2026-09-15 item 5：探针 SINK_HIT 现场上报 sinkMethod / stackTrace。
    # sink 既可能是字符串（仅文件名）也可能是对象（含 file/method），统一归一。
    sink_raw = ev.get("sink") or ""
    if isinstance(sink_raw, dict):
        sink_file = str(sink_raw.get("file") or "")
        sink_method = str(sink_raw.get("method") or "")
    else:
        sink_file = str(sink_raw)
        sink_method = ""
    # 顶层 sinkMethod 优先（探针 2026-09-15 新增字段），兜底对象内 method。
    sink_method = str(ev.get("sinkMethod") or sink_method or "")
    payload = ev.get("payload")
    if payload is None:
        payload = ""
    payload = str(payload)
    context = ev.get("context") or {}
    if not isinstance(context, dict):
        context = {}
    vuln_type = str(context.get("vulnType") or context.get("vuln_type") or event_type)
    principal = str(context.get("principal") or "")
    # 顶层 stackTrace 优先（探针 2026-09-15 新增字段），兜底 context.stackTrace / stack_trace。
    stack_trace = str(ev.get("stackTrace") or context.get("stackTrace") or context.get("stack_trace") or "")

    # v2 证据分层（L3 语义层）：探针在 context 中回带的消毒器 / 异常 / 插桩台账，提升到顶层，
    # 使 service.compute_value_hit / d2_facade 各通道直接可读，不必深挖 context。
    l3_fields = {}
    for _k in ("sink_sanitizer", "sink_outcome", "sink_exception_class", "sink_exception_msg", "hook_inventory"):
        _v = context.get(_k)
        if _v not in (None, ""):
            l3_fields[_k] = _v

    # 层1A（2026-08-30 决议）：优先采用探针在 sink 现场经 TaintStore 解析出的 canary 身份段。
    # header 通道 A 的 X-SASTAI-Trace 仅落在探针字段、payload 里没有，此路修复 header 路径 0 行问题；
    # 否则退回在 payload/context/traceId 文本里扫描平台注入的 s4st41<16hex>。
    probe_canary = str(ev.get("canary") or "")
    probe_identity = _extract_canary_identity(probe_canary, {}, "")
    identity = probe_identity or _extract_canary_identity(payload, context, trace_id)

    # 层2A（2026-08-30 决议）：canary 抵达 sink 时探针断言 SINK_REACHED。
    # 优先信任探针断言（ev["canaryState"]）；探针未断言时，对 sink 型事件按「命中 canary 即抵达 sink」
    # 兜底断言 sink-reached（与探针 resolveCanaryForSink 语义一致），使 D1 重放链路标记 confirmed_runtime。
    # 设计一①：探针在 sink 现场（canary 确证位于 sink 实参）显式断言的 SINK_REACHED，归一到独立的
    # sink-reached-probe 态——与被动兜底 sink-reached 区分，使 D2 即便 attack_degraded 也判有害。
    probe_canary_state = str(ev.get("canaryState") or ev.get("canary_state") or "")
    # 2026-10-07（r63-verify 实测根因修复，方法A 第三处）：把 TAINT_FLOW 从「参与到达裁决」里摘掉。
    #
    # 实测依据（run 239 pathtraver-1）：
    #   162 个被判「到达」的 spec 里，0 个带真实 sink 级断言；到达信号全部来自 TAINT_FLOW，
    #   而它的 canary_match 是 **trace 级**（请求里带过 canary 即为 1）、
    #   且 821 条 TAINT_FLOW 的 sink_method **全为空串**（后端连是哪个 sink 都不知道）。
    #   真 TP(00001) 与安全 FP(00063/00064) 的 TAINT_FLOW 签名完全一致
    #   （sink_reached=1, canary_match=1）⇒ 到达 ≠ 可利用。
    #   LDAP 对照实验佐证：到达 39→94，TP 命中恒为 27，精确率恒 56.2%（多出的全是 FP）。
    #
    # 收紧后：到达只认「探针在 sink 实参里断言的抵达态」（canaryState 非空，或事件是 SINK_HIT）。
    # TAINT_FLOW 降级为「污点流过」的观测记录，**不再**单独构成 sink-reached。
    # 开关保留：SAST_AI_TAINT_FLOW_AS_ARRIVAL=1 可恢复旧行为（便于回滚与 A/B 对比）。
    _taint_flow_counts = os.environ.get("SAST_AI_TAINT_FLOW_AS_ARRIVAL", "0") not in (
        "0", "", "false", "False", "no")
    _SINK_EVENTS = ("SINK_HIT", "TAINT_FLOW", "RASP_BLOCKED_TAINT", "BOLA_SUSPECT")
    # 真正构成「到达」的事件类型：TAINT_FLOW 仅在显式打开旧开关时才计入
    _ARRIVAL_EVENTS = (("SINK_HIT", "RASP_BLOCKED_TAINT", "BOLA_SUSPECT") if not _taint_flow_counts
                       else _SINK_EVENTS)
    if identity:
        canary = identity
        canary_source = "platform"
        if probe_canary_state:
            # 设计一①：探针在 sink 现场（canary 确证位于 sink 实参）显式断言的抵达态，
            # 归一到独立的 sink-reached-probe，使 D2 即便 attack_degraded 也判有害（不降级）。
            # 探针仅会在 sink 站点 resolveCanaryForSink 命中时发出正抵达态；若探针显式判否
            # （no-arrival）则尊重其判否，不强置 sink-reached-probe。
            if probe_canary_state == CanaryStates.NO_ARRIVAL:
                canary_state = CanaryStates.NO_ARRIVAL
            else:
                canary_state = CanaryStates.SINK_REACHED_PROBE
        elif event_type in _ARRIVAL_EVENTS:
            canary_state = CanaryStates.SINK_REACHED
        else:
            canary_state = ""
    else:
        # 未命中平台身份段：事件与平台 canary 无关，直接判 no-arrival。
        # 不造任何合成身份键（探针与 rasp 无关）。
        canary = ""
        canary_source = "none"
        canary_state = ""

    return {
        "eventType": event_type,
        "severity": severity,
        "traceId": trace_id,
        "vulnType": vuln_type,
        "canary": canary,
        "canary_source": canary_source,
        "canaryState": canary_state,
        "sink": {"file": sink_file, "line": 0, "method": sink_method},
        "source": {"name": canary_source, "type": "probe", "value": payload},
        "principal": principal,  # 占位，真正 principal 由 context 提供
        "stackTrace": stack_trace,
        # 方案 B：透传探针回带的污点传播路径（JSON 数组字符串），供 I1 逐节点核对。
        "taintPath": str(context.get("taint_path") or ""),
        # 顶层透传探针原始 context（污点路径、HTTP 细节等），供 I1/I2 逐节点核对。
        "context": context,
        "evidence": {"payload": payload, "context": context},
        **l3_fields,
    }


def _extract_canary_identity(payload: str, context: Dict[str, Any], trace_id: str) -> str:
    """在探针上报文本中查找平台 canary 身份段 s4st41<16hex>。"""
    from src.iast.canary import CanaryMatcher
    candidates = [payload, json.dumps(context, ensure_ascii=False), trace_id]
    for c in candidates:
        ident = CanaryMatcher.find_identity(c)
        if ident:
            return ident
    return ""


@router.post("/heartbeat")
async def agent_heartbeat(request: Request, x_agent_token: str = Header(default="")):
    """探针心跳：X-Agent-Token 鉴权，按 token 反查会话并更新 last_heartbeat_at。

    方案 3：心跳体携带 agentPhase（WARMING_UP / READY），一并写回 iast_sessions.agent_phase，
    供前端展示「预热中 / 已就绪」。
    """
    body = _safe_json(await request.body())
    app_name = str(body.get("appName") or body.get("app_name") or "")
    agent_id = str(body.get("agentId") or body.get("agent_id") or "")
    agent_phase = str(body.get("agentPhase") or body.get("agent_phase") or "")
    # 2026-10-28（本轮/486/488 根因）：本端点原先把 authenticate/update_heartbeat 这类
    # 同步 DB 调用直接跑在事件循环线程上；扫描期 runner 高频心跳 + 事件批量写会把循环堵死，
    # 所有 HTTP（含 /ping）一起超时。DB 调用一律 run_in_threadpool 挪出事件循环。
    session = await run_in_threadpool(
        container.iast_service.authenticate_by_token, x_agent_token)
    if not session:
        detail = f"X-Agent-Token 不匹配（app={app_name} agent={agent_id}）"
        record_auth_reject(app_name, agent_id, x_agent_token[:6],
                           "/api/agent/heartbeat", detail)
        return _envelope(None, error=detail)
    updated = await run_in_threadpool(
        partial(container.iast_service.update_heartbeat_by_token,
                x_agent_token, agent_phase=agent_phase if agent_phase else None))
    return _envelope({
        "status": "ok",
        "session_id": updated.get("id"),
        "appName": updated.get("app_name"),
        "agentId": updated.get("agent_id"),
        "agentPhase": updated.get("agent_phase"),
        "last_heartbeat_at": updated.get("last_heartbeat_at"),
    })


@router.post("/events")
async def agent_events(request: Request, x_agent_token: str = Header(default="")):
    """探针事件批量上报：X-Agent-Token 鉴权 + RASP→canary 事件翻译 → IastService.ingest_events。"""
    body = _safe_json(await request.body())
    app_name = str(body.get("appName") or body.get("app_name") or "")
    agent_id = str(body.get("agentId") or body.get("agent_id") or "")
    events = body.get("events") or []
    if not isinstance(events, list):
        events = []
    session = await run_in_threadpool(
        container.iast_service.authenticate_by_token, x_agent_token)
    if not session:
        detail = f"X-Agent-Token 不匹配（app={app_name} agent={agent_id}）"
        record_auth_reject(app_name, agent_id, x_agent_token[:6],
                           "/api/agent/events", detail)
        return {"accepted": 0, "rejected": len(events), "errors": [detail]}
    translated = [_translate_probe_event(e) for e in events if isinstance(e, dict)]
    # 批量写库必须出事件循环（见 heartbeat 处注释）。
    result = await run_in_threadpool(
        partial(
            container.iast_service.ingest_events,
            app_name=session["app_name"],
            agent_id=session["agent_id"],
            token=x_agent_token,
            events=translated,
        )
    )
    return result


def _safe_json(raw: bytes) -> Dict[str, Any]:
    if not raw:
        return {}
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        # 2026-10-15 修复（P-A 根因兜底）：探针 JsonCodec.quote 曾漏转义控制字符（\r/\t 等），
        # 使整批事件体 JSON 非法 → 本函数原返回 {} → events=[] → accepted:0（HTTP 200），整批
        # 被**静默丢弃**（探针侧无告警）。探针 JSON 为紧凑格式（无结构空白），故所有控制字符都在
        # 字符串内——补转义为 \uXXXX 后重试即可救回。仅对首次解析失败者生效，合法 JSON 不受影响。
        import re as _re
        salvaged = _re.sub(r"[\x00-\x1f]", lambda m: "\\u%04x" % ord(m.group()), text)
        try:
            data = json.loads(salvaged)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}


def _envelope(data: Optional[Dict[str, Any]], error: Optional[str] = None) -> Dict[str, Any]:
    if error:
        return {"data": None, "error": error}
    return {"data": data or {}}
