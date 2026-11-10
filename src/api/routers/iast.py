"""IAST 边缘模块路由（I1 listener）。

端点：
- POST /api/iast/sessions            注册探针会话（颁发 probe_token）
- GET  /api/iast/sessions            列出会话
- GET  /api/iast/sessions/{id}       查单个
- POST /api/iast/trigger-specs       登记 A2 产出的 TriggerSpec（canary 来源）
- POST /api/iast/events              探针批量上报事件（X-Iast-Token 鉴权，见 3.15）
"""
from typing import Optional

from fastapi import APIRouter, Header

from src.api.dependencies import container
from src.iast.schemas import (
    IastEventIngest,
    IastEventIngestResponse,
    IastSessionRegister,
    IastSessionResponse,
    TriggerSpecRegister,
    TriggerSpecResponse,
)

router = APIRouter(prefix="/api/iast", tags=["iast"])


@router.post("/sessions", response_model=IastSessionResponse)
def register_session(payload: IastSessionRegister):
    return container.iast_service.register_session(payload.model_dump())


@router.get("/sessions")
def list_sessions(workspace_id: Optional[int] = None):
    return container.iast_service.list_sessions(workspace_id)


@router.get("/sessions/{session_id}")
def get_session(session_id: int):
    return container.iast_service.get_session(session_id)


@router.post("/sessions/{session_id}/heartbeat")
def session_heartbeat(session_id: int, x_iast_token: str = Header(default="")):
    """§3.13/§3.14 探针心跳上报：写 last_heartbeat_at（X-Iast-Token 鉴权，与事件摄取同机制）。"""
    return container.iast_service.update_heartbeat(session_id, x_iast_token)


@router.post("/trigger-specs", response_model=TriggerSpecResponse)
def register_trigger_spec(payload: TriggerSpecRegister):
    row = container.iast_service.register_trigger_spec(payload.model_dump())
    return {
        "id": row["id"],
        "vulnerability_hash_v2": row["vulnerability_hash_v2"],
        "family": row["family"],
        "taint_marker": row["taint_marker"],
        "target_endpoint": row["target_endpoint"],
        "created_at": row["created_at"],
    }


@router.post("/events", response_model=IastEventIngestResponse)
def ingest_events(payload: IastEventIngest, x_iast_token: str = Header(default="")):
    result = container.iast_service.ingest_events(
        app_name=payload.appName,
        agent_id=payload.agentId,
        token=x_iast_token,
        events=[ev.model_dump() for ev in payload.events],
    )
    return result


@router.get("/correlation")
def correlation(workspace_id: Optional[int] = None, task_id: Optional[int] = None):
    """§3.3 统一 Finding 清单：SAST 根 + IAST 运行时证据 + 统计（覆盖率/confirmed_runtime/按资产）。"""
    return container.iast_correlation_service.correlate(workspace_id=workspace_id, task_id=task_id)


@router.get("/task-events-summary")
def task_events_summary(task_id: int):
    """I1 监听器摘要：本 task 的 IAST 运行时事件统计（sink 事件数 / canary 到达 / 在线探针）。"""
    return container.iast_service.summarize_task_events(task_id)


@router.get("/ingest-stats")
def ingest_stats():
    """item 4 方向 5：ingest 吞吐可观测性。

    返回探针事件摄取链路的实时吞吐指标（队列深度 / 排空速率 / 批大小 / 刷盘延迟 / 背压窗口），
    用于判断瓶颈在写库还是探针上报——与方案文档「一眼判断是否瓶颈在写库」对齐。
    """
    from src.iast.ingest_metrics import INGEST_METRICS
    return INGEST_METRICS.snapshot()


@router.post("/correlation/report")
def correlation_report(workspace_id: int, task_id: Optional[int] = None):
    """§4.5 独立 iast-correlation 报告：生成 .md/.json，并在提供有效 task_id 时登记 reports 表。"""
    meta = container.iast_correlation_service.generate_report(workspace_id, task_id=task_id)
    # reports.task_id 有 FK 非空约束，仅当提供有效 task_id 时持久化（不碰 B1/B2 内核）。
    if task_id is not None:
        container.db.execute(
            "INSERT INTO reports (task_id, workspace_id, report_type, file_path, generated_at) VALUES (?, ?, ?, ?, ?)",
            (task_id, workspace_id, "iast-correlation", meta["file_path"], meta["generated_at"]),
        )
    return meta


@router.get("/adjudication")
def adjudication(workspace_id: Optional[int] = None, task_id: Optional[int] = None):
    """§4.7.1/§8.1 I2 覆盖率差集审计（只读，不落库反哺候选）。"""
    return container.i2_adjudicator.audit_coverage(workspace_id=workspace_id, task_id=task_id)


@router.get("/trigger-specs")
def list_trigger_specs(workspace_id: Optional[int] = None, task_id: Optional[int] = None):
    """§D1 靶面清单：返回本 workspace/task 的 TriggerSpec（D1 实际会重放的靶面），
    供前端 D1 子面板逐项展示 endpoint/param/family/canary，并标注来源（a2 / idor_or_other）。"""
    from src.iast.canary import CanaryMatcher
    sql = "SELECT * FROM trigger_specs"
    clauses: list = []
    params: list = []
    if workspace_id is not None:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    if task_id is not None:
        clauses.append("task_id = ?")
        params.append(task_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    rows = container.db.execute(sql, params, fetchall=True) or []
    out = []
    for r in rows:
        r = dict(r)
        tm = r.get("taint_marker") or ""
        out.append({
            "id": r.get("id"),
            "task_id": r.get("task_id"),
            "vulnerability_hash_v2": r.get("vulnerability_hash_v2"),
            "endpoint": r.get("target_endpoint") or "",
            "http_method": r.get("http_method") or "",
            "param_name": r.get("param_name") or "",
            "param_location": r.get("param_location") or "",
            "family": r.get("family") or "",
            "canary_identity": CanaryMatcher.find_identity(tm),
            "source": "a2" if r.get("task_id") == task_id else "idor_or_other",
        })
    return out


@router.get("/bola-race/status")
def bola_race_status_endpoint():
    """§2.2/§7.9 BOLA/RACE 占位状态：本期不交付，依赖 SAST 业务逻辑策略分析能力。"""
    from src.iast.bola_race import bola_race_status
    return bola_race_status()


@router.post("/adjudication/harvest")
def adjudication_harvest(workspace_id: Optional[int] = None, task_id: Optional[int] = None):
    """§4.6/§4.7.1 I2 反哺候选入库（净化器 + 新规则种子，走 RuleFeedback 人工 confirm 闸门）。"""
    return container.i2_adjudicator.harvest_feedback(workspace_id=workspace_id, task_id=task_id)
