"""Cost + operations metrics endpoints (G9 + G12, 第四版 //).

Exposes annual-cost estimation, scan-trigger policies, the operating dashboard
(denoise/false-kill/adoption rates), and offline ticket export. All handlers are
offline/pure — no external network I/O.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from src.api.dependencies import container
from src.api.schemas import (
    ScanCostRecordRequest,
    ScanTriggerPolicyRequest,
    TicketExportRequest,
)
from src.api.security import ROLE_REVIEWER, require_role
from src.core import cost_model

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.post("/scan-cost", dependencies=[Depends(require_role(ROLE_REVIEWER))])
def record_scan_cost(payload: ScanCostRecordRequest):
    fields = payload.model_dump()
    if fields.get("cost_usd") is None:
        fields["cost_usd"] = cost_model.scan_cost(
            input_tokens=fields["input_tokens"],
            output_tokens=fields["output_tokens"],
            model=fields["model"],
        )
    return container.metrics_service.record_scan_cost(**fields)


@router.get("/annual-cost")
def annual_cost(workspace_id: Optional[int] = None, variance: float = 0.2):
    return container.metrics_service.annual_cost(workspace_id=workspace_id, variance=variance)


@router.post("/trigger-policy", dependencies=[Depends(require_role(ROLE_REVIEWER))])
def upsert_trigger_policy(payload: ScanTriggerPolicyRequest):
    return container.metrics_service.upsert_trigger_policy(**payload.model_dump())


@router.get("/trigger-policy")
def list_trigger_policies(workspace_id: Optional[int] = None):
    return {"policies": container.metrics_service.list_trigger_policies(workspace_id=workspace_id)}


@router.get("/ops")
def ops_dashboard(workspace_id: Optional[int] = None):
    return container.metrics_service.ops_dashboard(workspace_id=workspace_id)


@router.get("/usage")
def usage_stats(workspace_id: Optional[int] = None):
    """用量统计：扫描次数与周期、扫描代码量、LLM token 与成本、Agent 调用次数与耗时、
    按工作区分布。与 /ops（效果度量：降噪率/误杀率/覆盖度）互补，不是同一件事。"""
    return container.metrics_service.usage_stats(workspace_id=workspace_id)


@router.get("/iast")
def iast_source_stats(workspace_id: Optional[int] = None, task_id: Optional[int] = None):
    """ IAST 来源统计切片（覆盖率 / confirmed_runtime 占比 / 按资产分布），复用关联聚合。"""
    return container.metrics_service.iast_source_stats(workspace_id=workspace_id, task_id=task_id)


@router.post("/ticket", dependencies=[Depends(require_role(ROLE_REVIEWER))])
def export_ticket(payload: TicketExportRequest):
    try:
        return container.metrics_service.export_ticket(
            payload.finding_id,
            platform=payload.platform,
            project=payload.project,
            webhook_url=payload.webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
