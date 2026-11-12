"""配额策略端点。

提供配额策略的增删查与评估接口。配额本身不新建流水表，评估时实时聚合
scan_tasks / model_runs。金额型（cost）当前 provider 未上报单价，limit 仅占位。
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException

from src.application.quota_service import QuotaService

router = APIRouter(prefix="/api/quota", tags=["quota"])


@router.get("/policies")
def list_policies(workspace_id: Optional[int] = None) -> Dict[str, Any]:
    return {"policies": QuotaService().list_policies(workspace_id=workspace_id)}


@router.post("/policies")
def upsert_policy(payload: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    try:
        return QuotaService().upsert_policy(**payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/policies/{policy_id}")
def delete_policy(policy_id: int) -> Dict[str, Any]:
    ok = QuotaService().delete_policy(policy_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"policy {policy_id} not found")
    return {"deleted": True}


@router.get("/evaluate")
def evaluate(workspace_id: int, planned_count: int = 0) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = QuotaService().evaluate(workspace_id, planned_count=planned_count)
    blocking = [r for r in rows if r["exceeded"] and r["action"] == "reject"]
    return {"workspace_id": workspace_id, "evaluations": rows, "blocked": bool(blocking)}
