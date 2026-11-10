from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import AutonomyEvaluateRequest, AutonomyPolicyRequest

router = APIRouter(prefix="/api/autonomy", tags=["autonomy"])


@router.get("/policies")
def list_policies(enabled_only: bool = Query(default=False)):
    return container.autonomy_service.list_policies(enabled_only=enabled_only)


@router.post("/policies")
def upsert_policy(payload: AutonomyPolicyRequest):
    return container.autonomy_service.upsert_policy(**payload.model_dump())


@router.post("/evaluate")
def evaluate(payload: AutonomyEvaluateRequest):
    try:
        return container.autonomy_service.evaluate_finding(payload.finding_id, created_by=payload.created_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/actions")
def list_actions(workspace_id: Optional[int] = Query(default=None)):
    return container.autonomy_service.list_actions(workspace_id=workspace_id)


@router.post("/actions/{action_id}/rollback")
def rollback(action_id: int):
    try:
        return container.autonomy_service.rollback_action(action_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
