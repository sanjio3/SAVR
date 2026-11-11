from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import TaintRuleCandidateRequest, TaintRuleConfirmRequest

router = APIRouter(prefix="/api/rule-feedback", tags=["rule-feedback"])


@router.post("/taint-candidates")
def record_candidate(payload: TaintRuleCandidateRequest):
    try:
        return container.rule_feedback_service.record_candidate(
            kind=payload.kind,
            pattern=payload.pattern,
            language=payload.language,
            family=payload.family,
            confidence=payload.confidence,
            workspace_id=payload.workspace_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/taint-candidates")
def list_candidates(
    workspace_id: Optional[int] = Query(default=None),
    status: str = Query(default=""),
    kind: str = Query(default=""),
):
    return container.rule_feedback_service.list_candidates(workspace_id=workspace_id, status=status, kind=kind)


@router.post("/taint-candidates/{rule_id}/confirm")
def confirm_candidate(rule_id: int, payload: TaintRuleConfirmRequest):
    try:
        return container.rule_feedback_service.confirm(rule_id, confirmed_by=payload.confirmed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/metrics")
def metrics(workspace_id: Optional[int] = Query(default=None)):
    return container.rule_feedback_service.metrics(workspace_id=workspace_id)
