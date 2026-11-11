from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import FixSuggestionResponse, FixFeedbackRequest, HumanDecisionRequest, PatchDraftResponse

router = APIRouter(prefix="/api", tags=["finding-workflow"])


@router.post("/findings/{finding_id}/ai-review")
def ai_review(finding_id: int):
    try:
        return container.finding_workflow_service.generate_ai_review(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/findings/{finding_id}/human-decision")
def human_decision(finding_id: int, payload: HumanDecisionRequest):
    try:
        return container.finding_workflow_service.record_human_decision(
            finding_id,
            decision=payload.decision,
            reason_type=payload.reason_type,
            reason_detail=payload.reason_detail,
            reviewer=payload.reviewer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/findings/{finding_id}/fix-suggestion", response_model=FixSuggestionResponse)
def fix_suggestion(finding_id: int):
    try:
        return container.finding_workflow_service.generate_fix_suggestion(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/findings/{finding_id}/patch-draft", response_model=PatchDraftResponse)
def patch_draft(finding_id: int):
    try:
        return container.finding_workflow_service.generate_patch_draft(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/review/queue")
def review_queue(task_id: Optional[int] = Query(default=None), workspace_id: Optional[int] = Query(default=None)):
    return container.finding_workflow_service.review_queue(task_id=task_id, workspace_id=workspace_id)


@router.post("/findings/{finding_id}/fix-feedback")
def fix_feedback(finding_id: int, payload: FixFeedbackRequest):
    try:
        return container.finding_workflow_service.record_fix_feedback(
            finding_id,
            adopted=payload.adopted,
            misleading=payload.misleading,
            led_to_retest_pass=payload.led_to_retest_pass,
            suggestion_id=payload.suggestion_id,
            comment=payload.comment,
            created_by=payload.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/metrics/fix-feedback")
def fix_feedback_metrics(workspace_id: Optional[int] = Query(default=None)):
    return container.finding_workflow_service.fix_feedback_metrics(workspace_id=workspace_id)


@router.get("/findings/{finding_id}/review-history")
def review_history(finding_id: int):
    try:
        return container.finding_workflow_service.review_history(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/model-runs")
def model_runs(purpose: str = "", limit: int = Query(default=200, le=1000)):
    return container.model_run_repository.list(purpose=purpose, limit=limit)


@router.get("/metrics/review")
def review_metrics(task_id: Optional[int] = Query(default=None), workspace_id: Optional[int] = Query(default=None)):
    return container.finding_workflow_service.review_metrics(task_id=task_id, workspace_id=workspace_id)
