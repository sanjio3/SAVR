from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from src.api.dependencies import container
from src.api.schemas import EntryDiscoveryRequest, RuleCandidateDecisionRequest

router = APIRouter(prefix="/api/entry-discovery", tags=["entry-discovery"])


@router.post("/tasks")
def discover(payload: EntryDiscoveryRequest):
    if payload.persist:
        return container.entry_discovery_service.discover_and_persist(
            payload.project_path, workspace_id=payload.workspace_id, task_id=payload.task_id
        )
    return container.entry_discovery_service.discover(payload.project_path)


@router.get("/tasks/{task_id}/results")
def task_results(task_id: str):
    return {"task_id": task_id, "status": "ephemeral", "message": "Entry discovery runs synchronously; call POST /api/entry-discovery/tasks with persist=true to store assets."}


@router.get("/assets")
def list_assets(workspace_id: Optional[int] = Query(default=None), entry_type: str = Query(default="")):
    return container.entry_asset_repository.list_entries(workspace_id=workspace_id, entry_type=entry_type)


@router.get("/rule-candidates")
def list_rule_candidates(workspace_id: Optional[int] = Query(default=None), status: str = Query(default="")):
    return container.entry_asset_repository.list_rule_candidates(workspace_id=workspace_id, status=status)


@router.post("/rule-candidates/{rule_id}/decision")
def decide_rule_candidate(rule_id: int, payload: RuleCandidateDecisionRequest):
    updated = container.entry_asset_repository.set_rule_status(rule_id, payload.status, payload.confirmed_by)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"rule candidate {rule_id} not found")
    return updated
