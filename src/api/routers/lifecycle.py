from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import RetestRequest, StatusUpdateRequest

router = APIRouter(prefix="/api", tags=["lifecycle"])


@router.get("/vulnerabilities")
def list_vulnerabilities(workspace_id: Optional[int] = Query(default=None), status: str = ""):
    return container.retest_service.list_instances(workspace_id=workspace_id, status=status)


@router.get("/vulnerabilities/{vulnerability_hash}")
def vulnerability_detail(vulnerability_hash: str, workspace_id: int = Query(...)):
    try:
        return container.retest_service.instance_detail(workspace_id, vulnerability_hash)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/vulnerabilities/{vulnerability_hash}/retest")
def retest(vulnerability_hash: str, payload: RetestRequest):
    try:
        return container.retest_service.retest(
            payload.workspace_id,
            vulnerability_hash,
            strategy=payload.strategy,
            result=payload.result,
            app_id=payload.app_id,
            base_ref=payload.base_ref,
            patch_ref=payload.patch_ref,
            repo_path=payload.repo_path,
            evidence=payload.evidence,
            created_by=payload.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/vulnerabilities/{vulnerability_hash}/status")
def update_status(vulnerability_hash: str, payload: StatusUpdateRequest):
    try:
        return container.retest_service.set_status(
            payload.workspace_id,
            vulnerability_hash,
            payload.target_status,
            created_by=payload.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
