from fastapi import APIRouter

from src.api.dependencies import container
from src.api.schemas import FindingResponse

router = APIRouter(prefix="/api/results", tags=["results"])


@router.get("/findings", response_model=list[FindingResponse])
def list_findings(workspace_id: int | None = None, task_id: int | None = None):
    return container.finding_repository.list(workspace_id=workspace_id, task_id=task_id)
