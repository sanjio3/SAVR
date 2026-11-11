from fastapi import APIRouter, HTTPException, Query, Response

from src.api.dependencies import container
from src.api.schemas import WorkspaceCreate, WorkspaceResponse, WorkspaceUpdate

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


@router.get("", response_model=list[WorkspaceResponse])
def list_workspaces(include_archived: bool = Query(False)):
    return container.workspace_service.list_workspaces(include_archived=include_archived)


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
def get_workspace(workspace_id: int):
    workspace = container.workspace_service.get_workspace(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return workspace


@router.get("/by-slug/{slug}", response_model=WorkspaceResponse)
def get_workspace_by_slug(slug: str):
    """按 slug 解析 workspace（前端 /workspace/:slug/task/:id 路由用，保证 URL 携带 workspace 上下文）。"""
    from src.infrastructure.repositories import WorkspaceRepository
    ws = WorkspaceRepository(container.db).get_by_slug(slug)
    if ws is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return ws


@router.post("", response_model=WorkspaceResponse, status_code=201)
def create_workspace(payload: WorkspaceCreate):
    try:
        return container.workspace_service.create_workspace(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/{workspace_id}", response_model=WorkspaceResponse)
def update_workspace(workspace_id: int, payload: WorkspaceUpdate):
    try:
        return container.workspace_service.update_workspace(workspace_id, payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{workspace_id}/archive", response_model=WorkspaceResponse)
def archive_workspace(workspace_id: int):
    try:
        return container.workspace_service.archive_workspace(workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{workspace_id}/unarchive", response_model=WorkspaceResponse)
def unarchive_workspace(workspace_id: int):
    try:
        return container.workspace_service.unarchive_workspace(workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{workspace_id}", status_code=204)
def delete_workspace(workspace_id: int):
    try:
        container.workspace_service.delete_workspace(workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)
