
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import (
    AdvisoryIngestRequest,
    AdvisoryMatchRequest,
    SCAImpactQueryRequest,
    SCAScanRequest,
)

router = APIRouter(prefix="/api/sca", tags=["sca"])


@router.get("/tools")
def tools():
    return container.sca_asset_service.tool_statuses()


@router.post("/scan")
def scan(payload: SCAScanRequest):
    result = container.sca_asset_service.scan_project(
        payload.project_path,
        workspace_id=payload.workspace_id,
        task_id=payload.task_id,
        output_dir=payload.output_dir or None,
        tool=payload.tool,
        severity_threshold=payload.severity_threshold,
        ignore_unfixed=payload.ignore_unfixed,
        run_tool=payload.run_tool,
        persist=payload.persist,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("message", "SCA scan failed"))
    return result


@router.get("/components")
def components(workspace_id: Optional[int] = Query(default=None), name: str = "", ecosystem: str = ""):
    return container.sca_asset_service.list_components(workspace_id=workspace_id, name=name, ecosystem=ecosystem)


@router.get("/vulnerabilities")
def vulnerabilities(workspace_id: Optional[int] = Query(default=None), advisory_id: str = "", component_name: str = ""):
    return container.sca_asset_service.list_vulnerabilities(workspace_id=workspace_id, advisory_id=advisory_id, component_name=component_name)


@router.post("/impact-query")
def impact_query(payload: SCAImpactQueryRequest):
    return container.sca_asset_service.impact_query(payload.model_dump(exclude_none=True))


@router.post("/advisories/ingest")
def ingest_advisories(payload: AdvisoryIngestRequest):
    try:
        stored = container.advisory_service.ingest_dataset(payload.entries, source=payload.source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ingested": len(stored), "advisories": stored}


@router.get("/advisories")
def list_advisories(malicious_only: bool = Query(default=False)):
    return container.advisory_service.repo.list(malicious_only=malicious_only)


@router.post("/advisories/match")
def match_advisories(payload: AdvisoryMatchRequest):
    return container.advisory_service.match_component(
        ecosystem=payload.ecosystem, name=payload.name, version=payload.version
    )


@router.get("/advisories/scan-installed")
def scan_installed(workspace_id: Optional[int] = Query(default=None)):
    return container.advisory_service.scan_installed(workspace_id=workspace_id)
