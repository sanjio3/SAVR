from fastapi import APIRouter, HTTPException, Query

from src.api.dependencies import container
from src.api.schemas import EvaluationMatrixRequest, EvaluationRunRequest

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.post("/runs")
def run_evaluation(payload: EvaluationRunRequest):
    try:
        return container.evaluation_service.run(
            name=payload.name,
            dataset_path=payload.dataset_path,
            model=payload.model,
            prompt_version=payload.prompt_version,
            repeat=payload.repeat,
            seed_jitter=payload.seed_jitter,
            scan_mode=payload.scan_mode,
            agent_impl=payload.agent_impl,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/matrix")
def run_matrix(payload: EvaluationMatrixRequest):
    try:
        return container.evaluation_service.run_matrix(
            name=payload.name,
            dataset_path=payload.dataset_path,
            repeat=payload.repeat,
            seed_jitter=payload.seed_jitter,
            models=payload.models or None,
            prompt_versions=payload.prompt_versions or None,
            scan_modes=payload.scan_modes or None,
            agent_impls=payload.agent_impls or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/runs")
def list_runs(limit: int = Query(default=100, le=1000)):
    return container.evaluation_service.list_runs(limit=limit)


@router.get("/runs/{run_id}")
def run_detail(run_id: int):
    try:
        return container.evaluation_service.run_detail(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/compare")
def compare(run_a: int = Query(...), run_b: int = Query(...)):
    try:
        return container.evaluation_service.compare(run_a, run_b)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
