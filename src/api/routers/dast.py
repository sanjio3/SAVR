
from fastapi import APIRouter
from typing import Any, Dict

from src.api.dependencies import container
from src.api.schemas import IdorAccountImportRequest, IdorApiImportRequest, IdorAppRequest, IdorScanRequest, IdorTrafficImportRequest

router = APIRouter(prefix="/api/dast", tags=["dast"])


@router.post("/apps")
def create_app(payload: IdorAppRequest):
    return container.d1_service.create_app(payload.model_dump())


@router.get("/apps")
def list_apps():
    return container.d1_service.list_apps()


@router.get("/apps/{app_id}")
def get_app(app_id: str):
    return container.d1_service.get_app(app_id)


@router.post("/apps/{app_id}/accounts/import")
def import_accounts(app_id: str, payload: IdorAccountImportRequest):
    return container.d1_service.import_accounts(app_id, payload.model_dump())


@router.post("/apps/{app_id}/apis/import")
def import_apis(app_id: str, payload: IdorApiImportRequest):
    return container.d1_service.import_apis(app_id, payload.model_dump())


@router.post("/apps/{app_id}/traffic/import")
def import_traffic(app_id: str, payload: IdorTrafficImportRequest):
    return container.d1_service.import_traffic(app_id, payload.model_dump())


@router.post("/apps/{app_id}/scan")
def scan(app_id: str, payload: IdorScanRequest = IdorScanRequest()):
    return container.d1_service.scan(app_id, payload.model_dump())


@router.get("/apps/{app_id}/results")
def results(app_id: str):
    return container.d1_service.results(app_id)


@router.post("/replay")
def replay(payload: Dict[str, Any]):
    """§3.17 D1 重放契约的 HTTP 入口：接收 TriggerSpec + ExternalTarget，
    调 D1Service.replay 打带 canary 的触发流量，返回 DastImpact（DAST 影响证据）。"""
    trigger_spec = payload.get("trigger_spec") or {}
    target = payload.get("target") or {}
    return container.d1_service.replay(trigger_spec, target).to_dict()
