
from fastapi import APIRouter

from src.api.dependencies import container
from src.api.schemas import IdorAccountImportRequest, IdorApiImportRequest, IdorAppRequest, IdorScanRequest, IdorTrafficImportRequest

router = APIRouter(prefix="/api/idor", tags=["idor"])


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


@router.get("/apps/{app_id}/accounts")
def list_accounts(app_id: str):
    return container.d1_service.list_accounts(app_id)


@router.post("/apps/{app_id}/apis/import")
def import_apis(app_id: str, payload: IdorApiImportRequest):
    return container.d1_service.import_apis(app_id, payload.model_dump())


@router.get("/apps/{app_id}/apis")
def list_apis(app_id: str):
    return container.d1_service.list_apis(app_id)


@router.post("/apps/{app_id}/traffic/import")
def import_traffic(app_id: str, payload: IdorTrafficImportRequest):
    return container.d1_service.import_traffic(app_id, payload.model_dump())


@router.get("/apps/{app_id}/traffic")
def list_traffic(app_id: str):
    return container.d1_service.list_traffic(app_id)


@router.post("/apps/{app_id}/scan")
def scan(app_id: str, payload: IdorScanRequest = IdorScanRequest()):
    return container.d1_service.scan(app_id, payload.model_dump())


@router.get("/apps/{app_id}/runs")
def runs(app_id: str):
    return container.d1_service.runs(app_id)


@router.get("/runs/{run_id}/findings")
def run_findings(run_id: int):
    return container.d1_service.run_findings(run_id)


@router.get("/apps/{app_id}/results")
def results(app_id: str):
    return container.d1_service.results(app_id)
