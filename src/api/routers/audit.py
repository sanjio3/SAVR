from fastapi import APIRouter, Depends, Query

from src.api.dependencies import container
from src.api.security import ROLE_REVIEWER, require_role

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/log")
def audit_log(limit: int = Query(default=200, le=1000), _principal=Depends(require_role(ROLE_REVIEWER))):
    return container.audit_log_repository.list(limit=limit)
