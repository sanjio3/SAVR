from fastapi import APIRouter, Depends

from src.api.dependencies import container
from src.api.schemas import ChatOpsQueryRequest
from src.api.security import ROLE_REVIEWER, require_role
from src.chatops.bots import get_bot_adapter

router = APIRouter(prefix="/api/chatops", tags=["chatops"])


@router.post("/query", dependencies=[Depends(require_role(ROLE_REVIEWER))])
def query(payload: ChatOpsQueryRequest):
    answer = container.chatops_skill.query(payload.text, workspace_id=payload.workspace_id)
    if payload.platform:
        answer["bot_payload"] = get_bot_adapter(payload.platform).build_payload(answer)
    return answer
