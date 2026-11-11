from fastapi import APIRouter

from src.api.dependencies import container
from src.api.schemas import SystemStatusResponse, ToolSpecResponse
from src.core.config import config
from src.core.tool_registry import ToolRegistry

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/ping")
async def ping():
    """轻量存活探针：**不碰 DB，且 async**。

    大量写 iast_events/replay_attempts 时会长期持锁；同步端点都要占 anyio 线程池 worker，
    线程池被等锁请求占满后连本端点都排不到 worker。故本端点 (a) 不碰 DB、(b) 用 async
    直接跑在事件循环上，不占线程池 —— 无论后端多忙都能立即返回。
    """
    return {"status": "ok"}


@router.get("/health", response_model=SystemStatusResponse)
def health():
    # 实测每行 options_json 平均 ~1.2MB、151 行≈185MB，一次 health 要几百 ms~数秒；
    # 叠加 db 层全局锁与高频心跳，会拖到 10s+ 超时，被 supervisor 误判「进程在但 HTTP 不响应」
    # 而强杀后端，进而打断正在跑的扫描任务。health 只需计数，改 COUNT（O(1)）。
    _active = container.db.execute(
        "SELECT COUNT(*) AS n FROM scan_tasks WHERE status IN ('pending','running')",
        fetchone=True,
    )
    _ws = container.db.execute("SELECT COUNT(*) AS n FROM workspaces", fetchone=True)
    return SystemStatusResponse(
        status="ok",
        db_path=str(container.db.path),
        active_tasks=int(_active["n"]) if _active else 0,
        workspace_count=int(_ws["n"]) if _ws else 0,
    )


@router.get("/tool-registry", response_model=list[ToolSpecResponse])
def tool_registry():
    return ToolRegistry.list_tools()


@router.get("/hitl-defaults")
def hitl_defaults():
    return {
        "approval_mode": config.get("agents.d2.hitl.approval_mode", "ask_on_risky_tools"),
        "tool_allowlist": list(config.get("agents.d2.hitl.tool_allowlist", []) or []),
    }


@router.get("/sca-tools")
def sca_tools():
    return container.sca_asset_service.tool_statuses()
