"""A0 预处理编排路由（§8.1）。

提供 A0 三职责整合的同步入口：路径校验 + 环境识别前置（可选）+ 入口发现/框架特化/补盲回灌。
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException

from src.api.dependencies import container
from src.api.schemas import EntryDiscoveryRequest

router = APIRouter(prefix="/api/a0", tags=["a0"])


@router.post("/run")
def run_a0(payload: EntryDiscoveryRequest):
    """执行 A0 编排：路径校验 + R0 框架特化 + 入口发现（含参数采集）+ 可选补盲回灌。"""
    try:
        workspace = None
        if payload.workspace_id is not None:
            workspace = container.workspace_repository.get(payload.workspace_id)
        result = container.a0_service.run(
            project_path=payload.project_path,
            workspace=workspace,
            task_id=payload.task_id,
        )
        if result.get("status") == "error":
            raise HTTPException(status_code=400, detail=result.get("message", "A0 执行失败"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"A0 run failed: {exc}") from exc


@router.post("/run/backfill")
def run_a0_with_backfill(payload: Dict[str, Any] = Body(...)):
    """执行 A0 编排并回灌 IAST 补盲入口（§8.4 第3点）。"""
    try:
        project_path = str(payload.get("project_path") or "")
        workspace_id = payload.get("workspace_id")
        iast_observed = payload.get("iast_observed_entries") or []
        workspace = None
        if workspace_id is not None:
            workspace = container.workspace_repository.get(int(workspace_id))
        result = container.a0_service.run(
            project_path=project_path,
            workspace=workspace,
            task_id=payload.get("task_id"),
            iast_observed_entries=iast_observed,
        )
        if result.get("status") == "error":
            raise HTTPException(status_code=400, detail=result.get("message", "A0 执行失败"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"A0 backfill run failed: {exc}") from exc
