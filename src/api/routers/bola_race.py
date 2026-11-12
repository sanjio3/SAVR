"""BOLA / RACE 路由。

端点：
- POST /api/bola-race/status        能力状态（取代占位）
- POST /api/bola-race/analyze       源文件 → BOLA 假说（SAST 业务逻辑策略分析）
- POST /api/bola-race/verify-bola  BOLA 多身份重放验证（运行时影响证明）
- POST /api/bola-race/verify-race  RACE 并发重放验证（运行时影响证明）
"""
from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException

from src.iast import bola_race as bola_race_module

router = APIRouter(prefix="/api/bola-race", tags=["bola-race"])


@router.post("/status")
def status():
    return bola_race_module.bola_race_status()


@router.post("/analyze")
def analyze(payload: Dict[str, Any] = Body(...)):
    """源文件 → BOLA 假说。files: [{path, content, language?}]。"""
    try:
        files = payload.get("files") or []
        return {"bola_hypotheses": bola_race_module.analyze_bola(files)}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"BOLA analyze failed: {exc}") from exc


@router.post("/verify-bola")
def verify_bola(payload: Dict[str, Any] = Body(...)):
    """BOLA 多身份重放验证。body: {trigger_spec, target, accounts}。"""
    try:
        return bola_race_module.verify_bola(
            trigger_spec=payload.get("trigger_spec", {}),
            target=payload.get("target", {}),
            accounts=payload.get("accounts"),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"BOLA verify failed: {exc}") from exc


@router.post("/verify-race")
def verify_race(payload: Dict[str, Any] = Body(...)):
    """RACE 并发重放验证。body: {trigger_spec, target, concurrency?}。"""
    try:
        return bola_race_module.verify_race(
            trigger_spec=payload.get("trigger_spec", {}),
            target=payload.get("target", {}),
            concurrency=payload.get("concurrency", 5),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"RACE verify failed: {exc}") from exc
