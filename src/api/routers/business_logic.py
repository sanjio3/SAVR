"""业务逻辑漏洞 全类目路由（§2.2 / §7.9：SAST 策略分析 + D1 重放验证，六大类全覆盖）。

端点：
- POST /api/business-logic/status       能力状态（六大类）
- POST /api/business-logic/analyze       源文件 → 业务逻辑假说（files，可选 categories 子集）
- POST /api/business-logic/verify        单类目运行时重放验证（category + trigger_spec + target）
"""
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException

from src.core.config import config as app_config
from src.core.model_gateway import gateway_from_config, resolve_llm_config
from src.iast import business_logic as bl_module
from src.infrastructure.db import Database

router = APIRouter(prefix="/api/business-logic", tags=["business-logic"])


@router.post("/status")
def status():
    return bl_module.business_logic_status()


@router.post("/analyze")
def analyze(payload: Dict[str, Any] = Body(...)):
    """源文件 → 业务逻辑假说。files: [{path, content, language?}]；可选 categories: [...]。

    携带根配置（config.yaml）中的 LLM/CodeQL 配置，使主链路走真实 GLM 语义识别；
    未配置 LLM 时自动降级自写启发式分析器。
    """
    try:
        files = payload.get("files") or []
        categories = payload.get("categories")
        cfg = app_config.snapshot()
        return {"business_logic_hypotheses": bl_module.analyze(files, categories=categories, config=cfg)}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"business-logic analyze failed: {exc}") from exc


@router.post("/verify")
def verify(payload: Dict[str, Any] = Body(...)):
    """单类目运行时重放验证。body: {category, trigger_spec, target, accounts?, concurrency?}。

    携带 root 配置的 LLM gateway（在线时 D1 重放判定可叠加 AI 语义复核，best-effort）。

    R23-2：透传真实 DB（SAST_AI_DB_PATH 优先，默认 data/app.db），使 replay_* 的
    victim_identifiers / accounts_json 回填落在真实库而非 D1Service 的临时库。
    """
    try:
        cfg = app_config.snapshot()
        # resolve_llm_config：即便未来 snapshot() 变成局部投影，也能取到 llm 段而不静默降级离线
        gateway = gateway_from_config(resolve_llm_config(cfg))
        db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        return bl_module.verify(
            category=payload.get("category", ""),
            trigger_spec=payload.get("trigger_spec", {}),
            target=payload.get("target", {}),
            accounts=payload.get("accounts"),
            concurrency=payload.get("concurrency", 5),
            gateway=gateway,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"business-logic verify failed: {exc}") from exc
