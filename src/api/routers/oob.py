"""OOB（带外）回调 HTTP 接收端点（2026-10-02 发难清单 Q1 落地）。

oob_monitor（src/iast/oob_monitor.py）自 2026-09-28 起提供了回执登记/等待/D2 关联
的完整链路，但其文档明确「回调接入方——DNS 服务 / HTTP 回调端点——调 record_callback」，
此前平台**没有**这个 HTTP 接收端点，HTTP 形态的带外验证（SSRF / XXE http 实体 /
Log4j ${jndi:http://...} 等）打出来没人接，回执永远为空。

本路由就是那个缺口：
- ANY /api/oob/{token}          —— 目标服务出网打到这里的收数端点，落 kind='callback'；
- GET /api/oob/recent           —— 最近回执列表（人工核对 / 报告举证）；
- GET /api/oob/status/{token}   —— 单 token 查询是否已回执。

无回调即无证据：本路由只收数不判真，判定一律由 oob_monitor / D2 关联层完成。
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from src.iast import oob_monitor

router = APIRouter(prefix="/api/oob", tags=["oob"])


def _db_path() -> str:
    return os.environ.get("SAST_AI_DB_PATH", "data/app.db")


@router.get("/recent")
def recent(limit: int = 50):
    return {"callbacks": oob_monitor.recent_callbacks(limit=limit, db_path=_db_path())}


@router.get("/status/{token}")
def status(token: str):
    tok = (token or "").strip().split(".")[0]
    return {"token": tok, "has_callback": oob_monitor.has_callback(tok, db_path=_db_path())}


# 注意：catch-all 必须声明在 /recent 与 /status/{token} 之后，
# 否则 GET /api/oob/recent 会被当成 token="recent" 吃进收数端点。
@router.api_route("/{token}", methods=["GET", "POST", "PUT", "HEAD", "OPTIONS"])
async def receive_callback(token: str, request: Request):
    """目标服务出网回调收数端点：任何方法任何路径形态都记一次回执。"""
    tok = (token or "").strip()
    # 域名形态（<token>.<base> 被反代/重写进 path）与纯 token 都兼容
    tok = tok.split(".")[0].strip("/")
    if tok:
        detail = f"{request.method} {request.url.path}"
        qs = str(request.url.query or "")
        if qs:
            detail += f"?{qs}"
        oob_monitor.record_callback(
            tok,
            source=str(request.client.host if request.client else ""),
            detail=detail,
            db_path=_db_path(),
        )
    return PlainTextResponse("ok")
