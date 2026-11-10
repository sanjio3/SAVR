"""prompt → response 缓存（P0-3：LLM 级断点续跑）。

问题：调 LLM 的成本分两种——钱和时间。用户反复调试同一批 prompt 时，
每一次重跑都要把已经算过的调用再算一遍；任务跑到一半崩了也只能从头再来。

本模块以「调用指纹」为键缓存响应：

    cache_key = sha256(provider | model | messages | temperature | max_tokens | prompt_version)

指纹包含模型与采样参数，因此换模型、改提示词版本、调 temperature 都会自动失效，
不需要手工清缓存（这也是当初选择把 prompt_version 纳入键的原因之一）。

命中后返回原文与埋点，并累加 hit_count，便于事后判断「缓存到底省了多少」。
默认开启（`SAST_AI_LLM_CACHE`），但对 temperature > 0.2 的调用不缓存——
高采样下同一 prompt 的响应本就不该复用，缓存会造成「看起来确定性、其实不是」的假象。

存储：复用 data/app.db 的 llm_cache 表（见 infrastructure/db.py 的 schema）。
所有 DB 异常一律 fail-open：缓存只是加速手段，不能因为它把主流程搞挂。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_db = None
_db_lock = threading.Lock()

# 超过此采样温度不缓存（响应不可复现）
CACHEABLE_TEMPERATURE_MAX = 0.2


def _enabled() -> bool:
    raw = (os.environ.get("SAST_AI_LLM_CACHE") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _get_db():
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                try:
                    from src.infrastructure.db import Database
                    _db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                except Exception as exc:  # pragma: no cover
                    logger.debug("[llm-cache] 初始化失败，缓存关闭：%s", exc)
                    return None
    return _db


def build_cache_key(
    *,
    provider: str = "",
    model: str = "",
    messages: Any = None,
    system: str = "",
    temperature: float = 0.0,
    max_tokens: int = 0,
    prompt_version: str = "",
    extra: str = "",
) -> str:
    """计算调用指纹。所有影响输出的输入都必须进键，否则会造成串味。"""
    payload_obj = {
        "provider": provider or "",
        "model": model or "",
        "system": system or "",
        "messages": messages if messages is not None else [],
        "temperature": round(float(temperature or 0.0), 4),
        "max_tokens": int(max_tokens or 0),
        "prompt_version": prompt_version or "",
        "extra": extra or "",
    }
    raw = json.dumps(payload_obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now() -> str:
    from datetime import datetime
    return datetime.utcnow().isoformat()


def get(cache_key: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """命中返回 (text, telemetry)；未命中或异常返回 None。"""
    if not _enabled() or not cache_key:
        return None
    db = _get_db()
    if db is None:
        return None
    try:
        row = db.execute(
            "SELECT text, telemetry_json FROM llm_cache WHERE cache_key = ?",
            (cache_key,),
            fetchone=True,
        )
        if not row:
            return None
        telemetry = {}
        try:
            telemetry = json.loads(row["telemetry_json"] or "{}")
        except ValueError:
            telemetry = {}
        try:
            db.execute(
                "UPDATE llm_cache SET hit_count = hit_count + 1, last_access_at = ? WHERE cache_key = ?",
                (_now(), cache_key),
            )
        except Exception:
            pass
        telemetry["cache_hit"] = True
        return (row["text"], telemetry)
    except Exception as exc:
        logger.debug("[llm-cache] 读取失败（忽略）：%s", exc)
        return None


def put(
    cache_key: str,
    *,
    text: str,
    provider: str = "",
    model: str = "",
    prompt_hash: str = "",
    telemetry: Optional[Dict[str, Any]] = None,
) -> None:
    """写入缓存。已在 _enabled 关闭时直接返回。"""
    if not _enabled() or not cache_key:
        return
    # 空响应不缓存：那通常是失败输出，缓存它会把偶发故障固化成永久故障
    if not (text or "").strip():
        return
    db = _get_db()
    if db is None:
        return
    try:
        now = _now()
        db.execute(
            """
            INSERT INTO llm_cache
            (cache_key, provider, model, prompt_hash, text, telemetry_json, hit_count, created_at, last_access_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                text = excluded.text,
                telemetry_json = excluded.telemetry_json,
                last_access_at = excluded.last_access_at
            """,
            (
                cache_key, provider, model, prompt_hash, text,
                json.dumps(dict(telemetry or {}), ensure_ascii=False),
                now, now,
            ),
        )
    except Exception as exc:
        logger.debug("[llm-cache] 写入失败（忽略）：%s", exc)


def stats() -> Dict[str, Any]:
    """缓存概况：条数、总命中、省下的调用次数估算。"""
    db = _get_db()
    if db is None:
        return {"entries": 0, "hits": 0, "enabled": _enabled()}
    try:
        row = db.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(hit_count), 0) AS hits FROM llm_cache",
            fetchone=True,
        )
        return {
            "entries": int(row["n"] or 0),
            "hits": int(row["hits"] or 0),
            "enabled": _enabled(),
        }
    except Exception as exc:
        logger.debug("[llm-cache] 统计失败：%s", exc)
        return {"entries": 0, "hits": 0, "enabled": _enabled()}


def clear(older_than_days: int = 0) -> int:
    """清理缓存。older_than_days<=0 表示全清。返回删除条数。"""
    db = _get_db()
    if db is None:
        return 0
    try:
        if older_than_days and older_than_days > 0:
            cutoff_ts = time.time() - older_than_days * 86400
            from datetime import datetime
            cutoff = datetime.utcfromtimestamp(cutoff_ts).isoformat()
            cur = db.execute("DELETE FROM llm_cache WHERE created_at < ?", (cutoff,))
        else:
            cur = db.execute("DELETE FROM llm_cache")
        return int(getattr(cur, "rowcount", 0) or 0)
    except Exception as exc:
        logger.debug("[llm-cache] 清理失败：%s", exc)
        return 0
