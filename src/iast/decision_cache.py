"""判定缓存（2026-10-25，plan §20.5.1）。

代码片段指纹 + 族 → 判定结果，跨任务复用。Benchmark 模板化代码极多，同一段净化器实现 /
同一处注入点在多个 task、多个文件里重复出现；缓存命中即可跳过重复 LLM 判别，省下 prefill+decode。

设计要点：
- 指纹 = sha1(族 \0 归一化源码)。归一化去注释、折叠空白，使「仅差注释/格式」的代码判定为同一条。
- 键唯一索引 (code_hash, family)：同段代码同族只存一条，ON CONFLICT 覆盖（最新判定胜出）。
- 不缓存「未决」结果（verdict 为空视为未命中）；属性族静态强证据这类确定性判定最适合缓存。
- 纯模块，无 LLM 依赖，可直接单测。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def ensure_decision_cache(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS decision_cache ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "code_hash TEXT NOT NULL DEFAULT '',"
        "family TEXT NOT NULL DEFAULT '',"
        "verdict TEXT NOT NULL DEFAULT '',"
        "spec_json TEXT NOT NULL DEFAULT '{}',"
        "confidence REAL NOT NULL DEFAULT 0.0,"
        "source TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL)")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_decision_cache_key "
        "ON decision_cache(code_hash, family)")


def _normalize(code: str) -> str:
    """归一化：去块注释、去行注释、折叠空白、去尾随空白。保留换行近似结构。"""
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//[^\n]*", "", code)
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in code.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def fingerprint(code: str, family: str = "") -> str:
    norm = _normalize(code or "")
    return hashlib.sha1(("%s\x00%s" % (family, norm)).encode("utf-8")).hexdigest()


def get(connection: sqlite3.Connection, code_hash: str,
        family: str) -> Optional[Dict[str, Any]]:
    row = connection.execute(
        "SELECT * FROM decision_cache WHERE code_hash=? AND family=?",
        (code_hash, family)).fetchone()
    return dict(row) if row else None


def lookup(connection: sqlite3.Connection, code: str,
           family: str) -> Optional[Dict[str, Any]]:
    return get(connection, fingerprint(code, family), family)


def put(connection: sqlite3.Connection, *, code_hash: str, family: str, verdict: str,
        spec_json: Optional[Dict[str, Any]] = None, confidence: float = 0.0,
        source: str = "") -> None:
    if not verdict:
        # 未决结果不缓存——缓存只存确定性判定，避免污染后续复用。
        return
    now = datetime.now(timezone.utc).isoformat()
    try:
        connection.execute(
            "INSERT INTO decision_cache "
            "(code_hash, family, verdict, spec_json, confidence, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(code_hash, family) DO UPDATE SET "
            "verdict=excluded.verdict, spec_json=excluded.spec_json, "
            "confidence=excluded.confidence, source=excluded.source, created_at=excluded.created_at",
            (code_hash, family, verdict, json.dumps(spec_json or {}, ensure_ascii=False),
             float(confidence), source or "", now))
        connection.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[decision_cache] put 失败（跳过）：%s", exc)


def put_code(connection: sqlite3.Connection, *, code: str, family: str, verdict: str,
             spec_json: Optional[Dict[str, Any]] = None, confidence: float = 0.0,
             source: str = "") -> None:
    put(connection, code_hash=fingerprint(code, family), family=family, verdict=verdict,
        spec_json=spec_json, confidence=confidence, source=source)


def lookup_specs(connection: sqlite3.Connection, code: str,
                 family_key: str) -> Optional[Any]:
    """按 (源码, 族组合) 查询缓存的 A2 判定结果（spec 列表）。未命中/损坏返回 None。"""
    row = get(connection, fingerprint(code, family_key), family_key)
    if row and row.get("verdict") == "cached":
        try:
            import json as _json
            return _json.loads(row["spec_json"])
        except Exception:
            return None
    return None


def put_specs(connection: sqlite3.Connection, code: str, family_key: str,
              specs: Any, source: str = "a2_cache") -> None:
    """缓存一次 A2 对「某文件 + 某族组合」的完整判定（spec 列表）。空结果不缓存。"""
    if not specs:
        return
    put(connection, code_hash=fingerprint(code, family_key), family=family_key,
        verdict="cached", spec_json=specs, source=source)
