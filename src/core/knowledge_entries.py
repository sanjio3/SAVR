"""知识条目（黑板阶段二）：环境事实 / 靶场档案 / 已知坑的一等公民化。

设计目标：
- 把「频繁开新 session 不掉信息」从设计笔记迁移为机器可读、阶段必读的 DB 真相源。
- 条目形状：{workspace_id, kind, key, value_json, source, confidence, ttl, status,
  first_seen_at, last_seen_at, superseded_by}
- kind 枚举：target_profile / env_fact / pitfall / family_alias / verified_conclusion
- workspace_id=0 表示全局知识（跨 session 可用，不绑具体工作区）。

本模块只提供读写机制，不内置任何种子数据。目标应用与环境因用户而异，把一份写死的
「事实」套到别人的靶场上只会变成错误先验；条目应由使用方按 workspace 写入。
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

KIND_TARGET_PROFILE = "target_profile"
KIND_ENV_FACT = "env_fact"
KIND_PITFALL = "pitfall"
KIND_FAMILY_ALIAS = "family_alias"
KIND_VERIFIED_CONCLUSION = "verified_conclusion"

_KINDS = {
    KIND_TARGET_PROFILE,
    KIND_ENV_FACT,
    KIND_PITFALL,
    KIND_FAMILY_ALIAS,
    KIND_VERIFIED_CONCLUSION,
}

# 阶段必读映射（read_for_stage 用）
_STAGE_KINDS = {
    "a0": [KIND_TARGET_PROFILE, KIND_PITFALL],
    "a2": [KIND_FAMILY_ALIAS],
    "d1": [KIND_PITFALL],
}


def _now() -> str:
    return datetime.utcnow().isoformat()


def upsert(
    db,
    workspace_id: int,
    kind: str,
    key: str,
    value: Any,
    *,
    source: str = "",
    confidence: str = "medium",
    ttl: str = "",
    status: str = "active",
) -> bool:
    """写入/更新一条知识条目；同 (workspace_id, kind, key) 存在则更新 last_seen_at 与值。"""
    if kind not in _KINDS:
        logger.warning("[knowledge] 未知 kind=%s，归入 verified_conclusion", kind)
        kind = KIND_VERIFIED_CONCLUSION
    now = _now()
    try:
        db.execute(
            """
            INSERT INTO knowledge_entries
            (workspace_id, kind, key, value_json, source, confidence, ttl, status, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, kind, key) DO UPDATE SET
                value_json=excluded.value_json,
                source=excluded.source,
                confidence=excluded.confidence,
                ttl=excluded.ttl,
                status=excluded.status,
                last_seen_at=excluded.last_seen_at
            """,
            (workspace_id, kind, key, json.dumps(value, ensure_ascii=False),
             source, confidence, ttl, status, now, now),
        )
        return True
    except Exception as _e:
        logger.warning("[knowledge] upsert 失败 kind=%s key=%s：%s", kind, key, _e)
        return False


def get(db, workspace_id: int, kind: str, key: str) -> Optional[Dict[str, Any]]:
    row = db.execute(
        "SELECT * FROM knowledge_entries WHERE workspace_id=? AND kind=? AND key=?",
        (workspace_id, kind, key), fetchone=True,
    )
    return dict(row) if row else None


def get_by_kind(db, workspace_id: int, kind: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        "SELECT * FROM knowledge_entries WHERE workspace_id=? AND kind=? ORDER BY key",
        (workspace_id, kind), fetchall=True,
    ) or []
    return [dict(r) for r in rows]


def load_knowledge(db, workspace_id: int, kinds: Optional[List[str]] = None) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """读某 workspace 的知识条目，返回 {kind: {key: rec}}，rec 含解析后的 value 字段。

    kinds 为 None 时读全部 kind。不过滤 ttl（首期 ttl 留空，所有条目常驻）。
    """
    sql = "SELECT * FROM knowledge_entries WHERE workspace_id=?"
    args: List[Any] = [workspace_id]
    if kinds:
        ph = ",".join("?" * len(kinds))
        sql += f" AND kind IN ({ph})"
        args += list(kinds)
    sql += " ORDER BY kind, key"
    try:
        rows = db.execute(sql, tuple(args), fetchall=True) or []
    except Exception as _e:
        logger.warning("[knowledge] load_knowledge 失败：%s", _e)
        return {}
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for r in rows:
        rec = dict(r)
        try:
            rec["value"] = json.loads(rec.get("value_json") or "{}")
        except Exception:
            rec["value"] = {}
        out.setdefault(rec["kind"], {})[rec["key"]] = rec
    return out


def read_for_stage(workspace_id: Optional[int], stage: str, db=None) -> Dict[str, Any]:
    """best-effort：为某阶段读取"必读"知识并记日志，返回条目（不抛异常、不阻断扫描）。

    合并逻辑：先读具体 workspace_id，再读全局 workspace_id=0，后者作为跨 session 兜底。
    仅日志化消费（digest），不改变任何阶段行为。
    """
    kinds = _STAGE_KINDS.get(stage)
    if not kinds:
        return {}
    if workspace_id is None:
        workspace_ids = [0]
    else:
        workspace_ids = [workspace_id, 0] if workspace_id != 0 else [0]

    if db is None:
        try:
            from src.infrastructure.db import Database
            db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        except Exception as _e:
            logger.warning("[knowledge] 阶段 %s 无法获取 DB，跳过必读：%s", stage, _e)
            return {}

    merged: Dict[str, Any] = {}
    try:
        for wid in workspace_ids:
            data = load_knowledge(db, wid, kinds)
            for kind, keys in data.items():
                for k, rec in keys.items():
                    # 具体 workspace 优先；全局仅在缺失时兜底
                    if k not in merged.get(kind, {}):
                        merged.setdefault(kind, {})[k] = rec
    except Exception as _e:
        logger.warning("[knowledge] 阶段 %s 必读加载失败（不阻断）：%s", stage, _e)
        return {}

    digest = {kind: sorted(keys.keys()) for kind, keys in merged.items()}
    if digest:
        logger.info("[knowledge] 阶段 %s 必读知识已载入：%s", stage, digest)
    return merged
