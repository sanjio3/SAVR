"""replay_intents 仓储。

探索图 + 单步意图的落点。ARTEX 的本质不是 planner-worker 角色划分，而是：
1. 状态外置——LLM 上下文只有「当前状态」，历史全在库里；
2. 单步意图 + 每步重读——一次只产出一个意图，执行完写回，下一轮重新读状态再决策。

本模块负责 replay_intents 表的读写，以及两个纯函数：
- `build_intent_from_i2_verdict`：把 I2 判因四态 + 受限动作映射成一条 intent 记录（可单测，无 LLM）；
- `summarize_for_prompt`：产出 ≤20 条 pending + ≤10 条 ineffective 的动作摘要，供 A2 prompt 注入。
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

STATUSES = ("pending", "running", "done_effective", "done_ineffective", "abandoned")
ACTIONS = (
    "change_payload", "change_encoding", "change_location", "change_content_type",
    "add_header", "change_method", "adjust_window", "give_up",
)


def ensure_replay_intents(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS replay_intents ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "task_id INTEGER NOT NULL,"
        "workspace_id INTEGER NOT NULL DEFAULT 0,"
        "spec_id INTEGER,"
        "vulnerability_hash_v2 TEXT NOT NULL DEFAULT '',"
        "round_no INTEGER NOT NULL DEFAULT 1,"
        "target_endpoint TEXT NOT NULL DEFAULT '',"
        "http_method TEXT NOT NULL DEFAULT 'GET',"
        "param_name TEXT NOT NULL DEFAULT '',"
        "param_location TEXT NOT NULL DEFAULT 'query',"
        "action TEXT NOT NULL DEFAULT '',"
        "payload_hint TEXT NOT NULL DEFAULT '',"
        "encoding_hint TEXT NOT NULL DEFAULT '',"
        "header_hint TEXT NOT NULL DEFAULT '',"
        "rationale TEXT NOT NULL DEFAULT '',"
        "priority INTEGER NOT NULL DEFAULT 0,"
        "status TEXT NOT NULL DEFAULT 'pending',"
        "evidence_ref TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL,"
        "updated_at TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_replay_intents_task ON replay_intents(task_id, spec_id)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_replay_intents_pending "
        "ON replay_intents(task_id, status, priority)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def insert_intent(connection: sqlite3.Connection, **fields) -> int:
    now = _now()
    row = {
        "task_id": int(fields.get("task_id", 0)),
        "workspace_id": int(fields.get("workspace_id", 0)),
        "spec_id": fields.get("spec_id"),
        "vulnerability_hash_v2": fields.get("vulnerability_hash_v2", "") or "",
        "round_no": int(fields.get("round_no", 1)),
        "target_endpoint": fields.get("target_endpoint", "") or "",
        "http_method": fields.get("http_method", "GET") or "GET",
        "param_name": fields.get("param_name", "") or "",
        "param_location": fields.get("param_location", "query") or "query",
        "action": fields.get("action", "") or "",
        "payload_hint": fields.get("payload_hint", "") or "",
        "encoding_hint": fields.get("encoding_hint", "") or "",
        "header_hint": fields.get("header_hint", "") or "",
        "rationale": (fields.get("rationale", "") or "")[:120],
        "priority": int(fields.get("priority", 0)),
        "status": fields.get("status", "pending") or "pending",
        "evidence_ref": fields.get("evidence_ref", "") or "",
        "created_at": now,
        "updated_at": now,
    }
    cols = ", ".join(row.keys())
    placeholders = ", ".join("?" for _ in row)
    cur = connection.execute(
        "INSERT INTO replay_intents (%s) VALUES (%s)" % (cols, placeholders),
        tuple(row.values()))
    connection.commit()
    return int(cur.lastrowid)


def get_pending(connection: sqlite3.Connection, task_id: int,
                limit: int = 20) -> List[Dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM replay_intents WHERE task_id=? AND status='pending' "
        "ORDER BY priority DESC, id ASC LIMIT ?", (task_id, int(limit))).fetchall()
    return [dict(r) for r in rows]


def get_recent_ineffective(connection: sqlite3.Connection, task_id: int,
                           limit: int = 10) -> List[Dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM replay_intents WHERE task_id=? AND status='done_ineffective' "
        "ORDER BY updated_at DESC, id DESC LIMIT ?", (task_id, int(limit))).fetchall()
    return [dict(r) for r in rows]


def update_status(connection: sqlite3.Connection, intent_id: int, status: str,
                  evidence_ref: str = "", rationale: Optional[str] = None) -> None:
    if status not in STATUSES:
        raise ValueError("bad status: %s" % status)
    now = _now()
    if rationale is not None:
        connection.execute(
            "UPDATE replay_intents SET status=?, evidence_ref=?, rationale=?, updated_at=? "
            "WHERE id=?", (status, evidence_ref or "", rationale[:120], now, intent_id))
    else:
        connection.execute(
            "UPDATE replay_intents SET status=?, evidence_ref=?, updated_at=? "
            "WHERE id=?", (status, evidence_ref or "", now, intent_id))
    connection.commit()


def summarize_for_prompt(connection: sqlite3.Connection, task_id: int,
                         max_pending: int = 20, max_ineffective: int = 10) -> str:
    """产出 ≤20 条 pending + ≤10 条 ineffective 的动作摘要，供 A2 prompt 注入（状态外置）。

    返回空串表示没有待注入的意图（第一轮或已收敛）——调用方据此决定是否追加提示块。
    """
    pending = get_pending(connection, task_id, max_pending)
    ineffective = get_recent_ineffective(connection, task_id, max_ineffective)
    if not pending and not ineffective:
        return ""
    lines: List[str] = []
    if pending:
        lines.append("【待试意图（优先尝试，勿重复已试无效的打法）】")
        for p in pending:
            desc = "  - %s %s(%s): action=%s" % (
                p.get("target_endpoint"), p.get("param_name"), p.get("param_location"),
                p.get("action"))
            if p.get("payload_hint"):
                desc += " payload_hint=%s" % str(p.get("payload_hint"))[:60]
            if p.get("encoding_hint"):
                desc += " encoding=%s" % p.get("encoding_hint")
            if p.get("header_hint"):
                desc += " header=%s" % p.get("header_hint")
            lines.append(desc)
    if ineffective:
        lines.append("【已试无效（避免重复）】")
        for i in ineffective:
            lines.append("  - %s %s(%s): %s 已证无效" % (
                i.get("target_endpoint"), i.get("param_name"), i.get("param_location"),
                i.get("action")))
    return "\n".join(lines)


def build_intent_from_i2_verdict(*, task_id: int, spec_id: Optional[int],
                                 vulnerability_hash_v2: str, family: str,
                                 endpoint: str, http_method: str, param_name: str,
                                 param_location: str, verdict: str, action: str,
                                 payload: str = "", encoding: str = "",
                                 header: str = "", rationale: str = "",
                                 round_no: int = 1, priority: int = 0) -> Dict[str, Any]:
    """把 I2 判因四态 + 受限动作映射成一条 replay_intent 字段（纯函数，可单测，无 LLM）。

    映射口径：
    - verdict 为 confirmed / false_positive，或 action 为 give_up → status=abandoned（无需再试）；
    - 否则（payload_problem / approach_problem 且 action != give_up）→ status=pending（下一轮试）；
    - action 非法 → 强制 give_up（abandoned），避免写进一个无法执行的动作。
    """
    _action = action if action in ACTIONS else "give_up"
    _status = "abandoned" if (
        verdict in ("confirmed", "false_positive") or _action == "give_up") else "pending"
    return {
        "task_id": int(task_id),
        "spec_id": spec_id,
        "vulnerability_hash_v2": vulnerability_hash_v2 or "",
        "round_no": int(round_no),
        "target_endpoint": endpoint or "",
        "http_method": http_method or "GET",
        "param_name": param_name or "",
        "param_location": param_location or "query",
        "action": _action,
        "payload_hint": payload or "",
        "encoding_hint": encoding or "",
        "header_hint": header or "",
        "rationale": rationale or "",
        "priority": int(priority),
        "status": _status,
    }
