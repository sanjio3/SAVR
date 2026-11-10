"""HITL 审计事件落库与查询（破坏性闸门决策的可持久化记录）。

设计：guard 事件在验证热路径（benchmark_cli 子进程）产生，通过
``src.iast.attack_context.register_guard_audit_sink`` 注入的闭包调用本模块的
``persist_guard_event`` 落库。本模块不依赖 service 容器，单独可被 CLI 轻量 import。

决策口径（2026-09-20 重设计）：HITL 只拦**不可逆动作**；不论放行（allowed）还是
拦截（gated）都写审计，让「人入环」体现在关键决策而非每一步。
"""

from typing import Any, Dict, List, Optional

from src.infrastructure.db import Database


def persist_guard_event(db: Database, task_id: int, event: Dict[str, Any]) -> None:
    """把一次 guard 决策写入 ``hitl_audit`` 表（best-effort）。"""
    try:
        db.execute(
            """
            INSERT INTO hitl_audit
                (task_id, action, category, reason, route, method, tool_id,
                 approval_mode, stage, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(task_id or 0),
                str(event.get("action") or "unknown"),
                str(event.get("category") or ""),
                str(event.get("reason") or ""),
                str(event.get("route") or ""),
                str(event.get("method") or ""),
                str(event.get("tool_id") or ""),
                str(event.get("approval_mode") or ""),
                str(event.get("stage") or "d2_hitl"),
                db.dumps(event.get("detail") or {}),
                str(event.get("created_at") or _now()),
            ),
        )
    except Exception:  # noqa: BLE001 审计失败绝不阻断验证
        pass


def list_guard_events(db: Database, task_id: int) -> List[Dict[str, Any]]:
    """按时间倒序返回某任务的全部 HITL 审计事件。"""
    rows = (
        db.execute(
            "SELECT * FROM hitl_audit WHERE task_id = ? ORDER BY id DESC",
            (int(task_id),),
            fetchall=True,
        )
        or []
    )
    out: List[Dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        try:
            item["detail"] = db.loads(item.get("detail_json") or "{}")
        except Exception:  # noqa: BLE001
            item["detail"] = {}
        out.append(item)
    return out


def _now() -> str:
    from datetime import datetime

    return datetime.utcnow().isoformat()
