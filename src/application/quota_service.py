"""配额服务。

配额 = 按「主体」（workspace / global）设定的用量上限与超限处置规则。
维度：count（扫描次数）/ code_lines（代码量）/ tokens（LLM token）/ concurrency（并发）/
cost（金额，当前 provider 未上报单价，恒为 0，仅占位）。
周期：day / month / total。
动作：reject（拒新任务）/ warn（仅告警）/ degrade（降级扫描强度）。

设计约束（与用量统计口径一致）：
- 用量侧**不新建流水表**，实时聚合 scan_tasks / model_runs（避免双份真相）。
- 金额型（cost）当前全库 cost_usd 恒为 0，limit 仅作占位，命中后也只告警不拒。
- 硬上限默认 reject，但**不自动杀在跑任务**，只在提交入口拦截新任务。
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.infrastructure.db import Database


class QuotaExceededError(Exception):
    """提交新任务时被配额硬上限拦截。API 层映射为 429。"""


# 受支持的维度与默认安全上限（仅当未建任何策略时，框架不主动限制）。
DIMENSIONS = ("count", "code_lines", "tokens", "concurrency", "cost")
PERIODS = ("day", "month", "total")
ACTIONS = ("reject", "warn", "degrade")


def _period_start(period: str) -> Optional[str]:
    """返回周期起始的 ISO 时间戳（UTC）。total 返回 None（不过滤）。"""
    now = datetime.utcnow()
    if period == "day":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        return None
    return start.isoformat()


def _preprocess_file_count(summary_json: Any) -> int:
    if not summary_json:
        return 0
    try:
        data = json.loads(summary_json) if isinstance(summary_json, str) else dict(summary_json)
    except (TypeError, ValueError):
        return 0
    for source in (data.get("pipeline"), data.get("results")):
        if not isinstance(source, dict):
            continue
        node = source.get("preprocess")
        if isinstance(node, dict):
            metrics = node.get("metrics")
            if isinstance(metrics, dict):
                try:
                    return int(float(metrics.get("file_count") or 0))
                except (TypeError, ValueError):
                    return 0
    return 0


class QuotaService:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))

    # ----------------------------------------------------------- 策略 CRUD #
    def list_policies(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        if workspace_id is None:
            rows = self.db.execute(
                "SELECT * FROM quota_policies ORDER BY subject_type, subject_id, dimension",
                fetchall=True,
            ) or []
        else:
            rows = self.db.execute(
                "SELECT * FROM quota_policies WHERE subject_type='workspace' AND subject_id=?"
                " ORDER BY dimension, period",
                (int(workspace_id),),
                fetchall=True,
            ) or []
        return [self._row(r) for r in rows]

    def upsert_policy(self, **fields: Any) -> Dict[str, Any]:
        dimension = str(fields.get("dimension") or "")
        if dimension not in DIMENSIONS:
            raise ValueError(f"未知维度：{dimension}（支持 {DIMENSIONS}）")
        period = str(fields.get("period") or "total")
        if period not in PERIODS:
            raise ValueError(f"未知周期：{period}（支持 {PERIODS}）")
        action = str(fields.get("action") or "reject")
        if action not in ACTIONS:
            raise ValueError(f"未知动作：{action}（支持 {ACTIONS}）")
        subject_type = str(fields.get("subject_type") or "workspace")
        subject_id = fields.get("subject_id")
        subject_id = int(subject_id) if subject_id is not None else None
        if subject_type == "global":
            # 全局策略用固定哨兵 0 代替 NULL：SQLite 的 UNIQUE 对 NULL 不做去重，
            # 否则同名全局策略重复提交会变成多行、且评估时取最早一行导致口径漂移。
            subject_id = 0
        elif subject_id is None:
            raise ValueError("非 global 主体必须提供 subject_id")
        limit_value = float(fields.get("limit_value") or 0)
        now = datetime.utcnow().isoformat()
        self.db.execute(
            """
            INSERT INTO quota_policies
            (name, subject_type, subject_id, dimension, limit_value, period, action, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(subject_type, subject_id, dimension, period) DO UPDATE SET
                name = excluded.name,
                limit_value = excluded.limit_value,
                action = excluded.action,
                enabled = 1,
                updated_at = excluded.updated_at
            """,
            (
                str(fields.get("name") or ""),
                subject_type,
                subject_id,
                dimension,
                limit_value,
                period,
                action,
                now,
                now,
            ),
        )
        row = self.db.execute(
            "SELECT * FROM quota_policies WHERE subject_type=? AND subject_id IS ? AND dimension=? AND period=?",
            (subject_type, subject_id, dimension, period),
            fetchone=True,
        )
        return self._row(row)

    def delete_policy(self, policy_id: int) -> bool:
        rowcount = self.db.execute("DELETE FROM quota_policies WHERE id=?", (int(policy_id),), return_rowcount=True)
        return int(rowcount or 0) > 0

    # -------------------------------------------------------------- 用量聚合 #
    def _usage_for(self, workspace_id: int, period: str, *, planned_count: int = 0) -> Dict[str, float]:
        """聚合某工作区在指定期内的真实用量（不新建流水表）。"""
        start = _period_start(period)
        where = " WHERE workspace_id = ?"
        args: tuple = (int(workspace_id),)
        if start is not None:
            where += " AND created_at >= ?"
            args = (int(workspace_id), start)
        tasks = self.db.execute(
            "SELECT id, status, summary_json FROM scan_tasks" + where, args, fetchall=True
        ) or []

        count = len(tasks) + max(0, int(planned_count))
        code_lines = sum(_preprocess_file_count(t.get("summary_json")) for t in tasks)

        task_ids = [t.get("id") for t in tasks if t.get("id") is not None]
        tokens = 0.0
        cost = 0.0
        if task_ids:
            ph = ",".join("?" * len(task_ids))
            mr_where = f"task_id IN ({ph})"
            mr_args: tuple = tuple(task_ids)
            if start is not None:
                mr_where += " AND created_at >= ?"
                mr_args = tuple(task_ids) + (start,)
            rows = self.db.execute(
                f"SELECT input_tokens, output_tokens, cost_usd FROM model_runs WHERE {mr_where}",
                mr_args,
                fetchall=True,
            ) or []
            for r in rows:
                try:
                    tokens += float(r.get("input_tokens") or 0) + float(r.get("output_tokens") or 0)
                    cost += float(r.get("cost_usd") or 0)
                except (TypeError, ValueError):
                    pass

        # 并发：当前在跑/排队/待处理，非周期维度
        running = self.db.execute(
            "SELECT COUNT(*) AS n FROM scan_tasks WHERE workspace_id=? AND status IN ('pending','queued','running')",
            (int(workspace_id),),
            fetchone=True,
        )
        concurrency = int((running or {}).get("n") or 0)

        return {
            "count": float(count),
            "code_lines": float(code_lines),
            "tokens": tokens,
            "concurrency": float(concurrency),
            "cost": cost,
        }

    # --------------------------------------------------------------- 评估 #
    def evaluate(self, workspace_id: int, *, planned_count: int = 0) -> List[Dict[str, Any]]:
        """评估某工作区的所有适用策略（workspace 级 + global 级）。"""
        rows = self.db.execute(
            "SELECT * FROM quota_policies WHERE enabled=1 AND"
            " ((subject_type='workspace' AND subject_id=?) OR subject_type='global')",
            (int(workspace_id),),
            fetchall=True,
        ) or []
        result: List[Dict[str, Any]] = []
        # 同一 (dimension, period) 可能 workspace 与 global 各一条，workspace 优先
        best: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            row = self._row(r)
            key = (row["dimension"], row["period"])
            if key not in best or row["subject_type"] == "workspace":
                best[key] = row
        for row in best.values():
            usage = self._usage_for(workspace_id, row["period"], planned_count=planned_count)
            used = usage.get(row["dimension"], 0.0)
            limit_value = row["limit_value"]
            exceeded = bool(limit_value > 0 and used > limit_value)
            result.append({
                "id": row["id"],
                "name": row["name"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "dimension": row["dimension"],
                "period": row["period"],
                "limit_value": limit_value,
                "used": round(used, 2),
                "action": row["action"],
                "exceeded": exceeded,
            })
        result.sort(key=lambda x: (x["dimension"], x["period"]))
        return result

    def assert_within_quota(self, workspace_id: int) -> None:
        """提交新任务前调用：任一 reject 策略超限即抛 QuotaExceededError。"""
        evals = self.evaluate(workspace_id, planned_count=1)
        blocking = [e for e in evals if e["exceeded"] and e["action"] == "reject"]
        if blocking:
            desc = "; ".join(
                f"{e['dimension']}/{e['period']} 已用 {e['used']} 超上限 {e['limit_value']}"
                for e in blocking
            )
            raise QuotaExceededError(f"配额超限，已拒绝新建任务：{desc}")

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return {
            "id": row.get("id"),
            "name": row.get("name") or "",
            "subject_type": row.get("subject_type") or "workspace",
            "subject_id": row.get("subject_id"),
            "dimension": row.get("dimension") or "",
            "limit_value": float(row.get("limit_value") or 0),
            "period": row.get("period") or "total",
            "action": row.get("action") or "reject",
            "enabled": int(row.get("enabled") or 1),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
        }
