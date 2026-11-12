"""Cost + operations metrics service (G9 + G12).

Ties the cost model and ops-metrics aggregation to persistence: records per-scan
cost, manages scan-trigger policies, estimates annual cost, and assembles the
operating dashboard. Offline/pure — no network I/O.
"""

import json
import os
import math
from collections import Counter
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from src.core import cost_model, ops_metrics
from src.infrastructure.db import Database
from src.infrastructure.repositories import (
    AutonomyRepository,
    FindingRepository,
    FixFeedbackRepository,
    ScanCostRepository,
    ScanTriggerPolicyRepository,
)
from src.integrations.ticketing import get_ticketing_adapter


class MetricsService:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        self.cost_repo = ScanCostRepository(self.db)
        self.trigger_repo = ScanTriggerPolicyRepository(self.db)
        self.finding_repo = FindingRepository(self.db)
        self.autonomy_repo = AutonomyRepository(self.db)
        self.fix_feedback_repo = FixFeedbackRepository(self.db)

    # ------------------------------------------------------------------ G9 #
    def record_scan_cost(self, **fields: Any) -> Dict[str, Any]:
        return self.cost_repo.add(**fields)

    def upsert_trigger_policy(self, **fields: Any) -> Dict[str, Any]:
        return self.trigger_repo.upsert(**fields)

    def list_trigger_policies(self, workspace_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return self.trigger_repo.list(workspace_id=workspace_id)

    def annual_cost(self, workspace_id: Optional[int] = None, *, variance: float = 0.2) -> Dict[str, Any]:
        records = self.cost_repo.list(workspace_id=workspace_id)
        policies = self.trigger_repo.list(workspace_id=workspace_id)
        avg = cost_model.average_scan_cost(records)
        estimate = cost_model.annual_cost(avg_scan_cost=avg, policies=policies, variance=variance)
        estimate["scan_record_count"] = len(records)
        estimate["policy_count"] = len([p for p in policies if p.get("enabled", True)])
        estimate["recommendation"] = cost_model.recommend_model_split()
        return estimate

    # ------------------------------------------------------------------ G12 #
    def ops_dashboard(self, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        findings = [self._finding_dict(f) for f in self.finding_repo.list(workspace_id=workspace_id)]
        actions = self.autonomy_repo.list_actions(workspace_id=workspace_id, limit=5000)
        fix_metrics = self.fix_feedback_repo.metrics(workspace_id=workspace_id)
        return ops_metrics.aggregate_ops_metrics(
            findings=findings,
            autonomy_actions=actions,
            fix_feedback_metrics=fix_metrics,
        )

    # ---------------------------------------------------------------- 用量 #
    def usage_stats(self, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        """用量统计：扫描次数与周期、扫描代码量、LLM token 与成本、Agent 调用次数与耗时、
        按工作区分布。与「成本与效果度量」（降噪率/误杀率/覆盖度）是两件事：这里回答的是
        「平台被用掉了多少」，不是「用得好不好」。

        - model_runs.cost_usd 当前全库为 0（provider 未上报单价）。因此只汇总真实字段，
          billed=False 时前端须显示「未计费」，**不得**用假设单价反推金额。
          （a2-semantic→a2-semantic、gray-review→gray-review，可复现、非臆造），残留空串仍归入
          「未标注阶段」，不静默丢弃、也不冒充某个真实阶段。
        - 配额（quota）在领域模型里没有实体，故本方法不产出配额字段。
        """
        where = " WHERE workspace_id = ?" if workspace_id is not None else ""
        args: tuple = (workspace_id,) if workspace_id is not None else ()
        tasks = self.db.execute(
            "SELECT id, workspace_id, name, status, created_at, started_at, finished_at, summary_json"
            " FROM scan_tasks" + where + " ORDER BY id",
            args,
            fetchall=True,
        ) or []

        durations: List[float] = []
        by_status: Dict[str, int] = {}
        for task in tasks:
            by_status[str(task.get("status") or "unknown")] = (
                by_status.get(str(task.get("status") or "unknown"), 0) + 1
            )
            started = _parse_dt(task.get("started_at"))
            finished = _parse_dt(task.get("finished_at"))
            if started and finished and finished >= started:
                durations.append((finished - started).total_seconds())

        code_rows = []
        for task in tasks:
            metrics = _preprocess_metrics(task.get("summary_json"))
            if not metrics:
                continue
            code_rows.append({
                "task_id": task.get("id"),
                "name": task.get("name"),
                "created_at": task.get("created_at"),
                "file_count": _as_int(metrics.get("file_count")),
                "indexed_functions": _as_int(metrics.get("indexed_functions")),
                "http_entries": _as_int(metrics.get("http_entries")),
                "endpoint_count": _as_int(metrics.get("endpoint_count")),
            })

        workspaces = self.db.execute("SELECT id, name, slug FROM workspaces", fetchall=True) or []
        ws_names = {w.get("id"): (w.get("name") or w.get("slug") or f"工作区 #{w.get('id')}") for w in workspaces}
        task_ws = {t.get("id"): t.get("workspace_id") for t in tasks}

        task_ids = [t.get("id") for t in tasks if t.get("id") is not None]
        runs: List[Dict[str, Any]] = []
        if workspace_id is None:
            # 未筛选工作区：直接取全表，一条不漏（含 task_id 为 NULL 与哨兵值 999999 的调用）
            runs = self.db.execute(
                "SELECT task_id, purpose, stage, model, model_profile, input_tokens, output_tokens,"
                " cost_usd, latency_ms, prompt_hash, workspace_id FROM model_runs",
                fetchall=True,
            ) or []
        elif task_ids:
            placeholders = ",".join("?" * len(task_ids))
            # （task_id 列是后加的，早期调用没有归属，其任务也可能已被清理）。
            # 它们是真实发生过的用量，静默丢掉会让总用量少算三分之二；
            # 所以未筛选工作区时一并纳入，但单列为「未关联任务」，不与具体任务/工作区混淆。
            # 一旦筛选了工作区，这些调用无法归属到该工作区，只能不计。
            scope_sql = (
                f"task_id IN ({placeholders})"
                if workspace_id is not None
                else f"(task_id IN ({placeholders}) OR task_id IS NULL)"
            )
            runs = self.db.execute(
                "SELECT task_id, purpose, stage, model, model_profile, input_tokens, output_tokens,"
                " cost_usd, latency_ms, prompt_hash, workspace_id FROM model_runs WHERE " + scope_sql,
                tuple(task_ids),
                fetchall=True,
            ) or []

        attributed = [r for r in runs if (r.get("workspace_id") or r.get("task_id") in task_ws)]
        unassigned = [r for r in runs if not (r.get("workspace_id") or r.get("task_id") in task_ws)]

        latencies = [_as_float(r.get("latency_ms")) for r in runs]
        input_tokens = sum(_as_int(r.get("input_tokens")) for r in runs)
        output_tokens = sum(_as_int(r.get("output_tokens")) for r in runs)
        cost_total = sum(_as_float(r.get("cost_usd")) for r in runs)

        by_model = _group_runs(runs, lambda r: str(r.get("model") or r.get("model_profile") or "未标注"))
        # stage 空串是历史数据缺口，显式归到「未标注阶段」而不是当成某个阶段
        by_stage = _group_runs(runs, lambda r: str(r.get("stage") or "").strip() or "未标注阶段")
        by_purpose = _group_runs(runs, lambda r: str(r.get("purpose") or "未标注"))

        # 多次发送）。prompt_hash 结果缓存已对这些重复输入做「命中就跳过」（相同输入直接复用输出、
        # 不进模型）；此处只量化冗余体积，给出优化依据，不改扫描行为、不丢弃任何调用。
        ph_counter = Counter(str(r.get("prompt_hash") or "") for r in runs if (r.get("prompt_hash") or ""))
        dupe_hashes = {h: c for h, c in ph_counter.items() if c > 1}
        redundant_calls = sum(c - 1 for c in dupe_hashes.values())
        redundant_tokens = sum(
            (_as_int(r.get("input_tokens")) + _as_int(r.get("output_tokens")))
            for r in runs if str(r.get("prompt_hash") or "") in dupe_hashes
        )

        by_workspace: Dict[Any, Dict[str, Any]] = {}
        for task in tasks:
            wid = task.get("workspace_id")
            bucket = by_workspace.setdefault(wid, {
                "workspace_id": wid,
                "name": ws_names.get(wid, f"工作区 #{wid}"),
                "scans": 0,
                "llm_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            })
            bucket["scans"] += 1
        for row in code_rows:
            wid = task_ws.get(row["task_id"])
            if wid in by_workspace:
                bucket = by_workspace[wid]
                bucket.setdefault("file_count", 0)
                bucket["file_count"] += row["file_count"] or 0
        for run in runs:
            wid = run.get("workspace_id") or task_ws.get(run.get("task_id"))
            if wid in by_workspace:
                bucket = by_workspace[wid]
                bucket["llm_calls"] += 1
                bucket["input_tokens"] += _as_int(run.get("input_tokens"))
                bucket["output_tokens"] += _as_int(run.get("output_tokens"))

        notes: List[str] = []
        if not cost_total:
            notes.append(
                f"成本未计费：{len(runs)} 条 model_runs 的 cost_usd 全为 0"
                "（provider 未上报单价），本页不按假设单价推算金额。"
            )
        unlabeled = next((g for g in by_stage if g["key"] == "未标注阶段"), None)
        if unlabeled and unlabeled["calls"]:
            notes.append(f"阶段未标注：{unlabeled['calls']} 次调用 stage 为空（历史数据），已单列，不并入具体阶段。")
        if unassigned:
            notes.append(
                f"未关联任务：{len(unassigned)} 次调用的 task_id 为空或指向已不存在的任务（早期调用，"
                "task_id 列后加）。已计入总量，但无法归属到具体任务与工作区。"
            )

        return {
            "workspace_id": workspace_id,
            "scans": {
                "total": len(tasks),
                "by_status": by_status,
                "duration": {
                    "count": len(durations),
                    "total_seconds": round(sum(durations), 1),
                    "avg_seconds": _round1(_mean(durations)),
                    "p50_seconds": _round1(_percentile(durations, 0.5)),
                    "p95_seconds": _round1(_percentile(durations, 0.95)),
                    "max_seconds": _round1(max(durations) if durations else 0.0),
                },
                "recent": [
                    {
                        "task_id": t.get("id"),
                        "name": t.get("name"),
                        "status": t.get("status"),
                        "created_at": t.get("created_at"),
                        "duration_seconds": (
                            round((_parse_dt(t.get("finished_at")) - _parse_dt(t.get("started_at"))).total_seconds(), 1)
                            if _parse_dt(t.get("started_at")) and _parse_dt(t.get("finished_at"))
                            else None
                        ),
                    }
                    for t in list(reversed(tasks))[:10]
                ],
            },
            "code_volume": {
                "scans_indexed": len(code_rows),
                "files_total": sum(r["file_count"] or 0 for r in code_rows),
                "functions_total": sum(r["indexed_functions"] or 0 for r in code_rows),
                "http_entries_total": sum(r["http_entries"] or 0 for r in code_rows),
                "avg_files_per_scan": _round1(_mean([r["file_count"] or 0 for r in code_rows])),
                "per_scan": list(reversed(code_rows))[:10],
            },
            "llm": {
                "calls": len(runs),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "cost_usd": round(cost_total, 6),
                "billed": bool(cost_total),
                "attributed": {
                    "calls": len(attributed),
                    "total_tokens": sum(
                        _as_int(r.get("input_tokens")) + _as_int(r.get("output_tokens")) for r in attributed
                    ),
                },
                "unassigned": {
                    "calls": len(unassigned),
                    "total_tokens": sum(
                        _as_int(r.get("input_tokens")) + _as_int(r.get("output_tokens")) for r in unassigned
                    ),
                },
                "latency": {
                    "avg_ms": _round1(_mean(latencies)),
                    "p50_ms": _round1(_percentile(latencies, 0.5)),
                    "p95_ms": _round1(_percentile(latencies, 0.95)),
                    "max_ms": _round1(max(latencies) if latencies else 0.0),
                    "total_ms": _round1(sum(latencies)),
                },
                "by_model": by_model,
                "by_stage": by_stage,
                "redundant": {
                    "distinct_prompt_hashes": len(ph_counter),
                    "duplicated_hashes": len(dupe_hashes),
                    "redundant_calls": redundant_calls,
                    "redundant_tokens": redundant_tokens,
                },
            },
            "agents": {
                "calls": len(runs),
                "by_purpose": by_purpose,
            },
            "by_workspace": sorted(by_workspace.values(), key=lambda b: b["scans"], reverse=True),
            "notes": notes,
        }

    # ------------------------------------------------------------------ IAST #
    def iast_source_stats(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> Dict[str, Any]:
        """ 接入 IAST 来源统计（覆盖率 / confirmed_runtime 占比 / 按资产分布）。

        复用 IastCorrelationService 的查询层聚合（不改表），作为 ops 大盘的 IAST 来源切片。
        """
        from src.iast.correlation import IastCorrelationService

        svc = IastCorrelationService(self.db)
        return svc.correlate(workspace_id=workspace_id, task_id=task_id)["stats"]

    def export_ticket(self, finding_id: int, *, platform: str = "offline", project: str = "",
                      webhook_url: str = "") -> Dict[str, Any]:
        record = self.finding_repo.get(finding_id)
        if record is None:
            raise ValueError(f"finding {finding_id} not found")
        adapter = get_ticketing_adapter(platform, webhook_url=webhook_url)
        return adapter.create_ticket(self._finding_dict(record), project=project)

    @staticmethod
    def _finding_dict(record) -> Dict[str, Any]:
        raw = dict(record.raw or {})
        raw.setdefault("display_family", record.finding_type)
        raw.setdefault("severity", record.severity)
        raw.setdefault("file", record.file_path)
        raw.setdefault("line", record.line)
        raw.setdefault("title", record.title)
        # Prefer the reviewed status when present in the raw payload.
        raw.setdefault("status", raw.get("status") or "")
        raw.setdefault("language", raw.get("language") or "")
        return raw


# --------------------------------------------------------------------- 用量辅助 #
def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0
    return int(num) if math.isfinite(num) else 0


def _as_float(value: Any) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return 0.0
    return num if math.isfinite(num) else 0.0


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _percentile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(ordered[lo])
    return float(ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo))


def _round1(value: float) -> float:
    return round(float(value), 1)


def _preprocess_metrics(raw: Any) -> Dict[str, Any]:
    """取预处理阶段的代码量指标。pipeline 与 results 两处都可能落，找不到就返回空 ——
    宁可显示「无数据」也不拿别的阶段数字顶替。"""
    if not raw:
        return {}
    try:
        data = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (TypeError, ValueError):
        return {}
    for source in (data.get("pipeline"), data.get("results")):
        if not isinstance(source, dict):
            continue
        node = source.get("preprocess")
        if isinstance(node, dict):
            metrics = node.get("metrics")
            if isinstance(metrics, dict) and metrics:
                return metrics
    return {}


def _group_runs(runs: List[Dict[str, Any]], key_of: Callable[[Dict[str, Any]], str]) -> List[Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    for run in runs:
        key = key_of(run)
        bucket = buckets.setdefault(
            key, {"key": key, "calls": 0, "input_tokens": 0, "output_tokens": 0, "latencies": []}
        )
        bucket["calls"] += 1
        bucket["input_tokens"] += _as_int(run.get("input_tokens"))
        bucket["output_tokens"] += _as_int(run.get("output_tokens"))
        bucket["latencies"].append(_as_float(run.get("latency_ms")))
    rows: List[Dict[str, Any]] = []
    for bucket in buckets.values():
        latencies = bucket.pop("latencies")
        rows.append({
            **bucket,
            "avg_ms": _round1(_mean(latencies)),
            "p95_ms": _round1(_percentile(latencies, 0.95)),
            "total_ms": _round1(sum(latencies)),
        })
    rows.sort(key=lambda row: row["calls"], reverse=True)
    return rows
