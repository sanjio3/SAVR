"""扫描结果差分门禁（2026-09-20）。

规则提级流程声明为「staging → 跑 golden 回归 + D2 差分门禁 → 人工确认 → active」。
其中 **golden 回归** 已由 ``src/core/rule_golden_gate.py`` 落地；**D2 差分门禁**此前同样没有实现 ——
项目里只有一堆一次性临时脚本（``_cmp_2427.py``、``scripts/_diag_*`` 等），每次对比都要重写一遍。

本模块把「拿两次扫描任务做前后差分、并按守卫指标判定是否回归」做成可复用能力：

  - ``collect_metrics(task_id)`` —— 从 ``scan_tasks.summary_json`` 取该任务的权威指标。
    取这里是刻意的：``findings`` 表只在任务收尾由 ``replace_for_task`` 统一重写，
    运行期该表无本任务行，运行期数字必须取自 ``summary.final_report_summary``
    （见项目铁律）。
  - ``diff_metrics(baseline, candidate)`` —— 数值指标逐项 delta + 分布（by_severity / by_type）差异。
  - ``evaluate_diff_gate(baseline_id, candidate_id, guards=)`` —— 守卫指标**只允许不小于基线**，
    任一跌破即判回归（``ok=False``）。

只读打开数据库（``mode=ro``），不会与运行中的后端争锁。
只用标准库。
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.tool_paths import get_repo_root

# 默认守卫指标：D2 链路的口径。激活一条**纯增量**的 A1 静态规则不应让这些数字下降；
# 一旦下降说明新规则扰动了既有判定（例如顶掉了别的族、或让某条链不再成立）。
DEFAULT_GUARDS: List[str] = [
    "d2_verified_count",
    "d2_confirmed_exploitable",
    "d2_sink_reached_count",
    "d2_poc_generated",
    "chain_proven_count",
    "contract_ready_count",
]

# 参与差分展示的数值指标（不全是守卫，只是给人看全貌）
NUMERIC_METRICS: List[str] = [
    "total_vulnerabilities",
    "sca_count",
    "a1_count",
    "a2_count",
    "broad_static_count",
    "chain_proven_count",
    "contract_ready_count",
    "d2_tested_count",
    "d2_verified_count",
    "d2_confirmed_exploitable",
    "d2_sink_reached_count",
    "d2_poc_generated",
    "d2_harmful_count",
    "d2_impact_count",
    "exploitable_count",
]

DISTRIBUTION_KEYS: List[str] = ["by_severity", "by_type"]


def default_db_path() -> Path:
    """数据库路径：优先 ``SAST_AI_DB_PATH``（与 MCP 侧取数口径一致），否则 ``<repo>/data/app.db``。"""
    env = os.environ.get("SAST_AI_DB_PATH")
    return Path(env) if env else get_repo_root() / "data" / "app.db"


def _connect(db_path: Optional[Path]) -> sqlite3.Connection:
    path = Path(db_path) if db_path else default_db_path()
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def _model_mix(con: sqlite3.Connection, task_id: int) -> Dict[str, Any]:
    """统计该任务的模型画像（provider / model 计数）。

    ``options_json`` **不记录** model/provider（它们在 config.yaml 里），所以可比性只能由
    ``model_runs`` 反推：provider 在 ``metadata_json``，model 是独立列，两表都有 ``task_id``。
    """
    providers: Dict[str, int] = {}
    models: Dict[str, int] = {}
    runs = 0
    for row in con.execute(
        "SELECT model, metadata_json FROM model_runs WHERE task_id=?", (int(task_id),)
    ):
        runs += 1
        models[str(row["model"] or "?")] = models.get(str(row["model"] or "?"), 0) + 1
        try:
            meta = json.loads(row["metadata_json"] or "{}")
        except Exception:
            meta = {}
        key = str(meta.get("provider") or meta.get("api_provider") or "?")
        providers[key] = providers.get(key, 0) + 1
    return {"runs": runs, "providers": providers, "models": models}


def _compare_model_mix(base: Dict[str, Any], cand: Dict[str, Any]) -> Dict[str, Any]:
    """判定两次扫描的模型画像是否可比。

    两任务若跑在不同的 provider / 模型上，指标差异**不能归因于被测改动**（例如规则提级），
    此时差分门禁的结论无效 —— 必须显式指出，否则会得出错误归因。
    """
    if base["runs"] == 0 and cand["runs"] == 0:
        return {"status": "unknown", "note": "两侧均无 model_runs 记录，模型画像无法核对"}
    if base["runs"] == 0 or cand["runs"] == 0:
        return {
            "status": "mismatch",
            "note": f"一侧无 model_runs 记录（baseline={base['runs']} / candidate={cand['runs']}），"
                    f"模型画像不可比",
        }
    if set(base["providers"]) != set(cand["providers"]) or set(base["models"]) != set(cand["models"]):
        return {
            "status": "mismatch",
            "note": f"provider/模型不一致：baseline={base['providers']}/{list(base['models'])} vs "
                    f"candidate={cand['providers']}/{list(cand['models'])}",
        }
    return {"status": "ok", "note": ""}


def collect_metrics(task_id: int, *, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """取单个任务的可比较指标。任务不存在或无 summary 时抛 ValueError。"""
    con = _connect(db_path)
    try:
        row = con.execute(
            "SELECT id, status, workspace_id, summary_json FROM scan_tasks WHERE id=?",
            (int(task_id),),
        ).fetchone()
        if row is None:
            raise ValueError(f"scan_task {task_id} not found")
        mix = _model_mix(con, task_id)
    finally:
        con.close()
    summary = json.loads(row["summary_json"] or "{}")
    frs = summary.get("final_report_summary") or {}
    metrics = {
        "task_id": int(row["id"]),
        "status": row["status"],
        "workspace_id": row["workspace_id"],
        "has_summary": bool(frs),
        "model_mix": mix,
    }
    for key in NUMERIC_METRICS:
        try:
            metrics[key] = int(frs.get(key) or 0)
        except Exception:
            metrics[key] = 0
    for key in DISTRIBUTION_KEYS:
        raw = frs.get(key) or {}
        metrics[key] = {str(k): int(v or 0) for k, v in raw.items()} if isinstance(raw, dict) else {}
    return metrics


def diff_metrics(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """逐项数值 delta + 分布差异。delta = candidate - baseline。"""
    numeric: Dict[str, Dict[str, int]] = {}
    for key in NUMERIC_METRICS:
        base_v = int(baseline.get(key) or 0)
        cand_v = int(candidate.get(key) or 0)
        numeric[key] = {"baseline": base_v, "candidate": cand_v, "delta": cand_v - base_v}

    distributions: Dict[str, Dict[str, Dict[str, int]]] = {}
    for key in DISTRIBUTION_KEYS:
        base_d = baseline.get(key) or {}
        cand_d = candidate.get(key) or {}
        entries: Dict[str, Dict[str, int]] = {}
        for name in set(base_d) | set(cand_d):
            b = int(base_d.get(name) or 0)
            c = int(cand_d.get(name) or 0)
            if b != c:
                entries[str(name)] = {"baseline": b, "candidate": c, "delta": c - b}
        distributions[key] = entries

    return {
        "baseline_task_id": baseline.get("task_id"),
        "candidate_task_id": candidate.get("task_id"),
        "numeric": numeric,
        "distributions": distributions,
    }


def evaluate_diff_gate(
    baseline_id: int,
    candidate_id: int,
    *,
    guards: Optional[List[str]] = None,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """D2 差分门禁：守卫指标**只允许不小于基线**，任一跌破即 ``ok=False``。

    返回 ``{ok, baseline, candidate, diff, guards, regressions}``。
    """
    guards = list(guards) if guards else list(DEFAULT_GUARDS)
    baseline = collect_metrics(baseline_id, db_path=db_path)
    candidate = collect_metrics(candidate_id, db_path=db_path)
    comparability = _compare_model_mix(baseline.get("model_mix") or {"runs": 0, "providers": {}, "models": {}},
                                       candidate.get("model_mix") or {"runs": 0, "providers": {}, "models": {}})
    if not baseline.get("has_summary") or not candidate.get("has_summary"):
        missing = [t["task_id"] for t in (baseline, candidate) if not t.get("has_summary")]
        return {
            "ok": False,
            "reason": f"任务缺少 final_report_summary，无法差分：{missing}",
            "baseline": baseline,
            "candidate": candidate,
            "diff": None,
            "guards": guards,
            "regressions": [],
            "comparability": comparability,
        }

    diff = diff_metrics(baseline, candidate)
    regressions = [
        {"metric": g, **diff["numeric"][g]}
        for g in guards
        if g in diff["numeric"] and diff["numeric"][g]["delta"] < 0
    ]
    reasons: List[str] = []
    if comparability["status"] == "mismatch":
        # 模型画像不同 → 指标差异不可归因于被测改动，结论无效（既不算通过也不算回归）
        reasons.append("两任务模型画像不可比，差分结论不可归因：" + comparability["note"])
    if regressions:
        reasons.append("守卫指标跌破基线：" + ", ".join(
            f"{r['metric']} {r['baseline']}->{r['candidate']}" for r in regressions
        ))
    return {
        "ok": not reasons,
        "reason": "；".join(reasons),
        "baseline": baseline,
        "candidate": candidate,
        "diff": diff,
        "guards": guards,
        "regressions": regressions,
        "comparability": comparability,
    }


def format_diff_report(result: Dict[str, Any]) -> str:
    """纯文本报告（含数值 delta 与分布差异）。"""
    base = result["baseline"]
    cand = result["candidate"]
    lines = [
        f"baseline task-{base.get('task_id')} ({base.get('status')}) "
        f"-> candidate task-{cand.get('task_id')} ({cand.get('status')})",
        f"guards = {result.get('guards')}",
        f"verdict = {'PASS' if result['ok'] else 'FAIL'}",
    ]
    cm = result.get("comparability") or {}
    if cm:
        note = f" ({cm['note']})" if cm.get("note") else ""
        lines.append(f"comparability = {cm.get('status')}{note}")
    lines.append(f"model_mix baseline = {base.get('model_mix')}")
    lines.append(f"model_mix candidate = {cand.get('model_mix')}")
    if result.get("reason"):
        lines.append(f"reason = {result['reason']}")
    diff = result.get("diff")
    if not diff:
        return "\n".join(lines)
    lines.append("")
    lines.append("指标            baseline   candidate      delta")
    for key, v in diff["numeric"].items():
        flag = "  <= guard" if key in (result.get("guards") or []) else ""
        lines.append(f"  {key:<24} {v['baseline']:>8} {v['candidate']:>11} {v['delta']:>+10}{flag}")
    for key, entries in (diff.get("distributions") or {}).items():
        if not entries:
            continue
        lines.append("")
        lines.append(f"{key} 差异（仅列有变化的项）：")
        for name, v in sorted(entries.items(), key=lambda kv: -abs(kv[1]["delta"])):
            lines.append(f"  {name:<28} {v['baseline']:>8} {v['candidate']:>11} {v['delta']:>+10}")
    return "\n".join(lines)
