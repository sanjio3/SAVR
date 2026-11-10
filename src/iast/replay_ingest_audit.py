"""Q9 闭环差值告警：发出重放数 vs 收到 IAST 事件数。

SAVR 摄取侧已是「阻塞不丢」（SQLite 单写者串行刷盘 + 背压降速，非丢弃，见
service.py:ingest_events 与 ingest_metrics.py），故本模块只做闭环核对：D2 重验后，
比对「本 task 发出重放数」与「本 task 收到 iast_events 条数」的差值，差值超容差即
判定探针侧可能丢事件（sec-probe.jar 的 EventBuffer 满则 passthrough 丢，属跨仓库
待修项），并落一条可见告警（scan_task_events，event_type='replay_ingest_gap'），
而非静默。

探针侧 EventBuffer 改「阻塞生产者 / 落盘不丢」是 sec-probe.jar 仓库的修复，本仓库
只负责暴露信号并告警，与 Q4 的 JVM 真 Pattern 互校同为跨仓库 TODO。
"""
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# 软告警阈值：收到事件数 / 发出重放数 < 该比例 且 no-arrival 占比高 → 疑似探针丢事件。
_SAST_AI_REPLAY_INGEST_GAP_RATIO = float(os.environ.get("SAST_AI_REPLAY_INGEST_GAP_RATIO", "0.1"))
# no-arrival 占比达到该比例才触发软告警（避免把「确实大量无到达」误判成丢事件）。
_SAST_AI_REPLAY_INGEST_GAP_NOARRIVAL_RATIO = float(
    os.environ.get("SAST_AI_REPLAY_INGEST_GAP_NOARRIVAL_RATIO", "0.5")
)


def _count(db, sql: str, params) -> int:
    row = db.execute(sql, params, fetchone=True)
    if not row:
        return 0
    return int(next(iter(row.values()), 0) or 0)


def _count_safe(db, sql: str, params) -> int:
    """列可能不存在的安全计数（如 scan_tasks.replayed_count 并不存在该列）。"""
    try:
        return _count(db, sql, params)
    except Exception as _e:  # noqa: BLE001 —— 口径缺失不应让核对整个失败
        logger.debug("[Q9] 计数失败（按 0 处理）：%s", _e)
        return 0


def reconcile_replay_ingest_gap(db, task_id: int) -> Dict[str, Any]:
    """比对本 task 发出重放数 vs 收到 IAST 事件数，输出差值诊断与告警。

    返回 dict（含 replayed_count / iast_event_count / specs_total / no_arrival_count /
    gap / recovery_ratio / alert / severity / tolerance / reason），并视情况把告警写进
    scan_task_events（event_type='replay_ingest_gap'），保证不静默。

    口径（2026-10-26 修正）：
    - 发出重放数优先取 **replay_attempts 行数**（观察层：每次重放落一行，含 bypass 变体
      与 oracle 探测臂），这是「真正发出的 HTTP 重放次数」的准确口径；
      次取 scan_tasks.replayed_count（该列在当前 schema 中**并不存在**，旧实现直接查它
      ⇒ `no such column: replayed_count`，整个差值核对被降级为「计算失败」告警）；
      两者都取不到时退化为本 task trigger_specs 条数（每条 spec 至少一次重放）。
    - 收到 IAST 事件数 = iast_events WHERE task_id = ?（已含 canary 三态 / no-arrival 诊断）。
    """
    task_id = int(task_id)
    # ① 首选：观察层 replay_attempts（真实重放次数）
    replayed = _count_safe(db, "SELECT COUNT(*) FROM replay_attempts WHERE task_id=?", (task_id,))
    replayed_source = "replay_attempts"
    # ② 兼容旧字段（当前 schema 无此列时静默降级）
    if replayed <= 0:
        legacy = _count_safe(
            db, "SELECT COALESCE(replayed_count,0) FROM scan_tasks WHERE id=?", (task_id,)
        )
        if legacy > 0:
            replayed, replayed_source = legacy, "scan_tasks.replayed_count"
    specs_total = _count(db, "SELECT COUNT(*) FROM trigger_specs WHERE task_id=?", (task_id,))
    # ③ 退化：按 spec 条数还原发出重放数（每 spec 至少一次重放）
    if replayed <= 0 and specs_total > 0:
        replayed = specs_total
        replayed_source = "trigger_specs(count)"
    iast_event_count = _count(db, "SELECT COUNT(*) FROM iast_events WHERE task_id=?", (task_id,))
    no_arrival_count = _count(
        db,
        "SELECT COUNT(*) FROM trigger_specs WHERE task_id=? "
        "AND (iast_state IS NULL OR iast_state='' OR iast_state='no-arrival')",
        (task_id,),
    )
    gap = replayed - iast_event_count
    ratio = (iast_event_count / replayed) if replayed > 0 else 1.0

    alert = False
    severity = "ok"
    reason = ""
    # 硬告警：发了重放却零事件 → 探针几乎必然丢事件（run 40 的 /log4j 重放事件全丢成 no-arrival）。
    if replayed > 0 and iast_event_count == 0:
        alert = True
        severity = "hard"
        reason = (
            f"本 task 发出重放 {replayed} 次但收到 IAST 事件 0 条，探针侧几乎必然丢事件"
            f"（sec-probe.jar EventBuffer 背压 passthrough 丢弃，属跨仓库待修项），"
            f"请排查探针织桩覆盖与 EventBuffer 背压策略。"
        )
    # 软告警：事件回收率远低于阈值 且 no-arrival 占比高 → 疑似探针丢事件而非真实无到达。
    elif (
        replayed > 0
        and ratio < _SAST_AI_REPLAY_INGEST_GAP_RATIO
        and specs_total > 0
        and (no_arrival_count / specs_total) >= _SAST_AI_REPLAY_INGEST_GAP_NOARRIVAL_RATIO
    ):
        alert = True
        severity = "soft"
        reason = (
            f"本 task 发出重放 {replayed} 次仅收到 IAST 事件 {iast_event_count} 条"
            f"（回收率 {ratio:.1%} < 容差 {_SAST_AI_REPLAY_INGEST_GAP_RATIO:.1%}），"
            f"且 {no_arrival_count}/{specs_total} 条 no-arrival 占比高，疑似探针侧丢事件而非真实无到达，"
            f"需排查探针织桩/EventBuffer（sec-probe.jar）。"
        )

    out: Dict[str, Any] = {
        "task_id": task_id,
        "replayed_count": replayed,
        "replayed_source": replayed_source,
        "iast_event_count": iast_event_count,
        "specs_total": specs_total,
        "no_arrival_count": no_arrival_count,
        "gap": gap,
        "recovery_ratio": round(ratio, 4),
        "tolerance_ratio": _SAST_AI_REPLAY_INGEST_GAP_RATIO,
        "no_arrival_ratio": round((no_arrival_count / specs_total), 4) if specs_total > 0 else 0.0,
        "alert": alert,
        "severity": severity,
        "reason": reason,
    }
    if alert:
        _record_gap_event(db, task_id, out)
    return out


def _record_gap_event(db, task_id: int, payload: Dict[str, Any]) -> None:
    """把差值告警写进 scan_task_events（event_type='replay_ingest_gap'），保证不静默。"""
    try:
        db.execute(
            "INSERT INTO scan_task_events (task_id, event_type, payload_json, created_at) "
            "VALUES (?, 'replay_ingest_gap', ?, datetime('now'))",
            (int(task_id), json.dumps(payload, ensure_ascii=False)),
        )
    except Exception as _e:  # 告警记录失败绝不阻断任务收尾
        logger.warning("[Q9] 差值告警落库失败（不影响任务收尾）：%s", _e)
