"""假说表（hypotheses）：SAST 假说的生命周期与差集载体。

「SAST ⊖ IAST 自我修正系统」未成型的四因之一，是**没有差集载体**——假说只以自然语言
reason 字符串存在于 I2 的 feedback_to_a2 里，没有「哪一轮提出、是否被证实、是否被证伪、
是否仍悬置」的结构化记录，所以无法计算「假说集 ⊖ 观测集」，闭环只能退化成关键词分流。

本模块提供：
- ``refresh_hypotheses``：以 trigger_specs 为假说来源、以 iast_events / verification_status
  为观测来源，把每条假说收敛到 proposed / confirmed / refuted / open 四态之一；
- ``difference_set``：导出「观测集没能证实或证伪的假说」（state=open）及其未闭合的门禁项，
  即真正的差集，供 A2 定向修正。

设计取舍：state 由「已落库的 spec + 事件」派生而非从 A2 出生即跟踪，理由是派生方式不需要
改动 A2 产出路径、可对历史任务回溯重算，且与黑板保持同一套观测判据（canary 身份段匹配）。
代价是丢失「第几次提出」的精确轮次，故表内以 first/last_seen_task_id 近似记录。
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.iast.canary import canary_key, is_sink_reached

logger = logging.getLogger(__name__)

# 假说状态
PROPOSED = "proposed"
CONFIRMED = "confirmed"  # 运行时观测证实（sink 到达 / D2 判定可利用）
REFUTED = "refuted"      # 假说被观测证伪（声称可达但既未到达、且探针未插桩该路径）
OPEN = "open"            # 观测既未证实也未证伪 → 差集成员，需回流 A2 或重放侧

# verification_status 中代表「已证实」的取值
_CONFIRMED_VERIF = ("confirmed_exploitable", "exploitable", "confirmed",
                    "confirmed_code_property")
# 代表「明确无证据」的取值
_NO_EVIDENCE_VERIF = ("no_evidence",)


def _now() -> str:
    return datetime.utcnow().isoformat()


def _claimed_chain(spec: Dict[str, Any]) -> Dict[str, Any]:
    """从 spec 提取「假说声称的链路」摘要，供差集回流时还原上下文。"""
    return {
        "family": spec.get("family") or "",
        "endpoint": spec.get("target_endpoint") or "",
        "method": spec.get("http_method") or "",
        "param_name": spec.get("param_name") or "",
        "param_location": spec.get("param_location") or "",
        "expected_sink_file": spec.get("expected_sink_file") or "",
        "expected_sink_line": spec.get("expected_sink_line") or 0,
        "taint_marker": spec.get("taint_marker") or "",
        "gates": ["reachable", "attacker_control_proven", "gate_bypass_or_satisfaction_proven",
                  "payload_shape_proven"],
    }


def refresh_hypotheses(db, task_id: int, workspace_id: Optional[int] = None,
                       run_id: Optional[int] = None) -> Dict[str, int]:
    """按 trigger_specs + iast_events 重算本任务的假说表（幂等 upsert）。

    返回各状态计数。fail-open：任何异常只告警，不影响任务终态。
    """
    out = {"total": 0, PROPOSED: 0, CONFIRMED: 0, REFUTED: 0, OPEN: 0}
    if not task_id:
        return out
    try:
        if workspace_id is None:
            row = db.execute("SELECT workspace_id FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
            workspace_id = int(row["workspace_id"]) if row else 0
        if run_id is None:
            row = db.execute("SELECT run_id FROM scan_tasks WHERE id=?", (task_id,), fetchone=True)
            run_id = int(row["run_id"]) if row and row.get("run_id") else 0

        specs = db.execute(
            "SELECT id, vulnerability_hash_v2, family, target_endpoint, http_method, param_name,"
            " param_location, expected_sink_file, expected_sink_line, taint_marker,"
            " verification_status, iast_state, finding_id"
            " FROM trigger_specs WHERE task_id=?",
            (task_id,), fetchall=True,
        ) or []

        # 事件侧：canary 身份段 → sink 是否到达（与黑板同一判据）
        reached_canaries = set()
        events = db.execute(
            "SELECT canary, canary_state FROM iast_events WHERE task_id=?", (task_id,), fetchall=True
        ) or []
        for e in events:
            st = (e.get("canary_state") or "").strip().lower()
            if is_sink_reached(st) and e.get("canary"):
                reached_canaries.add(canary_key(e["canary"]))

        # 事件计数按 finding 粒度（关联归因写入 correlated_finding_id 后即生效）
        ev_count: Dict[int, int] = {}
        for e in (db.execute(
            "SELECT correlated_finding_id, COUNT(*) AS n FROM iast_events"
            " WHERE task_id=? AND correlated_finding_id IS NOT NULL GROUP BY 1",
            (task_id,), fetchall=True
        ) or []):
            ev_count[int(e["correlated_finding_id"])] = int(e["n"] or 0)

        now = _now()
        for s in specs:
            spec = dict(s)
            vh = spec.get("vulnerability_hash_v2") or ""
            if not vh:
                continue
            iast_state = (spec.get("iast_state") or "").strip().lower()
            verif = (spec.get("verification_status") or "").strip().lower()
            taint = spec.get("taint_marker") or ""
            sink_ok = bool(taint) and canary_key(taint) in reached_canaries

            if sink_ok or verif in _CONFIRMED_VERIF or is_sink_reached(iast_state):
                state, reason = CONFIRMED, "运行时观测证实：canary 到达 sink 或 D2 判定可利用"
            elif verif in _NO_EVIDENCE_VERIF and iast_state == "no-iast-evidence":
                state, reason = REFUTED, "观测证伪：假说声称可达，但既无 sink 到达、探针也未插桩该路径"
            elif not verif and not iast_state:
                state, reason = PROPOSED, "尚未进入观测（无重放结论）"
            else:
                state, reason = OPEN, "观测未证实亦未证伪：门禁项仍未闭合"

            try:
                db.execute(
                    """
                    INSERT INTO hypotheses
                    (workspace_id, task_id, run_id, vulnerability_hash_v2, family, target_endpoint,
                     http_method, claimed_chain_json, state, state_reason, evidence_event_count,
                     first_seen_task_id, last_seen_task_id, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(workspace_id, vulnerability_hash_v2, run_id) DO UPDATE SET
                        family=excluded.family,
                        target_endpoint=excluded.target_endpoint,
                        http_method=excluded.http_method,
                        claimed_chain_json=excluded.claimed_chain_json,
                        state=excluded.state,
                        state_reason=excluded.state_reason,
                        evidence_event_count=excluded.evidence_event_count,
                        last_seen_task_id=excluded.last_seen_task_id,
                        updated_at=excluded.updated_at
                    """,
                    (int(workspace_id or 0), int(task_id), int(run_id or 0), vh,
                     spec.get("family") or "", spec.get("target_endpoint") or "",
                     spec.get("http_method") or "GET",
                     json.dumps(_claimed_chain(spec), ensure_ascii=False),
                     state, reason, int(ev_count.get(int(spec.get("finding_id") or 0), 0)),
                     int(task_id), int(task_id), now, now),
                )
                out["total"] += 1
                out[state] = out.get(state, 0) + 1
            except Exception as _e:
                logger.warning("[hypotheses] 写入失败 vhash=%s：%s", str(vh)[:12], _e)
    except Exception as _e:
        logger.warning("[hypotheses] refresh 失败（不阻断）：%s", _e)
    return out


def difference_set(db, task_id: int, limit: int = 200) -> Dict[str, Any]:
    """导出差集：观测既未证实、也未证伪的假说（state=open）。

    这就是「SAST 假说集 ⊖ IAST 观测集」中真正需要回流的那一部分：不是全部失败，
    而是「重放跑了但四个门禁一个都没闭合」的条目。回流的对象应是结构化字段
    （gap_items / claimed_chain），不再是自然语言 reason。
    """
    try:
        rows = db.execute(
            "SELECT vulnerability_hash_v2, family, target_endpoint, http_method, state_reason,"
            " claimed_chain_json FROM hypotheses WHERE task_id=? AND state=? LIMIT ?",
            (task_id, OPEN, int(limit)), fetchall=True,
        ) or []
    except Exception as _e:
        logger.warning("[hypotheses] difference_set 失败：%s", _e)
        return {"open_count": 0, "items": []}

    items: List[Dict[str, Any]] = []
    for r in rows:
        try:
            chain = json.loads(r.get("claimed_chain_json") or "{}")
        except Exception:
            chain = {}
        items.append({
            "vulnerability_hash_v2": r.get("vulnerability_hash_v2"),
            "family": r.get("family"),
            "endpoint": r.get("target_endpoint"),
            "method": r.get("http_method"),
            "reason": r.get("state_reason"),
            "gates": chain.get("gates") or [],
            "claimed_chain": chain,
        })
    return {"open_count": len(items), "items": items}
