"""意图桥接。

把 I2 判因结果转成 replay_intents 记录，并在 D2 重放后据确定性证据回写 status；
同时给 A2 生成「意图摘要」注入 prompt（状态外置）。

- emit_intents_from_verdicts：I2 判因产出 {hid: verdict_dict} 后调用，落库为 intent 记录；
- reconcile_intent_after_attempt：D2 重放完成后据 oracle/证据回写 done_effective/done_ineffective；
- build_a2_intent_hints：下一轮 A2 调用前读取 pending/ineffective 摘要。

纯函数为主，无 LLM 依赖。连接统一用原始 sqlite3.Connection（测试用 :memory:；
生产用 `Database.connect` 取底层连接）。
"""
from __future__ import annotations

import sqlite3
from typing import Any, Dict, Optional

from src.iast import replay_intents_repo as R


def _spec_context(connection: sqlite3.Connection, task_id: int,
                  vhash: str) -> Dict[str, Any]:
    """按 (task_id, vhash) 取 trigger_specs 行，补充 endpoint/family 等。取不到返回空。"""
    try:
        row = connection.execute(
            "SELECT * FROM trigger_specs WHERE task_id=? AND vulnerability_hash_v2=? "
            "ORDER BY id DESC LIMIT 1", (int(task_id), str(vhash))).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


def emit_intents_from_verdicts(connection: sqlite3.Connection, task_id: int,
                               classified: Dict[str, Dict[str, Any]],
                               spec_ctx: Optional[Dict[str, Dict[str, Any]]] = None) -> int:
    """对 I2 判因结果逐条产出 intent 记录。

    classified: {vulnerability_hash_v2: {"verdict","action","payload","reason","source",...}}
    spec_ctx:   可选 {vhash: spec_row}，避免每条都查 trigger_specs；缺省时按 (task_id, vhash) 查。
    返回新建 intent 条数。
    """
    spec_ctx = spec_ctx or {}
    n = 0
    for vhash, vd in (classified or {}).items():
        if not isinstance(vd, dict):
            continue
        # 去重：同一 (task_id, vhash, action) 只保留一条意图记录，避免每轮 I2 重复插入
        # 导致 pending 永不收敛。已存在则跳过（无论状态；pending/ineffective 都已记录）。
        try:
            _dup = connection.execute(
                "SELECT 1 FROM replay_intents WHERE task_id=? AND vulnerability_hash_v2=? AND action=? "
                "LIMIT 1", (int(task_id), str(vhash), vd.get("action") or "give_up")).fetchone()
        except Exception:
            _dup = None
        if _dup:
            continue
        ctx = spec_ctx.get(vhash) or _spec_context(connection, task_id, vhash)
        rec = R.build_intent_from_i2_verdict(
            task_id=task_id,
            spec_id=ctx.get("id"),
            vulnerability_hash_v2=vhash,
            family=ctx.get("family", "") or "",
            endpoint=ctx.get("target_endpoint", "") or "",
            http_method=ctx.get("http_method", "GET") or "GET",
            param_name=ctx.get("param_name", "") or "",
            param_location=ctx.get("param_location", "query") or "query",
            verdict=vd.get("verdict", ""),
            action=vd.get("action") or "give_up",
            payload=vd.get("payload", "") or "",
            encoding=vd.get("encoding", "") or "",
            header=vd.get("header", "") or "",
            rationale=vd.get("reason", "") or "",
            round_no=int(ctx.get("round_no") or vd.get("round") or 1),
        )
        R.insert_intent(connection, **rec)
        n += 1
    return n


def reconcile_intent_after_attempt(connection: sqlite3.Connection, intent_id: int, *,
                                   effective: bool, evidence_ref: str = "",
                                   rationale: Optional[str] = None) -> None:
    """D2 重放后据确定性证据回写 intent 状态。effective=True→done_effective，否则 done_ineffective。"""
    R.update_status(connection, intent_id,
                    "done_effective" if effective else "done_ineffective",
                    evidence_ref=evidence_ref, rationale=rationale)


def build_a2_intent_hints(connection: sqlite3.Connection, task_id: int,
                          max_pending: int = 20, max_ineffective: int = 10) -> str:
    return R.summarize_for_prompt(connection, task_id, max_pending, max_ineffective)
