# -*- coding: utf-8 -*-
"""trigger_specs 权威列 ↔ raw_json.exploit_spec.entry 投影同步。

问题（本轮实测 39/145 处差异）：I1 的多个 post-pass 会在 D1 重放前把
``param_name / param_location / content_type`` 这些**权威列**改成按注解、源码、
形参类型推断出的真值，但只发 ``UPDATE trigger_specs SET ...``，从不回写
``raw_json.exploit_spec.entry``。D1 读权威列所以重放没问题，报告层读 entry 却拿到
A2 阶段的旧猜测（如 ``query`` vs 实际 ``body``），看起来像「两套真相」。

结论：这不是需要并存的双轨语义，而是投影漏同步。统一在这里收口——
所有改权威列的 post-pass 必须跟着调 ``sync_entry_projection``，让 entry 恒等于权威列；
A2 原始意图若需留存，用 ``entry.a2_intent`` 显式快照，不要靠「不回写」隐式保留。

对外只读审计 ``audit_entry_projection`` 用于离线复核历史 task 的漂移。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 权威列 → entry 字段
_FIELD_MAP = {
    "param_name": "parameter_name",
    "param_location": "parameter_location",
    "content_type": "content_type",
}


def _parse_raw(raw: Any) -> Optional[Dict[str, Any]]:
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return None
    return out if isinstance(out, dict) else None


def _write_raw(db, spec_id: int, doc: Dict[str, Any]) -> bool:
    db.execute("UPDATE trigger_specs SET raw_json=? WHERE id=?",
               (json.dumps(doc, ensure_ascii=False), int(spec_id)))
    return True


def sync_entry_projection(db, spec_id: int, *, param_name: Optional[str] = None,
                          param_location: Optional[str] = None,
                          content_type: Optional[str] = None) -> bool:
    """把刚写入的权威列值投影回 raw_json.exploit_spec.entry。

    只读一次、写一次；任何异常都吞掉并记 debug，绝不让投影同步阻断重放主流程。
    返回是否真的改了内容（值原本就一致时返回 False，避免无谓写库）。
    """
    values = {"param_name": param_name, "param_location": param_location,
              "content_type": content_type}
    values = {k: v for k, v in values.items() if v is not None}
    if not values:
        return False
    try:
        row = db.execute("SELECT raw_json FROM trigger_specs WHERE id=?",
                         (int(spec_id),), fetchone=True)
        if not row:
            return False
        raw = row["raw_json"] if isinstance(row, dict) else row[0]
        doc = _parse_raw(raw)
        if not doc:
            return False
        spec = doc.get("exploit_spec")
        if not isinstance(spec, dict):
            return False
        entry = spec.get("entry")
        if not isinstance(entry, dict):
            return False
        changed = False
        for col, val in values.items():
            key = _FIELD_MAP[col]
            new = str(val or "")
            if str(entry.get(key) or "") != new:
                # 只在第一次改动时留一份 A2 意图快照，避免多次 post-pass 把快照层层覆盖
                if "a2_intent" not in entry and key in ("parameter_name", "parameter_location"):
                    entry["a2_intent"] = {
                        "parameter_name": str(entry.get("parameter_name") or ""),
                        "parameter_location": str(entry.get("parameter_location") or ""),
                    }
                entry[key] = new
                changed = True
        if changed:
            entry["param_authority"] = "trigger_specs"
            return _write_raw(db, spec_id, doc)
    except Exception as exc:  # noqa: BLE001  投影是旁路，不能影响主流程
        logger.debug("[spec-projection] spec=%s 同步失败（忽略）：%s", spec_id, exc)
    return False


_AUDIT_COLS = ("id", "param_name", "param_location", "content_type", "raw_json")


def audit_entry_projection_rows(rows) -> List[Dict[str, Any]]:
    """只读审计的纯函数：接受 dict / sqlite3.Row / tuple 行，返回漂移清单。"""
    out: List[Dict[str, Any]] = []
    for r in rows or []:
        def get(key, _r=r):
            if isinstance(_r, dict):
                return _r.get(key)
            try:
                return _r[key]          # sqlite3.Row 支持按列名
            except (TypeError, KeyError, IndexError):
                return _r[_AUDIT_COLS.index(key)]  # 普通 tuple

        doc = _parse_raw(get("raw_json"))
        entry = ((doc or {}).get("exploit_spec") or {}).get("entry")
        if not isinstance(entry, dict):
            continue
        diffs = {}
        for col, key in _FIELD_MAP.items():
            authoritative = str(get(col) or "")
            projected = str(entry.get(key) or "")
            if col == "content_type" and not authoritative and not projected:
                continue
            if authoritative != projected:
                diffs[col] = {"authoritative": authoritative, "entry": projected}
        if diffs:
            out.append({"spec_id": get("id"), "diffs": diffs})
    return out


def audit_entry_projection(db, task_id: int) -> List[Dict[str, Any]]:
    """只读审计：列出该 task 下 entry 与权威列不一致的 spec。"""
    rows = db.execute(
        "SELECT id, param_name, param_location, content_type, raw_json "
        "FROM trigger_specs WHERE task_id=?", (int(task_id),), fetchall=True) or []
    return audit_entry_projection_rows(rows)
