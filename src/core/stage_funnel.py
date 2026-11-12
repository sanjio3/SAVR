#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""阶段漏斗计数：在每个 stage 边界记录 ``(in, out, dropped_by_reason)``，按族分组。

## 为什么需要这个模块

- specs 从 109 静默变成 97，只能靠两个数字倒推是「孤儿清理」删的；
- Fastjson / ClassDataLoader 的 framework finding 在报告装配时被吞，只能靠
  「findings 里没有、spec 里有、报告里没有」三处对比才定位到方向。

两次排查都花了大量时间在**猜断点在哪**。**没有 stage 边界计数，每次都是猜。**

## 设计约束（缺一不可）

1. **只写不读**：不参与任何判定，返回值无人消费。
2. **绝不抛异常**：整个模块任何失败都被吞掉（主链路不能因为埋点而中断）。
3. **追加写 jsonl**：`data/stage_funnel/<task_id>.jsonl`，一行一个快照，
   便于 `diff` 两轮之间的漏斗形状，而不是读日志。
4. **可关**：`SAST_AI_STAGE_FUNNEL=0` 整体关闭（默认开，开销可忽略）。

## 用法

    from src.core.stage_funnel import record, record_counts
    record(task_id, "a1.framework_merge", in_count=len(hits), out_count=added,
           reasons={"dedup": skipped, "no_route": dropped},
           families={"crlf_injection": 2, "deserialization": 3})

    # 只有 in/out、没有细分原因时
    record_counts(task_id, "report.assemble", before=1234, after=153)
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_OUT_DIR = os.path.join(_ROOT, "data", "stage_funnel")


def _enabled() -> bool:
    return str(os.environ.get("SAST_AI_STAGE_FUNNEL", "1")).strip().lower() not in (
        "0", "false", "no", "off")


def record(task_id: Optional[int], stage: str, *,
           in_count: int = 0, out_count: int = 0,
           reasons: Optional[Dict[str, Any]] = None,
           families: Optional[Dict[str, Any]] = None,
           note: str = "") -> None:
    """记一条 stage 快照。**任何异常都不外抛**——埋点不允许影响扫描。"""
    try:
        if not _enabled():
            return
        os.makedirs(_OUT_DIR, exist_ok=True)
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "task_id": task_id,
            "stage": stage,
            "in": int(in_count or 0),
            "out": int(out_count or 0),
            "dropped": max(0, int(in_count or 0) - int(out_count or 0)),
            "reasons": {str(k): v for k, v in (reasons or {}).items() if v},
            "families": {str(k): v for k, v in (families or {}).items() if v},
        }
        if note:
            payload["note"] = note
        path = os.path.join(_OUT_DIR, f"{task_id if task_id is not None else 'unknown'}.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        return


def record_counts(task_id: Optional[int], stage: str, *,
                  before: int, after: int, note: str = "") -> None:
    """``record`` 的简写：只关心前后条数。"""
    record(task_id, stage, in_count=before, out_count=after, note=note)


def family_hist(items, family_of=None) -> Dict[str, int]:
    """把一批对象按族计数，供 ``families=`` 参数使用。

    ``family_of`` 默认读 ``.family`` / ``.type`` 属性或 dict 的 ``family``/``type`` 键。
    """
    out: Dict[str, int] = {}
    for it in items or []:
        try:
            if family_of is not None:
                fam = family_of(it)
            elif isinstance(it, dict):
                fam = it.get("family") or it.get("type") or ""
            else:
                fam = getattr(it, "family", "") or getattr(it, "type", "") or ""
            fam = str(fam).strip().lower() or "(unknown)"
            out[fam] = out.get(fam, 0) + 1
        except Exception:
            continue
    return out


def dump(task_id: Optional[int]) -> str:
    """把该 task 的漏斗快照拼成可读文本（排查用，非生产路径）。"""
    path = os.path.join(_OUT_DIR, f"{task_id if task_id is not None else 'unknown'}.jsonl")
    if not os.path.isfile(path):
        return f"(无漏斗记录：{path})"
    lines = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            try:
                d = json.loads(raw)
            except Exception:
                continue
            drop = f"  dropped={d['dropped']}" if d.get("dropped") else ""
            reasons = f"  reasons={d['reasons']}" if d.get("reasons") else ""
            lines.append(f"{d['ts']}  {d['stage']:28s} in={d['in']:<6d} out={d['out']:<6d}{drop}{reasons}")
    return "\n".join(lines) if lines else f"(空：{path})"
