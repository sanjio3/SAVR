#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""只读复算「候选真值追加」对历史轮次四档口径的影响面。

L1 的 ``log4j.java/xss`` 是真值表未覆盖的真实反射 XSS。若把它补进
in_scope，历史**所有**轮次的分母都会变。本脚本把这个代价算成数字，供口径决议；
它不修改主真值表、不写 DB、不启动扫描，输出不是正式读数。

用法::

    py -3 tools/truth_addendum_impact.py
    py -3 tools/truth_addendum_impact.py --tasks 631,632 --output docs/report.md

需要 PyYAML 与 ``config/known_unreachable.yaml``：读不到豁免清单时动态分母会多算
4 条，脚本直接拒绝输出错误数字（fail-closed，与四档脚本的 fail-open 不同，因为
这里是批量结论而不是单轮诊断）。
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tools import jsc_four_tier as ft  # noqa: E402

DEFAULT_ADDENDUM = os.path.join(ROOT, "config", "truth_addendum_l1_log4j_xss.csv")
DEFAULT_TASKS = "628,629,631,632"


def _key(row):
    return (str(row.get("base", "")).lower(), str(row.get("family", "")).lower())


def metrics(truth, findings, specs, unreachable):
    """与 jsc_four_tier.main() 同源的口径，只取影响面对账需要的几个数。"""
    rows = ft.compute(truth, findings, specs)
    elig = [r for r in rows if r.get("dyn_eligible") and _key(r) not in unreachable]
    fp = ft.compute_fp(truth, specs)
    return {
        "truth_rows": len(rows),
        "static_fam": sum(1 for r in rows if r["static_fam"]),
        "dyn_den": len(elig),
        "rep_fam": sum(1 for r in elig if r["rep_fam"]),
        "confirmed": fp["confirmed"],
        "fp_confirmed": len(fp["fp_confirmed"]),
        "replay": fp["replay"],
        "fp_replay": len(fp["fp_replay"]),
        "fp_replay_specs": sorted({"%s/%s" % (x["base"], x["family"])
                                   for x in fp["fp_replay"]}),
    }


def _fmt(m):
    return ("静态族 %d/%d · 动态分母 %d · 重放族 %d/%d · 红线 %d/%d · confirmed 误报 %d/%d"
            % (m["static_fam"], m["truth_rows"], m["dyn_den"],
               m["rep_fam"], m["dyn_den"], m["fp_replay"], m["replay"],
               m["fp_confirmed"], m["confirmed"]))


def _pct(num, den):
    return 100.0 * num / den if den else 0.0


def _task_name(db_path, task_id):
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        row = con.execute("SELECT name FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        con.close()
    return row[0] if row else "(unknown)"


def build_report(base_truth, added, findings_by_task, unreachable,
                 truth_label, addendum_label, only, db_path):
    lines = [
        "# 影子真值口径影响面复算（只读）",
        "",
        "主真值 `%s`（%s %d 行）未修改；候选追加 `%s` 共 %d 行："
        % (truth_label, only, len(base_truth), addendum_label, len(added)),
    ]
    for t in added:
        lines.append("- %s / %s（scope=%s，PROPOSED / NOT ADOPTED）"
                     % (t["base"], t["family"], only))
    lines += [
        "",
        "本报告是口径变更的决策依据，不是正式读数；`tools/jsc_four_tier.py` 不带 "
        "`--truth-addendum` 时的输出才是当前口径。",
        "",
    ]
    for tid, (findings, specs) in findings_by_task.items():
        a = metrics(base_truth, findings, specs, unreachable)
        b = metrics(base_truth + added, findings, specs, unreachable)
        delta = _pct(b["rep_fam"], b["dyn_den"]) - _pct(a["rep_fam"], a["dyn_den"])
        lines += [
            "## task %d · %s" % (tid, _task_name(db_path, tid)),
            "",
            "- 主口径：%s" % _fmt(a),
            "- 影子口径：%s" % _fmt(b),
            "- 变化：真值行 %+d、动态分母 %+d、重放族命中 %+d、重放率 %+.1fpp、"
            "红线 %d/%d → %d/%d、confirmed 误报 %d → %d"
            % (b["truth_rows"] - a["truth_rows"],
               b["dyn_den"] - a["dyn_den"],
               b["rep_fam"] - a["rep_fam"], delta,
               a["fp_replay"], a["replay"], b["fp_replay"], b["replay"],
               a["fp_confirmed"], b["fp_confirmed"]),
            "- 主口径红线明细：%s" % (", ".join(a["fp_replay_specs"]) or "无"),
            "- 影子口径红线明细：%s" % (", ".join(b["fp_replay_specs"]) or "无（红线归零）"),
            "",
        ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addendum", default=DEFAULT_ADDENDUM)
    ap.add_argument("--truth", default=ft.DEFAULT_TRUTH)
    ap.add_argument("--db", default=ft.DB)
    ap.add_argument("--tasks", default=DEFAULT_TASKS)
    ap.add_argument("--only", default="in_scope")
    ap.add_argument("--output", default="", help="可选，把同一份报告写成 md")
    args = ap.parse_args()

    for p in (args.truth, args.addendum, args.db):
        if not os.path.isfile(p):
            print("[fatal] 文件不存在：%s" % p)
            return 2
    unreachable = ft.load_known_unreachable()
    if not unreachable:
        print("[fatal] 物理不可达豁免清单为空（缺 PyYAML 或 "
              "config/known_unreachable.yaml 不存在）；继续会让动态分母多算 4 条，"
              "拒绝输出错误数字")
        return 3

    base_truth = ft.load_truth(args.truth, args.only)
    extra = ft.load_truth(args.addendum, args.only)
    seen = {(t["base"], t["family"]) for t in base_truth}
    added = [t for t in extra if (t["base"], t["family"]) not in seen]
    if not added:
        print("[fatal] 候选真值全部与主真值表重复，没有可复算的口径变更")
        return 2

    by_task = {}
    for tid in [int(x) for x in args.tasks.split(",") if x.strip()]:
        findings, specs = ft.load_task(args.db, tid)
        if not specs and not findings:
            print("[warn] task %d 无 findings / specs，跳过" % tid)
            continue
        by_task[tid] = (findings, specs)
    if not by_task:
        print("[fatal] 没有任何可复算的任务")
        return 2

    report = build_report(base_truth, added, by_task, unreachable,
                          os.path.basename(args.truth), os.path.basename(args.addendum),
                          args.only, args.db)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.rstrip() + "\n")
        print("\n[ok] 报告已写入 %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
