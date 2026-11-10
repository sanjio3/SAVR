"""OWASP 分片抽样轮的分层对账（mini 等 <全集> 抽样专用）。

为什么需要：
- `reconcile_owasp.py` 的 load_truth 用 csv.DictReader 读「带表头 test/real」的
  sample-200 真值；`expectedresults-1.2.csv` 是无表头 + `#` 注释行，会被当成表头，
  只析出 1 行，进而 ZeroDivisionError。它也不带 shard 收窄，分母恒为全量。
- `fp_measure.py` 默认用全集 2740 例分母，对 130 例抽样轮会算出「TP 5.4%」这类
  明显误读数，不能作为抽样轮效果结论。
- `gate_quality_redline.py --truth owasp --shard mini` 才是抽样轮的权威红线口径，
  但它只给确认层一个数。本脚本复用它的真值/分片加载器，补出 L1/L2/L3 分层。

两处归因口径（本轮逐例复核后修正）：
- `trigger_specs.family` 是平台内部族标签，与官方真值 category 不是同一套命名，
  还存在整族错配（实测 15 个 weakrand 正样本的 spec 全部标成 xss）。未确认 TP 的
  族归因必须用真值 category，否则会把整族缺口误判成个别族的 oracle 判据问题。
- 一个用例平均有 2~5 条 spec，只取最后一条会把状态覆盖掉；状态归因按用例聚合
  全部 spec 取最强态，确认判定同样用 any 口径，与门禁脚本保持一致。

只读，不写扫描任务。用法：
    python tools/reconcile_owasp_mini.py --task-id 647 --shard mini --format json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from typing import Dict, Set

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import gate_quality_redline as gate  # noqa: E402

CASE_RE = re.compile(r"BenchmarkTest\d+")
DB = os.path.join(ROOT, "data", "app.db")


def load_truth_categories() -> Dict[str, str]:
    """读 OWASP 官方真值表的用例 -> category（sqli / weakrand / xss ...）。

    `expectedresults-1.2.csv` 无表头，三列起为 test, category, true|false[, cwe]。
    与 `gate.load_truth()` 读同一份文件，保证真值标签与分片宇宙同源。
    """
    cats: Dict[str, str] = {}
    if not os.path.isfile(gate._OWASP):
        return cats  # 外部真值表缺失时退化为 <unknown>，不阻断分层主口径
    with open(gate._OWASP, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) < 3 or not parts[0].startswith("BenchmarkTest"):
                continue
            m = CASE_RE.search(parts[0])
            if m:
                cats[m.group(0)] = parts[1].strip()
    return cats


def _layer(cases: Set[str], tp_all: Set[str], fp_all: Set[str]) -> Dict[str, float]:
    tp, fp = len(cases & tp_all), len(cases & fp_all)
    return {
        "cases": tp + fp, "tp": tp, "fp": fp,
        "recall_pct": round(tp / len(tp_all) * 100, 1) if tp_all else 0.0,
        "precision_pct": round(tp / max(1, tp + fp) * 100, 1),
    }


def measure(task_id: int, shard: str) -> Dict[str, object]:
    truth = gate.load_truth("owasp")
    universe = gate.load_shard_cases(shard)
    tp_all = {k for k, v in truth.items() if v and k in universe}
    fp_all = {k for k, v in truth.items() if not v and k in universe}

    con = sqlite3.connect("file:%s?mode=ro" % DB.replace("\\", "/"), uri=True,
                          timeout=20)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT target_endpoint, verification_status, iast_state, family "
            "FROM trigger_specs WHERE task_id=?", (task_id,)).fetchall()
    finally:
        con.close()

    detected: Set[str] = set()
    conf_strict: Set[str] = set()
    conf_all: Set[str] = set()
    probe_reached: Set[str] = set()
    any_reached: Set[str] = set()
    case_specs: Dict[str, list] = {}
    for r in rows:
        m = CASE_RE.search(r["target_endpoint"] or "")
        if not m:
            continue
        cs = m.group(0)
        if cs not in universe:
            continue
        detected.add(cs)
        # 一个用例平均 2~5 条 spec，取最后一条会覆盖状态；按用例聚合全部 spec。
        case_specs.setdefault(cs, []).append({
            "status": str(r["verification_status"] or ""),
            "family": str(r["family"] or ""),
        })
        if r["verification_status"] == "confirmed_exploitable":
            conf_strict.add(cs)
        if r["verification_status"] in gate.CONFIRMED_STATES:
            conf_all.add(cs)
        if r["iast_state"] == "sink-reached-probe":
            probe_reached.add(cs)
        if r["iast_state"] in ("sink-reached-probe", "sink-reached"):
            any_reached.add(cs)

    def strongest(case: str) -> str:
        states = [s["status"] for s in case_specs.get(case, []) if s["status"]]
        if not states:
            return "<no_spec>"
        for st in gate.CONFIRMED_STATES:
            if st in states:
                return st
        for st in ("sink_reached", "unconfirmed", "no_evidence"):
            if st in states:
                return st
        return states[0]

    missed = sorted(tp_all - conf_all)
    cats = load_truth_categories()
    spec_family = lambda c: (case_specs[c][0]["family"] if case_specs.get(c)
                             else "<no_spec>")  # noqa: E731
    redline = gate.fake_confirm_redline(conf_all, fp_all, 0.66)
    out: Dict[str, object] = {
        "task_id": task_id, "shard": shard,
        "truth_total": len(truth),
        "universe_cases": len(universe), "tp_basis": len(tp_all),
        "fp_basis": len(fp_all), "specs": len(rows),
        "layers": {
            "L1_detected": _layer(detected, tp_all, fp_all),
            "L2_confirmed_strict": _layer(conf_strict, tp_all, fp_all),
            "L2_confirmed_all_states": _layer(conf_all, tp_all, fp_all),
            "L3_probe_sink_reached": _layer(probe_reached, tp_all, fp_all),
            "L3_any_sink_reached": _layer(any_reached, tp_all, fp_all),
        },
        "redline": {"actual": redline["actual"], "limit": redline["limit"],
                    "pass": redline["pass"]},
        "missed_tp": {"count": len(missed), "cases": missed,
                      "by_truth_category": dict(Counter(cats.get(c, "<unknown>")
                                                        for c in missed).most_common()),
                      "by_family": dict(Counter(spec_family(c)
                                                for c in missed).most_common()),
                      "by_spec_family": dict(Counter(spec_family(c)
                                                     for c in missed).most_common()),
                      "by_status": dict(Counter(strongest(c)
                                                for c in missed).most_common()),
                      "multi_spec_cases": sum(1 for c in missed
                                              if len(case_specs.get(c, [])) > 1)},
    }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--shard", default="mini")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    d = measure(args.task_id, args.shard)
    if args.format == "json":
        text = json.dumps(d, ensure_ascii=False, indent=2)
    else:
        lines = ["OWASP 抽样分层对账 task=%s shard=%s 宇宙=%s（TP %s / FP %s）specs=%s"
                 % (d["task_id"], d["shard"], d["universe_cases"],
                    d["tp_basis"], d["fp_basis"], d["specs"])]
        for k, v in d["layers"].items():  # type: ignore[union-attr]
            lines.append("  %-28s cases=%3s tp=%3s fp=%3s recall=%5s%% precision=%5s%%"
                         % (k, v["cases"], v["tp"], v["fp"], v["recall_pct"],
                            v["precision_pct"]))
        r = d["redline"]
        lines.append("假确认红线 actual=%s limit=%s -> %s"
                     % (r["actual"], r["limit"], "PASS" if r["pass"] else "FAIL"))
        m = d["missed_tp"]
        lines.append("未确认 TP %s 个，按真值 category：%s"
                     % (m["count"], m["by_truth_category"]))
        lines.append("按 spec 内部族标签（可能与真值错配）：%s" % m["by_spec_family"])
        lines.append("按终态（用例级最强态）：%s" % m["by_status"])
        text = "\n".join(lines)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(d, ensure_ascii=False, indent=2))
    return 0 if d["redline"]["pass"] else 1  # type: ignore[index]


if __name__ == "__main__":
    sys.exit(main())
