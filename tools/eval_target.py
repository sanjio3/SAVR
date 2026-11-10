#!/usr/bin/env python3
"""目标无关的评估 harness（M4）：换靶场后仍能算精度/召回/抑损。

为什么需要它
------------
现有对账（tools/owasp_run_shards.py --reconcile）把真值表写死成 OWASP 的
expectedresults-1.2.csv，且按 BenchmarkTest 用例名聚合。换到真实靶场后：
  - 没有真值表 ⇒ precision/recall 直接算不出；
  - 没有「一个 URL 一个 case」的结构 ⇒ 案件级口径失效。

本工具把「评估」从「OWASP 靶场」里解耦出来，提供三种模式（按可得性递进）：

  1) label 模式      —— 有人工标签（或等价真值）时，算 precision / recall / 抑损；
  2) proxy 模式      —— 无标签时，报「证据分布」（S4/S3/S2/S1）+ 抑制构成，用于趋势判断；
  3) compare 模式    —— 两轮任务逐组对比（新增检出/丢失检出），无标签也能做 A/B。

聚合键（--group-by）默认 endpoint；真实项目可用 finding / spec。
证据阶梯（与 src/core/sink_value_gate.py 同一真相源）：
  S4 payload_at_sink   → 可确认
  S3 sink_reached_absent（到达族 sink 但实参无 payload）→ 可否决
  S2 app_reached_only（有事件但没到族 sink）→ 不改判
  S1 no_delivery（零事件）→ 不改判

用法
----
  # 生成标签模板（人工填 label: tp/fp）
  python tools/eval_target.py --task <id> --emit-labels labels/weakrand-1.jsonl

  # 有标签：算指标
  python tools/eval_target.py --task <id> --labels labels/weakrand-1.jsonl

  # OWASP 真值表直连（本仓自测用，非必需）
  python tools/eval_target.py --task <id> --labels-from-owasp

  # 无标签：证据分布
  python tools/eval_target.py --task <id> --proxy

  # 两轮 A/B（无标签）
  python tools/eval_target.py --compare 397 398

退出码：0 正常；1 参数/数据错误；2 指标未达门槛（--min-precision/--min-recall 时）。
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

DEFAULT_DB = os.environ.get("SAST_AI_DB_PATH", os.path.join(REPO, "data", "app.db"))
# OWASP Benchmark 真值 CSV 不随本仓库分发；用环境变量指定路径。
OWASP_CSV = os.environ.get("SAST_AI_OWASP_CSV", "").strip()

_BENCH_CASE = re.compile(r"BenchmarkTest\d+")


# ---------------------------------------------------------------- 数据加载
def _connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    return con


def _load_specs(con, task_id: int):
    return [dict(r) for r in con.execute(
        "SELECT id, target_endpoint, expected_sink_file, taint_marker, family, "
        "capability_family, verification_status, iast_state, suppressed_by_safe_verdict, "
        "suppress_rule, finding_id "
        "FROM trigger_specs WHERE task_id=?", (task_id,)).fetchall()]


def _load_events(con, task_id: int):
    by_canary = defaultdict(list)
    for r in con.execute(
            "SELECT canary, sink_file, source_value FROM iast_events WHERE task_id=?",
            (task_id,)).fetchall():
        by_canary[str(r["canary"] or "")].append(dict(r))
    return by_canary


def _group_key(spec: dict, mode: str) -> str:
    if mode == "finding":
        return str(spec.get("finding_id") or "")
    if mode == "spec":
        return str(spec.get("id") or "")
    return str(spec.get("target_endpoint") or spec.get("expected_sink_file") or "")


# ---------------------------------------------------------------- 证据阶梯
def _evidence_of_group(items, events_by_canary):
    """返回 (bucket, detail)：S4 > S3 > S2 > S1（取组内最强证据）。

    M1（2026-10-20）：分桶逻辑迁到唯一真相源 ``src.core.evidence_policy``，
    与 benchmark_cli 值级闸共用同一套判据（r113 5270 spec 逐案等价，0 差异）。
    """
    try:
        from src.core.evidence_policy import best_kind, classify
        from src.core.sink_value_gate import identity_of
    except Exception as exc:  # 依赖缺失时退化为「无判定」，绝不编造
        return "S1", {"error": f"evidence_policy 不可用：{exc}"}

    evidences = []
    detail = []
    for sp in items:
        marker = str(sp.get("taint_marker") or "")
        ident = identity_of(marker) if marker else ""
        evs = events_by_canary.get(ident, [])
        fam = str(sp.get("family") or sp.get("capability_family") or "")
        ev = classify(sp, evs)
        evidences.append(ev)
        detail.append({"spec": sp.get("id"), "family": fam, "verdict": ev.verdict or "-",
                       "events": len(evs), "bucket": ev.kind})
    return best_kind(evidences), detail


def _collect(con, task_id: int, group_by: str):
    specs = _load_specs(con, task_id)
    events = _load_events(con, task_id)
    groups = defaultdict(list)
    for sp in specs:
        groups[_group_key(sp, group_by)].append(sp)
    out = {}
    for key, items in groups.items():
        detected = any(not int(sp.get("suppressed_by_safe_verdict") or 0) for sp in items)
        bucket, detail = _evidence_of_group(items, events)
        out[key] = {
            "detected": detected,
            "suppressed": not detected,
            "n_specs": len(items),
            "bucket": bucket,
            "families": sorted({str(sp.get("family") or "") for sp in items if sp.get("family")}),
            "suppress_rules": sorted({str(sp.get("suppress_rule") or "") for sp in items
                                      if int(sp.get("suppressed_by_safe_verdict") or 0)}),
            "detail": detail,
        }
    return out


# ---------------------------------------------------------------- 标签
def _load_labels(path: str) -> dict:
    labels = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            key = str(row.get("group") or row.get("endpoint") or row.get("case") or "")
            raw = str(row.get("label") or "").strip().lower()
            if not key or raw not in ("tp", "fp", "true", "false", "vuln", "safe"):
                continue
            labels[key] = raw in ("tp", "true", "vuln")
    return labels


def _labels_from_owasp(csv_path: str) -> dict:
    """OWASP 真值表 → {BenchmarkTestNNNNN: bool}。仅供本仓自测，不是必需路径。"""
    out = {}
    with open(csv_path, encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            m = _BENCH_CASE.search(row[0])
            if m and len(row) > 2:
                out[m.group(0)] = row[2].strip().lower() == "true"
    return out


def _label_of(key: str, labels: dict):
    """把 group key 映射到标签：优先精确匹配，其次从 endpoint 里抽 BenchmarkTestNNN。"""
    if key in labels:
        return labels[key]
    m = _BENCH_CASE.search(key)
    if m and m.group(0) in labels:
        return labels[m.group(0)]
    return None


def _labels_in_scope(result: dict, labels: dict) -> dict:
    """只保留「本任务实际扫到的分组」的标签。

    否则用全量真值表当标签时，分母会把整个靶场的 TP 都算进来（sqli-1 只有 93 个 TP，
    却拿全表 1415 当分母 ⇒ 召回被算成 6.6%）。这是口径 bug，不是扫描问题。
    """
    scoped = {}
    for key in result:
        v = _label_of(key, labels)
        if v is not None:
            scoped[key] = v
    return scoped


# ---------------------------------------------------------------- 报表
def _fmt_pct(x):
    return "n/a" if x is None else f"{x:.1%}"


def _report_labeled(result: dict, labels: dict, title: str) -> int:
    labels = _labels_in_scope(result, labels)
    tp_total = sum(1 for v in labels.values() if v)
    detected = [k for k, v in result.items() if v["detected"]]
    tp_hit = [k for k in detected if labels.get(k) is True]
    fp_hit = [k for k in detected if labels.get(k) is False]
    unknown = [k for k in detected if k not in labels]
    # 抑损：真值 TP 被抑制（= 召回损失）
    suppressed_tp = [k for k, v in result.items()
                     if not v["detected"] and labels.get(k) is True]
    miss = [k for k in labels if labels[k] and not result[k]["detected"]]
    prec = (len(tp_hit) / len(detected)) if detected else None
    rec = (len(tp_hit) / tp_total) if tp_total else None
    print(f"\n=== {title}（label 模式）===")
    print(f"分组数 {len(result)} | 真值 TP {tp_total} | 检出 {len(detected)} | 未标注 {len(unknown)}")
    print(f"精确率 {_fmt_pct(prec)}（TP {len(tp_hit)} / 检出 {len(detected)}）")
    print(f"召回   {_fmt_pct(rec)}（TP {len(tp_hit)} / 真值 {tp_total}）")
    print(f"漏检   {len(miss)} | 抑损（TP 被抑制）{len(suppressed_tp)}")
    if fp_hit:
        print(f"FP 检出 {len(fp_hit)}：" + ", ".join(sorted(fp_hit)[:8])
              + (" ..." if len(fp_hit) > 8 else ""))
    if miss:
        print(f"漏检明细：" + ", ".join(sorted(miss)[:8]) + (" ..." if len(miss) > 8 else ""))
    if suppressed_tp:
        print(f"⚠️ 抑损明细（必须为 0）：" + ", ".join(sorted(suppressed_tp)[:8]))
    return 0


def _report_proxy(result: dict, title: str) -> int:
    buckets = Counter(v["bucket"] for v in result.values())
    rules = Counter()
    for v in result.values():
        for r in v["suppress_rules"]:
            if r:
                parts = r.split(":")
                rules[":".join(parts[:3])] += 1
    detected = sum(1 for v in result.values() if v["detected"])
    print(f"\n=== {title}（proxy 模式：无标签，只看证据结构）===")
    print(f"分组数 {len(result)} | 检出 {detected} | 抑制 {len(result) - detected}")
    for b in ("S4", "S3", "S2", "S1"):
        n = buckets.get(b, 0)
        pct = f"{n / len(result):.1%}" if result else "n/a"
        print(f"  {b}: {n:>5} ({pct})")
    # 按族看：某族若全部落在 S1，说明该族没有 sink token（值级闸对它不适用），
    # 这不是「安全」，而是「没判定」——换靶场后最常见的失效形态，必须在报表里显式暴露。
    fam_buckets = defaultdict(Counter)
    for v in result.values():
        fam = (v["families"] or ["?"])[0]
        fam_buckets[fam][v["bucket"]] += 1
    no_token = [f for f, c in fam_buckets.items() if c.get("S1", 0) == sum(c.values()) and c]
    if no_token:
        print("  ⚠️ 以下族的证据全为 S1（无 sink token，值级闸对该族不适用，不等于安全）：")
        print("     " + ", ".join(sorted(no_token)))
    if rules:
        print("  抑制规则构成（按分组计）：")
        for r, n in rules.most_common(8):
            print(f"    {r:<48} {n}")
    print("  提示：S4 占比是「铁证率」；S3 是可安全否决的反证；S1/S2 不得用于否决。")
    return 0


def _report_compare(a: dict, b: dict, ta: int, tb: int) -> int:
    keys = set(a) | set(b)
    new = sorted(k for k in keys if b.get(k, {}).get("detected") and not a.get(k, {}).get("detected"))
    lost = sorted(k for k in keys if a.get(k, {}).get("detected") and not b.get(k, {}).get("detected"))
    print(f"\n=== 两轮对比 task {ta} → {tb} ===")
    print(f"新增检出 {len(new)} | 丢失检出 {len(lost)} | 共同检出 "
          f"{sum(1 for k in keys if a.get(k,{}).get('detected') and b.get(k,{}).get('detected'))}")
    if new:
        print("新增：" + ", ".join(new[:10]) + (" ..." if len(new) > 10 else ""))
        print("  证据桶：" + str(Counter(b[k]["bucket"] for k in new)))
    if lost:
        print("丢失：" + ", ".join(lost[:10]) + (" ..." if len(lost) > 10 else ""))
    return 0


def _emit_labels(result: dict, path: str) -> int:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# 标签模板：把 label 填成 tp / fp（其余字段仅供人工参考）\n")
        for key in sorted(result):
            v = result[key]
            fh.write(json.dumps({
                "group": key, "label": "", "detected": v["detected"],
                "bucket": v["bucket"], "n_specs": v["n_specs"], "families": v["families"],
            }, ensure_ascii=False) + "\n")
    print(f"[eval] 标签模板已写入 {path}（{len(result)} 组）")
    return 0


# ---------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="目标无关的评估 harness（M4）")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--task", type=int, help="单任务评估")
    ap.add_argument("--compare", nargs=2, type=int, metavar=("OLD", "NEW"), help="两轮对比")
    ap.add_argument("--group-by", default="endpoint", choices=("endpoint", "finding", "spec"))
    ap.add_argument("--labels", help="标签文件（JSONL：{group|endpoint, label: tp|fp}）")
    ap.add_argument("--labels-from-owasp", action="store_true",
                    help="用 OWASP 真值表当标签（本仓自测用）")
    ap.add_argument("--proxy", action="store_true", help="无标签：只报证据分布")
    ap.add_argument("--emit-labels", metavar="PATH", help="生成标签模板")
    ap.add_argument("--min-precision", type=float, help="低于则退出码 2")
    ap.add_argument("--min-recall", type=float, help="低于则退出码 2")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.db):
        print(f"[eval] 数据库不存在：{args.db}", file=sys.stderr)
        return 1
    con = _connect(args.db)

    if args.compare:
        old, new = args.compare
        a = _collect(con, old, args.group_by)
        b = _collect(con, new, args.group_by)
        return _report_compare(a, b, old, new)

    if not args.task:
        print("[eval] 需要 --task 或 --compare", file=sys.stderr)
        return 1
    result = _collect(con, args.task, args.group_by)
    if not result:
        print(f"[eval] task {args.task} 无 trigger_spec", file=sys.stderr)
        return 1

    if args.emit_labels:
        return _emit_labels(result, args.emit_labels)

    labels = None
    if args.labels:
        labels = _load_labels(args.labels)
    elif args.labels_from_owasp:
        if not OWASP_CSV or not os.path.isfile(OWASP_CSV):
            print("[eval] 未指定有效的 OWASP 真值表：请设置环境变量 SAST_AI_OWASP_CSV "
                  "指向 expectedresults-1.2.csv。", file=sys.stderr)
            return 1
        labels = _labels_from_owasp(OWASP_CSV)

    if labels:
        rc = _report_labeled(result, labels, f"task {args.task}")
        # 门槛检查（用与报表同一口径：只统计本任务扫到的分组）
        scoped = _labels_in_scope(result, labels)
        tp_total = sum(1 for v in scoped.values() if v)
        detected = [k for k, v in result.items() if v["detected"]]
        tp_hit = [k for k in detected if scoped.get(k) is True]
        prec = (len(tp_hit) / len(detected)) if detected else None
        rec = (len(tp_hit) / tp_total) if tp_total else None
        if args.min_precision is not None and (prec is None or prec < args.min_precision):
            print(f"[eval] 精确率未达门槛 {args.min_precision:.1%}")
            return 2
        if args.min_recall is not None and (rec is None or rec < args.min_recall):
            print(f"[eval] 召回未达门槛 {args.min_recall:.1%}")
            return 2
        return rc

    return _report_proxy(result, f"task {args.task}")


if __name__ == "__main__":
    raise SystemExit(main())
