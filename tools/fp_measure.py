#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""误报（FP）度量：用 OWASP Benchmark 的 `real=false` 用例做负样本。

## 为什么需要这个工具

2026-11-01 复盘发现：**误报从来没有被测量过**。
java-sec-code 的真值表只有正样本（29 个 in_scope），`_wb_jsc_compare.py` 也明写
「非真值文件上的发现不计入 FP」——于是 本轮里落在非真值文件上的 69 条
既可能是真缺陷（例如 `UserMapper.xml` 的 2 处 `${}` 注入，真值表根本没收录），
也可能是 FP，**无法判定**。

OWASP Benchmark 是现成的负样本库：2740 个用例里约一半 `real=false`，
每个用例对应一个 `BenchmarkTestNNNNN.java`。

## 指标定义

- **FP 率** = 命中负样本的用例数 / 负样本用例总数
  （按用例计，不按告警条数——同一用例报 3 条和报 1 条一样都是「误报了这个用例」）
- **TP 率** = 命中正样本的用例数 / 正样本用例总数
- **告警密度** = 告警总数 / 千用例（真实业务里换成 KLOC，这里用千用例近似）

## 用法

    python tools/fp_measure.py --task-id 452
    python tools/fp_measure.py --task-id 452 --expected D:/.../expectedresults-1.2.csv
    python tools/fp_measure.py --task-id 452 --verbose      # 打印命中负样本的用例明细
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "app.db")
DEFAULT_EXPECTED = os.path.join(
    os.path.dirname(ROOT), "owasp-code", "BenchmarkJava-master", "expectedresults-1.2.csv")

_CASE_RE = re.compile(r"(BenchmarkTest\d+)")


def load_expected(path: str):
    """返回 {case: (category, is_real)}。"""
    out = {}
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            case, cat, real = parts[0], parts[1], parts[2].lower()
            if not case:
                continue
            out[case] = (cat, real == "true")
    return out


def load_findings(db_path: str, task_id: int):
    """返回 [(case, family, file_path)]。"""
    rows = []
    con = sqlite3.connect(db_path)
    for fp, ft in con.execute(
            "SELECT file_path, finding_type FROM findings WHERE task_id=?", (task_id,)):
        m = _CASE_RE.search(str(fp or ""))
        if m:
            rows.append((m.group(1), str(ft or "").strip().lower(), str(fp)))
    con.close()
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--expected", default=DEFAULT_EXPECTED)
    ap.add_argument("--db", default=DB)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.expected):
        print(f"[fatal] 真值文件不存在：{args.expected}")
        return 2

    expected = load_expected(args.expected)
    pos = {c for c, (_cat, real) in expected.items() if real}
    neg = {c for c, (_cat, real) in expected.items() if not real}
    findings = load_findings(args.db, args.task_id)

    hit_cases = {c for c, _f, _p in findings}
    fp_cases = hit_cases & neg
    tp_cases = hit_cases & pos

    n_pos, n_neg = len(pos) or 1, len(neg) or 1
    print("=" * 72)
    print(f"误报度量 · task {args.task_id} · 真值 {os.path.basename(args.expected)}")
    print("=" * 72)
    print(f"  用例总数        {len(expected)}（正样本 {len(pos)} / 负样本 {len(neg)}）")
    print(f"  告警总数        {len(findings)} 条，覆盖 {len(hit_cases)} 个用例")
    print()
    print(f"  TP 用例         {len(tp_cases):4d}/{n_pos:<4d} = {len(tp_cases)/n_pos*100:5.1f}%")
    print(f"  **FP 用例**     {len(fp_cases):4d}/{n_neg:<4d} = {len(fp_cases)/n_neg*100:5.1f}%")
    print(f"  告警密度        {len(findings)/len(expected)*1000:.1f} 条 / 千用例")

    # 未覆盖用例里，有多少是「该报没报」的漏报（正样本没命中）
    fn_cases = pos - hit_cases
    print(f"  FN 用例（正样本未命中） {len(fn_cases):4d}/{n_pos:<4d} = {len(fn_cases)/n_pos*100:5.1f}%")

    if fp_cases:
        print()
        print("  负样本误报按族分布：")
        by_fam = Counter(f for c, f, _p in findings if c in fp_cases)
        for fam, n in by_fam.most_common(12):
            print(f"    {n:4d}  {fam}")
        if args.verbose:
            print()
            print("  误报用例明细（前 20）：")
            seen = set()
            for c, f, p in findings:
                if c in fp_cases and (c, f) not in seen:
                    seen.add((c, f))
                    print(f"    {c}  {f:26s}  {os.path.basename(p)}")
                    if len(seen) >= 20:
                        break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
