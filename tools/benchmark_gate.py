#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""OWASP Benchmark 小样本对账门槛（常设）。

为什么需要它
------------
2026-09-24 的教训：只看单一口径会得出完全相反的结论。改 A1 规则前，宽松口径
（用例是否被报）显示 TPR 97.17%，看起来很好；实际是同一条 XSS 规则无差别命中，
真实能力（严格口径：被报且族名匹配）只有 28.30%。所以任何"检出率"结论都必须
双口径并列，且每次改规则后都要与基线对比，而不是只看绝对值。

用法
----
    # 对某次已完成的扫描做双口径对账，打印结果
    python tools/benchmark_gate.py --task-id 54

    # 与基线对比并判定（退出码 0=PASS 1=FAIL 2=错误），CI 可直接用退出码
    python tools/benchmark_gate.py --task-id 60

    # 把某次结果设为新基线（改动被确认为改善后使用）
    python tools/benchmark_gate.py --task-id 60 --update-baseline

    # 指定别的样本目录 / 真值表
    python tools/benchmark_gate.py --task-id 60 --truth <csv> --sample <dir>

门槛判据（2026-10-04 起改以 L2 为主）
------------------------------------
改动前本工具只量 **L1 检出层**（用例上有没有 finding），而 2026-09-28 确认的主口径是
**L2 确认层**（trigger_specs.verification_status=confirmed_exploitable），且明确「L1 只作
过程观测、不考核」。两把尺子量不同层 ⇒ 同一轮会一 PASS 一 FAIL（实测 run 46：主口径
68.9%/69.5% PASS，gate 判 FAIL）。此后合并成一把尺子：

- **主判据（会判 FAIL）**：L2 确认层的严格 Score 回落、严格 TPR 回落、假确认红线。
- **观测项（不判 FAIL）**：L1 检出层的宽松/严格四元组与文件扫描数。

1. 文件扫描数必须与基线一致（不一致说明样本被污染，对账不可信）—— 观测告警
2. **严格 Score(L2) 下降超过 STRICT_SCORE_DROP 即 FAIL**
3. **严格 TPR(L2) 下降超过 STRICT_TPR_DROP 即 FAIL（漏检回归）**
4. **假确认红线：confirmed 落在 FP 用例上的数量 > FP 基数 × FAKE_CONFIRM_RATIO 即 FAIL**
5. L1 宽松 FPR 作为观测打印（历史上它是发现「无差别命中」的灵敏指标，但按该口径不考核）
"""
import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(REPO, "data", "app.db")
# OWASP Benchmark sample 语料不随本仓库分发（体量大且有独立许可）。
# 用环境变量指向本地语料目录；未设置时 CLI 会给出明确提示而不是猜路径。
DEFAULT_SAMPLE = os.environ.get("SAST_AI_OWASP_SAMPLE_DIR", "").strip()
BASELINE_PATH = os.path.join(REPO, "tools", "benchmark_baseline.json")

TEST_RE = re.compile(r"BenchmarkTest(\d{5})\.java", re.I)

# 端点/文件两种载体里的用例号：TEST_RE 要求带 `.java`，而 target_endpoint 是路由串
# （如 /xpathi-00/BenchmarkTest01014），拿它去匹配会一条都匹配不上。
_ENDPOINT_CASE_RE = re.compile(r"BenchmarkTest(\d+)", re.I)

# 门槛阈值（比例，不是百分点）
STRICT_SCORE_DROP = 0.02   # 严格 Score 最多允许降 2 个百分点
STRICT_TPR_DROP = 0.03     # 严格 TPR 最多允许降 3 个百分点
LOOSE_FPR_RISE = 0.05      # 宽松 FPR 最多允许涨 5 个百分点（L1 观测项，2026-10-04 起不判 FAIL）

# 确认层假确认红线比例：红线 = FP 基数 × 该比例（与 tools/reconcile_owasp.py 同一口径）
FAKE_CONFIRM_RATIO = float(os.environ.get("SAST_AI_FAKE_CONFIRM_RATIO", "0.66"))

# Benchmark category -> 可接受的 SAVR 族名关键词（小写子串匹配）
FAMILY_MAP = {
    "sqli": ["sql 注入", "sql_injection", "sqli", "jdbc", "sql injection"],
    "xss": ["xss", "跨站"],
    "cmdi": ["command_execution", "命令执行", "命令注入", "cmdi", "processbuilder",
             "command execution"],
    "pathtraver": ["路径穿越", "路径遍历", "pathtraver", "file read", "文件路径", "文件读写",
                   "path traversal", "fileoutputstream", "fileinputstream", "filereader",
                   "filewriter", "randomaccessfile"],
    "ldapi": ["ldap"],
    "xpathi": ["xpath"],
    # 2026-09-24 新增的五个族（此前是能力空白，占样本 41.5%，严格口径 TPR 恒为 0）
    "crypto": ["不安全加密", "insecure-crypto", "cipher", "des"],
    "hash": ["弱哈希", "weak-hash", "md5", "sha1"],
    "weakrand": ["弱随机", "weak-random", "random"],
    "securecookie": ["cookie", "insecure-cookie"],
    "trustbound": ["信任边界", "trust-boundary", "trust"],
}


def load_truth(path):
    out = {}
    with open(path, "r", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            out[r["test"]] = {
                "category": r["category"],
                "real": str(r["real"]).strip().lower() == "true",
            }
    return out


def load_findings(task_id):
    """{用例名: [族名候选串]}，只取落在 BenchmarkTest*.java 上的 finding。"""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    per = defaultdict(list)
    for r in conn.execute(
            "SELECT file_path, line, severity, raw_json FROM findings WHERE task_id=?",
            (task_id,)):
        m = TEST_RE.search((r["file_path"] or "").replace("/", "\\"))
        if not m:
            continue
        try:
            raw = json.loads(r["raw_json"] or "{}")
        except Exception:
            raw = {}
        blob = " ".join(str(x) for x in (
            raw.get("type"), raw.get("finding_family"), raw.get("display_family"),
            raw.get("rule_name"), raw.get("sink"),
        ) if x).lower()
        per["BenchmarkTest" + m.group(1)].append({
            "line": r["line"], "severity": r["severity"], "blob": blob,
            "type": str(raw.get("type") or ""),
        })
    conn.close()
    return per


def load_confirmed(task_id):
    """L2 确认层：返回 (per, exploitable_cases)。

    per：{用例名: [族名候选串]}，结构与 load_findings 对齐，好让下面的 run() 原样复用
    同一套宽松/严格判定逻辑，避免两处口径漂移。

    predicted 判据必须同时接纳两个终态：**confirmed_exploitable** 与
    **confirmed_code_property**。后者是 I 族路由给算法/属性族（crypto/hash/securecookie）
    批准的正确终态；若只算 exploitable，这 29 个 TP 会永久计成 FN，L2 TPR 天花板被压到
    72.6%，门槛判据失去区分力（实测 run 46 的 crypto L2 TPR 只有 11.1%，而其 L1 是 100%）。

    exploitable_cases 单独返回，只用于假确认红线 —— reconcile_owasp 的红线口径就是
    confirmed_exploitable，不含 code_property。

    用例身份取自 target_endpoint（同 tools/reconcile_owasp.py:case_of），族信息取自
    trigger_specs.family —— 它是经族路由后的权威族列，比 findings.raw_json 更可靠。
    """
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    per = defaultdict(list)
    exploitable = set()
    try:
        rows = conn.execute(
            "SELECT family, target_endpoint, verification_status, raw_json "
            "FROM trigger_specs WHERE task_id=?", (task_id,)).fetchall()
    except sqlite3.Error:
        conn.close()
        return {}, set()
    for r in rows:
        vs = str(r["verification_status"] or "")
        if vs not in ("confirmed_exploitable", "confirmed_code_property"):
            continue
        m = _ENDPOINT_CASE_RE.search(str(r["target_endpoint"] or "").replace("/", "\\"))
        if not m:
            continue
        case = "BenchmarkTest" + m.group(1)
        if vs == "confirmed_exploitable":
            exploitable.add(case)
        try:
            raw = json.loads(r["raw_json"] or "{}")
        except Exception:
            raw = {}
        blob = " ".join(str(x) for x in (
            r["family"], raw.get("type"), raw.get("finding_family"),
            raw.get("display_family"), raw.get("rule_name"), raw.get("sink"),
        ) if x).lower()
        per[case].append({"blob": blob})
    conn.close()
    return per, exploitable


def fake_confirm_redline(confirmed_cases, truth, ratio=FAKE_CONFIRM_RATIO):
    """确认层假确认红线：confirmed 落在 FP 用例上的数量 <= FP 基数 × ratio 即 pass。

    与 tools/reconcile_owasp.py:_fake_confirm_redline 同为相对口径（随 FP 基数放大），
    不再硬编码 65。
    """
    # truth 的 value 是 {category, real} 字典，必须取 real 字段；写成 `not v` 会因字典
    # 恒为真而把 fp_all 算成空集，红线基数显示为 0（假 PASS）。
    fp_all = {c for c, info in truth.items() if not (info or {}).get("real")}
    limit = int(round(len(fp_all) * float(ratio)))
    actual = len(set(confirmed_cases) & fp_all)
    return {
        "actual": actual,
        "limit": limit,
        "fp_basis": len(fp_all),
        "ratio": float(ratio),
        "pass": actual <= limit,
    }


def file_count_of(task_id):
    """取该任务的 Phase 1 文件扫描数。找不到返回 None。

    2026-09-24 修复：原实现遍历 data/workspaces/* 取第一个 task-<id>/scan_progress.json。
    DB 重置后任务 id 从 1 重新编号，而磁盘上残留旧 DB 时代的 task-N 目录（跨靶场同名），
    会读到别的靶场的进度文件（实测 task-2 读到旧 jsc 的 95，真值 232）。
    现按任务所属 workspace 从 workspaces 表解析目录名（name 与 slug 都试），只在该目录找。
    """
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    r = conn.execute(
        "SELECT t.workspace_id, w.name, w.slug FROM scan_tasks t "
        "LEFT JOIN workspaces w ON w.id = t.workspace_id WHERE t.id=?",
        (task_id,),
    ).fetchone()
    conn.close()
    if not r:
        return None
    ws_root = os.path.join(REPO, "data", "workspaces")
    if not os.path.isdir(ws_root):
        return None
    # 目录历史上有两种命名：workspace name（owasp-benchmark-sample）与 slug（xxx-5），都试
    candidates = [d for d in (r["name"], r["slug"]) if d]
    for d in candidates:
        p = os.path.join(ws_root, d, f"task-{task_id}", "scan_progress.json")
        if os.path.isfile(p):
            try:
                j = json.load(open(p, encoding="utf-8"))
                return ((j.get("stage_results") or {}).get("preprocess") or {}).get("file_count")
            except Exception:
                return None
    return None


def metrics(tp, fp, tn, fn):
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": round(tpr, 4), "fpr": round(fpr, 4),
            "precision": round(prec, 4), "f1": round(f1, 4),
            "score": round(tpr - fpr, 4)}


def run(truth, per_case, strict):
    tp = fp = tn = fn = 0
    per_cat = defaultdict(lambda: [0, 0, 0, 0])
    for case, info in truth.items():
        hits = per_case.get(case, [])
        if strict:
            keys = [k.lower() for k in FAMILY_MAP.get(info["category"], [])]
            predicted = any(any(k in h["blob"] for k in keys) for h in hits) if keys else False
        else:
            predicted = len(hits) > 0
        slot = per_cat[info["category"]]
        if info["real"] and predicted:
            tp += 1; slot[0] += 1
        elif info["real"]:
            fn += 1; slot[3] += 1
        elif predicted:
            fp += 1; slot[1] += 1
        else:
            tn += 1; slot[2] += 1
    return metrics(tp, fp, tn, fn), {c: v for c, v in per_cat.items()}


def evaluate(task_id, truth_path, sample_dir=None):
    truth = load_truth(truth_path)
    per = load_findings(task_id)
    loose, lc = run(truth, per, strict=False)
    strict_m, sc = run(truth, per, strict=True)
    # L2 确认层（主口径）：同一套 run()，只是把 finding 换成确认层终态。
    conf, conf_expl = load_confirmed(task_id)
    l2_loose, l2c = run(truth, conf, strict=False)
    l2_strict, l2s = run(truth, conf, strict=True)
    redline = fake_confirm_redline(conf_expl, truth)
    return {
        "task_id": task_id,
        "sample_size": len(truth),
        "file_count": file_count_of(task_id),
        "finding_count": sum(len(v) for v in per.values()),
        "confirmed_count": sum(len(v) for v in conf.values()),
        "loose": loose,
        "strict": strict_m,
        "l2_loose": l2_loose,
        "l2_strict": l2_strict,
        "redline": redline,
        "per_category_strict": {c: dict(zip(("tp", "fp", "tn", "fn"), v)) for c, v in sc.items()},
        "per_category_loose": {c: dict(zip(("tp", "fp", "tn", "fn"), v)) for c, v in lc.items()},
        "per_category_l2_strict": {c: dict(zip(("tp", "fp", "tn", "fn"), v)) for c, v in l2s.items()},
        "per_category_l2_loose": {c: dict(zip(("tp", "fp", "tn", "fn"), v)) for c, v in l2c.items()},
    }


def print_report(res):
    print(f"\n===== OWASP Benchmark 对账 (task {res['task_id']}) =====")
    print(f"样本 {res['sample_size']} 用例   文件扫描数 {res['file_count']}   "
          f"用例上 finding {res['finding_count']}   确认层 confirmed {res['confirmed_count']}")

    print("\n--- L1 检出层（过程观测，不考核）---")
    for tag, key in (("宽松/二元", "loose"), ("严格/族名", "strict")):
        m = res[key]
        print(f"[{tag}]  TP {m['tp']:>3}  FP {m['fp']:>3}  TN {m['tn']:>3}  FN {m['fn']:>3}")
        print(f"  TPR {m['tpr']*100:6.2f}%   FPR {m['fpr']*100:6.2f}%   "
              f"Precision {m['precision']*100:6.2f}%   Score {m['score']*100:6.2f}%")

    print("\n--- L2 确认层（主口径，门槛判据）---")
    for tag, key in (("宽松/二元", "l2_loose"), ("严格/族名", "l2_strict")):
        m = res[key]
        print(f"[{tag}]  TP {m['tp']:>3}  FP {m['fp']:>3}  TN {m['tn']:>3}  FN {m['fn']:>3}")
        print(f"  TPR {m['tpr']*100:6.2f}%   FPR {m['fpr']*100:6.2f}%   "
              f"Precision {m['precision']*100:6.2f}%   Score {m['score']*100:6.2f}%")

    rl = res.get("redline") or {}
    verdict = "PASS" if rl.get("pass") else "FAIL"
    print(f"\n假确认红线  {rl.get('actual', '-')} / {rl.get('limit', '-')}"
          f"（FP 基数 {rl.get('fp_basis', '-')} × {rl.get('ratio', '-')}）-> {verdict}")

    print("\n--- 分类别（严格口径 TP/FP/TN/FN  TPR/FPR：L2 → L1）---")
    for c in sorted(res["per_category_strict"]):
        v = res["per_category_strict"][c]
        v2 = (res.get("per_category_l2_strict") or {}).get(c, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        tp, fp, tn, fn = v["tp"], v["fp"], v["tn"], v["fn"]
        t = tp / (tp + fn) if (tp + fn) else 0.0
        f = fp / (fp + tn) if (fp + tn) else 0.0
        t2 = v2["tp"] / (v2["tp"] + v2["fn"]) if (v2["tp"] + v2["fn"]) else 0.0
        f2 = v2["fp"] / (v2["fp"] + v2["tn"]) if (v2["fp"] + v2["tn"]) else 0.0
        flag = "   (无对应规则)" if not FAMILY_MAP.get(c) else ""
        print(f"  {c:<14} L2 {v2['tp']:>3}/{v2['fp']:>3}/{v2['tn']:>3}/{v2['fn']:>3} "
              f"{t2*100:6.1f}% {f2*100:6.1f}%   | L1 {tp:>3}/{fp:>3}/{tn:>3}/{fn:>3} "
              f"{t*100:6.1f}% {f*100:6.1f}%{flag}")


def compare(res, base):
    """返回 (ok, [判定行])。

    2026-10-04 起：主判据改为 **L2 确认层**（严格 Score / 严格 TPR / 假确认红线），
    L1 检出层降级为观测打印。旧基线（task-4 那份）没有 l2_* 字段时，L2 对比会明确跳过
    而不是静默当成 0 —— 那是比误判更危险的假信号。
    """
    lines = []
    ok = True

    fc, bfc = res.get("file_count"), base.get("file_count")
    if fc is not None and bfc is not None and fc != bfc:
        lines.append(f"FAIL  文件扫描数 {fc} != 基线 {bfc}（样本被污染，对账不可信）")
        return False, lines
    lines.append(f"OK    文件扫描数 {fc} == 基线 {bfc}")

    # ── 主判据 1/2：L2 确认层不得回退 ──
    # 没有 L2 数据时（如单测构造的精简 res）不能 KeyError，也不能当成 0 去比 ——
    # 那会把「没数据」误算成「跌到 0」而判 FAIL。
    if base.get("l2_strict") and res.get("l2_strict"):
        checks = [
            ("严格 Score(L2)", res["l2_strict"]["score"], base["l2_strict"]["score"],
             STRICT_SCORE_DROP, "drop"),
            ("严格 TPR(L2)", res["l2_strict"]["tpr"], base["l2_strict"]["tpr"],
             STRICT_TPR_DROP, "drop"),
        ]
        for name, cur, bas, tol, kind in checks:
            delta = cur - bas
            bad = delta < -tol if kind == "drop" else delta > tol
            if bad:
                ok = False
            mark = "FAIL" if bad else "OK  "
            lines.append(f"{mark}  {name:<16} {bas*100:6.2f}% -> {cur*100:6.2f}%  "
                         f"({delta*100:+.2f}pp, 容差 {tol*100:.0f}pp)")
    else:
        lines.append("SKIP  基线无 L2 确认层数据（旧基线），跳过 L2 回退判定；"
                     "确认本轮可信后请 --update-baseline 重建基线")

    # ── 主判据 3：假确认红线 ──
    rl = res.get("redline") or {}
    if rl:
        bad = not rl.get("pass")
        if bad:
            ok = False
        lines.append(f"{'FAIL' if bad else 'OK  '}  假确认红线(L2)    "
                     f"{rl.get('actual', '-')} / {rl.get('limit', '-')}"
                     f"（FP 基数 {rl.get('fp_basis', '-')} × {rl.get('ratio', '-')}）")

    # ── 观测项：L1 检出层（不判 FAIL，但历史上它是「无差别命中」最灵敏的哨兵）──
    if base.get("loose"):
        d = res["loose"]["fpr"] - base["loose"]["fpr"]
        lines.append(f"obs   宽松 FPR(L1)      {base['loose']['fpr']*100:6.2f}% -> "
                     f"{res['loose']['fpr']*100:6.2f}%  ({d*100:+.2f}pp，观测不考核)")
        ds = res["strict"]["score"] - base["strict"]["score"]
        lines.append(f"obs   严格 Score(L1)    {base['strict']['score']*100:6.2f}% -> "
                     f"{res['strict']['score']*100:6.2f}%  ({ds*100:+.2f}pp，观测不考核)")

    _cur_l2 = (res.get("l2_strict") or {}).get("score")
    _base_l2 = (base.get("l2_strict") or {}).get("score")
    if ok and _cur_l2 is not None and _base_l2 is not None and _cur_l2 > _base_l2:
        lines.append("      L2 严格 Score 提升（可考虑 --update-baseline）")
    return ok, lines


def main():
    ap = argparse.ArgumentParser(description="OWASP Benchmark 小样本对账门槛")
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--truth", default=os.path.join(DEFAULT_SAMPLE, "sample-truth.csv")
                    if DEFAULT_SAMPLE else "")
    ap.add_argument("--sample", default=DEFAULT_SAMPLE)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    args = ap.parse_args()

    if not args.truth:
        print("未指定真值 CSV：请用 --truth <path>，或设置环境变量 "
              "SAST_AI_OWASP_SAMPLE_DIR 指向 OWASP Benchmark sample 目录。",
              file=sys.stderr)
        return 2
    if not os.path.isfile(DB):
        print(f"DB not found: {DB}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.truth):
        print(f"truth csv not found: {args.truth}", file=sys.stderr)
        return 2

    res = evaluate(args.task_id, args.truth, args.sample)

    if args.update_baseline:
        with open(BASELINE_PATH, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print(f"[baseline] 已写入 {BASELINE_PATH}  (task {args.task_id})")
        return 0

    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print_report(res)

    if not os.path.isfile(BASELINE_PATH):
        print(f"\n[!] 无基线文件 {BASELINE_PATH}，跳过判定。"
              f"确认本次结果可信后运行 --update-baseline 建立基线。")
        return 0

    base = json.load(open(BASELINE_PATH, encoding="utf-8"))
    ok, lines = compare(res, base)
    print(f"\n===== 门槛判定（基线 task {base.get('task_id')}）=====")
    for ln in lines:
        print("  " + ln)
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
