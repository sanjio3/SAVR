"""质量红线 CI 门禁：确认层假确认数 <= FP基数 × ratio 即 PASS（退出码 0 / 1）。

定位（2026-10-15，P-F 前半）。背景：tools/reconcile_owasp.py 已经把红线算出来并打印
PASS/FAIL，但 main() 永远返回 0 —— 也就是「只 print 不判」。CI 无法据此拦回归，只能靠人
眼看。本脚本把同一口径做成可执行门禁：

- 红线公式与 reconcile_owasp._fake_confirm_redline 完全一致（直接 import 复用，单一事实源）；
- 确认集按 _CONFIRMED_STATES = (confirmed_exploitable, confirmed_code_property) 计
  （dataflow 族 + 三失效族路由终态都算真正确认；只算 exploitable 会少算假确认 → 红线虚松）；
- actual <= limit → PASS / exit 0；否则 FAIL / exit 1；
- 支持两种真相集与分片收窄，附输出召回/精度便于定位。

真相集：
  sample200  : data/../benchmark-sample-200/sample-truth.csv（205 例：TP106/FP99）
  owasp      : BenchmarkJava-master/expectedresults-1.2.csv（全集）
  <path>     : 自定义（sample-truth.csv 或 expectedresults 格式）

用法：
    python tools/gate_quality_redline.py --task-id 359 --truth owasp --shard mini
    python tools/gate_quality_redline.py --task-id 28 --truth sample200 --format json
    SAST_AI_GATE_RATIO=0.5 python tools/gate_quality_redline.py --task-id 359 --truth owasp --shard mini
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
CASE_RE = re.compile(r"BenchmarkTest\d+")

# 与 reconcile_owasp 完全一致的确认态口径（2026-10-04 收口）。
# 2026-10-17 补 confirmed_sink_control：族误判 spec（family 错、capability_family 对）走错族
# 会拿到 confirmed_sink_control 终态（run 361 实测 00009/00022/00121 三个 safe case 被误确认
# 为该态）。只算前两态会漏计这类假确认 → 红线虚松。三态并计才是「全部确认态」口径。
CONFIRMED_STATES = ("confirmed_exploitable", "confirmed_code_property", "confirmed_sink_control")

# OWASP Benchmark 真值 CSV 不随本仓库分发（体量大且有独立许可）。
# 用 --truth <path> 指定，或设置下面两个环境变量。
_SAMPLE200 = os.environ.get("SAST_AI_OWASP_SAMPLE200_CSV", "").strip()
_OWASP = os.environ.get("SAST_AI_OWASP_TRUTH_CSV", "").strip()


def _load_reconcile_module():
    """按路径加载 tools/reconcile_owasp.py，复用其红线公式与 sample200 真相加载。"""
    path = os.path.join(HERE, "reconcile_owasp.py")
    spec = importlib.util.spec_from_file_location("_wb_reconcile_owasp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


recon_mod = _load_reconcile_module()
fake_confirm_redline = recon_mod._fake_confirm_redline


def load_owasp_truth(path: str) -> dict:
    """解析 expectedresults-1.2.csv（无表头：BenchmarkTestNNNNN, category, true|false）。"""
    truth = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 3 or not parts[0].startswith("BenchmarkTest"):
                continue
            m = CASE_RE.search(parts[0])
            if m:
                truth[m.group(0)] = parts[2].strip().lower() == "true"
    return truth


def load_truth(name_or_path: str) -> dict:
    p = name_or_path
    if name_or_path == "sample200":
        if not _SAMPLE200:
            raise RuntimeError("未配置 sample200 真值：设置环境变量 "
                               "SAST_AI_OWASP_SAMPLE200_CSV 或直接传 --truth <path>")
        return recon_mod.load_truth(_SAMPLE200)
    if name_or_path == "owasp":
        if not _OWASP:
            raise RuntimeError("未配置 OWASP 全集真值：设置环境变量 "
                               "SAST_AI_OWASP_TRUTH_CSV 或直接传 --truth <path>")
        return load_owasp_truth(_OWASP)
    if os.path.isfile(p):
        # 兼容两种格式：有表头（test/real）走 sample-truth 加载器，否则按 expectedresults 解析
        head = open(p, encoding="utf-8-sig", errors="replace").readline()
        if "test" in head and "real" in head:
            # E13：带表头的通用真值（Juliet 等第二真值源）优先走通用加载器
            try:
                generic = load_generic_truth(p)
                if generic:
                    return generic
            except Exception:  # noqa: BLE001
                pass
            return recon_mod.load_truth(p)
        return load_owasp_truth(p)
    raise SystemExit(f"[gate] 真相集不存在：{name_or_path}")


def load_generic_truth(path: str) -> dict:
    """解析**带表头**的通用真值 CSV（E13：第二真值源用）。

    支持表头列：test name / test / case、real vulnerability / real、category、cwe。
    case 名不限前缀（Juliet 的 `CWE_89_servlet_00001` 这类也能进），
    这正是「第二真值源」的关键 —— Benchmark 口径（BenchmarkTest 前缀）不通用。

    返回 {case_name: bool}。同时兼容「无表头 + 4 列」的老格式（test, category, real, cwe）。
    """
    truth: dict = {}
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return truth
    head = [h.strip().lower() for h in lines[0].split(",")]
    has_header = not head[0].startswith("BenchmarkTest") and not head[0].startswith("CWE_")
    if not has_header:
        # 无表头：test, category, real[, cwe]
        for ln in lines:
            parts = [p.strip() for p in ln.split(",")]
            if len(parts) < 3:
                continue
            truth[parts[0]] = parts[2].strip().lower() == "true"
        return truth
    ti = next((i for i, h in enumerate(head)
               if h in ("test name", "test", "case", "case name", "name")), 0)
    ri = next((i for i, h in enumerate(head)
               if h in ("real vulnerability", "real", "is_vulnerable", "vulnerable")), None)
    if ri is None:
        return truth
    for ln in lines[1:]:
        parts = [p.strip() for p in ln.split(",")]
        if len(parts) <= max(ti, ri):
            continue
        name = parts[ti]
        if not name:
            continue
        truth[name] = parts[ri].strip().lower() in ("true", "1", "yes", "y")
    return truth


def load_shard_cases(name: str) -> set:
    p = name if os.path.isfile(name) else os.path.join(ROOT, "data", "owasp_shards", "shards", f"{name}.json")
    if not os.path.isfile(p):
        raise SystemExit(f"[gate] 分片清单不存在：{p}")
    with open(p, encoding="utf-8") as fh:
        data = json.load(fh)
    return {str(c) for c in data["cases"]}


def evaluate(task_id: int, truth: dict, universe: set, ratio: float) -> dict:
    tp_all = {k for k, v in truth.items() if v and k in universe}
    fp_all = {k for k, v in truth.items() if not v and k in universe}
    con = sqlite3.connect(os.path.join(ROOT, "data", "app.db"), timeout=20)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT target_endpoint, verification_status FROM trigger_specs WHERE task_id=?",
        (task_id,)).fetchall()
    con.close()

    confirmed, detected, reached = set(), set(), set()
    for r in rows:
        cs = CASE_RE.search(r["target_endpoint"] or "")
        if not cs:
            continue
        cs = cs.group(0)
        detected.add(cs)
        if r["verification_status"] in CONFIRMED_STATES:
            confirmed.add(cs)

    tp = len(confirmed & tp_all)
    fp = len(confirmed & fp_all)
    rc = fake_confirm_redline(confirmed, fp_all, ratio)
    out = {
        "task_id": task_id,
        "cases_in_universe": len(tp_all) + len(fp_all),
        "specs": len(rows),
        "detected_cases": len(detected),
        "confirmed_cases": len(confirmed),
        "confirmed_tp": tp,
        "confirmed_fp": fp,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "recall": round(tp / len(tp_all), 4) if tp_all else 0.0,
        "redline": rc,
        "verdict": "PASS" if rc["pass"] else "FAIL",
    }
    return out


def derive_shard_from_task(task_id: int) -> str:
    """按任务名推导分片名：shard-<x>-rNN → data/owasp_shards/shards/x.json。

    为什么必须推导：红线分母是「FP 基数」，而 FP 基数必须与**扫描作用域**同口径。
    分片任务（如 shard-trustbound-r95 只扫 83 个用例）若直接用全集合 2740 例算 FP 基数，
    limit 会被放大到 874，等于没有红线——假确认 800 个也 PASS。
    """
    try:
        con = sqlite3.connect(os.path.join(ROOT, "data", "app.db"), timeout=20)
        row = con.execute("SELECT name FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
        con.close()
    except Exception:
        return ""
    if not row or not row[0]:
        return ""
    m = re.match(r"shard-([a-z0-9_]+)-r\d+$", str(row[0]).strip())
    if not m:
        return ""
    cand = m.group(1)
    p = os.path.join(ROOT, "data", "owasp_shards", "shards", f"{cand}.json")
    return cand if os.path.isfile(p) else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--truth", default="sample200",
                    help="sample200 | owasp | <path>（默认 sample200）")
    ap.add_argument("--shard", default="",
                    help="分片名（如 mini）或清单路径；缺省时按任务名 shard-<x>-rNN 自动推导，"
                         "推导不到则用全集（会平摊红线，仅建议全量任务如此）")
    ap.add_argument("--ratio", type=float,
                    default=float(os.environ.get("SAST_AI_GATE_RATIO",
                                                 os.environ.get("SAST_AI_FAKE_CONFIRM_RATIO", "0.66"))))
    ap.add_argument("--format", choices=("text", "json"), default="text")
    args = ap.parse_args()

    truth = load_truth(args.truth)
    universe = set(truth)
    shard_used = args.shard
    if not shard_used:
        shard_used = derive_shard_from_task(args.task_id)
        if shard_used:
            print(f"[gate] 未指定 --shard，按任务名自动推导分片作用域：{shard_used}")
    if shard_used:
        shard_cases = load_shard_cases(shard_used)
        outside = len(shard_cases - set(truth))
        if outside:
            print(f"[gate] 注意：分片 {shard_used} 有 {outside} 个用例不在真相集 {args.truth} 内，已忽略")
        universe = shard_cases & set(truth)

    res = evaluate(args.task_id, truth, universe, args.ratio)
    res["shard"] = shard_used or None
    res["truth"] = args.truth

    if args.format == "json":
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        rc = res["redline"]
        print(f"[gate] task={res['task_id']} 真相集={args.truth}"
              + (f" 分片={shard_used}" if shard_used else " 作用域=全集")
              + f" 用例宇宙={res['cases_in_universe']}")
        print(f"[gate] 确认 {res['confirmed_cases']} 用例（TP={res['confirmed_tp']} FP={res['confirmed_fp']}）"
              f" precision={res['precision']:.3f} recall={res['recall']:.3f}")
        print(f"[gate] 假确认红线：actual={rc['actual']} limit={rc['limit']}"
              f"（FP 基数 {rc['fp_basis']} × {rc['ratio']}）")
        print(f"[gate] 判定：{res['verdict']}")

    return 0 if res["redline"]["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
