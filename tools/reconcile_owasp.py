"""OWASP Benchmark 对账脚本（H 主口径，2026-09-28 定稿）。

主口径：
- 主指标 = 确认层召回：trigger_specs.verification_status=confirmed_exploitable 对 106 个 TP 用例。
- 质量红线 = 确认层假确认数：confirmed_exploitable 落在 FP 用例上的用例数，相对口径
  （不再死定 65）：红线 = FP 基数 × 比例（默认 0.66，可由 SAST_AI_FAKE_CONFIRM_RATIO
  或 --fake-confirm-ratio 覆盖）。当前 99 个 FP × 0.66 ≈ 65，与旧基线一致，但靶场变大时
  随 FP 基数自动放大，避免「靶场一大就永远踩红线」。程序化判据：actual <= limit 即 pass。
- L1 检出层召回/精度 = 过程观测，不考核。
- I 族路由后：三失效族（weak_hash/weak_crypto/securecookie）确认走 confirmed_code_property
  独立终态，单列统计，不计入 confirmed_exploitable（数据流族不动）。

用法：
    python tools/reconcile_owasp.py --task-id 28
    python tools/reconcile_owasp.py --task-id 26 27 28   # 多轮对比
真相集：OWASP Benchmark 真值 CSV 不随本仓库分发（体量大且有独立许可）。
用 --truth <path> 指定，或设置环境变量 SAST_AI_OWASP_TRUTH_CSV。
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEFAULT_TRUTH = os.environ.get("SAST_AI_OWASP_TRUTH_CSV", "").strip()
CASE_RE = re.compile(r"BenchmarkTest\d+")

# I 族路由的三失效族（与 src/core/family_verdict.route_for 对齐）
_ALGO_TOKENS = ("weak_hash", "weak_crypto", "hash", "crypto")
_ATTR_TOKENS = ("secure_cookie", "securecookie", "cookie_flags", "cookieflags")


def _route_bucket(family: str) -> str:
    f = str(family or "").lower().replace("-", "_")
    if any(t in f for t in _ALGO_TOKENS):
        return "algorithm"
    if any(t in f for t in _ATTR_TOKENS):
        return "attribute"
    return "dataflow"


def load_truth(path: str) -> dict:
    truth = {}
    with open(path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            name = (row.get("test") or "").strip()
            truth[name] = (row.get("real") or "").strip().lower() == "true"
    return truth


def case_of(endpoint: str) -> str:
    m = CASE_RE.search(endpoint or "")
    return m.group(0) if m else ""


def _fake_confirm_redline(confirmed: set, fp_all: set, ratio: float) -> dict:
    """相对口径质量红线（2026-09-29 落地，替换旧硬编码 65）。

    - 红线 = FP 基数 × ratio（默认 0.66）。当前 99 个 FP × 0.66 ≈ 65，与旧基线一致；
      靶场变大时随 FP 基数自动放大，避免「靶场一大就永远踩红线」。
    - actual = confirmed 落在 FP 用例上的用例数。
    - pass = actual <= limit（程序化判据，不再只 print 不判）。
    """
    fp_basis = len(fp_all)
    limit = int(round(fp_basis * float(ratio)))
    actual = len(confirmed & fp_all)
    return {
        "actual": actual,
        "limit": limit,
        "fp_basis": fp_basis,
        "ratio": float(ratio),
        "pass": actual <= limit,
    }


def recon(task_id: int, truth: dict, fake_confirm_ratio: float = 0.66) -> dict:
    tp_all = {k for k, v in truth.items() if v}
    fp_all = {k for k, v in truth.items() if not v}

    con = sqlite3.connect("data/app.db")
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT family, target_endpoint, verification_status, iast_state "
        "FROM trigger_specs WHERE task_id=?", (task_id,)).fetchall()

    det, conf, reached = set(), set(), set()
    code_property = defaultdict(set)   # family bucket -> cases（仅真正的 confirmed_code_property）
    routed_still_exploitable = defaultdict(set)  # 三族里仍挂在 confirmed_exploitable 的（族路由落地后应清零）
    dataflow_conf = set()
    for r in rows:
        cs = case_of(r["target_endpoint"])
        if not cs:
            continue
        det.add(cs)
        vs = r["verification_status"]
        bucket = _route_bucket(r["family"])
        if vs == "confirmed_exploitable":
            conf.add(cs)
            if bucket == "dataflow":
                dataflow_conf.add(cs)
            else:
                routed_still_exploitable[bucket].add(cs)
        if vs == "confirmed_code_property":
            code_property[bucket].add(cs)
        if r["iast_state"] == "sink-reached-probe":
            reached.add(cs)

    def layer(s):
        tp, fp = len(s & tp_all), len(s & fp_all)
        return {"recall": round(tp / len(tp_all) * 100, 1),
                "precision": round(tp / max(1, tp + fp) * 100, 1),
                "cases": tp + fp, "tp": tp, "fp": fp}

    # L2 确认层的**两种口径**并列（2026-10-04 收口）。
    # 起因：weak_random 族路由修好后，14 条 spec 从 confirmed_exploitable 迁到
    # confirmed_code_property（本属正确终态），而「只算 exploitable」的主口径把它们全排除，
    # 召回被动掉 8.5pp ⇒ 看起来像退化。而 gate 的 L2 判据**两个终态都算**，
    # 同一份数据给出 60→51 与 82→80 两个答案，验收没法判。
    # 现在两行都在：主口径维持原判据（不篡改历史），并显式给出与 gate 同口径的那一行。
    _conf_with_prop = set(conf)
    for _v in code_property.values():
        _conf_with_prop |= _v
    out = {
        "task_id": task_id,
        "specs": len(rows),
        "L1_检出层_过程观测": layer(det),
        "L2_确认层_主指标": layer(conf),
        "L2_确认层_含code_property": layer(_conf_with_prop),
        "L2_数据流族_确认层": layer(dataflow_conf),
        "L3_运行时到达": layer(reached),
        "族路由终态": {k: {"cases": len(v), "tp": len(v & tp_all), "fp": len(v & fp_all)}
                       for k, v in sorted(code_property.items())},
        "三失效族_待重判_仍confirmed": {k: {"cases": len(v), "tp": len(v & tp_all), "fp": len(v & fp_all)}
                                        for k, v in sorted(routed_still_exploitable.items())},
        # 质量红线（相对口径）：假确认数 vs FP 基数 × 比例。
        "假确认红线": _fake_confirm_redline(conf, fp_all, fake_confirm_ratio),
    }
    con.close()
    return out


# 确认态集合（与 route_for 落地后口径一致：数据流族 confirmed_exploitable + 三失效族
# confirmed_code_property，都算「真正确认」）。仅 no_evidence / unconfirmed / 其他算未确认。
_CONFIRMED_STATES = ("confirmed_exploitable", "confirmed_code_property")


def _status_rank(status: str) -> int:
    return 2 if status in _CONFIRMED_STATES else (1 if status == "unconfirmed" else 0)


def load_case_map(task_id: int) -> Dict[str, Dict[str, str]]:
    """按「用例身份」（endpoint 用例名，族无关）归并某 task 的确认态。

    一个用例在 OWASP 里可能登记了多个族 spec（如 rmi@/jwt/createToken 实为垂直越权），
    口径迁移（P2 后改判 broken_access_control）会让族名变、hash 变、按 hash 对不齐。
    这里按用例名对齐：取该用例「最高确认态」的那条 spec 的族与态，作为用例级结论，
    使跨任务对比不被族标签噪声干扰。
    """
    con = sqlite3.connect("data/app.db")
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT family, target_endpoint, verification_status FROM trigger_specs WHERE task_id=?",
        (task_id,)).fetchall()
    out: Dict[str, Dict[str, str]] = {}
    for r in rows:
        cs = case_of(r["target_endpoint"])
        if not cs:
            continue
        status = r["verification_status"] or ""
        fam = r["family"] or "unknown"
        prev = out.get(cs)
        if prev is None or _status_rank(status) > _status_rank(prev["status"]):
            out[cs] = {"family": fam, "status": status}
    con.close()
    return out


def _compare_mode(a: int, b: int, truth_path: str, fake_confirm_ratio: float) -> int:
    """黄金集对账（2026-09-30 落地，#381/迁移 vs 回归 判定）。

    按用例身份对齐 A、B 两轮 verification_status：
      - 两者都 confirmed：口径稳定，无变化。
      - 仅 A confirmed（B 未确认）：按 A 的族聚合——集中在 rmi→jndi_injection /
        broken_access_control 即「口径迁移」（纯度提升，非回归）；散在多族且 confirm 总集
        缩小才是真回归。
      - 仅 B confirmed：改善（新增确认）。
    """
    truth = load_truth(truth_path)
    tp_all = {k for k, v in truth.items() if v}
    fp_all = {k for k, v in truth.items() if not v}

    ma, mb = load_case_map(a), load_case_map(b)
    all_cases = set(ma) | set(mb)

    both_confirmed, only_a, only_b = [], [], []
    for cs in sorted(all_cases):
        sa = ma.get(cs, {}).get("status", "")
        sb = mb.get(cs, {}).get("status", "")
        ca = sa in _CONFIRMED_STATES
        cb = sb in _CONFIRMED_STATES
        if ca and cb:
            both_confirmed.append(cs)
        elif ca and not cb:
            only_a.append((cs, ma.get(cs, {}).get("family", "unknown")))
        elif cb and not ca:
            only_b.append((cs, mb.get(cs, {}).get("family", "unknown")))

    # 仅 A 按族聚合，区分迁移 vs 回归
    only_a_by_fam: Dict[str, List[str]] = defaultdict(list)
    for cs, fam in only_a:
        only_a_by_fam[fam].append(cs)
    only_b_by_fam: Dict[str, List[str]] = defaultdict(list)
    for cs, fam in only_b:
        only_b_by_fam[fam].append(cs)

    conf_a = sum(1 for cs in ma if ma[cs]["status"] in _CONFIRMED_STATES)
    conf_b = sum(1 for cs in mb if mb[cs]["status"] in _CONFIRMED_STATES)
    # 仅 A 落在 FP 用例上 = 假确认损失（迁移到 FP 族也是损失）
    only_a_fp = sum(1 for cs, _ in only_a if cs in fp_all)
    only_b_tp = sum(1 for cs, _ in only_b if cs in tp_all)

    print(f"黄金集对账：task{a} vs task{b}（真相集 TP={len(tp_all)} / FP={len(fp_all)}）")
    print(f"  两者都 confirmed：{len(both_confirmed)} 用例")
    print(f"  仅 A confirmed（B 退回）：{len(only_a)} 用例（其中落在 FP 用例={only_a_fp}）")
    print(f"  仅 B confirmed（B 新增）：{len(only_b)} 用例（其中落在 TP 用例={only_b_tp}）")
    print(f"  confirm 总集：A={conf_a} → B={conf_b}（{'↑B 扩大' if conf_b > conf_a else '↓B 缩小' if conf_b < conf_a else '持平'}）")

    print(f"\n仅 A 按族聚合（定位迁移来源）：")
    for fam in sorted(only_a_by_fam, key=lambda f: -len(only_a_by_fam[f])):
        _cases = only_a_by_fam[fam]
        _tp = sum(1 for c in _cases if c in tp_all)
        _fp = sum(1 for c in _cases if c in fp_all)
        print(f"  {fam:<24} {len(_cases):>4} 用例（TP={_tp} / FP={_fp}）：{', '.join(_cases[:12])}{' …' if len(_cases) > 12 else ''}")

    print(f"\n仅 B 按族聚合（改善来源）：")
    for fam in sorted(only_b_by_fam, key=lambda f: -len(only_b_by_fam[f])):
        _cases = only_b_by_fam[fam]
        print(f"  {fam:<24} {len(_cases):>4} 用例：{', '.join(_cases[:12])}{' …' if len(_cases) > 12 else ''}")

    # 判定：仅 A 集中在 rmi→jndi_injection / broken_access_control（迁移族）= 口径纯化；
    # 否则（散在多族 + confirm 总集缩小）= 真回归。
    _MIGRATION_FAMS = ("jndi_injection", "broken_access_control", "rmi")
    mig = sum(len(v) for k, v in only_a_by_fam.items() if any(t in k for t in _MIGRATION_FAMS))
    non_mig = len(only_a) - mig
    verdict = "迁移/口径纯化（非回归）" if (mig > 0 and non_mig == 0) else (
        "真回归" if (non_mig > 0 and conf_b < conf_a) else "混合/需人工看明细")
    print(f"\n判定：{verdict}")
    print(f"  （仅 A 中迁移族命中 {mig} 条、非迁移族 {non_mig} 条）")
    print(f"\n仅 A 明细：{json.dumps([{'case': c, 'family': f} for c, f in only_a], ensure_ascii=False)}")
    print(f"仅 B 明细：{json.dumps([{'case': c, 'family': f} for c, f in only_b], ensure_ascii=False)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", type=int, nargs="+", required=False)
    ap.add_argument("--compare", type=int, nargs=2, metavar=("A", "B"),
                    help="黄金集对账模式：按「用例身份」（expected_sink 用例，族无关）对齐 A、B 两轮"
                         "的 verification_status，输出三张清单（两者都 confirmed / 仅 A / 仅 B），"
                         "并把「仅 A」按族聚合以区分口径迁移（rmi→jndi_injection、broken_access_control）"
                         "与真回归（散在多族且 confirm 总集缩小）。与 --task-id 互斥。")
    ap.add_argument("--truth", default=DEFAULT_TRUTH)
    ap.add_argument("--fake-confirm-ratio", type=float,
                    default=float(os.environ.get("SAST_AI_FAKE_CONFIRM_RATIO", "0.66")),
                    help="质量红线比例：红线 = FP 基数 × 该比例（默认 0.66，可由 SAST_AI_FAKE_CONFIRM_RATIO 覆盖）")
    args = ap.parse_args()
    if not args.truth:
        ap.error("未指定真值 CSV：请用 --truth <path>，或设置环境变量 SAST_AI_OWASP_TRUTH_CSV。")
    if args.compare:
        return _compare_mode(args.compare[0], args.compare[1], args.truth, args.fake_confirm_ratio)
    if not args.task_id:
        ap.error("必须指定 --task-id 或 --compare")
    truth = load_truth(args.truth)
    tp_all = sum(1 for v in truth.values() if v)
    print(f"真相集：{len(truth)} 用例（TP={tp_all} / FP={len(truth) - tp_all}）")
    print(f"主指标=确认层召回；红线=确认层假确认（相对 FP 基数×{args.fake_confirm_ratio}）；L1 为过程观测\n")

    results = [recon(t, truth, fake_confirm_ratio=args.fake_confirm_ratio) for t in args.task_id]

    hdr = f"{'layer':<24}" + "".join(f"{'task'+str(t):>16}" for t in args.task_id)
    print(hdr)
    for key in ("L1_检出层_过程观测", "L2_确认层_主指标", "L2_确认层_含code_property",
                "L2_数据流族_确认层", "L3_运行时到达"):
        print(f"{key:<24}" + "".join(f"{r[key]['recall']:>7}%/{r[key]['precision']:.1f}%"
                                     for r in results))
    print(f"{'fake_confirm_redline(actual/limit)':<24}" + "".join(
        f"{r['假确认红线']['actual']:>8}/{r['假确认红线']['limit']:<6}" for r in results))
    # I 落地后的统一主口径：数据流族 confirmed_exploitable TP + 族路由终态 TP（合计对 106 TP）
    print("\n质量红线判定（actual <= limit 即 PASS）：")
    for r in results:
        rc = r["假确认红线"]
        verdict = "PASS" if rc["pass"] else "FAIL"
        print(f"  task{r['task_id']}: {verdict}（假确认 {rc['actual']} / 红线 {rc['limit']}，"
              f"FP 基数 {rc['fp_basis']} × {rc['ratio']}）")
    print(f"{'combined_confirm_recall':<24}" + "".join(
        f"{round((r['L2_数据流族_确认层']['tp'] + sum(v['tp'] for v in r['族路由终态'].values())) / tp_all * 100, 1):>15}%" for r in results))
    print("\nI 族路由终态（confirmed_code_property，独立口径）：")
    for r in results:
        parts = [f"{k}: cases={v['cases']} tp={v['tp']} fp={v['fp']}" for k, v in r["族路由终态"].items()]
        print(f"  task{r['task_id']}: " + ("；".join(parts) if parts else "无"))
    print("三失效族仍在 confirmed_exploitable（族路由重判后应清零）：")
    for r in results:
        parts = [f"{k}: cases={v['cases']} tp={v['tp']} fp={v['fp']}"
                 for k, v in r["三失效族_待重判_仍confirmed"].items()]
        print(f"  task{r['task_id']}: " + ("；".join(parts) if parts else "无（已全部路由）"))
    print("\n逐轮明细：")
    print(json.dumps([{k: v for k, v in r.items() if k != "假确认红线"} for r in results],
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
