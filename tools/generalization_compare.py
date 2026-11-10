"""泛化验证统一对比脚本：三层实验共用一个口径，只读 DB，不发请求、不占 GPU。

三层：
  blind        第一层 · 同靶场路由盲化（628 vs blind 变体），量 URL 布局先验依赖
  cross-target 第二层 · 换靶场（RuoYi 451 / Juliet 子集），可无基线只报绝对值
  stability    第三层 · 同配置连跑两轮，量 late-evidence 抖动方差

为什么不用 tools/_wb_compare_tasks.py：那个脚本写死 jsc 真值表、只比两个 task，
且没有「严格重放」（确有 attempts）与红线误报的跨轮 diff。本脚本把口径统一到
tools/jsc_four_tier.py，并额外输出逐真值点退步归因。

用法：
    python tools/generalization_compare.py --baseline 628 --variant 629 --mode blind
    python tools/generalization_compare.py --baseline 0 --variant 630 --mode cross-target \
        --truth data/ruoyi_451_truth.csv
    python tools/generalization_compare.py --baseline 631 --variant 632 --mode stability
    python tools/generalization_compare.py --self-check          # 628 自比，验证脚本本身
    python tools/generalization_compare.py ... --json out.json   # 机器可读结果
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
os.chdir(ROOT)

import jsc_four_tier as J  # noqa: E402

DEFAULT_TRUTH = os.path.join(ROOT, "data", "java_sec_code_truth_v2.csv")
DEFAULT_CONFIG = os.path.join(ROOT, "config", "generalization.yaml")

# 2026-11-07：Gate 0 批准的预登记例外按「层 + 文件 basename + 族」登记，
# 比较工具必须按当前 mode 映射到对应层，绝不能跨层外溢。
_MODE_TO_LAYER = {
    "blind": "L1_blind_route",
    "stability": "L3_stability",
    "cross-target": "L2_cross_target",
}


def load_pre_registered_exceptions(config_path: str = "") -> list:
    """读 config/generalization.yaml 的 execution.pre_registered_exceptions。

    配置缺失 / 解析失败时返回空列表（fail-closed：口径退化为「不放行任何例外」，
    宁可判未通过，也不能让例外悄悄吞掉新红线）。
    """
    path = config_path or DEFAULT_CONFIG
    if not os.path.isfile(path):
        return []
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        items = ((cfg.get("execution") or {}).get("pre_registered_exceptions") or [])
        return [x for x in items if isinstance(x, dict)]
    except Exception as exc:  # noqa: BLE001
        print("[warn] 预登记例外配置读取失败（按不放行处理）：%s" % exc)
        return []


def apply_pre_registered_exceptions(var: dict, mode: str, exceptions: list) -> dict:
    """按层/文件/族三元组放行已批准例外，返回扣除后的有效红线。

    计数按**红线 spec 条数**（fp_replay_items），不是去重后的 (base, family) 键：
    同一文件同一族出现 2 条红线时，max_count_per_round=1 只能放行 1 条，
    第 2 条必须留下并判未通过。
    """
    layer = _MODE_TO_LAYER.get(mode, "")
    items = [tuple(k) for k in var.get("fp_replay_items", [])]
    remaining = list(items)
    matched, violations = [], []
    for ex in exceptions:
        m = ex.get("match") if isinstance(ex.get("match"), dict) else {}
        if layer not in (m.get("applies_to") or []):
            continue
        fb = str(m.get("file_basename") or "").strip().lower()
        fam = str(m.get("family") or "").strip().lower()
        if not fb or not fam:
            violations.append("例外 %s 缺 file_basename/family，不予放行" % ex.get("id", "?"))
            continue
        try:
            cap = int(ex.get("max_count_per_round") or 0)
        except (TypeError, ValueError):
            cap = 0
        hits = [k for k in remaining
                if str(k[0]).strip().lower() == fb and str(k[1]).strip().lower() == fam]
        if len(hits) > cap:
            violations.append(
                "例外 %s 命中 %d 条 > max_count_per_round=%d，超出部分按新红线处理"
                % (ex.get("id", "?"), len(hits), cap))
        for k in hits[:max(0, cap)]:
            remaining.remove(k)
            matched.append({"id": ex.get("id", "?"), "key": k})
    return {
        "layer": layer,
        "matched": matched,
        "violations": violations,
        "fp_replay_effective": len(remaining),
        "effective_keys": sorted({(str(k[0]), str(k[1])) for k in remaining}),
    }


def strict_replay_set(con, task_id: int) -> set:
    """严格重放：confirmed_exploitable + 非 framework + 该 spec 确实发过请求。

    628 实测有 3 条零重放 spec 被算进四档重放确认（sqli.java 靠其中一条撑起一个
    真值点）。泛化验证必须同时看四档与严格两档，否则换靶场后口径失真看不出来。
    """
    rows = con.execute(
        """SELECT s.expected_sink_file, s.family, count(a.id) AS na
           FROM trigger_specs s
           LEFT JOIN replay_attempts a ON a.spec_id = s.id AND a.task_id = s.task_id
           WHERE s.task_id = ? AND s.verification_status = 'confirmed_exploitable'
             AND (s.positive_evidence_rule IS NULL
                  OR s.positive_evidence_rule NOT LIKE 'framework:%')
           GROUP BY s.id HAVING na > 0""", (task_id,))
    return {(J._base(r[0]), J._fam(r[1])) for r in rows}


def measure(task_id: int, truth_path: str, db_path: str, exempt: set) -> dict:
    truth = J.load_truth(truth_path)
    findings, specs = J.load_task(db_path, task_id)
    rows = J.compute(truth, findings, specs)
    fp = J.compute_fp(truth, specs)
    con = sqlite3.connect(db_path)
    strict = strict_replay_set(con, task_id)
    # 逐点归因：该真值点上未确认 spec 的状态，用于解释退步
    attrib = {}
    for x in specs:
        if x["confirmed"]:
            continue
        attrib.setdefault((x["base"], x["family"]), []).append(
            x.get("iast_state") or "(empty)")
    con.close()
    elig = [r for r in rows if r.get("dyn_eligible") and r["base"] not in exempt]
    # 2026-11-09（L2 本轮）：分母必须是「不同的 (文件, 族) 真值点」，不能是真值行数。
    # RuoYi 真值表 6 行里 SysUserMapper.xml/sql_injection 有 3 行（三条不同路由的实例），
    # 而匹配只到 (文件, 族) 一级，分子自然去重成 1 —— 行数做分母会算出 4/6 这种
    # 分子分母不同粒度的读数。jsc 31 行全是不同对，此项对历史读数零影响。
    pair_keys = {(r["base"], r["family"]) for r in elig}
    n = len(pair_keys)

    def _hits(key):
        return {(r["base"], r["family"]) for r in elig if r[key]}

    strict_hits = {(r["base"], r["family"]) for r in elig
                   if (r["base"], r["family"]) in strict}
    return {
        "task_id": task_id,
        "truth": os.path.basename(truth_path),
        "denominator": n,
        "truth_rows": len(elig),
        "static_file": len({r["base"] for r in elig if r["static_file"]}),
        "static_fam": len({(r["base"], r["family"]) for r in elig if r["static_fam"]}),
        "dyn_fam": len(_hits("dyn_fam")),
        "rep_fam": len(_hits("rep_fam")),
        "strict_replay": len(strict_hits),
        "confirmed": fp["confirmed"],
        # 红线误报的分母必须是 confirmed_replay spec 数（628=60），
        # 不是全部 confirmed（628=74），否则与 jsc_four_tier.py CLI 口径不一致。
        "replay": fp["replay"],
        "fp_confirmed": len(fp["fp_confirmed"]),
        "fp_replay": len(fp["fp_replay"]),
        "fp_replay_keys": sorted({(x["base"], x["family"]) for x in fp["fp_replay"]}),
        # 不去重的逐 spec 列表：例外放行上限必须按条数算，不能按去重键算
        "fp_replay_items": [(x["base"], x["family"]) for x in fp["fp_replay"]],
        "hits": {k: sorted(_hits(k)) for k in ("static_fam", "dyn_fam", "rep_fam")},
        "strict_hits": sorted(strict_hits),
        "attrib": attrib,
        "rules": {r["base"] + "|" + r["family"]: r["n_confirmed_replay"] for r in elig},
    }


def pct(a: int, n: int) -> float:
    return round(100.0 * a / n, 1) if n else 0.0


def diff_keys(a, b):
    return sorted(set(a) - set(b)) or []


def render(base, var, mode: str) -> str:
    L = []
    L.append("=" * 74)
    L.append("泛化验证对比 · mode=%s · 真值=%s" % (mode, var["truth"]))
    L.append("=" * 74)
    n = var["denominator"]
    if base is None:
        L.append("基线：无（cross-target 首轮，只报绝对值）")
    else:
        L.append("基线 task %d → 变体 task %d ｜ 可重放分母 %d" %
                 (base["task_id"], var["task_id"], n))
    L.append("")
    metrics = [
        ("静态·文件+族", "static_fam"),
        ("动态·文件+族", "dyn_fam"),
        ("重放·文件+族", "rep_fam"),
        ("严格重放", "strict_replay"),
    ]
    L.append("  %-18s %12s %12s %10s" % ("指标", "基线", "变体", "变化"))
    for label, key in metrics:
        b = "%d/%d=%.1f%%" % (base[key], base["denominator"],
                              pct(base[key], base["denominator"])) if base else "—"
        v = "%d/%d=%.1f%%" % (var[key], n, pct(var[key], n))
        d = "%+.1fpp" % (pct(var[key], n) - pct(base[key], base["denominator"])) if base else "—"
        L.append("  %-18s %12s %12s %10s" % (label, b, v, d))
    L.append("")
    L.append("  红线误报(confirmed_replay)：%s → %s" % (
        ("%d/%d" % (base["fp_replay"], base["replay"])) if base else "—",
        "%d/%d" % (var["fp_replay"], var["replay"])))
    L.append("  确认级误报：%s → %s" % (
        ("%d/%d" % (base["fp_confirmed"], base["confirmed"])) if base else "—",
        "%d/%d" % (var["fp_confirmed"], var["confirmed"])))

    if base:
        if base["denominator"] != n or base["truth"] != var["truth"]:
            L.append("  [warn] 基线与变体真值表/分母不同，逐点 diff 不可比，仅供参考")
        gained = diff_keys(var["hits"]["rep_fam"], base["hits"]["rep_fam"])
        lost = diff_keys(base["hits"]["rep_fam"], var["hits"]["rep_fam"])
        L.append("")
        L.append("  重放口径 · 新命中 %d / 退步 %d" % (len(gained), len(lost)))
        for k in lost:
            L.append("    - 退步 %-28s %-22s 未确认态=%s" %
                     (k[0], k[1], ",".join(sorted(set(var["attrib"].get(k, [])))[:3]) or "—"))
        for k in gained:
            L.append("    + 新命中 %-28s %-22s" % (k[0], k[1]))
        new_fp = diff_keys(var["fp_replay_keys"], base["fp_replay_keys"])
        if new_fp:
            L.append("  [红线] 新增误报：%s" % ", ".join("%s/%s" % k for k in new_fp))

    ex = var.get("exceptions") or {}
    eff = int(ex.get("fp_replay_effective", var["fp_replay"]))
    viol = list(ex.get("violations") or [])
    raw = int(var["fp_replay"])
    if ex.get("matched"):
        L.append("  预登记例外（层=%s）：" % (ex.get("layer") or "—"))
        for m in ex["matched"]:
            L.append("    - %s 放行 %s/%s" % (m["id"], m["key"][0], m["key"][1]))
    else:
        L.append("  预登记例外（层=%s）：本轮未命中" % (ex.get("layer") or "—"))
    for v in viol:
        L.append("    [违规] %s" % v)
    L.append("")
    L.append("  验收线（判定见 docs/generalization_validation_design.md）：")
    L.append("    - 红线误报扣除已批准例外后必须为 0；原始 %d 条 → 有效 %d 条，%s" %
             (raw, eff,
              "通过" if eff == 0 and not viol else
              "未通过（%d 条%s）" % (eff, "，且例外违规" if viol else "")))
    if mode == "stability":
        L.append("    - 同配置两轮波动点应可解释，且分母/静态侧一致")
    elif mode == "blind":
        L.append("    - 掉的点须能归因到路由先验，而非认证/环境/探针故障")
        L.append("    - 严格重放与四档重放的差值不应扩大（否则是靠静态确认撑数）")
    else:
        L.append("    - 首次跨靶场只建立基线，不与 jsc 的 24/24 直接比大小")
    L.append("=" * 74)
    return "\n".join(L)


def to_jsonable(obj):
    """把 measure() 的 tuple-key dict / set 归一化成纯 JSON 结构，仅供 --json 输出。

    measure()['attrib'] 用 (base, family) 元组作 key，render() 依赖它做逐点归因；
    json.dump 不接受非字符串 key，故只在序列化前转换，不改任何判定或渲染逻辑。
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = "|".join(str(x) for x in k) if isinstance(k, (tuple, list)) else str(k)
            out[key] = to_jsonable(v)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(x) for x in obj]
    return obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", type=int, default=0)
    ap.add_argument("--variant", type=int, default=0)
    ap.add_argument("--mode", choices=("blind", "cross-target", "stability"), default="blind")
    ap.add_argument("--truth", default=DEFAULT_TRUTH)
    ap.add_argument("--db", default=J.DB)
    ap.add_argument("--json", default="", help="额外把结果写成 JSON")
    ap.add_argument("--config", default=DEFAULT_CONFIG,
                    help="预登记例外配置（默认 config/generalization.yaml）")
    ap.add_argument("--no-exceptions", action="store_true",
                    help="不读取预登记例外，按原始口径输出（对照用）")
    ap.add_argument("--self-check", action="store_true", help="628 自比，验证脚本本身")
    args = ap.parse_args()

    if args.self_check:
        args.baseline = args.variant = 628
        args.mode = "stability"
    if not args.variant:
        print("[FATAL] 需要 --variant（或用 --self-check）")
        return 2
    if not os.path.isfile(args.truth):
        print("[FATAL] 真值表不存在：%s" % args.truth)
        return 2

    exempt = {k[0] for k in J.load_known_unreachable()}
    exempt |= {"crlfinjection.java", "ooxmlxxe.java",
               "classdataloader.java", "websecurityconfig.java"}
    exceptions = [] if args.no_exceptions else load_pre_registered_exceptions(args.config)
    base = measure(args.baseline, args.truth, args.db, exempt) if args.baseline else None
    var = measure(args.variant, args.truth, args.db, exempt)
    # 2026-11-07：例外只作用于变体轮，且必须按当前 mode 的层匹配（L1 例外不外溢到 L3/L2）
    var["exceptions"] = apply_pre_registered_exceptions(var, args.mode, exceptions)
    print(render(base, var, args.mode))

    if args.json:
        _ex = var["exceptions"]
        payload = {
            "mode": args.mode, "baseline": base, "variant": var,
            "status": "script_ready_not_executed" if args.self_check else "measured",
            "gate": {
                "redline_pass": _ex["fp_replay_effective"] == 0 and not _ex["violations"],
                "fp_replay_raw": int(var["fp_replay"]),
                "fp_replay_effective": _ex["fp_replay_effective"],
                "exception_matched": _ex["matched"],
                "exception_violations": _ex["violations"],
            },
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(to_jsonable(payload), fh, ensure_ascii=False, indent=2)
        print("[i] JSON 已写入 %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
