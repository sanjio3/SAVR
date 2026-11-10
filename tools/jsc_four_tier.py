#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""四档口径一次出全（静态/动态 × 文件级/文件+族），并把 confirmed 拆成
「重放确认」与「静态自动确认」。

## 为什么要单独一个脚本

2026-10-31 复盘：四档口径分散在三个地方——静态走 ``tools/_wb_jsc_compare.py``
（findings ∪ specs），动态要现写 SQL，``confirmed`` 里还混着
``_apply_framework_property_upgrade`` 自动升的那部分（本轮 33 条里 15 条是自动的）。
三处口径各写各的 ⇒ 同一轮任务能数出三个不同的数，讨论时各说各话。

本脚本把四档钉在**一处**，并且强制打印分子分母明细，避免「数字涨了但不知道为什么」。

## 口径定义（唯一真相）

- 静态 · 文件级：该真值文件的 basename 在 findings ∪ specs 里出现过
- 静态 · 文件+族：出现过 (该文件, 该族) 的组合
- 动态 · 文件级：该文件有任一 ``verification_status LIKE 'confirmed%'`` 的 spec
- 动态 · 文件+族：该文件有该族的 confirmed spec
- ``confirmed`` 拆分：
  - ``confirmed_replay``：真正经过重放/裁决得到的。**2026-11-06 收紧**：除
    ``confirmed_exploitable`` 且非 ``framework:`` 外，还要求该 spec 在
    ``replay_attempts`` 里确有发包记录；否则是「裁决凭空确认」，不算动态证明。
  - ``confirmed_replay_legacy``：收紧前的口径（不检查 attempts），只用于与历史
    轮次对齐，不作为对外能力指标。CLI 双列并列输出。
  - ``confirmed_static``：``positive_evidence_rule LIKE 'framework:%'``，即规则直接升级的
    （这不算动态验证，对外报「动态确认」时不应计入）

## 用法

    python tools/jsc_four_tier.py --task-id 576
    python tools/jsc_four_tier.py --task-id 576 --truth data/java_sec_code_truth_v2.csv
    python tools/jsc_four_tier.py --task-id 576 --only in_scope
"""
from __future__ import annotations

import argparse
import csv
import importlib
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "data", "app.db")
DEFAULT_TRUTH = os.path.join(ROOT, "data", "java_sec_code_truth_v2.csv")

sys.path.insert(0, ROOT)
try:
    from src.core.normalize import normalize_family as _norm_family
except Exception:  # 极端情况下退回小写直比（会让 auth_bypass≠authentication_session，仅作降级）
    def _norm_family(x):
        return str(x or "").strip().lower()


def _fam(raw) -> str:
    """族名两侧都过 normalize_family：真值写 auth_bypass、平台写 authentication_session
    是同一个族，不归一就会把这一条算成「族错」——这正是 P4-3「族名口径三套」的现场。"""
    return _norm_family(str(raw or "").strip()) or str(raw or "").strip().lower()


def _base(path: str) -> str:
    return os.path.basename(str(path or "").replace("\\", "/")).lower()


# 2026-11-08 下面三处依赖原本各带 try/except 降级，缺依赖时会**静默**
# 改变读数（族名不归一、动态分母不剔除属性族、物理不可达豁免失效）。
# 本轮实测系统 Python 3.13 缺 PyYAML 时：静态·文件+族 30/31→29/31、
# 动态分母 24→31、重放 23/24→23/31。正式读数必须在缺依赖时直接失败。
_DEPS = (
    ("yaml", "", "PyYAML（config/known_unreachable.yaml 物理不可达豁免）"),
    ("src.core.normalize", "normalize_family", "族名归一 normalize_family"),
    ("src.core.spec_state_normalize", "is_dynamic_eligible", "动态可重放族 is_dynamic_eligible"),
)


def dependency_report() -> list:
    """返回缺失/不可用的口径依赖；为空才允许输出正式四档读数。"""
    missing = []
    for mod, attr, label in _DEPS:
        try:
            m = importlib.import_module(mod)
            if attr and not hasattr(m, attr):
                missing.append("%s: 模块 %s 缺属性 %s" % (label, mod, attr))
        except Exception as exc:  # noqa: BLE001
            missing.append("%s: %s" % (label, exc))
    return missing


def load_truth(path: str, only: str = "in_scope"):
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for r in rows:
        if only and str(r.get("scope", "")).strip() != only:
            continue
        f = str(r.get("file", "")).strip()
        fam = _fam(r.get("family", ""))
        if not f or not fam:
            continue
        out.append({"file": f, "base": _base(f), "family": fam,
                    "detectability": str(r.get("detectability", "")).strip()})
    return out


def load_task(db_path: str, task_id: int):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    findings = []
    for r in con.execute(
            "SELECT file_path, finding_type FROM findings WHERE task_id=?", (task_id,)):
        findings.append({"base": _base(r["file_path"]),
                         "family": _fam(r["finding_type"])})
    specs = []
    # has_attempts 在 SQL 里下推，避免把整张 replay_attempts 捞到 Python 再过滤。
    # 2026-11-06 口径收紧：628 的 sqli.java 靠零发包的
    # business-logic-confirmed 撑起一个真值点，必须让「确认」与「发过请求」绑定。
    for r in con.execute(
            """SELECT s.expected_sink_file, s.family, s.verification_status,
                       s.positive_evidence_rule, s.iast_state,
                       EXISTS(SELECT 1 FROM replay_attempts a
                              WHERE a.task_id = s.task_id AND a.spec_id = s.id) AS has_attempts
               FROM trigger_specs s WHERE s.task_id=?""", (task_id,)):
        status = str(r["verification_status"] or "").lower()
        rule = str(r["positive_evidence_rule"] or "")
        has_attempts = bool(r["has_attempts"])
        _legacy = status == "confirmed_exploitable" and not rule.startswith("framework:")
        specs.append({
            "base": _base(r["expected_sink_file"]),
            "family": _fam(r["family"]),
            "confirmed": status.startswith("confirmed"),
            "confirmed_static": status.startswith("confirmed") and rule.startswith("framework:"),
            "has_attempts": has_attempts,
            "confirmed_replay_legacy": _legacy,
            # 2026-11-03：**真正经过重放/裁决**的确认。判定收紧到 `confirmed_exploitable` 一档。
            #
            # 只排 `framework:` 前缀是不够的：`confirmed_code_property`（如 MyBatis `${}` 强证据、
            # 属性族强算法门禁）本身就是**静态代码属性确认**，positive_evidence_rule 常常为空串，
            # 不会被 `framework:` 过滤掉。603 实测：fileupload 的 file_upload 是
            # `confirmed_code_property / payload_unavailable`（请求都没发），却因此被算进「重放」，
            # 把重放档从 9 虚报到 10。
            #
            # 三档语义必须分开：
            #   confirmed_exploitable  = 运行时打穿（真重放/裁决）
            #   confirmed_code_property = 代码属性成立（静态）
            #   confirmed_sink_control  = sink 可控（静态）
            # 对外报「动态能力」只能引用第一档。
            "confirmed_replay": _legacy and has_attempts,
            "status": status,
            "iast_state": str(r["iast_state"] or ""),
        })
    con.close()
    return findings, specs


def compute(truth, findings, specs):
    rows = []
    for t in truth:
        b, fam = t["base"], t["family"]
        f_hit = [x for x in findings if x["base"] == b]
        s_hit = [x for x in specs if x["base"] == b]
        static_file = bool(f_hit or s_hit)
        static_fam = any(x["family"] == fam for x in f_hit + s_hit)
        dyn_specs = [x for x in s_hit if x["confirmed"]]
        rep_specs = [x for x in s_hit if x["confirmed_replay"]]
        rep_legacy = [x for x in s_hit if x.get("confirmed_replay_legacy")]
        dyn_file = bool(dyn_specs)
        dyn_fam = any(x["family"] == fam for x in dyn_specs)
        rep_file = bool(rep_specs)
        rep_fam = any(x["family"] == fam for x in rep_specs)
        rep_file_legacy = bool(rep_legacy)
        rep_fam_legacy = any(x["family"] == fam for x in rep_legacy)
        try:
            from src.core.spec_state_normalize import is_dynamic_eligible
            dyn_eligible = bool(is_dynamic_eligible(fam))
        except Exception:
            dyn_eligible = True
        rows.append({
            **t,
            "dyn_eligible": dyn_eligible,
            "static_file": static_file,
            "static_fam": static_fam,
            "dyn_file": dyn_file,
            "dyn_fam": dyn_fam,
            "rep_file": rep_file,
            "rep_fam": rep_fam,
            "rep_file_legacy": rep_file_legacy,
            "rep_fam_legacy": rep_fam_legacy,
            "n_findings": len(f_hit),
            "n_specs": len(s_hit),
            "n_confirmed": len(dyn_specs),
            "n_confirmed_static": sum(1 for x in dyn_specs if x["confirmed_static"]),
            "n_confirmed_replay": len(rep_specs),
            "n_confirmed_replay_legacy": len(rep_legacy),
        })
    return rows


def compute_fp(truth, specs):
    """确认级误报：confirmed spec 中 (文件, 族) 不在真值 in_scope 里的比例。

    2026-11-03 补：原脚本只算「漏报」（真值有没有被命中），**完全不算误报**，于是
    「动态 51.7%」这种数字读起来像能力，实际里面混着 25% 的确认级误报（599 实测
    56 条 confirmed 里 14 条不在真值）。误报必须和漏报一起看，否则调参只会朝一个方向偏。

    口径：分母 = 该 task 全部 confirmed spec（不是只落在真值文件上的那些），
    分子 = (basename(expected_sink_file), family) 不在真值 in_scope 集合里的条数。
    重放确认单独再算一遍——那才是红线口径。
    """
    tset = {(t["base"], t["family"]) for t in truth}
    conf = [x for x in specs if x["confirmed"]]
    rep = [x for x in specs if x["confirmed_replay"]]
    rep_legacy = [x for x in specs if x.get("confirmed_replay_legacy")]
    fp_conf = [x for x in conf if (x["base"], x["family"]) not in tset]
    fp_rep = [x for x in rep if (x["base"], x["family"]) not in tset]
    fp_rep_legacy = [x for x in rep_legacy if (x["base"], x["family"]) not in tset]
    # 口径收紧不等于「误报被修好」：被新口径排除的零重放确认单列出来，防止把
    # 分母变小误读成红线改善。
    zero_replay_confirmed = [x for x in rep_legacy
                             if x not in rep and (x["base"], x["family"]) not in tset]
    return {
        "confirmed": len(conf), "fp_confirmed": fp_conf,
        "replay": len(rep), "fp_replay": fp_rep,
        "replay_legacy": len(rep_legacy), "fp_replay_legacy": fp_rep_legacy,
        "fp_zero_replay_excluded": zero_replay_confirmed,
        "truth_set": tset,
    }


def load_known_unreachable(path: str = "") -> dict:
    """读物理不可达豁免清单，返回 {(basename_lower, family_lower): id}。

    2026-11-04：这些点（zip XXE / defineClass / WebSocket / CRLF）在 SUT 能力边界内
    无法用 HTTP 重放证明，混在动态分母里会让覆盖率系统性偏低，且每轮都要重复确认。
    清单缺失或解析失败时返回空 dict（fail-open：口径退化为「不豁免」，
    宁可数字难看，也不能让豁免悄悄吞掉真漏报）。
    """
    if not path:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'config', 'known_unreachable.yaml')
    try:
        import yaml
        with open(path, encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return {}
    out = {}
    for it in (data.get('items') or []):
        if not isinstance(it, dict):
            continue
        f = os.path.basename(str(it.get('file') or '').strip()).lower()
        fam = str(it.get('family') or '').strip().lower()
        if f and fam:
            out[(f, fam)] = str(it.get('id') or f)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--truth", default=DEFAULT_TRUTH)
    ap.add_argument("--db", default=DB)
    ap.add_argument("--only", default="in_scope", help="只统计该 scope（默认 in_scope，传 '' 为全部）")
    ap.add_argument("--verbose", action="store_true", help="打印逐文件明细")
    ap.add_argument("--param-drift", action="store_true",
                    help="只读审计 trigger_specs 权威列与 raw_json.exploit_spec.entry 的投影漂移")
    ap.add_argument("--truth-addendum", default="",
                    help="只读追加候选真值行（与主真值表同列结构），不修改主真值表；"
                         "用于口径变更的影响面复算，结果不得作为正式口径引用")
    ap.add_argument("--allow-degraded", action="store_true",
                    help="仅诊断用：允许在依赖缺失时输出降级读数，结果不得作为正式口径引用")
    args = ap.parse_args()

    missing = dependency_report()
    if missing and not args.allow_degraded:
        print("[fatal] 四档口径依赖缺失，拒绝输出会被误读的降级读数：")
        for item in missing:
            print("  - %s" % item)
        print("  请用项目 .venv 解释器重跑；仅离线诊断可加 --allow-degraded")
        return 2
    if missing:
        print("[警告] 降级模式（依赖缺失）：本次输出仅供诊断，不得作为正式口径引用")
        for item in missing:
            print("  - %s" % item)

    if not os.path.isfile(args.truth):
        print(f"[fatal] 真值表不存在：{args.truth}")
        return 2
    truth = load_truth(args.truth, args.only)
    shadow_n = 0
    if args.truth_addendum:
        if not os.path.isfile(args.truth_addendum):
            print(f"[fatal] 追加真值文件不存在：{args.truth_addendum}")
            return 2
        extra = load_truth(args.truth_addendum, args.only)
        seen = {(t["base"], t["family"]) for t in truth}
        added = [t for t in extra if (t["base"], t["family"]) not in seen]
        shadow_n = len(added)
        truth += added
        print(f"[影子口径] 追加 {shadow_n} 条候选真值（{os.path.basename(args.truth_addendum)}）；"
              f"主真值表未修改，本次输出仅供口径决策，不是正式读数")
    findings, specs = load_task(args.db, args.task_id)
    rows = compute(truth, findings, specs)
    n = len(rows) or 1

    def pct(k):
        return sum(1 for r in rows if r[k]) / n * 100

    print("=" * 78)
    print(f"四档口径 · task {args.task_id} · 真值 {os.path.basename(args.truth)}"
          f"（{args.only or 'all'} {len(rows)} 条）"
          + (f" · 影子口径 +{shadow_n}" if args.truth_addendum else ""))
    print("=" * 78)
    print(f"  静态 · 文件级      {sum(1 for r in rows if r['static_file']):3d}/{n:<3d} = {pct('static_file'):5.1f}%")
    print(f"  静态 · 文件+族     {sum(1 for r in rows if r['static_fam']):3d}/{n:<3d} = {pct('static_fam'):5.1f}%")
    print(f"  动态 · 文件级      {sum(1 for r in rows if r['dyn_file']):3d}/{n:<3d} = {pct('dyn_file'):5.1f}%")
    print(f"  动态 · 文件+族     {sum(1 for r in rows if r['dyn_fam']):3d}/{n:<3d} = {pct('dyn_fam'):5.1f}%")
    # 2026-11-03：原实现是 sum(r["n_confirmed"])，同一条 spec 命中多条真值行时会被重复计数
    # （601 实测报 16、实际 12；599 报 52、实际 56）。总数按 spec 去重，与误报段的分母对齐。
    conf = len([x for x in specs if x["confirmed"]])
    conf_static = len([x for x in specs if x["confirmed_static"]])
    conf_replay = len([x for x in specs if x["confirmed_replay"]])
    conf_replay_legacy = len([x for x in specs if x.get("confirmed_replay_legacy")])
    print()
    print(f"  confirmed 总数 {conf}（其中静态自动确认 {conf_static}，"
          f"真实重放确认 {conf_replay}）")
    print(f"  口径：confirmed_replay 已收紧为「confirmed_exploitable + 非 framework: + 有 replay_attempts」")
    print(f"        旧口径（不查 attempts）= {conf_replay_legacy}，差 {conf_replay_legacy - conf_replay} 条为零重放确认")
    print(f"  任务侧总计：findings {len(findings)} 条 / specs {len(specs)} 条")

    # ── 动态口径（只算「平台有 D2 证明模板」的族）──────────────────────────
    # 属性/配置族（csrf / secure_cookie / information_exposure / log_injection / unmapped）
    # 结构上不可能靠「把 payload 送进 sink」证明，算进动态分母只会让数字系统性偏低。
    # 两个口径都出，方便和历史数字对齐，也方便看真实能力。
    elig = [r for r in rows if r.get("dyn_eligible")]
    # 2026-11-04：剔除「物理不可达」点（config/known_unreachable.yaml）。
    # 这些点在 SUT 能力边界内无法用 HTTP 重放证明，静态照常计入检出，只从动态分母剔除。
    _kw = load_known_unreachable()
    _kw_key = lambda r: (str(r.get("base", "")).lower(), str(r.get("family", "")).lower())
    _exempt = [r for r in elig if _kw_key(r) in _kw]
    elig = [r for r in elig if _kw_key(r) not in _kw]
    ne = len(elig) or 1
    if _exempt:
        print()
        print(f"  [豁免] 物理不可达 {len(_exempt)} 个，已从动态分母剔除（静态仍计入）：")
        for r in _exempt:
            print(f"    - {str(r.get('base','')).replace('.java',''):24s} {str(r.get('family','')):22s} "
                  f"[{_kw[_kw_key(r)]}]")
    print()
    print(f"  动态口径（只算可重放族 {len(elig)}/{len(rows)} 条真值点）")
    print(f"    动态 · 文件级    {sum(1 for r in elig if r['dyn_file']):3d}/{ne:<3d} = "
          f"{sum(1 for r in elig if r['dyn_file'])/ne*100:5.1f}%   （含 framework: 静态升级）")
    print(f"    动态 · 文件+族   {sum(1 for r in elig if r['dyn_fam']):3d}/{ne:<3d} = "
          f"{sum(1 for r in elig if r['dyn_fam'])/ne*100:5.1f}%   （含 framework: 静态升级）")
    # 2026-11-03：**对外报「动态能力」只认这一档**。上一档把规则静态升级算进来了。
    print(f"    重放 · 文件级    {sum(1 for r in elig if r['rep_file']):3d}/{ne:<3d} = "
          f"{sum(1 for r in elig if r['rep_file'])/ne*100:5.1f}%   ← 新口径（有发包记录）")
    print(f"    重放 · 文件+族   {sum(1 for r in elig if r['rep_fam']):3d}/{ne:<3d} = "
          f"{sum(1 for r in elig if r['rep_fam'])/ne*100:5.1f}%   ← 新口径（有发包记录）")
    print(f"    [旧口径对照] 重放 文件级 "
          f"{sum(1 for r in elig if r['rep_file_legacy']):3d}/{ne:<3d} / 文件+族 "
          f"{sum(1 for r in elig if r['rep_fam_legacy']):3d}/{ne:<3d}"
          f"   （仅用于与历史轮次对齐，不得对外引用）")
    excluded = [r["base"] for r in rows if not r.get("dyn_eligible")]
    if excluded:
        print(f"    已排除的属性/配置族：{', '.join(x.replace('.java','') for x in excluded)}")

    # ── 确认级误报（2026-11-03 补：原脚本只有漏报，没有误报）──────────────
    fp = compute_fp(truth, specs)
    print()
    print(f"  确认级误报（口径：confirmed spec 的 文件+族 不在真值 in_scope 集合内）")
    _c, _fc = fp["confirmed"], len(fp["fp_confirmed"])
    _r, _fr = fp["replay"], len(fp["fp_replay"])
    _rl, _frl = fp["replay_legacy"], len(fp["fp_replay_legacy"])
    print(f"    confirmed      {_fc:3d}/{_c:<3d} = {(_fc/_c*100 if _c else 0):5.1f}%"
          f"   （分母=全部 confirmed spec，不是只落在真值上的）")
    print(f"    重放确认       {_fr:3d}/{_r:<3d} = {(_fr/_r*100 if _r else 0):5.1f}%"
          f"   ← 红线口径（新）")
    print(f"    重放[旧口径]   {_frl:3d}/{_rl:<3d} = {(_frl/_rl*100 if _rl else 0):5.1f}%"
          f"   （历史对照；分母变小不代表红线改善）")
    if fp["fp_zero_replay_excluded"]:
        print(f"    [提醒] 有 {len(fp['fp_zero_replay_excluded'])} 条旧口径红线误报因零重放被新口径排除，"
              f"属口径收紧，不是修复")
    for x in fp["fp_replay"][:10]:
        print(f"      - {x['base'][:40]:40s} {x['family']:18s} {x['iast_state']}")

    # ── 未确认的原因分布（口径归一的直接产物）────────────────────────────
    st = {}
    for x in specs:
        if x["confirmed"]:
            continue
        k = x.get("iast_state") or "(空)"
        st[k] = st.get(k, 0) + 1
    if st:
        print()
        print("  未确认 spec 的状态分布：")
        for k, v in sorted(st.items(), key=lambda kv: -kv[1]):
            note = {
                "payload_unavailable": "A2 没弹可投（D1 拒绝投假弹，未发请求）",
                "no-arrival": "发了但没到 sink",
                "sink-reached": "到了 sink 但 D2 未确认有害",
                "sink-reached-probe": "探针断言到达但 D2 未确认",
                "no-iast-evidence": "无 IAST 证据（属性族静态通道）",
            }.get(k, "")
            print(f"    {v:3d}  {k:24s} {note}")

    if args.param_drift:
        from src.iast.spec_projection import audit_entry_projection_rows
        _con = sqlite3.connect(args.db)
        _rows = _con.execute(
            "SELECT id, param_name, param_location, content_type, raw_json "
            "FROM trigger_specs WHERE task_id=?", (args.task_id,)).fetchall()
        _con.close()
        drift = audit_entry_projection_rows(_rows)
        print()
        print(f"  参数投影漂移 {len(drift)}/{len(_rows)} 条"
              f"（权威列 vs raw_json.exploit_spec.entry；新轮次应为 0）")
        for d in drift[:10]:
            print(f"    - spec {d['spec_id']}: " + ", ".join(
                f"{k} 权威={v['authoritative']!r} entry={v['entry']!r}"
                for k, v in d["diffs"].items()))
        if len(drift) > 10:
            print(f"    ... 其余 {len(drift)-10} 条略")

    if args.verbose:
        print()
        print(f"  {'文件':38s} {'族':20s} 静态族 动态族 spec/conf")
        for r in rows:
            mark = lambda b: " ✓" if b else " ·"
            print(f"  {r['base'][:38]:38s} {r['family'][:20]:20s}"
                  f"  {mark(r['static_fam'])}     {mark(r['dyn_fam'])}   {r['n_specs']}/{r['n_confirmed']}")

    # 非零退出码便于 CI：任一档未达 100% 即返回 1（默认不启用，避免误伤脚本调用）
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
