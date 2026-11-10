#!/usr/bin/env python
"""R23 验收口径核对（只读，唯一真相源 = data/app.db）。

用途：每轮扫描终态后核对 R23 三处修复是否真的生效，并给出与历史轮次的对照带。

R23 验收判据（按优先级）：
  A. a1_evidence 是否落在「本轮自己」的行上
     - 非空条数 > 0；
     - route_status='static' 的条数量级应与「本轮」A1 产出一致，而不是与上一轮一致
       （修复前是跨任务滞后写入：task N 的证据落在 task N-1 行上，最新一轮恒空）。
     - 该计数同时是 §6.9「静态路由优先于 LLM」能否端到端实证的唯一判据（task-7 此项为 0）。
  B. 业务族受害者目标覆盖率
     - 业务族 spec 中 victim_resource_id 为空的比例应从 87%（99/114）降到接近 0。
  C. 业务族受害者标识与账户落库
     - victim_identifiers 非空条数应 > 0（修复前 114/114 全空）；
     - accounts_json 非空条数应 > 0（修复前全空，bootstrap 回写进了临时库）。
  D. 结果面不回归
     - specs / confirmed / bizconf 应落在历史轮次的方差带内。
  E. R23-4 回归门禁（仅在给出 --baseline 时判定）
     - confirmed / biz_confirmed / bola 族 confirmed 不得低于基线带下界。
       成因：R23-3 把业务族 victim_resource_id 写成哨兵，但哨兵在重放期未能解析（user_id 被
       bootstrap 输出白名单过滤）→ 字面量进 URL → bola confirmed 12→3。该门禁专防此复发。

用法：
    python scripts/check_r23_acceptance.py --task-id 8
    python scripts/check_r23_acceptance.py --task-id 8 --baseline 1,2,3,4,5,6,7
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import statistics
import sys
from typing import Any, Dict, List, Optional


def _db_path() -> str:
    return os.environ.get("SAST_AI_DB_PATH", "data/app.db")


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _loads(raw: Any, default: Any) -> Any:
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return default


# ---------------- 真值逐条对账（R23 验收升级：从「只看计数」到「按真值逐条」）----------------
# 真值表单一真相源 = src/api/routers/round_report.py 的 VULNS（35 条：18 技术 + 17 业务），
# 与 scripts/reconcile_target_mall_v2.py 保持一致。此处只做「导入」，不复制，避免口径漂移。
CONFIRMED_IAST_STATES = {
    "iast-authz-confirmed", "business-logic-confirmed",
    "sink-reached", "sink-reached-probe", "iast-reached",
}

# —— 真值匹配口径归一（2026-09-11 修）——
# 旧实现拿真值表的原始写法直接做子串匹配，产生两类「假 finding-only」：
#   ① 路由带 query：真值 #2/#17 写 '/products?keyword'，spec 记 '/products' → 子串不命中；
#   ② 族名不同源：真值 #8 的 token 'ssti' 与 spec family 'template-injection' 不同字面。
# 复核后确认这三条 spec 其实都在（甚至已 confirmed），属口径误判而非登记缺口。
# 修法：路由两侧先归一（去 query / 去尾斜杠），族 token 允许已知等价族名。
_TECH_TOKEN_ALIASES = {
    # 目标：真值 token → 可接受的 spec family 子串集合（同一漏洞的不同族名写法）
    "ssti": ("ssti", "template-injection"),
    # target-mall 的 /api/coupon/preview 同时具 SpEL 与模板注入语义，A2 归类为 template-injection
    "spel": ("spel", "template-injection"),
}


def _norm_route_key(r: str) -> str:
    """路由归一：去 query/fragment、去尾斜杠（'/products?keyword' → '/products'）。"""
    s = str(r or "").strip()
    for sep in ("?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    s = s.strip()
    if len(s) > 1:
        s = s.rstrip("/")
    return s.lower()


def _expand_tokens(tokens: List[str]) -> List[str]:
    out: List[str] = []
    for t in tokens or []:
        for alias in _TECH_TOKEN_ALIASES.get(t, (t,)):
            if alias not in out:
                out.append(alias)
    return out


def _canon(s: str) -> str:
    """族名/类别名归一：小写 + 把下划线与连字符视为同一分隔符。

    真值 token 与 spec family / 代码类别名对分隔符的写法不统一（真值 `abuse_dos` vs
    family `abuse-dos`、`state_machine` vs `state-machine`），字面比对会漏。（修复 #33
    在路由修好后仍认不出 abuse-dos 族即由此。）"""
    return re.sub(r"[_\-]", "-", str(s or "").lower())


def _load_truth() -> Any:
    """加载 target-mall 真值表 VULNS。优先 API 源，回退同目录脚本源（无 fastapi 依赖）。"""
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 项目根
    if _root not in sys.path:
        sys.path.insert(0, _root)
    try:
        from src.api.routers.round_report import VULNS  # type: ignore
        return VULNS, "round_report.VULNS"
    except Exception:
        pass
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "reconcile_target_mall_v2.py")
    if os.path.exists(p):
        spec = importlib.util.spec_from_file_location("_reconcile_tm_v2", p)
        mod = importlib.util.module_from_spec(spec)  # type: ignore
        spec.loader.exec_module(mod)  # type: ignore
        return mod.VULNS, "scripts/reconcile_target_mall_v2.py"
    raise RuntimeError("无法加载真值表 VULNS（round_report 与 reconcile_target_mall_v2 均不可用）")


def _spec_is_confirmed(spec: Dict[str, Any]) -> bool:
    """真正的「已确认」口径（区别于 round_report 的 confirm=命中 spec）。

    confirmed_exploitable / business_logic_confirmed=1 / iast_state 命中确认态，三者任一即确认。
    """
    if str(spec.get("verification_status") or "") == "confirmed_exploitable":
        return True
    try:
        if int(spec.get("business_logic_confirmed") or 0) == 1:
            return True
    except Exception:
        pass
    return str(spec.get("iast_state") or "") in CONFIRMED_IAST_STATES


def _match_specs(tokens: List[str], routes: List[str], specs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """族 token 命中 family 且路由命中 target_endpoint；返回全部命中（含已确认优先）。

    路由两侧均经 _norm_route_key 归一（去 query / 去尾斜杠）后做双向包含；
    族 token 先经 _expand_tokens 展开为可接受族名集合再判断。
    """
    toks = [_canon(t) for t in _expand_tokens(tokens)]
    route_keys = [_norm_route_key(r) for r in routes if str(r or "").strip()]
    out = []
    for s in specs:
        fam = _canon(s.get("family"))
        if not any(t in fam for t in toks):
            continue
        ep = _norm_route_key(s.get("target_endpoint"))
        # 裸 '/' / 空串是 A2 幻觉的残缺路由；作为子串它能匹配任意真值路由（'/' in '/admin' 恒真），
        # 会让「端点记成 /」的 spec 冒充命中任何真值 → 假 confirmed。此类 spec 一律不参与匹配。
        # 注意：不能波及 '/admin'（target-mall 里是真实路由），故只排除纯根路径。
        if not ep or ep == "/":
            continue
        # 单向包含：真值路由 token 必须出现在 spec 端点内（如真值 /refund 命中 spec /order/{id}/refund）。
        # 反向包含（spec 端点 ⊂ 真值路由）会跨漏洞污染：spec /profile（idor/bola）会冒充命中
        # 真值 /profile/password（越权改密），把 #24 假判为 confirmed。故只保留单向。
        if any(k in ep for k in route_keys if k):
            out.append(s)
    return out


def _finding_hit(tokens: List[str], finds: List[Any]) -> bool:
    toks = [_canon(t) for t in _expand_tokens(tokens)]
    for ft, src, rj in finds:
        blob = _canon(str(ft or "") + " " + str(src or ""))
        try:
            d = json.loads(rj) if rj else {}
            blob += " " + _canon(str(d.get("sink") or "") + " " + str(d.get("entry_point") or ""))
        except Exception:
            pass
        if any(t in blob for t in toks):
            return True
    return False


def collect_per_item(conn: sqlite3.Connection, task_id: int) -> Any:
    """按真值表逐条对账：每个真值项落在 confirmed / spec-unconfirmed / finding-only / missing。

    - confirmed       : 命中 spec 且该 spec 真确认（vs=confirmed_exploitable 或 biz_confirmed=1 或 iast 确认态）
    - spec-unconfirmed: 命中 spec 但未确认（「检测到但没确认」= R23 要消灭的漏报）
    - finding-only    : 无 spec，但有族命中的 finding（登记缺口：finding→spec 未接通）
    - missing         : 无 spec 且无 finding（最彻底缺口，如 #21 /admin/ 垂直越权）
    """
    specs = [dict(r) for r in conn.execute(
        "SELECT family, target_endpoint, category, business_logic_category, verification_status, "
        "iast_state, business_logic_confirmed FROM trigger_specs WHERE task_id = ?", (task_id,)).fetchall()]
    finds = [(r["finding_type"], r["source"], r["raw_json"]) for r in conn.execute(
        "SELECT finding_type, source, raw_json FROM findings WHERE task_id = ?", (task_id,)).fetchall()]
    vulns, src = _load_truth()
    items = []
    for vid, vtype, routes, tokens, kind in vulns:
        ms = _match_specs(tokens, routes, specs)
        conf = [s for s in ms if _spec_is_confirmed(s)]
        if conf:
            verdict = "confirmed"
        elif ms:
            verdict = "spec-unconfirmed"
        elif _finding_hit(tokens, finds):
            verdict = "finding-only"
        else:
            verdict = "missing"
        best = (conf or ms or [{}])[0]
        items.append({
            "id": vid, "type": vtype, "kind": kind, "routes": routes, "tokens": tokens,
            "verdict": verdict, "matched_specs": len(ms), "confirmed_specs": len(conf),
            "spec_endpoint": best.get("target_endpoint"),
            "spec_family": best.get("family"),
            "verification_status": best.get("verification_status"),
            "iast_state": best.get("iast_state"),
        })
    return items, src


def _bucket(items: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"confirmed": 0, "spec-unconfirmed": 0, "finding-only": 0, "missing": 0, "total": len(items)}
    for it in items:
        out[it["verdict"]] = out.get(it["verdict"], 0) + 1
    return out


def collect_findings(conn: sqlite3.Connection, task_id: int) -> Dict[str, Any]:
    rows = conn.execute(
        "SELECT a1_evidence, raw_json FROM findings WHERE task_id = ?", (task_id,)
    ).fetchall()
    total = len(rows)
    a1_nonempty = 0
    route_static = 0
    route_failed = 0
    family_nonempty = 0
    es_present = 0
    for row in rows:
        ev = _loads(row["a1_evidence"], {})
        if isinstance(ev, dict) and ev:
            a1_nonempty += 1
            status = str(ev.get("route_status") or "")
            if status == "static":
                route_static += 1
            elif status.startswith("static-failed"):
                route_failed += 1
        raw = _loads(row["raw_json"], {})
        if isinstance(raw, dict):
            es = raw.get("exploit_spec") or {}
            if es:
                es_present += 1
                fam = ((es.get("payload") or {}) or {}).get("payload_family")
                if fam:
                    family_nonempty += 1
    return {
        "findings": total,
        "a1_evidence_nonempty": a1_nonempty,
        "route_status_static": route_static,
        "route_status_static_failed": route_failed,
        "exploit_spec_present": es_present,
        "exploit_spec_family_nonempty": family_nonempty,
    }


def collect_specs(conn: sqlite3.Connection, task_id: int) -> Dict[str, Any]:
    rows = conn.execute("SELECT * FROM trigger_specs WHERE task_id = ?", (task_id,)).fetchall()
    total = len(rows)
    biz = [r for r in rows if str(r["business_logic_category"] or "")]
    empty = 0
    vid_empty = 0
    vid_concrete = 0
    vid_sentinel = 0
    vi_nonempty = 0
    accounts_nonempty = 0
    confirmed = 0
    bizconf = 0
    obj_specs = 0
    obj_vid_empty = 0
    # R23 收口 polish：B 门禁只统计「已进入裁决」的对象访问型业务 spec
    # （verification_status 为 confirmed_exploitable 或 no_evidence）。
    # unconfirmed 是 D1 重放前的预登记态，victim_resource_id 尚未被解析，空值合理，不计入覆盖率门禁，
    # 否则会把「未裁决」误判为「覆盖率掉点」，掩盖真问题。
    obj_eval_specs = 0
    obj_eval_vid_empty = 0
    by_cat: Dict[str, Dict[str, int]] = {}
    for r in rows:
        if not str(r["verification_status"] or ""):
            empty += 1
        if str(r["verification_status"] or "") == "confirmed_exploitable":
            confirmed += 1
        if int(r["business_logic_confirmed"] or 0) == 1:
            bizconf += 1
    for r in biz:
        cat = str(r["business_logic_category"] or "")
        slot = by_cat.setdefault(cat, {"specs": 0, "confirmed": 0})
        slot["specs"] += 1
        if str(r["verification_status"] or "") == "confirmed_exploitable":
            slot["confirmed"] += 1
        vrid = str(r["victim_resource_id"] or "")
        if not vrid:
            vid_empty += 1
        elif vrid == "VICTIM_FROM_POOL":
            vid_sentinel += 1
        else:
            vid_concrete += 1
        # R23 收口 polish：B 门禁只统计「对象访问型」业务 spec（端点含 {id}/:id 或 param_location=path），
        # 非对象端点（/login、/seckill、/payment/sign 等动作/状态型）本就无「受害者对象 id」语义，空值合理，免统计。
        ep = str(r["target_endpoint"] or "")
        pl = str(r["param_location"] or "").lower()
        if ("{id}" in ep) or (":id" in ep) or (pl == "path"):
            obj_specs += 1
            if not vrid:
                obj_vid_empty += 1
            if str(r["verification_status"] or "") in ("confirmed_exploitable", "no_evidence"):
                obj_eval_specs += 1
                if not vrid:
                    obj_eval_vid_empty += 1
        vi = _loads(r["victim_identifiers"], [])
        if isinstance(vi, list) and [x for x in vi if str(x).strip()]:
            vi_nonempty += 1
        acc = _loads(r["accounts_json"], [])
        if acc not in ([], {}, "", None):
            accounts_nonempty += 1
    return {
        "specs": total,
        "specs_empty_status": empty,
        "confirmed_exploitable": confirmed,
        "biz_specs": len(biz),
        "biz_confirmed": bizconf,
        "biz_victim_resource_id_empty": vid_empty,
        "biz_obj_specs": obj_specs,
        "biz_obj_victim_resource_id_empty": obj_vid_empty,
        "biz_obj_evaluated_specs": obj_eval_specs,
        "biz_obj_evaluated_victim_resource_id_empty": obj_eval_vid_empty,
        "biz_victim_resource_id_concrete": vid_concrete,
        "biz_victim_resource_id_sentinel": vid_sentinel,
        "biz_victim_identifiers_nonempty": vi_nonempty,
        "biz_accounts_json_nonempty": accounts_nonempty,
        "biz_by_category": by_cat,
        "biz_confirmed_by_status": sum(int(v["confirmed"]) for v in by_cat.values()),
        "bola_confirmed": int(by_cat.get("bola", {}).get("confirmed", 0)),
    }


def _fmt(label: str, value: Any) -> str:
    return "  {:<34s} {}".format(label, value)


def report(conn: sqlite3.Connection, task_id: int) -> Dict[str, Any]:
    f = collect_findings(conn, task_id)
    s = collect_specs(conn, task_id)
    merged = {**f, **s}
    print("=" * 62)
    print("task-{}".format(task_id))
    print("=" * 62)
    print("findings")
    print(_fmt("findings 总数", f["findings"]))
    print(_fmt("a1_evidence 非空", f["a1_evidence_nonempty"]))
    print(_fmt("route_status=static", f["route_status_static"]))
    print(_fmt("route_status=static-failed", f["route_status_static_failed"]))
    print(_fmt("exploit_spec 存在", f["exploit_spec_present"]))
    print(_fmt("exploit_spec.payload_family 非空", f["exploit_spec_family_nonempty"]))
    print("trigger_specs")
    print(_fmt("specs 总数", s["specs"]))
    print(_fmt("空状态 spec", s["specs_empty_status"]))
    print(_fmt("confirmed_exploitable", s["confirmed_exploitable"]))
    print("业务族 spec")
    print(_fmt("业务族 spec 数", s["biz_specs"]))
    print(_fmt("business_logic_confirmed=1", s["biz_confirmed"]))
    print(_fmt("victim_resource_id 为空（全部业务族）", s["biz_victim_resource_id_empty"]))
    print(_fmt("victim_resource_id 空值（仅对象访问型，全部）", "{}/{}".format(s["biz_obj_victim_resource_id_empty"], s["biz_obj_specs"])))
    print(_fmt("victim_resource_id 空值（对象访问型·已裁决）", "{}/{}".format(s["biz_obj_evaluated_victim_resource_id_empty"], s["biz_obj_evaluated_specs"])))
    print(_fmt("victim_resource_id 具体值（已解析真 id 数）", s["biz_victim_resource_id_concrete"]))
    print(_fmt("victim_resource_id 哨兵", s["biz_victim_resource_id_sentinel"]))
    print(_fmt("victim_identifiers 非空", s["biz_victim_identifiers_nonempty"]))
    print(_fmt("accounts_json 非空", s["biz_accounts_json_nonempty"]))
    print(_fmt("业务族 confirmed（按状态）", s["biz_confirmed_by_status"]))
    for cat, slot in sorted(s["biz_by_category"].items()):
        print(_fmt("  {} : specs/confirmed".format(cat),
                   "{}/{}".format(slot["specs"], slot["confirmed"])))
    print()
    return merged


def band(values: List[float]) -> str:
    if not values:
        return "n/a"
    if len(values) == 1:
        return "{:.0f}".format(values[0])
    return "{:.1f}±{:.1f} (min {:.0f}, max {:.0f})".format(
        statistics.mean(values), statistics.pstdev(values), min(values), max(values)
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="R23 验收口径核对（只读）")
    ap.add_argument("--task-id", type=int, required=True)
    ap.add_argument("--baseline", default="", help="历史轮次对照，逗号分隔，如 1,2,3,4,5,6,7")
    ap.add_argument("--db", default="", help="覆盖 DB 路径（默认取 SAST_AI_DB_PATH 或 data/app.db）")
    ap.add_argument("--per-item-all", action="store_true", help="逐条对账打印全部 35 条（默认仅业务 17 条）")
    ap.add_argument("--min-biz-confirmed", type=int, default=16,
                    help="业务真值 confirmed 数下限（R24 定档 16 = R23 认定的必达目标，不含 #21；"
                         "17 为理论满分，15 为扣掉一条硬骨头的容忍线）")
    ap.add_argument("--no-item-check", action="store_true", help="跳过逐条对账的 F 判据（仅打印）")
    args = ap.parse_args()

    path = args.db or _db_path()
    if not os.path.exists(path):
        print("[ERR] DB 不存在：{}".format(path), file=sys.stderr)
        return 2
    conn = _connect(path)

    keys = [
        "findings", "a1_evidence_nonempty", "route_status_static",
        "specs", "specs_empty_status", "confirmed_exploitable",
        "biz_specs", "biz_confirmed",         "biz_victim_resource_id_empty",
        "biz_obj_specs", "biz_obj_victim_resource_id_empty",
        "biz_obj_evaluated_specs", "biz_obj_evaluated_victim_resource_id_empty",
        "biz_victim_identifiers_nonempty", "biz_accounts_json_nonempty",
    ]

    base_ids = [int(x) for x in args.baseline.split(",") if x.strip()]
    base_rows: List[Dict[str, Any]] = []
    for tid in base_ids:
        exists = conn.execute("SELECT 1 FROM scan_tasks WHERE id = ?", (tid,)).fetchone()
        if not exists:
            continue
        base_rows.append({**collect_findings(conn, tid), **collect_specs(conn, tid)})

    if base_rows:
        print("=" * 62)
        print("基线轮次对照（{} 轮）".format(len(base_rows)))
        print("=" * 62)
        for k in keys:
            print(_fmt(k, band([float(r.get(k) or 0) for r in base_rows])))
        print()

    cur = report(conn, args.task_id)

    # ---- 真值逐条对账（R23 验收升级口径：从「只看计数」到「按真值逐条」）----
    per_items, truth_src = collect_per_item(conn, args.task_id)
    show = per_items if args.per_item_all else [it for it in per_items if it["kind"] == "biz"]
    print("=" * 62)
    print("真值逐条对账（来源 {}，共 {} 条；本次打印 {} 条）".format(truth_src, len(per_items), len(show)))
    print("=" * 62)
    print("  {:<19s} {:<3s} {:<18s} {:<24s} {:<21s} {}".format(
        "VERDICT", "ID", "TYPE", "SPEC_ENDPOINT", "VERIFICATION_STATUS", "IAST_STATE"))
    for it in show:
        print("  {:<19s} {:<3d} {:<18s} {:<24s} {:<21s} {}".format(
            "[" + it["verdict"] + "]", it["id"], it["type"],
            str(it["spec_endpoint"] or "-"), str(it["verification_status"] or "-"),
            str(it["iast_state"] or "-")))
    biz_items = [it for it in per_items if it["kind"] == "biz"]
    tech_items = [it for it in per_items if it["kind"] == "tech"]
    bb = _bucket(biz_items)
    tb = _bucket(tech_items)
    print()
    print("业务真值（{} 条）".format(bb["total"]))
    print(_fmt("  confirmed（真确认）", bb["confirmed"]))
    print(_fmt("  spec-unconfirmed（检测到未确认）", bb["spec-unconfirmed"]))
    print(_fmt("  finding-only（有 finding 无 spec）", bb["finding-only"]))
    print(_fmt("  missing（无 spec 无 finding）", bb["missing"]))
    print("技术真值（{} 条）".format(tb["total"]))
    print(_fmt("  confirmed", tb["confirmed"]))
    print(_fmt("  spec-unconfirmed", tb["spec-unconfirmed"]))
    print(_fmt("  missing", tb["missing"]))
    if bb["spec-unconfirmed"] or bb["missing"] or bb["finding-only"]:
        print()
        print("业务漏报清单（unconfirmed/missing，供下一轮定位）：")
        for it in biz_items:
            if it["verdict"] != "confirmed":
                print("  - #{:<3d} {:<16s} [{}] spec={} vs={}".format(
                    it["id"], it["type"], it["verdict"], str(it["spec_endpoint"] or "-"),
                    str(it["verification_status"] or "-")))
    print()

    print("=" * 62)
    print("R23 验收判据")
    print("=" * 62)
    checks = [
        ("A1 a1_evidence 本轮自身落库 > 0", cur["a1_evidence_nonempty"] > 0),
        ("A2 route_status=static > 0（§6.9 可实证）", cur["route_status_static"] > 0),
        ("B 业务族 victim_resource_id 空值接近 0（对象访问型·已裁决 <=10%）",
         cur["biz_obj_evaluated_specs"] == 0 or cur["biz_obj_evaluated_victim_resource_id_empty"] <= max(1, int(cur["biz_obj_evaluated_specs"] * 0.1))),
        ("C victim_identifiers 非空 > 0", cur["biz_victim_identifiers_nonempty"] > 0),
        ("C accounts_json 非空 > 0", cur["biz_accounts_json_nonempty"] > 0),
        ("D 空状态 spec 恒 0", cur["specs_empty_status"] == 0),
        ("F1 业务真值逐条 confirmed >= {} / {}".format(args.min_biz_confirmed, bb["total"]),
         True if args.no_item_check else bb["confirmed"] >= args.min_biz_confirmed),
        ("F2 业务真值无 missing（无 spec 无 finding）",
         True if args.no_item_check else bb["missing"] == 0),
    ]
    if base_rows:
        # E. R23-4 回归门禁：结果面不得低于基线带下界（防「哨兵不可解析」复发，bola confirmed 12→3）。
        def _lo(key: str, slack: int = 2) -> float:
            vals = [float(r.get(key) or 0) for r in base_rows]
            return min(vals) - slack

        checks.extend([
            ("E confirmed 不低于基线带下界",
             float(cur["confirmed_exploitable"]) >= _lo("confirmed_exploitable")),
            ("E 业务族 confirmed 不低于基线带下界",
             float(cur["biz_confirmed_by_status"]) >= _lo("biz_confirmed_by_status")),
            ("E bola 族 confirmed 不低于基线最小值",
             float(cur["bola_confirmed"]) >= min([float(r.get("bola_confirmed") or 0) for r in base_rows])),
        ])
    failed = 0
    for label, ok in checks:
        print("  [{}] {}".format("PASS" if ok else "FAIL", label))
        if not ok:
            failed += 1

    if base_rows:
        print()
        print("对照带检查（供人工判断，不计入 PASS/FAIL）")
        for k in ("specs", "confirmed_exploitable", "biz_confirmed", "biz_confirmed_by_status",
                  "bola_confirmed", "findings"):
            vals = [float(r.get(k) or 0) for r in base_rows]
            lo, hi = min(vals), max(vals)
            v = float(cur.get(k) or 0)
            flag = "in-band" if lo - 2 <= v <= hi + 2 else "OUT-OF-BAND"
            print(_fmt("{} -> {}".format(k, flag), "cur={:.0f} baseline {}".format(v, band(vals))))

    print()
    print("判定：{}".format("全部 PASS" if failed == 0 else "存在 {} 项 FAIL".format(failed)))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
