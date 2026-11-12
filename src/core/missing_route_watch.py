"""missing_route 观测面。

29 个是已被其他 spec 覆盖的重复假说、39 个 FP、26 个跨文件未映射、真漏报仅 2 用例
代价 ≈2 用例召回，本质是「垃圾假说被路由解析器隐性过滤」+ 无显式反馈；真实风险在
未来跨文件靶场（sink 在 service 层）。

本模块把 skipped reasons 变成显式观测面：
- missing_route / route_is_source_path 的跳过项，逐条做「用例覆盖交叉核对」：
  按 finding 的 file 名（OWASP 惯例 = 用例名）映射用例；该用例已被任何 spec 的
  target_endpoint 覆盖 → 判「重复已覆盖」，从观测面丢弃（顺带减负）；
  未被覆盖 → **真漏报信号**，进 true_miss 列表（供 E-2 定向回填消费）；
  文件名映射不出用例 → cross_file（抽样人工定性项）。
- 纯读计算 + 落 stage_results，不改任何登记行为；定向回填见
  trigger_spec_registry 的 servlet 自注解最后兜底。
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

CASE_RE = re.compile(r"BenchmarkTest\d+")
WATCH_REASONS = ("missing_route", "route_is_source_path")


def _case_from_text(text: str) -> str:
    m = CASE_RE.search(text or "")
    return m.group(0) if m else ""


def _q(db, sql: str, params: tuple, one: bool = False):
    """兼容平台 Database.execute（fetchone/fetchall 关键字）与裸 sqlite3（返回 cursor）；统一转 dict。"""
    try:
        res = db.execute(sql, params, fetchone=True) if one else db.execute(sql, params, fetchall=True)
    except TypeError:
        cur = db.execute(sql, params)
        res = cur.fetchone() if one else cur.fetchall()
    if res is None:
        return None
    if one:
        return dict(res) if not isinstance(res, dict) else res
    return [dict(r) if not isinstance(r, dict) else r for r in res]


def build_missing_route_watch(db, task_id: int, reasons: List[Dict[str, Any]]) -> Dict[str, Any]:
    """对登记漏斗的 skipped reasons 做覆盖交叉核对，产出观测面结构。

    reasons 条目：{vulnerability_hash_v2, family, reason, reason_label, param_name, route}
    （trigger_spec_registry.auto_register 产物，task_result.stage_results.a2_poc.unresolved_reasons）。
    """
    out: Dict[str, Any] = {
        "watch_total": 0,
        "covered_dropped": 0,
        "true_miss": [],
        "cross_file": [],
        "by_reason": {},
    }
    if not reasons:
        return out
    watch_items = [r for r in reasons
                   if isinstance(r, dict) and str(r.get("reason") or "") in WATCH_REASONS]
    out["watch_total"] = len(watch_items)
    for r in watch_items:
        key = str(r.get("reason") or "unknown")
        out["by_reason"][key] = out["by_reason"].get(key, 0) + 1

    # 已覆盖用例集合：本任务全部 spec 的 target_endpoint 里的用例名
    covered_cases: set = set()
    try:
        rows = _q(db, "SELECT target_endpoint FROM trigger_specs WHERE task_id=?",
                  (task_id,)) or []
        for row in rows:
            cs = _case_from_text(str(row.get("target_endpoint") or ""))
            if cs:
                covered_cases.add(cs)
    except Exception as _e:
        logger.warning("[missing_route_watch] 读取已覆盖用例失败（观测面降级）：%s", _e)

    for r in watch_items:
        vhash = str(r.get("vulnerability_hash_v2") or "")
        item = {
            "vulnerability_hash_v2": vhash,
            "family": r.get("family"),
            "reason": r.get("reason"),
            "case": "",
            "file": "",
        }
        # 用例名兜底链：reason 自带 file
        # → findings 表回查（仅离线补录历史任务时可用）→ reason 里的 route
        case = ""
        file_path = str(r.get("file") or "")
        if not file_path:
            try:
                frow = _q(db,
                          "SELECT file_path FROM findings WHERE task_id=? AND vulnerability_hash_v2=? LIMIT 1",
                          (task_id, vhash), one=True)
                file_path = str((frow or {}).get("file_path") or "")
            except Exception:
                file_path = ""
        item["file"] = file_path
        case = _case_from_text(file_path)
        item["case"] = case or _case_from_text(str(r.get("route") or ""))
        if not item["case"]:
            out["cross_file"].append(item)
            continue
        if item["case"] in covered_cases:
            out["covered_dropped"] += 1
            continue
        out["true_miss"].append(item)
    logger.info(
        "[missing_route_watch] task=%s watch=%d covered_dropped=%d true_miss=%d cross_file=%d",
        task_id, out["watch_total"], out["covered_dropped"], len(out["true_miss"]),
        len(out["cross_file"]),
    )
    return out


def backfill_via_servlet_self(db, task_id: int, true_miss_item: Dict[str, Any],
                              resolve_fn, register_fn) -> bool:
    """E-2 定向回填钩子：对真漏报子集用 servlet 自注解（@WebServlet）回填路由并登记 spec。

    仅对 item 里给出 file 且文件确有 @WebServlet 的条目生效；绝不触发 A2 全量重跑。
    resolve_fn=param_resolver.servlet_self_endpoint，register_fn=调用方提供的登记入口。
    当前主链路的回填在 trigger_spec_registry 登记端兜底（reject 前最后尝试），
    本函数供离线补录历史任务时使用。
    """
    file_path = str(true_miss_item.get("file") or "")
    if not file_path:
        return False
    try:
        resolved = resolve_fn(file_path)
    except Exception:
        return False
    if not resolved or not resolved.get("route"):
        return False
    try:
        register_fn(true_miss_item, resolved)
        logger.info("[missing_route_watch] 定向回填 %s -> %s", true_miss_item.get("case"),
                    resolved.get("route"))
        return True
    except Exception as _e:
        logger.warning("[missing_route_watch] 定向回填登记失败（忽略）：%s", _e)
        return False
