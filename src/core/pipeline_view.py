"""pipeline 阶段 -> 具体任务清单。

背景：前端 TaskDetailPage 总览原用「阶段卡片」（只有阶段名 / 状态 / 一句话释义 /
前 3 个指标），用户看不出每个阶段究竟在做什么具体任务。本模块把各阶段**已产出**的
细粒度数据统一成任务清单结构，供前端把卡片替换为「阶段头 + 可展开任务列表」。

数据结构（挂在 pipeline[stage]["tasks"]）：
    {"total": N, "items": [{"name": str, "status": str, "detail": str}, ...]}

items 最多 MAX_TASKS_PER_STAGE 条——pipeline 会随 task_progress 事件每秒推送一次，
因此只回传前若干条代表性任务 + 总数，前端按需「查看全部」。

数据来源口径：优先用已落库的细粒度数组（attack_plan.entries / d1.replayed_specs_detail /
d2.verifications_detail / i2.closed_loop.history / i2.feedback_to_a2）；只有聚合计数的
阶段（a1 / a2 / sca / i1 / reporting 等）如实给聚合条目，不伪造逐条明细。
"""
from typing import Any, Dict, List, Optional

MAX_TASKS_PER_STAGE = 8

# 前端 TASK_STAGE_ORDER 的全集（含 i1/i2/a2_poc；后端实时 pipeline 原本缺 i1/i2）。
ALL_STAGE_KEYS = (
    "preprocess", "sca", "a1", "a2", "a2_poc", "entry_discovery", "ai_review",
    "attack_plan", "d1", "i1", "d2", "i2", "reporting",
)

_TERMINAL_OK = {
    "completed", "complete", "done", "ok", "success", "passed", "pass",
    "confirmed", "exploitable", "verified", "replay_done", "replay_reconciled",
    "reconciled", "closed", "healthy",
    # 缺这些会让已确认的条目被误判成 pending（实测 attack_plan 55 条 confirmed_exploitable
    # 全显示 pending）。
    "confirmed_exploitable", "confirmed_attributable", "runtime_confirmed",
    "business_confirmed", "d2_confirmed", "observed",
    "business-logic-confirmed", "sink-reached-probe", "iast-reached",
    # 110 条 D2 验证里 66 条 no_evidence 全画成待处理灰点，看起来像 D2 只做了 44 条。
    # 结论本身由 detail 的「有害 / 无害 / 置信」承载，状态点只回答「跑没跑完」。
    # unconfirmed 保持 pending（确属未确认，不是裁决终态）。
    "no_evidence", "ambiguous",
}
_TERMINAL_RUN = {
    "running", "in_progress", "replaying", "processing", "active", "started", "verifying",
}
_TERMINAL_BAD = {
    "failed", "error", "refuted", "blocked", "unhealthy", "target_unhealthy", "aborted",
    # 归入「非完成」桶，避免前端把它画成已完成绿点。
    "invalidated",
}


def _task(name: str, status: str = "completed", detail: str = "") -> Dict[str, Any]:
    return {"name": str(name or "").strip(), "status": status, "detail": str(detail or "").strip()}


def _pack(items: List[Dict[str, Any]], total: int) -> Dict[str, Any]:
    return {"total": int(total or 0), "items": list(items)[:MAX_TASKS_PER_STAGE]}


def _norm_status(value: Any) -> str:
    """把各阶段五花八门的状态值归一到 completed / running / pending / failed。"""
    s = str(value or "").strip().lower()
    if not s:
        return "pending"
    if s in _TERMINAL_OK:
        return "completed"
    if s in _TERMINAL_RUN:
        return "running"
    if s in _TERMINAL_BAD:
        return "failed"
    if s in ("skipped", "no_arrival", "not_run", "unknown", "open", "missing"):
        return "pending"
    # 未知状态一律按 pending，避免把真实运行中的阶段显示成已完成。
    return "pending"


def _best_status(*values: Any) -> str:
    """多级状态字段取「最优确认态」。

    runtime_status=d2_confirmed（最终裁决未闭环，但运行时已确认）。若只取第一个字段，
    已确认的条目会被误判成 pending。故依次找确认态 -> 失败态 -> 运行态，都没有才 pending。
    """
    norms = [_norm_status(v) for v in values]
    for s in norms:
        if s == "completed":
            return "completed"
    for s in norms:
        if s == "failed":
            return "failed"
    for s in norms:
        if s == "running":
            return "running"
    return "pending"


def _endpoint_text(d: Dict[str, Any]) -> str:
    ep = d.get("endpoint") or ""
    method = d.get("http_method") or d.get("method") or ""
    param = d.get("param_name") or d.get("param") or ""
    loc = d.get("param_location") or d.get("location") or ""
    head = " ".join([x for x in (method, ep) if x]).strip()
    if param:
        head += f" · 参数 {param}" + (f"({loc})" if loc else "")
    return head.strip(" ·")


# ---------- 逐条明细阶段（后端已产出细粒度数组） ----------

def _tasks_attack_plan(sr: Dict[str, Any]) -> Dict[str, Any]:
    ap = sr.get("attack_plan") or {}
    entries = [e for e in (ap.get("entries") or []) if isinstance(e, dict)]
    items = []
    for e in entries:
        fam = e.get("family") or ""
        detail_parts = [fam]
        if e.get("flow_type"):
            detail_parts.append(str(e["flow_type"]))
        if e.get("candidate_payload_count") is not None:
            detail_parts.append(f"{e['candidate_payload_count']} 载荷")
        if e.get("runtime_status"):
            detail_parts.append(f"运行时 {e['runtime_status']}")
        items.append(_task(
            _endpoint_text(e) or fam or "攻击计划条目",
            _best_status(e.get("verification_status"), e.get("runtime_status"), "completed"),
            " · ".join([p for p in detail_parts if p]),
        ))
    return _pack(items, len(entries) or int(ap.get("plan_count") or 0))


def _tasks_d1(sr: Dict[str, Any]) -> Dict[str, Any]:
    d = sr.get("d1") or {}
    det = [x for x in (d.get("replayed_specs_detail") or []) if isinstance(x, dict)]
    items = []
    for s in det:
        fam = s.get("family") or ""
        detail = " · ".join([p for p in (fam, f"来源 {s.get('source')}" if s.get("source") else "") if p])
        items.append(_task(_endpoint_text(s) or fam or "重放条目", "completed", detail))
    return _pack(items, len(det) or int(d.get("candidate_count") or 0))


def _tasks_d2(sr: Dict[str, Any]) -> Dict[str, Any]:
    d = sr.get("d2") or {}
    det = [x for x in (d.get("verifications_detail") or []) if isinstance(x, dict)]
    items = []
    for v in det:
        name = v.get("endpoint") or v.get("type") or v.get("family") or "验证条目"
        harmful = v.get("d2_harmful")
        parts = [v.get("family") or ""]
        if harmful is True:
            parts.append("有害")
        elif harmful is False:
            parts.append("无害")
        if v.get("d2_confidence") is not None:
            parts.append(f"置信 {v['d2_confidence']}")
        detail = " · ".join([p for p in parts if p])
        # 不用 iast_state 参与取优：no_evidence 是裁决结论（未证可利用），
        # 仅 IAST 到达 sink 不足以推翻它，否则会把「观测到但未证实」显示成已完成。
        items.append(_task(name, _best_status(v.get("final_state"), v.get("verification_status")), detail))
    return _pack(items, len(det) or int(d.get("verified_count") or 0))


def _tasks_i2(sr: Dict[str, Any]) -> Dict[str, Any]:
    """I2 的任务 = 闭环每一轮 + 每条回灌反馈（用户要看的就是这个循环）。"""
    i2 = sr.get("i2") or {}
    history = [h for h in ((i2.get("closed_loop") or {}).get("history") or []) if isinstance(h, dict)]
    items = []
    for h in history:
        routed = h.get("routed") or {}
        routed_text = "、".join(f"{k} {v}" for k, v in routed.items()) if routed else "无分流"
        items.append(_task(
            f"第 {h.get('iteration', '?')} 轮闭环",
            "completed",
            f"A2 重研判 {h.get('a2_feedback', 0)} 条、重放调整 {h.get('replay_adjustments', 0)} 条"
            f"；分流 {routed_text}；增益 {h.get('gain', 0)}",
        ))
    fbs = [f for f in (i2.get("feedback_to_a2") or []) if isinstance(f, dict)]
    for f in fbs:
        reason = str(f.get("reason") or "")
        items.append(_task(
            f"回灌 A2：{f.get('failure_class') or f.get('final_state') or 'feedback'}",
            "completed",
            (reason[:180] + ("…" if len(reason) > 180 else "")),
        ))
    return _pack(items, len(history) + len(fbs))


# ---------- 聚合阶段（后端当前只产出计数，如实聚合不伪造明细） ----------

def _tasks_preprocess(sr: Dict[str, Any]) -> Dict[str, Any]:
    p = sr.get("preprocess") or {}
    items = [
        _task("扫描项目文件", "completed", f"{p.get('file_count', 0)} 个文件"),
        _task("索引函数", "completed", f"{p.get('indexed_functions', 0)} 个"),
        _task("识别 HTTP 入口", "completed",
              f"{p.get('http_entries', 0)} 个入口 / {p.get('endpoint_count', 0)} 个端点"),
    ]
    return _pack(items, len(items))


def _tasks_sca(sr: Dict[str, Any]) -> Dict[str, Any]:
    s = sr.get("sca") or {}
    items = [
        _task("识别组件", "completed", f"{s.get('component_count', 0)} 个"),
        _task("组件漏洞命中", "completed", f"{s.get('vulnerability_count', 0)} 条"),
        _task("SCA 工具", "completed", str(s.get("tool") or "-")),
    ]
    return _pack(items, len(items))


def _tasks_a1(sr: Dict[str, Any]) -> Dict[str, Any]:
    a = sr.get("a1") or {}
    items = [_task("规则扫描产出", "completed", f"{a.get('finding_count', 0)} 条 findings")]
    return _pack(items, len(items))


def _tasks_a2(sr: Dict[str, Any], progress: Dict[str, Any]) -> Dict[str, Any]:
    a = sr.get("a2") or {}
    items = []
    ap = (progress or {}).get("a2_progress") or {}
    if ap:
        items.append(_task("语义分析文件", _norm_status(ap.get("status") or "running"),
                           f"{ap.get('done', 0)}/{ap.get('total', 0)} 个文件"))
    items.append(_task("A2 产出 findings", "completed", f"{a.get('finding_count', 0)} 条"))
    return _pack(items, len(items))


def _tasks_a2_poc(sr: Dict[str, Any], progress: Dict[str, Any]) -> Dict[str, Any]:
    p = sr.get("a2_poc") or {}
    pp = (progress or {}).get("a2_poc_progress") or {}
    items = []
    if pp:
        items.append(_task("PoC 规划", _norm_status(pp.get("status") or "running"),
                           f"{pp.get('done', 0)}/{pp.get('total', 0)}"))
    items.append(_task("登记 TriggerSpec", "completed",
                       f"{p.get('registered_trigger_specs', 0)} 条，跳过 {p.get('skipped_specs', 0)} 条"))
    return _pack(items, len(items))


def _tasks_entry_discovery(sr: Dict[str, Any]) -> Dict[str, Any]:
    e = sr.get("entry_discovery") or {}
    items = [
        _task("入口发现", "completed", f"{e.get('entry_count', 0)} 个入口"),
        _task("规则候选", "completed", f"{e.get('rule_candidate_count', 0)} 条"),
    ]
    return _pack(items, len(items))


def _tasks_ai_review(sr: Dict[str, Any]) -> Dict[str, Any]:
    r = sr.get("ai_review") or {}
    items = [
        _task("AI 复核", "completed", f"{r.get('ai_review_total', 0)} 条"),
        _task("自动关闭候选", "completed", f"{r.get('auto_close_candidates', 0)} 条"),
    ]
    return _pack(items, len(items))


def _tasks_i1(sr: Dict[str, Any], progress: Dict[str, Any]) -> Dict[str, Any]:
    """I1 链路监听器：无独立 stage_results，如实取 IAST 到达数（来自 d1）。"""
    d = sr.get("d1") or {}
    arrivals = d.get("iast_arrivals", 0)
    rp = (progress or {}).get("replay_progress") or {}
    items = [_task("IAST 运行时观测", "completed", f"{arrivals} 条到达")]
    if rp:
        items.append(_task("链路监听", _norm_status(rp.get("status") or "running"),
                           f"sink 到达 {rp.get('sink_reached', 0)} / 重放 {rp.get('replayed', 0)}"))
    return _pack(items, len(items))


def _tasks_reporting(sr: Dict[str, Any], progress: Dict[str, Any]) -> Dict[str, Any]:
    r = sr.get("reporting") or {}
    rp = (progress or {}).get("reporting") or {}
    items = [_task("生成报告", _norm_status(rp.get("status") or ("completed" if r.get("report_count") else "pending")),
                   f"{r.get('report_count', 0)} 份")]
    return _pack(items, len(items))


_BUILDERS = {
    "preprocess": lambda sr, pg: _tasks_preprocess(sr),
    "sca": lambda sr, pg: _tasks_sca(sr),
    "a1": lambda sr, pg: _tasks_a1(sr),
    "a2": _tasks_a2,
    "a2_poc": _tasks_a2_poc,
    "entry_discovery": lambda sr, pg: _tasks_entry_discovery(sr),
    "ai_review": lambda sr, pg: _tasks_ai_review(sr),
    "attack_plan": lambda sr, pg: _tasks_attack_plan(sr),
    "d1": lambda sr, pg: _tasks_d1(sr),
    "i1": _tasks_i1,
    "d2": lambda sr, pg: _tasks_d2(sr),
    "i2": lambda sr, pg: _tasks_i2(sr),
    "reporting": _tasks_reporting,
}


def build_stage_tasks(stage_key: str, stage_results: Dict[str, Any],
                      progress: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """为单个阶段生成任务清单。未知阶段返回空清单（不报错）。"""
    sr = stage_results or {}
    pg = progress or {}
    fn = _BUILDERS.get(stage_key)
    if not fn:
        return _pack([], 0)
    try:
        return fn(sr, pg)
    except Exception:
        # fail-open：任务清单是展示增强，任何异常都不能影响 pipeline 主流程。
        return _pack([], 0)


def _fallback_progress_tasks(stage_key: str, st: Dict[str, Any]) -> Dict[str, Any]:
    """阶段明细尚未产出时的进度兜底：只用该阶段**自身的真实 metrics/message** 生成条目。

    任务清单来源分别是 ``d2.verifications_detail``（D2 收尾才写）与
    ``i2.closed_loop.history``（闭环每轮收尾才写）。于是整段 D2 跑着的 50 多分钟里，
    前端「阶段任务」显示 0 个任务——正是「运行状态须同步前端」要避免的形态。
    这里不伪造轮次：只把阶段自己已经报出来的计数原样摊成条目（有则显示，无则仍然空）。
    """
    m = st.get("metrics") if isinstance(st.get("metrics"), dict) else {}
    msg = str(st.get("message") or "").strip()
    items: List[Dict[str, Any]] = []
    if stage_key == "d2":
        total = int(m.get("replay_total") or 0)
        if total:
            items.append(_task(
                "重放池排空", "completed",
                "%d/%d（confirmed=%d, sink_reached=%d）" % (
                    int(m.get("replay_replayed") or 0), total,
                    int(m.get("replay_confirmed") or 0), int(m.get("replay_sink_reached") or 0),
                )))
        if "d2_verify_iteration" in m:
            items.append(_task(
                "D2 统一验证 第 %s 轮" % m.get("d2_verify_iteration"),
                _norm_status(m.get("d2_verify_status")),
                "已证可利用 %d 条" % int(m.get("d2_verify_exploitable_count") or 0)))
    elif stage_key == "d1":
        if "candidate_count" in m or "finding_count" in m:
            cand = int(m.get("candidate_count") or 0)
            items.append(_task(
                "重放候选",
                "pending" if cand == 0 else _norm_status(st.get("status")),
                "候选 %d 条、已重放 %d 条" % (cand, int(m.get("replayed_count") or 0))))
    elif stage_key == "i2" and msg:
        # I2 在闭环有 history 之前只回答「在等谁 / 在裁决什么」，不自造轮次
        items.append(_task("闭环裁决", _norm_status(st.get("status")), msg))
    return _pack(items, len(items))


def attach_stage_tasks(pipeline: Dict[str, Dict[str, Any]],
                       progress: Optional[Dict[str, Any]] = None,
                       options: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """给 pipeline 每个阶段挂 tasks，并补齐前端需要但后端实时缺失的 i1 / i2 并发阶段。

    i1 与 d1 并发、i2 与 d2 并发（与 application/task_service.py 的派生口径一致）：
    自身无数据时状态跟随源阶段，避免前端永远显示 pending 空壳。
    """
    pg = progress or {}
    sr = pg.get("stage_results") or {}
    out = dict(pipeline or {})
    for key in ALL_STAGE_KEYS:
        st = out.get(key)
        if not isinstance(st, dict):
            # 该阶段不在实时 pipeline 里（如 scan_task_runner 缺 a2_poc）：有 stage_results
            # 就如实取它的状态，不要一律 pending。
            own_status = (sr.get(key) or {}).get("status")
            st = {"status": str(own_status) if own_status else "pending",
                  "message": "", "metrics": {}}
            out[key] = st
        st["tasks"] = build_stage_tasks(key, sr, pg)
        if not (st["tasks"].get("items") or []):
            # 明细未产出（运行中）时用阶段自身指标摊成进度条目，避免「running + 0 个任务」
            st["tasks"] = _fallback_progress_tasks(key, st)

    # i1 与 d1 并发、i2 与 d2 并发：无自身 stage_results 时状态跟随源阶段。
    for target, source in (("i1", "d1"), ("i2", "d2")):
        tgt = out.get(target) or {}
        src = out.get(source) or {}
        own = (sr.get(target) or {}).get("status")
        if own:
            tgt["status"] = str(own)
        else:
            tgt["status"] = str(src.get("status", "pending"))
        out[target] = tgt
    return out
