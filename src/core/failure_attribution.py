"""D2 失败归因（failure_attribution）—— 「未确认」的四值判责（2026-10-03 M1）。

为什么要这一列
--------------
旧口径里 ``no_evidence`` / ``unconfirmed`` 是一个大杂烩：探针没插桩、spec 压根
没被重放、靶场环境根本不支持、以及「真的打不通」全落在同一个桶里。于是任何
一次改进都无法判断自己到底修了什么 —— 判据改了，数字动了，但不知道动的是哪
一类。归因列把「未确认」按**责任归属**劈成四类：

    env_unsupported    环境不支持（L_exploit 层打不通，但 L_code 层缺陷仍在）。
                       不是检测失败，应从「漏检」里摘出去。典型：Tomcat 高版本
                       sanitize 响应头 ⇒ CRLF 无法在运行时打通；靶场 D2 期停服。
    probe_not_covered  探针没覆盖到该 sink（插桩清单里没有这个 sink / 探针不可用）。
                       是探针侧的活，不是判据的活。
    pipeline_gap       流水线自身缺口：spec 从未进入重放、无注入点、被 canonical
                       组吸收从未重放、差分族缺 victim 资源/双账号等必需输入。
                       是调度/构造侧的活。
    true_miss          重放跑了、探针覆盖了、环境也支持，就是没打通。
                       这才是真正需要改判据/换弹药的那一类。

判定顺序（先判「不是我们的锅」，剩下的才是 true_miss）
------------------------------------------------------
env → probe → pipeline → true_miss。顺序不可颠倒：环境不支持时 probe/pipeline
信号本身不可信（靶场都停服了，读什么都是 no-arrival）。

未知一律 fail-open 归 ``true_miss``：宁可高估自己的责任，不可把真漏检藏进
「环境不支持」里自我安慰。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

ENV_UNSUPPORTED = "env_unsupported"
PROBE_NOT_COVERED = "probe_not_covered"
PIPELINE_GAP = "pipeline_gap"
TRUE_MISS = "true_miss"

ALL_CLASSES = (ENV_UNSUPPORTED, PROBE_NOT_COVERED, PIPELINE_GAP, TRUE_MISS)

# 视为「非失败」的终态（已确认 / 已裁决可解释），不需要归因
_POSITIVE_STATUS = frozenset({
    "confirmed_exploitable", "exploitable", "confirmed_sink_control",
    "confirmed_code_property", "filtered_not_exploitable",
})
# 靶场自身不可用：不是漏洞打不通，是场地没了
_INVALID_STATUS = frozenset({"invalidated"})

# 探针侧缺覆盖的显式 iast_state（Q8 落地后由探针覆盖清单产出）
_PROBE_GAP_STATES = frozenset({
    "probe_not_instrumented",
    "probe_unavailable",
})
# 投放侧 / 调度侧缺口：canary 从未发出去
_PIPELINE_GAP_STATES = frozenset({
    "no-injectable-param",   # spec 没解析出可注入参数 ⇒ canary 从未投放
    "no-iast-sink",          # 该类 IAST 语义下无 sink 可断言 ⇒ 需换通道，非探针缺陷
})
# 已抵达 sink（用于把 true_miss 再细读：抵达却证不成 vs 压根没抵达）
_ARRIVED_STATES = frozenset({
    "sink-reached", "sink-reached-probe", "iast-reached",
    "business-logic-confirmed", "business-side-effect-confirmed",
    "arrival-sanitized",
})

# 需要「双主体 / 受害者资源」才能下结论的差分族（语义差分通道）
_DIFFERENTIAL_FAMILIES = frozenset({
    "bola", "idor", "vertical_privesc", "horizontal_privesc",
    "business_logic", "state_machine",
})


# iast_state 常被 D2 的后处理加上前缀（确认硬闸 / 族路由改判）。归因时要**剥掉前缀**
# 再比状态，否则 'confirm-gate:no-arrival' 会被当成未知态直接掉进 true_miss，把
# 「探针没覆盖」误记成「打不通」（实测 run 50 有 36 条正是此形态）。
_STATE_PREFIXES = ("confirm-gate:", "family-route:")


def _normalize_iast_state(state: str) -> Tuple[str, str]:
    """返回 (基础态, 前缀标签)。无前缀时标签为空。"""
    s = str(state or "").strip()
    for p in _STATE_PREFIXES:
        if s.startswith(p):
            return s[len(p):].strip(), p.rstrip(":")
    return s, ""


def _load_raw(raw_json: Any) -> Dict[str, Any]:
    if isinstance(raw_json, dict):
        return raw_json
    try:
        d = json.loads(raw_json or "{}")
    except Exception:
        return {}
    return d if isinstance(d, dict) else {}


def classify(
    spec: Dict[str, Any],
    facts: Optional[Dict[str, Any]] = None,
    env_premise: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """给一条 trigger_spec 的「未确认」结果归因。

    参数：
        spec        trigger_specs 行（dict），至少含 verification_status/iast_state/raw_json
        facts       运行时事实（runtime_facts.collect_facts()）
        env_premise 该族/该黄金条目的环境前提（可空）

    返回 ``(cls, reason)``；已确认的 spec 返回 ``("", "")``。
    """
    if not isinstance(spec, dict):
        return "", ""
    status = str(spec.get("verification_status") or "").strip()
    if status in _POSITIVE_STATUS:
        return "", ""
    iast_state, _gate = _normalize_iast_state(spec.get("iast_state"))
    raw = _load_raw(spec.get("raw_json"))

    # ---- 1) 环境层：靶场自己没了 / 前提明确不满足 ----
    if status in _INVALID_STATUS:
        return ENV_UNSUPPORTED, "target_unhealthy_or_invalidated"
    if env_premise:
        try:
            from src.core.env_premise import check_premise, UNSATISFIED
            state, reason = check_premise(env_premise, facts)
            if state == UNSATISFIED:
                return ENV_UNSUPPORTED, f"env_premise:{reason}"
        except Exception:  # fail-open：归因失败不该中断 D2
            logger.debug("[failure_attribution] env_premise 判定异常（忽略）", exc_info=True)

    # ---- 2) 探针侧：没插桩 / 不可用 ----
    if iast_state in _PROBE_GAP_STATES:
        return PROBE_NOT_COVERED, f"iast_state={iast_state}"
    _cov = raw.get("d2_evidence") if isinstance(raw.get("d2_evidence"), dict) else {}
    _cov_state = str(_cov.get("probe_coverage") or "").strip()
    if _cov_state in ("not_instrumented", "unavailable"):
        return PROBE_NOT_COVERED, f"probe_coverage={_cov_state}"

    # ---- 3) 流水线侧：从未重放 / 无注入点 / 被吸收 / 差分族缺输入 ----
    kind = str(raw.get("unverified_kind") or "").strip()
    if kind == "never_replayed":
        return PIPELINE_GAP, "never_replayed: spec 从未进入 D2 重放"
    if iast_state in _PIPELINE_GAP_STATES:
        return PIPELINE_GAP, f"iast_state={iast_state}"
    if raw.get("is_absorbed") is True:
        return PIPELINE_GAP, "absorbed_by_canonical_group: 吸收成员未独立重放"
    if not str(spec.get("target_endpoint") or "").strip():
        return PIPELINE_GAP, "empty_target_endpoint"
    fam = str(spec.get("family") or spec.get("category") or "").strip().lower()
    if fam in _DIFFERENTIAL_FAMILIES:
        if not str(spec.get("victim_resource_id") or "").strip():
            return PIPELINE_GAP, "differential_family_missing_victim_resource_id"
        try:
            accounts = json.loads(spec.get("accounts_json") or "[]")
        except Exception:
            accounts = []
        if not isinstance(accounts, list) or len(accounts) < 2:
            return PIPELINE_GAP, "differential_family_missing_dual_accounts"

    # ---- 4) 剩下的才是真漏检 ----
    # 到这一步说明：重放跑了、探针覆盖了、环境也支持，就是没打通。
    # reason 里保留「是否抵达 sink」—— 抵达了却证不成（判据/弹药问题）与压根没抵达
    # （投放/路由问题）是两种要分别攻的方向，不能只给一个数字。
    _arrived = iast_state in _ARRIVED_STATES
    _bits = [f"status={status or 'empty'}", f"iast_state={iast_state or 'empty'}"]
    if _gate:
        _bits.append(f"gate={_gate}")
    _bits.append("arrived_sink=yes" if _arrived else "arrived_sink=no")
    return TRUE_MISS, ";".join(_bits)


def classify_many(
    specs,
    facts: Optional[Dict[str, Any]] = None,
    premise_by_family: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """批量归因，返回 ``{"counts": {...}, "rows": [{id, cls, reason}]}``。

    ``premise_by_family``：族名 → env_premise，供环境层判定。
    """
    counts = {c: 0 for c in ALL_CLASSES}
    rows = []
    premise_by_family = premise_by_family if isinstance(premise_by_family, dict) else {}
    for s in specs or []:
        if not isinstance(s, dict):
            # sqlite3.Row / 具名元组：转成 dict 再判，避免漏掉整批
            try:
                s = dict(s)
            except Exception:
                continue
        if not isinstance(s, dict):
            continue
        fam = str(s.get("family") or "").strip().lower()
        cls, reason = classify(s, facts, premise_by_family.get(fam))
        if not cls:
            continue
        counts[cls] = counts.get(cls, 0) + 1
        rows.append({"id": s.get("id"), "family": fam, "class": cls, "reason": reason})
    return {"counts": counts, "rows": rows}


# ── 阶段层归因（2026-11-04）：回答「卡在流水线哪一层」 ──
#
# 与上方 classify() 的分工：
#   failure_attribution（四类）＝「该谁修」——env/probe/pipeline/true_miss
#   failure_attribution_layer ＝「卡在哪层」——spec/replay/verdict/iast
#
# 为什么要这一列：四层是串联的，任何一层断了，最终症状都是
# verification_status != confirmed。旧口径只记 true_miss，导致每轮都要人工回查
# attempt/iast_state 才能判断责任层（2026-11-04 jsc 615 的 10 个未覆盖点就是这样
# 逐点人工归因的）。有了这一列，一次 GROUP BY 就能看到水位在哪一层。
LAYER_SPEC = "layer1_spec"        # A2 未产出可投载荷 / 未产出 spec
LAYER_REPLAY = "layer2_replay"    # D1 未发请求、路由错（4xx/5xx）、零重放
LAYER_VERDICT = "layer3_verdict"  # canary 已到 sink，D2 判据未确认
LAYER_IAST = "layer4_iast"        # 已重放且有载荷，canary 未到 sink（观测/链路）

ALL_LAYERS = (LAYER_SPEC, LAYER_REPLAY, LAYER_VERDICT, LAYER_IAST)

# 视为「已到 sink」的态：这些态下证据已经在我方 sink 上出现，问题在判据
_LAYER_SINK_REACHED = frozenset({
    "sink-reached", "sink_reached", "sink-reached-probe", "sink_reached_probe",
    "technique-proven", "confirm-gate:technique-proven",
})
# 已重放但 canary 没到：观测或链路问题
_LAYER_NO_ARRIVAL = frozenset({
    "no-arrival", "no_arrival", "arrival-sanitized", "arrival_sanitized",
})
# 载荷不可用：A2 没给弹药，D1 拒绝投假弹（设计如此，不是 D1 缺陷）
_LAYER_NO_PAYLOAD = frozenset({"payload_unavailable"})

# 这些族的「载荷」本来就是请求本身，不要求 replay_attempts.payload 非空。
# csrf：不带 token 的状态变更请求就是攻击载荷，D1 发的就是空 payload 的 POST；
# 旧逻辑把它记成「A2 未产出可投弹药」，jsc 617 spec 237772 就是这样被误归
# layer1_spec 的（同一 spec 的 6 次重放其实已把 `CSRF passed.` 打出来了）。
_PAYLOAD_OPTIONAL_FAMILIES = frozenset({"csrf"})


def classify_layer(
    spec: Dict[str, Any],
    attempts: Optional[Any] = None,
) -> Tuple[str, str]:
    """给一条未确认 spec 判定「卡在哪一层」，返回 ``(layer, reason)``。

    参数：
        spec      trigger_specs 行（dict）：verification_status / iast_state /
                  failure_attribution / raw_json
        attempts  该 spec 的 replay_attempts 列表（dict，至少含 status_code）；
                  传 None 表示「未查询」，此时跳过 layer2 的零重放判定，
                  避免把「没查」误判成「没发」。

    判定顺序严格按流水线先后：spec → replay → verdict → iast。
    已确认的 spec 返回 ``("", "")``。
    """
    if not isinstance(spec, dict):
        return "", ""
    status = str(spec.get("verification_status") or "").strip()
    if status in _POSITIVE_STATUS:
        return "", ""
    iast_state, _gate = _normalize_iast_state(spec.get("iast_state"))
    fa = str(spec.get("failure_attribution") or "").strip()

    # 1) 载荷层：A2 没产出弹药
    if iast_state in _LAYER_NO_PAYLOAD or fa == "no_payload_synthesized":
        return LAYER_SPEC, "A2 未产出可投载荷（D1 按设计拒绝投假弹，请求未发出）"

    _atts = [a for a in attempts if isinstance(a, dict)] if attempts is not None else None
    _fam = str(spec.get("family") or "").strip().lower()
    _payload_optional = _fam in _PAYLOAD_OPTIONAL_FAMILIES
    # 「有实投载荷」= 至少一次 attempt 带了非空 payload。
    # 注意 attack_payloads_json 为空**不等于**没弹药：多数族走 payload_library 内置生成器，
    # 该字段本就为空，真载荷在 replay_attempts 里（2026-11-04 修正，避免把 55 条
    # 有实投载荷的 spec 误判成 layer1）。
    _real_payload = bool(_atts) and any(str(a.get("payload") or "").strip() for a in _atts)
    if not _real_payload and not _payload_optional and iast_state not in _LAYER_SINK_REACHED:
        _pay_raw = str(spec.get("attack_payloads_json") or "").strip()
        _declared = _pay_raw not in ("", "[]", "null", "{}")
        if not _declared:
            return LAYER_SPEC, "无弹药（attack_payloads 空且无实投载荷，D1 无内容可投）"

    # 2) D1 重放层：没发 / 发了但全部非 2xx-3xx
    if _atts is not None:
        if not _atts:
            return LAYER_REPLAY, "零重放：该 spec 从未发出请求"
        if not _real_payload and not _payload_optional:
            return LAYER_SPEC, "已发出但全部空载荷（A2 未产出可投弹药）"
        codes = [a.get("status_code") for a in _atts]
        codes_int = [c for c in codes if isinstance(c, int)]
        reachable = [c for c in codes_int if 200 <= c < 400]
        if codes_int and not reachable:
            return LAYER_REPLAY, "重放全部非 2xx/3xx（路由或可达性）status=%s" % sorted(set(codes_int))

    # 3) D2 判据层：证据到了 sink，但没确认
    if iast_state in _LAYER_SINK_REACHED:
        return LAYER_VERDICT, "canary 已到 sink，D2 判据未确认（iast_state=%s）" % iast_state

    # 4) I1 观测层：发了、有载荷，canary 没到
    if iast_state in _LAYER_NO_ARRIVAL:
        return LAYER_IAST, "已重放但 canary 未到 sink（观测/链路，iast_state=%s）" % iast_state

    # 其余（no-iast-evidence / 空态）：证据缺失，归观测层（最保守，不当判据问题）
    return LAYER_IAST, "无有效 IAST 证据（iast_state=%s）" % (iast_state or "空")


def classify_layers(
    specs,
    attempts_by_spec: Optional[Dict[Any, Any]] = None,
) -> Dict[str, Any]:
    """批量阶段归因，返回 ``{"counts": {layer: n}, "rows": [...]}``。

    ``attempts_by_spec``：spec_id → replay_attempts 列表；缺省时跳过 layer2 判定。
    """
    counts = {layer: 0 for layer in ALL_LAYERS}
    rows = []
    attempts_by_spec = attempts_by_spec if isinstance(attempts_by_spec, dict) else {}
    for s in specs or []:
        if not isinstance(s, dict):
            try:
                s = dict(s)
            except Exception:
                continue
        sid = s.get("id")
        layer, reason = classify_layer(s, attempts_by_spec.get(sid))
        if not layer:
            continue
        counts[layer] = counts.get(layer, 0) + 1
        rows.append({"id": sid, "family": str(s.get("family") or ""),
                     "layer": layer, "reason": reason})
    return {"counts": counts, "rows": rows}


def golden_premise_map(workspace_name: str = "") -> Dict[str, Any]:
    """从黄金集反查「族 token → env_premise」，供批量归因使用。

    fail-open：拿不到黄金集（未识别靶场 / 导入失败）返回空 dict，归因退化为
    「不看环境前提」，只是少判一类，不会误判。
    """
    out: Dict[str, Any] = {}
    try:
        from src.api.routers.round_report import GOLDEN_SETS
        low = str(workspace_name or "").lower()
        picked = None
        for key, golden in GOLDEN_SETS.items():
            if key in low:
                picked = golden
                break
        # 未识别靶场时不猜：空前提意味着「不因环境剔除任何条目」，是最保守的选择
        if not picked:
            return out
        for entry in picked or []:
            if len(entry) < 6:
                continue
            _premise, _tokens = entry[5], entry[3]
            if not _premise:
                continue
            for t in (_tokens or []):
                out.setdefault(str(t).lower(), _premise)
    except Exception:  # pragma: no cover
        logger.debug("[failure_attribution] 黄金前提表加载失败（退化为无前提）", exc_info=True)
    return out


def attribute_task(db, task_id: Any, premise_by_family: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """对某 task 的全部 spec 做一次批量归因并写回 failure_attribution 列。

    放在 D2 终态落定**之后**跑（此时 verification_status / iast_state / raw_json 都是
    最终态），这样归因读到的是结论而不是中间态。fail-open：任何异常都不阻断 D2。
    """
    if db is None or task_id is None:
        return {"counts": {}, "written": 0}
    try:
        if premise_by_family is None:
            _ws = ""
            try:
                rows = db.execute(
                    "SELECT w.name FROM scan_tasks t LEFT JOIN workspaces w ON t.workspace_id=w.id "
                    "WHERE t.id=?", (int(task_id),), fetchall=True) or []
                if rows:
                    _r = rows[0]
                    _ws = (_r.get("name") if isinstance(_r, dict) else _r[0]) or ""
            except Exception:
                _ws = ""
            premise_by_family = golden_premise_map(_ws)
        rows = db.execute(
            "SELECT id, family, target_endpoint, verification_status, iast_state, raw_json, "
            "accounts_json, victim_resource_id, failure_attribution, attack_payloads_json "
            "FROM trigger_specs WHERE task_id=?",
            (int(task_id),), fetchall=True) or []
        specs = [dict(r) if isinstance(r, dict) else {
            "id": r[0], "family": r[1], "target_endpoint": r[2], "verification_status": r[3],
            "iast_state": r[4], "raw_json": r[5], "accounts_json": r[6],
            "victim_resource_id": r[7], "failure_attribution": r[8],
            "attack_payloads_json": r[9] if len(r) > 9 else "",
        } for r in rows]
        res = classify_many(specs, None, premise_by_family)
        # 阶段层归因（2026-11-04）：同时算「卡在哪层」，与责任归属并列写入。
        # 需要 replay_attempts 才能判 layer2（零重放/路由不通），故单独查一次。
        _att_map: Dict[Any, Any] = {}
        try:
            _arows = db.execute(
                "SELECT spec_id, status_code, payload FROM replay_attempts WHERE task_id=?",
                (int(task_id),), fetchall=True) or []
            for _a in _arows:
                if isinstance(_a, dict):
                    _sid, _code, _pay = _a.get("spec_id"), _a.get("status_code"), _a.get("payload")
                else:
                    _sid = _a[0]
                    _code = _a[1] if len(_a) > 1 else None
                    _pay = _a[2] if len(_a) > 2 else ""
                # payload 必须带上：阶段层要靠「是否有实投载荷」区分 layer1/layer2，
                # 只传 status_code 会让所有 spec 都被判成「无弹药」（2026-11-04 踩过）。
                _att_map.setdefault(_sid, []).append(
                    {"status_code": _code, "payload": _pay})
        except Exception as _ae:
            logger.debug("[failure_attribution] 查 replay_attempts 失败（layer2 降级跳过）：%s", _ae)
        lres = classify_layers(specs, _att_map)
        _cls_by = {r.get("id"): (r.get("class"), r.get("reason")) for r in res["rows"]}
        _lay_by = {r.get("id"): (r.get("layer"), r.get("reason")) for r in lres["rows"]}
        written = 0
        for _sid in set(_cls_by) | set(_lay_by):
            _c, _cr = _cls_by.get(_sid, ("", ""))
            _l, _lr = _lay_by.get(_sid, ("", ""))
            if persist(db, _sid, _c, _cr, _l, _lr):
                written += 1
        res["layer_counts"] = lres["counts"]
        res["written"] = written
        res["total_specs"] = len(specs)
        logger.info(
            "[failure_attribution] task=%s 归因完成：责任=%s 层=%s（写入 %d/%d 条 spec）",
            task_id, res["counts"], lres["counts"], written, len(specs),
        )
        return res
    except Exception as _e:
        logger.warning("[failure_attribution] task=%s 批量归因失败（忽略）：%s", task_id, _e)
        return {"counts": {}, "written": 0}


def persist(db, spec_id: Any, cls: str, reason: str = "",
            layer: str = "", layer_reason: str = "") -> bool:
    """把归因写回 trigger_specs（列不存在时静默跳过）。

    同时写两列：
      failure_attribution*       责任归属（env/probe/pipeline/true_miss）
      failure_attribution_layer* 阶段层（spec/replay/verdict/iast，2026-11-04 新增）
    layer 为空时只写旧列，保持向后兼容。
    """
    if db is None or not spec_id or (not cls and not layer):
        return False
    try:
        if layer:
            db.execute(
                "UPDATE trigger_specs SET failure_attribution=?, failure_attribution_reason=?, "
                "failure_attribution_layer=?, failure_attribution_layer_reason=? WHERE id=?",
                (str(cls or ""), str(reason)[:500], str(layer),
                 str(layer_reason)[:500], int(spec_id)),
            )
        else:
            db.execute(
                "UPDATE trigger_specs SET failure_attribution=?, failure_attribution_reason=? WHERE id=?",
                (str(cls), str(reason)[:500], int(spec_id)),
            )
        return True
    except Exception as _e:
        # 列尚未迁移（旧库）时退回只写旧列，绝不因新列缺失而丢归因
        if layer:
            try:
                db.execute(
                    "UPDATE trigger_specs SET failure_attribution=?, failure_attribution_reason=? WHERE id=?",
                    (str(cls or ""), str(reason)[:500], int(spec_id)),
                )
                return True
            except Exception:
                pass
        logger.debug("[failure_attribution] 写回失败（列可能尚未迁移）：%s", _e)
        return False
