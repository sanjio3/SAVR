"""
Unified D2 verification facade.

一条总路径，不分 IAST 模式 / legacy 纯 EXP 双入口：
verify() 运行时即设计层效果，驱动 D1 重放 → I1 逐节点链路符合 → D2 站 sink 立场核实
结果点 → I2 综合裁决五态。iast_service(探针/I1) 与 dast_operator(D1) 由 verify() 内部
按 DB 构造，调用方无需感知「模式」。不存在 legacy 回落分支。
"""
import json
import logging
import os
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .d2_types import VerificationResult
from .runtime_contract import normalize_external_target
from src.iast.adjudicator import (
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_NO_EVIDENCE,
    FINAL_TARGET_UNHEALTHY,
    _FINAL_STATE_RANK,
)
from src.iast.canary import CanaryMatcher, STATE_RANK_STR, canary_key
from src.iast.sanitizer_trace import is_sanitized_for_family
from src.iast.orchestrator import is_sink_reached, STATE_SINK_REACHED_PROBE, compute_value_hit
from src.iast.sink_identity import iast_evidence_sink_reached_genuine, is_family_relevant_sink, is_genuine_sink_identity
from src.iast.deserialization_chain import runtime_chain_confirmed as _deser_runtime_chain_confirmed
from src.core.exploit_spec import canonical_business_logic_family, derive_flow_type, DIFFERENTIAL_PROOF_FAMILIES
from src.core import evidence_channels as _ec
from src.core import result_point as _rp

# 业务逻辑漏洞全类目（与 src/iast/business_logic.py::ALL_CATEGORIES 对齐）：真源见
# src/core/exploit_spec.py 的 DIFFERENTIAL_PROOF_FAMILIES（2026-09-03 合并 P1–P5 五套判据）。
_BUSINESS_LOGIC_CATEGORIES = tuple(DIFFERENTIAL_PROOF_FAMILIES)
# D1 重放路由特例：business_logic.verify（src/iast/business_logic.py::ALL_CATEGORIES 仅 8 类，无 idor）
# 在 D1 层与 BOLA 同路由（都是多身份取受害者资源），故 idor→bola。其余 category 经
# canonical_business_logic_family 归一为规范 token，无需在此重复列举别名。
_BL_ROUTE_OVERRIDES = {"idor": "bola"}

logger = logging.getLogger(__name__)

# ── D2 探针事件轮询埋点（2026-10-26，P2.1）────────────────────────────────
# 背景：run 471 实测 phase_times['d2'] = 4442.8s，而 replay_attempts 的 HTTP 耗时
# 合计只有 227s —— 95% 的时间不在请求上。最大嫌疑是下面的「有界轮询」
# （默认 10 次 × 1.5s = 每条核验最多空等 13.5s；315 条 ≈ 4250s，与 4443s 吻合）。
# 但这只是「总时长 - HTTP 时长」倒推，不能确认。故先埋点拿真数：
# 每条核验记录「用了几次 poll / 等了多久 / 是否命中」，聚合后由编排侧写进
# stage_results.d2.poll_stats。**先有数再优化，不重复「写了没生效」的老路。**
_POLL_STATS: Dict[str, Any] = {
    "verifications": 0,      # 进入轮询的核验数
    "hit": 0,                # 命中（提前 break）
    "timeout": 0,            # 跑满 attempts 仍未命中
    "total_wait_ms": 0.0,    # 累计等待（不含查询本身）
    "total_attempts": 0,     # 累计 poll 次数
    "max_wait_ms": 0.0,
}


def poll_stats() -> Dict[str, Any]:
    """返回 D2 探针轮询统计（含派生指标）。供编排侧落 stage_results.d2.poll_stats。"""
    n = int(_POLL_STATS.get("verifications") or 0)
    wait = float(_POLL_STATS.get("total_wait_ms") or 0.0)
    att = int(_POLL_STATS.get("total_attempts") or 0)
    return {
        "verifications": n,
        "hit": int(_POLL_STATS.get("hit") or 0),
        "timeout": int(_POLL_STATS.get("timeout") or 0),
        "hit_rate": round(int(_POLL_STATS.get("hit") or 0) / n, 4) if n else 0.0,
        "total_wait_s": round(wait / 1000.0, 1),
        "avg_wait_s": round(wait / 1000.0 / n, 2) if n else 0.0,
        "avg_attempts": round(att / n, 2) if n else 0.0,
        "max_wait_s": round(float(_POLL_STATS.get("max_wait_ms") or 0.0) / 1000.0, 1),
    }


def reset_poll_stats() -> None:
    for k in _POLL_STATS:
        _POLL_STATS[k] = 0 if k != "total_wait_ms" and k != "max_wait_ms" else 0.0


def _hitl_gate_for_spec(project_context: Dict, spec: Optional[Dict]) -> Dict[str, Any]:
    """对单条 trigger_spec 做 HITL 闸门判定，返回 decide_hitl_gate 的 act 字典（含 gate 标记）。

    规范字段优先 target_endpoint/route、http_method/method，与 neutralize_destructive_spec 同源。
    """
    _sp = spec or {}
    route = _sp.get("target_endpoint") or _sp.get("route") or ""
    method = _sp.get("http_method") or _sp.get("method") or "GET"
    try:
        from src.agents.d2_strategy import decide_hitl_gate
        return decide_hitl_gate(project_context or {}, method, route)
    except Exception as _e:  # 闸门判定异常不阻断验证，fail-open 视为放行
        logger.warning("[D2][hitl] 闸门判定异常（放行）：%s", _e)
        return {
            "irreversible": False, "category": None, "route": route, "method": method,
            "reason": f"闸门判定异常：{_e}", "gate": False, "approval_mode": "ask_on_risky_tools",
            "hitl_configured": False,
        }


def _record_hitl_gate_audit(act: Dict[str, Any], action: str) -> None:
    """写 HITL 闸门审计事件（gated/allowed），经 register_guard_audit_sink 落 hitl_audit。"""
    try:
        from src.iast.attack_context import record_destructive_guard_event
        record_destructive_guard_event({
            "action": action,
            "category": act.get("category") or "none",
            "reason": act.get("reason"),
            "route": act.get("route"),
            "method": act.get("method"),
            "approval_mode": act.get("approval_mode"),
            "stage": "d2_hitl",
        })
    except Exception:  # 审计失败绝不阻断验证
        pass


def _build_hitl_gated_result(act: Dict[str, Any]) -> "VerificationResult":
    """构造「待人工放行」结果：不实际执行破坏性重放（两阶段只读先行），只回只读计划。"""
    _route = act.get("route") or ""
    _method = act.get("method") or "GET"
    _cat = act.get("category") or ""
    vr = VerificationResult(
        exploitable=False,
        confidence="low",
        reason=f"HITL 闸门：不可逆动作（{_cat}）待人工放行（approval_mode={act.get('approval_mode')}）。{act.get('reason')}",
        evidence=[],
    )
    vr.iast_evidence = {}
    vr.dast_impact_evidence = {}
    vr.exploit_spec = {"entry": {"route": _route, "method": _method}}
    vr.failure_classification = {"category": _cat, "explanation": act.get("reason") or ""}
    vr.verification_decision = {
        "verification_status": "approval_required",
        "judge_reason": vr.reason,
        "category": _cat,
        "hitl_gate": True,
    }
    return vr


def _recover_value_hit(db, iast_evidence, specs):
    """值级证据补捞：聚合层没产出 value_hit 时，用**已落库事件**按 spec 标记重算一次。

    为什么需要：r75 实测出现「落库事件里明明比得出 hit_live（38 条，真值 100% TP），
    但送进确认闸的 iast_evidence.value_hit 为空」的断层，闸门因此把全部到达态判成
    arrival_without_semantics，动态召回归零。补捞把这条事实重新接回闸门。

    边界（严格遵守证据分层，绝不越权出结论）：
      - 只补**事实**：返回 compute_value_hit 的四态结果（hit_live / hit_sanitized / …）；
      - 算不出就返回空 dict（= 证据缺失），绝不臆断有害；
      - 调用方只在 iast_evidence.value_hit 为空时才调用，已有值不覆盖。
    """
    if db is None:
        return {}
    ids = [int(i) for i in (iast_evidence.get("matched_event_ids") or []) if str(i).isdigit()]
    if not ids:
        return {}
    markers = []
    for sp in (specs or []):
        m = str((sp or {}).get("taint_marker") or "").strip()
        if not m:
            continue
        markers.append(m)
        try:
            ident = CanaryMatcher.find_identity(m)
        except Exception:
            ident = ""
        if ident and ident not in markers:
            markers.append(ident)
    if not markers:
        return {}
    try:
        from src.iast.orchestrator import compute_value_hit
    except Exception:
        return {}
    ids = ids[:20]
    ph = ",".join("?" * len(ids))
    try:
        rows = db.execute(
            f"SELECT source_value, evidence_json, sink_file, sink_method, sink_line "
            f"FROM iast_events WHERE id IN ({ph})", ids, fetchall=True) or []
    except Exception:
        return {}
    for r in rows:
        try:
            ev = dict(r) if not isinstance(r, dict) else dict(r)
        except Exception:
            continue
        # 2026-10-11：此处**刻意不**把 evidence_json 映射成 evidence 去开第二比对源。
        # 实证：开了之后 285+286 的补捞命中从「纯 source_value 的 100% 精确」掉到
        # 84 TP / 10 FP（89.4%）—— evidence 里记录的常是探针侧的整包上下文，含
        # 我方可比对的标记但与该族数据流无关，会造成假命中。只信 sink 实参原文。
        for m in markers:
            try:
                vh = compute_value_hit(m, ev)
            except Exception:
                continue
            if vh.get("hit"):
                vh["recovered"] = True
                return vh
    return {}


# 三个确认终态（与 _reconcile_r73.py / benchmark_cli 对齐，避免把已确认 spec 误升级/误降级）。
_RECOVER_CONFIRMED = ("confirmed_exploitable", "confirmed_code_property", "confirmed_sink_control")


def recover_late_arrival(db, task_id, dry_run=False, only_unconfirmed=False):
    """Post-scan 迟到回收（修复 orchestrator 采集窗口硬上限 900s 把探针批量迟到事件丢掉的事故，
    见 memory 2026-10-11 第六节）。

    对尚未确认的 spec，用**全量** iast_events（不受采集窗口约束）重算 arrival + value_hit，
    按值级闸门(gate B: 到达真实 sink 且值级命中 hit_live)升级为 confirmed_exploitable。

    另含「迟到 arrival 回填」子过程（2026-10-11 增）：D2 采集窗内探针批量 flush 迟到会让运行期
    把 spec 判成 no-arrival（r77 实测 306/307 有 112+137 个 spec 存在真 sink 的 sink-reached
    事件却未被登记）。本过程对这类 spec 单调回填 iast_state + verification_status='sink_reached'
    ——**只补到达到达层，绝不升 confirmed**（确认仍由值级闸门独享），故对 ②/④ 零影响。

    证据分层纪律：
      - 严格单调：只把「definitive 阳性」(value_hit.hit) 的 spec 升级为确认；arrival 回填只增到达态；
        绝不降级、绝不碰已确认 spec；
      - 只信 sink 实参原文（compute_value_hit 比对 source_value），不臆断；
      - ldap/xpath 两族额外认 evidence_json.payload（探针把 canary 落在过滤器串/表达式里，
        不在 source_value）；该扩展**仅限这两族**，不开全局（r75 SQL 开 evidence 曾混进 10 FP）。
      - 真到达但值级无命中的 spec（如 xss 反射 writer 未把写入串记成可读值、trustbound 无语义
        sink 观测、xpathi 求值 sink 未 hook）保持原态，留给 sink 覆盖率补强，不放行弱信号（不灌 FP）。
    幂等：已升级过的 spec（verification_status 已是确认态）直接跳过；重跑不产生新副作用。

    返回 (upgraded_ids, stats)。dry_run=True 只算不写，供离线评估用。
    """
    specs = db.execute(
        "SELECT id, taint_marker, family, capability_family, target_endpoint, "
        "verification_status, iast_state FROM trigger_specs WHERE task_id=?",
        (task_id,), fetchall=True) or []
    if not specs:
        return [], {"task": task_id, "specs": 0, "considered": 0, "upgraded": 0}
    evs = db.execute(
        "SELECT canary, canary_state, sink_file, source_value, evidence_json "
        "FROM iast_events WHERE task_id=?",
        (task_id,), fetchall=True) or []
    ev_by_ident = defaultdict(list)
    for e in evs:
        c = e.get("canary") or ""
        if c:
            ev_by_ident[canary_key(c)].append(e)

    upgraded = []
    affected_arrivals = []  # 迟到 arrival 回填（单调，绝不升确认）
    considered = 0
    for sp in specs:
        vs = (sp.get("verification_status") or "") or ""
        if vs in _RECOVER_CONFIRMED:
            continue  # 已确认，绝不降级
        if only_unconfirmed and vs not in ("", "no_evidence", "unconfirmed"):
            continue
        considered += 1
        ident = CanaryMatcher.find_identity(sp.get("taint_marker") or "")
        if not ident:
            continue
        matched = ev_by_ident.get(ident, [])
        if not matched:
            continue
        fam = (sp.get("family") or sp.get("capability_family") or "").lower().replace("-", "_")
        marker = sp.get("taint_marker") or ""
        # 在所有 matched 事件中找「真实 sink 且值级命中」的最强事件——不迷信 top[0]：
        # 同态事件里若排第一的是噪声 sink（Cookie/Random/setHeader），原逻辑会误 skip 掉本可
        # 确认的 genuine 事件。故改为遍历 matched，取 (rank, event) 最强的 genuine+value_hit。
        # 仅 ldap/xpath 两族在值级无命中时**再试 evidence_json.payload**：探针把 canary 落在
        # 过滤器串/表达式里（不在 source_value）。r75 时 SQL 开 evidence 混进 10 FP，故**严格限
        # 这两族**，绝不开全局（避免把探针整包上下文当数据流证据）。
        _evidence_fams = ("ldap" in fam or "xpath" in fam)
        genuine_hit = None  # (rank, event)
        best_arrival = None  # (rank, state) —— 仅取真 sink 的 sink-reached 最强态，供回填
        for e in matched:
            if not is_sink_reached(e.get("canary_state") or ""):
                continue
            sf = e.get("sink_file") or ""
            # Cookie 构造/标志设置是请求 cookie 原值建对象（canary 就在名字/值旁边），属输入处理噪声，
            # 非输出反射——对任何注入族都不能算值级 definitive 阳性（memory：与任何注入族都无关）。
            # 否则会把「请求把自己的 cookie 原值建对象」误判成 XSS 反射（r77 实测 1 例 FP）。
            if "cookie" in (sf or "").lower():
                continue
            if not is_family_relevant_sink(sf, fam):
                # 2026-11-03（jsc-leakfix-r17）：从此处只查 is_genuine_sink_identity 改为
                # 叠加族画像相关性。identity 只挡框架噪声黑名单，对 xss 族因「响应写入
                # 放行」几乎恒真——log4j 端点的 JNDI lookup / writeInternal 事件由此把
                # xss spec 确认成 exploitable（jsc 607 实测 FP）。族相关性要求「sink 属于
                # 本族画像」，无画像族仍 fail-open（spel/ssti/url_redirect 等），不伤真值。
                continue
            # 迟到 arrival 回填的候选：真 sink 的 sink-reached 态，只记最强（与值级判定无关，
            # 便于「到达真实 sink 但没有值级命中」的 spec 恢复 L3 到达层，供 I2/family-route 消费）。
            _rank = STATE_RANK_STR.get(e.get("canary_state") or "", 0)
            if best_arrival is None or _rank > best_arrival[0]:
                best_arrival = (_rank, e.get("canary_state") or "")
            vh = compute_value_hit(marker, {"source_value": e.get("source_value") or ""})
            if not vh.get("hit") and _evidence_fams and e.get("evidence_json"):
                try:
                    vh = compute_value_hit(marker, {
                        "source_value": e.get("source_value") or "",
                        "evidence": json.loads(e["evidence_json"]),
                    })
                except Exception:
                    vh = {"hit": False}
            if vh.get("hit"):
                if genuine_hit is None or _rank > genuine_hit[0]:
                    genuine_hit = (_rank, e)
        if genuine_hit:
            upgraded.append(sp["id"])
            continue
        # 迟到 arrival 回填（单调）：本 spec 有真 sink 的 sink-reached 事件，但当前登记态更弱
        # （典型：D2 采集窗内探针批量 flush 迟到 → 运行期判 no-arrival）→ 回填到达态。
        # 只写 verification_status='sink_reached' + iast_state，**绝不升 confirmed**（值级闸门独享）。
        if best_arrival is not None:
            _cur = STATE_RANK_STR.get((sp.get("iast_state") or "").split(":")[-1], 0)
            if best_arrival[0] > _cur:
                affected_arrivals.append((sp["id"], best_arrival[1]))

    if not dry_run and upgraded:
        for sid in upgraded:
            db.execute(
                "UPDATE trigger_specs SET verification_status=?, iast_state=?, raw_json=? WHERE id=?",
                ("confirmed_exploitable", "sink-reached-probe",
                 json.dumps({"recovered": True, "reason": "late-arrival value_hit gate B"},
                            ensure_ascii=False), sid))
    if not dry_run and affected_arrivals:
        for sid, state in affected_arrivals:
            # 只动 iast_state + verification_status（不动 raw_json，避免覆盖 A2 原始证据）；
            # 幂等：重跑时 iast_state 已是最强态 → _cur >= best → 不再进入本列表。
            db.execute(
                "UPDATE trigger_specs SET verification_status=?, iast_state=? WHERE id=?",
                ("sink_reached", state, sid))
    return upgraded, {"task": task_id, "specs": len(specs), "considered": considered,
                      "upgraded": len(upgraded), "arrivals_backfilled": len(affected_arrivals)}


class D2Agent:
    """统一验证入口（设计层即运行时，无 legacy / IAST 双模式）。

    verify() 一条总路径：
        D1 重放(攻击) → I1 监听+逐节点链路符合 → D2 站 sink 立场核实结果点是否有害
        → I2 综合裁决五态 + 控制回路(重发/修正)。

    iast_service(探针/I1) 与 dast_operator(D1) 由 verify() 内部按 DB 构造，调用方无需注入，
    因此也不存在「缺失则回落 legacy」的可能——统一链路是唯一的路径。
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def verify(
        self,
        vulnerability: Dict,
        project_context: Dict,
        external_target: Optional[Dict[str, Any]] = None,
        trigger_spec: Optional[Dict[str, Any]] = None,
        iast_service: Optional[Any] = None,
        dast_operator: Optional[Any] = None,
    ) -> VerificationResult:
        # §3.5 删除 is_ready 门禁；ExternalTarget 归一化后透传。
        context = dict(project_context or {})
        target = normalize_external_target(external_target or context.get("external_target"))
        context["external_target"] = target.to_dict()

        # 内部构造统一链路依赖：iast_service=I1/探针，dast_operator=D1。
        # 调用方无需感知模式，也不存在 legacy 分支可回落。允许注入（测试 / 已构造实例复用），
        # 缺失时按 DB 构造（统一链路唯一路径）。
        db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
        from src.infrastructure.db import Database
        from src.iast.service import IastService
        from src.application.d1_service import D1Service
        db = None
        if iast_service is None or dast_operator is None:
            db = Database(db_path)
            if iast_service is None:
                iast_service = IastService(db)
            if dast_operator is None:
                # 2026-09-19：按 agents.d1.enable_llm_overlay（默认关）决定是否注入 LLM 网关。
                # 关时传 None，与接入前行为完全一致（D1 的 AI 复核与 LLM 造弹两条腿都不走）。
                dast_operator = D1Service(
                    db=db, gateway=D1Service.build_gateway_from_config(self.config)
                )

        # trigger_spec 是 SAST finding → IAST 重放的唯一桥梁。
        # 调用方显式传入（推荐，由 run_d2_verify 按漏洞 hash 关联），缺失则无法跑 D1。
        # 业务逻辑漏洞走「双账号差分重放」而非 canary 污点重放：其 trigger_spec 带
        # business_logic_category，统一 verify() 透明路由到 business_logic.verify（见 #2/#5）。
        bl_category = self._resolve_business_logic_category(trigger_spec, vulnerability)
        if bl_category:
            if not trigger_spec:
                vr = VerificationResult(
                    exploitable=False,
                    confidence="low",
                    reason=(
                        "统一验证缺少 business_logic trigger_spec：业务逻辑差分重放需要端点/参数/双账号 spec，"
                        "无法做 D1 运行时验证。"
                    ),
                    evidence=[],
                )
                vr.final_state = "no_evidence"
                vr.iast_evidence = {}
                vr.dast_impact_evidence = {}
                return vr
            return self._verify_business_logic(bl_category, trigger_spec, external_target, vulnerability, iast_service, project_context=context)

        if not trigger_spec:
            vr = VerificationResult(
                exploitable=False,
                confidence="low",
                reason=(
                    "统一验证缺少 trigger_spec：D1 无靶可重放，无法做 IAST 运行时验证。"
                    "需先由 A2→TriggerSpec 自动登记有效路由/参数（按漏洞 hash 关联）。"
                ),
                evidence=[],
            )
            vr.final_state = "no_evidence"
            vr.iast_evidence = {}
            vr.dast_impact_evidence = {}
            return vr

        logger.info("[D2] verify (unified): external_target=%s", external_target.get("service_url") if external_target else None)

        # §3.14 A0 环境识别（预处理门禁）：发流量前确认目标可达 + 探针在线 + 绑定一致，
        # 否则阻断本次发流量（非静默、不自动降级、不进触发事务）。仅当 iast_service 真实具备
        # check_environment_readiness 且 target 带 app_name/agent_id 时激活；FakeIast 类桩
        # 无此方法，守卫跳过以保既有测试绿。
        if (
            hasattr(iast_service, "check_environment_readiness")
            and external_target.get("app_name")
            and external_target.get("agent_id")
        ):
            readiness = iast_service.check_environment_readiness(
                external_target.get("service_url", ""),
                external_target["app_name"],
                external_target["agent_id"],
            )
            if not readiness.get("ready"):
                logger.warning("[D2] A0 环境未就绪，阻断发流量：%s", readiness.get("block_reason", ""))
                vr = VerificationResult(
                    exploitable=False,
                    confidence="low",
                    reason=f"A0 环境未就绪，已阻断发流量：{readiness.get('block_reason', '')}",
                    evidence=[],
                )
                vr.iast_evidence = {}
                vr.dast_impact_evidence = {
                    "blocked": True,
                    "target_unhealthy": True,
                    "reason": readiness.get("block_reason", ""),
                    "environment_readiness": readiness,
                }
                # 环境门禁未过（探针未就绪 / 连续 5xx / 不可达）= 靶场不健康，可重试，
                # 与 no_evidence（永久非漏洞）严格区分，避免把「靶场挂了」误判成「无漏洞」。
                vr.final_state = FINAL_TARGET_UNHEALTHY
                return vr

        from src.iast.orchestrator import (
            TriggerTransactionOrchestrator,
            aggregate_iast_evidence,
        )
        from src.iast.adjudicator import D2Judge, I1Judge, I2Adjudicator

        specs = trigger_spec if isinstance(trigger_spec, list) else [trigger_spec]

        # ── ⑤ HITL 闸门（2026-09-23 接入活跃链路）：真正发破坏性重放前，判不可逆动作是否需人放行 ──
        # 在 orchestrator.run_transaction（实际发破坏性重放）之前短接：gate 时只回只读计划，
        # 不实际执行；不可逆但无需拦（off / strict 已放行 / 动作级白名单）→ 全量审计记 allowed。
        _gate_act = _hitl_gate_for_spec(context, specs[0] if specs else None)
        if _gate_act.get("hitl_configured") and _gate_act.get("irreversible"):
            if _gate_act.get("gate"):
                _record_hitl_gate_audit(_gate_act, "gated")
                return _build_hitl_gated_result(_gate_act)
            _record_hitl_gate_audit(_gate_act, "allowed")
        result = self._replay_transaction(
            target=target, external_target=external_target, specs=specs,
            iast_service=iast_service, dast_operator=dast_operator, db=db,
        )
        return self._adjudicate_result(result, vulnerability, specs, db=db)

    def _replay_transaction(self, target, external_target, specs, iast_service,
                            dast_operator, db):
        """跑一次 IAST 触发事务（D1 重放 + 证据窗口），返回 TransactionResult。

        从 verify() 中抽出，使 verify_group() 能让多个漏洞共用同一次事务：窗口等待是
        耗时主体且与批内假说数无关，逐漏洞各起一个事务时 304 个漏洞/18 并发 ≈ 17 轮 × 57s。
        """
        from src.iast.orchestrator import TriggerTransactionOrchestrator, _replay_overrides_of

        # §4.2 事件隔离：把本次事务的 app_name / agent_id（及 trigger_spec 携带的 trace_id，
        # 见 §3.11 trace 头透传，探针侧可选）烤进 event_source 闭包，使 poll 仅命中本目标事件，
        # 避免共用同一运行实例的多次扫描事件混流污染。空值视为「不限定」以兼容旧链路。
        tgt_app = external_target.get("app_name") or target.to_dict().get("app_name") or ""
        tgt_agent = external_target.get("agent_id") or target.to_dict().get("agent_id") or ""
        tgt_trace = ""
        for sp in specs:
            sp_trace = sp.get("trace_id") if isinstance(sp, dict) else None
            if sp_trace:
                tgt_trace = sp_trace
                break

        def event_source(canary, since_id, limit):
            rows = iast_service.poll_events_by_canary(
                canary, since_id, limit,
                app_name=tgt_app or None,
                agent_id=tgt_agent or None,
                trace_id=tgt_trace or None,
            ) or []
            # 携带 stack_trace/sink/source/taint_path 全字段，供 I1 逐节点链路符合性校验
            # （方案 B：taint_path 来自探针回带的污点传播路径，精确逐节点命中）
            return [{
                "id": int(r.get("id", 0) or 0),
                "canary_state": r.get("canary_state", ""),
                "canary": r.get("canary", ""),
                "stack_trace": r.get("stack_trace", ""),
                "sink_method": r.get("sink_method", ""),
                "sink_file": r.get("sink_file", ""),
                "sink_line": r.get("sink_line", 0),
                "source_value": r.get("source_value", ""),
                "taint_path": _parse_taint_path(r.get("taint_path_json", "")),
            } for r in rows]

        # §3.14 编排器层廉价复探：把 A0 环境识别复用为 readiness_probe，使 run_transaction
        # 真正发流量前再确认一次（预处理阶段已跑过一次，这里防结论中途过期）。仅当 iast_service
        # 真实具备 check_environment_readiness 且 target 带 app_name/agent_id 时注入；否则 None 不复探。
        readiness_probe = None
        if (
            hasattr(iast_service, "check_environment_readiness")
            and tgt_app
            and tgt_agent
        ):
            def readiness_probe(target_dict):
                return iast_service.check_environment_readiness(
                    target_dict.get("service_url", ""),
                    target_dict.get("app_name", "") or tgt_app,
                    target_dict.get("agent_id", "") or tgt_agent,
                )

        # §3.12 事件隔离：提供「当前 iast_events 最大 id」水位线，使编排器只轮询本事务启动后
        # 产生的事件，剔除上一轮残留的空路径/陈旧事件（I1 逐节点符合性的直接前置条件）。
        def watermark_provider() -> int:
            if db is None:
                return 0
            try:
                row = db.execute("SELECT MAX(id) FROM iast_events", fetchone=True)
                if not row:
                    return 0
                return int(next(iter(row.values()), 0) or 0)
            except Exception:
                return 0

        orchestrator = TriggerTransactionOrchestrator(
            dast_operator=dast_operator,
            event_source=event_source,
            readiness_probe=readiness_probe,
            event_watermark_provider=watermark_provider,
        )
        # §8.4 ③ 选项A：活跃扫描会话归属。replay 窗口内探针回采的事件若无 canary 身份段
        # （普通 SINK_HIT 实时流量常为空），在多 task workspace 下会被 _resolve_event_task_id
        # 归为 NULL 而静默丢失。这里把本任务标记为该 workspace 的「活跃扫描 task」，使窗口内
        # 无身份段事件仍能正确归属本 task；窗口结束后清除。fail-open：标记失败不影响重放。
        _active_task_id = None
        _active_workspace_id = None
        for sp in specs:
            tid = sp.get("task_id")
            wid = sp.get("workspace_id")
            if tid and wid:
                _active_task_id, _active_workspace_id = tid, wid
                break
        try:
            if db is not None and _active_task_id is not None:
                try:
                    db.execute(
                        "UPDATE iast_sessions SET current_task_id = ? WHERE workspace_id = ?",
                        (_active_task_id, _active_workspace_id),
                    )
                except Exception as _e:
                    logger.warning("[D2] 标记活跃扫描 task 失败（不影响重放）：%s", _e)
            # （2026-09-29 落地）：把 spec 的重放侧覆盖动作（inject_all_params / extend_wait_window /
            # switch_param_location，存于 raw_json.replay_adjust.actions）显式挂到 spec 上，供编排器消费。
            # extend_wait_window → 编排器放宽本事务 I1 采集窗口；inject_all_params 已由 D1 默认全参注入
            # （representative_request_params 全参数带标），此处仅确保覆盖标记可见、可追溯。
            for sp in specs:
                if isinstance(sp, dict) and not sp.get("replay_overrides"):
                    sp["replay_overrides"] = _replay_overrides_of(sp)
            result = orchestrator.run_transaction(target.to_dict(), specs)
        finally:
            if db is not None and _active_workspace_id is not None:
                try:
                    db.execute(
                        "UPDATE iast_sessions SET current_task_id = NULL WHERE workspace_id = ?",
                        (_active_workspace_id,),
                    )
                except Exception:
                    pass
        return result

    def _adjudicate_result(self, result, vulnerability, specs, db=None, dast_impact=None):
        """对一次事务结果做 I1/D2/I2 三级裁决，返回该 vulnerability 的 VerificationResult。

        dast_impact：按假说切片后的影响证据（批量合并事务时由调用方传入）；为空则用
        result.raw_dast_impact（与逐条 verify 完全同语义）。
        """
        from src.iast.orchestrator import aggregate_iast_evidence
        from src.iast.adjudicator import D2Judge, I1Judge, I2Adjudicator
        from src.infrastructure.db import Database

        # 2026-10-31（本轮/560 实证）：**裁决前从 DB 重读 oracle 观测**。
        # 时间线问题：oracle 探测发生在 D1（`d1_service._run_family_oracle` → 写
        # trigger_specs.oracle_state/oracle_signal），而 `specs` 是 D2 入口时的内存快照，
        # 那时 oracle_state 还没写 ⇒ 裁决读到的永远是空串。
        #
        # 坑（本轮第 2 次踩）：specs 可能是 `sqlite3.Row` —— **没有 .get() 方法、且只读**。
        # 第一版直接写 `sp.get("id")` 抛 AttributeError，被下面的 except 静默吞掉，
        # 于是 本轮仍只转化 3/11。故：①先统一转成 dict（可写）；
        # ②except 用 warning 而非 debug，杜绝「改了没生效还看不出来」。
        try:
            if specs and not isinstance(specs[0], dict):
                specs = [dict(sp) for sp in specs]
            if db is not None and specs:
                _ids = [int(sp["id"]) for sp in specs if sp.get("id")]
                if _ids:
                    _ph = ",".join("?" * len(_ids))
                    _rows = db.execute(
                        "SELECT id, oracle_state, oracle_signal FROM trigger_specs "
                        "WHERE id IN (%s)" % _ph,
                        _ids, fetchall=True,
                    ) or []
                    _by_id = {int(dict(r)["id"]): dict(r) for r in _rows}
                    _filled = 0
                    for sp in specs:
                        _r = _by_id.get(int(sp.get("id") or 0))
                        if _r:
                            sp["oracle_state"] = _r.get("oracle_state") or ""
                            sp["oracle_signal"] = _r.get("oracle_signal") or ""
                            if sp["oracle_state"]:
                                _filled += 1
                    if _filled:
                        logger.info("[D2] 从 DB 重读 oracle 观测：%d/%d 条带信号",
                                    _filled, len(specs))
                        print("[D2][oracle-reload] %d/%d 条带信号" % (_filled, len(specs)),
                              flush=True)
                    else:
                        print("[D2][oracle-reload] 0/%d（specs keys=%s）"
                              % (len(specs), sorted((specs[0] or {}).keys())[:12]), flush=True)
        except Exception as _oe:  # noqa: BLE001  fail-open：读不到就按原快照判
            logger.warning("[D2] oracle 观测重读失败（按原快照继续）：%s", _oe)

        iast_evidence = aggregate_iast_evidence(result.per_hypothesis)
        # 2026-10-31（本轮实证）：把本事务内**行为 oracle 正向**信号汇入 iast_evidence。
        # 聚合层 aggregate_iast_evidence 只看探针观测，不带 oracle；而下游
        # 「到达 ≠ 可利用」降级（_build_verification_result 的 _arrival_only_hit）需要知道
        # 「本条除探针断言外还有没有独立证据」。oracle 的布尔差分 / 时延 / 文件签名 /
        # 响应头回显是纯黑盒行为证据，与探针无关，必须让它参与该判断。
        # 只在确实有 exploitable 时写入，且 signal 必须非空 —— 与 harm_evidence 的
        # 判据同源（那里也要求 exploitable + signal 才认 harm_confirmed）。
        try:
            _orc_hits = [sp for sp in (specs or [])
                         if str(sp.get("oracle_state") or "") == "exploitable"
                         and str(sp.get("oracle_signal") or "").strip()]
            if _orc_hits:
                iast_evidence["oracle_state"] = "exploitable"
                iast_evidence["oracle_signal"] = str(_orc_hits[0].get("oracle_signal") or "")
        except Exception:  # noqa: BLE001  fail-open：汇总失败不影响原判据
            pass
        # ── 值级证据幂等补捞（2026-10-11，r75 实证）──────────────────────────────────
        # 现象：r75 用 spec 的 taint_marker 对落库事件离线重算，得到 38 条 hit_live 且
        # **真值 100% TP**，线上闸门却把它们判成 arrival_without_semantics（57 条）→
        # sqli-1 ② 仍为 0。反推可知聚合层送进闸门的 iast_evidence.value_hit 为空：
        # d2_evidence 的 primary_channel=none / evidence_strength=0 即为此证。
        # 补捞是**事实层**动作（不是裁决层）：只用已落库的事件 + spec marker 重算一遍
        # 「我方数据是否真的出现在 sink 实参里」，已有 value_hit 时不覆盖，算不出就保持
        # 空（miss = 证据缺失，绝不臆断有害）。与铁律①一致：下层只补事实，不出结论。
        if not (iast_evidence.get("value_hit") or {}).get("hit"):
            _recovered = _recover_value_hit(db, iast_evidence, specs)
            if _recovered.get("hit"):
                iast_evidence["value_hit"] = _recovered
        # 按假说切片的影响证据优先（批量合并事务时用）：raw_dast_impact 是事务级聚合，
        # 合并多漏洞后会让每个成员都吃到整批 OR 出来的 reached → 抬 FP。
        dast_impact_evidence = dict(dast_impact or result.raw_dast_impact or {})
        # v2 证据分层 A5：把「观测冒充裁决」的 impact_observed 拆成四层，各自有独立生产者。
        # 铁律①：下层不得直接产出上层结论 —— impact_observed(L4) 绝不由 reached(L1) 派生。
        _raw_dast = result.raw_dast_impact or {}
        dast_impact_evidence.setdefault("request_completed", bool(_raw_dast.get("reached")))
        _iast_state = str(iast_evidence.get("state") or "")
        dast_impact_evidence.setdefault("sink_invoked", is_sink_reached(_iast_state))
        _dvh = iast_evidence.get("value_hit") or {}
        dast_impact_evidence.setdefault("value_level_hit", bool(_dvh.get("hit")))
        # 2026-10-11：确认闸 _differential_override 需要区分 hit_live（definitive 正向，
        # 必须否决差分降级）与 hit_sanitized（definitive 阴性，应当允许降级）—— 只有 value_hit
        # 的 form 携带这个区分，此前只透传了布尔 hit，闸门无法分辨，只能一律当命中。
        dast_impact_evidence.setdefault("value_hit_form", str(_dvh.get("form") or ""))
        # L4 impact_observed：只能由下列之一置位（OOB 回调 / 响应差分显著 / 时延盲注 / sink 异常类型）。
        # 这些才是「语义生效」的可观测证据；reached 不再充当 impact_observed。
        _diff = dast_impact_evidence.get("differential")
        _diff_harmful = bool(isinstance(_diff, dict) and _diff.get("harmful"))
        _oob = bool(_raw_dast.get("oob_confirmed") or dast_impact_evidence.get("oob_confirmed"))
        _tb = bool(dast_impact_evidence.get("time_blind_confirmed"))
        _exc = bool(iast_evidence.get("sink_exception_class") or _dvh.get("sink_exception_class")
                    or dast_impact_evidence.get("sink_exception_class"))
        dast_impact_evidence.setdefault("impact_observed", _oob or _diff_harmful or _tb or _exc)
        # P1：对照实验差分结论从 raw_dast_impact 兜底透传（DastImpact.to_dict 已含 differential），
        # 避免批量切片 dast_impact 不含该字段时丢失，确保闸门 _differential_override 能读到。
        if "differential" not in dast_impact_evidence:
            dast_impact_evidence["differential"] = (result.raw_dast_impact or {}).get("differential")

        # Q2：I1 监听器 / D2 校验器只做「这条 spec 是否符合要求」的判断（不论成败），
        # 把完整结果交给 I2 LLM 裁决器；I2 综合 I1 + D2 双重证据，以「条」为颗粒度裁决
        # pass / re_send / rollback_to_a2，并把不符合的假说回灌 A2 重新推导（闭环反思）。
        i1_verdicts = I1Judge().judge(result.per_hypothesis)
        _flow_by_h = {}
        for _sp in (specs or []):
            _fh = _sp.get("flow_type") or derive_flow_type(_sp.get("family") or _sp.get("category") or "")
            _h = _sp.get("vulnerability_hash_v2")
            if _h:
                _flow_by_h[_h] = _fh
        for _iv in i1_verdicts:
            _iv.flow_type = _flow_by_h.get(_iv.hypothesis_id, "") or derive_flow_type("")
        d2_verdicts = D2Judge().judge(result.per_hypothesis, result.raw_dast_impact)
        i2 = I2Adjudicator(db=db, config=self.config)
        i2_decisions = i2.adjudicate(
            i1_verdicts,
            d2_verdicts,
            specs=specs,
            vulnerability_context=vulnerability,
            taint_flow_hypothesis=(vulnerability or {}).get("taint_flow_hypothesis"),
            dast_impact_evidence=dast_impact_evidence,
        )

        # 兼容性：保留聚合的 d2_verdict（供前端 / test 读取）。
        # ④ sink 身份校验：透传族名，使 _verify_sink_result 能区分「真 sink」与「框架噪声 sink」。
        _family = ""
        for _sp in (specs or []):
            if _sp.get("family"):
                _family = _sp["family"]
                break
        if not _family:
            _family = (vulnerability or {}).get("family") or (vulnerability or {}).get("finding_type") or ""
        d2_verdict = _verify_sink_result(iast_evidence, dast_impact_evidence, _family)

        # 多 spec 裁决合并：取最强 final_state；整体 action 优先 rollback_to_a2。
        vr = _build_verification_result(i2_decisions, iast_evidence, dast_impact_evidence, d2_verdict)

        # Point5 语义分级：D2 最终裁决确认「可观测危害」→ 置 exploit_confirmed=1，
        # 与 status='confirmed_runtime'（污点抵达 sink 的传播证明）并存，供 correlation/前端分两档展示。
        #
        # 修正（回灌断裂修复）：原条件只看 vr.d2_verdict.harmful，而该字段来自
        # _verify_sink_result（LINE 280 的兼容性聚合），其判有害的前提是
        # is_sink_reached(iast_state)——即只覆盖 canary/污点通道。业务族（bola/idor 等）
        # 走的是 _verify_business_logic 差分重放通道，iast_state 为 business-logic-confirmed
        # 而非 sink-reached，故 d2_verdict.harmful 恒为 False，导致 13 条 confirmed_exploitable
        # 一条都没回写到 vulnerability_instances.exploit_confirmed（实测恒 0）。
        # 正确口径应取最终裁决：vr.exploitable（I2 strongest.confirmed）
        # 或 vr.verification_decision.verification_status == confirmed_exploitable。
        _vr_d2 = getattr(vr, "d2_verdict", None) or {}
        _vr_vd = getattr(vr, "verification_decision", None) or {}
        _final_confirmed = bool(
            _vr_d2.get("harmful")
            or getattr(vr, "exploitable", False)
            or _vr_vd.get("verification_status") == "confirmed_exploitable"
        )
        if _final_confirmed:
            _workspace_id = next((sp.get("workspace_id") for sp in specs if sp.get("workspace_id")), None)
            # 逐个回写本 vulnerability 关联的全部 spec hash，而非只写 specs[0]，
            # 避免多 spec 聚合时漏写（同一 vuln 下其余 spec 的 exploit_confirmed 恒 0）。
            _vhs = []
            _v_vh = (vulnerability or {}).get("vulnerability_hash_v2")
            if _v_vh:
                _vhs.append(str(_v_vh))
            for sp in (specs or []):
                _h = sp.get("vulnerability_hash_v2")
                if _h and str(_h) not in _vhs:
                    _vhs.append(str(_h))
            if _workspace_id and _vhs:
                try:
                    from src.iast.service import IastService
                    _mark_db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
                    _mark_svc = IastService(_mark_db)
                    for _vh in _vhs:
                        _mark_svc.mark_exploit_confirmed(int(_workspace_id), str(_vh))
                except Exception as _e:
                    logger.warning("[D2] mark_exploit_confirmed 失败（不影响裁决）：%s", _e)
        return vr

    def verify_group(self, members, project_context, external_target=None,
                     iast_service=None, dast_operator=None):
        """批量合并事务：一组 (vulnerability, trigger_spec) 共用一次 IAST 触发事务。

        动机：run_transaction 的耗时主体是「重放之后的证据窗口等待」（t_max 60s + settle），
        与批内假说数基本无关。逐漏洞各起一个事务时，304 个漏洞 / 18 并发 ≈ 17 轮 × 57s ≈ 963s
        （round-18 实测）。把 N 个漏洞的 spec 合进一个事务后，事务数降到 ceil(304/N)，
        18 并发足以一轮打完 → D2 降到约 1~2 分钟。

        安全边界（缺一即整体回退逐条 verify，绝不以降质换速度）：
          - canary 每 spec 唯一 → per_hypothesis 按 vulnerability_hash_v2 切片归因，互不串味；
          - raw_dast_impact 是**事务级聚合**（reached = 批内所有重放取 OR），绝不能共享，
            改用编排器 2026-09-27 新增的 dast_impact_by_hypothesis 按假说切片；
          - 业务逻辑漏洞走差分重放（完全不同的通道），不入批；
          - 批内所有 spec 的 trace_id 必须一致，否则 event_source 的 trace 过滤会漏事件；
          - 早停要求批内全部假说到达才 break，故调用方须按「族 + 端点」同质分批，
            别让快批被慢假说拖满整窗口。
        """
        import dataclasses as _dc

        members = list(members or [])
        results: List[Optional[VerificationResult]] = [None] * len(members)
        context = dict(project_context or {})
        target = normalize_external_target(external_target or context.get("external_target"))
        context["external_target"] = target.to_dict()

        from src.infrastructure.db import Database
        from src.iast.service import IastService
        from src.application.d1_service import D1Service
        db = None
        if iast_service is None or dast_operator is None:
            db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
            if iast_service is None:
                iast_service = IastService(db)
            if dast_operator is None:
                dast_operator = D1Service(db=db, gateway=D1Service.build_gateway_from_config(self.config))

        def _no_spec_result():
            vr = VerificationResult(
                exploitable=False, confidence="low",
                reason=("统一验证缺少 trigger_spec：D1 无靶可重放，无法做 IAST 运行时验证。"),
                evidence=[],
            )
            vr.final_state = "no_evidence"
            vr.iast_evidence = {}
            vr.dast_impact_evidence = {}
            return vr

        pending = []  # [(idx, vuln, specs)] —— 真正进入共享事务的成员
        for i, m in enumerate(members):
            vuln = m.get("vulnerability") or {}
            ts = m.get("trigger_spec")
            specs = ts if isinstance(ts, list) else ([ts] if ts else [])
            bl = self._resolve_business_logic_category(specs[0] if specs else None, vuln)
            if bl:
                results[i] = (
                    self._verify_business_logic(bl, specs[0], external_target, vuln,
                                                iast_service, project_context=context)
                    if specs else _no_spec_result()
                )
                continue
            if not specs:
                results[i] = _no_spec_result()
                continue
            gate = _hitl_gate_for_spec(context, specs[0])
            if gate.get("hitl_configured") and gate.get("irreversible"):
                if gate.get("gate"):
                    _record_hitl_gate_audit(gate, "gated")
                    results[i] = _build_hitl_gated_result(gate)
                    continue
                _record_hitl_gate_audit(gate, "allowed")
            pending.append((i, vuln, specs))

        if not pending:
            return results

        def _fallback_all(reason):
            logger.warning("[D2] 批量合并事务回退逐条：%s", reason)
            for i, vuln, specs in pending:
                if results[i] is None:
                    results[i] = self.verify(
                        vuln, context, external_target,
                        specs[0] if len(specs) == 1 else specs,
                        iast_service, dast_operator,
                    )

        # ① trace 一致性：event_source 把 trace_id 烤死在闭包里，批内混用会漏事件。
        traces = {str(sp.get("trace_id") or "") for _i, _v, sps in pending for sp in sps}
        if len(traces) > 1:
            _fallback_all("批内 trace_id 不一致（%d 种）" % len(traces))
            return results

        # ② A0 环境门禁：整组共用同一 target，判一次即可。
        if (hasattr(iast_service, "check_environment_readiness")
                and (external_target or {}).get("app_name")
                and (external_target or {}).get("agent_id")):
            readiness = iast_service.check_environment_readiness(
                (external_target or {}).get("service_url", ""),
                external_target["app_name"], external_target["agent_id"],
            )
            if not readiness.get("ready"):
                for i, vuln, specs in pending:
                    vr = VerificationResult(
                        exploitable=False, confidence="low",
                        reason="A0 环境未就绪，已阻断发流量：%s" % readiness.get("block_reason", ""),
                        evidence=[],
                    )
                    vr.iast_evidence = {}
                    vr.dast_impact_evidence = {
                        "blocked": True, "target_unhealthy": True,
                        "reason": readiness.get("block_reason", ""),
                        "environment_readiness": readiness,
                    }
                    vr.final_state = FINAL_TARGET_UNHEALTHY
                    results[i] = vr
                return results

        all_specs = [sp for _i, _v, sps in pending for sp in sps]
        try:
            result = self._replay_transaction(
                target=target, external_target=external_target, specs=all_specs,
                iast_service=iast_service, dast_operator=dast_operator, db=db,
            )
        except Exception as exc:  # 事务级异常 → 绝不吞，整组回退逐条
            _fallback_all("事务执行异常：%s" % exc)
            return results

        if result is None:
            _fallback_all("事务返回 None")
            return results

        by_h = getattr(result, "dast_impact_by_hypothesis", None) or {}
        for i, vuln, specs in pending:
            hashes = {str(sp.get("vulnerability_hash_v2") or sp.get("hypothesis_id") or "") for sp in specs}
            hashes.discard("")
            # ③ 影响证据按假说切片：只取本漏洞假说所属 endpoint 组的结果，reached 仍取 OR
            #    （同端点多参数的既有语义），但绝不会吃批内其它端点的值。
            sub_dast = None
            picked = [v for k, v in by_h.items() if (not hashes) or (k in hashes)]
            if picked:
                merged: Dict[str, Any] = {}
                for d in picked:
                    for k, v in (d or {}).items():
                        if k == "reached":
                            merged["reached"] = bool(merged.get("reached")) or bool(v)
                        elif v:
                            merged.setdefault(k, v)
                sub_dast = merged
            sub_h = ({k: v for k, v in (result.per_hypothesis or {}).items() if k in hashes}
                     if hashes else dict(result.per_hypothesis or {}))
            try:
                sub_result = _dc.replace(result, per_hypothesis=sub_h)
            except Exception:
                sub_result = result
            results[i] = self._adjudicate_result(sub_result, vuln, specs, db=db, dast_impact=sub_dast)
        return results

    # ---------------- 业务逻辑漏洞：统一 verify() 透明路由到差分重放 ----------------
    @staticmethod
    def _resolve_business_logic_category(trigger_spec: Optional[Dict], vulnerability: Optional[Dict]) -> Optional[str]:
        """从 trigger_spec 或 vulnerability 解析业务逻辑类目；非业务逻辑返回 None。

        trigger_spec 带 business_logic_category 即为业务差分重放 spec；否则回退到 vulnerability
        的 a1_evidence.business_logic / category（A1 已把业务逻辑假说作为一级 findings 注入）。
        """
        spec = trigger_spec or {}
        cat = spec.get("business_logic_category") or spec.get("category")
        if not cat and isinstance(vulnerability, dict):
            ae = vulnerability.get("a1_evidence") or {}
            if ae.get("business_logic"):
                cat = ae.get("category")
        if not cat:
            return None
        norm = canonical_business_logic_family(cat)
        if norm not in _BUSINESS_LOGIC_CATEGORIES:
            return None
        # D1 重放路由特例：idor 在 D1 层归 bola（见 _BL_ROUTE_OVERRIDES）
        return _BL_ROUTE_OVERRIDES.get(norm, norm)

    def _verify_business_logic(
        self,
        category: str,
        trigger_spec: Dict[str, Any],
        external_target: Optional[Dict[str, Any]],
        vulnerability: Optional[Dict[str, Any]],
        iast_service: Optional[Any] = None,
        project_context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """业务逻辑漏洞统一验证：双账号差分重放（与 canary 污点重放并列，用户感知为『一次 D 阶段验证』）。

        canary 污点证明不了授权/归属，故 BOLA/越权/状态机/计算逻辑等必须走双账号差分重放
        （business_logic.verify → D1Service.replay_*）。结果折叠成与 canary 路径同构的
        VerificationResult，使下游聚合（_aggregate_d2_verdict / 攻击计划命中指标）无需区分来源。
        """
        from src.iast import business_logic as bl_mod

        # ── ⑤ HITL 闸门（2026-09-23 接入业务链路）：差分重放会改 victim 状态，属不可逆动作，
        # 在真正执行 bl_mod.verify 前（含账户 bootstrap）判是否需人放行；gate 时只回只读计划。
        _bl_act = _hitl_gate_for_spec(project_context or {}, trigger_spec)
        if _bl_act.get("hitl_configured") and _bl_act.get("irreversible"):
            if _bl_act.get("gate"):
                _record_hitl_gate_audit(_bl_act, "gated")
                return _build_hitl_gated_result(_bl_act)
            _record_hitl_gate_audit(_bl_act, "allowed")

        target = normalize_external_target(external_target or {}).to_dict()
        # 双账号优先级：trigger_spec > target(external_target) > vulnerability
        accounts = (
            trigger_spec.get("accounts")
            or target.get("accounts")
            or (vulnerability or {}).get("accounts")
        )
        # Point3 auth bootstrap：双账户类目（bola/垂直/跨模块）缺账户时，按 target.login
        # 真登录取 token，避免落到 canary 攻击路径或空跑。单账户/裸请求类目不强制。
        from src.iast.attack_context import needs_dual_accounts
        # R23-2：bootstrap 与 verify 必须共用真实 db（iast_service.db）。否则 D1Service 退化为
        # 临时库，bootstrap 的双账户 accounts_json 回写、以及 replay_* 的 victim_identifiers
        # 回填全部落在临时库 → 真实 DB 恒空（§6.13：victim_identifiers 0/144、0/167）。
        _real_db = getattr(iast_service, "db", None)
        if not accounts and needs_dual_accounts(category) and (target.get("login") or trigger_spec.get("login")):
            try:
                from src.application.d1_service import D1Service
                _boot = D1Service(db=_real_db).bootstrap_accounts(target, trigger_spec)
                if _boot:
                    accounts = _boot
            except Exception as _e:
                logger.warning("[D2] business_logic 账户 bootstrap 失败（降级 no_evidence）：%s", _e)
        try:
            bl_result = bl_mod.verify(category, trigger_spec, target, accounts=accounts, db=_real_db)
        except Exception as _e:  # 重放执行异常不应让整条流水线崩，降级为 no_evidence 并留痕
            logger.warning("[D2] business_logic.verify 异常（降级 no_evidence）：%s", _e)
            bl_result = {"confirmed": False, "confidence": "low", "category": category,
                         "reason": f"差分重放执行异常：{_e}"}

        # §消费端（用户指令第3/4点）：独立消费 IAST 可达性，而非补 taint transform 匹配。
        # 业务型无污点 source，故不靠 sink 污点证明；改消费「带 canary 的攻击请求是否命中
        # A2 预测操作/controller」这一可达性证据。探针侧（产出端）须对 target-mall 的
        # AccessDecisionManager 授权决策点织入 BOLA_SUSPECT/authz_hook 事件（携带 canary）——
        # 当前 task-9 实测 BOLA_SUSPECT=0，poll 回来是空，故 iast_reached 默认 False（fail-open，
        # 不污染差分结论）。一旦产出端补上，这里无需改动即可消费。
        iast_reached = False
        iast_authz_confirmed = False
        iast_event_count = 0
        authz_event_count = 0
        iast_event_types: List[str] = []
        if iast_service is not None:
            canary_raw = trigger_spec.get("taint_marker") or ""
            canary = CanaryMatcher.find_identity(canary_raw) or canary_raw
            app_name = trigger_spec.get("app_name") or target.get("app_name") or None
            agent_id = trigger_spec.get("agent_id") or target.get("agent_id") or None
            if canary:
                # §回归修复（ 并发引入）：探针事件经后端异步摄取端点落 iast_events，
                # 存在固有写入延迟。原实现只在 D2 verify 内做一次瞬时 poll，在高并发（12 worker 并
                # 行 + I1 后台采集）压垮摄取端点时，事件尚未 flush 即被判 no-iast-evidence，导致
                # BOLA/IDOR 等运行时确认从 task-2 基线 13 倒退到 task-3 的 1。复扫证明事件最终
                # 都落库且 canary 完全可匹配——纯属轮询竞态。此处改为有界轮询（命中即停，单测用
                # 非空的桩不产生 sleep），覆盖摄取延迟，恢复运行时确认闭环。
                _poll_attempts = int(trigger_spec.get("iast_poll_attempts") or 10)
                _poll_interval = float(trigger_spec.get("iast_poll_interval") or 1.5)
                rows = []
                blind = []
                # P2.1 埋点：本核验的轮询代价（次数 / 等待 / 是否命中）
                _p_used = 0
                _p_wait_ms = 0.0
                _p_hit = False
                for _attempt in range(max(1, _poll_attempts)):
                    _p_used += 1
                    try:
                        rows = iast_service.poll_events_by_canary(
                            canary, 0, 50,
                            app_name=app_name, agent_id=agent_id,
                        ) or []
                        blind = iast_service.poll_authz_blindspots(
                            canary, app_name=app_name, agent_id=agent_id,
                        ) or []
                    except Exception as _e:  # 探针查询异常不应让整条流水线崩，fail-open 回退差分结论
                        logger.warning("[D2] 业务 IAST 可达性消费异常（fail-open）：%s", _e)
                        rows = []
                        blind = []
                        break
                    if rows or blind:
                        _p_hit = True
                        break
                    if _attempt < max(1, _poll_attempts) - 1:
                        time.sleep(_poll_interval)
                        _p_wait_ms += _poll_interval * 1000.0
                # 聚合进模块级统计（只读观测，不影响任何判定）
                try:
                    _POLL_STATS["verifications"] = int(_POLL_STATS.get("verifications") or 0) + 1
                    _POLL_STATS["total_attempts"] = int(_POLL_STATS.get("total_attempts") or 0) + _p_used
                    _POLL_STATS["total_wait_ms"] = float(_POLL_STATS.get("total_wait_ms") or 0.0) + _p_wait_ms
                    _POLL_STATS["max_wait_ms"] = max(float(_POLL_STATS.get("max_wait_ms") or 0.0), _p_wait_ms)
                    if _p_hit:
                        _POLL_STATS["hit"] = int(_POLL_STATS.get("hit") or 0) + 1
                    else:
                        _POLL_STATS["timeout"] = int(_POLL_STATS.get("timeout") or 0) + 1
                except Exception:  # noqa: BLE001  埋点失败绝不影响主流程
                    pass
                iast_event_count = len(rows)
                iast_event_types = sorted({str(r.get("event_type", "") or "") for r in rows})
                # canary 仅注入攻击请求，故任何带此 canary 的事件即证明攻击请求
                # 命中了被探针插桩的操作/controller/sink（可达性证据）。
                iast_reached = iast_event_count > 0
                authz_event_count = len(blind)
                # 机制级确认：探针在授权决策点证明「访问了域对象但无对象级归属校验」。
                iast_authz_confirmed = authz_event_count > 0
            else:
                logger.debug("[D2] business_logic 无 taint_marker，跳过 IAST 可达性消费")

        diff_confirmed = bool(bl_result.get("confirmed"))
        # 设计二②：消费 replay_race 返回的可观测副作用确认（victim 状态 before-after 差分 / 并发双成功）。
        side_effect_confirmed = bool(
            bl_result.get("business_confirmed") or bl_result.get("observed_side_effect")
        )
        # confirmed = 差分确认 OR 可观测副作用确认（业务状态被真实改动）。
        # v2 证据分层 B4：移除 iast_reached —— 业务族「仅到达应用」不构成有害判定，
        # 必须差分式确认（越权差异）或副作用确认，避免「到达即越权」误报（trustbound 族尤其）。
        # F 批回归锁修正（2026-10-10）：iast_authz_confirmed（探针在授权决策点证明「访问域对象
        # 但无对象级归属校验」）是机制级语义证据，不是「仅到达」—— 与 B3 迟到补捞路径
        # （authz 盲点 → 直接确认）及 adjudicate_final_state 的 authz_hook_confirmed 分支同口径。
        confirmed = diff_confirmed or side_effect_confirmed or iast_authz_confirmed
        confirmation_source = (
            "iast-authz" if iast_authz_confirmed
            else "iast-reach" if iast_reached
            else "side-effect" if side_effect_confirmed
            else "differential" if diff_confirmed
            else "none"
        )
        confidence = str(bl_result.get("confidence") or ("high" if confirmed else "low"))
        cat = str(bl_result.get("category") or category)

        # ── C 批（2026-10-10，证据分层诚实声明）：双账号差分矩阵三态 + correct_reject 阴性 +
        # 诚实降级 + 时序竞态声明。均**不改变确认逻辑**（confirmed 仍由 B4 的 diff/side-effect 决定，
        # 见上方），只在 iast_evidence / verification_decision 上补「诚实声明」元数据，使报告能区分
        # 「真阴性（正确拒绝）」与「证据缺失（ambiguous）」，杜绝把「没验出来」当成「没漏洞」。
        #   - confirmed      ：差分确实观测到越权差异 / 副作用 → 真阳性。
        #   - no_difference  ：差分**真跑了**且高置信无差异 → 真阴性（correct_reject，正确拒绝）。
        #   - ambiguous      ：差分没跑成（缺双账户 / 被破坏性闸门 skip / 回滚失败）→ 证据缺失，
        #                      绝不臆断无害，交 HITL / 人工复核。
        _replay_ran = bool(accounts) and not bl_result.get("skipped")
        _verdict = str(bl_result.get("verdict") or "")
        differential_state = differential_three_state(confirmed, _replay_ran, _verdict)
        correct_reject = (differential_state == "no_difference")
        # trustbound 诚实降级：信任边界类目（若经此路径或经 canary 路径）只要不是 confirmed，
        # 一律按证据缺失 / 真阴性诚实降级，绝不强行确认或强行判无漏洞（B6 闸门已约束 canary 路径）。
        _is_trustbound = (cat in ("trust_boundary_violation", "trustbound", "trust_boundary"))
        trustbound_honest_downgrade = (_is_trustbound and differential_state != "confirmed")
        # 时序竞态声明：IAST 可达性消费走了有界轮询（见上方轮询修复），若最终仍未取到任何事件、
        # 且结论非 confirmed，声明本结论可能受「探针摄取竞态」影响（诚实标注，不臆断无害）。
        timing_race_declared = (
            (not iast_reached and not iast_authz_confirmed)
            and int(trigger_spec.get("iast_poll_attempts") or 10) > 1
            and not confirmed
        )
        reason = str(bl_result.get("reason") or "")
        if not reason:
            if confirmed:
                if confirmation_source == "iast-authz":
                    reason = (
                        f"业务逻辑 IAST 授权 hook 确认（{cat}）：探针观测到攻击请求在授权决策点未做对象级归属校验"
                        f"（BOLA_SUSPECT），带 canary 的攻击请求命中预测操作"
                    )
                elif confirmation_source == "iast-reach":
                    reason = (
                        f"业务逻辑 IAST 可达性确认（{cat}）：带 canary 的攻击请求命中 A2 预测操作/controller"
                        f"（事件类型：{', '.join(iast_event_types) or 'n/a'}），差分未单独确认"
                    )
                elif confirmation_source == "side-effect":
                    reason = (
                        f"业务逻辑可观测副作用确认（{cat}）：重放导致可观测业务状态异常变化"
                        f"（observed_side_effect={bl_result.get('observed_side_effect')}），证明结果点有害"
                    )
                else:
                    reason = f"业务逻辑差分确认（{cat}）：攻击者账户成功访问受害者资源，结果点有害"
            else:
                reason = (
                    f"业务逻辑重放（{cat}）未确认：差分无数据泄露、且无 IAST 可达性/授权 hook 证据"
                    f"（iast_event_count={iast_event_count}, authz_event_count={authz_event_count}）"
                )
        vr = VerificationResult(
            exploitable=confirmed,
            confidence=confidence,
            reason=reason,
            business_confirmed=confirmed,
            evidence=[
                f"business_logic:{cat}",
                f"data_leak={bool(bl_result.get('data_leak_confirmed'))}",
                f"authz_hook={bool(bl_result.get('authz_hook_confirmed'))}",
                f"side_effect_confirmed={side_effect_confirmed}",
            ],
        )
        vr.final_state = "confirmed" if confirmed else "no_evidence"
        # 真实状态（替换合成 state）：优先 IAST 机制级确认，其次 IAST 可达性，再次副作用/差分确认，最后无证据。
        if iast_authz_confirmed:
            iast_state = "iast-authz-confirmed"
        elif iast_reached:
            iast_state = "iast-reached"
        elif diff_confirmed:
            iast_state = "business-logic-confirmed"
        elif side_effect_confirmed:
            iast_state = "business-side-effect-confirmed"
        else:
            iast_state = "no-iast-evidence"
        vr.iast_evidence = {
            "state": iast_state,
            "business_logic": True,
            "iast_reached": iast_reached,
            "iast_authz_confirmed": iast_authz_confirmed,
            "iast_event_count": iast_event_count,
            "authz_event_count": authz_event_count,
            "iast_event_types": iast_event_types,
            "confirmed_via": confirmation_source,
            "authz_hook_confirmed": bool(bl_result.get("authz_hook_confirmed")),
            "data_leak_confirmed": bool(bl_result.get("data_leak_confirmed")),
            "side_effect_confirmed": side_effect_confirmed,
            "observed_side_effect": bl_result.get("observed_side_effect"),
            "victim_account_snapshot": bl_result.get("victim_account_snapshot"),
            # C 批诚实声明：差分矩阵三态 / 真阴性 / 诚实降级 / 时序竞态
            "differential_state": differential_state,
            "correct_reject": correct_reject,
            "trustbound_honest_downgrade": trustbound_honest_downgrade,
            "timing_race_declared": timing_race_declared,
        }
        vr.dast_impact_evidence = {
            "reached": bool(bl_result.get("data_leak_confirmed")),
            "business_logic": {
                "confirmed": confirmed,
                "category": cat,
                "data_leak": bool(bl_result.get("data_leak_confirmed")),
                "authz_hook": bool(bl_result.get("authz_hook_confirmed")),
                "side_effect_confirmed": side_effect_confirmed,
                "observed_side_effect": bl_result.get("observed_side_effect"),
            },
        }
        vr.d2_verdict = {
            "harmful": confirmed,
            "business_logic_confirmed": confirmed,
            "confidence": confidence,
            "reason": reason,
            # C 批诚实声明
            "differential_state": differential_state,
            "correct_reject": correct_reject,
            "trustbound_honest_downgrade": trustbound_honest_downgrade,
            "timing_race_declared": timing_race_declared,
        }
        vr.verification_decision = {
            "verification_status": "confirmed_exploitable" if confirmed else "unconfirmed",
            "judge_reason": reason,
            "final_state": vr.final_state,
            "business_logic": True,
            "category": cat,
            # C 批诚实声明：真阴性（正确拒绝）与证据缺失（ambiguous）必须区分，
            # 否则报告会把「没验出来」误读为「没漏洞」。
            "differential_state": differential_state,
            "correct_reject": correct_reject,
            "trustbound_honest_downgrade": trustbound_honest_downgrade,
            "timing_race_declared": timing_race_declared,
        }
        return vr


def _iast_stream_head(iast_service: Any, app_name: Optional[str], agent_id: Optional[str]) -> Optional[int]:
    """当前 iast_events 的最大 id，用于判定探针事件摄取流是否仍在推进。

    取不到（无表 / 无 db / 异常）一律返回 None，由调用方按「无法观测」处理，不抛。
    """
    try:
        db = getattr(iast_service, "db", None)
        if db is None:
            return None
        sql = "SELECT MAX(id) FROM iast_events"
        params: List[Any] = []
        if app_name is not None or agent_id is not None:
            sql += " WHERE 1 = 1"
            if app_name is not None:
                sql += " AND app_name = ?"
                params.append(app_name)
            if agent_id is not None:
                sql += " AND agent_id = ?"
                params.append(agent_id)
        rows = db.execute(sql, params, fetchall=True) or []
        if not rows:
            return None
        first = rows[0]
        if isinstance(first, (tuple, list)):
            val = first[0]
        elif isinstance(first, dict):
            val = list(first.values())[0]
        else:
            val = first
        return int(val) if val is not None else None
    except Exception:
        return None


# 2026-10-29：迟到证据补捞的**适用状态集**。
# 只收「未观测态」——即裁决当时认定「canary 没到 / 没有证据」的结论；已到达（arrived /
# sink-reached / sink-reached-probe）与已确认的裁决一律不进补捞，保证方向单调（只会把
# 漏判补成到达/确认，绝不会把已有确认改坏）。
#   - no-iast-evidence：BL 业务逻辑路径专属（原补捞范围）
#   - no-arrival / genuine_no_arrival / probe_unavailable：非 BL 路径的「没到」
#   - no_evidence：D2 兜底无证据态
_LATE_RECONCILE_STATES = frozenset({
    "no-iast-evidence",
    "no-arrival",
    "genuine_no_arrival",
    "probe_unavailable",
    "no_evidence",
})

# 2026-10-29：属性族 / 业务族**不参与运行时迟到补捞**。
# 这些族的「有害」不靠 canary 到 sink 证明：
#   - weak_hash / crypto / weak_random：安全用例（SHA-256 / SecureRandom）同样把 canary 送进
#     MessageDigest.getInstance / Cipher.getInstance，「到达 + hit_live」会把安全用例全判成漏洞；
#   - secure_cookie：Cookie 构造天然带 canary，缺 setSecure 才是问题，与到达无关；
#   - calculation_logic：业务逻辑族，确认靠差分。
# 用子串匹配覆盖族名变体（weak_hash / insecure crypto algorithm / weak_crypto / secure_cookie）。
_LATE_PROPERTY_FAMILY_HINTS = (
    "hash", "crypto", "random", "secure_cookie", "securecookie",
    "calculation_logic", "business_logic",
)


def _is_late_property_family(family: str) -> bool:
    f = (family or "").lower()
    return any(h in f for h in _LATE_PROPERTY_FAMILY_HINTS)


def _wait_for_ingest_quiescence(iast_service: Any, app_name: Optional[str] = None,
                                agent_id: Optional[str] = None, quiet_seconds: float = 20.0,
                                max_wait: float = 180.0, poll_interval: float = 3.0) -> int:
    """等探针事件摄取流静止：连续 quiet_seconds 内无新事件即返回。

    返回等待期间观察到的新增事件数（用于日志与度量）。到达 max_wait 立即返回，绝不无限等。
    """
    head0 = _iast_stream_head(iast_service, app_name, agent_id)
    if head0 is None:
        return 0
    deadline = time.time() + max(0.0, float(max_wait))
    last = int(head0)
    last_change = time.time()
    while time.time() < deadline:
        time.sleep(poll_interval)
        cur = _iast_stream_head(iast_service, app_name, agent_id)
        if cur is None:
            break
        if int(cur) > last:
            last = int(cur)
            last_change = time.time()
            continue
        if (time.time() - last_change) >= float(quiet_seconds):
            break
    return max(0, last - int(head0))


def reconcile_late_iast_evidence(phase1_items, iast_service: Any, app_name: Optional[str] = None,
                                 agent_id: Optional[str] = None, quiet_seconds: Optional[float] = None,
                                 max_wait: Optional[float] = None) -> int:
    """Phase1（并发 verify）结束后，对仍判 no-iast-evidence 的 spec 做一次迟到证据补捞。

    根因：D2 裁决与探针事件摄取是并发的。per-spec 有界轮询窗口（默认 15×1.5s≈22s）远小于
    真实摄取延迟——实测 task-7 里事件摄取跨度 04:40:23→04:44:51（约 4.5 分钟），而 D2 阶段
    是 04:40:22→04:44:42，两者几乎完全重叠。于是事件最终落库、canary 也完全可匹配
    （spec815↔事件2640、spec763↔事件2743 身份段逐字符相同），但裁决早已按
    no-iast-evidence 定稿，造成「sink_reached=1 却 iast_state=no-iast-evidence」的矛盾行。

    修法：Phase1 全部重放结束后先做**一次全局**摄取静止等待（比让每个 spec 各自干等廉价得多），
    再对仍为 no-iast-evidence 的 spec 按 canary 重查；查到即按既有确认口径升级
    （BL 路径本来就是 confirmed = 差分 or IAST 可达性 or 副作用），并同步
    verification_decision，让 Phase2 的 trigger_specs 回写拿到升级后的状态。

    返回被升级的 spec 数。
    """
    if iast_service is None or not phase1_items:
        return 0
    _qs = float(os.environ.get("SAST_AI_I1_QUIET_SECONDS")
                or (quiet_seconds if quiet_seconds is not None else 20.0))
    _mw = float(os.environ.get("SAST_AI_I1_MAX_WAIT")
                or (max_wait if max_wait is not None else 180.0))
    try:
        added = _wait_for_ingest_quiescence(iast_service, app_name, agent_id,
                                            quiet_seconds=_qs, max_wait=_mw)
        logger.info("[D2][late-evidence] 摄取静止等待结束：等待期间新增事件=%s", added)
    except Exception as _qe:  # 等静止失败不应阻断补捞本身
        logger.warning("[D2][late-evidence] 摄取静止等待异常（继续补捞）：%s", _qe)

    upgraded = 0
    for item in phase1_items:
        try:
            result, ts, _vhash = item[:3]
        except Exception:
            continue
        if result is None or not ts:
            continue
        ev = getattr(result, "iast_evidence", None) or {}
        # 2026-10-29（本轮实证）：补捞范围从「BL 路径专属 no-iast-evidence」扩到**全部未观测态**。
        # 根因：D2 裁决与探针摄取并发，而 ingest 落库要与 D2 抢 SQLite 单写者锁（db.py 全局 RLock），
        # 探针 POST 被阻塞 → 事件按 ~4 分钟一批落库，普遍晚于裁决。实测 13 个 trustbound 用例在
        # iast_events 里都有 canary_state=sink-reached-probe + 真 sink（StandardSessionFacade.setAttribute）
        # 事件，却全部被判 no-arrival → 召回 27/28 掉到 14/28。
        # 门禁只放「未观测态」：已到达/已确认的裁决不进补捞，方向单调，不可能把确认改坏。
        _late_state = str(ev.get("state") or "")
        if _late_state not in _LATE_RECONCILE_STATES:
            continue
        marker = str(ts.get("taint_marker") or "")
        canary = CanaryMatcher.find_identity(marker) or marker
        if not canary:
            continue
        try:
            # limit 从 50 抬到 200：一个 spec 的 canary 常伴生几十条 TAINT_FLOW + 多臂 oracle 事件，
            # 50 条窗口会把「最靠后的真 sink SINK_HIT」截掉（本轮实测 01550 单 canary 48 条，
            # 已贴边）→ 迟到补捞看不到 sink-reached-probe，白等。
            rows = iast_service.poll_events_by_canary(canary, 0, 200,
                                                      app_name=app_name, agent_id=agent_id) or []
            blind = iast_service.poll_authz_blindspots(canary, app_name=app_name,
                                                       agent_id=agent_id) or []
        except Exception as _pe:
            logger.warning("[D2][late-evidence] canary=%s 重查异常（跳过）：%s", canary[:24], _pe)
            continue
        # D5（2026-10-10）：no-iast-evidence 归因二分——从已轮询事件提取 hook_inventory，
        # 判断「本轮没拿到任何探针记录」是探针组件缺陷（关键 hook 未织入）还是 A2/D1 攻击计划缺陷
        # （hook 就位但 canary 没投到正确入口）。证据缺失（无 hook_inventory）一律 unknown，不臆断。
        try:
            _inv = TriggerTransactionOrchestrator.extract_hook_inventory(rows)
            _bl_cat = str(ts.get("business_logic_category") or ts.get("category") or "")
            _attr = TriggerTransactionOrchestrator.attribute_no_iast_evidence(_bl_cat, _inv)
        except Exception:
            _attr = "unknown"
        if not rows and not blind:
            # 连普通事件都没有：把归因（可能 unknown）落到 verification_decision，供判责统计。
            try:
                vd = getattr(result, "verification_decision", None)
                if not isinstance(vd, dict):
                    vd = {}
                vd["no_evidence_attribution"] = _attr
                result.verification_decision = vd
            except Exception:
                pass
            continue
        new_ev = dict(ev)
        new_ev["iast_reached"] = True
        new_ev["iast_event_count"] = len(rows)
        new_ev["authz_event_count"] = len(blind)
        new_ev["iast_event_types"] = sorted({str(r.get("event_type") or "") for r in rows})
        new_ev["late_reconciled"] = True
        if _late_state == "no-iast-evidence":
            # B3（2026-10-10）：BL 迟到补捞必须过确认闸 + 消毒校验，否则只升 unconfirmed。
            #   - authz 盲点命中（blind）是本族真实的业务越权旁证 → 直接确认；
            #   - 仅「到达」的普通 IAST 事件（iast-reached）不构成 BL 语义证据，必须按 B6 收紧，
            #     只升 unconfirmed，交后续 HITL / 人工复核，绝不臆断有害。
            if blind:
                new_ev["iast_authz_confirmed"] = True
                new_ev["state"] = "iast-authz-confirmed"
                _confirmed = True
            else:
                new_ev["state"] = "iast-reached"
                # 即便只是普通 IAST 到达，也再扫一遍语义层：若某条事件里我方投放数据真的到了
                # sink 实参（值级 live 命中）或抛出了本族 sink 异常签名，仍视为有语义证据，准予确认；
                # 否则一律 unconfirmed（证据缺失，fail-open）。消毒命中（hit_sanitized）不计入语义。
                _confirmed = False
                try:
                    for _r in rows:
                        try:
                            _vh = compute_value_hit(canary, _r)
                        except Exception:
                            _vh = {}
                        if _vh.get("form") == "hit_live":
                            _confirmed = True
                            break
                        _exc = str((_r.get("sink_exception_class")
                                    or (_r.get("evidence") or {}).get("sink_exception_class")
                                    or "") or "")
                        if _exc:
                            _confirmed = True
                            break
                except Exception:
                    _confirmed = False
        else:
            # 2026-10-29：非 BL 路径的迟到补捞——只认「探针在**本族真实 sink** 上
            # 断言到的到达态」。判据与 correlation.confirmed_runtime / adjudicator 完全一致：
            #   state ∈ {sink-reached, sink-reached-probe} 且 is_genuine_sink_identity(sink, family)。
            # 这样补捞出来的确认与原路径能得出的最强结论同源，不会放宽口径：
            #   - trustbound 只认 setAttribute/putValue 白名单（Cookie 假 sink 不算）；
            #   - 响应写入族（xss/ssti）按族例外；
            #   - 其它族未知 sink fail-open（零误杀原则，与 is_genuine_sink_identity 一致）。
            _fam_late = str(ts.get("family") or ts.get("category") or "")
            if _is_late_property_family(_fam_late):
                # 属性族/业务族不参与运行时补捞（见 _LATE_PROPERTY_FAMILY_HINTS 注释）：
                # 它们的「有害」靠静态强算法门禁 / 业务差分，canary 到达安全算法同样成立。
                continue
            _genuine: List[Any] = []
            for _r in rows:
                try:
                    _st = str(_r.get("canary_state") or "")
                    _sf = str(_r.get("sink_file") or "")
                except Exception:
                    continue
                if not is_sink_reached(_st):
                    continue
                if not is_genuine_sink_identity(_sf, _fam_late):
                    continue
                # 2026-10-30：**不再在这里查 is_family_relevant_sink**。
                # 原意是挡住跨族冒充（本轮实测 31 条 sql_injection spec 落在 session
                # putValue 上），但它在补捞侧比主路径更严，导致同一份事件因「到得早晚」得出
                # 两种结论（本轮 6 个 path_traversal TP 被挡在补捞之外，主路径却认）。
                # 跨族冒充改由共享判据兜：is_genuine_sink_identity 已内置
                # 「session 写入只对 trustbound 有意义」「Cookie 构造只对 secure_cookie 有意义」。
                _genuine.append((STATE_RANK_STR.get(_st, 0), _st, _sf, _r))
            if not _genuine:
                # 事件到了但没落在本族真 sink 上 → 维持原判，不臆断。
                continue
            _genuine.sort(key=lambda _x: _x[0], reverse=True)
            _best_rank, _best_state, _best_sink, _best_row = _genuine[0]
            new_ev["state"] = _best_state
            new_ev["matched_sink_file"] = _best_sink
            new_ev["reached_sink_files"] = sorted({_g[2] for _g in _genuine if _g[2]})
            # 值级证据必须一并补：确认闸 的语义层认 `value_hit.form == hit_live`，
            # 只补 state 不补 value_hit 会在 Phase2 被三准入降级回 unconfirmed（白补）。
            try:
                _vh_late = compute_value_hit(canary, _best_row)
            except Exception:
                _vh_late = {}
            if _vh_late:
                new_ev["value_hit"] = _vh_late
            new_ev["late_sink_verified"] = True
            new_ev["late_reconcile_prev_state"] = _late_state
            # 与主路径同源：确认强度取决于语义层（hit_live / sink 异常签名），与 BL 分支一致。
            _confirmed = bool((_vh_late or {}).get("form") == "hit_live")
            _attr = "late_evidence_genuine_sink"
            logger.info(
                "[D2][late-evidence] 非 BL 迟到补捞命中：spec=%s fam=%s %s→%s sink=%s value_hit=%s",
                ts.get("id"), _fam_late, _late_state, _best_state, _best_sink,
                (_vh_late or {}).get("form"),
            )
        result.iast_evidence = new_ev
        vd = getattr(result, "verification_decision", None)
        if not isinstance(vd, dict):
            vd = {}
        vd["late_reconciled"] = True
        # D5（2026-10-10）：把归因二分落到 verification_decision，供判责统计（重放智能化是否有用）。
        vd["no_evidence_attribution"] = _attr
        if _confirmed:
            vd["verification_status"] = "confirmed_exploitable"
            result.exploitable = True
            result.business_confirmed = True
            try:
                result.final_state = "confirmed"
            except Exception:
                pass
        else:
            # B3：仅到达无语义 → 不臆断有害。
            #   - BL 路径：升 unconfirmed（BL 语义证据缺失，保持既有口径，测试已锁）
            #   - 非 BL 路径：记 sink_reached（"到了但没确认有害"，与主路径同口径；
            #     比 unconfirmed 更准确，且不会被任何确认闸当成已确认）
            vd["verification_status"] = (
                "sink_reached" if _late_state != "no-iast-evidence" else "unconfirmed"
            )
            result.exploitable = False
            result.business_confirmed = False
            try:
                result.final_state = (
                    "sink_reached" if _late_state != "no-iast-evidence" else "unconfirmed"
                )
            except Exception:
                pass
        result.verification_decision = vd
        upgraded += 1
        logger.info("[D2][late-evidence] 补捞升级 spec=%s canary=%s state=%s confirmed=%s events=%s authz=%s",
                    ts.get("id"), canary[:24], new_ev["state"], _confirmed, len(rows), len(blind))
    logger.info("[D2][late-evidence] 迟到证据补捞完成：升级 %s 条", upgraded)
    return upgraded


def _aggregate_proof_diff(i2_decisions) -> Dict[str, Any]:
    """闭环信号汇总：A2 声称的 flow ⊖ I2 解析后的 flow = 残差 diff（跨 spec 合并）。

    newly_closed 是本轮运行时证据新闭合的证明义务；refuted 是被运行时证据反驳的
    （例如确实观测到 sanitizer）；still_open 是仍未闭合的，作为下一轮反思的靶子。
    """
    closed, refuted, still_open, newly = set(), set(), set(), set()
    for d in i2_decisions or []:
        pr = dict(getattr(d, "proof_resolution", {}) or {})
        closed.update(pr.get("closed") or [])
        refuted.update(pr.get("refuted") or [])
        still_open.update(pr.get("open") or [])
        newly.update((pr.get("residual") or {}).get("newly_closed") or [])
    return {
        "closed": sorted(closed),
        "refuted": sorted(refuted),
        "still_open": sorted(still_open),
        "newly_closed": sorted(newly),
    }


def _build_verification_result(i2_decisions, iast_evidence, dast_impact_evidence, d2_verdict) -> "VerificationResult":
    """把 I2 逐条裁决合并成单条 VerificationResult（保持与既有调用方 / 前端兼容）。

    - 多 spec 取最强 final_state；
    - 整体 action 优先 rollback_to_a2（存在不符合假说 → 回灌 A2 重新推导），其次 re_send，否则 pass；
    - 每条 spec 的 I2Decision 与回灌 A2 的反馈清单写入 verification_decision / next_action，供闭环反思消费。
    """
    if not i2_decisions:
        vr = VerificationResult(
            exploitable=False, confidence="low", reason="I2 未产出任何裁决（无 I1/D2 证据）", evidence=[],
        )
        vr.final_state = FINAL_NO_EVIDENCE
        vr.iast_evidence = iast_evidence
        vr.dast_impact_evidence = dast_impact_evidence
        vr.d2_verdict = d2_verdict
        vr.verification_decision = {
            "verification_status": "unconfirmed", "judge_reason": vr.reason, "final_state": FINAL_NO_EVIDENCE,
        }
        return vr

    strongest = max(i2_decisions, key=lambda d: _FINAL_STATE_RANK.get(d.final_state, 0))
    confirmed = bool(strongest.confirmed)
    # ── 到达 ≠ 可利用：仅靠探针断言（证明力 2）时不落 confirmed_exploitable ──
    # 2026-10-07（r64c 实测，方法A 收尾）。判据全部取自**落库的真实字段**，不猜：
    #   r64c 的 105 条 confirmed 里，primary_channel **100% 是 probe_sink_assert**
    #   （evidence_strength=2），即「探针在危险函数实参里断言到投放的数据」。
    #   该通道只证明**污点抵达**，不证明**利用成功**，而 OWASP 真值口径下它 FP 率 35%
    #   （真TP 68 / 真FP 37）。
    #
    # 为什么必须降级而不是继续挂着 confirmed：
    #   「confirmed_exploitable」在报告/前端会被读成「已证实可利用」，是**误导性标签**。
    #   能力边界应当如实呈现，而不是用 64.8% 这种数字自我说服。
    #
    # 降级范围**严格限定**：只有当主判据是探针断言（证明力 2，且无更高阶通道支撑）时才降。
    # 带外回调(4) / 跨请求回显(3) / 结果点比对(3) / 语义差分(3) / 时间盲注(2, 达标即真延时)
    # 支撑的确认**一律不动** —— 它们是真正的可利用性证据，降级会误伤真阳性。
    # 时间盲注虽同为证明力 2，但它的 harmful 来自「延时差分达标」，与探针断言不同源，
    # 故按通道名精确排除，不按 strength 粗暴比较。
    #
    # 开关：SAST_AI_D2_ARRIVAL_ONLY=0 可恢复旧行为（回滚/A-B 口径用）。
    _ARRIVAL_ONLY = os.environ.get("SAST_AI_D2_ARRIVAL_ONLY", "1") not in (
        "0", "", "false", "False", "no")
    _ARRIVAL_ONLY_CHANNELS = ("probe_sink_assert",)
    # 2026-10-13 补：r88 实测 6 个误报（run 331 的 sqli 安全用例）primary_channel='none'
    # —— 即**没有任何证据通道命中**（无值级、无 OOB、无差分有害、无异常类），却仍被 I2
    # 落 confirmed_exploitable。原白名单只拦 probe_sink_assert，'none' 反而绕过了降级。
    # 铁律：无证据通道 = 证据缺失，判据只许做正向，不得落 confirmed。
    _NO_EVIDENCE_CHANNELS = ("none", "", "unknown")
    _primary = str((d2_verdict or {}).get("primary_channel") or "").strip()
    # 2026-10-07 修正（回归锁 tests/test_iast_orchestrator.py 抓到）：
    # 原判据只看 primary_channel，会把**有 DAST 真实影响证据**的 spec 一并降级 ——
    # 那是误伤。impact_observed / data_leak_confirmed / business_logic_confirmed 都意味着
    # 「攻击真的产生了后果」，本身就是可利用性证据，优先于「canary 到了 sink」。
    _die = dast_impact_evidence or {}
    _has_real_impact = bool(
        _die.get("impact_observed")
        or _die.get("data_leak_confirmed")
        or (isinstance(_die.get("business_logic"), dict) and _die["business_logic"].get("confirmed"))
    )
    # 值级证据豁免：探针在 sink 实参里比对到 canary 值（value_level_sink_arg 通道）是强证据，
    # 即便 primary_channel 因迟到证据/通道注册竞态未回填，也不得因此降级真阳性。
    _value_hit = bool(
        _die.get("value_level_hit")
        or ((iast_evidence or {}).get("value_hit") or {}).get("hit"))
    _primary_norm = (_primary or "none").strip().lower()
    _no_evidence_channel = _primary_norm in _NO_EVIDENCE_CHANNELS
    # 2026-10-31（本轮实证）：**只豁免行为 oracle 正向**这一种，不放宽到所有
    # 「可归因确认」。原因：final_state=confirmed_attributable 也可能来自「探针断言 +
    # 结果点有害」，那属于「到达 ≠ 可利用」，必须照旧降级（r64c 实测该通道 FP 率 35%，
    # 回归锁 tests/test_iast_orchestrator.py::test_facade_verify_via_iast_trigger_end_to_end
    # 就锁着这条）。
    # 而 oracle 的布尔差分 / 时延 / 文件签名 / 响应头回显是**独立于探针**的黑盒行为证据，
    # 证明力高于「canary 到了 sink」，被 _no_evidence_channel（primary_channel='none'）
    # 连带降级是错的。实测 /urlRedirect/redirect（location_reflect）、
    # /path_traversal/vul（file_signature）两条 oracle=exploitable 都被这条降级砍掉。
    _oracle_positive = (
        str((iast_evidence or {}).get("oracle_state") or "") == "exploitable"
        and bool(str((iast_evidence or {}).get("oracle_signal") or "").strip())
    )
    _arrival_only_hit = bool(
        _ARRIVAL_ONLY and not _has_real_impact and not _value_hit and not _oracle_positive
        and (_primary in _ARRIVAL_ONLY_CHANNELS or _no_evidence_channel))
    actions = [d.action for d in i2_decisions]
    # Q1 一致性闸门：I2 终态已因 sink 身份校验把噪声 sink 降为不明确（见 adjudicator 的
    # noise_sink_reached 分支），此处再兜一层「运行时层明确判未确证有害 ⇒ 不得落 confirmed」。
    # 两条判据同源于 sink_identity，若仍出现冲突（如迟到证据只改 state 未回填 sink_file、
    # 或未来新增旁路通道），一律以运行时层为准降级，绝不让 spec 层单方面标 confirmed。
    #
    # 判据不能只看 harmful=False：降级攻击（attack_degraded）、业务族差分、反序列化链、OOB
    # 等独立确认通道都合法返回 harmful=False 却仍应确认。只有「sink 态被判定为假」才是
    # 真冲突——_verify_sink_result 的所有非确认分支里，兜底那支带 sink_reached=genuine_sink_reached，
    # 噪声 sink 时为 False；真抵达但结果点未打出效果时为 True。据此精确取「假 sink 抵达」。
    _d2v = d2_verdict or {}
    _false_sink_reached = (
        ("harmful" in _d2v)
        and (not _d2v.get("harmful"))
        and (_d2v.get("sink_reached") is False)
    )
    if confirmed and _false_sink_reached:
        confirmed = False
    # Q1：一致性闸门触发时必须改写 overall_action 与 prefix，否则会出现「action=pass 且
    # 结论未确认」的自相矛盾文案，且前端看不到降级原因。
    _q1_downgraded = bool(strongest.confirmed) and not confirmed
    if "rollback_to_a2" in actions:
        overall_action = "rollback_to_a2"
        prefix = "I2 裁决：存在不符合的假说，回灌 A2 重新推导。"
    elif "re_send" in actions:
        overall_action = "re_send"
        prefix = "I2 裁决：D1 重放需重发修正触发参数。"
    else:
        overall_action = "pass"
        prefix = "I2 裁决：全部 spec 通过统一链路验证。"
    if _q1_downgraded:
        overall_action = "re_send"
        prefix = (
            "I2 一致性闸门：canary 抵达的 sink 被判为框架噪声 sink（非本族真实危险函数），"
            "运行时层未确证有害，故不落 confirmed_exploitable，降为待补证。"
        )

    feedback_to_a2 = [d.feedback_to_a2 for d in i2_decisions if d.feedback_to_a2]
    reasons = [f"[{d.hypothesis_id}] {d.reason}" for d in i2_decisions]

    # 到达判定降级的对外表达（见上方 _ARRIVAL_ONLY 注释）：
    # 状态降为 sink_reached（已确认抵达，未证实可利用），exploitable 一并置 False。
    # 保留 confirmed_raw 供对账/审计还原「若未降级会是什么」，不丢信息。
    _status = ("sink_reached" if (_arrival_only_hit and confirmed)
               else ("confirmed_exploitable" if confirmed else "unconfirmed"))
    _arrival_note = ""
    if _arrival_only_hit and confirmed:
        _arrival_note = (
            "【运行时能力边界】本次确认的唯一依据是探针在危险函数实参里断言到投放数据"
            "（primary_channel=%s，证明力 2），它只证明「污点抵达危险函数」，"
            "不证明「利用成功」。故不标 confirmed_exploitable，改为 sink_reached —— "
            "若要证实利用，需带外回连/结果点内容比对等独立证据（当前未具备）。" % (_primary or "?"))

    vr = VerificationResult(
        exploitable=(confirmed and not _arrival_only_hit),
        confidence=strongest.confidence,
        reason=(prefix + " " if not _arrival_note else _arrival_note + " ") + " | ".join(reasons),
        evidence=reasons,
    )
    vr.iast_evidence = iast_evidence
    vr.dast_impact_evidence = dast_impact_evidence
    vr.d2_verdict = d2_verdict
    vr.final_state = strongest.final_state
    vr.next_action = {
        "action": overall_action,
        "reason": prefix,
        "per_spec": [d.__dict__ for d in i2_decisions],
        "feedback_to_a2": feedback_to_a2,
        "proof_diff": _aggregate_proof_diff(i2_decisions),
        "retry": overall_action == "re_send",
    }
    # 向下游报告兼容：五态映射回 verification_decision，并附带逐条裁决与回灌提示。
    vr.verification_decision = {
        "verification_status": _status,
        "judge_reason": vr.reason,
        "final_state": strongest.final_state,
        "per_spec_decisions": [d.__dict__ for d in i2_decisions],
        "feedback_to_a2": feedback_to_a2,
        "proof_diff": _aggregate_proof_diff(i2_decisions),
        # Q1：显式记录本次是否被一致性闸门降级，供 DB 兜底闸与前端对账识别「两处曾打架」。
        "q1_sink_identity_downgraded": _q1_downgraded,
        # 到达判定降级：primary_channel / 降级前状态一并留痕，可对账、可回溯。
        "arrival_only_downgraded": bool(_arrival_only_hit and confirmed),
        "confirmed_raw": bool(confirmed),
        "primary_channel": _primary,
    }
    return vr


def _parse_taint_path(raw: Any) -> List[Dict[str, Any]]:
    """把 DB 里的 taint_path_json（探针回带的污点传播路径，JSON 数组字符串）解析为节点列表。

    每个节点形如 {"role": "source|transform|sink", "origin": "java.util.Base64$Decoder.decode"}。
    解析失败或为空返回 []（I1 退化为方案 A 的 unverifiable 逻辑）。
    """
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [n for n in data if isinstance(n, dict)]
    except (ValueError, TypeError):
        return []
    return []


# ── 时间盲注时延双阈值确认门（2026-09-07 承接断链①修复）──
#
# 定位：作为 IAST sink-reached 的「旁证兜底」，只在所有 sink-reached 分支均未命中后调用，
# 绝不替代 IAST 主信号。前提是 D1 已投放 sleep 型主载荷（sleep_seconds_hint>0）并对主请求计时。
# 承接的断链：时间盲注/命令注入 sleep 是「威力大不破坏」的典型攻击，但探针未必织得到 DB 驱动
# 内部的 sink（或 sink 在预编译语句层不可织），此时 canary 到不了、IAST 报不出 sink-reached，
# D2 只能判 no_evidence——本门用「注入 SLEEP 后响应真的变慢」作为 sink 触达的独立旁证。
#
# 双阈值（保守，宁可漏确认不可误确认）：
#   - 有基线（baseline_elapsed_ms>0）：净时延差 (elapsed-baseline) 需 ≥ 预期时延 × 0.7
#     → 同结构 SLEEP(N) vs SLEEP(0) 的净差达标，几乎排除网络抖动/慢接口 → high。
#   - 无基线：绝对 elapsed 需 ≥ 预期时延 × 0.8（更严，缺对照可能撞上慢接口）→ medium。
# 单位换算：sleep_seconds_hint 是秒，elapsed/baseline 是毫秒。
_TIME_BLIND_DELTA_RATIO = 0.7      # 有基线：净时延差 / 预期时延
_TIME_BLIND_ABSOLUTE_RATIO = 0.8   # 无基线：绝对耗时 / 预期时延
_TIME_BLIND_MIN_MS = 1500.0        # 预期时延 < ~2s 时时延信号不可靠（普通抖动即可达标），一律不采信


def _time_blind_confirmed(dast_impact_evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """时延双阈值确认门。命中返回 verdict dict（harmful=True），未命中返回 None。

    仅在 D1 投放了 sleep 型主载荷（sleep_seconds_hint>0）且主请求耗时（elapsed_ms>0）时才评估；
    预期时延过小（<1.5s）直接不采信，避免把普通请求波动误判为盲注成功。
    """
    d = dast_impact_evidence or {}
    try:
        hint = float(d.get("sleep_seconds_hint") or 0.0)
        elapsed = float(d.get("elapsed_ms") or 0.0)
        baseline = float(d.get("baseline_elapsed_ms") or 0.0)
    except (TypeError, ValueError):
        return None
    if hint <= 0.0 or elapsed <= 0.0:
        return None
    expected_ms = hint * 1000.0
    if expected_ms < _TIME_BLIND_MIN_MS:
        return None
    if baseline > 0.0:
        delta = elapsed - baseline
        if delta >= expected_ms * _TIME_BLIND_DELTA_RATIO:
            return {
                "harmful": True,
                "sink_reached": True,
                "confidence": "high",
                "reason": (
                    f"时间盲注确认（差分）：注入 SLEEP({hint:g}s) 主请求耗时 {elapsed:.0f}ms，"
                    f"同结构 SLEEP(0) 基线 {baseline:.0f}ms，净时延差 {delta:.0f}ms "
                    f"≥ 预期 {expected_ms * _TIME_BLIND_DELTA_RATIO:.0f}ms，"
                    "攻击 payload 在 sink 处真实执行了延时（sink 已触达）。"
                ),
                "evidence": "",
                "time_blind_confirmed": True,
                "time_blind_mode": "differential",
            }
        return None
    if elapsed >= expected_ms * _TIME_BLIND_ABSOLUTE_RATIO:
        return {
            "harmful": True,
            "sink_reached": True,
            "confidence": "medium",
            "reason": (
                f"时间盲注确认（绝对）：注入 SLEEP({hint:g}s) 主请求耗时 {elapsed:.0f}ms "
                f"≥ 预期 {expected_ms * _TIME_BLIND_ABSOLUTE_RATIO:.0f}ms"
                "（无同结构基线对照，按绝对阈值保守判定）。"
            ),
            "evidence": "",
            "time_blind_confirmed": True,
            "time_blind_mode": "absolute",
        }
    return None


# ── 六条证据通道的评估器（M4，注册进 src/core/evidence_channels.py）──
#
# 每个评估器只回答「本通道看到了什么」，不做跨通道的取舍——取舍全交给 arbitrate。
# 两条硬规矩：
#   1. 通道不适用 / 没投放 / 没观测到 → 返回 definitive=False（或 None），
#      绝不能返回 definitive=True 的 harmful=False，那会把「证据缺失」当「无害证据」。
#   2. 评估器内部不得 import 仲裁器，也不得参考其他通道的结论，否则就不是正交通道了。


def _ch_oob_callback(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """带外回调通道（证明力 4）：服务端主动出网找我，跨过回显/探针织点的全部不确定性。

    M3 决策：带外从「梯子末阶」改为**正交伴随通道**——任何族只要投了带外弹就独立判一次，
    不再躲在反序列化那一支里（原来只有 deser 分支顺手查了一次）。
    """
    iast = ctx.get("iast") or {}
    dast = ctx.get("dast") or {}
    tok = str((iast.get("oob") or {}).get("token") or dast.get("oob_token") or "")
    if not tok:
        return _ec.make_outcome(
            "oob_callback", harmful=False, sink_reached=False, confidence="low",
            reason="本轮未投放带外载荷（无 token）", definitive=False, oob_attempted=False)
    try:
        from src.iast import oob_monitor as _oob

        has = bool(_oob.has_callback(tok))
        mode = _oob.oob_mode()
    except Exception as _e:
        return _ec.make_outcome(
            "oob_callback", harmful=False, sink_reached=False, confidence="low",
            reason=f"带外回调查询失败：{_e}", definitive=False, error=str(_e))
    if has:
        return _ec.make_outcome(
            "oob_callback", harmful=True, sink_reached=True, confidence="high",
            reason="带外回调已收到：服务端主动出网访问了本次投放的唯一域名/端点，"
                   "payload 被真实解析并执行（跨过回显与探针织点的最强证据）",
            evidence=tok[:32], definitive=True, oob_confirmed=True, oob_mode=mode)
    return _ec.make_outcome(
        "oob_callback", harmful=False, sink_reached=False, confidence="low",
        reason="带外载荷已投放但未收到回调（证据缺失，不等于无害）",
        definitive=False, oob_attempted=True, oob_mode=mode)


def _ch_semantic_diff(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """语义差分通道（证明力 3）：双身份/双参数对照，响应语义确实不同才认。

    服务于 ldap / xpath / bola / idor / vertical_privesc：这些族的「漏洞」是
    **语义差异**（同一个请求换个身份/换个参数，返回的语义变了），不是污点流到某个 sink。
    主信号是结构差（JSON key 集 / 状态码），相似度兜底，**长度差不采信**。
    """
    dast = ctx.get("dast") or {}
    sd = _rp.evaluate_semantic_diff(dast)
    if isinstance(sd, dict) and sd:
        matched = bool(sd.get("matched"))
        cat = str(sd.get("category") or "semantic")
        definitive = bool(sd.get("definitive", True))
        return _ec.make_outcome(
            "semantic_diff", harmful=matched, sink_reached=matched,
            confidence="high" if matched else "medium",
            reason=(f"语义差分确认（{cat}）：{sd.get('detail') or '双身份/双参数响应语义不同'}"
                    if matched else
                    f"语义差分未成立（{cat}）：{sd.get('detail') or '两组响应语义一致，未观测到越权/注入效果'}"),
            evidence=str(sd.get("evidence") or dast.get("body", "") or "")[:500],
            definitive=definitive,
            semantic_diff_confirmed=matched, semantic_diff_category=cat,
            semantic_diff_similarity=sd.get("similarity"),
            semantic_diff_length_only=bool(sd.get("length_only")))
    biz = dast.get("business_logic") or {}
    if not (isinstance(biz, dict) and biz.get("confirmed")):
        return None
    return _ec.make_outcome(
        "semantic_diff", harmful=True, sink_reached=True, confidence="high",
        reason=f"业务差分确认（{biz.get('category', 'business')}）：攻击者账户成功访问受害者资源，结果点有害",
        evidence=str(dast.get("body", "") or "")[:500],
        definitive=True, business_logic_confirmed=True)


def _ch_result_point_diff(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """结果点比对通道（证明力 3）：投放值与结果点（回显/响应头/求值结果）对得上才算。

    M5 真正落地三族判据（src/core/result_point.py）：
      - XSS 三态：原样回显=有害 / 转义或编码=过滤器有效 / 无回显=转两步（不是无害）；
      - CRLF 单开判据：只看响应头里有没有被注入的头，不看响应体；
      - SSTI 求值对：投引擎专属表达式看是不是回 49，而不是回原式
        （M10：按 velocity/freemarker/thymeleaf/pebble/spel/ognl/mvel 分桶派发，
         桶由 A1 从 import/class 路径静态识别，识别不出才走跨引擎兜底）。
    没比对上分两种：比上了但被转义/未求值 → definitive=True（结论）；压根没出现 →
    definitive=False（没看到，转两步重放）。
    """
    dast = ctx.get("dast") or {}
    spec = ctx.get("spec") or {}
    # 引擎桶优先级：DastImpact 上挂的（A1 已识别）→ spec 上的 → 空（跨引擎兜底）
    engines = (dast.get("ssti_engines") or spec.get("ssti_engines") or [])
    if isinstance(engines, str):
        engines = [engines]
    rpd = _rp.evaluate_result_point(ctx.get("family") or "", dast,
                                    engines=[str(x) for x in engines if x])
    if not (isinstance(rpd, dict) and rpd):
        return None
    matched = bool(rpd.get("matched"))
    state = str(rpd.get("state") or ("matched" if matched else "unmatched"))
    definitive = bool(rpd.get("definitive", True))
    detail = str(rpd.get("detail") or ("投放值在结果点原样复现" if matched else "投放值未在结果点复现"))
    return _ec.make_outcome(
        "result_point_diff",
        harmful=matched, sink_reached=matched,
        confidence="high" if matched else ("medium" if definitive else "low"),
        reason=(f"结果点比对{'命中' if matched else '未命中'}（{state}）：{detail}"),
        evidence=str(rpd.get("evidence") or dast.get("body", "") or "")[:500],
        definitive=definitive,
        result_point_matched=matched, result_point_state=state,
        suggested_status=rpd.get("suggested_status"),
        next_action=rpd.get("next_action"))


def _value_gate_probe_enabled() -> bool:
    """FP-6 值级佐证闸开关（2026-10-17）。默认关——需探针先补齐族 sink 事件捕获
    （8 个 trace-only TP 如 01000 当前无族 sink 事件，开闸会误伤）。探针重建后置
    SAST_AI_VALUE_GATE_PROBE=1 启用。"""
    return os.environ.get("SAST_AI_VALUE_GATE_PROBE", "0") == "1"


def _has_family_value_hit(iast: Dict[str, Any], family: str) -> bool:
    """iast_evidence 里是否有「族相关 sink 的值级命中」（canary 真出现在族 sink 实参里）。

    复用 _ch_value_level_sink_arg 的族相关性过滤：只有 value_hit 落在 is_family_relevant_sink
    的 sink 上才算数（Cookie.<init>/setHeader 等噪声 sink 上的命中不算）。FP-6 实测：真 TP
    的族 sink 实参含 canary（00108 DelegatingStatement.execute src 含 canary）；假 FP 的族 sink
    实参是硬编码安全值、canary 只落噪声 sink（00110 实参=barbarians，value_hit 落 Cookie.<init>）。
    """
    hits = [h for h in (iast.get("value_hits") or []) if isinstance(h, dict) and h.get("hit")]
    if not hits:
        single = iast.get("value_hit")
        if isinstance(single, dict) and single.get("hit"):
            hits = [single]
    return any(is_family_relevant_sink(str(h.get("sink_file") or ""), family) for h in hits)


def _ch_probe_sink_assert(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """探针 sink 断言通道（证明力 2）：canary 落在危险函数实参 + D1 影响侧佐证。

    复刻原 _verify_sink_result 的四条分支（降级 / 抵达+reached / 抵达+未 reached /
    反序列化链路），分支互斥性质不变，只是从 if-return 改写为「谁的前提成立谁出结论」。
    """
    iast = ctx.get("iast") or {}
    dast = ctx.get("dast") or {}
    family = ctx.get("family") or ""
    iast_state = iast.get("state", "")
    reached = bool(dast.get("reached"))
    status = dast.get("status_code")
    body = str(dast.get("body", "") or "")
    attack_degraded = bool(dast.get("attack_degraded"))
    biz = dast.get("business_logic") or {}
    biz_confirmed = bool(biz.get("confirmed")) if isinstance(biz, dict) else False
    probe_asserted = (iast_state == STATE_SINK_REACHED_PROBE)
    # 2026-11-03（r17b 验证实测）：降级攻击 = A2 未产出真实 payload、D1 只投 canary 探针。
    # 原实现 `and not probe_asserted` 让「探针断言到 sink」豁免降级，于是无载荷 spec 直接落
    # confirmed_exploitable。jsc 609 实测：FileUpload 的 7 条路径穿越、log4j 的 xss 全是这条
    # 路径进来的误报（裁决原文自己写着「部分 spec 为降级攻击，证据强度较弱」却仍确认）。
    # 无真实攻击载荷 ⇒ 没有可利用性证据，与探针是否断言到 sink 无关：canary 到达只证可达。
    degraded_no_attack = attack_degraded and not biz_confirmed
    genuine_sink_reached = iast_evidence_sink_reached_genuine(iast, family)

    if is_sink_reached(iast_state) and reached and degraded_no_attack and genuine_sink_reached:
        return _ec.make_outcome(
            "probe_sink_assert", harmful=False, sink_reached=True, confidence="low",
            reason=(f"数据到达 sink 且请求被处理（status={status}），但本次为降级攻击"
                    "（A2 未产出真实 payload，D1 仅投放 canary 探针）。"
                    "canary 到达仅证可达性，不构成有害性证据。"),
            evidence=body[:500], definitive=True, attack_degraded=True)
    if genuine_sink_reached and reached:
        # FP-6 值级佐证闸（2026-10-17，env: SAST_AI_VALUE_GATE_PROBE，默认关）：
        # probe_sink_assert 原只靠 trace 级 reached_sink_files 确认（非 trustbound 族 fail-open），
        # FP 的真 sink 实参是硬编码安全值（无 canary）、taint_path sink 节点是噪声 sink，却因
        # trace 级 canary_match=1 被误确认（run 361 实测 00110 等 5 个 dataflow FP）。开闸时
        # probe_asserted（纯探针 trace 断言）必须有「族相关值级命中」才判有害，否则降级为证据缺失。
        # 前提：探针须先补齐族 sink 事件捕获（8 个 trace-only TP 如 01000 当前无族 sink 事件，
        # 开闸会误伤），故默认关，探针重建后置 SAST_AI_VALUE_GATE_PROBE=1 启用。
        if probe_asserted and _value_gate_probe_enabled() and not _has_family_value_hit(iast, family):
            return _ec.make_outcome(
                "probe_sink_assert", harmful=False, sink_reached=True, confidence="low",
                reason=("探针 trace 级断言 canary 抵达，但值级比对未在我方族 sink 实参里找到 canary"
                        "（族 sink 实参不含 canary 或 taint_path sink 节点是噪声 sink）——"
                        "trace 断言不能单独当结论，证据缺失不判有害（待探针补齐族 sink 事件捕获后开闸）"),
                evidence=body[:500], definitive=False, probe_asserted=probe_asserted)
        return _ec.make_outcome(
            "probe_sink_assert", harmful=True, sink_reached=True, confidence="high",
            reason=("探针在 sink 现场显式断言 canary 抵达危险函数实参，攻击者可控数据确证到达 sink"
                    if probe_asserted else
                    f"数据到达 sink 且请求被处理（status={status}），真实攻击 payload 已投放，结果点被打中/有害"),
            evidence=body[:500], definitive=True, probe_asserted=probe_asserted)
    if genuine_sink_reached and not reached:
        # v2 证据分层 B5：sink 到达但 D1 未证 reached（可能传输中断/超时）—— 证据缺失，
        # 改为 definitive=False（绝不臆断有害）。仲裁时本条不计入确定性结论，由兜底 "none" 收口，
        # 与「观测冒充裁决」的铁律一致（reached 不足证 harmful）。
        return _ec.make_outcome(
            "probe_sink_assert", harmful=False, sink_reached=True, confidence="low",
            reason="sink 到达但 D1 未证 reached（可能传输中断/超时）—— 证据缺失，不判有害",
            definitive=False, probe_asserted=probe_asserted)
    # 反序列化族专用确证（2026-09-28 落地，第三层）：canary 是字符串、序列化 payload 是二进制，
    # canary 结构性进不了 readObject 实参；readObject 是 final，探针只把 resolveClass 当 transform
    # 跳点不产 sink 事件 → 该族永远走不到上面的 genuine_sink_reached 分支。
    # 替代判据：同一请求内「反序列化节点 + 命令执行 sink」同时被观测到即确证
    # （gadget 链终点必然是 Runtime.exec / ProcessBuilder.start，探针已钩住）。
    _deser = _deser_runtime_chain_confirmed(iast, family)
    if _deser:
        _oob_confirmed = False
        try:
            from src.iast import oob_monitor as _oob

            _tok = str((iast.get("oob") or {}).get("token") or "")
            if _tok and _oob.has_callback(_tok):
                _oob_confirmed = True
        except Exception:
            _oob_confirmed = False
        return _ec.make_outcome(
            "probe_sink_assert", harmful=True, sink_reached=True, confidence="high",
            reason=((_deser.get("reason") or "反序列化链路确证")
                    + ("；带外域名已收到回调，payload 确证被服务端反序列化并执行" if _oob_confirmed else "")),
            evidence="; ".join((_deser.get("deserialization_nodes") or []) + (_deser.get("rce_sinks") or []))[:500],
            definitive=True,
            deserialization_chain_confirmed=True,
            deserialization_nodes=_deser.get("deserialization_nodes") or [],
            rce_sinks=_deser.get("rce_sinks") or [],
            oob_confirmed=_oob_confirmed)
    # 注意：这里必须是 definitive=False（证据缺失），不能是 definitive=True 的 harmful=False。
    # 否则本通道会以证明力 2 压过后面的时间盲注（同为 2 但 priority 更靠后），
    # 复刻出的就是原 if-return 链序而非证明力序——那正是本次改造要修的病。
    # 兜底结论由 channel="none"（证明力 0）给出，语义与原来的最终 return 完全一致。
    return _ec.make_outcome(
        "probe_sink_assert", harmful=False, sink_reached=False, confidence="low",
        reason=(f"I1 状态={iast_state}，探针未断言 canary 抵达本族真实危险函数"
                + ("" if genuine_sink_reached else
                   "（到达 sink 为框架噪声 sink，非本族真实危险函数，不计入 confirmed_runtime）")),
        definitive=False, probe_asserted=False)


def _ch_value_level_sink_arg(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """值级 sink 实参通道（证明力 4，2026-10-10 新增，正向专用）。

    判据：探针记录的**危险函数实参值**里，是否真的看得见我方投放的数据（canary 原文），
    且这个 sink 属于本族的 sink 画像。这是"比对"而非"断言"——探针那条 canary_match 是
    trace 级断言（run 251 实测 4943/4943 全为 1，而记录值里真能看到 canary 的只有 129 条），
    污点传播对 map 回读 / 常量三元分支是值不敏感的，所以断言不能单独当结论，值级比对可以。

    ## 为什么只做正向（红线，重复对照 r250 的教训）
    离线实测（tools/_diag_valuelevel.py 251）：本判据在 30 条真 FP 上穿透 **0 条**，
    但在 73 条真 TP 上只覆盖 16~17 条。即它是「精确率高、覆盖率低」的判据 ——
    命中 ⇒ 确凿是我方投放的数据进了危险函数；未命中 ⇒ **什么都说明不了**
    （可能值被 URL 解码/拼接改写了，也可能 sink 名字换了导致证据没采到）。
    因此未命中必须返回 definitive=False 的证据缺失态，绝不能当阴性裁决 ——
    一旦当阴性裁决，立刻把 57 条沉默成功的真阳性一起干掉，与 r250 的召回崩塌同型。

    ## 族相关性约束
    只看"有没有命中"会被非本族 sink 污染：实测 129 条值级命中里有 28 条落在
    ``javax.servlet.http.Cookie.<init>``（请求把自己的 cookie 原值建对象，与注入无关），
    SQL 族还会被 PrintWriter 回显污染。故必须叠 ``is_family_relevant_sink`` 身份约束。
    """
    iast = ctx.get("iast") or {}
    family = ctx.get("family") or ""
    hits = [h for h in (iast.get("value_hits") or []) if isinstance(h, dict) and h.get("hit")]
    if not hits:
        single = iast.get("value_hit")
        if isinstance(single, dict) and single.get("hit"):
            hits = [single]
    # 族相关性：任一条命中落在本族 sink 画像上即可（未登记族一律 fail-open 放行）
    relevant = [
        h for h in hits
        if is_family_relevant_sink(str(h.get("sink_file") or ""), family)
    ]
    if not relevant:
        return _ec.make_outcome(
            "value_level_sink_arg", harmful=False, sink_reached=False, confidence="low",
            reason=("本次记录的 sink 实参值里未比对到我方投放数据"
                    + ("" if not hits else f"（{len(hits)} 条命中均落在非本族 sink 上，已按身份校验剔除）")),
            definitive=False, value_level_hit=False)
    h = relevant[0]
    _form = str(h.get("form") or "hit_live")
    if _form == "hit_sanitized":
        # 值级命中但 sink 实参录得消毒器：需族相关性二次校验（铁律③：证据缺失≠阴性）。
        _san = h.get("sanitizer") or ""
        if is_sanitized_for_family(_san, family):
            return _ec.make_outcome(
                "value_level_sink_arg", harmful=False, sink_reached=True, confidence="high",
                reason=(f"值级命中但 sink 实参录得消毒器（{_san or 'n/a'}），且针对本族（{family}），"
                        f"数据到达但被消毒 —— 合法的 definitive 阴性（有判据，非证据缺失）"),
                evidence=str(h.get("snippet") or "")[:500],
                definitive=True, value_level_hit=True, value_level_sanitized=True,
                value_level_sink=str(h.get("sink_file") or ""),
                value_level_form=_form)
        # 消毒器与本族正交（不中和本族注入）→ 数据仍按未消毒到达，回退为阳性证据。
        return _ec.make_outcome(
            "value_level_sink_arg", harmful=True, sink_reached=True, confidence="high",
            reason=(f"值级确证：我方投放数据在 {h.get('sink_file') or '未知 sink'} 实参原样复现，"
                    f"且录得消毒器（{_san or 'n/a'}）不针对本族（{family}）—— 数据未被消毒，构成正向证据"),
            evidence=str(h.get("snippet") or "")[:500],
            definitive=True, value_level_hit=True,
            value_level_sink=str(h.get("sink_file") or ""),
            value_level_form=_form)
    return _ec.make_outcome(
        "value_level_sink_arg", harmful=True, sink_reached=True, confidence="high",
        reason=(f"值级确证：我方投放数据在 {h.get('sink_file') or '未知 sink'} 的实参值里原样复现"
                f"（比对字段 {h.get('where') or 'source_value'}，不是探针 trace 级断言）"),
        evidence=str(h.get("snippet") or "")[:500],
        definitive=True, value_level_hit=True,
        value_level_sink=str(h.get("sink_file") or ""),
        value_level_form=_form)


# ── C 批差分三态（2026-10-10，证据分层诚实声明，纯函数供回归锁）──
# 差分没跑成（缺双账户 / 被破坏性闸门 skip / 回滚失败）的 verdict 集合——
# 这些 verdict 下的「无差异」不是真阴性而是证据缺失，绝不能当 correct_reject。
_C_DIFF_AMBIGUOUS_VERDICTS = frozenset({
    "no_restore_baseline", "restore_failed", "skipped_destructive_guard", "non_dict_result",
})


def differential_three_state(confirmed: bool, replay_ran: bool, verdict: str) -> str:
    """双账号差分矩阵三态推导（纯函数，F6 回归锁对象）。

    - confirmed     ：差分/副作用确实观测到越权 → 真阳性。
    - no_difference ：差分**真跑了**（replay_ran）且 verdict 非歧义集 → 真阴性（correct_reject）。
    - ambiguous     ：差分没跑成（缺账户 / 破坏性闸门 skip / 回滚失败）→ 证据缺失，
                      绝不臆断无害（「没验出来」≠「没漏洞」）。
    """
    if confirmed:
        return "confirmed"
    if replay_ran and verdict not in _C_DIFF_AMBIGUOUS_VERDICTS:
        return "no_difference"
    return "ambiguous"


# ── B2 sink 异常签名通道（2026-10-10 新增，证明力 3）──
# 异常类名 → 族签名映射。键用 OWASP Benchmark 规范族 token；匹配时同时接受别名包含（见
# _exception_matches_family）。含义：这些异常是对应族「危险操作真的执行并抛错」的特征签名——
# 在 safe 用例里几乎不会因「被净化的输入」抛出（净化后操作正常完成或抛无关异常），
# 故可作为独立的 definitive 阳性候选。空签名族（securecookie / weakrand 等纯属性族）不登记，
# 它们的主张本来就不在运行时「可利用后果」上。
_SINK_EXCEPTION_FAMILY_SIGNATURE: Dict[str, tuple] = {
    "cmdi": ("java.io.IOException", "java.lang.InterruptedException"),
    "ldapi": ("javax.naming", "NamingException"),
    "pathtraver": ("java.io.FileNotFoundException", "java.io.IOException",
                   "java.nio.file.NoSuchFileException", "java.nio.file"),
    "sqli": ("java.sql.SQLException", "java.sql"),
    "xpathi": ("javax.xml", "TransformerException", "XPathException", "XPathExpressionException"),
    "xxe": ("org.xml.sax", "javax.xml", "SAXException", "ParserConfigurationException",
            "TransformerException"),
    "ssrf": ("java.net.ConnectException", "java.net.UnknownHostException",
             "java.net.SocketException", "java.net.SocketTimeoutException"),
}


def _exception_matches_family(exc: str, family: str) -> bool:
    """异常类名是否属本族危险操作的签名（宽松别名匹配）。

    F7（2026-10-10）：族名先做 ``_``/``-`` 剥除归一再做双向包含匹配 ——
    ``path_traversal`` / ``path-traversal`` 等别名写法剥除后仍包含 ``pathtraver``，
    否则这些别名族的 sink 异常签名会被静默漏匹配（归因回证据缺失，丢 TP 佐证）。
    归一后 ``xpathi`` 与 ``pathtraver`` 仍互不包含（xpathi 无 pathtraver 子串、反之亦然），
    不会引入跨族抢判。
    """
    fam = (family or "").strip().lower().replace("_", "").replace("-", "")
    e = (exc or "").strip()
    if not fam or not e:
        return False
    for key, sigs in _SINK_EXCEPTION_FAMILY_SIGNATURE.items():
        if key == fam or key in fam or fam in key:
            if any(tok in e for tok in sigs):
                return True
    return False


def _ch_sink_exception(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """sink 现场异常签名通道（证明力 3，B2，正向专用，definitive 阳性）。

    判据：探针在 sink 现场抛出的异常类名属本族危险操作的签名（如 SQL 注入触发
    java.sql.SQLException、命令注入触发 java.io.IOException），且该 sink 已通过家族身份校验
    （genuine_sink_reached）——即异常确实发生在「本族真实危险函数」上，而非框架噪声 sink。

    为什么只做正向（与值级通道同一条红线，重复对照 r250 教训）：
    异常类名是「操作执行并抛错」的一手事实，命中 ⇒ 确凿是危险操作被我方数据触发；
    未命中（无异常 / 异常不属本族签名 / sink 未过身份校验）一律返回 None（证据缺失），
    交兜底通道收口，**绝不臆断无害**——否则会重演 r250 召回崩塌。

    与探针断言（strength 2）的关系：本通道要求 genuine_sink_reached，故在探针断言已判
    有害的场景里是「加一重独立佐证」；更关键的价值是**填补 B5 的证据缺失缺口**——
    当 genuine_sink_reached 为真、但 D1 未证 reached（B5 只能给 definitive=False）时，
    若 sink 现场抛出了本族异常签名，本通道仍能给出 definitive 阳性，把那条原本会被
    fail-open 漏掉的 TP 抢救回来。
    """
    iast = ctx.get("iast") or {}
    family = ctx.get("family") or ""
    exc = iast.get("sink_exception_class") or ""
    if not exc:
        return None  # 本通道不适用（证据缺失，由兜底收口）
    if not iast_evidence_sink_reached_genuine(iast, family):
        # 异常未在家族真实 sink 上抛 → 不归因本族（证据缺失，fail-open）
        return None
    if not _exception_matches_family(exc, family):
        return None
    return _ec.make_outcome(
        "sink_exception", harmful=True, sink_reached=True, confidence="high",
        reason=(f"家族真实危险 sink 现场抛出 {exc}，属本族危险操作异常签名"
                f"（如 {(_SINK_EXCEPTION_FAMILY_SIGNATURE.get(family) or ('',))[0] or '本族特征异常'}），"
                "危险操作确被执行并抛错 —— 独立的 definitive 阳性"),
        evidence=exc, definitive=True, sink_exception_class=exc)


def _ch_time_blind(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """时间盲注通道（证明力 2）：时延差分达标的旁证（探针织不到 DB sink 时的承接）。"""
    dast = ctx.get("dast") or {}
    tb = _time_blind_confirmed(dast)
    if tb is None:
        return _ec.make_outcome(
            "time_blind", harmful=False, sink_reached=False, confidence="low",
            reason="时间盲注未达标（未投 sleep 弹 / 时延不足 / 预期时延 < 1.5s）——证据缺失，不等于无害",
            definitive=False)
    return _ec.make_outcome(
        "time_blind", harmful=True, sink_reached=True,
        confidence=tb.get("confidence") or "medium",
        reason=tb.get("reason") or "", evidence=tb.get("evidence") or "",
        definitive=True,
        time_blind_confirmed=True, time_blind_mode=tb.get("time_blind_mode"))


def _ch_echo_marker(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """跨请求回显通道（M7，证明力 3）：两步重放写进去的自限标记，在读取侧响应里被搜到。

    这条通道对存储型是**唯一通用手段**：读取侧参数里根本没有 canary（值是从库里读
    出来的），探针在该侧完全盲区——所以回显比对是它唯一能拿到的证据。

    三态纪律（与 M5 结果点比对同一条）：
      raw     → 到渲染了但没转义 → 可利用，definitive=True
      escaped → 到了但被转义输出 → **真阴性**（filtered_not_exploitable），
                绝不能当可利用。这条通道的 harmful=False 在这里不是「证据缺失」
                而是「确证无害」，但要靠下游 i2_feedback 把它落成过滤态而不是 no_evidence。
      absent  → 没搜到 → 证据缺失，definitive=False（可能是写没成功、读端点判错、
                或这根本不是存储型），一律不许当无害。
    """
    dast = ctx.get("dast") or {}
    ts = dast.get("two_step") or {}
    if not isinstance(ts, dict) or not ts.get("enabled"):
        return None
    mk = str(ts.get("marker") or "")
    # 落库会被截断，seen 状态已从 D1 侧定好，直接信 D1 的形态判定（不重新搜 body）
    state = str((ts.get("read") or {}).get("state") or "absent")
    src = str(ts.get("read_endpoint_source") or "none")
    if state == "raw":
        return _ec.make_outcome(
            "echo_marker", harmful=True, sink_reached=True, confidence="high",
            reason=("两步重放：自限标记经写接口入库，在读取侧 %s（读端点来源=%s）的响应里"
                    "原样出现——存储型回显确证，且未转义"
                    % ((ts.get("read") or {}).get("endpoint") or "-", src)),
            evidence=mk, definitive=True,
            echo_state="raw", echo_endpoint=(ts.get("read") or {}).get("endpoint") or "",
            read_endpoint_source=src)
    if state == "escaped":
        # 到 sink 了但被转义 —— 真阴性，且是**确证**的无害，不是没证据
        return _ec.make_outcome(
            "echo_marker", harmful=False, sink_reached=True, confidence="high",
            reason=("两步重放标记为 %s 的响应里找到了，但输出被转义——数据确实写进去又被读出来，"
                    "只是渲染时做了转义，属真阴性（filtered_not_exploitable），不是可利用"
                    % ((ts.get("read") or {}).get("endpoint") or "-")),
            evidence=mk, definitive=True,
            echo_state="escaped", echo_endpoint=(ts.get("read") or {}).get("endpoint") or "",
            read_endpoint_source=src)
    return _ec.make_outcome(
        "echo_marker", harmful=False, sink_reached=False, confidence="low",
        reason=("两步重放未在读取侧 %s 搜到自限标记（state=absent，读端点来源=%s）——"
                "可能是写没落库、读端点判错、或这条根本不是存储型；证据缺失 ≠ 无害"
                % ((ts.get("read") or {}).get("endpoint") or "-", src)),
        evidence="", definitive=False,
        echo_state="absent", echo_endpoint=(ts.get("read") or {}).get("endpoint") or "",
        read_endpoint_source=src)


def _ch_browser_dom(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """M13「DAST 的浏览器扩展」通道（证明力 4，按需起 headless 浏览器、用完释放）。

    只有「必须看渲染后 DOM 才下得了结论」的族才走这里（DOM XSS / 前端渲染型反射 XSS）：
    服务端响应体里没有的东西，浏览器执行完前端脚本才能看出来。

    三态纪律（与 M5/M7 一致，不许把「没看到」说成「无害」）：
      raw        → 标记被浏览器当可执行片段渲染/求值 → 可利用，definitive=True
      escaped    → 在 DOM 里但被转义 → **真阴性**（确证，definitive=True）
      absent     → 页面渲染完没搜到 → 证据缺失，definitive=False
      unavailable→ 本机没有浏览器运行时（playwright/Chromium 缺失）→ 也是证据缺失，
                   绝不允许伪造一条「没搜到」或「可利用」出来

    浏览器进程只在这一个函数里存在，返回即 close（见 browser_probe.BrowserProbe.close）。
    """
    dast = ctx.get("dast") or {}
    spec = ctx.get("spec") or {}
    family = ctx.get("family") or ""
    try:
        from src.core.browser_probe import (STATE_ABSENT, STATE_ESCAPED, STATE_RAW,
                                            STATE_UNAVAILABLE, run_browser_probe)
    except Exception as exc:
        return _ec.make_outcome(
            "browser_dom", harmful=False, sink_reached=False, confidence="low",
            reason=("浏览器取证模块不可用（%s）：证据缺失 ≠ 无害" % str(exc)[:200]),
            definitive=False, browser_state=STATE_UNAVAILABLE)
    try:
        from src.core.browser_probe import is_dom_family
    except Exception:
        is_dom_family = lambda _f: False
    if not is_dom_family(family):
        return None

    mk = str((dast.get("dom_probe") or {}).get("marker") or spec.get("browser_marker") or "")
    if not mk:
        mk = _bp_marker()
    url = str((dast.get("dom_probe") or {}).get("url")
              or _bp_url(spec, dast))
    if not url:
        return None
    res = run_browser_probe(url, mk)
    state = str(res.get("state") or STATE_ABSENT)
    detail = str(res.get("reason") or "")
    engine = str(res.get("engine") or "")
    dur = res.get("duration_ms", 0)
    if state == STATE_RAW:
        return _ec.make_outcome(
            "browser_dom", harmful=True, sink_reached=True, confidence="high",
            reason=("浏览器渲染取证（%s，耗时 %sms）：投放标记在渲染后的 DOM 里被当可执行片段"
                    "渲染/求值——响应体里看不出、前端脚本拼接后才发生的注入确证"
                    % (engine or "headless", dur)),
            evidence=mk, definitive=True, browser_state=STATE_RAW, browser_url=url)
    if state == STATE_ESCAPED:
        return _ec.make_outcome(
            "browser_dom", harmful=False, sink_reached=True, confidence="high",
            reason=("浏览器渲染取证（%s，耗时 %sms）：标记进了 DOM 但被转义输出——"
                    "数据确实流到渲染层，只是输出被转义，属真阴性" % (engine or "headless", dur)),
            evidence=mk, definitive=True, browser_state=STATE_ESCAPED, browser_url=url)
    if state == STATE_UNAVAILABLE:
        return _ec.make_outcome(
            "browser_dom", harmful=False, sink_reached=False, confidence="low",
            reason=("浏览器取证未执行（%s）——没有可用浏览器运行时，证据缺失 ≠ 无害，"
                    "也不许伪造结论" % (detail or "runtime_unavailable")),
            definitive=False, browser_state=STATE_UNAVAILABLE, browser_url=url)
    return _ec.make_outcome(
        "browser_dom", harmful=False, sink_reached=False, confidence="low",
        reason=("浏览器渲染取证（%s，耗时 %sms）未在 DOM 里搜到投放标记（%s）——"
                "可能是页面 404/脚本报错/标记没进渲染路径；证据缺失 ≠ 无害"
                % (engine or "headless", dur, detail or "state=absent")),
        evidence="", definitive=False, browser_state=STATE_ABSENT, browser_url=url)


def _bp_marker() -> str:
    try:
        from src.core.browser_probe import make_marker
        return make_marker()
    except Exception:
        return "sastai-browser"


def _bp_url(spec: Dict[str, Any], dast: Dict[str, Any]) -> str:
    try:
        from src.core.browser_probe import probe_url_for
        return str(probe_url_for(spec, dast) or "")
    except Exception:
        return str((spec or {}).get("target_endpoint") or "")


def _ch_code_property(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """代码属性通道（证明力 1）：只证属性（弱算法/缺失标志位/非安全随机源），不证可利用。

    对这类族（weak_random / weak_hash / weak_crypto / securecookie）给出 harmful=False 是
    **正确的问法**：它们的主张本来就不是「运行时可利用」。终态由 family_verdict 的族路由
    落到 confirmed_code_property，不该被数据流通道抬成 confirmed_exploitable。
    """
    family = ctx.get("family") or ""
    if not _ec.is_code_property_family(family):
        return None
    return _ec.make_outcome(
        "code_property", harmful=False, sink_reached=False, confidence="medium",
        reason=("该族主张是代码属性（算法/标志位/随机源），运行时无「可利用后果」可观测；"
                "本通道只确认属性层成立，终态按 confirmed_code_property 计入，不并入可利用口径"),
        definitive=True, code_property_family=True)


def _ch_none(ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """兜底通道（证明力 0）：永远出结论，永远垫底，保证 _verify_sink_result 恒有返回值。"""
    iast = ctx.get("iast") or {}
    family = ctx.get("family") or ""
    iast_state = iast.get("state", "")
    genuine_sink_reached = iast_evidence_sink_reached_genuine(iast, family)
    return _ec.make_outcome(
        "none", harmful=False,
        # ④：状态为 sink-reached 但落点在框架噪声 sink（非本族真实危险函数）→ 不背书。
        sink_reached=genuine_sink_reached, confidence="low",
        reason=(f"I1 状态={iast_state}，结果点未确证有害"
                + ("" if genuine_sink_reached else
                   "（到达 sink 为框架噪声 sink，非本族真实危险函数，不计入 confirmed_runtime）")),
        definitive=True)


for _name, _fn in (
    ("oob_callback", _ch_oob_callback),
    ("echo_marker", _ch_echo_marker),
    ("browser_dom", _ch_browser_dom),
    ("semantic_diff", _ch_semantic_diff),
    ("result_point_diff", _ch_result_point_diff),
    ("probe_sink_assert", _ch_probe_sink_assert),
    ("value_level_sink_arg", _ch_value_level_sink_arg),
    ("sink_exception", _ch_sink_exception),
    ("time_blind", _ch_time_blind),
    ("code_property", _ch_code_property),
    ("none", _ch_none),
):
    _ec.register_evaluator(_name, _fn)


def _verify_sink_result(iast_evidence: Dict[str, Any], dast_impact_evidence: Dict[str, Any], family: str = "",
                        facts: Optional[Dict[str, Any]] = None, spec: Optional[Dict[str, Any]] = None,
                        budget: int = _ec.DEFAULT_REPLAY_BUDGET) -> Dict[str, Any]:
    """D2 结果点核实（看结果点，不重发 EXP）——**六通道不短路仲裁版**。

    原实现是一条 if-return 单链：第一个命中的分支直接 return，后面分支永不执行，
    于是「证明力」被链的书写顺序绑架（低阶判据排在前面就能盖掉高阶证据），
    且带外回调这类正交证据只能躲在反序列化那一支里才被看一眼。

    现在改为（评审 2026-10-02 决策丙）：
      - 按族适用通道**全跑不短路**，每条通道独立出结论；
      - 仲裁取**证明力最高者**为主判据（带外 4 > 结果点比对 3 = 语义差分 3 >
        时间盲注 2 = 探针断言 2 > 代码属性 1 > 兜底 0）；
      - 与主判据结论相反的通道打进 `conflicting_channels`，不静默丢弃；
      - 重放预算 5 次/spec 含基线，不够时按证明力从低到高砍通道（先判后投）。

    返回值在原有 harmful/sink_reached/confidence/reason/evidence 之上新增审计字段：
    primary_channel / evidence_strength / evidence_channels / channel_conflict /
    channels_run / channel_plan。

    ④ sink 身份校验仍在每个通道内部生效（见 iast_evidence_sink_reached_genuine）：
    canary 落在框架噪声 sink（响应写入 / 序列化类）且非本族真实危险函数时，
    该「抵达」不构成本族真实漏洞证据，避免 confirmed_runtime 虚高。
    """
    return _ec.verify_with_channels(
        family, iast_evidence, dast_impact_evidence,
        facts=facts, spec=spec, budget=budget,
    )


def create_d2_agent(config: Optional[Dict] = None) -> D2Agent:
    return D2Agent(config or {})

