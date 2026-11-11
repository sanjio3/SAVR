"""攻击计划阶段（介于 A2 语义分析与 D1 操作器之间）。

把 A2 阶段登记到 trigger_specs 的 poc 假说，投影成一份**可读的攻击计划**，让用户在
A2 与 D1 之间就能看到「准备打什么、打在哪个端点、注入哪个参数、用什么 payload、如何判定成功」。

设计要点：
- 本阶段是**透明可视化/记录层**，不重复造 payload。真实攻击 payload 仍由 A2 在 exploit_spec 里设计、
  D1 重放时消费 trigger_specs（统一链路），攻击计划只是把这些信息「投射」出来给人看 + 落盘留痕。
- canary 只暴露「身份段」(s4st41 + 16hex)，绝不把完整 canary 透出前端（避免被当作可利用 token）。
- 计划条目与 trigger_specs 一一对应（spec_id 关联），D1 打完之后可由 I1/D1 面板按 spec 反查命中。

- 孤儿/跨靶场 spec：spec 的 vhash 在本 task findings 无对应行（历史实测 mall 端点混入 OWASP
  计划，即「任务漂移」在 AP 层的表现），或 expected_sink_file 绝对路径落在靶场工程根之外
  → 不进计划，杜绝把无关目标写进攻击计划膨胀 FP 分母。
- 幻觉族：族名经 normalize_family 归一后不在 KNOWN_CANONICAL_FAMILIES 的（LLM 自由发挥的
  ssrf/vertical_privesc/批量赋值提权 等）→ 不进计划。过滤明细落 result["filtered"] 供审计。

- 本阶段自始至终是**展示/留痕层**，D2 动态裁决**不消费** attack_plan，它只读 trigger_specs
  实测确认是投影侧闸门（族归一 + 靶场锚）把 OWASP 的条目全滤掉了，**对检出与精确率零影响**。
- 因此这里只做状态标注：**不要**因为 plan_count=0 就去排查流水线健康度；若将来要下掉 AP，
  需连同 task_service._STAGE_ORDER、scan_task_runner 各 STAGE 元组、repositories 的
  plan_count 重投影、report_manager 的 details['attack_plan'] 一起移除（改一处会散落报 KeyError）。
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional

from src.iast.service import IastService
from src.core.exploit_spec import derive_flow_type, normalize_exploit_spec
from src.core.normalize import normalize_family, is_known_family

logger = logging.getLogger(__name__)

# AP 面板与 D1 重放吃不到）。默认开启；SAST_AI_AP_RAG_ENABLED=false 即回退纯投影。
_AP_RAG_ENABLED = os.environ.get("SAST_AI_AP_RAG_ENABLED", "true").strip().lower() in (
    "1", "true", "yes", "on")


def _loads(value: Any, default: Any = None) -> Any:
    if value is None or value == "":
        return default if default is not None else {}
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default if default is not None else {}


class AttackPlanService:
    def __init__(self, db):
        self.db = db

    def build(self, task_id: Optional[int] = None, workspace_id: Optional[int] = None, enrich_runtime: bool = False, gateway=None) -> Dict[str, Any]:
        iast = IastService(self.db)
        if task_id is not None:
            specs = iast.list_trigger_specs(task_id=task_id)
        else:
            specs = iast.list_trigger_specs(workspace_id=workspace_id) if workspace_id else []

        # 过滤闸门①：本 task findings 真值锚（spec 的 vhash 必须能在本 task findings 找到来源，
        # 否则视为孤儿/跨靶场污染 spec——mall 端点混入 OWASP 计划的根因即此）。
        task_hashes = self._task_finding_hashes(task_id) if task_id is not None else set()
        # 过滤闸门②：靶场工程根（expected_sink_file 绝对路径在根外 = 外靶场代码）。
        ws_root = self._workspace_target_root(workspace_id, specs)

        entries: List[Dict[str, Any]] = []
        kept_specs: List[Dict[str, Any]] = []
        by_family: Dict[str, int] = {}
        filtered: Dict[str, List[Dict[str, Any]]] = {"orphan_no_finding": [], "foreign_sink": [], "unknown_family": []}
        for idx, spec in enumerate(specs, start=1):
            fam_raw = str(spec.get("family") or "")
            # 闸门a：幻觉族（归一后不在规范族词表）
            if fam_raw and not is_known_family(fam_raw):
                filtered["unknown_family"].append({"spec_id": spec.get("id"), "family": fam_raw})
                continue
            # 闸门b：vhash 在本 task 无 finding 来源（孤儿/跨靶场）
            vhash = str(spec.get("vulnerability_hash_v2") or "")
            if task_id is not None and vhash and vhash not in task_hashes:
                filtered["orphan_no_finding"].append({"spec_id": spec.get("id"), "vhash": vhash[:12], "endpoint": spec.get("target_endpoint")})
                continue
            # 闸门c：sink 绝对路径在靶场根之外
            if self._is_foreign_sink(spec, ws_root):
                filtered["foreign_sink"].append({"spec_id": spec.get("id"), "sink": spec.get("expected_sink_file")})
                continue
            entry = self._project(spec, idx)
            if fam_raw:
                entry["family"] = normalize_family(fam_raw) or entry["family"]
                entry["flow_type"] = derive_flow_type(entry["family"])
            entries.append(entry)
            kept_specs.append(spec)
            fam = entry.get("family") or "unknown"
            by_family[fam] = by_family.get(fam, 0) + 1
        # 增强：D1 重放后回填运行时命中态，让 AP 面板显示"打了什么 + 命中没"
        if enrich_runtime and task_id is not None:
            for spec, entry in zip(kept_specs, entries):
                identity = entry.get("canary_identity", "")
                evs = iast.query_events_by_canary(task_id, identity) if identity else []
                status, count = self._classify(evs)
                # §#3③：业务差分重放不产生 canary sink 事件，原分类器恒判 not_hit。
                # 若 D2 已把验证裁决写回 trigger_specs，据此提升命中态，使 AP 正确呈现业务型确认。
                _bl_confirmed = int(spec.get("business_logic_confirmed") or 0)
                _vstatus = str(spec.get("verification_status") or "")
                _istate = str(spec.get("iast_state") or "")
                # #point-1 新增：同时消费 findings 权威 D2 裁决（d2_verdict.harmful /
                # verification_decision.verification_status / iast_evidence.iast_authz_confirmed）。
                # 使已在 findings 落库的已确认漏洞在 AP 也显示命中，而不依赖 trigger_specs 是否回填该字段。
                _fv = self._lookup_finding_verdict(task_id, entry.get("source_finding_hash", "")) or {}
                _f_harmful = bool(_fv.get("d2_harmful"))
                _f_status = str(_fv.get("verification_status") or "")
                _f_authz = bool(_fv.get("iast_authz_confirmed"))
                _confirmed = (
                    _bl_confirmed
                    or _f_harmful
                    or _f_authz
                    or _vstatus == "confirmed_exploitable"
                    or _f_status == "confirmed_exploitable"
                )
                if _confirmed and status == "not_hit":
                    # 业务差分确认（布尔/认证绕过/差分证明）→ 最高置信 business_confirmed；
                    # 注入型已确认但未触达 sink → d2_confirmed（因探针 sink 无污点门控，通常无 canary 事件）。
                    if entry.get("flow_type") == "business_logic" or _bl_confirmed or _f_authz or _f_status == "confirmed_exploitable":
                        status = "business_confirmed"
                    else:
                        status = "d2_confirmed"
                    count = max(count, 1)
                elif _vstatus and _vstatus not in ("", "unconfirmed") and status == "not_hit":
                    status = "d2_confirmed"
                    count = max(count, 1)
                entry["runtime_status"] = status
                entry["runtime_event_count"] = count
                entry["verification_status"] = _vstatus or _f_status
                entry["iast_state"] = _istate
                entry["d2_harmful"] = _f_harmful
                entry["iast_authz_confirmed"] = _f_authz
        # suggested_route/parameter（经白名单校验），通过校验的值写回 trigger_specs.raw_json
        # 的 exploit_spec.entry 空位，使紧随其后的 D1 重放与 D2 验证吃到。AP 面板同时展示
        # plan source 计数与采纳明细。
        enrich_summary = self._enrich_rag_plans(task_id, kept_specs, entries, gateway=gateway)
        return {
            "plan_count": len(entries),
            "by_family": by_family,
            "entries": entries,
            # 过滤审计：被闸门拦下的条目明细（孤儿/跨靶场/幻觉族），供对账与前端展示
            "filtered": filtered,
            "filtered_count": sum(len(v) for v in filtered.values()),
            "plan_source_counts": enrich_summary["plan_source_counts"],
            "rag_enrich": enrich_summary,
        }

    def _enrich_rag_plans(
        self,
        task_id: Optional[int],
        specs: List[Dict[str, Any]],
        entries: List[Dict[str, Any]],
        gateway=None,
    ) -> Dict[str, Any]:
        """低完备度 spec 的 RAG+LLM 计划补齐 + 白名单校验 + 写回（A 第二/三步）。

        任何异常都降级为跳过（RAG 是增强项，绝不阻断 AP 主链路）。
        """
        summary: Dict[str, Any] = {
            "enabled": False, "considered": 0, "llm_plans": 0, "writebacks": 0,
            "rejected": {"route": 0, "param": 0},
            "plan_source_counts": {"llm": 0, "deterministic": 0},
        }
        if not _AP_RAG_ENABLED or gateway is None or getattr(gateway, "is_offline", True):
            summary["plan_source_counts"] = {"llm": 0, "deterministic": len(entries)}
            return summary
        summary["enabled"] = True
        try:
            from src.agents.d2_plan_rag import (
                attack_plan_completeness,
                generate_attack_plan,
                bump_metric,
            )
        except Exception as _e:
            logger.warning("[AP] RAG 计划模块加载失败（跳过增强）：%s", _e)
            summary["plan_source_counts"] = {"llm": 0, "deterministic": len(entries)}
            return summary
        for spec, entry in zip(specs, entries):
            raw = _loads(spec.get("raw_json", "{}"), {})
            exploit = raw.get("exploit_spec") or {}
            try:
                comp = attack_plan_completeness(exploit)
            except Exception:
                continue
            if comp.get("complete"):
                summary["plan_source_counts"]["deterministic"] += 1
                continue
            summary["considered"] += 1
            allowed_eps = [str(spec.get("target_endpoint") or "")]
            allowed_params = {str(spec.get("param_name") or "")}
            try:
                rep = _loads(spec.get("representative_request_params_json", "[]"), [])
                if isinstance(rep, list):
                    for item in rep:
                        if isinstance(item, dict) and item.get("name"):
                            allowed_params.add(str(item["name"]))
            except Exception:
                pass
            vuln_ctx = {
                "type": str(spec.get("family") or ""),
                "sink": str(spec.get("expected_sink_file") or ""),
                "file": str(spec.get("expected_sink_file") or ""),
                "line": str(spec.get("expected_sink_line") or ""),
                "entry_point": str(spec.get("target_endpoint") or ""),
            }
            try:
                plan = generate_attack_plan(
                    vulnerability=vuln_ctx,
                    project_context={"language": "", "framework": ""},
                    exploit_spec=exploit,
                    gateway=gateway,
                    allowed_endpoints=[e for e in allowed_eps if e],
                    allowed_params=[p for p in allowed_params if p],
                )
            except Exception:
                plan = None
            if not plan:
                continue
            summary["llm_plans"] += 1
            summary["plan_source_counts"]["llm"] += 1
            bump_metric("llm_generated")
            adopted_fields: List[str] = []
            sr = str(plan.get("suggested_route") or "").strip()
            sp = str(plan.get("suggested_parameter") or "").strip()
            if sr or sp:
                ok = self._write_back_entry_fields(spec, sr, sp)
                if ok:
                    summary["writebacks"] += 1
                    if sr:
                        adopted_fields.append("route")
                    if sp:
                        adopted_fields.append("parameter")
            entry["rag_plan"] = {"source": "llm", "adopted_fields": adopted_fields}
        return summary

    def _write_back_entry_fields(self, spec: Dict[str, Any], route: str, param: str) -> bool:
        """把白名单通过的 suggested_route/parameter 写回 trigger_specs.raw_json（仅空位，幂等）。"""
        if not route and not param:
            return False
        try:
            raw = _loads(spec.get("raw_json", "{}"), {})
            exploit = raw.get("exploit_spec")
            if not isinstance(exploit, dict):
                return False
            entry = exploit.setdefault("entry", {}) if isinstance(exploit.get("entry"), dict) else {}
            changed = False
            if route and not str(entry.get("route") or "").strip():
                entry["route"] = route
                entry["resolved_by"] = "llm-rag"
                changed = True
            if param and not str(entry.get("parameter_name") or "").strip():
                entry["parameter_name"] = param
                entry["resolved_by"] = "llm-rag"
                changed = True
            if not changed:
                return False
            exploit = normalize_exploit_spec(exploit)
            raw["exploit_spec"] = exploit
            self.db.execute(
                "UPDATE trigger_specs SET raw_json=? WHERE id=?",
                (json.dumps(raw, ensure_ascii=False), spec.get("id")),
            )
            return True
        except Exception as _e:
            logger.debug("[AP] spec 写回失败（忽略 spec_id=%s）：%s", spec.get("id"), _e)
            return False

    def _task_finding_hashes(self, task_id: int) -> set:
        """本 task findings 的 vhash 集合（spec 来源真值锚）。"""
        try:
            rows = self.db.execute(
                "SELECT DISTINCT vulnerability_hash_v2 FROM findings WHERE task_id=?",
                (task_id,), fetchall=True,
            ) or []
            return {str(r["vulnerability_hash_v2"]) for r in rows if r.get("vulnerability_hash_v2")}
        except Exception:
            return set()

    def _workspace_target_root(self, workspace_id: Optional[int], specs: List[Dict[str, Any]]) -> str:
        """取 workspace 靶场工程根（用于绝对 sink 路径外靶场判定）。"""
        ws = workspace_id
        if not ws:
            for spec in specs or []:
                if spec.get("workspace_id"):
                    ws = spec.get("workspace_id")
                    break
        if not ws:
            return ""
        try:
            row = self.db.execute(
                "SELECT target_path FROM workspaces WHERE id=?", (ws,), fetchone=True
            )
            return str((row or {}).get("target_path") or "")
        except Exception:
            return ""

    @staticmethod
    def _is_foreign_sink(spec: Dict[str, Any], ws_root: str) -> bool:
        """expected_sink_file 为绝对路径且不在靶场工程根下 → 外靶场代码（跨靶场污染）。"""
        sink = str(spec.get("expected_sink_file") or "").strip()
        if not sink or not ws_root:
            return False
        try:
            norm = os.path.normpath(sink)
            if not os.path.isabs(norm):
                return False
            root = os.path.normpath(ws_root)
            return not norm.lower().startswith(root.lower())
        except Exception:
            return False

    @staticmethod
    def _classify(events: List[Dict[str, Any]]) -> tuple:
        if not events:
            return "not_hit", 0
        states = {str(e.get("canary_state", "")).lower() for e in events}
        matched = any(int(e.get("canary_match") or 0) == 1 for e in events)
        if "sink-reached" in states or "sink_reached" in states:
            return "arrived", len(events)
        if matched or "arrived" in states or "arrival-sanitized" in states:
            return "observed", len(events)
        return "not_hit", len(events)

    def _lookup_finding_verdict(self, task_id: int, vhash: str) -> Optional[Dict[str, Any]]:
        """按 vulnerability_hash_v2 反查 findings 的权威 D2 裁决，供 AP 运行时命中回填（#point-1）。

        返回 d2_harmful / verification_status / iast_authz_confirmed 三项裁决信号。
        findings 表才是 D2 裁决的唯一真相（report_manager 落盘的 d2_verdict / verification_decision /
        iast_evidence），trigger_specs 的 business_logic_confirmed 等字段只是其部分投影。
        """
        if not vhash:
            return None
        try:
            row = self.db.execute(
                "SELECT raw_json FROM findings WHERE task_id = ? AND vulnerability_hash_v2 = ? LIMIT 1",
                (task_id, vhash), fetchone=True,
            )
        except Exception:
            return None
        if not row:
            return None
        raw = _loads(row.get("raw_json"), {})
        d2 = raw.get("d2_verdict") or {}
        vd = raw.get("verification_decision") or {}
        ie = raw.get("iast_evidence") or {}
        return {
            "d2_harmful": bool(d2.get("harmful")),
            "verification_status": str(vd.get("verification_status") or ""),
            "iast_authz_confirmed": bool(ie.get("iast_authz_confirmed")),
        }

    def _project(self, spec: Dict[str, Any], order: int) -> Dict[str, Any]:
        family = spec.get("family", "")
        canary = spec.get("taint_marker", "")
        raw = _loads(spec.get("raw_json", "{}"), {})
        exploit = raw.get("exploit_spec") or {}
        payload_block = exploit.get("payload") or {}
        candidate_payloads = payload_block.get("candidate_payloads") or []
        high_impact = payload_block.get("high_impact_ladder") or []
        success = exploit.get("success_signal") or {}
        attack_payloads = _loads(spec.get("attack_payloads_json", "[]"), [])

        # POC 预览：优先 A2 设计的候选 payload，其次 D1 弹药库回退；截断避免前端溢出。
        poc_preview = candidate_payloads[0] if candidate_payloads else (attack_payloads[0] if attack_payloads else "")
        if isinstance(poc_preview, dict):
            poc_preview = poc_preview.get("value") or poc_preview.get("payload") or json.dumps(poc_preview, ensure_ascii=False)
        if isinstance(poc_preview, str) and len(poc_preview) > 200:
            poc_preview = poc_preview[:200] + " …(截断)"

        # 仅暴露 canary 身份段（s4st41 + 16hex），不暴露完整 canary
        canary_identity = ""
        if canary:
            import re
            m = re.search(r"(s4st41[0-9a-fA-F]{16})", canary)
            canary_identity = m.group(1) if m else canary[:22]

        return {
            "order": order,
            "spec_id": spec.get("id"),
            "family": family,
            "flow_type": derive_flow_type(family),
            "endpoint": spec.get("target_endpoint", ""),
            "method": spec.get("http_method", "GET"),
            "param": spec.get("param_name", ""),
            "location": spec.get("param_location", "query"),
            "canary_identity": canary_identity,
            "poc_preview": poc_preview,
            "candidate_payload_count": len(candidate_payloads),
            "high_impact_count": len(high_impact),
            "success_signal": success.get("signal_type", ""),
            "expected_indicators": success.get("expected_indicators", [])[:5],
            "source_finding_hash": spec.get("vulnerability_hash_v2", ""),
            "target_sink": "{}:{}".format(
                spec.get("expected_sink_file", ""), spec.get("expected_sink_line", 0)
            ),
        }
