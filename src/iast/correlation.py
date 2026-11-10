"""关联聚合服务（重构文档 §3.3 核心粘合层 + §4.5 报告，方向A：查询层 join，不改表）。

跨源关联主键 = vulnerability_hash_v2（复用 core/vuln_hash.py）：SAST finding 与 IAST
观测通过同一条 TriggerSpec 关联——trigger_specs.vulnerability_hash_v2 即 SAST finding
的哈希，其 taint_marker 即 canary，iast_events.canary 命中该 canary 即该 finding 的运行时观测。

§7.11 重定义：SAST 是唯一漏洞发现者（finding / vuln 实例之根），I1/D1/D2 只提供观测与校验证据。
故本服务以 findings 为根、在查询层 join IAST 证据，产出统一 Finding（sources 多源视图 + confirmed_runtime），
不写 vulnerability_instances、不建新表。

产出三块统计（§4.5）：覆盖率（iast_observed / total_hypotheses）、confirmed_runtime 占比、
按资产（appName）分布。
"""
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.infrastructure.db import Database
from src.iast.canary import CanaryMatcher, canary_key, is_sink_reached
from src.iast.canary import STATE_RANK_STR
from src.iast.sink_identity import is_genuine_sink_identity
from src.iast.probe_coverage import (
    refine_no_arrival_state, load_coverage_manifest, GENUINE_NO_ARRIVAL,
)


# 观测态强弱（用于对同一 finding 的多条事件取最强态）。
# v2 证据分层 D1：收敛为 src/iast/canary.py 的 STATE_RANK_STR 单一真相源，
# 旧副本把 arrived(1)/arrival-sanitized(2) 序位反转、且 sink-reached-probe 被压到与 sink-reached 同档。
_STATE_RANK = STATE_RANK_STR


def _now() -> str:
    return datetime.utcnow().isoformat()


# 探针自写日志噪声哨兵：探针把自身运行日志写入 <log-dir>/sec-agent.log，会产生
# sink=java.nio.file.Files 且 source_value 含该路径的事件（含 TAINT_FLOW 主通道），调用栈常为空、
# 与应用真实漏洞无关。该文件名是探针内部日志名，真实靶场漏洞不会涉及，故在关联层直接排除其对
# confirmed_runtime 的背书（与探针侧 EventBuffer.isSelfSinkNoise 纵深防御）。fail-open：缺字段不误杀。
_PROBE_SELF_LOG_MARKER = "sec-agent.log"


def _is_probe_self_noise(event: Dict[str, Any]) -> bool:
    try:
        sv = event.get("source_value") or ""
        if _PROBE_SELF_LOG_MARKER in sv:
            return True
        sf = event.get("sink_file") or ""
        if _PROBE_SELF_LOG_MARKER in sf:
            return True
        return False
    except Exception:
        return False


class IastCorrelationService:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))

    # ------------------------------------------------------------------ 聚合 #
    def correlate(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> Dict[str, Any]:
        findings = self._load_findings(workspace_id, task_id)
        specs = self._load_specs(workspace_id, task_id)
        events = self._load_events(workspace_id, task_id)
        # Q8：探针整体存活探针 = 本 workspace/task 任一事件到达过非 no-arrival 态。
        # 用于区分 probe_unavailable（探针整体异常）与 genuine_no_arrival。
        probe_alive = any((e.get("canary_state") or "") not in ("", "no-arrival") for e in events)
        ws_apps = self._load_workspace_apps(workspace_id)

        ev_by_canary: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            # §2026-09-21：探针自写日志噪声（source_value 含 sec-agent.log）不参与关联——
            # 它共享请求上下文的 canary，却与应用真实漏洞无关，会错误背书 confirmed_runtime。
            if _is_probe_self_noise(e):
                continue
            # 两侧一律归一为身份段再比对：事件 canary 可能带元字符尾缀或被截断。
            if e["canary"]:
                ev_by_canary[canary_key(e["canary"])].append(e)

        # Point5 语义分级：exploit_confirmed 是 D2 harmful 裁决确认的可观测危害（与 canary 抵 sink
        # 的「污点抵达」互补）。按 vulnerability_hash_v2 取本 workspace/task 的确认集合。
        exploit_map = self._load_exploit_confirmed(workspace_id, task_id)

        hash_to_canaries: Dict[str, set] = defaultdict(set)
        hash_to_family: Dict[str, str] = {}
        hash_to_session: Dict[str, Optional[int]] = {}
        hash_to_sink: Dict[str, str] = {}
        # Q8：按 session 预载探针织桩清单，用于把无事件 spec 的 no-arrival 拆三态。
        session_manifests: Dict[Optional[int], Optional[Set[str]]] = {}
        for s in specs:
            # 用身份段（s4st41<16hex>）关联：trigger_specs.taint_marker 形如
            # 「身份段 + 元字符段」，而探针事件经 bridge 翻译后 canary 即身份段，
            # 两段前缀一致即可精确关联（子串/前缀匹配，容错探针 512 截断）。
            ident = CanaryMatcher.find_identity(s["taint_marker"])
            if s["vulnerability_hash_v2"] and ident:
                hash_to_canaries[s["vulnerability_hash_v2"]].add(ident)
                if s.get("family"):
                    hash_to_family.setdefault(s["vulnerability_hash_v2"], s["family"])
                hash_to_session.setdefault(s["vulnerability_hash_v2"], s.get("session_id"))
                hash_to_sink.setdefault(s["vulnerability_hash_v2"], s.get("expected_sink_file") or "")

        out: List[Dict[str, Any]] = []
        observed = 0
        confirmed = 0
        exploit_confirmed = 0
        per_asset: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "observed": 0, "confirmed_runtime": 0, "exploit_confirmed": 0})

        for f in findings:
            h = f["vulnerability_hash_v2"] or ""
            evs: List[Dict[str, Any]] = []
            for c in hash_to_canaries.get(h, set()):
                evs.extend(ev_by_canary.get(c, []))

            state: Optional[str] = None
            confirmed_runtime = False
            app_name = agent_id = sink_file = last_seen = ""
            sink_line = 0
            trace_id = ""
            event_types: List[str] = []
            canary_observed = False
            if evs:
                # 取最强态（含探针显式断言 sink-reached-probe）；ties 取首个，但身份校验看全部最强态事件。
                strongest_rank = max(_STATE_RANK.get(e.get("canary_state") or "", 0) for e in evs)
                top_events = [e for e in evs if _STATE_RANK.get(e.get("canary_state") or "", 0) == strongest_rank]
                best = top_events[0]
                state = (best.get("canary_state") or "") or "no-arrival"
                fam = hash_to_family.get(h) or f.get("finding_type") or ""
                # ④ sink 身份校验：canary 虽抵达 sink 态，但只要最强态里「任意一条」是真实 sink
                # （非框架噪声 sink，XSS/SSTI 例外）即确认——零误杀；若最强态全是框架噪声 sink
                # （如 Response.setHeader），则不构成该族真实漏洞证据，confirmed_runtime 不予背书。
                confirmed_runtime = any(
                    is_sink_reached(e.get("canary_state") or "") and is_genuine_sink_identity(e.get("sink_file") or "", fam)
                    for e in top_events
                )
                # 展示用 sink：优先取真实 sink，否则退回首条最强态事件。
                genuine_top = [e for e in top_events if is_genuine_sink_identity(e.get("sink_file") or "", fam)]
                display = genuine_top[0] if genuine_top else best
                app_name = display.get("app_name") or ""
                agent_id = display.get("agent_id") or ""
                sink_file = display.get("sink_file") or ""
                sink_line = int(display.get("sink_line") or 0)
                last_seen = display.get("ingested_at") or ""
                trace_id = display.get("trace_id") or ""
                # §7.1 事件流：标记 canary_observed 轻量事件（消解 no-arrival 歧义，前端事件流可见）
                event_types = sorted({str(e.get("event_type") or "sink_call") for e in evs})
                canary_observed = "canary_observed" in event_types

            # Q8：无 IAST 事件（state 为 None）的 spec，用探针织桩清单把笼统 no-arrival 拆三态。
            # 有事件则维持 canary_state 原态，不覆盖。
            probe_state = GENUINE_NO_ARRIVAL
            if state is None:
                _sid = hash_to_session.get(h)
                _manifest = session_manifests.get(_sid) if _sid in session_manifests else None
                if _manifest is None and _sid is not None:
                    _manifest = load_coverage_manifest(self.db, _sid)
                    session_manifests[_sid] = _manifest
                probe_state = refine_no_arrival_state(
                    hash_to_sink.get(h, ""), _manifest, probe_alive,
                )

            exp_conf = bool(exploit_map.get(h))
            if state and state != "no-arrival":
                observed += 1
            if confirmed_runtime:
                confirmed += 1
            if exp_conf:
                exploit_confirmed += 1

            asset = app_name or self._resolve_asset(f["workspace_id"], ws_apps)
            per_asset[asset]["total"] += 1
            if state and state != "no-arrival":
                per_asset[asset]["observed"] += 1
            if confirmed_runtime:
                per_asset[asset]["confirmed_runtime"] += 1
            if exp_conf:
                per_asset[asset]["exploit_confirmed"] += 1

            sources = ["SAST"]
            if state:
                sources.append("IAST")

            out.append({
                "vulnerability_hash_v2": h,
                "finding_type": f["finding_type"],
                "severity": f["severity"],
                "file_path": f["file_path"],
                "line": f["line"],
                "title": f["title"],
                "source": f.get("source", ""),
                "iast": {
                    "state": state,
                    "confirmed_runtime": confirmed_runtime,
                    "exploit_confirmed": exp_conf,
                    "event_count": len(evs),
                    "last_seen": last_seen,
                    "app_name": app_name,
                    "agent_id": agent_id,
                    "sink_file": sink_file,
                    "sink_line": sink_line,
                    "trace_id": trace_id,
                    "event_types": event_types,
                    "canary_observed": canary_observed,
                    "probe_state": probe_state,
                },
                "sources": sources,
            })

        total = len(out)
        stats = {
            "total_hypotheses": total,
            "iast_observed": observed,
            "confirmed_runtime": confirmed,
            "sink_reached_count": confirmed,
            "exploit_confirmed": exploit_confirmed,
            "coverage_ratio": round(observed / total, 4) if total else 0.0,
            "confirmed_runtime_ratio": round(confirmed / total, 4) if total else 0.0,
            "exploit_confirmed_ratio": round(exploit_confirmed / total, 4) if total else 0.0,
            "per_asset": [
                {
                    "asset": k,
                    "total": v["total"],
                    "observed": v["observed"],
                    "confirmed_runtime": v["confirmed_runtime"],
                    "exploit_confirmed": v["exploit_confirmed"],
                }
                for k, v in sorted(per_asset.items())
            ],
        }

        # §I1 诊断：列出「带 canary 但不属于本 task 任何 spec」的事件（即跨任务/跨运行泄漏的旧
        # canary 串），让用户一眼看出 I1 为 0 到底是「探针没捕获」还是「捕获到的是别的 task 的残留」。
        diagnostics = self._build_canary_diagnostics(workspace_id, task_id, events, specs)

        return {
            "workspace_id": workspace_id,
            "task_id": task_id,
            "generated_at": _now(),
            "stats": stats,
            "findings": out,
            "diagnostics": diagnostics,
        }

    def _build_canary_diagnostics(self, workspace_id, task_id, events, current_specs) -> Dict[str, Any]:
        # 本 task 的 spec 身份段集合
        current_idents = {
            CanaryMatcher.find_identity(s["taint_marker"])
            for s in current_specs
            if s.get("taint_marker")
        }
        current_idents.discard("")
        # workspace 内所有 spec 的 身份段→归属 task_id 映射（用于判定外来 canary 的真实归属）
        owner_map: Dict[str, int] = {}
        if workspace_id is not None:
            for s in self._load_specs(workspace_id):
                ident = CanaryMatcher.find_identity(s.get("taint_marker") or "")
                if ident:
                    owner_map[ident] = s.get("task_id")
        unmatched: List[Dict[str, Any]] = []
        seen_idents = set()
        for e in events:
            canary = e.get("canary") or ""
            if not canary:
                continue
            ident = CanaryMatcher.find_identity(canary)
            if not ident or ident in current_idents:
                continue
            if ident in seen_idents:
                continue
            seen_idents.add(ident)
            unmatched.append({
                "canary_identity": ident,
                "owner_task_id": owner_map.get(ident),
                "event_type": e.get("event_type") or "",
                "canary_state": e.get("canary_state") or "",
                "ingested_at": e.get("ingested_at") or "",
            })
            if len(unmatched) >= 30:
                break
        return {
            "current_task_spec_count": len(current_idents),
            "unmatched_canary_events": unmatched,
            "unmatched_count": len(unmatched),
        }

    # ------------------------------------------------------------------ 报告 #
    def render_markdown(self, workspace_id: Optional[int] = None, task_id: Optional[int] = None) -> str:
        data = self.correlate(workspace_id, task_id)
        stats = data["stats"]
        lines: List[str] = []
        lines.append("# IAST 关联聚合报告")
        lines.append("")
        lines.append("报告类型：iast-correlation（独立报告，不碰 B1/B2 内核）")
        lines.append(f"生成时间：{data['generated_at']}")
        if workspace_id is not None:
            lines.append(f"workspace_id：{workspace_id}")
        if task_id is not None:
            lines.append(f"task_id：{task_id}")
        lines.append("")
        lines.append("## 总体统计")
        lines.append("")
        lines.append(f"SAST 假说总数：{stats['total_hypotheses']}")
        lines.append(f"IAST 观测命中：{stats['iast_observed']}")
        lines.append(f"污点抵达 sink（taint_reached / confirmed_runtime）：{stats['confirmed_runtime']}")
        lines.append(f"确认可利用（exploit_confirmed）：{stats['exploit_confirmed']}")
        lines.append(f"覆盖率：{stats['coverage_ratio']:.2%}")
        lines.append(f"污点抵达占比：{stats['confirmed_runtime_ratio']:.2%}")
        lines.append(f"确认可利用占比：{stats['exploit_confirmed_ratio']:.2%}")
        lines.append("")
        lines.append("## 按资产分布")
        lines.append("")
        for a in stats["per_asset"]:
            lines.append(f"{a['asset']}：total={a['total']} observed={a['observed']} taint_reached={a['confirmed_runtime']} exploit_confirmed={a['exploit_confirmed']}")
        lines.append("")
        lines.append("## 统一 Finding 清单")
        lines.append("")
        for f in data["findings"]:
            iast = f["iast"]
            tag = "confirmed_runtime" if iast["confirmed_runtime"] else (iast["state"] or "no-observation")
            lines.append(
                f"{f['finding_type']} [{tag}] {f['file_path']}:{f['line']} "
                f"(hash={f['vulnerability_hash_v2'] or '<空>'}, sources={'+'.join(f['sources'])})"
            )
        lines.append("")
        return "\n".join(lines)

    def generate_report(
        self,
        workspace_id: int,
        task_id: Optional[int] = None,
        out_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """生成 iast-correlation 报告文件（.md + .json），返回报告元数据（report_type=iast-correlation）。"""
        data = self.correlate(workspace_id, task_id)
        markdown = self.render_markdown(workspace_id, task_id)

        base = Path(out_dir) if out_dir else Path("data") / "iast_reports"
        base.mkdir(parents=True, exist_ok=True)
        stem = f"iast_correlation_ws{workspace_id}"
        if task_id is not None:
            stem += f"_task{task_id}"
        md_path = base / f"{stem}.md"
        json_path = base / f"{stem}.json"
        md_path.write_text(markdown, encoding="utf-8")
        json_path.write_text(Database.dumps(data), encoding="utf-8")

        return {
            "report_type": "iast-correlation",
            "workspace_id": workspace_id,
            "task_id": task_id,
            "file_path": str(md_path),
            "json_file_path": str(json_path),
            "generated_at": data["generated_at"],
            "stats": data["stats"],
        }

    # ------------------------------------------------------------------ 内部 #
    def _load_findings(self, workspace_id, task_id) -> List[Dict[str, Any]]:
        # §SCA 隔离：SCA findings 只走 SCA 软件成分分析模块，不参与 I1/I2 运行时关联/裁决。
        sql = "SELECT * FROM findings WHERE COALESCE(source, '') != 'sca'"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        sql += " ORDER BY id"
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _load_specs(self, workspace_id, task_id=None) -> List[Dict[str, Any]]:
        # task_id / family 必须一并取出：task_id 供 _build_canary_diagnostics 构建归属映射；
        # family 供 ④ sink 身份校验区分 XSS/SSTI（响应写入即真 sink）与普通族（框架噪声 sink 不背书）。
        # session_id / expected_sink_file：Q8 探针织桩清单消歧用（按 session 取 manifest，按 sink 比对）。
        sql = "SELECT vulnerability_hash_v2, taint_marker, task_id, family, session_id, expected_sink_file FROM trigger_specs"
        clauses: List[str] = []
        params: List[Any] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _load_events(self, workspace_id, task_id=None) -> List[Dict[str, Any]]:
        sql = ("SELECT canary, canary_state, app_name, agent_id, workspace_id, "
               "sink_file, sink_line, trace_id, event_type, ingested_at, source_value "
               "FROM iast_events")
        clauses: List[str] = []
        params: List[Any] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(task_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return [dict(r) for r in (self.db.execute(sql, params, fetchall=True) or [])]

    def _load_exploit_confirmed(self, workspace_id, task_id=None) -> Dict[str, int]:
        """Point5：取本 workspace/task 内已被 D2 harmful 裁决确认为「可利用」的 vulnerability_hash_v2 集合。

        来源 vulnerability_instances.exploit_confirmed（由 D2 门面在 harmful 裁决后写入），与
        canary 抵 sink 的 confirmed_runtime 是两层不同语义，此处仅取第二层（exploit_confirmed）。
        """
        sql = "SELECT vulnerability_hash_v2, MAX(exploit_confirmed) AS ec FROM vulnerability_instances WHERE exploit_confirmed = 1"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " AND workspace_id = ?"
            params.append(workspace_id)
        if task_id is not None:
            sql += " AND (first_seen_task_id = ? OR last_seen_task_id = ?)"
            params.extend([task_id, task_id])
        sql += " GROUP BY vulnerability_hash_v2"
        out: Dict[str, int] = {}
        for r in (self.db.execute(sql, params, fetchall=True) or []):
            h = r.get("vulnerability_hash_v2") or ""
            if h:
                out[h] = 1
        return out

    def _load_workspace_apps(self, workspace_id) -> Dict[int, List[str]]:
        """workspace_id → 去重后的 app_name 列表（供未观测 finding 归入资产）。"""
        sql = "SELECT workspace_id, app_name FROM iast_sessions"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id = ?"
            params.append(workspace_id)
        mapping: Dict[int, List[str]] = defaultdict(list)
        for r in (self.db.execute(sql, params, fetchall=True) or []):
            row = dict(r)
            ws = row["workspace_id"]
            app = row.get("app_name") or ""
            if app and app not in mapping[ws]:
                mapping[ws].append(app)
        return mapping

    @staticmethod
    def _resolve_asset(workspace_id: int, ws_apps: Dict[int, List[str]]) -> str:
        apps = ws_apps.get(workspace_id, [])
        if len(apps) == 1:
            return apps[0]
        return f"workspace:{workspace_id}"
