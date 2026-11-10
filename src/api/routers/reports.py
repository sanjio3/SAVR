from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from src.api.dependencies import container
from src.api.schemas import ReportContentResponse, ReportResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_report_or_404(report_id: int):
    report = next((item for item in container.report_repository.list() if item.id == report_id), None)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _build_structured(task_id: int) -> dict:
    """按 task 聚合出可视化看板所需的结构化数据（只读，不改任何落库契约）。

    为什么需要：FINAL_REPORT 是纯 Markdown（reports 表实测 35/35 全是 FINAL_REPORT），
    数字全压在一张表里不可读；而 findings/vuln_blackboard/trigger_specs 三表已具备
    全部可视化维度（严重度、族、来源引擎、验证状态、sink 身份、闭环状态），只是没人读。
    本函数把这些维度一次算清，前端按维度画图 + 联动筛选，无需再解析 Markdown。
    """
    import json as _json

    # 复用容器的 Database（同一 DB 真相 + 线程缓存连接 + 自身锁），
    # 不用另开 sqlite3 连接，避免 WAL 快照不一致与长事务锁竞争。
    db = getattr(container, "db", None)
    if db is None:
        raise HTTPException(status_code=503, detail="DB not ready")

    def _all(sql: str, params=()) -> list:
        rows = db.execute(sql, list(params), fetchall=True) or []
        return [dict(r) for r in rows]

    def _one(sql: str, params=()) -> int:
        rows = _all(sql, params)
        if not rows:
            return 0
        return int(next(iter(rows[0].values()), 0) or 0)

    # —— 概览 ——
    app_findings = _one(
        "SELECT COUNT(*) FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0) AND COALESCE(source,'')!='sca'", (task_id,))
    sca_findings = _one("SELECT COUNT(*) FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0) AND source='sca'", (task_id,))
    confirmed_specs = _one(
        "SELECT COUNT(*) FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0 "
        "AND verification_status IN ('confirmed_exploitable','exploitable','confirmed_code_property')",
        (task_id,))
    total_specs = _one("SELECT COUNT(*) FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0", (task_id,))
    # 族标错的可观测信号：族标签与「代码能力证据」对不上的条数。
    # 族标签来自 A1/A2，会标错（实测检出用例里 17.3% 与真实类别完全对不上）。
    # 这里不改族，只把冲突数暴露出来，并同时给出能力族供人工判读。
    family_evidence_conflict = _one(
        "SELECT COUNT(*) FROM trigger_specs WHERE task_id=? "
        "AND COALESCE(suppressed_by_safe_verdict, 0) = 0 "
        "AND COALESCE(capability_family,'') != '' "
        "AND capability_family != family", (task_id,))

    # —— 维度分布（各一个 GROUP BY，前端直接画图）——
    def _dist(sql: str, params) -> dict:
        try:
            return {str(r.get("k")): int(r.get("c") or 0) for r in _all(sql, params)}
        except Exception:
            return {}

    severity = _dist(
        "SELECT severity k, COUNT(*) c FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0) "
        "AND COALESCE(source,'')!='sca' GROUP BY 1 ORDER BY 2 DESC", (task_id,))
    by_source = _dist(
        "SELECT COALESCE(source,'(未知)') k, COUNT(*) c FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0) "
        "GROUP BY 1 ORDER BY 2 DESC", (task_id,))
    by_verification = _dist(
        "SELECT COALESCE(verification_status,'(无 spec)') k, COUNT(*) c FROM trigger_specs "
        "WHERE task_id=? GROUP BY 1 ORDER BY 2 DESC", (task_id,))
    by_iast_state = _dist(
        "SELECT COALESCE(iast_state,'(无观测)') k, COUNT(*) c FROM trigger_specs "
        "WHERE task_id=? GROUP BY 1 ORDER BY 2 DESC", (task_id,))
    by_family = _dist(
        "SELECT COALESCE(family,'(未归族)') k, COUNT(*) c FROM trigger_specs "
        "WHERE task_id=? GROUP BY 1 ORDER BY 2 DESC LIMIT 40", (task_id,))
    by_capability_family = _dist(
        "SELECT COALESCE(capability_family,'(无能力证据)') k, COUNT(*) c FROM trigger_specs "
        "WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0 "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 40", (task_id,))

    # —— 族 × 验证状态 矩阵（发现列表的分组视图）——
    matrix: dict = {}
    for r in _all(
        "SELECT COALESCE(family,'(未归族)') f, COALESCE(verification_status,'(无 spec)') v, "
        "COUNT(*) c FROM trigger_specs WHERE task_id=? AND COALESCE(suppressed_by_safe_verdict, 0) = 0 GROUP BY 1,2", (task_id,)
    ):
        matrix.setdefault(str(r.get("f")), {})[str(r.get("v"))] = int(r.get("c") or 0)

    # —— 发现清单（含 Q1 证据强度，让「运行时/两层打架」变人话）——
    from src.iast.canary import CanaryMatcher as _CM
    from src.iast.sink_identity import is_genuine_sink_identity as _Genuine
    items = []
    for r in _all(
        "SELECT b.family, b.verification_status, b.iast_state, b.target_endpoint, "
        "b.http_method, b.sink_reached, b.vulnerability_hash_v2, "
        "f.finding_type, f.severity, f.file_path, f.line, "
        "f.title, f.source, s.taint_marker, s.expected_sink_file, "
        "COALESCE(s.capability_family,'') AS capability_family "
        "FROM vuln_blackboard b "
        "LEFT JOIN findings f ON f.id=b.finding_id "
        "LEFT JOIN trigger_specs s ON s.id=b.trigger_spec_id "
        "WHERE b.task_id=? ORDER BY f.severity, f.file_path LIMIT 800", (task_id,)
    ):
        fam = str(r.get("family") or r.get("finding_type") or "")
        vstat = str(r.get("verification_status") or "")
        istate = str(r.get("iast_state") or "")
        # 证据强度：confirmed 且运行时抵达真 sink = 强；confirmed 但落噪声 sink = 弱
        # （Q1 修复后这类会被降级，此处仅作展示口径兜底）；仅 DAST 轴 = dast_only。
        reached = bool(r.get("sink_reached")) or istate in (
            "sink-reached", "sink-reached-probe", "iast-reached", "iast-authz-confirmed")
        noise_only = False
        try:
            # 证据反查的 canary 标识有三处可能来源，按可靠性排序：
            # ① spec.taint_marker（最直接）；② 用黑板自身的 vulnerability_hash_v2 反查本 task
            # 的 spec（黑板行常不带 trigger_spec_id —— 那条 LEFT JOIN 会拿到 NULL，
            # 只靠 ① 会静默退化成「无证据」而误判为 strong）；③ 无从反查则不判。
            _id = _CM.find_identity(str(r.get("taint_marker") or ""))
            if not _id:
                _vh = str(r.get("vulnerability_hash_v2") or "")
                if _vh:
                    for sr in _all(
                        "SELECT taint_marker FROM trigger_specs "
                        "WHERE task_id=? AND vulnerability_hash_v2=? LIMIT 1", (task_id, _vh)
                    ):
                        _id = _CM.find_identity(str(sr.get("taint_marker") or ""))
                        if _id:
                            break
            if _id and reached:
                _sfs = [str(x.get("sink_file") or "") for x in _all(
                    "SELECT sink_file FROM iast_events WHERE task_id=? AND canary LIKE ?",
                    (task_id, "%" + _id + "%"))]
                _sfs = [x for x in _sfs if x]
                noise_only = bool(_sfs) and not any(_Genuine(x, fam) for x in _sfs)
        except Exception:
            noise_only = False
        if vstat in ("confirmed_exploitable", "exploitable", "confirmed_code_property"):
            strength = "weak" if noise_only else ("strong" if reached else "dast_only")
        elif vstat in ("filtered_not_exploitable", "false_positive"):
            strength = "negative"
        elif vstat:
            strength = "unverified"
        else:
            strength = "detect_only"
        items.append({
            "family": fam,
            "finding_type": str(r.get("finding_type") or ""),
            "severity": str(r.get("severity") or ""),
            "title": str(r.get("title") or ""),
            "location": ("%s:%s" % (r.get("file_path"), r.get("line")) if r.get("file_path") else ""),
            "endpoint": str(r.get("target_endpoint") or ""),
            "http_method": str(r.get("http_method") or ""),
            "source": str(r.get("source") or ""),
            "verification_status": vstat,
            "iast_state": istate,
            "expected_sink": str(r.get("expected_sink_file") or ""),
            "evidence_strength": strength,
            # 代码能力证据给出的族：与 family 并列展示，族标错时用户有第二个参照
            "capability_family": str(r.get("capability_family") or ""),
        })
    total_items = _one("SELECT COUNT(*) FROM vuln_blackboard WHERE task_id=?", (task_id,))
    return {
        "task_id": task_id,
        "overview": {
            "app_findings": app_findings,
            "sca_findings": sca_findings,
            "total_findings": app_findings + sca_findings,
            "total_specs": total_specs,
            "confirmed_specs": confirmed_specs,
            "family_evidence_conflict": family_evidence_conflict,
            "spec_coverage": round(confirmed_specs / total_specs, 4) if total_specs else 0.0,
        },
        "distributions": {
            "severity": severity,
            "by_source": by_source,
            "by_verification": by_verification,
            "by_iast_state": by_iast_state,
            "by_family": by_family,
            "by_capability_family": by_capability_family,
        },
        "family_matrix": matrix,
        "findings": items,
        "findings_truncated": total_items > len(items),
        "findings_total": total_items,
    }


@router.get("", response_model=list[ReportResponse])
def list_reports(workspace_id: int | None = None, task_id: int | None = None):
    return container.report_repository.list(workspace_id=workspace_id, task_id=task_id)


@router.get("/{report_id}/structured")
def structured_report(report_id: int):
    """结构化可视化数据（只读）。按 report 所属 task 聚合，供 ReportDashboard 画图。"""
    report = _get_report_or_404(report_id)
    return _build_structured(int(report.task_id))


@router.get("/{report_id}/download")
def download_report(report_id: int):
    report = _get_report_or_404(report_id)
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")
    return FileResponse(path)


@router.get("/{report_id}/content", response_model=ReportContentResponse)
def read_report_content(report_id: int):
    report = _get_report_or_404(report_id)
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")

    suffix = path.suffix.lower()
    content_type = "text/plain"
    if suffix == ".md":
        content_type = "text/markdown"
    elif suffix == ".json":
        content_type = "application/json"

    return ReportContentResponse(
        id=report.id,
        task_id=report.task_id,
        workspace_id=report.workspace_id,
        report_type=report.report_type,
        file_path=report.file_path,
        content=path.read_text(encoding="utf-8", errors="replace"),
        content_type=content_type,
        exists=True,
    )
