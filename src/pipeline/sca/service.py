import re
import time
from typing import Any, Dict, List

from src.pipeline.sca.adapters import (
    VULNERABILITY_TOOLS,
    OSVScannerAdapter,
    all_tool_statuses,
    get_adapter,
    reconcile_cross_validation,
    apply_fixed_version_check,
    _norm_comp_name,
    _norm_eco,
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)


def _cve_ids_of(finding: Dict[str, Any]) -> List[str]:
    sca = finding.get("sca") or {}
    ids: List[str] = []
    vid = str(sca.get("vulnerability_id", "") or "")
    if _CVE_RE.match(vid):
        ids.append(vid.upper())
    for a in (sca.get("aliases") or []):
        if _CVE_RE.match(str(a)):
            ids.append(str(a).upper())
    # 去重保序
    seen = set()
    out = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def explode_findings_by_cve(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把「一个公告打包多个 CVE」的 finding 按 CVE 拆成多条，使跨工具去重能以 CVE 为最小单位。

    OSV 一个 GHSA 公告常并列 CVE-1 / CVE-2，而 Grype 按 CVE 各报一条。若不拆，按公告粒度合并会
    把 CVE-2 吞掉、漏报。拆到 CVE 粒度后，同一组件同一 CVE 无论在 OSV 还是 Grype 都落入同一桶，
    既不会漏报也不会重复计数（「双重检测」每个 CVE 只算一次）。仅含 GHSA（无 CVE 别名）的公告
    保持原样，按其 GHSA id 去重。
    """
    out: List[Dict[str, Any]] = []
    for f in findings or []:
        cves = _cve_ids_of(f)
        if len(cves) <= 1:
            out.append(f)
            continue
        sca = f.get("sca") or {}
        for cve in cves:
            clone = dict(f)
            csca = dict(sca)
            csca["vulnerability_id"] = cve
            csca["aliases"] = [c for c in (sca.get("aliases") or []) if _CVE_RE.match(str(c)) and str(c).upper() != cve]
            if cve not in csca["aliases"]:
                csca["aliases"] = [cve] + csca["aliases"]
            clone["sca"] = csca
            clone["display_title"] = f"SCA: {sca.get('component_name', '')} {cve}".strip()
            out.append(clone)
    return out


class SCAPipelineService:
    """Front door to the SCA tool adapters.

    A single ``tool`` selects one adapter (osv-scanner, trivy, grype, syft).  The
    special value ``auto`` runs every available vulnerability scanner and merges the
    results, deduplicated by ``vulnerability_hash_v2`` so the same advisory reported by
    multiple tools collapses into one finding that records every tool that saw it.
    """

    stage_name = "sca"

    def __init__(self, tool: str = "auto"):
        self.tool = (tool or "auto").strip().lower()

    def tool_status(self) -> Dict[str, Any]:
        if self.tool == "auto":
            return {"tool": "auto", "available": any(s.get("available") for s in all_tool_statuses()), "tools": all_tool_statuses()}
        return get_adapter(self.tool).tool_status()

    @staticmethod
    def available_tools() -> List[Dict[str, Any]]:
        return all_tool_statuses()

    def scan(self, project_path: str, output_dir: str, severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> Dict[str, Any]:
        if self.tool == "auto":
            return self._scan_auto(project_path, output_dir, severity_threshold, ignore_unfixed)
        # 单工具路径同样要做交叉验证标记与 fixed 版本核查。此前只有 auto 走富集，
        # 而任务/API 默认 sca_tool='osv-scanner'（单工具），导致 cross_validated /
        # not_affected / confidence 永不落库，前端 SCA 面板无从展示（Q1 根因）。
            result = get_adapter(self.tool).run(project_path, output_dir, severity_threshold=severity_threshold, ignore_unfixed=ignore_unfixed)
        result["findings"] = explode_findings_by_cve(result.get("findings") or [])
        return self._apply_enrichment(result)

    @staticmethod
    def _apply_enrichment(result: Dict[str, Any]) -> Dict[str, Any]:
        """对任意工具产出的 findings 补齐交叉验证 / 版本比对标记与计数。

        单工具时 cross_validated 恒 False（定义要求 ≥2 个不同工具），但 not_affected
        （实际版本 ≥ fixed 版本 = 已修复/疑似误报）在单工具下依然成立且可判定。
        """
        findings = list(result.get("findings") or [])
        if not findings:
            result.setdefault("cross_validated_count", 0)
            result.setdefault("not_affected_count", 0)
            return result
        findings = reconcile_cross_validation(findings)
        findings = apply_fixed_version_check(findings)
        result["findings"] = findings
        # 去重后：并集 = 全部唯一漏洞（全量，保召回）；交集 = 被 ≥2 工具共同报出的高置信漏洞（准）。
        # 同一组件漏洞在「双重检测」中只计一次（已在 _merge_finding 按 CVE 别名去重合并）。
        union_count = len(findings)
        intersection_count = sum(1 for f in findings if (f.get("sca") or {}).get("cross_validated"))
        result["finding_count"] = union_count
        result["union_count"] = union_count
        result["intersection_count"] = intersection_count
        result["single_tool_count"] = union_count - intersection_count
        result["cross_validated_count"] = intersection_count
        result["not_affected_count"] = sum(1 for f in findings if (f.get("sca") or {}).get("not_affected"))
        for f in findings:
            sca = f.setdefault("sca", {})
            dby = sca.get("detected_by") or [sca.get("source_tool", "")]
            distinct = sorted({t for t in dby if t})
            sca["detection_tools"] = distinct
            # detection_type：前端据此外显「osv检测 / grype检测 / 双重检测」
            sca["detection_type"] = "double" if len(distinct) >= 2 else (distinct[0] if distinct else "unknown")
        return result

    def _scan_auto(self, project_path: str, output_dir: str, severity_threshold: str, ignore_unfixed: bool) -> Dict[str, Any]:
        started = time.time()
        tool_results: List[Dict[str, Any]] = []
        merged: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        ran_any = False
        for name in VULNERABILITY_TOOLS:
            adapter = get_adapter(name)
            if not adapter.is_available():
                tool_results.append({"tool": name, "status": "skipped", "finding_count": 0, "message": adapter.install_hint})
                continue
            ran_any = True
            result = adapter.run(project_path, output_dir, severity_threshold=severity_threshold, ignore_unfixed=ignore_unfixed)
            tool_results.append({k: v for k, v in result.items() if k != "findings"})
            for finding in explode_findings_by_cve(result.get("findings") or []):
                self._merge_finding(finding, name, merged, order)
        findings = [merged[key] for key in order]
        # 交叉验证：同组件跨工具（osv/trivy/grype）都报同一 advisory 才标 high confidence；
        # fixed 版本核查：实际版本已 ≥ fixed 版本则标 not_affected（疑似已修复/误报）。
        return self._apply_enrichment(
            {
                "status": "completed" if ran_any else "skipped",
                "tool": "auto",
                "tools_run": [r.get("tool") for r in tool_results if r.get("status") != "skipped"],
                "tool_results": tool_results,
                "finding_count": len(findings),
                "findings": findings,
                "message": "" if ran_any else "No SCA vulnerability scanner is available on PATH",
                "duration_seconds": round(time.time() - started, 3),
            }
        )

    @staticmethod
    def _canonical_vuln_key(finding: Dict[str, Any]):
        """跨工具同一漏洞的归一键（CVE 粒度）：OSV 报 GHSA-xxx（别名含 CVE-yyy）+ Grype 报 CVE-yyy
        必须落入同一桶，才能把「同一组件同一 CVE 被双工具报出」合并成一条。

        爆炸后每个 finding 至多 1 个 CVE，故直接以 (归一化组件名, 归一化生态, CVE) 为键；
        纯 GHSA（无 CVE 别名）则退化为 (组件, 生态, GHSA id)；两者皆无时再退化到原始 hash，
        避免同组件无 id 的多条被错误合并。
        """
        sca = finding.get("sca") or {}
        cves = _cve_ids_of(finding)
        comp = _norm_comp_name(sca.get("component_name", ""), sca.get("ecosystem", ""))
        eco = _norm_eco(sca.get("ecosystem", ""))
        if cves:
            return (comp, eco, cves[0])
        vid = str(sca.get("vulnerability_id", "") or "")
        if vid:
            return (comp, eco, vid)
        return finding.get("vulnerability_hash_v2") or f"{sca.get('source_tool', '')}:{finding.get('display_title', '')}"

    @staticmethod
    def _merge_finding(finding: Dict[str, Any], tool: str, merged: Dict[str, Dict[str, Any]], order: List[str]) -> None:
        key = SCAPipelineService._canonical_vuln_key(finding)
        existing = merged.get(key)
        if existing is None:
            sca = finding.setdefault("sca", {})
            sca["detected_by"] = [tool]
            merged[key] = finding
            order.append(key)
            return
        # 合并：union detected_by / aliases / fixed_versions，取最高 severity；跨工具同一 CVE 合并
        # 即视为双工具置信（≥2 不同工具），与 cross_validated 语义一致。
        sca_e = existing.setdefault("sca", {})
        db_e = sca_e.setdefault("detected_by", [sca_e.get("source_tool", "")])
        if tool not in db_e:
            db_e.append(tool)
        distinct = {t for t in db_e if t}
        if len(distinct) >= 2:
            sca_e["cross_validated"] = True
            sca_e["confidence"] = "high"
        ea = set(sca_e.get("aliases") or [])
        ea.update(finding.get("sca", {}).get("aliases") or [])
        sca_e["aliases"] = sorted(ea)
        ef = set(sca_e.get("fixed_versions") or [])
        ef.update(finding.get("sca", {}).get("fixed_versions") or [])
        sca_e["fixed_versions"] = sorted(ef)
        # severity 取最高（语义化比较）
        from src.pipeline.sca.adapters import severity_rank
        if severity_rank(finding.get("severity")) > severity_rank(existing.get("severity")):
            existing["severity"] = finding.get("severity")

    def _normalize_osv(self, payload: Dict[str, Any], severity_threshold: str = "LOW", ignore_unfixed: bool = False) -> List[Dict[str, Any]]:
        """Backward-compatible helper that normalizes raw OSV-Scanner JSON output."""
        return OSVScannerAdapter().normalize(payload, severity_threshold=severity_threshold, ignore_unfixed=ignore_unfixed)
