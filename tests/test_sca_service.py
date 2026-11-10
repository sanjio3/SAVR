from src.pipeline.sca.service import SCAPipelineService


def _scan_result(findings):
    return {"status": "completed", "findings": findings, "finding_count": len(findings)}


def test_single_tool_path_still_runs_enrichment():
    """单工具（非 auto）也必须执行交叉验证标记与 fixed 版本核查。

    回归背景：此前只有 _scan_auto 走富集，而任务/API 默认 sca_tool='osv-scanner'
    是单工具，导致 cross_validated / not_affected / confidence 永不落库，
    前端 SCA 面板无从展示（Q1 根因）。
    """
    findings = [
        {
            "severity": "HIGH",
            "sca": {
                "component_name": "demo",
                "component_version": "1.0.0",
                "ecosystem": "PyPI",
                "vulnerability_id": "GHSA-affected",
                "fixed_versions": ["1.0.1"],
                "source_tool": "osv-scanner",
            },
        },
        {
            "severity": "HIGH",
            "sca": {
                "component_name": "demo",
                "component_version": "2.0.0",
                "ecosystem": "PyPI",
                "vulnerability_id": "GHSA-fixed",
                "fixed_versions": ["1.0.1"],
                "source_tool": "osv-scanner",
            },
        },
    ]
    result = SCAPipelineService._apply_enrichment(_scan_result(findings))

    sca = [f["sca"] for f in result["findings"]]
    # 交叉验证需 ≥2 个不同工具，单工具恒 False（但字段必须存在）
    assert [s["cross_validated"] for s in sca] == [False, False]
    # 版本核查：1.0.0 < 1.0.1 受影响；2.0.0 ≥ 1.0.1 已修复
    assert [s["not_affected"] for s in sca] == [False, True]
    assert all(s["confidence"] for s in sca)
    assert result["cross_validated_count"] == 0
    assert result["not_affected_count"] == 1


def test_fixed_version_check_is_release_line_aware():
    """跨分支 backport 必须按发布线比对，不能跨线比较。

    反例：tomcat 9.0.35 的 advisory 同时列出 8.5.96 / 9.0.83 / 10.1.16 / 11.0.0-M11。
    9.0 线的修复版本是 9.0.83，9.0.35 < 9.0.83 → 仍受影响；若拿 8.5.96 比则误判已修复。
    """
    def _sca(version, fixed):
        return {
            "severity": "HIGH",
            "sca": {
                "component_name": "demo",
                "component_version": version,
                "ecosystem": "Maven",
                "vulnerability_id": "GHSA-x",
                "fixed_versions": fixed,
                "source_tool": "osv-scanner",
            },
        }

    multi_line = ["11.0.0-M11", "10.1.16", "9.0.83", "8.5.96"]
    cases = [
        ("9.0.35", multi_line, False),   # 同线有修复但未达到 -> 仍受影响
        ("9.0.83", multi_line, True),    # 恰好等于本线修复版本 -> 已修复
        ("9.0.90", multi_line, True),    # 高于本线修复版本 -> 已修复
        ("12.0.0", multi_line, True),    # 高于全部修复线 -> 已修复
        ("7.0.50", multi_line, False),   # 低于所有修复线且本线无修复 -> 保守判受影响
    ]
    for version, fixed, expected in cases:
        result = SCAPipelineService._apply_enrichment(_scan_result([_sca(version, fixed)]))
        got = result["findings"][0]["sca"]["not_affected"]
        assert got is expected, f"{version} vs {fixed}: 期望 {expected}，实际 {got}"


def test_apply_enrichment_handles_empty_findings():
    result = SCAPipelineService._apply_enrichment(_scan_result([]))
    assert result["cross_validated_count"] == 0
    assert result["not_affected_count"] == 0


def test_sca_service_normalizes_osv_payload():
    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-demo",
                                "summary": "demo vuln",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = SCAPipelineService()._normalize_osv(payload)
    assert len(findings) == 1
    assert findings[0]["sca"]["component_name"] == "demo"
    assert findings[0]["severity"] == "HIGH"


def _auto_merge(findings_by_tool):
    """复刻 _scan_auto 的「爆炸 + 按 CVE 合并」逻辑，便于单测。"""
    from src.pipeline.sca.service import explode_findings_by_cve

    merged = {}
    order = []
    for tool, findings in findings_by_tool:
        for f in explode_findings_by_cve(findings):
            SCAPipelineService._merge_finding(f, tool, merged, order)
    return [merged[k] for k in order]


def test_auto_merge_dedups_by_cve_union_intersection():
    """auto 模式：同一组件同一 CVE 被 OSV(GHSA+CVE 别名) 与 Grype(CVE) 双报 → 合并为 1 条，
    detection_type=double，并集=1、交集=1；另一 CVE 仅 Grype 报 → 单工具，不被双重计数。

    这是「181 虚高」的根因修复：此前按 vulnerability_hash_v2（OSV=GHSA / Grype=CVE）无法合并，
    导致同一组件漏洞在双重检测里被报两次。
    """
    osv = [{
        "severity": "HIGH",
        "sca": {
            "component_name": "log4j-core", "component_version": "2.14.1", "ecosystem": "Maven",
            "vulnerability_id": "GHSA-xy", "aliases": ["CVE-2021-44228"],
            "fixed_versions": ["2.15.0"], "source_tool": "osv-scanner",
        },
    }]
    grype = [
        {
            "severity": "HIGH",
            "sca": {
                "component_name": "log4j-core", "component_version": "2.14.1", "ecosystem": "Maven",
                "vulnerability_id": "CVE-2021-44228", "aliases": [],
                "fixed_versions": ["2.15.0"], "source_tool": "grype",
            },
        },
        {
            "severity": "MEDIUM",
            "sca": {
                "component_name": "other-lib", "component_version": "1.0", "ecosystem": "Maven",
                "vulnerability_id": "CVE-2022-9999", "aliases": [],
                "fixed_versions": ["1.1"], "source_tool": "grype",
            },
        },
    ]
    findings = _auto_merge([("osv-scanner", osv), ("grype", grype)])
    result = SCAPipelineService._apply_enrichment({"findings": findings})

    # 并集 = 2（log4j 的 CVE-2021-44228 + other-lib 的 CVE-2022-9999）
    assert result["union_count"] == 2
    # 交集（双重检测）= 1（只有 log4j 双工具报出）
    assert result["intersection_count"] == 1
    assert result["single_tool_count"] == 1
    assert result["finding_count"] == 2
    # 双重检测里同一 CVE 只出现一次，不重复计数
    double = [f for f in findings if f["sca"]["detection_type"] == "double"]
    assert len(double) == 1
    assert double[0]["sca"]["detected_by"] == ["osv-scanner", "grype"]
    assert double[0]["sca"]["cross_validated"] is True


def test_explode_finding_with_multiple_cves():
    """一个公告打包多个 CVE 必须按 CVE 拆成多条，避免跨工具按 CVE 去重时漏报/吞并。"""
    from src.pipeline.sca.service import explode_findings_by_cve

    f = {
        "sca": {
            "component_name": "lib", "component_version": "1.0", "ecosystem": "Maven",
            "vulnerability_id": "GHSA-bundle", "aliases": ["CVE-2021-1", "CVE-2021-2"],
            "source_tool": "osv-scanner",
        }
    }
    out = explode_findings_by_cve([f])
    assert len(out) == 2
    ids = sorted(o["sca"]["vulnerability_id"] for o in out)
    assert ids == ["CVE-2021-1", "CVE-2021-2"]


