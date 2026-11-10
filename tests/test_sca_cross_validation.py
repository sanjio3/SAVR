"""SCA 跨工具交叉验证（§用户需求 Q1）：组件名归一化后，OSV(Maven groupId:artifactId) 与
Grype(java-archive 裸 artifactId) 对同一组件的交叉比对应当触发 cross_validated=True。

复现历史 bug：未归一时 OSV 报 ``com.fasterxml.jackson.core:jackson-databind``、
Grype 报 ``jackson-databind``，分组键不一致 → 永远不交叉比对 → cross_validated 恒为 0。
"""
import sys
from pathlib import Path

import pytest

# 让测试能 import src.*
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pipeline.sca.adapters import (  # noqa: E402
    _norm_comp_name,
    reconcile_cross_validation,
)


def _osv_finding(component_name, vuln_id, aliases=None, version="2.9.8"):
    return {
        "type": "SCA",
        "sca": {
            "source_tool": "osv-scanner",
            "component_name": component_name,          # Maven: groupId:artifactId
            "component_version": version,
            "ecosystem": "Maven",
            "vulnerability_id": vuln_id,
            "aliases": aliases or [],
            "fixed_versions": [],
            "detected_by": ["osv-scanner"],
        },
    }


def _grype_finding(component_name, vuln_id, aliases=None, version="2.9.8"):
    return {
        "type": "SCA",
        "sca": {
            "source_tool": "grype",
            "component_name": component_name,          # java-archive: 裸 artifactId
            "component_version": version,
            "ecosystem": "java-archive",
            "vulnerability_id": vuln_id,
            "aliases": aliases or [],
            "fixed_versions": [],
            "detected_by": ["grype"],
        },
    }


def test_norm_comp_name_maven_strips_groupid():
    assert _norm_comp_name("com.fasterxml.jackson.core:jackson-databind", "Maven") == "jackson-databind"
    # 裸 artifactId（Grype java-archive）原样归一
    assert _norm_comp_name("jackson-databind", "java-archive") == "jackson-databind"
    # 非 maven 生态不处理
    assert _norm_comp_name("lodash", "npm") == "lodash"
    assert _norm_comp_name("", "Maven") == ""


def test_cross_validation_fires_after_normalization():
    findings = [
        _osv_finding("com.fasterxml.jackson.core:jackson-databind", "GHSA-abcd-1234",
                     aliases=["CVE-2020-11111"]),
        _grype_finding("jackson-databind", "CVE-2020-11111"),
    ]
    out = reconcile_cross_validation(findings)
    a, b = out[0]["sca"], out[1]["sca"]
    assert a["cross_validated"] is True
    assert b["cross_validated"] is True
    assert a["confidence"] == "high"
    assert "grype" in a["detected_by"] and "osv-scanner" in a["detected_by"]


def test_cross_validation_no_false_positive_on_different_component():
    findings = [
        _osv_finding("com.fasterxml.jackson.core:jackson-databind", "GHSA-aaa",
                     aliases=["CVE-2020-11111"]),
        _grype_finding("logback-classic", "CVE-2020-99999"),
    ]
    out = reconcile_cross_validation(findings)
    assert out[0]["sca"]["cross_validated"] is False
    assert out[1]["sca"]["cross_validated"] is False


def test_single_tool_never_cross_validated():
    findings = [
        _osv_finding("com.fasterxml.jackson.core:jackson-databind", "GHSA-aaa"),
        _osv_finding("com.fasterxml.jackson.core:jackson-databind", "GHSA-bbb"),
    ]
    out = reconcile_cross_validation(findings)
    assert all(f["sca"]["cross_validated"] is False for f in out)
