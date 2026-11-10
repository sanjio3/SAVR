from src.pipeline.sca.adapters import (
    GrypeAdapter,
    OSVScannerAdapter,
    TrivyAdapter,
    all_tool_statuses,
    get_adapter,
)
from src.pipeline.sca.service import SCAPipelineService


def test_get_adapter_dispatches_by_name_and_defaults_to_osv():
    assert isinstance(get_adapter("trivy"), TrivyAdapter)
    assert isinstance(get_adapter("grype"), GrypeAdapter)
    assert isinstance(get_adapter("unknown-tool"), OSVScannerAdapter)


def test_all_tool_statuses_reports_four_tools():
    tools = {status["tool"] for status in all_tool_statuses()}
    assert tools == {"osv-scanner", "trivy", "grype", "syft"}


def test_trivy_adapter_normalizes_native_payload():
    payload = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "demo",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1, 1.1.0",
                        "Severity": "HIGH",
                        "Title": "demo vuln",
                        "PrimaryURL": "https://example.test/cve",
                    }
                ],
            }
        ]
    }
    findings = TrivyAdapter().normalize(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["sca"]["source_tool"] == "trivy"
    assert finding["sca"]["component_name"] == "demo"
    assert finding["sca"]["fixed_versions"] == ["1.0.1", "1.1.0"]
    assert finding["severity"] == "HIGH"
    assert finding["vulnerability_hash_v2"]


def test_grype_adapter_normalizes_and_filters_by_severity():
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-high",
                    "severity": "High",
                    "fix": {"versions": ["2.0.1"]},
                    "urls": ["https://example.test/ghsa"],
                },
                "artifact": {"name": "left", "version": "2.0.0", "type": "python", "locations": [{"path": "requirements.txt"}]},
            },
            {
                "vulnerability": {"id": "GHSA-low", "severity": "Negligible", "fix": {"versions": []}},
                "artifact": {"name": "right", "version": "1.0.0", "type": "python", "locations": []},
            },
        ]
    }
    findings = GrypeAdapter().normalize(payload, severity_threshold="MEDIUM")
    assert len(findings) == 1
    assert findings[0]["sca"]["component_name"] == "left"
    assert findings[0]["severity"] == "HIGH"


def test_grype_ignore_unfixed_drops_components_without_fix():
    payload = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-nofix", "severity": "High", "fix": {"versions": []}},
                "artifact": {"name": "demo", "version": "1.0.0", "type": "python", "locations": [{"path": "req.txt"}]},
            }
        ]
    }
    assert GrypeAdapter().normalize(payload, ignore_unfixed=True) == []
    assert len(GrypeAdapter().normalize(payload, ignore_unfixed=False)) == 1


def test_pipeline_normalize_osv_backward_compatible():
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


def test_pipeline_auto_skips_when_no_tool_available(monkeypatch):
    monkeypatch.setattr("src.pipeline.sca.adapters.SCAToolAdapter.executable", lambda self: None)
    result = SCAPipelineService(tool="auto").scan("/nonexistent", "/tmp/does-not-matter")
    assert result["status"] == "skipped"
    assert result["finding_count"] == 0
    assert result["tool"] == "auto"
