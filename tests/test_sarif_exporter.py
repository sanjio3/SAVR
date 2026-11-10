"""SARIF 2.1.0 导出单测（Phase 5a）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.benchmark.sarif_exporter import to_sarif, write_sarif, SARIF_VERSION, SARIF_SCHEMA

VULNS = [
    {
        "type": "SQL 注入", "display_family": "sqli", "severity": "HIGH",
        "file": "src\\main\\java\\org\\owasp\\benchmark\\testcode\\BenchmarkTest00008.java",
        "line": 52, "description": "tainted parameter reaches JDBC prepareCall",
        "vulnerability_hash_v2": "50c365bf208d24898745d2ed",
        "verification_state": "confirmed",
        "data_flow": [
            {"file": "src/main/java/A.java", "line": 10},
            {"file": "src/main/java/B.java", "line": 20},
        ],
    },
    {
        "type": "XSS", "severity": "medium",
        "file": "/tmp/X.java", "line": 0,
        "vulnerability_hash_v2": "deadbeefdeadbeefdeadbeef",
        "verification_state": "detected_unverified",
    },
]


def test_to_sarif_structure():
    doc = to_sarif(VULNS, tool_name="savr", tool_version="9.9")
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"] == SARIF_SCHEMA
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "savr"
    assert run["tool"]["driver"]["version"] == "9.9"
    # 两条 result（默认含未确认）
    assert len(run["results"]) == 2
    # 规则按 CWE 去重
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "CWE-89" in rule_ids and "CWE-79" in rule_ids


def test_to_sarif_mapping_and_levels():
    doc = to_sarif(VULNS)
    res = doc["runs"][0]["results"]
    sqli = next(r for r in res if r["ruleId"] == "CWE-89")
    assert sqli["level"] == "error"
    assert sqli["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith(
        "BenchmarkTest00008.java")
    assert sqli["locations"][0]["physicalLocation"]["region"]["startLine"] == 52
    assert sqli["partialFingerprints"]["vulnerabilityHash/v2"] == "50c365bf208d24898745d2ed"
    assert "codeFlows" in sqli
    xss = next(r for r in res if r["ruleId"] == "CWE-79")
    assert xss["level"] == "warning"
    # line=0 归一为 1
    assert xss["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_include_unconfirmed_filter():
    doc = to_sarif(VULNS, include_unconfirmed=False)
    res = doc["runs"][0]["results"]
    assert len(res) == 1
    assert res[0]["ruleId"] == "CWE-89"


def test_write_sarif(tmp_path):
    p = os.path.join(str(tmp_path), "out.sarif")
    write_sarif(p, VULNS)
    with open(p, encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["version"] == SARIF_VERSION
    assert len(doc["runs"][0]["results"]) == 2
