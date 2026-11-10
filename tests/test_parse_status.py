"""发难清单 Q3 单测：解析失败显式状态化（parsed/unknown/empty），不静默丢弃。

resolve_endpoint_full 产物必须带 parse_status；summarize_parse_status 聚合分布并按
20% 阈值给出解析器盲区告警判定。
"""
from src.iast.trigger_spec_registry import resolve_endpoint_full, summarize_parse_status


def test_parse_status_parsed_when_route_and_param_resolve():
    vuln = {
        "type": "xss",
        "file": "A.java",
        "line": 1,
        "entry_point": "/check",
        "exploit_spec": {
            "entry": {"route": "/check", "param_name": "rule", "param_location": "query"}
        },
    }
    routes = [{
        "route": "/check", "method": "GET",
        "params": [{"param_name": "rule", "param_location": "query"}],
    }]
    out = resolve_endpoint_full(vuln, discovered_routes=routes)
    assert out.get("parse_status") == "parsed"
    assert out.get("resolvable") is True


def test_parse_status_unknown_when_route_missing():
    vuln = {
        "type": "sql注入",
        "file": "NoRoute.java",
        "entry_point": "",
    }
    out = resolve_endpoint_full(vuln)
    assert out.get("parse_status") == "unknown"
    # unknown 必须带具体解析失败原因，不许留 unknown 黑洞
    assert out.get("resolution_failure")


def test_parse_status_empty_when_no_parseable_input():
    out = resolve_endpoint_full({"type": "sca"})
    assert out.get("parse_status") == "empty"


def test_summarize_parse_status_counts_and_alert():
    rows = [{"parse_status": "parsed"}] * 7 + [{"parse_status": "unknown"}] * 3
    s = summarize_parse_status(rows)
    assert s["parsed"] == 7 and s["unknown"] == 3 and s["empty"] == 0
    assert s["total"] == 10
    assert s["unknown_ratio"] == 0.3
    assert s["unknown_alert"] is True
    # 低占比不告警
    s2 = summarize_parse_status([{"parse_status": "parsed"}] * 99 + [{"parse_status": "unknown"}])
    assert s2["unknown_alert"] is False
    # 空输入不告警、不除零
    s3 = summarize_parse_status([])
    assert s3["unknown_alert"] is False and s3["total"] == 0
