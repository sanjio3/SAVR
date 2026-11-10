from pathlib import Path

from src.application.entry_discovery_service import EntryDiscoveryService
from src.application.d1_service import D1Service


def test_idor_service_detects_cross_subject_success():
    service = D1Service()
    service.create_app({"app_id": "demo", "app_name": "Demo"})
    service.import_apis("demo", {"apis": [{"method": "GET", "path": "/orders/{id}", "params": ["id"]}]})
    service.import_traffic("demo", {"samples": [
        {"api_path": "/orders/{id}", "role": "alice", "resource_owner": "alice", "tenant": "t1", "request": "GET /orders/1", "response_summary": "200 success"},
        {"api_path": "/orders/{id}", "role": "bob", "resource_owner": "alice", "tenant": "t2", "request": "GET /orders/1", "response_summary": "200 success"},
    ]})
    result = service.scan("demo")
    assert result["finding_count"] == 1
    assert result["findings"][0]["idor"]["is_idor"] is True


def test_entry_discovery_finds_java_route(tmp_path: Path):
    source = tmp_path / "DemoController.java"
    source.write_text('@GetMapping("/api/demo")\npublic String demo(){ return "ok"; }', encoding="utf-8")
    result = EntryDiscoveryService().discover(str(tmp_path))
    assert result["entry_count"] == 1
    assert result["entries"][0]["entry_type"] == "web_route"
