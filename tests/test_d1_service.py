
from pathlib import Path

from src.application.d1_service import D1Service
from src.infrastructure.db import Database


def test_dast_idor_persists_assets_and_detects_cross_subject_access(tmp_path: Path):
    service = D1Service(Database(str(tmp_path / "app.db")))
    app = service.create_app({
        "app_id": "shop",
        "app_name": "Shop",
        "base_url": "http://example.test",
        "role_boundaries": [{"roles": ["admin"], "allow_cross_subject": True}],
        "accounts": [
            {"account_id": "alice", "role": "user", "tenant": "t1", "subject": "alice"},
            {"account_id": "bob", "role": "user", "tenant": "t2", "subject": "bob"},
        ],
    })
    assert app["app_id"] == "shop"
    service.import_apis("shop", {"apis": [{"method": "GET", "path": "/orders/{id}", "params": [{"name": "id"}]}]})
    service.import_traffic("shop", {"samples": [
        {"api_path": "/orders/{id}", "path": "/orders/100", "method": "GET", "role": "user", "tenant": "t1", "subject": "alice", "resource_owner": "alice", "resource_tenant": "t1", "resource_id": "100", "request": {"path": "/orders/100"}, "status_code": 200, "response_body": "order 100 owner alice amount 9"},
        {"api_path": "/orders/{id}", "path": "/orders/100", "method": "GET", "role": "user", "tenant": "t2", "subject": "bob", "resource_owner": "alice", "resource_tenant": "t1", "resource_id": "100", "request": {"path": "/orders/100"}, "status_code": 200, "response_body": "order 100 owner alice amount 9"},
    ]})

    result = service.scan("shop", {"execute_http": False})

    assert result["candidate_count"] >= 1
    assert result["finding_count"] == 1
    finding = result["findings"][0]
    assert finding["source"] == "dast-idor"
    assert finding["idor"]["is_idor"] is True
    assert finding["vulnerability_hash_v2"]
    assert service.results("shop")["finding_count"] == 1
    assert len(service.runs("shop")) == 1
