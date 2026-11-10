"""BOLA / RACE 落地验证（重构文档 §2.2 / §7.9）。

覆盖：SAST 策略分析器（业务逻辑 BOLA 命中 / 归属校验存在时不命中）+ D1 多身份重放(BOLA)
+ D1 并发重放(RACE)，均用 mock HTTP 替代真实目标。
"""
import json
import unittest
from unittest import mock

from src.agents.a1_bola_analyzer import analyze_file, analyze_sources
from src.application.d1_service import D1Service


JAVA_BOLA = """
public class OrderController {
    public Order getOrder(@PathVariable String orderId) {
        return orderRepository.findById(orderId);
    }
}
"""

JAVA_SAFE = """
public class OrderController {
    public Order getOrder(@PathVariable String orderId, @AuthenticationPrincipal User currentUser) {
        Order order = orderRepository.findById(orderId);
        if (!order.getOwnerId().equals(currentUser.getId())) {
            throw new AccessDeniedException("no");
        }
        return order;
    }
}
"""

PY_BOLA = """
def get_document(doc_id):
    return Document.objects.get(id=doc_id)
"""

PY_SAFE = """
def get_document(doc_id, user):
    doc = Document.objects.get(id=doc_id)
    if doc.owner_id != user.id:
        raise PermissionError
    return doc
"""


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def test_analyzer_detects_java_bola():
    hypos = analyze_file("OrderController.java", JAVA_BOLA, "java")
    assert len(hypos) == 1
    h = hypos[0]
    assert h["vuln_type"] == "BOLA"
    assert h["family"] == "IDOR"
    assert "orderId" in h["param"]
    assert "findById" in h["data_access_sink"]


def test_analyzer_skips_java_with_ownership_check():
    hypos = analyze_file("OrderController.java", JAVA_SAFE, "java")
    assert hypos == []


def test_analyzer_detects_python_bola():
    hypos = analyze_file("views.py", PY_BOLA, "py")
    assert len(hypos) == 1
    assert hypos[0]["vuln_type"] == "BOLA"


def test_analyzer_skips_python_with_ownership_check():
    hypos = analyze_file("views.py", PY_SAFE, "py")
    assert hypos == []


def test_analyze_sources_batch():
    files = [
        {"path": "a.java", "content": JAVA_BOLA, "language": "java"},
        {"path": "b.py", "content": PY_SAFE, "language": "py"},
    ]
    hypos = analyze_sources(files)
    assert len(hypos) == 1  # 仅 java 命中


def test_d1_replay_bola_confirmed():
    spec = {
        "target_endpoint": "/api/order/{id}", "http_method": "GET",
        "param_name": "id", "param_location": "path",
        "victim_resource_id": "999", "victim_identifiers": ["victim@corp.com"],
    }
    target = {"service_url": "http://target"}
    accounts = {"attacker": {"auth_headers": {"Authorization": "Bearer attacker"}}}

    def fake_request(method, url, **kwargs):
        assert "api/order/999" in url
        return _Resp(200, '{"owner":"victim@corp.com","data":"secret"}')

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_bola(spec, target, accounts=accounts)
    assert out["confirmed"] is True
    assert "victim@corp.com" in out["leaked_victim_identifiers"]
    assert out["verdict"] == "confirmed"


def test_d1_replay_bola_no_leak():
    spec = {
        "target_endpoint": "/api/order/{id}", "http_method": "GET",
        "param_name": "id", "param_location": "path",
        "victim_resource_id": "999", "victim_identifiers": ["victim@corp.com"],
    }
    target = {"service_url": "http://target"}

    def fake_request(method, url, **kwargs):
        return _Resp(200, '{"error":"not found"}')

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_bola(spec, target, accounts={"attacker": {}})
    assert out["confirmed"] is False
    assert out["leaked_victim_identifiers"] == []


def test_d1_replay_race_single_use_suspected():
    spec = {
        "target_endpoint": "/api/redeem", "http_method": "POST",
        "race_single_use": True,
    }
    target = {"service_url": "http://target"}

    def fake_request(method, url, **kwargs):
        return _Resp(200, "ok")

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_race(spec, target, concurrency=5)
    assert out["concurrency"] == 5
    assert out["success_count"] == 5
    assert out["race_suspected"] is True


def test_d1_replay_race_not_single_use():
    spec = {"target_endpoint": "/api/ping", "http_method": "GET", "race_single_use": False}
    target = {"service_url": "http://target"}

    def fake_request(method, url, **kwargs):
        return _Resp(200, "ok")

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_race(spec, target, concurrency=3)
    assert out["success_count"] == 3
    assert out["race_suspected"] is False


def test_d1_replay_race_single_use_confirmed():
    """设计二②：single_use 且并发多成功 → confirmed / business_confirmed=True 且带副作用证据。"""
    spec = {
        "target_endpoint": "/coupon/claim", "http_method": "POST",
        "race_single_use": True,
    }
    target = {"service_url": "http://target"}

    def fake_request(method, url, **kwargs):
        return _Resp(200, "claimed")

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_race(spec, target, concurrency=5)
    assert out["success_count"] == 5
    assert out["race_suspected"] is True
    assert out["confirmed"] is True
    assert out["business_confirmed"] is True
    assert out["confirmation_source"] == "concurrency-double-success"
    assert isinstance(out["observed_side_effect"], dict)


def test_d1_replay_race_state_delta_side_effect():
    """设计二②：before/after 状态差分命中 → side-effect 确认（即便非 single_use）。"""
    class _JsonResp:
        def __init__(self, status_code=200, payload=None, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text if text else (json.dumps(payload) if payload is not None else "")
        def json(self):
            return self._payload

    spec = {
        "target_endpoint": "/order/checkout", "http_method": "POST",
        "state_query": {"endpoint": "/wallet/balance", "json_paths": ["balance", "orders"]},
    }
    target = {"service_url": "http://target"}
    attacker = {"auth_headers": {"Authorization": "Bearer x"}}

    def fake_request(method, url, **kwargs):
        # GET /wallet/balance 返回随调用次数变化的余额/订单（差分命中）
        if url.endswith("/wallet/balance"):
            fake_request.n += 1
            return _JsonResp(200, {"balance": 100 - fake_request.n, "orders": fake_request.n})
        return _JsonResp(200, {"ok": True})
    fake_request.n = 0

    with mock.patch("requests.request", side_effect=fake_request):
        out = D1Service().replay_race(spec, target, concurrency=2, accounts={"attacker": attacker})
    assert out["observed_side_effect"] is not None
    assert out["observed_side_effect"].get("changed") is True
    assert out["business_confirmed"] is True


if __name__ == "__main__":
    unittest.main()
