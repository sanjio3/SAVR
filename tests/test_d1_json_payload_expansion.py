"""D1 重放：JSON 对象型 payload 展开 回归测试（R25#30/#31/#25）。

背景：A2 有时把「整组请求参数」写成一个 JSON 对象字符串作为 payload
（如 {"id":1,"amount":0.01}、{"role":"admin","isVip":true}）。D1 原样把它塞进单个参数位，
于是 amount / code / role / address 等关键参数根本没被发出去 —— 金额篡改、批量赋值、
状态机一类业务判据永远不成立，最终表现为 unconfirmed / no-iast-evidence
（run 14 中 #30 支付金额篡改、#31 优惠券叠加、#25 批量赋值提权即此类）。

锁死四件事：
1. 对象里 rep_params 未覆盖的键会被补发，关键业务参数真正上线；
2. rep_params 已覆盖的键不被覆盖（canary 语义不变）；
3. 非 JSON 对象的普通 payload 行为完全不变（不误伤注入类）；
4. 无真 payload（attack_degraded）时不展开。
"""
import json

import pytest

from src.application.d1_service import D1Service


class _Resp:
    status_code = 200
    text = "ok"
    # 2026-09-28（测试桩对齐）：补 headers，与真实 requests.Response 对齐。
    headers = {}


class FakeDB:
    def __init__(self, target_path="D:/proj/app"):
        self.target_path = target_path

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        if "workspaces" in sql:
            row = {"target_path": self.target_path}
            return row if fetchone else [row]
        return None


@pytest.fixture
def captured(monkeypatch):
    box = {}

    def fake_request(method, url, **kw):
        box.update(method=method, url=url, params=kw.get("params"),
                   json_body=kw.get("json"), data=kw.get("data"),
                   headers=kw.get("headers"))
        return _Resp()

    monkeypatch.setattr("src.application.d1_service.requests.request", fake_request)
    return box


def _spec(**over):
    spec = {
        "http_method": "GET",
        "target_endpoint": "order/{id}",
        "param_name": "id",
        "param_location": "path",
        "taint_marker": "CANARY_ABC",
        "family": "payment-amount-tampering",
        "content_type": "",
        "attack_payloads_json": json.dumps(['{"id": 1, "amount": 0.01}']),
        "representative_request_params": [
            {"param_name": "id", "param_location": "path", "taint_marker": "CANARY_ABC"}
        ],
    }
    spec.update(over)
    return spec


TARGET = {"service_url": "http://127.0.0.1:8092"}


def _is_canary(v) -> bool:
    """canary 形态随 family 而异：有的就是 taint_marker 本体，有的是派生的 s4st41… 形态。"""
    return isinstance(v, str) and (v == "CANARY_ABC" or v.startswith("s4st41"))


def _strip_name_injection(params):
    """剔除 P-B 名注入引入的键（`<taint_marker>` / `<taint_marker>Z`）。

    P-B（2026-10-15）会额外把 canary 当参数/头**名**投放，覆盖「读参数名」的 servlet
    （00587/01426 等）。对读「值」的本测试用例，这两个键是**无害的额外参数**（servlet 按
    固定名取参时会忽略它们），故断言请求形态时先把它们剔掉，只锁 payload 展开语义本身。
    """
    if not params:
        return params
    return {k: v for k, v in params.items() if k not in ("CANARY_ABC", "CANARY_ABCZ")}


def test_object_payload_keys_are_actually_sent(captured):
    """核心：payload 对象里的 amount 必须真的出现在请求里（此前整串塞进 path，从未发出）。"""
    D1Service(db=FakeDB())._replay_attack(_spec(), TARGET)
    assert _strip_name_injection(captured["params"]) == {"amount": "0.01"}


def test_path_param_takes_real_id_not_whole_json(captured):
    """path 场景：{id} 取 payload 对象里的真实 id，而不是把 JSON 整串拼进 URL（此前必然 404）。"""
    D1Service(db=FakeDB())._replay_attack(_spec(), TARGET)
    assert "{" not in captured["url"]
    assert '"' not in captured["url"]
    assert captured["url"].endswith("/order/1")
    # canary 仍在请求头（通道A），IAST 关联不受影响
    assert captured["headers"]["X-SASTAI-Trace"] == "CANARY_ABC"


def test_post_object_payload_expands_into_body(captured):
    """POST 场景：批量赋值提权的 role / isVip 必须进 body（#25）。"""
    D1Service(db=FakeDB())._replay_attack(
        _spec(
            http_method="POST",
            target_endpoint="login",
            param_name="username",
            param_location="body",
            family="mass-assignment",
            attack_payloads_json=json.dumps(['{"id":1,"role":"admin","isVip":true,"balance":999999}']),
            representative_request_params=[
                {"param_name": "username", "param_location": "body", "taint_marker": "CANARY_ABC"}
            ],
        ),
        TARGET,
    )
    body = captured["json_body"]
    assert body["role"] == "admin"
    assert body["isVip"] == "true"        # 布尔按字面串发出，服务端类型绑定自行处理
    assert body["balance"] == "999999"
    # username 由 rep_params 注入 canary，未被 payload 覆盖
    assert _is_canary(body["username"])


def test_plain_payload_unchanged(captured):
    """非 JSON 对象的普通 payload 行为完全不变（注入类不误伤）。"""
    D1Service(db=FakeDB())._replay_attack(
        _spec(
            target_endpoint="products",
            param_name="keyword",
            param_location="query",
            family="sql-injection",
            attack_payloads_json=json.dumps(["' OR 1=1 -- "]),
            representative_request_params=[
                {"param_name": "keyword", "param_location": "query", "taint_marker": "CANARY_ABC"}
            ],
        ),
        TARGET,
    )
    # 非对象 payload 不展开：请求里除名注入的两个无害键外，只有 keyword 一个参数
    assert set(_strip_name_injection(captured["params"]).keys()) == {"keyword"}
    assert _is_canary(captured["params"]["keyword"])


def test_degraded_no_payload_means_no_expansion(captured):
    """无真 payload（纯 canary 探针）时不展开。"""
    D1Service(db=FakeDB())._replay_attack(
        _spec(attack_payloads_json=json.dumps([])), TARGET
    )
    assert not _strip_name_injection(captured["params"])
    assert captured["headers"]["X-SASTAI-Trace"] == "CANARY_ABC"


def test_rep_covered_key_not_overwritten(captured):
    """payload 里与 rep_params 同名的键不注入（避免把 canary 冲掉）。"""
    D1Service(db=FakeDB())._replay_attack(
        _spec(
            target_endpoint="address",
            param_name="id",
            param_location="query",
            attack_payloads_json=json.dumps(['{"id": "1", "address": "attacker_address"}']),
            representative_request_params=[
                {"param_name": "id", "param_location": "query", "taint_marker": "CANARY_ABC"}
            ],
        ),
        TARGET,
    )
    assert _is_canary(captured["params"]["id"])
    assert captured["params"]["address"] == "attacker_address"
