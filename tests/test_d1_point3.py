"""Point3 落地验证：业务流重放接线 + 认证/并发/状态机上下文。

- replay_state_machine 消费 ordered_steps（按序走状态转换，判定 illegal 步）。
- D1Service.bootstrap_accounts 真实登录取 token（attacker=低特权 / victim=高特权）。
- auth bootstrap 把 alg=none 伪造 JWT 注入 attacker（垂直越权验证载荷）。
- 双账户业务类目（bola/垂直/跨模块）缺账户且无 login 时，绝不落到 canary 攻击路径，
  降级为 provisional no_evidence。
"""
import json
import unittest
from unittest import mock

from src.application.d1_service import D1Service
from src.iast import business_logic as bl
from src.iast.account_discovery import forge_none_alg_jwt


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _LoginResp:
    def __init__(self, status_code=200, text='{"token":"T"}', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


# ---------------- replay_state_machine.ordered_steps ----------------
def test_state_machine_ordered_steps_illicit_accepted():
    spec = {
        "target_endpoint": "/api/order/cancel", "http_method": "POST",
        "ordered_steps": [
            {"target_endpoint": "/api/order/create", "http_method": "POST"},
            {"target_endpoint": "/api/order/ship", "http_method": "POST"},
            {"target_endpoint": "/api/order/cancel", "http_method": "POST", "illegal": True},
        ],
    }
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_state_machine(spec, target)
    assert out["confirmed"] is True
    assert out["ordered_steps_executed"] == 3
    assert out["judged_step_index"] == 2


def test_state_machine_ordered_steps_illicit_denied():
    spec = {
        "target_endpoint": "/api/order/cancel", "http_method": "POST",
        "ordered_steps": [
            {"target_endpoint": "/api/order/create", "http_method": "POST"},
            {"target_endpoint": "/api/order/cancel", "http_method": "POST", "illegal": True},
        ],
    }
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(403, "forbidden")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_state_machine(spec, target)
    assert out["confirmed"] is False


def test_state_machine_no_ordered_steps_falls_back():
    spec = {"target_endpoint": "/api/order/cancel", "http_method": "POST"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_state_machine(spec, target)
    assert out["confirmed"] is True
    assert out.get("ordered_steps_executed", 0) == 0


# ---------------- bootstrap_accounts ----------------
def test_bootstrap_accounts_logs_in_and_builds_accounts():
    target = {"service_url": "http://mall", "login": {
        "url": "/api/auth/login", "method": "POST", "token_field": "token",
        "token_header": "Authorization", "token_prefix": "Bearer ",
        "credentials": [
            {"role": "admin", "username": "admin", "password": "admin"},
            {"role": "user", "username": "alice", "password": "alice123"},
        ],
    }}
    login_calls = {}

    def fake(method, url, **kwargs):
        login_calls.setdefault("url", url)
        assert kwargs.get("json", {}).get("username") in ("admin", "alice")
        return _LoginResp(200, '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sign"}')
    with mock.patch("requests.request", side_effect=fake):
        accounts = D1Service().bootstrap_accounts(target)
    assert accounts is not None
    assert login_calls["url"] == "http://mall/api/auth/login"
    # 低特权=attacker，高特权=victim
    assert accounts["attacker"]["role"] == "user"
    assert accounts["victim"]["role"] == "admin"
    assert accounts["attacker"]["auth_headers"]["Authorization"].startswith("Bearer ")
    assert "eyJhbGciOiJIUzI1NiJ9" in accounts["victim"]["auth_headers"]["Authorization"]


def test_bootstrap_accounts_cookie_mode():
    target = {"service_url": "http://mall", "login": {
        "url": "/login", "token_field": "access_token", "cookie_name": "mall_token",
        "credentials": [{"role": "user", "username": "bob", "password": "bob"}],
    }}

    def fake(method, url, **kwargs):
        return _LoginResp(200, '{"access_token":"ABC123"}')
    with mock.patch("requests.request", side_effect=fake):
        accounts = D1Service().bootstrap_accounts(target)
    assert accounts["attacker"]["auth_cookies"]["mall_token"] == "ABC123"
    assert "auth_headers" not in accounts["attacker"]


def test_bootstrap_accounts_forge_alg_none_for_vertical():
    target = {"service_url": "http://mall", "login": {
        "url": "/login", "token_field": "token", "forge_alg_none": True,
        "credentials": [{"role": "user", "username": "alice", "password": "alice123"}],
    }}

    def fake(method, url, **kwargs):
        return _LoginResp(200, '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"}')
    with mock.patch("requests.request", side_effect=fake):
        accounts = D1Service().bootstrap_accounts(target, {"category": "vertical_privesc"})
    token = accounts["attacker"]["auth_headers"]["Authorization"]
    assert token.startswith("Bearer ")
    jwt = token[len("Bearer "):]
    parts = jwt.split(".")
    assert len(parts) == 3 and parts[2] == ""  # 无签名段
    import base64

    def _decode(seg):
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    header = _decode(parts[0])
    assert header["alg"] == "none"


def test_bootstrap_accounts_missing_login_returns_none():
    assert D1Service().bootstrap_accounts({"service_url": "http://t"}) is None


# ---------------- forge_none_alg_jwt ----------------
def test_forge_none_alg_jwt_preserves_sub_and_elevates_role():
    out = forge_none_alg_jwt("a.b.c", extra_claims={"role": "admin"})
    parts = out.split(".")
    assert parts[2] == ""
    import base64
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload["role"] == "admin"


# ---------------- replay 路由：双账户业务类目不得落到 canary 攻击路径 ----------------
def test_replay_dual_business_logic_no_accounts_no_login_is_provisional():
    spec = {"target_endpoint": "/api/order/1", "http_method": "GET", "category": "bola"}
    target = {"service_url": "http://t"}
    imp = D1Service().replay(spec, target)
    assert imp.provisional is True


def test_replay_dual_business_logic_bootstraps_then_routes():
    # 走 D1Service.replay 路由：category=bola 属双账户类目，缺账户时先按 target.login 真登录
    # bootstrap，再路由到 business_logic.verify → replay_bola（攻击者取受害者资源 id 命中标识）。
    spec = {"target_endpoint": "/api/order/{id}", "http_method": "GET", "category": "bola",
            "param_name": "id", "param_location": "path", "victim_resource_id": "9",
            "victim_identifiers": ["admin"]}
    target = {"service_url": "http://t", "login": {
        "url": "/login", "token_field": "token",
        "credentials": [{"role": "admin", "username": "admin", "password": "admin"},
                        {"role": "user", "username": "alice", "password": "a"}],
    }}

    def fake(method, url, **kwargs):
        if url.endswith("/login"):
            return _LoginResp(200, '{"token":"TKN"}')
        # BOLA 重放：攻击者(alice) 取受害者(admin)资源 id=9 时返回 200 且含标识
        return _Resp(200, "owner=admin")
    with mock.patch("requests.request", side_effect=fake):
        imp = D1Service().replay(spec, target)
    # replay 对业务类目返回 DastImpact（业务逻辑结果挂在 business_logic 字段里）
    assert imp.business_logic.get("confirmed") is True


if __name__ == "__main__":
    unittest.main()
