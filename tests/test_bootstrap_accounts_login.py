"""回归测试 bootstrap_accounts 必须支持表单登录 + Set-Cookie token 提取 + alg:none 伪造。

此前 bootstrap_accounts 只发 JSON body、只从 body/header 取 token，与 target-mall
（@RequestParam 表单登录、token 落在 Set-Cookie: mall_token）不兼容，导致双账户
bootstrap 失败、BOLA/垂直越权差分重放静默降级 no_evidence。本测试用 mock 锁定修复行为，
不依赖外部网络。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

from src.application.d1_service import D1Service, _extract_set_cookie_value


class _FakeResp:
    def __init__(self, cookie_val=None, set_cookie_header=None, body_token=None, text=""):
        self.cookies = {"mall_token": cookie_val} if cookie_val else {}
        hdrs = {}
        if set_cookie_header:
            hdrs["Set-Cookie"] = set_cookie_header
        self.headers = hdrs
        self.text = text
        self._body_token = body_token

    def json(self):
        if self._body_token:
            return {"token": self._body_token}
        return {}


def test_extract_set_cookie_value():
    h = "mall_token=abc123; Path=/; HttpOnly, lang=zh"
    assert _extract_set_cookie_value(h, "mall_token") == "abc123"
    assert _extract_set_cookie_value(h, "lang") == "zh"
    assert _extract_set_cookie_value(h, "missing") == ""
    assert _extract_set_cookie_value("", "mall_token") == ""


def test_bootstrap_form_with_cookie_and_forge():
    svc = D1Service()
    login = {
        "url": "http://x/login", "method": "POST", "content_type": "form",
        "cookie_name": "mall_token", "forge_alg_none": True,
        "credentials": [
            {"role": "ADMIN", "username": "admin", "password": "p"},
            {"role": "USER", "username": "alice", "password": "q"},
        ],
    }
    target = {"service_url": "http://x"}

    with mock.patch("src.application.d1_service.requests.request") as m_req, \
         mock.patch("src.iast.account_discovery.forge_none_alg_jwt",
                    side_effect=lambda t, **k: t + ".FORGED") as m_forge:
        # 验证：发送的是表单（data=）而非 JSON，且 token 来自 Set-Cookie
        m_req.return_value = _FakeResp(cookie_val="RAW.TOKEN")
        # forge 仅对 vertical_privesc / signature 类目生效（P0-3 守卫，避免污染 BOLA/race 差分），
        # 故传入 category=vertical_privesc 让登录取得的 JWT 被改写成 alg=none 无签名令牌。
        out = svc.bootstrap_accounts(target, {"login": login, "category": "vertical_privesc"})

    assert out, "bootstrap 应返回双账户"
    # 表单提交：requests.request 必须以 data= 发送而非 json=
    (_method, _url), kwargs = m_req.call_args
    assert kwargs.get("data") == {"username": "alice", "password": "q"}, "未以表单 data= 提交登录"
    assert kwargs.get("json") is None, "不应再以 JSON body 提交"
    # attacker 取低特权账户 alice，victim 取 admin
    assert out["attacker"]["username"] == "alice"
    assert out["victim"]["username"] == "admin"
    # token 来自 cookie，且经过 alg:none 伪造
    assert out["attacker"]["auth_cookies"]["mall_token"] == "RAW.TOKEN.FORGED"
    assert out["victim"]["auth_cookies"]["mall_token"] == "RAW.TOKEN.FORGED"
    assert m_forge.called, "应调用 forge_none_alg_jwt 做垂直越权伪造"


def test_bootstrap_cookie_fallback_to_header_parse():
    svc = D1Service()
    login = {
        "url": "http://x/login", "method": "POST", "content_type": "form",
        "cookie_name": "mall_token", "credentials": [
            {"role": "USER", "username": "alice", "password": "q"},
        ],
    }
    target = {"service_url": "http://x"}
    # requests cookies 未捕获（空），但 Set-Cookie 头里带了 mall_token
    resp = _FakeResp(set_cookie_header="mall_token=HEADER.VAL; Path=/")
    with mock.patch("src.application.d1_service.requests.request", return_value=resp):
        out = svc.bootstrap_accounts(target, {"login": login})
    assert out["attacker"]["auth_cookies"]["mall_token"] == "HEADER.VAL"


def test_bootstrap_json_body_token_still_works():
    svc = D1Service()
    login = {
        "url": "http://x/login", "method": "POST", "content_type": "json",
        "token_field": "token", "credentials": [
            {"role": "USER", "username": "alice", "password": "q"},
        ],
    }
    target = {"service_url": "http://x"}
    with mock.patch("src.application.d1_service.requests.request",
                    return_value=_FakeResp(body_token="BODY.TOKEN", text='{"token":"BODY.TOKEN"}')):
        out = svc.bootstrap_accounts(target, {"login": login})
    assert out["attacker"]["auth_headers"]["Authorization"] == "Bearer BODY.TOKEN"
