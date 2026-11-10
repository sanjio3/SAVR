"""D1 per-request 认证守卫回归锁（jsc 628 根因）。

事故：628 跑批 67.5min > Tomcat 30min 会话过期，`_tech_session_cache` 一轮只登录一次
且无失效检测，导致 /sqli/jdbc/vuln 的 60 次登录墙 302（其中 45 次是 oracle 探测臂），
SLEEP 弹全被拦在 controller 之前，时间盲注判据天然不成立。

本测试全程离线：不发真实 HTTP、不连靶场、不调 LLM。
"""
import os
import types

import pytest

from src.application import d1_service as d1
from src.application.d1_service import D1Service, _attempt_action


def _svc():
    svc = D1Service.__new__(D1Service)
    svc.db = None
    svc._auth_guard_ctx = {
        "target": {"login": {"username": "u", "password": "p"},
                   "service_url": "http://127.0.0.1:8080"},
        "spec": {},
        "cache_key": ("http://127.0.0.1:8080", ""),
        "relogin_count": 0,
    }
    svc._tech_session_cache = {}
    return svc


def _resp(status=200, location=""):
    headers = {"Location": location} if location else {}
    return types.SimpleNamespace(status_code=status, headers=headers, text="body")


# ── 登录墙判据：必须严，不能把业务跳 / 取证用重定向误判 ──────────────────

@pytest.mark.parametrize("status,location,expected", [
    (302, "http://127.0.0.1:8080/login", True),
    (302, "/login", True),
    (301, "/login?next=/x", True),
    (401, "", True),
    (302, "/file/status", False),           # 628 实测 29 次业务跳
    (302, "http://evil.example/a", False),  # url_redirect 族靠 302 取证
    (403, "", False),                        # 权限问题重登无益
    (200, "/login", False),
    (302, "", False),
])
def test_login_wall_detection(status, location, expected):
    assert d1._is_login_wall_response(status, {"Location": location}) is expected


def test_login_wall_paths_configurable(monkeypatch):
    monkeypatch.setenv("SAST_AI_LOGIN_PATHS", "/signin, /auth/login")
    assert d1._is_login_wall_response(302, {"Location": "/signin"}) is True
    assert d1._is_login_wall_response(302, {"Location": "/auth/login?x=1"}) is True
    assert d1._is_login_wall_response(302, {"Location": "/login"}) is False
    # /login2 不能被 /login 前缀误伤
    monkeypatch.setenv("SAST_AI_LOGIN_PATHS", "/login")
    assert d1._is_login_wall_response(302, {"Location": "/login2"}) is False


# ── 重登：就地刷新 cookies 与 oracle 基线，并失效会话缓存 ────────────────

def test_relogin_refreshs_cookies_and_baseline_in_place(monkeypatch):
    svc = _svc()
    svc._tech_session_cache[("http://127.0.0.1:8080", "")] = {
        "auth_cookies": {"JSESSIONID": "OLD"}}
    calls = {}

    def fake_fallback(target, force=False):
        calls["force"] = force
        return {"JSESSIONID": "NEW"}

    monkeypatch.setattr(d1, "_fallback_auth_cookies", fake_fallback)
    cookies, baseline = {"JSESSIONID": "OLD"}, {"JSESSIONID": "OLD"}
    assert svc._auth_guard_relogin(cookies, baseline) is True
    assert calls["force"] is True
    assert cookies == {"JSESSIONID": "NEW"}
    # oracle 循环 finally 会用 c0 恢复，基线不同步刷新就会把旧会话盖回去
    assert baseline == {"JSESSIONID": "NEW"}
    assert svc._tech_session_cache[("http://127.0.0.1:8080", "")]["auth_cookies"] == \
        {"JSESSIONID": "NEW"}
    assert svc._auth_guard_ctx["relogin_count"] == 1


def test_relogin_skipped_without_login_config(monkeypatch):
    svc = _svc()
    svc._auth_guard_ctx["target"] = {"service_url": "http://x"}
    monkeypatch.setattr(d1, "_fallback_auth_cookies", lambda *a, **k: {"JSESSIONID": "X"})
    assert svc._auth_guard_relogin({}) is False


def test_relogin_capped_per_spec(monkeypatch):
    svc = _svc()
    svc._auth_guard_ctx["relogin_count"] = d1._AUTH_GUARD_MAX_RELOGIN
    monkeypatch.setattr(d1, "_fallback_auth_cookies", lambda *a, **k: {"JSESSIONID": "X"})
    assert svc._auth_guard_relogin({}) is False


def test_relogin_failed_keeps_cookies(monkeypatch):
    svc = _svc()
    monkeypatch.setattr(d1, "_fallback_auth_cookies", lambda *a, **k: {})
    cookies = {"JSESSIONID": "OLD"}
    assert svc._auth_guard_relogin(cookies) is False
    assert cookies == {"JSESSIONID": "OLD"}


def test_guard_can_be_disabled(monkeypatch):
    svc = _svc()
    monkeypatch.setenv("SAST_AI_D1_AUTH_GUARD", "0")
    assert svc._auth_guard_enabled() is False
    monkeypatch.delenv("SAST_AI_D1_AUTH_GUARD")
    assert svc._auth_guard_enabled() is True


# ── _guarded_request：只重发一次、携带新会话、状态可观测 ──────────────────

def test_guarded_request_passes_through_clean_response(monkeypatch):
    svc = _svc()
    seen = []

    def fake_request(**kw):
        seen.append(dict(kw.get("cookies") or {}))
        return _resp(200)

    monkeypatch.setattr(d1.requests, "request", fake_request)
    resp, state = svc._guarded_request(method="GET", url="http://x/a",
                                       cookies={"JSESSIONID": "A"})
    assert resp.status_code == 200
    assert state == "authenticated"
    assert len(seen) == 1


def test_guarded_request_relogins_and_resends_with_new_cookie(monkeypatch):
    svc = _svc()
    seen = []

    def fake_request(**kw):
        seen.append(dict(kw.get("cookies") or {}))
        return _resp(302, "http://127.0.0.1:8080/login") if len(seen) == 1 else _resp(200)

    monkeypatch.setattr(d1.requests, "request", fake_request)
    monkeypatch.setattr(d1, "_fallback_auth_cookies",
                        lambda *a, **k: {"JSESSIONID": "NEW"})
    cookies = {"JSESSIONID": "OLD"}
    resp, state = svc._guarded_request(method="GET", url="http://x/a", cookies=cookies,
                                       baseline_cookies={"JSESSIONID": "OLD"})
    assert state == "reauthed"
    assert resp.status_code == 200
    assert seen == [{"JSESSIONID": "OLD"}, {"JSESSIONID": "NEW"}]
    assert cookies == {"JSESSIONID": "NEW"}


def test_guarded_request_does_not_touch_business_redirect(monkeypatch):
    svc = _svc()
    seen = []

    def fake_request(**kw):
        seen.append(1)
        return _resp(302, "/file/status")

    monkeypatch.setattr(d1.requests, "request", fake_request)
    resp, state = svc._guarded_request(method="POST", url="http://x/upload",
                                       cookies={"JSESSIONID": "A"})
    assert state == "authenticated"
    assert len(seen) == 1  # 业务跳不能触发重登


def test_guarded_request_reauth_failed_when_no_new_session(monkeypatch):
    svc = _svc()
    seen = []

    def fake_request(**kw):
        seen.append(1)
        return _resp(302, "/login")

    monkeypatch.setattr(d1.requests, "request", fake_request)
    monkeypatch.setattr(d1, "_fallback_auth_cookies", lambda *a, **k: {})
    resp, state = svc._guarded_request(method="GET", url="http://x/a", cookies={})
    assert state == "reauth_failed"
    assert len(seen) == 1


def test_guarded_request_elapsed_excludes_relogin_time(monkeypatch):
    """重登耗时不能算进 oracle delay 臂，否则伪造 time_delay 假阳性。"""
    svc = _svc()
    clock = [0.0]
    calls = []

    def fake_time():
        return clock[0]

    def fake_request(**kw):
        # 第一次请求 5ms；重登耗 3s；第二次请求 7ms
        calls.append(1)
        clock[0] += 0.005 if len(calls) == 1 else 0.007
        return _resp(302, "/login") if len(calls) == 1 else _resp(200)

    def slow_relogin(*a, **k):
        clock[0] += 3.0
        return {"JSESSIONID": "NEW"}

    # 只替换 d1 模块内的 time 名字，不动全局 time 模块（避免影响 pytest 自身计时）
    monkeypatch.setattr(d1, "time", types.SimpleNamespace(time=fake_time))
    monkeypatch.setattr(d1.requests, "request", fake_request)
    monkeypatch.setattr(d1, "_fallback_auth_cookies", slow_relogin)
    _, state = svc._guarded_request(method="GET", url="http://x/a", cookies={})
    assert state == "reauthed"
    assert 0 < svc._guarded_request_ms < 100  # 7ms，不是 3007ms


# ── auth_state 落库载荷 ───────────────────────────────────────────────────

def test_attempt_action_keeps_source_and_adds_auth_state():
    assert _attempt_action("") == {"source": "d1_replay"}
    assert _attempt_action("reauthed") == {
        "source": "d1_replay", "auth_state": "reauthed"}


def test_guarded_request_with_none_cookies_carries_fresh_session(monkeypatch):
    """cookies=None 时也必须能自愈：kw 要持有可就地刷新的 dict。"""
    svc = _svc()
    seen = []

    def fake_request(**kw):
        seen.append(dict(kw.get("cookies") or {}))
        return _resp(302, "/login") if len(seen) == 1 else _resp(200)

    monkeypatch.setattr(d1.requests, "request", fake_request)
    monkeypatch.setattr(d1, "_fallback_auth_cookies",
                        lambda *a, **k: {"JSESSIONID": "NEW"})
    resp, state = svc._guarded_request(method="GET", url="http://x/a", cookies=None)
    assert state == "reauthed"
    assert resp.status_code == 200
    assert seen == [{}, {"JSESSIONID": "NEW"}]


# ── auth_state 必须落到 raw_dast_impact，不能只是内存里的动态属性 ────────────

def test_dast_impact_auth_state_survives_to_dict():
    from src.iast.orchestrator import DastImpact
    assert DastImpact(reached=True, auth_state="reauthed").to_dict()["auth_state"] == "reauthed"
    assert DastImpact().to_dict()["auth_state"] == ""


def test_aggregate_dast_prefers_reauth_failed():
    from src.iast.orchestrator import DastImpact, TriggerTransactionOrchestrator
    orc = TriggerTransactionOrchestrator.__new__(TriggerTransactionOrchestrator)
    merged = orc._aggregate_dast([
        DastImpact(reached=True, auth_state="reauthed"),
        DastImpact(reached=True, auth_state="reauth_failed"),
    ])
    assert merged.auth_state == "reauth_failed"
    assert orc._aggregate_dast([DastImpact(auth_state="authenticated")]).auth_state \
        == "authenticated"


# ── 主重放 _replay_attack 必须真的走守卫（628 缺口）────────────────────────

import json as _json  # noqa: E402


class _FakeDB:
    target_path = "D:/proj/app"

    def __init__(self):
        self.rows = []

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        self.rows.append((sql, params))
        if "workspaces" in sql:
            row = {"target_path": self.target_path}
            return row if fetchone else [row]
        return None

    @staticmethod
    def dumps(obj):
        return _json.dumps(obj)


def _main_spec():
    return {
        "task_id": 628,
        "workspace_id": 4,
        "id": 1,
        "http_method": "GET",
        "target_endpoint": "order/{id}",
        "param_name": "id",
        "param_location": "path",
        "taint_marker": "CANARY_ABC",
        "family": "payment-amount-tampering",
        "content_type": "",
        "attack_payloads_json": _json.dumps(["1"]),
        "representative_request_params": [
            {"param_name": "id", "param_location": "path", "taint_marker": "CANARY_ABC"}
        ],
    }


def test_main_replay_uses_guard_state_and_true_http_elapsed(monkeypatch):
    """_replay_attack 主重放：auth_state 落 impact + attempts，elapsed 不含重登耗时。

    628 的主重放原本在 _replay_attack 内联裸发 requests.request，守卫只接了
    _send_one 与 oracle 臂；这条测试锁死主链路不再回退。
    """
    svc = D1Service.__new__(D1Service)
    svc.db = _FakeDB()
    svc._tech_session_cache = {}
    svc._auth_guard_ctx = {
        "target": {"service_url": "http://127.0.0.1:8092",
                   "login": {"username": "u", "password": "p"}},
        "spec": {}, "cache_key": ("http://127.0.0.1:8092", ""),
        "relogin_count": 0,
    }
    guarded = []

    def fake_guarded(**kw):
        guarded.append(kw)
        svc._guarded_request_ms = 7.0
        return _resp(200), "reauthed"

    monkeypatch.setattr(svc, "_guarded_request", fake_guarded)
    monkeypatch.setattr(d1.requests, "request", lambda **kw: _resp(200))
    monkeypatch.setattr(d1, "_fallback_auth_cookies",
                        lambda *a, **k: {"JSESSIONID": "OLD"})

    impact = svc._replay_attack(_main_spec(), svc._auth_guard_ctx["target"])
    assert guarded, "主重放必须走 _guarded_request"
    assert impact.auth_state == "reauthed"
    assert impact.to_dict()["auth_state"] == "reauthed"
    assert 0 < impact.elapsed_ms < 100, "elapsed_ms 必须是真实 HTTP 往返，不能含重登"
    # 主重放 attempts 的 action_json 也要带 auth_state，泛化验证靠它剔除登录墙干扰
    actions = []
    for sql, params in svc.db.rows:
        if not params or "INSERT INTO replay_attempts" not in sql:
            continue
        for cell in params:
            if not (isinstance(cell, str) and cell.startswith("{")):
                continue
            try:
                obj = _json.loads(cell)
            except ValueError:
                continue
            if isinstance(obj, dict):
                actions.append(obj)
    assert any(a.get("auth_state") == "reauthed" for a in actions), actions


# ── 629 收尾：注销端点豁免 + bypass_variant 旁路接入守卫 ────────────────

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/logout",
    "http://127.0.0.1:8080/logout?next=/",
    "http://127.0.0.1:8080/api/logout",
    "http://127.0.0.1:8080/j_spring_security_logout",
])
def test_logout_redirect_is_not_a_login_wall(url):
    """629 剩余 11 次 302 中 9 次打 /logout，登出跳 /login 是业务预期。"""
    assert d1._is_login_wall_response(302, {"Location": "/login"}, url) is False
    # 不传 url 时保持原判据（兼容既有调用方）
    assert d1._is_login_wall_response(302, {"Location": "/login"}) is True


def test_logout_401_also_exempt():
    assert d1._is_login_wall_response(401, {}, "http://x/logout") is False
    assert d1._is_login_wall_response(401, {}, "http://x/other") is True


def test_logout_paths_are_configurable(monkeypatch):
    monkeypatch.setenv("SAST_AI_LOGOUT_PATHS", "/bye,/session/end")
    assert d1._is_login_wall_response(302, {"Location": "/login"}, "http://x/bye") is False
    assert d1._is_login_wall_response(302, {"Location": "/login"},
                                      "http://x/session/end/sub") is False
    # 默认列表被覆盖后 /logout 不再豁免，按普通登录墙处理
    assert d1._is_login_wall_response(302, {"Location": "/login"}, "http://x/logout") is True


def test_bypass_variant_uses_guard_and_records_auth_state():
    import inspect
    src = inspect.getsource(d1.D1Service._replay_attack)
    assert "_p_resp, _p_auth_state = self._guarded_request(" in src
    assert "auth_state=_p_auth_state" in src
    # bypass 段内不得残留裸 requests.request（否则 629 的旁路 302 会原样复现）
    start = src.find("_probe_cands")
    end = src.find('slices["bypass_probe', start)
    assert start > 0 and end > start
    assert "requests.request(" not in src[start:end]
