"""302 会话透传兜底回归锁（jsc 622 spec 238030/238031）。

事故：workspace 4 的 settings_json 明明配了 login（JSESSIONID + csrf + 两组凭据），
但 sqli 重放的 replay_attempts 请求头里一个 Cookie 都没有、整片 302 → /login。
根因不是配置，而是 D1 有多条调用入口（benchmark_cli._auto_replay / orchestrator /
REST），此前只在 _auto_replay 一处做过 login 透传；且 _fallback_auth_cookies 只认
service_url / base_url，而 workspace 原生键名是 target_url。

修法：把兜底下沉到 replay() 唯一入口 + base_url 兼容 target_url。
本测试全程离线，不连靶场、不调 LLM。
"""
import json

from src.application.d1_service import D1Service, _fallback_auth_cookies
from src.infrastructure.db import Database

_LOGIN = {
    "url": "http://127.0.0.1:8080/login",
    "method": "POST",
    "cookie_name": "JSESSIONID",
    "credentials": [{"role": "user", "username": "joychou", "password": "joychou123"}],
}


def _seed(tmp_path, settings):
    db = Database(str(tmp_path / "app.db"))
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, settings_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (4, "java-sec-code", "", json.dumps(settings), "2026-01-01", "2026-01-01"),
    )
    return db


# ── replay() 入口兜底 ──────────────────────────────────────────────────────

def test_ensure_login_config_fills_login_from_workspace(tmp_path):
    db = _seed(tmp_path, {"target_url": "http://127.0.0.1:8080", "login": _LOGIN})
    svc = D1Service(db=db)
    target = {"service_url": "http://127.0.0.1:8080"}  # 模拟漏传 login 的调用入口
    svc._ensure_login_config(target, {"workspace_id": 4})
    assert target["login"] == _LOGIN
    assert target["service_url"] == "http://127.0.0.1:8080"


def test_ensure_login_config_adds_service_url_when_target_has_none(tmp_path):
    db = _seed(tmp_path, {"target_url": "http://127.0.0.1:8080", "login": _LOGIN})
    svc = D1Service(db=db)
    target = {}  # orchestrator 路径：连 service_url 都没带
    svc._ensure_login_config(target, {"workspace_id": 4})
    assert target["service_url"] == "http://127.0.0.1:8080"
    assert target["login"] == _LOGIN


def test_ensure_login_config_supports_auth_alias(tmp_path):
    db = _seed(tmp_path, {"target_url": "http://x", "auth": {"username": "u", "password": "p"}})
    svc = D1Service(db=db)
    target = {}
    svc._ensure_login_config(target, {"workspace_id": 4})
    assert target["login"] == {"username": "u", "password": "p"}


def test_ensure_login_config_never_overrides_existing_login(tmp_path):
    db = _seed(tmp_path, {"target_url": "http://x", "login": _LOGIN})
    svc = D1Service(db=db)
    target = {"login": {"url": "http://other/login"}, "service_url": "http://keep"}
    svc._ensure_login_config(target, {"workspace_id": 4})
    assert target["login"]["url"] == "http://other/login"
    assert target["service_url"] == "http://keep"


def test_ensure_login_config_safe_without_db_or_workspace_id(tmp_path):
    svc = D1Service.__new__(D1Service)
    svc.db = None
    t1 = {}
    svc._ensure_login_config(t1, {"workspace_id": 4})
    assert t1 == {}

    db = _seed(tmp_path, {})
    svc2 = D1Service(db=db)
    t2 = {}
    svc2._ensure_login_config(t2, {})  # 无 workspace_id
    assert t2 == {}


# ── _fallback_auth_cookies 的 base_url 键名兼容 ────────────────────────────

def test_fallback_auth_cookies_accepts_target_url(monkeypatch):
    """workspace 原生键名 target_url 不再让兜底登录静默 return {}。"""
    captured = {}

    class _Mgr:
        def get_cookie(self, base_url):
            captured["base_url"] = base_url
            return "JSESSIONID=ABC123"

    monkeypatch.setattr("src.iast.auth_session.get_manager", lambda _settings: _Mgr())
    out = _fallback_auth_cookies({"target_url": "http://127.0.0.1:8080", "login": _LOGIN})
    assert out == {"JSESSIONID": "ABC123"}
    assert captured["base_url"] == "http://127.0.0.1:8080"


def test_fallback_auth_cookies_service_url_still_works(monkeypatch):
    """原有 service_url 写法零回归。"""
    class _Mgr:
        def get_cookie(self, _base_url):
            return "JSESSIONID=OLD123"

    monkeypatch.setattr("src.iast.auth_session.get_manager", lambda _s: _Mgr())
    assert _fallback_auth_cookies({"service_url": "http://x", "login": _LOGIN}) == {
        "JSESSIONID": "OLD123"}


def test_fallback_auth_cookies_no_base_url_never_calls_login(monkeypatch):
    def _boom(_settings):
        raise AssertionError("无 base_url 时不应发起登录")

    monkeypatch.setattr("src.iast.auth_session.get_manager", _boom)
    assert _fallback_auth_cookies({"login": _LOGIN}) == {}
