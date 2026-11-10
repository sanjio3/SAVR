#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""鉴权态会话单测（若依 P3）。

锁三类坑（都是实测踩过的，改回去就红）：
1. 多条 Set-Cookie 必须逐条取（urllib 的 items() 会合并成一条并保留最后一条，
   RuoYi 登录同时下发 JSESSIONID 与 rememberMe=deleteMe，合并后会话直接丢）。
2. Set-Cookie 里有 `Expires=Fri, 30-Oct...` 这种带逗号的值，不能按逗号切。
3. Git Bash 会把 `/index` 改写成 Windows 路径，探针必须归一。
"""
from __future__ import annotations

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.iast.auth_session import (  # noqa: E402
    AuthSession, AuthSessionManager, _cookie_from_headers, _norm_probe_path,
    settings_from_workspace,
)


# ─────────────────────────────────────────────────────────── 纯函数
def test_norm_probe_path_git_bash_mangling():
    """Git Bash 改写后的 Windows 路径要还原成 /index。"""
    assert _norm_probe_path("/index") == "/index"
    assert _norm_probe_path("index") == "/index"
    assert _norm_probe_path(r"D:/tools/PortableGit/index") == "/index"
    assert _norm_probe_path("") == ""


def test_cookie_from_headers_multi_set_cookie():
    """多条 Set-Cookie 都要保留，deleteMe 要丢。"""
    hdrs = {
        "__set_cookie__": [
            "JSESSIONID=abc-123; Path=/; HttpOnly; SameSite=lax",
            "rememberMe=deleteMe; Path=/; Max-Age=0; "
            "Expires=Fri, 30-Oct-2026 15:58:08 GMT; SameSite=lax",
        ]
    }
    assert _cookie_from_headers(hdrs) == "JSESSIONID=abc-123"


def test_cookie_from_headers_expires_comma_not_split():
    """退化路径：只有一条合并后的 set-cookie，Expires 里的逗号不能把值切碎。"""
    hdrs = {"set-cookie": "JSESSIONID=abc-123; Path=/; Expires=Fri, 30-Oct-2026 15:58:08 GMT"}
    assert _cookie_from_headers(hdrs) == "JSESSIONID=abc-123"


def test_cookie_from_headers_skips_attributes():
    """Path/Expires/Max-Age 这些属性不是 cookie。"""
    hdrs = {"__set_cookie__": ["token=v1; Path=/; Secure; HttpOnly; Max-Age=60"]}
    assert _cookie_from_headers(hdrs) == "token=v1"


# ─────────────────────────────────────────────────────────── 配置
def test_settings_from_workspace_nested_and_flat():
    assert settings_from_workspace({"auth": {"username": "a", "password": "b"}})["username"] == "a"
    assert settings_from_workspace({"username": "a", "password": "b"})["username"] == "a"
    assert settings_from_workspace({}) == {}


def test_manager_disabled_without_credentials():
    assert AuthSessionManager.from_settings({}).enabled() is False
    assert AuthSessionManager.from_settings({"username": "a"}).enabled() is False
    assert AuthSessionManager.from_settings({"username": "a", "password": "b"}).enabled() is True
    # 未启用时取 cookie 直接返回空，不发请求
    assert AuthSessionManager.from_settings({}).get_cookie("http://127.0.0.1:1") == ""


# ─────────────────────────────────────────────────────────── 端到端（本地 stub）
class _Stub(BaseHTTPRequestHandler):
    """极简登录桩：POST /login 下发 JSESSIONID，GET /index 无 cookie 返回 302。"""

    def log_message(self, *a):  # 静音
        pass

    def do_POST(self):
        if self.path.startswith("/login"):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode()
            ok = "username=u" in body and "password=p" in body
            if not ok:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"code":500}')
                return
            self.send_response(200)
            self.send_header("Set-Cookie", "JSESSIONID=sess-1; Path=/; HttpOnly")
            self.send_header("Set-Cookie", "rememberMe=deleteMe; Path=/; Max-Age=0")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"code":0}')
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/index"):
            if "JSESSIONID=sess-1" in (self.headers.get("Cookie") or ""):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"home")
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture()
def stub_server():
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()


def test_login_end_to_end_with_probe(stub_server):
    """登录 → 拿到 JSESSIONID → 探针判定「带凭据 200 / 无凭据 302」。"""
    sess = AuthSession(stub_server, "u", "p", login_path="/login", probe_path="/index")
    cookie = sess.get_cookie(force=True)
    assert cookie == "JSESSIONID=sess-1"
    assert sess.status()["has_cookie"] is True
    assert sess.last_error == ""


def test_login_failure_returns_empty(stub_server):
    sess = AuthSession(stub_server, "u", "wrong", login_path="/login", probe_path="/index")
    assert sess.get_cookie(force=True) == ""
    assert "登录判定失败" in sess.last_error


def test_apply_injects_cookie_without_mutating_input(stub_server):
    sess = AuthSession(stub_server, "u", "p", login_path="/login", probe_path="/index")
    base = {"User-Agent": "x"}
    out = sess.apply(base)
    assert out["Cookie"] == "JSESSIONID=sess-1"
    assert "Cookie" not in base  # 不改原字典


def test_get_manager_is_process_singleton():
    """同一份配置必须复用同一个 manager —— 否则 D1 per-spec 路径会逐条重新登录。"""
    from src.iast.auth_session import get_manager

    cfg = {"username": "u", "password": "p", "probe_path": "/index"}
    assert get_manager(cfg) is get_manager(dict(cfg))
    assert get_manager(cfg) is not get_manager({**cfg, "username": "other"})


# ── 富 login 结构 + 成功标记容错（2026-11-02）────────────────────────────────
#
# 事故：workspace settings 里 java-sec-code 用的是
#   {"login": {"url": ".../login", "credentials": [{role, username, password}], "csrf": {...}}}
# 而 `settings_from_workspace` 只认顶层的 username/password（或 auth 键）
# ⇒ 返回空 ⇒ `enabled()` False ⇒ **D1 全程不带凭据重放**。
# 实测 592 的 496 条 200 响应里 43 条是登录页，就是被这一条挡在业务代码外面。
#
# 同时登录判定也有坑：默认成功标记只有 `"code":0`，而目标返回 `{"code":"0"}`，
# 于是「Set-Cookie 里 JSESSIONID 都下发了」仍被判失败。


def test_settings_from_rich_login_schema():
    from src.iast.auth_session import settings_from_workspace

    ws = {
        "url": "http://127.0.0.1:8080/login",
        "method": "POST",
        "credentials": [
            {"role": "admin", "username": "admin", "password": "admin123"},
            {"role": "user", "username": "joychou", "password": "joychou123"},
        ],
        "csrf": {"fetch_url": "http://127.0.0.1:8080/login",
                 "field": "_csrf", "pattern": 'name="_csrf"\\s+content="([^"]+)"'},
    }
    s = settings_from_workspace(ws)
    # 优先 role=user：权限最小，也不踢掉管理员在线会话
    assert s["username"] == "joychou", s
    assert s["password"] == "joychou123"
    assert s["login_path"] == "/login", s
    assert s["csrf"]["field"] == "_csrf"


def test_settings_from_flat_and_auth_key_still_work():
    """新写法不能被富结构支持破坏（若依用 auth 键）。"""
    from src.iast.auth_session import settings_from_workspace

    assert settings_from_workspace({"auth": {"username": "admin", "password": "x"}})["username"] == "admin"
    assert settings_from_workspace({"username": "u", "password": "p"})["username"] == "u"
    assert settings_from_workspace({"login": {"url": "http://h/login"}}) == {}


def test_success_marker_tolerates_quoted_code(monkeypatch):
    """`{"code":"0"}` 必须被判成功 —— 否则拿到了 cookie 也被丢掉。"""
    from src.iast import auth_session as A

    sess = A.AuthSession("http://127.0.0.1:1", "u", "p")
    body = '{"code":"0","message":"Login success"}'
    cmp_body = A.re.sub(r"\s+", "", body).lower()
    ok = any(A.re.sub(r"\s+", "", m).lower() in cmp_body for m in sess.success_markers)
    assert ok, sess.success_markers


# ── 富 login 结构 + CSRF + 成功标记容错（2026-11-02）──────────────────────────
#
# 事故：java-sec-code 的 workspace settings 用的是早期注册器的富结构
#   {"login": {"url":..., "credentials":[{role,username,password}], "csrf":{...}}}
# 而 `settings_from_workspace` 只认顶层/`auth` 下的 username/password
# ⇒ 返回空 ⇒ `enabled()` False ⇒ D1 全程**不带凭据**重放。
# 实测：修之前所有受保护端点都返回 2402 字节的登录页；修之后带凭据返回 36/0/1278 字节的业务响应。
#
# 第二个坑：成功标记只认 `"code":0`，而该应用返回 `{"code":"0","message":"Login success"}`
# ⇒ 明明拿到了 JSESSIONID 也判成失败（has_cookie=false）。


def test_settings_from_rich_login_schema():
    """`login.credentials[]` 富结构必须能解析成 username/password/login_path。"""
    s = settings_from_workspace({
        "url": "http://127.0.0.1:8080/login",
        "credentials": [
            {"role": "admin", "username": "admin", "password": "admin123"},
            {"role": "user", "username": "joychou", "password": "joychou123"},
        ],
        "csrf": {"fetch_url": "http://127.0.0.1:8080/login", "field": "_csrf",
                 "pattern": 'name="_csrf"\\s+content="([^"]+)"'},
    })
    assert s["username"] == "joychou", "必须优先 role=user（权限最小，不踢管理员）"
    assert s["password"] == "joychou123"
    assert s["login_path"] == "/login"
    assert s["csrf"]["field"] == "_csrf"


def test_settings_from_auth_block_still_wins():
    """`auth` 块是首选写法（若依用这个），不能被富结构逻辑干扰。"""
    s = settings_from_workspace({"auth": {"username": "admin", "password": "admin123",
                                          "login_path": "/login", "probe_path": "/index"}})
    assert s["username"] == "admin"
    assert s["probe_path"] == "/index"


def test_settings_from_flat_still_works():
    s = settings_from_workspace({"username": "u", "password": "p", "login_path": "/signin"})
    assert (s["username"], s["login_path"]) == ("u", "/signin")


def test_settings_from_empty_is_empty():
    assert settings_from_workspace({}) == {}
    assert settings_from_workspace({"login": {"credentials": []}}) == {}


def test_login_accepts_quoted_code_success_marker(monkeypatch):
    """`{"code":"0"}` 也算登录成功（原先只认 `"code":0`，导致明明有会话却判失败）。"""
    from src.iast import auth_session as mod

    def _fake_http(opener, url, data=None, headers=None, timeout=15.0):
        if data is None:  # CSRF / probe 的 GET
            return 200, "", {}
        return 200, '{"code":"0","redirectUrl":"","message":"Login success"}', {
            "__set_cookie__": ["JSESSIONID=abc123;path=/;HttpOnly"],
        }

    monkeypatch.setattr(mod, "_http", _fake_http)
    sess = AuthSession("http://127.0.0.1:8080", "joychou", "joychou123")
    cookie = sess.get_cookie(force=True)
    assert "JSESSIONID=abc123" in cookie, sess.last_error


def test_login_still_rejects_wrong_password(monkeypatch):
    """容错不能容成「什么都说成功」：失败响应仍必须判失败。"""
    from src.iast import auth_session as mod

    def _fake_http(opener, url, data=None, headers=None, timeout=15.0):
        if data is None:
            return 200, "", {}
        return 200, '{"code":"1","message":"用户名或密码错误"}', {
            "__set_cookie__": ["XSRF-TOKEN=x;path=/"],
        }

    monkeypatch.setattr(mod, "_http", _fake_http)
    sess = AuthSession("http://127.0.0.1:8080", "joychou", "wrong")
    assert sess.get_cookie(force=True) == "", sess.last_error
