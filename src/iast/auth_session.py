#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""鉴权态会话：登录 → 缓存 → 注入重放。

## 为什么需要

「动态确认」会接近 0 —— 这不是判据不好，是**请求根本没到达业务代码**。

## 设计约束

1. **配置化**：账号密码、登录路径、额外表单字段一律从 workspace settings 读，不写死在代码里。
2. **不猜成功**：登录是否成功只看两件事——响应体里的成功标记，或「受保护端点从 302 变 200」。
   后者更可靠（不同框架的成功标记五花八门）。
3. **cookie 值必须编码**：含空格/引号/分号的 cookie 值会被 Tomcat **整条丢弃**
4. **失败不阻断**：拿不到会话就返回空 cookie，由调用方退回无凭据重放，绝不抛异常中断扫描。

## 与探针无关

本模块只做 HTTP 层的会话维持，不依赖 IAST 探针——真实业务场景不能插桩，
会话能力必须在纯黑盒下可用。

## 用法

    from src.iast.auth_session import AuthSessionManager
    mgr = AuthSessionManager.from_settings({"username": "admin", "password": "admin123",
                                            "login_path": "/login",
                                            "extra_params": {"rememberMe": "false"},
                                            "probe_path": "/index"})
    cookie = mgr.get_cookie(base_url)          # "JSESSIONID=xxxx"
    headers = mgr.apply({}, cookie)            # 注入到重放 headers

命令行自检（运维用）：

    python -m src.iast.auth_session --base-url http://127.0.0.1:8081 \
        --user admin --password admin123 --extra rememberMe=false --probe /index
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

# 与 D1 共用同一套 cookie 编码：含空格/引号的值会被 Tomcat 整条丢弃
try:
    from src.iast.response_oracle import encode_cookie_value as _cookie_safe
except Exception:  # pragma: no cover
    def _cookie_safe(value: str) -> str:
        return str(value or "")


def _no_proxy_opener(follow_redirect: bool = True):
    """本机 HTTP_PROXY 会让 127.0.0.1 走代理返回 502；且「未授权」必须看真 302。"""
    handlers = [urllib.request.ProxyHandler({})]
    if not follow_redirect:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw):
                return None
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _http(opener, url: str, data: Optional[bytes] = None,
          headers: Optional[Dict[str, str]] = None, timeout: float = 15.0) -> Tuple[int, str, Dict[str, str]]:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            # 关键：urllib 的 items 会把多条 Set-Cookie **合并成一条**，
            # 合并后只剩 deleteMe，会话直接丢。必须用 get_all 逐条取。
            try:
                hdrs["__set_cookie__"] = list(r.headers.get_all("Set-Cookie") or [])
            except Exception:
                hdrs["__set_cookie__"] = []
            return r.status, body, hdrs
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            hdrs["__set_cookie__"] = list((e.headers or {}).get_all("Set-Cookie") or [])
        except Exception:
            hdrs["__set_cookie__"] = []
        return e.code, body, hdrs
    except Exception as e:
        return 0, str(e), {}


def _cookie_from_headers(hdrs: Dict[str, str]) -> str:
    """从响应头抽 cookie，返回 ``k=v; k2=v2`` 形式（值已编码）。

    优先用 ``__set_cookie__`` 的原始多值列表；退化为对单条 Set-Cookie 做解析
    （此时按 ``;`` 切段，不按 ``,``——``Expires=Fri, 30-Oct...`` 里有逗号，
    按逗号切会把过期时间切碎，进而把 JSESSIONID 丢掉）。
    """
    raw_list = hdrs.get("__set_cookie__") or []
    if not raw_list:
        single = hdrs.get("set-cookie") or ""
        raw_list = [single] if single else []
    pairs = []
    for raw in raw_list:
        for seg in str(raw).split(";"):
            seg = seg.strip()
            if "=" not in seg:
                continue
            k, v = seg.split("=", 1)
            k, v = k.strip(), v.strip()
            if not k or not v:
                continue
            # 只取 cookie 本体：Path/Expires/Max-Age/SameSite 这些属性值不是 cookie
            if k.lower() in ("path", "expires", "max-age", "domain", "samesite", "secure",
                             "httponly", "version", "comment"):
                continue
            if v.lower() == "deleteme":
                continue
            pairs.append(f"{k}={_cookie_safe(v)}")
    # 去重保序
    seen, out = set(), []
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return "; ".join(out)


def _norm_probe_path(raw) -> str:
    """把探针路径归一成 ``/xxx``。

    真实踩到的坑：Git Bash 会把命令行里的 ``/index`` 按 MSYS 规则改写成
    ``<盘符>:/<路径>/PortableGit/index``，于是探针打到一个不存在的
    Windows 路径上，永远拿不到 200，表现为「登录成功但判定失败」。
    这里把「盘符 + 常见 PortableGit 前缀」剥掉，再补前导斜杠。
    """
    p = str(raw or "").strip()
    if not p:
        return ""
    if p.startswith("http://") or p.startswith("https://"):
        return p
    low = p.lower().replace("\\", "/")
    idx = low.find("/portablegit/")
    if idx >= 0:
        p = p[idx + len("/portablegit"):]
    elif len(p) > 2 and p[1] == ":":
        # 纯盘符路径（D:/xxx）：取最后一段当探针，避免整条 Windows 路径进 URL
        p = "/" + p.replace("\\", "/").rsplit("/", 1)[-1]
    if not p.startswith("/"):
        p = "/" + p
    return p


class AuthSession:
    """一个账号在一个 base_url 上的会话（带 TTL 缓存）。"""

    def __init__(self, base_url: str, username: str = "", password: str = "",
                 login_path: str = "/login", probe_path: str = "",
                 extra_params: Optional[Dict[str, str]] = None,
                 success_markers: Optional[list] = None,
                 ttl_seconds: float = 900.0,
                 csrf: Optional[Dict[str, str]] = None):
        self.base_url = str(base_url or "").rstrip("/")
        self.username = username
        self.password = password
        self.login_path = login_path or "/login"
        # 路径归一：Git Bash 会把 `--probe /index` 这类参数按 MSYS 规则改写成
        # ` <盘符>:/.../PortableGit/index`，所以既补前导 "/"，也识别被改写的形态。
        self.probe_path = _norm_probe_path(probe_path)
        self.extra_params = dict(extra_params or {})
        # 成功标记必须容错：同一框架不同版本返回 `{"code":0}` / `{"code":"0"}` /
        # `{"code": "0", "message":"Login success"}` 三种都见过。原先只认 `"code":0`
        # 表现为 `has_cookie=false`，D1 全程无凭据重放。
        self.success_markers = list(success_markers or [
            '"code":0', '"code":"0"', '"success":true', '"success": true',
            "loginsuccess", "login success",
        ])
        self.ttl_seconds = float(ttl_seconds or 0)
        # CSRF 配置（可选）：{"fetch_url":..., "field":"_csrf", "pattern":"name=\"_csrf\"\\s+value=\"([^\"]+)\""}
        # 为什么需要：Spring Security 默认开启 CSRF，登录 POST 缺 token 会被 403，
        # 表现为「用户名密码都对却拿不到会话」，以前只能手工把 token 写进 extra_params。
        self.csrf = dict(csrf or {})
        self._cookie = ""
        self._at = 0.0
        self._lock = threading.Lock()
        self.last_error = ""

    # ---------------------------------------------------------------- 内部
    def _form_fields(self) -> Dict[str, str]:
        fields = {"username": self.username, "password": self.password}
        fields.update({str(k): str(v) for k, v in self.extra_params.items()})
        return fields

    def _form(self) -> bytes:
        return urllib.parse.urlencode(self._form_fields()).encode()

    def _fetch_csrf_token(self, opener) -> str:
        """按配置取 CSRF token（GET 登录页 → 正则抽取）。取不到返回空串，不影响原流程。"""
        if not self.csrf:
            return ""
        url = str(self.csrf.get("fetch_url") or "")
        pattern = str(self.csrf.get("pattern") or "")
        if not url or not pattern:
            return ""
        try:
            status, body, _ = _http(opener, url)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"CSRF 取 token 异常：{exc}"
            return ""
        if status == 0:
            return ""
        m = re.search(pattern, body or "")
        return str(m.group(1) if m else "")

    def _login(self) -> str:
        opener = _no_proxy_opener()
        fields = self._form_fields()
        if self.csrf:
            token = self._fetch_csrf_token(opener)
            if token:
                fields[str(self.csrf.get("field") or "_csrf")] = token
            else:
                self.last_error = "CSRF token 未取到（继续尝试无 token 登录）"
        status, body, hdrs = _http(
            opener, f"{self.base_url}{self.login_path}",
            data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        cookie = _cookie_from_headers(hdrs)
        if status == 0:
            self.last_error = f"登录请求失败：{body[:120]}"
            return ""
        ok_by_body = False
        if body:
            _cmp = re.sub(r"\s+", "", body).lower()
            for _m in self.success_markers:
                _mm = re.sub(r"\s+", "", str(_m or "")).lower()
                if _mm and _mm in _cmp:
                    ok_by_body = True
                    break
        # 有 probe_path 时以「受保护端点是否 200」为准——比成功标记可靠，
        ok_by_probe = None
        if self.probe_path and cookie:
            ok_by_probe = self._probe(cookie)
        if ok_by_probe is True or (ok_by_probe is None and ok_by_body):
            return cookie
        self.last_error = (f"登录判定失败 status={status} body={body[:120]!r} "
                           f"probe={ok_by_probe}")
        return ""

    def _probe(self, cookie: str) -> Optional[bool]:
        """带/不带 cookie 访问受保护端点，返回「带凭据是否真的通了」。"""
        opener = _no_proxy_opener(follow_redirect=False)
        with_status, _, _ = _http(opener, f"{self.base_url}{self.probe_path}",
                                  headers={"Cookie": cookie} if cookie else {})
        if with_status != 200:
            return False
        anon_status, _, _ = _http(opener, f"{self.base_url}{self.probe_path}")
        # 无凭据也 200 ⇒ 这个端点没被保护，探针无意义，返回 None 交回 body 判定
        if anon_status == 200:
            return None
        return True

    # ---------------------------------------------------------------- 对外
    def get_cookie(self, force: bool = False) -> str:
        with self._lock:
            fresh = self._cookie and (time.time() - self._at) < self.ttl_seconds
            if fresh and not force:
                return self._cookie
            cookie = self._login()
            if cookie:
                self._cookie, self._at = cookie, time.time()
                self.last_error = ""
            return cookie or self._cookie

    def invalidate(self) -> None:
        with self._lock:
            self._cookie, self._at = "", 0.0

    def apply(self, headers: Optional[Dict[str, str]] = None,
              cookie: Optional[str] = None) -> Dict[str, str]:
        """把会话 cookie 注入 headers（不改原字典）。"""
        out = dict(headers or {})
        c = cookie if cookie is not None else self.get_cookie()
        if c:
            existing = out.get("Cookie") or out.get("cookie") or ""
            out["Cookie"] = f"{existing}; {c}".strip("; ") if existing else c
        return out

    def status(self) -> Dict[str, object]:
        return {
            "base_url": self.base_url,
            "username": self.username,
            "has_cookie": bool(self._cookie),
            "age_seconds": int(time.time() - self._at) if self._at else None,
            "last_error": self.last_error,
        }


class AuthSessionManager:
    """按 (base_url, username) 管一组会话，供 D1 在重放前取 cookie。"""

    def __init__(self, settings: Optional[Dict] = None):
        self.settings = dict(settings or {})
        self._sessions: Dict[Tuple[str, str], AuthSession] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: Optional[Dict]) -> "AuthSessionManager":
        return cls(settings or {})

    def enabled(self) -> bool:
        return bool(self.settings.get("username")) and bool(self.settings.get("password"))

    def for_base(self, base_url: str, username: str = "") -> AuthSession:
        user = username or str(self.settings.get("username") or "")
        key = (str(base_url or "").rstrip("/"), user)
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                sess = AuthSession(
                    base_url=base_url,
                    username=user,
                    password=str(self.settings.get("password") or ""),
                    login_path=str(self.settings.get("login_path") or "/login"),
                    probe_path=str(self.settings.get("probe_path") or ""),
                    extra_params=self.settings.get("extra_params") or {},
                    success_markers=self.settings.get("success_markers") or None,
                    ttl_seconds=float(self.settings.get("ttl_seconds") or 900),
                    csrf=self.settings.get("csrf") or None,
                )
                self._sessions[key] = sess
            return sess

    def get_cookie(self, base_url: str, username: str = "") -> str:
        if not self.enabled():
            return ""
        try:
            return self.for_base(base_url, username).get_cookie()
        except Exception:
            return ""


_MANAGER_CACHE: Dict[str, "AuthSessionManager"] = {}
_MANAGER_LOCK = threading.Lock()


def get_manager(settings: Optional[Dict]) -> "AuthSessionManager":
    """按配置内容取**进程级单例** manager。

    为什么必须缓存：``_fallback_auth_cookies`` 在 D1 的 per-spec 路径里被调用，
    目标会被反复踢下线，而且登录请求本身会把扫描拖慢一个量级。
    用配置内容做 key，配置变了自然换新实例。
    """
    # key 用配置的 sha256：配置里含明文密码，直接把 JSON 当 key 会让
    # 任何一次 debug dump（打印缓存字典）把口令带出来。
    raw = json.dumps(settings or {}, sort_keys=True, ensure_ascii=False, default=str)
    key = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    with _MANAGER_LOCK:
        mgr = _MANAGER_CACHE.get(key)
        if mgr is None:
            mgr = AuthSessionManager(settings or {})
            _MANAGER_CACHE[key] = mgr
        return mgr


def settings_from_workspace(ws_settings: Optional[Dict]) -> Dict:
    """从 workspace settings 里取鉴权配置。

    支持三种写法（历史原因，三套并存）：

    2. 字段直接平铺在 settings 顶层；
    3. ``{"login": {"url":..., "credentials":[{role,username,password}], "csrf":{...}}}``

    **第 3 种以前完全没被解析**：`enabled` 只看顶层的 `username`/`password`，
    富结构里没有这两个键 ⇒ 返回空 ⇒ D1 全程**不带凭据**重放。实测 592 里
    43/496 条响应是登录页，就是被这一条挡在业务代码外面的。
    """
    ws = dict(ws_settings or {})
    auth = ws.get("auth")
    if isinstance(auth, dict):
        return dict(auth)
    keys = ("username", "password", "login_path", "probe_path", "extra_params",
            "success_markers", "ttl_seconds", "csrf")
    flat = {k: ws[k] for k in keys if k in ws}
    if flat.get("username"):
        return flat

    # 富结构：login.url + login.credentials[] (+ login.csrf)
    creds = [c for c in (ws.get("credentials") or []) if isinstance(c, dict)]
    if not creds:
        return {}
    # 优先 role=user：权限最小，避免用 admin 触发越权路径、也避免踢掉管理员在线会话
    pick = next((c for c in creds if str(c.get("role") or "").lower() == "user"), creds[0])
    if not pick.get("username") or not pick.get("password"):
        return {}
    out: Dict = {
        "username": str(pick.get("username") or ""),
        "password": str(pick.get("password") or ""),
    }
    url = str(ws.get("url") or "")
    if url:
        path = urllib.parse.urlparse(url).path or ""
        out["login_path"] = path or "/login"
    if isinstance(ws.get("csrf"), dict):
        out["csrf"] = dict(ws["csrf"])
    if isinstance(ws.get("extra_params"), dict):
        out["extra_params"] = dict(ws["extra_params"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="鉴权态会话自检")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--login-path", default="/login")
    ap.add_argument("--probe", default="", help="受保护端点，如 /index")
    ap.add_argument("--extra", action="append", default=[],
                    help="额外表单字段 k=v（可多次），如 --extra rememberMe=false")
    args = ap.parse_args()

    extra = {}
    for kv in args.extra:
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra[k.strip()] = v.strip()
    sess = AuthSession(args.base_url, args.user, args.password,
                       login_path=args.login_path, probe_path=args.probe,
                       extra_params=extra)
    cookie = sess.get_cookie(force=True)
    print(json.dumps({**sess.status(), "cookie": cookie}, ensure_ascii=False, indent=2))
    return 0 if cookie else 1


if __name__ == "__main__":
    raise SystemExit(main())
