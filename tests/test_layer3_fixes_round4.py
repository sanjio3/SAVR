"""jsc 625 追出的第 6 类根因回归锁：WebSocket 握手凭据（2026-11-06）。

证据链：625 真跑里会话自愈已让 203/203 出站请求带上 JSESSIONID，HTTP 注册端点
`/websocket/cmd?path=/sastai_ws_x` 实测 200（`[-] Websocket: ... has been injected!`），
但第二步 `_ws_exchange()` 连 ws:// 时没带 Cookie ⇒ 靶场把握手 302 到 /login，
websockets 17.2 跟随重定向后把 `http://127.0.0.1:8080/login` 当 WS URI 校验，
抛 `InvalidURI: scheme isn't ws or wss` ⇒ 623/624 的 websocket_cmd 点
oracle_state 恒 inconclusive。活靶场对照：只加 additional_headers 的 Cookie +
proxy=None 即可收到 `SASTAI_WS_pcookieonly\r\n` 回显；proxy=False 不被 17.2 支持。
"""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


class _FakeWS:
    def __init__(self, frame: str):
        self.frame = frame
        self.sent = []

    async def send(self, msg: str) -> None:
        self.sent.append(msg)

    async def recv(self) -> str:
        return self.frame


class _FakeCM:
    def __init__(self, ws: _FakeWS):
        self.ws = ws

    async def __aenter__(self) -> _FakeWS:
        return self.ws

    async def __aexit__(self, *args) -> bool:
        return False


def _run_ws_exchange(cookies=None, headers=None, frame: str = "SASTAI_WS_OK\r\n"):
    """替换 websockets.connect，捕获 connect 的真实 kwargs 后返回假回显帧。"""
    import websockets

    from src.application.d1_service import D1Service

    captured: dict = {}

    def fake_connect(uri, **kwargs):
        captured["uri"] = uri
        captured["kwargs"] = kwargs
        return _FakeCM(_FakeWS(frame))

    # inspect.signature 会被 _ws_exchange 用来判断该版本支持 proxy / additional_headers；
    # patch 成普通函数后签名会退化成 (uri, **kwargs)，故显式挂回真实签名。
    fake_connect.__signature__ = inspect.signature(websockets.connect)
    with patch("websockets.connect", new=fake_connect):
        out = D1Service._ws_exchange(
            "ws://127.0.0.1:8080/sastai_ws_test", "echo SASTAI_WS_OK", 1.0,
            cookies=cookies, headers=headers)
    return out, captured


def test_ws_exchange_forwards_cookie_and_disables_proxy():
    """握手必须带会话 Cookie；本机靶场必须直连（proxy=None，不能用 False）。"""
    out, cap = _run_ws_exchange(cookies={"JSESSIONID": "SID123", "XSRF-TOKEN": "T9"})
    assert out == "SASTAI_WS_OK\r\n"
    kw = cap["kwargs"]
    assert kw["proxy"] is None, kw
    hdr_key = "additional_headers" if "additional_headers" in kw else "extra_headers"
    assert hdr_key in kw, kw
    cookie = kw[hdr_key].get("Cookie", "")
    assert "JSESSIONID=SID123" in cookie and "XSRF-TOKEN=T9" in cookie, cookie
    assert kw["open_timeout"] == 1.0 and kw["close_timeout"] == 1.0


def test_ws_exchange_keeps_explicit_cookie_header():
    """上游已给 Cookie 头时不得被 cookies dict 覆盖（避免凭据降级）。"""
    _out, cap = _run_ws_exchange(
        cookies={"JSESSIONID": "FROM_DICT"},
        headers={"Cookie": "JSESSIONID=FROM_HEADER", "X-XSRF-TOKEN": "T9"})
    kw = cap["kwargs"]
    hdr_key = "additional_headers" if "additional_headers" in kw else "extra_headers"
    assert kw[hdr_key]["Cookie"] == "JSESSIONID=FROM_HEADER", kw[hdr_key]
    assert kw[hdr_key]["X-XSRF-TOKEN"] == "T9"


def test_ws_exchange_without_credentials_has_no_extra_headers():
    """零凭据时保持旧行为，不给不需要认证的靶场塞多余头。"""
    out, cap = _run_ws_exchange()
    assert out == "SASTAI_WS_OK\r\n"
    kw = cap["kwargs"]
    assert "additional_headers" not in kw and "extra_headers" not in kw, kw
    assert kw["proxy"] is None


def test_ws_oracle_forwards_session_cookies_to_handshake():
    """_run_websocket_oracle 必须把同一份 cookies/headers 透传到 WS 握手。"""
    from src.application.d1_service import D1Service
    from src.iast import response_oracle as orc

    captured: dict = {}

    def spy(uri, message, timeout, cookies=None, headers=None):
        captured.update(uri=uri, cookies=cookies, headers=headers, message=message)
        return orc.build_ws_probe("7777")["marker"] + "\r\n"

    resp = SimpleNamespace(status_code=200, text="injected", headers={})
    spec = {"id": 7777, "family": "command_execution",
            "expected_sink_file": "org/joychou/config/WebSocketsCmdEndpoint.java",
            "target_endpoint": "/websocket/cmd"}
    probes = orc.build_probes("websocket_cmd", payload="", servlet_name="", probe_token="7777")
    with patch.object(D1Service, "_ws_exchange", staticmethod(spy)), \
         patch("src.application.d1_service.requests.get", return_value=resp):
        res = D1Service(db=None)._run_websocket_oracle(
            spec=spec, url="http://127.0.0.1:8080/websocket/cmd", probes=probes,
            probe_token="7777", timeout=5, headers={}, cookies={"JSESSIONID": "SID777"},
            content_type="", method="GET", baseline_ms=0.0, body=None)
    assert captured["cookies"] == {"JSESSIONID": "SID777"}, captured
    assert str(captured["uri"]).startswith("ws://"), captured
    assert res["verdict"]["verdict"] == "exploitable", res["verdict"]
    assert res["verdict"]["signal"] == "websocket_echo", res["verdict"]


def test_ws_echo_verdict_requires_real_frame():
    """回显臂没收到帧时保持 inconclusive，不把注册成功页当正向结论。"""
    from src.iast import response_oracle as orc

    empty = [orc.ArmResult(arm="ws_echo", payload="echo SASTAI_WS_abcd", status=None,
                           body="", error="ws_endpoint_not_registered")]
    v = orc.judge("websocket_cmd", empty, baseline_ms=0.0)
    assert v["verdict"] != "exploitable", v
    good = [orc.ArmResult(arm="ws_echo", payload="echo SASTAI_WS_abcd", status=101,
                          body="SASTAI_WS_abcd\r\n")]
    v2 = orc.judge("websocket_cmd", good, baseline_ms=0.0)
    assert v2["verdict"] == "exploitable" and v2["signal"] == "websocket_echo", v2


def test_ws_exchange_call_site_passes_credentials():
    """锁住调用点：只改 _ws_exchange 而忘了传 cookies 等于没修。"""
    text = _src("src/application/d1_service.py")
    assert "_ws_exchange(ws_uri, wp[\"command\"], _to," in text
    assert "cookies=cookies, headers=headers" in text


def test_websocket_echo_is_a_recognized_oracle_harm_signal():
    """第三道门：握手打通后判出 websocket_echo，硬闸/升级必须认这个信号。"""
    from src.cli.benchmark_cli import _oracle_positive_signal

    assert _oracle_positive_signal("command_execution", "exploitable",
                                   "websocket_echo") == "websocket_echo"
    # 族严格匹配：其它族不能借 WS 回显升成 command_execution 的正向证据
    assert _oracle_positive_signal("xss", "exploitable", "websocket_echo") == ""
    assert _oracle_positive_signal("command_execution", "inconclusive",
                                   "websocket_echo") == ""


def test_websocket_echo_bypasses_arrival_state_gate():
    """探针不覆盖 WS 端点时到达态可能是 no-arrival，硬观测仍应允许升级。"""
    from src.cli.benchmark_cli import _RESPONSE_ONLY_ORACLE_SIGNALS

    assert "websocket_echo" in _RESPONSE_ONLY_ORACLE_SIGNALS
