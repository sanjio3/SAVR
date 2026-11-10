"""WebSocket 命令执行探测臂闭环回归锁（jsc 622 spec 237906/237997/238010）。

真实形态：``/websocket/cmd?path=<ws_path>`` 动态注册一个 WebSocket 端点，连上该端点
发的每条消息都会被 ``Runtime.exec`` 执行，stdout 通过 **WebSocket 帧**回显。
622 实测这三条 spec 是 ``family=command_execution`` / ``param_name=''`` /
``iast_state=sink-reached`` / ``verification_status=unconfirmed``，卡在两处：

- ``param_name`` 为空 ⇒ D1 族级探测臂被 ``no_param`` 守门跳过，且命令注入参数本来
  就不在 HTTP 层；
- 命令 stdout 不进 HTTP 响应体 ⇒ 现有 ``cmd_echo`` / ``cmd_native`` 判据永远读不到。

本测试锁住四段闭环：探测臂生成 → 回显帧判据 → D2 技术归类/确认 → D1 两步投递。
所有网络均 mock，纯离线，不连靶场、不调 LLM。
"""
from src.iast import response_oracle as orc
from src.iast.technique_oracle import (
    detect_technique, judge_attempts, supported_techniques)
from src.application.d1_service import D1Service


def _arm(payload, body, *, status=101, error="", note=""):
    return orc.ArmResult(arm="ws_echo", payload=payload, status=status,
                         body=body, error=error, note=note, elapsed_ms=120.0)


def _att(payload, body, no=100):
    return {"attempt_no": no, "payload": payload, "resp_body_head": body,
            "resp_headers_digest": "", "status_code": 101,
            "http_method": "GET", "elapsed_ms": 120}


# ── 1. 探测臂生成 ───────────────────────────────────────────────────────────

def test_build_ws_probe_is_deterministic_and_harmless():
    a = orc.build_ws_probe("238010")
    assert a == orc.build_ws_probe("238010")
    assert a != orc.build_ws_probe("238011")
    assert a["command"] == "echo " + a["marker"]
    assert a["marker"].startswith("SASTAI_WS_")
    assert a["ws_path"].startswith("/sastai_ws_")
    assert a["register_param"] == "path"
    # 无破坏性：只有 echo，不含管道/重定向/删除/外连/读文件
    for bad in ("|", ">", "<", "&", ";", "rm ", "curl", "whoami", "cat "):
        assert bad not in a["command"]


def test_build_probes_websocket_cmd_shape():
    probes = orc.build_probes("websocket_cmd", probe_token="238010")
    assert len(probes) == 1
    p = probes[0]
    assert p.arm == "ws_echo"
    assert p.payload == orc.build_ws_probe("238010")["command"]
    assert "SASTAI_WS_" in p.note


def test_canonical_family_websocket_aliases():
    for f in ("websocket_cmd", "websocketscmdendpoint", "websocket_cmd_endpoint",
              "websocket_command_execution"):
        assert orc.canonical_family(f) == "websocket_cmd"
    assert "websocket_cmd" in orc.ORACLE_FAMILIES
    # 普通 command_execution 绝不能被别名带偏（否则所有 cmdi 端点都会走 WS 投递）
    assert orc.canonical_family("command_execution") == "command_execution"


# ── 2. response_oracle 回显帧判据 ──────────────────────────────────────────

def test_judge_ws_echo_confirms():
    wp = orc.build_ws_probe("238010")
    v = orc.judge("websocket_cmd", [_arm(wp["command"], wp["marker"] + "\r\n")])
    assert v["verdict"] == "exploitable"
    assert v["signal"] == "websocket_echo"


def test_judge_ws_registration_page_does_not_confirm():
    """端点注册成功页不是命令执行证据，绝不据此造正向结论。"""
    wp = orc.build_ws_probe("238010")
    v = orc.judge("websocket_cmd",
                  [_arm(wp["command"], "[+] Websocket: inject success!!!")])
    assert v["verdict"] == "inconclusive"
    assert v["signal"] == "no_ws_echo"


def test_judge_ws_connection_failure_is_inconclusive():
    wp = orc.build_ws_probe("238010")
    v = orc.judge("websocket_cmd",
                  [_arm(wp["command"], "", status=None,
                        error="ws_endpoint_not_registered")])
    assert v["verdict"] == "inconclusive"
    assert "观测缺失" in v["reason"]


# ── 3. D2 technique_oracle 归类与确认 ──────────────────────────────────────

def test_detect_technique_ws_marker_wins_over_cmd_echo():
    wp = orc.build_ws_probe("238010")
    # `echo SASTAI_WS_...` 必须排在 cmd_echo / ssrf_echo 之前
    assert detect_technique("command_execution", wp["command"]) == "websocket_echo"
    assert "websocket_echo" in supported_techniques("websocket_cmd")


def test_judge_attempts_ws_echo_closes_loop():
    wp = orc.build_ws_probe("238010")
    ok, tech, _ = judge_attempts("command_execution", [
        _att(wp["command"], "[+] Websocket: " + wp["ws_path"] + " inject success", no=100),
        _att(wp["command"], wp["marker"], no=101),
    ])
    assert ok is True
    assert tech == "websocket_echo"


def test_judge_attempts_ws_only_registration_page_unconfirmed():
    wp = orc.build_ws_probe("238010")
    ok, _, _ = judge_attempts("command_execution", [
        _att(wp["command"], "[+] Websocket inject success", no=100)])
    assert ok is False


# ── 4. D1 族提升与两步投递 ─────────────────────────────────────────────────

def test_is_websocket_sink_matches_real_622_specs():
    assert D1Service._is_websocket_sink({
        "expected_sink_file": "src/main/java/org/joychou/config/WebSocketsCmdEndpoint.java",
        "target_endpoint": "/websocket/cmd"}) is True
    # Windows 绝对路径反斜杠形态（622 里同一 spec 的另一种写法）
    assert D1Service._is_websocket_sink({
        "expected_sink_file": r"D:\src\main\java\org\joychou\config\WebSocketsCmdEndpoint.java",
        "target_endpoint": "/websocket/cmd"}) is True
    # target_endpoint 兜底（expected_sink_file 缺失时）
    assert D1Service._is_websocket_sink({"target_endpoint": "/websocket/cmd"}) is True


def test_is_websocket_sink_leaves_normal_cmdi_alone():
    for spec in (
        {"expected_sink_file": "src/main/java/org/joychou/controller/Rce.java",
         "target_endpoint": "/rce/runtime/exec"},
        {"expected_sink_file": "src/main/java/org/joychou/controller/CommandInject.java",
         "target_endpoint": "/codeinject"},
        {},
    ):
        assert D1Service._is_websocket_sink(spec) is False


def test_run_websocket_oracle_two_step_and_consumes_frame(monkeypatch):
    """mock 掉网络：验证「HTTP 注册端点 → WS 发命令 → 读回显帧」两步与最终确认。"""
    svc = D1Service.__new__(D1Service)
    svc.db = None  # 跳过落库，仅验证投递与判据
    calls = []
    wp = orc.build_ws_probe("238010")

    class _Resp:
        status_code = 200
        text = "[+] Websocket: inject success!!!"
        headers = {}

    def _fake_get(*_a, **kw):
        calls.append(("http", dict(kw.get("params") or {})))
        return _Resp()

    def _fake_ws(uri, msg, _t, cookies=None, headers=None):
        # 2026-11-06：WS 握手现在必须复用 HTTP 注册那一步的会话凭据，
        # _run_websocket_oracle 会以关键字透传 cookies/headers。
        calls.append(("ws", uri, msg))
        return wp["marker"]

    monkeypatch.setattr("src.application.d1_service.requests.get", _fake_get)
    monkeypatch.setattr(D1Service, "_ws_exchange", staticmethod(_fake_ws))

    probes = orc.build_probes("websocket_cmd", probe_token="238010")
    out = svc._run_websocket_oracle(
        spec={"id": 238010, "target_endpoint": "/websocket/cmd"},
        url="http://127.0.0.1:8080/websocket/cmd", probes=probes,
        probe_token="238010", timeout=5, headers={}, cookies={},
        content_type="", method="GET", baseline_ms=10.0, body=None)

    assert out["verdict"]["verdict"] == "exploitable"
    assert out["verdict"]["signal"] == "websocket_echo"
    http_calls = [c for c in calls if c[0] == "http"]
    ws_calls = [c for c in calls if c[0] == "ws"]
    assert http_calls == [("http", {"path": wp["ws_path"]})]
    assert len(ws_calls) == 1
    assert ws_calls[0][1].startswith("ws://127.0.0.1:8080/")
    assert ws_calls[0][2] == wp["command"]


def test_run_websocket_oracle_registration_failure_is_fail_safe(monkeypatch):
    """注册端点返回 302（登录墙）时不得连接、不得确认。"""
    svc = D1Service.__new__(D1Service)
    svc.db = None
    ws_calls = []

    class _Resp:
        status_code = 302
        text = ""
        headers = {"Location": "/login"}

    monkeypatch.setattr("src.application.d1_service.requests.get",
                        lambda *_a, **_kw: _Resp())
    monkeypatch.setattr(D1Service, "_ws_exchange",
                        staticmethod(lambda *_a: ws_calls.append(1)))

    probes = orc.build_probes("websocket_cmd", probe_token="238010")
    out = svc._run_websocket_oracle(
        spec={"id": 238010, "target_endpoint": "/websocket/cmd"},
        url="http://127.0.0.1:8080/websocket/cmd", probes=probes,
        probe_token="238010", timeout=5, headers={}, cookies={},
        content_type="", method="GET", baseline_ms=10.0, body=None)

    assert out["verdict"]["verdict"] == "inconclusive"
    assert ws_calls == []
