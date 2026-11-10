"""M13「DAST 的浏览器扩展」测试（2026-10-03）。

要钉住的纪律（按评审的「按需起浏览器、用完释放、非常驻」）：
  1. 只在需要渲染后 DOM 的族上投，其他族（sqli/idor…）绝不因为模块存在就起浏览器；
  2. 浏览器运行时不可用时如实报 unavailable —— **绝不伪造**「没搜到」或「可利用」；
  3. 三态：raw=可利用 / escaped=真阴性（确证）/ absent=证据缺失（不 definitive）/
     unavailable=证据缺失（不 definitive）；
  4. 进程与临时 profile 用完即关（close 幂等、上下文管理保证）；
  5. URL 取 D1 真实发出的 replay_url，退化才用 endpoint（浏览器打不开只有路径的串）；
  6. 进 D2 通道注册表，证明力/代价登记完整，仲裁能取到它。
"""
from src.core import browser_probe as bp
from src.core import evidence_channels as ec


class _FakeProbe:
    """假浏览器：不真起进程，返回预设取证结果，并记录调用与 close。"""

    def __init__(self, result=None, fail=False):
        self.result = result or {}
        self.fail = fail
        self.closed = 0
        self.calls = []

    def probe(self, url, marker):
        self.calls.append((url, marker))
        if self.fail:
            raise RuntimeError("boom")
        return dict(self.result)

    def close(self):
        self.closed += 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False


def _res(state, **kw):
    d = {"url": "http://h/p", "marker": "sastai-abc", "state": state, "engine": "chromium",
         "duration_ms": 123, "reason": "", "dom_hits": [], "eval_called": False,
         "observed": True, "timeout": False}
    d.update(kw)
    return d


def _d2_dom_ctx(url="http://h/p?x=1"):
    return {"family": "dom_xss", "dast": {"replay_url": url},
            "spec": {"target_endpoint": "/p"}, "iast": {"state": "no_evidence"}}


# ---------------- 族判定：只看需要渲染后 DOM 的族 ----------------

def test_dom_family_detected():
    assert bp.is_dom_family("dom_xss")
    assert bp.is_dom_family("client_side_xss")
    assert bp.is_dom_family("front_end_render")
    assert bp.is_dom_family("DOM-XSS")


def test_non_dom_family_not_triggered():
    """sqli/idor 这类后端族不该走浏览器 —— 起了就是浪费，且会把重放预算烧在页面上。

    防回归点：裸 "dom" token 走子串匹配会把 weak_**random**、abuse**dom** 之类
    名字里恰好含 dom 三个字母的后端族误判成前端族。
    """
    for f in ("sqli", "sql_injection", "idor", "bola", "weak_random", "secure_cookie",
              "abused_observable"):
        assert not bp.is_dom_family(f)


# ---------------- URL 解析 ----------------

def test_prefers_real_replay_url():
    assert bp.probe_url_for({"target_endpoint": "/p"},
                            {"replay_url": "http://h/p?a=1"}) == "http://h/p?a=1"


def test_falls_back_to_endpoint_field():
    assert bp.probe_url_for({"target_endpoint": "/p"}, {}) == "/p"


def test_no_endpoint_no_url():
    assert not bp.probe_url_for({"target_endpoint": ""}, {})


# ---------------- 运行时探测 ----------------

def test_backend_unavailable_is_reported_truthfully(monkeypatch):
    monkeypatch.setattr(bp, "backend_available", lambda: (False, "playwright_not_installed"))
    out = bp.run_browser_probe("http://h/p", "sastai-abc")
    assert out["state"] == bp.STATE_UNAVAILABLE
    assert "playwright_not_installed" in out["reason"]
    assert out["observed"] is False


def test_run_browser_probe_never_raises():
    p = _FakeProbe(fail=True)
    out = bp.run_browser_probe("http://h/p", "m", probe=p)
    assert out["state"] == bp.STATE_UNAVAILABLE


def test_marker_is_self_limiting_and_unique():
    m1, m2 = bp.make_marker(), bp.make_marker()
    assert m1.startswith("sastai-")
    assert m1 != m2
    assert not any(ch in m1 for ch in (";", "|", "&", "<", ">", "$", "`"))


def test_three_states_are_distinguishable():
    for st in (bp.STATE_RAW, bp.STATE_ESCAPED, bp.STATE_ABSENT):
        out = bp.run_browser_probe("http://h/p", "m", probe=_FakeProbe(_res(st)))
        assert out["state"] == st


def test_probe_close_is_idempotent():
    with _FakeProbe(_res(bp.STATE_ABSENT)) as p:
        p.probe("http://h/p", "m")
    assert p.closed >= 1


def test_timeout_env_is_picked_up(monkeypatch):
    monkeypatch.setenv("SASTAI_BROWSER_TIMEOUT", "7")
    assert bp._env_timeout() == 7.0
    monkeypatch.delenv("SASTAI_BROWSER_TIMEOUT")
    assert bp._env_timeout() == bp.DEFAULT_TIMEOUT_SECONDS


# ---------------- 通道注册表与先判后投 ----------------

def test_channel_registered_with_strength_and_cost():
    assert ec.CHANNEL_STRENGTH["browser_dom"] == 4
    assert ec.CHANNEL_REPLAY_COST["browser_dom"] == 1
    assert ec.CHANNEL_LABEL["browser_dom"] == "浏览器渲染取证"
    assert "browser_dom" in ec._CHANNEL_PRIORITY


def test_channel_not_offered_for_non_dom_family():
    """sqli 不该被塞上浏览器通道（先判后投，避免无谓起进程）。"""
    assert "browser_dom" not in ec.plan_channels("sqli")["planned"]


def test_browser_channel_not_planned_when_runtime_missing(monkeypatch):
    """运行时不可用时通道不进计划 —— 没有浏览器就别占重放预算。"""
    monkeypatch.setattr(bp, "backend_available", lambda: (False, "playwright_not_installed"))
    assert "browser_dom" not in ec.plan_channels("dom_xss")["planned"]


def test_browser_channel_planned_when_runtime_ready(monkeypatch):
    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    assert "browser_dom" in ec.plan_channels("dom_xss")["planned"]


def test_applicability_reports_runtime_reason(monkeypatch):
    ok, _why = ec._browser_dom_applicable("dom_xss")
    assert ok is False                      # 本机没装 playwright
    monkeypatch.setattr(bp, "backend_available", lambda: (False, "no chromium"))
    ok, why = ec._browser_dom_applicable("dom_xss")
    assert ok is False and "no chromium" in why
    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    ok, why = ec._browser_dom_applicable("dom_xss")
    assert ok is True and "playwright" in why
    ok, _ = ec._browser_dom_applicable("sqli")
    assert ok is False


# ---------------- D2 通道仲裁 ----------------

def test_d2_channel_raw_is_definitive_harmful(monkeypatch):
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    monkeypatch.setattr(bp, "run_browser_probe",
                        lambda url, marker, *_a, **_kw:
                        _res(bp.STATE_RAW, eval_called=True, url=url))
    ctx = _d2_dom_ctx()
    out = d2_facade._ch_browser_dom(ctx)
    assert out["channel"] == "browser_dom"
    assert out["definitive"] is True and out["harmful"] is True
    assert out["browser_state"] == bp.STATE_RAW
    assert ctx["dast"]["replay_url"] in out["browser_url"]


def test_d2_channel_escaped_is_true_negative(monkeypatch):
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    monkeypatch.setattr(bp, "run_browser_probe",
                        lambda url, marker, *_a, **_kw: _res(bp.STATE_ESCAPED, url=url))
    out = d2_facade._ch_browser_dom(_d2_dom_ctx())
    assert out["definitive"] is True and out["harmful"] is False


def test_d2_channel_absent_is_not_definitive(monkeypatch):
    """没搜到 ≠ 无害（可能页面 404 / 脚本报错 / 标记没进渲染路径）。"""
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    monkeypatch.setattr(bp, "run_browser_probe",
                        lambda url, marker, *_a, **_kw: _res(bp.STATE_ABSENT, url=url))
    out = d2_facade._ch_browser_dom(_d2_dom_ctx())
    assert out["definitive"] is False and out["harmful"] is False


def test_d2_channel_unavailable_never_fakes(monkeypatch):
    """没有运行时时如实报证据缺失，绝不伪造「可利用」。"""
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (False, "playwright_not_installed"))
    out = d2_facade._ch_browser_dom(_d2_dom_ctx())
    assert out["harmful"] is False
    assert out["definitive"] is False
    assert out["browser_state"] == bp.STATE_UNAVAILABLE


def test_d2_channel_never_runs_for_non_dom_family(monkeypatch):
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    monkeypatch.setattr(bp, "run_browser_probe",
                        lambda url, marker, *_a, **_kw: _res(bp.STATE_RAW))
    out = d2_facade._ch_browser_dom(
        {"family": "sqli", "dast": {"replay_url": "http://h/p"},
         "spec": {"target_endpoint": "/p"}, "iast": {"state": "no_evidence"}})
    assert out is None


def test_d2_verification_runs_browser_channel(monkeypatch):
    """假浏览器下，_verify_sink_result 的 channels_run 里要能看到这条通道真的跑了。"""
    from src.agents import d2_facade

    monkeypatch.setattr(bp, "backend_available", lambda: (True, "playwright"))
    monkeypatch.setattr(bp, "run_browser_probe",
                        lambda url, marker, *_a, **_kw:
                        _res(bp.STATE_RAW, url=url, eval_called=True))
    verdict = d2_facade._verify_sink_result(
        {"state": "no_evidence"}, {"replay_url": "http://h/p?x=1"},
        "dom_xss", spec={"target_endpoint": "/p"})
    run = verdict.get("channels_run") or {}
    assert "browser_dom" in run
