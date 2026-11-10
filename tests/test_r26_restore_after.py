"""R26：restore_after（可回滚验证）回归守卫。

覆盖三件事：
  1. 闸门对 credential_mutation / mass_assignment 放行但声明强制回滚，且总开关可退回 skip；
  2. 拿不到基线就绝不投放；
  3. 回滚失败必须把 confirmed 改判 False（不留持久变更优先于取证）。
"""
import os
from contextlib import contextmanager

import pytest

from src.iast import attack_context as ac


def _spec(ep, method="POST", param="id", **kw):
    s = {"target_endpoint": ep, "http_method": method, "param_name": param}
    s.update(kw)
    return s


def test_password_change_is_restore_after_not_skip():
    _, g = ac.neutralize_destructive_spec(_spec("/profile/password"))
    assert g.get("action") == "restore_after"
    assert g.get("category") == "credential_mutation"
    assert "回滚" in (g.get("reason") or "")


def test_mass_assignment_is_restore_after_not_skip():
    _, g = ac.neutralize_destructive_spec(_spec("/profile/update"))
    assert g.get("action") == "restore_after"
    assert g.get("category") == "mass_assignment"


def test_restore_after_does_not_touch_other_categories():
    """放行只针对那两类：删除类仍是 absent_id，资金类非 id 参数仍是 skip。"""
    _, g1 = ac.neutralize_destructive_spec(_spec("/ops/user/delete", param="uid"))
    assert g1.get("action") == "absent_id"
    _, g2 = ac.neutralize_destructive_spec(_spec("/wallet/withdraw", param="amount"))
    assert g2.get("action") == "skip"


def test_switch_off_falls_back_to_skip(monkeypatch):
    monkeypatch.setattr(ac, "RESTORE_AFTER_ENABLED", False)
    _, g = ac.neutralize_destructive_spec(_spec("/profile/password"))
    assert g.get("action") == "skip"


def test_switch_reads_env():
    """开关从环境变量读取（在 import 时求值）。

    必须在子进程里验：直接 importlib.reload 会把 attack_context 的模块级
    DESTRUCTIVE_GUARD_EVENTS 重新绑定成新列表，而其它测试模块持有的是旧引用，
    会导致 test_destructive_operation_guard 的事件计数用例在合跑时莫名失败。
    """
    import subprocess
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = ("import os; os.environ['SAST_AI_RESTORE_AFTER']='0'; "
            "import src.iast.attack_context as ac; print(ac.RESTORE_AFTER_ENABLED)")
    proc = subprocess.run([sys.executable, "-c", code], cwd=root,
                          capture_output=True, text=True, timeout=120)
    assert "False" in (proc.stdout or ""), (proc.stdout, proc.stderr)


# ---------------- business_logic.verify 层的强制回滚契约 ----------------

class _FakeSvc:
    """只暴露 verify 会用到的接口；用 restored/note 模拟回滚结果。"""

    def __init__(self, baseline, restored, note="", dispatch_result=None):
        self._baseline = baseline
        self._restored = restored
        self._note = note
        self._dispatch_result = dispatch_result or {
            "confirmed": True, "status_code": 302, "response_summary": "status=302",
        }
        self.dispatched = False

    @contextmanager
    def restorable_profile(self, target, accounts, spec):
        st = {"rid": "3", "baseline": self._baseline, "restored": None, "note": ""}
        try:
            yield st
        finally:
            st["restored"] = self._restored
            st["note"] = self._note

    def replay_bola(self, trigger_spec, target, accounts=None):
        self.dispatched = True
        return dict(self._dispatch_result)


def _run_verify(monkeypatch, fake):
    from src.iast import business_logic as bl
    monkeypatch.setattr(bl, "D1Service", lambda **kw: fake)
    return bl.verify("bola", _spec("/profile/password"), {"service_url": "http://x"},
                     accounts={"victim": {"user_id": 3}})


def test_no_baseline_means_no_dispatch(monkeypatch):
    """取不到基线就绝不投放 —— 这是 restore_after 的第一条硬契约。"""
    fake = _FakeSvc(baseline=None, restored=None)
    res = _run_verify(monkeypatch, fake)
    assert fake.dispatched is False
    assert res["confirmed"] is False
    assert res["verdict"] == "no_restore_baseline"
    assert res["restore"]["attempted"] is False


def test_restore_ok_keeps_verdict(monkeypatch):
    fake = _FakeSvc(baseline={"role": "USER", "id": 3}, restored=True, note="已回滚")
    res = _run_verify(monkeypatch, fake)
    assert fake.dispatched is True
    assert res["restore"]["ok"] is True
    assert res["confirmed"] is True


def test_restore_failure_overrides_confirmed(monkeypatch):
    """回滚失败必须把 confirmed 打回 False：不留持久变更优先于取证。"""
    fake = _FakeSvc(baseline={"role": "USER", "id": 3},
                    restored=False, note="回滚后仍有字段与基线不一致：role")
    res = _run_verify(monkeypatch, fake)
    assert fake.dispatched is True
    assert res["confirmed"] is False
    assert res["verdict"] == "restore_failed"
    assert "role" in res["reason"]


# ---------------- 回滚原语本身 ----------------

def test_restore_target_rid_skips_pool_placeholder():
    from src.application.d1_service import D1Service
    rid = D1Service._restore_target_rid(
        {"victim": {"user_id": "VICTIM_FROM_POOL"}}, {"victim_resource_id": "VICTIM_FROM_POOL"})
    assert rid == ""
    rid2 = D1Service._restore_target_rid({"victim": {"user_id": "VICTIM_FROM_POOL"},
                                          "attacker": {"user_id": 2}}, {})
    assert rid2 == "2"


def test_profile_restore_reports_field_mismatch(monkeypatch):
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    base = {"role": "USER", "balance": 88.0}
    after = {"role": "ADMIN", "balance": 88.0}
    monkeypatch.setattr(svc, "_profile_snapshot", lambda t, a, r: after)
    monkeypatch.setattr(svc, "_send_one", lambda *a, **kw: None)
    ok, detail = svc._profile_restore({"service_url": "http://x"}, {}, "3", base)
    assert ok is False
    assert "role" in detail


# ---------------- R26 顺带修掉的两处真实缺陷 ----------------


def test_replay_bola_injects_new_password_into_attack(monkeypatch):
    """回归守卫：/profile/password 必须把新密码注入攻击请求。

    此前 endpoint 被 lstrip("/") 后仍用 "/profile/password" in ep 匹配，恒为 False，
    新密码从未发出 → 改密没发生 → 登录差分恒为「改前=改后」→ #24 永不确认。
    """
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    calls = []

    class _R:
        reached = True
        status_code = 302
        body = ""
        response_summary = "status=302"

    def fake_send(method, url, query, headers, cookies, body, ct):
        calls.append((method, url, dict(query or {}), body if isinstance(body, dict) else None))
        return _R()

    monkeypatch.setattr(svc, "_send_one", fake_send)
    monkeypatch.setattr(svc, "_resolve_victim_identity",
                        lambda t, s, a: {"victim_resource_id": "1", "victim_markers": []})
    monkeypatch.setattr(svc, "_confirm_authz_hook",
                        lambda *a, **k: {"authz_hook_confirmed": False,
                                         "authz_hook_objects": [], "authz_hook_events": 0})
    spec = {"target_endpoint": "/profile/password", "http_method": "POST",
            "param_name": "id", "param_location": "query"}
    svc.replay_bola(spec, {"service_url": "http://t"},
                    accounts={"victim": {"username": "admin"}, "attacker": {"username": "alice"}})
    attack = [c for c in calls if c[1].endswith("/profile/password")]
    assert attack, calls
    sent = {**attack[0][2], **(attack[0][3] or {})}
    assert "password" in sent, sent
    assert sent["password"] != ""


def test_self_elevation_uid_prefers_attacker(monkeypatch):
    """自提升的对象必须是攻击者自己 —— 拿（常已是 ADMIN 的）受害者当对象，role 差分恒无变化。"""
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    monkeypatch.setattr(svc, "_resolve_uid_by_username",
                        lambda b, u, h=None, c=None: "2" if u == "alice" else "")
    assert svc._self_elevation_uid("http://t", {"attacker": {"username": "alice"},
                                                "victim": {"username": "admin"}}) == "2"


def test_resolve_victim_identity_overrides_for_self_elevation(monkeypatch):
    """即便 spec 已登记 victim_resource_id，自提升仍以攻击者为对象。

    否则「投放打攻击者、回滚打受害者」错位，改动会被留在靶标上（实测踩到过）。
    """
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    monkeypatch.setattr(svc, "_self_elevation_uid", lambda b, a, h=None, c=None: "2")
    out = svc._resolve_victim_identity(
        {"service_url": "http://t"},
        {"target_endpoint": "/profile/update", "victim_resource_id": "1"},
        {"attacker": {"username": "alice"}, "victim": {"username": "admin"}})
    assert out["victim_resource_id"] == "2"


# ---------------- 覆盖面的守卫：非业务通道也必须受保护 ----------------


def _svc_with_spies(monkeypatch, baseline):
    from src.application.d1_service import D1Service
    from src.iast.orchestrator import DastImpact
    svc = D1Service(db=None)
    seen = {"attack": 0, "restore": 0, "snapshot": 0}
    # 打桩掉会真发请求的解析链，避免测试去打 http://t（重试+退避会拖很久）
    monkeypatch.setattr(svc, "_resolve_victim_identity",
                        lambda t, s, a: {"victim_resource_id": "2", "victim_markers": []})
    monkeypatch.setattr(svc, "_profile_snapshot",
                        lambda t, a, r: (seen.__setitem__("snapshot", seen["snapshot"] + 1),
                                         baseline)[1])
    monkeypatch.setattr(svc, "_profile_restore",
                        lambda t, a, r, b: (seen.__setitem__("restore", seen["restore"] + 1),
                                            (True, "ok"))[1])
    monkeypatch.setattr(svc, "_replay_attack",
                        lambda s, t, sess=None, acc=None: (
                            seen.__setitem__("attack", seen["attack"] + 1),
                            DastImpact(reached=True, status_code=200))[1])
    return svc, seen


def test_replay_protects_non_business_channel(monkeypatch):
    """category 为空的 spec 走 _replay_attack，同样必须被回滚包住。

    run 17 实测：这条通道此前完全没保护，把 alice 留在了 ADMIN。
    """
    svc, seen = _svc_with_spies(monkeypatch, {"role": "USER"})
    spec = {"target_endpoint": "/profile/update", "http_method": "POST",
            "param_name": "id", "category": ""}
    svc.replay(spec, {"service_url": "http://t"}, accounts={"attacker": {"username": "alice"}})
    assert seen["attack"] == 1
    assert seen["restore"] == 1


def test_replay_skips_dispatch_without_baseline(monkeypatch):
    svc, seen = _svc_with_spies(monkeypatch, None)
    spec = {"target_endpoint": "/profile/update", "http_method": "POST",
            "param_name": "id", "category": ""}
    res = svc.replay(spec, {"service_url": "http://t"},
                     accounts={"attacker": {"username": "alice"}})
    assert seen["attack"] == 0
    assert res.blocked is True


def test_restorable_profile_is_reentrant(monkeypatch):
    """内层包装复用外层状态：不重复取快照、不重复回滚（否则会把已投放状态当成基线）。"""
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    seen = {"restore": 0, "snapshot": 0}
    monkeypatch.setattr(svc, "_resolve_victim_identity",
                        lambda t, s, a: {"victim_resource_id": "2", "victim_markers": []})
    monkeypatch.setattr(svc, "_profile_snapshot",
                        lambda t, a, r: (seen.__setitem__("snapshot", seen["snapshot"] + 1),
                                         {"role": "USER"})[1])
    monkeypatch.setattr(svc, "_profile_restore",
                        lambda t, a, r, b: (seen.__setitem__("restore", seen["restore"] + 1),
                                            (True, "ok"))[1])
    spec = {"target_endpoint": "/profile/update"}
    with svc.restorable_profile({"service_url": "http://t"}, {}, spec) as outer:
        with svc.restorable_profile({"service_url": "http://t"}, {}, spec) as inner:
            assert inner is outer
    assert seen["snapshot"] == 1
    assert seen["restore"] == 1


def test_profile_restore_ok_when_identical(monkeypatch):
    from src.application.d1_service import D1Service
    svc = D1Service(db=None)
    base = {"role": "USER", "balance": 88.0}
    monkeypatch.setattr(svc, "_profile_snapshot", lambda t, a, r: dict(base))
    monkeypatch.setattr(svc, "_send_one", lambda *a, **kw: None)
    ok, detail = svc._profile_restore({"service_url": "http://x"}, {}, "3", base)
    assert ok is True
    assert "一致" in detail
