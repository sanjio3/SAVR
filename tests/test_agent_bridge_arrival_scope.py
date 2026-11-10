"""回归锁：TAINT_FLOW 不得再单独构成「到达」，SINK_HIT 仍可（方法A 第三处，2026-10-07）。

背景（r63-verify 实测根因）：
    run 239 pathtraver-1 的 162 个「到达」spec 里 0 个带真实 sink 级断言，
    到达信号全部来自 TAINT_FLOW —— 而它的 canary_match 是 trace 级
    （请求带过 canary 即为 1）、sink_method 821 条全空。
    真 TP(00001) 与安全 FP(00063/00064) 签名完全一致 ⇒ 到达 ≠ 可利用。
    LDAP 对照实验：到达 39→94，TP 命中恒 27，精确率恒 56.2%。

判据：
    1. 带 canary + TAINT_FLOW + **无** canaryState ⇒ 不得判 sink-reached。
    2. 带 canary + SINK_HIT + 无 canaryState ⇒ 仍判 sink-reached（不能把真阳性也砍掉）。
    3. 探针显式断言 canaryState=sink-reached ⇒ 归一到 sink-reached-probe（既有行为不变）。
    4. 探针显式断言 no-arrival ⇒ 尊重判否（既有行为不变）。
    5. 开关 SAST_AI_TAINT_FLOW_AS_ARRIVAL=1 ⇒ 恢复旧行为（回滚/A-B 口径）。
    6. 探针自带 canaryScope=sink_arg 的实参级断言 ⇒ 判 sink-reached-probe。
"""
from src.api.routers.agent_bridge import _translate_probe_event
from src.iast.canary import CanaryStates

IDENT = "s4st41c97588ece1824f87"


def _ev(**kw):
    base = {
        "eventType": "SINK_HIT",
        "severity": "MEDIUM",
        "traceId": "trace-1",
        "sink": "java.io.File.<init>(File.java:1)",
        "payload": "bar",
        "context": {},
    }
    base.update(kw)
    return _translate_probe_event(base)


def test_taint_flow_without_state_is_not_arrival():
    """红线1：TAINT_FLOW + 无 canaryState 不得判 sink-reached。"""
    r = _ev(eventType="TAINT_FLOW", payload=IDENT + "-bar")
    assert r["canary"] == IDENT
    assert r["canaryState"] != CanaryStates.SINK_REACHED, (
        "TAINT_FLOW 是 trace 级信号，不得单独构成到达（r63 到达假阳性根因）")
    assert r["canaryState"] != CanaryStates.SINK_REACHED_PROBE


def test_sink_hit_without_state_still_arrival():
    """红线2：SINK_HIT 仍判到达——不能把真阳性一起砍掉。"""
    r = _ev(eventType="SINK_HIT", payload=IDENT + "-bar")
    assert r["canaryState"] == CanaryStates.SINK_REACHED


def test_probe_explicit_state_becomes_probe_reached():
    """红线3：探针显式断言 ⇒ sink-reached-probe（既有行为不变）。"""
    r = _ev(eventType="SINK_HIT", payload=IDENT, canaryState="sink-reached")
    assert r["canaryState"] == CanaryStates.SINK_REACHED_PROBE


def test_probe_explicit_no_arrival_respected():
    """红线4：探针显式判否 ⇒ 尊重，不强置（既有行为不变）。"""
    r = _ev(eventType="SINK_HIT", payload=IDENT, canaryState=CanaryStates.NO_ARRIVAL)
    assert r["canaryState"] == CanaryStates.NO_ARRIVAL


def test_sink_arg_scope_assertion_reaches():
    """红线6：实参级 canary 断言（探针新字段）⇒ 判 sink-reached-probe。"""
    r = _ev(eventType="SINK_HIT", payload=IDENT, canary=IDENT, canaryState="sink-reached")
    assert r["canaryState"] == CanaryStates.SINK_REACHED_PROBE
    assert r["canary"] == IDENT


def test_env_switch_restores_legacy(monkeypatch):
    """红线5：开关可恢复旧行为，便于回滚与 A/B 对比。"""
    import importlib
    import src.api.routers.agent_bridge as ab
    monkeypatch.setenv("SAST_AI_TAINT_FLOW_AS_ARRIVAL", "1")
    try:
        importlib.reload(ab)
        r = ab._translate_probe_event({
            "eventType": "TAINT_FLOW", "severity": "MEDIUM", "traceId": "t",
            "sink": "java.io.File.<init>", "payload": IDENT, "context": {},
        })
        assert r["canaryState"] == ab.CanaryStates.SINK_REACHED
    finally:
        monkeypatch.delenv("SAST_AI_TAINT_FLOW_AS_ARRIVAL", raising=False)
        importlib.reload(ab)
