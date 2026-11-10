"""四项靶场健康度 SAVR 侧通用修法的回归守卫（2026-09-08 落地）。

覆盖：
- Fix #1 自适应并发 + 熔断自动复位（_AdaptiveConcurrencyGate / _is_target_unhealthy_impact）
- Fix #2 canary 类型感知放置（D1Service._canary_for_param 不把 canary 注入 Long 型参数）
- Fix #4 靶场不健康标记（DastImpact.target_unhealthy 与 _is_target_unhealthy_impact 区分）

不碰真实网络与靶场；纯函数 + 注入探测。
"""
import time

from src.iast.orchestrator import (
    DastImpact,
    _AdaptiveConcurrencyGate,
    _is_target_unhealthy_impact,
)


# ---------------- Fix #1：自适应并发 + 熔断自动复位 ----------------
def test_adaptive_gate_trips_on_high_error_rate():
    """错误率超阈值（窗口内 50%+ 失败）→ 熔断置位。"""
    states = {"ready": False}

    def probe(_t):
        return {"ready": states["ready"]}

    gate = _AdaptiveConcurrencyGate(
        probe, {"url": "x"}, initial=4, min_w=1, max_w=8,
        trip_rate=0.5, window=8, max_wait=5.0, sleep_fn=lambda s: None,
    )
    for _ in range(6):
        gate.record(False)
    assert gate.tripped is True, "高错误率下应熔断"


def test_adaptive_gate_recovers_after_probe_healthy():
    """熔断后健康探针恢复 → wait_if_tripped 自动复位续跑（非永久阻断）。"""
    states = {"ready": False}

    def probe(_t):
        return {"ready": states["ready"]}

    gate = _AdaptiveConcurrencyGate(
        probe, {"url": "x"}, initial=4, min_w=1, max_w=8,
        trip_rate=0.5, window=8, max_wait=5.0, sleep_fn=lambda s: None,
    )
    for _ in range(6):
        gate.record(False)
    assert gate.tripped is True
    states["ready"] = True  # 靶场恢复
    gate.wait_if_tripped()
    assert gate.tripped is False, "健康探针恢复后熔断应自动复位"
    assert gate.current_workers() >= 1


def test_adaptive_gate_forced_reset_on_timeout():
    """探针始终不健康但超过最大等待 → 强制复位续跑，避免卡死整轮扫描。"""
    def probe_down(_t):
        return {"ready": False}

    gate = _AdaptiveConcurrencyGate(
        probe_down, {"url": "x"}, initial=4, min_w=1, max_w=8,
        trip_rate=0.5, window=8, max_wait=0.05, sleep_fn=lambda s: None,
    )
    for _ in range(6):
        gate.record(False)
    assert gate.tripped is True
    gate.wait_if_tripped()  # 探针永远不恢复，但 max_wait 极小 → 强制复位
    assert gate.tripped is False, "超时后必须强制复位，不能卡死"


def test_adaptive_gate_ramps_up_on_steady_success():
    """持续成功后并发缓慢爬升（不抖动误升）。"""
    gate = _AdaptiveConcurrencyGate(
        lambda _t: {"ready": True}, {"url": "x"}, initial=2, min_w=1, max_w=6,
        trip_rate=0.5, window=24, max_wait=5.0, sleep_fn=lambda s: None,
    )
    for _ in range(12):
        gate.record(True)
    assert gate.current_workers() > 2, "稳态成功后并发应爬升"


def test_is_target_unhealthy_impact_classifies():
    """区分「靶场不健康」与「spec 级阻断 / 真实无证据」。"""
    # 5xx 响应 → 靶场不健康
    assert _is_target_unhealthy_impact(DastImpact(status_code=500)) is True
    # 连接异常文本 → 靶场不健康
    assert _is_target_unhealthy_impact(DastImpact(error="Connection refused: target down")) is True
    # spec 级阻断（端点非法/路由缺失）不是靶场问题
    assert _is_target_unhealthy_impact(DastImpact(blocked=True, error="missing_route")) is False
    # 正常到达 → 非不健康
    assert _is_target_unhealthy_impact(DastImpact(reached=True, status_code=200)) is False
    # 生产者显式标记优先于文本匹配（2026-09-22：d1_service 改用 is_connection_level_failure
    # 收紧置位口径后，错误文本不再含旧 marker，若本谓词忽略该字段就会把已判定的不健康读成健康）
    assert _is_target_unhealthy_impact(DastImpact(target_unhealthy=True)) is True
    # blocked 仍优先于显式标记：未发流量的 spec 级阻断不参与闸门退让
    # （orchestrator 未就绪分支的 blocked=True+target_unhealthy=True 不经本谓词，见其 docstring）
    assert _is_target_unhealthy_impact(
        DastImpact(blocked=True, error="missing_route", target_unhealthy=True)
    ) is False


# ---------------- Fix #2：canary 类型感知放置 ----------------
def test_canary_type_aware_numeric_param_uses_typed_marker():
    """Long/数值型参数：canary 退化为 typed（合法数值形态 + 指纹），不注入字面字符串。"""
    from src.application.d1_service import D1Service

    svc = D1Service()
    spec = {"family": "sqli", "param_type": "long"}
    out = svc._canary_for_param(spec, "productId", "s4st41LITERAL_XSS_PAYLOAD")
    assert out != "s4st41LITERAL_XSS_PAYLOAD", "数值参数不应注入字面 canary（会被类型绑定拒绝 → 400/500）"
    assert isinstance(out, str) and out.strip(), "typed canary 必须是非空字符串"


def test_canary_type_aware_string_param_keeps_literal():
    """String 参数：保留字面 canary（流向 sink 的可达性证据不变）。"""
    from src.application.d1_service import D1Service

    svc = D1Service()
    spec = {"family": "sqli"}  # 无 param_type，param_name 非数值型
    out = svc._canary_for_param(spec, "name", "s4st41LITERAL_XSS_PAYLOAD")
    assert out == "s4st41LITERAL_XSS_PAYLOAD", "String 参数应保留字面 canary"


# ---------------- Fix #4：靶场不健康标记（非 no_evidence）----------------
def test_dast_impact_target_unhealthy_field():
    """D1 重放因靶场 5xx/连接异常失败时，产出 target_unhealthy=True 的 DastImpact。"""
    imp = DastImpact(
        error="500 transient 5xx after replay load",
        provisional=True,
        target_unhealthy=True,
    )
    assert imp.target_unhealthy is True
    assert imp.to_dict().get("target_unhealthy") is True
    # 下游应据 target_unhealthy 标 target-unhealthy 而非 no_evidence
    assert _is_target_unhealthy_impact(imp) is True
