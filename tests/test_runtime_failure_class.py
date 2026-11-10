"""2026-10-02（#BVR）：blocked 与 route_unreachable 的结构化分层判据回归测试。

背景：两者在结果终点上都表现为「没到 sink」，但成因完全不同——错放（放错位置）与
拦截（路对了被拦）。旧判据拿 reason自然语言做关键词匹配，且第一条分支含 "endpoint" /
"no-arrival" 这类极泛词，导致含 waf/blocked 的 reason 也会被抢判成 route_unreachable，
blocked→escalate_variant 分支实为不可达（variant_escalated 两轮实测恒为 0）。

本测试钉死「按可观测事实分层」的新判据：同一个 spec 的重放只有一组确定的事实
（状态码 + 响应摘要 + 到达事实 + 是否确证有害），判据不再随措辞漂移。
"""
import pytest

from src.agents import i2_feedback as i2fb


# ---------------------------------------------------------------- 结构判据
@pytest.mark.parametrize("evidence,expected", [
    # 1) 路由缺席：端点不存在，请求压根没进 controller → 错放
    ({"status_code": 404, "response_summary": "Not Found"}, "route_unreachable"),
    ({"status_code": 405, "response_summary": "Method Not Allowed"}, "route_unreachable"),
    # 2) 鉴权墙：跳登录，良性请求也进不去 → 既不是拦截也不是错放
    ({"status_code": 302, "response_summary": "redirect to /login"}, i2fb.AUTH_MISSING),
    ({"status_code": 401, "response_summary": "Unauthorized"}, i2fb.AUTH_MISSING),
    # 3) 被拦：路由活着但 payload 被拒 → 拦截（关键：区分于上面两类）
    ({"status_code": 403, "response_summary": "Forbidden"}, "blocked"),
    ({"status_code": 200, "response_summary": "Bad boy. I got u."}, "blocked"),
    # 4) 到了 sink 但没确证有害
    ({"status_code": 200, "reached": True, "iast_state": "sink-reached-probe"},
     "arrived_unconfirmed"),
    # 5) 200 但数据没到 sink
    ({"status_code": 200, "reached": False}, "param_not_arrived"),
])
def test_classify_runtime_evidence_layers(evidence, expected):
    assert i2fb.classify_runtime_evidence(evidence) == expected


def test_classify_runtime_evidence_insufficient():
    """证据不足时必须返回空串，让调用方回落到关键词，绝不硬猜。"""
    assert i2fb.classify_runtime_evidence({}) == ""
    assert i2fb.classify_runtime_evidence(None) == ""


def test_blocked_wins_over_arrival_when_not_harmful():
    """最关键的用例：现实的 /codeinject/sec 形态。

    攻击 payload 被 cmdFilter 拦（200 + "Bad boy. I got u."），同时良性 canary 到达了
    sink（reached=True），但 d2_harmful=False（框架噪声 sink，未确证有害）。
    过去这条会被算作「到达」而判非 blocked，escalate_variant 永远拿不到它；
    新判据要求判 blocked——「到达」不代表可利用，必须走出去试绕过变体。
    """
    ev = {
        "status_code": 200,
        "response_summary": "Bad boy. I got u.",
        "reached": True,
        "d2_harmful": False,
        "iast_state": "sink-reached-probe",
    }
    assert i2fb.classify_runtime_evidence(ev) == "blocked"


def test_harmful_arrival_is_not_a_failure():
    """已被确证有害且已到达 → 不是运行时失败，不该被判成 blocked/arrived_unconfirmed。"""
    ev = {"status_code": 200, "reached": True, "d2_harmful": True,
          "iast_state": "sink-reached-probe"}
    assert i2fb.classify_runtime_evidence(ev) not in ("blocked", "arrived_unconfirmed")


def test_nested_d2_shape():
    """兼容 D2 校验产物原本的嵌套形状（dast_impact_evidence / d2_verdict / iast_evidence）。"""
    ev = {
        "dast_impact_evidence": {"status_code": 403, "body": "request blocked"},
        "d2_verdict": {"harmful": False},
        "iast_evidence": {"state": "no-arrival"},
    }
    assert i2fb.classify_runtime_evidence(ev) == "blocked"


# ---------------------------------------------------------------- 关键词回退次序
def test_keyword_route_token_no_longer_hijacks_blocked():
    """回归：旧实现里 reason 提到 endpoint/no-arrival 就会抢判成 route_unreachable。

    这是 blocked→escalate_variant 永不可达的直接原因，新次序必须先判具体成因。
    """
    reason = "endpoint /codeinject/sec no-arrival: 403 waf blocked by firewall"
    assert i2fb._infer_failure_class(reason) == "blocked"


def test_keyword_auth_and_route_layers():
    assert i2fb._infer_failure_class("请求被重定向：302 未登录") == i2fb.AUTH_MISSING
    assert i2fb._infer_failure_class("路由不存在 404") == "route_unreachable"
    assert i2fb._infer_failure_class("参数 param 未命中 sink") == "param_not_arrived"


# ---------------------------------------------------------------- 端到端：决策表字面
def test_decision_table_maps_auth_missing():
    assert i2fb.AUTH_MISSING in i2fb._FIVE_CLASS_ACTIONS
    assert i2fb.AUTH_MISSING in i2fb.RUNTIME_FIVE_CLASS
    # 拦截才升变体；错放走换位置/重推，二者动作不同——证明「错放与拦截」确实分辨出来了
    assert "escalate_variant" in i2fb._FIVE_CLASS_ACTIONS["blocked"]
    assert "escalate_variant" not in i2fb._FIVE_CLASS_ACTIONS["route_unreachable"]


def test_plan_replay_adjustments_prefers_structural_evidence():
    """带结构化事实时，决策表结果必须由事实驱动，而非 reason 措辞。"""
    fb = {
        "hypothesis_id": "h1",
        # reason 故意写成会把旧判据带偏的话术
        "reason": "endpoint no-arrival，看起来像是路由问题",
        "status_code": 200,
        "response_summary": "Bad boy. I got u.",
        "d2_harmful": False,
    }
    out = i2fb.plan_replay_adjustments({i2fb.RUNTIME_OBSERVATION: [fb]})
    assert len(out) == 1
    assert out[0]["failure_class"] == "blocked"
    assert out[0]["actions"] == ["escalate_variant"]
