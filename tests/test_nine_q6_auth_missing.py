"""净化器判定九问 — Q6：401 + WWW-Authenticate 应判 auth_missing（走双账户重放），而非 blocked/auth_denied。

背景（净化器判定9问分析-本轮.md §Q6）：
- 401 + WWW-Authenticate 是服务端「你没登录，来认证」的标准挑战，是预期行为（未带凭证的探测
  本就该被挡），不是「攻击被 WAF/过滤器拦截」。当前把它和 403、WAF 拒绝词混为一谈，会高估鉴权
  覆盖率，且未带凭证的探测被误读成 blocked/no_evidence，永远 success=0。
- 修复：_classify_request_state 对 401 + WWW-Authenticate 返回 auth_missing；403 与 401 无挑战头
  仍为 auth_denied；i2_feedback.classify_runtime_evidence 同步把 401+WWW-Authenticate 判 auth_missing。
- auth_missing 已登记进 RUNTIME_FIVE_CLASS 与 _FIVE_CLASS_ACTIONS（repush_endpoint），路由到
  「带会话/双账户重放」，不当 blocked。
"""
import pytest

from src.application.d1_service import D1Service
from src.agents.i2_feedback import classify_runtime_evidence, AUTH_MISSING


def test_q6_401_with_www_authenticate_is_auth_missing():
    headers = {"WWW-Authenticate": 'Basic realm="app"'}
    assert D1Service._classify_request_state(401, True, headers) == "auth_missing"


def test_q6_401_case_insensitive_header_name():
    headers = {"www-authenticate": 'Bearer realm="app"'}
    assert D1Service._classify_request_state(401, True, headers) == "auth_missing"


def test_q6_401_without_www_authenticate_is_auth_denied():
    # 401 无标准挑战头 —— 非标准，按被拦截（auth_denied/blocked 路径）处理，不当 auth_missing。
    assert D1Service._classify_request_state(401, True, {}) == "auth_denied"
    assert D1Service._classify_request_state(401, True, None) == "auth_denied"


def test_q6_403_is_auth_denied_not_auth_missing():
    # 403 已登录但无权限，不应混进鉴权墙 auth_missing。
    headers = {"WWW-Authenticate": 'Basic realm="app"'}
    assert D1Service._classify_request_state(403, True, headers) == "auth_denied"


def test_q6_other_states_unchanged():
    assert D1Service._classify_request_state(200, True, {}) == "accepted"
    # 404 路由缺失在 d1_service 层归 "other"（i2_feedback 层再细分为 route_unreachable）；
    # 405 属请求装配/方法错误，归 malformed_request。
    assert D1Service._classify_request_state(404, True, {}) == "other"
    assert D1Service._classify_request_state(405, True, {}) == "malformed_request"
    assert D1Service._classify_request_state(500, True, {}) == "server_error"
    assert D1Service._classify_request_state(None, False, {}) == "no_response"


def test_q6_classify_runtime_evidence_401_www_authenticate():
    # i2_feedback 的运行时证据分类器也须把 401 + WWW-Authenticate 判 auth_missing。
    ev = {"status_code": 401, "headers": {"WWW-Authenticate": 'Basic realm="x"'},
          "response_summary": "please log in"}
    assert classify_runtime_evidence(ev) == AUTH_MISSING


def test_q6_auth_missing_routes_to_dual_account_replay():
    # auth_missing 已在五类动作表里登记 repush_endpoint（带会话重推），不当 blocked 的 escalate_variant。
    from src.agents.i2_feedback import _FIVE_CLASS_ACTIONS
    assert AUTH_MISSING in _FIVE_CLASS_ACTIONS
    assert _FIVE_CLASS_ACTIONS[AUTH_MISSING] == ["repush_endpoint"]
