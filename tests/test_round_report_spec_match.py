"""2026-09-22 落地项的回归测试。

覆盖四件事：
  1. ``_spec_match`` 三态拆分：no-arrival / no-injectable-param / 多候选择优；
  2. 黄金项「IAST 无 sink 可断言」的标注（CSRF）；
  3. D1 的 cookie 值净化与「连接级失败」判据（target_unhealthy 误标根因链的源头修复）；
  4. orchestrator ``_looks_like_target_down`` 收紧后不再被裸数字子串误命中。
"""
import unittest

from src.api.routers.round_report import (
    _GOLDEN_NO_IAST_SINK,
    _SPEC_IAST_RANK,
    _spec_injectable,
    _spec_match,
)
from src.application.d1_service import is_connection_level_failure, sanitize_cookie_value
from src.iast.orchestrator import _looks_like_target_down


def _spec(**kw):
    base = {
        "id": 1, "family": "xss", "target_endpoint": "/xss/reflect",
        "verification_status": "unconfirmed", "iast_state": "no-arrival",
        "business_logic_category": "", "param_name": "xss",
        "representative_request_params_json": "[]",
    }
    base.update(kw)
    return base


class SpecMatchThreeStateTests(unittest.TestCase):
    def test_no_param_spec_is_not_reported_as_no_arrival(self):
        """spec 连注入点都没有 ⇒ canary 从未投放，不能读成 no-arrival（探针漏命中）。"""
        specs = [_spec(param_name="", representative_request_params_json="[]")]
        sm = _spec_match(["xss"], ["xss"], specs)
        self.assertIsNotNone(sm)
        self.assertEqual(sm[2], "no-injectable-param")
        self.assertFalse(sm[6])

    def test_representative_params_make_spec_injectable(self):
        specs = [
            _spec(
                param_name="",
                representative_request_params_json='[{"name": "url", "location": "query"}]',
            )
        ]
        sm = _spec_match(["xss"], ["xss"], specs)
        self.assertEqual(sm[2], "no-arrival")
        self.assertTrue(sm[6])

    def test_prefers_arrival_evidence_over_no_arrival(self):
        """多候选择优：有抵达证据的那条必须胜出（#13 Log4j / #19 SpEL 的教训）。"""
        specs = [
            _spec(id=100, iast_state="no-arrival"),
            _spec(id=200, iast_state="sink-reached-probe", verification_status="confirmed_exploitable"),
        ]
        sm = _spec_match(["xss"], ["xss"], specs)
        self.assertEqual(sm[4], 200)
        self.assertEqual(sm[5], 2)

    def test_injectable_candidate_beats_non_injectable_when_both_weak(self):
        """两条都弱时，选「投放过、但没到」的那条 —— 信息量比「压根没注入点」大。"""
        specs = [
            _spec(id=1, param_name="", representative_request_params_json="[]"),
            _spec(id=2, param_name="xss"),
        ]
        sm = _spec_match(["xss"], ["xss"], specs)
        self.assertEqual(sm[4], 2)
        self.assertEqual(sm[2], "no-arrival")

    def test_real_arrival_is_never_downgraded(self):
        """即便 spec 没有注入点，只要它真的抵达了，就不许改判成 no-injectable-param。"""
        specs = [_spec(iast_state="sink-reached-probe", param_name="", representative_request_params_json="[]")]
        sm = _spec_match(["xss"], ["xss"], specs)
        self.assertEqual(sm[2], "sink-reached-probe")

    def test_rank_table_covers_new_states(self):
        self.assertIn("no-injectable-param", _SPEC_IAST_RANK)
        self.assertIn("no-iast-sink", _SPEC_IAST_RANK)
        self.assertLess(_SPEC_IAST_RANK["no-injectable-param"], _SPEC_IAST_RANK["no-arrival"])

    def test_csrf_is_declared_iast_inapplicable(self):
        """CSRF 是配置级控制缺失，IAST 无 sink 可断言 —— 必须显式声明，不靠人记。"""
        self.assertIn("CSRF", _GOLDEN_NO_IAST_SINK)
        self.assertIn("配置级控制缺失", _GOLDEN_NO_IAST_SINK["CSRF"])
        self.assertIn("DAST", _GOLDEN_NO_IAST_SINK["CSRF"])

    def test_injectable_helper_handles_broken_json(self):
        self.assertFalse(_spec_injectable({"param_name": "", "representative_request_params_json": "{"}))
        self.assertFalse(_spec_injectable({"param_name": "", "representative_request_params_json": "null"}))


class CookieSanitizeTests(unittest.TestCase):
    def test_strips_the_four_characters_that_actually_break_the_cookie(self):
        """实测（Tomcat 8.5，带会话 curl 打 /xss/stored/show）：

        A"B → 400；A,B → 400；A\\B → 400；"A B" → 400；
        而 A<B / A>B / A(B / A[1]B / A:B / A/B / A@B 全部 200。
        即真正的破坏字符是 RFC6265 cookie-octet 之外的那几个（双引号/逗号/分号/反斜杠/空白/控制符），
        不是「所有非字母数字」。分号那例虽返回 200，但值被截断在前半段，同样必须净化。
        """
        raw = 's4st41ebbebe1cc5cd727a"><svg0a973df9'
        out = sanitize_cookie_value(raw)
        for bad in ('"', ",", ";", "\\", " ", "\t", "\r", "\n"):
            self.assertNotIn(bad, out)
        # 这两个是合法 cookie-octet，不该被乱改（乱改会破坏 payload 语义）
        self.assertIn("<", out)
        self.assertIn(">", out)

    def test_preserves_identity_segment(self):
        """身份段是 I1 关联的钥匙，必须原样保留。"""
        raw = 's4st41ebbebe1cc5cd727a"><svg0a973df9'
        self.assertTrue(sanitize_cookie_value(raw).startswith("s4st41ebbebe1cc5cd727a"))

    def test_plain_value_is_untouched(self):
        self.assertEqual(sanitize_cookie_value("s4st417168ad0e5800f564PAYLOADbd506aa6"),
                         "s4st417168ad0e5800f564PAYLOADbd506aa6")

    def test_empty_and_none(self):
        self.assertEqual(sanitize_cookie_value(""), "")
        self.assertEqual(sanitize_cookie_value(None), "")


class ConnectionLevelFailureTests(unittest.TestCase):
    def test_transport_failures_count_as_connection_level(self):
        for msg in (
            "HTTPConnectionPool(host='127.0.0.1', port=8080): Max retries exceeded with url: /x (Caused by NewConnectionError(... Connection refused))",
            "Connection reset by peer",
            "Read timed out. (read timeout=10)",
            "RemoteDisconnected('Remote end closed connection without response')",
            "HTTPSConnectionPool: getaddrinfo failed",
        ):
            self.assertTrue(is_connection_level_failure(msg), msg)

    def test_repeated_5xx_is_not_target_unhealthy(self):
        """靶场应答了 5xx 说明它是活的 —— 可重试，不等于「靶场不健康」。

        这正是 run 26/27/28/30/31 的 target_unhealthy 误标源：旧实现无条件置位。
        """
        self.assertFalse(is_connection_level_failure("transient 5xx: 503"))
        self.assertFalse(is_connection_level_failure("transient 5xx: 500"))

    def test_payload_containing_digits_is_not_connection_level(self):
        self.assertFalse(is_connection_level_failure("400 Client Error: Bad Request for url: /x?q=500"))
        self.assertFalse(is_connection_level_failure(""))
        self.assertFalse(is_connection_level_failure(None))


class TargetDownHeuristicTests(unittest.TestCase):
    def test_real_connection_signals_still_detected(self):
        for msg in ("Connection refused", "Read timed out", "target_down", "A0 复探未就绪",
                    "target not serving"):
            self.assertTrue(_looks_like_target_down(msg), msg)

    def test_bare_digit_substrings_no_longer_match(self):
        """收紧前 "500"/"501" 是裸子串，端口号/请求 id/混淆载荷都会误命中靶场不健康。"""
        for msg in (
            "400 Client Error for url: /api/x?port=5000",
            "spec 1500 未匹配",
            "invalid payload len=1501",
            "探针路由未配置",           # 旧 markers 含 "探针"，会把探针提示当成靶场不健康
            "environment variable missing",
        ):
            self.assertFalse(_looks_like_target_down(msg), msg)


if __name__ == "__main__":
    unittest.main()
