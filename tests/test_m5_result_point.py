"""M5 结果点比对：XSS 三态 / CRLF 响应头单开判据 / SSTI 求值对 / 语义差分正交对。

每条用例对应一条「原来判不了、现在能判」的具体缺口。改判据前先看这里——
这里挂了说明又把「没看到」当成了「没有」，或者又开始采信长度差了。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import result_point as rp  # noqa: E402
from src.agents.d2_facade import _verify_sink_result  # noqa: E402


CANARY = "s4st41a1b2c3d4e5f6"


# ── XSS 三态 ──

def test_xss_raw_echo_is_exploitable():
    payload = f"<script>alert('{CANARY}')</script>"
    r = rp.judge_xss({"attack_payload_used": payload,
                      "body": f"<div>{payload}</div>"})
    assert r["state"] == rp.REFLECTED_RAW
    assert r["matched"] is True
    assert r["definitive"] is True
    assert r["suggested_status"] == "confirmed_exploitable"


def test_xss_escaped_is_true_negative():
    """回显被 HTML 转义：这是「过滤器有效」的正向证据，不是「没看到」。"""
    payload = f"<script>alert('{CANARY}')</script>"
    r = rp.judge_xss({"attack_payload_used": payload,
                      "body": f"<div>&lt;script&gt;alert('{CANARY}')&lt;/script&gt;</div>"})
    assert r["state"] == rp.REFLECTED_ESCAPED
    assert r["matched"] is False
    assert r["definitive"] is True          # 结论，不是证据缺失
    assert r["suggested_status"] == "filtered_not_exploitable"


def test_xss_absent_routes_to_two_step():
    """响应体里根本没有 → 存储型/二阶要两步重放，绝不能判成无害。"""
    r = rp.judge_xss({"attack_payload_used": f"<script>{CANARY}</script>",
                      "body": "<html>nothing here</html>"})
    assert r["state"] == rp.ABSENT
    assert r["definitive"] is False
    assert r["next_action"] == "two_step_replay"


def test_xss_short_payload_not_matched_by_coincidence():
    """短载荷（无唯一标记）不能靠页面里恰好出现的同名字符串误判回显。"""
    assert rp.judge_xss({"attack_payload_used": "<b>x</b>",
                         "body": "<i>y</i>"})["state"] == rp.ABSENT


# ── CRLF 响应头单开判据 ──

def test_crlf_header_injected_detected():
    payload = f"vuln%0d%0aX-Sastai-Injected:%20{CANARY}"
    r = rp.judge_crlf({"attack_payload_used": payload, "body": "ok",
                       "headers": {"x-sastai-injected": CANARY, "content-type": "text/html"}})
    assert r["matched"] is True
    assert r["state"] == "header_injected"
    assert r["definitive"] is True


def test_crlf_is_not_exempted_by_missing_body_echo():
    """CRLF 的结果点是响应头：响应体没回显照样能确认（单开判据不豁免）。"""
    payload = f"vuln%0d%0aX-Sastai-Injected:%20{CANARY}"
    r = rp.judge_crlf({"attack_payload_used": payload, "body": "",
                       "headers": {"X-Sastai-Injected": CANARY}})
    assert r["matched"] is True


def test_crlf_absent_is_not_definitive():
    r = rp.judge_crlf({"attack_payload_used": f"vuln%0d%0aX-A:%20{CANARY}",
                       "body": "ok", "headers": {"content-type": "text/html"}})
    assert r["matched"] is False
    assert r["definitive"] is False


# ── SSTI 求值对 ──

def test_ssti_evaluated():
    r = rp.judge_ssti({"attack_payload_used": "hello {{7*7}}",
                       "body": "hello 49"})
    assert r["state"] == rp.EVALUATED
    assert r["matched"] is True


def test_ssti_echo_only_is_true_negative():
    """表达式原样回显 = 模板没渲染，这是真阴性不是没看到。"""
    r = rp.judge_ssti({"attack_payload_used": "hello {{7*7}}",
                       "body": "hello {{7*7}}"})
    assert r["state"] == rp.ECHO_ONLY
    assert r["matched"] is False
    assert r["definitive"] is True
    assert r["suggested_status"] == "filtered_not_exploitable"


def test_ssti_supports_multiple_engine_syntaxes():
    for expr, expected in (("${7*7}", "49"), ("#{7*7}", "49"), ("<%= 7*7 %>", "49")):
        r = rp.judge_ssti({"attack_payload_used": f"v {expr}", "body": f"v {expected}"})
        assert r["matched"] is True, expr


# ── 语义差分正交对 ──

def test_semantic_diff_victim_marker():
    r = rp.semantic_diff_pair('{"id":9,"email":"victim@x.com"}', '{"error":"forbidden"}',
                              victim_markers=["victim@x.com"])
    assert r["matched"] is True


def test_semantic_diff_status_code_differs():
    r = rp.semantic_diff_pair("ok", "forbidden", status_a=200, status_b=403)
    assert r["matched"] is True


def test_semantic_diff_structure_differs():
    r = rp.semantic_diff_pair('{"a":1}', '{"b":2}')
    assert r["matched"] is True
    assert r["structure_diff"] is True


def test_length_only_diff_is_not_trusted():
    """长度差不采信：时间戳/随机数会让长度永远在抖，采信必误判。"""
    a = '{"ts":"2026-10-03T10:00:00Z","data":"same"}'
    b = '{"ts":"2026-10-03T10:00:00.123Z","data":"same"}'
    r = rp.semantic_diff_pair(a, b)
    assert r["matched"] is False
    assert r["length_only"] is True


def test_semantic_diff_identical():
    r = rp.semantic_diff_pair('{"a":1}', '{"a":1}')
    assert r["matched"] is False


def test_evaluate_semantic_diff_from_pair_responses():
    dast = {"pair_responses": [{"body": '{"id":9}', "status_code": 200},
                               {"body": '{"error":1}', "status_code": 200}]}
    r = rp.evaluate_semantic_diff(dast)
    assert r is not None and r["matched"] is True


# ── 接入仲裁后的端到端 ──

def test_xss_escaped_beats_probe_assert():
    """结果点比对（3）盖过探针断言（2）：转义用例不得再被抬成可利用。"""
    v = _verify_sink_result(
        {"state": "sink-reached-probe",
         "matched_sink_file": "org.thymeleaf.TemplateEngine.process"},
        {"reached": True, "status_code": 200,
         "attack_payload_used": f"<script>{CANARY}</script>",
         "body": f"&lt;script&gt;{CANARY}&lt;/script&gt;"},
        "xss",
    )
    assert v["primary_channel"] == "result_point_diff"
    assert v["harmful"] is False
    assert v["result_point_state"] == rp.REFLECTED_ESCAPED


def test_xss_raw_echo_confirms():
    v = _verify_sink_result(
        {"state": "no-arrival"},
        {"reached": True, "status_code": 200,
         "attack_payload_used": f"<script>{CANARY}</script>",
         "body": f"<div><script>{CANARY}</script></div>"},
        "xss",
    )
    assert v["primary_channel"] == "result_point_diff"
    assert v["harmful"] is True


def test_crlf_without_iast_still_confirms():
    """探针没织到响应头写入点，CRLF 仍能靠响应头单开判据确认。"""
    v = _verify_sink_result(
        {"state": "no-arrival"},
        {"reached": True, "status_code": 200, "body": "ok",
         "attack_payload_used": f"v%0d%0aX-Sastai-Injected:%20{CANARY}",
         "headers": {"X-Sastai-Injected": CANARY}},
        "crlf",
    )
    assert v["primary_channel"] == "result_point_diff"
    assert v["harmful"] is True


def test_unsupported_family_has_no_result_point_channel():
    """没有对应判据的族不出结果点结论（没比对就不该有结论）。"""
    assert rp.evaluate_result_point("sqli", {"attack_payload_used": "1' OR '1'='1",
                                             "body": "error"}) is None
