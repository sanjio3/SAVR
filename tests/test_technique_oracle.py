"""注入技术判据（technique_oracle）的回归锁（2026-11-02）。

背景：现有判定只认「canary 到达 sink」，对**盲注/反射类**不成立。
实测 本轮 13 个未确认真值文件里 5 个（sqli/xss/xxe/shiro/jwt）的 canary
明明到了业务 sink（`Files.readAllBytes` / `JdbcTemplate`），却因「响应里没有明显危害」
被判 unconfirmed。而同族不同技术的观测方式本来就不同：

    sqli 报错 → 响应体里的 DB 错误特征
    sqli 布尔 → 真/假两个载荷的响应差异
    sqli 时间 → 含 SLEEP 的那次耗时显著高于基线
    xss 反射  → 响应体里出现原始载荷
    ssti     → 出现求值结果 49 且原文 7*7 不在
    xxe/穿越 → 响应体出现 /etc/passwd 特征

本文件锁两件事：**技术判定要认全**（尤其布尔盲注的载荷常省略闭合引号）、
**判据只认硬观测**（不能把「像是有漏洞」判成确认）。
"""
from __future__ import annotations

import pytest

from src.iast.technique_oracle import detect_technique, judge_attempts, supported_techniques


@pytest.mark.parametrize("payload,expect", [
    ("' OR '1'='1", "sqli_bool_true"),          # 省略末尾闭合引号（真实载荷常见形态）
    ("' OR '1'='2", "sqli_bool_false"),
    ("1' OR 1=1--", "sqli_bool_true"),
    ("' OR 1=2--", "sqli_bool_false"),
    ("1 AND SLEEP(3)--", "sqli_time"),
    ("1'; WAITFOR DELAY '0:0:3'--", "sqli_time"),
    ("1' AND extractvalue(1,concat(0x7e))--", "sqli_error"),
    ("1 UNION SELECT username,password FROM users--", "sqli_union"),
    ("1'; DROP TABLE users--", "sqli_stacked"),
    ("<script>alert(1)</script>", "xss_reflected"),
    ('<img src=x onerror=alert(1)>', "xss_reflected"),
    ("${7*7}", "ssti_eval"),
    ("{{7*7}}", "ssti_eval"),
    ('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>&e;', "xxe_echo"),
    ("%0d%0aX-Injected:1", "crlf_header"),
    ("http://127.0.0.1:9/sast-probe", "ssrf_echo"),
    ("${jndi:ldap://127.0.0.1:9/x}", "jndi_lookup"),
    ("../../../../etc/passwd", "path_traversal_echo"),
])
def test_detect_technique(payload, expect):
    assert detect_technique("sql_injection", payload) == expect


def test_error_based_sqli_confirms_on_db_error_signature():
    atts = [{"attempt_no": 1, "payload": "1' AND extractvalue(1)--",
             "resp_body_head": "You have an error in your SQL syntax; check the manual",
             "elapsed_ms": 20}]
    ok, tech, ev = judge_attempts("sql_injection", atts, 20)
    assert ok and tech == "sqli_error" and "signature" in ev


def test_boolean_blind_needs_a_real_difference():
    """真/假两次响应长度差异 ≥15% 才算；差异小说明注入没生效。"""
    same = [{"attempt_no": 1, "payload": "' OR '1'='1", "resp_body_head": "same", "elapsed_ms": 20},
            {"attempt_no": 2, "payload": "' OR '1'='2", "resp_body_head": "same", "elapsed_ms": 20}]
    assert judge_attempts("sql_injection", same, 20)[0] is False

    diff = [{"attempt_no": 1, "payload": "' OR '1'='1", "resp_body_head": "admin page content", "elapsed_ms": 20},
            {"attempt_no": 2, "payload": "' OR '1'='2", "resp_body_head": "x", "elapsed_ms": 20}]
    ok, tech, ev = judge_attempts("sql_injection", diff, 20)
    assert ok and tech == "sqli_boolean" and ev["ratio"] >= 0.15


def test_time_blind_needs_real_delay_not_noise():
    """耗时必须 ≥2s 且 >2× 基线；普通慢响应不算。"""
    slow_noise = [{"attempt_no": 1, "payload": "1 AND SLEEP(0)--", "resp_body_head": "", "elapsed_ms": 900}]
    assert judge_attempts("sql_injection", slow_noise, 800)[0] is False

    real = [{"attempt_no": 1, "payload": "1 AND SLEEP(3)--", "resp_body_head": "", "elapsed_ms": 3200}]
    ok, tech, ev = judge_attempts("sql_injection", real, 20)
    assert ok and tech == "sqli_time" and ev["elapsed_s"] >= 3


def test_xss_needs_verbatim_reflection():
    hit = [{"attempt_no": 1, "payload": "<script>alert(1)</script>",
            "resp_body_head": "<html><script>alert(1)</script></html>", "elapsed_ms": 10}]
    assert judge_attempts("xss", hit, 10)[0] is True

    escaped = [{"attempt_no": 1, "payload": "<script>alert(1)</script>",
                "resp_body_head": "&lt;script&gt;alert(1)&lt;/script&gt;", "elapsed_ms": 10}]
    assert judge_attempts("xss", escaped, 10)[0] is False, "转义后不能算反射"


def test_ssti_needs_evaluated_result_not_echo():
    hit = [{"attempt_no": 1, "payload": "${7*7}", "resp_body_head": "result: 49", "elapsed_ms": 10}]
    assert judge_attempts("ssti", hit, 10)[0] is True

    echo = [{"attempt_no": 1, "payload": "${7*7}", "resp_body_head": "result: ${7*7}", "elapsed_ms": 10}]
    assert judge_attempts("ssti", echo, 10)[0] is False, "原样回显不是求值"


def test_no_attempts_is_not_a_confirmation():
    assert judge_attempts("sql_injection", [], 10)[0] is False


def test_supported_techniques_covers_all_families():
    """族 → 技术清单必须存在，否则「按技术选判据」无从下手。"""
    for fam in ("sql_injection", "xss", "xxe", "ssti", "ssrf", "crlf_injection", "path_traversal"):
        assert supported_techniques(fam), fam
