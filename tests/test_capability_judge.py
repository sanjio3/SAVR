"""安全能力识别层的回归锁定（族标错的通用解法）。

每一条都是 r60 上实测踩出来的，放宽任何一条都会让能力层退化成噪声：

1. Session 写入只有当**写进去的值来自外部输入**才算危险 —— 真实项目里
   `session.setAttribute("k", 安全随机值)` 完全正常，出现即判危险会把 359 条
   weak_random 抑制全部无意义地否决掉；
2. 危险信号**不认**「字符串拼进了 sink」—— 那是绝大多数用例的正常形态，
   拿它当否决条件会把精确率从 62.62% 打回 58.76%（纯 FP 回归，零 TP 收益）；
3. 能力族优先级：越"到处都有"的能力排越后（getWriter() 几乎每个 servlet 都有，
   排在前面会把 1774 个用例一律判成 xss，含全部 sqli 真漏洞）；
4. 与本条 spec 同族的能力要跳过（同一条判据不许用两次）。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.core.capability_judge import (  # noqa: E402
    capability_family_of, danger_capabilities, safe_capabilities, supports,
)

# 值来自 SecureRandom ⇒ 安全（OWASP weakrand 安全变体的真实形态）
SESSION_SAFE = """
String rememberMeKey = Integer.toString(java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99));
request.getSession().setAttribute(cookieName, rememberMeKey);
"""

# 值来自 request header ⇒ trust_boundary 真漏洞（BenchmarkTest00321 的真实形态）
SESSION_TAINTED = """
String param = request.getHeader("p");
String bar = param;
request.getSession().putValue(bar, "10340");
"""

CONCAT_ONLY = """
String q = "SELECT * FROM t WHERE a = '" + param + "'";
stmt.executeQuery(q);
"""

XSS_ENCODED_WITH_BAD_COOKIE = """
String bar = ESAPI.encoder().encodeForHTML(param);
Cookie c = new Cookie("k", "v");
c.setSecure(false);
response.addCookie(c);
"""


def test_session_write_of_safe_value_is_not_danger():
    """SecureRandom 生成的 key 写进 session 是正常写法，不许否决。"""
    assert danger_capabilities(SESSION_SAFE) == []


def test_session_write_of_external_value_is_danger():
    """外部输入（经一层赋值）写进 session ⇒ trust_boundary，必须否决。"""
    assert "session_write" in danger_capabilities(SESSION_TAINTED)


def test_string_concat_alone_is_not_a_danger_signal():
    """「字符串拼进了 sink」不是实锤配置错误，不能拿它否决（会打回 58.76%）。"""
    assert danger_capabilities(CONCAT_ONLY) == []


def test_cross_capability_danger_is_detected():
    """输出已编码（xss 判定正确）但 Cookie 关了 secure ⇒ 真实问题在别处。"""
    assert "cookie_flag" in danger_capabilities(XSS_ENCODED_WITH_BAD_COOKIE)
    assert "output_encoding" in safe_capabilities(XSS_ENCODED_WITH_BAD_COOKIE)


def test_skip_family_avoids_double_counting():
    """同族的能力要跳过：xss 的判定自己负责 output_encoding，不该被别的族否决。"""
    src = "String a = Math.random() + \"\";"
    assert "rng" in danger_capabilities(src)
    assert danger_capabilities(src, skip_family="weak_random") == []


def test_capability_family_prefers_specific_capability_over_output():
    """SQL 执行能力比「有输出 API」特异得多 —— 不能被 getWriter() 带偏成 xss。"""
    src = "stmt.executeQuery(q); response.getWriter().println(q);"
    fam, ev = capability_family_of(src)
    assert fam == "sql_injection", (fam, ev)


def test_capability_family_empty_when_nothing_detected():
    assert capability_family_of("int x = 1;") == ("", [])


def test_supports_family_check():
    assert supports("sql_injection", "stmt.executeQuery(q);") is True
    assert supports("sql_injection", "int x = 1;") is False
    # 没登记能力的族不做自洽校验（否则全是噪声）
    assert supports("business_logic", "int x = 1;") is True
