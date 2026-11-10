"""Cookie 构造类 sink 的族归属守卫（2026-10-30）。

背景：探针在每个 doGet 里都会织一个 Cookie（只处理硬编码 "color"），它的
``javax.servlet.http.Cookie.<init>`` / ``setSecure`` / ``setHttpOnly`` 会以
``sink-reached-probe`` 落库。这个 sink 只对 secure_cookie 族有意义，对其它族是纯噪声，
却因为不在 SINK_NOISE_BLACKLIST 里被 fail-open 放行：

  - BenchmarkTest00969（cmdi/safe）：11 条事件**全部**是 Cookie.<init>，没有任何 ProcessBuilder；
  - BenchmarkTest01841（pathtraver/safe）：12 条事件全部是 Cookie.<init>，没有任何文件 IO。

两者因此被确认成 confirmed_exploitable ⇒ Benchmark 误报。

修法：非 cookie 族遇到 Cookie 构造类 sink 一律判非真，且该判定必须在
``is_response_writer_family`` 放行**之前**（否则 xss 族会被提前放行）。

零误杀验证（case 级，17 族全部已确认 spec）：丢 TP = 0，消 FP = 2。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.iast.sink_identity import (  # noqa: E402
    is_family_relevant_sink,
    is_genuine_sink_identity,
)

COOKIE_CTOR = "javax.servlet.http.Cookie.<init>"
COOKIE_SECURE = "javax.servlet.http.Cookie.setSecure"
COOKIE_HTTPONLY = "javax.servlet.http.Cookie.setHttpOnly"


def test_cookie_ctor_rejected_for_non_cookie_families():
    for fam in ("command_execution", "path_traversal", "sql_injection",
                "ldap_injection", "xpathi", "error message exposure"):
        assert is_genuine_sink_identity(COOKIE_CTOR, fam) is False, fam


def test_cookie_ctor_rejected_for_response_writer_family():
    """xss 会被 is_response_writer_family 提前放行 —— Cookie 判定必须在它之前。"""
    assert is_genuine_sink_identity(COOKIE_CTOR, "xss") is False


def test_cookie_sinks_accepted_for_secure_cookie():
    for sf in (COOKIE_CTOR, COOKIE_SECURE, COOKIE_HTTPONLY):
        assert is_genuine_sink_identity(sf, "secure_cookie") is True, sf


def test_real_sinks_still_accepted():
    assert is_genuine_sink_identity("java.sql.Statement.execute", "sql_injection") is True
    assert is_genuine_sink_identity(
        "java.lang.ProcessBuilder.start", "command_execution") is True
    assert is_genuine_sink_identity(
        "java.io.FileInputStream.<init>", "path_traversal") is True
    assert is_genuine_sink_identity(
        "org.apache.catalina.connector.CoyoteWriter.write", "xss") is True


def test_empty_sink_fail_open():
    """无 sink 信息一律 fail-open，绝不误杀。"""
    assert is_genuine_sink_identity("", "sql_injection") is True
    assert is_genuine_sink_identity("", "command_execution") is True


def test_family_relevant_sink_inherits_cookie_rule():
    """is_family_relevant_sink 先过 is_genuine_sink_identity，因此同样拒绝 Cookie。"""
    assert is_family_relevant_sink(COOKIE_CTOR, "command_execution") is False
    assert is_family_relevant_sink(COOKIE_CTOR, "path_traversal") is False
