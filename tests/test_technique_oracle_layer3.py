"""D2 判据层修复回归锁（2026-11-04，jsc 617 layer3_verdict 实证）。

锁两件事：

1. 形态规则没接住的载荷必须交给族级兜底技术，不能丢进无判据的 ``*_generic``；
2. 判据只认响应层确定性硬观测——普通业务响应、转义回显、安全端点、无关的
   500 异常都不得确认。

背景：617 的 47 条 layer3_verdict 里，落到 generic/空 的 attempt 有
xss 45、command_execution 39、deserialization 27、ssrf 15、path_traversal 4、
ssti 3、url_redirect 3、crlf 2、cors 1、xxe 1 条。本轮只补有确定性响应观测的
xss / command_execution / ssti / cors 四族；deser/ssrf/path/xxe 的响应是
``NullPointerException`` / ``SSRF check failed`` / ``xxe except`` 这类，属于探针
观测层或载荷层，不能用响应判据硬认，留给 D1 / A2 / I1 层。
"""
from __future__ import annotations

import pytest

from src.iast.technique_oracle import (
    detect_technique, judge_attempts, supported_techniques)


def _att(payload, body, headers="", status=200, no=1, method="GET", elapsed=20):
    return {"attempt_no": no, "payload": payload, "resp_body_head": body,
            "resp_headers_digest": headers, "status_code": status,
            "http_method": method, "elapsed_ms": elapsed}


# ── 技术识别：族级兜底 ────────────────────────────────────────────────────

@pytest.mark.parametrize("fam,payload,expect", [
    ("xss", "<sastxss1>", "xss_reflected"),
    ("xss", "<script>alert(1)</script>", "xss_reflected"),
    ("command_execution", "whoami", "cmd_native"),
    ("command_execution", "; calc", "cmd_native"),
    ("command_execution", "echo sastai_cmd_3da0b9e8", "cmd_echo"),
    ("ssti", '#set($e="e");$e.getClass().forName("java.lang.Runtime")', "ssti_engine"),
    ("ssti", "${7*7}", "ssti_eval"),
    ("cors", "*s4st41ccbfaad82ac7c8e6PAYLOADc81715d2", "cors_reflect"),
    ("cors", "http://evil.com", "cors_reflect"),
    ("deserialization", "rO0ABXNyAC5qYXZh", "deserialization_generic"),
    ("ssrf", "http://169.254.169.254", "ssrf_echo"),
])
def test_detect_technique_family_fallback(fam, payload, expect):
    assert detect_technique(fam, payload) == expect


# ── XSS：任意未转义原样回显 ───────────────────────────────────────────────

class TestXSSReflection:
    def test_custom_tag_verbatim_reflection_confirms(self):
        # jsc 617 spec 237715 /log4j、237746 /xss/stored/show
        ok, tech, _ = judge_attempts("xss", [_att("<sastxss1>", "<sastxss1>")])
        assert ok and tech == "xss_reflected"

    def test_escaped_reflection_does_not_confirm(self):
        assert judge_attempts("xss", [_att("<sastxss1>", "&lt;sastxss1&gt;")])[0] is False

    def test_safe_endpoint_body_does_not_confirm(self):
        # jsc 617 spec 237744 /url/sec
        a = _att("<sastxss1>", "SecurityUtil is not http or https")
        assert judge_attempts("xss", [a])[0] is False


# ── 命令执行：裸命令的进程创建异常 / whoami 输出 ──────────────────────────

class TestCommandNative:
    def test_whoami_output_confirms(self):
        # jsc 617 spec 237684 /rce/runtime/exec no=2
        ok, tech, ev = judge_attempts(
            "command_execution", [_att("whoami", "sanjio\\dell")])
        assert ok and tech == "cmd_native" and ev["signature"] == "whoami_output"

    def test_createprocess_error_confirms(self):
        # 同 spec no=1 / no=100：JVM 真的调用了 Runtime.exec
        body = ('java.io.IOException: Cannot run program "sastai1": '
                'CreateProcess error=2, 系统找不到指定的文件。')
        ok, tech, _ = judge_attempts(
            "command_execution", [_att("sastai1", body)])
        assert ok and tech == "cmd_native"

    def test_plain_parameter_reflection_does_not_confirm(self):
        # 参数被原样反射不会凭空造出 IOException / whoami 输出
        assert judge_attempts(
            "command_execution", [_att("whoami", "whoami")])[0] is False

    def test_windows_path_is_not_whoami_output(self):
        assert judge_attempts(
            "command_execution", [_att("dir", "C:\\Users\\tester")])[0] is False

    def test_unrelated_endpoint_body_does_not_confirm(self):
        # jsc 617 spec 237671 /websocket/cmd：body='path is null'
        assert judge_attempts(
            "command_execution", [_att("; calc", "path is null")])[0] is False


# ── SSTI：模板引擎异常类名 ─────────────────────────────────────────────────

class TestSSTIEngine:
    def test_velocity_method_invocation_exception_confirms(self):
        # jsc 617 spec 237689 /ssti/velocity no=2：已到 Runtime.exec 调用
        body = ('{"status":500,"exception":"org.apache.velocity.exception.'
                'MethodInvocationException","message":"Invocation of method \'exec\' '
                'in class java.lang.Runtime threw exception"}')
        a = _att('#set($e="e");$e.getClass().forName("java.lang.Runtime")',
                 body, status=500)
        ok, tech, _ = judge_attempts("ssti", [a])
        assert ok and tech == "ssti_engine"

    def test_velocity_parse_error_exception_confirms(self):
        body = ('{"exception":"org.apache.velocity.exception.ParseErrorException",'
                '"message":"Encountered ..."}')
        assert judge_attempts(
            "ssti", [_att("#set($e=%22e%22)", body, status=500)])[0] is True

    def test_plain_500_without_engine_signature_does_not_confirm(self):
        # jsc 617 spec 237691 的 java.lang.NullPointerException 不能算 SSTI
        a = _att("#set($e=1)", '{"exception":"java.lang.NullPointerException"}',
                 status=500)
        assert judge_attempts("ssti", [a])[0] is False

    def test_eval_49_still_uses_ssti_eval(self):
        ok, tech, _ = judge_attempts("ssti", [_att("${7*7}", "49")])
        assert ok and tech == "ssti_eval"


# ── CORS：非 http:// 载荷 + canary 反射 ───────────────────────────────────

class TestCORSReflect:
    def test_canary_reflected_in_acao_confirms(self):
        # jsc 617 spec 237767：ACAO 反射 canary，不是 `*` 也不是 evil.com
        hdr = ("access-control-allow-credentials=true,"
               "access-control-allow-origin=s4st41ccbf729d502fd8a0PAYLOAD35607917,"
               "cache-control=no-cache")
        a = _att("http://sastai-oracle.example.com", '{"name":"JoyChou"}', headers=hdr)
        ok, tech, ev = judge_attempts("cors", [a])
        assert ok and tech == "cors_reflect" and ev["acao"] == "reflected_canary"

    def test_star_canary_origin_confirms(self):
        # jsc 617 spec 237696 no=1
        hdr = ("access-control-allow-credentials=true,"
               "access-control-allow-origin=*s4st41ccbfaad82ac7c8e6PAYLOADc81715d2,"
               "cache-control=no-cache")
        a = _att("*s4st41ccbfaad82ac7c8e6PAYLOADc81715d2",
                 '{"name": "JoyChou"}', headers=hdr)
        assert judge_attempts("cors", [a])[0] is True

    def test_safe_endpoint_without_acao_does_not_confirm(self):
        # jsc 617 spec 237769 /cors/sec/checkOrigin：Origin is not safe.
        a = _att("", "Origin is not safe.",
                 headers="cache-control=no-cache,content-type=text/plain")
        assert judge_attempts("cors", [a])[0] is False


def test_supported_techniques_lists_new_branches():
    assert "cmd_native" in supported_techniques("command_execution")
    assert "ssti_engine" in supported_techniques("ssti")
    assert "cors_reflect" in supported_techniques("cors")


# ── 路径穿越回显：泛化签名（2026-11-05）────────────────────────────────────
# 背景：jsc 622 实测 java-sec-code /path_traversal/vul 把文件整段 base64 回显，
# 且读的是 Windows hosts / pom.xml 而非 /etc/passwd。旧判据只认 `root:x:0:0`，
# 永远确认不了。这里锁「绝对 Windows 路径被识别为 path_traversal_echo」+
# 「base64 回显的 hosts / pom.xml / passwd 都能被确认」。

import base64 as _b64mod


def _b64(body: str) -> str:
    return _b64mod.b64encode(body.encode("utf-8")).decode("ascii")


class TestPathTraversalEchoGeneralized:
    def test_abs_windows_path_classified_as_traversal(self):
        # 绝对 Windows 路径（含盘符与斜杠）必须被识别为穿越技术，否则判据走不到。
        assert detect_technique("path_traversal", "C:/Windows/System32/drivers/etc/hosts") \
            == "path_traversal_echo"
        assert detect_technique("path_traversal", "C:\\Windows\\win.ini") \
            == "path_traversal_echo"

    def test_base64_hosts_confirms(self):
        body = _b64("# Copyright (c) 1993-2009 Microsoft Corp.\n127.0.0.1 localhost\n")
        ok, tech, ev = judge_attempts("path_traversal",
                                     [_att("C:/Windows/System32/drivers/etc/hosts", body)])
        assert ok is True
        assert tech == "path_traversal_echo"

    def test_base64_pom_xml_confirms(self):
        body = _b64('<?xml version="1.0"?>\n<project>\n  <artifactId>x</artifactId>\n</project>\n')
        ok, tech, ev = judge_attempts("path_traversal", [_att("../pom.xml", body)])
        assert ok is True
        assert tech == "path_traversal_echo"

    def test_raw_passwd_still_confirms(self):
        ok, tech, _ = judge_attempts("path_traversal", [_att("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")])
        assert ok is True
        assert tech == "path_traversal_echo"

    def test_benign_body_not_confirmed(self):
        # 普通业务响应（base64 编码的无关文本）不得误确认。
        ok, _, _ = judge_attempts("path_traversal",
                                  [_att("../pom.xml", _b64("this is a normal business response, no file leaked"))])
        assert ok is False



# ── 2026-11-05：sqli 时间盲注探测臂 → confirmed_exploitable 闭环 ──
# D1 的 _run_family_oracle 把族级探测臂（含新增的 SLEEP 弹）逐条落进
# replay_attempts（payload + elapsed_ms），postpass 读它们喂给 judge_attempts。
# 这组测试锁住「探测臂落库形态」到「sqli_time 判据确认」的最后一环。

class TestSqliTimeBlindClosedLoop:
    def test_detect_sleep_payload_is_sqli_time(self):
        assert detect_technique("sql_injection", "' OR SLEEP(3)-- ") == "sqli_time"
        assert detect_technique("sql_injection", "1 OR SLEEP(3)-- ") == "sqli_time"
        assert detect_technique("sql_injection", "' OR pg_sleep(3)-- ") == "sqli_time"
        assert detect_technique("sql_injection", "'; WAITFOR DELAY '0:0:3'-- ") == "sqli_time"

    def test_sleep_arm_elapsed_confirms(self):
        """探测臂 SLEEP 生效（3120ms）⇒ judge_attempts 判 sqli_time 确认。"""
        ok, tech, ev = judge_attempts("sql_injection", [
            _att("' OR SLEEP(3)-- ", "", no=100, elapsed=3120),
        ], baseline_ms=45)
        assert ok is True
        assert tech == "sqli_time"
        assert ev["elapsed_s"] >= 2.0

    def test_sleep_arm_not_elapsed_not_confirmed(self):
        """内嵌库/认证墙下 SLEEP 没生效（30ms）：绝不误报。"""
        ok, _, _ = judge_attempts("sql_injection", [
            _att("' OR SLEEP(3)-- ", "", no=100, elapsed=30),
        ], baseline_ms=45)
        assert ok is False

    def test_empty_db_boolean_same_plus_sleep_confirms(self):
        """空库完整现场：布尔对全空一致 + SLEEP 臂延时 ⇒ 仍能确认（jsc 622）。"""
        attempts = [
            _att("sastai1", "", no=100, elapsed=18),
            _att("' OR '1'='1", "", no=101, elapsed=21),
            _att("' OR '1'='2", "", no=102, elapsed=19),
            _att("1 OR SLEEP(3)-- ", "", no=103, elapsed=3080),
        ]
        ok, tech, _ = judge_attempts("sql_injection", attempts, baseline_ms=20)
        assert ok is True
        assert tech == "sqli_time"
