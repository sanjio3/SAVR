"""族特有「有害证据」判定单测（src/iast/harm_evidence.py）。

夹具全部取自 run 469 的真实响应（两个 FP 的实测文本），锁住三态语义：
只有 harm_absent 才允许降级，harm_unknown 必须保持原判据。
"""
from src.iast import harm_evidence as H


# ───────────────────────── 族名归一化 ─────────────────────────

def test_normalize_family_aliases():
    assert H.normalize_family("http response splitting") == "http_response_splitting"
    assert H.normalize_family("HTTP_RESPONSE_SPLITTING") == "http_response_splitting"
    assert H.normalize_family("stack trace exposure") == "stack_trace_exposure"
    # error message exposure 不能映射到 stack_trace_exposure：它的危害是泄露内部错误信息，
    # 不需要堆栈帧。早期误映射导致 469 里 8 条真漏洞被当成「无堆栈帧」降级 —— 已回滚。
    assert H.normalize_family("error message exposure") == "error_message_exposure"
    assert H.normalize_family("sqli") == "sql_injection"
    assert H.normalize_family("cmdi") == "command_execution"
    assert H.normalize_family("pathtraver") == "path_traversal"
    assert H.normalize_family(None) == ""
    assert H.normalize_family("unknown family") == "unknown_family"


# ───────────────────────── HTTP 响应拆分（00016 的实测形态） ─────────────────────────

def test_response_splitting_absent_when_canary_echoed_in_cookie():
    """469 的 00016：canary 回显在 cookie 值里，但响应头无拆分痕迹 ⇒ harm_absent。

    注意必须带 CRLF payload：只投 canary 时「响应无拆分痕迹」是**预期结果**，
    拿它当 absent 等于用「没攻击」证明「打不穿」⇒ 此时必须返回 unknown。
    """
    attempts = [{
        "family": "http response splitting",
        "payload": "sastcanary%0d%0aInjected-Header: pwned",
        "resp_body_head": "Created cookie: 'SomeCookie': with value: "
                          "'s4st41dd7ce04c0d2e1412PAYLOADdf7ddf32'",
        "resp_headers_digest": '[["content-type","text/html;charset=utf-8"],'
                               '["content-length","92"],["date","Sun, 25 Oct 2026"]]',
    }]
    got = H.evaluate("http response splitting", attempts=attempts)
    assert got["verdict"] == "harm_absent"
    assert got["kind"] == "no_crlf_evidence"


def test_response_splitting_unknown_when_no_crlf_payload():
    """只投 canary、没投 CRLF ⇒ unknown（不降级）。这是避免误伤真漏洞的硬边界。"""
    attempts = [{
        "family": "http response splitting",
        "payload": "sastcanary",
        "resp_body_head": "Created cookie: 'SomeCookie': with value: 's4st41dd7ce04c0d2e1412PAYLOADdf7ddf32'",
    }]
    got = H.evaluate("http response splitting", attempts=attempts)
    assert got["verdict"] == "harm_unknown"
    assert got["kind"] == "no_crlf_payload"


def test_response_splitting_confirmed_on_fake_response_line():
    attempts = [{
        "family": "http response splitting",
        "payload": "sastcanary%0d%0a%0d%0aHTTP/1.1 200 OK",
        "resp_body_head": "Set-Cookie: x=1\r\n\r\nHTTP/1.1 200 OK\r\nX-Injected: pwned",
    }]
    got = H.evaluate("http response splitting", attempts=attempts)
    assert got["verdict"] == "harm_confirmed" and got["kind"] == "crlf_injected"


def test_response_splitting_confirmed_on_injected_header():
    attempts = [{"family": "http response splitting",
                 "payload": "sastcanary%0d%0aX-Injected-Header: pwned",
                 "resp_body_head": "X-Injected-Header: sastcanary"}]
    assert H.evaluate("http response splitting", attempts=attempts)["verdict"] == "harm_confirmed"


# ───────────────────────── 栈追踪泄露（00121 的实测形态） ─────────────────────────

def test_stack_trace_absent_when_no_frame():
    """469 的 00121：探针断言值到达，但响应体无堆栈帧 ⇒ harm_absent。"""
    attempts = [{
        "family": "stack trace exposure",
        "resp_body_head": "<html><body>An error occurred. Please try again.</body></html>",
        "resp_headers_digest": '[["content-type","text/html"]]',
    }]
    got = H.evaluate("stack trace exposure", attempts=attempts)
    assert got["verdict"] == "harm_absent" and got["kind"] == "no_stack_frame"


def test_stack_trace_confirmed_on_frame_line():
    attempts = [{"family": "stack trace exposure",
                 "resp_body_head": "java.lang.NullPointerException\n"
                                   "\tat org.owasp.benchmark.helpers.DatabaseHelper.getSQLResult(DatabaseHelper.java:123)\n"
                                   "\tat org.owasp.benchmark.testcode.BenchmarkTest00121.doPost(BenchmarkTest00121.java:88)"}]
    got = H.evaluate("stack trace exposure", attempts=attempts)
    assert got["verdict"] == "harm_confirmed" and got["kind"] == "stack_frame_leaked"


# ───────────────────────── 三态语义：证据不足绝不降级 ─────────────────────────

def test_unknown_when_no_response_text():
    """没有响应文本时返回 unknown——绝不能当成 absent 去降级真漏洞。"""
    assert H.evaluate("http response splitting")["verdict"] == "harm_unknown"
    assert H.evaluate("stack trace exposure")["verdict"] == "harm_unknown"


def test_unknown_for_uncovered_family():
    """未覆盖的族一律 unknown（保持现有判据），不参与降级。"""
    for fam in ("ldap_injection", "xpath_injection", "trust_boundary_violation",
                "secure_cookie", "weak_hash", "business_logic"):
        got = H.evaluate(fam, attempts=[{"family": fam, "resp_body_head": "ok"}])
        assert got["verdict"] == "harm_unknown", fam


def test_other_family_attempts_do_not_leak():
    """跨族尝试不能串味：查 stack_trace 时不应读到 xss 的响应。"""
    attempts = [
        {"family": "xss", "resp_body_head": "\tat evil.Class(Evil.java:1)"},
        {"family": "stack trace exposure", "resp_body_head": "<html>ok</html>"},
    ]
    assert H.evaluate("stack trace exposure", attempts=attempts)["verdict"] == "harm_absent"


# ───────────────────────── oracle 信号优先 ─────────────────────────

def test_oracle_signal_confirms_injection_family():
    got = H.evaluate("sql_injection", oracle_state="exploitable", oracle_signal="boolean_diff")
    assert got["verdict"] == "harm_confirmed" and "boolean_diff" in got["kind"]


def test_oracle_signal_must_match_family():
    """oracle 信号属于别的族时不算本族有害证据。"""
    got = H.evaluate("sql_injection", oracle_state="exploitable", oracle_signal="time_delay")
    assert got["verdict"] == "harm_unknown"


def test_injection_family_without_oracle_is_unknown_not_absent():
    """注入族无 oracle 信号 ⇒ unknown（不降级）——这是保住 462 的 TP 78 的关键。"""
    for fam in ("sql_injection", "command_execution", "path_traversal", "xss"):
        got = H.evaluate(fam, attempts=[{"family": fam, "resp_body_head": "normal page"}])
        assert got["verdict"] == "harm_unknown", fam


def test_falls_back_to_dast_response_summary():
    got = H.evaluate("stack trace exposure",
                     dast_impact_evidence={"response_summary": "at foo.Bar(Bar.java:9)"})
    assert got["verdict"] == "harm_confirmed"
