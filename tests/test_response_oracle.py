"""族级行为 oracle（src/iast/response_oracle.py）单测。

夹具全部来自 2026-10-24 对 OWASP Benchmark 的**真实响应实测**（见 scripts/oracle_smoke.py），
不是构造的理想数据 —— 目的就是把「payload 回显导致假差异」「HTML 转义导致签名读不到」
「cookie 带空格被整条丢弃」这几类真实坑锁住。
"""
import html
import urllib.parse

from src.iast import response_oracle as orc


# ───────────────────────── 基础工具 ─────────────────────────

def test_canonical_family_aliases():
    assert orc.canonical_family("sqli") == "sql_injection"
    assert orc.canonical_family("command_injection") == "command_execution"
    assert orc.canonical_family("pathtraver") == "path_traversal"
    assert orc.canonical_family("XSS") == "xss"
    assert orc.canonical_family("weak_hash") == ""
    assert orc.canonical_family(None) == ""


def test_encode_cookie_value_only_when_illegal():
    # 纯引号连字符：Tomcat 接受，保持原样（不改变既有基线）
    assert orc.encode_cookie_value("bar'--") == "bar'--"
    # 含空格：必须百分号编码，否则整条 cookie 被丢
    enc = orc.encode_cookie_value("' OR '1'='1")
    assert " " not in enc
    assert urllib.parse.unquote(enc) == "' OR '1'='1"
    assert orc.encode_cookie_value("") == ""


def test_normalize_body_strips_payload_and_entities():
    body = "<p>Update complete for query: VALUES ('foo','sastai1')</p>"
    norm = orc.normalize_body(body, ["sastai1"])
    assert "sastai1" not in norm
    assert "\u00abP\u00bb" in norm
    # HTML 实体先解再匹配
    assert "<Server" in orc.normalize_body("&lt;Server port=8080")


def test_bodies_differ_ignores_pure_payload_echo():
    """Benchmark 会把 SQL 原文回显；布尔对只差 payload 文本时必须判「无差异」。"""
    t = "Your results are:<br> </p>"
    f = "Your results are:<br> </p>"
    assert not orc.bodies_differ(orc.normalize_body(t, ["' OR '1'='1"]),
                                 orc.normalize_body(f, ["' OR '1'='2"]))


# ───────────────────────── 探测臂构造 ─────────────────────────

def test_build_probes_sqli_quote_vs_numeric():
    quote = orc.build_probes("sql_injection", payload="bar'--", servlet_name="BenchmarkTest01888")
    arms = {(p.arm, p.channel) for p in quote}
    assert ("bool_true", "value") in arms and ("bool_false", "name") in arms
    numeric = orc.build_probes("sql_injection", payload="1")
    assert any("1 OR 1=1" == p.payload for p in numeric)


def test_build_probes_path_ladder_and_xss_channels():
    paths = orc.build_probes("path_traversal", servlet_name="BenchmarkTest00001")
    assert paths and all(p.arm == "file" for p in paths)
    # 签名文件必须在 webapp 之外：放 WEB-INF 下并置只读会阻塞 Tomcat 重解包
    # （ExpandWar.deleteDir 删不掉 ⇒ 上下文[/benchmark] 起不来，2026-10-26 实测）。
    assert any(p.payload == "../../oracle-sig.txt" for p in paths), \
        "签名文件必须指向 webapp 之外的 TOMCAT/oracle-sig.txt"
    assert not any("webapps/" in p.payload for p in paths), \
        "探测路径不得落在 webapp 内（会被重解包清掉，且可能破坏靶场）"
    xss = orc.build_probes("xss", servlet_name="BenchmarkTest00013")
    assert {p.channel for p in xss} == {"value", "name", "header"}
    assert any(p.note == "hdr:Referer" for p in xss)


def test_build_probes_unknown_family_is_empty():
    assert orc.build_probes("weak_hash") == []


# ───────────────────────── judge：sqli ─────────────────────────

def _arm(arm, payload, body="", status=200, ms=0.0, note=""):
    return orc.ArmResult(arm=arm, payload=payload, status=status, body=body,
                         elapsed_ms=ms, note=note)


def test_judge_sqli_boolean_diff_exploitable():
    # 实测 BenchmarkTest00100：true 臂返回三行用户，false/benign 返回空结果集
    benign = "<p> Your results are:<br> </p>"
    true_body = ("<p> Your results are:<br> 0,  User01,  P455w0rd<br> "
                 "1,  User02,  B3nchM3rk<br> 2,  User03,  a$c<br> </p>")
    arms = [
        _arm("benign", "sastai1", benign),
        _arm("bool_true", "' OR '1'='1", true_body),
        _arm("bool_false", "' OR '1'='2", benign),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "exploitable"
    assert v["signal"] == "boolean_diff"


def test_judge_sqli_identical_arms_is_inconclusive_not_negative():
    """INSERT/UPDATE 型语句布尔对天然一致：只能 inconclusive，绝不判 not_exploitable。"""
    body = "<p>Update complete for query: INSERT ...</p>"
    arms = [
        _arm("benign", "sastai1", body),
        _arm("bool_true", "' OR '1'='1", body),
        _arm("bool_false", "' OR '1'='2", body),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "inconclusive"
    assert v["signal"] == "boolean_same"


def test_judge_sqli_error_diff_only_not_confirmed():
    """布尔对一致但与对照不同（500 报错页）：只记录，不确认（安全实现也可能拒绝输入）。"""
    ok = "<p>Update complete</p>"
    err = "<h1>HTTP 500</h1>"
    arms = [
        _arm("benign", "sastai1", ok),
        _arm("bool_true", "' OR '1'='1", err, status=500),
        _arm("bool_false", "' OR '1'='2", err, status=500),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "inconclusive"
    assert v["signal"] == "error_diff_only"


# ── 2026-11-05：空库 / 报错被吞 / 302 认证墙下的 sqli 时间盲注补齐 ──

def test_build_probes_sqli_has_delay_arms():
    """探测臂必须补 SLEEP 时间盲注臂：jsc 622 空库 boolean_same 的唯一解。"""
    probes = orc.build_probes("sql_injection", payload="bar'--")
    delays = [p for p in probes if p.arm == "delay"]
    assert delays, "sqli 探测臂缺少时间盲注（delay）臂"
    assert any("SLEEP" in p.payload or "pg_sleep" in p.payload
               or "WAITFOR" in p.payload for p in delays)
    # 无破坏性：绝不出现 DROP/INSERT/UPDATE/UNION 全列枚举
    for p in delays:
        assert not any(w in p.payload.upper() for w in ("DROP", "INSERT", "UPDATE", "DELETE"))
    # 布尔臂仍保留（既有能力不回退）
    assert any(p.arm == "bool_true" for p in probes)
    assert any(p.arm == "bool_false" for p in probes)


def test_judge_sqli_time_delay_confirms_when_boolean_same():
    """空库：布尔对完全一致（boolean_same），但 SLEEP 臂比基线慢 3s ⇒ 确认。"""
    arms = [
        _arm("benign", "sastai1", "", ms=40),
        _arm("bool_true", "' OR '1'='1", "", ms=45),
        _arm("bool_false", "' OR '1'='2", "", ms=42),
        _arm("delay", "' OR SLEEP(3)-- ", "", ms=3120, note="sqli_sleep_mysql_quote"),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "exploitable"
    assert v["signal"] == "time_delay"


def test_judge_sqli_no_delay_falls_back_to_boolean_same():
    """SLEEP 未生效（内嵌库/被拦截）⇒ 绝不误报，回落 inconclusive/boolean_same。"""
    arms = [
        _arm("benign", "sastai1", "", ms=40),
        _arm("bool_true", "' OR '1'='1", "", ms=45),
        _arm("bool_false", "' OR '1'='2", "", ms=42),
        _arm("delay", "' OR SLEEP(3)-- ", "", ms=48, note="sqli_sleep_mysql_quote"),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "inconclusive"
    assert v["signal"] == "boolean_same"


def test_judge_sqli_delay_5xx_not_confirmed():
    """delay 臂返回 5xx（WAF/网关错误）不能算时延证据。"""
    arms = [
        _arm("benign", "sastai1", "", ms=40),
        _arm("delay", "' OR SLEEP(3)-- ", "gateway error", status=503, ms=3100),
    ]
    v = orc.judge("sql_injection", arms)
    assert v["verdict"] == "inconclusive"


def test_canonical_family_url_whitelist_aliases():
    """url 白名单绕过族必须能归一到可投探测臂的族。"""
    for alias in ("url_whitelist_bypass", "url_whitelist", "url_allowlist", "url_bypass"):
        assert orc.canonical_family(alias) == "url_redirect"


def test_build_probes_url_whitelist_uses_redirect_arm():
    """归一后能产出 redirect 探测臂（此前 canonical 返回空 ⇒ 完全不投）。"""
    probes = orc.build_probes("url_whitelist_bypass", servlet_name="URLWhiteList")
    assert probes
    assert any(p.arm == "redirect" for p in probes)


# ───────────────────────── judge：cmdi / pathtraver / xss ─────────────────────────

def test_judge_cmdi_time_delay_exploitable():
    arms = [
        _arm("benign", "sastai1", "ok", ms=45),
        _arm("delay", "& ping -n 5 127.0.0.1", "ok", ms=4115, note="cmd_append@name"),
        _arm("delay", "FOO=ping -n 5 127.0.0.1", "ok", ms=60, note="env_assign@name"),
    ]
    v = orc.judge("command_execution", arms, baseline_ms=45)
    assert v["verdict"] == "exploitable"
    assert v["signal"] == "time_delay"


def test_judge_cmdi_no_delay_is_inconclusive():
    arms = [
        _arm("benign", "sastai1", "ok", ms=50),
        _arm("delay", "& ping -n 5 127.0.0.1", "ok", ms=55),
    ]
    v = orc.judge("command_execution", arms, baseline_ms=50)
    assert v["verdict"] == "inconclusive"


def test_judge_pathtraver_signature_with_html_escape():
    """实测：文件内容被 ESAPI 转义后回显（&lt;web-app），必须解实体再匹配签名。"""
    body = ("The beginning of file: '...web.xml' is:\n\n"
            + html.escape("<?xml version=\"1.0\"?>\n<web-app version=\"3.1\">"))
    arms = [_arm("file", "../../webapps/benchmark/WEB-INF/web.xml", body, note="web_xml")]
    v = orc.judge("path_traversal", arms)
    assert v["verdict"] == "exploitable"
    assert v["signal"] == "file_signature"


def test_judge_pathtraver_no_signature_inconclusive():
    body = "Problem getting FileInputStream: D:\\...\\testfiles\\..\\..\\conf\\server.xml"
    arms = [_arm("file", "../conf/server.xml", body, note="server_xml")]
    v = orc.judge("path_traversal", arms)
    assert v["verdict"] == "inconclusive"


def test_judge_xss_reflection_raw_vs_escaped():
    raw = [_arm("reflect", "<sastxss1>", "<sastxss1>", note="hdr:Referer")]
    assert orc.judge("xss", raw)["verdict"] == "exploitable"
    esc = [_arm("reflect", "<sastxss1>", html.escape("<sastxss1>"), note="value_channel")]
    v = orc.judge("xss", esc)
    assert v["verdict"] == "not_exploitable"
    assert v["signal"] == "reflection_escaped"


def test_judge_missing_arms_is_inconclusive():
    v = orc.judge("command_execution", [])
    assert v["verdict"] == "inconclusive"
    assert "缺失" in v["reason"]


# ───────────────────────── 被动判定 ─────────────────────────

def test_evaluate_passive_xss_and_pathtraver():
    assert orc.evaluate_passive("xss", "<sastxss1>", "hi <sastxss1>")["verdict"] == "exploitable"
    assert orc.evaluate_passive("xss", "<sastxss1>", "hi")["verdict"] == "inconclusive"
    assert orc.evaluate_passive(
        "path_traversal", "../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")["verdict"] == "exploitable"
