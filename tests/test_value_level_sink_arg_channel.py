# -*- coding: utf-8 -*-
"""值级 sink 实参通道回归锁（2026-10-10 落地）。

锁的是三件事，每一条都有对应的真实事故：

1. 「到达」必须与「值级命中」分家。探针的 canary_match 是 trace 级断言——run 251 实测
   4943/4943 全为 1，而记录下来的 sink 实参值里真能看到 canary 原文的只有 129 条（2.6%）。
   靠断言定案会把 map 回读 / 常量三元分支的安全版一起判成真漏洞（当时 30 条误报）。
2. 值级命中必须叠「本族 sink 画像」身份约束。129 条命中里有 28 条落在 Cookie.<init>
   （请求把自己的 cookie 原值建对象），SQL 族还会被 PrintWriter 回显污染。
3. 本通道**只做正向**。离线实测：30 条真 FP 零穿透，但 73 条真 TP 只覆盖 16 条。
   未命中是「证据缺失」不是「无害」，必须 definitive=False。把它当阴性裁决会重演
   r250 那次召回崩塌（69.8%→35.4%）。
"""
from __future__ import annotations

import pytest

from src.agents import d2_facade  # noqa: F401  # 注册全部通道评估器（真实链路前提）
from src.core import evidence_channels as ec
from src.iast.orchestrator import compute_value_hit
from src.iast.sink_identity import is_family_relevant_sink

CANARY = "s4st414bf83225e75d3b9f"


def _value_hit(sink: str = "org.hsqldb.jdbc.JDBCStatement.execute") -> dict:
    # A3 四态契约：原文命中且无消毒器 → form=hit_live（旧名 canary_exact 已废弃）
    return {"hit": True, "form": "hit_live", "where": "source_value",
            "sink_file": sink, "snippet": "INSERT INTO users VALUES ('%s','x')" % CANARY,
            "matched_len": len(CANARY)}


def _run(family: str, iast: dict, dast: dict | None = None) -> dict:
    return ec.verify_with_channels(family, iast, dast or {"reached": True, "status_code": 200, "body": ""})


# ── 1. compute_value_hit：比对而非断言 ──────────────────────────────────────

def test_value_hit_detects_verbatim_payload_in_sink_arg():
    ev = {"source_value": "INSERT INTO users VALUES ('%s','x')" % CANARY,
          "sink_file": "org.hsqldb.jdbc.JDBCStatement.execute", "evidence": {"payload": ""}}
    hit = compute_value_hit(CANARY, ev)
    assert hit["hit"] is True
    assert hit["form"] == "hit_live"
    assert CANARY in hit["snippet"]


def test_value_hit_misses_when_sink_receives_a_constant():
    """OWASP BenchmarkTest00440 形态：HashMap 回读了另一个 key，SQL 拿到的是常量。

    这是 30 条误报里 sqli 那一簇的根——污点标签没掉，值却被换成了常量。
    """
    ev = {"source_value": "INSERT INTO users (username, password) VALUES ('foo','a_Value')",
          "sink_file": "org.hsqldb.jdbc.JDBCStatement.execute", "evidence": {}}
    assert compute_value_hit(CANARY, ev)["hit"] is False


def test_value_hit_misses_on_parameterized_sql():
    ev = {"source_value": "SELECT * from USERS where USERNAME=? and PASSWORD=''",
          "sink_file": "org.hsqldb.jdbc.JDBCPreparedStatement.execute", "evidence": {}}
    assert compute_value_hit(CANARY, ev)["hit"] is False


def test_value_hit_never_crashes_on_garbage():
    assert compute_value_hit("", {"source_value": "x"})["hit"] is False
    assert compute_value_hit(CANARY, {})["hit"] is False
    assert compute_value_hit("short", {"source_value": "short"})["hit"] is False


# ── 1b. HTML 反解码分支（Phase1 2026-10-11）：检测得到反射、但绝不据此确认 ──

def test_value_hit_html_encoded_reflection_is_not_a_confirming_hit():
    """完整 marker（身份段+含 HTML 特殊字符的 payload）被 HTML 转义后回显：
    身份段是纯字母数字永不被转义，但 payload 的 &lt;script&gt; 部分会——
    原文全串匹配失败、html.unescape 后命中 → 数据确实到达输出（事实层），
    但转义反射=防护生效，不是可利用证据。返回独立态 hit_html_encoded 且
    hit=False —— 确认闸按 hit 门控，不会误升（防 FP）。
    """
    marker = CANARY + "<script>alert('xss')</script>"
    ev = {"source_value": "s4st414bf83225e75d3b9f&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
          "sink_file": "org.apache.catalina.connector.CoyoteWriter.println", "evidence": {}}
    hit = compute_value_hit(marker, ev)
    assert marker not in ev["source_value"]   # 原文全串确实不在（payload 被转义）
    assert hit["hit"] is False                # 绝不据此确认（防 FP）
    assert hit["form"] == "hit_html_encoded"
    assert hit["definitive"] is False


def test_value_hit_raw_match_still_wins_over_html_decode():
    """完整 marker 原文在值里（裸 servlet 不转义，Benchmark 主形态）→ 仍走 hit_live
    确认，反解码分支不得截胡降级。"""
    marker = CANARY + "<script>alert('xss')</script>"
    ev = {"source_value": "echo: " + marker,
          "sink_file": "org.apache.catalina.connector.CoyoteWriter.println", "evidence": {}}
    hit = compute_value_hit(marker, ev)
    assert hit["hit"] is True
    assert hit["form"] == "hit_live"
    assert hit["harmful"] is True


def test_value_hit_html_decode_branch_is_quiet_when_no_canary_at_all():
    """安全用例（体写 'foo'/'bar'）：原文与反解码后都没有 marker → 纯 miss。"""
    marker = CANARY + "<script>alert('xss')</script>"
    ev = {"source_value": "&lt;script&gt;alert('foo')&lt;/script&gt;",
          "sink_file": "org.apache.catalina.connector.CoyoteWriter.println", "evidence": {}}
    hit = compute_value_hit(marker, ev)
    assert hit["hit"] is False
    assert hit["form"] == "miss"


def test_recover_gate_never_upgrades_on_html_encoded_only():
    """端到端闸门回归：d2_facade.recover_late_arrival 按 vh['hit'] 门控升级，
    hit_html_encoded（hit=False）不允许把 spec 升成 confirmed_exploitable。"""
    import inspect
    src = inspect.getsource(d2_facade.recover_late_arrival)
    assert 'if vh.get("hit"):' in src  # 门控仍按 hit 布尔值，不认 form 字符串


# ── 2. 族相关 sink 身份约束 ────────────────────────────────────────────────

@pytest.mark.parametrize("sink,family,expected", [
    ("java.lang.Runtime.exec", "cmdi", True),
    ("org.hsqldb.jdbc.JDBCStatement.execute", "sqli", True),
    ("java.io.FileInputStream.<init>", "pathtraver", True),
    ("javax.naming.directory.DirContext.search", "ldapi", True),
    ("java.security.MessageDigest.getInstance", "hash", True),
    # 非本族 sink：值级命中也不许背书
    ("javax.servlet.http.Cookie.<init>", "sqli", False),
    ("java.io.PrintWriter.write", "sqli", False),
    # SecureRandom 继承陷阱（2026-10-09 实证）
    ("java.security.SecureRandom", "weakrand", False),
    # 框架噪声 sink
    ("org.apache.catalina.connector.Response.setHeader", "sqli", False),
    # fail-open：无 sink 信息 / 未登记族
    ("", "sqli", True),
    # trustbound 是**唯一例外**：不能 fail-open。该族真 sink 只有会话属性写入
    # （setAttribute/putValue），必须正向白名单，否则 doGet 里的 Cookie.<init> 假 sink 与
    # Response Set-Cookie 框架噪声会被当成确认（task-4 实测 7 条 confirmed 全是噪声）。
    # 故未知 sink 对 trustbound 一律判 False，见 src/iast/sink_identity.py 42-59 行。
    ("some.unknown.Sink.doThing", "trustbound", False),
])
def test_family_relevant_sink(sink, family, expected):
    assert is_family_relevant_sink(sink, family) is expected


def test_xpathi_is_not_stealed_by_pathtraver_profile():
    """'path' 是 'xpathi' 的子串，画像查表顺序反了会让 XPath 族整族静默归零。"""
    assert family_hits_profile("com.sun.org.apache.xpath.internal.jaxp.XPathImpl.evaluate", "xpathi")
    assert not family_hits_profile("java.io.FileInputStream.<init>", "xpathi")


def family_hits_profile(sink: str, family: str) -> bool:
    return is_family_relevant_sink(sink, family)


# ── 3. 通道行为：正向专用 ──────────────────────────────────────────────────

def test_channel_promotes_to_primary_on_family_relevant_hit():
    vh = _value_hit()
    iast = {"state": "sink-reached-probe", "value_hits": [vh], "value_hit": vh,
            "matched_sink_file": vh["sink_file"], "reached_sink_files": [vh["sink_file"]]}
    v = _run("sqli", iast)
    assert v["primary_channel"] == "value_level_sink_arg"
    assert v["evidence_strength"] == 4
    assert v["harmful"] is True and v["confidence"] == "high"
    assert v["value_level_hit"] is True


def test_channel_is_not_definitive_on_cross_family_sink():
    vh = _value_hit("javax.servlet.http.Cookie.<init>")
    iast = {"state": "sink-reached-probe", "value_hits": [vh], "value_hit": vh}
    v = _run("sqli", iast)
    assert v["primary_channel"] != "value_level_sink_arg"
    outcomes = {o["channel"]: o for o in v["evidence_channels"]}
    assert outcomes["value_level_sink_arg"]["definitive"] is False


def test_channel_is_not_definitive_when_nothing_matches():
    """未命中 = 证据缺失，绝不等于无害（这是本通道的红线）。"""
    v = _run("sqli", {"state": "sink-reached-probe"})
    outcomes = {o["channel"]: o for o in v["evidence_channels"] if o["channel"] == "value_level_sink_arg"}
    assert not outcomes or outcomes["value_level_sink_arg"]["definitive"] is False


def test_channel_never_appears_without_value_evidence():
    """适用性必须是证据驱动：没比对到值就不准出现在计划里，否则对账会谎报覆盖度。"""
    assert "value_level_sink_arg" not in ec.applicable_channels("sqli", iast=None)
    assert "value_level_sink_arg" not in ec.applicable_channels("", iast={})
    assert "value_level_sink_arg" in ec.applicable_channels("sqli", iast={"value_hits": [_value_hit()]})


def test_baseline_invariant_holds_when_family_and_evidence_are_missing():
    """族名缺失且无任何证据时，适用性只剩 probe_sink_assert 一条基线通道。"""
    assert ec.applicable_channels("") == ["probe_sink_assert"]


def test_unregistered_families_fail_open():
    """未登记族（业务逻辑等）不能被新画像误杀。"""
    assert is_family_relevant_sink("com.acme.MySink.execute", "business_logic") is True
