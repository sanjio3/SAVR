"""④ sink 身份校验单测（零误杀 / 噪声黑名单 / XSS·SSTI 例外 / fail-open）。

不依赖 DB，纯函数 + 编排器聚合行为验证。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.iast.canary import is_sink_reached  # noqa: E402
from src.iast.sink_identity import (  # noqa: E402
    SINK_NOISE_BLACKLIST,
    family_sink_tokens,
    is_family_relevant_sink,
    is_genuine_sink_identity,
    is_response_writer_family,
    is_sink_reached_genuine,
    iast_evidence_sink_reached_genuine,
)
from src.iast.orchestrator import IastVerdict, aggregate_iast_evidence, STATE_NO_ARRIVAL, STATE_SINK_REACHED  # noqa: E402


def test_noise_sink_is_not_genuine_for_normal_family():
    # 框架响应写入 sink 对 sql_injection / command_execution 等普通族不是真 sink
    for fam in ("sql_injection", "command_execution", "ssrf", "xxe", "deserialization", "path_traversal", "jndi_injection"):
        assert is_genuine_sink_identity("org.apache.catalina.connector.Response.setHeader", fam) is False
        assert is_genuine_sink_identity("org.springframework.http.converter.StringHttpMessageConverter.writeInternal", fam) is False
        assert is_genuine_sink_identity("org.thymeleaf.TemplateEngine.process", fam) is False


def test_real_sink_is_genuine():
    assert is_genuine_sink_identity("java.lang.Runtime.exec", "command_execution") is True
    assert is_genuine_sink_identity("com.mysql.cj.jdbc.StatementImpl.executeQuery", "sql_injection") is True
    assert is_genuine_sink_identity("sun.net.www.protocol.http.HttpURLConnection.getInputStream", "ssrf") is True
    assert is_genuine_sink_identity("java.io.FileInputStream.<init>", "path_traversal") is True


def test_xss_ssti_exception():
    # 响应写入/模板渲染即 XSS/SSTI 的真 sink
    assert is_response_writer_family("java_reflected_xss") is True
    assert is_response_writer_family("java_thymeleaf_ssti") is True
    assert is_response_writer_family("template_injection") is True
    assert is_response_writer_family("ssti") is True
    # 真页面上下文 sink：writer / 模板引擎
    assert is_genuine_sink_identity("org.apache.catalina.connector.CoyoteWriter.print", "java_reflected_xss") is True
    assert is_genuine_sink_identity("org.thymeleaf.TemplateEngine.process", "java_thymeleaf_ssti") is True
    # 2026-11-03（jsc-leakfix-r17 收紧）：HTTP 基础设施写入不是页面上下文 sink。
    # 旧断言「setHeader/writeInternal 对 xss 仍真」正是 FP 根因——jsc 607 实测
    # websocket 异常串经 writeInternal、log4j 回显经 setHeader 被误确认 xss（3 条 FP）。
    assert is_genuine_sink_identity("org.apache.catalina.connector.Response.setHeader", "java_reflected_xss") is False
    assert is_genuine_sink_identity(
        "org.springframework.http.converter.StringHttpMessageConverter.writeInternal", "java_reflected_xss") is False
    assert is_genuine_sink_identity(
        "org.springframework.http.converter.StringHttpMessageConverter.writeInternal", "ssti") is False


def test_empty_or_unknown_sink_fail_open():
    # 未知 sink 类 / 空 sink_file → fail-open 视为真实，绝不误杀
    assert is_genuine_sink_identity("", "sql_injection") is True
    assert is_genuine_sink_identity("some.unknown.Sink.method", "sql_injection") is True


def test_csrf_cors_have_no_dataflow_sink():
    """csrf/cors 是路由级配置属性族：任何具体 sink 上的探针/值级命中都不为其背书
    （jsc 607 实测 4 条 csrf spec 被 xxe/xstream 端点的解析器 sink 跨族确认）。"""
    assert is_genuine_sink_identity("com.thoughtworks.xstream.XStream.fromXML", "csrf") is False
    assert is_genuine_sink_identity("org.apache.xerces.jaxp.DocumentBuilderImpl.parse", "csrf") is False
    assert is_genuine_sink_identity("java.io.PrintWriter.println", "cors") is False
    # sink_file 为空 → fail-open（无信息不误杀，交由 oracle/静态规则通道）
    assert is_genuine_sink_identity("", "csrf") is True


def test_is_sink_reached_genuine():
    assert is_sink_reached_genuine("sink-reached", "java.lang.Runtime.exec", "command_execution") is True
    assert is_sink_reached_genuine("no-arrival", "java.lang.Runtime.exec", "command_execution") is False
    # 状态是 sink-reached 但落点在噪声 sink → 不真
    assert is_sink_reached_genuine("sink-reached", "org.apache.catalina.connector.Response.setHeader", "ssrf") is False
    # 2026-11-03（jsc-leakfix-r17 收紧）：setHeader 对 xss 也不再是真（见 test_xss_ssti_exception）
    assert is_sink_reached_genuine("sink-reached", "org.apache.catalina.connector.Response.setHeader", "java_reflected_xss") is False
    # 真 writer 对 xss 仍真
    assert is_sink_reached_genuine("sink-reached", "org.apache.catalina.connector.CoyoteWriter.print", "java_reflected_xss") is True


def test_iast_evidence_sink_reached_genuine():
    # 聚合证据只含噪声 sink → 不真
    ie_noise = {"state": "sink-reached", "reached_sink_files": ["org.apache.catalina.connector.Response.setHeader"], "matched_sink_file": "org.apache.catalina.connector.Response.setHeader"}
    assert iast_evidence_sink_reached_genuine(ie_noise, "ssrf") is False
    # 同时含真 sink（不同假说到达不同 sink）→ 真（零误杀）
    ie_mix = {"state": "sink-reached", "reached_sink_files": ["org.apache.catalina.connector.Response.setHeader", "java.lang.Runtime.exec"], "matched_sink_file": "org.apache.catalina.connector.Response.setHeader"}
    assert iast_evidence_sink_reached_genuine(ie_mix, "command_execution") is True
    # 无 sink_file 信息 → fail-open 真
    ie_nofile = {"state": "sink-reached", "reached_sink_files": [], "matched_sink_file": ""}
    assert iast_evidence_sink_reached_genuine(ie_nofile, "ssrf") is True
    # 非 sink 状态 → 不真
    assert iast_evidence_sink_reached_genuine({"state": "no-arrival"}, "ssrf") is False


def test_aggregate_iast_evidence_surfaces_reached_sink_files():
    # 两个假说：一个到噪声 sink，一个到真 sink；聚合应透传两者 reached_sink_files
    v1 = IastVerdict(state=STATE_SINK_REACHED, matched_sink_file="org.apache.catalina.connector.Response.setHeader")
    v2 = IastVerdict(state=STATE_SINK_REACHED, matched_sink_file="java.lang.Runtime.exec")
    agg = aggregate_iast_evidence({"h1": v1, "h2": v2})
    assert set(agg["reached_sink_files"]) == {
        "org.apache.catalina.connector.Response.setHeader",
        "java.lang.Runtime.exec",
    }
    # 未到 sink 的假说不计入
    v3 = IastVerdict(state=STATE_NO_ARRIVAL, matched_sink_file="x")
    agg2 = aggregate_iast_evidence({"h1": v1, "h3": v3})
    assert agg2["reached_sink_files"] == ["org.apache.catalina.connector.Response.setHeader"]


def test_aggregate_iast_evidence_empty():
    agg = aggregate_iast_evidence({})
    assert agg["reached_sink_files"] == []
    assert agg["state"] == STATE_NO_ARRIVAL


def test_noise_blacklist_entries_are_concrete_sinks():
    # 黑名单条目必须是经验证的具体 sink（不是通配），防止误伤
    assert "java.io.RandomAccessFile.<init>" not in SINK_NOISE_BLACKLIST  # path-traversal 真 sink，绝不入黑名单
    assert len(SINK_NOISE_BLACKLIST) >= 8


def test_xss_family_relevant_covers_tomcat_coyotewriter():
    """2026-10-12 回归锁：Tomcat 真实反射入口 CoyoteWriter 的覆写形态必须判为本族相关。

    r80 实证（run 315/316）：xss 最主要的反射路径是 response.getWriter()（实际类型
    CoyoteWriter）的 print/println/format，而旧 tokens 只有 writer.write 侥幸命中 write，
    其余被 is_family_relevant_sink 判成「非本族 sink」剔除 —— 值级通道长期只出零星几条。
    ByteBuddy 按类织入，CoyoteWriter 覆写了这些方法，钩父类 PrintWriter 对 Tomcat 零命中，
    所以必须认 CoyoteWriter 这个类。
    """
    for m in ("write", "print", "println", "format", "printf", "append", "write(char[],int,int)"):
        sf = f"org.apache.catalina.connector.CoyoteWriter.{m}"
        assert is_family_relevant_sink(sf, "xss") is True, sf
    # DB 里的真实形态（带源码文件名行号）也要覆盖
    assert is_family_relevant_sink(
        "org.apache.catalina.connector.CoyoteWriter.write(CoyoteWriter.java:188)", "xss") is True
    # 传统写法不受影响（防回归）
    assert is_family_relevant_sink("java.io.PrintWriter.println", "xss") is True
    assert is_family_relevant_sink("javax.servlet.ServletOutputStream.print", "xss") is True
    assert is_family_relevant_sink("java.io.PrintStream.println", "xss") is True


def test_xss_family_relevant_still_rejects_noise_and_cookie():
    """守 FP：响应头噪声与 Cookie 构造不得因补 token 而被放行。

    这两类是已实测过的 FP 来源：setHeader 的实参恒为 [X-XSS-Protection, 0] 之类框架值，
    Cookie.<init> 只是把请求自带 cookie 原值建对象 —— 都对 xss 无证明力。
    """
    for sf in ("org.apache.catalina.connector.ResponseFacade.setHeader",
               "org.apache.catalina.connector.Response.setHeader",
               "org.apache.catalina.connector.ResponseFacade.addHeader",
               "javax.servlet.http.Cookie.<init>",
               "org.apache.catalina.connector.ResponseFacade.sendRedirect"):
        assert is_family_relevant_sink(sf, "xss") is False, sf


def test_coyotewriter_not_relevant_for_other_families():
    """守跨族污染：CoyoteWriter 对非响应写入族仍须判非本族（响应回显不当别族链路证据）。"""
    for fam in ("sql_injection", "command_execution", "path_traversal", "ldap_injection"):
        assert is_family_relevant_sink(
            "org.apache.catalina.connector.CoyoteWriter.print", fam) is False, fam
    # xss 自身仍取得到画像（防止 family_sink_tokens 被改空）
    assert family_sink_tokens("xss")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
