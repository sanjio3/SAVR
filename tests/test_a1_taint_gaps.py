"""三个 A1 静态检出缺口的红灯锁（2026-10-05，OWASP Benchmark 漏检归因驱动）。

背景：sample-200 上 L1 静态层已到不动点（run 46/90/112/113 逐位相同：
检出 142 用例、TP 94、FP 48、漏 12）。按真值族拆，八个族已 100%，
只有三族有缺口：sqli 70%（漏6）、pathtraver 70%（漏3）、hash 66.7%（漏3）。
逐条验尸后，12 条漏检归为三处能力缺口：

① JDBC 转义语法 `{call " + param + "}`：SQL 拼接规则只认
   SELECT/INSERT/UPDATE/DELETE 开头，存储过程调用形式整类漏
   （BenchmarkTest00008 / 02170 / 01379）。
② 非标准污点源不被认作 SQL 注入的「query-like source evidence」：
   getParameterNames() / getCookies() / 自定义包装类 getter（getTheParameter）
   都不匹配硬编码的 `getparameter(` token，导致 A2 已判「真漏洞」的候选
   被 A21 以 missing query-like source evidence 刷掉，永不生成 spec
   （BenchmarkTest00100 / 00595 / 01552）。
③ 弱哈希算法名来自 .properties 配置（`props.getProperty("hashAlg1")`
   而 benchmark.properties 里 hashAlg1=MD5）：规则要求算法名是字符串
   字面量，非常量即漏（BenchmarkTest00710 等 3 条）。

三条测试在修复前全部为红，修复后转绿，用于锁住这三类回归。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.a1_injection_heuristic import analyze_content  # noqa: E402
from src.core.proof_obligations import has_sql_injection_source_evidence  # noqa: E402

JAVA_LANG = "java"


# ── ① JDBC 转义语法（存储过程调用 `{call ...}`）───────────────────────────────

_CALL_SQL = '''
public class BenchmarkTest00008 extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String sql = "{call " + param + "}";
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        java.sql.ResultSet rs = statement.executeQuery();
    }
}
'''


def test_callable_statement_concat_is_detected():
    """`{call " + param + "}` 是真实 SQL 注入形态，必须被 SQL 拼接规则认出。

    修复前：拼接规则的 SQL 关键字白名单只有 SELECT/INSERT/UPDATE/DELETE，
    OWASP Benchmark 用 `{call ...}` 表示存储过程调用，整类漏检。
    """
    hits = analyze_content("/tmp/BenchmarkTest00008.java", _CALL_SQL, JAVA_LANG)
    sql_hits = [h for h in hits if h.type == "SQL Injection"]
    assert sql_hits, (
        "`{call \" + param + \"}` 未被任何 SQL 规则命中；"
        f"实际出条={[(h.type, h.sink) for h in hits]}"
    )


def test_call_syntax_does_not_fire_without_taint():
    """负例：`{call sp_name}` 是纯字面量，无拼接、无外部输入，不应出条。"""
    benign = '''
public class SafeProc extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String sql = "{call sp_reset_db}";
        java.sql.CallableStatement statement = connection.prepareCall(sql);
    }
}
'''
    hits = analyze_content("/tmp/SafeProc.java", benign, JAVA_LANG)
    assert not [h for h in hits if h.type == "SQL Injection"], (
        "纯字面量存储过程调用被误报为 SQL 注入"
    )


# ── ② 非标准污点源的 SQL source evidence ────────────────────────────────────

class _V:
    """has_sql_injection_source_evidence 只用到这几个属性。"""

    def __init__(self, type_="SQL Injection", description="", code_snippet="",
                 data_flow="", sink="", a1_evidence=None):
        self.type = type_
        self.description = description
        self.code_snippet = code_snippet
        self.data_flow = data_flow
        self.sink = sink
        self.a1_evidence = a1_evidence or {}


@pytest.mark.parametrize("snippet,label", [
    ('java.util.Map<String, String[]> map = request.getParameterMap();', "getParameterMap"),
    ('java.util.Enumeration<String> names = request.getParameterNames();', "getParameterNames"),
    ('String[] values = request.getParameterValues(name);', "getParameterValues"),
    ('javax.servlet.http.Cookie[] theCookies = request.getCookies();', "getCookies"),
    ('String param = scr.getTheParameter("BenchmarkTest01552");', "自定义包装类getter"),
    ('String param = request.getHeader("BenchmarkTest00008");', "getHeader"),
])
def test_sqli_source_evidence_recognises_nonstandard_sources(snippet, label):
    """非标准污点源形态必须能支撑 SQL 注入的 source evidence。

    修复前 has_sql_injection_source_evidence 的文本兜底只认硬编码的
    `getparameter(` 等 token：getParameterNames( / getParameterValues( 因
    后缀不匹配而漏，getCookies( 与自定义 getter 整类漏。结果 A2 已判「真漏洞」
    的候选被 A21 以 missing query-like source evidence 刷掉，永不生成 spec。
    """
    v = _V(code_snippet=snippet, description=snippet)
    assert has_sql_injection_source_evidence(v, parameter_name="BenchmarkTest01552"), (
        f"{label} 形态未被认作 SQL 注入的 source evidence"
    )


def test_sqli_source_evidence_still_rejects_no_source():
    """负例：完全没有任何外部输入的描述，不应凭空判定有 source evidence。"""
    v = _V(description="内部常量拼接，无外部输入", code_snippet='String sql = "SELECT 1";')
    assert not has_sql_injection_source_evidence(v, parameter_name="id")


# ── ③ 弱哈希算法名来自 .properties 配置 ──────────────────────────────────────

_HASH_FROM_PROPS = '''
public class BenchmarkTest00710 extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        java.util.Properties benchmarkprops = new java.util.Properties();
        benchmarkprops.load(this.getClass().getClassLoader()
                .getResourceAsStream("benchmark.properties"));
        String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
        md.update(input);
    }
}
'''


def test_weak_hash_resolved_from_properties():
    """算法名来自 .properties 配置时应能折叠成常量再判定。

    实测 benchmark.properties 里 hashAlg1=MD5（真弱哈希）。修复前规则要求
    getInstance("MD5") 形式的字符串字面量，变量形式整类漏检（hash 族漏 3 条）。
    """
    props = {"hashAlg1": "MD5", "hashAlg2": "SHA-256"}
    hits = analyze_content(
        "/tmp/BenchmarkTest00710.java", _HASH_FROM_PROPS, JAVA_LANG,
        properties_map=props,
    )
    weak = [h for h in hits if "弱哈希" in str(h.type)]
    assert weak, (
        f"算法名来自 properties(hashAlg1=MD5) 的弱哈希未被检出；"
        f"实际出条={[(h.type, h.sink) for h in hits]}"
    )


def test_weak_hash_properties_not_weak_stays_negative():
    """负例：配置里是安全算法（SHA-256）时不应报弱哈希。

    这条是防「见 getProperty 就报」的粗暴修法——必须真的读到值再判。
    """
    safe_props = {"hashAlg1": "SHA-256"}
    hits = analyze_content(
        "/tmp/BenchmarkTest00710.java", _HASH_FROM_PROPS, JAVA_LANG,
        properties_map=safe_props,
    )
    assert not [h for h in hits if "弱哈希" in str(h.type)], (
        "配置值为安全算法 SHA-256 却被报弱哈希"
    )
