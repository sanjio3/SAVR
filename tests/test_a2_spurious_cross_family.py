"""A2 侧「跨族无 sink 即捏造」门禁回归守卫（2026-10-29）。

背景：hash / xss 的安全用例上，A2 自建出 sql_injection finding，而该文件里连
sql/jdbc/statement 关键字都没有。A1 侧早有同一道闸（spurious_no_sink），但 A2 自建
finding 不走那条路 ⇒ 长期贡献 5 个跨族 FP（01045 / 01169 / 01348 / 01586 / 01661）。

本测试锁三件事：
  1. 文件里没有该族 API ⇒ 该 finding 被剔除；
  2. 同文件里本族 finding 不受影响（不能把整份结果清空）；
  3. 文件里有该族 API ⇒ 不剔除（绝不误杀真漏洞）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cli.benchmark_cli import _drop_spurious_cross_family  # noqa: E402

HASH_ONLY = """
public class T {
    public void doPost() throws Exception {
        String algorithm = "SHA-256";
        java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);
        md.update(new byte[]{1});
    }
}
"""

WITH_SQL = """
public class T {
    public void doPost() throws Exception {
        java.sql.Connection c = null;
        java.sql.Statement st = c.createStatement();
        st.executeQuery("select * from users where id = '" + x + "'");
    }
}
"""


class _V:
    def __init__(self, vtype):
        self.type = vtype


class _R:
    def __init__(self, path, types):
        self.file = path
        self.vulnerabilities = [_V(t) for t in types]


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_drops_sql_injection_on_hash_file(tmp_path):
    p = _write(tmp_path, "Hash.java", HASH_ONLY)
    r = _R(p, ["sql_injection", "weak_hash"])
    _drop_spurious_cross_family([r], str(tmp_path))
    assert [v.type for v in r.vulnerabilities] == ["weak_hash"]


def test_keeps_sql_injection_when_file_has_sql(tmp_path):
    p = _write(tmp_path, "Sql.java", WITH_SQL)
    r = _R(p, ["sql_injection"])
    _drop_spurious_cross_family([r], str(tmp_path))
    assert [v.type for v in r.vulnerabilities] == ["sql_injection"]


def test_unregistered_family_untouched(tmp_path):
    """path_traversal 不在 _SINK_PATTERNS（会误杀真漏洞）⇒ 一律不动。"""
    p = _write(tmp_path, "Path.java", HASH_ONLY)
    r = _R(p, ["path_traversal"])
    _drop_spurious_cross_family([r], str(tmp_path))
    assert [v.type for v in r.vulnerabilities] == ["path_traversal"]


def test_missing_file_is_fail_open(tmp_path):
    r = _R(str(tmp_path / "nope.java"), ["sql_injection"])
    _drop_spurious_cross_family([r], str(tmp_path))
    assert [v.type for v in r.vulnerabilities] == ["sql_injection"]


def test_empty_input_safe():
    assert _drop_spurious_cross_family([], "") == []
    assert _drop_spurious_cross_family(None, "") is None


def test_relative_path_under_subroot_resolves(tmp_path):
    """2026-10-29（本轮实证）：vuln.file 是相对路径，而 code_root 已是子根。

    直接 join 会得到 .../src/main/java/src/main/java/... （不存在）⇒ code 为空 ⇒
    门禁静默空转，01586/01661 两个跨族 FP 因此漏掉。必须走 _resolve_source_path。
    """
    sub = tmp_path / "src" / "main" / "java"
    (sub / "org" / "owasp" / "benchmark" / "testcode").mkdir(parents=True)
    p = sub / "org" / "owasp" / "benchmark" / "testcode" / "BenchmarkTest01586.java"
    # 必须有 xss 族的 sink（getWriter/println），否则 xss finding 也会被判「无 sink」，
    # 用例就变成「两条都被剔除」，测不出「只剔除跨族那条」。
    p.write_text(HASH_ONLY + "\nresponse.getWriter().println(v);\n", encoding="utf-8")

    rel = r"src\main\java\org\owasp\benchmark\testcode\BenchmarkTest01586.java"
    r = _R(rel, ["sql_injection", "xss"])
    _drop_spurious_cross_family([r], str(sub))
    assert [v.type for v in r.vulnerabilities] == ["xss"]


def test_relative_path_under_subroot_resolves(tmp_path):
    """2026-10-29（本轮实证）：vuln.file 是相对路径，而 code_root 已是子根。

    直接 join 会得到 .../src/main/java/src/main/java/... （不存在）⇒ code 为空 ⇒
    门禁静默空转，01586/01661 两个跨族 FP 因此漏掉。必须走 _resolve_source_path。
    """
    sub = tmp_path / "src" / "main" / "java"
    (sub / "org" / "owasp" / "benchmark" / "testcode").mkdir(parents=True)
    p = sub / "org" / "owasp" / "benchmark" / "testcode" / "BenchmarkTest01586.java"
    # 必须有 xss 族的 sink（getWriter/println），否则 xss finding 也会被判「无 sink」，
    # 用例就变成「两条都被剔除」，测不出「只剔除跨族那条」。
    p.write_text(HASH_ONLY + "\nresponse.getWriter().println(v);\n", encoding="utf-8")

    rel = r"src\main\java\org\owasp\benchmark\testcode\BenchmarkTest01586.java"
    r = _R(rel, ["sql_injection", "xss"])
    _drop_spurious_cross_family([r], str(sub))
    assert [v.type for v in r.vulnerabilities] == ["xss"]


# --------------------------------------------------------------------------- #
# 登记阶段门禁（2026-10-30）：A2 产出 type=unknown，族在登记时才推断出来，
# 上游门禁按 finding 自己的 type 判会漏（01586/01661）。这里用**最终族**再判一次。
# --------------------------------------------------------------------------- #
from src.iast.trigger_spec_registry import (  # noqa: E402
    spurious_no_sink_at_registration as _gate_at_reg,
)


def test_registration_gate_relative_path(tmp_path):
    sub = tmp_path / "src" / "main" / "java"
    (sub / "org" / "owasp" / "benchmark" / "testcode").mkdir(parents=True)
    p = sub / "org" / "owasp" / "benchmark" / "testcode" / "BenchmarkTest01586.java"
    p.write_text(HASH_ONLY, encoding="utf-8")
    rel = r"src\main\java\org\owasp\benchmark\testcode\BenchmarkTest01586.java"
    assert _gate_at_reg(str(sub), rel, "sql_injection") is True
    assert _gate_at_reg(str(sub), rel, "weak_hash") is False


def test_registration_gate_keeps_real_sql(tmp_path):
    p = tmp_path / "Sql.java"
    p.write_text(WITH_SQL, encoding="utf-8")
    assert _gate_at_reg(str(tmp_path), "Sql.java", "sql_injection") is False


def test_registration_gate_uncovered_family_untouched(tmp_path):
    p = tmp_path / "P.java"
    p.write_text(HASH_ONLY, encoding="utf-8")
    assert _gate_at_reg(str(tmp_path), "P.java", "path_traversal") is False
    assert _gate_at_reg(str(tmp_path), "P.java", "trust_boundary_violation") is False


def test_registration_gate_fail_open(tmp_path):
    assert _gate_at_reg(str(tmp_path), "missing.java", "sql_injection") is False
    assert _gate_at_reg("", "", "sql_injection") is False
