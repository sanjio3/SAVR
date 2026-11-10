"""回归：确定性 A2 路径（_build_exploit_spec）按族填充默认攻击 payload。

背景：真实攻击载荷此前只在 A2ContractPlanner（LLM 路径）按族填充；走确定性
_build_exploit_spec 的 spec 不会经过该路径，导致 candidate_payloads 恒空 →
attack_payloads_json 落库为 [] → D1 重放退化为纯 canary → 注入族确认率 0%。
本测试保证确定性路径也能产出具体可利用 payload。
"""
import unittest

from src.core.models import Vulnerability
from src.agents.a2_intelligent_agent import A2SemanticAgent


def _agent():
    # 绕过 AI 客户端初始化（__init__ 会建 LLM client），仅构造空壳用于确定性方法。
    a = A2SemanticAgent.__new__(A2SemanticAgent)
    a.config = {}
    return a


class TestDefaultPayloads451(unittest.TestCase):
    def test_static_default_payload_table(self):
        table = {
            "sql-injection": ["' OR '1'='1", "\" OR \"1\"=\"1"],
            "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin"],
            "command-execution": ["; id", "| id", "$(id)"],
            "xss": ["<script>alert(1)</script>", "\"><svg/onload=alert(1)>"],
            "path-traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"],
            "xxe": ["<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"],
            "template-injection": ["${7*7}", "{{7*7}}", "T(java.lang.Runtime).getRuntime().exec('id')"],
        }
        for fam, expect in table.items():
            self.assertEqual(A2SemanticAgent._default_payloads_for_family(fam), expect)
        # 2026-10-14 更新（r89 根因 B）：默认载荷表改为**全覆盖**——每一族都有可注入载荷，
        # 消除"零载荷 spec"（此前 auth/race/cookie/generic 等族返回 [] → D1 纯 canary 重放
        # → 永久 no-arrival；r89 实测 1490 条零载荷）。取值保守、指向本地回环或明显标记。
        for fam in ("generic", "cookie", "cors", "csrf", "auth-bypass",
                    "race-condition", "workflow-bypass", "open-redirect", "jwt"):
            self.assertTrue(A2SemanticAgent._default_payloads_for_family(fam),
                            f"{fam} 应有默认载荷")
        self.assertEqual(A2SemanticAgent._default_payloads_for_family("idor"), ["alternate_owner_resource_id"])

    def test_build_exploit_spec_emits_sql_payload(self):
        a = _agent()
        v = Vulnerability(type="SQL Injection", severity="HIGH", line=1,
                         description="select where name=", file="X.java", sink="JDBC createStatement")
        spec = a._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "sql-injection")
        self.assertIn("' OR '1'='1", spec["payload"]["candidate_payloads"])
        self.assertTrue(spec["payload"]["verification_payloads"])

    def test_build_exploit_spec_emits_ssrf_payload(self):
        a = _agent()
        v = Vulnerability(type="SSRF", severity="MEDIUM", line=1,
                         description="ssrf outbound request", file="X.java", sink="new URL(...)")
        spec = a._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "ssrf")
        self.assertTrue(any("169.254.169.254" in p for p in spec["payload"]["candidate_payloads"]))

    def test_build_exploit_spec_emits_command_payload(self):
        a = _agent()
        v = Vulnerability(type="Command Injection", severity="HIGH", line=1,
                         description="run cmd rce", file="X.java", sink="Runtime.exec")
        spec = a._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "command-execution")
        self.assertTrue(spec["payload"]["candidate_payloads"])

    def test_cookie_position_does_not_hijack_xss_family(self):
        """run 31#26 实测回归（2026-09-22）：参数位置类族不得抢占真实漏洞族。

        实测形状：java-sec-code 的 XSS stored/show 端点用 @CookieValue("xss") 取参，
        code_snippet 因而含 cookie。旧映射顺序里 ("cookie",) 排在 ("xss",) 之前 →
        payload_family 被判成 cookie → 默认载荷表无此族 → attack_payloads_json=[] →
        D1 重放没有载荷可注入 → 该黄金项永久 no-arrival（而它的端点/参数名/参数位置/
        sink 行全部正确，唯一缺的就是载荷）。
        """
        a = _agent()
        v = Vulnerability(
            type="XSS", severity="MEDIUM", line=58, file="XSS.java",
            description="stored xss reflected to body", sink="return xss",
            code_snippet='public String show(@CookieValue("xss") String xss) { return xss; }',
        )
        spec = a._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "xss")
        self.assertTrue(spec["payload"]["candidate_payloads"])
        self.assertTrue(any("<script>" in p for p in spec["payload"]["candidate_payloads"]))

    def test_crlf_family_recognised_from_snippet(self):
        """CRLF 族此前无映射 → 落到 generic（实测 run 31#4，载荷被 LLM 给成命令注入形态）。"""
        a = _agent()
        v = Vulnerability(
            type="CRLF Injection", severity="MEDIUM", line=23, file="CRLFInjection.java",
            description="crlf header injection",
            sink='response.addHeader("test1", request.getParameter("test1"))',
        )
        spec = a._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "crlf-injection")
        self.assertTrue(spec["payload"]["candidate_payloads"])

    def test_newly_added_families_have_default_payloads(self):
        """2026-09-22 补齐的四族：CRLF / JSONP / JNDI / URL whitelist bypass。

        这四族此前在 _payload_family 里落到 generic，默认载荷表也没有条目 →
        走确定性路径的 spec 载荷恒空、重放退化为纯 canary。此处锁住载荷非空。
        """
        for fam, needle in (
            ("crlf-injection", "%0d%0a"),
            ("jsonp", "Callback"),
            ("jndi-injection", "${jndi:"),
            ("url-whitelist-bypass", "127.0.0.1"),
        ):
            payloads = A2SemanticAgent._default_payloads_for_family(fam)
            self.assertTrue(payloads, "%s 应有默认载荷" % fam)
            self.assertTrue(any(needle in p for p in payloads), "%s 载荷应含 %s" % (fam, needle))


if __name__ == "__main__":
    unittest.main()
