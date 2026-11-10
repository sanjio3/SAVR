import unittest

from src.agents.a2_intelligent_agent import A2SemanticAgent
from src.core.models import ScanResult, Vulnerability


class A2CanonicalizationTests(unittest.TestCase):
    def setUp(self):
        self.agent = A2SemanticAgent.__new__(A2SemanticAgent)

    def test_canonicalize_prefers_http_controller_and_keeps_supporting_nodes(self):
        controller = Vulnerability(
            type="Insecure Deserialization",
            severity="HIGH",
            file="src/main/java/com/quote/controller/DebugController.java",
            line=24,
            description="HTTP import endpoint reaches a deserialization chain",
            code_snippet='public String importConfig(@RequestParam String data)',
            entry_point="/debug/import",
            sink="importConfig",
            has_http_entry=True,
            callers="DebugController#importConfig",
            verdict="⚠️ A2:可疑-Java反序列化需A3验证",
            source="a2",
        )
        service = Vulnerability(
            type="JDK Serialization",
            severity="HIGH",
            file="src/main/java/com/quote/service/QuoteService.java",
            line=73,
            description="Imported object is forwarded to the quote cache",
            code_snippet="setQuoteCache(userConfig)",
            sink="setQuoteCache",
            has_call_chain=True,
            callers="QuoteService#setQuoteCache",
            verdict="⚠️ A2:可疑-Java反序列化需A3验证",
            source="a2",
        )
        processor = Vulnerability(
            type="Insecure Deserialization",
            severity="HIGH",
            file="src/main/java/com/quote/processor/CacheProcessor.java",
            line=42,
            description="Deserialized object reaches process(userConfig)",
            code_snippet="processor.process(userConfig)",
            sink="processor.process",
            has_call_chain=True,
            callers="CacheProcessor#process",
            verdict="⚠️ A2:可疑-Java反序列化需A3验证",
            source="a2",
        )

        results = [
            ScanResult(file=controller.file, vulnerabilities=[controller], agent="a2"),
            ScanResult(file=service.file, vulnerabilities=[service], agent="a2"),
            ScanResult(file=processor.file, vulnerabilities=[processor], agent="a2"),
        ]

        canonicalized = self.agent.canonicalize_scan_results(results)
        kept = [v for result in canonicalized for v in result.vulnerabilities]

        # 2026-09-18（A2 方案二）：被吸收成员不再被丢弃，改为补一行（is_absorbed=True）。
        # 故 kept = 1 条 canonical + 2 条补行；canonical 的选取与 supporting_nodes 不变。
        self.assertEqual(len(kept), 3)
        canonicals = [v for v in kept if v.is_canonical]
        self.assertEqual(len(canonicals), 1)
        canonical = canonicals[0]
        self.assertEqual(canonical.file, controller.file)
        self.assertEqual(canonical.line, controller.line)
        self.assertTrue(canonical.is_canonical)
        self.assertEqual(canonical.canonical_group_key, "deserialization:project_chain")
        self.assertEqual(canonical.chain_id, "deserialization:project_chain")
        self.assertEqual(canonical.proof_tier, "chain_proven")
        self.assertTrue(canonical.chain_proof["reachable"])
        self.assertTrue(canonical.chain_proof["attacker_control_proven"])
        self.assertEqual(canonical.supporting_node_count, 2)
        self.assertEqual(
            {(node["file"], node["line"]) for node in canonical.supporting_nodes},
            {
                (service.file, service.line),
                (processor.file, processor.line),
            },
        )
        # 补行必须各自回到自己所在文件，且带归属标记 —— 这是覆盖率统计与关联桥恢复的前提。
        absorbed = [v for v in kept if v.is_absorbed]
        self.assertEqual(len(absorbed), 2)
        self.assertEqual(
            {(v.file, v.line) for v in absorbed},
            {
                (service.file, service.line),
                (processor.file, processor.line),
            },
        )
        for vuln in absorbed:
            self.assertFalse(vuln.is_canonical)
            self.assertEqual(vuln.absorbed_by_group_key, "deserialization:project_chain")
            self.assertEqual(vuln.canonical_group_key, "deserialization:project_chain")
            self.assertEqual(vuln.chain_id, "deserialization:project_chain")

    def test_canonicalize_assigns_generic_chain_key_to_reachable_http_findings(self):
        ssrf = Vulnerability(
            type="SSRF",
            severity="HIGH",
            file="vault/app.py",
            line=197,
            description="dashboard route reaches outbound request",
            entry_point="ROUTE /dashboard",
            has_call_chain=True,
            verdict="true positive",
            source="a2",
        )
        results = [ScanResult(file=ssrf.file, vulnerabilities=[ssrf], agent="a2")]

        canonicalized = self.agent.canonicalize_scan_results(results)
        kept = [v for result in canonicalized for v in result.vulnerabilities]

        self.assertEqual(len(kept), 1)
        canonical = kept[0]
        self.assertTrue(canonical.is_canonical)
        # 2026-10-02（发难清单 Q2）：通用兜底键去行号化——chain_id 一律走行号无关弱键
        # （family:chain:<stable_vuln_key>），行号漂移不再改变聚合键。旧行号键
        # "ssrf:vault/app.py:197" 已废弃。
        self.assertTrue(canonical.canonical_group_key.startswith("ssrf:chain:"))
        self.assertNotIn(":197", canonical.canonical_group_key)
        self.assertEqual(canonical.chain_id, canonical.canonical_group_key)

    def test_resolve_parameter_name_from_static_ignores_database_keyword(self):
        vuln = Vulnerability(
            type="Insecure Default Configuration",
            severity="MEDIUM",
            description="The application uses a default SQLite database and creates an admin user.",
            entry_point="GET /",
        )

        # Q3：不再正则猜测；无 A1 静态证据时返回空串，由登记阶段结合观测请求面解析。
        parameter = self.agent._resolve_parameter_name_from_static(vuln)

        self.assertEqual(parameter, "")

    def test_sql_injection_signal_requires_query_and_attacker_control_evidence(self):
        self.assertFalse(
            self.agent._has_sql_injection_signal(
                "The application uses sqlite:///vault.db as a default database configuration."
            )
        )
        self.assertTrue(
            self.agent._has_sql_injection_signal(
                "request.args.get('q') reaches cursor.execute(select * from users where name = ...)"
            )
        )

    def test_java_expression_chain_is_normalized_as_template_injection(self):
        vuln = Vulnerability(
            type="SpEL Injection",
            severity="HIGH",
            file="com/ctf/gateway/service/EvaluationService.java",
            line=24,
            description="SpelExpressionParser.parseExpression(expression, new TemplateParserContext())",
            code_snippet="return this.parser.parseExpression(expression, new TemplateParserContext()).getValue(String.class);",
            callers="GatewayController.checkRule(@RequestParam String rule)",
            entry_point="GET /check",
            has_http_entry=True,
        )

        family = self.agent._canonical_family(vuln)
        group_key = self.agent._early_chain_group_key(vuln)
        exploit_spec = self.agent._build_exploit_spec(vuln)

        self.assertEqual(family, "template-injection")
        self.assertEqual(group_key, "template-injection:expression_chain")
        self.assertEqual(exploit_spec["entry"]["route"], "/check")
        self.assertEqual(exploit_spec["entry"]["method"], "GET")
        self.assertEqual(exploit_spec["entry"]["parameter_name"], "rule")
        self.assertEqual(exploit_spec["payload"]["payload_family"], "template-injection")

    def test_expression_chain_prefers_template_sink_over_controller_xss(self):
        controller = Vulnerability(
            type="XSS",
            severity="HIGH",
            file="com/ctf/gateway/controller/GatewayController.java",
            line=37,
            description="rule is concatenated into the HTML response",
            code_snippet='result = (String)result + "<br><b>Flag:</b>" + content;',
            entry_point="GET /check",
            has_http_entry=True,
            source="a2",
        )
        service = Vulnerability(
            type="SpEL Injection",
            severity="HIGH",
            file="com/ctf/gateway/service/EvaluationService.java",
            line=24,
            description="SpelExpressionParser.parseExpression(expression, new TemplateParserContext())",
            code_snippet="return this.parser.parseExpression(expression, new TemplateParserContext()).getValue(String.class);",
            callers="GatewayController.checkRule(@RequestParam String rule)",
            entry_point="GET /check",
            has_call_chain=True,
            source="a2",
        )

        results = [
            ScanResult(file=controller.file, vulnerabilities=[controller], agent="a2"),
            ScanResult(file=service.file, vulnerabilities=[service], agent="a2"),
        ]

        canonicalized = self.agent.canonicalize_scan_results(results)
        kept = [v for result in canonicalized for v in result.vulnerabilities]

        # 2026-09-18（A2 方案二）：1 条 canonical（SpEL 侧）+ 1 条补行（controller XSS 侧）。
        self.assertEqual(len(kept), 2)
        canonical = next(v for v in kept if v.is_canonical)
        self.assertEqual(canonical.canonical_group_key, "template-injection:expression_chain")
        self.assertEqual(canonical.file, service.file)
        absorbed = [v for v in kept if v.is_absorbed]
        self.assertEqual(len(absorbed), 1)
        self.assertEqual(absorbed[0].file, controller.file)
        self.assertEqual(absorbed[0].absorbed_by_group_key, "template-injection:expression_chain")
        self.assertEqual(canonical.exploit_spec["payload"]["payload_family"], "template-injection")
        self.assertEqual(canonical.exploit_spec["entry"]["route"], "/check")
        self.assertEqual(canonical.exploit_spec["entry"]["parameter_name"], "rule")


if __name__ == "__main__":
    unittest.main()
