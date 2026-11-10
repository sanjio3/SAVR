"""A2「真实入口 ground-truth + RAG 检索增强」回归测试。

覆盖 2026-09-01 落地的 4 项方案：
- ① RAG：``retrieve_rag_context`` 跨文件切片检索（只读 / 降级安全）。
- ② 一次 LLM 调用：语义判定与 payload 同上下文（由 ``llm_verdict`` 落库体现，见集成测试）。
- ③ 前移解析：``_pre_resolve_a2_endpoints`` 在 plan_pocs 之前把 route/method/param 写回
  ``exploit_spec.entry``，并标记 ``entry_resolved``。
- ④ AP 正确性：类级 ``@RequestMapping`` 前缀拼接（/status→/api/status）；
  族名归一（spel/IDOR 合并）；解析不出入口的漏洞标「无可达入口」不进 D2。
"""
import os
import shutil
import tempfile
import unittest

from src.core.param_resolver import (
    normalize_payload_family,
    resolve_trigger_endpoint,
)
from src.core.code_retriever import retrieve_rag_context
from src.agents.a2_contract_planner import A2ContractPlanner
from src.core.models import ScanResult, Vulnerability


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class NormalizePayloadFamilyTests(unittest.TestCase):
    def test_template_injection_aliases_merge(self):
        for raw in ("spel", "ognl", "ssti", "template-injection", "freemarker",
                    "velocity", "thymeleaf", "el-injection", "expression-injection", "jexl"):
            self.assertEqual(normalize_payload_family(raw), "template-injection", raw)

    def test_idor_aliases_merge(self):
        for raw in ("idor", "bola", "bfla", "broken-access-control",
                    "object-level", "function-level", "authz", "insecure-direct-object"):
            self.assertEqual(normalize_payload_family(raw), "idor", raw)

    def test_canonical_families_untouched(self):
        for raw in ("sql-injection", "command-execution", "deserialization",
                    "ssrf", "xss", "path-traversal", "file-upload", "xxe"):
            self.assertEqual(normalize_payload_family(raw), raw, raw)

    def test_empty_and_generic_pass_through(self):
        self.assertEqual(normalize_payload_family(""), "")
        self.assertEqual(normalize_payload_family("generic"), "generic")


class ClassLevelPrefixResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="a2rt_")
        # 类级前缀 + 方法级路由（用于验证 /status → /api/status 拼接）
        self.class_file = os.path.join(self.tmp, "QuoteController.java")
        _write(self.class_file, (
            "package com.quote.controller;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "\n"
            "@RestController\n"
            '@RequestMapping("/api")\n'
            "public class QuoteController {\n"
            "    @GetMapping(\"/status\")\n"
            "    public String status(@RequestParam String status) {\n"
            "        return status;\n"
            "    }\n"
            "}\n"
        ))
        # 无类级前缀，纯方法级路由
        self.plain_file = os.path.join(self.tmp, "PingController.java")
        _write(self.plain_file, (
            "package com.quote.controller;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "\n"
            "@RestController\n"
            "public class PingController {\n"
            "    @GetMapping(\"/status\")\n"
            "    public String status(@RequestParam String id) {\n"
            "        return id;\n"
            "    }\n"
            "}\n"
        ))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_class_level_prefix_concatenation(self):
        vuln = Vulnerability(
            type="SSTI", severity="HIGH",
            file="QuoteController.java", line=999,
        )
        resolved = resolve_trigger_endpoint(vuln, {}, code_root=self.tmp)
        self.assertTrue(resolved.get("resolvable"))
        self.assertEqual(resolved.get("route"), "/api/status")
        self.assertEqual(resolved.get("method"), "GET")
        self.assertEqual(resolved.get("param_name"), "status")
        self.assertEqual(resolved.get("param_location"), "query")

    def test_method_level_route_without_class_prefix(self):
        vuln = Vulnerability(
            type="SSTI", severity="HIGH",
            file="PingController.java", line=999,
        )
        resolved = resolve_trigger_endpoint(vuln, {}, code_root=self.tmp)
        self.assertTrue(resolved.get("resolvable"))
        self.assertEqual(resolved.get("route"), "/status")
        self.assertEqual(resolved.get("param_name"), "id")


class PreResolveEndpointsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="a2pre_")
        self.ok_file = os.path.join(self.tmp, "QuoteController.java")
        _write(self.ok_file, (
            "package com.quote.controller;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "\n"
            "@RestController\n"
            '@RequestMapping("/api")\n'
            "public class QuoteController {\n"
            "    @GetMapping(\"/status\")\n"
            "    public String status(@RequestParam String status) {\n"
            "        return status;\n"
            "    }\n"
            "}\n"
        ))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pre_resolve_marks_reachable_and_writes_entry(self):
        from src.cli.benchmark_cli import _pre_resolve_a2_endpoints
        vuln = Vulnerability(type="SSTI", severity="HIGH", file="QuoteController.java", line=999)
        scan = ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")
        _pre_resolve_a2_endpoints([scan], code_root=self.tmp)
        self.assertTrue(getattr(vuln, "entry_resolved", False))
        res = getattr(vuln, "entry_resolution", {})
        self.assertEqual(res.get("route"), "/api/status")
        self.assertEqual(vuln.exploit_spec["entry"]["route"], "/api/status")
        self.assertEqual(vuln.exploit_spec["entry"]["method"], "GET")
        self.assertEqual(vuln.exploit_spec["entry"]["parameter_name"], "status")

    def test_pre_resolve_marks_unreachable_and_keeps_entry(self):
        from src.cli.benchmark_cli import _pre_resolve_a2_endpoints
        # 无 file / 无路由 → 解析不出可达入口
        vuln = Vulnerability(type="Command Injection", severity="HIGH", file="", line=0)
        # A2 已给出 ground-truth 入口（如靶场里 A2 静态定位的 route），解析失败不应抹掉它
        vuln.exploit_spec["entry"]["route"] = "bogus"
        vuln.exploit_spec["entry"]["method"] = "POST"
        scan = ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")
        _pre_resolve_a2_endpoints([scan], code_root=self.tmp)
        self.assertFalse(getattr(vuln, "entry_resolved", True))
        self.assertEqual(getattr(vuln, "entry_resolution", {}).get("resolvable"), False)
        # Q3②：不再清空 entry，保留 A2 既有的 ground truth（route 仍为 bogus）
        self.assertEqual(vuln.exploit_spec["entry"]["route"], "bogus")
        # 但必须显式落解析失败原因，门禁据此（而非「全部清空」的副作用）判定 no_reachable_entry
        self.assertTrue(vuln.exploit_spec["entry"].get("entry_resolution_failure"))


class NoReachableEntryGateTests(unittest.TestCase):
    def _build_complete_vuln(self):
        # 结构完整（route/method/family/signal/callers/is_canonical 齐全），
        # 若没有「无可达入口」硬门禁，应当被选中——用来证明门禁确实拦截。
        vuln = Vulnerability(
            type="Command Injection", severity="HIGH",
            file="Util.java", line=9,
            entry_point="POST route:/admin/run",
            has_http_entry=True, has_call_chain=True,
            callers="http param reaches Runtime.exec",
            verdict="✅ A2:真漏洞-有危险sink",
        )
        vuln.is_canonical = True
        vuln.exploit_spec["entry"]["route"] = "/admin/run"
        vuln.exploit_spec["entry"]["method"] = "POST"
        vuln.exploit_spec["entry"]["parameter_name"] = "cmd"
        vuln.exploit_spec["payload"]["payload_family"] = "command-execution"
        vuln.exploit_spec["success_signal"]["signal_type"] = "response_body"
        return vuln

    def test_gate_blocks_when_entry_resolved_false(self):
        agent = A2ContractPlanner()
        vuln = self._build_complete_vuln()
        # 模拟 _pre_resolve_a2_endpoints 解析失败后的标记
        setattr(vuln, "entry_resolved", False)
        planned = agent.plan_vulnerability(vuln)
        self.assertFalse(planned.a21_selected)
        self.assertIn("no_reachable_entry", planned.a21_reason)

    def test_no_gate_when_entry_resolved_true(self):
        agent = A2ContractPlanner()
        vuln = self._build_complete_vuln()
        setattr(vuln, "entry_resolved", True)
        planned = agent.plan_vulnerability(vuln)
        self.assertTrue(planned.a21_selected)
        self.assertNotIn("no_reachable_entry", planned.a21_reason)


class RagRetrievalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="a2rag_")
        # route /api/quote/status 连续出现在源码，便于 _find_controller_file 命中
        self.ctrl = os.path.join(self.tmp, "QuoteController.java")
        _write(self.ctrl, (
            "package com.quote.controller;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "\n"
            '@RequestMapping("/api")\n'
            "public class QuoteController {\n"
            "    @GetMapping(\"/quote/status\")\n"
            "    public String status(@RequestParam String q) {\n"
            "        return q;\n"
            "    }\n"
            "}\n"
        ))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _vuln(self):
        vuln = Vulnerability(type="Template Injection", severity="HIGH",
                             file="QuoteController.java", line=999)
        vuln.exploit_spec["entry"]["route"] = "/api/quote/status"
        vuln.exploit_spec["payload"]["payload_family"] = "template-injection"
        return vuln

    def test_rag_hits_controller_slice(self):
        ctx = retrieve_rag_context(self._vuln(), self.tmp)
        self.assertTrue(ctx, "RAG 应返回非空上下文")
        self.assertIn("QuoteController", ctx)
        self.assertIn("@GetMapping", ctx)

    def test_rag_degrades_on_missing_code_root(self):
        self.assertEqual(retrieve_rag_context(self._vuln(), None), "")

    def test_rag_degrades_on_nonexistent_dir(self):
        self.assertEqual(retrieve_rag_context(self._vuln(), os.path.join(self.tmp, "nope")), "")


if __name__ == "__main__":
    unittest.main()
