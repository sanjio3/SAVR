"""§四 零测试核心模块落地测试。

覆盖 测试清单.md §四 登记的 3 个零测试核心模块：
- src/core/poc_generator.py      (PoC 生成器)
- src/core/proof_obligations.py  (证据义务 / 证明链)
- src/core/shared_context.py     (跨阶段共享上下文)

设计：全部为离线、确定性单测，不依赖 docker daemon / 网络 / 外部进程。
对真实执行路径（docker build / echo 子进程）只验证"返回结构正确"，不在 CI 触发副作用。
"""
import os
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from src.core import poc_generator as pg
from src.core import proof_obligations as po
from src.core import shared_context as sc
from src.core.models import Vulnerability


# ===========================================================================
# 1. poc_generator
# ===========================================================================
SPRING_SNIPPET = """package com.quote;
import org.springframework.web.bind.annotation.*;
@RestController
public class UserController {
    @GetMapping(value = "/api/user/{id}")
    public User get(@PathVariable("id") String id) {
        // vuln here
        return repo.findById(id);
    }
}
"""


class TestPocGenerator:
    def test_extract_endpoint_spring(self):
        ep = pg.extract_endpoint_from_code(SPRING_SNIPPET, 6)
        assert ep["path"] == "/api/user/{id}"
        assert ep["method"] == "GET"
        assert ep["framework"] == "spring"
        assert any(p["name"] == "id" for p in ep["params"])

    def test_extract_endpoint_empty(self):
        ep = pg.extract_endpoint_from_code("", 0)
        assert ep["path"] == ""
        assert ep["method"] == "GET"

    def test_infer_param_from_vuln(self):
        assert pg._infer_param_from_vuln("SQL Injection") == "id"
        assert pg._infer_param_from_vuln("Command Injection") == "cmd"
        assert pg._infer_param_from_vuln("SSRF") == "url"
        assert pg._infer_param_from_vuln("Path Traversal") == "path"
        assert pg._infer_param_from_vuln("Open Redirect") == "next"
        assert pg._infer_param_from_vuln("weird") == "input"

    def test_generate_context_aware_poc(self):
        poc = pg.generate_context_aware_poc(
            {"type": "sql", "code_snippet": "select"},
            {"path": "/api/x", "method": "POST", "params": []},
        )
        assert poc["path"] == "/api/x"
        assert poc["method"] == "POST"
        assert poc["test_param"]  # 退化为推断参数
        assert poc["vuln_type"] == "sql"

    def test_poc_generator_generate_poc(self):
        p = pg.POCGenerator()
        out = p.generate_poc("SQL Injection", "http://h/v", "id")
        for k in ("name", "description", "python", "java", "nodejs", "curl"):
            assert k in out
        assert out["target_url"] == "http://h/v"
        assert out["param"] == "id"
        assert "id" in out["python"]

    def test_poc_generator_vuln_type_key_mapping(self):
        p = pg.POCGenerator()
        assert p._get_vuln_type_key("命令注入") == "command_injection"
        assert p._get_vuln_type_key("XSS") == "xss"
        assert p._get_vuln_type_key("unknown-thing") == "sql_injection"  # 默认

    def test_safe_format_template_keeps_literal_braces(self):
        p = pg.POCGenerator()
        tpl = "print('{raw}') and {target_url}"
        rendered = p._safe_format_template(tpl, target_url="http://h")
        assert "http://h" in rendered
        assert "{raw}" in rendered  # 字面量大括号被保留

    def test_generate_pocs_for_results_with_context(self):
        vulns = [{"type": "SQL Injection", "file": "src/UserController.java", "line": 6}]
        results = pg.POCGenerator().generate_pocs_for_results(
            vulns, project_language="java", file_contents={"src/UserController.java": SPRING_SNIPPET}
        )
        assert len(results) == 1
        assert "poc" in results[0]
        assert results[0]["poc"]["context_extracted"] is True
        assert results[0]["poc"]["python"]


# ===========================================================================
# 2. proof_obligations
# ===========================================================================
EVIDENCE = {
    "source_candidates": [
        {"name": "id", "location": "query", "file": "a.java", "line": 10},
        {"name": "url", "location": "query", "file": "a.java", "line": 20},
        {"name": "token", "location": "header", "file": "a.java", "line": 30},
    ],
    "guard_candidates": [{"name": "checkAuth", "route": "/api/x", "file": "a.java", "line": 5}],
    "sanitizer_candidates": [],
}


class TestProofObligations:
    def test_empty_summary_shape(self):
        s = po.empty_proof_context_summary()
        assert "entry_candidate_count" in s
        assert s["entry_candidate_count"] == 0

    def test_merge_a1_evidence(self):
        merged = po.merge_a1_evidence(
            {"source_candidates": [{"name": "x"}]},
            {"source_candidates": [{"name": "y"}]},
        )
        assert len(merged["source_candidates"]) == 2

    def test_pick_nearest_candidate(self):
        cands = [
            {"file": "a.java", "line": 100},
            {"file": "a.java", "line": 12},
            {"file": "b.java", "line": 10},
        ]
        vuln = SimpleNamespace(file="a.java", line=10)
        best = po.pick_nearest_candidate(vuln, cands)
        assert best["line"] == 12

    def test_pick_nearest_none(self):
        assert po.pick_nearest_candidate(SimpleNamespace(file="a.java", line=1), []) is None

    def test_summarize_counts(self):
        vuln = SimpleNamespace(file="a.java", line=10)
        summary = po.summarize_proof_context(vuln, EVIDENCE)
        assert summary["source_candidate_count"] == 3
        assert summary["guard_candidate_count"] == 1

    def test_is_ssrf_source_candidate(self):
        assert po.is_ssrf_source_candidate({"name": "url"})
        assert po.is_ssrf_source_candidate({"name": "target"})
        assert not po.is_ssrf_source_candidate({"name": "id"})

    def test_has_ssrf_source_evidence(self):
        vuln = SimpleNamespace(file="a.java", line=10)
        assert po.has_ssrf_source_evidence(vuln, EVIDENCE) is True
        assert po.has_ssrf_source_evidence(vuln, {"source_candidates": []}) is False

    def test_has_sql_source_evidence(self):
        vuln = SimpleNamespace(file="a.java", line=10)
        assert po.has_sql_injection_source_evidence(vuln, "id", EVIDENCE) is True
        assert po.has_sql_injection_source_evidence(vuln, "zzz", {"source_candidates": []}) is False

    def test_has_idor_source_evidence(self):
        vuln = SimpleNamespace(file="a.java", line=10)
        assert po.has_idor_source_evidence(vuln, "id", EVIDENCE) is True
        assert po.has_idor_source_evidence(vuln, "zzz", {"source_candidates": []}) is False

    def test_has_auth_source_evidence(self):
        vuln = SimpleNamespace(file="a.java", line=10)
        assert po.has_auth_source_evidence(vuln, "token", EVIDENCE) is True
        # 非 auth 参数名 -> 立即 False
        assert po.has_auth_source_evidence(vuln, "id", EVIDENCE) is False

    def test_merge_supporting_text(self):
        vuln = SimpleNamespace(type="SQL", description="d", code_snippet="s", entry_point="e",
                               sink="k", data_flow="f", callers="c", verdict="v", file="x.java")
        text = po.merge_supporting_text(vuln)
        assert "sql" in text.lower()

    def test_evaluate_proof_obligations_returns_dict(self):
        vuln = SimpleNamespace(file="a.java", line=10, type="SQL Injection", has_http_entry=True)
        result = po.evaluate_proof_obligations(
            vuln,
            {"entry": {"route": "/api/x", "parameter_name": "id", "parameter_location": "query"},
             "payload": {"payload_family": "sql-injection"}},
            evidence=EVIDENCE,
        )
        assert isinstance(result, dict)
        assert "reachable" in result
        assert result["proof_confidence"] in ("high", "medium", "low")


# ===========================================================================
# 3. shared_context
# ===========================================================================
class TestSharedContext:
    def test_init_defaults(self):
        ctx = sc.SharedContext("/tmp/proj")
        assert ctx.project_path == "/tmp/proj"
        assert ctx.state == sc.ContextState.INITIAL
        assert ctx.vulnerabilities == {"a1": [], "a2": [], "d2": []}

    def test_update_project_info(self):
        ctx = sc.SharedContext("")
        ctx.update_project_info("path", "/x")
        assert ctx.project_info.path == "/x"

    def test_vulnerability_lifecycle(self):
        ctx = sc.SharedContext("")
        v = Vulnerability(type="SQL Injection", severity="high", file="a.java", line=1)
        ctx.add_vulnerability("a1", v)
        assert len(ctx.get_vulnerabilities("a1")) == 1
        v2 = Vulnerability(type="XSS", severity="medium", file="b.java", line=2)
        ctx.add_vulnerability("a2", v2)
        merged = ctx.merge_vulnerabilities()
        assert len(merged) == 2

    def test_decisions(self):
        ctx = sc.SharedContext("")
        ctx.add_decision("a1", "skip", {"why": "no source"})
        assert ctx.get_decisions("a1")[0]["type"] == "skip"
        assert len(ctx.get_decisions()) == 1

    def test_progress_and_state(self):
        ctx = sc.SharedContext("")
        ctx.update_progress("a1", completed=True, percent=50)
        assert ctx.progress.a1_completed is True
        ctx.set_state(sc.ContextState.ANALYZING)
        assert ctx.get_state() == sc.ContextState.ANALYZING

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            ctx = sc.SharedContext(os.path.join(td, "proj"))
            v = Vulnerability(type="SQL Injection", severity="high", file="a.java", line=1)
            ctx.add_vulnerability("a1", v)
            path = os.path.join(td, "ctx.json")
            ctx.save_to_file(path)
            assert os.path.exists(path)
            loaded = sc.SharedContext.load_from_file(path)
            assert loaded.project_path == ctx.project_path

    def test_to_dict(self):
        ctx = sc.SharedContext("")
        d = ctx.to_dict()
        assert isinstance(d, dict)
        assert "vulnerabilities" in d

    def test_global_accessors(self):
        unique = os.path.join(tempfile.gettempdir(), "savr_unique_proj_xyz")
        ctx = sc.get_shared_context(unique)
        assert isinstance(ctx, sc.SharedContext)
        reset = sc.reset_shared_context(unique)
        assert isinstance(reset, sc.SharedContext)


