"""A2 族名证据纠正的兜底回读 与 族名自洽校验（2026-09-18，E2 评审）。

两件事：

1. 兜底回读源文件：LLM 未回带 code 时，族名纠正规则看不到 jsonp / callback 等关键证据，
   纠正静默失效——run 17 实测 Jsonp.java:L56、Object2Jsonp.java:L75 两条因 code_snippet
   为空仍留 csrf。现在按行号回读源文件兜底（只用于判定，不写回 code_snippet）。

2. 族名自洽校验：original_type 归一后的族与最终 family 不一致、且不在有意纠正白名单内时，
   打 family_mismatch 标记并告警。实测 id=4840 属此形态：
   original_type="SSRF/开放重定向"（归一为 ssrf）而最终 family=csrf。
"""
from pathlib import Path

from src.agents.a2_intelligent_agent import A2SemanticAgent, _correct_llm_family
from src.benchmark.report_manager import ReportManager

JSONP_SOURCE = """package com.x;

import org.springframework.web.bind.annotation.*;

@RestController
public class Object2Jsonp {

    @RequestMapping("/jsonp/obj")
    public String objCallback(@RequestParam String callback) {
        return callback + "({\\"a\\":1})";
    }
}
"""


def _agent_with_root(root: Path) -> A2SemanticAgent:
    """绕过 __init__（会初始化 LLM client），只构造带 project_path 的实例。"""
    agent = A2SemanticAgent.__new__(A2SemanticAgent)
    agent.project_path = str(root)
    return agent


class TestSourceSnippetFallback:
    """按行号回读源文件窗口。"""

    def test_reads_window_around_line(self, tmp_path: Path):
        src = tmp_path / "Sample.java"
        src.write_text("\n".join("line%d" % i for i in range(1, 201)), encoding="utf-8")
        agent = _agent_with_root(tmp_path)

        snippet = agent._source_snippet_for_family_check("Sample.java", 75, context_lines=40)

        assert "line75" in snippet
        assert "line35" in snippet
        assert "line34" not in snippet

    def test_missing_file_returns_empty(self, tmp_path: Path):
        agent = _agent_with_root(tmp_path)
        assert agent._source_snippet_for_family_check("Nope.java", 10) == ""

    def test_absolute_path_works_without_project_path(self, tmp_path: Path):
        src = tmp_path / "Abs.java"
        src.write_text("a\nb\nc\n", encoding="utf-8")
        agent = A2SemanticAgent.__new__(A2SemanticAgent)
        agent.project_path = ""

        assert "b" in agent._source_snippet_for_family_check(str(src), 2)

    def test_unknown_line_returns_head(self, tmp_path: Path):
        src = tmp_path / "Head.java"
        src.write_text("first\nsecond\n", encoding="utf-8")
        agent = _agent_with_root(tmp_path)

        assert "first" in agent._source_snippet_for_family_check("Head.java", None)


class TestFamilyCorrectionWithFallback:
    """回读兜底让族名纠正规则真正生效。"""

    def test_empty_code_without_source_keeps_family(self):
        """复现 run 17 的漏修场景：只有文件名（含 jsonp）、没有 callback 证据 → 不纠正。"""
        assert _correct_llm_family("CSRF", "Object2Jsonp.java", "") == "CSRF"

    def test_source_fallback_enables_correction(self, tmp_path: Path):
        """回读源文件后拿到 jsonp + callback 证据 → 纠正为 XSS。"""
        (tmp_path / "Object2Jsonp.java").write_text(JSONP_SOURCE, encoding="utf-8")
        agent = _agent_with_root(tmp_path)

        evidence = agent._source_snippet_for_family_check("Object2Jsonp.java", 9)
        assert "callback" in evidence.lower()
        assert _correct_llm_family("CSRF", "Object2Jsonp.java", evidence) == "XSS"


class TestFamilySelfCheck:
    """original_type 归一结果 vs 最终 family 的自洽判定。"""

    @staticmethod
    def _rm() -> ReportManager:
        return ReportManager.__new__(ReportManager)

    def test_matching_family_is_self_consistent(self):
        assert self._rm()._family_mismatch("CSRF", "csrf") == ""

    def test_unrelated_family_is_flagged(self):
        """实测 id=4840 的形态。"""
        assert self._rm()._family_mismatch("SSRF/开放重定向", "csrf") == "ssrf -> csrf"

    def test_intentional_fixes_are_allowed(self):
        rm = self._rm()
        assert rm._family_mismatch("XXE", "jndi_injection") == ""
        assert rm._family_mismatch("CSRF", "xss") == ""

    def test_blank_inputs_are_ignored(self):
        rm = self._rm()
        assert rm._family_mismatch("", "csrf") == ""
        assert rm._family_mismatch("CSRF", "") == ""
