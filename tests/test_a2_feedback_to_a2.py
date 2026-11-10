"""P4 回归（2026-09-02）：I2 裁决产出的 feedback_to_a2 必须真正接回 A2 标准通道。

此前断点：run_a2_scan / A2PipelineService.scan_files 已把 feedback 透传到 A2Agent.scan_file，
但 scan_file 只把 feedback 传给 _build_exploit_spec（事后 exploit_spec 修正），从未喂给
A2SemanticAgent.analyze → _ai_deep_analysis 的 LLM prompt。即 A2 二次分析「看不见」I2 反馈，
闭环修正对语义分析无效。

修复：scan_file 把 feedback 写入 context['feedback']，_ai_deep_analysis 把反馈段渲染进 prompt；
rerun_a2_with_feedback 作为二次回灌标准入口（复用 run_a2_scan(feedback=...)）。

测试锁死：①feedback 注入 A2 deep-analysis prompt；②无 feedback 时不注入；③rerun_a2_with_feedback
把 feedback 透传给 run_a2_scan 并经 plan_pocs 投影。
"""

import json
import unittest
from unittest import mock

from src.agents.a2_intelligent_agent import A2SemanticAgent


class _FakeLLMClient:
    """记录所有 prompt，返回合法漏洞 JSON，便于断言 feedback 是否进入 deep-analysis prompt。"""

    def __init__(self):
        self.prompts = []

    def create_message(self, system, messages, **kwargs):
        self.prompts.append(messages[0]["content"] if messages else "")
        return json.dumps({
            "vulnerabilities": [
                {"type": "SQL Injection", "file": "X.java", "line": 1, "description": "x"}
            ]
        })


class TestA2FeedbackToA2Prompt(unittest.TestCase):
    def _agent(self):
        agent = A2SemanticAgent({})
        agent.client = _FakeLLMClient()
        # 自包含模板，避免依赖 yaml 是否含 {context} 占位
        agent.prompts = {"semantic_analysis": "CODE:\n{code}\nFILE:{file_path}\nCTX:\n{context}"}
        return agent

    def test_feedback_injected_into_a2_deep_analysis_prompt(self):
        agent = self._agent()
        fb = [{
            "hypothesis_id": "h42",
            "final_state": "no_evidence",
            "reason": "端点幻觉，真实端点应为 /admin/users",
            "correction_hint": {"endpoint": "/admin/users"},
            "current_spec": {"target_endpoint": "/ops/user/delete"},
            "missing_chain_nodes": ["sink"],
        }]
        agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": fb})
        prompt = agent.client.prompts[0]
        self.assertIn("D2/I2 闭环回灌反馈", prompt)
        self.assertIn("h42", prompt)                          # 假说 id 透传
        self.assertIn("/ops/user/delete", prompt)            # 当前(错误)假说端点被回显
        self.assertIn("/admin/users", prompt)                # 修正提示被注入
        self.assertIn("端点幻觉", prompt)

    def test_no_feedback_no_injection(self):
        agent = self._agent()
        agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": []})
        self.assertNotIn("D2/I2 闭环回灌反馈", agent.client.prompts[0])


class TestRerunA2WithFeedback(unittest.TestCase):
    @mock.patch("src.cli.benchmark_cli.A2PipelineService")
    @mock.patch("src.cli.benchmark_cli.run_a2_scan")
    def test_rerun_wires_feedback_into_run_a2_scan(self, mock_run, mock_svc):
        from src.cli.benchmark_cli import rerun_a2_with_feedback

        fake_results = ["r1"]
        mock_run.return_value = (fake_results, "llm")
        mock_svc.plan_pocs.return_value = ["planned"]

        fb = [{"hypothesis_id": "h1", "reason": "端点幻觉"}]
        out = rerun_a2_with_feedback(
            files=[{"rel_path": "X.java", "content": "x"}],
            feedback=fb,
            discovered_routes=[{"route": "/a"}],
            code_root="/tmp/x",
        )
        self.assertEqual(out, ["planned"])
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get("feedback"), fb)  # 反馈必须透传给 run_a2_scan
        mock_svc.plan_pocs.assert_called_once_with(
            fake_results, llm_client="llm", a1_evidence_index=None,
            code_root="/tmp/x", code_index=None,
        )


class TestA2AgenticSwitch(unittest.TestCase):
    """2026-09-17（Agentic 闭环）开关与多轮路径回归。

    锁死两件极易复发的事故：
    ① 开关取值必须兼容嵌套 dict 形态的 config（benchmark_cli.run_a2_scan 组装的是
       {'api': {...}, 'agents': {...}}，直接 config.get('agents.a2.xxx') 恒取不到，
       开关静默失效且无任何报错）；
    ② 取 feedback 必须从入参 context（dict）取，不能从已拼成字符串的 context_info 取——
       后者会抛 'str' object has no attribute 'get'，被 _ai_deep_analysis 末尾 except
       吞掉，表现为「闭环二次分析整体静默归零」。
    """

    def _agent(self, config):
        agent = A2SemanticAgent(config)
        agent.client = _FakeLLMClient()
        agent.prompts = {"semantic_analysis": "CODE:\n{code}\nFILE:{file_path}\nCTX:\n{context}"}
        return agent

    def test_switch_reads_nested_dict_config(self):
        cfg = {"agents": {"a2": {"enable_agentic_loop": True, "agentic_max_rounds": 5}}}
        agent = self._agent(cfg)
        self.assertTrue(agent._agentic_enabled)
        self.assertEqual(agent._agentic_max_rounds, 5)

    def test_switch_defaults_off_and_empty_config_safe(self):
        self.assertFalse(self._agent({})._agentic_enabled)
        self.assertFalse(self._agent({"agents": {}})._agentic_enabled)
        self.assertEqual(self._agent({})._agentic_max_rounds, 3)

    def test_agentic_enabled_still_produces_vulnerabilities(self):
        """开启 agentic 后，闭环二次分析必须照常产出结果（不能因工具循环静默归零）。"""
        agent = self._agent({"agents": {"a2": {"enable_agentic_loop": True}}})
        fb = [{"hypothesis_id": "h42", "final_state": "no_evidence", "reason": "端点幻觉"}]
        vulns = agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": fb})
        self.assertEqual(len(vulns), 1)
        # 反馈段仍须进入 prompt（agentic 不绕过回灌语义）
        self.assertIn("D2/I2 闭环回灌反馈", agent.client.prompts[0])

    def test_feedback_nonempty_must_not_silently_zero_out(self):
        """feedback 非空时不得因取值错误被 except 吞掉（回归：在 str 上调 .get）。"""
        agent = self._agent({})
        fb = [{"hypothesis_id": "h42", "final_state": "no_evidence", "reason": "端点幻觉"}]
        vulns = agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": fb})
        self.assertEqual(len(vulns), 1, "feedback 非空时 _ai_deep_analysis 不得返回空")


class TestA2AgenticFailOpen(unittest.TestCase):
    """2026-09-18：agentic 是增强路径，失败必须回退单次 completion，绝不静默归零。

    若让异常冒到 _ai_deep_analysis 末尾的 except，会被吞成 return []，
    表现为「feedback 非空时 A2 一条都不产且不报错」——与 9-17 的 context_info.get
    事故同一形态。真实 LLM 下工具输出畸形 / 网络抖动都可能触发，必须在这一层拦住。
    """

    def _agent(self):
        agent = A2SemanticAgent({"agents": {"a2": {"enable_agentic_loop": True}}})
        agent.client = _FakeLLMClient()
        agent.prompts = {"semantic_analysis": "CODE:\n{code}\nFILE:{file_path}\nCTX:\n{context}"}
        return agent

    def test_agentic_exception_falls_back_to_single_shot(self):
        agent = self._agent()
        fb = [{"hypothesis_id": "h42", "reason": "端点幻觉"}]
        with mock.patch("src.agents.a2_agentic.run_agentic_loop",
                        side_effect=RuntimeError("tool output malformed")):
            vulns = agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": fb})
        self.assertEqual(len(vulns), 1, "agentic 抛异常必须回退单次 completion，不得返回空")
        self.assertEqual(len(agent.client.prompts), 1)

    def test_agentic_empty_text_falls_back_to_single_shot(self):
        """多轮跑完却没结论文本（模型只吐 TOOL 行 / 达上限未结论）同样要回退。"""
        agent = self._agent()
        fb = [{"hypothesis_id": "h42", "reason": "端点幻觉"}]
        with mock.patch("src.agents.a2_agentic.run_agentic_loop",
                        return_value={"text": "", "rounds": 3, "tool_calls": [], "stopped_by": "max_rounds"}):
            vulns = agent._ai_deep_analysis("void f(){}", "X.java", {"feedback": fb})
        self.assertEqual(len(vulns), 1, "agentic 空结论必须回退单次 completion")


if __name__ == "__main__":
    unittest.main()
