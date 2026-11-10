import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import PropertyMock, patch

from src.agents.a2_ai_agent import (
    A2AIAgent,
    AnthropicCompatibleClient,
    DeepseekClient,
    DoubaoClient,
    QwenClient,
    FallbackLLMClient,
    load_anthropic_compatible_config,
)
from src.agents.a2_intelligent_agent import A2SemanticAgent


class _FakeClient:
    def __init__(self, name, fail_with=None, out=None):
        self.name = name
        self.fail_with = fail_with
        self.out = out

    def create_message(self, *a, **k):
        if self.fail_with:
            raise Exception(self.fail_with)
        return self.out


class A2ProviderConfigTests(unittest.TestCase):
    """本文件全部是「构造 + 配置解析」断言，不做真实 LLM 调用。

    2026-09-20 修复：FallbackLLMClient.create_message 内部会写 model_runs 台账，
    而这里用 _FakeClient 假客户端驱动它 —— 假客户端不发网络请求，但会把
    provider=deepseek/glm 的假行写进生产库 data/app.db（实测 5 条）。
    故整文件置静音开关，既避免污染，也避免污染「id 水位线」判云端混入的口径。
    """

    def setUp(self):
        self._prev_flag = os.environ.get("SAST_AI_DISABLE_MODEL_RUN_LOG")
        os.environ["SAST_AI_DISABLE_MODEL_RUN_LOG"] = "1"

    def tearDown(self):
        if self._prev_flag is None:
            os.environ.pop("SAST_AI_DISABLE_MODEL_RUN_LOG", None)
        else:
            os.environ["SAST_AI_DISABLE_MODEL_RUN_LOG"] = self._prev_flag

    def test_semantic_agent_wraps_qwen_in_fallback_chain(self):
        agent = A2SemanticAgent(
            {
                "api": {"provider": "qwen"},
                "qwen": {
                    "api_key": "qwen-secret",
                    "base_url": "https://dashscope.aliyuncs.com/api/v1",
                    "model": "qwen-plus",
                },
                "agents": {"a2": {"prompts_file": "src/prompts/audit_prompts.yaml"}},
            },
            provider="doubao",
        )

        self.assertIsInstance(agent.client, FallbackLLMClient)
        self.assertEqual(agent.provider, "qwen")
        self.assertEqual(len(agent.client.clients), 1)
        self.assertIsInstance(agent.client.clients[0], QwenClient)
        self.assertEqual(agent.client.clients[0].base_url, "https://dashscope.aliyuncs.com/api/v1")

    def test_semantic_agent_wraps_doubao_in_fallback_chain(self):
        agent = A2SemanticAgent(
            {
                "api": {"provider": "doubao"},
                "doubao": {
                    "api_key": "doubao-secret",
                    "base_url": "https://ark.cn-beijing.volces.com/api/v3",
                    "model": "doubao-pro-32k",
                },
                "agents": {"a2": {"prompts_file": "src/prompts/audit_prompts.yaml"}},
            },
            provider="qwen",
        )

        self.assertIsInstance(agent.client, FallbackLLMClient)
        self.assertEqual(agent.provider, "doubao")
        self.assertIsInstance(agent.client.clients[0], DoubaoClient)

    def test_ai_agent_chains_primary_deepseek_then_glm_fallback(self):
        from src.agents import a2_ai_agent as a2_module

        values = {
            "api.provider": "deepseek",
            "agents.a2.max_lines_per_request": 500,
            "agents.a2.prompts_file": "src/prompts/audit_prompts.yaml",
            "deepseek": {
                "api_key": "ds-key",
                "base_url": "https://api.maorongheai.site/v1",
                "model": "Deepseek-V4-Flash",
                "thinking_intensity": "medium",
            },
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4.5-air",
                "auth_mode": "x-api-key",
            },
            "qwen.api_key": "",
            "doubao.api_key": "",
            "minimax.api_key": "",
            "claude.api_key": "",
        }

        def fake_get(key, default=None):
            return values.get(key, default)

        with patch.object(a2_module.config, "get", side_effect=fake_get), patch.object(
            type(a2_module.config), "claude_api_key", new_callable=PropertyMock, return_value=""
        ):
            agent = A2AIAgent(provider="deepseek")

            self.assertIsInstance(agent.client, FallbackLLMClient)
            self.assertEqual(agent.provider, "deepseek")
            self.assertEqual(agent.model, "Deepseek-V4-Flash")
            # 顺序降级链：主用 deepseek -> 兜底 GLM(anthropic-compatible)
            self.assertEqual(agent.client.provider_names, ["deepseek", "anthropic-compatible"])
            self.assertIsInstance(agent.client.clients[0], DeepseekClient)
            self.assertIsInstance(agent.client.clients[1], AnthropicCompatibleClient)

    def test_ai_agent_falls_back_to_glm_when_primary_unconfigured(self):
        from src.agents import a2_ai_agent as a2_module

        values = {
            "api.provider": "deepseek",
            "agents.a2.max_lines_per_request": 500,
            "agents.a2.prompts_file": "src/prompts/audit_prompts.yaml",
            "deepseek": {},
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4.5-air",
                "auth_mode": "x-api-key",
            },
            "qwen.api_key": "",
            "doubao.api_key": "",
            "minimax.api_key": "",
            "claude.api_key": "",
        }

        def fake_get(key, default=None):
            return values.get(key, default)

        with patch.object(a2_module.config, "get", side_effect=fake_get), patch.object(
            type(a2_module.config), "claude_api_key", new_callable=PropertyMock, return_value=""
        ):
            agent = A2AIAgent(provider="deepseek")

            # 主用 deepseek 缺 key -> 链中只剩兜底 GLM
            self.assertIsInstance(agent.client, FallbackLLMClient)
            self.assertEqual(agent.provider, "deepseek")
            self.assertEqual(len(agent.client.clients), 1)
            self.assertIsInstance(agent.client.clients[0], AnthropicCompatibleClient)

    def test_load_anthropic_compatible_config_from_claude_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_dir = Path(tmpdir)
            (settings_dir / "settings.json.qwen").write_text(
                """
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://coding.dashscope.aliyuncs.com/apps/anthropic",
    "ANTHROPIC_AUTH_TOKEN": "sk-sp-test-token",
    "ANTHROPIC_MODEL": "qwen3-coder-plus"
  }
}
                """.strip(),
                encoding="utf-8",
            )

            resolved = load_anthropic_compatible_config(
                configured={"source": "qwen", "settings_dir": str(settings_dir)}
            )

            self.assertEqual(resolved["api_key"], "sk-sp-test-token")
            self.assertEqual(resolved["base_url"], "https://coding.dashscope.aliyuncs.com/apps/anthropic")
            self.assertEqual(resolved["model"], "qwen3-coder-plus")

    def test_ai_agent_prefers_anthropic_compatible_provider(self):
        from src.agents import a2_ai_agent as a2_module

        values = {
            "api.provider": "anthropic-compatible",
            "agents.a2.max_lines_per_request": 500,
            "agents.a2.prompts_file": "src/prompts/audit_prompts.yaml",
            "anthropic_compatible": {
                "api_key": "compat-token",
                "base_url": "https://coding.dashscope.aliyuncs.com/apps/anthropic",
                "model": "qwen3-coder-plus",
                "auth_mode": "bearer",
            },
            "qwen.api_key": "",
            "doubao.api_key": "",
            "minimax.api_key": "",
            "claude.api_key": "",
        }

        def fake_get(key, default=None):
            return values.get(key, default)

        with patch.object(a2_module.config, "get", side_effect=fake_get), patch.object(
            type(a2_module.config), "claude_api_key", new_callable=PropertyMock, return_value=""
        ):
            agent = A2AIAgent(provider="qwen")

            self.assertIsInstance(agent.client, FallbackLLMClient)
            self.assertEqual(agent.provider, "anthropic-compatible")
            self.assertEqual(agent.model, "qwen3-coder-plus")
            self.assertEqual(len(agent.client.clients), 1)
            self.assertIsInstance(agent.client.clients[0], AnthropicCompatibleClient)

    def test_anthropic_compatible_client_normalizes_messages_endpoint(self):
        client = AnthropicCompatibleClient(
            api_key="compat-token",
            model="qwen3-coder-plus",
            base_url="https://coding.dashscope.aliyuncs.com/apps/anthropic",
        )
        self.assertEqual(
            client._messages_endpoint(),
            "https://coding.dashscope.aliyuncs.com/apps/anthropic/v1/messages",
        )

    def test_fallback_llm_client_prefers_primary(self):
        fb = FallbackLLMClient(
            [_FakeClient("deepseek", out="DS-OK"), _FakeClient("glm", out="GLM-OK")],
            ["deepseek", "glm"],
        )
        self.assertEqual(fb.create_message("s", [{}]), "DS-OK")
        self.assertEqual(fb.last_used, "deepseek")

    def test_fallback_llm_client_switches_on_failure(self):
        fb = FallbackLLMClient(
            [_FakeClient("deepseek", fail_with="API error: 429 quota"), _FakeClient("glm", out="GLM-OK")],
            ["deepseek", "glm"],
        )
        self.assertEqual(fb.create_message("s", [{}]), "GLM-OK")
        self.assertEqual(fb.last_used, "glm")

    def test_fallback_llm_client_all_fail_raises(self):
        fb = FallbackLLMClient(
            [_FakeClient("deepseek", fail_with="429"), _FakeClient("glm", fail_with="500")],
            ["deepseek", "glm"],
        )
        with self.assertRaises(Exception):
            fb.create_message("s", [{}])


class ModelRunLedgerIsolationTests(unittest.TestCase):
    """回归守卫：假客户端不得把行写进生产 model_runs 台账。

    2026-09-20 事故：本文件三个 fallback 用例用 _FakeClient 驱动真实
    FallbackLLMClient，create_message 内的 _record_model_run 便把
    provider=deepseek×3 / glm×2 共 5 条假行写进 data/app.db（task_id=NULL），
    污染了「按 id 水位线判断是否有云端混入」的口径。
    """

    def setUp(self):
        self._prev_db = os.environ.get("SAST_AI_DB_PATH")
        self._prev_flag = os.environ.get("SAST_AI_DISABLE_MODEL_RUN_LOG")
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["SAST_AI_DB_PATH"] = str(Path(self._tmp.name) / "app.db")

    def tearDown(self):
        self._tmp.cleanup()
        for key, prev in (("SAST_AI_DB_PATH", self._prev_db),
                          ("SAST_AI_DISABLE_MODEL_RUN_LOG", self._prev_flag)):
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

    @staticmethod
    def _row_count(db_path: str) -> int:
        import sqlite3
        # 注意：不要用 f"file:{db_path}?mode=ro" —— Windows 反斜杠路径会让 URI 打开失败
        if not Path(db_path).exists():
            return 0
        # 注意：with sqlite3.connect(...) 只提交事务、不关闭连接，Windows 下会锁住文件
        conn = sqlite3.connect(db_path)
        try:
            return conn.execute("select count(*) from model_runs").fetchone()[0]
        except sqlite3.OperationalError:
            return 0
        finally:
            conn.close()

    def _drive_fake_clients(self):
        fb = FallbackLLMClient(
            [_FakeClient("deepseek", fail_with="429"), _FakeClient("glm", out="GLM-OK")],
            ["deepseek", "glm"],
        )
        self.assertEqual(fb.create_message("s", [{}]), "GLM-OK")

    def test_switch_off_is_the_polluting_default(self):
        # 开关关闭时确实会写台账 —— 这正是需要隔离的原因（假客户端也记）
        os.environ.pop("SAST_AI_DISABLE_MODEL_RUN_LOG", None)
        self._drive_fake_clients()
        self.assertEqual(self._row_count(os.environ["SAST_AI_DB_PATH"]), 2)

    def test_switch_on_silences_ledger_completely(self):
        os.environ["SAST_AI_DISABLE_MODEL_RUN_LOG"] = "1"
        self._drive_fake_clients()
        self.assertEqual(self._row_count(os.environ["SAST_AI_DB_PATH"]), 0)


if __name__ == "__main__":
    unittest.main()
