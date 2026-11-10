"""「切换默认 provider 到本地模型」时的三处注册/路由缺口回归测试。

背景（2026-09-19）：把 api.provider 从云端切到本地 Ollama 时，实测发现三处
「provider 名换了但取不到对应配置」的缺口，每一处都会静默退化而不是报错：

1. ``benchmark_cli.run_a2_scan`` 的 ``agent_config['api']`` 少登记 ``ollama``
   与 ``fallback_provider`` → A2 拿到的是客户端硬编码默认值，且兜底仍走云端 GLM。
2. ``Config._aggregate_api_config`` 的 ``config.get('api')`` 同样缺这两项。
3. ``gateway_from_config`` 无条件从 ``anthropic_compatible`` 段取
   base_url/api_key/model → ``llm.provider: agnes`` 实测拿到智谱端点 + GLM key，
   请求必然鉴权失败后被 fail-open 静默降级为离线（A1 业务逻辑语义 / A1 CodeQL 语义 /
   业务逻辑 API / I2 裁决四条通路受影响）。

本文件全部为纯内存断言，不触网、不读 DB。
"""
import os
import unittest
from unittest import mock

from src.core.model_gateway import ModelGateway, gateway_from_config


class TestGatewayFromConfigProviderSection(unittest.TestCase):
    def test_uses_provider_own_section(self):
        # provider 写 ollama 时必须取 ollama 段，而不是 anthropic_compatible 段
        gw = gateway_from_config({
            "llm": {"provider": "ollama"},
            "ollama": {"base_url": "http://127.0.0.1:11434", "model": "qwen3:8b"},
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4-flash",
            },
        })
        self.assertEqual(gw.provider, "ollama")
        self.assertEqual(gw._base_url, "http://127.0.0.1:11434")
        self.assertEqual(gw.model, "qwen3:8b")
        self.assertEqual(gw._api_key, "")

    def test_keyless_provider_is_not_offline(self):
        # Ollama 本地服务无鉴权：没有 api_key 也必须算在线，否则整族静默回落离线
        gw = gateway_from_config({
            "llm": {"provider": "ollama"},
            "ollama": {"base_url": "http://127.0.0.1:11434", "model": "qwen3:8b"},
        })
        self.assertIs(gw.is_offline, False)

    def test_ollama_without_section_does_not_inherit_glm_credentials(self):
        # 配了 provider 名却没配专属段时，绝不能继承 GLM 的端点与凭据
        gw = gateway_from_config({
            "llm": {"provider": "ollama"},
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
            },
        })
        self.assertEqual(gw.provider, "ollama")
        self.assertEqual(gw._base_url, "")
        self.assertEqual(gw._api_key, "")
        self.assertIs(gw.is_offline, False)

    def test_agnes_does_not_inherit_glm_endpoint(self):
        # 回归守卫：这是切换前就存在的缺陷 —— llm.provider=agnes 却拿到智谱端点
        gw = gateway_from_config({
            "llm": {"provider": "agnes"},
            "agnes": {
                "api_key": "agnes-key",
                "base_url": "https://apihub.agnes-ai.com/v1",
                "model": "agnes-3.0-flash",
            },
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4-flash",
            },
        })
        self.assertEqual(gw.provider, "agnes")
        self.assertEqual(gw._base_url, "https://apihub.agnes-ai.com/v1")
        self.assertEqual(gw.model, "agnes-3.0-flash")
        self.assertEqual(gw._api_key, "agnes-key")

    def test_compat_family_still_reads_anthropic_compatible(self):
        # GLM 族沿用 anthropic_compatible 段（历史行为，另见 test_llm_codeql_config）
        gw = gateway_from_config({
            "llm": {"provider": "glm", "model": "glm-4.5-air"},
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4.5-air",
            },
        })
        self.assertEqual(gw.provider, "anthropic-compatible")
        self.assertEqual(gw._base_url, "https://open.bigmodel.cn/api/anthropic")

    def test_llm_section_overrides_provider_section(self):
        gw = gateway_from_config({
            "llm": {"provider": "ollama", "model": "qwen3:30b-a3b"},
            "ollama": {"base_url": "http://127.0.0.1:11434", "model": "qwen3:8b"},
        })
        self.assertEqual(gw.model, "qwen3:30b-a3b")
        self.assertEqual(gw._base_url, "http://127.0.0.1:11434")


class TestFallbackProviderConfigurable(unittest.TestCase):
    def _cfg(self, fallback, **extra):
        api = {
            "provider": "ollama",
            "ollama": {"base_url": "http://127.0.0.1:11434", "model": "qwen3:8b"},
            "anthropic_compatible": {
                "api_key": "glm-key",
                "base_url": "https://open.bigmodel.cn/api/anthropic",
                "model": "glm-4-flash",
            },
        }
        if fallback is not None:
            api["fallback_provider"] = fallback
        api.update(extra)
        return {"api": api}

    def test_empty_fallback_keeps_chain_local_only(self):
        # 本地跑必须不产生云端兜底，否则源码会在本地模型失败时静默外发
        client = ModelGateway.build_fallback_client(
            config=self._cfg(""), provider="ollama")
        self.assertEqual(client.provider_names, ["ollama"])

    def test_missing_key_keeps_historical_default(self):
        # 键缺失（老配置）时保留历史默认 anthropic-compatible，行为不变
        client = ModelGateway.build_fallback_client(
            config=self._cfg(None), provider="ollama")
        self.assertEqual(client.provider_names, ["ollama", "anthropic-compatible"])

    def test_explicit_fallback_argument_wins(self):
        client = ModelGateway.build_fallback_client(
            config=self._cfg(""), provider="ollama", fallback="anthropic-compatible")
        self.assertEqual(client.provider_names, ["ollama", "anthropic-compatible"])


class TestApiAggregateRegistersLocalProvider(unittest.TestCase):
    def test_aggregate_contains_ollama_and_fallback_provider(self):
        from src.core.config import Config
        import tempfile
        import os

        yaml_text = (
            "api:\n"
            "  provider: ollama\n"
            "  model: qwen3:8b\n"
            "  fallback_provider: ''\n"
            "ollama:\n"
            "  base_url: http://127.0.0.1:11434\n"
            "  model: qwen3:8b\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(yaml_text)
            path = fh.name
        try:
            cfg = Config()
            cfg.load(path)
            agg = cfg.get("api")
            self.assertIn("ollama", agg)
            self.assertIn("fallback_provider", agg)
            self.assertEqual(agg["ollama"]["base_url"], "http://127.0.0.1:11434")
            self.assertEqual(agg["provider"], "ollama")
        finally:
            os.unlink(path)


class TestRunA2ScanRegistersOllama(unittest.TestCase):
    """A2 主链路的 agent_config 必须带 ollama 与 fallback_provider。

    这是切换默认 provider 时最容易漏的一处：_provider_conf 取不到就静默用客户端
    硬编码默认值，表现为「改了 config.yaml 却毫无效果」。
    """

    def test_agent_config_api_registers_ollama(self):
        from src.cli import benchmark_cli
        from src.core.config import config as app_config

        captured = {}

        class _FakeSvc:
            def __init__(self, agent_config, provider):
                captured["agent_config"] = agent_config
                captured["provider"] = provider

            def scan_files(self, *a, **kw):
                return []

            def build_llm_client(self):
                return None

        with mock.patch.object(benchmark_cli, "A2PipelineService", _FakeSvc):
            benchmark_cli.run_a2_scan([])

        api = captured["agent_config"]["api"]
        self.assertIn("ollama", api)
        self.assertEqual(api["ollama"], app_config.get("ollama", {}))
        self.assertIn("fallback_provider", api)
        self.assertEqual(
            api["fallback_provider"],
            app_config.get("api.fallback_provider", "anthropic-compatible"),
        )
        self.assertEqual(captured["provider"], app_config.get("api.provider", "qwen"))


class TestProfileAdaptationForRealModels(unittest.TestCase):
    """Q2：画像要同时适配市面云端模型与本地模型。"""

    def setUp(self):
        from src.core import model_capabilities as mc
        self.mc = mc
        mc.clear_probe_cache()
        os.environ.pop("SAST_AI_OLLAMA_PROBE", None)

    def tearDown(self):
        self.mc.clear_probe_cache()
        os.environ.pop("SAST_AI_OLLAMA_PROBE", None)

    def test_mainstream_cloud_models_match_dedicated_profiles(self):
        cases = {
            "gpt-4o": "cloud-openai-large",
            "gpt-5": "cloud-openai-large",
            "claude-sonnet-4-6": "claude-large",
            "glm-4.5-air": "glm-large",
            "gemini-2.5-pro": "cloud-openai-large",
            "kimi-k2": "cloud-openai-large",
            "deepseek-v3": "cloud-openai-large",
            "qwen-max": "cloud-openai-large",
            # 中档：32k 上下文，够用且不虚报
            "qwen-turbo": "cloud-medium",
            "ernie-4.0": "cloud-medium",
            "doubao-pro-32k": "cloud-medium",
            "hunyuan-turbo": "cloud-medium",
        }
        for model, expected in cases.items():
            with self.subTest(model=model):
                p = self.mc.resolve_profile(model=model)
                self.assertEqual(p.name, expected, f"{model} -> {p.name}")
                self.assertGreaterEqual(p.context_window, 32000)

    def test_reasoning_models_prefer_reasoning_profile(self):
        # 顺序上 reasoning 排第一，必须先于云端/本地档命中
        for model in ("o1-preview", "o3", "o4-mini", "deepseek-reasoner",
                      "qwq-32b", "glm-z1-air", "qwen3-32b-thinking"):
            with self.subTest(model=model):
                self.assertEqual(self.mc.resolve_profile(model=model).name, "reasoning")

    def test_local_models_match_local_small(self):
        for model in ("qwen3:8b", "qwen3:30b-a3b", "llama3.1:8b", "gemma3:4b",
                      "phi4:14b", "mistral:7b", "deepseek-r1:8b"):
            with self.subTest(model=model):
                p = self.mc.resolve_profile(model=model, provider="ollama")
                self.assertEqual(p.name, "local-small")

    def test_unknown_cloud_model_uses_cloud_fallback(self):
        # 认不出的新云端模型：按 provider 归到云端兜底（不裁输入），而不是保守档
        p = self.mc.resolve_profile(model="some-brand-new-model-2099", provider="openai")
        self.assertEqual(p.name, self.mc.CLOUD_FALLBACK.name)
        self.assertIs(p, self.mc.CLOUD_FALLBACK)

    def test_unknown_model_unknown_provider_uses_conservative_fallback(self):
        p = self.mc.resolve_profile(model="mystery-model", provider="")
        self.assertIs(p, self.mc.SAFE_FALLBACK)
        self.assertEqual(p.context_window, 4096)

    def test_use_thinking_defaults_off_for_local(self):
        self.assertFalse(self.mc.resolve_profile(model="qwen3:8b", provider="ollama").use_thinking)

    def test_profile_yaml_override_applied_from_config_dir(self):
        # config/model_capabilities.yaml 必须真的生效（本地档 max_attempts=2）
        p = self.mc.resolve_profile(model="qwen3:8b", provider="ollama")
        self.assertEqual(p.max_attempts, 2)

    def test_same_name_override_is_field_level_not_whole_replace(self):
        """回归守卫：同名档位覆盖必须是逐字段的。

        原实现整体替换 → yaml 里没写的 `match` 被默认值（空）覆盖 → 该档位再也匹配不上
        任何模型名。实测症状：local-small 丢掉 `qwen3:\\d+b` 后，
        resolve_profile("qwen3:8b", provider="qwen") 掉进 CLOUD_FALLBACK。
        provider="ollama" 时靠 provider 回落命中，会把问题掩盖住。
        """
        base = [p for p in self.mc._BUILTIN_PROFILES if p.name == "local-small"][0]
        merged = self.mc._merge_profiles(
            list(self.mc._BUILTIN_PROFILES),
            [{"name": "local-small", "recommended_concurrency": 99}],  # 故意不写 match
        )
        got = [p for p in merged if p.name == "local-small"][0]
        self.assertEqual(got.recommended_concurrency, 99)          # 覆盖生效
        self.assertEqual(got.match_patterns, base.match_patterns)  # 未写的键必须保留
        self.assertEqual(got.use_thinking, base.use_thinking)

    def test_load_profiles_reports_bad_override_instead_of_silent_fallback(self):
        """回归守卫：yaml 加载/合并失败不能被宽 except 静默吞掉。

        曾把一个 NameError 吞了整整一轮，表现为「yaml 改了不生效」却毫无症状。
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "model_capabilities.yaml")
            with open(bad, "w", encoding="utf-8") as fh:
                # context_window 写成非数字 → int() 抛异常，进入 except 分支
                fh.write("profiles:\n  - name: local-small\n    context_window: not-a-number\n")
            with mock.patch.object(self.mc, "_candidate_config_paths", return_value=[bad]):
                with self.assertLogs("src.core.model_capabilities", level="WARNING") as logs:
                    self.mc.load_profiles(force_reload=True)
            self.assertTrue(
                any("加载/合并失败" in m for m in logs.output),
                f"未记录告警：{logs.output}",
            )
        # 回退到内置表，且清理缓存避免污染后续用例
        self.mc.load_profiles(force_reload=True)


class TestOllamaProbe(unittest.TestCase):
    """运行时探测：本地模型的真实 num_ctx 覆盖内置上下文值。"""

    def setUp(self):
        from src.core import model_capabilities as mc
        self.mc = mc
        mc.clear_probe_cache()
        os.environ.pop("SAST_AI_OLLAMA_PROBE", None)

    def tearDown(self):
        self.mc.clear_probe_cache()
        os.environ.pop("SAST_AI_OLLAMA_PROBE", None)

    def test_parse_num_ctx(self):
        self.assertEqual(self.mc._parse_num_ctx("num_ctx                        8192"), 8192)
        self.assertEqual(self.mc._parse_num_ctx("temperature 0.6\nnum_ctx 40960"), 40960)
        self.assertIsNone(self.mc._parse_num_ctx("temperature 0.6"))
        self.assertIsNone(self.mc._parse_num_ctx(""))

    def _fake_urlopen(self, payload):
        class _Resp:
            def read(self_inner):
                import json as _json
                return _json.dumps(payload).encode("utf-8")

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        return mock.patch("urllib.request.urlopen", return_value=_Resp())

    def test_probe_prefers_parameters_num_ctx_over_model_info(self):
        payload = {
            "capabilities": ["tools", "thinking", "completion"],
            "parameters": "num_ctx                        8192",
            "model_info": {"qwen3.context_length": 40960},
        }
        with self._fake_urlopen(payload):
            probe = self.mc.probe_ollama_model("qwen3:8b")
        self.assertEqual(probe["context_window"], 8192)
        self.assertTrue(probe["supports_tools"])
        self.assertTrue(probe["supports_thinking"])

    def test_probe_falls_back_to_model_info_when_parameters_lack_num_ctx(self):
        payload = {"capabilities": [], "parameters": "", "model_info": {"qwen3.context_length": 40960}}
        with self._fake_urlopen(payload):
            probe = self.mc.probe_ollama_model("qwen3:8b")
        self.assertEqual(probe["context_window"], 40960)

    def test_probe_fail_open_returns_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            self.assertIsNone(self.mc.probe_ollama_model("qwen3:8b"))

    def test_probe_disabled_by_env(self):
        os.environ["SAST_AI_OLLAMA_PROBE"] = "0"
        self.assertIsNone(self.mc.probe_ollama_model("qwen3:8b"))

    def test_runtime_override_replaces_context_window_for_ollama(self):
        payload = {"capabilities": ["completion"], "parameters": "num_ctx 20480", "model_info": {}}
        with self._fake_urlopen(payload):
            p = self.mc.resolve_profile(model="qwen3:8b", provider="ollama")
        self.assertEqual(p.context_window, 20480)

    def test_runtime_override_not_applied_for_cloud_provider(self):
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("不应探测云端")):
            p = self.mc.resolve_profile(model="qwen3:8b", provider="qwen")
        self.assertEqual(p.name, "local-small")


if __name__ == "__main__":
    unittest.main()
