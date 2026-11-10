"""Ollama 原生端点客户端（OllamaNativeClient）与 CJK 感知输入预算的回归测试。

背景（2026-09-19）：项目接入本地 Qwen3-8B-Q4_K_M 时实测发现，Ollama 0.34.1 的
OpenAI 兼容层不认 think:false，Qwen3 的思维链会与正文争抢同一个输出预算，
预算不足时正文为空（finish_reason=length / content=''）。因此新增走原生 /api/chat
+ think:false 的客户端。本文件全部为打桩单测，不触网。
"""
import unittest
from unittest import mock

from src.agents import a2_ai_agent as A
from src.core import model_capabilities as mc


class _FakeResponse:
    def __init__(self, payload, status=200, ctype="application/json"):
        self._payload = payload
        self.status_code = status
        self.headers = {"content-type": ctype}
        self.text = ""

    def json(self):
        return self._payload

    def close(self):
        pass


class TestOllamaNativeClient(unittest.TestCase):
    def _client(self, model="qwen3:8b", num_ctx=None):
        return A.OllamaNativeClient(model=model, base_url="http://127.0.0.1:11434",
                                    num_ctx=num_ctx)

    def test_endpoint_and_v1_stripping(self):
        c = self._client()
        self.assertEqual(c._chat_endpoint(), "http://127.0.0.1:11434/api/chat")
        self.assertEqual(c._PROVIDER_NAME, "ollama")
        # 误填 OpenAI 兼容地址时应自动剥掉 /v1，避免拼出 /v1/api/chat
        c2 = A.OllamaNativeClient(base_url="http://127.0.0.1:11434/v1")
        self.assertEqual(c2._chat_endpoint(), "http://127.0.0.1:11434/api/chat")

    def test_request_shape_uses_native_endpoint_and_think_false(self):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["url"] = url
            captured["json"] = json
            captured["stream"] = stream
            return _FakeResponse({"message": {"role": "assistant", "content": "{}"},
                                  "done": True, "done_reason": "stop",
                                  "prompt_eval_count": 11, "eval_count": 3})

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            out = self._client().create_message("sys", [{"role": "user", "content": "hi"}],
                                                max_tokens=400, temperature=0.1)

        self.assertEqual(captured["url"], "http://127.0.0.1:11434/api/chat")
        body = captured["json"]
        self.assertIs(body["think"], False)
        self.assertIs(body["stream"], False)
        self.assertEqual(body["options"]["num_predict"], 400)
        self.assertEqual(body["model"], "qwen3:8b")
        # system 必须并入 messages（原生端点没有独立的 system 字段）
        self.assertEqual(body["messages"][0], {"role": "system", "content": "sys"})
        self.assertEqual(out, "{}")

    def test_num_ctx_only_sent_when_configured(self):
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["json"] = json
            return _FakeResponse({"message": {"content": "ok"}, "done_reason": "stop"})

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            self._client().create_message("", [{"role": "user", "content": "x"}])
        self.assertNotIn("num_ctx", captured["json"]["options"])

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            self._client(num_ctx=8192).create_message("", [{"role": "user", "content": "x"}])
        self.assertEqual(captured["json"]["options"]["num_ctx"], 8192)

    def test_profile_clamps_num_predict_not_only_max_tokens(self):
        """画像钳制必须同时落到 options.num_predict，否则模型按 4096 生成而画像以为 1024。"""
        captured = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["json"] = json
            return _FakeResponse({"message": {"content": "{}"}, "done_reason": "stop"})

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            self._client().create_message("", [{"role": "user", "content": "x"}],
                                          max_tokens=4096)
        ceiling = mc.resolve_profile("qwen3:8b", "ollama").max_output_tokens
        self.assertEqual(captured["json"]["max_tokens"], ceiling)
        self.assertEqual(captured["json"]["options"]["num_predict"], ceiling)

    def test_reasoning_fallback_when_content_empty(self):
        """think:false 万一未生效，也不能返回空串——空串会被当『模型判定无问题』。"""
        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            return _FakeResponse({"message": {"content": "", "reasoning": "思考后给出结论"},
                                  "done_reason": "stop"})

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            out = self._client().create_message("", [{"role": "user", "content": "x"}])
        self.assertEqual(out, "思考后给出结论")

    def test_cache_hit_must_return_text(self):
        """回归守卫：缓存命中时 request_chat_completion 返回 (None, text, tele)，
        客户端若只读 result 会返回空串 → 被上层当成「模型判定无问题」（P0-2 静默空值）。"""
        with mock.patch.object(A, "request_chat_completion",
                               return_value=(None, "CACHED_BODY", {"cached": True})):
            out = self._client().create_message("", [{"role": "user", "content": "x"}])
        self.assertEqual(out, "CACHED_BODY")

    def test_real_token_counts_are_reported(self):
        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            return _FakeResponse({"message": {"content": "{}"}, "done_reason": "stop",
                                  "prompt_eval_count": 1532, "eval_count": 130})

        with mock.patch.object(A.requests, "post", side_effect=fake_post):
            c = self._client()
            c.create_message("", [{"role": "user", "content": "x"}])
        self.assertEqual(c.last_call_telemetry.get("input_tokens"), 1532)
        self.assertEqual(c.last_call_telemetry.get("output_tokens"), 130)
        self.assertEqual(c.last_call_telemetry.get("finish_reason"), "stop")

    def test_ollama_usage_helper(self):
        self.assertEqual(A._ollama_usage({"prompt_eval_count": 5, "eval_count": 7}),
                         {"input_tokens": 5, "output_tokens": 7})
        self.assertEqual(A._ollama_usage({"prompt_eval_count": 0, "eval_count": 0}), {})
        self.assertEqual(A._ollama_usage(None), {})

    def test_finish_reason_from_done_reason(self):
        self.assertEqual(A._extract_finish_reason({"done_reason": "length"}, "ollama"), "length")
        self.assertEqual(A._extract_finish_reason({"done_reason": "stop"}, "ollama"), "stop")
        self.assertEqual(A._extract_finish_reason({}, "ollama"), "")

    def test_extract_text_ollama(self):
        self.assertEqual(A._extract_text({"message": {"content": "abc"}}, "ollama"), "abc")
        self.assertEqual(A._extract_text(None, "ollama"), "")

    def test_make_client_registers_ollama_without_api_key(self):
        c = A._make_client("ollama", {"ollama": {"model": "qwen3:8b"}})
        self.assertIsInstance(c, A.OllamaNativeClient)
        self.assertEqual(c.model, "qwen3:8b")
        c2 = A._make_client("ollama-native", {})
        self.assertIsInstance(c2, A.OllamaNativeClient)
        # 走 ModelGateway 远程分发入口也要认得
        c3 = A.build_client("ollama", "qwen3:8b", "")
        self.assertIsInstance(c3, A.OllamaNativeClient)


class TestCjkAwareTokenBudget(unittest.TestCase):
    def test_estimate_tokens_cjk_is_much_larger_than_len_over_4(self):
        chinese = "这是一个用于测试中文分词与 token 换算关系的句子。" * 20
        est = mc.estimate_tokens(chinese)
        self.assertGreater(est, len(chinese) // 4)
        # 该串以中文为主（夹杂 "token" 等 ASCII），估算值应接近字符数而非字符数/4
        self.assertGreaterEqual(est, int(len(chinese) * 0.7))

    def test_estimate_tokens_ascii_near_len_over_4(self):
        english = "This is a sentence used to measure the token ratio. " * 20
        est = mc.estimate_tokens(english)
        self.assertLessEqual(abs(est - len(english) // 4), len(english) // 4 * 0.5)

    def test_estimate_tokens_empty(self):
        self.assertEqual(mc.estimate_tokens(""), 0)

    def test_fit_to_token_budget_cuts_and_stays_within(self):
        text = "public class A { void f(String s) { Runtime.getRuntime().exec(s); } }\n" * 200
        fitted, cut = mc.fit_to_token_budget(text, 500)
        self.assertTrue(cut)
        self.assertLessEqual(mc.estimate_tokens(fitted), 500)
        self.assertLess(len(fitted), len(text))

    def test_fit_to_token_budget_noop_when_within(self):
        text = "short"
        fitted, cut = mc.fit_to_token_budget(text, 100)
        self.assertFalse(cut)
        self.assertEqual(fitted, text)

    def test_fit_to_token_budget_zero_budget(self):
        fitted, cut = mc.fit_to_token_budget("abc", 0)
        self.assertEqual(fitted, "")
        self.assertTrue(cut)


class TestProfileMergeSemantics(unittest.TestCase):
    def test_local_small_resolves_by_provider_fallback(self):
        # 裸模型名 + provider=ollama 也要命中 local-small，不能掉进 SAFE_FALLBACK
        p = mc.resolve_profile(model="qwen3", provider="ollama")
        self.assertEqual(p.name, "local-small")
        self.assertEqual(p.context_window, 8192)

    def test_yaml_override_merges_by_name_without_dropping_cloud(self):
        base = list(mc._BUILTIN_PROFILES)
        merged = mc._merge_profiles(base, [
            {"name": "local-small", "tier": "local", "context_window": 6144},
            {"name": "brand-new-model", "tier": "small", "context_window": 2048},
        ])
        by_name = {p.name: p for p in merged}
        # 覆盖项生效
        self.assertEqual(by_name["local-small"].context_window, 6144)
        # 云端档位必须保留（旧实现是整体替换，会把它们全丢掉）
        self.assertIn("cloud-medium", by_name)
        self.assertIn("claude-large", by_name)
        # 新增项追加在末尾
        self.assertEqual(merged[-1].name, "brand-new-model")

    def test_prepend_flag_moves_new_profile_to_front(self):
        merged = mc._merge_profiles(list(mc._BUILTIN_PROFILES), [
            {"name": "urgent", "tier": "small", "prepend": True},
        ])
        self.assertEqual(merged[0].name, "urgent")


if __name__ == "__main__":
    unittest.main()
