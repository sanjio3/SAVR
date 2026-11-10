"""A2 LLM 入口绑定回归测试（R5）。

守住两件事：
1. LLM 给出的路由必须进 exploit_spec，且残缺/敷衍路由（"/"、"/admin/"）要被拒收
2. A1 证据索引的路径键要能抹平 绝对 vs 相对 的差异

背景：task 8 的 17 条业务逻辑 findings 里，10 条因为没绑到真实 HTTP 路由，
在转 trigger_spec 时被整批丢弃 —— 其中就有正则兜底捞出来的 "/"、"/admin/" 假路由。
"""

import os
import unittest

from src.agents.a2_intelligent_agent import A2SemanticAgent
from src.core.path_norm import match_path_key, normalize_path_key


def _make_agent():
    agent = A2SemanticAgent.__new__(A2SemanticAgent)
    agent.config = {}
    agent.provider = "test"
    agent.taint_tracking = {}
    agent._a2_error_count = 0
    agent.prompts = {}
    agent.client = None
    return agent


class SanitizeLlmRouteTests(unittest.TestCase):
    def setUp(self):
        self.agent = _make_agent()

    def test_valid_routes_accepted(self):
        for route in ("/order/{id}", "/products", "/seckill/buy", "/api/profile/{id}", "/comment/delete/{id}"):
            self.assertEqual(self.agent._sanitize_llm_route(route), route, route)

    def test_root_rejected(self):
        """"/" 无信息量，历史上正是它让 findings 转不成 spec。"""
        self.assertEqual(self.agent._sanitize_llm_route("/"), "")

    def test_directory_style_route_rejected(self):
        """目录式残缺路由粒度太粗：非管理前缀（/api/、/foo/）仍拒收；
        已知管理前缀（/admin /manage /console /sys）保留为类级前缀（去尾斜杠），
        交由 _pick_admin_route / file:line 兜底择优具体子路由。"""
        self.assertEqual(self.agent._sanitize_llm_route("/api/"), "")
        self.assertEqual(self.agent._sanitize_llm_route("/foo/"), "")
        self.assertEqual(self.agent._sanitize_llm_route("/admin/"), "/admin")
        self.assertEqual(self.agent._sanitize_llm_route("/manage/"), "/manage")

    def test_trailing_punctuation_rejected(self):
        """LLM 常见尾部逗号/句号：管理前缀（/admin/）保留为 /admin；
        非管理目录式（/api/,）仍拒收；具体子路由尾部逗号正常清理。"""
        self.assertEqual(self.agent._sanitize_llm_route("/admin/,"), "/admin")
        self.assertEqual(self.agent._sanitize_llm_route("/admin/."), "/admin")
        self.assertEqual(self.agent._sanitize_llm_route("/api/,"), "")
        self.assertEqual(self.agent._sanitize_llm_route("/admin/users,"), "/admin/users")

    def test_non_path_rejected(self):
        for bad in ("", "order", "OrderController", "http://x/y", None):
            self.assertEqual(self.agent._sanitize_llm_route(bad), "")

    def test_query_and_fragment_stripped(self):
        self.assertEqual(self.agent._sanitize_llm_route("/products?kw=1"), "/products")
        self.assertEqual(self.agent._sanitize_llm_route("/products#top"), "/products")


class ParseAiResponseRouteBindingTests(unittest.TestCase):
    def setUp(self):
        self.agent = _make_agent()

    def _parse(self, payload):
        import json
        return self.agent._parse_ai_response(json.dumps(payload), "OrderController.java")

    def test_route_and_method_captured(self):
        vulns = self._parse(
            {
                "file": "o.java",
                "vulnerabilities": [
                    {
                        "type": "竞态条件",
                        "severity": "HIGH",
                        "line": 42,
                        "description": "秒杀先查库存再扣减，无锁",
                        "fix": "加分布式锁",
                        "entry_method": "SeckillController#buy",
                        "route": "/seckill/buy",
                        "params": [{"name": "productId", "in": "body"}],
                    }
                ],
            }
        )
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.llm_route, "/seckill/buy")
        self.assertEqual(v.llm_entry_method, "SeckillController#buy")
        self.assertEqual(v.llm_params, [{"name": "productId", "in": "body"}])

    def test_bogus_route_sanitized_to_empty(self):
        # 管理前缀 /admin/ 现在保留为类级前缀 /admin（交由 _pick_admin_route 择优具体子路由）
        vulns = self._parse(
            {
                "file": "o.java",
                "vulnerabilities": [
                    {"type": "垂直越权", "severity": "HIGH", "line": 16,
                     "description": "d", "fix": "f", "route": "/admin/",
                     "entry_method": "", "params": []}
                ],
            }
        )
        self.assertEqual(vulns[0].llm_route, "/admin")

    def test_missing_route_fields_default_empty(self):
        """旧格式响应（无 route 字段）不能炸，且默认为空。"""
        vulns = self._parse(
            {"file": "o.java", "vulnerabilities": [{"type": "XSS", "severity": "LOW", "line": 1}]}
        )
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].llm_route, "")
        self.assertEqual(vulns[0].llm_params, [])


class PathNormTests(unittest.TestCase):
    ABS = r"<sdl-root>/target-mall\src\main\java\com\sanjio\mall\web\OrderController.java"
    REL = r"src\main\java\com\sanjio\mall\web\OrderController.java"

    def test_absolute_vs_relative_matches(self):
        """核心回归点：A1 用绝对路径建索引，A2 用相对路径查，必须能命中。"""
        index = {self.ABS: {"entry_candidates": [{"route": "/order/{id}"}]}}
        # 旧行为：直接 .get() 恒 miss，A1 per-file 证据从未喂进 LLM
        self.assertIsNone(index.get(self.REL))
        # 新行为
        self.assertEqual(
            match_path_key(self.REL, index, "FALLBACK"),
            {"entry_candidates": [{"route": "/order/{id}"}]},
        )

    def test_fallback_when_no_match(self):
        index = {self.ABS: "value"}
        self.assertEqual(match_path_key("src/other/Foo.java", index, "FALLBACK"), "FALLBACK")

    def test_empty_inputs(self):
        self.assertEqual(match_path_key("", {"a": 1}, "FALLBACK"), "FALLBACK")
        self.assertEqual(match_path_key("x", {}, "FALLBACK"), "FALLBACK")
        self.assertEqual(match_path_key(None, {}, "FALLBACK"), "FALLBACK")

    def test_normalize_is_stable(self):
        self.assertEqual(normalize_path_key("A\\B\\c.java"), normalize_path_key("a/b/c.java"))
        self.assertEqual(normalize_path_key("D:/x/y.java"), normalize_path_key("x/y.java"))

    def test_same_name_different_dirs_not_confused(self):
        """同名不同目录的文件不能被尾部匹配误命中。"""
        index = {r"a\b\Foo.java": "B"}
        self.assertEqual(match_path_key(r"c\d\Foo.java", index, "FALLBACK"), "FALLBACK")


if __name__ == "__main__":
    unittest.main()
