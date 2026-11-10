"""prompt 模板安全渲染回归测试。

守住 R4 事故：audit_prompts.yaml 的 audit_file 模板曾因正文含字面路由示例
``/order/{id}`` 被 ``str.format()`` 解释为占位符，抛 ``KeyError: 'id'``，
A2 的 60 个文件全部分析失败且被 except 静默吞掉，业务逻辑类 findings 归零，
任务却仍标记为 completed。

任何让"模板里出现未知花括号就抛异常"的改动，都必须在这里红掉。
"""

import os
import unittest

from src.agents.prompt_render import render_prompt

_YAML_PATH = os.path.join("src", "prompts", "audit_prompts.yaml")


class PromptRenderTests(unittest.TestCase):
    def test_known_keys_are_substituted(self):
        out = render_prompt("{code}|{file_path}|{context}", code="C", file_path="F", context="X")
        self.assertEqual(out, "C|F|X")

    def test_unknown_placeholder_kept_literal(self):
        """核心回归点：未知占位符必须原样保留，不得抛 KeyError。"""
        out = render_prompt("路由 /order/{id} 和 /address/{id}", code="C")
        self.assertEqual(out, "路由 /order/{id} 和 /address/{id}")

    def test_unknown_placeholder_does_not_raise(self):
        try:
            render_prompt("{id}{orderId}{userId}", code="C")
        except KeyError as exc:  # pragma: no cover - 失败路径
            self.fail(f"未知占位符不得抛 KeyError: {exc}")

    def test_already_escaped_braces_render_to_literal(self):
        out = render_prompt('{{"file": "{code}"}}', code="A.java")
        self.assertEqual(out, '{"file": "A.java"}')

    def test_mixed_known_and_unknown(self):
        out = render_prompt("{code}/{id}/{file_path}", code="C", file_path="F")
        self.assertEqual(out, "C/{id}/F")

    def test_compound_field_names(self):
        """复合字段（属性/下标/格式符）的基名要能正确识别为"已知键"。"""

        class _User:
            name = "u"

        out = render_prompt("{user.name}-{items[0]}-{n:>4}", user=_User(), items=["i"], n=7)
        self.assertEqual(out, "u-i-   7")

    def test_empty_template(self):
        self.assertEqual(render_prompt("", code="C"), "")
        self.assertEqual(render_prompt(None, code="C"), None)

    def test_real_audit_file_template_renders(self):
        """真实模板回归守卫：audit_file 含 {id} 字面量，一度让 A2 全量归零。"""
        try:
            import yaml  # noqa: PLC0415
        except ImportError:  # pragma: no cover
            self.skipTest("PyYAML 未安装")
        if not os.path.exists(_YAML_PATH):
            self.skipTest(f"模板不存在: {_YAML_PATH}")

        with open(_YAML_PATH, encoding="utf-8") as fh:
            template = (yaml.safe_load(fh) or {}).get("prompts", {}).get("audit_file", "")

        # 先确认裸 format 确实会炸（事故前提仍然成立）
        with self.assertRaises(KeyError):
            template.format(code="C", file_path="F", context="")

        # 安全渲染必须成功
        out = render_prompt(template, code="CODE", file_path="A.java", context="CTX")
        self.assertIn("CODE", out)
        self.assertNotIn("{code}", out)


if __name__ == "__main__":
    unittest.main()
