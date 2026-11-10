"""M2 后端侧：sink token 数据集验收（数据化 FAMILY_SINK_TOKENS）。

核心验收：tokens_for(family) 与硬编码 FAMILY_SINK_TOKENS 逐族相等——
数据化后行为零变化，后续扩展只改 YAML 不动代码。
"""
import unittest

from src.core.sink_token_dataset import (
    canonical_family,
    is_dataflow_family,
    load_data,
    tokens_for,
)
from src.core.sink_value_gate import FAMILY_SINK_TOKENS


class TestSinkTokenDataset(unittest.TestCase):
    def test_yaml_loads(self):
        data = load_data()
        self.assertIn("families", data)
        self.assertIn("aliases", data)
        self.assertIn("non_dataflow", data)

    def test_tokens_match_legacy_per_family(self):
        # 逐族相等：数据化零行为变化
        for fam, toks in FAMILY_SINK_TOKENS.items():
            with self.subTest(family=fam):
                self.assertEqual(set(tokens_for(fam)), set(toks),
                                 f"族 {fam} token 与硬编码不一致")

    def test_canonical_family_aliases(self):
        self.assertEqual(canonical_family("weakrand"), "weak_random")
        self.assertEqual(canonical_family("sqli"), "sql_injection")
        self.assertEqual(canonical_family("ldapi"), "ldap_injection")
        self.assertEqual(canonical_family("trustbound"), "trust_boundary_violation")
        self.assertEqual(canonical_family("sql_injection"), "sql_injection")

    def test_is_dataflow_family(self):
        self.assertFalse(is_dataflow_family("weakrand"))
        self.assertFalse(is_dataflow_family("hash"))
        self.assertFalse(is_dataflow_family("crypto"))
        self.assertFalse(is_dataflow_family("securecookie"))
        self.assertTrue(is_dataflow_family("sqli"))
        self.assertTrue(is_dataflow_family("cmdi"))
        self.assertTrue(is_dataflow_family("xss"))
        self.assertTrue(is_dataflow_family("ldapi"))

    def test_tokens_for_known_families(self):
        self.assertIn("Runtime.exec", tokens_for("command_execution"))
        self.assertIn("StandardSession.setAttribute",
                      tokens_for("trust_boundary_violation"))
        self.assertIn("DirContext.search", tokens_for("ldap_injection"))


if __name__ == "__main__":
    unittest.main()
