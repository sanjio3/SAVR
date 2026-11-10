"""回归守卫：trigger_spec_registry._infer_business_category_from_family 必须直接读中文显示族标签。

背景（R10 / P0-2 根因，spec 3116 / 源 finding 4338 / 路由 /ops/order/review）：

_vuln_hash._norm_family 的映射针 ``("越权") -> "idor"`` 过宽，把「垂直越权」也误归 idor→bola。
上游 A2 修复（test_a2_vertical_privesc_family.py）确保了 payload_family 在 A2 阶段被正确填成
vertical-privilege-escalation；但若在 trigger_spec 登记那一刻 payload_family 仍为空（注册时序
快照），旧实现只能依赖 _norm_family，于是垂直越权被错标水平越权，连续 10 轮（run 11–run 20）全部 bola。

本测试守卫「最后一道防线」：即使 payload_family 为空，只要 vuln 的 type/finding_type/display_family/
finding_family 任一显示族标签是「垂直越权」，也必须经 canonical_business_logic_family 归一为
vertical_privesc，绕过过宽的 _norm_family（idor→bola）。同时确认不误伤真实 bola / 注入族。
"""

import unittest

from src.iast.trigger_spec_registry import (
    _infer_business_category_from_family,
    _resolve_business_category,
)


def _vuln_dict(type_label="", display_family="", finding_family="", finding_type="",
               payload_family=""):
    """构造贴近 auto_register_from_a2 实际传入的 vuln_dict（vuln.to_dict() 投影）。"""
    rj = {
        "type": type_label,
        "display_family": display_family,
        "finding_family": finding_family,
        "finding_type": finding_type,
        "exploit_spec": {
            "payload": {"payload_family": payload_family},
        },
    }
    return rj


class InferBusinessCategoryRegistryTests(unittest.TestCase):
    def test_vertical_privesc_recovered_from_type_when_payload_family_empty(self):
        # spec 3116 的精确复现：注册时 payload_family 为空，仅 type=垂直越权
        rj = _vuln_dict(type_label="垂直越权", display_family="垂直越权",
                        finding_family="垂直越权", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "vertical_privesc")

    def test_vertical_privesc_recovered_from_finding_type_field(self):
        # 某些投影 finding_type 是承载显示族标签的字段
        rj = _vuln_dict(finding_type="垂直越权", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "vertical_privesc")

    def test_prefixed_vertical_privesc_still_resolves(self):
        # 基础设施层-/业务逻辑类- 前缀必须被剥离后再归一
        rj = _vuln_dict(type_label="基础设施层-垂直越权", finding_family="基础设施层-垂直越权",
                        display_family="基础设施层-垂直越权", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "vertical_privesc")

    def test_payload_family_still_takes_precedence(self):
        # payload_family 已正确填充时应直接采信，不被标签覆盖
        rj = _vuln_dict(type_label="垂直越权", payload_family="vertical-privilege-escalation")
        self.assertEqual(_infer_business_category_from_family(rj), "vertical_privesc")

    def test_genuine_bola_not_mislabeled_as_vertical(self):
        # 真实水平越权：_norm_family 已归 idor→bola，不得被改写为 vertical_privesc
        rj = _vuln_dict(type_label="水平越权", display_family="水平越权(idor)",
                        finding_family="水平越权(idor)", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "bola")

    def test_injection_family_not_mislabeled_as_business(self):
        # 注入类（SQL 注入）必须返回空，绝不进业务差分重放
        rj = _vuln_dict(type_label="SQL Injection", display_family="SQL Injection",
                        finding_family="SQL Injection", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "")

    def test_generic_or_empty_label_returns_empty(self):
        # 无业务族标签时返回空，由调用方走普通 canary 污点重放
        rj = _vuln_dict(type_label="some unrelated text", payload_family="")
        self.assertEqual(_infer_business_category_from_family(rj), "")


class ResolveBusinessCategoryTests(unittest.TestCase):
    """守卫 band-aid 覆盖决策（_resolve_business_category）：_family_cat 优先于退化的 _family_cat2。"""

    def test_3116_vertical_recovered_when_upstream_mislabels_bola(self):
        # spec 3116 精确复现：上游把 category 错标 bola、payload_family 为空、family 退 _norm_family=idor→bola，
        # 但中文显示族标签是「垂直越权」——最终必须还原为 vertical_privesc。
        rj = _vuln_dict(type_label="垂直越权", display_family="垂直越权",
                        finding_family="垂直越权", payload_family="")
        result = _resolve_business_category("bola", "idor", rj)
        self.assertEqual(result, "vertical_privesc")

    def test_payload_family_filled_vertical_still_resolves(self):
        # payload_family 已正确填充时同样还原 vertical_privesc
        rj = _vuln_dict(type_label="垂直越权", payload_family="vertical-privilege-escalation")
        result = _resolve_business_category("bola", "vertical-privilege-escalation", rj)
        self.assertEqual(result, "vertical_privesc")

    def test_genuine_bola_unchanged(self):
        # 真实水平越权：category 已是 bola，family 派生也是 bola，不得改写为 vertical_privesc
        rj = _vuln_dict(type_label="水平越权", display_family="水平越权(idor)",
                        finding_family="水平越权(idor)", payload_family="")
        result = _resolve_business_category("bola", "idor", rj)
        self.assertEqual(result, "bola")

    def test_injection_keeps_empty_category(self):
        # 注入族：family/_infer 均空，category 保持原样（空），走普通 canary 重放
        rj = _vuln_dict(type_label="SQL Injection", payload_family="")
        result = _resolve_business_category("", "sql-injection", rj)
        self.assertEqual(result, "")

    def test_label_beats_ambiguous_family_when_they_conflict(self):
        # 冲突场景：_family_cat2 因 _norm_family 退化给出 bola，但 _family_cat 从中文标签给出 vertical_privesc，
        # 必须以 _family_cat 为准（这正是修复前把 vertical_privesc 错写成 bola 的回退路径）。
        rj = _vuln_dict(type_label="垂直越权", payload_family="")
        result = _resolve_business_category("bola", "idor", rj)
        self.assertEqual(result, "vertical_privesc")
        # 反例（修复前行为）：若直接采信 _family_cat2 会得到 bola
        from src.iast.trigger_spec_registry import _infer_business_category_from_family
        from src.core.exploit_spec import canonical_business_logic_family, DIFFERENTIAL_PROOF_FAMILIES
        from src.iast.trigger_spec_registry import _normalize_business_logic_category
        cat2 = (_normalize_business_logic_category(canonical_business_logic_family("idor"))
                if canonical_business_logic_family("idor") in DIFFERENTIAL_PROOF_FAMILIES else "")
        self.assertEqual(cat2, "bola")  # 证明退化路径确实会给 bola，凸显优先 _family_cat 的必要性

    def test_correct_category_not_overwritten_by_degenerate_family(self):
        # Bug 3 精确复现（run 21 spec 3347 暴露）：上游 _derive_category 经 _infer 已正确算出
        # category="vertical_privesc"，但本 spec 落库 family 退化为 "idor"（_family_cat2="bola"）。
        # 旧实现 elif 分支会用退化的 _family_cat2 把正确值打回 bola；修复后 _family_cat 权威，
        # 与 category 一致时稳定返回、绝不回退覆盖。这是 run 21 仍残留 bola 的真实路径。
        rj = _vuln_dict(type_label="垂直越权", payload_family="")
        result = _resolve_business_category("vertical_privesc", "idor", rj)
        self.assertEqual(result, "vertical_privesc")


if __name__ == "__main__":
    unittest.main()
