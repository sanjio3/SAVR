"""回归守卫：垂直越权（vertical-privilege-escalation）必须正确落到 payload_family。

背景（R10 / P0-2 根因）：
A2 的 LLM 已在结构化字段 type/finding_family/display_family 显式给出漏洞族
（如「垂直越权」），但 _payload_family 仅靠英文关键词自下而上匹配（无 vertical/越权 等
needle），对垂直越权类恒回落 'generic'；而 _business_logic_category 只读
business_logic_category/category 属性（垂直越权类这两字段为空），于是 payload_family 彻底
丢失、下游 trigger_spec 被错标 bola → 永远 no-iast-evidence。

修复：在 _build_exploit_spec 中，当文本探测无果（generic）且业务类目属性为空时，回退到
LLM 结构化族标签，经 canonical_business_logic_family 归一（"垂直越权"→vertical_privesc 等），
命中 DIFFERENTIAL_PROOF_FAMILIES 即采信。仅作 generic 时的最终兜底，不覆盖已正确识别的
注入/idor 等族，不会把注入类误判为业务族。
"""

import unittest

from src.agents.a2_intelligent_agent import A2SemanticAgent
from src.core.exploit_spec import DIFFERENTIAL_PROOF_FAMILIES


class A2VerticalPrivescFamilyTests(unittest.TestCase):
    def setUp(self):
        self.agent = A2SemanticAgent.__new__(A2SemanticAgent)

    def _vuln(self, **kw):
        from src.core.models import Vulnerability

        v = Vulnerability(
            type=kw.get("type", ""),
            severity=kw.get("severity", "HIGH"),
            file=kw.get("file", "com/mall/AdminController.java"),
            line=kw.get("line", 10),
            description=kw.get("description", ""),
            code_snippet=kw.get("code_snippet", ""),
            entry_point=kw.get("entry_point", ""),
            sink=kw.get("sink", ""),
            has_http_entry=kw.get("has_http_entry", True),
            callers=kw.get("callers", ""),
            source=kw.get("source", "a2"),
        )
        # 允许设置 LLM 结构化族标签字段（真实 A2 产物带这些）
        for _k in ("finding_family", "display_family", "category", "business_logic_category",
                  "data_flow", "has_call_chain", "chain_id", "chain_proof",
                  "supporting_nodes", "supporting_node_count", "canonical_group_key",
                  "is_canonical", "llm_route", "llm_params", "verdict"):
            if _k in kw:
                setattr(v, _k, kw[_k])
        if "llm_params" not in kw:
            setattr(v, "llm_params", [])
        # _early_chain_group_key 读取的兜底字段
        for _k in ("has_call_chain", "chain_id", "chain_proof",
                   "supporting_nodes", "supporting_node_count",
                   "canonical_group_key", "is_canonical"):
            if not hasattr(v, _k):
                setattr(v, _k, None if _k in ("chain_id", "chain_proof", "canonical_group_key") else [])
        return v

    def test_vertical_privesc_clean_type_resolves(self):
        v = self._vuln(
            type="垂直越权",
            finding_family="垂直越权",
            display_family="垂直越权",
            entry_point="/api/comment/moderate",
            description="普通用户可越权审批管理操作",
        )
        spec = self.agent._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "vertical_privesc")
        self.assertEqual(spec["entry"]["route"], "/api/comment/moderate")

    def test_vertical_privesc_prefixed_type_resolves(self):
        # 基础设施层降级标记前缀「基础设施层-」必须被剥离后再归一
        v = self._vuln(
            type="基础设施层-垂直越权",
            finding_family="基础设施层-垂直越权",
            display_family="基础设施层-垂直越权",
            entry_point="/ops/order/review",
            description="越权审核他人订单",
        )
        spec = self.agent._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "vertical_privesc")
        self.assertEqual(spec["entry"]["route"], "/ops/order/review")

    def test_sql_injection_not_misrouted_to_business_family(self):
        # 注入类必须保持注入族，绝不被兜底逻辑误判为业务族
        v = self._vuln(
            type="SQL Injection",
            finding_family="SQL Injection",
            display_family="SQL Injection",
            entry_point="/search",
            description="request.args.get('q') reaches cursor.execute(select * from users where name = ...)",
            code_snippet="cursor.execute('select * from users where name = ' + q)",
        )
        spec = self.agent._build_exploit_spec(v)
        self.assertEqual(spec["payload"]["payload_family"], "sql-injection")
        self.assertNotIn(spec["payload"]["payload_family"], DIFFERENTIAL_PROOF_FAMILIES)

    def test_idor_stays_idor_not_overridden(self):
        # idor 已由 _payload_family 正确识别，兜底不应把它改写为 bola
        v = self._vuln(
            type="IDOR",
            finding_family="IDOR",
            display_family="水平越权(idor)",
            entry_point="/api/user/{id}",
            description="user_id supplied by attacker reaches owner lookup",
            code_snippet="@GetMapping('/api/user/{id}') public User get(@PathVariable Long id)",
        )
        spec = self.agent._build_exploit_spec(v)
        # idor 已由 _payload_family 正确识别；兜底逻辑只在 generic 时介入，
        # 绝不应把已识别的 idor 改写为 vertical_privesc/state_machine 等其他业务族。
        self.assertEqual(spec["payload"]["payload_family"], "idor")
        self.assertNotEqual(spec["payload"]["payload_family"], "vertical_privesc")
        self.assertNotEqual(spec["payload"]["payload_family"], "state_machine")


if __name__ == "__main__":
    unittest.main()
