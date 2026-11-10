"""A2 输出契约的 vuln_type 字段回归守卫（2026-10-30）。

背景（java-sec-code 实测）：A2 集成分析师的输出契约原本**不含漏洞类型**，族只能从 A1
finding 继承。A1（CodeQL）没有对应规则的文件（Velocity SSTI / QLExpress / CORS / JSONP…）
就只能落成 ``type=unknown``，下游既无法分族、也过不了族级门禁。

修法：只在**文件没有 A1 锚点**时才要求模型输出 ``vuln_type``。
Benchmark 每条 finding 都有 A1 族 ⇒ 契约不变、解码 token 不变、判定行为零影响。
本测试锁这条「按需加字段」的边界。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.a2_integrated_analyst import _output_contract, _user_prompt  # noqa: E402


def test_contract_omits_vuln_type_by_default():
    """默认契约（Benchmark 路径）不能出现 vuln_type —— 保证零影响。"""
    assert '"vuln_type"' not in _output_contract()


def test_contract_includes_vuln_type_when_requested():
    assert '"vuln_type"' in _output_contract(include_vuln_type=True)


def test_user_prompt_no_vuln_type_when_anchored():
    """有 A1 告警时不给族清单、不加字段（Benchmark 路径）。"""
    findings = [{"line": 10, "family": "sql_injection", "note": ""}]
    p = _user_prompt("class A{}", "A.java", findings)
    assert "vuln_type" not in p


def test_user_prompt_requests_vuln_type_without_anchors():
    """无 A1 告警时要求模型给族名，并附族清单。"""
    p = _user_prompt("class A{}", "A.java", [])
    assert "vuln_type" in p
    assert "jsonp_referer" in p
    assert "trust_boundary_violation" in p
