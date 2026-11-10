"""D2 门禁 `_d2_gate_predicate` 回归测试（2026-09-07）。

背景：Mapper 派生 SQLi（/products GET keyword，A1 规则引擎产出）自身
exploit_spec.entry.route 未被 `_pre_resolve_a2_endpoints` 回填（仅 a2_results 被回填），
但 `auto_register_from_a2` 已用 `resolve_endpoint_full` 独立解析出路由并登记 trigger_spec。
原门禁只认「自身 entry.route 非空」，会把这类 A1 技术漏洞裁掉，导致其 verification_status
永远为空（从未进 D2）。修复后：只要「已登记且解析出可达入口的 trigger_spec」存在即放行。

本文件锁死该门禁行为。

2026-09-22 追加（闭环 D2_NOT_SCHEDULED）：
- proof_tier=chain_proven 的一级 finding 强制入队，不受 route / spec 兜底分支约束；
- 聚合吸收成员（is_absorbed）硬闸优先，不得被强制入队穿透；
- _d2_gate_skip_reason 与 _d2_gate_predicate 同源：凡被拒的输入必须给出非空原因，
  不得留 unknown（需求约定「未测必须显式记 runtime 原因」）。
"""
from src.cli.benchmark_cli import _d2_gate_predicate, _d2_gate_skip_reason


def _tech_vuln(vhash, route="", a21=None):
    return {
        "type": "sql注入",
        "a21_selected": a21,
        "exploit_spec": {"entry": {"route": route}} if route else {"entry": {}},
        "vuln_vhash": vhash,
        "file": "x",
    }


def test_gate_admits_technical_with_registered_spec_but_empty_own_route():
    """核心：A1 技术漏洞自身 entry.route 为空，但已登记解析出路由的 spec → 进 D2。"""
    vuln = _tech_vuln("abc")
    specs = {"abc": [{"target_endpoint": "/products", "family": "sql-injection"}]}
    assert _d2_gate_predicate(vuln, specs) is True


def test_gate_rejects_technical_without_spec_or_route():
    """无 spec 且无自身 route 的 A1 技术漏洞 → 不进 D2（保持 sound，避免误放）。"""
    vuln = _tech_vuln("abc")
    assert _d2_gate_predicate(vuln, {}) is False


def test_gate_admits_technical_with_own_route():
    """自身 entry.route 非空（a2_results 已回填）→ 进 D2。"""
    vuln = _tech_vuln("abc", route="/api/products/sort")
    assert _d2_gate_predicate(vuln, {}) is True


def test_gate_admits_a21_selected_technical_without_spec():
    """a21_selected=True 的技术漏洞 → 进 D2（不依赖 spec 反查）。"""
    vuln = _tech_vuln("abc", a21=True)
    assert _d2_gate_predicate(vuln, {}) is True


def test_gate_admits_business_a21_selected():
    """业务逻辑族 a21_selected=True → 进 D2。"""
    vuln = {"type": "bola", "a21_selected": True, "exploit_spec": {"entry": {}}, "vuln_vhash": "b", "file": "y"}
    assert _d2_gate_predicate(vuln, {}) is True


def test_gate_rejects_business_without_a21_and_no_spec():
    """业务逻辑族 a21_selected 未显式选中且无 spec → 不进 D2（不享受技术族 spec 反查放行）。"""
    vuln = {"type": "bola", "a21_selected": None, "exploit_spec": {"entry": {}}, "vuln_vhash": "b", "file": "y"}
    assert _d2_gate_predicate(vuln, {}) is False


# ---------------------------------------------------------------------------
# §③ 强制入队 + 调度留痕（2026-09-22，闭环 D2_NOT_SCHEDULED）
# ---------------------------------------------------------------------------

def test_gate_admits_chain_proven_without_route_or_spec():
    """核心：proof_tier=chain_proven 的一级 finding 即使自身无 route、也未命中任何
    trigger_spec，也必须进 D2。

    历史缺口（run 31/32 各 14 条）：A2.1 二次证明把某条 finding 升级为 chain_proven，
    但其 canonical_group_key 为空、entry.route 未回填、spec 关联又未命中 → 被门禁整体裁掉，
    终态是「契约就绪却零执行痕迹」的沉默空壳。强制入队后即便打不到，也会得到明确的
    unconfirmed / no_evidence + 运行原因。
    """
    vuln = {
        "type": "命令注入",
        "a21_selected": None,
        "proof_tier": "chain_proven",
        "exploit_spec": {"entry": {}},
        "vuln_vhash": "deadbeef",
        "file": "z",
    }
    assert _d2_gate_predicate(vuln, {}) is True


def test_gate_absorbed_member_hard_gate_not_pierced_by_chain_proven(monkeypatch):
    """吸收成员硬闸双态锁定（2026-10-02 更新）。

    2026-10-01（批次 A）起默认放行：吸收成员凭自身 target_endpoint 单独重放取真实
    verification_status（run 44 实测旧硬闸造成 27/28 连带假阴性）。旧「硬闸优先于
    强制入队」行为仅在显式开关 SAST_AI_ABSORBED_NO_D2=1 下保留。
    """
    vuln = {
        "type": "命令注入",
        "a21_selected": None,
        "proof_tier": "chain_proven",
        "is_absorbed": True,
        "exploit_spec": {"entry": {"route": "/x"}},
        "file": "z",
    }
    monkeypatch.setenv("SAST_AI_ABSORBED_NO_D2", "1")
    assert _d2_gate_predicate(vuln, {}) is False
    monkeypatch.delenv("SAST_AI_ABSORBED_NO_D2", raising=False)
    assert _d2_gate_predicate(vuln, {}) is True


def test_skip_reason_empty_exactly_when_gate_admits():
    """同源约束：reason 为空 <=> 门禁放行；二者不得各行其是。"""
    admitted = [
        ({"type": "sql注入", "a21_selected": True, "exploit_spec": {"entry": {}}, "file": "a"}, {}),
        ({"type": "命令注入", "proof_tier": "chain_proven", "exploit_spec": {"entry": {}}, "file": "b"}, {}),
        ({"type": "sql注入", "a21_selected": None, "exploit_spec": {"entry": {"route": "/p"}}, "file": "c"}, {}),
        (
            {"type": "sql注入", "a21_selected": None, "vuln_vhash": "abc", "exploit_spec": {"entry": {}}, "file": "d"},
            {"abc": [{"target_endpoint": "/products"}]},
        ),
    ]
    for vuln, specs in admitted:
        assert _d2_gate_predicate(vuln, specs) is True, vuln
        assert _d2_gate_skip_reason(vuln, specs) == "", vuln


def test_skip_reason_enumerates_every_rejection_branch():
    """每个拒绝分支都要有可读的机读前缀，供 d2_zero_audit 直接消费。"""
    cases = [
        # 吸收成员（absorbed_member 前缀）双态单列：见
        # test_skip_reason_absorbed_member_prefix_dual_state（2026-10-01 起默认放行，
        # 仅 SAST_AI_ABSORBED_NO_D2=1 下才记 absorbed_member，不能进本默认态循环）。
        (
            {"type": "bola", "a21_selected": None, "exploit_spec": {"entry": {}}, "file": "b"},
            {},
            "business_logic_not_selected",
        ),
        (
            {"type": "sql注入", "a21_selected": None, "vuln_vhash": "nope",
             "exploit_spec": {"entry": {}}, "file": "c"},
            {},
            "no_trigger_spec",
        ),
        (
            {"type": "sql注入", "a21_selected": None, "vuln_vhash": "abc",
             "exploit_spec": {"entry": {}}, "file": "d"},
            {"abc": [{"target_endpoint": ""}]},
            "trigger_spec_without_endpoint",
        ),
    ]
    for vuln, specs, expected_prefix in cases:
        assert _d2_gate_predicate(vuln, specs) is False, vuln
        reason = _d2_gate_skip_reason(vuln, specs)
        assert reason, "被拒条目必须给出显式原因，不得留 unknown"
        assert reason.split(":", 1)[0] == expected_prefix, (reason, expected_prefix)


def test_skip_reason_absorbed_member_prefix_dual_state(monkeypatch):
    """吸收成员 skip reason 双态：开关下记 absorbed_member；默认（放行）下无该原因。

    2026-10-01（批次 A）起吸收成员默认进 D2，skip_reason 只有在
    SAST_AI_ABSORBED_NO_D2=1 时才给出 absorbed_member 前缀。
    """
    vuln = {
        "type": "命令注入", "a21_selected": None, "is_absorbed": True,
        "exploit_spec": {"entry": {}}, "file": "a",
    }
    monkeypatch.setenv("SAST_AI_ABSORBED_NO_D2", "1")
    assert _d2_gate_predicate(vuln, {}) is False
    assert _d2_gate_skip_reason(vuln, {}).split(":", 1)[0] == "absorbed_member"
    monkeypatch.delenv("SAST_AI_ABSORBED_NO_D2", raising=False)
    # 默认放行语义下：本例无 route 无 spec，仍被拒但原因落到 no_trigger_spec
    assert _d2_gate_predicate(vuln, {}) is False
    assert _d2_gate_skip_reason(vuln, {}).split(":", 1)[0] == "no_trigger_spec"
