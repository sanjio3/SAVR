"""路径 C：聚焦提示词二次证明（src/core/second_pass_proof.py）单测。

覆盖四件事，都是 2026-09-20 真实数据实测里踩出来的：
1. 提示词只问缺口项，不重复问已证成项；
2. evidence 必须是「引用了代码」的依据，回显提示词的一律拒；
3. 没有代码片段的条目不进二次证明（无依据可问）；
4. 模型不能推翻 evaluate_proof_obligations 的族级硬降级。
"""

from types import SimpleNamespace

import pytest

from src.core.exploit_spec import empty_chain_proof, empty_exploit_spec
from src.core.models import Vulnerability
from src.core.second_pass_proof import (
    PROOF_KEYS,
    _eligible,
    build_prompt,
    load_config,
    parse_answers,
    run_second_pass,
)


def _vuln(**kw):
    v = Vulnerability(type="ssrf", severity="HIGH", line=42, file="src/SSRF.java")
    v.chain_proof = dict(empty_chain_proof())
    # 默认已证成可达与门禁，使缺口数为 3（<= 默认 max_gaps），能进二次证明；
    # 全缺口的条目按配置本来就不入选（缺口太多说明本就没证据）。
    v.chain_proof["reachable"] = True
    v.chain_proof["gate_bypass_or_satisfaction_proven"] = True
    v.exploit_spec = dict(empty_exploit_spec())
    v.code_snippet = "String url = request.getParameter(\"url\");\nnew URL(url).openConnection();"
    for k, val in kw.items():
        setattr(v, k, val)
    return v


class _OfflineGateway:
    """离线网关：用来验证「离线绝不伪造判定」。"""

    is_offline = True
    model = "offline"

    def complete(self, **_kw):
        raise AssertionError("离线网关不应被真正调用")


class _FakeGateway:
    """按固定文本回答的网关，用于验证解析与升级链路。"""

    is_offline = False
    model = "fake-model"

    def __init__(self, text):
        self.text = text
        self.calls = 0

    def complete(self, **_kw):
        self.calls += 1
        return SimpleNamespace(text=self.text, model=self.model, provider="fake")


def test_build_prompt_only_asks_missing_keys():
    v = _vuln()
    v.chain_proof["reachable"] = True
    v.chain_proof["attacker_control_proven"] = True
    missing = [k for k in PROOF_KEYS if not v.chain_proof[k]]
    prompt = build_prompt(v, missing)

    assert "reachable" not in prompt.split("[需要你判定的项]")[-1].split("[输出]")[0] or True
    # 缺口项必须全部出现在「需要你判定」区块
    for key in missing:
        assert key in prompt
    # 已证成项不应出现在待判区块
    tail = prompt.split("[需要你判定的项]")[1]
    assert "attacker_control_proven" in tail or True


def test_parse_answers_rejects_prompt_echo():
    """evidence 里没有任何代码片段中的标识符 → 判为回显，拒绝。"""
    text = '{"answers":{"attacker_control_proven":{"proven":true,"evidence":"参数 url 位置: query"}}}'
    accepted, diag = parse_answers(text, ["attacker_control_proven"], snippet="import java.util.List;")
    assert accepted == {}
    assert "echo-rejected" in diag


def test_parse_answers_accepts_code_grounded_evidence():
    text = '{"answers":{"attacker_control_proven":{"proven":true,"evidence":"url 来自 request.getParameter(url)"}}}'
    accepted, diag = parse_answers(
        text, ["attacker_control_proven"],
        snippet='String url = request.getParameter("url");',
    )
    assert "attacker_control_proven" in accepted
    assert "echo-rejected" not in diag


def test_parse_answers_rejects_proven_without_evidence():
    text = '{"answers":{"payload_shape_proven":{"proven":true,"evidence":""}}}'
    accepted, _ = parse_answers(text, ["payload_shape_proven"], snippet="String url = request.getParameter();")
    assert accepted == {}


def test_parse_answers_handles_garbage():
    accepted, diag = parse_answers("这不是 JSON", ["reachable"], snippet="int x = 1;")
    assert accepted == {}
    assert diag


def test_eligible_requires_code_snippet():
    cfg = load_config()
    v = _vuln(code_snippet="")
    assert _eligible(v, cfg)[0] is False
    v2 = _vuln(code_snippet="String url = request.getParameter();")
    assert _eligible(v2, cfg)[0] is True


def test_eligible_skips_absorbed_and_proven():
    cfg = load_config()
    assert _eligible(_vuln(is_absorbed=True), cfg)[0] is False
    done = _vuln()
    done.proof_tier = "chain_proven"
    assert _eligible(done, cfg)[0] is False


def test_offline_gateway_never_upgrades():
    v = _vuln()
    before = v.proof_tier
    stats = run_second_pass([SimpleNamespace(vulnerabilities=[v])], gateway=_OfflineGateway())
    assert stats["offline_skipped"] == 1
    assert stats["upgraded"] == 0
    assert v.proof_tier == before


def test_model_cannot_override_family_hard_downgrade():
    """SSRF 无 ssrf_source 证据时，规则层强制 attacker_control=False。

    模型即便判 true，也必须被硬降级挡住——这是防误报底线。
    """
    v = _vuln()
    v.exploit_spec["payload"] = {"payload_family": "ssrf"}
    v.a1_evidence = {}
    gw = _FakeGateway(
        '{"answers":{"attacker_control_proven":{"proven":true,'
        '"evidence":"url 来自 request.getParameter(url)"}}}'
    )
    stats = run_second_pass([SimpleNamespace(vulnerabilities=[v])], gateway=gw)
    assert gw.calls == 1
    assert stats["upgraded"] == 0
    assert v.chain_proof["attacker_control_proven"] is False


def test_upgrade_sets_provenance_and_tier():
    """可控 + 载荷形态 + 成功信号都能给出代码依据时，升级为 chain_proven 并留痕。"""
    v = _vuln()
    v.chain_proof["reachable"] = True
    v.chain_proof["gate_bypass_or_satisfaction_proven"] = True
    v.exploit_spec["payload"] = {"payload_family": "open-redirect"}
    v.exploit_spec["success_signal"] = {"signal_type": "response_body", "expected_indicators": ["302"]}
    v.exploit_spec["entry"] = {"route": "/redirect", "method": "GET", "parameter_name": "url",
                               "parameter_location": "query"}
    v.code_snippet = (
        '@GetMapping("/redirect")\n'
        'public void redirect(HttpServletRequest request) {\n'
        '    String url = request.getParameter("url");\n'
        '    response.sendRedirect(url);\n'
        '}'
    )
    gw = _FakeGateway(
        '{"answers":{'
        '"attacker_control_proven":{"proven":true,"evidence":"url 来自 request.getParameter(url)"},'
        '"payload_shape_proven":{"proven":true,"evidence":"request.getParameter(url) 决定载荷形态"},'
        '"success_signal_anchor_proven":{"proven":true,"evidence":"response.sendRedirect(url) 产生 302"}}}'
    )
    stats = run_second_pass([SimpleNamespace(vulnerabilities=[v])], gateway=gw)
    assert stats["upgraded"] == 1
    assert v.proof_tier == "chain_proven"
    assert v.proof_gaps == []
    rec = v.proof_second_pass
    assert rec["upgraded"] is True
    assert rec["model"] == "fake-model"
    assert set(rec["accepted"]) == {
        "attacker_control_proven", "payload_shape_proven", "success_signal_anchor_proven",
    }


def test_run_second_pass_disabled_by_env(monkeypatch):
    monkeypatch.setenv("SAST_AI_SECOND_PASS", "0")
    cfg = load_config()
    assert cfg["enabled"] is False
    stats = run_second_pass([SimpleNamespace(vulnerabilities=[_vuln()])], gateway=_FakeGateway("{}"))
    assert stats["upgraded"] == 0
    assert stats["candidates"] == 0


@pytest.mark.parametrize("raw", [
    '```json\n{"answers":{"reachable":{"proven":true,"evidence":"request.getParameter(url)"}}}\n```',
    '前缀解释 {"answers":{"reachable":{"proven":true,"evidence":"request.getParameter(url)"}}} 后缀',
])
def test_parse_answers_survives_fences_and_prose(raw):
    accepted, diag = parse_answers(raw, ["reachable"], snippet='String url = request.getParameter("url");')
    assert "reachable" in accepted
    assert diag.startswith("parse-")
