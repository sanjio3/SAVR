"""post-pass → confirm-gate 证据链回归锁（2026-11-04）。

根因：_apply_technique_oracle_postpass 旧实现只 UPDATE 了 verification_status /
iast_state / failure_attribution / failure_attribution_reason 四个字段，docstring
承诺的 ``raw_json.technique_evidence`` 根本没写。紧接着的 _apply_confirmation_gate
用 _confirm_gate_decide 复核时只认 raw_json.d2_evidence / dast_impact_evidence
里的结构化正向证据 ⇒ 判据命中又被判 no_positive_evidence 降级
（jsc 617 的 /csrf/post、/cors/vuln/origin 都是 `confirm-gate:technique-proven`
+ 非 confirmed_exploitable）。

本文件锁：post-pass 写出的 raw_json 必须能被硬闸用同一套判据准入。
"""
from __future__ import annotations

import json

from src.cli.benchmark_cli import (
    _apply_technique_oracle_postpass, _confirm_gate_decide)


class _FakeDB:
    """最小 sdb 替身：只实现 post-pass 用到的 SQL 形态。"""

    def __init__(self, spec, attempts):
        self.spec = dict(spec)
        self.attempts = [dict(a) for a in attempts]
        self.updates = []

    def execute(self, sql, params=(), fetchall=False, fetchone=False):
        s = " ".join(str(sql).split())
        # 2026-11-04：post-pass 的候选查询新增了 target_endpoint / expected_sink_file /
        # expected_sink_line 三列（归属校验要用），这里用前缀匹配保持同步。
        if s.startswith("SELECT id, family, iast_state, verification_status,"):
            return [dict(self.spec)] if fetchall else []
        if s.startswith("SELECT elapsed_ms FROM replay_attempts"):
            return [] if fetchall else None
        if s.startswith("SELECT attempt_no, payload"):
            return [dict(a) for a in self.attempts] if fetchall else []
        if s.startswith("SELECT raw_json FROM trigger_specs WHERE id=?"):
            return {"raw_json": self.spec.get("raw_json") or "{}"} if fetchone else []
        if s.startswith("UPDATE trigger_specs SET failure_attribution_reason=? WHERE id=?"):
            self.updates.append(("attribution-only", params))
            return None
        if s.startswith("UPDATE trigger_specs SET verification_status='confirmed_exploitable'"):
            self.updates.append(tuple(params))
            # 应用写回，供后续用「硬闸读到的同一份 raw_json」复核
            self.spec["raw_json"] = params[0]
            self.spec["verification_status"] = "confirmed_exploitable"
            self.spec["iast_state"] = "technique-proven"
            return None
        return [] if fetchall else None


def _xss_spec():
    return {"id": 1, "family": "xss", "iast_state": "sink-reached",
            "verification_status": "unconfirmed", "raw_json": "{}",
            "target_endpoint": "/xss/stored/show",
            "expected_sink_file": "src/main/java/org/joychou/controller/XSS.java",
            "expected_sink_line": 57}


def _xss_attempt():
    return {"attempt_no": 100, "payload": "<sastxss1>",
            "resp_body_head": "<sastxss1>", "resp_headers_digest": "",
            "status_code": 200, "http_method": "GET", "elapsed_ms": 20}


def test_postpass_writes_gate_readable_evidence():
    db = _FakeDB(_xss_spec(), [_xss_attempt()])
    assert _apply_technique_oracle_postpass(617, db) == 1
    assert len(db.updates) == 1

    rj = json.loads(db.spec["raw_json"])
    te = rj["technique_evidence"]
    assert te["admitted"] is True
    assert te["technique"] == "xss_reflected"
    assert rj["d2_evidence"]["d2_harmful"] is True
    assert rj["dast_impact_evidence"]["impact_observed"] is True
    assert db.spec["verification_status"] == "confirmed_exploitable"

    # 2026-11-06：收紧后硬闸要求 impact_observed 另有结构化交叉支撑。
    # post-pass 必须把技术判据投影成明确影响类型，否则写出的 raw_json 只剩裸布尔，
    # 证据链在 post-pass 与硬闸之间二次断裂。
    dast_block = rj["dast_impact_evidence"]
    assert dast_block["impact_kind"] == "technique_oracle:xss_reflected"
    assert dast_block["observation"]

    # 硬闸用「同一份完整 dast_impact_evidence」复核（与 _apply_confirmation_gate
    # 的真实调用形态一致）：必须准入，而不是降级。
    ok, code, _ = _confirm_gate_decide(
        db.spec["iast_state"],
        {"matched_event_ids": [], "value_hit": {}},
        dast_block,
        {"harmful": bool(rj["d2_evidence"].get("d2_harmful"))},
    )
    assert ok and code == "impact_evidence"

    # 反证：只摘出裸布尔交给硬闸仍必须拒绝 —— 的 629 误报闸门不放宽。
    bare_ok, bare_code, _ = _confirm_gate_decide(
        "technique-proven",
        {"matched_event_ids": [], "value_hit": {}},
        {"impact_observed": True},
        {"harmful": True},
    )
    assert not bare_ok and bare_code == "no_positive_evidence"


def test_empty_raw_json_is_rejected_by_gate():
    """反证：旧实现（不写 raw_json）会被硬闸判 no_positive_evidence。"""
    ok, code, _ = _confirm_gate_decide(
        "technique-proven",
        {"matched_event_ids": [], "value_hit": {}},
        {},
        {"harmful": False},
    )
    assert not ok and code == "no_positive_evidence"


def test_postpass_does_not_upgrade_when_no_hard_observation():
    """无硬观测时 post-pass 必须原样保留（只升级、不降级、不造证据）。"""
    a = dict(_xss_attempt())
    a["resp_body_head"] = "SecurityUtil is not http or https"
    db = _FakeDB(_xss_spec(), [a])
    assert _apply_technique_oracle_postpass(617, db) == 0
    assert db.updates == []
    assert db.spec["verification_status"] == "unconfirmed"


def test_classify_layer_csrf_empty_payload_is_verdict_not_spec_gap():
    """CSRF 的空载荷是设计（无 token 请求本身即载荷），不该归 layer1_spec。

    jsc 617 spec 237772：6 次重放全空 payload，但 `CSRF passed.` 已打出来，
    旧逻辑把它误记成「A2 未产出可投弹药」。
    """
    from src.core.failure_attribution import LAYER_VERDICT, classify_layer
    spec = {"family": "csrf", "verification_status": "unconfirmed",
            "iast_state": "confirm-gate:technique-proven",
            "failure_attribution": "true_miss", "attack_payloads_json": "[]"}
    atts = [{"status_code": 200, "payload": ""} for _ in range(6)]
    layer, reason = classify_layer(spec, atts)
    assert layer == LAYER_VERDICT, reason


def test_classify_layer_other_family_empty_payload_still_spec_gap():
    """口径修正只放宽 csrf，其它族空载荷仍归 layer1_spec。"""
    from src.core.failure_attribution import LAYER_SPEC, classify_layer
    spec = {"family": "jsonp_referer", "verification_status": "unconfirmed",
            "iast_state": "sink-reached", "failure_attribution": "true_miss",
            "attack_payloads_json": "[]"}
    atts = [{"status_code": 200, "payload": ""} for _ in range(2)]
    layer, _ = classify_layer(spec, atts)
    assert layer == LAYER_SPEC
