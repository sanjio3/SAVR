"""确认态硬闸 + D2 证据回灌 spec.raw_json 回归守卫。

背景（run 32/ run 34 实证）：
  ① 证伪失效：283 条 confirmed_exploitable 里有 17 条 iast_state=no-arrival —— 探针明确记录
     「请求没抵达应用」，平台却仍下肯定结论。按「自己提出假说、自己否定收紧」的框架，这不是
     与真值比精确率的问题，是证伪环节失效：假说提出了却没有任何正向证据就确认了。
  ② 信息黑洞：D2 产物只写 findings.raw_json，trigger_specs 侧 d2_evidence / d2_output /
     poc / executed / sink / data_flow 恒为空（run 32 实测 262/262 全空）。

本测试锁定三条不变量：
  A. 三准入（运行时到达 / 结果点有害且有可观测影响 / 业务差分确认）任一成立才允许确认；
  B. 无正向证据的 confirmed_exploitable 一律降级 unconfirmed（DB 兜底路径也要覆盖）；
  C. 证据回灌是 merge 不是覆盖（吃掉 replay_adjust 多轮修正史是回归），且 evidence_summary
     必须是人话、不得出现内部状态枚举字眼。
"""
import json

import pytest

from src.infrastructure.db import Database
from src.cli.benchmark_cli import (
    _confirm_gate_decide,
    _build_d2_evidence_block,
    _merge_spec_raw_json,
    _apply_confirmation_gate,
)

TASK = 1
WS = 3
_TS = "2026-09-29T00:00:00"

# 内部状态枚举字眼：evidence_summary 里不得原样出现（用户读不懂）
_INTERNAL_TOKENS = (
    "sink-reached-probe", "sink-reached", "iast-reached",
    "no-arrival", "no-iast-evidence", "impact_observed",
)


class _Res:
    """VerificationResult 的最小替身（benchmark_cli 只经 getattr 读取这几个字段）。"""

    def __init__(self, iast=None, dast=None, verdict=None, exec_ev=None,
                 poc_type="", poc_code=""):
        self.iast_evidence = iast or {}
        self.dast_impact_evidence = dast or {}
        self.d2_verdict = verdict or {}
        self.execution_evidence = exec_ev or {}
        self.poc_type = poc_type
        self.poc_code = poc_code


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "app.db"))
    d.execute(
        "INSERT INTO workspaces (id, name, target_path, settings_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (WS, "ws", "/tmp/proj", "{}", _TS, _TS),
    )
    d.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, "
        "options_json, summary_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (TASK, WS, "task1", "completed", "done", "/tmp/out", "{}", "{}", _TS),
    )
    return d


def _seed(db, rows):
    """rows: (id, family, verification_status, iast_state, bl_confirmed, raw_json)"""
    for i, fam, vs, st, bl, rj in rows:
        # vulnerability_hash_v2 逐条唯一：trigger_specs 有 UNIQUE(task_id, vhash)（upsert 用），
        # 同一任务插多条 spec 时留空会撞索引。
        db.execute(
            "INSERT INTO trigger_specs (id, task_id, workspace_id, vulnerability_hash_v2, family, "
            "target_endpoint, verification_status, iast_state, business_logic_confirmed, raw_json,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (i, TASK, WS, "h%s" % i, fam, "/benchmark/x", vs, st, bl,
             json.dumps(rj, ensure_ascii=False), _TS),
        )


def _get(db, sid):
    r = db.execute(
        "SELECT verification_status, iast_state, business_logic_confirmed, raw_json "
        "FROM trigger_specs WHERE id=?", (sid,), fetchone=True,
    )
    return r


# ---------------------------------------------------------------- A. 三准入判定


def test_admit_on_runtime_arrival():
    """v2 B6（2026-10-10）：到达单独不足（L1≠L4），须配语义层正向证据才准入。"""
    ok, code, _ = _confirm_gate_decide("sink-reached-probe", {}, {}, {})
    assert ok is False and code == "arrival_without_semantics"
    # 到达 + 值级 hit_live（L2 事实层）→ 准入
    ok2, code2, _ = _confirm_gate_decide(
        "sink-reached-probe", {"value_hit": {"hit": True, "form": "hit_live"}}, {}, {})
    assert ok2 and code2 == "runtime_arrival"
    # 到达 + sink 异常签名（B2，L3 语义层）→ 准入
    ok3, code3, _ = _confirm_gate_decide(
        "sink-reached-probe", {"sink_exception_class": "java.sql.SQLException"}, {}, {})
    assert ok3 and code3 == "runtime_arrival"


def test_admit_on_matched_events_even_without_arrival_state():
    """matched_event_ids 构成到达，但无语义证据 → v2 B6 降级为 arrival_without_semantics。"""
    ok, code, _ = _confirm_gate_decide("no-arrival", {"matched_event_ids": [1, 2]}, {}, {})
    assert ok is False and code == "arrival_without_semantics"
    # 补上带结构化证据的影响观测即准入（到达证据本身不算结果点证据）
    ok2, code2, _ = _confirm_gate_decide(
        "no-arrival", {"matched_event_ids": [1, 2]},
        {"impact_observed": True, "impact_kind": "reflection"}, {})
    assert ok2 and code2 == "runtime_arrival"


def test_admit_on_impact_evidence():
    # 2026-11-06：impact_observed 是 D2 布尔，必须有结构化结果点证据交叉支撑。
    ok, code, _ = _confirm_gate_decide(
        "no-arrival", {}, {"impact_observed": True, "impact_kind": "reflection"},
        {"harmful": True})
    assert ok and code == "impact_evidence"


def test_bare_impact_observed_cannot_confirm_629_regression():
    """629 红线误报锁：sink-reached + D2 一个裸布尔不得放行。

    本轮的 spec 239136 只有 sink-reached、一条 1292ms 慢请求、
    oracle=inconclusive/no_delay，D2 却置 impact_observed=True，
    runtime_arrival 无条件采信 ⇒ tomcatfiltermemshell.java 被误判为命令执行。
    """
    ok, code, _ = _confirm_gate_decide(
        "sink-reached", {}, {"impact_observed": True}, {"harmful": True})
    assert ok is False and code == "arrival_without_semantics"
    # 有值级命中时仍要放行，证明收紧没误杀真阳性
    ok2, code2, _ = _confirm_gate_decide(
        "sink-reached", {"value_hit": {"hit": True, "form": "hit_live"}},
        {"impact_observed": True}, {"harmful": True})
    assert ok2 and code2 == "runtime_arrival"
    # 带外回调也仍然独立构成语义证据
    ok3, code3, _ = _confirm_gate_decide(
        "sink-reached", {}, {"impact_observed": True}, {"harmful": True},
        oob_confirmed=True)
    assert ok3 and code3 == "runtime_arrival"


def test_technique_postpass_does_not_gate_on_iast_state():
    """629 掉点锁：postpass 入口不得再把探针到达态当门槛。

    technique_oracle 的判据全是 HTTP 响应层硬观测，不依赖 IAST。
    629 的 jsonp spec 因探针抖动落成 no-arrival，明明 `alert(...)//`
    原样回显却被入口 SQL 整个跳过，真值点掉 1 个。
    """
    import inspect
    from src.cli.benchmark_cli import _apply_technique_oracle_postpass
    src = inspect.getsource(_apply_technique_oracle_postpass)
    assert "iast_state LIKE" not in src
    assert "EXISTS (SELECT 1 FROM replay_attempts" in src


def test_admit_on_oob_callback():
    ok, code, _ = _confirm_gate_decide(
        "no-arrival", {}, {}, {"harmful": True}, oob_confirmed=True)
    assert ok and code == "impact_evidence"


def test_admit_on_deserialization_chain():
    ok, code, _ = _confirm_gate_decide(
        "no-arrival", {}, {}, {"harmful": True, "deserialization_chain_confirmed": True})
    assert ok and code == "runtime_arrival"


def test_admit_on_business_diff():
    ok, code, _ = _confirm_gate_decide("no-arrival", {}, {}, {}, bl_confirmed=True)
    assert ok and code == "business_diff"


def test_deny_when_no_positive_evidence():
    ok, code, why = _confirm_gate_decide("no-arrival", {}, {}, {"harmful": False})
    assert (ok, code) == (False, "no_positive_evidence")
    assert why


def test_deny_when_harmful_but_no_observable_impact():
    """有害裁决但没有可观测影响实证 → 仍是「提出了没能证实」，不得确认。"""
    ok, code, _ = _confirm_gate_decide(
        "no-iast-evidence", {}, {"impact_observed": False}, {"harmful": True})
    assert ok is False and code == "no_positive_evidence"


# ---------------------------------------------------------------- B. DB 兜底硬闸


def test_gate_downgrades_no_arrival_confirmed(db):
    _seed(db, [
        (1, "sql_injection", "confirmed_exploitable", "no-arrival", 0, {}),
    ])
    n = _apply_confirmation_gate(TASK, db)
    r = _get(db, 1)
    assert n == 1
    assert r["verification_status"] == "unconfirmed"
    assert r["iast_state"] == "confirm-gate:no-arrival"
    assert r["business_logic_confirmed"] == 0
    assert json.loads(r["raw_json"])["confirm_gate"]["code"] == "no_positive_evidence"


def test_gate_keeps_arrival_confirmed(db):
    """v2 B6：到达 + 语义证据（业务差分 bl=1）保持确认；仅到达无语义 → 降级 unconfirmed。"""
    _seed(db, [
        (2, "xss", "confirmed_exploitable", "sink-reached-probe", 0, {}),
        (3, "idor", "confirmed_exploitable", "business-logic-confirmed", 1, {}),
    ])
    _apply_confirmation_gate(TASK, db)
    # idor：business_logic_confirmed=1 是语义层正向证据 → 保持确认
    assert _get(db, 3)["verification_status"] == "confirmed_exploitable"
    # xss：仅到达、无任何语义证据 → 降级（fail-open 到 unconfirmed，不冒充已确认）
    r2 = _get(db, 2)
    assert r2["verification_status"] == "unconfirmed"
    assert json.loads(r2["raw_json"])["confirm_gate"]["code"] == "arrival_without_semantics"


def test_gate_keeps_confirmed_backed_by_evidence_block(db):
    """到达证据 + 结构化影响证据的 spec，即便 iast_state 是 no-arrival 也放行。

    2026-11-06：matched_event_ids 只证明到达，不再是结果点证据；
    裸 impact_observed 布尔不得据此确认（见 629 红线误报锁）。
    """
    _seed(db, [
        (4, "xss", "confirmed_exploitable", "no-arrival", 0,
         {"d2_evidence": {"matched_event_ids": [9]},
          "d2_output": {"impact_observed": True},
          "dast_impact_evidence": {"impact_kind": "reflection"}}),
    ])
    assert _apply_confirmation_gate(TASK, db) == 0
    assert _get(db, 4)["verification_status"] == "confirmed_exploitable"


def test_gate_demotes_bare_impact_observed_with_only_arrival(db):
    """到达证据 + 裸 D2 布尔 ⇒ 降级（本轮红线误报同形态）。"""
    _seed(db, [
        (44, "command_execution", "confirmed_exploitable", "no-arrival", 0,
         {"d2_evidence": {"matched_event_ids": [9], "d2_harmful": True},
          "d2_output": {"impact_observed": True}}),
    ])
    _apply_confirmation_gate(TASK, db)
    assert _get(db, 44)["verification_status"] != "confirmed_exploitable"


def test_gate_does_not_touch_other_statuses(db):
    _seed(db, [
        (5, "xss", "unconfirmed", "no-arrival", 0, {}),
        (6, "xss", "no_evidence", "no-iast-evidence", 0, {}),
        (7, "xss", "confirmed_code_property", "family-route:confirmed_code_property", 0, {}),
    ])
    assert _apply_confirmation_gate(TASK, db) == 0
    for sid, expect in ((5, "unconfirmed"), (6, "no_evidence"), (7, "confirmed_code_property")):
        assert _get(db, sid)["verification_status"] == expect


def test_gate_never_pairs_no_arrival_with_confirmed(db):
    """验收口径：跑完硬闸后 no-arrival 与 confirmed_exploitable 同时出现的条数必须为 0。"""
    _seed(db, [
        (8, "sqli", "confirmed_exploitable", "no-arrival", 0, {}),
        (9, "sqli", "confirmed_exploitable", "no-iast-evidence", 0, {}),
        (10, "sqli", "confirmed_exploitable", "sink-reached-probe", 0, {}),
    ])
    _apply_confirmation_gate(TASK, db)
    left = db.execute(
        "SELECT COUNT(*) AS n FROM trigger_specs WHERE task_id=? "
        "AND verification_status='confirmed_exploitable' AND iast_state='no-arrival'",
        (TASK,), fetchone=True,
    )["n"]
    assert left == 0


# ---------------------------------------------------------------- C. 证据回灌


def test_evidence_block_fills_all_previously_empty_fields():
    res = _Res(
        iast={"state": "sink-reached-probe", "matched_event_ids": [103110],
              "sink_file": "src/BenchmarkTest00153.java", "sink_line": 59,
              "sink_method": "ResponseFacade.setHeader", "source_value": "Referer",
              "taint_path": ["HttpServletRequest.getHeaders", "doPost"],
              "chain_conformance": {"conforms": True, "checked": 3, "matched": 3, "missing": []}},
        dast={"reached": True, "status_code": 200, "impact_observed": True,
              "attack_payload_used": "<script>alert(1)</script>",
              "response_summary": "status=200; body=<script>alert(1)</script>"},
        verdict={"harmful": True, "sink_reached": True, "confidence": "high",
                 "reason": "探针在 sink 现场显式断言 canary 抵达危险函数实参"},
        exec_ev={"requests_made": [{"url": "http://x/y"}]},
        poc_type="python", poc_code="import requests\n...",
    )
    spec = {"target_endpoint": "/benchmark/BenchmarkTest00153", "http_method": "POST",
            "param_name": "Referer", "param_location": "header",
            "expected_sink_file": "src/BenchmarkTest00153.java", "expected_sink_line": 59,
            "attack_payloads_json": "[]"}
    block = _build_d2_evidence_block({"family": "xss", "file": "src/B.java", "line": 59}, res, spec)

    assert block["payload"] == "<script>alert(1)</script>"
    assert block["executed"] is True
    assert block["sink"]["file"] and block["sink"]["line"] == 59
    assert block["data_flow"]["taint_path"]
    assert block["d2_evidence"]["d2_harmful"] is True
    assert block["d2_output"]["status_code"] == 200
    assert block["d2_output"]["endpoint"] == "/benchmark/BenchmarkTest00153"
    assert block["poc"]["verified"] is True
    assert block["evidence_summary"]

    # 人话：不得原样出现内部状态枚举
    for tok in _INTERNAL_TOKENS:
        assert tok not in block["evidence_summary"], tok


def test_evidence_summary_falls_back_to_human_wording_without_events():
    res = _Res(iast={"state": "no-arrival"}, dast={}, verdict={"harmful": False})
    block = _build_d2_evidence_block({"family": "xss"}, res, {"attack_payloads_json": "[\"a\"]"})
    assert block["evidence_summary"]
    assert "没有运行时到达证据" in block["evidence_summary"]
    for tok in _INTERNAL_TOKENS:
        assert tok not in block["evidence_summary"], tok


def test_no_arrival_wording_does_not_claim_target_unreachable():
    """jsc 622 实证 no-arrival 可与 HTTP 200 / reached=true 并存（请求到了应用，
    只是探针没在目标危险函数处抓到 canary）。旧人话「靶场不可达或路由不匹配」会误导
    对账，必须改成如实表述，且仍不得泄漏内部状态枚举。
    """
    res = _Res(iast={"state": "no-arrival"}, dast={}, verdict={"harmful": False})
    block = _build_d2_evidence_block({"family": "xss"}, res, {"attack_payloads_json": "[\"a\"]"})
    summary = block["evidence_summary"]
    assert "靶场不可达" not in summary
    assert "路由不匹配" not in summary
    assert "请求可能已抵达应用" in summary
    assert "没有运行时到达证据" in summary
    for tok in _INTERNAL_TOKENS:
        assert tok not in summary, tok


def test_d2_output_separates_delivery_from_execution_evidence_count():
    """requests_made 是 D2 执行证据里抽取的 HTTP 条目数，不等于 D1 投递数。
    实测 status_code=200 / reached=true 但 requests_made=0 时，delivery_observed 必须为
    True、requests_made_scope 标清来源，让对账能直接区分两路证据，且 executed 仍为 True。
    """
    res = _Res(
        iast={},
        dast={"reached": True, "status_code": 200, "impact_observed": False},
        verdict={"harmful": False},
        exec_ev={"requests_made": []},  # D2 证据里没抽出条目，但请求确实投递并拿到 200
    )
    block = _build_d2_evidence_block({"family": "xss"}, res, {"attack_payloads_json": "[]"})
    out = block["d2_output"]
    assert out["requests_made"] == 0
    assert out["status_code"] == 200
    assert out["reached"] is True
    assert out["delivery_observed"] is True
    assert out["requests_made_scope"] == "d2_execution_evidence"
    assert block["executed"] is True  # 靠 de.reached 兜底，不受 requests_made=0 影响


def test_delivery_observed_false_when_no_response_evidence():
    """反例：D2 证据与 DAST 到达证据都为空时，不得凭空宣称投递已发生。"""
    res = _Res(iast={}, dast={}, verdict={"harmful": False}, exec_ev={"requests_made": []})
    block = _build_d2_evidence_block({"family": "xss"}, res, {"attack_payloads_json": "[]"})
    assert block["d2_output"]["delivery_observed"] is False
    assert block["executed"] is False


def test_merge_preserves_existing_replay_adjust():
    """硬约束：merge 不是覆盖，i2_feedback 落的 replay_adjust 多轮修正史必须存活。"""
    base = {"replay_adjust": {"round": 2, "actions": ["param_alias"]}, "source": "a2"}
    merged = _merge_spec_raw_json(
        json.dumps(base, ensure_ascii=False),
        {"payload": "p", "evidence_summary": "s"}, "confirmed_exploitable",
        gate={"admitted": True, "code": "runtime_arrival"},
    )
    assert merged["replay_adjust"]["round"] == 2
    assert merged["source"] == "a2"
    assert merged["payload"] == "p"
    assert merged["verification_status"] == "confirmed_exploitable"
    assert merged["confirm_gate"]["code"] == "runtime_arrival"


def test_merge_survives_corrupt_raw_json():
    merged = _merge_spec_raw_json("{not-json", {"payload": "p"}, "unconfirmed")
    assert merged["payload"] == "p"
    assert merged["verification_status"] == "unconfirmed"
