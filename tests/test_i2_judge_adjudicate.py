"""I2 判因的闭环接线（i2_judge.adjudicate_feedbacks）单测。

重点锁定四件事：四态到 failure_class 的映射、LLM 预算硬上限、spec/attempts 缺失时降级、
以及「只喂摘要不喂响应原文」的纪律。
"""
import json

from src.agents import i2_judge as J


class _FakeDB:
    """最小 DB 替身：按 SQL 特征返回 spec / attempts。"""

    def __init__(self, spec=None, attempts=None):
        self.spec = spec
        self.attempts = attempts or []

    def execute(self, sql, params=(), *, fetchone=False, fetchall=False, **kw):
        if "trigger_specs" in sql:
            return dict(self.spec) if (fetchone and self.spec) else (None if fetchone else [])
        if "replay_attempts" in sql:
            return list(self.attempts) if fetchall else None
        return None if fetchone else []


def _spec(**kw):
    base = {"id": 11, "task_id": 9, "family": "sql_injection",
            "target_endpoint": "/sqli-00/BenchmarkTest00100", "http_method": "POST",
            "param_name": "BenchmarkTest00100", "param_location": "cookie",
            "attack_payloads_json": json.dumps(["' OR '1'='1"]),
            "filter_spec_json": "{}", "oracle_state": "", "oracle_signal": "",
            "verification_status": "unconfirmed"}
    base.update(kw)
    return base


def _fb(hid="h1", **kw):
    base = {"hypothesis_id": hid, "reason": "假说门禁悬置"}
    base.update(kw)
    return base


# ───────────────────────── 分桶映射 ─────────────────────────

def test_oracle_exploitable_maps_to_confirmed_and_hypothesis_defect():
    """oracle 已正向 ⇒ 规则判 confirmed ⇒ 仍属 hypothesis_defect（回灌重造，不是运行时问题）。"""
    db = _FakeDB(spec=_spec(oracle_state="exploitable", oracle_signal="boolean_diff"))
    out = J.adjudicate_feedbacks([_fb()], db=db, task_id=9)
    d = out["classified"]["h1"]
    assert d["verdict"] == "confirmed" and d["source"] == "rule"
    assert d["failure_class"] == "hypothesis_defect"
    assert out["llm_calls"] == 0  # 规则判定，不烧 LLM


def test_oracle_not_exploitable_maps_to_runtime_refutation():
    db = _FakeDB(spec=_spec(oracle_state="not_exploitable",
                            oracle_signal="reflection_escaped"))
    out = J.adjudicate_feedbacks([_fb()], db=db, task_id=9)
    d = out["classified"]["h1"]
    assert d["verdict"] == "false_positive"
    assert d["failure_class"] == "runtime_refutation"  # 不进 A2 回灌
    assert out["llm_calls"] == 0


def test_property_family_maps_to_runtime_refutation():
    db = _FakeDB(spec=_spec(family="weak_hash"))
    out = J.adjudicate_feedbacks([_fb()], db=db, task_id=9)
    assert out["classified"]["h1"]["failure_class"] == "runtime_refutation"


def test_no_payload_asks_change_payload():
    db = _FakeDB(spec=_spec(attack_payloads_json="[]"))
    out = J.adjudicate_feedbacks([_fb()], db=db, task_id=9)
    d = out["classified"]["h1"]
    assert d["verdict"] == "payload_problem" and d["action"] == "change_payload"
    assert d["failure_class"] == "hypothesis_defect"


# ───────────────────────── LLM 路径与预算 ─────────────────────────

def _patch_llm(responses):
    import src.agents.a2_integrated_analyst as a2
    calls = {"n": 0}

    def _fake(msgs, timeout=120.0):
        calls["n"] += 1
        idx = min(calls["n"] - 1, len(responses) - 1)
        return responses[idx]

    a2.ollama_chat = _fake
    return a2, calls


def test_ambiguous_goes_to_llm_and_reclassifies():
    a2, calls = _patch_llm([json.dumps({
        "verdict": "payload_problem", "action": "change_payload",
        "payload": "x'/**/OR/**/1=1", "reason": "引号被过滤", "confidence": 0.8})])
    orig = a2.ollama_chat
    try:
        out = J.adjudicate_feedbacks([_fb()], db=_FakeDB(spec=_spec()), task_id=9)
    finally:
        a2.ollama_chat = orig
    d = out["classified"]["h1"]
    assert d["source"] == "llm" and d["verdict"] == "payload_problem"
    assert d["failure_class"] == "hypothesis_defect"
    assert out["llm_calls"] == 1 and calls["n"] == 1


def test_llm_budget_is_hard_capped():
    a2, calls = _patch_llm([json.dumps({
        "verdict": "approach_problem", "action": "change_location",
        "payload": "x", "reason": "位置不对", "confidence": 0.6})])
    orig = a2.ollama_chat
    try:
        fbs = [_fb("h%d" % i) for i in range(5)]
        out = J.adjudicate_feedbacks(fbs, db=_FakeDB(spec=_spec()), task_id=9,
                                     max_llm_calls=2)
    finally:
        a2.ollama_chat = orig
    assert out["llm_calls"] == 2          # 硬上限
    assert calls["n"] == 2
    assert len(out["classified"]) == 5    # 超预算的仍给规则结论，不丢条目
    assert out["classified"]["h4"]["source"] in ("rule", "fallback")


def test_llm_disabled_falls_back_to_rule():
    out = J.adjudicate_feedbacks([_fb()], db=_FakeDB(spec=_spec()), task_id=9,
                                 llm_enabled=False)
    d = out["classified"]["h1"]
    assert d["source"] == "rule" and out["llm_calls"] == 0


# ───────────────────────── 降级与纪律 ─────────────────────────

def test_missing_spec_and_db_do_not_crash():
    out = J.adjudicate_feedbacks([_fb()], db=None, task_id=9, llm_enabled=False)
    assert out["classified"]["h1"]["verdict"] == "payload_problem"  # 无 payload ⇒ 换弹
    out2 = J.adjudicate_feedbacks([_fb()], db=_FakeDB(spec=None), task_id=None,
                                  llm_enabled=False)
    assert "h1" in out2["classified"]


def test_feedback_without_id_is_skipped():
    out = J.adjudicate_feedbacks([{"reason": "无身份"}], db=_FakeDB(spec=_spec()),
                                 task_id=9)
    assert out["classified"] == {}


def test_attempts_summary_excludes_body_text():
    """纪律：观察包只喂摘要，绝不喂响应原文。"""
    attempts = [{"attempt_no": 1, "payload": "x", "param_location": "query",
                 "encoding": "a2", "status_code": 200, "elapsed_ms": 30,
                 "waf_blocked": 0, "read_state": "absent", "verdict": "",
                 "resp_body_head": "<html>SECRET BODY</html>"}]
    out = J._load_attempts(_FakeDB(attempts=attempts), spec_id=11)
    assert out and "resp_body_head" not in out[0]


def test_feedback_facts_are_merged_into_packet():
    db = _FakeDB(spec=_spec())
    fb = _fb(status_code=403, iast_state="blocked")
    pkt_seen = {}

    orig = J.decide
    def _spy(packet, gateway=None, llm_enabled=True):
        pkt_seen["status_code"] = getattr(packet, "status_code", "")
        pkt_seen["iast_state"] = getattr(packet, "iast_state", "")
        return {"verdict": "false_positive", "action": "give_up", "payload": "",
                "reason": "spy", "confidence": 0.0, "source": "rule"}
    J.decide = _spy
    try:
        J.adjudicate_feedbacks([fb], db=db, task_id=9)
    finally:
        J.decide = orig
    assert pkt_seen["status_code"] == "403" and pkt_seen["iast_state"] == "blocked"


# ───────────────────────── 分桶应用（纯函数，锁住「旧桶被清空」的 bug） ─────────────────────────

def test_apply_reclassification_moves_only_judged_items():
    kept = _fb("keep1")
    moved = _fb("move1")
    routed = {"hypothesis_defect": [kept, moved], "runtime_observation": []}
    verdicts = {"classified": {"move1": {"failure_class": "runtime_refutation",
                                         "verdict": "false_positive", "source": "rule",
                                         "action": "give_up", "reason": "判否",
                                         "confidence": 0.8}}}
    out = J.apply_reclassification(routed, verdicts)
    assert out["moved"] == 1 and out["kept"] == 1 and out["annotated"] == 1
    assert routed["hypothesis_defect"] == [kept]          # 未判的必须留下
    assert routed["runtime_refutation"] == [moved]
    assert moved["llm_verdict"] == "false_positive"       # 判因结果标注在条目上


def test_apply_reclassification_keeps_bucket_when_nothing_moved():
    a, b = _fb("a"), _fb("b")
    routed = {"hypothesis_defect": [a, b]}
    out = J.apply_reclassification(routed, {"classified": {
        "a": {"failure_class": "hypothesis_defect"}, "b": {"failure_class": "hypothesis_defect"}}})
    assert out["moved"] == 0 and out["kept"] == 2
    assert routed["hypothesis_defect"] == [a, b]          # 一条都不能丢


def test_apply_reclassification_handles_empty_and_garbage():
    assert J.apply_reclassification({}, {})["moved"] == 0
    assert J.apply_reclassification({"hypothesis_defect": []}, {})["kept"] == 0
    r = {"hypothesis_defect": ["not-a-dict", _fb("x")]}
    out = J.apply_reclassification(r, {"classified": {}})
    assert out["moved"] == 0 and len(r["hypothesis_defect"]) == 2


# ───────────────────────── 动作建议注入（最后一公里） ─────────────────────────

def test_attach_llm_directives_appends_action_into_reason():
    fb = _fb("h1", reason="未确认")
    fb.update({"llm_action": "change_payload", "llm_reason": "引号被过滤"})
    out = J.attach_llm_directives({"hypothesis_defect": [fb]})
    assert out["attached"] == 1
    assert "LLM 判因建议：change_payload" in fb["reason"]
    assert "引号被过滤" in fb["reason"] and fb["llm_directive_attached"] is True


def test_attach_llm_directives_skips_give_up_and_empty():
    a = _fb("a"); a["llm_action"] = "give_up"
    b = _fb("b")  # 无 llm_action
    out = J.attach_llm_directives({"hypothesis_defect": [a, b]})
    assert out["attached"] == 0
    assert "LLM 判因建议" not in a["reason"] and "LLM 判因建议" not in b["reason"]


def test_attach_llm_directives_is_idempotent():
    fb = _fb("h1", reason="r")
    fb.update({"llm_action": "change_location", "llm_reason": "位置不对"})
    routed = {"hypothesis_defect": [fb]}
    J.attach_llm_directives(routed)
    first = fb["reason"]
    J.attach_llm_directives(routed)   # 二次调用不应重复追加
    assert fb["reason"] == first and fb["reason"].count("LLM 判因建议") == 1


# ───────────────────────── 多源候选（runtime_observation 有弹打不通） ─────────────────────────

def test_apply_reclassification_multi_source_moves_payload_problem():
    """runtime_observation 里判出 payload_problem ⇒ 移到 hypothesis_defect（该换弹了）。"""
    ro = _fb("ro1", reason="canary 未观测到")
    routed = {"hypothesis_defect": [], "runtime_observation": [ro]}
    verdicts = {"classified": {"ro1": {"failure_class": "hypothesis_defect",
                                       "verdict": "payload_problem", "action": "change_payload",
                                       "source": "llm", "reason": "引号被吞"}}}
    out = J.apply_reclassification(routed, verdicts,
                                   source_classes=["hypothesis_defect", "runtime_observation"])
    assert out["moved"] == 1
    assert routed["hypothesis_defect"] == [ro] and routed["runtime_observation"] == []


def test_apply_reclassification_keeps_approach_problem_in_runtime_bucket():
    """打法问题留在运行时桶：重放侧改位置/编码比 A2 静态重写更对症。"""
    ro = _fb("ro2", reason="canary 未观测到")
    routed = {"hypothesis_defect": [], "runtime_observation": [ro]}
    verdicts = {"classified": {"ro2": {"failure_class": "hypothesis_defect",
                                       "verdict": "approach_problem",
                                       "action": "change_location",
                                       "source": "llm", "reason": "该换 cookie"}}}
    out = J.apply_reclassification(routed, verdicts,
                                   source_classes=["hypothesis_defect", "runtime_observation"])
    assert out["moved"] == 0
    assert routed["runtime_observation"] == [ro] and routed["hypothesis_defect"] == []
    assert ro["llm_action"] == "change_location"   # 但动作要标上，供重放侧消费


def test_payload_vhash_set_reads_spec_payloads():
    class _DB:
        def execute(self, sql, params=(), **kw):
            return [
                {"vulnerability_hash_v2": "a", "attack_payloads_json": '["x"]'},
                {"vulnerability_hash_v2": "b", "attack_payloads_json": "[]"},
                {"vulnerability_hash_v2": "c", "attack_payloads_json": "not-json"},
                {"vulnerability_hash_v2": "", "attack_payloads_json": '["y"]'},
            ]
    assert J.payload_vhash_set(_DB(), 1) == {"a"}
    assert J.payload_vhash_set(None, 1) == set()


def test_attach_directives_covers_runtime_bucket():
    ro = _fb("ro3", reason="canary 未观测到")
    ro.update({"llm_action": "change_encoding", "llm_reason": "编码问题"})
    out = J.attach_llm_directives(
        {"hypothesis_defect": [], "runtime_observation": [ro]},
        source_classes=["hypothesis_defect", "runtime_observation"])
    assert out["attached"] == 1
    assert "LLM 判因建议：change_encoding" in ro["reason"]


def test_llm_confirmed_is_not_trusted_but_rule_confirmed_is():
    """按来源分表：规则判 confirmed 可信（有 oracle 硬证据），LLM 判 confirmed 不采信。

    run 468 实测：LLM 判出 5/10 条 confirmed，对应 spec 的 oracle 全是
    inconclusive/boolean_same（零直接证据）——采信会把未打通的白送进 A2 重跑。
    """
    import json as _json
    import src.agents.a2_integrated_analyst as a2

    # 规则：oracle 正向 ⇒ confirmed 可信 ⇒ 归 hypothesis_defect（回灌重造）
    db_rule = _FakeDB(spec=_spec(oracle_state="exploitable", oracle_signal="boolean_diff"))
    out_rule = J.adjudicate_feedbacks([_fb("r1")], db=db_rule, task_id=9)
    assert out_rule["classified"]["r1"]["source"] == "rule"
    assert out_rule["classified"]["r1"]["failure_class"] == "hypothesis_defect"

    # LLM：判 confirmed 但不采信 ⇒ failure_class 为空（不移动）
    orig = a2.ollama_chat
    a2.ollama_chat = lambda msgs, timeout=120.0: _json.dumps({
        "verdict": "confirmed", "action": "give_up", "payload": "",
        "reason": "运行时证据表明成立", "confidence": 0.9})
    try:
        db_llm = _FakeDB(spec=_spec(oracle_state="inconclusive",
                                    oracle_signal="boolean_same"))
        out_llm = J.adjudicate_feedbacks([_fb("l1")], db=db_llm, task_id=9)
    finally:
        a2.ollama_chat = orig
    d = out_llm["classified"]["l1"]
    assert d["source"] == "llm" and d["verdict"] == "confirmed"
    assert d["failure_class"] == ""          # 不采信：不触发任何分桶移动
    # 应用后条目仍留在原桶（不会因为 LLM 说成立就白跑 A2）
    routed = {"hypothesis_defect": [_fb("l1")]}
    applied = J.apply_reclassification(routed, out_llm,
                                       source_classes=["hypothesis_defect"])
    assert applied["moved"] == 0 and len(routed["hypothesis_defect"]) == 1
