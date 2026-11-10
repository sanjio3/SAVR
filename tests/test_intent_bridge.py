"""意图桥接单测（src/iast/intent_bridge.py）。

无 LLM 依赖。覆盖：emit_intents_from_verdicts（含从 trigger_specs 取 endpoint/param）、
reconcile 回写、build_a2_intent_hints 透传。需要 replay_intents + trigger_specs 两张表。
"""
import sqlite3

from src.iast import intent_bridge as IB
from src.iast import replay_intents_repo as R


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = lambda cur, row: {col[0]: row[idx]
                                      for idx, col in enumerate(cur.description)}
    R.ensure_replay_intents(c)
    c.execute(
        "CREATE TABLE IF NOT EXISTS trigger_specs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, vulnerability_hash_v2 TEXT, "
        "family TEXT, target_endpoint TEXT, http_method TEXT, param_name TEXT, "
        "param_location TEXT, round_no INTEGER DEFAULT 1)")
    return c


def _seed_spec(c, *, task_id, vhash, family="sql_injection", endpoint="/x",
               method="GET", param="p", loc="query"):
    c.execute(
        "INSERT INTO trigger_specs (task_id, vulnerability_hash_v2, family, target_endpoint, "
        "http_method, param_name, param_location) VALUES (?,?,?,?,?,?,?)",
        (task_id, vhash, family, endpoint, method, param, loc))
    c.commit()
    return c.execute("SELECT id FROM trigger_specs ORDER BY id DESC LIMIT 1").fetchone()["id"]


def test_emit_from_verdicts_creates_pending_for_payload_problem():
    c = _conn()
    sid = _seed_spec(c, task_id=7, vhash="h1")
    classified = {"h1": {"verdict": "payload_problem", "action": "change_payload",
                         "payload": "%00", "reason": "被转义"}}
    n = IB.emit_intents_from_verdicts(c, 7, classified)
    assert n == 1
    pend = R.get_pending(c, 7)
    assert len(pend) == 1
    assert pend[0]["spec_id"] == sid
    assert pend[0]["target_endpoint"] == "/x"
    assert pend[0]["action"] == "change_payload"
    assert pend[0]["status"] == "pending"


def test_emit_from_verdicts_confirmed_becomes_abandoned():
    c = _conn()
    _seed_spec(c, task_id=7, vhash="h2", family="xss", endpoint="/y", param="q", loc="body")
    classified = {"h2": {"verdict": "confirmed", "action": "give_up"}}
    IB.emit_intents_from_verdicts(c, 7, classified)
    # abandoned 不进 pending
    assert R.get_pending(c, 7) == []
    row = c.execute("SELECT status FROM replay_intents WHERE vulnerability_hash_v2='h2'").fetchone()
    assert row["status"] == "abandoned"


def test_emit_uses_spec_ctx_over_db_lookup():
    c = _conn()
    # 不种表，仅用 spec_ctx 提供 endpoint
    classified = {"h3": {"verdict": "approach_problem", "action": "change_location",
                         "reason": "位置错"}}
    ctx = {"h3": {"id": 99, "target_endpoint": "/ctx", "http_method": "POST",
                  "param_name": "z", "param_location": "cookie", "family": "cmdi",
                  "round_no": 2}}
    n = IB.emit_intents_from_verdicts(c, 7, classified, spec_ctx=ctx)
    assert n == 1
    pend = R.get_pending(c, 7)
    assert pend[0]["target_endpoint"] == "/ctx"
    assert pend[0]["param_location"] == "cookie"
    assert pend[0]["round_no"] == 2


def test_reconcile_marks_effective():
    c = _conn()
    iid = R.insert_intent(c, task_id=7, action="change_encoding", priority=10)
    IB.reconcile_intent_after_attempt(c, iid, effective=True,
                                      evidence_ref="replay_attempts:5", rationale="布尔差异")
    row = c.execute("SELECT status, evidence_ref, rationale FROM replay_intents WHERE id=?",
                    (iid,)).fetchone()
    assert row["status"] == "done_effective"
    assert row["evidence_ref"] == "replay_attempts:5"
    assert row["rationale"] == "布尔差异"


def test_reconcile_marks_ineffective():
    c = _conn()
    iid = R.insert_intent(c, task_id=7, action="add_header", priority=10)
    IB.reconcile_intent_after_attempt(c, iid, effective=False)
    row = c.execute("SELECT status FROM replay_intents WHERE id=?", (iid,)).fetchone()
    assert row["status"] == "done_ineffective"


def test_build_a2_intent_hints_passes_through():
    c = _conn()
    R.insert_intent(c, task_id=7, target_endpoint="/a", param_name="p",
                    param_location="query", action="change_payload", priority=90)
    iid = R.insert_intent(c, task_id=7, target_endpoint="/b", param_name="c",
                           param_location="cookie", action="change_encoding", priority=5)
    R.update_status(c, iid, "done_ineffective")
    s = IB.build_a2_intent_hints(c, 7)
    assert "待试意图" in s and "已试无效" in s
    assert "/a p(query)" in s and "change_payload" in s
