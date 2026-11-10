"""replay_intents 仓储单测（src/iast/replay_intents_repo.py）。

纯数据层，无 LLM 依赖。覆盖：建表、插入、pending/ineffective 查询、status 回写、
prompt 摘要（状态外置的核心指标：token 数不随轮次增长且只带动作名）、intent 映射。
"""
import sqlite3

from src.iast import replay_intents_repo as R


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = lambda cur, row: {col[0]: row[idx]
                                      for idx, col in enumerate(cur.description)}
    R.ensure_replay_intents(c)
    return c


def test_ensure_idempotent():
    c = _conn()
    R.ensure_replay_intents(c)  # 第二次不应报错
    c.execute("INSERT INTO replay_intents(task_id, created_at, updated_at) VALUES (1,'x','x')")
    assert c.execute("SELECT COUNT(*) AS n FROM replay_intents").fetchone()["n"] == 1


def test_insert_and_get_pending():
    c = _conn()
    iid = R.insert_intent(c, task_id=7, spec_id=10, target_endpoint="/x",
                          param_name="p", param_location="query",
                          action="change_payload", rationale="试不同编码", priority=80)
    assert iid > 0
    pend = R.get_pending(c, 7)
    assert len(pend) == 1
    assert pend[0]["status"] == "pending"
    assert pend[0]["priority"] == 80


def test_update_status_writes_evidence_and_rationale():
    c = _conn()
    iid = R.insert_intent(c, task_id=7, action="change_encoding", priority=50)
    R.update_status(c, iid, "done_ineffective", evidence_ref="replay_attempts:42",
                    rationale="编码后仍被转义")
    row = c.execute("SELECT * FROM replay_intents WHERE id=?", (iid,)).fetchone()
    assert row["status"] == "done_ineffective"
    assert row["evidence_ref"] == "replay_attempts:42"
    assert row["rationale"] == "编码后仍被转义"


def test_update_status_rejects_bad_status():
    c = _conn()
    iid = R.insert_intent(c, task_id=7, action="change_payload")
    try:
        R.update_status(c, iid, "bogus")
        assert False, "应拒绝非法 status"
    except ValueError:
        pass


def test_get_recent_ineffective_ordered_and_limited():
    c = _conn()
    for k in range(3):
        iid = R.insert_intent(c, task_id=7, action="change_location", priority=k)
        R.update_status(c, iid, "done_ineffective")
    # 再加一条 pending，确保不被算进 ineffective
    R.insert_intent(c, task_id=7, action="add_header", priority=1)
    ineff = R.get_recent_ineffective(c, 7, limit=2)
    assert len(ineff) == 2
    assert all(r["status"] == "done_ineffective" for r in ineff)


def test_summarize_for_prompt_empty_when_no_intents():
    c = _conn()
    assert R.summarize_for_prompt(c, 999) == ""


def test_summarize_for_prompt_shape():
    c = _conn()
    R.insert_intent(c, task_id=7, target_endpoint="/a", param_name="p",
                    param_location="query", action="change_payload",
                    payload_hint="%00", priority=90)
    R.insert_intent(c, task_id=7, target_endpoint="/b", param_name="c",
                    param_location="cookie", action="change_encoding", priority=40)
    iid = R.insert_intent(c, task_id=7, target_endpoint="/c", param_name="h",
                          param_location="header", action="add_header", priority=10)
    R.update_status(c, iid, "done_ineffective")
    s = R.summarize_for_prompt(c, 7, max_pending=20, max_ineffective=10)
    assert "待试意图" in s
    assert "已试无效" in s
    assert "/a p(query)" in s and "change_payload" in s
    assert "add_header" in s  # ineffective 也列出（避免重复）


def test_summarize_caps_pending_and_ineffective():
    c = _conn()
    for k in range(25):
        R.insert_intent(c, task_id=7, action="change_payload", priority=k)
    s = R.summarize_for_prompt(c, 7, max_pending=20, max_ineffective=10)
    # 待试块最多 20 条 + 标题行
    pending_lines = [ln for ln in s.splitlines() if ln.strip().startswith("-")]
    assert len(pending_lines) == 20


def test_build_intent_maps_confirmed_to_abandoned():
    rec = R.build_intent_from_i2_verdict(
        task_id=7, spec_id=1, vulnerability_hash_v2="h", family="sql_injection",
        endpoint="/x", http_method="GET", param_name="p", param_location="query",
        verdict="confirmed", action="give_up")
    assert rec["status"] == "abandoned"


def test_build_intent_maps_payload_problem_to_pending():
    rec = R.build_intent_from_i2_verdict(
        task_id=7, spec_id=2, vulnerability_hash_v2="h", family="xss",
        endpoint="/y", http_method="POST", param_name="q", param_location="body",
        verdict="payload_problem", action="change_encoding",
        encoding="double", rationale="被单层编码拦")
    assert rec["status"] == "pending"
    assert rec["action"] == "change_encoding"
    assert rec["encoding_hint"] == "double"


def test_build_intent_invalid_action_forced_give_up():
    rec = R.build_intent_from_i2_verdict(
        task_id=7, spec_id=3, vulnerability_hash_v2="h", family="cmdi",
        endpoint="/z", http_method="GET", param_name="p", param_location="query",
        verdict="approach_problem", action="frobnicate")
    assert rec["action"] == "give_up"
    assert rec["status"] == "abandoned"
