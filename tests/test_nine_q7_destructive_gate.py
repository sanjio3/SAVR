"""净化器判定九问（Q7）：解耦「破坏性闸门降级」与「无害探针发送」。

死局（分析-本轮.md §Q7）：破坏性闸门降级（出于安全不 fire 破坏性弹、只发无害探针 `'`）后，
该无害探针恰好被运行时净化器拦成 arrival-sanitized → 无 sink-reached → 确认闸门拿不到正向证据
→ 降级 unconfirmed。表现「既不能真打又打不出去」，闭环在 unconfirmed 空转。

本质修复：arrival-sanitized（探针证明污点抵达 sink 但被净化）本身就是「过滤器有效」的**正向**
证据，与静态 non_bypassable 等价，直接落 filtered_not_exploitable（真阴性进对账），不再降级
unconfirmed 空转。只有在**无 canary 到达信号**（no-arrival）时才降级 no_evidence（交靶场可达性排查）。
"""
import json
import tempfile

from src.infrastructure.db import Database
from src.agents.i2_feedback import mark_filtered_not_exploitable, FILTERED_NOT_EXPLOITABLE


def _make_db():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    db.execute("INSERT INTO workspaces (name, target_path, created_at, updated_at) "
               "VALUES (?,?,?,?)", ("ws", ".", "now", "now"))
    return db, path


def _insert_spec(db, task_id, raw_json, iast_state="", vstatus=""):
    # vhash 必须逐条唯一：trigger_specs 有 UNIQUE(task_id, vulnerability_hash_v2)（upsert 用），
    # 同一用例插两条 spec 时写死 "h1" 会撞索引。
    _insert_spec.seq = getattr(_insert_spec, "seq", 0) + 1
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, family, "
        "target_endpoint, http_method, taint_marker, expected_sink_file, raw_json, "
        "verification_status, iast_state, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, task_id, "h%d" % _insert_spec.seq, "sqli", "/x", "GET", "mk", "sink.java",
         raw_json, vstatus, iast_state, "now"),
    )
    return db.execute("SELECT last_insert_rowid() i", fetchone=True)["i"]


def _non_terminal_raw():
    # 静态 verdict 未判终态（equiv. 破坏性闸门降级、没静态判死），仅带原始 spec
    return json.dumps({
        "filter_verdict": {"verdict": "undetermined", "confidence": "low",
                           "reason": "候选不足，未判终态"},
        "filter_spec": {"kind": "allow", "patterns": ["^[a-z]+$"]},
    })


def test_q7_arrival_sanitized_marks_filtered_not_exploitable():
    # 核心：运行时 arrival-sanitized（即便静态未判终态）即「过滤器有效」→ filtered_not_exploitable。
    db, _ = _make_db()
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="arrival-sanitized", vstatus="unconfirmed")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 1
    row = db.execute("SELECT verification_status, bypass_reason FROM trigger_specs WHERE task_id=1",
                     (), fetchone=True)
    assert row["verification_status"] == FILTERED_NOT_EXPLOITABLE
    assert "arrival-sanitized" in (row["bypass_reason"] or "")


def test_q7_no_arrival_stays_unmarked():
    # 无 canary 到达信号（no-arrival）→ 不当 filtered_not_exploitable，交靶场可达性排查。
    db, _ = _make_db()
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="no-arrival", vstatus="unconfirmed")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 0


def test_q7_sink_reached_not_misclassified_as_filtered():
    # 真到达 sink（sink-reached）不该被当成过滤器有效；由别的通路判 confirmed，此处不标记。
    db, _ = _make_db()
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="sink-reached", vstatus="unconfirmed")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 0


def test_q7_confirmed_exploitable_untouched():
    # 已真确认优先于过滤器判定，不被改判。
    db, _ = _make_db()
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="arrival-sanitized",
                 vstatus="confirmed_exploitable")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 0


def test_q7_decouples_destructive_gate_from_observability():
    # 两条 spec 都因破坏性闸门降级只发无害探针：一个被净化（arrival-sanitized），一个没到（no-arrival）。
    # 两者都应「发了探针、收了证据」——前者得真阴性结论，后者交可达性，都不是 unconfirmed 空转。
    db, _ = _make_db()
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="arrival-sanitized", vstatus="unconfirmed")
    _insert_spec(db, 1, _non_terminal_raw(), iast_state="no-arrival", vstatus="unconfirmed")
    n = mark_filtered_not_exploitable(db, 1)
    assert n == 1  # 仅 arrival-sanitized 那条被收口为 filtered_not_exploitable
    rows = db.execute("SELECT iast_state, verification_status FROM trigger_specs WHERE task_id=1 "
                      "ORDER BY iast_state", (), fetchall=True)
    by_state = {r["iast_state"]: r["verification_status"] for r in rows}
    assert by_state["arrival-sanitized"] == FILTERED_NOT_EXPLOITABLE
    # no-arrival 那条不被当作 unconfirmed 之外的死局：保留原状态交可达性（此处即未标记）
    assert by_state["no-arrival"] == "unconfirmed"
