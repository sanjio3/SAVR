"""F4 回归：sync_blackboard 的 confirm_state 必须基于真实确认判据，而非「有 spec 即 confirmed」。

旧实现：confirm_state = "confirmed" if spec else "unconfirmed"
  → 任何存在 trigger_spec（A2 待重放假说）的行都计为 confirmed，导致 detected==confirmed 无区分力。

新实现（src/core/blackboard._is_confirmed）：
  confirmed 当且仅当
    - verification_status ∈ {confirmed_exploitable, exploitable}
    - 或 iast_state 含 sink-reached（IAST canary 运行时真到达 sink）
"""
from datetime import datetime

from src.core.blackboard import sync_blackboard, derive_counts
from src.infrastructure.db import Database


def _now():
    return datetime.utcnow().isoformat()


def _make_db(tmp_path):
    db = Database(str(tmp_path / "app.db"))
    ws, task, run = 3, 901, 901
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, created_at, updated_at) VALUES (?, 'ws', '/p', ?, ?)",
        (ws, _now(), _now()),
    )
    db.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, created_at) "
        "VALUES (?, ?, 't', 'completed', 'done', '/o', ?)",
        (task, ws, _now()),
    )
    db.execute(
        "INSERT INTO scan_runs (id, workspace_id, task_id, round_no, code_fingerprint, git_revision, "
        "key_files_json, options_json, metrics_json, status, started_at, finished_at, created_at) "
        "VALUES (?, ?, ?, 1, 'fp', '', '[]', '{}', '{}', 'completed', ?, ?, ?)",
        (run, ws, task, _now(), _now(), _now()),
    )
    db.execute("UPDATE scan_tasks SET run_id=? WHERE id=?", (run, task))
    return db, ws, task, run


def _add_finding(db, task, ws, vh):
    db.execute(
        "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, title, raw_json, created_at, vulnerability_hash_v2) "
        "VALUES (?, ?, 'sast', 'high', '/x', 'f', '{}', ?, ?)",
        (task, ws, _now(), vh),
    )


def _add_spec(db, task, ws, vh, verif="", iast_state="", taint=""):
    db.execute(
        "INSERT INTO trigger_specs (task_id, workspace_id, vulnerability_hash_v2, family, target_endpoint, "
        "http_method, verification_status, iast_state, taint_marker, created_at) "
        "VALUES (?, ?, ?, 'sqli', '/e', 'GET', ?, ?, ?, ?)",
        (task, ws, vh, verif, iast_state, taint, _now()),
    )


def test_confirm_state_requires_real_verification_not_spec_existence(tmp_path):
    db, ws, task, run = _make_db(tmp_path)
    # 三个仅 findings 的 vhash（无 spec）：应 detected 但 unconfirmed
    for v in ("F1", "F2", "F3"):
        _add_finding(db, task, ws, v)
    # 四个 spec：
    _add_spec(db, task, ws, "V1", verif="confirmed_exploitable")   # 真确认 → confirmed
    _add_spec(db, task, ws, "V2", verif="no_evidence")             # 仅 spec、未验证 → 旧 bug 会判 confirmed，修复后 unconfirmed
    _add_spec(db, task, ws, "V3", verif="", iast_state="sink-reached-probe")  # 运行时到达 sink → confirmed
    _add_spec(db, task, ws, "V4", verif="", iast_state="no-arrival")           # 未到达 → unconfirmed

    n = sync_blackboard(db, task, run)
    assert n == 7, f"应写入 7 行（3 finding + 4 spec），实际 {n}"

    derived = derive_counts(db, task, run)
    # F4 核心不变量：confirmed 必须 < detected，且有真实区分力
    assert derived["detected"] == 7, derived
    assert derived["confirmed"] == 2, f"确认态应仅 V1/V3 共 2 个，实际 {derived['confirmed']}（旧 bug 会是 4）"
    assert derived["confirmed"] < derived["detected"], "confirm_state 不得等于 detect_state（F4 老毛病）"

    # 关键：V2「有 spec 但未验证」必须是 unconfirmed
    row_v2 = db.execute(
        "SELECT confirm_state FROM vuln_blackboard WHERE task_id=? AND run_id=? AND vulnerability_hash_v2=?",
        (task, run, "V2"), fetchone=True,
    )
    assert row_v2["confirm_state"] == "unconfirmed", "F4：仅存在 spec 不该计为 confirmed"
    # V1 / V3 必须 confirmed
    for v in ("V1", "V3"):
        r = db.execute(
            "SELECT confirm_state FROM vuln_blackboard WHERE task_id=? AND run_id=? AND vulnerability_hash_v2=?",
            (task, run, v), fetchone=True,
        )
        assert r["confirm_state"] == "confirmed", f"{v} 应 confirmed"
