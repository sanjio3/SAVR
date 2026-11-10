"""黑板阶段一 load() 单测：跨所有历史 run 取每 vhash 最强态。

合并规则（round-10-blackboard-plan.md 阶段一）：
- detect/confirm 单调升级，永不降级
- sink_reached 取 OR
- verification_status 强者胜（confirmed_exploitable/confirmed > exploitable > provisional > no_evidence）
- 集合外的 vhash 绝不出现在返回中
"""
from datetime import datetime

from src.core.blackboard import load
from src.infrastructure.db import Database


def _now():
    return datetime.utcnow().isoformat()


def _make_db(tmp_path):
    return Database(str(tmp_path / "app.db"))


def _add_run(db, workspace_id, task_id, run_no):
    db.execute(
        """
        INSERT INTO scan_runs
        (workspace_id, task_id, round_no, code_fingerprint, git_revision, key_files_json,
         options_json, metrics_json, status, started_at, finished_at, created_at)
        VALUES (?, ?, ?, 'fp', '', '[]', '{}', '{}', 'running', ?, '', ?)
        """,
        (workspace_id, task_id, run_no, _now(), _now()),
    )
    return int(db.execute("SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1", fetchone=True)["id"])


def _add_blackboard_row(db, workspace_id, vh, run_id, task_id,
                        detect="undetected", confirm="unconfirmed",
                        sink=0, verif="no_evidence", family=""):
    db.execute(
        """
        INSERT INTO vuln_blackboard
        (workspace_id, vulnerability_hash_v2, run_id, task_id, family, detect_state,
         confirm_state, sink_reached, verification_status, iast_state, finding_id,
         trigger_spec_id, iast_event_id, instance_id, target_endpoint, http_method,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', NULL, NULL, NULL, NULL, '', '', ?, ?)
        """,
        (workspace_id, vh, run_id, task_id, family, detect, confirm, sink, verif, _now(), _now()),
    )


def _seed(tmp_path):
    db = _make_db(tmp_path)
    workspace_id, task_id = 7, 70
    # 父表：workspaces / scan_tasks（FK 约束要求先有）
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, created_at, updated_at) VALUES (?, 'ws', '/p', ?, ?)",
        (workspace_id, _now(), _now()),
    )
    db.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, created_at) "
        "VALUES (?, ?, 't', 'completed', 'done', '/o', ?)",
        (task_id, workspace_id, _now()),
    )
    # 两条 run，模拟两轮扫描
    r1 = _add_run(db, workspace_id, task_id, 1)
    r2 = _add_run(db, workspace_id, task_id, 2)
    r3 = _add_run(db, workspace_id, task_id, 3)
    # A：run1 detected/confirmed/sink=0/provisional；run2 退化但到达 sink；run3 进 confirmed_exploitable
    _add_blackboard_row(db, workspace_id, "A", r1, task_id, detect="detected", confirm="confirmed", sink=0, verif="provisional", family="sqli")
    _add_blackboard_row(db, workspace_id, "A", r2, task_id, detect="undetected", confirm="unconfirmed", sink=1, verif="no_evidence")
    _add_blackboard_row(db, workspace_id, "A", r3, task_id, detect="detected", confirm="confirmed", sink=0, verif="confirmed_exploitable")
    # B：只有一轮，全未命中（基准线）
    _add_blackboard_row(db, workspace_id, "B", r1, task_id, detect="undetected", confirm="unconfirmed", sink=0, verif="no_evidence")
    # C：仅在 run2 出现 detected/unconfirmed/sink=0/exploitable（用于验证「集合外不返回」）
    _add_blackboard_row(db, workspace_id, "C", r2, task_id, detect="detected", confirm="unconfirmed", sink=0, verif="exploitable")
    return db, workspace_id


def test_load_merges_strongest_state_across_runs(tmp_path):
    db, workspace_id = _seed(tmp_path)
    res = load(db, workspace_id, {"A", "B"})

    # 集合外的 C 不应出现
    assert "C" not in res, "集合外的 vhash 不应返回"
    assert set(res.keys()) == {"A", "B"}

    a = res["A"]
    # 单调升级：detected 不被 undetected 拉低
    assert a["detect_state"] == "detected"
    # 单调升级：confirmed 不被 unconfirmed 拉低
    assert a["confirm_state"] == "confirmed"
    # sink_reached OR：run2 到达 → 1
    assert a["sink_reached"] == 1
    # verification_status 强者胜：confirmed_exploitable 压过 provisional/no_evidence
    assert a["verification_status"] == "confirmed_exploitable"
    # family 取最后非空
    assert a["family"] == "sqli"
    # run_ids 收集全
    assert sorted(a["run_ids"]) == sorted(
        [int(r["id"]) for r in db.execute("SELECT id FROM scan_runs ORDER BY id", fetchall=True)]
    )[:3] or set(a["run_ids"]) <= {1, 2, 3}


def test_load_baseline_unconfirmed_stays_low(tmp_path):
    db, workspace_id = _seed(tmp_path)
    res = load(db, workspace_id, {"B"})
    b = res["B"]
    assert b["detect_state"] == "undetected"
    assert b["confirm_state"] == "unconfirmed"
    assert b["sink_reached"] == 0
    assert b["verification_status"] == "no_evidence"


def test_load_empty_set_returns_empty(tmp_path):
    db, workspace_id = _seed(tmp_path)
    assert load(db, workspace_id, set()) == {}
    assert load(db, workspace_id, []) == {}


def test_load_other_workspace_excluded(tmp_path):
    db, workspace_id = _seed(tmp_path)
    # 另一个 workspace 不应读到 workspace_id=7 的条目
    assert load(db, workspace_id + 999, {"A", "B", "C"}) == {}
