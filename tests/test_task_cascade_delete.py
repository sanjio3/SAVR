"""发难清单 Q5 落地单测：删任务必须级联删全部子表，且能清孤儿残留。

背景：旧 TaskRepository.delete 只删 scan_tasks 一行，子表（trigger_specs /
model_runs / hypotheses / vuln_blackboard / scan_runs / scan_task_events /
findings / reports）全部残留（实测 vuln_blackboard 残留 2 万+ 行）。
"""
import pytest

from src.infrastructure.db import Database
from src.infrastructure.repositories import TaskRepository


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    # scan_tasks.workspace_id 有 FK 到 workspaces，先建工作区
    database.execute(
        "INSERT INTO workspaces (name, target_path, created_at, updated_at) "
        "VALUES ('ws-test', '', '2026-01-01', '2026-01-01')"
    )
    return database


def _mk_task(db, name="t"):
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) "
        "VALUES (1, ?, 'completed', 'completed', '', '2026-01-01')",
        (name,),
    )
    # 必须取「刚插入的那一行」：原来用 `SELECT id FROM scan_tasks`（无 ORDER BY）在多任务场景下
    # 恒返回第一行 ⇒ 第二个任务拿到 task_id=1，与第一个任务的 trigger_specs 撞
    # UNIQUE(task_id, vulnerability_hash_v2) 唯一索引（2026-10-24 加索引后暴露）。
    return int(db.execute("SELECT last_insert_rowid() i", fetchone=True)["i"])


def _mk_children(db, task_id, tag="h1"):
    db.execute(
        "INSERT INTO scan_runs (workspace_id, task_id, started_at, created_at) "
        "VALUES (1, ?, '2026-01-01', '2026-01-01')", (task_id,)
    )
    run_id = int(db.execute("SELECT last_insert_rowid() i", fetchone=True)["i"])
    db.execute(
        "INSERT INTO vuln_blackboard (workspace_id, vulnerability_hash_v2, run_id, task_id, "
        "created_at, updated_at) VALUES (1, ?, ?, ?, '2026-01-01', '2026-01-01')",
        (tag, run_id, task_id),
    )
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, family, target_endpoint, created_at) "
        "VALUES (1, ?, 'sqli', '/a', '2026-01-01')",
        (task_id,),
    )
    db.execute(
        "INSERT INTO model_runs (purpose, task_id, created_at) VALUES ('a2-semantic', ?, '2026-01-01')",
        (task_id,),
    )
    db.execute(
        "INSERT INTO hypotheses (workspace_id, task_id, vulnerability_hash_v2, created_at, updated_at) "
        "VALUES (1, ?, ?, '2026-01-01', '2026-01-01')",
        (task_id, tag),
    )
    db.execute(
        "INSERT INTO scan_task_events (task_id, event_type, payload_json, created_at) "
        "VALUES (?, 'task_progress', '{}', '2026-01-01')",
        (task_id,),
    )


def test_delete_task_cascades_children(db):
    repo = TaskRepository(db)
    tid = _mk_task(db)
    _mk_children(db, tid)
    repo.delete(tid)
    assert db.execute("SELECT COUNT(*) c FROM scan_tasks", fetchone=True)["c"] == 0
    for table in ("trigger_specs", "model_runs", "hypotheses", "vuln_blackboard", "scan_runs", "scan_task_events"):
        assert db.execute(f"SELECT COUNT(*) c FROM {table}", fetchone=True)["c"] == 0, table


def test_purge_orphans_removes_rows_without_task(db):
    repo = TaskRepository(db)
    tid = _mk_task(db)
    _mk_children(db, tid)
    # 模拟历史残留：直接删掉 scan_tasks 行（旧实现无级联的行为），留下孤儿子表行
    db.execute("DELETE FROM scan_tasks WHERE id = ?", (tid,))
    removed = repo.purge_orphans()
    # scan_task_events 对 scan_tasks 有 ON DELETE CASCADE，会随任务行删除自动清掉，
    # 因此 purge 计数是 5（其余子表）而不是 6；最终口径看「子表全空」。
    assert removed >= 5
    for table in ("trigger_specs", "model_runs", "hypotheses", "vuln_blackboard", "scan_runs", "scan_task_events"):
        assert db.execute(f"SELECT COUNT(*) c FROM {table}", fetchone=True)["c"] == 0, table


def test_delete_all_purges_everything(db):
    repo = TaskRepository(db)
    for i, name in enumerate(("t1", "t2")):
        tid = _mk_task(db, name=name)
        _mk_children(db, tid, tag=f"h{i}")
    n = repo.delete_all()
    assert n == 2
    assert db.execute("SELECT COUNT(*) c FROM scan_tasks", fetchone=True)["c"] == 0
    for table in ("trigger_specs", "model_runs", "hypotheses", "vuln_blackboard", "scan_runs", "scan_task_events"):
        assert db.execute(f"SELECT COUNT(*) c FROM {table}", fetchone=True)["c"] == 0, table
