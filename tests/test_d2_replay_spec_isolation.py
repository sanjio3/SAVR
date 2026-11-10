"""D2 重放 TriggerSpec 按 task_id 隔离（待请示 6 项 #3，2026-09-16）。

回归背景：R28 run 10 全量时，_run_iast_auto_replay 按 workspace 取全部 trigger_specs，
workspace 3 共 195 条（task-6 62 / task-9 70 / run 663），实际重放 206 条——
历史任务的假说被反复重放，重放量随历史累积只增不减，且旧假说对应代码改动后与本轮 findings 对不上。

本测试把「按 task_id 隔离」钉死：
1. task_id 给定时只返回本 task 登记的 spec，历史任务 spec 不混入；
2. task_id=None（离线 CLI 入口）退回 workspace 全量，保持旧语义；
3. 其他 workspace 的同 task_id spec 不得泄漏。
"""

import tempfile
from pathlib import Path

from src.infrastructure.db import Database
from src.cli.benchmark_cli import _select_replay_specs


def _make_db():
    path = Path(tempfile.mkdtemp()) / "t.db"
    db = Database(str(path))
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, description, created_at, updated_at) "
        "VALUES (3, 'ws3', '/p3', '', '2026', '2026')"
    )
    return db


def _insert_spec(db, ws, task, vhash):
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, created_at) "
        "VALUES (?, ?, ?, '2026')",
        (ws, task, vhash),
    )


def test_task_id_isolation_filters_history():
    db = _make_db()
    for i in range(70):
        _insert_spec(db, 3, 9, f"h9-{i}")   # 历史 task-9
    for i in range(62):
        _insert_spec(db, 3, 6, f"h6-{i}")   # 历史 task-6
    for i in range(63):
        _insert_spec(db, 3, 10, f"h10-{i}")  # 本轮 run 10

    rows = _select_replay_specs(db, 3, 10)
    assert len(rows) == 63, f"应只重放本轮 63 条，实际 {len(rows)}"
    assert all(dict(r).get("task_id") == 10 for r in rows)


def test_task_id_none_returns_workspace_all():
    db = _make_db()
    _insert_spec(db, 3, 9, "a")
    _insert_spec(db, 3, 10, "b")

    rows = _select_replay_specs(db, 3, None)
    assert len(rows) == 2, f"离线入口应返回 workspace 全量 2 条，实际 {len(rows)}"


def test_other_workspace_not_leaked():
    db = _make_db()
    _insert_spec(db, 3, 10, "x")  # 本轮 workspace 3
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, description, created_at, updated_at) "
        "VALUES (4, 'ws4', '/p4', '', '2026', '2026')"
    )
    _insert_spec(db, 4, 10, "y")  # 另一个 workspace 的同 task_id

    rows = _select_replay_specs(db, 3, 10)
    assert len(rows) == 1
    assert dict(rows[0]).get("vulnerability_hash_v2") == "x"
