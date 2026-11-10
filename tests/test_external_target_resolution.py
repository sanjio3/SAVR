"""live 路径 external_target 解析回归：D1 重放投递根因修复。

实证：task_service → scan_task_runner → run_benchmark 在 live 路径默认不传 external_target，
导致 D1 重放打到空 service_url、0 DAST impact、全部 no-arrival（判定方法本身正确，是投递地址缺失）。
修复后，run_benchmark 应按 task_id → workspace_id → iast_sessions 解析出就绪探针目标并回填。
"""

import os
import tempfile

from src.cli.benchmark_cli import _resolve_external_target_from_session
from src.infrastructure.db import Database


def _seed(tmp_path):
    db_path = os.path.join(str(tmp_path), "app.db")
    os.environ["SAST_AI_DB_PATH"] = db_path
    db = Database(db_path)
    db.execute(
        "INSERT INTO workspaces (name, target_path, created_at, updated_at) VALUES (?,?,?,?)",
        ("ws", str(tmp_path), "2026-01-01", "2026-01-01"),
    )
    workspace_id = db.execute("SELECT id FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
        (workspace_id, "task", "pending", "queued", "/tmp/out", "2026-01-01"),
    )
    task_id = db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    return db, workspace_id, task_id


def test_resolves_ready_session_target():
    """就绪探针会话应被解析为 D1 重放目标（service_url/app_name/agent_id）。"""
    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp)
    db.execute(
        "INSERT INTO iast_sessions "
        "(workspace_id, app_name, agent_id, target_url, code_path, probe_mode, status, registered_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (workspace_id, "java-quote", "java-quote-01", "http://127.0.0.1:8899/", "", "monitor", "ready", "2026-01-01", "2026-01-01"),
    )
    tgt = _resolve_external_target_from_session(task_id)
    assert tgt is not None, "就绪会话应解析出 external_target"
    assert tgt["service_url"] == "http://127.0.0.1:8899/"
    assert tgt["app_name"] == "java-quote"
    assert tgt["agent_id"] == "java-quote-01"
    assert tgt["probe_mode"] == "monitor"


def test_no_session_returns_none():
    """无 IAST 会话时返回 None（A0 门禁据此放行纯 SAST/SCA）。"""
    tmp = tempfile.mkdtemp()
    _seed(tmp)  # 无 iast_sessions
    assert _resolve_external_target_from_session(_last_task_id(tmp)) is None


def test_task_id_none_returns_none():
    """未提供 task_id（离线/无归属）时返回 None，不臆造目标。"""
    tmp = tempfile.mkdtemp()
    _seed(tmp)
    assert _resolve_external_target_from_session(None) is None


def _last_task_id(tmp_path):
    os.environ["SAST_AI_DB_PATH"] = os.path.join(str(tmp_path), "app.db")
    db = Database(os.environ["SAST_AI_DB_PATH"])
    return db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
