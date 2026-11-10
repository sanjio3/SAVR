"""#D 计划 ③ 事件归属实证：多 task workspace 下，运行期事件（探针只带 workspace，不带 task_id）
正确归属到 task，而不是静默归 NULL。

覆盖 IastService._resolve_event_task_id 的四条路径：
1) canary 身份段命中 trigger_specs → 归属该 spec 的 task_id
2) 单 task 回退：workspace 仅单一 task 登记过 trigger_specs → 无身份段事件也归属该 task
3) ③ 选项A：多 task 共存 + 无 canary 身份段 + 活跃扫描会话 current_task_id 已标记
   → 归属 current_task_id（避免窗口内无身份段事件结构性丢数据），而非 NULL
4) 多 task + 无 current_task_id + 无身份段 → 不臆测，保持 NULL

③ 的设计动机：java-quote 实时会话里普通 SINK_HIT 实时流量常不带 canary 身份段，
若仅依赖 canary 反查，11/12 条事件 task_id 全为 NULL，I1 监听 / I2 裁决永远看不到数据。
选项A 用 verify() 在 run_transaction 窗口起止处标记/清除 iast_sessions.current_task_id 兜底。
"""

import os
import tempfile

from src.iast.canary import CanaryFactory
from src.iast.service import IastService
from src.infrastructure.db import Database


def _seed():
    db_path = os.path.join(tempfile.mkdtemp(), "app.db")
    os.environ["SAST_AI_DB_PATH"] = db_path
    db = Database(db_path)
    db.execute(
        "INSERT INTO workspaces (name, target_path, created_at, updated_at) VALUES (?,?,?,?)",
        ("ws", "/tmp/ws", "2026-01-01", "2026-01-01"),
    )
    workspace_id = int(db.execute("SELECT id FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
        (workspace_id, "t1", "pending", "queued", "/tmp/o1", "2026-01-01"),
    )
    t1 = int(db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
        (workspace_id, "t2", "pending", "queued", "/tmp/o2", "2026-01-01"),
    )
    t2 = int(db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    db.execute(
        "INSERT INTO iast_sessions (workspace_id, app_name, agent_id, target_url, probe_token, status, registered_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (workspace_id, "app", "agent", "http://x", "tok", "ready", "2026-01-01", "2026-01-01"),
    )
    sid = int(db.execute("SELECT id FROM iast_sessions ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    return db, workspace_id, t1, t2, sid


def _insert_spec(db, workspace_id, task_id, vhash, canary):
    db.execute(
        """INSERT INTO trigger_specs
           (workspace_id, task_id, vulnerability_hash_v2, family, target_endpoint, param_name, taint_marker, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (workspace_id, task_id, vhash, "sql", "/api/x", "q", canary, "2026-01-01"),
    )


def test_canary_identity_attribution():
    """路径1：canary（完整 / 仅身份段）命中 trigger_specs → 归属该 spec 的 task_id。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    svc = IastService(db)
    # 完整 canary → 命中 t1 的 spec
    assert svc._resolve_event_task_id(workspace_id, c1, "") == t1
    # 仅身份段（被截断 / 编码后）→ 仍命中 t1
    ident = c1[:22]  # s4st41<16hex> 前缀
    assert svc._resolve_event_task_id(workspace_id, ident, "") == t1


def test_single_task_fallback():
    """路径2：workspace 仅单一 task 登记过 trigger_specs → 无身份段事件也归属该 task。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)  # 仅 t1 登记过 spec
    svc = IastService(db)
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "") == t1


def test_option_a_active_session_attribution():
    """路径3（③ 选项A）：多 task + 无 canary 身份段 + current_task_id 已标记 → 归属该活跃 task。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # ③ 选项A：标记活跃扫描会话 current_task_id = t2
    db.execute("UPDATE iast_sessions SET current_task_id = ? WHERE id = ?", (t2, sid))
    svc = IastService(db)
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "") == t2


def test_multi_task_no_active_no_identity_returns_none():
    """路径4：多 task + 无 current_task_id + 无身份段 + 事件落在任何 task 运行窗之外
    → 不臆测，保持 NULL（避免跨 task 错归 / 时间窗外臆测）。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # 给 t1/t2 各一个运行时间窗（无重叠），互相独立
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:00:00", "2026-01-01 10:30:00", t1))
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 11:00:00", "2026-01-01 11:30:00", t2))
    # current_task_id 未标记；无 canary 身份段；事件落在两窗之外 → 保持 NULL
    svc = IastService(db)
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 10:45:00") is None


def test_multi_task_time_window_fallback():
    """新增时间窗回退：多 task 共存 + 无身份段 + 无 current_task_id 时，
    按事件 ingested_at 落入的 task 运行窗归属（重叠窗取最晚启动的 task）。
    修复 ws 内多 task 并发时 696+ 事件 task_id=NULL 的结构性丢数据问题。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # 重叠运行窗：t1 [10:00,11:00]、t2 [10:30,11:30]；重叠区间 10:30~11:00
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:00:00", "2026-01-01 11:00:00", t1))
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:30:00", "2026-01-01 11:30:00", t2))
    svc = IastService(db)
    # 仅 t1 窗内（10:15）→ 归属 t1
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 10:15:00") == t1
    # 重叠窗内（10:45）→ 取最晚启动的 t2
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 10:45:00") == t2
    # 仅 t2 窗内（11:15）→ 归属 t2
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 11:15:00") == t2


def test_multi_task_window_fallback_excludes_task_without_window():
    """时间窗回退：登记了 spec 但 scan_tasks 无 started_at 的 task 不参与落窗（避免无起始时间臆测）。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # 仅 t1 有运行窗；t2 无 started_at（视为无法定窗，跳过）
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:00:00", "2026-01-01 11:00:00", t1))
    svc = IastService(db)
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 10:30:00") == t1
    # 落在 t1 窗外、且 t2 无窗可落 → 保持 NULL
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 12:00:00") is None


def test_active_task_priority_over_time_window():
    """丙 修复回归：多 task + 重叠窗 + 无身份段事件，若某 task 正处于活跃重放（current_task_id 标记），
    则空 canary 事件优先归活跃 task，而非被时间窗「最晚启动」规则错归到后启动 task。
    这是 r79 实证根因（312 的空 canary collateral 被错归到后启动的 313）的直接反向锁。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # 重叠运行窗：t1 [10:00,11:00]、t2 [10:30,11:30]
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:00:00", "2026-01-01 11:00:00", t1))
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:30:00", "2026-01-01 11:30:00", t2))
    # 标记 t1 为活跃重放 task（按 workspace 兜底，避免隐式 id 歧义）
    db.execute("UPDATE iast_sessions SET current_task_id = ? WHERE workspace_id = ?", (t1, workspace_id))
    active_now = db.execute(
        "SELECT current_task_id FROM iast_sessions WHERE workspace_id = ?", (workspace_id,), fetchone=True)["current_task_id"]
    assert active_now == t1
    svc = IastService(db)
    # 重叠窗内（10:45）原本按时间窗归 t2；因 t1 活跃，应归 t1（active_now）
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 10:45:00") == active_now


def test_finished_task_grace_catches_late_flush():
    """丙 修复回归：task 已结束，但其运行窗（finished_at + _ATTR_GRACE_SECONDS）仍覆盖「结束后探针
    批量 flush 的迟到事件」，避免迟到事件归 NULL 或被后启动 task 抢。无活跃会话、且迟到时刻不落
    下一 task 窗时，归已结束 task。"""
    db, workspace_id, t1, t2, sid = _seed()
    c1 = CanaryFactory.build("sql")
    c2 = CanaryFactory.build("sql")
    _insert_spec(db, workspace_id, t1, "h1", c1)
    _insert_spec(db, workspace_id, t2, "h2", c2)
    # t1 结束于 11:00；t2 窗在 11:30 之后（迟到事件时刻不落 t2 窗）
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 10:00:00", "2026-01-01 11:00:00", t1))
    db.execute("UPDATE scan_tasks SET started_at=?, finished_at=? WHERE id=?", ("2026-01-01 11:30:00", "2026-01-01 11:45:00", t2))
    svc = IastService(db)
    # 11:01（t1 结束后 60s，仍在 GRACE 内，且不在 t2 窗）→ 归 t1（无 GRACE 则归 NULL）
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 11:01:00") == t1
    # 落在 t1 延长窗之外、也不落 t2 窗 → 保持 NULL（不臆测）
    assert svc._resolve_event_task_id(workspace_id, "random-no-identity", "", event_time="2026-01-01 12:00:00") is None
