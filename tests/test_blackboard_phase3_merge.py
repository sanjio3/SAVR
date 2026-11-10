"""黑板阶段三：并发读改写合并 + audit 表回归测试。

验收口径（round-10-blackboard-plan.md 阶段三）：
- 3 个并发写入打同一 (workspace, vhash, run)，最终条目状态必须等于三者最强者；
- blackboard_entries_audit 对该 vhash 须见 ≥3 次写入、且 ≥2 次合并（version 冲突重试）。

合并语义：
- detect_state / confirm_state 单调升级，永不降级；
- sink_reached 取 OR；
- verification_status 强者胜；
- 其余列取非空（desired 优先）。
"""
import threading
from datetime import datetime

from src.core.blackboard import write_blackboard_row, _merge_blackboard_state
from src.infrastructure.db import Database


def _now():
    return datetime.utcnow().isoformat()


def _make_db(tmp_path):
    db = Database(str(tmp_path / "app.db"))
    workspace_id = 3
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, created_at, updated_at) VALUES (?, 'ws', '/p', ?, ?)",
        (workspace_id, _now(), _now()),
    )
    return db, workspace_id


def _row(db, workspace_id, vhash, run_id):
    return db.execute(
        "SELECT * FROM vuln_blackboard WHERE workspace_id=? AND vulnerability_hash_v2=? AND run_id=?",
        (workspace_id, vhash, run_id), fetchone=True,
    )


def _audit(db, workspace_id, vhash):
    return db.execute(
        "SELECT op, version_before, version_after, writer FROM blackboard_entries_audit "
        "WHERE workspace_id=? AND vulnerability_hash_v2=? ORDER BY id",
        (workspace_id, vhash), fetchall=True,
    ) or []


# ---------------------------------------------------------------------------
# 确定性合并语义（无并发）
# ---------------------------------------------------------------------------
def test_merge_detect_monotonic_no_downgrade():
    cur = {"detect_state": "detected", "confirm_state": "confirmed", "sink_reached": 1,
           "verification_status": "confirmed_exploitable", "family": "sqli"}
    merged, changed = _merge_blackboard_state(cur, {"detect_state": "undetected", "confirm_state": "unconfirmed"})
    # 永不降级
    assert merged["detect_state"] == "detected", merged
    assert merged["confirm_state"] == "confirmed", merged
    assert changed is False, "降级合并不应产生变化"


def test_merge_sink_or_and_verif_stronger():
    cur = {"detect_state": "undetected", "confirm_state": "unconfirmed", "sink_reached": 0,
           "verification_status": "no_evidence", "family": ""}
    merged, changed = _merge_blackboard_state(
        cur, {"detect_state": "detected", "sink_reached": 1, "verification_status": "provisional", "family": "xss"})
    assert merged["detect_state"] == "detected"
    assert merged["sink_reached"] == 1
    assert merged["verification_status"] == "provisional"
    assert merged["family"] == "xss"
    assert changed is True


def test_merge_noop_when_identical():
    cur = {"detect_state": "detected", "confirm_state": "confirmed", "sink_reached": 1,
           "verification_status": "confirmed_exploitable", "family": "sqli"}
    merged, changed = _merge_blackboard_state(cur, {"detect_state": "detected", "family": "sqli"})
    assert changed is False


def test_write_blackboard_row_insert_then_merge(tmp_path):
    db, workspace_id = _make_db(tmp_path)
    vh, run_id, task_id = "VH-1", 11, 101
    writer_a = "task:101/run:11/pid:1"
    op1 = write_blackboard_row(db, workspace_id, vh, run_id, task_id, {"detect_state": "detected"}, writer_a)
    assert op1 == "insert"
    op2 = write_blackboard_row(db, workspace_id, vh, run_id, task_id, {"confirm_state": "confirmed"}, writer_a)
    assert op2 == "merge"
    row = _row(db, workspace_id, vh, run_id)
    assert row["detect_state"] == "detected"
    assert row["confirm_state"] == "confirmed"
    assert row["version"] == 1
    assert row["last_writer"] == writer_a


# ---------------------------------------------------------------------------
# 并发验收：3 线程同 (ws, vhash, run)，末态==最强者 + audit 见 3 写 ≥2 合并
# ---------------------------------------------------------------------------
def test_concurrent_merge_three_writers_same_vhash(tmp_path):
    db, workspace_id = _make_db(tmp_path)
    vh, run_id, task_id = "VH-CONC", 22, 202
    barrier = threading.Barrier(3)
    results = {}

    def writer(partial, wid):
        try:
            barrier.wait()
            op = write_blackboard_row(db, workspace_id, vh, run_id, task_id, partial, f"task:{task_id}/run:{run_id}/pid:{wid}")
            results[wid] = op
        except Exception as e:  # pragma: no cover
            results[wid] = f"ERR:{e}"

    threads = [
        threading.Thread(target=writer, args=({"detect_state": "detected"}, 1)),
        threading.Thread(target=writer, args=({"confirm_state": "confirmed"}, 2)),
        threading.Thread(target=writer, args=({"sink_reached": 1, "verification_status": "confirmed_exploitable"}, 3)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # 末态 == 三者最强者
    row = _row(db, workspace_id, vh, run_id)
    assert row is not None, "并发后应有黑板行"
    assert row["detect_state"] == "detected", row
    assert row["confirm_state"] == "confirmed", row
    assert row["sink_reached"] == 1, row
    assert row["verification_status"] == "confirmed_exploitable", row

    # audit：3 次写入 + 至少 2 次合并
    audit = _audit(db, workspace_id, vh)
    assert len(audit) >= 3, f"audit 写入应≥3，实际 {len(audit)}: {audit}"
    merges = [a for a in audit if a["op"] == "merge"]
    assert len(merges) >= 2, f"合并次数应≥2，实际 {len(merges)}: {audit}"
    inserts = [a for a in audit if a["op"] == "insert"]
    assert len(inserts) == 1, f"插入应恰好 1 次，实际 {len(inserts)}"
    # version_after 单调推进到 2
    assert row["version"] == 2, f"最终 version 应=2（1 插入+2 合并），实际 {row['version']}"


def test_concurrent_merge_no_lost_update_stress(tmp_path):
    """压力：20 轮 × 3 线程对同一 vhash 各自贡献不同字段，末态必须收敛到最强者，且无丢失更新。"""
    db, workspace_id = _make_db(tmp_path)
    vh, run_id, task_id = "VH-STRESS", 33, 303
    contributions = [
        {"detect_state": "detected"},
        {"confirm_state": "confirmed"},
        {"sink_reached": 1, "verification_status": "confirmed_exploitable", "family": "sqli"},
    ]

    def worker(idx):
        for _ in range(20):
            write_blackboard_row(db, workspace_id, vh, run_id, task_id, contributions[idx],
                                 f"task:{task_id}/run:{run_id}/pid:{idx}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    row = _row(db, workspace_id, vh, run_id)
    assert row["detect_state"] == "detected", row
    assert row["confirm_state"] == "confirmed", row
    assert row["sink_reached"] == 1, row
    assert row["verification_status"] == "confirmed_exploitable", row
    assert row["family"] == "sqli", row
    # 在 60 次写入中只有 1 次 insert + 2 次真正 merge（其余均为 noop），故 version=2
    assert row["version"] == 2, f"无丢失更新时应 version=2，实际 {row['version']}"
