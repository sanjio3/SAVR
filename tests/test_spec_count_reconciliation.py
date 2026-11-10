"""快照计数统一真相源回归。

孤儿 spec 清理（reconcile_orphan_specs）会裁剪 trigger_specs 行数，但 scan_tasks.summary_json
里的 attack_plan.plan_count / a2_poc.registered_trigger_specs / d1.candidate_count 是清理前的
快照，长期与 DB 实表不一致（如 task-9：70/55/38 vs 21）。本测试锁定
FindingRepository._reconcile_spec_count_snapshots 以 trigger_specs 实表行数为唯一真相，把三处
展示计数收敛一致，并修正 stale message、截断 entries、过滤 replayed_specs_detail。
"""
from pathlib import Path

import pytest

from src.infrastructure.db import Database
from src.infrastructure.repositories import FindingRepository

WORKSPACE_ID = 1


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-09-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    database.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, "
        "summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (WORKSPACE_ID, "task1", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    return database


def _seed_stale_summary(db: Database) -> None:
    stale = {
        "results": {
            "attack_plan": {
                "status": "completed",
                "message": "攻击计划已生成 70 条",
                "plan_count": 70,
                "by_family": {},
                "entries": [{"order": i} for i in range(70)],
                "runtime_enriched": True,
            },
            "a2_poc": {"registered_trigger_specs": 55, "selected_count": 49},
            "d1": {
                "candidate_count": 38,
                "finding_count": 12,
                # 38 条重放明细，其中前 21 条 hash 与真实 spec 对应，后 17 条为孤儿（应被过滤）
                "replayed_specs_detail": [
                    {"vulnerability_hash_v2": "hash-{}".format(i)} for i in range(38)
                ],
            },
        },
        "stage_results": {},
        "pipeline": {
            "attack_plan": {"metrics": {"plan_count": 70, "entries": [], "by_family": {}}},
        },
    }
    db.execute(
        "UPDATE scan_tasks SET summary_json=? WHERE id=1",
        (Database.dumps(stale),),
    )


def _seed_specs(db: Database, n: int) -> None:
    now = "2026-09-01T00:00:00"
    for i in range(n):
        # 2026-09-28（测试桩对齐）：attack_plan 的过滤闸门 b 要求 vhash 在本 task 的 findings
        # 里有来源；旧种子只插 spec 不插 findings，21 条被闸门全滤掉 → plan_count=0。
        # 补 findings 使种子还原「spec 由 finding 派生」的真实形态（不是放宽闸门）。
        db.execute(
            "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, line, "
            "title, raw_json, vulnerability_hash_v2, hash_components_json, source, created_at) "
            "VALUES (?, ?, 'IDOR', 'HIGH', 'A.java', ?, 't', '{}', ?, '{}', 'sast', ?)",
            (1, WORKSPACE_ID, i + 1, "hash-{}".format(i), now),
        )
        db.execute(
            "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, family, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (WORKSPACE_ID, 1, "hash-{}".format(i), "idor", now),
        )


def test_reconcile_unifies_counts_to_spec_truth(db: Database) -> None:
    _seed_stale_summary(db)
    _seed_specs(db, 21)

    FindingRepository(db)._reconcile_spec_count_snapshots(1)

    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    s = Database.loads(row["summary_json"])
    r = s["results"]

    # 三处展示计数全部收敛到 trigger_specs 实表行数（21）
    assert r["attack_plan"]["plan_count"] == 21
    assert r["a2_poc"]["registered_trigger_specs"] == 21
    assert r["d1"]["candidate_count"] == 21

    # stale message 修正为真相数量
    assert "21 条" in r["attack_plan"]["message"]

    # entries 由 attack_plan.build 实时重投影，长度与 plan_count 一致
    assert len(r["attack_plan"]["entries"]) == 21

    # replayed_specs_detail 过滤到当前仍存在的 spec（保留 21 条）
    assert len(r["d1"]["replayed_specs_detail"]) == 21

    # pipeline.attack_plan.metrics 子键同步（前端两种读取路径都正确）
    assert s["pipeline"]["attack_plan"]["metrics"]["plan_count"] == 21


def test_reconcile_is_idempotent(db: Database) -> None:
    _seed_stale_summary(db)
    _seed_specs(db, 21)
    repo = FindingRepository(db)
    repo._reconcile_spec_count_snapshots(1)
    # 第二次调用不应改变结果（幂等）
    repo._reconcile_spec_count_snapshots(1)
    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    s = Database.loads(row["summary_json"])
    assert s["results"]["attack_plan"]["plan_count"] == 21
    assert s["results"]["a2_poc"]["registered_trigger_specs"] == 21
    assert s["results"]["d1"]["candidate_count"] == 21


def test_reconcile_keeps_pipeline_d1_top_level_clean(db: Database) -> None:
    """E1（2026-09-18 评审「删顶层冗余键」）。

    pipeline.d1 顶层的 candidate_count / replayed_count 没有任何消费方
    （前端 stageMetric 读 summary.results、运行监控读 pipeline.d1.metrics），
    保留只会与 metrics 口径分裂（实测 run 18 顶层 80/60 vs metrics 71/71、
    run 17 顶层 64/52 vs metrics 44/44）。此处确认历史脏值会被清掉，
    且 results 侧的真相写入不受影响。
    """
    _seed_stale_summary(db)
    _seed_specs(db, 21)
    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    s = Database.loads(row["summary_json"])
    s["pipeline"]["d1"] = {"candidate_count": 99, "replayed_count": 98, "status": "completed"}
    db.execute("UPDATE scan_tasks SET summary_json=? WHERE id=1", (Database.dumps(s),))

    FindingRepository(db)._reconcile_spec_count_snapshots(1)

    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    s = Database.loads(row["summary_json"])
    assert "candidate_count" not in s["pipeline"]["d1"]
    assert "replayed_count" not in s["pipeline"]["d1"]
    # 前端读取路径（results）仍写真相
    assert s["results"]["d1"]["candidate_count"] == 21


def test_reaggregate_writes_metrics_not_top_level(db: Database) -> None:
    """_reaggregate_d1_summary：修正值落 metrics，顶层键清掉，message 的 DAST / IAST 计数改从 metrics 读。

    原先 message 的 _impacts / _arrivals 读的是 d1 顶层（里面根本没有这两个键），恒为 0。
    """
    _seed_stale_summary(db)
    _seed_specs(db, 21)
    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    s = Database.loads(row["summary_json"])
    s["pipeline"]["d1"] = {
        "status": "completed",
        "message": "D1 统一重放（已并入 verify 链路）：驱动重放 38 条 TriggerSpec，0 条 DAST impact，0 条 IAST arrival",
        "metrics": {"candidate_count": 38, "finding_count": 12, "iast_arrivals": 7},
        "candidate_count": 38,
        "replayed_count": 38,
    }
    db.execute("UPDATE scan_tasks SET summary_json=? WHERE id=1", (Database.dumps(s),))

    FindingRepository(db)._reaggregate_d1_summary(1)

    row = db.execute("SELECT summary_json FROM scan_tasks WHERE id=1", fetchone=True)
    d1 = Database.loads(row["summary_json"])["pipeline"]["d1"]
    assert "candidate_count" not in d1
    assert "replayed_count" not in d1
    # min(38, 实表 21) = 21
    assert d1["metrics"]["candidate_count"] == 21
    assert d1["metrics"]["replayed_count"] == 21
    assert "21 条 TriggerSpec" in d1["message"]
    assert "12 条 DAST impact" in d1["message"]
    assert "7 条 IAST arrival" in d1["message"]
