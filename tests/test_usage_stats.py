"""用量统计（/api/metrics/usage）。

与 test_ops_metrics.py 分开：后者度量的「用得好不好」（降噪率/误杀率/覆盖度），
这里度量「用掉多少」（扫描次数与周期、代码量、LLM token、Agent 调用）。

口径用例刻意覆盖三个真实数据缺口，防止后人「顺手美化」：
- cost_usd 全为 0 时必须如实报未计费，不许按假设单价反推金额；
- stage 为空必须单列为「未标注阶段」，不许冒充某个真实阶段；
- task_id 为 NULL 的历史调用必须计入总量但单列，不许静默丢掉。
"""

import json
from pathlib import Path

import pytest

from src.application.metrics_service import MetricsService
from src.infrastructure.db import Database

WS_A = 1
WS_B = 2


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("ws-a", "/tmp/a", "", "{}", now, now),
    )
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("ws-b", "/tmp/b", "", "{}", now, now),
    )
    # 两次扫描：一次 60 秒完成，一次 600 秒失败
    database.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json,"
        " error_message, created_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (WS_A, "t1", "completed", "done", "/tmp/o1", "{}", "{}", "", now,
         "2026-01-01T00:00:00", "2026-01-01T00:01:00"),
    )
    database.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json,"
        " error_message, created_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (WS_A, "t2", "failed", "failed", "/tmp/o2", "{}", "{}", "boom", now,
         "2026-01-01T01:00:00", "2026-01-01T01:10:00"),
    )
    return database


def _seed_run(database: Database, *, task_id, stage="a2-semantic", model="m1", purpose="a2-semantic",
              input_tokens=10, output_tokens=5, cost_usd=0.0, latency_ms=100):
    database.execute(
        "INSERT INTO model_runs (purpose, model_profile, model, prompt_version, input_summary, output_summary,"
        " status, input_tokens, output_tokens, cost_usd, latency_ms, error_message, metadata_json, created_at,"
        " task_id, prompt_hash, stage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (purpose, "default", model, "v1", "", "", "completed", input_tokens, output_tokens, cost_usd,
         latency_ms, "", "{}", "2026-01-01T00:00:30", task_id, "h", stage),
    )


def _seed_unassigned_run(database: Database, **kwargs):
    """task_id 为 NULL 的历史调用（task_id 列后加，早期调用没有归属）。"""
    database.execute(
        "INSERT INTO model_runs (purpose, model_profile, model, prompt_version, input_summary, output_summary,"
        " status, input_tokens, output_tokens, cost_usd, latency_ms, error_message, metadata_json, created_at,"
        " prompt_hash, stage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (kwargs.get("purpose", "a2-semantic"), "default", kwargs.get("model", "m-old"), "v1", "", "",
         "completed", kwargs.get("input_tokens", 7), kwargs.get("output_tokens", 3), 0.0,
         kwargs.get("latency_ms", 50), "", "{}", "2025-12-01T00:00:00", "h", kwargs.get("stage", "")),
    )


def test_scans_count_and_duration_percentiles(db: Database):
    stats = MetricsService(db).usage_stats()
    assert stats["scans"]["total"] == 2
    assert stats["scans"]["by_status"] == {"completed": 1, "failed": 1}
    duration = stats["scans"]["duration"]
    assert duration["count"] == 2
    assert duration["avg_seconds"] == pytest.approx(330.0)  # (60 + 600) / 2
    assert duration["p50_seconds"] == pytest.approx(330.0)
    assert duration["max_seconds"] == pytest.approx(600.0)


def test_code_volume_comes_from_preprocess_metrics_only(db: Database):
    summary = {"pipeline": {"preprocess": {"metrics": {
        "file_count": 95, "indexed_functions": 276, "http_entries": 131, "endpoint_count": 133,
    }}}}
    db.execute(
        "UPDATE scan_tasks SET summary_json = ? WHERE name = ?",
        (json.dumps(summary), "t1"),
    )
    stats = MetricsService(db).usage_stats()
    # t2 没有预处理指标，不应被计入「纳入统计的扫描」，也不拿别处数字顶替
    assert stats["code_volume"]["scans_indexed"] == 1
    assert stats["code_volume"]["files_total"] == 95
    assert stats["code_volume"]["functions_total"] == 276
    assert stats["code_volume"]["http_entries_total"] == 131


def test_zero_cost_is_reported_as_unbilled_not_as_free(db: Database):
    _seed_run(db, task_id=1, input_tokens=100, output_tokens=50, cost_usd=0.0)
    stats = MetricsService(db).usage_stats()
    assert stats["llm"]["cost_usd"] == 0.0
    assert stats["llm"]["billed"] is False
    assert any("未计费" in note for note in stats["notes"])


def test_unassigned_calls_are_counted_but_kept_separate(db: Database):
    _seed_run(db, task_id=1, input_tokens=100, output_tokens=50)
    _seed_unassigned_run(db, input_tokens=7, output_tokens=3)
    stats = MetricsService(db).usage_stats()
    assert stats["llm"]["calls"] == 2
    assert stats["llm"]["attributed"]["calls"] == 1
    assert stats["llm"]["unassigned"]["calls"] == 1
    assert stats["llm"]["total_tokens"] == 160
    # 未关联任务无法归属工作区，by_workspace 只算可归属的那部分
    assert [b["llm_calls"] for b in stats["by_workspace"]] == [1]
    assert any("未关联任务" in note for note in stats["notes"])


def test_empty_stage_is_labeled_not_silently_merged(db: Database):
    _seed_run(db, task_id=1, stage="")
    _seed_run(db, task_id=2, stage="a2-semantic")
    stats = MetricsService(db).usage_stats()
    stages = {row["key"]: row["calls"] for row in stats["llm"]["by_stage"]}
    assert stages.get("未标注阶段") == 1
    assert stages.get("a2-semantic") == 1
    assert any("阶段未标注" in note for note in stats["notes"])


def test_workspace_filter_drops_unassignable_calls(db: Database):
    _seed_run(db, task_id=1)
    _seed_unassigned_run(db)
    scoped = MetricsService(db).usage_stats(workspace_id=WS_A)
    # 筛了工作区，NULL task_id 的调用无法归属，只能不计（不是丢了，是分不下去）
    assert scoped["llm"]["calls"] == 1
    assert scoped["llm"]["unassigned"]["calls"] == 0
    assert scoped["scans"]["total"] == 2


def test_agent_calls_grouped_by_purpose(db: Database):
    _seed_run(db, task_id=1, purpose="a2-semantic", latency_ms=100)
    _seed_run(db, task_id=1, purpose="a2-semantic", latency_ms=300)
    _seed_run(db, task_id=2, purpose="gray-review", latency_ms=50)
    stats = MetricsService(db).usage_stats()
    by_purpose = {row["key"]: row for row in stats["agents"]["by_purpose"]}
    assert by_purpose["a2-semantic"]["calls"] == 2
    assert by_purpose["a2-semantic"]["avg_ms"] == pytest.approx(200.0)
    assert by_purpose["gray-review"]["calls"] == 1
