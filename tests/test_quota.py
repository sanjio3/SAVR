"""配额框架（quota_service / /api/quota/*）与用量冗余观测（vhash）的单元测试。

配额=按主体(workspace/global)设定的用量上限与超限处置，实时聚合 scan_tasks/model_runs，
不新建流水表。金额型(cost)当前 provider 未上报单价，limit 仅占位。
"""

import pytest

from src.application.metrics_service import MetricsService
from src.application.quota_service import QuotaExceededError, QuotaService
from src.infrastructure.db import Database

WS_A = 1
WS_B = 2


@pytest.fixture()
def db():
    database = Database(":memory:")
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        ("ws-a", "/tmp/a", "", "{}", "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
    )
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        ("ws-b", "/tmp/b", "", "{}", "2026-01-01T00:00:00", "2026-01-01T00:00:00"),
    )
    # WS_A 已有 2 次扫描、若干 LLM 调用
    for i in range(2):
        database.execute(
            "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json,"
            " summary_json, error_message, created_at, started_at, finished_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (WS_A, f"t{i}", "completed", "done", "/o", "{}", "{}", "",
             "2026-01-01T00:00:00", "2026-01-01T00:00:00", "2026-01-01T00:01:00"),
        )
    database.execute(
        "INSERT INTO model_runs (purpose, model_profile, model, prompt_version, input_summary,"
        " output_summary, status, input_tokens, output_tokens, cost_usd, latency_ms, error_message,"
        " metadata_json, created_at, task_id, prompt_hash, stage, workspace_id) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("a2-semantic", "default", "m1", "v1", "", "", "completed", 100, 50, 0.0, 100, "", "{}",
         "2026-01-01T00:00:30", 1, "h-reused", "a2-semantic", WS_A),
    )
    return database


def test_upsert_and_list_policy(db):
    svc = QuotaService(db)
    p = svc.upsert_policy(
        name="ws-a-scan-cap", subject_type="workspace", subject_id=WS_A,
        dimension="count", limit_value=5, period="total", action="reject",
    )
    assert p["dimension"] == "count" and p["limit_value"] == 5.0
    listed = svc.list_policies(workspace_id=WS_A)
    assert len(listed) == 1 and listed[0]["id"] == p["id"]
    # upsert 同键覆盖（不新增行）
    svc.upsert_policy(
        name="ws-a-scan-cap-v2", subject_type="workspace", subject_id=WS_A,
        dimension="count", limit_value=3, period="total", action="reject",
    )
    assert len(svc.list_policies(workspace_id=WS_A)) == 1
    assert svc.list_policies(workspace_id=WS_A)[0]["limit_value"] == 3.0


def test_upsert_rejects_unknown_enum(db):
    svc = QuotaService(db)
    with pytest.raises(ValueError):
        svc.upsert_policy(dimension="bogus", subject_id=WS_A)
    with pytest.raises(ValueError):
        svc.upsert_policy(dimension="count", period="weekly", subject_id=WS_A)
    with pytest.raises(ValueError):
        svc.upsert_policy(dimension="count", action="explode", subject_id=WS_A)
    with pytest.raises(ValueError):
        svc.upsert_policy(dimension="count", subject_type="workspace")  # 缺 subject_id


def test_evaluate_reject_when_exceeded(db):
    svc = QuotaService(db)
    # WS_A 已有 2 次扫描；上限 1 → 超限 → 拒绝
    svc.upsert_policy(dimension="count", limit_value=1, period="total",
                      subject_type="workspace", subject_id=WS_A, action="reject")
    evals = svc.evaluate(WS_A, planned_count=0)
    assert evals[0]["used"] == 2.0
    assert evals[0]["exceeded"] is True
    with pytest.raises(QuotaExceededError):
        svc.assert_within_quota(WS_A)


def test_evaluate_warn_does_not_block(db):
    svc = QuotaService(db)
    svc.upsert_policy(dimension="count", limit_value=1, period="total",
                      subject_type="workspace", subject_id=WS_A, action="warn")
    evals = svc.evaluate(WS_A, planned_count=0)
    assert evals[0]["exceeded"] is True  # 超限但动作是 warn
    # warn 不抛异常
    svc.assert_within_quota(WS_A)


def test_workspace_policy_overrides_global(db):
    svc = QuotaService(db)
    svc.upsert_policy(dimension="count", limit_value=99, period="total",
                      subject_type="global", action="reject")
    svc.upsert_policy(dimension="count", limit_value=1, period="total",
                      subject_type="workspace", subject_id=WS_A, action="reject")
    evals = svc.evaluate(WS_A)
    assert len(evals) == 1  # workspace 优先，global 被覆盖
    assert evals[0]["subject_type"] == "workspace"
    with pytest.raises(QuotaExceededError):
        svc.assert_within_quota(WS_A)


def test_delete_policy(db):
    svc = QuotaService(db)
    p = svc.upsert_policy(dimension="count", limit_value=1, period="total",
                          subject_type="workspace", subject_id=WS_A)
    assert svc.delete_policy(p["id"]) is True
    assert svc.list_policies(workspace_id=WS_A) == []
    assert svc.delete_policy(99999) is False


def test_no_policy_means_no_block(db):
    # 未建任何策略 → 不拦截
    QuotaService(db).assert_within_quota(WS_A)


def test_usage_redundancy_metric(db):
    # 再插一条相同 prompt_hash 的调用（重复分析），并插一条不同 hash
    db.execute(
        "INSERT INTO model_runs (purpose, model_profile, model, prompt_version, input_summary,"
        " output_summary, status, input_tokens, output_tokens, cost_usd, latency_ms, error_message,"
        " metadata_json, created_at, task_id, prompt_hash, stage, workspace_id) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("a2-semantic", "default", "m1", "v1", "", "", "completed", 100, 50, 0.0, 100, "", "{}",
         "2026-01-01T00:00:31", 1, "h-reused", "a2-semantic", WS_A),
    )
    db.execute(
        "INSERT INTO model_runs (purpose, model_profile, model, prompt_version, input_summary,"
        " output_summary, status, input_tokens, output_tokens, cost_usd, latency_ms, error_message,"
        " metadata_json, created_at, task_id, prompt_hash, stage, workspace_id) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("a2-semantic", "default", "m1", "v1", "", "", "completed", 30, 10, 0.0, 100, "", "{}",
         "2026-01-01T00:00:32", 2, "h-unique", "a2-semantic", WS_A),
    )
    stats = MetricsService(db).usage_stats(workspace_id=WS_A)
    red = stats["llm"]["redundant"]
    # h-reused 出现 2 次 → 1 次冗余调用；h-unique 1 次 → 不计。
    # redundant_tokens 统计「所有命中重复 hash 的调用」的 token 总量（两条 h-reused = (100+50)*2）。
    assert red["duplicated_hashes"] == 1
    assert red["redundant_calls"] == 1
    assert red["redundant_tokens"] == 300
