"""G9: annual cost model + scan-trigger timing (第四版 §2.12)."""

from pathlib import Path

import pytest

from src.application.metrics_service import MetricsService
from src.core import cost_model
from src.infrastructure.db import Database

WORKSPACE_ID = 1


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    return database


def test_scan_cost_uses_model_unit_price():
    # 10k tokens on doubao (0.001/1k) = 0.01 USD
    assert cost_model.scan_cost(input_tokens=6000, output_tokens=4000, model="doubao") == pytest.approx(0.01)
    # unknown model falls back to default 0.002/1k
    assert cost_model.scan_cost(input_tokens=1000, output_tokens=0, model="mystery") == pytest.approx(0.002)


def test_average_scan_cost_handles_empty():
    assert cost_model.average_scan_cost([]) == 0.0
    assert cost_model.average_scan_cost([{"cost_usd": 0.02}, {"cost_usd": 0.04}]) == pytest.approx(0.03)


def test_predicted_scans_prefers_explicit_frequency_else_trigger_default():
    policies = [
        {"trigger": "pr", "enabled": True},                       # 60/mo default
        {"trigger": "weekly", "monthly_frequency": 6, "enabled": True},  # explicit 6/mo
        {"trigger": "nightly", "enabled": False},                 # disabled -> ignored
    ]
    # (60 + 6) * 12 = 792
    assert cost_model.predicted_scans_per_year(policies) == pytest.approx(792.0)


def test_annual_cost_returns_band_from_avg_and_frequency():
    est = cost_model.annual_cost(avg_scan_cost=0.05, predicted_scans=1000, variance=0.2)
    assert est["annual_cost"] == pytest.approx(50.0)
    assert est["annual_cost_low"] == pytest.approx(40.0)
    assert est["annual_cost_high"] == pytest.approx(60.0)


def test_recommend_model_split_separates_routine_and_deep():
    rec = cost_model.recommend_model_split()
    assert rec["routine"]["scan_mode"] == "filter_first"
    assert rec["deep"]["scan_mode"] == "pure_ai"
    assert rec["routine"]["unit_cost_per_1k"] < rec["deep"]["unit_cost_per_1k"]


def test_service_records_cost_and_estimates_annual(db: Database):
    service = MetricsService(db)
    service.record_scan_cost(
        workspace_id=WORKSPACE_ID, project="proj", scan_mode="filter_first",
        model="doubao", input_tokens=6000, output_tokens=4000, cost_usd=0.01,
    )
    service.record_scan_cost(
        workspace_id=WORKSPACE_ID, project="proj", scan_mode="pure_ai",
        model="anthropic", input_tokens=10000, output_tokens=10000, cost_usd=0.05,
    )
    service.upsert_trigger_policy(
        workspace_id=WORKSPACE_ID, name="pr-gate", trigger="pr", monthly_frequency=50, enabled=True,
    )
    estimate = service.annual_cost(workspace_id=WORKSPACE_ID)
    # avg = (0.01 + 0.05)/2 = 0.03 ; scans = 50*12 = 600 ; annual = 18.0
    assert estimate["avg_scan_cost"] == pytest.approx(0.03)
    assert estimate["predicted_scans"] == pytest.approx(600.0)
    assert estimate["annual_cost"] == pytest.approx(18.0)
    assert estimate["annual_cost_low"] < estimate["annual_cost"] < estimate["annual_cost_high"]
    assert estimate["scan_record_count"] == 2
    assert estimate["policy_count"] == 1
    assert "routine" in estimate["recommendation"]


def test_trigger_policy_upsert_is_idempotent(db: Database):
    service = MetricsService(db)
    service.upsert_trigger_policy(workspace_id=WORKSPACE_ID, name="nightly", trigger="nightly", monthly_frequency=30)
    service.upsert_trigger_policy(workspace_id=WORKSPACE_ID, name="nightly", trigger="nightly", monthly_frequency=20)
    policies = service.list_trigger_policies(workspace_id=WORKSPACE_ID)
    assert len(policies) == 1
    assert policies[0]["monthly_frequency"] == pytest.approx(20.0)
