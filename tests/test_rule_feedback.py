from pathlib import Path

import pytest
import yaml

from src.application.rule_feedback_service import RuleFeedbackService
from src.infrastructure.db import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(str(tmp_path / "app.db"))


@pytest.fixture()
def service(tmp_path: Path, db: Database) -> RuleFeedbackService:
    generated = tmp_path / "generated_rules.yaml"
    return RuleFeedbackService(db, generated_rules_path=str(generated))


def test_record_candidate_persists_and_dedupes(service: RuleFeedbackService):
    a = service.record_candidate(kind="sanitizer", pattern=r"escape_html\(", language="python", family="xss")
    b = service.record_candidate(kind="sanitizer", pattern=r"escape_html\(", language="python", family="xss")
    assert a["id"] == b["id"]  # same rule_hash => upsert, not duplicate
    assert b["occurrences"] == 2
    assert a["status"] == "candidate"
    assert a["regression_passed"] is False


def test_confirm_merges_rule_into_generated_file_without_regression(service: RuleFeedbackService, tmp_path: Path):
    candidate = service.record_candidate(kind="sanitizer", pattern=r"bleach\.clean\(", language="python", family="xss")

    result = service.confirm(candidate["id"], confirmed_by="alice")
    assert result["candidate"]["status"] == "merged"
    assert result["candidate"]["regression_passed"] is True
    # Regression did not drop metrics on the builtin golden set.
    assert not result["regression"]["regressed_metrics"]

    generated_path = Path(service.generated_rules_path)
    assert generated_path.exists()
    data = yaml.safe_load(generated_path.read_text(encoding="utf-8"))
    rules = data["rules"]
    assert any(r["pattern"] == r"bleach\.clean\(" and r["kind"] == "sanitizer" for r in rules)
    assert any(r["confirmed_by"] == "alice" for r in rules)


def test_confirm_missing_candidate_raises(service: RuleFeedbackService):
    with pytest.raises(ValueError):
        service.confirm(9999)


def test_invalid_kind_rejected(service: RuleFeedbackService):
    with pytest.raises(ValueError):
        service.record_candidate(kind="bogus", pattern="x")


def test_ingest_from_a2_harvests_new_patterns(service: RuleFeedbackService):
    findings = [
        {"display_family": "xss", "language": "python", "new_sanitizers": [r"escape\("], "new_sinks": ["render("]},
        {"display_family": "sqli", "language": "python", "new_sources": ["request.args"]},
    ]
    recorded = service.ingest_from_a2(findings, workspace_id=1)
    kinds = {r["kind"] for r in recorded}
    assert kinds == {"sanitizer", "sink", "source"}
    assert len(service.list_candidates(workspace_id=1)) == 3


def test_metrics_reports_merge_rate(service: RuleFeedbackService):
    c1 = service.record_candidate(kind="sink", pattern="dangerous_exec(", language="python", family="rce")
    service.record_candidate(kind="source", pattern="req.body", language="js", family="idor")
    service.confirm(c1["id"])
    metrics = service.metrics()
    assert metrics["total"] == 2
    assert metrics["merged"] == 1
    assert metrics["pending"] == 1
    assert metrics["merge_rate"] == 0.5
