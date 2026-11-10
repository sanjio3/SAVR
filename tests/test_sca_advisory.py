"""G10: SCA advisory intelligence ingestion + version-range matching (第四版 §2.15).

All fixtures are in-memory / bundled dataset — zero network access.
"""

from pathlib import Path

import pytest

from src.application.advisory_service import AdvisoryService
from src.infrastructure.db import Database
from src.pipeline.sca.advisory import AffectedRange, parse_advisory


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(str(tmp_path / "app.db"))


@pytest.fixture()
def service(db: Database) -> AdvisoryService:
    return AdvisoryService(db)


def test_affected_range_boundaries():
    rng = AffectedRange(introduced="2.0", fixed="2.15.0")
    assert not rng.contains("1.9")       # below introduced
    assert rng.contains("2.0")           # introduced inclusive
    assert rng.contains("2.14.1")        # inside
    assert not rng.contains("2.15.0")    # fixed exclusive
    assert not rng.contains("2.16")      # above fix


def test_numeric_segment_ordering():
    rng = AffectedRange(introduced="1.9", fixed="1.20")
    assert rng.contains("1.10")  # 1.10 > 1.9 numerically, and < 1.20


def test_parse_osv_extracts_ranges_and_fixed():
    entry = {
        "id": "PYSEC-2023-62",
        "summary": "SQLi",
        "aliases": ["CVE-2023-0001"],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "example-orm"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.4.2"}]}],
        }],
    }
    advisory = parse_advisory(entry, "osv")
    assert advisory.package_name == "example-orm"
    assert advisory.ecosystem == "pypi"
    assert advisory.fixed_versions == ["1.4.2"]
    assert advisory.affects("1.4.1")
    assert not advisory.affects("1.4.2")


def test_ingest_and_match_component(service: AdvisoryService):
    service.ingest_local_dataset()
    hits = service.match_component(ecosystem="PyPI", name="example-orm", version="1.4.1")
    assert len(hits) == 1
    assert hits[0]["advisory_id"] == "PYSEC-2023-62"
    # Fixed version no longer matches.
    assert service.match_component(ecosystem="PyPI", name="example-orm", version="1.4.2") == []


def test_malicious_package_detection(service: AdvisoryService):
    service.ingest_local_dataset()
    hits = service.check_poisoning(ecosystem="PyPI", name="colourama", version="0.1.6")
    assert len(hits) == 1
    assert hits[0]["malicious"] is True
    # A different version is not the poisoned one.
    assert service.check_poisoning(ecosystem="PyPI", name="colourama", version="0.2.0") == []


def test_scan_installed_crosses_inventory(service: AdvisoryService, db: Database):
    service.ingest_local_dataset()
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO sca_components (workspace_id, ecosystem, name, version, source_file, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "pypi", "example-orm", "1.4.0", "requirements.txt", now, now),
    )
    db.execute(
        "INSERT INTO sca_components (workspace_id, ecosystem, name, version, source_file, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "pypi", "colourama", "0.1.6", "requirements.txt", now, now),
    )
    report = service.scan_installed(workspace_id=1)
    assert report["component_count"] == 2
    assert report["match_count"] >= 2
    assert len(report["malicious_hits"]) == 1
    assert report["malicious_hits"][0]["component"] == "colourama"


def test_ingest_is_idempotent(service: AdvisoryService):
    first = service.ingest_local_dataset()
    second = service.ingest_local_dataset()
    assert len(first) == len(second)
    assert len(service.repo.list()) == len(first)  # upsert, no duplicates


def test_unknown_source_rejected(service: AdvisoryService):
    with pytest.raises(ValueError):
        service.ingest_dataset([{"id": "X"}], source="bogus")
