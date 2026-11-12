"""Advisory intelligence ingestion + impact matching service (G10).

Ties the ``advisory`` parsing layer to persistence and to the installed
component inventory (``sca_components``). Offline by default: ingests from
in-memory / local dataset fixtures; outbound fetching is opt-in and proxy-aware.
"""

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.infrastructure.db import Database
from src.infrastructure.repositories import AdvisoryRepository
from src.pipeline.sca.advisory import AffectedRange, Advisory, parse_advisory


_DEFAULT_DATASET = Path(__file__).resolve().parents[1] / "config" / "advisory_dataset.yaml"


class AdvisoryService:
    def __init__(self, db: Optional[Database] = None, *, dataset_path: Optional[str] = None):
        self.db = db or Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        self.repo = AdvisoryRepository(self.db)
        self.dataset_path = Path(dataset_path) if dataset_path else _DEFAULT_DATASET

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def ingest_local_dataset(self) -> List[Dict[str, Any]]:
        """Ingest the bundled offline advisory dataset (zero network)."""
        if not self.dataset_path.exists():
            return []
        data = yaml.safe_load(self.dataset_path.read_text(encoding="utf-8")) or {}
        source = str(data.get("source") or "osv")
        return self.ingest_dataset(data.get("advisories") or [], source=source)

    def ingest_dataset(self, entries: List[Dict[str, Any]], *, source: str) -> List[Dict[str, Any]]:
        """Ingest a list of raw advisory records from one source into storage."""
        stored: List[Dict[str, Any]] = []
        for entry in entries or []:
            advisory = parse_advisory(entry, source)
            stored.append(self.repo.upsert(self._to_record(advisory)))
        return stored

    def ingest_advisories(self, advisories: List[Advisory]) -> List[Dict[str, Any]]:
        return [self.repo.upsert(self._to_record(a)) for a in advisories]

    @staticmethod
    def _to_record(advisory: Advisory) -> Dict[str, Any]:
        record = asdict(advisory)
        record["affected_ranges"] = [asdict(r) for r in advisory.affected_ranges]
        return record

    # ------------------------------------------------------------------ #
    # Matching
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rehydrate(record: Dict[str, Any]) -> Advisory:
        ranges = [AffectedRange(**r) for r in (record.get("affected_ranges") or [])]
        return Advisory(
            advisory_id=record.get("advisory_id", ""),
            source=record.get("source", ""),
            ecosystem=record.get("ecosystem", ""),
            package_name=record.get("package_name", ""),
            aliases=record.get("aliases") or [],
            affected_ranges=ranges,
            fixed_versions=record.get("fixed_versions") or [],
            severity=record.get("severity", "UNKNOWN"),
            summary=record.get("summary", ""),
            details=record.get("details", ""),
            malicious=bool(record.get("malicious")),
        )

    def match_component(self, *, ecosystem: str, name: str, version: str) -> List[Dict[str, Any]]:
        """Return advisories whose affected range contains this component version."""
        hits: List[Dict[str, Any]] = []
        for record in self.repo.list_for_package(ecosystem, name):
            advisory = self._rehydrate(record)
            if advisory.affects(version):
                hits.append({
                    "advisory_id": record["advisory_id"],
                    "source": record["source"],
                    "severity": record["severity"],
                    "summary": record["summary"],
                    "malicious": record["malicious"],
                    "fixed_versions": record["fixed_versions"],
                    "matched_version": version,
                })
        return hits

    def scan_installed(self, workspace_id: Optional[int] = None) -> Dict[str, Any]:
        """Cross the installed component inventory against ingested advisories."""
        components = self._installed_components(workspace_id)
        matched: List[Dict[str, Any]] = []
        malicious_hits: List[Dict[str, Any]] = []
        for comp in components:
            hits = self.match_component(
                ecosystem=comp.get("ecosystem", ""),
                name=comp.get("name", ""),
                version=comp.get("version", ""),
            )
            for hit in hits:
                entry = {**hit, "component": comp.get("name"), "component_version": comp.get("version"),
                         "ecosystem": comp.get("ecosystem"), "source_file": comp.get("source_file")}
                matched.append(entry)
                if hit["malicious"]:
                    malicious_hits.append(entry)
        return {
            "component_count": len(components),
            "match_count": len(matched),
            "matches": matched,
            "malicious_hits": malicious_hits,
        }

    def _installed_components(self, workspace_id: Optional[int]) -> List[Dict[str, Any]]:
        sql = "SELECT ecosystem, name, version, source_file FROM sca_components"
        params: List[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id = ?"
            params.append(workspace_id)
        rows = self.db.execute(sql, params, fetchall=True) or []
        return [
            {"ecosystem": row["ecosystem"], "name": row["name"], "version": row["version"], "source_file": row["source_file"]}
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # Poisoning ("malicious package") intel
    # ------------------------------------------------------------------ #
    def check_poisoning(self, *, ecosystem: str, name: str, version: str = "") -> List[Dict[str, Any]]:
        """Return malicious-package advisories that flag this package/version."""
        hits = []
        for record in self.repo.list_for_package(ecosystem, name):
            if not record["malicious"]:
                continue
            advisory = self._rehydrate(record)
            if not version or advisory.affects(version):
                hits.append(record)
        return hits
