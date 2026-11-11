"""SCA advisory intelligence ingestion + version-range impact matching (G10).

Independent of the tool scanners (OSV/Trivy/Grype/Syft): this layer ingests
vulnerability advisories from intelligence sources (OSV API / GitHub Advisory /
NVD / CNVD·CNNVD) into a unified ``Advisory`` model, persists them, and matches
installed components against affected version ranges. Poisoning ("malicious
package") intel is modelled as advisories with ``malicious=True``.

Safety guardrail (第四版 ): outbound fetching is opt-in and proxy-aware.
By default the service is offline — it ingests from local dataset fixtures so
tests need zero network access.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Version comparison (PEP440-ish / semver-ish dotted numeric compare).
# --------------------------------------------------------------------------- #

def _parse_version(version: str) -> tuple:
    """Best-effort ordered tuple for a dotted version string.

    Splits on '.', strips a leading 'v', and coerces numeric segments to int so
    that ``1.10`` > ``1.9``. Non-numeric segments compare lexically after any
    numeric prefix, which is adequate for range gating on release versions.
    """
    text = (version or "").strip().lstrip("vV")
    # Drop build/pre-release metadata for range gating.
    for sep in ("+", "-"):
        if sep in text:
            text = text.split(sep, 1)[0]
    parts: List[tuple] = []
    for seg in text.split("."):
        seg = seg.strip()
        if not seg:
            continue
        if seg.isdigit():
            parts.append((0, int(seg), ""))
        else:
            # split leading digits from suffix (e.g. "1rc" -> 1,"rc")
            digits = ""
            i = 0
            while i < len(seg) and seg[i].isdigit():
                digits += seg[i]
                i += 1
            parts.append((0 if digits else 1, int(digits) if digits else 0, seg[i:]))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    pa, pb = _parse_version(a), _parse_version(b)
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


@dataclass
class AffectedRange:
    """A single affected version window.

    Semantics mirror OSV ranges: ``introduced`` is inclusive, ``fixed`` is
    exclusive. Empty ``introduced`` means "from the beginning"; empty ``fixed``
    means "no known fix" (open-ended). ``last_affected`` (inclusive) is an
    alternative upper bound used by some feeds.
    """

    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""

    def contains(self, version: str) -> bool:
        if not version:
            return False
        if self.introduced and _cmp(version, self.introduced) < 0:
            return False
        if self.fixed and _cmp(version, self.fixed) >= 0:
            return False
        if self.last_affected and _cmp(version, self.last_affected) > 0:
            return False
        return True


@dataclass
class Advisory:
    advisory_id: str
    source: str = ""
    ecosystem: str = ""
    package_name: str = ""
    aliases: List[str] = field(default_factory=list)
    affected_ranges: List[AffectedRange] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    summary: str = ""
    details: str = ""
    malicious: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    def affects(self, version: str) -> bool:
        if self.malicious:
            # A poisoning advisory that names a specific version only affects that
            # version; with no ranges/versions it flags the package outright.
            if self.fixed_versions:
                return any(_cmp(version, v) == 0 for v in self.fixed_versions)
            if not self.affected_ranges:
                return True
        return any(r.contains(version) for r in self.affected_ranges)


# --------------------------------------------------------------------------- #
# Source adapters -> normalized Advisory list.
# --------------------------------------------------------------------------- #

def _ranges_from_osv(entry: Dict[str, Any]) -> List[AffectedRange]:
    ranges: List[AffectedRange] = []
    for affected in entry.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            introduced = fixed = last_affected = ""
            for event in rng.get("events", []) or []:
                if "introduced" in event:
                    value = str(event["introduced"] or "")
                    introduced = "" if value == "0" else value  # OSV "0" == from the beginning
                if "fixed" in event:
                    fixed = str(event["fixed"] or "")
                if "last_affected" in event:
                    last_affected = str(event["last_affected"] or "")
            ranges.append(AffectedRange(introduced=introduced, fixed=fixed, last_affected=last_affected))
        for version in affected.get("versions", []) or []:
            ranges.append(AffectedRange(introduced=str(version), last_affected=str(version)))
    return ranges


def parse_osv(entry: Dict[str, Any], *, source: str = "osv") -> Advisory:
    affected0 = (entry.get("affected") or [{}])[0]
    pkg = affected0.get("package", {}) if isinstance(affected0, dict) else {}
    severity = "UNKNOWN"
    sev_list = entry.get("severity") or []
    if sev_list and isinstance(sev_list, list):
        severity = str(sev_list[0].get("type") or "UNKNOWN")
    db_specific = entry.get("database_specific") or {}
    if db_specific.get("severity"):
        severity = str(db_specific["severity"])
    fixed_versions: List[str] = []
    for rng in _ranges_from_osv(entry):
        if rng.fixed:
            fixed_versions.append(rng.fixed)
    return Advisory(
        advisory_id=str(entry.get("id") or ""),
        source=source,
        ecosystem=str(pkg.get("ecosystem") or "").lower(),
        package_name=str(pkg.get("name") or ""),
        aliases=[str(a) for a in (entry.get("aliases") or [])],
        affected_ranges=_ranges_from_osv(entry),
        fixed_versions=fixed_versions,
        severity=severity,
        summary=str(entry.get("summary") or ""),
        details=str(entry.get("details") or ""),
        malicious="MAL" in str(entry.get("id") or "").upper() or bool(db_specific.get("malicious")),
        raw=entry,
    )


def parse_ghsa(entry: Dict[str, Any]) -> Advisory:
    """GitHub Advisory JSON (GHSA). Falls back to OSV shape when present."""
    if entry.get("affected") and entry.get("id"):
        return parse_osv(entry, source="ghsa")
    ranges: List[AffectedRange] = []
    fixed_versions: List[str] = []
    for vuln in entry.get("vulnerabilities", []) or []:
        rng = vuln.get("vulnerable_version_range") or ""
        first_patched = ((vuln.get("first_patched_version") or {}) or {}).get("identifier", "")
        ranges.append(_range_from_expr(rng, fixed=first_patched))
        if first_patched:
            fixed_versions.append(first_patched)
    pkg = ((entry.get("vulnerabilities") or [{}])[0].get("package") or {})
    return Advisory(
        advisory_id=str(entry.get("ghsa_id") or entry.get("id") or ""),
        source="ghsa",
        ecosystem=str(pkg.get("ecosystem") or "").lower(),
        package_name=str(pkg.get("name") or ""),
        aliases=[str(i.get("value")) for i in (entry.get("identifiers") or []) if i.get("value")],
        affected_ranges=ranges,
        fixed_versions=fixed_versions,
        severity=str(entry.get("severity") or "UNKNOWN").upper(),
        summary=str(entry.get("summary") or ""),
        details=str(entry.get("description") or ""),
        raw=entry,
    )


def _range_from_expr(expr: str, *, fixed: str = "") -> AffectedRange:
    """Parse a comparator range like ``>= 1.0, < 1.4`` into an AffectedRange."""
    introduced = ""
    upper_fixed = fixed
    last_affected = ""
    for token in str(expr or "").replace("&&", ",").split(","):
        token = token.strip()
        if not token:
            continue
        for op in (">=", ">", "<=", "<", "="):
            if token.startswith(op):
                value = token[len(op):].strip()
                if op in (">=", ">"):
                    introduced = value
                elif op == "<":
                    upper_fixed = value
                elif op == "<=":
                    last_affected = value
                elif op == "=":
                    introduced = value
                    last_affected = value
                break
    return AffectedRange(introduced=introduced, fixed=upper_fixed, last_affected=last_affected)


def parse_nvd(entry: Dict[str, Any]) -> Advisory:
    """Minimal NVD CVE shape: cve.id + configurations version ranges."""
    cve = entry.get("cve", entry)
    cve_id = str(cve.get("id") or cve.get("CVE_data_meta", {}).get("ID") or "")
    ranges: List[AffectedRange] = []
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", node.get("cpe_match", [])) or []:
                ranges.append(AffectedRange(
                    introduced=str(match.get("versionStartIncluding") or ""),
                    fixed=str(match.get("versionEndExcluding") or ""),
                    last_affected=str(match.get("versionEndIncluding") or ""),
                ))
    return Advisory(
        advisory_id=cve_id,
        source="nvd",
        ecosystem=str(entry.get("ecosystem") or "").lower(),
        package_name=str(entry.get("package_name") or ""),
        aliases=[cve_id] if cve_id else [],
        affected_ranges=ranges,
        severity=str(((cve.get("metrics") or {}).get("severity")) or "UNKNOWN"),
        summary=str((cve.get("descriptions") or [{}])[0].get("value") or ""),
        raw=entry,
    )


def parse_cnvd(entry: Dict[str, Any]) -> Advisory:
    """CNVD/CNNVD flat shape: id + affected package/version range fields."""
    ranges = []
    if entry.get("affected_range"):
        ranges.append(_range_from_expr(entry["affected_range"], fixed=entry.get("fixed_version", "")))
    elif entry.get("affected_version"):
        ranges.append(AffectedRange(introduced=str(entry["affected_version"]), last_affected=str(entry["affected_version"])))
    return Advisory(
        advisory_id=str(entry.get("id") or entry.get("cnvd_id") or entry.get("cnnvd_id") or ""),
        source=str(entry.get("source") or "cnvd"),
        ecosystem=str(entry.get("ecosystem") or "").lower(),
        package_name=str(entry.get("package_name") or entry.get("component") or ""),
        aliases=[str(a) for a in (entry.get("aliases") or []) if a],
        affected_ranges=ranges,
        fixed_versions=[entry["fixed_version"]] if entry.get("fixed_version") else [],
        severity=str(entry.get("severity") or "UNKNOWN"),
        summary=str(entry.get("title") or entry.get("summary") or ""),
        malicious=bool(entry.get("malicious")),
        raw=entry,
    )


_PARSERS = {
    "osv": parse_osv,
    "ghsa": parse_ghsa,
    "nvd": parse_nvd,
    "cnvd": parse_cnvd,
    "cnnvd": parse_cnvd,
}


def parse_advisory(entry: Dict[str, Any], source: str) -> Advisory:
    parser = _PARSERS.get((source or "").lower())
    if parser is None:
        raise ValueError(f"unknown advisory source: {source}")
    return parser(entry)
