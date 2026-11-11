"""Optional ground-truth input for evaluation runs.

No target-specific truth data is bundled with this repository. Point
``SAST_AI_TRUTH_FILES`` at your own CSV files (comma or semicolon separated)
to enable truth-based scoring. Each row is ``file path, vulnerability type``;
a header row is skipped. With nothing configured every lookup returns an empty
mapping, so scoring degrades to "no truth available" instead of silently
measuring against someone else's target.
"""

from __future__ import annotations

import csv
import os
from typing import Dict, List


def _truth_paths() -> List[str]:
    raw = os.environ.get("SAST_AI_TRUTH_FILES", "")
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


def _load() -> Dict[str, List[str]]:
    truth: Dict[str, List[str]] = {}
    for path in _truth_paths():
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 2:
                    continue
                key = row[0].strip().replace("\\", "/")
                kind = row[1].strip()
                if not key or not kind or key.lower() in ("file", "file_path", "path", "filename"):
                    continue
                truth.setdefault(key, []).append(kind)
    return truth


def get_ground_truth() -> Dict[str, List[str]]:
    """Return the configured truth mapping, or an empty mapping if none is set."""
    return _load()


def get_all_vulnerability_types() -> List[str]:
    """Return the sorted set of vulnerability types in the configured truth data."""
    types: set[str] = set()
    for vulns in get_ground_truth().values():
        types.update(vulns)
    return sorted(types)


def count_total_vulnerabilities() -> int:
    """Return the number of truth points in the configured truth data."""
    return sum(len(vulns) for vulns in get_ground_truth().values())
