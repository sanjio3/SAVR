from pathlib import Path
from typing import Any, Dict

import yaml


ROOT = Path(__file__).resolve().parents[1]
STANDARDS_DIR = ROOT / "config" / "standards"


def load_yaml_standard(name: str) -> Dict[str, Any]:
    path = STANDARDS_DIR / name
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def load_acceptance_standards() -> Dict[str, Any]:
    return load_yaml_standard("vuln_acceptance.yaml")


def load_rejection_standards() -> Dict[str, Any]:
    return load_yaml_standard("vuln_rejection.yaml")


def load_prompt_versions() -> Dict[str, Any]:
    return load_yaml_standard("prompt_versions.yaml")


def standards_for_family(family: str) -> Dict[str, Any]:
    normalized = str(family or "unknown").lower()
    acceptance = load_acceptance_standards()
    rejection = load_rejection_standards()
    common_reject = (rejection.get("common") or {}).get("reject", [])
    return {
        "family": normalized,
        "accept": (acceptance.get(normalized) or {}).get("accept", []),
        "reject": common_reject + ((rejection.get(normalized) or {}).get("reject", [])),
        "dynamic_evidence": (acceptance.get(normalized) or {}).get("dynamic_evidence", []),
        "prompt_version": load_prompt_versions().get("current", "terminal-first-v1"),
    }
