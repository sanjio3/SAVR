"""
Compatibility wrapper around the shared core config loader.
"""
from typing import Any, Dict

from ..core.config import config as core_config


class ConfigLoader:
    """Thin adapter kept for legacy callers."""

    def get(self, key: str, default: Any = None) -> Any:
        return core_config.get(key, default)

    def get_agent_config(self, agent_name: str) -> Dict:
        return core_config.get(f"agents.{agent_name}", {}) or {}

    def is_agent_enabled(self, agent_name: str) -> bool:
        return bool(self.get_agent_config(agent_name).get("enabled", True))

    def get_agent_skills(self, agent_name: str) -> list:
        return self.get_agent_config(agent_name).get("skills", [])


_config_loader = None


def get_config() -> ConfigLoader:
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader()
    return _config_loader
