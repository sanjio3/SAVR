"""
Core configuration loader with environment-variable support and sane defaults.
"""
from copy import deepcopy
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class Config:
    """Singleton configuration manager."""

    _instance: Optional["Config"] = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._config:
            self.load()

    def load(self, config_path: Optional[str] = None):
        """Load configuration from repo-local config files."""
        base_dir = Path(__file__).resolve().parents[2]
        if config_path is None:
            candidate_paths = [
                base_dir / "config" / "config.yaml",
                base_dir / "config.yaml",
                base_dir / "config" / "config.example.yaml",
            ]
        else:
            candidate_paths = [Path(config_path)]

        loaded: Dict[str, Any] = {}
        for candidate in candidate_paths:
            if candidate.exists():
                with open(candidate, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                break

        self._replace_env_vars(loaded)
        self._config = loaded
        self._apply_defaults()

    def set(self, key: str, value: Any) -> None:
        """Set configuration values via dot-separated key."""
        keys = key.split(".")
        node = self._config
        for item in keys[:-1]:
            child = node.get(item)
            if not isinstance(child, dict):
                child = {}
                node[item] = child
            node = child
        node[keys[-1]] = value

    def snapshot(self) -> Dict[str, Any]:
        """Return a deep copy of the active config."""
        return deepcopy(self._config)

    def restore(self, data: Dict[str, Any]) -> None:
        """Restore a previous config snapshot."""
        self._config = deepcopy(data)
        self._apply_defaults()

    def _apply_defaults(self):
        api = self._config.setdefault("api", {})
        api.setdefault("provider", "qwen")
        api.setdefault("model", "")
        api.setdefault("temperature", 0.1)
        api.setdefault("max_tokens", 4096)
        anthropic_compatible = self._config.setdefault("anthropic_compatible", {})
        anthropic_compatible.setdefault("source", "auto")
        anthropic_compatible.setdefault("auth_mode", "auto")
        anthropic_compatible.setdefault("settings_dir", "")

        scan = self._config.setdefault("scan", {})
        scan.setdefault("max_file_size", 500)
        scan.setdefault("concurrency", 3)
        scan.setdefault("languages", ["java", "python"])
        scan.setdefault("skip_dirs", [])

        benchmark = self._config.setdefault("benchmark", {})
        benchmark.setdefault("target_path", "")
        benchmark.setdefault("vulnerability_types", [])

        output = self._config.setdefault("output", {})
        output.setdefault("output_dir", "output")
        output.setdefault("formats", ["json", "markdown"])

        agents = self._config.setdefault("agents", {})
        # 原默认路径 src/config/rules/java_rules.yaml 是死配置 —— 全仓无任何代码加载它
        # （A1 现役规则来自 a1_injection_heuristic 的内置规则表；src/config/rules/
        # 下另有 rule_feedback 的回写通道 generated_rules.yaml），保留只会让配置指向
        # 一个不存在的文件。四份规则 yaml（java/javascript/php/python）已移除。
        # 注意：src/config/rules/ 目录本身必须保留 —— rule_feedback_service 会把
        # generated_rules.yaml 回写到该目录（mkdir(parents=True, exist_ok=True)）。
        agents.setdefault("a2", {}).setdefault("prompts_file", "src/prompts/audit_prompts.yaml")
        agents.setdefault("a2", {}).setdefault("max_lines_per_request", 500)
        agents.setdefault("d2", {}).setdefault("use_docker", True)
        agents.setdefault("d2", {}).setdefault("ai_judge_enabled", True)
        agents.setdefault("d2", {}).setdefault("ai_judge_on_statuses", ["partially_verified", "reached_but_not_triggered", "judge_inconclusive"])
        runtime = agents.setdefault("d2", {}).setdefault("runtime", {})
        runtime.setdefault("docker", {}).setdefault("fallback_policy", "local_jar_first")
        runtime.setdefault("docker", {}).setdefault("registry_mirror", "")
        runtime.setdefault("java", {}).setdefault("allow_local_jar", True)
        runtime.setdefault("java", {}).setdefault(
            "preferred_base_images",
            ["openjdk:21-jdk-slim", "eclipse-temurin:21-jre", "eclipse-temurin:17-jre"],
        )
        hitl = agents.setdefault("d2", {}).setdefault("hitl", {})
        hitl.setdefault("approval_mode", "off")
        hitl.setdefault("tool_allowlist", [])
        hitl.setdefault("act_allowlist", [])

    def _replace_env_vars(self, obj):
        """Recursively replace ${ENV_VAR} placeholders."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                    env_var = value[2:-1]
                    obj[key] = os.environ.get(env_var, "")
                elif isinstance(value, (dict, list)):
                    self._replace_env_vars(value)
        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                if isinstance(item, str) and item.startswith("${") and item.endswith("}"):
                    env_var = item[2:-1]
                    obj[index] = os.environ.get(env_var, "")
                elif isinstance(item, (dict, list)):
                    self._replace_env_vars(item)

    def _aggregate_api_config(self) -> Dict[str, Any]:
        return {
            "provider": self.get("api.provider", "qwen"),
            "model": self.get("api.model", ""),
            "temperature": self.get("api.temperature", 0.1),
            "max_tokens": self.get("api.max_tokens", 4096),
            # provider 子表，导致任何拿 config.get('api') 去组装降级链的调用方都看不到
            # ollama / fallback_provider，表现为「主用切了本地但兜底仍走云端」。
            "fallback_provider": self.get("api.fallback_provider", "anthropic-compatible"),
            "qwen": deepcopy(self._config.get("qwen", {})),
            "minimax": deepcopy(self._config.get("minimax", {})),
            "claude": deepcopy(self._config.get("claude", {})),
            "doubao": deepcopy(self._config.get("doubao", {})),
            "anthropic_compatible": deepcopy(self._config.get("anthropic_compatible", {})),
            "deepseek": deepcopy(self._config.get("deepseek", {})),
            "ollama": deepcopy(self._config.get("ollama", {})),
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Fetch configuration values via dot-separated keys."""
        if key == "api":
            return self._aggregate_api_config()

        keys = key.split(".")
        value: Any = self._config
        for item in keys:
            if isinstance(value, dict):
                value = value.get(item)
                if value is None:
                    return default
            else:
                return default
        return value

    @property
    def claude_api_key(self) -> str:
        return self.get("claude.api_key", "")

    @property
    def claude_model(self) -> str:
        return self.get("claude.model", "claude-sonnet-4-6")

    @property
    def benchmark_target_path(self) -> str:
        return self.get("benchmark.target_path", "")

    @property
    def output_dir(self) -> str:
        return self.get("output.output_dir", "output")


config = Config()
