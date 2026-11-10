"""配置注册表（2026-10-20 建立）：把散落的运维参数收进 config/*.yaml。

设计原则
--------
1. **单一真相源**：参数只在 config/*.yaml 里定义，代码不再硬编码。
2. **优先级**：环境变量 > config/*.yaml > 代码默认值。
3. **可观测**：``describe()`` 返回生效配置摘要，启动时可打印，避免「改了不知道生效没」。
4. **失败回退**：yaml 缺失 / 字段缺失时回退代码默认，绝不抛异常（扫描不能因配置缺失而中断）。

不配置化的东西（刻意留在代码）
------------------------------
- 算法常量、内部逻辑分支；
- 安全不变量（如「path_traversal 绝不扩 strict-C」）——配置化反而会被误改。

为什么要有它
------------
2026-10-20 一天内踩的坑（CodeQL 内存硬编码、族白名单硬编码、root 路径不统一）
本质都是「参数散落、没有单一真相源」。本模块把「运维要调的参数」收进来，
调参不再需要改代码。
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import yaml

# 项目根 / config。config_registry.py 在 src/core/，上溯三级到项目根。
CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config"
)


def _truthy(raw: Optional[str]) -> bool:
    return str(raw or "").strip().lower() in ("1", "true", "yes", "on")


def _load_yaml(name: str) -> Dict[str, Any]:
    """读 config/<name>；文件缺失/解析失败返回空 dict（由调用方回退默认值）。

    2026-10-20：不缓存。这些读取器只在「扫描初始化 / postpass」各调用一次，不在热路径，
    读小 yaml 的开销可忽略；而缓存会让「进程内改动 env / yaml 后不生效」（配置语义变成
    进程启动快照），与「配置即生效」的初衷相悖，也给测试埋下顺序耦合的坑。故每次现读。
    """
    path = os.path.join(CONFIG_DIR, name)
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def codeql_config() -> Dict[str, Any]:
    """CodeQL 配置（config/codeql.yaml + 环境变量覆盖）。

    优先级：环境变量 > config/codeql.yaml。环境变量每次现读，确保进程内改动即时生效。

    环境变量：
      SAST_AI_DISABLE_CODEQL=1  → enabled=False（关闭 CodeQL，走 heuristic）
      CODEQL_BIN                → bin_path
      CODEQL_RAM_MB             → memory.ram_mb
      CODEQL_THREADS            → memory.threads
    """
    cfg = dict(_load_yaml("codeql.yaml"))
    if _truthy(os.environ.get("SAST_AI_DISABLE_CODEQL")):
        cfg["enabled"] = False
    if os.environ.get("CODEQL_BIN"):
        cfg["bin_path"] = os.environ["CODEQL_BIN"]
    memory = dict(cfg.get("memory") or {})
    if os.environ.get("CODEQL_RAM_MB"):
        try:
            memory["ram_mb"] = int(os.environ["CODEQL_RAM_MB"])
        except ValueError:
            pass
    if os.environ.get("CODEQL_THREADS"):
        try:
            memory["threads"] = int(os.environ["CODEQL_THREADS"])
        except ValueError:
            pass
    cfg["memory"] = memory
    return cfg


def families_config() -> Dict[str, Any]:
    """族白名单配置（config/families.yaml）。现读，见 _load_yaml 说明。"""
    return _load_yaml("families.yaml")


# ---- 便捷读取器：带代码默认值，调用方无需关心 yaml 是否存在 ----

def codeql_enabled(default: bool = True) -> bool:
    return bool(codeql_config().get("enabled", default))


def codeql_bin_path(default: Optional[str] = None) -> Optional[str]:
    return codeql_config().get("bin_path") or default


def codeql_ram_mb(default: int = 4096) -> int:
    try:
        return int((codeql_config().get("memory") or {}).get("ram_mb") or default)
    except (TypeError, ValueError):
        return default


def codeql_threads(default: int = 2) -> int:
    try:
        return int((codeql_config().get("memory") or {}).get("threads") or default)
    except (TypeError, ValueError):
        return default


def codeql_timeout(kind: str, default: int) -> int:
    """kind ∈ {version, finalize, create, analyze}。"""
    try:
        return int((codeql_config().get("timeout_seconds") or {}).get(kind) or default)
    except (TypeError, ValueError):
        return default


def codeql_suite(default: str = "java-security-extended") -> str:
    return str(codeql_config().get("suite") or default)


def _fam_list(section: str, key: str, default: Optional[List[str]]) -> List[str]:
    fams = (families_config().get(section) or {}).get(key)
    if isinstance(fams, list) and fams:
        return [str(x) for x in fams]
    return list(default or [])


def value_gate_families(default: Optional[List[str]] = None) -> List[str]:
    return _fam_list("value_gate", "families", default)


def strict_c_families(default: Optional[List[str]] = None) -> List[str]:
    return _fam_list("strict_c", "families", default)


def confirm_sink_families(default: Optional[List[str]] = None) -> List[str]:
    return _fam_list("confirm_sink_identity", "families", default)


def non_dataflow_families(default: Optional[List[str]] = None) -> List[str]:
    return _fam_list("non_dataflow", "families", default)


def describe() -> Dict[str, Any]:
    """生效配置摘要（启动时打印，便于排查「配置到底生效没」）。"""
    c = codeql_config()
    f = families_config()
    return {
        "codeql.enabled": c.get("enabled"),
        "codeql.bin_path": c.get("bin_path"),
        "codeql.memory": c.get("memory"),
        "codeql.suite": c.get("suite"),
        "families.value_gate": (f.get("value_gate") or {}).get("families"),
        "families.strict_c": (f.get("strict_c") or {}).get("families"),
        "families.confirm_sink": (f.get("confirm_sink_identity") or {}).get("families"),
    }
