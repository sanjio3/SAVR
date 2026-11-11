"""sink token 数据集。

把 ``src.core.sink_value_gate.FAMILY_SINK_TOKENS`` 硬编码的「族 → 真 sink token」
数据化到 ``config/sink_tokens.yaml``，作为可扩展底座：printf 形态规则、M3 族归因、
4.3 探针合并匹配器都依赖它。

**纯加法**：不修改任何现有调用路径；现有 ``FAMILY_SINK_TOKENS`` 保留为 fallback。

**验收**：``tokens_for(family)`` 与 ``FAMILY_SINK_TOKENS`` 逐族相等（见
``tests/test_sink_token_dataset.py``）。
"""

from __future__ import annotations

import os
from functools import lru_cache

import yaml

DEFAULT_YAML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "config",
    "sink_tokens.yaml",
)


@lru_cache(maxsize=1)
def load_data(path: str = DEFAULT_YAML) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def canonical_family(family: str) -> str:
    """平台短族名 → 规范族名（与 sink_value_gate.canonical_family 等价）。"""
    fam = str(family or "").strip().lower()
    return load_data().get("aliases", {}).get(fam, fam)


def is_dataflow_family(family: str) -> bool:
    """该族是否为数据流族（值级闸适用）；算法/属性族返回 False。"""
    return canonical_family(family) not in set(load_data().get("non_dataflow", []))


def tokens_for(family: str) -> tuple:
    """返回该族的真 sink token 元组（与 FAMILY_SINK_TOKENS 逐族相等）。

    先查规范族名；查不到再做子串回退（兼容 sink_value_gate._sink_tokens 行为）。
    """
    fam = canonical_family(family)
    fams = load_data().get("families", {})
    if fam in fams:
        return tuple(fams[fam].get("tokens", []))
    for k, v in fams.items():
        if k in fam or fam in k:
            return tuple(v.get("tokens", []))
    return ()
