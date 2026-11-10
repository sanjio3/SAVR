#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CodeQL rule_id → 平台族 的唯一映射入口（2026-11-01，P1）。

## 解决什么问题

平台内部族名有三套写法（DB 的 snake_case、`exploit_spec` 的 kebab-case、报告的中文标题），
而 CodeQL 的原生 query 名之前**没有任何映射**——`_map_rule_to_type` 的兜底是

    tail.replace("-", " ").title()      # java/log-injection -> "Log Injection"

于是 `type` 字段里出现了 `log injection`、`http response splitting`、`format string controlled`
这类带空格的字符串，一路流到 `trigger_specs.family`。
D2 的证明模板按族索引，**族名不在字典里就没有模板可套**，spec 结构性停在 unconfirmed
（本轮实测：21 条原生名 spec 里 17 条零确认）。

## 设计约定

1. 映射表在 `config/codeql_family_map.yaml`，**每次现读**（与 `config_registry` 一致：
   配置即生效，不做进程级缓存，避免测试顺序耦合）。
2. 未登记的 rule_id 返回 `unmapped` 并打 WARNING —— **不再猜**。
3. `unsupported` 段登记「平台没有对应族」的规则：返回 `unmapped`，但 reason 更明确，
   且 `is_d2_supported()` 为 False，调用方据此把它排除在动态分母之外（显式决策，不是静默丢）。
4. 本模块只做「名字归一」，不判真假、不改证据。
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_MAP_PATH = os.path.join(_ROOT, "config", "codeql_family_map.yaml")

UNMAPPED = "unmapped"


def _load() -> Dict[str, Dict[str, str]]:
    """读映射表，返回 ``{"rules": {...}, "unsupported": {...}}``。失败返回空表。"""
    try:
        import yaml
        with open(_MAP_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        rules = data.get("rules") or {}
        unsupported = data.get("unsupported") or {}
        return {
            "rules": {str(k).strip(): str(v).strip() for k, v in rules.items()},
            "unsupported": {str(k).strip(): str(v).strip() for k, v in unsupported.items()},
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[family-map] 读取失败（%s），本次全部按 unmapped 处理：%s", _MAP_PATH, exc)
        return {"rules": {}, "unsupported": {}}


def canonical_from_rule(rule_id: str, *, warn: bool = True) -> Tuple[str, str]:
    """rule_id → ``(canonical_family, reason)``。

    ``reason`` 取值：``mapped`` / ``unsupported`` / ``unmapped``。
    调用方应把 ``unmapped`` 的结果单独计数（审计口径），不要混进正常族。
    """
    rid = str(rule_id or "").strip()
    if not rid:
        return UNMAPPED, "empty_rule_id"
    table = _load()
    if rid in table["rules"]:
        return table["rules"][rid], "mapped"
    if rid in table["unsupported"]:
        if warn:
            logger.info("[family-map] %s 属平台无对应族：%s", rid, table["unsupported"][rid])
        return UNMAPPED, "unsupported"
    # 子串兜底：自定义查询可能带前缀（sastai/java/...），但绝不猜显示名
    for known, fam in table["rules"].items():
        if known and known in rid:
            return fam, "mapped_prefix"
    if warn:
        logger.warning(
            "[family-map] 未登记的 CodeQL 规则 %s → 落 %s；"
            "请在 config/codeql_family_map.yaml 补映射，否则该族拿不到 D2 证明模板",
            rid, UNMAPPED)
    return UNMAPPED, "unmapped"


def is_d2_supported(family: str) -> bool:
    """该族是否有 D2 证明模板（决定是否进动态分母）。

    ``unmapped`` 一律 False；其余按平台已知族集合判断。
    """
    fam = str(family or "").strip().lower()
    if not fam or fam == UNMAPPED:
        return False
    try:
        from src.core.exploit_spec import (
            DIFFERENTIAL_PROOF_FAMILIES, EXPOSURE_OR_CONFIG_FAMILIES, _INJECTION_FAMILIES,
        )
        known = {x.replace("-", "_") for x in
                 (set(_INJECTION_FAMILIES) | set(DIFFERENTIAL_PROOF_FAMILIES)
                  | set(EXPOSURE_OR_CONFIG_FAMILIES))}
        return fam in known
    except Exception:
        return False


def table_snapshot() -> Dict[str, Dict[str, str]]:
    """供审计工具读取完整映射表。"""
    return _load()


def map_path() -> str:
    return _MAP_PATH
