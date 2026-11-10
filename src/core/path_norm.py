"""路径键归一化。

背景（2026-09-06）：
    流水线里同一份文件会以**两种形态**出现——A1 规则引擎产出绝对路径
    （``D:\\...\\target-mall\\src\\main\\java\\...\\Foo.java``），A2 语义分析产出
    相对路径（``src\\main\\java\\...\\Foo.java``）。

    A1 调用链证据索引（``benchmark_cli._build_a1_evidence_index``）以 A1 的
    ``result.file``（绝对）为 key，而 A2 用 ``file_info['rel_path']``（相对）去查，
    两边永远对不上 —— 结果 A2 每次都 miss，只能落到 aggregate 兜底，
    per-file 的 A1 证据（入口/source/sink/守卫）实际上从未喂进 LLM。

约定：
    任何跨阶段按文件路径做 key 的地方，两侧都必须用 ``normalize_path_key``
    归一化后再比较；无法精确命中时可用 ``match_path_key`` 做尾部匹配兜底。
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, Optional

__all__ = ["normalize_path_key", "match_path_key"]

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def normalize_path_key(path: Optional[str]) -> str:
    """把任意形态的路径归一成可比较的 key。

    处理：反斜杠→正斜杠、去盘符、去首尾空白与多余斜杠、转小写。
    不做 basename 截断，保留完整路径以便区分同名文件。
    """
    s = str(path or "").strip().replace("\\", "/")
    s = _DRIVE_RE.sub("", s)
    while "//" in s:
        s = s.replace("//", "/")
    return s.strip("/").lower()


def match_path_key(
    query: Optional[str],
    index: Dict[str, object],
    fallback: Optional[object] = None,
) -> Optional[object]:
    """在索引里查路径，先精确后尾部匹配。

    Args:
        query: 待查路径（任意形态）
        index: 以路径为 key 的字典（key 可以是任意形态，内部会归一化）
        fallback: 都没命中时返回的值

    Returns:
        命中的 value，或 fallback。
    """
    if not index:
        return fallback

    q = normalize_path_key(query)
    if not q:
        return fallback

    # 先做一次精确匹配（快路径）
    for key, value in index.items():
        if normalize_path_key(key) == q:
            return value
        # 任意一侧是相对路径时用尾部包含匹配，覆盖 绝对 vs 相对 的差异
        k = normalize_path_key(key)
        if k and (k.endswith("/" + q) or q.endswith("/" + k)):
            return value

    return fallback


def first_matching_keys(query: Optional[str], keys: Iterable[str]) -> list:
    """返回索引中所有与 query 匹配的 key（调试/诊断用）。"""
    q = normalize_path_key(query)
    if not q:
        return []
    hits = []
    for key in keys or []:
        k = normalize_path_key(key)
        if k == q or (k and (k.endswith("/" + q) or q.endswith("/" + k))):
            hits.append(key)
    return hits
