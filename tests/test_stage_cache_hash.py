"""阶段缓存键与作用域绑定的回归锁（2026-10-03 落地）。

背景（必须记住的坑）：FileScanner 产出的是 **dict 项**，而 stage_cache._file_path_of
原先只认 string / .path 属性 → dict 项被静跳过 → 文件一个都没进哈希 → 哈希退化成
「空输入哈希」，同工作区里任意两个不同作用域算出同一个缓存键。OWASP 分片 16 片全命中
run 53 的 xpathi 产物（a1=159、trigger_specs 全是 /xpathi-00/*）就是这么串味的。

三条锁：
    1. dict 项必须能解析出路径，且与字符串形态同哈希；
    2. 不同文件集合必须算出不同哈希（分片作用域必须进键）；
    3. 给了文件却一个都读不到，必须抛错（fail-closed，绝不容许「可碰撞的空哈希」溜出去）。
"""
from __future__ import annotations

import json
import os

import pytest

from src.pipeline import stage_cache
from src.pipeline.stage_cache import compute_target_code_hash


def _shard_files(name: str):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "owasp_shards", "shards", f"{name}.json")
    # 只有 mini 分片随仓库分发；其余分片的每条记录都带本机靶场源码路径，
    # 不能入库。分片缺失时返回空列表，由调用方按既有的 skip 分支优雅跳过。
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        blob = json.load(fh)
    return list(blob.get("files") or [])


def test_dict_items_hash_same_as_strings():
    """FileScanner 的 dict 项与磁盘路径字符串必须产出同一哈希。"""
    files = _shard_files("xpathi")[:5]
    if not files:
        pytest.skip("无 OWASP 分片清单可用")
    as_dict = [{"path": p} for p in files]
    assert compute_target_code_hash(as_dict) == compute_target_code_hash(files)


def test_dict_items_without_path_key_are_not_silently_skipped():
    """dict 只带 rel_path / name（FileScanner 那种）也要能取到路径并被读回。"""
    files = _shard_files("xpathi")[:3]
    if not files:
        pytest.skip("无 OWASP 分片清单可用")
    alt = [{"rel_path": p, "name": os.path.basename(p)} for p in files]
    assert compute_target_code_hash(alt) == compute_target_code_hash(files)


def test_distinct_scopes_produce_distinct_hashes():
    """不同分片（不同文件集合）必须算出不同缓存键——这条就是分片不串味的根锁。"""
    names = [n for n in ("xpathi", "cmdi-1", "crypto") if _shard_files(n)]
    if len(names) < 2:
        pytest.skip("分片清单不足两个")
    hashes = {
        n: compute_target_code_hash([{"path": p} for p in _shard_files(n)])
        for n in names
    }
    assert len(set(hashes.values())) == len(hashes), f"作用域不同却算出同键：{hashes}"


def test_unreadable_files_raise_instead_of_empty_hash():
    """文件清单非空却一个都读不到 → 抛错（由调用方 fail-closed 成「不命中缓存」）。"""
    with pytest.raises(ValueError):
        compute_target_code_hash([{"path": "__不存在__/nope.java"}])


def test_any_src_code_change_busts_cache(monkeypatch, tmp_path):
    """src/ 下任何 .py 改动都必须让 config_hash 变化（2026-10-04 补）。

    背景：`_CONFIG_SOURCES` 是手工白名单，改了没被列进去的文件（如 src/core/vuln_hash.py
    的族名归一）缓存不会失效 ⇒ 复跑拿到旧产物 ⇒ 闭环的「复跑验证」静默失效。
    实测事故：run 89 的 a2_poc.duration_seconds=0.0（对比 run 88 的 2769s）即缓存命中。
    """
    root = tmp_path / "proj"
    (root / "src" / "core").mkdir(parents=True)
    (root / "src" / "core" / "a.py").write_text("A = 1", encoding="utf-8")
    monkeypatch.setattr(stage_cache, "_project_root", lambda: root)

    h1 = stage_cache.compute_config_hash()
    # 改内容
    (root / "src" / "core" / "a.py").write_text("A = 2", encoding="utf-8")
    h2 = stage_cache.compute_config_hash()
    assert h1 != h2, "改了 src 代码却没 bust 缓存键"
    # 新增一个不在白名单里的文件
    (root / "src" / "core" / "b.py").write_text("B = 1", encoding="utf-8")
    h3 = stage_cache.compute_config_hash()
    assert h2 != h3, "新增源文件却没 bust 缓存键"
    # __pycache__ 变化不算代码改动，不应 bust（否则每次跑完就自动失效）
    (root / "src" / "core" / "__pycache__").mkdir()
    (root / "src" / "core" / "__pycache__" / "a.cpython-313.pyc").write_text("junk")
    assert stage_cache.compute_config_hash() == h3, "__pycache__ 不应影响缓存键"
