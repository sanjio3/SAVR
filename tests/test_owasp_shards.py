"""2026-10-02：OWASP Benchmark 全集分片与作用域过滤回归测试。

全集 2740 用例一次性扫会爆（CodeQL / 本地 LLM / 探针 / Commit 上限），故按族切分、
一片一跑。本测试钉死三件事：真值表能正确解析（表头带前导空格是既定坑）、切分正确、
路由匹配不依赖路由模板形态（用例名 token 子串匹配，模板换了也不失效）。
"""
import json
import os

import pytest

from src.core import scan_scope as ss

# expectedresults-1.2.csv 表头形如 "# test name, category, real vulnerability, cwe"
CSV_HEAD = "# test name, category, real vulnerability, cwe\n"


def _write_csv(tmp_path, rows):
    p = tmp_path / "expected.csv"
    p.write_text(CSV_HEAD + "\n".join(rows) + "\n", encoding="utf-8")
    return str(p)


def test_parse_expected_results_handles_padded_header(tmp_path):
    path = _write_csv(tmp_path, [
        "BenchmarkTest00001,pathtraver,true,22",
        "BenchmarkTest00002,pathtraver,false,22",
        "BenchmarkTest00003,sqli,true,89",
    ])
    out = ss.parse_expected_results(path)
    assert len(out) == 3
    assert out[0] == {"test_name": "BenchmarkTest00001", "category": "pathtraver", "is_tp": True}
    assert out[1]["is_tp"] is False
    assert out[2]["category"] == "sqli"


def test_build_shards_groups_by_category_and_splits_large(tmp_path):
    rows = [f"BenchmarkTest{i:05d},sqli,{'true' if i % 2 else 'false'},89" for i in range(1, 11)]
    rows += ["BenchmarkTest00011,xss,true,79"]
    cases = ss.parse_expected_results(_write_csv(tmp_path, rows))
    shards = ss.build_shards(cases, max_per_shard=4)
    names = [s["name"] for s in shards]
    # sqli 10 条 > 4 → 二次切分；xss 1 条保持单片
    assert names == ["sqli-1", "sqli-2", "sqli-3", "xss"]
    assert sum(s["count"] for s in shards) == 11
    assert sum(s["tp"] for s in shards) == 6  # i 奇数 5 个 + xss 1 个


def test_route_matching_ignores_route_template_shape():
    """路由模板形态变了（有无 category 段）仍能命中——因为匹配的是用例名 token。"""
    shard = {"name": "sqli-1", "cases": ["BenchmarkTest00001", "BenchmarkTest00002"]}
    assert ss.route_in_shard("/benchmark/sqli-00/BenchmarkTest00001", shard)
    assert ss.route_in_shard("/benchmark/BenchmarkTest00002", shard)  # 模板变了也命中
    assert not ss.route_in_shard("/benchmark/sqli-00/BenchmarkTest00003", shard)
    assert not ss.route_in_shard("", shard)


def test_filter_entries_and_files():
    shard = {"name": "sqli-1", "cases": ["BenchmarkTest00001"], "files": ["/src/BenchmarkTest00001.java"]}
    entries = [
        {"route": "/benchmark/sqli-00/BenchmarkTest00001"},
        {"route": "/benchmark/xss-00/BenchmarkTest00009"},
        {"path": "/benchmark/sqli-00/BenchmarkTest00001/detail"},
    ]
    kept, st = ss.filter_entries(entries, shard)
    assert len(kept) == 2 and st == {"total": 3, "kept": 2, "dropped": 1}

    files = ["/src/BenchmarkTest00001.java", "/src/BenchmarkTest00009.java"]
    keptf, stf = ss.filter_files(files, shard)
    assert keptf == ["/src/BenchmarkTest00001.java"] and stf["dropped"] == 1


def test_filter_files_accepts_scanner_dict_items():
    """FileScanner.scan() 返回的是 dict（path/rel_path/name），不是字符串。

    2026-10-03 实测：filter_files 若按字符串处理，`str(dict)` 把整个 dict 当路径 →
    分片收窄恒空（kept=0），扫描静默退化为全量。此处锁定 dict 入参行为。
    """
    shard = {"name": "xpathi", "cases": ["BenchmarkTest00116"],
             "files": ["/srv/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00116.java"]}
    items = [
        {"path": "/srv/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00116.java",
         "name": "BenchmarkTest00116.java", "rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00116.java"},
        {"path": "/srv/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00117.java",
         "name": "BenchmarkTest00117.java"},
    ]
    kept, st = ss.filter_files(items, shard)
    assert len(kept) == 1 and kept[0] is items[0]
    assert st == {"total": 2, "kept": 1, "dropped": 1}


def test_filter_files_matches_by_basename_when_tree_differs():
    """清单路径与扫描根不同形（如扫描根是 prepared 副本）时，按文件名兜底仍能收窄。

    兜底只在精确匹配失败时才有意义：真不匹配（文件名都不在清单里）仍要 dropped，
    由调用方中止并报清晰错误，绝不静默放行成全量。
    """
    shard = {"name": "x", "cases": ["BenchmarkTest00116"],
             "files": ["/real/BenchmarkTest00116.java"]}
    items = [
        {"path": "/tmp/prepared/BenchmarkTest00116.java", "name": "BenchmarkTest00116.java"},
        {"path": "/tmp/prepared/BenchmarkTest00117.java", "name": "BenchmarkTest00117.java"},
    ]
    kept, st = ss.filter_files(items, shard)
    assert [k["path"] for k in kept] == [items[0]["path"]]
    assert st["dropped"] == 1


def test_filter_entries_on_owasp_entry_shape():
    """EntryDiscoveryService 的入口 dict 是 entry_type/file/line/signature 形态（没有 route）。

    2026-10-03 实测：只认 route 时分片把入口收窄成 0 条（2743 → 0），依赖入口的链路全空转。
    此处锁定 OWASP 真实入口形态下的收窄行为：按 file（用例文件名全局唯一）也能精确命中。
    """
    shard = {"name": "xpathi", "cases": ["BenchmarkTest00116"],
             "files": ["/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00116.java"]}
    entries = [
        {"entry_type": "web_route",
         "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00116.java",
         "signature": '@WebServlet(value = "/xpathi-00/BenchmarkTest00116")'},
        {"entry_type": "web_route",
         "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00117.java",
         "signature": '@WebServlet(value = "/xpathi-00/BenchmarkTest00117")'},
    ]
    kept, st = ss.filter_entries(entries, shard)
    assert len(kept) == 1 and st == {"total": 2, "kept": 1, "dropped": 1}
    assert "BenchmarkTest00116" in str(kept[0].get("signature") or "")


def test_no_shard_means_no_filtering():
    """未配置分片时行为完全不变（零回归）。"""
    entries = [{"route": "/a"}, {"route": "/b"}]
    kept, st = ss.filter_entries(entries, None)
    assert len(kept) == 2 and st["kept"] == 2


def test_load_shard_from_generated_manifest():
    """与 tools/owasp_shards.py 的真实产物对拍（存在时才跑）。"""
    idx = os.path.join("data", "owasp_shards", "index.json")
    if not os.path.isfile(idx):
        pytest.skip("分片清单未生成（跑 tools/owasp_shards.py 才有）")
    with open(idx, encoding="utf-8") as fh:
        data = json.load(fh)
    summary = data["summary"]
    assert summary["case_count"] == 2740
    assert summary["tp"] == 1415 and summary["fp"] == 1325
    shard_file = os.path.join("data", "owasp_shards", "shards", f"{data['shards'][0]['name']}.json")
    shard = ss.load_shard(shard_file)
    assert shard and shard["cases"]
    # 分片之间互不重叠：并集大小 = 用例总数
    seen = set()
    for s in data["shards"]:
        p = os.path.join("data", "owasp_shards", "shards", f"{s['name']}.json")
        sh = ss.load_shard(p)
        seen.update(sh["cases"])
    assert len(seen) == 2740


# ── 分片必须约束「文件范围」，不能只约束入口（2026-11-02）─────────────────────
#
# 事故：neg-mini 分片只有 `cases`（198 个用例名）、`files` 是空数组。
# `filter_files` 原实现「files 为空就原样返回」⇒ 分片对文件范围完全无效：
#     [*] 分片作用域 neg-mini：文件 2843 → 保留 2843（丢弃 0）
#     [*] 分片作用域 neg-mini：入口 5486 → 保留 396（丢弃 5090）
# 结果 A2 仍要分析全部 2843 个文件（实测 2 小时只走完 737 个），分片白做。
# 入口侧走 filter_entries（认 cases）所以看起来是对的，问题只在文件侧、很隐蔽。

def test_filter_files_falls_back_to_cases_when_files_empty():
    from src.core.scan_scope import filter_files

    shard = {"name": "mini", "cases": ["BenchmarkTest00005", "BenchmarkTest00009"], "files": []}
    files = [
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00005.java",
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00009.java",
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest09999.java",
        "src/main/java/org/owasp/benchmark/helpers/Utils.java",
    ]
    kept, st = filter_files(files, shard)
    assert len(kept) == 2, kept
    assert st == {"total": 4, "kept": 2, "dropped": 2}, st


def test_filter_files_with_explicit_files_still_works():
    """有 files 时行为不变（回归锁）。"""
    from src.core.scan_scope import filter_files

    shard = {"name": "x", "files": ["/a/BenchmarkTest00001.java"]}
    files = ["/a/BenchmarkTest00001.java", "/a/BenchmarkTest00002.java"]
    kept, st = filter_files(files, shard)
    assert kept == ["/a/BenchmarkTest00001.java"], kept
    assert st["dropped"] == 1


def test_filter_files_no_constraint_returns_all():
    """既无 files 也无 cases ⇒ 原样返回（不能把「全量片」误判成空片）。"""
    from src.core.scan_scope import filter_files

    files = ["/a/A.java", "/a/B.java"]
    kept, st = filter_files(files, {"name": "full"})
    assert kept == files and st["kept"] == 2


# ── 分片必须约束「文件范围」，不能只约束入口（2026-11-02）─────────────────────
#
# 事故：neg-mini 分片只有 `cases`（198 个用例名）、`files` 是空数组。
# `filter_files` 原实现「files 为空就原样返回」⇒ 分片对文件范围完全无效：
#     [*] 分片作用域 neg-mini：文件 2843 → 保留 2843（丢弃 0）
#     [*] 分片作用域 neg-mini：入口 5486 → 保留 396（丢弃 5090）
# 结果 A2 仍要分析全部 2843 个文件（实测 2 小时只走完 737 个），分片白做。
# 入口侧走 filter_entries（认 cases）所以看起来是对的，问题只在文件侧、很隐蔽。

def test_filter_files_falls_back_to_cases_when_files_empty():
    from src.core.scan_scope import filter_files

    shard = {"name": "mini", "cases": ["BenchmarkTest00005", "BenchmarkTest00009"], "files": []}
    files = [
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00005.java",
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00009.java",
        "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest09999.java",
        "src/main/java/org/owasp/benchmark/helpers/Utils.java",
    ]
    kept, st = filter_files(files, shard)
    assert len(kept) == 2, kept
    assert st == {"total": 4, "kept": 2, "dropped": 2}, st


def test_filter_files_with_explicit_files_still_works():
    """有 files 时行为不变（回归锁）。"""
    from src.core.scan_scope import filter_files

    shard = {"name": "x", "files": ["/a/BenchmarkTest00001.java"]}
    files = ["/a/BenchmarkTest00001.java", "/a/BenchmarkTest00002.java"]
    kept, st = filter_files(files, shard)
    assert kept == ["/a/BenchmarkTest00001.java"], kept
    assert st["dropped"] == 1


def test_filter_files_no_constraint_returns_all():
    """既无 files 也无 cases ⇒ 原样返回（不能把「全量片」误判成空片）。"""
    from src.core.scan_scope import filter_files

    files = ["/a/A.java", "/a/B.java"]
    kept, st = filter_files(files, {"name": "full"})
    assert kept == files and st["kept"] == 2
