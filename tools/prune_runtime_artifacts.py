# -*- coding: utf-8 -*-
"""只读盘点 / 精确清理本机运行时冗余产物（2026-11-06）。

默认 dry-run：只打印清单与可回收体积，绝不删除任何文件。
`--apply` 才执行删除，且只删下面 RULES 精确命中的路径，不做通配递归删除。

保护清单（任何情况下都不动）：
  - data/app.db / app.db-wal / app.db-shm（生产库）
  - data/*_truth*.csv、data/owasp_shards/（可复现真值）
  - data/blind_variants/（L1 泛化验证变体，尚未执行）
  - data/workspaces/、data/juliet*/、data/samples/（靶场与运行产物）
  - logs/d1_req_dump_*.jsonl（628/629 对账证据）
  - .git/、src/、tests/、frontend/、docs/

`--include-backups` 才会删除 data/app.db.bak-* 历史快照；默认保留。

用法:
    python tools/prune_runtime_artifacts.py                     # 只读清单
    python tools/prune_runtime_artifacts.py --json             # 机器可读
    python tools/prune_runtime_artifacts.py --apply             # 清理可再生垃圾
    python tools/prune_runtime_artifacts.py --apply --include-backups
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 生产库必须精确匹配：不能用 `startswith("data/app.db")`，否则
# data/app.db.bak-* 历史快照会被连带保护、永远清不掉。
EXACT_PROTECTED = ("data/app.db", "data/app.db-wal", "data/app.db-shm")
# 其余按前缀保护（相对 ROOT，正斜杠）
PREFIX_PROTECTED = (
    ".git/", "src/", "tests/", "frontend/", "docs/", "probe-java/",
    "data/java_sec_code_truth", "data/juliet_truth", "data/ruoyi_451_truth",
    "data/owasp_shards/", "data/blind_variants/", "data/workspaces/",
    "data/juliet", "data/samples/", "logs/d1_req_dump_",
)


def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def _is_protected(rel: str) -> bool:
    return rel in EXACT_PROTECTED or any(rel.startswith(p) for p in PREFIX_PROTECTED)


def _size(path: str) -> int:
    if os.path.isfile(path) or os.path.islink(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for base, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(base, f))
            except OSError:
                pass
    return total


def collect(include_backups: bool) -> list[dict]:
    """返回候选清单；每条带 category / path / kind / size / reason / needs_backup_flag。"""
    out: list[dict] = []

    def add(category: str, pattern: str, reason: str, *, backup: bool = False,
            require_file: str = "") -> None:
        for path in sorted(glob.glob(os.path.join(ROOT, pattern))):
            rel = _rel(path)
            if _is_protected(rel):
                continue
            if require_file and not os.path.isfile(os.path.join(path, require_file)):
                continue
            out.append({
                "category": category,
                "path": rel,
                "kind": "dir" if os.path.isdir(path) else "file",
                "size": _size(path),
                "reason": reason,
                "needs_backup_flag": backup,
            })

    add("pytest_tmp", ".pytest_tmp_*", "pytest 临时工作目录，可由测试重建")
    add("temp_db", "data/tmp*/", "tempfile.mkdtemp 残留的 6GB 级数据库副本",
        require_file="c.db")
    add("legacy_backup_dir", "data/_old_dirs_*/", "2026-10-20 目录重组旧树")
    add("legacy_backup_dir", "data/_reorg_backup_*/", "2026-10-20 重组备份")
    add("legacy_backup_dir", "data/_probe_owasp_db*/", "一次性探针数据库试验目录")
    add("legacy_backup_dir", "data/backup/", "空的旧备份目录")
    add("legacy_backup_dir", "data/_tmp_verify/", "一次性校验临时目录")
    add("stale_run_file", "data/*_run_*.json", "历史跑批状态快照（一次性）")
    add("stale_run_file", "data/.*_run.lock", "历史跑批锁文件")
    add("stale_run_file", "data/monitor_*.log", "历史监控日志")
    add("db_snapshot", "data/app.db.bak-*",
        "生产库历史快照：状态已被 628/629 覆盖，对账均读 data/app.db",
        backup=True)
    if include_backups:
        return out
    return [r for r in out if not r["needs_backup_flag"]]


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return str(n)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际删除（默认只盘点）")
    ap.add_argument("--include-backups", action="store_true",
                    help="额外删除 data/app.db.bak-* 历史快照")
    ap.add_argument("--json", action="store_true", help="输出 JSON 清单")
    args = ap.parse_args()

    rows = collect(args.include_backups)
    total = sum(r["size"] for r in rows)
    if args.json:
        print(json.dumps({"root": ROOT, "count": len(rows), "bytes": total,
                          "items": rows}, ensure_ascii=False, indent=2))
        return 0

    by_cat: dict[str, list[dict]] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    print("[prune] root=%s  mode=%s  candidates=%d  reclaimable=%s"
          % (ROOT, "APPLY" if args.apply else "DRY-RUN", len(rows), _human(total)))
    for cat, items in sorted(by_cat.items()):
        print("\n  %-20s %d items  %s" % (cat, len(items),
                                          _human(sum(i["size"] for i in items))))
        for i in items[:8]:
            print("    %-62s %10s" % (i["path"], _human(i["size"])))
        if len(items) > 8:
            print("    ... %d more" % (len(items) - 8))
    if not args.apply:
        print("\n[prune] dry-run 未删除任何文件。确认清单后加 --apply 执行。")
        return 0

    done, failed, freed = 0, [], 0
    for r in rows:
        path = os.path.join(ROOT, r["path"].replace("/", os.sep))
        if _is_protected(_rel(path)):
            failed.append((r["path"], "protected"))
            continue
        try:
            if r["kind"] == "dir":
                shutil.rmtree(path)
            else:
                os.remove(path)
            done += 1
            freed += r["size"]
        except OSError as exc:
            failed.append((r["path"], str(exc)))
    print("\n[prune] removed=%d  freed=%s  failed=%d"
          % (done, _human(freed), len(failed)))
    for p, why in failed[:20]:
        print("  FAILED %s : %s" % (p, why))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
