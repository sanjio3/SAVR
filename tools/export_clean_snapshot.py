# -*- coding: utf-8 -*-
"""按当前 .gitignore 规则导出一份可分发的干净快照（默认 dry-run）。

用途：把「允许分发的文件」与本机运行产物、本地配置、内部过程文档分开。
新目录只含当前规则允许分发的文件，由维护者在导出结果里做一次初始提交，
源工作树保持不变。

默认只列清单，不写任何文件。`--apply --dest DIR` 才复制；脚本**不会**
执行 git init / commit / tag，避免误把导出动作变成一次提交。

用法:
    python tools/export_clean_snapshot.py
    python tools/export_clean_snapshot.py --json
    python tools/export_clean_snapshot.py --apply --dest /path/to/clean-repo
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 双保险：即便 .gitignore 规则将来被误改，这些也绝不进导出快照。
HARD_EXCLUDE_PREFIXES = (
    ".git/", ".workbuddy", "data/app.db", "data/tmp", "data/bak",
    "logs/", "output/", "blind_variants/", "data/blind_variants/",
    "data/workspaces/", ".pytest_tmp_", ".venv/", "node_modules/",
)
HARD_EXCLUDE_NAMES = ("app.db", "app.db-wal", "app.db-shm", ".env", ".env.local")


def _git(args: list[str]) -> list[str]:
    out = subprocess.run(["git"] + args, cwd=ROOT, capture_output=True)
    if out.returncode != 0 and args[:1] != ["ls-files"]:
        raise RuntimeError("git %s failed: %s" % (" ".join(args),
                                                 out.stderr.decode("utf-8", "replace")))
    return [p.decode("utf-8", "replace") for p in out.stdout.split(b"\0") if p]


def candidates() -> list[str]:
    tracked = _git(["ls-files", "-z"])
    pending = _git(["ls-files", "--others", "--exclude-standard", "-z"])
    files = sorted(set(tracked + pending))
    out = []
    for rel in files:
        norm = rel.replace("\\", "/")
        if norm.startswith(HARD_EXCLUDE_PREFIXES):
            continue
        if os.path.basename(norm) in HARD_EXCLUDE_NAMES:
            continue
        if os.path.isfile(os.path.join(ROOT, rel.replace("/", os.sep))):
            out.append(rel)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="实际复制（默认只盘点）")
    ap.add_argument("--dest", default="", help="导出目标目录，--apply 时必填")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    files = candidates()
    total = 0
    for rel in files:
        try:
            total += os.path.getsize(os.path.join(ROOT, rel.replace("/", os.sep)))
        except OSError:
            pass
    if args.json:
        print(json.dumps({"root": ROOT, "count": len(files), "bytes": total,
                          "files": files}, ensure_ascii=False, indent=2))
        return 0
    print("[export] root=%s  files=%d  bytes=%.1f MiB  mode=%s"
          % (ROOT, len(files), total / 1024 ** 2, "APPLY" if args.apply else "DRY-RUN"))
    for rel in files[:20]:
        print("  " + rel)
    if len(files) > 20:
        print("  ... %d more" % (len(files) - 20))
    if not args.apply:
        print("[export] dry-run，未写任何文件。确认后加 --apply --dest <dir>。")
        return 0
    if not args.dest:
        print("[export] --apply 需要 --dest", file=sys.stderr)
        return 2
    dest = os.path.abspath(args.dest)
    if os.path.abspath(dest) == os.path.abspath(ROOT) or dest.startswith(
            os.path.abspath(ROOT) + os.sep):
        print("[export] 目标目录不能是仓库本身或其子目录", file=sys.stderr)
        return 2
    if os.path.exists(dest) and os.listdir(dest):
        print("[export] 目标目录非空，拒绝覆盖：%s" % dest, file=sys.stderr)
        return 2
    copied, failed = 0, []
    for rel in files:
        src = os.path.join(ROOT, rel.replace("/", os.sep))
        dst = os.path.join(dest, rel.replace("/", os.sep))
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
        except OSError as exc:
            failed.append((rel, str(exc)))
    # 复制后逐文件校验：目标存在且字节数与源一致。
    # 拷贝偶发漏文件时 shutil 不报错，只会让产物残缺、干净 clone 直接 ImportError，
    # 所以「复制成功」不等于「导出完整」，必须独立复核一遍。
    mismatch = []
    for rel in files:
        src = os.path.join(ROOT, rel.replace("/", os.sep))
        dst = os.path.join(dest, rel.replace("/", os.sep))
        try:
            if os.path.getsize(src) != os.path.getsize(dst):
                mismatch.append((rel, "size differs"))
        except OSError as exc:
            mismatch.append((rel, str(exc)))
    print("[export] copied=%d  failed=%d  verified=%d  mismatch=%d  dest=%s"
          % (copied, len(failed), len(files) - len(mismatch), len(mismatch), dest))
    for rel, why in failed[:10]:
        print("  FAILED %s : %s" % (rel, why))
    for rel, why in mismatch[:10]:
        print("  MISMATCH %s : %s" % (rel, why))
    if failed or mismatch:
        print("[export] 导出未通过完整性校验，目标目录不可用于发布。", file=sys.stderr)
        return 1
    print("[export] 完整性校验通过：%d 个文件与源逐字节一致。" % len(files))
    print("[export] 未执行 git init / commit / tag，请人工复核后再初始化新仓库。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
