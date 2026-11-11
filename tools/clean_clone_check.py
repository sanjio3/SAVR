"""Check that a pristine checkout of HEAD passes the CI gate.

The publishable surface is defined by git, not by the working tree. Local-only
files, a dirty index and ignored artifacts must never be required for a fresh
clone to work. This helper creates a detached worktree at HEAD (equivalent to a
clone, without the network), copies nothing, and runs the exact command CI uses.

    uv run --frozen python tools/clean_clone_check.py
    uv run --frozen python tools/clean_clone_check.py --step static
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def git(*args, cwd=ROOT, check=True):
    proc = subprocess.run(
        ["git", "-C", str(cwd), *(str(a) for a in args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode:
        raise RuntimeError(
            "git %s failed: %s" % (" ".join(str(a) for a in args), proc.stderr.strip())
        )
    return proc


def make_checkout(base: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="savr_clone_", dir=str(base)))
    try:
        git("worktree", "add", "--detach", tmp, "HEAD")
    except RuntimeError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the CI gate in a pristine HEAD checkout")
    ap.add_argument("--step", choices=("all", "static", "test", "build"), default="all")
    ap.add_argument("--base", default="", help="parent directory for the temporary checkout")
    ap.add_argument("--keep", action="store_true", help="keep the checkout for inspection")
    args = ap.parse_args()

    base = Path(args.base) if args.base else ROOT.parent / "_clone_tmp"
    base.mkdir(parents=True, exist_ok=True)

    dirty = git("status", "--porcelain").stdout.splitlines()
    if dirty:
        print(
            "[clean-clone] note: %d local change(s) intentionally NOT copied" % len(dirty),
            flush=True,
        )

    tmp = make_checkout(base)
    # Scratch stays outside the checkout: uv writes a lock file into its cwd and
    # the hygiene gate would reject an unexpected root entry.
    scratch = base / ("scratch_" + tmp.name)
    scratch.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["TMPDIR"] = env["TEMP"] = env["TMP"] = str(scratch)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    cmd = ["uv", "run", "--frozen", "python", "tools/ci_gate.py"]
    if args.step != "all":
        cmd += ["--step", args.step]
    print("[clean-clone] checkout: %s" % tmp, flush=True)
    print("[clean-clone] command : %s" % " ".join(cmd), flush=True)
    try:
        return subprocess.call(cmd, cwd=str(tmp), env=env)
    finally:
        if args.keep:
            print("[clean-clone] kept: %s" % tmp, flush=True)
        else:
            git("worktree", "remove", "--force", tmp, check=False)
            git("worktree", "prune", check=False)
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
