"""Single source of truth for the CI gate.

Local machines and GitHub Actions run the same command:

    uv run --frozen python tools/ci_gate.py --step <static|test|build|all>

`static` inspects the publishable surface for secrets, machine-specific paths and
syntax errors. `test` is a dependency/import smoke that needs no test suite,
database or target. `build` builds the frontend.

No third-party dependency: this module uses only the standard library.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
NPM = ["cmd", "/c", "npm"] if os.name == "nt" else ["npm"]

SYNTAX_DIRS = ("src", "tools", "scripts")

# Lint is enforced on first-party tooling only. Adding a path here is an explicit
# decision to keep it formatted; the rest of the tree is out of scope on purpose.
LINT_FILES = (
    "tools/ci_gate.py",
    "tools/clean_clone_check.py",
)
LINT_DIRS = ("src", "tools", "scripts")

# Importing these in a clean process proves the runtime dependency closure is
# installed and the core package graph is loadable. None of them opens a database,
# starts a server or needs a target, so the check is platform-neutral.
SMOKE_MODULES = (
    "src.core.config_registry",
    "src.core.tool_paths",
    "src.core.vuln_hash",
    "src.core.knowledge_entries",
    "src.iast.probe_token",
)


def run(label, argv, cwd=ROOT):
    shown = " ".join(str(a).replace("\n", " ") for a in argv)
    if len(shown) > 160:
        shown = shown[:157] + "..."
    print("[ci-gate] %s: %s" % (label, shown), flush=True)
    rc = subprocess.call([str(a) for a in argv], cwd=str(cwd))
    if rc:
        print("[ci-gate] FAIL %s (exit %d)" % (label, rc), flush=True)
    return rc


def syntax_check():
    """Compile every Python source in memory, without writing any .pyc.

    `python -m compileall` writes a .pyc next to each source file. On Windows an
    external file watcher can invalidate those paths mid-run, so byte-compile
    fails with OSError(EBADF) on perfectly valid files. check_oss_hygiene.py also
    compiles sources, but silently skips files it cannot read or decode; this pass
    treats a missing or undecodable source as a failure instead.
    """
    print("[ci-gate] syntax check: %s" % ", ".join(SYNTAX_DIRS), flush=True)
    checked, errors = 0, []
    for top in SYNTAX_DIRS:
        root = ROOT / top
        if not root.is_dir():
            errors.append("missing directory: %s" % top)
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(ROOT).as_posix()
            try:
                compile(path.read_bytes(), rel, "exec")
            except (SyntaxError, ValueError, OSError) as exc:
                errors.append("%s: %s" % (rel, exc))
            else:
                checked += 1
    for msg in errors:
        print("[ci-gate]   %s" % msg, flush=True)
    if errors:
        print("[ci-gate] FAIL syntax check (%d bad)" % len(errors), flush=True)
        return 1
    print("[ci-gate] syntax check OK: %d files" % checked, flush=True)
    return 0


def step_static():
    rc = run("oss hygiene", [sys.executable, "tools/check_oss_hygiene.py"])
    if rc:
        return rc
    rc = run("ruff check", [sys.executable, "-m", "ruff", "check", *LINT_FILES])
    if rc:
        return rc
    rc = run("ruff format", [sys.executable, "-m", "ruff", "format", "--check", *LINT_FILES])
    if rc:
        return rc
    # The whole tree is linted with the same error-level rule set, so a defect
    # introduced anywhere is caught while the historical style debt stays out
    # of the gate.
    rc = run("ruff check (whole tree)", [sys.executable, "-m", "ruff", "check", *LINT_DIRS])
    if rc:
        return rc
    if rc:
        return rc
    return syntax_check()


def step_test():
    code = (
        "import importlib, sys\n"
        "bad = []\n"
        "for m in sys.argv[1:]:\n"
        "    try:\n"
        "        importlib.import_module(m)\n"
        "    except Exception as exc:\n"
        "        bad.append('%s: %s: %s' % (m, type(exc).__name__, exc))\n"
        "for line in bad:\n"
        "    print(line, file=sys.stderr)\n"
        "total = len(sys.argv) - 1\n"
        "print('imported %d/%d core modules' % (total - len(bad), total))\n"
        "sys.exit(1 if bad else 0)\n"
    )
    return run("core import smoke", [sys.executable, "-c", code, *SMOKE_MODULES])


def step_build():
    rc = run("npm ci", NPM + ["ci", "--no-audit", "--no-fund"], cwd=FRONTEND)
    if rc:
        return rc
    return run("npm run build", NPM + ["run", "build"], cwd=FRONTEND)


STEPS = {
    "static": step_static,
    "test": step_test,
    "build": step_build,
}


def main():
    ap = argparse.ArgumentParser(description="Run the SAVR CI gate")
    ap.add_argument("--step", choices=("all", *STEPS), default="all")
    args = ap.parse_args()
    todo = list(STEPS) if args.step == "all" else [args.step]
    for name in todo:
        rc = STEPS[name]()
        if rc:
            return rc
    print("[ci-gate] OK: %s" % ", ".join(todo), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
