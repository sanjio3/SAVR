"""Single source of truth for the CI gate.

Local machines and GitHub Actions run the same command:

    uv run --frozen python tools/ci_gate.py --step <static|test|build|all>

The gate owns the environment variables and pytest arguments so the CI workflow
and a developer checkout cannot drift apart. No third-party dependency: this
module uses only the standard library.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
JUNIT = ROOT / "output" / "ci" / "junit.xml"
NPM = ["cmd", "/c", "npm"] if os.name == "nt" else ["npm"]

# Keep in sync with .github/workflows/ci.yml and CONTRIBUTING.md.
GATE_ENV = {
    "SAST_AI_CLOSED_LOOP": "0",
    "SAST_AI_BENCHMARK_PRIOR": "1",
}


def run(label, argv, cwd=ROOT):
    env = os.environ.copy()
    env.update(GATE_ENV)
    print("[ci-gate] %s: %s" % (label, " ".join(str(a) for a in argv)), flush=True)
    rc = subprocess.call([str(a) for a in argv], cwd=str(cwd), env=env)
    if rc:
        print("[ci-gate] FAIL %s (exit %d)" % (label, rc), flush=True)
    return rc


SYNTAX_DIRS = ("src", "tools", "scripts", "tests")

# Lint is enforced on first-party tooling only. Adding a path here is an explicit
# decision to keep it formatted; the rest of the tree is out of scope on purpose.
LINT_FILES = (
    "tools/ci_gate.py",
    "tools/clean_clone_check.py",
)


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
    return syntax_check()


def junit_stats():
    try:
        root = ET.parse(JUNIT).getroot()
    except (OSError, ET.ParseError):
        return None
    suites = list(root.iter("testsuite"))
    if not suites and root.tag == "testsuite":
        suites = [root]
    if not suites:
        return None
    totals = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for key in totals:
            try:
                totals[key] += int(suite.get(key, 0))
            except (TypeError, ValueError):
                pass
    return totals


def skip_reasons():
    """Aggregate the skip conditions recorded in JUnit XML, most common first."""
    try:
        root = ET.parse(JUNIT).getroot()
    except (OSError, ET.ParseError):
        return []
    counts = {}
    for node in root.iter("skipped"):
        raw = (node.get("message") or "no reason given").strip()
        msg = raw.splitlines()[0][:160] if raw else "no reason given"
        counts[msg] = counts.get(msg, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]


def write_summary(stats, reasons, fast):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not stats:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("## Test results\n\n")
        fh.write("- tests: %d\n" % stats["tests"])
        fh.write("- failures: %d\n" % stats["failures"])
        fh.write("- errors: %d\n" % stats["errors"])
        fh.write("- skipped: %d\n\n" % stats["skipped"])
        fh.write("JUnit XML: `output/ci/junit.xml`\n\n")
        fh.write("## Why tests were skipped\n\n")
        if reasons:
            for msg, count in reasons:
                fh.write("- %d x %s\n" % (count, msg.replace("\n", " ")))
        else:
            fh.write("- none\n")
        fh.write("\n")
        if fast:
            fh.write("`external` and `benchmark` tests were deselected with `-m`.\n\n")
        else:
            fh.write(
                "Full suite selected. External and benchmark markers are informational; "
                "pass `--fast` to deselect them during local iteration.\n\n"
            )


def step_test(fast: bool = False):
    JUNIT.parent.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, "-m", "pytest", "tests/", "-q", "--junitxml=" + str(JUNIT)]
    if fast:
        argv += ["-m", "not external and not benchmark"]
    rc = run("pytest", argv)
    write_summary(junit_stats(), skip_reasons(), fast)
    return rc


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
    ap.add_argument("--step", choices=("all", "static", "test", "build"), default="all")
    ap.add_argument(
        "--fast",
        action="store_true",
        help="deselect external and benchmark tests (local iteration only; CI runs the full suite)",
    )
    args = ap.parse_args()
    todo = list(STEPS) if args.step == "all" else [args.step]
    for name in todo:
        rc = STEPS[name](fast=args.fast) if name == "test" else STEPS[name]()
        if rc:
            return rc
    print("[ci-gate] OK: %s" % ", ".join(todo), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
