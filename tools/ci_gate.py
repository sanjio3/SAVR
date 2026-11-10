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


def write_summary(stats):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path or not stats:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("## Test results\n\n")
        fh.write("- tests: %d\n" % stats["tests"])
        fh.write("- failures: %d\n" % stats["failures"])
        fh.write("- errors: %d\n" % stats["errors"])
        fh.write("- skipped: %d\n\n" % stats["skipped"])
        fh.write("JUnit XML: `output/ci/junit.xml`\n")


def step_test():
    JUNIT.parent.mkdir(parents=True, exist_ok=True)
    rc = run(
        "pytest",
        [sys.executable, "-m", "pytest", "tests/", "-q", "--junitxml=" + str(JUNIT)],
    )
    write_summary(junit_stats())
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
