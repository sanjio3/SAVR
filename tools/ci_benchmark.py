"""Maintainer-only entry point for L1-L3 validation rounds.

An orchestrator, not a simulator: it validates inputs and the runner's
environment, forwards to tools/run_validation_round.py, optionally reconciles
with tools/benchmark_gate.py, and writes a report under output/benchmark/.
A failed precondition is reported and returned as a non-zero exit code; it is
never converted into a passing run.

    uv run --frozen python tools/ci_benchmark.py --tier L2 --profile jsc --name l2-round-1
    uv run --frozen python tools/ci_benchmark.py --tier L1 --profile jsc --name l1-probe --dry-run

This needs a self-hosted runner with the local targets, CodeQL CLI, an LLM
endpoint and a scan database. GitHub-hosted runners cannot satisfy it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = ROOT / "output" / "benchmark"
PROFILES = ROOT / "config" / "run_profiles.yaml"
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

TIERS = {
    "L1": {"timeout": 45, "scope": "single semantic change, smoke shard"},
    "L2": {
        "timeout": 180,
        "scope": "multiple semantic changes, or registration/confirmation paths",
    },
    "L3": {"timeout": 600, "scope": "release-grade full round"},
}
REQUIRED_ENV = ("SAST_AI_SHIRO_KEY", "YSO_JAVA_HOME")


def load_profiles() -> list[str]:
    import yaml

    data = yaml.safe_load(PROFILES.read_text(encoding="utf-8")) or {}
    return sorted((data.get("profiles") or {}).keys())


def build_round_cmd(args) -> list[str]:
    cmd = [
        sys.executable,
        "tools/run_validation_round.py",
        "--name",
        args.name,
        "--profile",
        args.profile,
        "--task-timeout-minutes",
        str(TIERS[args.tier]["timeout"]),
    ]
    if args.truth:
        cmd += ["--truth", args.truth]
    if args.no_submit:
        cmd += ["--no-submit"]
    return cmd


def write_report(args, round_cmd, rc, missing_env, reconcile_cmd) -> None:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    payload = {
        "generated_at": stamp,
        "tier": args.tier,
        "scope": TIERS[args.tier]["scope"],
        "profile": args.profile,
        "name": args.name,
        "dry_run": args.dry_run,
        "round_command": " ".join(round_cmd),
        "round_exit_code": rc,
        "reconcile_command": " ".join(reconcile_cmd) if reconcile_cmd else "",
        "missing_environment": missing_env,
    }
    target = REPORT_ROOT / (args.name + ".json")
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [
        "# Benchmark report: %s" % args.name,
        "",
        "- tier: `%s` (%s)" % (args.tier, TIERS[args.tier]["scope"]),
        "- profile: `%s`" % args.profile,
        "- generated: %s" % stamp,
        "- dry run: %s" % args.dry_run,
        "- round exit code: %s" % rc,
        "",
        "## Commands",
        "",
        "```",
        " ".join(round_cmd),
        "```",
        "",
    ]
    if reconcile_cmd:
        lines += ["```", " ".join(reconcile_cmd), "```", ""]
    if missing_env:
        lines += ["## Missing environment", ""] + ["- `%s`" % k for k in missing_env] + [""]
    lines += [
        "Reports are CI artifacts only. Benchmark results are never committed to the repository.",
        "",
    ]
    (REPORT_ROOT / (args.name + ".md")).write_text("\n".join(lines), encoding="utf-8")
    print("[benchmark] report: %s" % target, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a maintainer validation round")
    ap.add_argument("--tier", choices=sorted(TIERS), required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--name", required=True, help="label used for the report file name")
    ap.add_argument("--truth", default="", help="optional truth table override")
    ap.add_argument("--task-id", type=int, default=0, help="optional scan task to reconcile")
    ap.add_argument(
        "--dry-run", action="store_true", help="validate inputs and print the plan only"
    )
    ap.add_argument(
        "--no-submit", action="store_true", help="check gates without submitting a scan"
    )
    args = ap.parse_args()

    if not SAFE_NAME.fullmatch(args.name):
        print(
            "[benchmark] invalid --name: use letters, digits, dot, dash or underscore", flush=True
        )
        return 2
    profiles = load_profiles()
    if args.profile not in profiles:
        print(
            "[benchmark] unknown profile %r; available: %s" % (args.profile, ", ".join(profiles)),
            flush=True,
        )
        return 2

    missing_env = [k for k in REQUIRED_ENV if not os.environ.get(k)]
    round_cmd = build_round_cmd(args)
    reconcile_cmd = []
    if args.task_id:
        reconcile_cmd = [
            sys.executable,
            "tools/benchmark_gate.py",
            "--task-id",
            str(args.task_id),
            "--json",
        ]

    if args.dry_run:
        print("[benchmark] dry run; would execute: %s" % " ".join(round_cmd), flush=True)
        if reconcile_cmd:
            print("[benchmark] then: %s" % " ".join(reconcile_cmd), flush=True)
        if missing_env:
            print("[benchmark] would require: %s" % ", ".join(missing_env), flush=True)
        write_report(args, round_cmd, 0, missing_env, reconcile_cmd)
        return 0
    if missing_env:
        print(
            "[benchmark] refusing to run; required environment is unset: %s"
            % ", ".join(missing_env),
            flush=True,
        )
        write_report(args, round_cmd, 3, missing_env, reconcile_cmd)
        return 3

    print(
        "[benchmark] tier=%s profile=%s name=%s" % (args.tier, args.profile, args.name),
        flush=True,
    )
    rc = subprocess.call(round_cmd, cwd=str(ROOT))
    if rc == 0 and reconcile_cmd:
        rc = subprocess.call(reconcile_cmd, cwd=str(ROOT))
    write_report(args, round_cmd, rc, missing_env, reconcile_cmd)
    return rc


if __name__ == "__main__":
    sys.exit(main())
