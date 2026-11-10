# Contributing

English | [中文](CONTRIBUTING_zh.md)

Thanks for taking the time to contribute. This project is a security tool; correctness and
reproducibility matter more than speed of merging.

## Development setup

```bash
uv sync --frozen --group dev
uv run --frozen python tools/ci_gate.py
```

Requirements: Python 3.12+ and Node 20+. The gate is a single cross-platform script that
owns the environment variables and pytest arguments. CI runs the exact same command, split
into three steps (`--step static`, `--step test`, `--step build`). A full gate takes about
4 minutes and needs no LLM, no CodeQL CLI and no running target. `cp .env.example .env` is
only needed when you actually start the services.

For a single step use `uv run --frozen python tools/ci_gate.py --step test`. The test step
writes `output/ci/junit.xml`; in CI that file is uploaded as an artifact and a pass/fail
summary is written to the run page.

`uv.lock` is the authority for dependency versions. Never loosen it inside a feature PR;
dependency bumps arrive as separate PRs via Dependabot.

## Pull request rules

1. **Tests are mandatory.** Any change to `src/` must keep the full gate green
   (`uv run --frozen python tools/ci_gate.py`). Do not run only the files you touched — cross-stage
   regressions are common in this codebase and have shipped before.
2. **Keep the LLM on a leash.** The model may judge and write specs; it must not perform
   actions against a target. New behaviour that touches a target goes through the
   deterministic replayer.
3. **No new silent fallbacks.** If a capability is unavailable (missing binary, failed CodeQL
   build, absent probe event), degrade explicitly and record the reason. Never turn a failure
   into "no findings".
4. **Metrics need a denominator.** Report recall / precision / FP counts on a named shard,
   not "success rate". If you change detection behaviour, state the expected effect on the
   two calibration rows in the README (normal and blind layout).
5. **Chinese is fine.** Code comments and `docs/` may be Chinese. Keep identifiers and public
   interfaces in English.

## Validation tiers

The PR gate is L0 and is the only tier required for a pull request: CI runs
`uv run --frozen python tools/ci_gate.py` and all three checks must pass before merge.

L1-L3 below are maintainer-only benchmark re-runs. They need a local target, CodeQL CLI,
an LLM endpoint and a scan database, take roughly 1.5h and add ~600MB of database growth
per run. They are triggered manually, never block a PR, and their reports go to CI
artifacts instead of new files in the repository.

| Tier | When | Cost |
|---|---|---|
| L0 | every pull request | ~4 min (full gate: hygiene, compile, pytest, build) |
| L1 | small semantic change | ~15 min (20-case smoke shard) |
| L2 | ≥2 semantic changes, or anything touching registration/confirmation | ~1.5h (130-case shard) |
| L3 | release | hours (2740 cases) |

Batch semantic changes: up to three per L2 run, with the expected effect stated per item.

## Commit style

Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`). One logical change per
commit; include the task id when the change comes from a benchmark run.
