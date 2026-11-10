# Contributing

English | [中文](CONTRIBUTING_zh.md)

Thanks for taking the time to contribute. This project is a security tool; correctness and
reproducibility matter more than speed of merging.

## Development setup

```bash
uv sync
cp .env.example .env
python -m pytest tests/ -q        # full suite, ~6-7 minutes
```

Requirements: Python 3.12+, Node 20+ for the frontend, CodeQL CLI on `PATH` for the static
stage. The LLM stage needs either a local Ollama instance or an OpenAI-compatible endpoint.

## Pull request rules

1. **Tests are mandatory.** Any change to `src/` must keep the full suite green
   (`python -m pytest tests/ -q`). Do not run only the files you touched — cross-stage
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

Re-runs against the benchmark are expensive (≈1.5h and ≈600MB of database growth per run).
Pick the smallest tier that can catch your regression:

| Tier | When | Cost |
|---|---|---|
| L0 | docs, comments, tooling, logging | seconds (`pytest -q` on touched files + `py_compile`) |
| L1 | small semantic change | ~15 min (20-case smoke shard) |
| L2 | ≥2 semantic changes, or anything touching registration/confirmation | ~1.5h (130-case shard) |
| L3 | release | hours (2740 cases) |

Batch semantic changes: up to three per L2 run, with the expected effect stated per item.

## Commit style

Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`). One logical change per
commit; include the task id when the change comes from a benchmark run.
