## Summary

What changed and why. Link the issue if there is one.

## Type of change

- [ ] Bug fix (deterministic reproduction attached)
- [ ] Detection capability change
- [ ] Engineering / tooling / docs
- [ ] Truth-table or measurement definition change

## Verification

- [ ] `python -m pytest tests/ -q`
- [ ] `python tools/check_oss_hygiene.py`
- [ ] `cd frontend && npm run typecheck && npm run build`
- [ ] Four-tier measurement recomputed if the change touches A1/A2/D1/D2

If a full re-scan was needed, state the task id and whether it was authorised.
Changes to detection logic must not be validated by re-running the tuning
target alone; see `docs/generalization_validation_design.md`.

## Measurement honesty

- [ ] No truth-table denominator was widened to make a number look better
- [ ] New oracles are family-general, not keyed to a specific test file
- [ ] Known limitations in README/CHANGELOG were updated if behaviour changed

## Hygiene

- [ ] No credentials, tokens, internal hostnames or developer absolute paths
- [ ] No generated databases, logs or one-off scripts added
- [ ] New environment variables are documented in `.env.example`
