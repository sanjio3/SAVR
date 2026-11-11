## What this changes

<!-- One or two sentences: the user-visible effect of this change. -->

## Why

<!-- The problem this solves, or the issue it closes. -->

## How it was verified

<!-- The commands you ran and what you observed. -->

- [ ] `uv run --frozen python tools/ci_gate.py` passes
- [ ] Frontend rebuilt (`cd frontend && npm run build`) if UI changed
- [ ] No credential, local path, database or scan target is included

## Notes for the reviewer

<!-- Anything that is risky, slow, or worth a second look. -->
