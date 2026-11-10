---
name: Bug report
about: Report a deterministic reproduction failure
title: "[BUG] "
labels: bug
assignees: ''
---

## What happened

Describe the observed behaviour. State whether it is a detection result
(a missed true positive / a false positive) or an engineering failure
(crash, hang, build error).

## Expected behaviour

What should have happened, and which published measurement or acceptance line
does that expectation come from?

## Reproduction

- Commit / version:
- Python version and OS:
- LLM provider and model:
- Target application and how it is started:
- Exact command(s):
- Relevant task id, if the issue comes from a scan:

If you are reporting a detection gap, include the four-tier output:

```bash
python tools/jsc_four_tier.py --task-id <id> --verbose
python tools/jsc_four_tier.py --task-id <id> --param-drift
```

## Evidence

Paste the relevant log lines, `replay_attempts` rows or `trigger_specs` fields.
Redact tokens, internal hostnames and absolute paths before posting.

## Scope note

This project does not ship target applications, JDKs, CodeQL binaries or a
pre-populated `data/app.db`. Issues that cannot be reproduced without those
external pieces should say so explicitly.
