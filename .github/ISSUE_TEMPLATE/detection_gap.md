---
name: Detection gap
about: Report a missed true positive or a false positive with truth-table evidence
title: "[DETECTION] "
labels: detection
assignees: ''
---

## Classification

- [ ] Missed true positive (a truth-table point was not detected)
- [ ] Red-line false positive (a `confirmed_replay` spec outside the truth set)
- [ ] Confirmation-level false positive (any `confirmed` spec outside the truth set)

## Truth reference

Which truth table and which row? Give `(file basename, family)` and the scope
(`in_scope`, physical-unreachable exemption, or property/config family).

## Measurement

Paste the four-tier output for the task:

```bash
python tools/jsc_four_tier.py --task-id <id> --verbose
```

Under the current definition, `confirmed_replay` means
`verification_status == confirmed_exploitable`, a non-`framework:` evidence rule,
and at least one `replay_attempts` row. Do not quote legacy figures as current.

## Failure tier

Where does the point stop?

- `spec` (no candidate registered)
- `payload_unavailable` (A2 produced nothing replayable)
- `no-arrival` (request sent, sink not reached)
- `sink-reached` (sink reached, impact not confirmed)

Include `oracle_state` / `oracle_signal` / `iast_state` / `auth_state` if
available. Login-wall 302s, target restarts and probe disconnects are execution
layer faults, not detection gaps.

## Guards

A new family-specific oracle is not an acceptable fix by itself. Proposals
should explain how they generalise to an unseen target.
