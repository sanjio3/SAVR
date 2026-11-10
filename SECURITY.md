# Security Policy

## Scope

`SAVR` is a defensive security tool. It analyses source code and replays requests against
targets you own or are authorised to test. Reports about the tool itself are welcome.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting (Security → Report a vulnerability) on this
repository. Include:

- affected version / commit
- reproduction steps or a minimal proof of concept
- impact assessment (what an attacker could do)

You can expect an acknowledgement within 72 hours and a remediation plan within 14 days for
confirmed issues. Please give us a reasonable window before public disclosure.

## Out of scope

- Findings produced **by** the scanner against third-party applications.
- Denial-of-service through intentionally pathological input files.
- Missing detections (those are tracked as regular issues, not vulnerabilities).

## Safe harbour

We will not pursue legal action for research conducted in good faith on your own
installations, provided you avoid privacy violations, data destruction and service
disruption, and you give us reasonable time to remediate before disclosure.

## Fixes and releases

Confirmed issues are fixed privately and shipped in the next `v*` tag. Release notes and
the SBOM are published by `.github/workflows/release.yml`; the report stays private until
that release is public. Do not attach reproduction material to a public pull request.

## Handling secrets

Never commit credentials. The repository ignores `.env`, `config.yaml` and runtime databases.
Agent tokens are injected through environment variables (`SAST_AI_AGENT_TOKEN`); if you find
a hard-coded credential anywhere in the tree, treat it as a vulnerability and report it
privately.
