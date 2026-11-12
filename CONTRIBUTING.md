# Contributing to SAVR

Thanks for taking the time. This file is intentionally short: everything below is
what you need to build, verify and propose a change.

## Set up

```bash
git clone https://github.com/sanjio3/SAVR.git && cd SAVR
uv sync --frozen --group dev
cd frontend && npm ci && cd ..
```

Python 3.12+, Node 20+ and JDK 11+ (only needed if you touch the probe) are
required. `uv` is the supported entry point for every Python command.

## Before you open a pull request

```bash
uv run --frozen python tools/ci_gate.py
```

That is the same gate CI runs: release hygiene checks, `ruff` over the whole
tree, a syntax pass over every distributed Python file, a core import smoke
test and the frontend production build. Everything it reports must be clean.

The regression suite is maintained outside this distribution, so `pytest` is
not part of the gate; the checks above are what CI enforces.

## Pull requests

- Branch from `main`, keep one topic per PR.
- Write the commit summary in the imperative mood; keep it short and specific.
- Describe what changes for a user, and how you verified it.
- Reference the issue it closes when there is one.

## What not to commit

`.env`, `config.yaml`, the SQLite database, scan output, your own scan targets
and any credential. `.gitignore` covers the common cases; the hygiene gate
rejects leaked keys and local absolute paths.

## Adding a vulnerability family

Families are declared in `config/families.yaml` and mapped to sinks in
`src/core/family_map.py`. Add the rule, the sink identity and the replay
evidence together — a family without a deterministic confirmation path will
only ever produce unconfirmed candidates.

## Working on the probe

`probe-java/` is plain Java with ByteBuddy. Build it with
`mvn -B -DskipTests -f probe-java/pom.xml clean package`, and produce the
bootstrap jar separately as documented in `probe-java/README.md`.
