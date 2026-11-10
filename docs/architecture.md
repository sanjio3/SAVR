# Architecture

## Overview

The repository is now split into:

- `frontend/`: Vue 3 UI for workspace, task, findings, and report views
- `src/api/`: FastAPI REST and WebSocket entrypoints
- `src/application/`: workspace/task orchestration services
- `src/infrastructure/`: SQLite database, repositories, task runner, event bus
- `src/pipeline/`: process-oriented backend modules for preprocessing, A1, A2, A3, and reporting
- `src/cli/`: service start command and isolated scan task runner

## Responsibility Boundaries

- Pages only render and trigger user actions.
- `frontend/src/services` owns REST and WebSocket communication.
- `frontend/src/domain` owns lightweight UI-facing business rules.
- `src/api` maps HTTP/WebSocket requests to application services.
- `src/application` coordinates use cases.
- `src/infrastructure` owns persistence and asynchronous execution.
- `src/pipeline` owns stage orchestration contracts, stage manifests, and stage service entrypoints.
- `src/agents` now focuses on stage-local implementation details and compatibility facades.
- Existing scan implementation remains the execution core and is wrapped by the new task runner.

## Stage Boundaries

- `src/pipeline/a1`
  - Owns the public A1 stage entrypoint and manifest.
  - Declares A1 skills as rule matching and context filtering.
  - Declares A1 tools as rule files and regex/context utilities.
- `src/pipeline/a2`
  - Owns the public A2 stage entrypoint and manifest.
  - Declares A2 skills as semantic reasoning and canonical re-anchoring.
  - Declares A2 tools as prompt packs, LLM clients, and code index context.
- `src/pipeline/a3`
  - Owns the public A3 stage entrypoint and manifest.
  - Declares A3 skills as env prep, attack planning, dynamic verification, and bundle output.
  - Declares A3 tools as runtime endpoints, exploit scripts, payload templates, Java helpers, ysoserial, and Docker runtime.

## Call Pattern

- CLI and orchestrator call `src/pipeline/*/service.py`.
- Pipeline services construct the correct stage implementation from `src/agents`.
- Agent modules do not decide global stage boundaries; they only implement one stage's local behavior.
- Stage manifests are centralized in `src/pipeline/*/manifest.py`, so skill/tool ownership is visible without tracing scattered imports.

## Task Flow

1. Create workspace
2. Create scan task
3. Task service allocates an output directory under `data/workspaces/...`
4. Task runner starts `python -m src.cli.scan_task_runner`
5. Existing benchmark flow writes reports and progress into the task output directory
6. Task runner persists findings/reports to SQLite and publishes task events
7. Frontend consumes state via REST and live events via WebSocket
