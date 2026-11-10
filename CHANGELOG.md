# Changelog

All notable changes to this project are documented here. Format follows
Keep a Changelog; this project has not yet cut a release tag.

## [Unreleased] - 2026-11-08

### Added

- `tools/ci_gate.py`: ruff lint and format checks on first-party tooling, a `--fast`
  switch to deselect external/benchmark tests, and a skip-reason breakdown in the
  CI step summary.
- `tools/clean_clone_check.py`: runs the full gate in a pristine detached HEAD
  worktree, so distribution-surface gaps fail locally instead of on a contributor's
  first clone.
- `tools/ci_benchmark.py` and `.github/workflows/benchmark.yml`: maintainer-only
  L1-L3 trigger on a self-hosted runner, with reports uploaded as CI artifacts.
- `.github/workflows/release.yml`, `.github/CODEOWNERS`, `.github/dependabot.yml`
  and a `compat` matrix in `ci.yml` (Python 3.13 and Windows, informational only).

### Changed

- `tests/test_d2_spec_association.py`: the empty-status spec regression guard now
  uses an in-memory SQLite fixture instead of historical rows in `data/app.db`, so
  it runs on a fresh clone with no database.
- Eight test modules that require local target sources are marked `external`. The
  default gate still runs the full suite; `--fast` is opt-in.
- `.gitignore` now covers config and secret filename variants plus test output.
- Both CONTRIBUTING files document the benchmark workflow, the clean-clone check,
  branch naming versus branch protection, and the no-test-records rule.

### Fixed

- `confirm_gate_recheck` late-evidence recovery now only promotes specs whose
  `expected_sink_file` matches a truth-table `file` entry. Out-of-scope genuine
  sinks (e.g. `TomcatFilterMemShell` writing a class file via
  `RandomAccessFile`) are recorded as `sink_reached` instead of
  `confirmed_exploitable`, so they no longer register as red-line false
  positives. Verified against the R0 re-scan: red line 0/62, replay 24/24 intact.
- `progress_logger.py`: atomic replacement of the markdown progress file now
  retries with backoff and falls back to an in-place write; a transient Windows
  file lock no longer fails an otherwise complete scan.
- `tools/run_validation_round.py`: added `--truth` passthrough so the four-tier
  reconciliation can use a non-default truth table (required for the RuoYi
  cross-target round). Default behaviour is unchanged.
- `a2_integrated_analyst.py`: the A2 integrated analyst no longer uses a
  hard-coded 180-second socket read timeout. The timeout is configurable via
  `SAST_AI_A2_LLM_TIMEOUT` (default 300s, aligned with `a2_ai_agent`);
  transport failures are retried with backoff (`SAST_AI_A2_LLM_RETRIES`,
  default 2), and consecutive exhaustion trips a circuit breaker
  (`A2LLMUnavailable`) so an unavailable Ollama fails the round fast instead of
  slowly producing empty files. Prompt, temperature, seed and output contract
  are untouched, so LLM verdicts do not drift.
- `benchmark_cli.py`: a per-file A2 failure is no longer swallowed as
  `specs = []`. It is recorded as an `analysis_error` placeholder plus
  `stage_results.a2.contract.file_failures` / `transport` counters, so a round
  with LLM-unavailable files can be rejected as invalid. The fallback
  concurrent path now defaults to 2 workers (matching `OLLAMA_NUM_PARALLEL=2`)
  and retries failed files serially once.
- `tools/generalization_compare.py`: reads `pre_registered_exceptions` from
  `config/generalization.yaml`, matching by layer + `(file_basename, family)`
  and enforcing `max_count_per_round` per red-line spec. Added `--config` and
  `--no-exceptions`; JSON output now exposes `gate.redline_pass`.
- `a2_integrated_analyst.py`: capped generation with `options.num_predict`
  (default 1024, `SAST_AI_A2_LLM_NUM_PREDICT`). With `stream=False` + JSON
  grammar and no cap, qwen3:8b occasionally never emits EOS, so generation
  runs to `num_ctx` and the server does not return until the socket read
  timeout. Socket read timeouts are now classified as generation timeouts and
  are **not retried** (re-sending the same prompt cannot complete faster);
  only connection-layer errors keep the bounded retry / circuit breaker.
  `transport` exposes `generation_timeouts` and `truncated`.
- `benchmark_cli.py`: the per-file retry no longer re-runs a generation timeout,
  preventing a single stuck file from consuming 15+ minutes (observed in an earlier invalid round).
  Prompt, temperature, seed, format and output contract are unchanged, so LLM
  verdicts do not drift; a real Ollama smoke call returned compliant JSON in
  6.59s with every transport counter at zero.
- `tools/generalization_compare.py`: `--json` no longer crashes with
  `TypeError: keys must be ... not tuple`. `measure()['attrib']` uses
  `(base, family)` tuple keys for the per-point attribution in `render()`, which
  `json.dump` cannot serialize. A new `to_jsonable()` normalizes tuple keys to
  `"base|family"` and sets/tuples to lists **at serialization time only**:
  measurement, rendering, red-line decisions and exception matching are
  untouched. Found during the real L1' blind-route reconciliation.
- `tools/check_effective_round.py`: the effective-round gate now also checks
  replay-layer target consistency. The first attempt at the second L3 round had
  an A2 contract byte-identical to R0'' / L3 run1 yet was misjudged EFFECTIVE:
  from 14:56 the 8080 port was taken over
  by another Spring Boot instance, 393 requests landed on a second generation of
  404 error body (ISO 8601 instead of the epoch timestamp), the 404 rate rose to
  18.3% across 20 endpoints and IAST events fell 21%. Two `ssrf.java/ssrf`
  `oracle:error_reflect` confirmations were lost, dropping replay from 24/24 to
  23/24. The gate now requires 404 rate <= 10%, <= 4 distinct 404 endpoints,
  <= 1 Spring error-body generation, IAST events > 0 and authenticated ratio
  >= 90%, fail-closed on missing data. `--no-replay-env` is for historical
  reference only and is marked as exempt. The first attempt at the second L3 round
  is now INVALID; R0'', L1' and L3 run1 remain EFFECTIVE (the L1 blind-route
  round needs no exemption). Thresholds
  are derived from five clean rounds, not tuned to make a round pass.

- `a2_integrated_analyst.py`: prompts are now bounded by a token budget
  (`SAST_AI_A2_PROMPT_TOKENS`, default 7000) before being sent to Ollama. The
  user prompt embedded the whole source file with no cap, so any file whose
  token count exceeded `num_ctx=8192` was rejected outright with
  `HTTP 400 request (N tokens) exceeds the available context size`. Token
  density, not file size, is what matters: a 26KB HTML file tokenises to 9,486
  tokens while a 34KB Java file fits. In the RuoYi cross-target round this
  silently failed 10 files and was recorded only as `file_failures`. Oversized
  sources are now windowed around the A1 finding lines (`_trim_code_to_budget`)
  with an explicit `... [omitted N lines] ...` marker, the attempt is counted as
  `code_trimmed`, and the prompt template, temperature, seed, `num_ctx`,
  `num_predict` and the output contract are untouched. Files already within
  budget take the previous code path byte-for-byte — the largest of the 92
  Java-sec-code files estimates 6,361 tokens, so every earlier jsc round
  (R0'' / L1' / L3 run1 / L3 run2') remains a valid measurement of this code.
- `a2_integrated_analyst.py`: the prompt token budget self-corrects when the
  server disagrees. `_est_tokens` is `len // 3`, which is optimistic for dense
  HTML/SQL (measured down to ~2.5 chars/token), so one 180KB file still hit
  `HTTP 400 ... exceeds the available context size` after being windowed. A 400
  whose body mentions the context size now halves the budget and re-windows
  (up to two attempts); any other 4xx is re-raised unchanged. Verified on that
  file: 179,686 → 12,475 chars still rejected, 5,864 chars accepted.
- `tools/check_effective_round.py`: the replay-layer 404 profile is now scoped
  per target workspace instead of using the jsc thresholds everywhere.
  `REPLAY_PROFILES` maps workspace 4 to 10% / 4 endpoints and workspace 8 to
  20% / 8 endpoints; unknown workspaces fall back to the strict default and
  every verdict prints the profile name. Rationale: in the RuoYi round all 138
  404s landed on five routes that A2 inferred from utility-class method names
  (`exportExcel`, `loadYaml`, `address`, `upload`, `nameUUIDFromBytes`) and that
  the application does not expose — zero touched the six in-scope truth points,
  so the old threshold was measuring route-inference quality rather than a
  change of target identity. The target-agnostic checks (single error-body
  generation, IAST liveness, authenticated ratio) are unchanged, and the first
  attempt at the second L3 round is still INVALID under the new profile
  (18.3% > 10%, 20 > 4 endpoints, two
  error-body generations); the same fingerprint evaluated under workspace 4
  also still fails.
- `tools/generalization_compare.py`: the measure denominator is now the number of
  distinct `(file, family)` truth points instead of the number of truth-table
  rows. In the RuoYi table three of the six in-scope rows are the same
  `(file, family)` (`SysUserMapper.xml / sql_injection`, three different routes),
  while matching only resolves to `(file, family)`, so the numerator collapsed
  to 4 while the denominator stayed 6 and the tool printed `4/6`. The row count
  is still reported as `truth_rows`. Every Java-sec-code row is already a unique
  pair, so historical comparisons are unchanged (verified: R0''→L1' still
  `24/24 → 23/24 / 21/24`, L3 run1→L3 run2' still `24/24 → 23/24`).
- `tools/run_validation_round.py` / `tools/jsc_four_tier.py`: the four-tier
  readout is now pinned to the project interpreter. The round runner used
  `PY = sys.executable`, so a launch from a system Python without PyYAML made
  `jsc_four_tier.py` silently take three degradation branches at once
  (`normalize_family` not applied -> static file+family 30/31 -> 29/31;
  `is_dynamic_eligible` not applied -> dynamic denominator 24 -> 31; the four
  physically-unreachable exemptions lost). The runner also ignored the
  subprocess return code, so a degraded reading was written as the official
  artifact. `project_python()` now resolves the project `.venv` interpreter,
  a non-zero subprocess exit fails closed after persisting the evidence, and
  the chosen interpreter is logged. `jsc_four_tier.py` gained a
  `dependency_report()` preflight: missing `yaml` / `normalize_family` /
  `is_dynamic_eligible` now aborts with exit 2, and only an explicit
  `--allow-degraded` prints a reading, labelled as non-authoritative. Judgement
  and rendering logic are untouched; the database results were never affected.
  Only the L3 run2' artifact was contaminated (the nine earlier `*.four_tier.txt`
  files all used the correct 24-point denominator) and it was regenerated.

### Added

- `tests/test_confirm_gate_recheck_truth_scope.py`,
  `tests/test_validation_round_truth_passthrough.py`,
  `tests/test_a2_llm_transport_retry.py` (19 cases) and
  `tests/test_generalization_compare_exceptions.py` (11 cases) regression locks.
- `tests/test_check_effective_round.py` (14 cases) and
  `tools/check_effective_round.py`: executable, fail-closed Gate 0 effective-
  round check. A round counts only when it completed, `file_failures` and
  `transport.{exhausted, generation_timeouts, circuit_broken}` are zero, and
  `transport.truncated` is present. Missing fields are INVALID; a non-zero
  `truncated` produces a warning that requires per-file reconciliation instead
  of vetoing the round.
- Release gate criteria (`docs/gate0_release_criteria.md`) and the per-round
  reconciliation notes for the generalization validation (R0 re-scan, L1
  blind-route re-run, the R0' invalid-round post-mortem and final A2 root
  cause, R0'' effective-round and four-tier acceptance, L1' blind-route
  acceptance), shipped under `docs/`.
- `tests/test_generalization_compare_json.py` (5 cases): regression lock for
  the `--json` payload, including tuple-key attribution, nested sets, and the
  combined case with a real pre-registered exception.
- `tests/test_check_effective_round_replay_env.py` (20 cases) and the L3
  run2 invalid-round post-mortem (`docs/`): regression lock and post-mortem for
  the replay-layer target-takeover invalid round.
- L3 run1 reconciliation notes (`docs/`: L3 run1 red-line halt,
  `log4j.java/xss` four-round spec comparison and the approved exception-scope
  correction) and L3 run2' reconciliation notes (`docs/`: L3 run2'
  acceptance, the two-round stability verdict, the `ssti.java/ssti`
  attribution and the interpreter-drift post-mortem).
- `tests/test_four_tier_interpreter_guard.py` (9 cases): regression lock for
  interpreter binding, `.venv` fallback, subprocess fail-closed behaviour and
  the degraded-reading guard.
- `tests/test_generalization_compare_denominator.py` (3 cases): regression lock
  for the numerator/denominator granularity, including the real Java-sec-code
  table having no duplicate `(file, family)` pair.
- `tests/test_a2_prompt_budget.py` (12 cases): regression lock for the prompt
  token budget — in-budget prompts stay byte-identical, oversized sources are
  windowed around the finding lines with the omission marker, the trimmed
  prompt lands back inside the budget, and every Java-sec-code file fits.
- `launch_ruoyi_full.py` can now attach the IAST probe to the RuoYi JVM.
  `SAST_RUOYI_PROBE=1` enables it; the probe token is read from the registered
  `iast_sessions` row for the workspace (only a prefix is logged), the jar is
  double-mounted (`-Xbootclasspath/a` + `-javaagent`) and configured with
  `sec.server.url` / `agent.id` / `app.name` / `app.packages`. Because the
  probe's own agent classes are Java 11 (class file version 55), attaching it
  requires `SAST_RUOYI_JAVA_HOME` to point at a JDK 11 runtime — the default
  stays JDK 8 and the probe stays opt-in, so historical behaviour is unchanged.
  Without this, the A0 environment-readiness gate correctly rejects the round
  (`ruoyi/ruoyi` probe offline), which is what happened to the RuoYi gate-rejection round.

### Changed

- The pre-registered exception `L1_log4j_xss` now applies to `L3_stability`
  in addition to `L1_blind_route` (approved by the user on 2026-11-08 after
  L3 run1 reproduced the same already-disclosed limitation). The
  original `L1_blind_route`-only scope assumed L3 / L2 would never see this
  red line; L3 run1 disproved that. **This is a scope correction for the same
  known limitation, not a new exception and not a relaxed red line**: matching
  is still strictly `(file_basename, family)`, at most 1 spec per round, and
  `L2_cross_target` remains non-exempt. The `confirmed_replay` definition,
  confirmation gate, truth table, `src/` and scan-side `run_env` are untouched.
  Re-running `--mode stability` for R0'' -> L3 run1 yields `1 raw -> 0 effective,
  pass` with `gate.redline_pass=true`. Added four regression cases covering
  L3 pass / L3 cap / L3 unrelated red lines still blocking / cross-target
  never exempt. See the L3 run1 reconciliation notes under `docs/`.

### Known Issues

- The A2 timeout diagnosis went through two corrections. The initial
  four-worker concurrency theory was disproved (the R0 re-scan / L1 blind-route re-run use the sequential
  `run_a2_integrated_scan` path). The retry approach was then disproved by
  an earlier invalid round: three groups of deterministic 300s timeouts, all six retries
  re-timing out, A2 reaching only 48/95 in 58 minutes. The final root cause and
  fix are described above and in the R0' invalid-round post-mortem under `docs/`.
- The effective-round gate was calibrated against the R0'' real A2 phase.
  `truncated` is now a required observability field (non-zero yields a warning)
  rather than a veto: the affected `ClassDataLoader.java` had been silently
  dropped by the old 180s timeout in every earlier round, while those rounds
  still reached red line 0 and replay 24/24. Accuracy remains guarded by
  `file_failures`, `exhausted`, `generation_timeouts` and `circuit_broken`,
  all of which must be zero. Every round must pass
  `tools/check_effective_round.py` before its red-line / replay figures count;
  rounds with warnings need a per-file reconciliation. This calibration only
  touched `tools/` and documentation, so the frozen `src/` baseline is intact.
  R0'' was the first full round to pass the final gate: EFFECTIVE with
  one `truncated=3` warning, red line 0/65, replay 24/24, gap 0.
- The earliest baseline rounds are historical references only. The R0 re-scan and
  L1 blind-route re-run lack the new instrumentation, and R0' is a non-completed
  invalid round. Changing `src/` again reset the frozen baseline to R0'', which
  has passed; L1' also passed and reproduces the historical R0 -> L1 deltas
  point-for-point. The chain is at L2 (R0'' -> L1' -> two L3 rounds -> L2).
  L3 has passed; the cross-target round has not run, so no cross-target
  capability claim may be made yet. See `docs/gate0_release_criteria.md`
  G0-1 / G0-3.
- The first attempt at the second L3 round is an invalid round: the
  8080 target was taken over by another application launched from a concurrent
  local session while the scan was running (404 rate 18.3%, 20 endpoints, mixed
  `epoch` + `iso` error bodies, IAST events -21%). Its 23/24 replay is an
  environment reading, not a variance measurement, and must not be cited; it is
  excluded from the stability verdict. The round was re-run as L3 run2' with the
  port exclusively owned by the instrumented `java-sec-code-1.0.0.jar`. See
  the L3 run2 invalid-round post-mortem under `docs/`.
- **L3 stability is bounded, not exact**: two same-configuration effective
  rounds gave replay 24/24 (L3 run1) and 23/24 (L3 run2'), i.e. a one-point /
  4.2pp spread. The single regression point is `ssti.java/ssti`: in L3 run1 the
  `d2_evidence.value_hit` gate recorded `hit_live / definitive=True` with
  `confirm_gate=runtime_arrival`, while in L3 run2' all three ssti specs stopped at
  `value_hit.hit=False / miss` and the related IAST events carried no
  `sink-reached-probe` record. This is the `confirm_gate_recheck` late-evidence
  channel — the same mechanism as the `log4j.java/xss` limitation — not an A2
  miss or an environment fault: L3 run2' had the highest `sink-reached-probe` (902)
  and `value_hit.hit=True` (22) counts of the four rounds, identical A2
  contracts, identical 6-item `run_env` and an identical replay-environment
  fingerprint. Release material must state 23~24/24 and must not claim
  "stable 100%". See the L3 run2' reconciliation notes under `docs/`.
- `log4j.java/xss` remains a real reflected XSS that the truth table does not
  register. It surfaced again in L3 run1 (`1/62`) because
  `confirm_gate_recheck` alternates between the `framework:` static channel
  (R0'' / L1' -> `confirmed_code_property`, excluded) and late IAST evidence
  recovery (L1 / L3 run1 -> `confirmed_exploitable`, counted). This is the
  late-evidence variance L3 is designed to measure, not a regression: L3 run1 had
  static 31/31, replay 24/24, zero regressions and an EFFECTIVE round. It is
  now handled by the approved exception scope above and must still be disclosed
  in the release notes as a limitation present in both L1 and L3.
- **L2 (RuoYi 4.5.1) first baseline is built** (EFFECTIVE): static
  `4/4` distinct `(file, family)` points (6/6 truth rows), dynamic `4/4` (6/6),
  runtime replay `2/4` (2/6 rows), red line `0/2`, confirmed false positives
  `0/7`. The four unconfirmed points are not misses: three are MyBatis `${}`
  static code-property confirmations whose boolean-blind SQLi oracle stayed
  `inconclusive / boolean_same`, and one reached the sink without D2 judging it
  harmful. Report it as "all six truth rows identified statically, two with
  runtime evidence", never as "only two vulnerabilities found".
- **A2 still infers routes for utility classes** (`ExcelUtil.exportExcel`,
  `YamlUtil.loadYaml`, …), which wasted about 13% of the replay budget in the
  RuoYi round (141 of 1046 attempts returned 404 on five routes the
  application does not expose). It does not distort the truth-point metrics,
  but D1 should verify a route against the entry inventory before sending
  traffic; tracked as follow-up.
- README capability statements still describe the pre-baseline (pre-R0'') state;
  the whole scan chain (R0'' → L1' → L3 → L2) now passes, so G0-6 is the next
  blocker.

## [Unreleased] - 2026-11-06

### Added

- Per-request D1 authentication guard with `auth_state` recorded on `DastImpact`
  and `replay_attempts.action_json`; login-wall detection, forced re-login, and
  logout-endpoint exemption (`SAST_AI_LOGOUT_PATHS`).
- `src/iast/spec_projection.py`: keeps `raw_json.exploit_spec.entry` in sync with
  the authoritative `trigger_specs` parameter columns across all I1 post-passes.
- `tools/jsc_four_tier.py`: strict `confirmed_replay` requires an actual
  `replay_attempts` row; legacy figures printed side by side for historical
  comparison; `--param-drift` audits entry/authority drift.
- `tools/check_oss_hygiene.py` and a matching CI gate for secrets, local absolute
  paths, internal notes and reproducibility files.
- `tools/generalization_compare.py`, `tools/jsc_make_blind_variant.py` and
  `config/generalization.yaml` for the three-layer generalization experiment
  (R0 and L1 executed; L3/L2 pending an oracle decision).
- Environment-first runtime configuration documented in `.env.example`,
  including network endpoints, probe token, JDK paths and local-target test root.
- `NOTICE`, `CODE_OF_CONDUCT.md`, `SBOM`, issue/PR templates and this changelog.
- Benchmark truth tables and the mini shard are now shipped so published numbers
  can be recomputed from a clean clone.
- `tools/prune_runtime_artifacts.py`: dry-run-first inventory and whitelist-protected
  cleanup of regenerable runtime artifacts; the production database, truth tables,
  blind variants and replay dumps are never touched.
- `tools/jsc_blind_switch.py`: reversible L1 target switch that swaps the running
  fat jar and workspace 4 `target_path` together, with an externalized state file
  and dry-run-by-default `blind` / `restore`.
- `tests/test_jsc_blind_variant_auth_paths.py`: regression lock ensuring the route
  blinder never rewrites `/login` or `/logout`.
- `--truth-addendum` in `tools/jsc_four_tier.py` and the batch tool
  `tools/truth_addendum_impact.py`: read-only shadow-truth accounting that quantifies
  how a proposed oracle change would shift every historical denominator. The shipped
  truth table is never modified and the shadow output is not an official reading.
- `config/truth_addendum_l1_log4j_xss.csv`: a PROPOSED / NOT ADOPTED truth row for
  the L1 reflected-XSS finding; four-task impact study in
  `docs/truth_addendum_impact_20261107.md`.
- `--scope class-only` in `tools/jsc_make_blind_variant.py`: blinds only class-level
  annotation first segments, keeping method-level full paths intact, so route-semantics
  priors can be isolated from path-structure changes. Implemented, not yet measured.
- `tests/test_truth_addendum.py` and `tests/test_jsc_blind_variant_class_only.py`.

### Changed

- `launch_stack.py` and `launch_java_quote.py` no longer contain a hard-coded
  probe token or developer-machine absolute paths; missing configuration now
  produces an explicit error instead of a silently useless session.
- Production code no longer seeds machine-specific JDK paths; JDK discovery uses
  `SAST_AI_JDK_ROOT` / `SAST_AI_JDK_CANDIDATES` plus standard install locations.
- Tests that need external target sources are gated on `SAST_AI_SDL_ROOT` and
  skip explicitly when it is unset, instead of passing only on one machine.
- `pyproject.toml` gained a PEP 517 build backend; CI also accepts the
  `pip install -r requirements.txt` path.
- `tools/jsc_make_blind_variant.py` now protects `/login` and `/logout` from route
  blinding and hard-fails if Spring Security login/logout literals are rewritten;
  its README and the L1 design doc now require switching the scanned source root,
  not just the target jar.
- Local-only watchdogs, archived one-off scripts, internal memory notes and
  build timestamp artefacts were removed from the git index (kept on disk).
- The hygiene gate also scans untracked files that `git add -A` would include, so
  newly added files can no longer bypass secret / local-path checks.
- `data/owasp_shards/shards/mini.json` now stores shard `files` as paths relative
  to the benchmark checkout; scope matching uses basename / case name and is
  unchanged. Three target-source tests derive their root from `SAST_AI_SDL_ROOT`.
- `.gitignore` was de-duplicated, `.pytest_tmp_*` is ignored, and historical
  one-off reports are excluded from distribution except the README-referenced docs.
- The L1 route-blinding run notes (`docs/`) record the first L1 route-blinding run:
  replay 21/24, strict replay 21/24, red line 1/47, and the finding
  that the extra "false positive" is a real reflected XSS that the truth table
  does not cover rather than a hallucinated family mismatch. The validation
  chain stopped there; L3 / L2 were not executed.
- The first L3 run1 attempt (now invalid) completed its data but ended `failed`
  on a Windows progress-file lock (now retried), replay 24/24 but a fresh red
  line `1/63` (the `tomcatfiltermemshell` FP that R0 had cleared regressed), and
  A1/A2 hitting the stage cache so CodeQL/LLM were skipped. It is not a valid
  stability run; a later L3 run replaced it.
- README, `config/generalization.yaml`, the L1 design doc and the shipped historical
  reconciliation notes now state the measured R0 / L1 results instead of
  the pre-execution "not executed / awaiting re-scan" wording. Historical notes keep
  their original text plus an explicit point-in-time status banner.
- `docs/generalization_validation_design.md`: corrected the claim that method-level
  sub-paths keep their semantics under `--scope class`; they are hashed too, so L1's
  -12.5pp is a combined upper bound.
- `config/generalization.yaml` and the run plan now require `SAST_AI_STAGE_CACHE=0`
  as a sixth `run_env` entry for any L3 re-run: with `src/` frozen, the stage cache
  key never changes and A1/A2 would silently skip CodeQL/LLM, flattening the very
  variance L3 is meant to measure.

### Fixed

- technique-oracle post-pass no longer skips HTTP-layer evidence when a spec's
  `iast_state` degrades to `no-arrival`.
- Confirmation gate no longer accepts a bare `impact_observed` boolean as
  semantic impact evidence; `matched_event_ids` proves arrival only.
- `bypass_variant` replay attempts now share the authentication guard and record
  `auth_state`.
- technique-oracle post-pass writes `impact_kind` and an observation summary next
  to `impact_observed`, so the strict confirmation gate can re-read the same
  evidence block instead of relying on a short-circuit.
- Progress markdown writes now retry the atomic replace on Windows
  `PermissionError` / `WinError 5` and fall back to an in-place write, so a transient
  file lock can no longer mark an otherwise complete scan as failed (first L3 attempt).
  JSON progress keeps its fail-closed semantics.

### Known limitations

- Generalization is only partially validated. R0 cleared the 629 red line
  to `0/61` with 24/24 replay; L1 measured a 12.5pp replay drop with one
  red-line FP (`1/47`). The first L3 run1 attempt completed its data but ended
  `failed` on a
  Windows progress-file lock and produced a fresh red-line FP (`1/63`); it also hit
  the A1/A2 stage cache and skipped CodeQL/LLM, so it is not a valid stability run.
  L3 re-run and L2 are halted pending confirmation. Detailed run evidence is
  kept in the local-only execution log (deployment paths and run_env values are
  not shipped with the repository).
- The L1 red line is a real reflected XSS at `Log4j.java` that the truth table does
  not register. `config/truth_addendum_l1_log4j_xss.csv` is a proposed, NOT ADOPTED
  truth row: adopting it would clear L1 to `0/47` but drop R0 from 24/24 to 24/25
  and shift every historical denominator. See `docs/truth_addendum_impact_20261107.md`.
- `--scope class-only` isolates class-level route semantics from path-structure
  changes but has not been used for a measured run; the 12.5pp L1 figure is an upper
  bound on both effects combined.
- H2 1.4.200 does not implement MySQL `SLEEP()`; SQL time-based probes cannot
  produce a delay on the h2 profile. SQLi confirmation relies on boolean pairs.
- This project is distributed from a clean snapshot: the published repository
  starts at a single initial commit and carries no development history. Never
  commit credentials; supply them through environment variables (see
  `.env.example`). The CI hygiene gate rejects hard-coded secrets, private keys
  and development-machine absolute paths.
- Two historical `app.db.bak-*` snapshots (15.2 GiB) are intentionally retained
  pending explicit confirmation; regenerable runtime artifacts (about 38 GiB)
  were already removed.
