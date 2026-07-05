# Refactor 83D: HSS Subsecond Tail Latency

Date created: July 5, 2026

Status: planned.

## Goal

Reduce the remaining Ed25519 HSS registration tail after Refactors 83B and 83C:

- HSS advance: from about `542-561ms` toward `<400ms`.
- HSS finalize: from about `590-637ms` toward `<400ms`.
- Client artifact build (`ed25519EvaluationArtifactMs`): from about
  `471ms` toward `<400ms` — this is an HSS bucket, and once advance drops
  below it, it becomes the critical parallel leg.
- Total registration: toward `<2.2s` for Email OTP and `<2.5s` for passkey on
  the local intended Worker/WASM path.

Total-target arithmetic, stated up front so the scope is honest: hitting both
server bucket targets yields roughly `~2.4s` Email OTP / `~2.7s` passkey from
83D's own scope (advance drops below the `~471ms` artifact leg, so the
parallel section saves only `~90ms`; finalize saves `~237ms`). The final
`~250ms` to `<2.2s` / `<2.5s` lives in buckets outside this plan —
`ed25519ClientMaterialMs` (~410ms), `emailOtpEnrollmentMaterialMs` (~390ms),
`thresholdEd25519SigningSessionHydrationMs` (~300ms), and for passkey
`ecdsaRegistrationPersistenceMs` (~560-607ms) — plus the client artifact
work now included above. The `<2.2s`/`<2.5s` totals are reachable only if
Phase 4 spawns the follow-up refactor for those buckets; 83D alone is
expected to land near `~2.4s`/`~2.7s`.

This is a focused HSS state-format and protocol-boundary optimization plan. It
does not revive Cloudflare Containers, native sidecars, WebSocket pinning, or
process-local handle persistence.

Unlock is deliberately out of scope: its remaining `~2.4s`
`ed25519MaterialRestoreMs` (the largest single latency prize in the codebase)
belongs to a separate unlock migration onto the 83B advance/durable pattern,
not to this tail plan.

## Baseline

Latest post-cleanup intended benchmark, July 5, 2026:

| Flow | Total | Advance | Finalize | Advance source | Finalize source |
| --- | ---: | ---: | ---: | --- | --- |
| Email OTP, Tempo+Arc | `2,766ms` | `561ms` | `637ms` | `durable_workerd_wasm` | `durable_advanced_eval` |
| Passkey, Tempo+Arc | `3,122ms` | `542ms` | `590ms` | `durable_workerd_wasm` | `durable_advanced_eval` |

Representative advance split:

- WASM advance: `515-536ms`;
- serialized session materialize: `152-153ms`;
- message-schedule rounds: `184-196ms`;
- round-core rounds: `134-135ms`;
- persistence: `12-15ms`.

Representative finalize split:

- HSS finalize: `568-600ms`;
- serialized session materialize: `149-151ms`;
- output projection: `79-81ms`;
- report assembly: `83-85ms`;
- open server output: `159-160ms`;
- open seed output: `97-98ms`.

Trace files:

- `test-results/intended-lifecycle-traces/1783258261598-email_otp.registration-brisk-meadow-2vpm9x-intended-lifecycle-trace.json`
- `test-results/intended-lifecycle-traces/1783258267070-passkey.registration-cedar-quartz-xvm5rb-intended-lifecycle-trace.json`

## Constraints

- Keep the 83B durable advanced-eval and finalized-report correctness model.
- Do not persist WASM/native process handles.
- Do not add compatibility flags or alternate runtime paths.
- Keep serialized replay out of normal registration finalize.
- Optimize total elapsed registration time, not an isolated timing bucket.
- Keep unlock/session HSS replay changes out of scope unless a phase explicitly
  measures and scopes them.

## Hypotheses

1. The `~150ms` materialization cost appears in both advance and finalize. A
   lower-cost durable state encoding or checkpoint shape may reduce both.
2. The stage loops after the pool fix are now `~320-330ms` total. Further gains
   likely require Rust/WASM arithmetic and allocation profiling. The client
   artifact build shares the same crate code and runs at `~3.9x` its native
   cost (`471ms` vs `122ms` native post-pool-fix), so the same profiling
   likely pays there too.
3. Finalize still spends `~340ms` in output projection, report assembly, and
   output opening. Some of that work may be independent of the final client
   artifact and movable to advance — but only within the overlap budget
   (see Phase 3): advance runs in parallel with the `~471ms` client artifact
   build, so work moved into advance is free only while advance stays under
   that leg.
4. Registration total time is also affected by non-HSS buckets:
   `ed25519ClientMaterialMs`, `emailOtpEnrollmentMaterialMs`,
   `thresholdEd25519SigningSessionHydrationMs`, and (passkey)
   `ecdsaRegistrationPersistenceMs`. 83D only owns HSS buckets; per the
   total-target arithmetic in the Goal, those buckets need their own
   follow-up refactor for the `<2.2s`/`<2.5s` totals to close.

## Non-Goals

- Do not reintroduce `native_service` provenance or sidecar startup.
- Do not make Durable Object memory a correctness dependency.
- Do not store `preparedSessionHandle`, `stagedEvaluatorArtifactHandle`, or any
  other process-local HSS handle in D1/DO state.
- Do not merge Ed25519 and ECDSA record shapes.
- Do not weaken transcript/context/add-stage digest binding.

## Phase 0: Measurement Harness

- [ ] Add a focused HSS tail benchmark command that runs registration advance
      and finalize fixtures without full browser registration.
- [ ] Record per-stage allocation counts where the Rust/WASM boundary can expose
      them cheaply.
- [ ] Add trace summarization that prints:
      - materialize/decode;
      - add-stage response;
      - message-schedule rounds;
      - round-core rounds;
      - output projection;
      - output opening;
      - report assembly;
      - encode/persist.
- [ ] Keep intended registration traces as the user-visible validation gate.

Exit criteria:

- We can reproduce the `~550-600ms` buckets outside the browser.
- Every optimization below has before/after numbers from the same harness.

## Phase 1: Durable State Format And Materialization

- [ ] Inspect the current serialized `ServerEvalState` and prepared-session
      state sizes.
- [ ] Split materialization timing into decode, allocation, validation, and
      runtime object construction.
- [ ] Evaluate a compact durable advanced-state encoding that avoids rebuilding
      expensive runtime structures in finalize.
- [ ] Evaluate whether advance can persist a finalized runtime-neutral
      checkpoint that finalize can consume with less materialization work.
- [ ] Add corruption tests for any new encoding:
      - wrong context binding;
      - wrong add-stage digest;
      - wrong projection mode;
      - expired record;
      - truncated/corrupted bytes.
- [ ] Delete old state-shape code if the new encoding replaces it.

Exit criteria:

- Advance and finalize materialization each drop below `75ms`, or the doc
  records why the current encoding is already near the practical floor.

## Phase 2: Stage-Loop Rust/WASM Profiling

- [ ] Profile message-schedule and round-core loops after the pool fix.
- [ ] Identify remaining allocation, clone, and bounds-check hotspots.
- [ ] Check whether stage input/output buffers can be reused inside one advance
      operation without changing transcript semantics.
- [ ] Check whether `wasm-bindgen` data conversion copies dominate any stage.
- [ ] Profile the client artifact build path
      (`build_client_owned_staged_evaluator_artifact`, browser WASM) with the
      same lens: it shares the crate code, runs at `~3.9x` native, and becomes
      the critical parallel leg once advance drops below `~471ms`. Apply
      allocation/copy fixes that transfer; record the client bucket
      before/after in the intended traces.
- [ ] Add microbenchmarks for the stage loops with fixed deterministic inputs.
- [ ] Keep native benchmark comparison only as a reference signal; Worker/WASM
      remains the product path.

Exit criteria:

- Combined message-schedule plus round-core timing drops below `250ms`, or the
  doc records the next algorithmic bottleneck.
- `ed25519EvaluationArtifactMs` drops below `400ms`, or the doc records why
  the client build is already at its practical WASM floor.

## Phase 3: Finalize Output Projection And Opening

Overlap budget constraint: advance executes in parallel with the client
artifact build (`~471ms`, both start after the add-stage request is
prepared). Advance is the critical leg whenever it exceeds the artifact
build, so work moved from finalize into advance is free only while advance
stays under that leg — after Phases 1-2 land advance near `~390ms`, the
free budget is roughly `80ms`; beyond it, every moved millisecond is 1:1
bucket-shifting that the plan's own constraints forbid. Every Phase 3 move
must show total-elapsed improvement in the intended trace, not just a
smaller finalize bucket.

- [ ] Split `registrationHssFinalizeReportMs` into projection, packet assembly,
      output opening, and seed/key derivation if any sub-bucket remains hidden.
- [ ] Determine which finalize work depends on the full client artifact and
      which work depends only on durable advanced eval.
- [ ] Move artifact-independent finalize preparation into the advance record
      only if the transcript binding remains explicit and testable, and only
      within the overlap budget above (verify advance stays under the client
      artifact leg in the intended trace after each move).
- [ ] Evaluate specialized registration projection paths for:
      - `registration_seed_and_output`;
      - `registration_output_only`.
- [ ] Add tests proving moved work cannot be replayed across a different
      ceremony, add-stage request, projection mode, or authority.

Exit criteria:

- HSS finalize drops below `400ms`, or all artifact-dependent work is
  documented as the remaining floor.
- Advance remains under the client artifact leg after all Phase 3 moves, and
  the critical-path summary shows the total improved by at least the finalize
  reduction minus any advance growth.

## Phase 4: Total Registration Rebalance

- [ ] Rerun intended passkey and Email OTP Tempo+Arc registration benchmarks.
- [ ] Verify advance still starts before client artifact build.
- [ ] Verify the critical-path summary shows total elapsed improvement, not only
      bucket movement.
- [ ] Record any newly dominant non-HSS buckets and spawn the follow-up
      refactor the Goal arithmetic anticipates. Known candidates:
      `ed25519ClientMaterialMs` (~410ms), `emailOtpEnrollmentMaterialMs`
      (~390ms), `thresholdEd25519SigningSessionHydrationMs` (~300ms), and
      (passkey) `ecdsaRegistrationPersistenceMs` (~560-607ms).

Exit criteria:

- Email OTP registration is at or below the `~2.4s` in-scope expectation —
  `<2.2s` if the follow-up refactor has landed — or the remaining top buckets
  are recorded as outside 83D.
- Passkey registration is at or below the `~2.7s` in-scope expectation —
  `<2.5s` if the follow-up refactor has landed — or the remaining top buckets
  are recorded as outside 83D.
- Intended harness violations remain `[]`.

## Validation

Minimum validation for each implementation slice:

```text
pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.build.json --noEmit
pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit
pnpm build:sdk
node tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs
node tests/scripts/check-intended-behaviour-contract-boundaries.mjs
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts --reporter=line
```

Final validation:

```text
SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line
```

Record final trace paths and summary numbers in this document.
