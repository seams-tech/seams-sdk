# Registration Full-Flow Optimization

Date created: June 7, 2026

Status: browser benchmark harness implemented; full 5-run passkey smoke
baseline recorded with SDK, HSS, gated relay route substep timings, and
fine-grained hidden-eval worker diagnostics; retained HSS worker/session-handle,
finalize cached-session, and preauth registration-prepare route optimizations
now bring SDK registration p50 to about `1.6s` to `2.1s` across the smoke
scenarios. Refactor 88 later retired the runnable registration-flow benchmark
runner because it depended on a deleted managed-registration mock harness;
historical reports remain in `docs/benchmarks/registration-flow.md`.

## Goal

Benchmark the full wallet registration flow, get a reliable step-by-step latency
read, then optimize the largest measured buckets one at a time.

This plan covers the user-visible registration path from SDK call start through
usable wallet state:

```text
registration.registerPasskey(...) or Email OTP registration finalize
  -> local auth proof
  -> relayer registration ceremony
  -> Ed25519 HSS bootstrap
  -> optional ECDSA bootstrap
  -> NEAR account creation and key visibility
  -> relay persistence
  -> local IndexedDB/session persistence
  -> post-registration readiness checks
```

## Current Read

The repo already has useful partial signals:

- `benchmarks/threshold-load` measures warm threshold signing and explicitly
  excludes registration bootstrap.
- `docs/refactor-55-hss-optimize-registration.md` tracks HSS-specific
  registration optimization work.
- `client/src/SeamsWeb/operations/registration/registration.ts` logs a coarse
  `[Registration] wallet flow timings` summary.
- Server-side HSS prepare/respond/finalize timing logs exist for registration.

The current benchmark now separates the browser, SDK, HSS client worker, HSS
client fetch, and relay route substeps well enough to choose the next
optimization target without guessing.

June 8 latest retained read:

- Latest instrumentation run: `20260608-053047Z`, four smoke scenarios, five
  successful runs each.
- SDK registration total is now `1933ms` to `2134ms` p50 across the smoke
  scenarios.
- Browser-observed total is now `2816ms` to `3228ms` p50 across the smoke
  scenarios.
- The retained finalize cached-session fast path removed serialized
  server-session materialization from the normal product finalize path:
  `registrationHssFinalizeSerializedSessionMaterializeMs` moved from about
  `241ms` to `244ms` p50 to `0ms` p50.
- `/wallets/register/finalize` moved from about `455ms` to `462ms` p50 to
  `216ms` to `222ms` p50.
- SDK registration p50 improved by `266ms` to `484ms` versus the
  `20260608-030241Z` pre-finalize-cache baseline.
- Current HSS client artifact construction is `666ms` to `673ms` p50.
- `/wallets/register/start` remains `371ms` to `373ms` p50 because signing-root
  server-input derivation (`366ms` to `368ms` p50) and server-session
  preparation (`356ms` to `359ms` p50) run in parallel.
- `/wallets/register/hss/respond` is now visible and comparatively small at
  `94ms` to `109ms` p50.
- Next target: reduce client artifact construction, reduce both start-route
  branches together, or move one of those branches off the post-auth critical
  path. Optimizing only one start branch is unlikely to move the route p50 much
  because the sibling branch still dominates.

June 7 update:

- `benchmarks/registration-flow` now runs Playwright-backed passkey
  registration scenarios and writes versioned JSON plus markdown reports.
- SDK dev-build freshness now includes the shared Rust crates used by SDK WASM
  builds (`signer-core`, `ed25519-hss`, `ecdsa-hss`, and `threshold-prf`), so
  registration benchmarks invalidate the SDK build after HSS crate-only edits.
- Failed scenario commands now preserve their parsed summary in the benchmark
  artifact with `status: failed`; the runner still exits nonzero so failures
  remain visible to CI and local callers.
- The prepared-SDK 5-run smoke group completed locally with gated relay
  diagnostics:
  - `passkey_ed25519_only_wallet_iframe`: browser p50 `3,812ms`, SDK p50
    `2,435ms`, browser p95 `4,624ms`, SDK p95 `2,932ms`
  - `passkey_ed25519_and_ecdsa_wallet_iframe`: browser p50 `3,842ms`, SDK p50
    `2,486ms`, browser p95 `4,505ms`, SDK p95 `3,109ms`
  - `passkey_ed25519_only_host_origin`: browser p50 `3,524ms`, SDK p50
    `2,633ms`, browser p95 `3,535ms`, SDK p95 `2,640ms`
  - `passkey_ed25519_and_ecdsa_host_origin`: browser p50 `3,555ms`, SDK p50
    `2,665ms`, browser p95 `3,783ms`, SDK p95 `2,896ms`
- The Ed25519-only wallet-iframe smoke captured sanitized HSS timings:
  - HSS client `prepare`: p50 `380ms`, p95 `385ms`, `23,046` response bytes
  - HSS client `respond`: p50 `106ms`, p95 `117ms`, `419,361` response bytes
  - HSS worker `build_client_owned_staged_evaluator_artifact`: p50 `738ms`,
    p95 `748ms`, `464,999` request bytes, `154,567` response bytes
  - HSS worker `prepare_client_request`: p50 `126ms`, p95 `135ms`
- The Ed25519-only wallet-iframe relay route diagnostics show:
  - `/wallets/register/start`: p50 `376ms`, p95 `544ms`; dominated by
    `registrationHssPrepareMs` p50 `375ms`, p95 `444ms`
  - `/wallets/register/finalize`: p50 `457ms`, p95 `467ms`; dominated by
    `registrationHssFinalizeMs` p50 `457ms`, p95 `466ms`
- The largest measured SDK p50 buckets are now:
  - Ed25519 evaluation artifact: roughly `733ms` to `746ms`
  - wallet register start: roughly `381ms` to `688ms`
  - wallet register finalize: roughly `466ms` to `479ms`
  - auth proof: roughly `211ms` to `546ms`
- Next target: split `build_client_owned_staged_evaluator_artifact` into
  WASM-boundary substeps before changing the HSS algorithm or serialization
  path.
- A one-run wallet-iframe probe after adding substep diagnostics completed
  successfully (`20260607-132324Z`). It showed
  `build_client_owned_staged_evaluator_artifact` at `735ms` total, with
  `buildArtifactMs` at `638ms`, `materializeSessionMs` at `90ms`, and
  encode/decode work near measurement noise. This points the next optimization
  at the hidden-eval artifact build itself, with runtime materialization as a
  smaller secondary target.
- A follow-up one-run probe with hidden-eval stage profiling completed
  successfully (`20260607-132826Z`). The `638ms` artifact-build bucket split
  into `hiddenEvalTotalMs` `604ms`, led by `hiddenEvalRoundCoreMs` `286ms` and
  `hiddenEvalOutputProjectorMs` `253ms`; `hiddenEvalMessageScheduleMs` was
  `59ms`.
- The full smoke group with hidden-eval stage profiling completed successfully
  (`20260607-133021Z`): all 4 scenarios passed, 20/20 registrations succeeded,
  and `docs/benchmarks/registration-flow.md` was synced. The stable next target
  is the client-owned hidden-eval core:
  - wallet iframe, Ed25519 only: `hiddenEvalTotalMs` p50 `634ms`,
    `hiddenEvalRoundCoreMs` p50 `298ms`, `hiddenEvalOutputProjectorMs` p50
    `264ms`, `materializeSessionMs` p50 `94ms`
  - host origin, Ed25519 only: `hiddenEvalTotalMs` p50 `616ms`,
    `hiddenEvalRoundCoreMs` p50 `289ms`, `hiddenEvalOutputProjectorMs` p50
    `263ms`, `materializeSessionMs` p50 `92ms`
- The first output-projector algebra simplification candidate was rejected:
  it removed one field addition but failed
  `protocol_validation::prime_order_succinct_hss_rejects_client_output_with_mismatched_value_kind`.
  The candidate was reverted before benchmarking.
- A retained label-buffer optimization completed successfully
  (`20260607-135114Z`): all 4 scenarios passed, 20/20 registrations succeeded,
  and `docs/benchmarks/registration-flow.md` was synced. The change keeps the
  same transcript label bytes and gate schedule while replacing per-bit
  `format!` allocations in local bit-word addition loops with a reusable label
  buffer. It is below the full-flow keep threshold, but is small and improved
  the wallet-iframe HSS p95 path:
  - wallet iframe, Ed25519 only: `ed25519EvaluationArtifactMs` p95
    `788ms -> 747ms`, `hiddenEvalTotalMs` p95 `648ms -> 612ms`,
    `hiddenEvalRoundCoreMs` p95 `309ms -> 293ms`,
    `hiddenEvalOutputProjectorMs` p95 `268ms -> 255ms`
  - wallet iframe, Ed25519 plus ECDSA: `ed25519EvaluationArtifactMs` p95
    `795ms -> 738ms`, `hiddenEvalTotalMs` p95 `653ms -> 607ms`,
    `hiddenEvalRoundCoreMs` p95 `309ms -> 287ms`,
    `hiddenEvalOutputProjectorMs` p95 `284ms -> 255ms`
  - host-origin scenarios were near noise: `hiddenEvalTotalMs` p95 moved
    `624ms -> 615ms` for Ed25519-only and `617ms -> 616ms` with ECDSA.
- A scoped worker-resident HSS session-handle optimization completed
  successfully (`20260607-142520Z`): all 4 scenarios passed, 20/20
  registrations succeeded, and `docs/benchmarks/registration-flow.md` was
  synced. The client worker now materializes the HSS client session during
  `prepare_client_request`, returns an ephemeral handle on that branch, consumes
  it in `build_client_owned_staged_evaluator_artifact`, expires stale handles
  after five minutes, and falls back to serialized state for direct/script
  runtimes. The retained result:
  - `materializeSessionMs` p50/p95 moved from about `91-95ms` to `0ms` in all
    four smoke scenarios
  - `build_client_owned_staged_evaluator_artifact` p50 moved:
    `736ms -> 688ms` for wallet-iframe Ed25519-only,
    `736ms -> 718ms` for wallet-iframe Ed25519+ECDSA,
    `734ms -> 686ms` for host-origin Ed25519-only, and
    `736ms -> 686ms` for host-origin Ed25519+ECDSA
  - SDK p95 moved `2959ms -> 2585ms`, `3033ms -> 2958ms`,
    `2591ms -> 2516ms`, and `2837ms -> 2563ms` across the four smoke scenarios
  - the remaining stable HSS target is now the hidden-eval core, especially
    `hiddenEvalRoundCoreMs` and `hiddenEvalOutputProjectorMs`; binary worker
    payloads remain a possible transport cleanup because the build request is
    still roughly `464KB`
- A second retained hidden-eval label-buffer cleanup completed successfully
  after a forced SDK/WASM rebuild (`20260607-144442Z`) and a repeat smoke run
  (`20260607-144642Z`): both runs passed all 4 scenarios, and the repeat run
  showed stable HSS worker wins versus the worker-handle baseline
  (`20260607-142520Z`). The change reuses child-label buffers in
  Boolean-to-arithmetic conversion helpers while preserving transcript label
  bytes and arithmetic shape. The repeat result:
  - wallet iframe, Ed25519 only: `hiddenEvalTotalMs` p50 `643ms -> 641ms`,
    p95 `657ms -> 650ms`
  - wallet iframe, Ed25519 plus ECDSA: `hiddenEvalTotalMs` p50
    `670ms -> 638ms`, p95 `676ms -> 642ms`
  - host origin, Ed25519 only: `hiddenEvalTotalMs` p50 `648ms -> 645ms`,
    p95 `656ms -> 651ms`
  - host origin, Ed25519 plus ECDSA: `hiddenEvalTotalMs` p50
    `649ms -> 641ms`, p95 `661ms -> 655ms`
  - full SDK p50 moved by `-26ms`, `-79ms`, `-6ms`, and `-72ms` across the
    four scenarios; full-flow p95 stayed within noise or improved
  - the next measurement step is to expose finer hidden-eval timing before
    deciding between binary worker payloads for the remaining roughly `464KB`
    staged-artifact request and a deeper executor-core change in the
    hidden-eval arithmetic loops
- The SDK build freshness fix was validated through the normal benchmark path:
  after a Rust-only HSS crate edit, `pnpm benchmark:registration-flow:smoke`
  rebuilt HSS WASM before running the browser benchmark.
- A follow-up output-projector reduce/select label-buffer candidate was
  rejected after smoke run `20260607-150450Z`. It passed the HSS protocol test
  suite, but the benchmark was weak and noisy: wallet-iframe Ed25519-only
  improved slightly while wallet-iframe Ed25519+ECDSA and host-origin
  Ed25519+ECDSA regressed in `hiddenEvalTotalMs` and full SDK time. The code was
  reverted and `docs/benchmarks/registration-flow.md` was restored to the last
  retained run (`20260607-144642Z`).
- Fine-grained hidden-eval worker diagnostics completed successfully in smoke
  run `20260607-152114Z`: all 4 scenarios passed, and
  `docs/benchmarks/registration-flow.md` was synced. The run exposed existing
  stage-profile fields through the WASM timing object without changing protocol
  behavior. The visible HSS latency ranking is:
  - `hiddenEvalRoundCoreMs`: p50 roughly `296ms` to `301ms`, p95 up to `308ms`
  - `hiddenEvalOutputProjectorMs`: p50 roughly `270ms` to `281ms`, p95 up to
    `287ms`
  - `hiddenEvalMessageScheduleMs`: p50 roughly `58ms` to `59ms`, p95 up to
    `61ms`
  - inside round core, `hiddenEvalRoundNewABitsMs` and
    `hiddenEvalRoundNewEBitsMs` are each about `45ms` to `46ms` p50,
    `hiddenEvalRoundMajMs` is about `38ms` to `39ms` p50, and
    `hiddenEvalRoundChMs` is about `31ms` to `32ms` p50
  - worker queue, decode, materialization, and encode are now secondary for
    this path; binary worker payloads remain useful transport cleanup, but the
    next latency-focused implementation should target the round-core A2B/carry
    conversion or boolean batch helpers
- The remaining top target is no longer a mechanical allocation cleanup. The
  next executor-core patch should start with a focused design/spec for the
  round-core A2B conversion and `ch`/`maj` boolean batch helpers, including the
  required transcript labels, provenance digests, gate schedule, and
  constant-time constraints. Implement only one candidate at a time after that
  design is explicit.
- The preauth HSS prepare route split and client overlap completed in smoke run
  `20260609-032110Z`: all 4 scenarios passed, and
  `docs/benchmarks/registration-flow.md` was synced. The server-side HSS
  prepare route is now fully overlapped in the measured passkey flows:
  - `walletRegisterPrepareWaitMs` is `0ms` p50 and p95 in all four smoke
    scenarios.
  - `registrationWarmupWaitMs` is `0ms` p50 and p95 in all four smoke
    scenarios.
  - `walletRegisterStartMs` remains single-digit p50 for the current
    host-origin and wallet-iframe scenarios (`6ms` to `7ms` p50).
  - `walletRegisterPrepareMs` is still roughly `375ms` to `377ms` p50, but it
    is no longer observed as a post-authority wait in the SDK flow.
  - current SDK p50 is `1989ms` wallet-iframe Ed25519-only, `2026ms`
    wallet-iframe combined, `1636ms` host-origin Ed25519-only, and `1692ms`
    host-origin combined.
  - next latency work should target Ed25519 client artifact construction,
    finalize, and wallet-iframe overhead rather than additional preauth HSS
    prepare overlap for the current passkey smoke path.

## Benchmark Questions

The first benchmark pass should answer:

- How long does passkey `ed25519_only` registration take end to end?
- How long does passkey `ed25519_and_ecdsa` registration take end to end?
- How much time is spent before `/wallets/register/start`?
- How much time is Ed25519 HSS client work versus relay work?
- How much time is optional ECDSA bootstrap and persistence?
- How much of `/wallets/register/finalize` is NEAR account creation, key
  visibility, and relay persistence?
- How much time is local IndexedDB/session persistence after finalize?
- Which bucket is stable enough to optimize first?

## Required Timing Buckets

The benchmark summary should include these buckets for every run.

Client-side buckets:

- `totalMs`
- `inputValidationMs`
- `registrationWarmupMs`
- `registrationWarmupWaitMs`
- `managedRegistrationGrantMs`
- `registrationIntentMs`
- `registrationIntentDigestMs`
- `authProofMs`
- `emailOtpEnrollmentMaterialMs`
- `ed25519ClientMaterialMs`
- `walletRegisterPrepareMs`
- `walletRegisterPrepareWaitMs`
- `walletRegisterStartMs`
- `ed25519ClientRequestMs`
- `walletRegisterHssRespondMs`
- `ed25519EvaluationArtifactMs`
- `emailOtpRecoveryCodeBackupMs`
- `walletRegisterFinalizeMs`
- `ed25519CompletionParseMs`
- `localWalletRegistrationPersistenceMs`
- `thresholdEd25519SessionPersistenceMs`
- `ecdsaRegistrationPersistenceMs`
- `walletStateActivationMs`
- `immediateSigningLaneAssertionMs`

Relay-side buckets:

- `registerStartTotalMs`
- `registrationHssPrepareMs`
- `registrationHssRespondMs`
- `registrationHssFinalizeMs`
- `nearAccountCreateMs`
- `nearKeyVisibilityMs`
- `relayAuthenticatorPersistenceMs`
- `relayCredentialBindingPersistenceMs`
- `relaySessionMintMs`
- `relayWalletPublicationMs`
- `registerFinalizeTotalMs`

The relay buckets come from structured response diagnostics that are stripped by
default and exposed only when the SDK sends the benchmark diagnostics header.

## Benchmark Artifact Shape

Add a dedicated benchmark output directory:

```text
benchmarks/registration-flow/out/<timestamp>/
  raw-summary.json
  summary.md
  passkey_ed25519_only.log
  passkey_ed25519_and_ecdsa.log
```

The machine-readable summary should be versioned:

```ts
type RegistrationFlowBenchmarkSummary = {
  reportVersion: 'registration_flow_benchmark_v1';
  generatedAt: string;
  environment: {
    sdkMode: 'source' | 'dist';
    browser: 'chromium';
    relayMode: 'local_relay_server';
    walletIframeMode: 'host_origin' | 'wallet_iframe';
    nearNetwork: 'testnet' | 'mocked';
  };
  scenarios: RegistrationFlowScenarioSummary[];
};
```

Each scenario summary should include count, min, mean, p50, p95, and p99 for
each bucket.

## Benchmark Harness Design

Create a registration-specific benchmark instead of extending
`benchmarks/threshold-load`. Threshold-load is a warm signing load harness, while
registration needs a real browser, WebAuthn mocks, IndexedDB, workers, and
optional wallet-iframe execution.

Historical target files:

- `benchmarks/registration-flow/src/scenario-harness.ts`
- `benchmarks/registration-flow/src/report.mjs`
- `benchmarks/registration-flow/src/runner.mjs`
- `benchmarks/registration-flow/src/scenarios.mjs`
- `benchmarks/registration-flow/README.md`
- `docs/benchmarks/registration-flow.md`

Historical package scripts:

```json
{
  "benchmark:registration-flow": "node ./benchmarks/registration-flow/src/runner.mjs",
  "benchmark:registration-flow:smoke": "node ./benchmarks/registration-flow/src/runner.mjs --group smoke",
  "benchmark:registration-flow:report-only": "node ./benchmarks/registration-flow/src/runner.mjs --skip-doc-sync"
}
```

The harness should reuse Playwright setup utilities where possible:

- `tests/setup/index.ts`
- `tests/setup/webauthn-mocks.ts`
- `tests/setup/fixtures.ts`
- existing e2e registration snippets that call `seams.registration.registerPasskey`

## Scenario Set

Start with passkey registration because it already has stable e2e coverage and
does not require Google/OIDC test credentials.

### Smoke

- [x] `passkey_ed25519_only_wallet_iframe`: 1 sequential registration probe.
- [x] `passkey_ed25519_only_host_origin`: 1 sequential registration probe.
- [x] `passkey_ed25519_only_host_origin`: 5 sequential registrations.
- [x] `passkey_ed25519_and_ecdsa_host_origin`: 5 sequential registrations.
- [x] `passkey_ed25519_only_wallet_iframe`: 5 sequential registrations.
- [x] `passkey_ed25519_and_ecdsa_wallet_iframe`: 5 sequential registrations.

### Extended

- [ ] 20 sequential passkey `ed25519_only` registrations.
- [ ] 20 sequential passkey `ed25519_and_ecdsa` registrations.
- [ ] 10 concurrent registration attempts with concurrency `2`.
- [ ] 10 concurrent registration attempts with concurrency `4`.

### Email OTP

- [ ] Add Google SSO Email OTP registration after the slim OTP registration
      flow has a deterministic local test authority.
- [ ] Include recovery-code backup timing as a first-class bucket.

## Phase 0: Add Canonical Timing Summary

Goal:

- make the SDK emit one typed timing summary for every registration attempt.

Work:

- replace the loose `Record<string, number>` timing object in
  `client/src/SeamsWeb/operations/registration/registration.ts`
- add a `RegistrationTimingSummary` discriminated union
- wrap every awaited boundary listed in `Required Timing Buckets`
- emit one console line:

```text
[Registration] wallet timing summary
```

Acceptance:

- [x] success and failure summaries share the same top-level shape
- [x] diagnostics are observational and cannot influence control flow
- [x] passkey and Email OTP auth-specific timing branches cannot be mixed
- [x] focused registration orchestration test covers the timing-summary shape
- [x] `pnpm -C sdk type-check` passes

## Phase 1: Build The Browser Benchmark Harness

Goal:

- run full registration flows repeatedly and extract the timing summaries into a
  stable report.

Work:

- [x] create `benchmarks/registration-flow`
- [x] launch Chromium with existing Playwright setup
- [x] run selected scenarios with fresh account ids
- [x] collect browser console HSS client timing summaries
- [x] write `raw-summary.json` and `summary.md`
- [x] sync latest summary into `docs/benchmarks/registration-flow.md`
- [x] sanitize HSS timing capture to keep aggregate durations and byte counts
      without raw key IDs or ceremony handles
- [x] collect SDK registration timing summaries from the browser path
- [x] include SDK WASM dependency crates in dev-build freshness checks

Acceptance:

- [x] one-run `passkey_ed25519_only_wallet_iframe` smoke completes locally
- [x] one-run `passkey_ed25519_only_host_origin` smoke completes locally
- [x] 5-run `passkey_ed25519_only_wallet_iframe` smoke completes locally
- [x] full 5-run smoke group completes locally
- [x] every successful run emits exactly one SDK registration timing summary
- [x] summary contains median and p95 for all required client buckets
- [x] failed registrations are included with failure status and partial timings

## Phase 2: Capture Baseline

Goal:

- establish the baseline before any optimization.

Work:

- use the retained `benchmark:registration-flow:smoke` baseline as historical
  evidence
- run the replacement real-topology registration latency benchmark once it
  exists
- run the extended sequential profiles
- record local machine, browser, relay mode, SDK mode, and date
- identify top three stable buckets by p50 and p95

Acceptance:

- [x] 5-run wallet-iframe mini-baseline summary is committed under
      `docs/benchmarks/registration-flow.md`
- [x] full smoke baseline summary is committed under
      `docs/benchmarks/registration-flow.md`
- [x] top three latency buckets are listed in this plan
- [x] relay substep diagnostics explain `walletRegisterStartMs` and
      `walletRegisterFinalizeMs` before route-shape optimizations begin

## Phase 3: Optimize The Largest Stable Bucket

Candidate buckets based on current code shape:

- work before `/wallets/register/start`
- Ed25519 HSS client material and evaluation artifact work
- `/wallets/register/finalize`, including NEAR account creation and key
  visibility
- local persistence and immediate signing-lane assertion
- ECDSA bootstrap persistence when ECDSA is enabled

Keep rule:

- keep an optimization only if it improves median full registration time by at
  least `10%` or `500ms`, or if it is a very small simplification with a clear
  p95 win.

Work:

- [x] preserve parsed partial summaries when a scenario command exits after
      failed registrations
- [x] add WASM-boundary substep timings for the client-owned staged evaluator
      artifact builder
- [x] thread staged-artifact substep timings through HSS worker diagnostics
- [x] include HSS worker WASM substep timings in benchmark markdown reports
- [x] run a one-registration wallet-iframe probe to verify staged-artifact
      substep diagnostics reach the benchmark report
- [x] expose existing hidden-eval stage profiles for the client-owned
      role-separated artifact path
- [x] run a one-registration wallet-iframe probe to identify the dominant
      hidden-eval stages
- [x] rerun the smoke benchmark and record the staged-artifact substep read
- [x] choose the first code-moving optimization from the measured substep split:
      inspect the round-core and output-projector executor loops for low-risk
      allocation or recomputation reductions
- [x] test one output-projector optimization candidate and reject it on
      protocol-validation failure
- [x] implement one retained round-core/output-projector optimization candidate
- [x] rerun the smoke benchmark and keep or revert the retained candidate
- [x] choose the next structural optimization candidate from the remaining
      largest stable buckets
- [x] implement scoped worker-resident client HSS handles for
      `prepare_client_request` to staged-artifact build
- [x] add worker-handle expiry and consume the build handle after use
- [x] rerun the smoke benchmark and keep the worker-resident handle candidate
- [x] choose the next hidden-eval core optimization candidate from
      `hiddenEvalRoundCoreMs` and `hiddenEvalOutputProjectorMs`
- [x] test and retain a second low-risk hidden-eval label-buffer cleanup in
      Boolean-to-arithmetic conversion helpers
- [x] test and reject an output-projector reduce/select label-buffer cleanup
      after the smoke benchmark produced weak/noisy results
- [x] expose fine-grained hidden-eval substage timings through worker
      diagnostics
- [x] rerun the smoke benchmark and record the finer hidden-eval ranking
- [x] decide whether binary worker payloads should precede more executor work:
      keep them as a transport cleanup, but prioritize hidden-eval executor work
      for latency because worker decode/encode/materialization are no longer
      dominant
- [x] choose the next deeper executor-core area after ranking it against binary
      worker payloads: round-core A2B/carry conversion first, then `maj`/`ch`
      boolean batch helpers
- [x] write a focused round-core A2B/boolean-helper optimization spec before
      changing protocol arithmetic
- [ ] implement one spec-backed executor-core candidate, rerun protocol
      validation, rerun the smoke benchmark, and keep only a meaningful win

Acceptance:

- [x] one optimization is implemented at a time
- [x] the benchmark is rerun with the same scenario set
- [x] the before/after comparison is added to the benchmark report
- [x] weak or noisy optimizations are reverted

## Phase 4: Relay Diagnostics

Goal:

- split `/wallets/register/finalize` into relay substeps when it remains one of
  the largest buckets.

Work:

- [x] add structured relay timing diagnostics at the route boundary or in server
  logs
- [x] keep diagnostics out of control flow
- [x] decide whether route responses may include benchmark diagnostics in dev/test
  mode, or whether the benchmark should parse relay logs

Acceptance:

- [x] relay diagnostics cannot expose secrets, token material, PRF outputs,
      client shares, recovery codes, or raw credential data
- [x] route response diagnostics are gated to benchmark/dev mode if they are
      returned to the browser
- [x] relay buckets are included in the benchmark summary

## Phase 5: Decide Optimization Order

After Phase 2 and any relay diagnostics from Phase 4, choose the next refactor in
this order:

1. A high-p50 bucket that affects every registration.
2. A high-p95 bucket that makes registration feel unreliable.
3. A bucket that is easy to move off the success path.
4. A bucket that requires route or lifecycle redesign.

Do not pick registration-start HSS prepare pipelining until the benchmark proves
that route sequencing is still a top contributor.

## Validation Ladder

For instrumentation-only changes:

```bash
pnpm -C sdk type-check
git diff --check
```

For benchmark harness changes:

```bash
# Run the replacement real-topology registration latency benchmark once available.
git diff --check
```

For behavior-changing registration optimizations:

```bash
pnpm -C sdk type-check
pnpm -C tests test:threshold-ed25519:active-path
# Run the replacement real-topology registration latency benchmark once available.
git diff --check
```

## Open Questions

- Should benchmark runs use wallet iframe mode by default, since that is the
  production embedding shape?
- Should the baseline use real testnet account creation, a mocked NEAR account
  creation path, or both?
- What is the acceptable registration success definition: finalize response
  returned, local wallet state active, or immediate signing lane verified?
