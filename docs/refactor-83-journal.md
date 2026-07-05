# Refactor 83 Journal

## Intended CI Harness Cache Isolation And Green Gate — July 5, 2026

The final intended lifecycle gate exposed reload flakes from local dev tooling
rather than registration logic. Wrangler and Vite were writing runtime files
inside watched workspace paths while the router worker was handling
registration, sealing, and Router A/B signing requests. Those writes could
restart the local worker mid-request and surface as 503s from
`/wallet-session/seal/apply-server-seal`,
`/router-ab/ed25519/sign/prepare`, or
`/router-ab/ecdsa-hss/export/share`.

Hardened the intended-services boundary:

- generated the D1-local Wrangler config under `.runtime/wrangler-d1-local`
  and passed it through `SEAMS_D1_LOCAL_WRANGLER_CONFIG`;
- moved local D1/DO persistence to the OS temp directory via
  `SEAMS_D1_LOCAL_PERSIST_TO`, with the repo-local `.runtime/intended-d1`
  path cleaned as stale state;
- made the server package D1 local scripts consume those environment variables
  for dev, migrate, and smoke commands;
- moved the site Vite cache to an OS temp directory through `VITE_CACHE_DIR`,
  so dependency prebundling no longer writes
  `apps/seams-site/node_modules/.vite` during intended runs;
- kept `.runtime/` ignored for generated local config artifacts.

Validation:

- `pnpm build:sdk` passed after the Router A/B ECDSA-HSS expiry and harness
  changes.
- `pnpm -C tests exec playwright test -c playwright.intended.config.ts
  --reporter=line
  e2e/intended-behaviours/passkey.registration.contract.test.ts` passed 1/1
  after the Wrangler runtime config moved out of `packages/sdk-server-ts`.
- `pnpm -C tests run test:intended:ci` completed with
  `tests/test-results/.last-run.json` reporting
  `{ "status": "passed", "failedTests": [] }`.
- Post-run process and port checks found no intended-services, Wrangler,
  Router A/B worker, Caddy, Vite, or intended Playwright processes listening on
  the managed local ports.

## Email OTP ECDSA Reauth Anchor From Canonical Candidate — July 5, 2026

The full intended gate exposed a post-step-up Email OTP failure after the
Phase 7B benchmark work: NEAR step-up succeeded, then the following Tempo sign
failed with `[SigningEngine][ecdsa] exhausted/expired lane did not produce a
reauth anchor`.

Root cause: the ECDSA prepare path selected a canonical `EcdsaLaneCandidate`,
but built the fresh-auth anchor from the projected available lane. That
projection can lose the exact policy state that made the canonical candidate
expired or exhausted. The anchor builder now consumes the canonical ECDSA lane
candidate directly, preserves `candidate.state` as the discriminant, and
normalizes exhausted anchors to zero remaining uses even when a stale source
counter is present.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  ./unit/signingSessionFreshness.unit.test.ts --reporter=line` passes 11/11.
- `pnpm build:sdk` passes.
- `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c
  playwright.intended.ci.config.ts
  e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line`
  passes 1/1.

The full `pnpm -C tests run test:intended:ci` wrapper did not reach the
contracts in this session: the Playwright-managed intended router exited during
startup twice, while `node tests/scripts/start-intended-services.mjs` reached
`site and router are ready` when run directly. Treat the full-wrapper failure as
a harness startup issue to rerun from a clean process table.

## Phase 7B Unlock Benchmark Matrix And Phase 9 Exit — July 5, 2026

Captured the remaining Email OTP unlock benchmark matrix against one fresh
intended-services stack after refreshing the Google token and rebuilding SDK/WASM
artifacts.

Commands:

```sh
SEAMS_INTENDED_PERSIST_TRACE=1 \
SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=none \
pnpm -C tests exec playwright test \
  -c playwright.intended.benchmark.config.ts \
  e2e/intended-behaviours/email-otp.unlock.benchmark.test.ts \
  --reporter=line

SEAMS_INTENDED_PERSIST_TRACE=1 \
SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=tempo \
pnpm -C tests exec playwright test \
  -c playwright.intended.benchmark.config.ts \
  e2e/intended-behaviours/email-otp.unlock.benchmark.test.ts \
  --reporter=line

SEAMS_INTENDED_PERSIST_TRACE=1 \
SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=tempo_arc \
pnpm -C tests exec playwright test \
  -c playwright.intended.benchmark.config.ts \
  e2e/intended-behaviours/email-otp.unlock.benchmark.test.ts \
  --reporter=line
```

All three passed 1/1.

Traces and core not-prewarmed unlock timings:

- `1783195830676-email_otp.unlock-violet-quartz-psqmbh-intended-lifecycle-trace.json`:
  Ed25519-only, total 5,001ms, `ed25519MaterialRestoreMs` 4,622ms,
  `emailOtpProofVerificationMs` 374ms.
- `1783195852065-email_otp.unlock-frost-summit-vx64pk-intended-lifecycle-trace.json`:
  Ed25519 plus Tempo, total 5,295ms, `ed25519MaterialRestoreMs`
  4,592ms, `signingSessionSealApplyMs` 270ms,
  `ecdsaMaterialRestoreMs` 48ms.
- `1783195871904-email_otp.unlock-cobalt-voyage-pfprt6-intended-lifecycle-trace.json`:
  Ed25519 plus Tempo plus Arc/EVM, total 5,651ms,
  `ed25519MaterialRestoreMs` 4,629ms, `signingSessionSealApplyMs`
  547ms, `ecdsaMaterialRestoreMs` 75ms.

The trace still emits a host-side iframe summary whose only non-zero bucket is
`walletIframeRoundTripMs`; the core not-prewarmed summary is the useful
optimization baseline. The matrix confirms the next latency target remains
Ed25519 material restore/server-HSS replay behavior, not ECDSA restore or
IndexedDB persistence.

Closed Phase 9 for Refactor 83 by accepting the residual server HSS replay as a
separate HSS execution-local DO/locality design. The current code has the
speed-oriented server WASM build, route sub-timings, and one full registration
server replay on the user-visible path. Same-DO HSS cache locality should be
planned as its own HSS latency refactor with explicit in-memory handle ownership
and failure semantics.

## Email OTP Ed25519 Unlock Iframe Routing — July 5, 2026

The Ed25519-only Email OTP unlock benchmark exposed an iframe storage-boundary
bug before it could be used as a timing baseline. Registration persisted the
wallet-bound Ed25519 signer rows in the wallet-service origin, while the
Ed25519-only login path tried to reconstruct the session from app-origin
IndexedDB. App-origin IndexedDB is intentionally disabled when
`wallet.mode === 'iframe'`, so both the exact wallet-subject lookup and the old
profile lookup returned no signers and unlock failed with
`missing_ed25519_key_identity`.

Fixed the routing asymmetry by adding a private wallet-iframe RPC for the
existing Ed25519 capability login path:

- `PM_LOGIN_EMAIL_OTP_ED25519_CAPABILITY` carries the same wallet-session,
  OTP, app-session, and authority-email payload needed by the existing
  Ed25519 login domain operation.
- The app-side Ed25519-only unlock path now mirrors the ECDSA iframe path:
  route to the wallet iframe, measure `walletIframeRoundTripMs`, and emit the
  app-level completion events only after the wallet-origin runtime returns.
- The wallet-iframe host calls the concrete `SeamsWeb`
  `loginWithEmailOtpEd25519CapabilityForWalletIframe()` method, which reuses
  the existing domain operation in wallet-origin mode. No public
  `AuthCapability` method was added.

Validation:

- `pnpm -C packages/sdk-web run build:sdk` passes.
- `SEAMS_D1_LOCAL_WASM_AUTO_BUILD=0 pnpm -C packages/sdk-server-ts run d1:local:ensure-wasm` passes after restoring generated WASM package outputs.
- The first `SEAMS_INTENDED_PERSIST_TRACE=1
  SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=none pnpm -C tests exec
  playwright test -c playwright.intended.benchmark.config.ts
  e2e/intended-behaviours/email-otp.unlock.benchmark.test.ts --reporter=line`
  attempt was blocked before registration because `/session/exchange` rejected
  the intended Google `id_token` as expired. The Phase 7B matrix entry above
  supersedes this with a refreshed token and a passing Ed25519-only unlock
  benchmark.

## Intended Services Startup Hardening — July 5, 2026

The intended benchmark startup failed intermittently when the router process
started `d1:local:ensure-wasm` and attempted a nested `build:wasm` while the
supervised SDK build was still producing package outputs. That race could clean
`wasm/near_signer/pkg*` under the router, then surface as
`router stopped before Playwright completed`.

Hardened the startup boundary:

- `ensure-d1-local-wasm.mjs` now supports
  `SEAMS_D1_LOCAL_WASM_AUTO_BUILD=0`, which turns it into a strict preflight
  check instead of a self-healing nested build.
- `start-intended-services.mjs` runs that D1 WASM preflight after the SDK build
  and starts the router with auto-build disabled.
- `tests/playwright.intended.benchmark.config.ts` runs only the benchmark specs
  against an already-running intended stack, so local benchmark slices do not
  invoke the CI web server lifecycle.

Validation:

- `node --check tests/scripts/start-intended-services.mjs` passes.
- `node --check packages/sdk-server-ts/scripts/ensure-d1-local-wasm.mjs` passes.
- `node tests/scripts/start-intended-services.mjs --check` passes.
- `SEAMS_D1_LOCAL_WASM_AUTO_BUILD=0 pnpm -C packages/sdk-server-ts run d1:local:ensure-wasm` passes after generated WASM package outputs are present.

## SDK WASM Package-Output Build Lock — July 5, 2026

The intended benchmark exposed a local build race: concurrent `build:sdk-full`
and standalone `build:wasm` runs both cleaned `wasm/*/pkg` outputs. One run
failed inside `wasm-opt` when another process removed `wasm/near_signer/pkg`,
and a later run failed in Rolldown because `build-sdk` tried to resolve
`../../wasm/near_signer/pkg/wasm_signer_worker.js` after another WASM build
cleaned it.

Added a shared build-output lock for the WASM package directories. It is held
by:

- standalone `build-wasm.sh` while it cleans and writes `wasm/*/pkg`
- standalone `build-sdk.sh` while it reads those package outputs
- `build-full.sh` across both WASM and SDK build steps
- `build-prod.sh` across its WASM and production bundling steps

Validation:

- `bash -n packages/sdk-web/scripts/build/build-output-lock.sh packages/sdk-web/scripts/build/build-wasm.sh packages/sdk-web/scripts/build/build-sdk.sh packages/sdk-web/scripts/build/build-full.sh packages/sdk-web/scripts/build/build-prod.sh` passes.
- `pnpm -C packages/sdk-web run build:wasm` passes, including a real wait for a pre-existing build lock holder.
- `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=none pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line` passes 1/1 after the lock change and token refresh.

## Email OTP Multi-Target ECDSA Registration Handles — July 5, 2026

The Google Email OTP combined `tempo_arc` registration benchmark exposed a
single-use handle bug before the HSS respond/finalize stages. The Email OTP
enrollment material issued one `wallet_registration_ecdsa_prepare` root handle
for the whole EVM-family branch. Registration then iterated the server
`startedEcdsa.targets` and tried to consume that handle once for Tempo and once
for Arc, so the second bootstrap failed with
`Email OTP ECDSA client-root handle expired or was already used`.

Fixed the boundary by making wallet-registration ECDSA root handles target
scoped:

- `PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs` now requests a
  non-empty set of `{ chainTarget, evmFamilySigningKeySlotId }` target scopes.
- The Email OTP worker issues one single-use
  `wallet_registration_ecdsa_prepare` handle per requested target and stores
  the target on the handle.
- Worker claim validates wallet id, subject, slot id, action, and chain target.
- Registration selects the handle by `thresholdEcdsaChainTargetKey()` for each
  server target and rejects missing, duplicate, or extra handles at the
  enrollment-material boundary.
- The Google Email OTP prewarm path now derives target-specific slot ids for all
  requested EVM-family targets.

Validation:

- `pnpm -C packages/sdk-web run build:sdk` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` passes 25/25, including a two-target registration prewarm assertion.
- A later intended Email OTP combined benchmark passed after hardening the
  intended-services startup and refreshing the target summary model:
  `test-results/intended-lifecycle-traces/1783192113778-email_otp.registration-polar-summit-wzneye-intended-lifecycle-trace.json`.
  Total registration was 5,145ms, with `walletRegisterFinalizeMs` 3,201ms and
  route `registrationHssFinalizeMs` 3,182ms.

## Email OTP Ed25519-Only Registration Material Boundary — July 5, 2026

Fixed the Google Email OTP registration flow so `ecdsaTargets: { kind: 'none' }`
does not start ECDSA registration prewarm and does not require an EVM-family
signing-key slot. The boundary now carries an explicit ECDSA-root material
request:

- `ecdsa_root_requested` / worker `requested`: carries the
  `evmFamilySigningKeySlotId` and returns an `available` worker handle.
- `ecdsa_root_not_requested` / worker `not_requested`: forbids the slot id and
  returns no ECDSA handle.

The ECDSA bootstrap path now extracts only the `available` branch, and
registration validates that prewarmed or freshly prepared material matches the
requested branch before it crosses into core registration. This removes the
old implicit invariant that every Email OTP registration had an ECDSA target,
while keeping ECDSA bootstrap strict.

Deleted the unused legacy
`packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/enrollment.ts`
wrapper because it still sent the old worker payload shape and had no active
imports.

Validation:

- `pnpm -C packages/sdk-web run build:sdk` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts ./unit/emailOtpRegistrationRoute.unit.test.ts ./unit/intendedBehaviourContracts.guard.unit.test.ts --reporter=line` passes 85/85.

Attempted the Email OTP Ed25519-only intended benchmark with:

```sh
SEAMS_INTENDED_PERSIST_TRACE=1 \
SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=none \
pnpm -C tests exec playwright test \
  -c playwright.intended.benchmark.ci.config.ts \
  e2e/intended-behaviours/email-otp.registration.benchmark.test.ts \
  --reporter=line
```

The benchmark now passes after refreshing the intended Google token and
regenerating SDK build artifacts. Clean trace:
`test-results/intended-lifecycle-traces/1783189388294-email_otp.registration-harbor-tempo-gtun6n-intended-lifecycle-trace.json`.

Observed Email OTP Ed25519-only timing:

- total registration: 5,256ms
- `walletRegisterFinalizeMs`: 3,257ms
- route `registrationHssFinalizeMs`: 3,232ms
- route `registrationHssFinalizeReportMs`: 2,798ms
- `ed25519EvaluationArtifactMs`: 456ms
- `thresholdEd25519SessionPersistenceMs`: 443ms

## Phase 9 Respond-Time Finalization Boundary — July 5, 2026

Rejected respond-time finalized-state persistence for the current
role-separated client-owned HSS flow. The Rust runtime can advance a responded
server eval state to `Finalized`, but the advance requires the add-stage request,
which depends on client-local evaluator OT state. That state is deliberately
kept out of `/wallets/register/hss/respond`: the route accepts only
`clientRequestMessageB64u` for the Ed25519 client request and rejects
`evaluatorOtStateB64u`, raw client inputs, and output-mask fields. A background
`waitUntil` immediately after respond has the same missing inputs.

The remaining server-HSS architectural option is same-Durable-Object execution
locality for one ceremony, with the prepared-session cache held in memory by a
dedicated HSS execution-local object. The existing registration ceremony DO is a
durable key-value facade and should not grow persisted WASM handles.

Also confirmed the Email OTP second-finalize task is already complete in the
current code. Both passkey and Email OTP registration worker-material stores use
`storeThresholdEd25519WorkerMaterialFromFinalizedHssReport`; the Email OTP path
uses recovery-code seal authorization and no registration path calls
`runThresholdEd25519HssCeremonyWithMaterialHandle`.

## Phase 9 Server HSS Speed Build And Passkey Benchmark — July 5, 2026

Built `wasm/near_signer/pkg-server` with speed-oriented release codegen by
overriding `CARGO_PROFILE_RELEASE_OPT_LEVEL=3` for the server-HSS build and
letting `wasm-opt` run. The browser Near signer package remains on its existing
release build path, and the generated server HSS WASM is now 2.0M.

Passkey registration benchmark passed:

```sh
SEAMS_INTENDED_PERSIST_TRACE=1 \
SEAMS_INTENDED_PASSKEY_ECDSA_TARGET_PROFILE=tempo_arc \
pnpm -C tests exec playwright test \
  -c playwright.intended.benchmark.ci.config.ts \
  e2e/intended-behaviours/passkey.registration.benchmark.test.ts \
  --reporter=line
```

Trace:
`test-results/intended-lifecycle-traces/1783184493610-passkey.registration-polar-orchid-2ugkxc-intended-lifecycle-trace.json`.

Observed timing:

- total registration: 6,025ms
- `walletRegisterFinalizeMs`: 3,354ms
- route `registerFinalizeTotalMs`: 3,343ms
- `registrationHssFinalizeMs`: 3,334ms
- `registrationHssFinalizeSerializedSessionMaterializeMs`: 155ms
- `registrationHssFinalizeReportMs`: 2,887ms

The server speed build removes about 2.0s from the finalize route versus the
July 4 sample (`registerFinalizeTotalMs` ~5,333ms,
`registrationHssFinalizeReportMs` 4,707ms). The hidden-eval replay remains the
top passkey registration bucket. The later Phase 9 exit decision accepts that
residual cost for Refactor 83 and defers same-DO locality to a separate HSS
latency design.

Validation:

- `pnpm -C packages/sdk-web run type-check` passes.
- `pnpm -C packages/sdk-server-ts run type-check` passes.
- `pnpm -C packages/sdk-web run build:wasm` passes.
- `pnpm -C packages/sdk-web run build:sdk` passes.
- The passkey registration benchmark above passes 1/1.

Email OTP benchmark note: a later July 5 run refreshed the intended Google
token and passed with
`test-results/intended-lifecycle-traces/1783189388294-email_otp.registration-harbor-tempo-gtun6n-intended-lifecycle-trace.json`.
The server HSS finalize cost remains the top bucket for both passkey combined
and Email OTP Ed25519-only registration.

## Phase 1 Target Profiles And Ed25519 Sub-Buckets — July 4, 2026

Added strict Email OTP ECDSA target-profile selection to the intended E2E page
and harness:

- page query parameter: `emailOtpEcdsaTargetProfile`
- harness environment variable:
  `SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE`
- accepted branches: `none`, `tempo`, `tempo_arc`

The page now passes that profile directly to
`beginGoogleEmailOtpWalletAuth({ ecdsaTargets })`, resolves only the exact target
keys required by the selected branch, and emits discriminated
`ecdsaTargetKeys` summaries. The harness parser and signature-verification
helpers now consume the same discriminant, so Ed25519-only benchmark runs are
parseable while the default intended contracts still use `tempo_arc`.

Split the misleading registration
`thresholdEd25519SessionPersistenceMs` wrapper into sub-buckets:

- `thresholdEd25519KeyMaterialPersistenceMs`
- `thresholdEd25519SessionNormalizeMs`
- `thresholdEd25519WarmMaterialValidationMs`
- `thresholdEd25519WarmCapabilityPersistenceMs`
- `thresholdEd25519WorkerMaterialPersistenceMs`
- `thresholdEd25519SigningSessionHydrationMs`
- `thresholdEd25519SealedSessionPersistenceMs`

The old wrapper remains in the detailed timing payload for continuity. The
critical-path ranking now uses the sub-buckets, so the next trace should show
whether the 6.9s registration tail is worker-material persistence, hydration,
or seal persistence.

Validation:

- `pnpm -C apps/seams-site exec tsc --noEmit`
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit`
- `pnpm -C packages/sdk-web exec tsc --noEmit`
- `git diff --check -- apps/seams-site/src/pages/intended-e2e/page.tsx
  tests/e2e/intended-behaviours/harness.ts
  packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts
  packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
  docs/refactor-83-registration.md docs/refactor-83-journal.md`

Evidence gap at this point: recapture the Phase 1 and Phase 7B matrices with
the new target-profile parameter. Later July 5 entries record those completed
matrix runs.

## Phase 1/7B Current Benchmark Samples — July 4, 2026

Captured current combined Email OTP registration and unlock benchmark samples
after the Refactor 83 instrumentation and sealed-material unlock path landed.
There was no clean pre-83 baseline, so these numbers are the current
post-instrumentation baseline.

Usable combined registration samples:

- `test-results/intended-lifecycle-traces/1783173093265-email_otp.registration-indigo-bloom-294f55-intended-lifecycle-trace.json`:
  14,072ms.
- `test-results/intended-lifecycle-traces/1783173252521-email_otp.unlock-frost-ember-s6y62s-intended-lifecycle-trace.json`:
  14,264ms during unlock-contract setup.
- `test-results/intended-lifecycle-traces/1783175459504-email_otp.unlock-crimson-raven-vkxvzk-intended-lifecycle-trace.json`:
  13,912ms during a green unlock-contract setup.

The current combined Email OTP registration p50 is 14,072ms, with 14,264ms as
the observed cold-run worst case. The top registration buckets remain
`thresholdEd25519SessionPersistenceMs`, `walletRegisterFinalizeMs`, and
`ed25519EvaluationArtifactMs`.

Usable combined core unlock samples:

- `test-results/intended-lifecycle-traces/1783173252521-email_otp.unlock-frost-ember-s6y62s-intended-lifecycle-trace.json`:
  8,011ms for core activation. The full lifecycle later failed during Arc/EVM
  signing, so the timing point is valid but not a green contract run.
- `test-results/intended-lifecycle-traces/1783175459504-email_otp.unlock-crimson-raven-vkxvzk-intended-lifecycle-trace.json`:
  7,993ms for core activation, with the full Email OTP unlock/sign/export
  contract passing.

The current combined core unlock nearest-rank p50 is 7,993ms, with 8,011ms as
the observed worst case. The green trace still shows Ed25519 material restore
dominating: `ed25519MaterialRestoreMs` 6,938ms,
`signingSessionSealApplyMs` 562ms, `emailOtpProofVerificationMs` 387ms,
`ecdsaMaterialRestoreMs` 83ms, and `warmCapabilityPersistenceMs` 13ms.
That evidence rejects a persistence-collapse or small-bucket parallelism slice
for Phase 7B; the next meaningful optimization target is Ed25519 material
restore/HSS finalization.

Attempted one additional warm unlock sample after the green run. It failed
before lifecycle execution because the harness health check timed out on
`GET https://localhost:9444/healthz` after 5s while the local Wrangler router
was rebuilding; the router eventually answered the health check after about
19s. Treat this as a local intended-services stability issue, not a Refactor 83
unlock regression.

Validation:

- `pnpm -C tests run ensure:intended-google-token` refreshed
  `.env.intended.local` successfully.
- `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c
  playwright.intended.config.ts
  e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line`
  passes 1/1 against direct intended services.

## Phase 1 Digest And Timing Boundary Guards — July 4, 2026

Kept the local registration-intent digest recomputation as a single
request/response boundary check in `verifyWalletRegistrationIntentResponse()`.
The registration core now has a guard that rejects any second
`computeRegistrationIntentDigest()` call path.

The suspicious-tail registration timing buckets remain observational in the
critical-path summary. The deleted second Ed25519 warm-material reconstruction
does not emit `threshold_ed25519_warm_material_reconstruction_started`; the
source guard rejects reintroducing that event.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.

## Phase 8 Registration Cleanup Sweep — July 4, 2026

Ran the targeted registration cleanup sweep for obsolete helpers and stale
tests. The registration production path has no remaining references to
`assertImmediateRegistrationSigningLanes`, `readPersistedAvailableSigningLanes`,
`threshold_ed25519_warm_material_reconstruction_started`, or registration-time
`reconstructThresholdEd25519SigningMaterialFromWarmSession()`.

The remaining precompute helpers, signer-plan helpers, and digest verification
helper are still live boundary code. No safe delete candidate remained in this
slice. The unlock-specific serial-material fixture cleanup stays open under
Phase 7B because the unlock trace has not been captured yet.

Validation:

- `rg` cleanup sweep over registration production/test files found no stale
  helper references in the production registration path.

## Phase 7B Active Wallet Session Boundary — July 4, 2026

Tightened `email_otp_unlock_activation_plan_v1` so it carries an
`ActiveWalletSession` instead of a loose `WalletSessionRef`. The builder derives
the active session from the committed Email OTP Ed25519 current record, then
requires every sibling ECDSA current record to have the same wallet-bound
authority and bearer JWT before unlock success is logged.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.

## Phase 7B Unlock Prewarm Trace Context — July 4, 2026

`email_otp_unlock_timing_summary_v1` now includes a typed prewarm snapshot.
The snapshot distinguishes `not_prewarmed` from `prewarm_attempted` and records
the prewarm request, status, age, scope, and whether the scope matches the
wallet being unlocked.

Email OTP worker responses do not currently expose worker-level WASM init
diagnostics. Phase 7B trace interpretation therefore uses prewarm state as the
source-level cold/steady marker: unprewarmed runs identify cold-ish user-visible
latency, while runs after `prewarm({ iframe: true })` or
`prewarm({ workers: true })` are the steady-state candidates for duplicate-work
removal.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.

## Phase 1/7B Parseable Timing Trace Lines — July 4, 2026

Registration and Email OTP unlock timing summaries now keep the existing
`console.info(label, summary)` object logs and also emit a JSON-line form. The
JSON line makes Playwright's `message.text()` based intended trace attachment
usable for baseline extraction instead of relying on browser-specific object
argument rendering.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "combined Ed25519 and ECDSA wallet registration" --reporter=line` passes 1/1.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11 after rerunning serially. An earlier parallel run failed before tests started because the unit web server port 3600 was already in use.

## Phase 1/7B Intended Trace Attempt — July 4, 2026

Attempted to run the Email OTP intended registration and unlock contracts as a
source for Refactor 83 timing baselines:

```sh
pnpm -C tests run ensure:intended-google-token
pnpm -C tests exec playwright test -c playwright.intended.config.ts \
  e2e/intended-behaviours/email-otp.registration.contract.test.ts \
  e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line
```

The Google token refresh succeeded, but both contracts failed before executing
the lifecycle because the local site readiness check saw
`https://localhost -> HTTP 502` from Caddy. No registration or unlock timing
baseline was captured from this run.

Validation:

- `pnpm -C tests run ensure:intended-google-token` succeeded and refreshed
  `.env.intended.local`.
- Targeted intended contracts failed at service readiness: `site is not ready at https://localhost: HTTP 502`.

## Phase 7B Ed25519 Unlock Material Inventory — July 4, 2026

Audited the Email OTP Ed25519 unlock path against the sealed restore path.
Unlock currently verifies OTP through `unlockEmailOtpWalletForEd25519Session()`,
receives fresh recovery-code material from the worker, then runs one
`reconstructEmailOtpEd25519Session()` call that persists through
`persistWarmSessionEd25519Capability()` and crosses the 82B current-session
commit boundary.

The durable sealed Ed25519 restore path is separate:
`EmailOtpSealedRestoreOrchestrator` uses
`restoreEmailOtpEd25519SealedRecordForAccount()` for signing/status restoration
and writes restored records with fact-write APIs. It does not promote restored
facts into wallet-unlock current sessions. That split is intentional after 82B
Phase 10C: restore/rehydration remains fact-write only, while unlock-created
current sessions use commit commands.

No stale unlock fixture was found that encodes duplicate Ed25519 sealed restore
plus reconstruction as intended behavior. The remaining optimization is
trace-gated: use sealed material first only if the Phase 7B baseline proves
steady-state reconstruction dominates unlock and the replacement still builds
`email_otp_unlock_activation_plan_v1` before success.

Validation:

- Source inventory only; no code change in this slice.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `git diff --check -- docs/refactor-83-registration.md docs/refactor-83-journal.md` passes.
- `pnpm build:sdk` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 9/9 after SDK build regenerated the local Vite plugin bundle.

## Phase 4 Persistence Write Subjects — July 4, 2026

`RegistrationPersistencePlan` now carries an explicit
`registration_persistence_write_subjects_v1` inventory. The plan builder derives
the inventory from the same auth, Ed25519, and ECDSA branches that the commit
uses, so callers no longer construct a bare persistence source object and leave
the intended wallet/profile/auth/signer/session/selected-wallet writes implicit.

The Refactor 83 source guard now rejects direct
`RegistrationPersistencePlan` object literals and requires the write-subject
inventory to stay attached to the plan.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 7/7 after rerunning serially; the first attempt hit a stale generated SDK plugin resolution failure before test execution.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "combined Ed25519 and ECDSA wallet registration|Email OTP enrollment material|per-call disabled ECDSA provisioning|scope mismatch diagnostics" --reporter=line` passes 4/4.
- `pnpm build:sdk` passes.

## Phase 7B Unlock Activation Plan Boundary — July 4, 2026

Email OTP Ed25519 provisioning now returns the operation-usable current record
committed during unlock. SeamsWeb uses that record, all ECDSA current records
returned by the unlock bootstrap, the wallet session, and the runtime
postcondition inventory to construct `email_otp_unlock_activation_plan_v1`
before emitting unlock success events.
This keeps unlock readiness as one typed boundary object instead of loose local
variables plus a later inventory scan. The Refactor 83 guard now rejects
dropping the activation-plan construction or the operation-usable record
boundary.

Validation:

- ECDSA iframe unlock now reports `walletIframeRoundTripMs` in
  `email_otp_unlock_timing_summary_v1`; lower-level seal, restore, and
  persistence sub-buckets remain explicit Phase 7B follow-up work.
- `pnpm build:wasm` passes and restores both NEAR signer WASM package targets.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm build:sdk` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 6/6.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "combined Ed25519 and ECDSA wallet registration|Email OTP enrollment material|per-call disabled ECDSA provisioning|scope mismatch diagnostics" --reporter=line` passes 4/4 after rerunning serially; the first parallel attempt collided on Playwright port 3600.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/seamsWeb.unlockCancellationEvents.unit.test.ts --reporter=line` passes 5/5.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` passes 25/25 after rerunning serially; the first parallel attempt collided on Playwright port 3600.

## Phase 6 Keyset Branch Gate — July 4, 2026

Changed registration precompute so Router A/B public-keyset prefetch starts only
when the normalized signer plan includes an EVM-family ECDSA branch.
Ed25519-only registration now resolves that precompute dependency as disabled;
combined Ed25519+ECDSA registration still fetches `/router-ab/keyset`.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration" --reporter=line` passes 2/2.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.

## Phase 5 Active Runtime State Test Coverage — July 4, 2026

The combined passkey registration orchestration fixture now asserts the
constructed `registration_active_runtime_state_v1` event directly. It verifies
that Ed25519 and ECDSA are ready after the registration commit, that the shared
signing grant is carried into the active state, and that ECDSA carries a
concrete threshold session id from the canonical `thresholdSessionId` field.
The active state itself now carries Refactor 79 exact-lane identities:
`ExactEd25519SigningLaneIdentity` for NEAR and a non-empty list of
`ExactEcdsaSigningLaneIdentity` values for EVM-family targets.

Deleted the stale split-grant fixture that rewrote persisted ECDSA lane records
after registration and expected a post-write lane inventory scan to fail. The
production registration path no longer reads persisted lane inventory as a
success postcondition. The Refactor 83 guard now rejects reintroducing either
`readPersistedAvailableSigningLanes` or
`assertImmediateRegistrationSigningLanes` in the registration operation.

Validation:

- `pnpm build:sdk` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "combined Ed25519 and ECDSA wallet registration|Email OTP enrollment material|per-call disabled ECDSA provisioning|scope mismatch diagnostics" --reporter=line` passes 4/4.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 5/5.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `git diff --check` passes.

## Phase 1 And Phase 6 Diagnostics — July 4, 2026

Added `registration_critical_path_summary_v1` to registration timing summaries.
The summary reports elapsed time, measured work, overlapped/background work, and
the top measured buckets without changing control flow.

Tightened started-precompute scope handling. `registerWalletWithStartedPrecompute()`
now fails closed before reading a stale handle and reports the exact mismatched
scope fields. The Ed25519-only registration fixture also asserts that ECDSA
client bootstrap preparation is not invoked.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 3/3.
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `git diff --check` passes.

## Phase 2 Stored Signer Plan Package Slice — July 4, 2026

Stored registration preparations and ceremonies now carry a normalized
`signerPlan`. The D1/DO persistence boundary validates the stored plan against
the stored intent, and `consumeRegistrationIntentForPreparation()` includes the
plan in its atomic related-record match. `/start`, `/hss/respond`, and
`/finalize` now use the stored signer plan for branch selection.

Remaining Phase 2 work at this point: move runtime-policy scope and normalized
ECDSA chain targets into the same prepared package so start/respond/finalize
stop deriving those facts from intent-shaped data. The later prepared-context
completion entry records that follow-up.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCeremonyStore.unit.test.ts --reporter=line` passes 8/8.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "registration" --reporter=line` passes 17/17.
- `pnpm --dir packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit --pretty false` passes.

## Phase 3 Direct Passkey Ed25519 Material Persistence — July 4, 2026

Passkey Ed25519 registration now passes the registration credential and prepared
registration HSS material into `persistRegisteredThresholdEd25519Session()`.
The persistence boundary validates the HSS binding, stores worker material from
the registration ceremony output, hydrates the warm session once, and persists
the sealed passkey session. The immediate post-finalize call to
`reconstructThresholdEd25519SigningMaterialFromWarmSession()` was removed from
registration and add-signer paths; reconstruction remains for login, recovery,
and sync flows.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/seamsWeb.unlockCancellationEvents.unit.test.ts --reporter=line` passes 5/5 after updating the fixture Ed25519 session record to include current Router A/B normal-signing state.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` passes 25/25.
- `git diff --check` passes.

## Phase 7B Unlock Current-Session Commit Guard — July 4, 2026

Added a Refactor 83 source guard for the unlock current-session boundary.
Ed25519 warm capability persistence must convert to an operation-usable record
before `commitCurrentThresholdEd25519Session`; ECDSA bootstrap persistence must
convert to an operation-usable record before `commitCurrentThresholdEcdsaSession`.
Exact and reusable sealed-material restore paths remain fact-write only, which
keeps restore/rehydration separate from current-session commits.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 4/4.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/seamsWeb.unlockCancellationEvents.unit.test.ts --reporter=line` passes 5/5 after updating the fixture Ed25519 session record to include current Router A/B normal-signing state.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` passes 25/25.
- `git diff --check` passes.
- `pnpm build:sdk` passes and refreshes `packages/sdk-web/dist/esm` for browser tests.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts --reporter=line` passes 5/5.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 3/3.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/refactor74LoginNoHss.guard.unit.test.ts --grep "sealed worker material|durable refresh" --reporter=line` passes 1/1.

## Phase 2 Prepared Context Completion — July 4, 2026

Stored registration preparations and ceremonies now carry a
`wallet_registration_prepared_context_v1` package with signing-root identity,
runtime-policy scope, and normalized EVM-family ECDSA chain targets. Start
consumes the prepared package when it atomically consumes a preparation, writes
the same package into ceremony state, and uses it for ECDSA HSS prepare.
Finalize now builds Ed25519 session policy from the ceremony's prepared context
instead of reparsing `intent.runtimePolicyScope`.

The D1 consume path now matches authority, signer plan, prepared context, and
Ed25519 prepare scope together. Type fixtures and registration store tests were
updated so old preparation/ceremony shapes without prepared context are rejected.

Validation:

- `pnpm --dir packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCeremonyStore.unit.test.ts --reporter=line` passes 8/8.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "registration" --reporter=line` passes 17/17.

## Phase 4/5 Registration Persistence Plan Slice — July 4, 2026

Client registration now builds a `RegistrationPersistencePlan` before local
writes. The plan carries auth context, Ed25519 session/material facts, optional
EVM-family ECDSA bootstrap/session facts, and expected ECDSA targets. Both
ECDSA-only and NEAR+optional-ECDSA registration paths commit through
`commitRegistrationPersistencePlan()`.

The commit removed the post-write `getUserBySignerSlot()` read that only
verified the IndexedDB write just performed. Production registration also no
longer runs `assertImmediateRegistrationSigningLanes()` or the registration-only
persisted-lane inventory scan; it constructs
`registration_active_runtime_state_v1` from the committed plan instead. The
registration signing surface no longer requires `readPersistedAvailableSigningLanes`.

Remaining Phase 4/5 work at this point: decide whether to promote literal
IndexedDB row construction into the plan itself, add direct lane-invariant tests
outside the production path, and manually validate fresh passkey/OTP
registration through NEAR, Tempo, Arc, step-up, and exports. Later entries and
manual validation close the active Phase 4/5 criteria.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts --reporter=line` passes 5/5.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 3/3 after rerunning serially; an earlier parallel run collided on Playwright port 3600.

## Phase 7 Email OTP Tail Parallelism Slice — July 4, 2026

Email OTP registration now starts enrollment material preparation immediately
after OTP authority proof instead of blocking before registration start. The
ECDSA-only path lets `/wallets/register/start` proceed while the material is
preparing. The combined Ed25519/ECDSA path routes Ed25519 material preparation
and ECDSA bootstrap through the same enrollment-material promise.

Recovery-code backup now starts as soon as enrollment material resolves and
still produces the existing backup outcome union. The finalize path remains the
only place that turns that backup result into a single-use
`emailOtpBackupAck`.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 3/3 on rerun. The first run failed before tests started because the unit web server briefly could not import the generated NEAR signer WASM worker; the file was present on inspection and the same command passed immediately after.
- `git diff --check` passes.

## Registration Intent Digest Boundary Helper — July 4, 2026

The local registration intent digest comparison now lives in
`verifyWalletRegistrationIntentResponse()` instead of being duplicated inline in
the precomputed Ed25519 path and the ECDSA-only path. This keeps the integrity
check while making the boundary explicit. Removing the local digest work
entirely remains open.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 3/3.
- `git diff --check` passes.

## Phase 7 Email OTP Tail Fixture Coverage — July 4, 2026

Added a direct registration orchestration fixture for the ECDSA-only Email OTP
path. The test holds enrollment material preparation open, verifies
`/wallets/register/start` has already been sent, and confirms `/hss/respond`
and `/finalize` wait for enrollment material plus backup acknowledgement.

The fixture also asserts the strict finalize payload: `emailOtpEnrollment` uses
the enrollment material fields, and `emailOtpBackupAck` uses the route contract
with `offerId`, `candidateId`, `recoveryCodesIssuedAtMs`,
`backupActionKind`, `acknowledgedAtMs`, and `idempotencyKey`.

Validation:

- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts --grep "Email OTP enrollment material|per-call disabled ECDSA provisioning|combined Ed25519 and ECDSA wallet registration|scope mismatch diagnostics" --reporter=line` passes 4/4.

## Phase 7B Email OTP Unlock Measurement Slice — July 4, 2026

Email OTP unlock now exposes the first timing split needed for the slow-unlock
investigation. Google session exchange success events carry
`appSessionExchangeMs`. Local Email OTP unlock logs
`email_otp_unlock_timing_summary_v1` after success or failure, with elapsed
time and top buckets for Ed25519 reconstruction resolution, email-hash lookup,
worker unlock/session bootstrap, wallet-state activation, and runtime
postconditions.

This slice is observational. Unlock still reports success only after activation
and runtime postconditions, preserving the Refactor 88 contract.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.

## Phase 7B Unlock Activation And Commit Boundary — July 4, 2026

Email OTP unlock now has a guarded activation boundary: local Ed25519 and
combined ECDSA unlock construct `email_otp_unlock_activation_plan_v1` before
success, while iframe unlock awaits the wallet-iframe router lifecycle before
the host reports success. The activation plan carries `ActiveWalletSession`,
operation-usable current session records, and runtime state together.

The persistence boundary remains curve-local by design. Ed25519 warm capability
persistence commits through `commitCurrentThresholdEd25519Session`, ECDSA
publication commits through `commitCurrentThresholdEcdsaSession`, and sealed
restore hydration stays fact-write only. ECDSA sealed-session persistence is a
separate durable seal/read-back write and does not reintroduce generic ECDSA
fact upserts. Any broader IndexedDB transaction collapse remains trace-gated.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm build:sdk` passes and restores the SDK plugin dist used by the unit web server.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11 after rebuilding the SDK dist.

## Phase 8 Line Count Accounting — July 4, 2026

Current 83-owned non-doc diff against `HEAD` records 2,820 additions and
884 deletions across tracked server, SDK, and focused unit-test files, plus the
new 432-line `registrationCapabilitySubjects.guard.unit.test.ts` source guard.
Generated SDK `dist` output is excluded.

The retained net growth is in stricter domain state and guard coverage:
normalized prepared-package state, registration persistence subjects, active
runtime-state construction, Email OTP unlock timing/activation types, and
guards that prevent stale runtime scans or fact/current session collapse from
returning.

## Intended Trace Attempt — July 4, 2026

Attempted the CI-managed Email OTP registration/unlock lifecycle contracts:

`pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line`

The run failed before router/site startup and before any lifecycle test ran.
`start-intended-services.mjs` invokes `pnpm run build:sdk-full`; that build
failed in `wasm-pack` while building WASM packages with:

`Error: invalid type: map, expected a string at line 7 column 16`

The focused 83 source validation still passes (`pnpm build:sdk`, SDK
typecheck, and the registration capability source guard). Registration/unlock
p50 and cold-run baselines remain open until the intended startup build issue is
fixed or the trace is captured from manually started local services.

## Current Benchmark Trace — July 4, 2026

No clean pre-83 registration benchmark was captured before implementation
started. The current trace is therefore the new reference point for later
performance work, not evidence of improvement by itself.

Added an env-gated intended harness trace sink:
`SEAMS_INTENDED_PERSIST_TRACE=1` writes the existing
`intended-lifecycle-trace.json` payload to
`test-results/intended-lifecycle-traces/` outside Playwright's managed
per-test output directory, so successful benchmark traces survive later test
failures in the same run.

Registration benchmark:

- Command: `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line`
- Result: passed 1/1 in 1.8m.
- Artifact:
  `test-results/intended-lifecycle-traces/1783173093265-email_otp.registration-indigo-bloom-294f55-intended-lifecycle-trace.json`
- Email OTP combined registration elapsed: 14,072ms.
- Top critical-path buckets:
  `thresholdEd25519SessionPersistenceMs` 6,913ms,
  `walletRegisterFinalizeMs` 5,411ms,
  `ed25519EvaluationArtifactMs` 470ms,
  `ed25519ClientMaterialMs` 382ms,
  `walletRegisterPrepareMs` 375ms.

Unlock benchmark:

- Command: `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line`
- Artifact:
  `test-results/intended-lifecycle-traces/1783173252521-email_otp.unlock-frost-ember-s6y62s-intended-lifecycle-trace.json`
- Setup registration elapsed: 14,264ms.
- Core unlock activation summary succeeded with `prewarm.kind =
  not_prewarmed` and elapsed time 8,011ms.
- Top unlock buckets: `workerUnlockAndSessionBootstrapMs` 8,002ms,
  `ed25519MaterialRestoreMs` 6,957ms, `signingSessionSealApplyMs` 562ms,
  `emailOtpProofVerificationMs` 388ms, `ecdsaMaterialRestoreMs` 80ms.

The full unlock lifecycle contract failed later during post-unlock Arc/EVM
signing with `Wallet request timeout for PM_SIGN_TEMPO after 30003ms`. The
unlock timing datapoint remains useful because it was emitted before that
later action failed. The full contract is not green from this run.

Validation in this slice:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.
- `pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line` passed 2/2 once after the unlock bearer-JWT postcondition fix, but that run did not persist timing traces.

## Email OTP Unlock Sealed-Material Fast Path — July 4, 2026

Implemented the Phase 7B sealed-material-first Ed25519 unlock path. Email OTP
unlock now canonicalizes exact operation-usable Ed25519 records for the current
wallet-bound authority, prepares a recovery-code unseal authorization, restores
sealed worker material through the existing Router A/B Ed25519 readiness
boundary, hydrates the recovery-code warm signing session, and returns the same
typed provisioning result shape used by the HSS reconstruction path. HSS
reconstruction remains the fallback when no exact sealed record is available.

Also aligned the in-flight Ed25519 material restore split: the restore
authorization implementation remains flow-local for now, while its readiness
dependency is owned by `session/warmCapabilities`. Stale imports created by the
mechanical move were corrected without adding compatibility shims or duplicate
restore implementations.

Validation:

- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passes.
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit --pretty false` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.
- `pnpm -C packages/sdk-web run build:sdk-full` passes.

Post-change intended timing rerun:

- Direct `start-intended-services.mjs` reached ready state.
- `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/email-otp.unlock.contract.test.ts --reporter=line` failed before registration because `/session/exchange` rejected the local Google `id_token` as expired.
- A fresh post-change unlock timing trace needs a refreshed intended Google token.

## Phase 1 Post-84b Registration Timing Breakdown — July 5, 2026

Added the missing measurement plumbing needed to explain the current combined
Email OTP registration latency:

- the intended E2E page and harness now support passkey and Email OTP ECDSA
  target profiles (`none`, `tempo`, `tempo_arc`) so the Phase 1 matrix can run
  Ed25519-only, Tempo-only, and combined registrations without creating a new
  registration path;
- intended pages enable the existing registration benchmark diagnostics flag,
  so SDK registration requests send `X-Seams-Benchmark-Diagnostics:
  registration-flow`;
- D1 wallet registration finalize now attaches
  `wallet_registration_route_diagnostics_v1` on successful finalize responses.

The fresh post-84b Email OTP combined registration contract passed:

`SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line`

Trace artifact:

`test-results/intended-lifecycle-traces/1783178970696-email_otp.registration-golden-ember-e4bdkp-intended-lifecycle-trace.json`

Observed timings:

- total registration: 13,954ms;
- `thresholdEd25519WorkerMaterialPersistenceMs`: 6,578ms;
- `walletRegisterFinalizeMs`: 5,345ms;
- `ed25519EvaluationArtifactMs`: 462ms;
- `walletRegisterPrepareMs`: 378ms;
- `ed25519ClientMaterialMs`: 376ms.

The old `thresholdEd25519SessionPersistenceMs` wrapper was 6,874ms, but the
inner buckets show the real cost: key-material persistence 1ms, session
normalization 0ms, warm-material validation 0ms, warm-capability persistence
1ms, worker-material persistence 6,578ms, signing-session hydration 294ms, and
sealed-session persistence 0ms.

The route diagnostics show `walletRegisterFinalizeMs` is also HSS dominated:
`registrationHssFinalizeMs` was 5,319ms out of `registerFinalizeTotalMs`
5,333ms. D1 persistence was 5ms and session mint was 1ms.

Conclusion: the current post-84b latency is not explained by local persistence
or D1 writes. The two dominant costs are Ed25519 HSS finalization on the server
and Email OTP Ed25519 worker-material persistence on the client.

Validation:

- `pnpm -C apps/seams-site exec tsc --noEmit` passes.
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit` passes after
  the generated `wasm/near_signer/pkg-server` output settled.
- `pnpm -C packages/sdk-server-ts run type-check` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "registration" --reporter=line` passes 17/17.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11 after rerunning serially; the first parallel attempt collided on Playwright port 3600.
- The intended registration contract above passes 1/1.

Build-tooling note:

- The intended CI startup build also exposed two local WASM toolchain issues:
  `wasm-pack 0.13.1` rejected generated package metadata containing a
  repository object, and the workspace wasm-pack cache exposed `wasm-opt` under
  `bin/wasm-opt` while the build path expected the root executable. Internal
  WASM crate repository metadata was removed, and
  `wasm-toolchain.sh` now normalizes the cached `wasm-opt` layout.

## Phase 3 Registration Worker-Material Direct Store — July 5, 2026

The post-84b registration trace showed
`thresholdEd25519WorkerMaterialPersistenceMs` at 6,578ms. Inspection found the
registration persistence helpers still ran
`runThresholdEd25519HssCeremonyWithMaterialHandle()` after `/wallets/register/finalize`.
That was a second warm-session HSS ceremony, used only to obtain the client
output needed by the sealed worker-material store.

Implemented the Phase 3 correction:

- D1 registration finalize now returns
  `threshold_ed25519_registration_worker_material_report_v1` on successful
  Ed25519 responses. The report contains `contextBindingB64u` and
  `clientOutputMessageB64u`; it has no seed output.
- SDK web threads the report together with the original registration
  `preparedSession` and `clientOutputMaskHandle` as
  `ThresholdEd25519FinalizedRegistrationHssMaterial`.
- Registration persistence stores passkey and Email OTP Ed25519 worker material
  through `storeThresholdEd25519WorkerMaterialFromFinalizedHssReport()`.
- Warm-session reconstruction remains available for login, recovery, and sync.
- Replay/persistence parsers treat the report as part of a valid Ed25519
  finalize success, so replay cannot silently return a partial response.

Validation so far:

- `pnpm -C packages/sdk-web exec tsc --noEmit` passes.
- `pnpm -C packages/sdk-server-ts run type-check` passes.
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit` passes.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts --reporter=line` passes 5/5.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line` passes 11/11.
