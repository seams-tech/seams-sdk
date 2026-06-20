# Optimize Registration 2: Auth-Agnostic Precompute

Date created: June 10, 2026

Status: closed as the retained registration baseline on June 11, 2026.
Broad prepared-registration lifecycle work is deferred/superseded by
Router A/B.

## Goal

Get registration to reliable sub-second visible latency by moving expensive HSS
work to the earliest safe registration-intent window for both Passkey and Email
OTP accounts.

The target is an auth-agnostic prepared-registration flow:

- client HSS artifact construction starts as soon as the user begins
  registration
- server HSS prepare starts only after cheap abuse gates allow it
- Passkey and Email OTP share the same prepared-registration lifecycle
- final account creation still requires a verified WebAuthn or Email OTP proof
- prepared material is short-lived, single-use, scoped, and abandonable

This plan builds on the retained refactor-61, refactor-62, and refactor-64
work. Refactor-61 moved registration preparation toward parallel orchestration.
Refactor-62 moved HSS server prepare out of the post-auth start route.
Refactor-64 reduced HSS runtime, but the remaining path still needs larger
critical-path overlap to reach sub-second user-visible registration.

## Relationship To Existing Plans

- `docs/refactor-61-registration-prep-parallelism.md` owns the first
  registration preparation route split and parallel orchestration.
- `docs/refactor-62-hss-prepare-preauth.md` owns the HSS preauth prepare
  record, route contract, scope binding, and start-route consumption rules.
- `docs/refactor-64-hss-protocol-runtime-latency.md` owns HSS executor and
  protocol runtime optimization.
- This plan owns the next prepared-registration orchestration layer: start
  client precompute earlier, gate server precompute against unauthenticated CPU
  abuse, and share the flow across Passkey and Email OTP registration.

## Current Read

Latest retained product benchmarks still show:

- client HSS artifact construction around `450ms` to `472ms` p50
- server HSS prepare around `378ms` to `383ms` p50
- `/wallets/register/hss/respond` around `77ms` to `79ms` p50
- `/wallets/register/finalize` around `44ms` to `46ms` p50
- `walletRegisterPrepareWaitMs` at `0ms` p50 in the retained smoke runs

The registration flow is close to the limit of local HSS micro-optimization.
The largest remaining win is overlap: prepare the client and server HSS pieces
while the user is entering OTP, touching TouchID, or waiting through WebAuthn
ceremony work.

## Closure Summary

This refactor is closed as the current production registration baseline. Keep
the narrow pieces that proved valuable:

- server-side `/wallets/register/prepare` admission gate before HSS prepare
- Email OTP Ed25519 session-persistence tail deferral
- early Google Email OTP host-origin registration prepare
- benchmark matrix, diagnostics, rejection notes, and abuse-gate tests

All retained implementation tasks are marked complete below. Non-retained broad
lifecycle work is moved into deferred Router A/B scope instead of staying as
open refactor-66 work.

Do not expand this document into the full prepared-registration lifecycle. That
work belongs in `docs/router-a-b-SPEC.md`, where the expensive HSS backend,
prepared-registration route model, and signer topology will change together.

Carry forward these stable lessons into Router A/B:

- expensive-work admission gate from trusted route metadata
- early prepare/precompute handle scoped to one registration intent
- scope binding across auth method, wallet/account, rp id, signer mode, and
  HSS context
- short TTL, replay protection, and single-use consumption
- diagnostics and benchmark matrix for visible latency and hidden work
- defer-under-load behavior with a slower authority-verified fallback

## Design Principles

- Treat Passkey and Email OTP as authority-proof branches over one
  prepared-registration lifecycle.
- Start client precompute immediately after registration intent exists, because
  the cost lands on the user's device.
- Start server precompute only after short-window gates and quotas accept the
  attempt.
- Reuse or return an existing pending attempt for duplicate clicks from the
  same user inside the short gate window.
- Skip early server precompute or fall back to post-auth prepare when the gate
  is saturated.
- Persist prepared packages with short TTLs and single-use consumption.
- Bind prepared material to the registration intent, authority method, account
  scope, signing root, and protocol context before start-route consumption.
- Keep diagnostics observational. Timing and gate diagnostics cannot influence
  cryptographic binding or proof verification.

## Target Flow

### Shared Intent Flow

```text
user starts registration
  -> allocate or reuse registrationAttemptId
  -> create/validate registration intent
  -> start client precompute in wallet iframe worker
  -> ask server for gated prepared-registration package
  -> collect authority proof in parallel
  -> wait for authority proof and required prepared material
  -> start registration with registrationPreparationId
  -> HSS respond
  -> finalize and persist wallet
```

### Passkey / TouchID

```text
user clicks register with Passkey
  -> registration attempt gate
  -> start client HSS artifact worker
  -> start gated server HSS prepare if allowed
  -> create WebAuthn challenge/options
  -> call navigator.credentials.create(...)
  -> TouchID / platform prompt remains open while HSS work continues
  -> verify WebAuthn response
  -> consume prepared HSS package
```

Workers and network requests should continue while the main thread awaits
`navigator.credentials.create(...)`. Fast TouchID users may still wait for the
tail of HSS preparation; slower prompt completion should hide most of it.

### Email OTP

```text
user clicks register with Email OTP
  -> registration attempt gate
  -> start client HSS artifact worker
  -> send OTP under normal OTP rate limits
  -> start gated server HSS prepare if allowed
  -> user enters OTP while HSS work continues
  -> verify OTP
  -> consume prepared HSS package
```

Email OTP gives a natural idle window. The architecture should not depend on
OTP-specific behavior, because Passkey needs the same sub-second benefit.

## Server Abuse Model

Client precompute is safe to start early. Server precompute is the sensitive
part because `prepare_prime_order_succinct_hss` is CPU-expensive.

A malicious client could otherwise spam registration starts without completing
OTP or WebAuthn and force the server to prepare unused HSS packages. Server
precompute must therefore sit behind short-window gates and a bounded worker
budget.

## Registration Attempt Gates

Initial gate policy:

- one active registration attempt per key per `5s` to `10s`
- prepared package TTL: `2min` to `5min`
- prepared package usage: single-use
- duplicate normal-user clicks: return or reuse the current pending attempt
- suspicious churn: skip early server precompute and continue with slower
  post-auth prepare
- abusive churn: reject before OTP/WebAuthn or HSS work

Gate keys:

```text
ip:<ip>
email:<normalized-email>
device:<device-fingerprint-or-session-id>
ip-email:<ip>:<normalized-email>
org-ip:<orgId>:<ip>
org-device:<orgId>:<device-fingerprint-or-session-id>
```

The system should prefer stable first-party identifiers over brittle browser
fingerprints. A signed anonymous registration-session id is acceptable for the
device key. Raw fingerprints should stay coarse and privacy-conscious.

## Prepared Registration Lifecycle

```ts
type RegistrationAttemptGateDecision =
  | {
      kind: 'accepted';
      registrationAttemptId: RegistrationAttemptId;
      serverPrecompute: 'start';
    }
  | {
      kind: 'reuse_existing';
      registrationAttemptId: RegistrationAttemptId;
      serverPrecompute: 'reuse';
    }
  | {
      kind: 'client_only';
      registrationAttemptId: RegistrationAttemptId;
      serverPrecompute: 'defer_until_auth';
      reason: 'short_window_saturated' | 'server_queue_saturated';
    }
  | {
      kind: 'rejected';
      reason: 'rate_limited' | 'abuse_policy';
      retryAfterMs: number;
    };
```

```ts
type PreparedRegistrationLifecycle =
  | {
      kind: 'preparing';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      scope: PreparedRegistrationScope;
      createdAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'prepared';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      scope: PreparedRegistrationScope;
      prepared: PreparedRegistrationMaterial;
      createdAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'failed';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      scope: PreparedRegistrationScope;
      failure: PreparedRegistrationFailure;
      createdAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'consumed';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      scope: PreparedRegistrationScope;
      consumedAtMs: number;
      createdAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'abandoned';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      scope: PreparedRegistrationScope;
      abandonedAtMs: number;
      createdAtMs: number;
      expiresAtMs: number;
    };
```

Required scope fields:

- `registrationAttemptId`
- `registrationPreparationId`
- registration intent grant and digest
- auth method intent: `passkey` or `email_otp`
- expected origin and rp id
- org id
- wallet id or wallet derivation input
- normalized account id
- signing root id and version
- Ed25519 key purpose, key version, derivation version, and participant ids
- HSS context binding and ceremony handle
- expiry

Core logic should accept only parsed lifecycle branches. Raw request or DB
shapes should normalize once at route/store boundaries.

## Client Precompute

Client precompute should start as soon as these inputs exist:

- registration intent
- target account id
- signer mode
- HSS runtime/program context
- wallet iframe or host-origin runtime

Client work:

- warm wallet iframe handshake
- initialize signing worker and WASM
- prepare client HSS request inputs
- construct the HSS client evaluation artifact when possible
- hold the artifact in the wallet iframe/worker under `registrationAttemptId`
- expose progress and readiness diagnostics
- abandon prepared client material on TTL expiry or attempt replacement

The client should support both Passkey and Email OTP. Authority proof collection
is a sibling task, not the parent of HSS precompute.

## Server Precompute

Server precompute should start only after the attempt gate accepts or reuses an
attempt.

Server work:

- validate registration intent and digest without consuming final authority
- evaluate short-window registration attempt gates
- enqueue or run HSS server prepare under bounded concurrency
- persist prepared material under `registrationPreparationId`
- return lifecycle state to the client
- support polling or push-style readiness through the existing client API shape
- consume the prepared record atomically in `/wallets/register/start`

If the gate returns `client_only`, the flow remains valid. The server prepares
after authority proof, and the UX degrades to the slower path under load.

Early server precompute must be optional. The gate is mandatory, but the
optimization is a rollout policy:

- `server_precompute_enabled`: start gated `/wallets/register/prepare` as early
  as possible.
- `client_only`: start client-side work early and defer server prepare until
  after authority proof.
- `disabled`: use the existing post-auth prepare path only.

The disable path is the safety valve for abuse, signer queue pressure, incident
response, or project-specific policy. Turning it off should not break
registration; it should only give back the latency win.

## Route Shape

This refactor can extend the existing `/wallets/register/prepare` route from
refactor-61/refactor-62.

Request:

```ts
type WalletRegistrationPrepareRequest = {
  registrationAttempt: RegistrationAttemptInput;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  authMethodIntent: WalletRegistrationAuthMethodIntent;
  precompute: WalletRegistrationPrecomputePolicy;
};

type WalletRegistrationAuthMethodIntent =
  | {
      kind: 'passkey';
      expectedOrigin: string;
      rpId: string;
    }
  | {
      kind: 'email_otp';
      normalizedEmail: string;
      otpOperation: 'wallet_registration';
    };

type WalletRegistrationPrecomputePolicy =
  | {
      kind: 'client_and_gated_server';
      serverGateWindowMs: number;
    }
  | {
      kind: 'client_only';
      reason: 'benchmark' | 'abuse_backoff' | 'server_disabled';
    };
```

Response:

```ts
type WalletRegistrationPrepareResponse =
  | {
      ok: true;
      state: 'prepared' | 'preparing';
      registrationAttemptId: RegistrationAttemptId;
      registrationPreparationId: RegistrationPreparationId;
      gate: Extract<
        RegistrationAttemptGateDecision,
        { kind: 'accepted' | 'reuse_existing' }
      >;
      expiresAtMs: number;
      diagnostics: WalletRegistrationPrepareDiagnostics;
    }
  | {
      ok: true;
      state: 'client_only';
      registrationAttemptId: RegistrationAttemptId;
      gate: Extract<RegistrationAttemptGateDecision, { kind: 'client_only' }>;
      diagnostics: WalletRegistrationPrepareDiagnostics;
    }
  | {
      ok: false;
      error: Extract<RegistrationAttemptGateDecision, { kind: 'rejected' }>;
    };
```

Start route:

- requires `registrationPreparationId` when server precompute succeeded
- accepts a typed `client_only` prepare result only when the route is allowed
  to run post-auth HSS prepare
- verifies the prepared scope against the loaded intent and verified authority
- consumes the registration intent and prepared record atomically

## Diagnostics

Add or preserve these benchmark fields:

- `registrationAttemptGateMs`
- `registrationAttemptGateDecision`
- `registrationPrecomputeStartedAtMs`
- `registrationClientPrecomputeStartedAtMs`
- `registrationClientPrecomputeReadyAtMs`
- `registrationServerPrecomputeStartedAtMs`
- `registrationServerPrecomputeReadyAtMs`
- `registrationServerPrecomputeQueueWaitMs`
- `walletRegisterPrepareWaitMs`
- `passkeyPromptOverlapMs`
- `emailOtpInputOverlapMs`
- `postAuthVisibleRegistrationMs`
- `ed25519EvaluationArtifactMs`
- `registrationHssPrepareMs`
- `registrationHssRespondMs`
- `registrationFinalizeMs`

Benchmark reporting should distinguish:

- wall-clock browser-observed total
- SDK visible total
- post-auth visible total
- HSS client artifact time
- server precompute time
- time hidden under OTP/WebAuthn user interaction

## Implementation Phases

Closure note: unchecked broad lifecycle tasks below are deferred/superseded by
Router A/B. Completed narrow phases remain the retained baseline for current
registration behavior.

### Phase 1: Spec And State Model

Status: deferred/superseded by Router A/B.

Deferred scope:

- registration attempt ids and reusable attempt semantics
- typed admission-gate decisions
- prepared-registration lifecycle state
- prepared-registration scope builders for Passkey and Email OTP
- type fixtures for invalid lifecycle and scope combinations
- TTL, single-use, and abandon semantics at the store boundary

### Phase 2: Gate Store And Policy

Status: deferred/superseded by Router A/B, except Phase 2A's retained narrow
prepare gate.

Deferred scope:

- durable registration attempt gate store
- IP, email, device/session, org-IP, and org-device gate keys
- reusable pending attempt responses for duplicate clicks
- bounded server queue and `client_only`/defer semantics
- cleanup for expired, abandoned, failed, and consumed attempts
- full gate-state unit tests
- config and project-policy tests for disabling early server precompute

### Phase 2A: Narrow Server Prepare Rate-Limit Gate

Status: implemented as a prerequisite guard on June 11, 2026.

Change:

- [x] Add a required server-side `prepareGate` context to
      `WalletRegistrationPrepareRequest`.
- [x] Keep `prepareGate` out of the client JSON body: the relay route injects
      normalized source-IP context and rejects client-supplied gate payloads.
- [x] Reuse the existing in-memory/Upstash/Redis rate-limit backend under
      `REGISTRATION_PREPARE_RATE_LIMIT_*` config.
- [x] Evaluate the gate after intent/digest validation and before Ed25519 HSS
      server prepare.
- [x] Key the initial guard by source IP, org+IP, wallet id, and Email OTP email
      where available.
- [x] Add route-boundary coverage for source-IP injection and client gate
      rejection.
- [x] Add an abuse-focused unit test proving a repeated same-source prepare is
      rejected before a second Ed25519 HSS prepare call.

Validation:

- `pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/registrationIntentAllocation.unit.test.ts
  tests/unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`

Read:

- This guard does not yet implement the full reusable prepared-registration
  lifecycle from Phase 2. It is the minimum CPU-amplification guard needed
  before moving `/wallets/register/prepare` earlier in Passkey and Email OTP
  flows.
- Duplicate normal-user clicks currently receive `rate_limited` when the
  configured short window is saturated. The later lifecycle work should reuse
  or return the current pending attempt instead.

### Phase 3: Server Prepared Registration Route

- [x] Extend `/wallets/register/prepare` to evaluate the gate before HSS server
      prepare.
- [x] Persist prepared HSS material under the shared prepared-registration
      lifecycle.
- [x] Ensure `/wallets/register/start` consumes a prepared package only after
      authority proof verification and scope matching.
- [x] Add route tests for Passkey and Email OTP prepared package consumption.
- [x] Add abuse tests proving repeated unauthenticated starts do not trigger
      unbounded HSS prepare.

Deferred/superseded by Router A/B:

- split route output into `prepared`, `preparing`, `client_only`, and
  `rejected` states
- bounded concurrency for server HSS prepare

### Phase 4: Client Runtime Orchestration

Status: deferred/superseded by Router A/B.

Deferred scope:

- wallet iframe and signing worker warmup tied to registration intent
- client HSS precompute before Passkey WebAuthn and Email OTP input
- in-flight client artifact state under a registration attempt id
- artifact reuse after authority proof succeeds
- artifact abandonment on TTL expiry, auth failure, account change, or attempt
  replacement
- lifecycle states for client-preparing, client-ready, server-preparing,
  server-ready, client-only, authority-pending, authority-verified, and
  start-ready
- SDK orchestration tests across Passkey and Email OTP

### Phase 5: Passkey Flow

Status: deferred/superseded by Router A/B.

Deferred scope:

- gated server prepare before WebAuthn prompt
- client artifact precompute before `navigator.credentials.create`
- prompt-overlap measurements
- fast TouchID handling through prepared material wait
- WebAuthn challenge verification as the authority gate

### Phase 6: Email OTP Flow

Status: partially implemented through Phase 6A, Phase 6B, and Phase 6C. The
remaining broad lifecycle work is deferred/superseded by Router A/B.

Deferred scope:

- auth-agnostic client artifact precompute before or alongside OTP challenge
  send
- durable OTP attempt record reuse for normalized email and operation scope
- OTP-input overlap measurements in the shared lifecycle
- OTP verification as an explicit authority-gate lifecycle branch

### Phase 6A: Email OTP Recovery-Code Backup Tail Overlap

Status: implemented as a narrow experiment on June 11, 2026.

Change:

- [x] Start Email OTP recovery-code backup as soon as registration enrollment
      material is available.
- [x] Keep the backup result as a typed in-flight outcome so rejected backup
      work cannot become an unhandled promise rejection.
- [x] Await the backup outcome only when finalize needs
      `emailOtpBackupAck`, preserving the existing finalize payload shape.
- [x] Remove the obsolete inline backup material state from the registration
      branches.

Validation:

- `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  tests/unit/addWalletSigner.orchestration.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/seamsWeb.emailOtp.unit.test.ts --reporter=line`

Benchmark note:

- `benchmarks/registration-flow` now has Email OTP registration scenarios for
  wallet iframe and host-origin runtimes.
- One-run probes on June 11, 2026 passed for all four new scenarios and caught
  a real SDK boundary parser gap: `/session/exchange` was dropping the Google
  Email OTP registration offer. The parser now preserves the offer, expiry,
  and candidates, with unit coverage in `tests/unit/seamsWeb.emailOtp.unit.test.ts`.
- Five-run Email OTP p50 matrix on June 11, 2026:
  - `email_otp_ed25519_only_wallet_iframe`: browser p50 `2949ms`, SDK p50
    `2360ms`, `walletRegisterPrepareWaitMs` p50 `0ms`,
    `emailOtpEnrollmentMaterialMs` p50 `477ms`, `ed25519EvaluationArtifactMs`
    p50 `418ms`, `thresholdEd25519SessionPersistenceMs` p50 `1149ms`.
  - `email_otp_ed25519_and_ecdsa_wallet_iframe`: browser p50 `2960ms`, SDK p50
    `2419ms`, `walletRegisterPrepareWaitMs` p50 `0ms`,
    `emailOtpEnrollmentMaterialMs` p50 `484ms`, `ed25519EvaluationArtifactMs`
    p50 `419ms`, `thresholdEd25519SessionPersistenceMs` p50 `1146ms`.
  - `email_otp_ed25519_only_host_origin`: browser p50 `2284ms`, SDK p50
    `2205ms`, `walletRegisterPrepareWaitMs` p50 `367ms`,
    `ed25519EvaluationArtifactMs` p50 `409ms`,
    `thresholdEd25519SessionPersistenceMs` p50 `1144ms`.
  - `email_otp_ed25519_and_ecdsa_host_origin`: browser p50 `2359ms`, SDK p50
    `2297ms`, `walletRegisterPrepareWaitMs` p50 `382ms`,
    `ed25519EvaluationArtifactMs` p50 `423ms`,
    `thresholdEd25519SessionPersistenceMs` p50 `1169ms`.

Read:

- Wallet iframe hides server prepare wait, but iframe browser-observed overhead
  is still about `600ms` to `700ms` versus host-origin in this benchmark.
- Host-origin still waits on server prepare, so refactor-62/66 overlap remains
  valuable there.
- `thresholdEd25519SessionPersistenceMs` around `1.14s` p50 is now the dominant
  Email OTP registration tail after HSS prepare overlap.
- Next comparison still needs same-build passkey p50s against the latest
  retained refactor-64 baselines.

### Phase 6B: Email OTP Ed25519 Session-Persistence Tail Deferral

Status: kept as a narrow latency optimization on June 11, 2026.

Change:

- [x] Stop reconstructing `xClientBaseB64u` synchronously inside
      `persistRegisteredThresholdEd25519Session` for Email OTP registration.
- [x] Persist the Email OTP Ed25519 warm-session record without client-base
      metadata when registration already has fresh PRF material.
- [x] Hydrate the volatile warm session immediately so the just-registered
      account remains signable.
- [x] Keep sealed-session persistence strict: exact sealed records still require
      restore metadata, and Email OTP Ed25519 sealing is deferred until
      client-base metadata is cached.
- [x] Route Email OTP availability checks through the combined warm-session
      status reader so freshly cached PRF material can satisfy the immediate
      signing-lane postcondition when the Email OTP worker does not yet hold
      material.
- [x] Add available-lane coverage for freshly hydrated Email OTP Ed25519 records
      before client-base caching.

Rejected intermediate probes:

- Run `20260611-081433Z` removed the synchronous reconstruction and dropped
  `thresholdEd25519SessionPersistenceMs` to about `25ms`, but sealed record
  writes failed because Email OTP Ed25519 sealed-session records require
  `xClientBaseB64u`.
- Run `20260611-081922Z` deferred sealed writes and dropped
  `thresholdEd25519SessionPersistenceMs` to about `2ms`, but failed
  `[WalletRuntimePostcondition] ed25519_lane_missing` because the postcondition
  path used a worker-only Email OTP status reader.

Validation:

- `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
- `pnpm -C packages/sdk-web run build:sdk-full`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts
  --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts
  --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/seamsWeb.emailOtp.unit.test.ts --reporter=line`
- `pnpm benchmark:registration-flow:report-only -- --group email_otp
  --skip-doc-sync`

Benchmark note:

- Final retained run: `20260611-082802Z`, all four Email OTP scenarios passed.
- Before/after p50s versus the Phase 6A five-run matrix:
  - `email_otp_ed25519_only_wallet_iframe`: browser `2949ms -> 1787ms`, SDK
    `2360ms -> 1211ms`, session persistence `1149ms -> 2ms`.
  - `email_otp_ed25519_and_ecdsa_wallet_iframe`: browser `2960ms -> 1813ms`,
    SDK `2419ms -> 1256ms`, session persistence `1146ms -> 2ms`.
  - `email_otp_ed25519_only_host_origin`: browser `2284ms -> 1130ms`, SDK
    `2205ms -> 1058ms`, session persistence `1144ms -> 2ms`.
  - `email_otp_ed25519_and_ecdsa_host_origin`: browser `2359ms -> 1148ms`,
    SDK `2297ms -> 1090ms`, session persistence `1169ms -> 2ms`.
- Immediate signing-lane assertion stayed cheap after the fix: p50 `3ms` to
  `11ms` across the four scenarios.
- Same-build passkey smoke run `20260611-083032Z` passed all four scenarios and
  showed no passkey session-persistence regression:
  - `passkey_ed25519_only_wallet_iframe`: browser p50 `2397ms`, SDK p50
    `1565ms`, session persistence p50 `1ms`.
  - `passkey_ed25519_and_ecdsa_wallet_iframe`: browser p50 `2452ms`, SDK p50
    `1615ms`, session persistence p50 `1ms`.
  - `passkey_ed25519_only_host_origin`: browser p50 `1568ms`, SDK p50
    `1193ms`, session persistence p50 `1ms`.
  - `passkey_ed25519_and_ecdsa_host_origin`: browser p50 `1601ms`, SDK p50
    `1228ms`, session persistence p50 `1ms`.
- Compared with the latest retained refactor-64 benchmark in
  `docs/benchmarks/registration-flow.md` (`20260611-041314Z`), same-build
  passkey SDK p50s moved `1616/1643/1236/1261ms -> 1565/1615/1193/1228ms`.
  Browser p50s moved `2257/2529/1624/1644ms -> 2397/2452/1568/1601ms`; the
  wallet-iframe Ed25519-only browser p50 regression is in auto-confirm/transport
  variance, while SDK p50 improved.
- Prepare-overlap diagnostics from the retained Email OTP and passkey runs:
  - `walletRegisterPrepareWaitMs` p50 is `0ms` for all wallet-iframe scenarios.
  - Host-origin p50 wait is `368/374ms` for Email OTP, because OTP has no
    passkey prompt window to hide server prepare in the current harness.
  - Host-origin p50 wait is `34/27ms` for passkey, because passkey credential
    collection hides almost all server prepare time.
- Rejected scheduling-yield probe `20260611-083610Z`:
  - Added a `setTimeout(0)` yield immediately after starting
    `/wallets/register/prepare`.
  - `email_otp_ed25519_only_host_origin` still reported
    `walletRegisterPrepareWaitMs` p50 `373ms`, with SDK p50 `1057ms`.
  - Conclusion: the host-origin Email OTP wait is not a browser dispatch-turn
    issue. The useful next work is either a real earlier Email OTP preparation
    window or lower HSS prepare cost.

Read:

- This is a high-value critical-path removal: about `1.15s` SDK p50 improvement
  across the Email OTP matrix.
- The remaining Email OTP Ed25519 p50 tail is now dominated by server prepare
  and HSS worker artifact construction, not local session persistence.
- Follow-up work should measure passkey scenarios on the same build and then
  focus on shared registration prepare overlap rather than more Email
  OTP-specific tails.

### Phase 6C: Google Email OTP Early Registration Prepare

Status: implemented as a narrow host-origin slice on June 11, 2026.

Change:

- [x] Add an explicit internal `WalletRegistrationPrecomputeHandle`.
- [x] Keep public `registerWallet` behavior unchanged: normal callers still
      start warmup, intent, digest, and `/wallets/register/prepare` inside
      `registerWallet`.
- [x] Add internal `registerWalletWithStartedPrecompute` for callers that
      already started a matching registration prepare handle.
- [x] Scope-check precompute reuse by auth method, wallet scope, rp id, signer
      mode, and NEAR account id before consuming the handle.
- [x] Start Google Email OTP registration precompute when the
      `registration_ready` flow is created, before `completeRegistration`.
- [x] Reuse the started handle when `completeRegistration` attaches prewarmed
      Email OTP enrollment material.
- [x] Dispose the started handle on completion, cancellation, and wallet-id
      reroll.
- [x] Preserve wallet-iframe routing: when the parent runtime would route final
      registration into the wallet iframe, early precompute is marked
      unavailable and completion falls back to the existing `registerWallet`
      domain path.
- [x] Add flow tests proving early precompute starts, precomputed completion is
      used, reroll starts a fresh precompute, cancellation disposes the flow,
      and unavailable precompute falls back to routed registration.

Validation:

- `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line`
- `pnpm -C packages/sdk-web run build:prepare`
- `pnpm benchmark:registration-flow:report-only -- --scenario
  email_otp_ed25519_only_host_origin`

Read:

- This targets the host-origin Email OTP wait identified in the retained
  benchmark: `walletRegisterPrepareWaitMs` p50 around `368ms` to `374ms`.
- Focused run `20260611-120433Z` passed `5 / 5` runs for
  `email_otp_ed25519_only_host_origin`: browser p50 `1115ms`, SDK p50
  `1041ms`, `walletRegisterPrepareWaitMs` p50 `0ms`, and
  `walletRegisterPrepareMs` p50 `376ms`.
- The same run shows the next exposed host-origin tail:
  `inputValidationMs` p50 `367ms`. Once server prepare wait is hidden, NEAR
  account existence preflight becomes the visible pre-start cost for this
  scenario. The next client-orchestration slice should move account preflight
  into the same early handle or prove that the server-provided Google OTP
  registration offer already gives enough freshness to avoid repeating the
  slow preflight at completion.
- Wallet-iframe Email OTP already showed `walletRegisterPrepareWaitMs` p50
  `0ms`, so this slice intentionally preserves the existing iframe-routed path
  instead of starting parent-origin prepare work that the iframe cannot consume.
- This is not the full prepared-registration lifecycle. The server route still
  returns the current `prepared` response shape, duplicate attempts still hit
  the narrow rate-limit gate, and `client_only` / reusable pending-attempt
  states remain future Phase 2/3 work.

### Phase 6D: Google Email OTP Early Account Preflight Experiment

Status: rejected on June 11, 2026.

Attempt:

- [x] Split registration input validation into cheap local checks and a typed
      NEAR account-existence preflight result.
- [x] Start the best-effort NEAR account-existence read inside
      `WalletRegistrationPrecomputeHandle`.
- [x] Add `accountPreflightMs` timing to distinguish hidden account lookup work
      from visible `inputValidationMs` wait.
- [x] Run SDK type checks after the account-preflight overlap.
- [x] Run focused Google Email OTP flow tests.
- [x] Benchmark `email_otp_ed25519_only_host_origin` and compare against Phase
      6C.
- [x] Revert the code path after benchmark comparison showed no material
      latency win.

Read:

- Phase 6C reduced `walletRegisterPrepareWaitMs` p50 to `0ms`, exposing
  `inputValidationMs` p50 around `367ms`.
- Rebuilt benchmark run `20260611-121256Z` moved `inputValidationMs` p50 to
  `0ms` and reported `accountPreflightMs` p50 `4ms`, but
  `walletRegisterPrepareWaitMs` regressed to `370ms`.
- Net result was slightly worse than Phase 6C:
  - Phase 6C run `20260611-120433Z`: browser p50 `1115ms`, SDK p50 `1041ms`.
  - Phase 6D run `20260611-121256Z`: browser p50 `1138ms`, SDK p50 `1067ms`.
- The harness calls `completeRegistration()` immediately after the Google
  exchange returns. With no human think-time, moving the account lookup earlier
  only changes which bucket waits; it does not hide both the account lookup and
  HSS prepare.
- Keep the retained Phase 6C behavior. A future version should start server
  prepare earlier than the `registration_ready` flow or reduce the HSS/client
  artifact cost.
- Confirmation run `20260611-121716Z` after reverting the experiment restored
  the retained profile: browser p50 `1141ms`, SDK p50 `1069ms`,
  `inputValidationMs` p50 `372ms`, and `walletRegisterPrepareWaitMs` p50
  `0ms`.

### Phase 7: Benchmarks And Keep Gate

- [x] Add benchmark scenarios for Passkey wallet iframe, Passkey host-origin,
      Email OTP wallet iframe, and Email OTP host-origin.
- [x] Capture five-run p50s for Email OTP wallet iframe and host-origin
      scenarios.
- [x] Keep the Email OTP Ed25519 session-persistence deferral after it passed
      immediate signing-lane assertions and cut SDK p50 by about `1.15s`.
- [x] Capture same-build passkey smoke p50s after the Email OTP availability
      reader change.
- [x] Capture precompute overlap diagnostics for every scenario.
- [x] Compare with the latest retained refactor-64 benchmark.
- [x] Keep the refactor only if p50 post-auth visible registration improves
      materially without increasing server CPU amplification under gate tests.
- [x] Run server type checks for the retained Email OTP session-persistence
      deferral and prepare-gate changes.
- [x] Run SDK type checks for the retained Email OTP session-persistence
      deferral.
- [x] Run focused registration route/store tests for the retained deferral and
      prepare-gate boundary.
- [x] Run registration smoke after the prepare gate and earlier-prepare
      orchestration changes.

## Closed Baseline Criteria

The retained refactor-66 slice met the practical keep bar:

- server HSS prepare is gated by short-window attempt policy
- abuse tests show repeated same-source prepare attempts do not trigger
  unbounded HSS prepare
- Google Email OTP host-origin prepare wait is hidden in the retained flow
- Email OTP session-persistence tail is removed from the critical path
- product smoke and focused unit/type checks passed for the retained slices

The full prepared-registration lifecycle keep rules are now Router A/B
requirements:

- Passkey and Email OTP share one prepared-registration lifecycle
- duplicate normal-user clicks reuse or return the existing attempt
- scope binding catches mismatched intent, auth method, account, signing root,
  and HSS context
- cleanup prevents long-lived unused prepared packages
- diagnostics remain observational and cannot influence proof verification or
  cryptographic binding

## Deferred Router A/B Decisions

- First production gate window: `5s`, `8s`, or `10s`.
- Duplicate-click response shape: full existing preparation response or typed
  `reuse_existing` state.
- Privacy-preserving device/session identifier for abuse defense.
- Server HSS prepare execution model: inline at low load, bounded queue under
  pressure, or queue for all prepare work.
- Router A/B post-auth visible p50 keep gate: `700ms`, `800ms`, or `1000ms`.
