# Optimize Registration 2: Auth-Agnostic Precompute

Date created: June 10, 2026

Status: planned.

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

### Phase 1: Spec And State Model

- [ ] Add `RegistrationAttemptId` if the current id model cannot represent
      attempt reuse cleanly.
- [ ] Add `RegistrationAttemptGateDecision` as a discriminated union.
- [ ] Add `PreparedRegistrationLifecycle` as a discriminated union with
      required identity and scope fields.
- [ ] Add `PreparedRegistrationScope` with Passkey and Email OTP branch
      builders.
- [ ] Add type fixtures rejecting missing identity fields, optional auth method
      fields, mixed lifecycle branches, raw string ids, and broad-spread
      construction.
- [ ] Document TTL, single-use, and abandon semantics at the store boundary.

### Phase 2: Gate Store And Policy

- [ ] Add a registration attempt gate store or extend the existing registration
      ceremony store with gate records.
- [ ] Implement gate keys for IP, email, device/session, org-IP, and org-device.
- [ ] Enforce one active attempt per key per `5s` to `10s`.
- [ ] Return existing pending attempts for normal duplicate clicks.
- [ ] Add server queue saturation policy returning `client_only`.
- [ ] Add cleanup for expired, abandoned, failed, and consumed attempts.
- [ ] Add unit tests for accepted, reuse, client-only, rejected, expired, and
      consumed states.

### Phase 3: Server Prepared Registration Route

- [ ] Extend `/wallets/register/prepare` to evaluate the gate before HSS server
      prepare.
- [ ] Split route output into `prepared`, `preparing`, `client_only`, and
      `rejected` states.
- [ ] Add bounded concurrency for server HSS prepare.
- [ ] Persist prepared HSS material under the shared prepared-registration
      lifecycle.
- [ ] Ensure `/wallets/register/start` consumes a prepared package only after
      authority proof verification and scope matching.
- [ ] Add route tests for Passkey and Email OTP prepared package consumption.
- [ ] Add abuse tests proving repeated unauthenticated starts do not trigger
      unbounded HSS prepare.

### Phase 4: Client Runtime Orchestration

- [ ] Start wallet iframe and signing worker warmup as soon as registration
      intent exists.
- [ ] Start client HSS precompute before Passkey `navigator.credentials.create`
      and before Email OTP input.
- [ ] Store in-flight client artifact state under `registrationAttemptId`.
- [ ] Reuse prepared client artifact after authority proof succeeds.
- [ ] Abandon client artifact state on TTL expiry, auth failure, account change,
      or attempt replacement.
- [ ] Add lifecycle states that make invalid combinations unrepresentable:
      client-preparing, client-ready, server-preparing, server-ready,
      client-only, authority-pending, authority-verified, start-ready.
- [ ] Add SDK tests for Passkey and Email OTP orchestration.

### Phase 5: Passkey Flow

- [ ] Start gated server prepare before WebAuthn prompt whenever the gate
      accepts the attempt.
- [ ] Start client artifact precompute before `navigator.credentials.create`.
- [ ] Measure overlap between WebAuthn prompt time and HSS readiness.
- [ ] Handle fast TouchID completion by waiting only for the remaining prepared
      material.
- [ ] Ensure WebAuthn challenge verification remains the authority gate for
      account creation.

### Phase 6: Email OTP Flow

- [ ] Start client artifact precompute before or alongside OTP challenge send.
- [ ] Start gated server prepare after OTP send rate limits accept the request.
- [ ] Reuse existing Email OTP registration attempt records where they already
      provide normalized email and operation scope.
- [ ] Measure overlap between OTP input time and HSS readiness.
- [ ] Ensure OTP verification remains the authority gate for account creation.

### Phase 7: Benchmarks And Keep Gate

- [ ] Add benchmark scenarios for Passkey wallet iframe, Passkey host-origin,
      Email OTP wallet iframe, and Email OTP host-origin.
- [ ] Capture precompute overlap diagnostics for every scenario.
- [ ] Compare with the latest retained refactor-64 benchmark.
- [ ] Keep the refactor only if p50 post-auth visible registration improves
      materially without increasing server CPU amplification under gate tests.
- [ ] Run server type checks, SDK type checks, registration smoke, and targeted
      route/store tests.

## Keep And Revert Rules

Keep this refactor only if:

- Passkey and Email OTP both use the same prepared-registration lifecycle
- server HSS prepare is gated by short-window attempt policy
- duplicate normal-user clicks reuse or return the existing attempt
- abuse tests show unauthenticated clients cannot force unbounded HSS prepare
- scope binding catches mismatched intent, auth method, account, signing root,
  and HSS context
- post-auth visible p50 improves in product smoke

Redesign if:

- server precompute starts before the attempt gate
- prepared material can be consumed by a different auth method or intent
- cleanup leaves long-lived unused prepared packages
- diagnostics influence proof verification or cryptographic binding
- Passkey and Email OTP drift into separate lifecycle implementations

## Open Questions

- What is the first production gate window: `5s`, `8s`, or `10s`?
- Should duplicate clicks reuse the full existing preparation response or return
  a typed `reuse_existing` state that the SDK resolves?
- Which device/session identifier is acceptable for privacy and abuse defense?
- Should server HSS prepare run inline for low load and queue only under
  pressure, or should every prepare go through the bounded worker queue?
- What post-auth visible p50 is the keep gate: `700ms`, `800ms`, or `1000ms`?
