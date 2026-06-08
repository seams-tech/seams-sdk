# Registration Preparation Parallelism

Date created: June 8, 2026

Status: planning.

## Goal

Move registration preparation work under the user's passkey or Email OTP proof
collection window.

The target is a registration flow where the SDK starts every safe preparation
task as soon as the registration intent exists, then consumes the prepared
material only after the final authority proof verifies. This should reduce the
post-proof path to proof verification, prepared-material binding, HSS respond
and finalize, persistence, and readiness checks.

Near-term latency target:

- full browser wallet-iframe registration p50 at or below `1500ms`
- `/wallets/register/start` no longer dominated by fresh
  `registrationHssPrepareMs`
- no weakening of registration intent, authority, HSS, signing-root, or wallet
  scope binding

## Relationship To Existing Plans

- `docs/refactor-59-optimize.md` owns the full registration benchmark and the
  timing report that showed `/wallets/register/start` p50 around `376ms`,
  dominated by `registrationHssPrepareMs`.
- `docs/refactor-55-hss-optimize-registration.md` owns historical HSS
  registration optimization work and the older registration-start pipelining
  candidate.
- `docs/refactor-62-hss-prepare-preauth.md` owns the HSS-specific preauth
  prepare contract and binding rules.
- This plan owns full registration orchestration across grant/intent work,
  wallet iframe warmup, worker/WASM init, HSS preauth prepare, optional account
  reservation, route contracts, and lifecycle state.

## Current Flow

Current browser registration is mostly serial:

```text
create managed registration grant
  -> create registration intent
  -> verify local registration intent digest
  -> collect passkey create or Email OTP proof
  -> POST /wallets/register/start
       -> load and consume registration intent
       -> verify authority proof
       -> prepare Ed25519 HSS server session
       -> prepare optional ECDSA route-local context
       -> persist registration ceremony
  -> prepare client HSS request
  -> POST /wallets/register/hss/respond
  -> build client-owned HSS evaluation artifact
  -> POST /wallets/register/finalize
  -> local persistence and readiness checks
```

The measured problem is that `registrationHssPrepareMs` runs after the user has
already completed the passkey or OTP proof. That makes HSS server prepare part
of the post-auth critical path.

## Target Flow

The new flow should start independent preparation tasks as soon as their inputs
exist:

```text
validate local inputs
  -> start wallet iframe warmup and signing worker/WASM init
  -> create managed registration grant
  -> create registration intent
  -> verify local registration intent digest
  -> start registration preparation
       -> Ed25519 HSS server prepare
       -> optional ECDSA prepare context
       -> optional account reservation
       -> route diagnostics preallocation
  -> collect passkey create or Email OTP proof in parallel
  -> wait until proof and required preparation are both ready
  -> POST /wallets/register/start with registrationPreparationId
       -> load prepared record
       -> verify authority proof
       -> atomically consume registration intent for the verified preparation
       -> bind prepared material to the verified intent and authority
       -> persist registration ceremony
  -> prepare client HSS request
  -> POST /wallets/register/hss/respond
  -> build client-owned HSS evaluation artifact
  -> POST /wallets/register/finalize
  -> local persistence and readiness checks
```

The route contract changes are intentional. The start route should receive a
typed `registrationPreparationId` for signer modes that require preauth
material. Missing prepared material should be a typed lifecycle error, because
the optimized flow is the only flow this refactor should support.

## Preparation Work Items

Safe to start before the final proof:

- wallet iframe load, handshake, and router warmup
- signing engine worker startup
- HSS client signer WASM init
- Email OTP worker startup
- registration intent digest computation
- Ed25519 HSS server prepare after the registration intent exists
- optional ECDSA registration prepare context after the registration intent
  exists
- optional bounded account reservation after the registration intent exists

Must wait for the final proof:

- WebAuthn registration verification
- Email OTP registration proof verification
- registration intent consumption
- ceremony persistence with verified authority
- HSS respond
- HSS finalize
- wallet, signer, credential, session, and key publication persistence
- any irreversible NEAR account creation or key publication

Optional account reservation is a latency and race-control optimization only. It
must expire quickly, be quota-bound by the managed registration grant or project
policy, and still require final existence checks before account creation.

## Route Contract

Add a registration preparation route:

```text
POST /wallets/register/prepare
```

Request:

```ts
type WalletRegistrationPrepareRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  work: WalletRegistrationPrepareWork;
};

type WalletRegistrationPrepareWork =
  | {
      kind: 'ed25519_hss';
      accountReservation: AccountReservationRequest;
      ecdsa?: never;
    }
  | {
      kind: 'ed25519_hss_and_ecdsa';
      accountReservation: AccountReservationRequest;
      ecdsa: EcdsaRegistrationPrepareRequest;
    }
  | {
      kind: 'ecdsa_only';
      accountReservation: AccountReservationRequest;
      ecdsa: EcdsaRegistrationPrepareRequest;
    };
```

Response:

```ts
type WalletRegistrationPrepareResponse =
  | {
      ok: true;
      state: 'prepared';
      registrationPreparationId: RegistrationPreparationId;
      expiresAtMs: number;
      prepared: WalletRegistrationPreparedBranches;
      diagnostics: RegistrationPrepareDiagnostics;
    }
  | {
      ok: true;
      state: 'preparing';
      registrationPreparationId: RegistrationPreparationId;
      expiresAtMs: number;
      diagnostics: RegistrationPrepareDiagnostics;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };
```

Update `/wallets/register/start`:

```ts
type WalletRegistrationStartRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  registrationPreparationId: RegistrationPreparationId;
  authority: WalletRegistrationStartAuthority;
};
```

The route parser should reject legacy HSS branches, raw session branches,
ad-hoc prepared material, and start requests without a preparation id for
prepared signer modes.

## Lifecycle Types

Model SDK registration with a discriminated lifecycle. Core functions should
accept the narrow branch they need.

```ts
type RegistrationPreparationLifecycle =
  | {
      kind: 'intent_allocated';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
    }
  | {
      kind: 'preauth_preparing';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
      registrationPreparationId: RegistrationPreparationId;
      startedAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'preauth_prepared';
      intent: RegistrationIntentV1;
      registrationIntentGrant: RegistrationIntentGrant;
      registrationIntentDigestB64u: string;
      registrationPreparationId: RegistrationPreparationId;
      prepared: WalletRegistrationPreparedBranches;
      expiresAtMs: number;
    }
  | {
      kind: 'authority_collected';
      prepared: RegistrationPreauthPreparedLifecycle;
      authority: WalletRegistrationStartAuthority;
    }
  | {
      kind: 'start_ready';
      prepared: RegistrationPreauthPreparedLifecycle;
      authority: WalletRegistrationStartAuthority;
    }
  | {
      kind: 'ceremony_started';
      registrationCeremonyId: string;
      started: WalletRegistrationStartedBranches;
    };
```

Do not use broad object spreads to construct these branches. Use branch-specific
builders that require all identity, digest, preparation, and authority fields.

## Client Implementation Plan

### Phase 1: Warmup Inventory

- [ ] Identify wallet iframe warmup calls that are safe before authority proof.
- [ ] Identify signing worker and HSS WASM init calls that can run without user
      secrets.
- [ ] Identify Email OTP worker init paths that can run before proof.
- [ ] Add diagnostics for warmup start, warmup ready, and warmup wait time.
- [ ] Add tests proving diagnostics do not influence registration control flow.

### Phase 2: Preparation Route Client

- [ ] Add `RegistrationPreparationId` as a branded domain id.
- [ ] Add `createWalletRegistrationPreparation` to the relayer RPC client.
- [ ] Parse prepare responses into discriminated result branches at the RPC
      boundary.
- [ ] Update `startWalletRegistration` to require
      `registrationPreparationId`.
- [ ] Add type fixtures rejecting raw strings, missing preparation id, mixed
      work branches, and direct object-literal invalid lifecycle states.

### Phase 3: Registration Orchestration

- [ ] Start iframe warmup and worker/WASM init before grant creation where the
      current platform runtime can do so.
- [ ] Start `/wallets/register/prepare` immediately after the registration
      intent digest verifies locally.
- [ ] Collect passkey create or Email OTP proof in parallel with preparation.
- [ ] Wait for both `preauth_prepared` and `authority_collected` before calling
      `/wallets/register/start`.
- [ ] Keep user-visible progress events stable while moving internal work
      earlier.
- [ ] Split timing buckets into preparation wait, proof wait, and start-route
      execution.

### Phase 4: Server Route And Store Contract

- [ ] Add a prepared-registration record to `RegistrationCeremonyStore`.
- [ ] Persist preparation records separately from verified registration
      ceremonies.
- [ ] Add an atomic consume method that consumes an intent only after the
      caller supplies the verified digest, preparation id, and expected scope.
- [ ] Bind preparation records to grant, digest, wallet id, rp id, signer
      selection, signing root, expected origin, participant ids, and expiry.
- [ ] Consume or invalidate the preparation record when
      `/wallets/register/start` succeeds.
- [ ] Expire abandoned preparation records aggressively.
- [ ] Keep raw DB parsing inside the store boundary.

### Phase 5: Optional Account Reservation

- [ ] Define `AccountReservationRequest` as an explicit branch with required
      wallet id, rp id, intent digest, reservation ttl, and reservation purpose.
- [ ] Add a disabled-by-default reservation policy in server config.
- [ ] Implement memory-store reservation first for tests and benchmarks.
- [ ] Add durable-store reservation only if benchmarks show a real win.
- [ ] Recheck account availability during finalize or account creation.
- [ ] Add abuse tests for abandoned reservations and repeated preparation.

### Phase 6: Benchmark And Keep Decision

- [ ] Add benchmark buckets for preparation route, preparation wait, iframe
      warmup, worker init, WASM init, and account reservation.
- [ ] Run `pnpm benchmark:registration-flow:smoke` before and after.
- [ ] Keep the change only if the post-proof start path improves materially.
- [ ] Record retained results in `docs/benchmarks/registration-flow.md`.
- [ ] Update `docs/refactor-59-optimize.md` with the new bottleneck ranking.

## Acceptance Criteria

- `/wallets/register/start` no longer runs fresh Ed25519 HSS prepare for
  prepared signer modes.
- Start requests require a `registrationPreparationId` for prepared signer
  modes.
- Prepared registration records cannot be reused across wallet id, rp id,
  digest, signing root, signer selection, expected origin, participant ids, or
  auth method kind.
- Registration intent consumption still happens only after authority proof
  verification.
- Prepared records expire and cannot create wallets, sessions, keys, or NEAR
  accounts by themselves.
- Client lifecycle state makes invalid proof/preparation combinations
  unrepresentable.
- Benchmarks show the post-proof path and full registration timing before the
  change is kept.

## Validation

Cheapest useful checks for this refactor:

- `pnpm -C sdk type-check`
- focused type fixtures for registration lifecycle and relayer RPC contracts
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationIntentAllocation.unit.test.ts ./unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`
- `pnpm benchmark:registration-flow:smoke` for keep decisions
- `git diff --check`

Run broader source guards only after the route/store shape lands, because this
touches public registration contracts, persistence boundaries, and auth-adjacent
flow state.
