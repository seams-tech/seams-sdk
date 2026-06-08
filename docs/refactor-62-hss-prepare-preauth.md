# HSS Prepare Preauth

Date created: June 8, 2026

Status: planning.

## Goal

Move Ed25519 HSS server prepare out of the post-auth registration critical path.

Today `/wallets/register/start` verifies the final authority proof and then runs
`threshold.ed25519Hss.prepareForRegistration`. Current benchmark diagnostics
show that route is dominated by `registrationHssPrepareMs`. To hit the `1500ms`
registration target, HSS server prepare should be precomputed or started while
the user is completing passkey create or Email OTP proof, then bound safely to
the verified registration proof.

## Relationship To Existing Plans

- `docs/refactor-61-registration-prep-parallelism.md` owns the full preparation
  pipeline.
- `docs/refactor-55-hss-optimize-registration.md` owns HSS registration
  optimization history.
- `docs/refactor-59-optimize.md` owns the measured registration benchmark.
- `docs/refactor-64-hss-protocol-runtime-latency.md` owns deeper HSS runtime
  and protocol latency work.
- This plan owns the HSS-specific preauth prepare route, persisted state,
  binding rules, invalid-state tests, and benchmark gate.

## Current State

Current server flow in `AuthService.startWalletRegistration`:

```text
load registration intent by grant
  -> verify supplied digest and request intent
  -> consume registration intent
  -> verify passkey or Email OTP authority
  -> create registrationCeremonyId
  -> threshold.ed25519Hss.prepareForRegistration(...)
  -> persist registration ceremony with signerState.kind = "ed25519_prepared"
  -> return ceremonyHandle, preparedSession, clientOtOfferMessageB64u
```

The HSS prepare request is already scoped to the registration intent fields:

- `orgId`
- `signingRootId`
- `signingRootVersion`
- Ed25519 `nearAccountId`
- `rpId`
- `keyPurpose`
- `keyVersion`
- `participantIds`
- `derivationVersion`

The missing piece is a persisted preauth record that proves these prepared HSS
bytes belong to the final verified registration authority.

## Target State

Add a preauth HSS prepare lifecycle:

```text
registration intent allocated
  -> POST /wallets/register/prepare
       -> validate grant, digest, and intent without consuming the grant
       -> compute HSS prepare scope
       -> run Ed25519 HSS prepare
       -> persist prepared HSS branch under registrationPreparationId
  -> user completes passkey create or Email OTP proof
  -> POST /wallets/register/start
       -> load prepared HSS record by registrationPreparationId
       -> load registration intent without consuming it
       -> verify authority proof
       -> compare prepared scope with loaded intent and verified authority
       -> atomically consume the registration intent for that preparation
       -> persist registration ceremony using the prepared HSS branch
       -> consume prepared HSS record
```

The preauth record is inert. It must never create a wallet, signer, session,
credential binding, NEAR account, or durable wallet key.

## HSS Preparation Record

Persist a dedicated record at the `RegistrationCeremonyStore` boundary.

```ts
type StoredWalletRegistrationPreparation =
  | StoredWalletRegistrationHssPreparationPreparing
  | StoredWalletRegistrationHssPreparationPrepared
  | StoredWalletRegistrationHssPreparationFailed;

type StoredWalletRegistrationHssPreparationBase = {
  registrationPreparationId: RegistrationPreparationId;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  orgId: string;
  expectedOrigin: string;
  signingRootId: string;
  signingRootVersion: string;
  ed25519Scope: StoredEd25519RegistrationPrepareScope;
  createdAtMs: number;
  expiresAtMs: number;
};

type StoredWalletRegistrationHssPreparationPreparing =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_preparing';
    prepared?: never;
    failure?: never;
    consumedAtMs?: never;
  };

type StoredWalletRegistrationHssPreparationPrepared =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_prepared';
    prepared: StoredEd25519RegistrationPrepared;
    failure?: never;
    consumedAtMs?: never;
  };

type StoredWalletRegistrationHssPreparationFailed =
  StoredWalletRegistrationHssPreparationBase & {
    kind: 'hss_prepare_failed';
    failure: {
      code: string;
      message: string;
    };
    prepared?: never;
    consumedAtMs?: never;
  };
```

Use required fields for every identity and lifecycle value. Raw DB shapes should
parse into these branches once, inside `RegistrationCeremonyStore`.

## Scope Binding

The HSS prepared branch must bind to:

- `registrationPreparationId`
- `registrationIntentGrant`
- `registrationIntentDigestB64u`
- canonical `RegistrationIntentV1`
- wallet id
- rp id
- auth method kind
- expected origin for passkey registration
- org id
- signing root id
- signing root version
- Ed25519 near account id
- Ed25519 key purpose
- Ed25519 key version
- Ed25519 derivation version
- Ed25519 participant ids
- HSS ceremony handle
- HSS context binding
- expiry

`/wallets/register/start` must verify the prepared scope against the loaded
intent and the verified authority. Any mismatch is an `invalid_state` or
`scope_mismatch` result, and the prepared record should be consumed or failed
according to the abuse policy.

## Route Contract

Add:

```text
POST /wallets/register/prepare
```

The route accepts only registration intent fields and preparation policy. It
does not accept WebAuthn registration output, Email OTP proof, client HSS
request, HSS evaluation artifact, session policy, or final wallet metadata.

Start route change:

```ts
type WalletRegistrationStartRequest = {
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  intent: RegistrationIntentV1;
  registrationPreparationId: RegistrationPreparationId;
  authority: WalletRegistrationStartAuthority;
};
```

For `ed25519_only` and `ed25519_and_ecdsa`, the start route requires a prepared
HSS record in `hss_prepare_prepared` state. If the record is still preparing,
the client should wait through the preparation lifecycle and call start after
the record is ready.

## Server Implementation Plan

### Phase 1: Domain Types

- [ ] Add `RegistrationPreparationId` as a branded id.
- [ ] Add `StoredWalletRegistrationPreparation` union branches.
- [ ] Add `StoredEd25519RegistrationPrepareScope` with required scope fields.
- [ ] Add builders for `hss_prepare_preparing`, `hss_prepare_prepared`, and
      `hss_prepare_failed`.
- [ ] Add `assertNever` coverage for preparation lifecycle switches.
- [ ] Add type fixtures rejecting missing identity fields, mixed prepared/failed
      branches, raw string ids, and broad-spread construction.

### Phase 2: Store Boundary

- [ ] Extend `RegistrationCeremonyStore` with `putPreparation`,
      `getPreparation`, `updatePreparation`, and `takePreparation`.
- [ ] Add an atomic intent consume method that requires grant, digest,
      preparation id, and expected scope after authority verification.
- [ ] Implement memory-store support first.
- [ ] Implement Postgres and Cloudflare Durable Object parsing only at the store
      boundary.
- [ ] Add aggressive expiry pruning for abandoned records.
- [ ] Add tests for expired, consumed, failed, and scope-mismatched records.

### Phase 3: Prepare Route

- [ ] Add `parseWalletRegistrationPrepareBody` beside
      `parseWalletRegistrationStartBody`.
- [ ] Reject raw HSS payloads, authority proofs, client requests, session
      policy, and finalization fields on the prepare route.
- [ ] Load the intent by grant without consuming it.
- [ ] Recompute and verify the canonical registration intent digest.
- [ ] Normalize signing root and Ed25519 scope with the same helpers used by
      `startWalletRegistration`.
- [ ] Run `threshold.ed25519Hss.prepareForRegistration`.
- [ ] Persist the prepared branch with the generated
      `registrationPreparationId`.
- [ ] Return only the prepared HSS client-facing fields and preparation id.

### Phase 4: Start Route Consumption

- [ ] Require `registrationPreparationId` for Ed25519 registration modes.
- [ ] Load the prepared HSS record before consuming the registration intent.
- [ ] Load the registration intent without consuming it.
- [ ] Verify passkey or Email OTP authority as the route does today.
- [ ] Compare prepared scope with the loaded intent and verified authority.
- [ ] Consume the registration intent only after authority verification and
      scope comparison both pass.
- [ ] Persist the registration ceremony using the preauth prepared HSS branch.
- [ ] Consume the prepared record after ceremony persistence succeeds.
- [ ] Do not rerun Ed25519 HSS prepare inside `/wallets/register/start`.

### Phase 5: Combined Ed25519 And ECDSA

- [ ] Decide whether ECDSA prepare context lives in the same preparation record
      or a sibling `ecdsa_prepare_prepared` branch.
- [ ] Keep ECDSA client bootstrap after the user proof because it needs
      passkey PRF or Email OTP root-share material.
- [ ] Bind ECDSA prepare context to the same registration preparation id,
      intent digest, wallet id, rp id, signing root, key scope, and participant
      ids.
- [ ] Add combined-mode tests proving Ed25519 and ECDSA prepared branches cannot
      be crossed between preparations.

### Phase 6: Observability And Benchmark

- [ ] Add route diagnostics for `registrationPreauthHssPrepareMs`,
      `registrationPreparationPersistMs`, `registrationPreparationLoadMs`,
      `registrationPreparationScopeCheckMs`, and post-auth
      `registrationHssPrepareMs`.
- [ ] Keep `registrationHssPrepareMs` in start diagnostics as `0ms` or absent
      only after benchmark code can distinguish preauth prepare from start
      prepare.
- [ ] Update the registration benchmark summary with preauth prepare buckets.
- [ ] Run `pnpm benchmark:registration-flow:smoke` before and after.
- [ ] Keep the route-shape change only if `/wallets/register/start` p50/p95
      drops materially and full registration improves.

## Abuse And Cleanup Rules

- Preparation records expire quickly, defaulting to the same or shorter TTL as
  registration intents.
- Repeated prepare attempts for the same grant should return the existing
  in-flight or prepared record when the scope is byte-identical.
- Repeated prepare attempts with a different intent digest, signer selection,
  expected origin, signing root, or participant ids fail.
- Failed HSS prepare records should retain only code, message, scope, and
  expiry.
- Abandoned records should be pruned by every store implementation.
- Prepare route rate limits should key by project, managed grant subject,
  wallet id, rp id, and IP or deployment-specific caller identity.

## Acceptance Criteria

- Ed25519 HSS prepare can start before passkey create or Email OTP proof
  finishes.
- `/wallets/register/start` consumes a prepared HSS record for Ed25519
  registration modes.
- Prepared HSS records cannot be reused across intent digest, wallet, rp id,
  auth method, expected origin, signing root, Ed25519 signer spec, participant
  ids, or expiry.
- Registration intent consumption and ceremony persistence still require a
  verified final authority proof.
- Preauth prepare does not create durable wallet credentials, sessions, NEAR
  accounts, or signer records.
- Store parsing keeps raw persistence shapes out of core registration logic.
- Type fixtures make invalid preparation lifecycle states unrepresentable.
- Benchmark evidence shows the retained route change moves
  `registrationHssPrepareMs` off the post-auth critical path.

## Validation

Run focused checks while implementing:

- `pnpm -C sdk type-check`
- preparation lifecycle type fixtures
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationIntentAllocation.unit.test.ts ./unit/registrationCeremonyStore.unit.test.ts ./unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`
- `pnpm benchmark:registration-flow:smoke`
- `git diff --check`

Run broad source guards after the store and route contracts land because this
touches persistence, public route shapes, auth-adjacent state, and HSS scope
binding.
