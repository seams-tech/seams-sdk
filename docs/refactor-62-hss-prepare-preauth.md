# HSS Prepare Preauth

Date created: June 8, 2026

Status: route split and client overlap landed, benchmarked, and retained.

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

Original server flow in `AuthService.startWalletRegistration`:

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

Implementation note: the first landed slice executes synchronously and persists
`hss_prepare_prepared`. The store boundary already models `preparing` and
`failed` so an async/background prepare worker can be added without changing the
record shape.

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

- [x] Add `RegistrationPreparationId` as a branded id.
- [x] Add `StoredWalletRegistrationPreparation` union branches.
- [x] Add the first `StoredWalletRegistrationHssPreparation` prepared branch.
- [x] Add `StoredEd25519RegistrationPrepareScope` with required scope fields.
- [x] Add builders for `hss_prepare_preparing`, `hss_prepare_prepared`, and
      `hss_prepare_failed`.
- [x] Add `assertNever` coverage for preparation lifecycle switches.
- [x] Add type fixtures rejecting missing identity fields, mixed prepared/failed
      branches, raw string ids, and broad-spread construction.

### Phase 2: Store Boundary

- [x] Extend `RegistrationCeremonyStore` with `putPreparation`,
      `getPreparation`, and `takePreparation`.
- [x] Add `updatePreparation` for async preparing/failed transitions.
- [x] Add an atomic intent consume method that requires grant, digest,
      preparation id, and expected scope after authority verification.
- [x] Implement memory-store support first.
- [x] Implement Postgres and Cloudflare Durable Object parsing only at the store
      boundary.
- [x] Add aggressive expiry pruning for abandoned records.
- [x] Add tests for prepared record put/get/take consumption.
- [x] Add tests for expired, failed, and scope-mismatched records.

### Phase 3: Prepare Route

- [x] Add `parseWalletRegistrationPrepareBody` beside
      `parseWalletRegistrationStartBody`.
- [x] Reject raw HSS payloads, authority proofs, client requests, session
      policy, and finalization fields on the prepare route.
- [x] Load the intent by grant without consuming it.
- [x] Recompute and verify the canonical registration intent digest.
- [x] Normalize signing root and Ed25519 scope with the same helpers used by
      `startWalletRegistration`.
- [x] Run `threshold.ed25519Hss.prepareForRegistration`.
- [x] Persist the prepared branch with the generated
      `registrationPreparationId`.
- [x] Return only the prepared HSS client-facing fields and preparation id.

### Phase 4: Start Route Consumption

- [x] Require `registrationPreparationId` for Ed25519 registration modes.
- [x] Load the prepared HSS record before consuming the registration intent.
- [x] Load the registration intent without consuming it.
- [x] Verify passkey or Email OTP authority as the route does today.
- [x] Compare prepared scope with the loaded intent and verified authority.
- [x] Consume the registration intent only after authority verification and
      scope comparison both pass.
- [x] Persist the registration ceremony using the preauth prepared HSS branch.
- [x] Consume the prepared record after ceremony persistence succeeds.
- [x] Do not rerun Ed25519 HSS prepare inside `/wallets/register/start`.

### Phase 5: Combined Ed25519 And ECDSA

- [x] Decide whether ECDSA prepare context lives in the same preparation record
      or a sibling `ecdsa_prepare_prepared` branch.
- [x] Keep ECDSA client bootstrap after the user proof because it needs
      factor-derived secret material.
- [x] Bind ECDSA prepare context to the same registration preparation id,
      intent digest, wallet id, rp id, signing root, key scope, and participant
      ids.
- [x] Add combined-mode tests proving Ed25519 start uses the prepared branch in
      combined registration mode.
- [x] Add combined-mode coverage proving the prepared Ed25519 branch is consumed
      after ceremony persistence.
- [x] Add combined-mode tests proving Ed25519 and ECDSA prepared branches cannot
      be crossed between preparations.
- [x] Preserve `registrationPreparationId` through the `/hss/respond` boundary
      parser and Email OTP worker parser so the real combined flow carries the
      same preparation binding that the service tests assert.

### Phase 6: Observability And Benchmark

- [x] Add route diagnostics for `registrationPreauthHssPrepareMs`,
      `registrationPreparationPersistMs`, `registrationPreparationLoadMs`,
      `registrationPreparationScopeCheckMs`, and post-auth
      `registrationHssPrepareMs`.
- [x] Keep `registrationHssPrepareMs` in start diagnostics as `0ms` or absent
      only after benchmark code can distinguish preauth prepare from start
      prepare.
- [x] Update the registration benchmark summary with preauth prepare buckets.
- [x] Run `pnpm benchmark:registration-flow:smoke` after the first slice.
- [x] Keep the route-shape change because `/wallets/register/start` p50/p95
      dropped materially.
- [x] Re-run the two combined scenarios after tightening the ECDSA binding.
- [x] Re-run the full smoke benchmark after fixing the combined-flow boundary
      parser.
- [x] Add `walletRegisterPrepareWaitMs` so benchmarks distinguish total preauth
      prepare duration from the critical-path wait after authority collection
      and Ed25519 client material construction.
- [x] Add earlier or deeper overlap measurement so the benchmark can prove
      whether preauth prepare remains on the SDK critical path. Current SDK flow
      starts `prepareWalletRegistration` immediately after local intent digest
      verification and records the critical-path wait separately; the latest
      smoke run shows no remaining prepare wait in the measured passkey flows.

Benchmark result:

- Command:
  `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Run ID: `20260609-032110Z`
- Output:
  `benchmarks/registration-flow/out/20260609-032110Z/summary.md`
- Result: all four smoke scenarios passed.
- Route effect: `walletRegisterStartMs` p50 is `6ms` for wallet iframe
  Ed25519-only, `7ms` for wallet iframe combined, `4ms` for host-origin
  Ed25519-only, and `5ms` for host-origin combined. The HSS server prepare work
  is no longer on the post-auth start route.
- New preauth bucket: `walletRegisterPrepareMs` p50 is `375ms` for wallet
  iframe Ed25519-only, `377ms` for wallet iframe combined, `374ms` for
  host-origin Ed25519-only, and `370ms` for host-origin combined. Relay
  diagnostics include `wallets_register_prepare` with
  `registrationPreauthHssPrepareMs`.
- Client wait bucket: `walletRegisterPrepareWaitMs` p50 and p95 are `0ms` in
  all four smoke scenarios. The current SDK orchestration fully overlaps
  preauth prepare with authority collection and Ed25519 client material work in
  these passkey flows.
- Registration warmup wait bucket: `registrationWarmupWaitMs` p50 and p95 are
  `0ms` in all four smoke scenarios.
- Product effect in the latest smoke: SDK p50 is `1989ms` for wallet iframe
  Ed25519-only, `2026ms` for wallet iframe combined, `1636ms` for host-origin
  Ed25519-only, and `1692ms` for host-origin combined. The route split is
  retained because it moves the expensive HSS prepare off the post-auth critical
  path; further end-to-end gains should target client HSS artifact construction,
  finalize, and wallet-iframe overhead.

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
- Benchmark evidence shows `walletRegisterPrepareWaitMs` is `0ms` p50/p95 in
  the current passkey smoke flows.
- Latest retained smoke run `20260610-024516Z` keeps
  `walletRegisterPrepareWaitMs` at `0ms` p50 in all four passkey scenarios.
  `/wallets/register/prepare` is still roughly `365ms` to `371ms` p50 and
  remains fully overlapped with passkey proof collection in the measured flow.
  This confirms refactor-62 is doing its intended job; further registration
  latency work belongs in refactor-64 client artifact construction or the
  finalize route.

## Validation

Run focused checks while implementing:

- `pnpm -C sdk type-check`
- preparation lifecycle type fixtures
- `pnpm exec playwright test -c tests/playwright.unit.config.ts tests/unit/registrationIntentAllocation.unit.test.ts tests/unit/registrationCeremonyStore.unit.test.ts tests/unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`
- `pnpm benchmark:registration-flow:smoke`
- `pnpm test:source-guards`
- `git diff --check`

Current validation:

- [x] `pnpm -C sdk type-check`
- [x] `pnpm exec playwright test -c tests/playwright.unit.config.ts tests/unit/registrationIntentAllocation.unit.test.ts tests/unit/registrationCeremonyStore.unit.test.ts tests/unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line`
      (96 passed)
- [x] `pnpm benchmark:registration-flow:smoke`
      (`20260609-032110Z`, four scenarios passed)
- [x] `pnpm test:source-guards`
      (281 passed)
- [x] `git diff --check`

Run broad source guards after the store and route contracts land because this
touches persistence, public route shapes, auth-adjacent state, and HSS scope
binding.
