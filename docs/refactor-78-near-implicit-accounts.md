# Refactor 78: NEAR Registration Account Provisioning

Date created: June 22, 2026

Status: planned

Related plans:

- [router-a-b-SPEC.md](./router-a-b-SPEC.md)
- [refactor-64-optimize-registration-2.md](./refactor-64-optimize-registration-2.md)
- [refactor-75-simplify-ed25519.md](./refactor-75-simplify-ed25519.md)
- [refactor-77-switch-case.md](./refactor-77-switch-case.md)

## Goal

Replace the current `createNearAccount` registration boolean with an explicit
NEAR account provisioning mode.

Registration should support two first-class options:

- implicit NEAR account provisioning, derived from the finalized Ed25519 public
  key and requiring no NEAR transaction during signup;
- sponsored named NEAR account provisioning, using the current relayer-funded
  `CreateAccount + Transfer + AddKey` flow for callers that need a human-readable
  NEAR account name.

Primary outcomes:

- account provisioning is a discriminated union, never a boolean;
- implicit registration returns a derived 64-character NEAR account ID;
- implicit registration performs no NEAR account-create transaction;
- sponsored named registration keeps the existing account creation behavior as
  an explicit branch;
- HSS registration scope handles implicit and sponsored account modes without
  mixing branch-specific fields;
- signing code explicitly models funded/direct NEAR execution readiness.

## NEAR Protocol Read

NEAR implicit accounts are account IDs derived from an Ed25519 public key. The
account ID is the lowercase hex encoding of the 32-byte public key.

Protocol implications:

- implicit signup needs no named-account reservation;
- implicit signup needs no `CreateAccount` action;
- implicit signup needs no `AddKey` action for the key that defines the account;
- direct NEAR execution still needs funding, sponsorship, or an intents/delegate
  path;
- sponsored named signup still dispatches a NEAR transaction and spends relayer
  funds by design.

References:

- <https://docs.near.org/protocol/accounts-contracts/account-id>
- <https://nomicon.io/DataStructures/Account.html>
- <https://docs.near-intents.org/integration/verifier-contract/account-abstraction>

## Current Code Read

Normal public registration chooses sponsored named account creation today.

Relevant files:

```text
packages/sdk-web/src/SeamsWeb/operations/registration/registrationSignerSelection.ts
packages/shared-ts/src/utils/registrationIntent.ts
packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts
packages/sdk-web/src/core/types/accountIds.ts
packages/sdk-server-ts/src/core/AuthService.ts
packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts
```

Specific current behavior:

- `buildNearWalletRegistrationSignerSelection()` hard-codes
  `createNearAccount: true`.
- `ThresholdEd25519RegistrationSpec` requires `nearAccountId` and
  `createNearAccount`.
- client registration preflight validates dotted NEAR account format and checks
  whether the account already exists.
- server finalization calls `createAccount()` when `ed25519.createNearAccount`
  is true.
- `createAccount()` builds `CreateAccount + Transfer + AddKey` actions and sends
  the transaction with `EXECUTED_OPTIMISTIC`.
- HSS registration routes require `new_account_id`.
- HSS canonical context and client share derivation use `nearAccountId` before
  the threshold public key is known.
- `AccountId.to()` rejects implicit accounts because it requires at least one
  dot.

The architectural constraint is specific to implicit provisioning. An implicit
account ID is derived from the final Ed25519 public key, while the current HSS
registration scope uses `nearAccountId` before finalization. This creates a
circular design for implicit accounts:

```text
nearAccountId -> HSS/client share derivation -> publicKey -> implicit nearAccountId
```

This refactor must break that cycle for the implicit branch while preserving a
clear sponsored named branch that still binds HSS registration to the requested
named account.

## Design Principles

- Model account provisioning with a discriminated union.
- Remove `createNearAccount` from registration types and route parsers.
- Make implicit provisioning the fast path with no NEAR transaction.
- Keep sponsored named account creation as an explicit opt-in branch.
- Bind implicit pre-finalize HSS work to wallet, RP, signing root, signer slot,
  derivation version, and registration intent digest.
- Bind sponsored named HSS work to the requested named account ID.
- Derive the implicit NEAR account ID exactly once after the Ed25519 public key
  is finalized.
- Use exhaustive switches for every provisioning branch.
- Keep request/persistence compatibility parsing at boundaries during the
  refactor, then delete obsolete boolean shapes.

## Target Domain Shape

Use explicit registration account provisioning:

```ts
type RegistrationNearAccountProvisioning =
  | {
      kind: 'implicit_account';
      accountIdSource: 'ed25519_public_key';
      requestedAccountId?: never;
      sponsor?: never;
    }
  | {
      kind: 'sponsored_named_account';
      requestedAccountId: NamedNearAccountId;
      sponsor: 'relayer';
      accountIdSource?: never;
    };
```

Use branch-specific pre-finalize HSS scopes:

```ts
type ThresholdEd25519RegistrationAccountScope =
  | {
      kind: 'implicit_registration_scope';
      walletId: WalletId;
      rpId: string;
      registrationIntentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      signerSlot: number;
      keyPurpose: 'near_tx';
      keyVersion: string;
      derivationVersion: number;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_registration_scope';
      walletId: WalletId;
      rpId: string;
      registrationIntentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      signerSlot: number;
      keyPurpose: 'near_tx';
      keyVersion: string;
      derivationVersion: number;
      nearAccountId: NamedNearAccountId;
    };
```

Resolve the account after finalization:

```ts
type ResolvedRegistrationNearAccount =
  | {
      kind: 'resolved_implicit_account';
      publicKey: string;
      nearAccountId: ImplicitNearAccountId;
      accountCreation?: never;
    }
  | {
      kind: 'resolved_sponsored_named_account';
      publicKey: string;
      nearAccountId: NamedNearAccountId;
      accountCreation: {
        transactionHash: string;
        sponsoredBy: 'relayer';
      };
    };
```

The implicit builder must decode the `ed25519:<base58>` public key, require
exactly 32 bytes, and return lowercase hex.

## Target Flows

### Implicit Account Registration

```text
user starts registration
  -> client creates registration intent with implicit_account provisioning
  -> client and server prepare HSS under implicit_registration_scope
  -> user completes Passkey or Email OTP authority proof
  -> HSS respond/finalize returns Ed25519 public key
  -> server derives implicit NEAR account ID from public key
  -> server skips createAccount()
  -> server stores key material and user/profile under derived account ID
  -> client persists wallet state under derived account ID
  -> registration returns derived account ID to caller
```

No NEAR transaction is dispatched in this flow.

### Sponsored Named Account Registration

```text
user starts registration
  -> client creates registration intent with sponsored_named_account provisioning
  -> client validates requested named account format
  -> client optionally checks account-name availability
  -> client and server prepare HSS under sponsored_named_registration_scope
  -> user completes Passkey or Email OTP authority proof
  -> HSS respond/finalize returns Ed25519 public key
  -> server dispatches CreateAccount + Transfer + AddKey through relayer
  -> server stores key material and user/profile under requested named account ID
  -> client persists wallet state under requested named account ID
  -> registration returns named account ID and creation transaction hash
```

This flow intentionally preserves the current sponsored account-creation cost
and latency for products that need named NEAR accounts.

## Implementation Plan

### Phase 1: Account ID Types And Derivation

- [ ] Add `ImplicitNearAccountId` and `NamedNearAccountId` branded types.
- [ ] Replace dotted-only `toAccountId()` validation with a parser that accepts
      either named NEAR accounts or 64-character lowercase implicit IDs.
- [ ] Add a stricter `parseNamedNearAccountId()` for sponsored account
      provisioning.
- [ ] Add `deriveImplicitNearAccountIdFromEd25519PublicKey(publicKey)` in shared
      code.
- [ ] Add unit tests for:
  - valid `ed25519:<base58>` public key to implicit account ID;
  - uppercase hex rejection at boundary parsers;
  - invalid public-key length rejection;
  - dotted named account parsing for sponsored account provisioning.

Acceptance:

- implicit account IDs pass every core account ID parser;
- sponsored account provisioning accepts only named account IDs;
- public-key-to-account derivation is shared by client and server;
- no core code accepts raw account strings after boundary parsing.

### Phase 2: Registration Intent Shape

- [ ] Replace `ThresholdEd25519RegistrationSpec.nearAccountId` and
      `createNearAccount` with `accountProvisioning`.
- [ ] Add `implicit_account` and `sponsored_named_account` registration type
      fixtures.
- [ ] Update registration intent digest fixtures so the provisioning branch is
      part of the signed intent.
- [ ] Update route parsers in `relayWalletRegistration.ts` and `AuthService.ts`
      to parse both provisioning branches.
- [ ] Reject old boolean registration Ed25519 shapes at request boundaries.
- [ ] Keep `AddSignerSelection` separate. Audit it in this phase and convert any
      account-creation mode to the same provisioning union if it remains needed.

Acceptance:

- `rg "createNearAccount" packages tests` returns no registration-path hits;
- invalid object literals with both implicit and sponsored fields fail type
  fixtures;
- both provisioning branches have canonical digest tests;
- route parsers return narrow branch-specific types.

### Phase 3: HSS Registration Scope

- [ ] Introduce `ThresholdEd25519RegistrationAccountScope`.
- [ ] Replace registration HSS `new_account_id` request fields with
      `registrationAccountScope`.
- [ ] Update `parseThresholdEd25519HssCanonicalContext()` so registration context
      accepts both implicit and sponsored named scope branches.
- [ ] Update client HSS input derivation:
  - implicit branch uses `implicit_registration_scope` as the
    PRF/domain-separation input;
  - sponsored branch uses `sponsored_named_registration_scope` including the
    requested named account ID.
- [ ] Update server HSS prepare/respond/finalize scope validation to compare the
      full branch-specific registration scope.
- [ ] Ensure HSS finalized output returns the public key before account
      resolution.

Acceptance:

- implicit pre-finalize HSS code has no dependency on a user-provided NEAR
  account ID;
- sponsored HSS code remains bound to the requested named account ID;
- adding another registration account provisioning branch breaks exhaustive
  switches;
- HSS scope mismatch tests cover wallet ID, RP ID, signing root, signer slot,
  key version, derivation version, intent digest, and named account ID where
  applicable.

### Phase 4: Server Finalize And Persistence

- [ ] Switch over `accountProvisioning` in wallet registration finalize.
- [ ] For `implicit_account`, derive `ResolvedRegistrationNearAccount` from
      `finalized.publicKey` and skip `createAccount()`.
- [ ] For `sponsored_named_account`, call `createAccount()` with the requested
      named account ID and finalized public key.
- [ ] Rename route timing from generic `nearAccountCreateMs` to a branch-specific
      `sponsoredNearAccountCreateMs`.
- [ ] Pass the resolved account ID into `keygenFromRegistrationMaterial()` and
      persistence.
- [ ] Update identity linking so `near:{accountId}` is stable for both implicit
      and sponsored named accounts.
- [ ] Update rollback semantics by branch:
  - implicit rollback removes local/server wallet state only;
  - sponsored rollback preserves the current best-effort handling for a created
    on-chain account.

Acceptance:

- implicit registration never calls `nearClient.sendTransaction()`;
- sponsored named registration is the only registration branch that can call
  `createAccount()`;
- server response includes the resolved account ID, public key, and branch kind;
- sponsored response includes the account creation transaction hash;
- persisted key material account ID equals the resolved account ID.

### Phase 5: Client Registration And Wallet Iframe

- [ ] Change public registration entrypoints to accept an account provisioning
      mode.
- [ ] Make `implicit_account` the default mode for API helpers that do not expose
      named account selection.
- [ ] Keep named-account input and account-name availability preflight only for
      `sponsored_named_account`.
- [ ] Update wallet iframe routing so implicit pre-finalize work is keyed by
      wallet ID or registration flow ID, then re-keyed to the derived account ID
      after finalize.
- [ ] Keep sponsored named wallet iframe routing keyed by the requested named
      account ID where the current code already needs it.
- [ ] Persist local account, profile, passkey metadata, warm session records, and
      ECDSA wallet keys under the resolved account ID for both branches.
- [ ] Update display helpers such as `extractUsername()` for 64-character account
      IDs.
- [ ] Update registration events so implicit account ID appears only after it is
      resolved; sponsored named events may include the requested account ID from
      the start.

Acceptance:

- implicit registration UI can run with no NEAR account-name input;
- sponsored named registration UI still accepts a named account ID;
- local persistence can restore and unlock both implicit and sponsored wallets;
- wallet iframe boot and `requireRouter()` work for implicit registration before
  the derived account ID exists;
- returned registration result includes provisioning branch and resolved account
  ID.

### Phase 6: Signing And Execution Readiness

- [ ] Classify NEAR signing readiness with a union:

```ts
type NearExecutionReadiness =
  | { kind: 'implicit_unfunded'; accountId: ImplicitNearAccountId }
  | { kind: 'sponsored_named_ready'; accountId: NamedNearAccountId; nonce: bigint }
  | { kind: 'access_key_available'; accountId: string; nonce: bigint }
  | { kind: 'account_lookup_failed'; accountId: string; message: string };
```

- [ ] Update nonce coordinator initialization to return `implicit_unfunded`
      instead of throwing for a derived implicit account with no visible access
      key.
- [ ] Route direct NEAR transaction submission through `access_key_available` or
      `sponsored_named_ready`.
- [ ] Route sponsored/intents/delegate flows through their own readiness branch
      after confirming their exact account-existence requirements.
- [ ] Add explicit user-facing errors for direct NEAR actions that require
      funding first.

Acceptance:

- direct NEAR transactions cannot be attempted from an unfunded implicit account;
- sponsored named accounts keep current direct NEAR transaction readiness after
  account creation;
- sponsored or intents paths state exactly whether they support unfunded
  implicit accounts;
- nonce-lane tests cover implicit-unfunded, funded implicit, sponsored named,
  and RPC failure.

### Phase 7: Tests, Benchmarks, And Cleanup

- [ ] Replace named-registration mocks with branch-specific implicit and
      sponsored named mocks.
- [ ] Add type fixtures for invalid registration account provisioning states.
- [ ] Add server unit tests proving implicit finalize skips account creation.
- [ ] Add server unit tests proving sponsored named finalize calls account
      creation exactly once.
- [ ] Add client registration tests proving account existence preflight runs only
      for `sponsored_named_account`.
- [ ] Add integration or e2e tests where implicit registration returns a derived
      64-character account ID.
- [ ] Add integration or e2e tests where sponsored named registration returns a
      named account ID and transaction hash.
- [ ] Update registration benchmark harness with separate implicit and sponsored
      scenarios.
- [ ] Record before/after numbers in `docs/benchmarks/registration-flow.md`.

Acceptance:

- `rg "createNearAccount" packages tests` has no hits;
- `rg "new_account_id" packages tests` has no HSS registration hits after the
  scope replacement lands;
- implicit benchmark has no NEAR account-create timing bucket;
- sponsored named benchmark reports `sponsoredNearAccountCreateMs`;
- production-like implicit registration removes the chain-bound account-create
  segment.

## Validation Plan

Cheap checks during implementation:

```text
pnpm -C packages/shared-ts exec tsc -p tsconfig.json --noEmit
pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit
pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
pnpm -C tests exec playwright test -c playwright.unit.config.ts tests/unit/registrationIntentDigest.unit.test.ts --reporter=line
```

Focused tests to add or update:

```text
tests/unit/nearAccountId.unit.test.ts
tests/unit/registrationIntentDigest.unit.test.ts
tests/unit/walletRegistrationAccountProvisioning.unit.test.ts
tests/unit/nearNonceLane.unit.test.ts
benchmarks/registration-flow
```

Full validation is justified because this touches public APIs, route contracts,
registration persistence, wallet session scope, and signing readiness.

## Open Risks

- HSS scope decoupling changes implicit-account key derivation. Existing dev
  wallets registered with account-name-derived shares should be treated as
  obsolete test data for the implicit branch.
- Direct NEAR transaction behavior for unfunded implicit accounts needs a focused
  RPC test against testnet or a trusted localnet fixture.
- Sponsored/intents support must be verified before messaging implicit accounts
  as immediately executable on NEAR.
- Several UI and storage helpers assume a dotted account name for display and
  profile keys.
- Sponsored named registration will remain slower and will continue spending
  relayer funds by design.

## Done Definition

- Registration exposes two explicit account provisioning options:
  `implicit_account` and `sponsored_named_account`.
- Implicit registration submits no NEAR transaction.
- Implicit registration returns the lowercase hex account ID derived from the
  finalized Ed25519 public key.
- Sponsored named registration preserves the current relayer-funded account
  creation behavior.
- Registration code contains no `createNearAccount` boolean.
- Implicit registration server diagnostics contain no NEAR account-create timing
  bucket.
- Sponsored named registration diagnostics report branch-specific account-create
  timing.
- First direct NEAR action from an unfunded implicit account fails with an
  explicit funding/readiness result.
- Tests reject invalid account provisioning states at compile time and runtime
  boundaries.
