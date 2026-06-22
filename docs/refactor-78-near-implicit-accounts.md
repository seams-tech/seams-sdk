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

- implicit signup needs no NEAR named-account reservation;
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

## Code Review Findings To Fold Into The Spec

The first draft captured the account provisioning switch, but the current code
has several deeper `nearAccountId` assumptions that must be specified before
implementation:

- client registration currently builds session policy inputs before finalize in
  `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`; the
  implicit account ID is unavailable at that point;
- server combined and Ed25519-only finalize paths duplicate the same
  `createAccount()` and persistence logic in `AuthService.ts`;
- HSS registration request types, HSS canonical context, client WASM inputs,
  server threshold PRF inputs, and local NEAR key ops all use `nearAccountId`
  as a domain-separation input before the public key exists;
- later warm-session signing re-derives threshold material from the session
  context, so registration and later signing must use the same Ed25519 key
  scope;
- local material bindings and warm session persistence currently key material
  only by resolved account ID;
- nonce-lane readiness currently treats a missing access key as an error, which
  is expected for an unfunded implicit account.

The implementation must introduce a stable Ed25519 key scope separate from the
resolved NEAR account ID. For sponsored named accounts the key scope can equal
the requested named account ID. For implicit accounts the wallet ID should be a
server-generated readable random name allocated before HSS starts, and the
resolved NEAR account ID is derived from the finalized public key.

## Design Principles

- Model account provisioning with a discriminated union.
- Remove `createNearAccount` from registration types and route parsers.
- Make implicit provisioning the fast path with no NEAR transaction.
- Keep sponsored named account creation as an explicit opt-in branch.
- Treat resolved NEAR account ID and Ed25519 key scope ID as separate domain
  values.
- Allocate implicit wallet IDs on the server with CSPRNG entropy, a readable
  word-list format, and collision checks before intent creation.
- Bind implicit pre-finalize HSS work to wallet, RP, signing root, signer slot,
  derivation version, and registration intent digest.
- Bind sponsored named HSS work to the requested named account ID.
- Use the same Ed25519 key scope ID for registration material, stored key
  material, and later HSS signing sessions.
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

Parse wallet input and account provisioning together at the route boundary into a
branch-specific request:

```ts
type RegistrationWalletIdentityRequest =
  | {
      kind: 'generated_implicit_wallet';
      accountProvisioning: { kind: 'implicit_account' };
      walletId?: never;
      requestedAccountId?: never;
    }
  | {
      kind: 'sponsored_named_wallet';
      accountProvisioning: { kind: 'sponsored_named_account' };
      requestedAccountId: NamedNearAccountId;
      walletId: WalletId;
    };
```

The route parser must construct `sponsored_named_wallet.walletId` from
`requestedAccountId` and reject a separate caller-provided wallet ID that does
not match the requested named account. For `generated_implicit_wallet`, the
server allocates `GeneratedImplicitWalletId` and rejects caller-provided wallet
IDs.

Use branch-specific pre-finalize HSS scopes:

```ts
type ThresholdEd25519RegistrationAccountScope =
  | {
      kind: 'generated_implicit_registration_scope';
      walletId: GeneratedImplicitWalletId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
      rpId: string;
      registrationIntentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      signerSlot: number;
      participantIds: readonly number[];
      keyPurpose: 'near_tx';
      keyVersion: string;
      derivationVersion: number;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_registration_scope';
      walletId: WalletId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
      rpId: string;
      registrationIntentDigestB64u: string;
      signingRootId: string;
      signingRootVersion: string;
      signerSlot: number;
      participantIds: readonly number[];
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
      walletId: GeneratedImplicitWalletId;
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

Separate the key-derivation scope from the account that will be returned to the
caller:

```ts
type Ed25519KeyScopeId = string & { readonly __brand: 'Ed25519KeyScopeId' };
type GeneratedImplicitWalletId = WalletId & {
  readonly __brand: 'GeneratedImplicitWalletId';
};

type RegistrationEd25519KeyScope =
  | {
      kind: 'generated_implicit_key_scope';
      walletId: GeneratedImplicitWalletId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_key_scope';
      walletId: WalletId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
      nearAccountId: NamedNearAccountId;
    };
```

The generated implicit wallet ID should use the existing hosted Email OTP
word-list style with a higher-entropy suffix, for example
`frost-vermillion-k7p9m2`. Generate it with CSPRNG bytes, parse it as `WalletId`,
and reserve it with a collision check before intent creation. Reroll allocates a
fresh generated wallet ID and key scope before HSS starts.

Generated wallet ID reservation rules:

- reserve generated names in the registration intent store, or in a small
  dedicated reservation store keyed by namespace/RP/wallet ID;
- use the same TTL as the registration intent;
- reject reroll after HSS preparation starts, or create a fresh registration
  intent and abandon the old key scope;
- release or expire unused reservations without touching completed wallets.

The implicit `ed25519KeyScopeId` is a canonical digest over the server
generated wallet ID and pre-finalize scope fields. It cannot depend on the
implicit NEAR account ID or finalized public key.

```ts
type GeneratedImplicitKeyScopeDigestInput = {
  kind: 'generated_implicit_ed25519_key_scope_v1';
  walletId: GeneratedImplicitWalletId;
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
  signerSlot: number;
  participantIds: readonly number[];
  keyPurpose: 'near_tx';
  keyVersion: string;
  derivationVersion: number;
};
```

HSS/PRF code uses `ed25519KeyScopeId` as the domain-separation input. Session
claims, local material bindings, and stored signer records carry both the
resolved `nearAccountId` and the `ed25519KeyScopeId`.
Normalize `participantIds` once at the route boundary and include the normalized
array in every registration key-scope digest and HSS scope comparison.

```ts
type RegisteredThresholdEd25519AccountBinding =
  | {
      kind: 'implicit_account_binding';
      accountProvisioning: { kind: 'implicit_account' };
      walletId: GeneratedImplicitWalletId;
      nearAccountId: ImplicitNearAccountId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
    }
  | {
      kind: 'sponsored_named_account_binding';
      accountProvisioning: { kind: 'sponsored_named_account' };
      walletId: WalletId;
      nearAccountId: NamedNearAccountId;
      ed25519KeyScopeId: Ed25519KeyScopeId;
    };
```

Identity vocabulary after this refactor:

- `walletId` is the durable user-facing wallet identity. For implicit default
  registration it is a readable random name allocated before HSS starts, such as
  `frost-vermillion-k7p9m2`.
- `nearAccountId` is the protocol account ID used for NEAR signing. For implicit
  registration it is the 64-character lowercase hex account derived from the
  finalized Ed25519 public key.
- `ed25519KeyScopeId` is the stable HSS/PRF domain input for the Ed25519 key.
  It is persisted with the wallet signer and reused for later signing sessions.
- For sponsored named registration, `walletId`, `nearAccountId`, and
  `ed25519KeyScopeId` may all resolve to the same named account string. The code
  must still carry them as distinct fields.

Registration session requests must be draft-shaped until the server resolves the
account:

```ts
type RegistrationEd25519SessionRequest =
  | {
      kind: 'mint_jwt_session';
      policyDraft: ThresholdWarmSessionPolicyDraft;
    }
  | {
      kind: 'none';
      policyDraft?: never;
    };
```

Finalize responses must expose the provisioning branch and resolved account:

```ts
type WalletRegistrationFinalizeSuccess = {
  kind: 'ok';
  walletId: WalletId;
  rpId: string;
  accountProvisioning: RegistrationNearAccountProvisioning;
  resolvedAccount: ResolvedRegistrationNearAccount;
  ed25519?: {
    nearAccountId: ImplicitNearAccountId | NamedNearAccountId;
    ed25519KeyScopeId: Ed25519KeyScopeId;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    session: ThresholdWarmSessionResult;
  };
};
```

## Target Flows

### Implicit Account Registration

```text
user starts registration
  -> client creates registration intent with implicit_account provisioning
  -> server allocates generated wallet/key name, e.g. frost-vermillion-k7p9m2
  -> client and server prepare HSS under generated_implicit_registration_scope
  -> user completes Passkey or Email OTP authority proof
  -> HSS respond/finalize returns Ed25519 public key
  -> server derives implicit NEAR account ID from public key
  -> server skips createAccount()
  -> server stores wallet/profile under walletId and signer binding under nearAccountId
  -> client persists wallet state with walletId, nearAccountId, and ed25519KeyScopeId
  -> registration returns generated wallet ID and derived NEAR account ID
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
  -> server stores wallet/profile and signer binding under requested named account ID
  -> client persists wallet state with walletId, nearAccountId, and ed25519KeyScopeId
  -> registration returns named account ID and creation transaction hash
```

This flow intentionally preserves the current sponsored account-creation cost
and latency for products that need named NEAR accounts.

## Direct Implementation Callchain

Client-side changes:

1. `registerPasskey()` and `registerWallet()` accept an account provisioning
   mode. Helpers that do not expose a name picker default to `implicit_account`
   and no longer require `nearAccountId`.
2. `buildNearWalletRegistrationSignerSelection()` builds branch-specific
   Ed25519 registration specs. It must stop emitting `createNearAccount`.
3. `walletRegistrationPrecomputeScopeFromArgs()` uses generated `walletId` for
   implicit pre-finalize routing; sponsored named registration can use the
   requested account ID.
4. HSS client material preparation passes `ed25519KeyScopeId` into the client
   signer worker and HSS WASM inputs.
5. Finalize sends `RegistrationEd25519SessionRequest` with a policy draft. The
   server completes the policy after account resolution.
6. After finalize, the client persists `walletId`, `nearAccountId`,
   `ed25519KeyScopeId`, account provisioning kind, passkey metadata, ECDSA keys,
   and warm-session material as one resolved binding.
7. Wallet iframe login/status events use `walletId` for wallet identity and
   include `nearAccountId` only after signer resolution.

Server-side changes:

1. `relayWalletRegistration.ts` parses `accountProvisioning` at the route
   boundary and returns narrow branch-specific types.
2. `AuthService.createRegistrationIntent()` allocates generated implicit wallet
   IDs and key scopes for server-generated implicit registration, reserves the
   wallet ID, and includes it in the intent digest.
3. `resolveEd25519RegistrationPrepareScope()` builds
   `RegistrationEd25519KeyScope` and returns `ed25519KeyScopeId`.
4. `prepareEd25519RegistrationHss()`, combined respond, Ed25519-only respond,
   combined finalize, and Ed25519-only finalize pass key-scope context rather
   than `new_account_id`.
5. A shared finalize helper resolves account provisioning:
   `implicit_account` derives the account ID from `finalized.publicKey`;
   `sponsored_named_account` calls `createAccount()`.
6. Key store records, wallet signer records, session claims, and session policy
   validation carry `walletId`, `nearAccountId`, and `ed25519KeyScopeId`.
7. Warm-session restore and signing-session authorization validate all three
   identity fields against the stored signer binding.

## Implementation Plan

### Phase 1: Account ID Types And Derivation

- [ ] Add `ImplicitNearAccountId` and `NamedNearAccountId` branded types.
- [ ] Add `GeneratedImplicitWalletId` and `Ed25519KeyScopeId` branded types.
- [ ] Replace dotted-only `toAccountId()` validation with a parser that accepts
      either named NEAR accounts or 64-character lowercase implicit IDs.
- [ ] Add a stricter `parseNamedNearAccountId()` for sponsored account
      provisioning.
- [ ] Add `deriveImplicitNearAccountIdFromEd25519PublicKey(publicKey)` in shared
      code.
- [ ] Add a server-side generated implicit wallet/key-scope allocator using the
      hosted Email OTP readable-name pattern with a higher-entropy suffix such as
      `frost-vermillion-k7p9m2`.
- [ ] Reserve generated wallet IDs with a collision check before intent creation.
- [ ] Add reservation TTL and reroll semantics for generated wallet IDs.
- [ ] Validate generated wallet IDs separately from NEAR account IDs.
- [ ] Add unit tests for:
  - valid `ed25519:<base58>` public key to implicit account ID;
  - uppercase hex rejection at boundary parsers;
  - invalid public-key length rejection;
  - dotted named account parsing for sponsored account provisioning.
  - generated wallet ID parsing and collision retry.

Acceptance:

- implicit account IDs pass every core account ID parser;
- sponsored account provisioning accepts only named account IDs;
- public-key-to-account derivation is shared by client and server;
- implicit generated wallet IDs are never parsed as NEAR account IDs;
- no core code accepts raw account strings after boundary parsing.

### Phase 2: Registration Intent Shape

- [ ] Replace `ThresholdEd25519RegistrationSpec.nearAccountId` and
      `createNearAccount` with `accountProvisioning`.
- [ ] Add `RegistrationEd25519KeyScope` to prepared registration state.
- [ ] For implicit server-generated registration, allocate `walletId` and
      `ed25519KeyScopeId` after participant IDs are normalized and before intent
      signing.
- [ ] For sponsored named registration, require
      `accountProvisioning.requestedAccountId` and use it as the named
      `nearAccountId`.
- [ ] Reject implicit registration requests with caller-provided wallet IDs.
- [ ] Reject sponsored named registration requests whose wallet ID differs from
      `requestedAccountId`.
- [ ] Add `implicit_account` and `sponsored_named_account` registration type
      fixtures.
- [ ] Update registration intent digest fixtures so the provisioning branch is
      part of the signed intent.
- [ ] Include generated implicit wallet ID and key-scope data in the signed
      intent digest.
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
- generated implicit wallet/key-scope IDs are stable across prepare/respond/
  finalize for one intent;
- invalid wallet/provisioning branch combinations fail route parser tests and
  type fixtures;
- route parsers return narrow branch-specific types.

### Phase 3: HSS Registration Scope

- [ ] Introduce `ThresholdEd25519RegistrationAccountScope`.
- [ ] Rename registration HSS/PRF domain inputs from `nearAccountId` to
      `ed25519KeyScopeId`.
- [ ] Replace registration HSS `new_account_id` request fields with
      `registrationAccountScope` and `ed25519KeyScopeId`.
- [ ] Update `parseThresholdEd25519HssCanonicalContext()` so registration context
      accepts both implicit and sponsored named scope branches.
- [ ] Update client HSS input derivation:
  - implicit branch uses generated `ed25519KeyScopeId` as the
    PRF/domain-separation input;
  - sponsored branch uses `sponsored_named_registration_scope` including the
    requested named account ID.
- [ ] Update client worker/WASM schemas:
  - `hssClientSignerWasm.ts`;
  - `nearSignerWasm.ts`;
  - `createNearKeyOps.ts`;
  - `clientOutputMask.ts`.
- [ ] Update server threshold PRF and HSS WASM schemas:
  - `thresholdPrfWasm.ts`;
  - `ed25519HssWasm.ts`.
- [ ] Update server HSS prepare/respond/finalize scope validation to compare the
      full branch-specific registration scope.
- [ ] Ensure HSS finalized output returns the public key before account
      resolution.

Acceptance:

- implicit pre-finalize HSS code has no dependency on a user-provided NEAR
  account ID;
- sponsored HSS code remains bound to the requested named account ID;
- registration and later signing use the same `ed25519KeyScopeId`;
- adding another registration account provisioning branch breaks exhaustive
  switches;
- HSS scope mismatch tests cover wallet ID, RP ID, signing root, signer slot,
  participant IDs, key version, derivation version, intent digest, and named
  account ID where applicable.

### Phase 4: Server Finalize And Persistence

- [ ] Switch over `accountProvisioning` in wallet registration finalize.
- [ ] For `implicit_account`, derive `ResolvedRegistrationNearAccount` from
      `finalized.publicKey` and skip `createAccount()`.
- [ ] For `sponsored_named_account`, call `createAccount()` with the requested
      named account ID and finalized public key.
- [ ] Extract shared provisioning resolution used by combined and Ed25519-only
      finalize paths.
- [ ] Rename route timing from generic `nearAccountCreateMs` to a branch-specific
      `sponsoredNearAccountCreateMs`.
- [ ] Pass `walletId`, `nearAccountId`, and `ed25519KeyScopeId` into
      `keygenFromRegistrationMaterial()` and persistence.
- [ ] Update identity linking so wallet identity and NEAR signer identity are
      separate records for implicit accounts.
- [ ] Complete session policy drafts after account resolution and validate the
      returned session against `walletId`, `nearAccountId`, and
      `ed25519KeyScopeId`.
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
- persisted key material stores the resolved account ID and Ed25519 key scope ID;
- session claims for implicit accounts do not require `walletId` to equal
  `nearAccountId`.

### Phase 5: Client Registration And Wallet Iframe

- [ ] Change public registration entrypoints to accept an account provisioning
      mode.
- [ ] Make `implicit_account` the default mode for API helpers that do not expose
      named account selection.
- [ ] Return generated implicit `walletId` from registration intent creation, and
      expose reroll where the UI supports name choice.
- [ ] Keep named-account input and account-name availability preflight only for
      `sponsored_named_account`.
- [ ] Update wallet iframe routing so implicit pre-finalize work is keyed by
      generated wallet ID, then attached to the resolved account binding after
      finalize.
- [ ] Keep sponsored named wallet iframe routing keyed by the requested named
      account ID where the current code already needs it.
- [ ] Persist local account, profile, passkey metadata, warm session records, and
      ECDSA wallet keys under the resolved wallet binding for both branches.
- [ ] Update display helpers such as `extractUsername()` for 64-character account
      IDs.
- [ ] Update public wallet/session responses to expose both `walletId` and
      `nearAccountId` for implicit wallets.
- [ ] Update registration events so implicit account ID appears only after it is
      resolved; sponsored named events may include the requested account ID from
      the start.

Acceptance:

- implicit registration UI can run with no NEAR account-name input;
- implicit registration UI can display and reroll a generated wallet name;
- sponsored named registration UI still accepts a named account ID;
- local persistence can restore and unlock both implicit and sponsored wallets;
- wallet iframe boot and `requireRouter()` work for implicit registration before
  the resolved NEAR account exists;
- returned registration result includes provisioning branch and resolved account
  ID.

### Phase 6: Signing And Execution Readiness

- [ ] Classify NEAR signing readiness with a union:

```ts
type NearExecutionReadiness =
  | {
      kind: 'implicit_unfunded';
      walletId: WalletId;
      nearAccountId: ImplicitNearAccountId;
    }
  | {
      kind: 'sponsored_named_ready';
      walletId: WalletId;
      nearAccountId: NamedNearAccountId;
      nonce: bigint;
    }
  | {
      kind: 'access_key_available';
      walletId: WalletId;
      nearAccountId: ImplicitNearAccountId | NamedNearAccountId;
      nonce: bigint;
    }
  | {
      kind: 'account_lookup_failed';
      walletId: WalletId;
      nearAccountId: ImplicitNearAccountId | NamedNearAccountId;
      message: string;
    };
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
- signing-session authorization derives shares with `ed25519KeyScopeId` and
  sends transactions with `nearAccountId`;
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
- [ ] Add tests proving implicit `walletId` can differ from `nearAccountId`.
- [ ] Add tests proving warm-session restore validates `walletId`,
      `nearAccountId`, and `ed25519KeyScopeId`.
- [ ] Add type fixtures rejecting functions that accept raw strings or partial
      identity bags for registration account binding.
- [ ] Add integration or e2e tests where implicit registration returns a derived
      64-character account ID.
- [ ] Add integration or e2e tests where implicit registration returns a
      generated readable wallet ID and can later sign with the derived NEAR
      account binding.
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
  segment;
- no implicit test fixture relies on `walletId === nearAccountId`.

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
tests/unit/warmSessionStore.reconnect.unit.test.ts
tests/unit/thresholdSessionClaims.unit.test.ts
benchmarks/registration-flow
```

Full validation is justified because this touches public APIs, route contracts,
registration persistence, wallet session scope, and signing readiness.

## Open Risks

- HSS scope decoupling changes implicit-account key derivation. Existing dev
  wallets registered with account-name-derived shares should be treated as
  obsolete test data for the implicit branch.
- Many code paths currently use `walletId`, `nearAccountId`, and wallet-session
  `userId` interchangeably. The implicit branch requires those paths to carry a
  resolved account binding instead.
- Generated wallet IDs need enough suffix entropy for the expected namespace
  size. Treat `frost-vermillion-k7p9m2` as the target shape, with server-side
  collision retry.
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
- Implicit registration allocates a readable generated wallet ID/key scope.
- Implicit registration submits no NEAR transaction.
- Implicit registration returns the lowercase hex account ID derived from the
  finalized Ed25519 public key.
- Implicit registration returns both `walletId` and `nearAccountId`, and tests
  prove they can differ.
- Sponsored named registration preserves the current relayer-funded account
  creation behavior.
- Registration code contains no `createNearAccount` boolean.
- Registration, stored signer material, warm sessions, and signing-session
  authorization carry `walletId`, `nearAccountId`, and `ed25519KeyScopeId`.
- Implicit registration server diagnostics contain no NEAR account-create timing
  bucket.
- Sponsored named registration diagnostics report branch-specific account-create
  timing.
- First direct NEAR action from an unfunded implicit account fails with an
  explicit funding/readiness result.
- Tests reject invalid account provisioning states at compile time and runtime
  boundaries.
