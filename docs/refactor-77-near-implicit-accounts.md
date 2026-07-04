# Refactor 77: NEAR Registration Account Provisioning

Date created: June 22, 2026

Status: implemented through Phase 8; benchmark evidence remains pending.
Phase 9 is planned for implicit-account activation and optional named-account
claiming.

Related plans:

- [router-a-b-SPEC.md](./router-a-b-SPEC.md)
- [refactor-64-optimize-registration-2.md](./refactor-64-optimize-registration-2.md)
- [refactor-75-simplify-ed25519.md](./refactor-75-simplify-ed25519.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)

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

## Original Code Read

At planning time, normal public registration chose sponsored named account
creation.

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

Original behavior:

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

The implementation must introduce a stable NEAR Ed25519 signing key separate from the
resolved NEAR account ID. For sponsored named accounts the key scope can equal
the requested named account ID. For implicit accounts the wallet ID should be a
server-generated readable random name allocated before HSS starts, and the
resolved NEAR account ID is derived from the finalized public key.

## Design Principles

- Model account provisioning with a discriminated union.
- Remove `createNearAccount` from registration types and route parsers.
- Make implicit provisioning the fast path with no NEAR transaction.
- Keep sponsored named account creation as an explicit opt-in branch.
- Treat resolved NEAR account ID and NEAR Ed25519 signing key ID as separate domain
  values.
- Allocate implicit wallet IDs on the server with CSPRNG entropy, a readable
  word-list format, and collision checks before intent creation.
- Bind implicit pre-finalize HSS work to wallet, RP, signing root, signer slot,
  derivation version, and registration intent digest.
- Bind sponsored named HSS work to the requested named account ID.
- Use the same NEAR Ed25519 signing key ID for registration material, stored key
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

The route parser must require `sponsored_named_wallet.walletId` as the durable
wallet identity and require `requestedAccountId` as the NEAR account to sponsor.
Those IDs may differ. For `generated_implicit_wallet`, the server allocates
`ServerAllocatedWalletId` and rejects caller-provided wallet IDs.

Use branch-specific pre-finalize HSS scopes:

```ts
type ThresholdEd25519RegistrationAccountScope =
  | {
      kind: 'generated_implicit_registration_scope';
      walletId: ServerAllocatedWalletId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
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
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
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
      walletId: ServerAllocatedWalletId;
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
type NearEd25519SigningKeyId = string & { readonly __brand: 'NearEd25519SigningKeyId' };
type ServerAllocatedWalletId = WalletId & {
  readonly __brand: 'ServerAllocatedWalletId';
};

type RegistrationEd25519KeyScope =
  | {
      kind: 'generated_implicit_key_scope';
      walletId: ServerAllocatedWalletId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      nearAccountId?: never;
    }
  | {
      kind: 'sponsored_named_key_scope';
      walletId: WalletId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      nearAccountId: NamedNearAccountId;
    };
```

The server-allocated wallet ID should use the existing hosted Email OTP
word-list style with a higher-entropy suffix, for example
`frost-vermillion-k7p9m2`. Generate it with CSPRNG bytes, parse it as `WalletId`,
and reserve it with a collision check before intent creation. Reroll allocates a
fresh server-allocated wallet ID and key scope before HSS starts.

Server-allocated wallet ID reservation rules:

- reserve generated names in the registration intent store, or in a small
  dedicated reservation store keyed by namespace/RP/wallet ID;
- use the same TTL as the registration intent;
- reject reroll after HSS preparation starts, or create a fresh registration
  intent and abandon the old key scope;
- release or expire unused reservations without touching completed wallets.

The implicit `nearEd25519SigningKeyId` is a canonical digest over the server
server-allocated wallet ID and pre-finalize scope fields. It cannot depend on the
implicit NEAR account ID or finalized public key.

```ts
type GeneratedImplicitNearEd25519SigningKeyDigestInput = {
  kind: 'generated_implicit_near_ed25519_signing_key_v1';
  walletId: ServerAllocatedWalletId;
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

HSS/PRF code uses `nearEd25519SigningKeyId` as the domain-separation input. Session
claims, local material bindings, and stored signer records carry both the
resolved `nearAccountId` and the `nearEd25519SigningKeyId`.
Normalize `participantIds` once at the route boundary and include the normalized
array in every registration key-scope digest and HSS scope comparison.

```ts
type RegisteredThresholdEd25519AccountBinding =
  | {
      kind: 'implicit_account_binding';
      accountProvisioning: { kind: 'implicit_account' };
      walletId: ServerAllocatedWalletId;
      nearAccountId: ImplicitNearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    }
  | {
      kind: 'sponsored_named_account_binding';
      accountProvisioning: { kind: 'sponsored_named_account' };
      walletId: WalletId;
      nearAccountId: NamedNearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    };
```

Identity vocabulary after this refactor:

- `walletId` is the durable user-facing wallet identity. For implicit default
  registration it is a readable random name allocated before HSS starts, such as
  `frost-vermillion-k7p9m2`.
- `nearAccountId` is the protocol account ID used for NEAR signing. For implicit
  registration it is the 64-character lowercase hex account derived from the
  finalized Ed25519 public key.
- `nearEd25519SigningKeyId` is the stable HSS/PRF domain input for the Ed25519 key.
  It is persisted with the wallet signer and reused for later signing sessions.
- For sponsored named registration, `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId` may all resolve to the same named account string, and they
  may also be distinct. The code must still carry them as distinct fields.

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
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
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
  -> server allocates wallet/key name, e.g. frost-vermillion-k7p9m2
  -> client and server prepare HSS under generated_implicit_registration_scope
  -> user completes Passkey or Email OTP authority proof
  -> HSS respond/finalize returns Ed25519 public key
  -> server derives implicit NEAR account ID from public key
  -> server skips createAccount()
  -> server stores wallet/profile under walletId and signer binding under nearAccountId
  -> client persists wallet state with walletId, nearAccountId, and nearEd25519SigningKeyId
  -> registration returns server-allocated wallet ID and derived NEAR account ID
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
  -> server stores wallet/profile under walletId and signer binding under requested named account ID
  -> client persists wallet state with walletId, nearAccountId, and nearEd25519SigningKeyId
  -> registration returns named account ID and creation transaction hash
```

This flow intentionally preserves the current sponsored account-creation cost
and latency for products that need named NEAR accounts.

## Direct Implementation Callchain

Client-side changes:

1. `registerPasskey()` and `registerWallet()` accept an account provisioning
   mode. Helpers that do not expose a name picker default to `implicit_account`
   and no longer require `nearAccountId`.
2. `buildNearWalletRegistrationSignerSetSelection()` builds branch-specific
   Ed25519 registration specs. It must stop emitting `createNearAccount`.
3. `walletRegistrationPrecomputeScopeFromArgs()` uses generated `walletId` for
   implicit pre-finalize routing; sponsored named registration can use the
   requested account ID.
4. HSS client material preparation passes `nearEd25519SigningKeyId` into the client
   signer worker and HSS WASM inputs.
5. Finalize sends `RegistrationEd25519SessionRequest` with a policy draft. The
   server completes the policy after account resolution.
6. After finalize, the client persists `walletId`, `nearAccountId`,
   `nearEd25519SigningKeyId`, account provisioning kind, passkey metadata, ECDSA keys,
   and warm-session material as one resolved binding.
7. Wallet iframe login/status events use `walletId` for wallet identity and
   include `nearAccountId` only after signer resolution.

Server-side changes:

1. `relayWalletRegistration.ts` parses `accountProvisioning` at the route
   boundary and returns narrow branch-specific types.
2. `AuthService.createRegistrationIntent()` allocates server-allocated wallet
   IDs and key scopes for server-allocated registration, reserves the
   wallet ID, and includes it in the intent digest.
3. `resolveEd25519RegistrationPrepareScope()` builds
   `RegistrationEd25519KeyScope` and returns `nearEd25519SigningKeyId`.
4. `prepareEd25519RegistrationHss()`, combined respond, Ed25519-only respond,
   combined finalize, and Ed25519-only finalize pass key-scope context rather
   than `new_account_id`.
5. A shared finalize helper resolves account provisioning:
   `implicit_account` derives the account ID from `finalized.publicKey`;
   `sponsored_named_account` calls `createAccount()`.
6. Key store records, wallet signer records, session claims, and session policy
   validation carry `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId`.
7. Warm-session restore and signing-session authorization validate all three
   identity fields against the stored signer binding.

## Implementation Plan

### Phase 1: Account ID Types And Derivation

- [x] Add `ImplicitNearAccountId` and `NamedNearAccountId` branded types.
- [x] Add `ServerAllocatedWalletId` and `NearEd25519SigningKeyId` branded types.
- [x] Replace dotted-only `toAccountId()` validation with a parser that accepts
      either named NEAR accounts or 64-character lowercase implicit IDs.
- [x] Add a stricter `parseNamedNearAccountId()` for sponsored account
      provisioning.
- [x] Add `deriveImplicitNearAccountIdFromEd25519PublicKey(publicKey)` in shared
      code.
- [x] Add a server-side wallet/key-scope allocator using the
      hosted Email OTP readable-name pattern with a higher-entropy suffix such as
      `frost-vermillion-k7p9m2`.
- [x] Reserve server-allocated wallet IDs with a collision check before intent creation.
- [x] Add reservation TTL and reroll semantics for server-allocated wallet IDs.
- [x] Validate server-allocated wallet IDs separately from NEAR account IDs.
- [x] Add unit tests for:
  - valid `ed25519:<base58>` public key to implicit account ID;
  - uppercase hex rejection at boundary parsers;
  - invalid public-key length rejection;
  - dotted named account parsing for sponsored account provisioning.
  - server-allocated wallet ID parsing and collision retry.

Acceptance:

- implicit account IDs pass every core account ID parser;
- sponsored account provisioning accepts only named account IDs;
- public-key-to-account derivation is shared by client and server;
- implicit server-allocated wallet IDs are never parsed as NEAR account IDs;
- no core code accepts raw account strings after boundary parsing.

### Phase 2: Registration Intent Shape

- [x] Replace `ThresholdEd25519RegistrationSpec.nearAccountId` and
      `createNearAccount` with `accountProvisioning`.
- [x] Add `RegistrationEd25519KeyScope` to prepared registration state.
- [x] For implicit server-generated registration, allocate `walletId` and
      `nearEd25519SigningKeyId` after participant IDs are normalized and before intent
      signing.
- [x] For sponsored named registration, require
      `accountProvisioning.requestedAccountId` and use it as the named
      `nearAccountId`.
- [x] Reject implicit registration requests with caller-provided wallet IDs.
- [x] Reject sponsored named registration requests without a provided durable
      wallet ID; the wallet ID may differ from `requestedAccountId`.
- [x] Add `implicit_account` and `sponsored_named_account` registration type
      fixtures.
- [x] Update registration intent digest fixtures so the provisioning branch is
      part of the signed intent.
- [x] Include server-allocated wallet ID and key-scope data in the signed
      intent digest.
- [x] Update route parsers in `relayWalletRegistration.ts` and `AuthService.ts`
      to parse both provisioning branches.
- [x] Reject old boolean registration Ed25519 shapes at request boundaries.
- [x] Keep `AddSignerSelection` separate. Audit it in this phase and convert any
      account-creation mode to the same provisioning union if it remains needed.

Acceptance:

- `rg "createNearAccount" packages tests` returns no registration-path hits;
- invalid object literals with both implicit and sponsored fields fail type
  fixtures;
- both provisioning branches have canonical digest tests;
- server-allocated wallet/key-scope IDs are stable across prepare/respond/
  finalize for one intent;
- invalid wallet/provisioning branch combinations fail route parser tests and
  type fixtures;
- route parsers return narrow branch-specific types.

### Phase 3: HSS Registration Scope

- [x] Introduce `ThresholdEd25519RegistrationAccountScope`.
- [x] Rename registration HSS/PRF domain inputs from `nearAccountId` to
      `nearEd25519SigningKeyId`.
- [x] Replace registration HSS `new_account_id` request fields with
      `registrationAccountScope` and `nearEd25519SigningKeyId`.
- [x] Update `parseThresholdEd25519HssCanonicalContext()` so registration context
      accepts both implicit and sponsored named scope branches.
- [x] Update client HSS input derivation:
  - implicit branch uses generated `nearEd25519SigningKeyId` as the
    PRF/domain-separation input;
  - sponsored branch uses `sponsored_named_registration_scope` including the
    requested named account ID.
- [x] Update client worker/WASM schemas:
  - `hssClientSignerWasm.ts`;
  - `nearSignerWasm.ts`;
  - `createNearKeyOps.ts`;
  - `clientOutputMask.ts`.
- [x] Update server threshold PRF and HSS WASM schemas:
  - `thresholdPrfWasm.ts`;
  - `ed25519HssWasm.ts`.
- [x] Update server HSS prepare/respond/finalize scope validation to compare the
      full branch-specific registration scope.
- [x] Ensure HSS finalized output returns the public key before account
      resolution.

Acceptance:

- implicit pre-finalize HSS code has no dependency on a user-provided NEAR
  account ID;
- sponsored HSS code remains bound to the requested named account ID;
- registration and later signing use the same `nearEd25519SigningKeyId`;
- adding another registration account provisioning branch breaks exhaustive
  switches;
- HSS scope mismatch tests cover wallet ID, RP ID, signing root, signer slot,
  participant IDs, key version, derivation version, intent digest, and named
  account ID where applicable.

### Phase 4: Server Finalize And Persistence

- [x] Switch over `accountProvisioning` in wallet registration finalize.
- [x] For `implicit_account`, derive `ResolvedRegistrationNearAccount` from
      `finalized.publicKey` and skip `createAccount()`.
- [x] For `sponsored_named_account`, call `createAccount()` with the requested
      named account ID and finalized public key.
- [x] Extract shared provisioning resolution used by combined and Ed25519-only
      finalize paths.
- [x] Rename route timing from generic `nearAccountCreateMs` to a branch-specific
      `sponsoredNearAccountCreateMs`.
- [x] Pass `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId` into
      `keygenFromRegistrationMaterial()` and persistence.
- [x] Persist `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId` in signer
      records, warm sessions, and signing-session authorization.
- [x] Update identity linking so wallet identity and NEAR signer identity are
      separate records for implicit accounts.
- [x] Complete session policy drafts after account resolution and validate the
      returned session against `walletId`, `nearAccountId`, and
      `nearEd25519SigningKeyId`.
- [x] Update rollback semantics by branch:
  - implicit rollback removes local/server wallet state only;
  - sponsored rollback preserves the current best-effort handling for a created
    on-chain account.

Acceptance:

- implicit registration never calls `nearClient.sendTransaction()`;
- sponsored named registration is the only registration branch that can call
  `createAccount()`;
- server response includes the resolved account ID, public key, and branch kind;
- sponsored response includes the account creation transaction hash;
- persisted key material stores the resolved account ID and NEAR Ed25519 signing key ID;
- session claims for implicit accounts do not require `walletId` to equal
  `nearAccountId`.

### Phase 5: Client Registration And Wallet Iframe

- [x] Change public registration entrypoints to accept an account provisioning
      mode.
- [x] Make `implicit_account` the default mode for API helpers that do not expose
      named account selection.
- [x] Return server-allocated `walletId` from registration intent creation, and
      expose reroll where the UI supports name choice.
- [x] Keep named-account input and account-name availability preflight only for
      `sponsored_named_account`.
- [x] Update wallet iframe routing so implicit pre-finalize work is keyed by
      server-allocated wallet ID, then attached to the resolved account binding after
      finalize.
- [x] Keep sponsored named wallet iframe routing keyed by the requested named
      account ID where the current code already needs it.
- [x] Persist local account, profile, passkey metadata, warm session records, and
      ECDSA wallet keys under the resolved wallet binding for both branches.
- [x] Update display helpers such as `extractUsername()` for 64-character account
      IDs.
- [x] Update public wallet/session responses to expose both `walletId` and
      `nearAccountId` for implicit wallets.
- [x] Update registration events so implicit account ID appears only after it is
      resolved; sponsored named events may include the requested account ID from
      the start.

Acceptance:

- implicit registration UI can run with no NEAR account-name input;
- implicit registration UI can display and reroll a server-allocated wallet name;
- sponsored named registration UI still accepts a named account ID;
- local persistence can restore and unlock both implicit and sponsored wallets;
- wallet iframe boot and `requireRouter()` work for implicit registration before
  the resolved NEAR account exists;
- returned registration result includes provisioning branch and resolved account
  ID.

### Phase 6: Signing And Execution Readiness

- [x] Classify NEAR signing readiness with a union:

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

- [x] Update nonce coordinator initialization to return `implicit_unfunded`
      instead of throwing for a derived implicit account with no visible access
      key.
- [x] Route direct NEAR transaction submission through `access_key_available` or
      `sponsored_named_ready`.
- [x] Route sponsored/intents/delegate flows through their own readiness branch
      after confirming their exact account-existence requirements.
- [x] Add explicit user-facing errors for direct NEAR actions that require
      funding first.

Acceptance:

- direct NEAR transactions cannot be attempted from an unfunded implicit account;
- sponsored named accounts keep current direct NEAR transaction readiness after
  account creation;
- signing-session authorization derives shares with `nearEd25519SigningKeyId` and
  sends transactions with `nearAccountId`;
- sponsored or intents paths state exactly whether they support unfunded
  implicit accounts;
- nonce-lane tests cover implicit-unfunded, funded implicit, sponsored named,
  and RPC failure.

### Phase 7: Tests, Benchmarks, And Cleanup

- [x] Replace named-registration mocks with branch-specific implicit and
      sponsored named mocks.
- [x] Add type fixtures for invalid registration account provisioning states.
- [x] Add server unit tests proving implicit finalize skips account creation.
- [x] Add server unit tests proving sponsored named finalize calls account
      creation exactly once.
- [x] Add client registration tests proving account existence preflight runs only
      for `sponsored_named_account`.
- [x] Add tests proving implicit `walletId` can differ from `nearAccountId`.
- [x] Add tests proving warm-session restore validates `walletId`,
      `nearAccountId`, and `nearEd25519SigningKeyId`.
- [x] Add type fixtures rejecting functions that accept raw strings or partial
      identity bags for registration account binding.
- [x] Add integration or e2e tests where implicit registration returns a derived
      64-character account ID.
- [x] Add integration or e2e tests where implicit registration returns a
      generated readable wallet ID and can later sign with the derived NEAR
      account binding.
- [x] Add integration or e2e tests where sponsored named registration returns a
      named account ID and transaction hash.
- [ ] Define replacement registration latency evidence for implicit and
      sponsored scenarios on the real intended-behaviour topology. The old
      `benchmark:registration-flow` runner was retired by Refactor 88 because
      it depended on a deleted managed-registration mock harness.
- [ ] Record before/after numbers in a replacement benchmark report.

Acceptance:

- `rg "createNearAccount" packages tests` has no hits;
- `rg "new_account_id" packages tests` has no HSS registration hits after the
  scope replacement lands;
- implicit benchmark has no NEAR account-create timing bucket;
- sponsored named benchmark reports `sponsoredNearAccountCreateMs`;
- production-like implicit registration removes the chain-bound account-create
  segment;
- no implicit test fixture relies on `walletId === nearAccountId`.

### Phase 8: Rename Ed25519 Key Scope To NEAR Ed25519 Signing Key ID

The legacy `ed25519KeyScopeId` name was accurate about domain separation, but too
generic. The code now proves this identifier is specifically the stable SDK key
identity for a NEAR Ed25519 signer:

- `NearEd25519SignerBinding` owns the field alongside `NearAccountBinding`;
- exact Ed25519 signing lanes are `curve: 'ed25519'` and `chainFamily: 'near'`;
- registration derives this value before the final implicit `nearAccountId`
  exists, then uses it for NEAR Ed25519 HSS/session/export/signing material;
- ECDSA has a separate `walletKeyId`/exact-lane model and must not share this
  name.

Rename the domain concept to `nearEd25519SigningKeyId`. This is clearer because
the value identifies the durable NEAR Ed25519 signing key lane, not the final
NEAR account, not the active threshold session, and not a generic Ed25519/HSS
scope. It is required for implicit accounts, but it is not an implicit-only
workaround; sponsored named accounts and add-signer flows also need a stable
NEAR Ed25519 signing-key identity that does not collapse into `nearAccountId`.

Tasks:

- [x] Add `NearEd25519SigningKeyId` as the canonical brand and parser.
- [x] Rename helpers:
  - `ed25519KeyScopeIdFromString` ->
    `nearEd25519SigningKeyIdFromString`;
  - `ed25519KeyScopeIdFromWalletId` ->
    `nearEd25519SigningKeyIdFromWalletId`;
  - `computeGeneratedImplicitEd25519KeyScopeId` ->
    `computeGeneratedImplicitNearEd25519SigningKeyId`;
  - `computeRegistrationEd25519KeyScopeId` ->
    `computeRegistrationNearEd25519SigningKeyId`.
- [x] Rename `GeneratedImplicitEd25519KeyScopeDigestInput` to a NEAR Ed25519 signing
      key digest input. Keep the digest branch explicit that this is generated
      for implicit NEAR registration.
- [x] Rename `NearEd25519SignerBinding.ed25519KeyScopeId` to
      `nearEd25519SigningKeyId`.
- [x] Rename exact Ed25519 lane identity fields and parsers from
      `ed25519KeyScopeId` to `nearEd25519SigningKeyId`.
- [x] Rename registration intent, registration ceremony, wallet store, key
      store, warm-session, sealed-restore, recovery, budget/readiness, and
      iframe/public wire fields.
- [x] Rename server registration HSS scope fields and request/response fields
      that carried `ed25519KeyScopeId`.
- [x] Rename SDK Ed25519-HSS binding facts from `ed25519KeyScopeId` to
      `nearEd25519SigningKeyId`. If the encoded fact label changes, bump the SDK
      application-binding domain version and treat old dev material as obsolete.
- [x] Keep `nearAccountId` separate. Remove any helper that derives the signing
      key ID from `nearAccountId` in core logic. If a request or persistence
      parser must accept legacy persisted `ed25519KeyScopeId`, normalize it once
      at that boundary and emit only `nearEd25519SigningKeyId` internally.
- [x] Update Refactor 78 and Refactor 79 docs, guards, and type fixtures so they
      reference `nearEd25519SigningKeyId`.
- [x] Add source guards rejecting `ed25519KeyScopeId`, `Ed25519KeyScopeId`, and
      `ed25519_key_scope` in core code after the rename. Allowlisted hits must be
      explicit legacy request/persistence parsers or deletion notes.

Acceptance:

- `NearEd25519SignerBinding` exposes `nearEd25519SigningKeyId`.
- `ExactEd25519SigningLaneIdentity` exposes `nearEd25519SigningKeyId` and still
  requires `nearAccountId` for NEAR signing.
- Registration intent and finalization responses carry
  `nearEd25519SigningKeyId`.
- SDK Ed25519-HSS binding facts hash `nearEd25519SigningKeyId`, signing root id,
  and signing root version; the HSS crate still receives only the application
  binding digest plus participant ids.
- No core signing, export, restore, budget, registration, or session logic uses
  the legacy `ed25519KeyScopeId` name.
- Boundary compatibility, if retained for existing local/dev persistence, is
  isolated to named parsers with tests proving the parsed internal shape uses
  `nearEd25519SigningKeyId`.
- Tests prove implicit `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId` can all differ.

### Phase 9: Activate Implicit NEAR Accounts And Claim Names

Direct NEAR signing from an implicit account requires that the implicit account
exist on-chain with the Ed25519 access key visible. Implicit registration
intentionally skips that NEAR transaction, so the first direct NEAR action can
surface `implicit_unfunded`.

Model two operations explicitly:

- **Activate implicit account** funds the existing 64-hex implicit account. This
  is a transfer from the configured relayer/funding account to `nearAccountId`.
  It must not create a new NEAR account, mutate `nearAccountId`, or rewrite exact
  lane identity.
- **Claim named NEAR account** creates a human-readable named NEAR account for
  the wallet. This changes the wallet's NEAR account binding or adds another
  NEAR signer/account binding. It is a separate account-management flow, not the
  minimal fix for `implicit_unfunded`.

Tasks:

- [x] Add a D1/router auth-service boundary for NEAR account activation:
      `fundImplicitNearAccount({ walletId, nearAccountId, nearPublicKeyStr })`.
      The implementation must require explicit
      `ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING`, configured
      `relayerPrivateKey`, `relayerAccount`, `nearRpcUrl`, and
      `accountInitialBalance`; if `relayerPublicKey` is configured, it must
      match the private key.
- [x] Validate at the route boundary that `nearAccountId` is an
      `ImplicitNearAccountId` and equals
      `deriveImplicitNearAccountIdFromEd25519PublicKey(nearPublicKeyStr)`.
- [ ] Verify the wallet's persisted NEAR Ed25519 signer binding matches
      `walletId`, `nearAccountId`, `nearPublicKeyStr`, and signer slot before
      dispatching funds.
- [x] Dispatch a transfer-only NEAR transaction to the implicit account. Do not
      use `CreateAccount` for implicit activation.
- [ ] Return a narrow activation result with transaction hash and readiness
      status. If key visibility is delayed, return a pending readiness result
      and schedule/refetch readiness on the client.
- [x] Add a confirmation modal CTA for `implicit_unfunded` direct NEAR signing:
      label it `Activate NEAR account` or `Fund account`. Disable `Confirm`
      until activation succeeds or ask the user to retry after activation.
- [x] After activation, clear/refetch the NEAR nonce/access-key lane for the
      exact `walletId + nearAccountId + nearPublicKeyStr` subject.
- [ ] Add local and D1 smoke coverage for implicit activation using a funded
      testnet/localnet relayer. Keep missing-funding-config failures explicit.
- [ ] Add source guards preventing `CreateAccount` from being used in the
      implicit-account activation path.

Acceptance:

- An unfunded implicit account signing prompt shows an actionable activation CTA
  instead of only a static error.
- Activation sends a transfer to the existing implicit account and keeps
  `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId` unchanged.
- The first direct NEAR action can succeed after activation and nonce readiness
  refreshes.
- Missing relayer private key, relayer account, NEAR RPC URL, or initial funding
  amount, or a disabled test-funding flag returns a clear `not_configured`
  route error. A configured relayer public key must match the private key.
- Named-account claiming is not implemented through the implicit activation
  route.

Future named-account claim tasks:

- [ ] Add a separate named-account claim route that accepts a desired
      `NamedNearAccountId` and requires wallet-session authorization.
- [ ] Decide whether claiming a name mutates the wallet's primary NEAR account
      binding or adds a second `near_ed25519_signer` binding. Prefer adding a
      second binding unless product semantics require migration.
- [ ] Update local IndexedDB, D1 `wallet_signers`, warm sessions, nonce keys,
      and display profiles through exact lane identity, not broad wallet lookup.
- [ ] Add UI that asks for a human-readable NEAR name only inside the named claim
      flow.

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
tests/unit/refactor79ExactSigningLane.guard.unit.test.ts
tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts
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
- Server-allocated wallet IDs need enough suffix entropy for the expected namespace
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
- Implicit registration allocates a readable server-allocated wallet ID/key scope.
- Implicit registration submits no NEAR transaction.
- Implicit registration returns the lowercase hex account ID derived from the
  finalized Ed25519 public key.
- Implicit registration returns both `walletId` and `nearAccountId`, and tests
  prove they can differ.
- Sponsored named registration preserves the current relayer-funded account
  creation behavior.
- Registration code contains no `createNearAccount` boolean.
- Registration, stored signer material, warm sessions, and signing-session
  authorization carry `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId`.
- Implicit registration server diagnostics contain no NEAR account-create timing
  bucket.
- Sponsored named registration diagnostics report branch-specific account-create
  timing.
- First direct NEAR action from an unfunded implicit account fails with an
  explicit funding/readiness result.
- Tests reject invalid account provisioning states at compile time and runtime
  boundaries.

## Review: Completion Pass, 2026-06-25

Status: Phase 1-8 implementation is complete; benchmark capture remains open
pending the post-Refactor 88 real-topology benchmark replacement.

- [x] Public/server registration exposes implicit and sponsored named account
  provisioning branches.
- [x] Implicit registration derives the final NEAR account ID from the Ed25519
  public key and skips NEAR account creation.
- [x] Sponsored named registration keeps the relayer-funded account creation
  path as an explicit branch.
- [x] Generated readable wallet IDs are distinct from implicit NEAR account IDs
  and are validated as wallet IDs, not NEAR account IDs.
- [x] Registration, signer records, warm sessions, restore, recovery, sync, and
  signing authorization carry `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId`.
- [x] Public, React, and iframe registration/session surfaces expose wallet and
  NEAR identities separately.
- [x] First direct NEAR actions from unfunded implicit accounts route through
  explicit funding/readiness handling.
- [x] Tests and guards cover implicit `walletId !== nearAccountId` identity and
  reject legacy account-creation shapes.
- [ ] Capture benchmark evidence comparing implicit registration against
  sponsored named registration.
