# Refactor 78: Wallet Capability Bindings

Date created: June 23, 2026

Status: implemented and audited; doc reconciled June 25, 2026.

Related plans:

- [router-a-b-SPEC.md](./router-a-b-SPEC.md)
- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-79-exact-signing-lane.md](./refactor-79-exact-signing-lane.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)

## Goal

Replace string-shaped wallet/account identity plumbing with capability-specific
bindings.

The Router A/B implicit-account refactor split one historical identifier into
multiple domain identities:

- `walletId`: durable user-facing wallet identity;
- `nearAccountId`: NEAR protocol account identity;
- `nearEd25519SigningKeyId`: Ed25519 HSS/PRF key-scope identity.

Those values are related only for specific capabilities. A wallet can exist
without a NEAR account. A wallet with a NEAR account can exist without a usable
Ed25519 signer. ECDSA signing is wallet-scoped and does not require a NEAR
Ed25519 signer.

This refactor makes that model explicit. Core code must pass narrow capability
bindings instead of deriving one identity from another.

Refactor 79 consumes these capability bindings as exact signing-lane authority:
`NearEd25519SignerBinding` and `EvmFamilyEcdsaSignerBinding` are wrapped under
`ExactSigningLaneIdentity.signer`, while Refactor 78 remains the owner of the
wallet/account/signer capability model. Refactor 79 owns exact-lane keys,
selection, restore, export, budget, and operation-state enforcement.

## Original Problem

The implementation audit found several post-refactor paths that treated
`nearAccountId` as a wallet identity:

- React `LoginState` drops `walletId`, so UI surfaces use `nearAccountId` for
  wallet-scoped recovery, export, and preferences calls.
- Account-menu ECDSA export passes `nearAccountId` as `walletSession.walletId`.
- NEAR Ed25519 export lane selection reads warm lanes with
  `walletId: nearAccountId`.
- Recovery-code UI passes `nearAccountId` as the `walletId` for status and
  rotation.
- Login warmup and passkey session provisioning contained fallbacks such as
  `walletId || nearAccountId`, `toWalletId(nearAccountId)`, and
  `nearEd25519SigningKeyId || nearAccountId`.

Those bugs survive normal tests because many fixtures use named accounts where
`walletId === nearAccountId`.

## Design Principles

- `WalletIdentity` is the durable wallet identity and carries only `walletId`.
- `rpId` is not wallet identity. It belongs on passkey/WebAuthn credential,
  registration, and session records. Existing ECDSA key identity also carries
  `rpId` as part of the current canonical lane/key namespace; Refactor 79
  replaces that with a dedicated key namespace field.
- Wallet auth methods are additive capabilities. A wallet can have passkey,
  Email OTP, both, or future auth methods without changing wallet identity.
- NEAR account binding is a wallet capability.
- NEAR Ed25519 signing is a narrower capability attached to a wallet and a NEAR
  account.
- ECDSA signing is wallet-scoped and lane-scoped.
- Recovery and Email OTP enrollment are wallet-scoped unless a specific flow
  states a NEAR or ECDSA exact-lane dependency.
- Core functions accept the narrowest capability object required by the
  operation.
- Raw strings are parsed once at request, persistence, iframe, and UI state
  boundaries.
- Core code must not derive `walletId` from `nearAccountId`.
- Core code must not derive `nearEd25519SigningKeyId` from `nearAccountId`.
- Optional identity fields are boundary/display concerns. Core lifecycle state
  uses discriminated unions.
- Capability resolution and runtime readiness are separate states.

## Enforcement Contract

This refactor succeeds only if the new bindings become the allowed command
surface for identity-sensitive core code. Treat these rules as hard constraints.

- Core functions that read, write, sign, export, recover, restore, budget,
  authorize, or hydrate wallet material must accept capability bindings instead
  of raw identifiers or partial identity bags.
- Core command inputs must not contain flat sibling identity fields such as
  `{ walletId, nearAccountId, nearEd25519SigningKeyId }`. Use the owning binding:
  `WalletIdentity`, `NearAccountBinding`, `NearEd25519SignerBinding`, or
  Refactor 79's canonical exact ECDSA lane identity.
- Core command inputs must not make identity fields optional. Missing identity
  is represented by a discriminated union branch before the command is built.
- Boundary code may accept raw strings from public APIs, iframe messages,
  decoded tokens, persistence records, UI prompt results, and worker responses.
  It must normalize those values immediately into capability bindings before
  invoking domain logic.
- Compatibility parsing may exist only in named request or persistence boundary
  parsers. Every compatibility parser must have tests and a deletion note.
- No core helper may repair missing identity with `nearAccountId`, `accountId`,
  current-wallet state, local cache lookup, or display state.
- No function may recompute `nearEd25519SigningKeyId` from `walletId` or
  `nearAccountId` after a signer binding has been resolved. Registration,
  stored signer records, session claims, or warm-session metadata provide the
  key scope exactly once at the boundary.
- UI components may hold display values, but wallet-scoped actions must receive
  `WalletIdentity`, NEAR-scoped actions must receive `NearAccountBinding`, and
  Ed25519 signer actions must receive `NearEd25519SignerBinding`.
- Tests and type fixtures must use at least one split implicit wallet fixture in
  every suite that touches identity-sensitive behavior.

The following patterns are build-blocking outside approved boundary parser,
migration, and typecheck fixture files:

```text
walletId || nearAccountId
walletId ?? nearAccountId
record.walletId ?? record.nearAccountId
toWalletId(nearAccountId)
walletId: nearAccountId
walletId: accountId
accountId: walletId
nearEd25519SigningKeyId || nearAccountId
nearEd25519SigningKeyId ?? nearAccountId
args.walletId || nearAccountId
walletSession.walletId || nearAccountId
as WalletId
as NearEd25519SigningKeyId
```

## Target Domain Shape

Use branded identifiers everywhere these types cross core logic. The shared
module should use `WalletId`, `NearAccountId`, and `NearEd25519SigningKeyId` from
`packages/shared-ts`. If `RpId` is promoted to shared-ts, use it only in
passkey/WebAuthn types. sdk-web can alias or re-export those names at its
boundaries while internal call sites move to the shared capability bindings.

```ts
type WalletIdentity = {
  walletId: WalletId;
};

type PasskeyAuthScope = {
  wallet: WalletIdentity;
  rpId: RpId;
};

type WalletAuthMethodBinding =
  | {
      kind: 'passkey';
      scope: PasskeyAuthScope;
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      wallet: WalletIdentity;
      emailHashHex: string;
      registrationAuthorityId: string;
    };

type CurrentWalletAuthMethod =
  | {
      kind: 'none';
    }
  | {
      kind: 'selected';
      binding: WalletAuthMethodBinding;
    };

type NearAccountBinding =
  | {
      kind: 'implicit_near_account';
      wallet: WalletIdentity;
      nearAccountId: ImplicitNearAccountId;
    }
  | {
      kind: 'named_near_account';
      wallet: WalletIdentity;
      nearAccountId: NamedNearAccountId;
    };

type NearEd25519SignerBinding = {
  account: NearAccountBinding;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
};
```

Do not export constructors or raw brand casts for these domain objects. Export
builders, parsers, predicates, and accessors only. Tests that intentionally
exercise invalid construction belong in `*.typecheck.ts` fixtures with
`@ts-expect-error`.

ECDSA wallet-scoped operations should use `WalletIdentity` directly. ECDSA
lane-scoped operations must use the canonical exact-lane identity from
`packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`.
Refactor 79 owns that type; this refactor must not introduce a second public
ECDSA lane identity.

Use capability unions where a flow actually switches over absence or
availability. Core command inputs should generally require the concrete binding
they need.

```ts
type NearAccountCapability =
  | {
      kind: 'none';
      wallet: WalletIdentity;
    }
  | {
      kind: 'bound';
      binding: NearAccountBinding;
    };

type NearEd25519SignerCapability =
  | {
      kind: 'none';
      account: NearAccountBinding;
    }
  | {
      kind: 'available';
      binding: NearEd25519SignerBinding;
    };
```

Represent runtime readiness separately from durable capability records.

```ts
type NearExecutionReadiness =
  | {
      kind: 'implicit_unfunded';
      account: NearAccountBinding;
    }
  | {
      kind: 'access_key_available';
      account: NearAccountBinding;
      nonce: bigint;
    }
  | {
      kind: 'server_dispatch_available';
      account: NearAccountBinding;
    }
  | {
      kind: 'account_lookup_failed';
      account: NearAccountBinding;
      error: string;
    };
```

Use a resolved wallet context at login, refresh, restore, iframe activation, and
account-menu boundaries. Domain commands should receive the narrow binding
extracted from this context.

```ts
type WalletContext = {
  wallet: WalletIdentity;
  nearAccount: NearAccountCapability;
  nearEd25519Signer:
    | {
        kind: 'none';
      }
    | {
        kind: 'available';
        binding: NearEd25519SignerBinding;
      };
  ecdsaWallet:
    | {
        kind: 'none';
      }
    | {
        kind: 'available';
        wallet: WalletIdentity;
      };
};
```

The context resolver is boundary code. Domain operations consume
`WalletIdentity`, `NearAccountBinding`, `NearEd25519SignerBinding`, or
Refactor 79's canonical exact ECDSA lane identity directly.

## Boundary Parsers And Builders

Create one shared identity module for cross-client/server shapes:

```text
packages/shared-ts/src/utils/walletCapabilityBindings.ts
packages/shared-ts/src/utils/walletCapabilityBindings.typecheck.ts
```

The shared module should expose parsers/builders for external and persistence
boundaries only:

```ts
function walletIdentityFromRaw(raw: unknown): WalletIdentity;
function passkeyAuthScopeFromRaw(raw: unknown): PasskeyAuthScope;
function walletAuthMethodBindingFromRaw(raw: unknown): WalletAuthMethodBinding;
function nearAccountBindingFromRaw(raw: unknown): NearAccountBinding;
function nearEd25519SignerBindingFromRaw(raw: unknown): NearEd25519SignerBinding;

function buildImplicitNearAccountBinding(args: {
  wallet: WalletIdentity;
  nearAccountId: ImplicitNearAccountId;
}): NearAccountBinding;

function buildNamedNearAccountBinding(args: {
  wallet: WalletIdentity;
  nearAccountId: NamedNearAccountId;
}): NearAccountBinding;

function buildNearEd25519SignerBinding(args: {
  account: NearAccountBinding;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
}): NearEd25519SignerBinding;
```

Export these builders as the only supported construction path. Call sites must
not construct bindings with object literals outside tests, parsers, and builder
implementations.

Builder invariants:

- `WalletIdentity` always carries `walletId`.
- `PasskeyAuthScope` carries `WalletIdentity` plus `rpId`.
- `WalletAuthMethodBinding.kind` is branch-specific. The passkey branch requires
  `rpId`; the Email OTP branch rejects `rpId` and carries Email OTP identity
  fields instead.
- `CurrentWalletAuthMethod` carries the selected concrete auth-method binding.
  It must not collapse back to a raw auth-method enum.
- React and public-session parsers must validate that a selected current auth
  method matches one entry in `authMethods`.
- Passkey boundaries validate the expected RP scope before minting or consuming
  passkey credentials.
- `walletId` is always provided by the wallet/profile/session boundary.
- `nearAccountId` is always provided by a NEAR account binding boundary.
- `nearEd25519SigningKeyId` is always provided by registration, stored signer, or warm
  session metadata.
- `NearEd25519SignerBinding` can be built only from an existing
  `NearAccountBinding`.
- `NearAccountBinding.kind` is branch-specific. Builders reject implicit IDs in
  named bindings and named IDs in implicit bindings.
- Core code reads `walletId` and `nearAccountId` through the binding owner
  object. It must not construct a signer binding by independently threading flat
  `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId` values.
- Public and iframe boundary parsers must preserve the incoming field meaning.
  A field named `accountId` can be accepted only in documented compatibility
  parsers, and the parser must map it to the correct branch-specific identity
  before returning a binding.
- Store parsers must fail closed when required identity fields are missing after
  the allowed migration parser has run. Core store consumers must not receive
  partial records.

## Command Input Model

Each operation must accept the narrow capability it needs.

```ts
type RecoveryCodesCommand = {
  wallet: WalletIdentity;
};

type EcdsaExportCommand = {
  lane: ExactEcdsaSigningLaneIdentity;
};

type NearAccessKeyCommand = {
  account: NearAccountBinding;
};

type NearEd25519ExportCommand = {
  signer: NearEd25519SignerBinding;
};

type NearTransactionCommand = {
  account: NearAccountBinding;
  signer: NearEd25519SignerBinding;
  readiness: NearExecutionReadiness;
};
```

Operations that can use sponsored dispatch or delegate/signature-only flows
should model those branches explicitly with discriminated unions. They must not
accept a partial NEAR signer object.

Example:

```ts
type NearSignatureCommand =
  | {
      kind: 'direct_transaction';
      account: NearAccountBinding;
      signer: NearEd25519SignerBinding;
      readiness: Extract<
        NearExecutionReadiness,
        { kind: 'access_key_available' | 'server_dispatch_available' }
      >;
    }
  | {
      kind: 'offchain_nep413';
      account: NearAccountBinding;
      signer: NearEd25519SignerBinding;
    }
  | {
      kind: 'sponsored_delegate';
      account: NearAccountBinding;
      signer: NearEd25519SignerBinding;
      sponsor: SponsoredDispatchBinding;
    };
```

Every switch over command or capability unions must use `assertNever` for
exhaustiveness.

## React And Public API Shape

React login state must carry wallet identity independently from NEAR account
identity.

```ts
type ReactLoginState =
  | {
      isLoggedIn: false;
      walletId: null;
      nearAccountId: null;
      nearPublicKey: null;
      currentAuthMethod: { kind: 'none' };
      authMethods: readonly [];
    }
  | {
      isLoggedIn: true;
      walletId: WalletId;
      nearAccountId: NearAccountId | null;
      nearPublicKey: string | null;
      currentAuthMethod: CurrentWalletAuthMethod;
      authMethods: readonly WalletAuthMethodBinding[];
      thresholdEcdsaEthereumAddress?: string | null;
      thresholdEcdsaPublicKeyB64u?: string | null;
    };
```

React state is UI boundary state. Immediately derive a `WalletContext` before
passing identity into account-menu actions, recovery-code actions, export flows,
unlock refresh, iframe routing, or signing commands. Components should not pass
`loginState.nearAccountId` to wallet-scoped operations.

React components should derive command inputs from this state:

- recovery-code status and rotation use `WalletIdentity`;
- ECDSA export uses `WalletIdentity` plus the selected ECDSA lane;
- NEAR explorer links and access-key reads require `NearAccountBinding`;
- NEAR Ed25519 export requires `NearEd25519SignerBinding`;
- linked-device NEAR key operations require both `WalletIdentity` and
  `NearAccountBinding`.

Public APIs should keep ergonomic inputs at the boundary, then normalize once to
capability bindings before calling core logic.

Public and iframe APIs must reject ambiguous runtime calls when the requested
operation needs a wallet binding and the caller provides only a NEAR account ID.
Published TypeScript types, runtime validators, and iframe message parsers must
agree on that rejection.

Selected-wallet restore is an explicit wallet-id restore path. React
`refreshLoginState()` and wallet-iframe lifecycle startup may read
`preferences.getCurrentWalletId()` only as a stored `WalletIdentity`; they must
not derive a wallet from `nearAccountId`, current NEAR account state, or account
projection fallback. Iframe preference handlers may fetch a wallet session only
when the message payload carries an explicit `walletId`, and that lookup remains
wallet-keyed.

## Persistence Model

Persist durable records by the identity each record actually belongs to.

- wallet/profile records are keyed by `walletId` and do not require `rpId`;
- NEAR account projections are keyed by `(walletId, nearAccountId)`;
- NEAR Ed25519 signer records are keyed by
  `(walletId, nearAccountId, nearEd25519SigningKeyId, signerSlot)`;
- ECDSA lane records use the canonical Refactor 79 exact-lane identity and the
  existing signing-lane records;
- recovery-code backup records are keyed by `walletId`;
- active-selection records store selected capability IDs, never copied identity
  fields without their owning binding.

Compatibility parsers may read legacy persistence records, but they must
normalize immediately to one of the target bindings. No core function should
receive a legacy raw record or a partial identity object.

Persisted compatibility readers must be named with a `parseLegacy*` or
`migrateLegacy*` prefix, and each reader must return a target binding or a typed
failure. Domain stores should expose only normalized methods once records leave
the repository boundary.

## Implementation Plan

### Phase 0: Enforcement Baseline

- Add a source-guard test that scans identity-sensitive source directories for
  forbidden fallback and cast patterns from the Enforcement Contract.
- Add an allowlist file for approved boundary parser, migration, and typecheck
  fixture locations. Every allowlist entry must include a removal note or a
  reason the file is a permanent boundary.
- Add a failing fixture that demonstrates a core command cannot be called with
  `{ walletId, nearAccountId, nearEd25519SigningKeyId }` as flat fields.
- Add a failing fixture that demonstrates wallet-scoped commands cannot accept
  `nearAccountId`, `accountId`, or a display account value.
- Add a split implicit fixture module shared by unit tests:

  ```ts
  const IMPLICIT_WALLET = walletIdentityFromRaw({
    walletId: 'frost-vermillion-k7p9m2',
  });

  const IMPLICIT_PASSKEY_SCOPE = passkeyAuthScopeFromRaw({
    wallet: IMPLICIT_WALLET,
    rpId: 'example.test',
  });

  const IMPLICIT_NEAR_ACCOUNT = buildImplicitNearAccountBinding({
    wallet: IMPLICIT_WALLET,
    nearAccountId: implicitNearAccountIdFromString('a'.repeat(64)),
  });

  const IMPLICIT_NEAR_ED25519_SIGNER = buildNearEd25519SignerBinding({
    account: IMPLICIT_NEAR_ACCOUNT,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      'ed25519-scope-implicit-test-k7p9m2',
    ),
    signerSlot: 0,
  });
  ```

- Update test helpers so new identity-sensitive tests start from split fixtures
  by default. Named-account fixtures should opt in explicitly.

### Phase 1: Shared Domain Types And Static Guards

- Add `walletCapabilityBindings.ts` in `packages/shared-ts`.
- Add branded type builders and parsers for wallet, NEAR account, NEAR Ed25519
  signer, passkey auth scope, and wallet auth-method bindings.
- Add `@ts-expect-error` fixtures rejecting:
  - `NearAccountBinding` without wallet identity;
  - `PasskeyAuthScope` without `rpId`;
  - Email OTP auth-method bindings with `rpId`;
  - `currentAuthMethod` modeled as `WalletAuthMethod | null`;
  - selected current auth methods without a concrete
    `WalletAuthMethodBinding`;
  - auth-method state modeled as a single exclusive method when multiple active
    auth methods should be representable;
  - implicit account IDs in the named NEAR account branch;
  - named account IDs in the implicit NEAR account branch;
  - `NearEd25519SignerBinding` without `nearEd25519SigningKeyId`;
  - `NearEd25519SignerBinding` with independently supplied `walletId` or
    `nearAccountId` outside the nested account binding;
  - ECDSA command inputs that accept `nearAccountId`;
  - recovery-code commands that accept `nearAccountId`;
  - broad object spreads that add both capability branches.
- Add `assertNever`-checked switches for all capability unions.
- Add type fixtures rejecting exported raw construction of capability bindings.
- Add type fixtures rejecting optional identity fields in core command inputs.
- Add type fixtures rejecting a `WalletContext` with multiple active branches
  for the same capability.

### Phase 1a: Server Boundary And Store Inventory

Update server-side request parsers, session claims, and stores before web code
depends on capability records.

- Update `AuthService` registration/add-signer helpers to pass wallet, NEAR
  account, and Ed25519 signer bindings as single branch-specific objects.
- Update `WalletStore` so all read/write paths keep `walletId` as the durable
  key. Wallet records must not require `rpId`.
- Update shared `WalletAuthMethodRecord` so the passkey branch requires `rpId`
  and the Email OTP branch rejects `rpId` with `never`.
- Update `RegistrationCeremonyStore` parsers so stored registration authority,
  generated wallet reservations, add-signer ceremonies, and finalize replay
  records normalize into capability bindings.
- Update `EmailOtpStores` records and parsers so challenge, grant, enrollment,
  auth-state, unlock-challenge, and Google registration-attempt records carry
  wallet identity as `WalletIdentity` plus Email OTP provider identity. They
  must not require passkey RP scope.
- Update relayer route parsers in `relayWalletRegistration.ts` for:
  - `/wallets/register/intent`;
  - `/wallets/register/start`;
  - `/wallets/register/finalize`;
  - `/wallets/:walletId/signers/intent`;
  - `/wallets/:walletId/signers/start`;
  - `/wallets/:walletId/auth-methods/*`;
  - `/wallets/:walletId/ecdsa/inventory`.
- Update wallet unlock routes so passkey unlock verifies wallet identity plus
  `rpId`, while Email OTP unlock verifies wallet identity plus Email OTP
  provider/challenge identity.
- Update Router A/B common route helpers so Ed25519 JWT session info parses into
  `NearEd25519SignerBinding`, and ECDSA JWT session info parses into Refactor
  79's canonical exact ECDSA lane state.
- Update ThresholdService validation/store parsers for:
  - Ed25519 key records;
  - Ed25519 wallet session records;
  - Ed25519 wallet session JWT claims;
  - ECDSA wallet session JWT claims;
  - app-session claims that carry wallet scope.
- Replace flat identity parameter lists in server core helpers with
  branch-specific bindings before updating call sites. Avoid adding overloads
  that accept both legacy and capability-shaped inputs.
- Add server tests that assert legacy request parsing stops at the route or store
  boundary and downstream service spies receive capability bindings.

### Phase 2: React Login State And Account Menu

- Add `walletId` to React `LoginState`.
- Add registered auth-method capability state to logged-in React `LoginState`.
  Passkey capabilities include `rpId`; Email OTP capabilities do not.
- Change React `currentAuthMethod` to `CurrentWalletAuthMethod`, where the
  selected branch carries a concrete `WalletAuthMethodBinding`.
- Validate session refresh and iframe refresh results so `currentAuthMethod`
  either has `kind: 'none'` or references one concrete entry in `authMethods`.
- Update `useLoginStateRefresher`, `useWalletIframeLifecycle`, and
  `useSeamsContextValue` so successful session reads store wallet identity.
- Add selected-wallet restore tests proving no-argument React/iframe refresh
  restores only `preferences.getCurrentWalletId()` and never falls back through
  `nearAccountId`.
- Update `AccountMenuButton` to compute:
  - `walletIdentity` from `loginState.walletId`;
  - `passkeyAuthScope` from the selected passkey auth-method capability only
    for passkey/WebAuthn calls;
  - `nearAccountBinding` only when `loginState.nearAccountId` is present.
- Update `RecoveryCodesModal` props from `nearAccountId` to `walletId`.
- Update ECDSA export calls to pass a wallet session derived from `walletId`.
- Update NEAR export and access-key UI to require a NEAR binding.
- Update linked-device UI so wallet-scoped and NEAR-scoped actions use separate
  bindings.
- Update recent-unlock prefill and display helpers so generated implicit wallet
  IDs and 64-character NEAR account IDs do not rely on `nearAccountId` for a
  username.
- Add React type fixtures that reject account-menu wallet actions when only
  `nearAccountId` is available.
- Add AccountMenu tests where `walletId !== nearAccountId` and assert recovery
  codes, ECDSA export, and NEAR Ed25519 export receive different bindings.

### Phase 2a: Auth And Unlock Public APIs

- Change wallet-scoped auth entrypoints to accept wallet identity:
  - `auth.unlock`;
  - `auth.hasPasskeyCredential`;
  - `auth.getWalletSession`;
  - recent unlock lookup and activation;
  - wallet iframe initialization and router selection.
- Keep NEAR account IDs only in NEAR account operations and display fields.
- Remove fallbacks from auth/login paths:
  - `record?.walletId || toWalletId(nearAccountId)`;
  - `walletSession?.login.walletId || nearAccountId`;
  - `login.walletId || toWalletId(login.nearAccountId)`.
- Add split-identity tests for passkey unlock, wallet session refresh,
  `hasPasskeyCredential`, recent unlock prefill, iframe init, and failed-unlock
  cleanup.
- Runtime validators must reject `getWalletSession(nearAccountId)` style calls
  for implicit 64-character NEAR account IDs unless the public contract names
  the value `walletId` and parses it as a wallet identity.

### Phase 3: Recovery And Email OTP Commands

- Change recovery-code status and rotation domains to accept `WalletIdentity`.
- Keep request and iframe payload fields named `walletId`.
- Remove UI and domain call sites that pass `nearAccountId` as `walletId`.
- Ensure `resolveEmailOtpRecoveryCodeAppSessionJwt()` takes `WalletIdentity`.
- Add tests with `walletId !== nearAccountId` for:
  - status lookup;
  - stored backup read/display;
  - rotation;
  - iframe delegated recovery-code display.
- Add source guards for `RecoveryCodesModal` props and recovery-code operation
  calls so the wallet argument cannot be named `nearAccountId` or `accountId`.

### Phase 3a: Email OTP Session And Companion Capability Flows

Email OTP auth is wallet-scoped except where a specific NEAR Ed25519 signer or
ECDSA exact lane is being used. Update all companion-session and warmup paths so
they consume capability bindings.

- Update Email OTP Ed25519 warmup to require `NearEd25519SignerBinding` and
  `WalletIdentity` when selecting companion ECDSA capability records.
- Update Email OTP ECDSA login, enrollment, refresh, publication, and sealed
  session registry paths to use `WalletIdentity` for wallet ownership and
  Refactor 79 exact-lane identity for ECDSA authority.
- Update app-session JWT cache helpers so the cache key and wallet-session
  subject are wallet-scoped and never recovered from `nearAccountId`.
- Update email-otp worker request/result payloads so wallet-scoped fields are
  named `walletId`, NEAR fields are named `nearAccountId`, Ed25519 fields
  include `nearEd25519SigningKeyId`, and ECDSA key namespace fields are carried only
  inside exact-lane/key material.
- Add tests with `walletId !== nearAccountId` for:
  - Email OTP challenge issuance;
  - Email OTP login;
  - Email OTP enrollment;
  - Ed25519 signing via Email OTP warmup;
  - ECDSA companion selection for an Ed25519 signing flow;
  - app-session JWT cache read/write.
- Add tests proving Email OTP recovery and sync hydrate warm sessions with the
  resolved wallet binding and fail when the relay response contains a mismatched
  `walletId`, `nearAccountId`, or `nearEd25519SigningKeyId`.

### Phase 4: NEAR Ed25519 Export And Restore

- Change `ExactNearEd25519ExportLane` to carry `NearEd25519SignerBinding`.
- Change `restoreNearEd25519SessionForExport()` input from `{ nearAccountId }`
  to `{ signer: NearEd25519SignerBinding }`.
- Read persisted lanes by `signer.account.wallet.walletId`.
- Validate selected lanes against `nearAccountId`, `nearEd25519SigningKeyId`,
  `signerSlot`, `signingGrantId`, and `thresholdSessionId`.
- Change HSS export inputs so Ed25519 derivation receives
  `nearEd25519SigningKeyId` where the HSS protocol needs key scope and
  `nearAccountId` where the NEAR protocol account is required.
- Add tests proving NEAR export works with:
  - implicit wallet `walletId = frost-vermillion-k7p9m2`;
  - `nearAccountId = <64 hex>`;
  - `nearEd25519SigningKeyId = ed25519-scope-implicit-test-k7p9m2`.
- Add a negative test proving export lane selection cannot restore from
  `nearAccountId` as a wallet key.

### Phase 5: Passkey Login Warmup And Session Provisioning

- Resolve the active wallet capability before passkey login warmup.
- Pass `NearEd25519SignerBinding` into Ed25519 warmup and session provisioning.
- Persist warm Ed25519 capabilities with `signer.account.wallet.walletId` and
  `signer.nearEd25519SigningKeyId`.
- Pass `WalletIdentity` into ECDSA inventory, first bootstrap, profile
  continuity, and available-lane reads.
- Delete fallbacks:
  - `walletId || nearAccountId`;
  - `toWalletId(nearAccountId)`;
  - `nearEd25519SigningKeyId || nearAccountId`.
- Add split-identity passkey unlock tests covering Ed25519 warmup, ECDSA warmup,
  inventory repair, and first bootstrap.
- Add a test that spies on warm-session persistence and fails if either
  `walletId` or `nearEd25519SigningKeyId` equals `nearAccountId` for an implicit
  account.

### Phase 5a: Budget, Availability, And Confirmation Metadata

- Update budget owner/readiness helpers so Ed25519 budget status receives a
  `NearEd25519SignerBinding` and ECDSA budget status receives an
  exact ECDSA lane identity from Refactor 79.
- Remove budget fallback parsing from records such as
  `record.walletId ?? record.nearAccountId`.
- Update warm capability status readers so Ed25519 status reads the signer
  binding from the persisted record before building a wallet-budget owner.
- Update available signing lane readers so runtime Ed25519 records are queried
  by NEAR account binding or signer binding, while runtime ECDSA records are
  queried by wallet/ECDSA lane binding.
- Update UI confirm sealed-restore metadata so the durable metadata contains
  wallet identity, NEAR account identity, Ed25519 signer identity, and ECDSA key
  identity as separate fields.
- Add split-identity tests for budget admission/status, warm status, available
  lane listing, confirm-modal restore metadata, and sealed restore.
- Add negative tests for budget and availability readers that receive records
  missing wallet identity after boundary parsing.

### Phase 6: Public And Iframe Protocol Tightening

- Update public types so identity-sensitive APIs take capability-shaped inputs:
  - wallet-scoped APIs take `{ walletId }` or a normalized `WalletIdentity`;
  - passkey/WebAuthn APIs take `{ walletId, rpId }` or a normalized
    `PasskeyAuthScope`;
  - Email OTP APIs take wallet identity plus Email OTP provider/challenge
    identity. They do not take `rpId`; Refactor 79 ECDSA exact-lane/key identity
    carries the ECDSA key namespace separately;
  - NEAR-scoped APIs take `{ walletSession, nearAccount }` or a normalized
    `NearAccountBinding`;
  - Ed25519 signer APIs take a normalized signer binding.
- Update iframe messages to carry the same split.
- Keep compatibility parsing only at request boundaries where intentionally
  supported during this refactor. Route handlers must normalize to capability
  bindings before calling domain code.
- Add static fixtures rejecting old raw argument forms.
- Add runtime tests for JavaScript callers that bypass TypeScript and omit
  required wallet/session bindings. These calls must fail at the boundary.
- Remove iframe message handlers that can route wallet-scoped commands by
  `nearAccountId`, `accountId`, current-wallet fallback, or cached active
  account fallback.

### Phase 6a: Result And Event Field Semantics

Define public result and event identity fields explicitly so compatibility names
do not leak into core logic.

- Wallet-scoped flow events carry `walletId`.
- NEAR account flow events carry `nearAccountId`, with `accountId` retained only
  for public compatibility where the documented meaning is a NEAR protocol
  account.
- ECDSA flow events carry `walletId` and chain/lane identity.
- Registration and sync results return `walletId` and `nearAccountId` as
  separate fields. Any retained `accountId` field is documented as boundary
  compatibility and populated from the correct branch-specific identity.
- Add source guards for `accountId: walletId` and `walletId: accountId` outside
  approved public event/result compatibility files.
- Public result types for successful registration, login, sync, recovery, and
  session refresh must require `walletId` whenever a wallet exists. Optional
  wallet identity is allowed only in logged-out or anonymous states.

### Phase 7: Persistence And Store Cleanup

- Update store readers/writers to return capability bindings.
- Split active selected wallet from active selected NEAR account.
- Ensure recovery-code backups are keyed by `walletId`.
- Ensure NEAR account projections retain `walletId` and `nearAccountId`.
- Ensure Ed25519 signer records require `walletId`, `nearAccountId`,
  `nearEd25519SigningKeyId`, and `signerSlot`.
- Remove helper paths that silently repair missing identity fields inside core
  logic.
- Update local persistence normalizers so legacy fallback from `nearAccountId`
  to `walletId` or `nearEd25519SigningKeyId` exists only in a named migration parser
  with tests and deletion notes.
- Update IndexedDB repositories, warm-session stores, runtime session stores,
  sealed session stores, nonce/lease records, and account signer lifecycle
  records to use capability bindings at their public boundary.
- Add store-level tests asserting normalized read results contain complete
  bindings and no consumer-facing method returns partial identity records.

### Phase 8: Regression Guards And Fixture Cleanup

- Add a shared split-identity test fixture:

  ```ts
  const IMPLICIT_WALLET = walletIdentityFromRaw({
    walletId: 'frost-vermillion-k7p9m2',
  });

  const IMPLICIT_PASSKEY_SCOPE = passkeyAuthScopeFromRaw({
    wallet: IMPLICIT_WALLET,
    rpId: 'example.test',
  });

  const IMPLICIT_NEAR_ACCOUNT = buildImplicitNearAccountBinding({
    wallet: IMPLICIT_WALLET,
    nearAccountId: implicitNearAccountIdFromString('a'.repeat(64)),
  });

  const IMPLICIT_NEAR_ED25519_SIGNER = buildNearEd25519SignerBinding({
    account: IMPLICIT_NEAR_ACCOUNT,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      'ed25519-scope-implicit-test-k7p9m2',
    ),
    signerSlot: 0,
  });
  ```

- Replace named-account-only tests in identity-sensitive suites.
- Update shared helper layers first so all downstream tests can opt into
  split-identity fixtures:
  - `tests/helpers/thresholdEcdsaTempoFlow.ts`;
  - `tests/helpers/emailOtpEcdsaTempoFlow.ts`;
  - `tests/helpers/thresholdEcdsaSealedRefreshHarness.ts`;
  - `tests/helpers/thresholdEd25519.testUtils.ts`;
  - `tests/unit/helpers/warmSessionStore.fixtures.ts`;
  - iframe/e2e helpers that currently pass `walletId: accountId`.
- Add source guards for forbidden core patterns:
  - `walletId || nearAccountId`;
  - `record.walletId ?? record.nearAccountId`;
  - `toWalletId(nearAccountId)`;
  - `walletId: nearAccountId`;
  - `walletId: accountId`;
  - `accountId: walletId`;
  - `nearEd25519SigningKeyId || nearAccountId`;
  - `args.walletId || nearAccountId`;
  - `walletSession.walletId || nearAccountId`;
  - `as WalletId` outside parser/builder/typecheck files;
  - `as NearEd25519SigningKeyId` outside parser/builder/typecheck files;
  - command parameter types with optional `walletId`, `nearAccountId`, or
    `nearEd25519SigningKeyId` in core paths;
  - direct object-literal construction of capability bindings outside builders,
    parsers, and typecheck fixtures;
  - React account-menu wallet actions that read only `loginState.nearAccountId`.
- Keep named-account tests for sponsored named flows, but every capability suite
  must include at least one `walletId !== nearAccountId` case.

## Existing Signing-Lane Integration

- Preserve the existing shared `WalletKeyRecord`, `SigningLaneReference`, and
  signing-lane intent model.
- Map wallet capability bindings to those records only at persistence, custody,
  warm-session, or lane-selection boundaries.
- Use Refactor 79's canonical exact-lane identity for ECDSA signing/export
  commands.
- Add type fixtures proving `NearEd25519SignerBinding` cannot be passed where an
  exact ECDSA lane is required, and an exact ECDSA lane cannot be passed where a
  NEAR Ed25519 signer is required.

## Direct Callchain Targets

Initial files expected to change:

```text
packages/shared-ts/src/utils/walletCapabilityBindings.ts
packages/shared-ts/src/utils/walletCapabilityBindings.typecheck.ts
packages/shared-ts/src/utils/registrationIntent.ts
packages/shared-ts/src/utils/registrationIntent.typecheck.ts
packages/shared-ts/src/signing-lanes/records.ts
packages/shared-ts/src/signing-lanes/intents.ts
packages/sdk-web/src/core/types/seams.ts
packages/sdk-web/src/react/types.ts
packages/sdk-web/src/react/context/useLoginStateRefresher.ts
packages/sdk-web/src/react/context/useWalletIframeLifecycle.ts
packages/sdk-web/src/react/context/useSeamsContextValue.ts
packages/sdk-web/src/react/components/AccountMenuButton/index.tsx
packages/sdk-web/src/react/components/AccountMenuButton/RecoveryCodesModal.tsx
packages/sdk-web/src/react/components/AccountMenuButton/RecoveryCodesModalState.ts
packages/sdk-web/src/react/components/AccountMenuButton/LinkedDevicesModal.tsx
packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519HssExport.ts
packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts
packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts
packages/sdk-web/src/SeamsWeb/operations/auth/login.ts
packages/sdk-web/src/SeamsWeb/SeamsWeb.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Provisioner.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory.ts
packages/sdk-web/src/SeamsWeb/publicApi/types.ts
packages/sdk-web/src/SeamsWeb/publicApi/auth.ts
packages/sdk-web/src/SeamsWeb/walletIframe/coordinator.ts
packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts
packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts
packages/sdk-web/src/core/types/sdkSentEvents.ts
packages/sdk-web/src/core/types/sdkPublicResults.ts
packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts
packages/sdk-web/src/core/signingEngine/session/lanes/laneRecords.ts
packages/sdk-web/src/core/signingEngine/session/lanes/laneReference.ts
packages/sdk-web/src/core/signingEngine/session/lanes/laneWarmSessionBinding.ts
packages/sdk-web/src/core/signingEngine/session/persistence/records.ts
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
packages/sdk-web/src/core/signingEngine/session/warmCapabilities/public.ts
packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts
packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts
packages/sdk-server-ts/src/core/AuthService.ts
packages/sdk-server-ts/src/core/WalletAuthMethodStore.ts
packages/sdk-server-ts/src/core/WalletStore.ts
packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts
packages/sdk-server-ts/src/core/EmailOtpStores.ts
packages/sdk-server-ts/src/router/relayWalletRegistration.ts
packages/sdk-server-ts/src/router/walletUnlockRouteHandlers.ts
packages/sdk-server-ts/src/router/commonRouterUtils.ts
packages/sdk-server-ts/src/core/ThresholdService/validation.ts
packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore.ts
packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts
packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts
```

## Acceptance Criteria

- A wallet can be logged in with `walletId` present and `nearAccountId` absent.
- A wallet can be logged in with `walletId !== nearAccountId`.
- Wallet identity carries `walletId`; passkey/WebAuthn flows validate `rpId`
  through `PasskeyAuthScope` or passkey credential/session records.
- Email OTP auth-method records and Email OTP auth bindings do not require or
  carry `rpId`. Refactor 79 owns the ECDSA lane/key namespace migration away
  from `rpId`.
- Recovery-code status, display, and rotation use `walletId`.
- ECDSA export and signing lane selection use `walletId`, never
  `nearAccountId`.
- NEAR access-key and explorer actions require a NEAR account binding.
- NEAR Ed25519 export and signing require a NEAR Ed25519 signer binding.
- Warm Ed25519 session persistence stores `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId` from the resolved signer binding.
- Passkey login warmup can restore and mint Ed25519 and ECDSA sessions for an
  implicit wallet where all three identities differ by role.
- Email OTP login, enrollment, Ed25519 warmup, and ECDSA companion-session paths
  use wallet bindings and split-identity fixtures. ECDSA authority reads use
  Refactor 79 exact-lane identity.
- Budget status, available lane listing, and UI-confirm sealed restore metadata
  use capability bindings.
- Public results and events define whether `walletId`, `nearAccountId`, or
  compatibility `accountId` is being emitted.
- No core code contains identity fallbacks from NEAR account ID to wallet ID or
  NEAR Ed25519 signing key ID.
- Static fixtures reject raw-string and partial-object command inputs for
  identity-sensitive operations.

## Validation Plan

Run targeted type and unit checks first:

```sh
pnpm -C packages/shared-ts exec tsc -p tsconfig.json --noEmit
pnpm -C packages/sdk-web exec tsc -p tsconfig.json --noEmit
pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
pnpm -C tests test:unit --grep "capability|walletId|implicit|export|recovery|warm|email otp|budget|availability|event"
```

Then run broader suites after the identity-sensitive paths pass:

```sh
pnpm -s type-check
pnpm -C tests test:unit
```

## Done Definition

- Capability binding types exist and are used by core identity-sensitive paths.
- React login state exposes `walletId` independently from `nearAccountId` and
  represents passkey and Email OTP as additive auth-method capabilities.
- React `currentAuthMethod` is a discriminated union whose selected branch
  carries a `WalletAuthMethodBinding`.
- Wallet-scoped commands cannot be called with only a NEAR account ID.
- NEAR-scoped commands cannot run without a NEAR account binding.
- Ed25519 HSS/session/export commands cannot run without an Ed25519 signer
  binding.
- ECDSA command paths use wallet and lane bindings.
- Existing compatibility logic is isolated to request and persistence parsers.
- Tests include split implicit fixtures for every wallet, NEAR, Ed25519, ECDSA,
  recovery, and account-menu path touched by this refactor.

## Review: Completion Pass, 2026-06-25

Status: implemented and audited in the Refactor 78/79 sequence.

- [x] Wallet identity is modeled as durable `walletId`, not as a NEAR account
  alias.
- [x] NEAR account and NEAR Ed25519 signer capabilities carry
  `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId` without recomputing one
  identity from another.
- [x] React login state, public APIs, iframe messages, registration, recovery,
  sync, warm sessions, and account-menu actions carry wallet identity
  explicitly.
- [x] Email OTP paths remain wallet-scoped and do not require or carry passkey
  `rpId`.
- [x] ECDSA paths use wallet identity plus Refactor 79 exact lane/key identity.
- [x] Recovery-code status/rotation and ECDSA export/signing use `walletId`
  rather than `nearAccountId`.
- [x] Source guards and type fixtures reject the known wallet/account collapse
  patterns in identity-sensitive code.
- [x] Split implicit fixtures cover `walletId !== nearAccountId` behavior across
  the touched suites.
