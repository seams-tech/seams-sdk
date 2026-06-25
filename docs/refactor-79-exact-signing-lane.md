# Refactor 79: Exact Signing Lane Identity

Date created: June 22, 2026

Status: planned

Related plans:

- [refactor-74-login-no-hss.md](./refactor-74-login-no-hss.md)
- [refactor-76-branded-keys.md](./refactor-76-branded-keys.md)
- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-78-wallet-capability-bindings.md](./refactor-78-wallet-capability-bindings.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)

## Goal

Make authority-bearing signing, export, restore, and budget flows operate on
exact signing-lane identity.

The target state is:

- core signing/session code receives exact lane identity;
- persistence writes enforce uniqueness for authority-bearing records;
- broad discovery remains display-only or repair-only;
- duplicate authority records fail closed at persistence/request boundaries;
- source guards reject first-candidate selection patterns in core paths.

Ambiguity should mean one of two things:

1. malformed or duplicate persisted state that needs repair;
2. a caller asked with insufficient identity.

Neither case should be resolved by ranking, timestamps, or picking the first
candidate during signing.

## Problem

Several recent regressions came from broad selection surfaces:

- stale records could be selected after a rollback or replacement path;
- records with the same broad identity could differ by `signingGrantId`,
  `thresholdSessionId`, chain target, auth binding, or material binding;
- `updatedAtMs` and first-candidate fallback made authority selection depend on
  incidental ordering;
- diagnostics and display helpers looked similar to signing admission helpers.

Refactor 74 Phase 9 introduced explicit fail-closed states such as
`ambiguous`, `ambiguous_candidates`, and `durable_restore_ambiguous_worker_material`.
Those states are safer than loose fallback. This refactor removes the need for
those states in core paths by making exact identity mandatory earlier.

## Design Principle

Boundary parsers and persistence lookup APIs may detect duplicate records. Core
signing, export, restore, and budget functions should accept exact identity and
return either the exact record or a typed failure.

The canonical implementation point is the existing identity module:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts
```

This refactor hardens that module and removes parallel exact-lane terminology.
Do not add another public `ExactSigningLaneIdentity` module.

Exact lane identity must separate auth principal identity from key identity.
`rpId` is passkey/WebAuthn auth scope, not wallet identity and not an ECDSA key
namespace. Email OTP lanes use Email OTP holder identity. ECDSA key identity
uses the wallet key namespace, key facts, signing root, and public identity.

Target shape:

```ts
type SigningLaneAuthBinding =
  | {
      kind: 'passkey';
      rpId: RpId;
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      providerSubjectId: string;
      rpId?: never;
      credentialIdB64u?: never;
    };

type EvmFamilyEcdsaKeyIdentity = {
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  keyScope: EvmFamilyKeyScope;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
  rpId?: never;
};

type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

type ExactEd25519SigningLaneIdentity = {
  kind: 'exact_ed25519_signing_lane_identity';
  curve: 'ed25519';
  chainFamily: 'near';
  walletId: WalletId;
  nearAccountId: NamedNearAccountId | ImplicitNearAccountId;
  ed25519KeyScopeId: Ed25519KeyScopeId;
  auth: SigningLaneAuthBinding;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

type ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity';
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: WalletId;
  auth: SigningLaneAuthBinding;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
};
```

`authMethod` is derived from `auth.kind` for display, analytics, and compatibility
payloads. Authority keys use `auth`. `EvmFamilyEcdsaKeyFingerprint` is a
diagnostic summary field. Authority reads use the full ECDSA key identity plus
`keyHandle`.

Boundary lookup result:

```ts
type ExactRecordLookup<TRecord> =
  | { kind: 'found'; record: TRecord }
  | { kind: 'not_found'; identity: ExactSigningLaneIdentity }
  | {
      kind: 'duplicate_records';
      identity: ExactSigningLaneIdentity;
      candidateSummaries: readonly DuplicateRecordSummary[];
    };
```

Core signing paths should switch on `found | not_found | duplicate_records`.
`duplicate_records` is a data-integrity failure. It should not flow into a
second selector.

## Terminology To Keep

Use one public vocabulary for lane identity:

| Term | Meaning | Authority-bearing |
| --- | --- | --- |
| `WalletId` | Durable wallet/profile id from `@shared/utils/domainIds` | yes |
| `WalletKeyId` | Durable wallet key id from `@shared/signing-lanes` | yes for ECDSA key identity |
| `nearAccountId` | Protocol NEAR account id, named or implicit | yes for Ed25519 |
| `SigningLaneAuthBinding` | Branch-specific holder principal for passkey or Email OTP | yes |
| `SelectedLane` | User/session selected lane without planning fields | yes only after exact identity is built |
| `ExactSigningLaneIdentity` | Canonical signing/export/restore/budget identity | yes |
| `NearTransactionSigningLane` / `EcdsaTransactionSigningLane` | Operation-ready lane with storage/source/readiness metadata | yes |
| `SigningLaneReference` | Durable wallet-key/lane-share reference from `@shared/signing-lanes` | yes for lane-share storage |
| `EcdsaSessionIdentity` | `signingGrantId` plus `thresholdSessionId` only | no |

Cleanup rules:

- `ExactSigningLaneIdentity` is the only public exact-lane authority type.
- `SelectedSigningLaneIdentity`, `ResolvedSigningSessionIdentity`, and
  `EcdsaSessionIdentity` may remain as private projections only when the name
  includes the narrower scope.
- `walletId` fields use `WalletId`. `nearAccountId` fields use the NEAR account
  id brands from Refactor 78.
- ECDSA public facts fingerprints are summaries. They cannot replace full key
  identity in authority reads.
- `authMethod` is a derived label. It must not be the only auth identity in an
  authority key.
- `rpId` appears only in passkey/WebAuthn auth bindings. ECDSA key identity
  uses `WalletKeyId` and signing-root facts.
- ECDSA-HSS cryptographic context uses an opaque SDK-provided binding digest
  plus HSS protocol parameters. SDK-specific wallet, wallet-key,
  signing-root, chain-target, auth, and display facts stay outside the HSS
  crate.
- Ed25519-HSS cryptographic context uses an opaque SDK-provided binding digest
  plus HSS protocol parameters. SDK-specific key-scope, signing-root, wallet,
  and final NEAR account facts stay outside the HSS crate.
- `SigningLaneReference` stays separate from threshold-session identity. It
  identifies wallet-key/lane-share custody state.

## Scope

In scope:

- Ed25519 and ECDSA signing-session record lookup;
- NEAR tx, NEP-413, delegate signing;
- EVM-family / Tempo signing;
- key export lane selection;
- signing-session budget admission;
- passkey and Email OTP material restore;
- UiConfirm session transport selection where it controls signing material;
- guards for first-candidate and timestamp authority selection.

Out of scope:

- network/RPC ambiguity, such as nonce backend network routing;
- UI display sorting where no authority decision is made;
- migration of old production records beyond request/persistence boundary
  parsers;
- optional product UX for repairing duplicate persisted records.

## Inventory

Initial grep terms:

```bash
rg -n "ambiguous|ambiguous_candidates|duplicate_records|exact_match|display_only_fallback|selectBest|selectCanonical|candidates\\[0\\]|\\[0\\] \\|\\| null|get.*ByThresholdSessionId" packages/sdk-web/src tests/unit
rg -n "updatedAtMs|newest|mostRecent|best.*Candidate|priority" packages/sdk-web/src/core/signingEngine packages/sdk-web/src/SeamsWeb
rg -n "getStoredThreshold.*ByThresholdSessionId|getThreshold.*ByThresholdSessionId" packages/sdk-web/src tests/unit
```

High-priority files:

```text
packages/sdk-web/src/core/signingEngine/session/persistence/records.ts
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts
packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts
packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts
packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts
packages/sdk-web/src/core/signingEngine/session/operationState/types.ts
packages/sdk-web/src/core/signingEngine/session/operationState/lanes.ts
packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts
packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts
packages/sdk-web/src/core/signingEngine/session/public.ts
packages/sdk-web/src/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner.ts
packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts
packages/shared-ts/src/utils/domainIds.ts
packages/shared-ts/src/signing-lanes/records.ts
crates/ecdsa-hss/src/shared/context.rs
crates/signer-core/src/commands/ecdsa_bootstrap.rs
crates/signer-core/src/commands/ecdsa_export.rs
crates/signer-core/src/threshold_ecdsa_hss/command.rs
wasm/eth_signer/src/ecdsa_hss.rs
wasm/hss_client_signer/src/threshold_hss.rs
wasm/threshold_prf/src/lib.rs
```

Important tests:

```text
tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts
tests/unit/walletScopedLookups.guard.unit.test.ts
tests/unit/refactor79ExactSigningLane.guard.unit.test.ts
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts
tests/unit/evmFamilyEcdsaIdentity.unit.test.ts
tests/unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts
tests/unit/ecdsaRoleLocalRecords.unit.test.ts
tests/unit/ecdsaSelection.restorable.unit.test.ts
tests/unit/exportLaneSelection.unit.test.ts
tests/unit/nearSigning.sessionSelection.unit.test.ts
tests/unit/signingSessionFreshness.unit.test.ts
tests/unit/warmSessionEd25519Persistence.unit.test.ts
tests/unit/routerAbEd25519.walletSessionState.unit.test.ts
tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts
tests/unit/unlockEcdsaWarmupPlanner.unit.test.ts
tests/unit/walletIframeHost.signTempoCancel.unit.test.ts
```

## Phase 0: Add Guards Before Behavior Changes

Add a new guard test file or extend
`tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts`.

Guard categories:

- no first-candidate selection in authority-bearing files:
  - `candidates[0]`
  - `[0] || null`
  - `records[0]`
  - `.at(0)` inside signing/export/budget selectors unless the helper name
    includes `selectOnly`;
- no timestamp-based authority selection in signing/export/budget flows:
  - `mostRecent`
  - `newest`
  - `selectNewest`
  - `updatedAtMs` ranking;
- no broad threshold-session lookup in core signing flows:
  - `getStoredThresholdEcdsaSessionRecordByThresholdSessionId(`
  - `getThresholdEcdsaSessionRecordByThresholdSessionId(`
  - allowed only in boundary adapters or tests proving duplicate rejection;
- no `ambiguous` branch in core signing inputs after later phases complete.
- no duplicate public exact-lane authority type names:
  - `ExactEcdsaLaneIdentity`;
  - `ExactEcdsaRuntimeLaneRef`;
  - new `ExactSigningLaneIdentity` exports outside the canonical module;
- no `walletId: AccountId` in signing-lane identity or planning types after
  Refactor 78 wallet id brands are available.
- no ECDSA key identity authority path reads or writes `key.rpId`;
- no Email OTP ECDSA login, enrollment, publication, restore, or export path
  calls `requireRpId(...)`;
- `rpId` in ECDSA files is allowed only in passkey auth bindings, WebAuthn
  boundary parsing, or named ECDSA key-identity migration parsers.
- no ECDSA-HSS cryptographic context or derivation input accepts
  `wallet_id`, `wallet_key_id`, `ecdsa_threshold_key_id`, `signing_root_id`,
  `signing_root_version`, `rp_id`, `key_purpose`, or `key_version`;
- no signer-core generated ECDSA-HSS bootstrap/export context exposes
  `walletId`, `walletKeyId`, `ecdsaThresholdKeyId`, `signingRootId`,
  `signingRootVersion`, `keyPurpose`, or `keyVersion`.

Initial guard should classify existing allowed hits:

- display-only UI selection;
- account-scoped discovery/repair;
- request/persistence boundary parsing;
- tests that intentionally assert duplicate rejection.

Required guard updates:

- flip the existing `refactor74LegacyFallbacks` assertions that currently expect
  newest-candidate helpers;
- include `signEvmFamily/ecdsaSelection.ts` in the authority-selector scan;
- extend `walletScopedLookups.guard.unit.test.ts` so exact-lane and planning
  structs use `WalletId` for `walletId`;
- extend source guards so exact ECDSA key identity builders reject `rpId` and
  require `walletKeyId`;
- add an allowlist comment for each remaining broad lookup that names the
  boundary role: display, repair, request parsing, or persistence parsing.

## Phase 1: Reconcile Existing Exact Lane Identity Types

Use the existing module as the canonical public surface:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts
```

Tasks:

- update `ExactEd25519SigningLaneIdentity` to carry `walletId`,
  `nearAccountId`, and `ed25519KeyScopeId`;
- update `ExactEcdsaSigningLaneIdentity` to use `WalletId`, require
  `keyHandle`, and keep full `EvmFamilyEcdsaKeyIdentity`;
- update `EvmFamilyEcdsaKeyIdentity` so it carries `walletKeyId` and rejects
  `rpId`;
- add `SigningLaneAuthBinding` and replace exact-lane `authMethod` authority
  fields with branch-specific `auth`;
- keep `authMethod` only as a derived display or compatibility field at
  boundaries;
- remove public `ExactEcdsaLaneIdentity` and `ExactEcdsaRuntimeLaneRef` exports
  from `session/persistence/records.ts` after consumers use the canonical type;
- reconcile `SelectedEcdsaLane`, `EcdsaSigningSessionPlanningLane`,
  `ResolvedEcdsaSigningSessionIdentity`, and `EcdsaWalletSigningSpendPlan` so
  `walletId` uses `WalletId`;
- reconcile Ed25519 planning/spend types so `walletId` and `nearAccountId` are
  separate fields after Refactor 78 lands;
- keep `EcdsaSessionIdentity` as the session pair projection only;
- keep `SigningLaneReference` as the wallet-key/lane-share custody reference;
- make `exactSigningLaneIdentityKey(...)` the only canonical authority key
  builder.

Builder rules:

- exact identity builders require every authority field;
- builders accept only branded or already-normalized boundary values;
- boundary parsers normalize raw strings once;
- broad object spreads cannot construct exact identity objects;
- core functions accept exact identity types or transaction lanes that can build
  the same exact identity.
- passkey auth bindings require `rpId` and `credentialIdB64u`;
- Email OTP auth bindings require `providerSubjectId` and reject `rpId`;
- ECDSA key identity builders require `walletKeyId` and reject `rpId`.
- ECDSA-HSS context builders accept `applicationBindingDigest` only for SDK
  identity binding. They reject wallet, wallet-key, threshold-key, signing-root,
  chain-target, auth, purpose, and version fields.

Type fixtures:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts
```

Fixtures should reject:

- missing `signingGrantId`;
- missing `thresholdSessionId`;
- missing Ed25519 `walletId`;
- missing Ed25519 `nearAccountId`;
- missing Ed25519 `ed25519KeyScopeId`;
- exact identity with `authMethod` as the only auth field;
- passkey auth binding without `rpId`;
- Email OTP auth binding with `rpId`;
- ECDSA identity without `chainTarget`;
- ECDSA identity without full `key`;
- ECDSA identity without `keyHandle`;
- ECDSA key identity without `walletKeyId`;
- ECDSA key identity with `rpId`;
- Ed25519 identity with ECDSA fields;
- `walletId: AccountId` in ECDSA identity fixtures;
- generic `string` cast into branded IDs outside a boundary builder.

## Phase 2: Make Persistence Reads Exact

Replace broad authority reads with exact reads:

```ts
readExactThresholdEd25519SessionRecord(identity: ExactEd25519SigningLaneIdentity): ExactRecordLookup<ThresholdEd25519SessionRecord>
readExactThresholdEcdsaSessionRecord(identity: ExactEcdsaSigningLaneIdentity): ExactRecordLookup<ThresholdEcdsaSessionRecord>
```

Use the `SigningCapabilityReaderDeps` exact lookup shape as the ECDSA starting
point: `walletId`, `chainTarget`, `keyHandle`, `thresholdSessionId`, and
`signingGrantId`. Extend it to carry full exact lane identity and typed duplicate
results.

The lookup must:

- use canonical lane key identity;
- return `duplicate_records` if more than one lane identity matches a broad
  index during compatibility parsing;
- return `not_found` for absent records;
- never select by `updatedAtMs`;
- never choose the first record from an indexed set.
- reject ECDSA record matches where `keyHandle` matches but full key identity
  facts differ;
- reject Ed25519 records where `walletId`, `nearAccountId`, or
  `ed25519KeyScopeId` differ.

Existing broad reads become boundary-only:

```text
getStoredThresholdEd25519SessionRecordByThresholdSessionId
getStoredThresholdEcdsaSessionRecordByThresholdSessionId
getThresholdEcdsaSessionRecordByThresholdSessionId
getStoredThresholdEd25519SessionRecordForAccount
getStoredThresholdEcdsaSessionRecordForWalletChain
```

Target action:

- move broad reads behind explicit names such as
  `readDisplayOrRepairRecordByThresholdSessionId`;
- update signing/export/budget flows to use exact reads;
- add guards that block broad reads in exact signing files.
- replace Ed25519 consume-by-account with consume-by-exact-lane and expected
  record version;
- keep account-current records for display/default wallet state only;
- update `EvmFamilyEcdsaSessionReaderDeps` so signing paths use exact record
  lookup, while list/broad readers sit behind display/repair names.

Tests:

- duplicate Ed25519 records with same threshold session and different grant fail
  with `duplicate_records`;
- duplicate ECDSA records with same threshold session and different lane keys
  fail with `duplicate_records`;
- exact lane identity selects the intended record when duplicates exist in
  unrelated lanes;
- target-specific ECDSA lookup requires `chainTarget`.
- ECDSA lookup fails when key handle matches but full key identity differs;
- Ed25519 consume fails when account-current points at another exact lane.

## Phase 3: Enforce Write-Time Uniqueness

Strengthen `upsert*` paths so authority records cannot accumulate silently.

Ed25519:

- canonical lane key includes `walletId`, `nearAccountId`,
  `ed25519KeyScopeId`, auth binding, signing grant, threshold session, and
  curve;
- material-bearing records include material binding digest in the durable
  restore identity when available;
- writing a new current lane for the same wallet/auth binding/curve/signing
  grant must replace the old current lane explicitly;
- writing two records for the same exact lane with conflicting material facts
  must throw or return a typed boundary failure.

ECDSA:

- canonical lane key includes wallet, auth binding, signing grant, threshold
  session, chain target, key handle, full key identity, and curve;
- shared EVM-family key identity checks stay active and compare `walletKeyId`,
  signing root, participants, threshold key id, and owner address;
- target-specific writes delete replaced current passkey lanes through one
  named replacement helper;
- Email OTP session-lifetime lanes may coexist only when their exact identities
  differ and the caller uses exact identity for reads.
- persistence parsers use `parseWalletId` for `walletId`;
- NEAR account validators are used only for `nearAccountId` fields.

Tests:

- replacement deletes the previous current lane and index entry;
- conflicting duplicate write fails before insertion;
- exact read after replacement returns only the new lane;
- exact read after duplicate fixture returns `duplicate_records`.
- implicit wallet id fixture writes Ed25519 and ECDSA records without projecting
  `walletId` through `toAccountId`;
- sponsored named wallet fixture still stores matching `walletId` and
  `nearAccountId` where the provisioning mode requires it.

## Phase 3a: Replace ECDSA RP Key Namespace

Current ECDSA key identity uses `rpId` as part of the key namespace. That makes
Email OTP-only and future-auth wallets depend on a passkey/WebAuthn concept.

Target:

- add `walletKeyId` to `EvmFamilyEcdsaKeyIdentity`, `EvmFamilyEcdsaWalletKey`,
  SDK session bootstrap records, and exact-lane/public-facts identity;
- remove `rpId` from ECDSA key identity, ECDSA key comparisons, exact ECDSA lane
  canonicalization, and ECDSA key fingerprints;
- keep `rpId` only in `PasskeyEcdsaAuthBinding` and passkey/WebAuthn transport
  boundaries;
- keep `walletKeyId` outside ECDSA-HSS derivation. It identifies the SDK wallet
  key lane; `ecdsaThresholdKeyId` is an SDK key fact that feeds the SDK
  ECDSA-HSS application-binding digest;
- update Email OTP ECDSA login, enrollment, publication, restore, and companion
  session flows so they resolve `walletKeyId` from bootstrap/key records instead
  of calling `requireRpId(...)`;
- compatibility parsers may read old persisted ECDSA key records with `rpId`,
  then normalize immediately to a `walletKeyId`-backed key identity or fail with
  a typed migration error;
- do not synthesize `walletKeyId` from `rpId`; derive it from `WalletKeyRecord`,
  signing-root metadata, or a named migration parser with tests and deletion
  notes.

Tests:

- Email OTP-only ECDSA enrollment, login, publication, restore, and export work
  without `rpId`;
- passkey ECDSA signing still validates `rpId` through passkey auth binding;
- exact ECDSA lane identity rejects `key.rpId`;
- two ECDSA records with the same `walletId` and different `walletKeyId` are
  distinct exact identities;
- compatibility parser rejects old ECDSA records when `walletKeyId` cannot be
  recovered.

## Phase 3b: Slim ECDSA-HSS Cryptographic Context

Current ECDSA-HSS stable context carries values that belong to SDK product
identity or single-value protocol constants:

```rust
pub struct EcdsaHssStableKeyContext {
    pub wallet_id: String,
    pub wallet_key_id: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
}
```

That makes the HSS crate understand Seams product identity. `wallet_id`,
`wallet_key_id`, `ecdsa_threshold_key_id`, `signing_root_id`, and
`signing_root_version` are SDK-level binding facts. `rp_id` is passkey/WebAuthn
auth scope, `key_purpose` is currently a caller-provided spelling of the fixed
EVM-family purpose, and `key_version` is currently the single protocol enum
value `v1`.

Target ECDSA-HSS crate context:

```rust
pub struct EcdsaHssStableKeyContext {
    pub application_binding_digest: [u8; 32],
}
```

The SDK builds `application_binding_digest` from the SDK facts it wants to bind:

```ts
type SdkEcdsaHssBindingFacts = {
  walletId: WalletId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
};
```

The digest builder uses a versioned, domain-separated, length-delimited
encoding. The HSS crate receives only the digest and does not know how the SDK
chose to compose it.

Keep these as code constants/domain parameters:

```rust
pub const ECDSA_HSS_CONTEXT_VERSION: &str = "v4";
pub const ECDSA_HSS_SCHEME_ID: &str = "ecdsa-hss-v4";
pub const ECDSA_HSS_CURVE: &str = "secp256k1";
pub const ECDSA_HSS_PARTICIPANT_IDS: [u16; 2] = [1, 2];
```

Rules:

- remove `wallet_id`, `wallet_key_id`, `ecdsa_threshold_key_id`,
  `signing_root_id`, `signing_root_version`, `rp_id`, `key_purpose`, and
  `key_version` from `crates/ecdsa-hss` derivation inputs, context encoding,
  tests, docs, and fixtures;
- remove the same fields from signer-core and WASM HSS command contexts when
  they only feed `EcdsaHssStableKeyContext`;
- introduce one SDK-owned digest builder for ECDSA-HSS binding facts. It
  currently binds `walletId`, `ecdsaThresholdKeyId`, `signingRootId`, and
  `signingRootVersion`. Future SDK facts must be added to that builder rather
  than to the HSS crate context;
- include EVM-family scope, chain namespace, or key-purpose labels in the SDK
  digest builder if the SDK needs to distinguish this material from another
  secp256k1 HSS use. Do not add app scope fields to the HSS crate context;
- make `applicationBindingDigest` the only SDK-controlled selector inside
  ECDSA-HSS derivation;
- bump the ECDSA-HSS context domain/scheme and pending/ready state blob magic
  or envelope version so old dev blobs fail clearly;
- update `wasm/threshold_prf` ECDSA-HSS derivation input so it no longer
  accepts SDK wallet, signing-root, chain, passkey RP, or purpose/version
  labels;
- keep `walletKeyId` in SDK exact lane identity, wallet-key records, public
  facts, export authorization, and persistence where it identifies the product
  wallet key lane;
- keep `walletId`, `ecdsaThresholdKeyId`, `signingRootId`, and
  `signingRootVersion` in SDK exact lane identity, public facts, admission, and
  digest-builder inputs where they define SDK authority;
- keep `rpId` only in passkey auth bindings and WebAuthn secret-source
  boundaries;
- do not include `walletKeyId` in the SDK digest unless the product intends a
  wallet-key lane alias change to create different HSS material. The current
  model keeps `walletKeyId` as SDK lane authority outside HSS derivation.

Tests:

- SDK ECDSA-HSS binding digest changes when `walletId`,
  `ecdsaThresholdKeyId`, `signingRootId`, or `signingRootVersion` changes;
- SDK ECDSA-HSS binding digest does not change when only `walletKeyId` changes
  under the current lane-alias model;
- ECDSA-HSS context binding changes when `applicationBindingDigest` changes;
- source guards reject `wallet_id`, `wallet_key_id`, `ecdsa_threshold_key_id`,
  `signing_root_id`, `signing_root_version`, `rp_id`, `key_purpose`, and
  `key_version` in `crates/ecdsa-hss` derivation context files;
- signer-core generated TS command types no longer expose `keyPurpose`,
  `keyVersion`, `walletId`, `walletKeyId`, `ecdsaThresholdKeyId`,
  `signingRootId`, or `signingRootVersion` inside HSS command contexts;
- passkey and Email OTP ECDSA bootstrap still produce matching client/relayer
  HSS context bindings after regeneration;
- export authorization validates `walletKeyId` against public facts at the SDK
  or server boundary, before signer-core/HSS export commands run.

## Phase 3c: Delete ECDSA-HSS Boundary and Planning Duplication

Phase 3b defines the slim cryptographic context. This phase removes the
surrounding request, adapter, generated, and planning shapes that can keep the
old broad context alive.

Generated and WASM boundary cleanup:

- regenerate `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`
  after the Rust signer-core command structs change;
- rebuild `wasm/threshold_prf/pkg/*` so generated JS and `.d.ts` exports match
  the slim `threshold_prf_derive_ecdsa_hss_y_relayer(...)` signature;
- update `packages/sdk-web/src/core/platform/ports.ts` and
  `packages/sdk-web/src/core/platform/signerCoreCommandAdapters.ts` so ECDSA-HSS
  bootstrap inputs carry `applicationBindingDigest` instead of SDK wallet,
  signing-root, chain, passkey RP, or purpose/version facts;
- update `packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts`,
  `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`,
  and `packages/shared-ts/src/utils/routerAbEcdsaHss.ts` so Router A/B ECDSA-HSS
  scope context is converted to the SDK binding digest before calling HSS;
- remove stale generated or fixture references to `wallet_id`, `wallet_key_id`,
  `ecdsa_threshold_key_id`, `signing_root_id`, `signing_root_version`, `rp_id`,
  `key_purpose`, and `key_version` in ECDSA-HSS derivation context files.

Command-shape cleanup:

- remove `chainTarget` from signer-core ECDSA-HSS bootstrap context when it is
  only validated and discarded before `EcdsaHssStableKeyContext` construction;
- remove `chainTarget` from signer-core ECDSA-HSS export public facts if it is
  only validated and discarded by the cryptographic export path;
- keep chain target in SDK exact lane identity, export selection identity, and
  operation planning where it controls EVM-family routing. Include a chain or
  key-scope label in the SDK digest builder only when it should change HSS
  material;
- move passkey/Email OTP export authorization validation out of signer-core HSS
  export commands. Signer-core export receives state blob, slim public facts,
  application binding digest, public keys, and server export share;
- keep `walletKeyId` checks in SDK/server export admission where wallet-key
  authority is available.

Planning and authority-field cleanup:

- remove stored `authMethod` from `SelectedLane`, lane candidates, and signing
  planning lanes. Use `signingLaneAuthMethod(auth)` for display, analytics, and
  compatibility payloads only;
- replace optional core identity/session fields on planning lanes with
  branch-specific lifecycle states, so selected lanes always require exact
  threshold-session identity;
- shrink `WalletSigningSpendPlan` so it carries operation id, optional operation
  fingerprint, lane, uses, reason, and backing-material ids. Derive `walletId`,
  `signingGrantId`, and threshold-session ids from the exact lane;
- delete legacy `ecdsaKey` stripping in spend-plan normalization after callers
  compile against the current shape;
- collapse ECDSA exact-record filtering to one canonical exact identity
  comparison path. Broad candidate summaries may remain diagnostics only.

Tests and guards:

- source guards fail when generated signer-core or WASM ECDSA-HSS bindings expose
  removed SDK context fields;
- Router A/B ECDSA-HSS fixtures use the same context byte framing as
  the SDK ECDSA-HSS application-binding digest builder;
- signer-core export tests prove passkey/Email OTP authorization branches are
  absent from cryptographic export commands;
- tests prove the SDK digest builder is the only place SDK identity facts are
  assembled for ECDSA-HSS;
- type fixtures reject direct `authMethod` authority construction in selected
  lanes, candidates, planning lanes, and spend plans;
- spend-plan tests prove duplicated wallet/session fields cannot be supplied and
  cannot diverge from the exact lane.

ECDSA-HSS digest-boundary inventory:

```bash
rg -n "EcdsaHss|ecdsa_hss|threshold_ecdsa_hss|EcdsaClientBootstrap|walletKeyId|ecdsaThresholdKeyId|routerAbEcdsaHss" crates/ecdsa-hss crates/signer-core wasm packages/sdk-server-ts/src/core/ThresholdService packages/sdk-web/src/core packages/shared-ts/src tests/unit
rg -n "wallet_id|wallet_key_id|ecdsa_threshold_key_id|signing_root_id|signing_root_version|key_purpose|key_version|applicationBindingDigest|application_binding_digest" crates/ecdsa-hss crates/signer-core/src/commands/ecdsa* crates/signer-core/src/threshold_ecdsa_hss wasm/eth_signer wasm/threshold_prf packages/sdk-server-ts/src/core/ThresholdService packages/sdk-web/src/core/platform packages/sdk-web/src/core/signingEngine packages/shared-ts/src/utils/routerAbEcdsaHss.ts tests/unit
```

Primary files:

```text
crates/ecdsa-hss/src/shared/context.rs
crates/ecdsa-hss/src/shared/derive.rs
crates/ecdsa-hss/specs/protocol.md
crates/ecdsa-hss/specs/export.md
crates/ecdsa-hss/security.md
crates/ecdsa-hss/fixtures/role_local_v2.json
crates/ecdsa-hss/tests/role_local_mvp.rs
crates/ecdsa-hss/formal-verification/lean-boundary/*
crates/ecdsa-hss/formal-verification/lean-boundary/generated/*
crates/ecdsa-hss/formal-verification/lean-boundary/rust-boundary/src/lib.rs
crates/signer-core/src/commands/ecdsa_bootstrap.rs
crates/signer-core/src/commands/ecdsa_export.rs
crates/signer-core/src/threshold_ecdsa_hss/command.rs
crates/signer-core/tests/export_typescript_schemas.rs
wasm/eth_signer/src/ecdsa_hss.rs
wasm/threshold_prf/src/lib.rs
packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts
packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm.ts
packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts
packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts
packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts
packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore.ts
packages/sdk-server-ts/src/core/ThresholdService/postgresRecords.ts
packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts
packages/sdk-web/src/core/platform/ports.ts
packages/sdk-web/src/core/platform/signerCoreCommandAdapters.ts
packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts
packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts
packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts
packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/*
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts
packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts
packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts
packages/sdk-web/src/core/signingEngine/threshold/ecdsa/keygen.ts
packages/shared-ts/src/utils/routerAbEcdsaHss.ts
packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts
```

Likely stale fixture tests:

```text
tests/unit/thresholdEcdsa.hssWasmSurface.unit.test.ts
tests/unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts
tests/unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts
tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts
tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts
tests/unit/routerAbEcdsaHssPresignBridge.unit.test.ts
tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts
tests/unit/ecdsaExportMaterial.unit.test.ts
tests/unit/ecdsaMaterialState.unit.test.ts
tests/unit/warmSessionEcdsaProvisioning.unit.test.ts
tests/unit/refactor79ExactSigningLane.guard.unit.test.ts
```

## Phase 3d: Slim Ed25519-HSS Cryptographic Context

Current Ed25519-HSS derivation accepts values that are either fixed protocol
labels or final NEAR account identity:

```rust
pub struct Ed25519HssCanonicalContextV1 {
    pub org_id: String,
    pub account_id: String,
    pub key_purpose: String,
    pub key_version: String,
    pub participant_ids: Vec<u16>,
    pub derivation_version: u32,
}
```

That shape keeps the old NEAR-account-as-wallet-id model alive. It also lets
callers provide `key_purpose` and `key_version` even though current flows use
single fixed values. For implicit accounts, deriving HSS material from final
`nearAccountId` is the wrong boundary: the final account id is derived from the
Ed25519 public key, while HSS registration needs a stable key scope before that
final account id exists.

Target Ed25519-HSS crate context:

```rust
pub struct Ed25519HssStableKeyContext {
    pub application_binding_digest: [u8; 32],
    pub participant_ids: Vec<u16>,
}
```

The SDK builds `application_binding_digest` from the SDK facts it wants to bind:

```ts
type SdkEd25519HssBindingFacts = {
  ed25519KeyScopeId: Ed25519KeyScopeId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
};
```

The digest builder uses a domain-separated, length-delimited encoding. The HSS
crate receives only the digest and does not know how the SDK chose to compose
it.

Seams SDK keeps the raw binding facts only where they are real SDK authority or
account-binding data. Any SDK type whose only purpose is to call Ed25519-HSS
must pass `applicationBindingDigest` rather than raw SDK identity fields.

Keep these as code constants/domain parameters:

```rust
pub const ED25519_HSS_CONTEXT_VERSION: &str = "v2";
pub const ED25519_HSS_SCHEME_ID: &str = "ed25519-hss-v2";
pub const ED25519_HSS_CURVE: &str = "ed25519";
```

Rules:

- remove `key_purpose`, `keyPurpose`, `key_version`, and `keyVersion` from
  Ed25519-HSS derivation inputs, context encoding, command bodies, generated
  bindings, tests, docs, and fixtures;
- remove `account_id`, `accountId`, and `nearAccountId` from Ed25519-HSS
  derivation inputs and context encoding;
- remove `ed25519_key_scope_id`, `ed25519KeyScopeId`, `signing_root_id`,
  `signingRootId`, `signing_root_version`, and `signingRootVersion` from the
  Ed25519-HSS crate context and generated HSS command shapes;
- introduce one SDK-owned digest builder for Ed25519-HSS binding facts. It
  currently binds `ed25519KeyScopeId`, `signingRootId`, and
  `signingRootVersion`. Future SDK facts must be added to that builder rather
  than to the HSS crate context;
- remove `nearAccountId`, `accountId`, `keyPurpose`, `keyVersion`,
  `ed25519KeyScopeId`, `signingRootId`, and `signingRootVersion` from Seams SDK
  request/result/worker/port types when those fields exist only to construct an
  Ed25519-HSS context;
- keep raw SDK binding facts in exact lane identity, wallet/account binding
  records, registration-session state, audit data, and digest-builder inputs
  where those facts still define SDK authority;
- make the SDK digest builder the single conversion point from raw SDK facts to
  Ed25519-HSS input. Core flows should pass an `Ed25519HssApplicationBindingDigest`
  branded value across signer-core, WASM, worker, and server boundaries;
- include NEAR scope in the SDK digest builder if the SDK needs to distinguish
  NEAR Ed25519 material from another Ed25519 use. Do not add a chain/scope field
  to the HSS crate context;
- use `applicationBindingDigest` as the only SDK-controlled selector inside
  Ed25519-HSS derivation. Do not replace `nearAccountId` with `walletId`; exact
  lane identity already carries `walletId`, and the SDK digest carries the
  desired app-level key binding;
- keep `nearAccountId` in `ExactEd25519SigningLaneIdentity`, NEAR transaction
  signer validation, access-key/nonce readiness, wallet-account binding records,
  public wallet/account surfaces, and audit logs where it represents the final
  protocol account;
- keep `walletId` outside the Ed25519-HSS cryptographic context unless a
  concrete collision case proves the SDK binding facts are insufficient. The
  preferred fix for such a collision is to strengthen the SDK digest builder
  instead of adding a second wallet alias to HSS;
- keep `participant_ids` in the HSS context because the participant set changes
  the threshold shares and binding;
- bump the Ed25519-HSS context domain/scheme and any pending/ready state blob
  magic or envelope version so old dev blobs fail clearly;
- delete old compatibility parsers, stale fixtures, and tests that encode
  `account_id`, `nearAccountId`, `keyPurpose`, or `keyVersion` as Ed25519-HSS
  derivation fields. If an external boundary still sends the old shape, update
  that boundary in the same phase or reject it with a typed request error.

Cleanup task list:

1. Add a single SDK digest type and builder.

   - define `Ed25519HssApplicationBindingDigest` as a branded 32-byte digest or
     base64url digest at the SDK boundary;
   - define `SdkEd25519HssBindingFacts` in one shared SDK module;
   - build the digest with a versioned, domain-separated, length-delimited
     encoding;
   - make all client/server SDK flows call this builder before crossing into
     signer-core, WASM, workers, or threshold PRF;
   - add test vectors for the digest encoding.

2. Replace crate/WASM HSS context shapes.

   - replace `Ed25519HssCanonicalContextV1` with the slim digest context;
   - remove key-purpose, key-version, account-id, key-scope, signing-root, and
     chain/scope field validation from HSS context parsing;
   - remove echo fields such as `keyPurpose` and `keyVersion` from HSS client
     and server outputs;
   - regenerate signer-core command schemas and WASM bindings;
   - update Rust/WASM tests so changed digest or participant set changes the HSS
     binding.

3. Clean Seams SDK HSS-facing request, result, port, and worker types.

   - replace raw HSS context facts with `applicationBindingDigest`;
   - remove raw context facts from Router A/B Ed25519-HSS prepare/respond/finalize
     request bodies when the fields exist only to feed HSS;
   - update web worker messages, near-signer messages, hss-client worker messages,
     `SigningSurface` ports, and generated signer-core adapters;
   - remove public or iframe API fields that only proxy old HSS context facts;
   - reject old request bodies that still include `keyPurpose`, `keyVersion`, or
     final account id as HSS context fields.

4. Classify remaining raw SDK identity fields.

   - keep `nearAccountId` where it represents the final NEAR account in exact
     lane identity, NEAR transaction signer checks, readiness, export display,
     wallet/account binding records, and audit logs;
   - keep `ed25519KeyScopeId`, `signingRootId`, and `signingRootVersion` where
     they are SDK authority facts or digest-builder input;
   - remove or rename `keyVersion` in Ed25519 worker material records. If it
     means HSS protocol version, delete it. If it means sealed-material or
     session-seal metadata, rename it to the precise material/seal version type;
   - keep `materialFormatVersion`, `sessionSealKeyVersion`, and similar storage
     metadata only when they are unrelated to HSS derivation.

5. Update persistence, registration, recovery, and warm-session call chains.

   - registration and add-signer should persist raw SDK authority facts and store
     HSS material created from the digest;
   - email OTP and passkey recovery should reconstruct the digest from persisted
     SDK facts before calling HSS;
   - warm-session hydration should persist exact lane identity separately from
     HSS digest input;
   - delete fixtures and helpers that still synthesize HSS `keyPurpose`,
     `keyVersion`, or final account id.

6. Add guards.

   - source guards fail when HSS crate files or generated HSS command types
     expose removed raw fields;
   - SDK guards fail when HSS-facing request/result/worker/port types expose raw
     SDK facts instead of `applicationBindingDigest`;
   - targeted type fixtures reject direct construction of old Ed25519-HSS
     request bodies.

Rough inventory and search plan:

Primary grep commands:

```bash
rg -n "Ed25519Hss|ed25519_hss|threshold_ed25519_hss|deriveThresholdEd25519Hss|prepareThresholdEd25519Hss|runThresholdEd25519Hss|ThresholdEd25519Hss|threshold_prf_derive_ed25519_hss|deriveEd25519HssServerInputs|ed25519Hss" crates/signer-core wasm packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests
rg -n "keyPurpose|key_purpose|keyVersion|key_version" crates/signer-core/src/near_ed25519_recovery.rs crates/signer-core/src/commands/ed25519_worker_material.rs wasm/threshold_prf wasm/hss_client_signer packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests
rg -n "applicationBindingDigest|application_binding_digest|nearAccountId|account_id|accountId|ed25519KeyScopeId|signingRootId|signing_root_id|signingRootVersion|signing_root_version" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests
```

Rust/signer-core and WASM HSS context:

```text
crates/signer-core/src/near_ed25519_recovery.rs
crates/signer-core/src/commands/ed25519_worker_material.rs
crates/signer-core/src/commands/mod.rs
crates/signer-core/tests/export_typescript_schemas.rs
wasm/threshold_prf/src/lib.rs
wasm/threshold_prf/pkg/*
wasm/hss_client_signer/src/client_inputs.rs
wasm/hss_client_signer/src/threshold_hss.rs
wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs
wasm/near_signer/src/threshold/threshold_hss.rs
wasm/near_signer/src/threshold/worker_material.rs
wasm/near_signer/src/types/worker_messages.rs
```

Server request, ceremony, and threshold-service surfaces:

```text
packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts
packages/sdk-server-ts/src/core/ThresholdService/ed25519HssWasm.ts
packages/sdk-server-ts/src/core/ThresholdService/signingRootShareResolver.ts
packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts
packages/sdk-server-ts/src/core/ThresholdService/schemes/thresholdServiceSchemes.types.ts
packages/sdk-server-ts/src/core/ThresholdService/validation.ts
packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts
packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts
packages/sdk-server-ts/src/core/AuthService.ts
packages/sdk-server-ts/src/router/relayWalletRegistration.ts
packages/sdk-server-ts/src/router/relay.ts
packages/sdk-server-ts/src/router/routeDefinitions.ts
packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts
packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts
```

Shared request/digest utilities:

```text
packages/shared-ts/src/threshold/index.ts
packages/shared-ts/src/threshold/participants.ts
packages/shared-ts/src/threshold/signingRootScope.ts
packages/shared-ts/src/utils/registrationIntent.ts
packages/shared-ts/src/utils/signingSessionSeal.ts
packages/shared-ts/src/utils/registrationIntent.typecheck.ts
```

Web SDK platform, worker, and generated boundaries:

```text
packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts
packages/sdk-web/src/core/platform/ports.ts
packages/sdk-web/src/core/platform/signerCoreCommandAdapters.ts
packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/clientOutputMask.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssClientBase.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/public.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialBinding.ts
packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts
packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts
packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts
packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts
packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts
packages/sdk-web/src/core/signingEngine/workerManager/nearKeyOps/createNearKeyOps.ts
packages/sdk-web/src/core/types/signer-worker.ts
```

Web SDK registration, recovery, signing, and persistence call chains:

```text
packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts
packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts
packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts
packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts
packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519HssExport.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts
packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts
packages/sdk-web/src/core/signingEngine/session/persistence/records.ts
packages/sdk-web/src/core/accountData/near/keyMaterial.ts
```

Tests and fixtures most likely to encode the old shape:

```text
tests/unit/*ed25519*hss*
tests/unit/*registration*
tests/unit/*warmSessionEd25519*
tests/unit/addWalletSigner.orchestration.unit.test.ts
tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts
tests/unit/registrationCeremonyStore.unit.test.ts
tests/unit/registrationIntentDigest.unit.test.ts
tests/unit/relayWalletRegistration.boundary.unit.test.ts
tests/unit/relayWalletRegistration.intentModes.unit.test.ts
tests/unit/signingRootShareResolver.script.unit.test.ts
tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts
tests/unit/thresholdEd25519.nearSignerWasm.unit.test.ts
tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts
tests/unit/thresholdEd25519.signingRootResolver.script.unit.test.ts
tests/unit/thresholdPrfWasm.script.unit.test.ts
tests/unit/warmSessionEd25519Persistence.unit.test.ts
tests/helpers/emailOtpEcdsaTempoFlow.ts
tests/helpers/thresholdEd25519TestUtils.ts
```

Tests and guards:

- SDK Ed25519-HSS binding digest changes when `ed25519KeyScopeId`,
  `signingRootId`, or `signingRootVersion` changes;
- Ed25519-HSS context binding changes when `applicationBindingDigest` or
  `participantIds` changes;
- generated implicit-account fixtures prove `walletId !== nearAccountId` and
  HSS derivation never receives `nearAccountId`;
- passkey and Email OTP Ed25519 registration/add-signer/recovery produce
  matching client/server HSS context bindings with only the slim fields;
- source guards reject `account_id`, `accountId`, `nearAccountId`,
  `ed25519_key_scope_id`, `ed25519KeyScopeId`, `signing_root_id`,
  `signingRootId`, `signing_root_version`, `signingRootVersion`,
  `key_purpose`, `keyPurpose`, `key_version`, and `keyVersion` inside
  Ed25519-HSS crate derivation-context files and generated HSS command types;
- tests reject constructing Ed25519-HSS request bodies with final account id or
  caller-provided purpose/version fields;
- tests prove the SDK digest builder is the only place SDK identity facts are
  assembled for Ed25519-HSS;
- source guards reject Seams SDK HSS-facing types that expose raw SDK binding
  facts instead of `applicationBindingDigest`;
- old fixtures that only exist to support the removed context shape are deleted.

## Phase 4: Remove Best-Candidate Selection From Transaction Signing

Current risk files:

```text
packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts
```

Target shape:

```ts
type TransactionLaneSelection =
  | { kind: 'selected_exact_lane'; identity: ExactSigningLaneIdentity; lane: TransactionLane }
  | { kind: 'needs_step_up'; reason: StepUpReason }
  | { kind: 'no_authorized_lane'; reason: NoLaneReason }
  | { kind: 'duplicate_authority_records'; details: DuplicateRecordSummary[] };
```

Selection rules:

- signing flow starts from current authenticated session identity or an exact
  lane identity derived from the selected operation;
- if multiple runtime lanes exist, the wallet/session layer resolves them before
  the signing flow starts;
- core transaction signing does not rank candidates by readiness, source, or
  timestamp;
- restore availability updates the exact lane, then retries the same exact
  identity.
- EVM-family signing receives an exact lane identity before
  `resolveEvmFamilyEcdsaSigningSelection(...)`;
- `selectPasskeyMaterialForCandidate(...)` can use visible passkey materials for
  diagnostics and repair only;
- `listPasskeyVisibleMaterials(...)` cannot provide authority material for a
  different exact lane;
- shared EVM-family source-material lookup does not rank by timestamp; obsolete
  broad helpers are deleted, and live shared-material authority paths return
  duplicate failure when more than one source-chain material record matches.

Tests:

- NEAR signing with duplicate candidate lanes returns duplicate authority error;
- restore retry preserves exact signing grant and threshold session;
- EVM/Tempo signing does not choose a newer record when exact identity points at
  a different valid lane;
- sponsored Tempo actions that do not require signing skip budget/lane admission.
- EVM passkey signing fails closed when exact material is missing and visible
  passkey material exists for another lane;
- shared EVM-family material requires exact source material lane plus target
  chain operation identity;
- prepared EVM material binding rejects mismatched `laneIdentityKey`.

## Phase 5: Remove Best-Candidate Selection From Export

Current risk file:

```text
packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts
```

Target shape:

- export requests include exact lane identity or exact export key identity;
- display inventory may group candidates for user choice;
- authority export flow accepts a single exact lane;
- duplicate exact lanes return `duplicate_records`.
- iframe/UI export selection sends the exact identity payload that the user chose;
- export worker inputs carry exact identity and reject display inventory groups;
- ECDSA export uses full key identity plus source material lane for shared
  EVM-family keys.

Remove or demote:

- `selectCanonicalLaneFromSelectionGroup`;
- state/source priority ranking for authority export;
- timestamp tie-breakers.

Keep display helpers under explicit names:

```ts
selectDisplayExportLaneGroup(...)
sortDisplayExportLaneCandidates(...)
```

Tests:

- duplicate export candidates require explicit identity;
- exact export lane selects even when display inventory has other lanes;
- ambiguous display inventory cannot call the export worker.
- exact ECDSA export for shared family material binds the export key identity to
  the source material lane.

## Phase 6: Remove Broad Restore Selection

Current risk files:

```text
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
```

Target shape:

```ts
type MaterialRestoreIdentity =
  | {
      kind: 'ed25519_worker_material_restore';
      lane: ExactEd25519SigningLaneIdentity;
      materialBindingDigest: Ed25519MaterialBindingDigest;
      materialKeyId: Ed25519MaterialKeyId;
    }
  | {
      kind: 'ecdsa_role_local_restore';
      lane: ExactEcdsaSigningLaneIdentity;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    };
```

Rules:

- restore uses the exact identity from unlock or step-up;
- account-scoped material discovery may only prepare display/repair evidence;
- `mostRecent*` restore helper names are removed from signing/restore paths;
- duplicate restore material returns `duplicate_records`;
- restore retry keeps the original exact identity.
- sealed-session filters include `signingGrantId`, `thresholdSessionId`,
  auth binding, curve, and ECDSA `chainTarget`;
- sealed-session read and lease APIs return typed duplicate results;
- `readRecordByThresholdSessionId(...)` cannot select the last matching record in
  authority paths;
- restore coordinator runs one exact restore work item per exact identity.

Tests:

- material-pending restore succeeds with exact identity;
- duplicate sealed material fails before worker call;
- no restore path uses latest/newest account-scoped record;
- Email OTP restore receives only opaque unseal authorization and exact lane
  identity.
- sealed restore lease fails closed when two sealed records match the exact
  identity;
- restore coordinator rejects duplicate exact-purpose work items.

## Phase 7: Budget Admission Uses Exact Identity

Current risk file:

```text
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.ts
packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.ts
```

Target shape:

```ts
type BudgetAdmissionInput = {
  lane: ExactSigningLaneIdentity;
  trustedBudgetStatus: TrustedSigningBudgetStatus;
};
```

Rules:

- caller-provided authenticated budget status is authoritative;
- if caller auth is rejected, do not retry with record-derived auth;
- record-derived auth is allowed only for unauthenticated status checks;
- budget status parser remains the only compatibility point for
  `remainingUses` / `availableUses` fallback;
- admission uses `availableUsesForBudgetAdmission`.
- reservation identity derives `thresholdSessionIds` from
  `ExactSigningLaneIdentity`;
- `WalletSigningSpendPlan.thresholdSessionIds` is removed from admission input or
  renamed to `backingMaterialSessionIds` when that is the intended meaning;
- `resolveWalletSigningBudgetStatusAuth(...)` cannot independently rediscover
  signing auth by broad threshold-session lookup;
- budget freshness and reservation keys use the same `laneIdentityKey`.

Tests:

- malformed active budget status fails closed;
- rejected auth status does not retry through persisted records;
- duplicate record lookup blocks budget admission;
- display policy hints cannot influence admission.
- caller-provided threshold-session list cannot alter the exact lane reservation;
- budget admission for implicit NEAR wallets uses `walletId` for wallet budget
  owner and `nearAccountId` only for NEAR signing.

## Phase 8: UiConfirm And Wallet Iframe Boundaries

Current risk file:

```text
packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache.ts
packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/export.ts
packages/sdk-web/src/SeamsWeb/walletIframe/host/runtime-export.ts
```

Target:

- wallet iframe and UiConfirm payloads parse into exact transport identity once;
- if payload lacks exact identity, return typed boundary error;
- display-only fallback may show diagnostics and repair prompts;
- signing material selection does not read broad records by threshold session.
- payloads that touch signing material include `walletId`, auth binding, curve,
  signing grant id, threshold session id, and branch-specific fields;
- Ed25519 payloads include `nearAccountId` and `ed25519KeyScopeId`;
- ECDSA payloads include `chainTarget`, `keyHandle`, and full key identity or a
  boundary-parsed key identity reference;
- Email OTP app-session JWT cache remains wallet-scoped only if the JWT is
  wallet-session auth; document that invariant in the cache type and tests;
- exact refresh identity rejection clears only the wallet-scoped cached JWT for
  that wallet.

Tests:

- iframe payload missing chain target for ECDSA is rejected;
- payload with threshold session only cannot select signing material;
- duplicate persisted records produce typed duplicate error;
- diagnostics label broad records as display-only.
- Ed25519 UiConfirm payload with `walletId !== nearAccountId` succeeds when both
  values match the exact identity;
- Email OTP JWT cache reuse cannot change the exact lane identity used for
  signing/export.

## Phase 9: Rename Errors And Delete Core `ambiguous` Branches

After exact identity is wired through core flows, rename authority errors:

```text
ambiguous_candidates -> duplicate_authority_records
durable_restore_ambiguous_worker_material -> duplicate_worker_material_records
ambiguous_shared_key_targets -> duplicate_shared_key_targets
ambiguous_key_handle -> duplicate_key_handles
```

Rules:

- `ambiguous` may remain in display inventory or external network routing;
- signing/export/restore/budget core unions use duplicate-specific names;
- every duplicate error carries safe candidate summaries;
- summaries include public identity only, never secret material or JWTs.
- public exact-lane type names outside `exactSigningLaneIdentity.ts` are deleted
  or renamed to private serialization helpers;
- helper names that include `exact` must require exact authority identity.

Tests:

- source guard rejects `kind: 'ambiguous'` in core signing files;
- existing tests are updated to duplicate-specific names;
- user-facing error messages describe duplicate session state and suggest
  refresh/repair, without exposing sensitive fields.
- guard tests reject new `Exact*LaneIdentity` exports outside the canonical
  module.

## Phase 10: Final Cleanup And Validation

Delete or rename:

- `selectBest*` authority helpers;
- `selectCanonical*` authority helpers;
- `mostRecent*` restore helpers in signing paths;
- broad `getByThresholdSessionId` imports from signing/export/budget paths;
- first-candidate fallback tests that encode old behavior.
- public `ExactEcdsaLaneIdentity` and `ExactEcdsaRuntimeLaneRef` exports after
  canonical identity wiring;
- `walletId: AccountId` from exact-lane, planning-lane, budget-spend, and warm
  capability identity structs;
- `toAccountId(args.walletId)` from wallet-scoped authority paths.

Keep:

- display-only sorting helpers;
- repair/discovery helpers with explicit names;
- boundary parser compatibility tests.

Validation matrix:

```text
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line unit/refactor74LegacyFallbacks.guard.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/walletScopedLookups.guard.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/refactor79ExactSigningLane.guard.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/evmFamilyEcdsaIdentity.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/ecdsaRoleLocalRecords.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/ecdsaSelection.restorable.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/exportLaneSelection.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/nearSigning.sessionSelection.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/signingSessionFreshness.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/warmSessionEd25519Persistence.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/routerAbEd25519.walletSessionState.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/emailOtpWalletSessionCoordinator.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/unlockEcdsaWarmupPlanner.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/thresholdEcdsa.hssWasmSurface.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts
cargo test -p ecdsa-hss
cargo test -p signer-core threshold_ecdsa_hss
git diff --check
```

Browser evidence after implementation:

- passkey registration;
- wallet unlock;
- first NEAR transaction after unlock, with no extra Touch ID prompt;
- first NEAR transaction for implicit account with `walletId !== nearAccountId`;
- NEAR lazy restore from cold worker material;
- NEP-413 signing;
- delegate signing;
- Tempo signed transaction;
- EVM signed transaction;
- sponsored Tempo action that does not consume budget;
- budget exhaustion and step-up after server-authoritative remaining uses.
- EVM passkey signing with exact material missing and another visible passkey
  lane present;
- Email OTP signing/export after JWT refresh rejection.

## Done Criteria

- Core signing/export/restore/budget functions accept exact lane identity.
- `ExactSigningLaneIdentity` is the only public exact-lane authority type.
- Exact Ed25519 identity separates `walletId`, `nearAccountId`, and
  `ed25519KeyScopeId`.
- Exact ECDSA identity uses `WalletId`, `keyHandle`, `WalletKeyId`, and full key
  identity without `rpId`.
- ECDSA-HSS stable context contains only `application_binding_digest`; SDK
  wallet, threshold-key, signing-root, chain-target, auth, caller-provided key
  purpose, and caller-provided key version facts are absent from HSS crate
  derivation inputs.
- Ed25519-HSS stable context contains only `application_binding_digest` and
  `participant_ids`; SDK key-scope/signing-root facts, final NEAR account ids,
  caller-provided key purpose, and caller-provided key version are absent from
  HSS crate derivation inputs.
- Persistence writes enforce uniqueness or return typed duplicate errors.
- Broad threshold-session reads are absent from authority-bearing paths.
- Candidate ranking and timestamp tie-breakers are absent from authority-bearing
  paths.
- Display-only and repair-only broad discovery helpers are explicitly named.
- Source guards block first-candidate fallback and broad authority reads.
- Unit tests prove duplicate records fail closed.
- Unit tests prove implicit `walletId !== nearAccountId` signing identity works.
- Browser evidence shows normal unlock/signing paths still work.

## Review: Auditor Pass, 2026-06-25

Status: auditor findings addressed in code and validation is green.
The HSS crate context cleanup is aligned: ECDSA-HSS is digest-only, and
Ed25519-HSS is digest plus participant ids. The SDK/server boundary modeling
and exact-lane propagation gaps from this pass have been closed.

Inventory reviewed from `git diff` covered the Refactor 79 implementation
surface across signer-core, near-signer WASM, server threshold service, SDK web
public/iframe APIs, signing engine recovery/signing/session code, UiConfirm,
guards, and focused tests.

Findings to fix before completion:

- [x] P0: `pnpm -C packages/sdk-web -s type-check` fails. Some migrated code expects
  `{ lane: ExactEcdsaSigningLaneIdentity }`, while callers still pass partial
  `{ walletId, chainTarget, thresholdSessionId }` shapes. Finish the exact-lane
  type migration end to end before claiming validation.
  - Verified green after finishing the exact-lane wiring.
- [x] P1: public and iframe key export payloads type `laneIdentity` as an exact
  identity, then forward raw postMessage/API input directly. Add boundary
  parsers that rebuild exact Ed25519/ECDSA lane identities with the canonical
  builders and reject malformed or cross-wallet payloads before core export.
  - Added runtime parsers for exact Ed25519/ECDSA identities and wired them
    through direct public export plus iframe router/host boundaries.
- [x] P1: Ed25519 registration HSS request/scope code still models wallet key scope
  as `rpId`. Rename this registration/account-scope field to `walletKeyId` or
  remove it if `ed25519KeyScopeId + signingRoot` is the real selector. Keep
  `rpId` inside passkey/WebAuthn auth branches only.
  - Renamed registration scope identity to `walletKeyId`, derive it from
    `ed25519KeyScopeId`, and reject the stale scope `rpId` field.
- [x] P2: warm ECDSA reconnect/provisioning still uses partial threshold-session
  lookup shapes and has a `recordCandidates[0]` fallback. Replace these with
  exact-lane capability/readiness lookups and duplicate-specific failures.
  - Reconnect and bootstrap readiness now use exact ECDSA lanes, and the
    first-candidate fallback is removed.
- [x] P2: budget consume fallback drops exact ECDSA identity by converting a lane
  budget check into broad wallet/signingGrant/thresholdSession status query.
  Carry `ExactSigningLaneIdentity` through the fallback or remove the fallback
  from authority-sensitive budget consume paths.
  - Budget fallback carries the original exact ECDSA budget lane through status
    reads.
- [x] P2: export shared-key source errors still use `ambiguous_source` and
  `ambiguous_candidates`. Rename these to duplicate-specific names such as
  `duplicate_shared_key_targets`.
- [x] P3: `refactor79ExactSigningLane.guard.unit.test.ts` scans too small a file
  set for first-candidate and broad authority patterns. Expand it to cover
  warm capability/provisioning, public/iframe export boundaries, UiConfirm, and
  all authority-bearing signing/export/restore/budget files.
  - Expanded guard inventory and added export-boundary plus Ed25519 HSS
    wallet-key guard checks.
- [x] Phase 4: transaction signing no longer ranks runtime/auth-method
  candidates by source, readiness, or timestamp. NEAR signing selects one exact
  runtime lane or fails closed on duplicate exact authority records.
- [x] Phase 5: key export execution requires a parsed exact lane identity at
  public/core/iframe boundaries; broad inventory remains display-only.
- [x] Phase 6: restore/discovery paths no longer pick newest account-scoped
  material. Exact restore work returns duplicate-specific failures before
  worker restore.
- [x] Phase 7: budget consume/status fallback preserves the original exact lane
  identity and no longer downgrades ECDSA to wallet/session-only status input.
- [x] Phase 8: UiConfirm and iframe export payloads parse exact Ed25519/ECDSA
  lane identities at the boundary before invoking authority paths.
- [x] Phase 9: core signing/export/restore/budget unions and tests use
  duplicate-specific names; stale `ambiguous` authority branches are removed.
- [x] Phase 10: first-candidate/timestamp selectors, `walletId: AccountId`, and
  wallet-id-to-NEAR-account projections are guarded in authority files. Stale
  fixtures were updated to the digest-only HSS and split wallet/account model.

Follow-up validation after fixes:

- [x] `pnpm -C packages/sdk-web -s type-check`
- [x] `pnpm -C packages/sdk-server-ts -s type-check`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/refactor74LegacyFallbacks.guard.unit.test.ts unit/walletScopedLookups.guard.unit.test.ts unit/refactor79ExactSigningLane.guard.unit.test.ts unit/evmFamilyEcdsaIdentity.unit.test.ts unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts unit/ecdsaRoleLocalRecords.unit.test.ts unit/ecdsaSelection.restorable.unit.test.ts unit/exportLaneSelection.unit.test.ts unit/nearSigning.sessionSelection.unit.test.ts unit/signingSessionFreshness.unit.test.ts unit/warmSessionEd25519Persistence.unit.test.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/emailOtpWalletSessionCoordinator.unit.test.ts unit/unlockEcdsaWarmupPlanner.unit.test.ts unit/thresholdEcdsa.hssWasmSurface.unit.test.ts unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts` (211 passed)
- [x] `pnpm -C tests exec playwright test --reporter=line unit/refactor79ExactSigningLane.guard.unit.test.ts`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/exportLaneSelection.unit.test.ts`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/warmSessionStore.reconnect.unit.test.ts`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/walletIframeHost.exportUi.unit.test.ts`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/evmFamilyStepUpProvisionPlan.unit.test.ts`
- [x] `pnpm -C tests exec playwright test --reporter=line unit/thresholdEcdsa.emailOtpBootstrapCommit.unit.test.ts`
- [x] `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
- [x] `cargo test --manifest-path crates/signer-core/Cargo.toml threshold_ecdsa_hss`
- [x] `git diff --check`
