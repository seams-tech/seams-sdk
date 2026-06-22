# Refactor 79: Exact Signing Lane Identity

Date created: June 22, 2026

Status: planned

Related plans:

- [refactor-74-login-no-hss.md](./refactor-74-login-no-hss.md)
- [refactor-76-branded-keys.md](./refactor-76-branded-keys.md)
- [refactor-77-switch-case.md](./refactor-77-switch-case.md)

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
  `thresholdSessionId`, chain target, auth method, or material binding;
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

Preferred shape:

```ts
type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

type ExactEd25519SigningLaneIdentity = {
  kind: 'exact_ed25519_signing_lane';
  walletId: WalletId;
  authMethod: 'passkey' | 'email_otp';
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdSessionId;
  materialBindingDigest?: Ed25519MaterialBindingDigest;
};

type ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane';
  walletId: WalletId;
  authMethod: 'passkey' | 'email_otp';
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdSessionId;
  chainTarget: ThresholdEcdsaChainTarget;
  evmFamilyKeyFingerprint?: EvmFamilyEcdsaKeyFingerprint;
};
```

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
packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts
packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts
packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts
packages/sdk-web/src/core/signingEngine/session/public.ts
packages/sdk-web/src/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner.ts
```

Important tests:

```text
tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts
tests/unit/ecdsaRoleLocalRecords.unit.test.ts
tests/unit/exportLaneSelection.unit.test.ts
tests/unit/nearSigning.sessionSelection.unit.test.ts
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

Initial guard should classify existing allowed hits:

- display-only UI selection;
- account-scoped discovery/repair;
- request/persistence boundary parsing;
- tests that intentionally assert duplicate rejection.

## Phase 1: Introduce Exact Lane Identity Types

Add co-located type-only domain module:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.types.ts
```

Types:

- `ExactSigningLaneIdentity`;
- `ExactEd25519SigningLaneIdentity`;
- `ExactEcdsaSigningLaneIdentity`;
- branch-specific builders:
  - `exactEd25519SigningLaneIdentity(...)`;
  - `exactEcdsaSigningLaneIdentity(...)`.

Use branded types from Refactor 76 where available:

- `SigningGrantId`;
- `ThresholdSessionId`;
- `WalletId` / `AccountId`;
- `Ed25519MaterialBindingDigest`;
- `EvmFamilyEcdsaKeyFingerprint`.

Rules:

- exact identity builders require every authority field;
- no broad object spread into identity objects;
- boundary parsers normalize raw strings once;
- core functions accept exact identity types instead of partial bags.

Type fixtures:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts
```

Fixtures should reject:

- missing `signingGrantId`;
- missing `thresholdSessionId`;
- ECDSA identity without `chainTarget`;
- Ed25519 identity with ECDSA fields;
- generic `string` cast into branded IDs outside a boundary builder.

## Phase 2: Make Persistence Reads Exact

Replace broad authority reads with exact reads:

```ts
readExactThresholdEd25519SessionRecord(identity: ExactEd25519SigningLaneIdentity): ExactRecordLookup<ThresholdEd25519SessionRecord>
readExactThresholdEcdsaSessionRecord(identity: ExactEcdsaSigningLaneIdentity): ExactRecordLookup<ThresholdEcdsaSessionRecord>
```

The lookup must:

- use canonical lane key identity;
- return `duplicate_records` if more than one lane identity matches a broad
  index during compatibility parsing;
- return `not_found` for absent records;
- never select by `updatedAtMs`;
- never choose the first record from an indexed set.

Existing broad reads become boundary-only:

```text
getStoredThresholdEd25519SessionRecordByThresholdSessionId
getStoredThresholdEcdsaSessionRecordByThresholdSessionId
getThresholdEcdsaSessionRecordByThresholdSessionId
```

Target action:

- move broad reads behind explicit names such as
  `readDisplayOrRepairRecordByThresholdSessionId`;
- update signing/export/budget flows to use exact reads;
- add guards that block broad reads in exact signing files.

Tests:

- duplicate Ed25519 records with same threshold session and different grant fail
  with `duplicate_records`;
- duplicate ECDSA records with same threshold session and different lane keys
  fail with `duplicate_records`;
- exact lane identity selects the intended record when duplicates exist in
  unrelated lanes;
- target-specific ECDSA lookup requires `chainTarget`.

## Phase 3: Enforce Write-Time Uniqueness

Strengthen `upsert*` paths so authority records cannot accumulate silently.

Ed25519:

- canonical lane key includes wallet/account, auth method, signing grant,
  threshold session, and curve;
- material-bearing records include material binding digest in the durable
  restore identity when available;
- writing a new current lane for the same wallet/auth/curve/signing grant must
  replace the old current lane explicitly;
- writing two records for the same exact lane with conflicting material facts
  must throw or return a typed boundary failure.

ECDSA:

- canonical lane key includes wallet, auth method, signing grant, threshold
  session, chain target, key handle, and curve;
- shared EVM-family key identity checks stay active;
- target-specific writes delete replaced current passkey lanes through one
  named replacement helper;
- Email OTP session-lifetime lanes may coexist only when their exact identities
  differ and the caller uses exact identity for reads.

Tests:

- replacement deletes the previous current lane and index entry;
- conflicting duplicate write fails before insertion;
- exact read after replacement returns only the new lane;
- exact read after duplicate fixture returns `duplicate_records`.

## Phase 4: Remove Best-Candidate Selection From Transaction Signing

Current risk files:

```text
packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
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

Tests:

- NEAR signing with duplicate candidate lanes returns duplicate authority error;
- restore retry preserves exact signing grant and threshold session;
- EVM/Tempo signing does not choose a newer record when exact identity points at
  a different valid lane;
- sponsored Tempo actions that do not require signing skip budget/lane admission.

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

## Phase 6: Remove Broad Restore Selection

Current risk files:

```text
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
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

Tests:

- material-pending restore succeeds with exact identity;
- duplicate sealed material fails before worker call;
- no restore path uses latest/newest account-scoped record;
- Email OTP restore receives only opaque unseal authorization and exact lane
  identity.

## Phase 7: Budget Admission Uses Exact Identity

Current risk file:

```text
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
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

Tests:

- malformed active budget status fails closed;
- rejected auth status does not retry through persisted records;
- duplicate record lookup blocks budget admission;
- display policy hints cannot influence admission.

## Phase 8: UiConfirm And Wallet Iframe Boundaries

Current risk file:

```text
packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts
```

Target:

- wallet iframe and UiConfirm payloads parse into exact transport identity once;
- if payload lacks exact identity, return typed boundary error;
- display-only fallback may show diagnostics and repair prompts;
- signing material selection does not read broad records by threshold session.

Tests:

- iframe payload missing chain target for ECDSA is rejected;
- payload with threshold session only cannot select signing material;
- duplicate persisted records produce typed duplicate error;
- diagnostics label broad records as display-only.

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

Tests:

- source guard rejects `kind: 'ambiguous'` in core signing files;
- existing tests are updated to duplicate-specific names;
- user-facing error messages describe duplicate session state and suggest
  refresh/repair, without exposing sensitive fields.

## Phase 10: Final Cleanup And Validation

Delete or rename:

- `selectBest*` authority helpers;
- `selectCanonical*` authority helpers;
- `mostRecent*` restore helpers in signing paths;
- broad `getByThresholdSessionId` imports from signing/export/budget paths;
- first-candidate fallback tests that encode old behavior.

Keep:

- display-only sorting helpers;
- repair/discovery helpers with explicit names;
- boundary parser compatibility tests.

Validation matrix:

```text
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line unit/refactor74LegacyFallbacks.guard.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/ecdsaRoleLocalRecords.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/exportLaneSelection.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/nearSigning.sessionSelection.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/warmSessionEd25519Persistence.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/routerAbEd25519.walletSessionState.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/emailOtpWalletSessionCoordinator.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/unlockEcdsaWarmupPlanner.unit.test.ts
git diff --check
```

Browser evidence after implementation:

- passkey registration;
- wallet unlock;
- first NEAR transaction after unlock, with no extra Touch ID prompt;
- NEAR lazy restore from cold worker material;
- NEP-413 signing;
- delegate signing;
- Tempo signed transaction;
- EVM signed transaction;
- sponsored Tempo action that does not consume budget;
- budget exhaustion and step-up after server-authoritative remaining uses.

## Done Criteria

- Core signing/export/restore/budget functions accept exact lane identity.
- Persistence writes enforce uniqueness or return typed duplicate errors.
- Broad threshold-session reads are absent from authority-bearing paths.
- Candidate ranking and timestamp tie-breakers are absent from authority-bearing
  paths.
- Display-only and repair-only broad discovery helpers are explicitly named.
- Source guards block first-candidate fallback and broad authority reads.
- Unit tests prove duplicate records fail closed.
- Browser evidence shows normal unlock/signing paths still work.
