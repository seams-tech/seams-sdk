# Refactor 37: Shared EVM-Family ECDSA Identity

Date created: 2026-05-15
Status: draft

## Purpose

Make the EVM-family threshold ECDSA signer identity a first-class internal type.

The recent ECDSA failures were caused by the same logical signer existing as
multiple loosely related shapes:

- HSS bootstrap context
- registration continuation metadata
- login warm-up key ids
- threshold ECDSA session records
- key refs
- available-lane candidates
- prepared signing lanes
- export lanes
- nonce sender state
- demo funding/preflight address state

Tightening `walletId`, `subjectId`, exact session identity, and lifecycle unions
exposed these loose areas. This refactor removes the duplication by splitting
shared EVM-family key identity from concrete target/session lane identity.

## Funds-Safety Invariant

EVM SIGNERS MUST ALL SHARE THE SAME ADDRESS for one wallet, subject, RP,
signing root, and ECDSA key version.

Tempo, Arc, Ethereum, and future EVM-family targets must resolve the same
threshold ECDSA owner address and the same `ecdsaThresholdKeyId`. Concrete
targets still have separate sessions, budgets, nonces, and chain-specific
transaction behavior.

## Target Shape

Introduce one shared key identity:

```ts
type EvmFamilyEcdsaKeyIdentity = {
  walletId: WalletId;
  subjectId: WalletSubjectId;
  rpId: RpId;
  keyScope: 'evm-family';
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
};
```

Concrete signing lanes reference that shared key identity:

```ts
type EvmFamilyEcdsaSessionLane = {
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'passkey' | 'email_otp';
  source: ThresholdEcdsaSessionStoreSource;
  thresholdSessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;

  // Session-specific fields.
  thresholdSessionKind: ThresholdSessionKind;
  thresholdSessionAuthToken: VerifiedThresholdSessionAuth | null;
  remainingUses: number;
  expiresAtMs: number;
};
```

Ready material should be one exact branch:

```ts
type ReadyEvmFamilyEcdsaMaterial = {
  kind: 'ready_evm_family_ecdsa_material';
  key: EvmFamilyEcdsaKeyIdentity;
  lane: EvmFamilyEcdsaSessionLane;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};
```

Record/keyRef mismatch should return a typed failure branch at the boundary:

```ts
type EvmFamilyEcdsaMaterialResolution =
  | { kind: 'ready'; material: ReadyEvmFamilyEcdsaMaterial }
  | { kind: 'record_only'; reason: EvmFamilyEcdsaIdentityMismatch }
  | { kind: 'key_ref_only'; reason: EvmFamilyEcdsaIdentityMismatch }
  | { kind: 'missing'; reason: EvmFamilyEcdsaIdentityMismatch };
```

Core signing, export, HSS bootstrap, and post-exhaustion reauth should consume
the `ready` branch only.

## High-Value Review Additions

1. The shared key identity must carry every stable HSS key-context field that
   affects funds safety. The invariant names RP, so `rpId` belongs in
   `EvmFamilyEcdsaKeyIdentity`. The identity should also name the stable
   `keyScope = "evm-family"` explicitly.
2. `thresholdOwnerAddress` must come from derived or server-verified key
   material. Builders should reject any stored record, key ref, or profile row
   whose owner address disagrees with the derived shared-key address.
3. Email OTP should reuse the same ECDSA identity brands as passkey. Phase 4
   should add Email OTP provider/auth-subject brands only; duplicating
   `EcdsaThresholdKeyId`, `SigningRootId`, session ids, or owner-address brands
   would recreate the parallel-shape problem.
4. Storage cutover needs to be explicit. Old target-scoped ECDSA key rows,
   sealed records, and server rows must be rejected or deleted at the boundary
   during this development refactor. Keeping them as fallback candidates risks
   reintroducing the exact ambiguous-lane and wrong-address failures.
5. Add a stable identity fingerprint for diagnostics and tests. HSS prepare,
   activation, lane resolution, export, budget admission, and nonce diagnostics
   should all be able to print the same `evmFamilyKeyFingerprint` without
   exposing secret material.

## Import Direction Contract

- `interfaces/*` may define primitive identity types and parsers with no session
  store imports.
- `session/identity/*` may build canonical identity and lane types from raw
  records/key refs.
- `session/persistence/*` may normalize raw persistence into canonical identity
  types at the read/write boundary.
- `session/passkey/*` and `session/emailOtp/*` may provision lanes from canonical
  identity and strict activation plans.
- `flows/signEvmFamily/*` may consume ready material and exact lanes. It must
  not infer key identity from partial record/keyRef bags.
- `threshold/ecdsa/*` may consume HSS activation requests built from canonical
  identity. It must not reconstruct EVM-family key identity from optional
  request fields.
- UI/demo code may read addresses from explicit public result fields. It must
  not call bootstrap merely to discover a sender address when wallet-session
  metadata already contains the canonical owner address.

## Phase 0: Baseline Inventory And Guards

- [ ] Inventory every shape that currently carries any of:
  - `ecdsaThresholdKeyId`
  - `signingRootId`
  - `signingRootVersion`
  - `rpId`
  - `keyScope`
  - `participantIds`
  - `thresholdOwnerAddress`
  - `ethereumAddress`
  - `chainTarget`
  - `thresholdSessionId`
  - `walletSigningSessionId`
- [ ] Produce a short table in this plan mapping each current type to either:
  - shared key identity
  - concrete session lane
  - raw persistence/request boundary
  - diagnostics/display only
- [ ] Add a guard that flags new internal EVM-family structs containing
  `ecdsaThresholdKeyId` and `thresholdSessionId` together unless the type is
  an approved lane/material type.
- [ ] Add a guard that flags EVM-family public/demo address reads from
  `counterfactualAddress` in raw EIP-1559 signing paths.
- [ ] Add a guard that fails if Tempo and EVM configured targets can produce
  different threshold owner addresses for one wallet in tests.
- [ ] Add a guard that rejects local construction of
  `EvmFamilyEcdsaKeyIdentity` outside approved builders/type fixtures.
- [ ] Add a fixture that logs one `evmFamilyKeyFingerprint` through HSS
  bootstrap, lane resolution, signing, export, and nonce resolution for the same
  wallet.

## Phase 1: Canonical Identity Types

- [ ] Add `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`.
- [ ] Define role-specific branded primitives used by EVM-family identity:
  - `WalletId`
  - `RpId`
  - `EcdsaThresholdKeyId`
  - `SigningRootId`
  - `SigningRootVersion`
  - `ThresholdEcdsaSessionId`
  - `WalletSigningSessionId`
  - `ThresholdOwnerAddress`
  - `SmartAccountAddress`
  - `CounterfactualAddress`
  - `EvmFamilyKeyScope`
- [ ] Define `EvmFamilyEcdsaKeyIdentity`.
- [ ] Define `EvmFamilyEcdsaSessionLane`.
- [ ] Define `ReadyEvmFamilyEcdsaMaterial`.
- [ ] Define `EvmFamilyEcdsaIdentityMismatch` with explicit branches:
  - `subject_mismatch`
  - `chain_family_mismatch`
  - `key_id_mismatch`
  - `signing_root_mismatch`
  - `participant_ids_mismatch`
  - `owner_address_mismatch`
  - `rp_id_mismatch`
  - `key_scope_mismatch`
  - `session_identity_mismatch`
  - `auth_method_mismatch`
  - `stale_or_unrestorable_material`
- [ ] Add builders:
  - `buildEvmFamilyEcdsaKeyIdentityFromKeyRef(...)`
  - `buildEvmFamilyEcdsaKeyIdentityFromRecord(...)`
  - `buildEvmFamilyEcdsaSessionLane(...)`
  - `resolveReadyEvmFamilyEcdsaMaterial(...)`
- [ ] Add `deriveEvmFamilyKeyFingerprint(...)` over stable public identity
  fields:
  - `walletId`
  - `subjectId`
  - `rpId`
  - `keyScope`
  - `ecdsaThresholdKeyId`
  - `signingRootId`
  - `signingRootVersion`
  - `participantIds`
  - `thresholdOwnerAddress`
- [ ] Ensure owner-address builders verify the address from trusted key material
  or a server-verified key ref before accepting persisted/profile/demo address
  data.
- [ ] Make `resolveReadyEvmFamilyEcdsaMaterial(...)` return a result union:
  - `ready`
  - `record_only`
  - `key_ref_only`
  - `missing`
  - `identity_mismatch`
  - `stale`
- [ ] Use `never` fields for invalid branch combinations in mismatch/result
  unions.
- [ ] Add type fixtures proving:
  - a key identity cannot carry session ids
  - a session lane must carry a key identity
  - ready material requires both record and keyRef
  - Tempo/EVM concrete targets cannot carry different key ids under one shared
    key identity
  - `ThresholdOwnerAddress` cannot be passed as `SmartAccountAddress`
  - `SmartAccountAddress` cannot be passed as a raw EIP-1559 sender
  - a key identity cannot omit `rpId`
  - a key identity cannot use a target-specific `keyScope`

## Phase 2: Persistence And Read Model Normalization

- [ ] Update `client/src/core/signingEngine/session/persistence/records.ts` so
  ECDSA record reads normalize into the shared key identity plus concrete lane.
- [ ] Keep raw legacy/persistence compatibility only inside persistence
  boundary parsers.
- [ ] Update `getThresholdEcdsaSessionRecordByKey(...)` and
  `getThresholdEcdsaKeyRefByKey(...)` callers to use the shared identity
  builders before control reaches operation flows.
- [ ] Update available-lane read models in
  `client/src/core/signingEngine/session/availability/*` so EVM-family lanes
  expose:
  - shared key identity
  - concrete `chainTarget`
  - concrete session identity
- [ ] Remove duplicate key identity fields from internal candidate shapes where
  a `key: EvmFamilyEcdsaKeyIdentity` reference can be passed.
- [ ] Add a persistence negative fixture for records that claim the same
  `ecdsaThresholdKeyId` but a different owner address across EVM-family targets.
- [ ] Add persistence fixtures proving restored passkey and Email OTP sealed
  ECDSA records preserve `ThresholdOwnerAddress`.
- [ ] Reject current-format sealed ECDSA records that are missing owner address,
  key id, signing root, or concrete lane identity at the persistence boundary.
- [ ] Add a storage cutover version for EVM-family ECDSA records. Any stored
  record from the target-scoped-key era should be deleted or rejected before it
  can become an available-lane candidate.
- [ ] Add client-store and server-store uniqueness checks for one shared
  EVM-family key identity per:
  - `walletId`
  - `subjectId`
  - `rpId`
  - `keyScope`
  - `signingRootId`
  - `signingRootVersion`
- [ ] Reject or delete rows where two configured EVM-family targets for the same
  shared identity point at different `ecdsaThresholdKeyId` or
  `thresholdOwnerAddress` values.

## Phase 3: HSS Bootstrap Boundary

- [ ] Update `client/src/core/signingEngine/threshold/ecdsa/activation.ts` so
  activation requests carry:
  - `key: EvmFamilyEcdsaKeyIdentity`
  - `lanePolicy: EvmFamilyEcdsaSessionLanePolicy`
- [ ] Update `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
  so HSS context is built from shared key identity plus concrete session policy.
- [ ] Keep `chainTarget` in the HSS session policy for concrete lane/budget
  scope.
- [ ] Ensure HSS stable context excludes concrete `chainTarget` from the shared
  key derivation when the target is Tempo vs Arc/EVM.
- [ ] Add or extend HSS tests proving changing only `chainTarget` does not
  change the shared EVM-family key id or owner address.
- [ ] Add HSS tests proving changing `rpId`, `signingRootId`,
  `signingRootVersion`, `participantIds`, or `ecdsaThresholdKeyId` does change
  the stable identity/fingerprint.
- [ ] Delete any helper that reconstructs `ecdsaThresholdKeyId`,
  `signingRootId`, or owner address from optional bootstrap fields after the
  activation request has been built.
- [ ] Replace broad activation/request bags with branch-specific builders:
  - `buildPasskeyRegistrationEcdsaActivation(...)`
  - `buildPasskeyReconnectEcdsaActivation(...)`
  - `buildEmailOtpSessionBootstrapEcdsaActivation(...)`
  - `buildEmailOtpPerOperationReauthEcdsaActivation(...)`
  - `buildThresholdSessionReconnectEcdsaActivation(...)`
  - `buildEcdsaExportActivation(...)`
- [ ] Ensure each builder accepts the narrowest valid auth/session/key state and
  rejects invalid branch combinations with `never` fields.

## Phase 4: Email OTP HSS Branded IDs And Compile Guards

- [ ] Add branded identity types for the Email OTP ECDSA HSS boundary:
  - `WalletSessionUserId`
  - `EmailOtpAuthSubjectId`
- [ ] Reuse ECDSA identity brands from
  `session/identity/evmFamilyEcdsaIdentity.ts`:
  - `WalletSubjectId` / ECDSA subject identity
  - `EcdsaThresholdKeyId`
  - `SigningRootId`
  - `SigningRootVersion`
  - `ThresholdEcdsaSessionId`
  - `WalletSigningSessionId`
  - `ThresholdOwnerAddress`
- [ ] Add boundary parsers/builders that convert raw strings once:
  - wallet/account id to `WalletSessionUserId`
  - provider subject such as `google:*` to `EmailOtpAuthSubjectId`
  - wallet ECDSA lane subject to `WalletSubjectId`
  - server key id to `EcdsaThresholdKeyId`
- [ ] Replace raw `walletSessionUserId: string` in Email OTP HSS request and
  session policy types with `WalletSessionUserId`.
- [ ] Keep provider identity out of wallet-scoped HSS fields:
  - `authSubjectId: EmailOtpAuthSubjectId`
  - `walletSessionUserId: WalletSessionUserId`
  - `subjectId: WalletSubjectId`
- [ ] Split Email OTP HSS bootstrap lifecycle types:
  - [ ] `EmailOtpRegistrationBootstrap` permits no preexisting
    `ecdsaThresholdKeyId`.
  - [ ] `EmailOtpExistingKeyBootstrap` requires `ecdsaThresholdKeyId`.
  - [ ] `SessionBootstrap` requires existing key identity and concrete lane
    policy.
  - [ ] Use `never` fields to reject invalid operation/key-id combinations.
- [ ] Make server-planned HSS context opaque:
  - [ ] Introduce `ServerPlannedEcdsaHssContext`.
  - [ ] Require Email OTP bootstrap workers to consume the context returned by
    `/threshold-ecdsa/hss/prepare`.
  - [ ] Forbid local client reconstruction of stable HSS context in Email OTP
    registration/bootstrap.
- [ ] Update file targets:
  - `client/src/core/signingEngine/session/emailOtp/*`
  - `client/src/core/signingEngine/threshold/ecdsa/*`
  - `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
  - `client/src/core/signingEngine/session/availability/*`
  - `server/src/core/ThresholdService/*`
- [ ] Add compile-only fixtures proving:
  - provider subject cannot be assigned to `walletSessionUserId`
  - wallet id cannot be assigned to `authSubjectId`
  - registration bootstrap cannot carry `ecdsaThresholdKeyId`
  - existing-key/session bootstrap cannot omit `ecdsaThresholdKeyId`
  - Email OTP bootstrap cannot pass a locally constructed HSS stable context to
    the worker
  - session ids cannot appear in stable HSS key context
- [ ] Add static guards:
  - [ ] no raw `walletSessionUserId: string` in Email OTP HSS core types
  - [ ] no `google:`/provider-shaped value assigned to wallet-scoped fields
  - [ ] no `EcdsaHssStableKeyContextV1` construction inside Email OTP bootstrap
    client code outside the server prepare response parser
  - [ ] no broad object spread into Email OTP HSS bootstrap request builders
- [ ] Document the invariant beside the builders: provider identity authorizes
  Email OTP enrollment, wallet/session identity scopes HSS audit and session
  policy, and server-planned context is the only HSS key-context source for
  Email OTP bootstrap.

## Phase 5: Registration And Wallet Unlock Warm-Up

- [ ] Update `client/src/core/SeamsPasskey/registration.ts` so registration
  emits one shared EVM-family key identity and target-specific session lanes.
- [ ] Update profile continuity persistence so account signer metadata stores:
  - shared EVM-family key identity
  - concrete target membership
  - account model/address information for smart-account paths
- [ ] Update `client/src/core/SeamsPasskey/login.ts` so unlock warm-up builds
  target lanes from the shared key identity.
- [ ] Keep the current ambiguity failure: multiple key ids for one EVM-family
  wallet must fail before warm-up.
- [ ] Replace target-key completion logic with a builder that returns:
  - `complete_shared_key_targets`
  - `ambiguous_shared_key_targets`
  - `missing_shared_key`
- [ ] Add tests for:
  - fresh account registration with Tempo and Arc/EVM targets
  - wallet unlock where only one target has stored metadata
  - wallet unlock with conflicting stored key ids
  - wallet unlock after IndexedDB cleanup

## Phase 6: EVM-Family Signing And Post-Exhaustion Reauth

- [ ] Update `client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
  to delegate record/keyRef matching to
  `resolveReadyEvmFamilyEcdsaMaterial(...)`.
- [ ] Update `preparedSigning.ts`, `ecdsaSelection.ts`, and `ecdsaLanes.ts` so
  prepared operations carry `ReadyEvmFamilyEcdsaMaterial` when signing can
  proceed.
- [ ] Update passkey reauth in `signingFlowRuntime.ts` so reconnect returns
  ready material, not keyRef alone.
- [ ] Update Email OTP reauth in `emailOtpRefresh.ts` so completion returns
  ready material from the same canonical resolver.
- [ ] Centralize EVM-family fresh-auth retry policy in one classifier:
  - [ ] Track side-effect state:
    - `no_auth_side_effect_started`
    - `auth_prompt_shown`
    - `auth_confirmed`
    - `threshold_reconnect_started`
  - [ ] Permit fresh-auth retry only before any auth prompt/confirmation side
    effect has started.
  - [ ] Reject fallback retry paths that can show a second passkey or Email OTP
    prompt for the same operation.
  - [ ] Emit the retry decision and side-effect state in signing diagnostics.
- [ ] Split Email OTP route authorization identity from minted signing-session
  identity:
  - [ ] Rename signing-session auth-lane fields at the boundary to
    `authorizingWalletSigningSessionId` or `sourceWalletSigningSessionId`.
  - [ ] Introduce branded types for
    `AuthorizingWalletSigningSessionId` and `MintedWalletSigningSessionId`.
  - [ ] Add a branch-specific builder for per-operation Email OTP ECDSA minting
    that always generates the minted `walletSigningSessionId`.
  - [ ] Forbid `loginWithEmailOtpEcdsaCapability` and
    `loginWithEmailOtpEcdsaCapabilityForSigning` from reading
    `routePlan.authLane.walletSigningSessionId` as the minted session identity.
  - [ ] Keep signing-session route auth usable only as authorization material
    for challenge/verify and HSS bootstrap.
  - [ ] Add a runtime boundary assertion that per-operation ECDSA minting never
    reuses the authorizing signing-session id as the minted signing-session id.
  - [ ] Add compile-only fixtures proving auth-lane session ids cannot be passed
    where minted session ids are required.
- [ ] Remove local `record + keyRef` matching logic from `signEvmFamily.ts`.
- [ ] Make post-exhaustion signing compile only when the reauth branch returns
  `ReadyEvmFamilyEcdsaMaterial`.
- [ ] Add tests for:
  - passkey Tempo sign after ECDSA session exhaustion
  - passkey Arc/EVM sign after ECDSA session exhaustion
  - Email OTP Tempo sign after ECDSA session exhaustion
  - Email OTP Arc/EVM sign after ECDSA session exhaustion
  - Email OTP per-operation reauth mints a fresh wallet signing-session id
    when authorized by an exhausted signing-session JWT
  - first post-exhaustion Email OTP Tempo attempt succeeds after one prompt
  - first post-exhaustion Email OTP Arc/EVM attempt succeeds after one prompt

## Phase 7: Key Export And Recovery

- [ ] Update `flows/recovery/exportLaneSelection.ts` so grouping uses
  `EvmFamilyEcdsaKeyIdentity`.
- [ ] Update `ecdsaExportMaterial.ts` so export material resolution consumes
  `ReadyEvmFamilyEcdsaMaterial`.
- [ ] Preserve the current behavior where multiple active session lanes for one
  shared EVM-family key are acceptable for export selection.
- [ ] Add tests proving key export remains unambiguous when runtime and durable
  lanes have different session ids for the same shared key.
- [ ] Add a regression where stale passkey ECDSA export lanes coexist with a
  selectable Email OTP lane, and export selects the Email OTP lane without
  ambiguity.
- [ ] Update sealed recovery readback so restored ECDSA records rebuild the
  shared key identity at the boundary.
- [ ] Remove duplicate export-specific identity comparison helpers after the
  shared resolver owns that logic.

## Phase 8: Budget, Session Status, And Warm Capability State

- [ ] Update warm capability state in
  `client/src/core/signingEngine/session/warmCapabilities/types.ts` so ECDSA
  capability branches reference shared key identity plus lane identity.
- [ ] Update budget status requests so ECDSA budget identity is always concrete
  lane identity:
  - shared key identity
  - `chainTarget`
  - `thresholdSessionId`
  - `walletSigningSessionId`
- [ ] Keep server budget/session lookups curve-bound and lane-bound.
- [ ] Update `BudgetCoordinator` and `budgetStatusReader.ts` to reject requests
  that only carry shared key identity without concrete session lane identity.
- [ ] Model wallet signing budget lifecycle as a discriminated union:
  - `PreparedNoBudget`
  - `BudgetAdmitted`
  - `StepUpConfirmed`
  - `ReauthAdmitted`
  - `Signed`
  - `Finalized`
- [ ] Make Email OTP/passkey reauth replace the active admitted operation before
  signing can proceed.
- [ ] Make old exhausted operations impossible to pass into transaction signing
  or finalization after reauth succeeds.
- [ ] Keep finalization branches explicit:
  - `reserved_success`
  - `unreserved_success`
  - `externally_consumed_success`
  - `zero_spend`
- [ ] Require Email OTP externally-consumed success to name the consumed backing
  threshold session ids.
- [ ] Add budget diagnostics fields to EVM-family signing/export/bootstrap
  failures:
  - `operationId`
  - `authMethod`
  - `evmFamilyKeyFingerprint`
  - `chainTargetKey`
  - `ecdsaThresholdKeyId`
  - `walletSigningSessionId`
  - `thresholdSessionId`
  - `budgetProjectionVersion`
  - retry side-effect state
- [ ] Add tests for:
  - fresh unlock budget status
  - one spend
  - exhausted lane
  - passkey reauth after exhaustion
  - Email OTP reauth after exhaustion
  - reauth replaces the exhausted operation before signing
  - finalization records spend against the refreshed operation

## Phase 9: Nonce, Sender Address, And Smart-Account Boundaries

- [ ] Update EVM-family nonce identity so raw EIP-1559 paths use
  `key.thresholdOwnerAddress` as sender.
- [ ] Keep smart-account/counterfactual account address in smart-account
  deployment paths only.
- [ ] Rename address fields at cross-boundary call sites to role-specific names:
  - `thresholdOwnerAddress`
  - `smartAccountAddress`
  - `counterfactualAddress`
  - `chainAccountAddress`
- [ ] Update `executeEvmFamilyTransaction.ts`, `transactionExecutor.ts`, and
  `nonceResolution.ts` to consume explicit sender identity.
- [ ] Update demo helpers in `examples/seams-site/src/flows/demo/hooks/*` so
  funding/preflight displays the owner address used by raw EIP-1559 broadcast.
- [ ] Add a regression test proving:
  - displayed funding address
  - preflight balance address
  - managed nonce sender
  - signed transaction sender
  all match for raw Arc/EVM signing.
- [ ] Add a separate test proving smart-account flows use account address
  through smart-account execution paths.

## Phase 10: Public API And Iframe Message Shape

- [ ] Update public ECDSA bootstrap/sign/export request types to expose shared
  key identity only through public-safe fields.
- [ ] Keep public operation inputs wallet-session shaped.
- [ ] Ensure iframe ECDSA messages carry:
  - `walletSession`
  - `subjectId`
  - concrete `chainTarget`
  - operation request
- [ ] Remove public request fields that allow callers to supply partial internal
  ECDSA key identity.
- [ ] Update public docs and examples:
  - `docs/threshold-ecdsa/ecdsa-threshold-signing.md`
  - `docs/threshold-ecdsa/evm-family-address-invariant.md`
  - `examples/seams-docs/src/getting-started/next-steps.md`

## Phase 11: Static Guards And Type Fixtures

- [ ] Extend `tests/unit/signingEngine.refactor36.guard.unit.test.ts` or create
  `signingEngine.refactor37.guard.unit.test.ts`.
- [ ] Guard against new internal EVM-family types that duplicate shared key
  fields and session fields in one unapproved struct.
- [ ] Guard against broad object spreads into `ReadyEvmFamilyEcdsaMaterial` and
  `EvmFamilyEcdsaSessionLane`.
- [ ] Guard against `as ReadyEvmFamilyEcdsaMaterial`,
  `as EvmFamilyEcdsaKeyIdentity`, and `as EvmFamilyEcdsaSessionLane` outside
  builder/typecheck files.
- [ ] Add compile-only fixtures for invalid branch combinations.
- [ ] Add compile-only fixtures for:
  - auth-lane wallet signing-session ids rejected where minted ids are required
  - stable HSS key context rejected when session lifecycle ids are present
  - raw EIP-1559 rejected when only a smart-account address is available
  - post-reauth signing rejected with the old exhausted admitted operation
- [ ] Add a guard that all EVM-family configured targets map to one owner
  address in fixture registration/login flows.
- [ ] Add a guard blocking raw EIP-1559 paths from calling profile or
  chain-account sender fallback helpers.
- [ ] Add a guard blocking local Email OTP stable HSS context construction
  outside the server prepare response parser.

## Phase 12: Test Matrix And Manual Checks

- [ ] Passkey account:
  - [ ] wallet unlock
  - [ ] NEAR signing
  - [ ] Tempo signing
  - [ ] Arc/EVM signing
  - [ ] Ed25519 key export
  - [ ] ECDSA key export
  - [ ] Ed25519 signing after exhaustion
  - [ ] ECDSA Tempo signing after exhaustion
  - [ ] ECDSA Arc/EVM signing after exhaustion
- [ ] Email OTP account:
  - [ ] wallet unlock
  - [ ] NEAR signing
  - [ ] Tempo signing
  - [ ] Arc/EVM signing
  - [ ] Ed25519 key export
  - [ ] ECDSA key export
  - [ ] Ed25519 signing after exhaustion
  - [ ] ECDSA Tempo signing after exhaustion
  - [ ] ECDSA Arc/EVM signing after exhaustion
- [ ] Fresh account registration:
  - [ ] Tempo and Arc/EVM owner addresses match
  - [ ] funding address matches broadcast sender
  - [ ] key export address matches funding address
- [ ] Existing account unlock:
  - [ ] stored one-target metadata completes all configured EVM-family targets
  - [ ] conflicting target metadata fails before warm-up

## Phase 13: Deletion And Cleanup

- [ ] Delete duplicate identity helpers replaced by
  `evmFamilyEcdsaIdentity.ts`.
- [ ] Delete stale fallback paths that choose between record/keyRef identity by
  local optional probing.
- [ ] Delete compatibility comments or TODOs that reference the old target-scoped
  key-id behavior.
- [ ] Shrink allowlists introduced during the refactor.
- [ ] Run `rg` checks for stale field groups:
  - `ecdsaThresholdKeyId` beside `thresholdSessionId`
  - `ethereumAddress` beside `counterfactualAddress`
  - `key_ref_only`
  - `record_only`
  - `reuse_warm_ecdsa_bootstrap`
- [ ] Keep remaining raw compatibility only at persistence/request boundaries.

## Validation Commands

Run focused validation during implementation:

```bash
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C examples/seams-site typecheck
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/warmSessionStore.capabilityResolution.unit.test.ts ./unit/warmSessionStore.bootstrapResolution.unit.test.ts --reporter=line
```

Run broader ECDSA regression coverage before closure:

```bash
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./e2e/signing-session-regressions.walletIframe.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./e2e/thresholdEcdsa.tempoSigning.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts --reporter=line
```

## Exit Criteria

- One internal type owns shared EVM-family ECDSA key identity.
- Concrete signing lanes reference the shared key identity and add only
  target/session/budget state.
- HSS bootstrap accepts canonical shared key identity plus concrete session
  policy.
- Email OTP ECDSA HSS bootstrap cannot compile with provider identity in
  wallet-scoped fields, missing existing-key ids, or locally reconstructed
  stable HSS context.
- Signing, export, and reauth consume `ReadyEvmFamilyEcdsaMaterial`.
- Tempo and Arc/EVM cannot compile or pass tests with different threshold owner
  addresses for one wallet.
- Post-exhaustion passkey and Email OTP signing pass for Tempo and Arc/EVM.
- Public/demo funding address, preflight address, nonce sender, and transaction
  sender match for raw EIP-1559 flows.
- Old duplicate identity helpers and stale fallback paths are deleted.
