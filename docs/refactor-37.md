# Refactor 37: Shared EVM-Family ECDSA Identity

Date created: 2026-05-15
Status: complete

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
  subjectId: WalletId;
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

- [x] Inventory every shape that currently carries any of:
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
- [x] Produce a short table in this plan mapping each current type to either:
  - shared key identity
  - concrete session lane
  - raw persistence/request boundary
  - diagnostics/display only

### Phase 0 Inventory

| Current shape/type                                                                                | Classification                   | Notes                                                                                                                                          |
| ------------------------------------------------------------------------------------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `EvmFamilyEcdsaKeyIdentity`                                                                       | shared key identity              | Owns stable public key fields: wallet, subject, RP, `evm-family` scope, ECDSA key id, signing root, participants, and threshold owner address. |
| `EvmFamilyEcdsaSessionLane`                                                                       | concrete session lane            | Adds concrete target, auth method, source, threshold session id, wallet signing-session id, budget counts, and expiry.                         |
| `ReadyEvmFamilyEcdsaMaterial`                                                                     | concrete session lane            | Operation-ready material that requires the shared key identity, exact lane, session record, and key ref.                                       |
| `ThresholdEcdsaSessionRecord` and `ThresholdEcdsaSecp256k1KeyRef`                                 | raw persistence/request boundary | Normalized immediately through `buildEvmFamilyEcdsaKeyIdentityFromRecord(...)` and `buildEvmFamilyEcdsaKeyIdentityFromKeyRef(...)`.            |
| Sealed ECDSA recovery records and stored session rows                                             | raw persistence/request boundary | Readback rejects stale target-scoped rows or records missing owner address, key id, signing root, or concrete lane identity.                   |
| `ConcreteAvailableEcdsaSigningLane` and persisted available-lane candidates                       | concrete session lane            | Carries canonical `key` plus target/session lane data for display and selection.                                                               |
| `SelectedEcdsaLane`, `EcdsaSigningSessionPlanningLane`, and `ResolvedEcdsaSigningSessionIdentity` | concrete session lane            | Approved operation-state lane shapes that carry key id with exact session identity; the Phase 11 guard intentionally allowlists this row.      |
| Passkey, Email OTP, and threshold-session ECDSA activation/bootstrap request types                | raw persistence/request boundary | Phase 3 will replace broad request bags with branch-specific activation builders.                                                              |
| HSS prepare/finalize request and response payloads                                                | raw persistence/request boundary | Server boundary currently validates RP, signing root, session policy, participants, and exact lane scope.                                      |
| Server integrated key records and store rows                                                      | raw persistence/request boundary | Store uniqueness enforces one shared EVM-family key identity per wallet, subject, RP, key scope, and signing root.                             |
| `EcdsaMaterialSummary`, available-lane diagnostics, export diagnostics, budget/nonce trace fields | diagnostics/display only         | May print `evmFamilyKeyFingerprint`, target key, key id, and lane ids; no secret material.                                                     |
| Public SDK and iframe ECDSA request/result shapes                                                 | raw persistence/request boundary | Public-safe wallet/session inputs and result fields; internal shared key identity is reconstructed inside SDK boundaries.                      |

- [x] Add a guard that flags new internal EVM-family structs containing
      `ecdsaThresholdKeyId` and `thresholdSessionId` together unless the type is
      an approved lane/material type.
- [x] Add a guard that fails if Tempo and EVM configured targets can produce
      different threshold owner addresses for one wallet in tests.
- [x] Add a guard that rejects local construction of
      `EvmFamilyEcdsaKeyIdentity` outside approved builders/type fixtures.
- [x] Add a fixture that logs one `evmFamilyKeyFingerprint` through HSS
      bootstrap, lane resolution, signing, export, and nonce resolution for the same
      wallet.

## Phase 1: Canonical Identity Types

- [x] Add `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`.
- [x] Define role-specific branded primitives used by EVM-family identity:
  - `WalletId`
  - `RpId`
  - `EcdsaThresholdKeyId`
  - `SigningRootId`
  - `SigningRootVersion`
  - `ThresholdEcdsaSessionId`
  - `WalletSigningSessionId`
  - `ThresholdOwnerAddress`
  - `EvmFamilyKeyScope`
- [x] Define `EvmFamilyEcdsaKeyIdentity`.
- [x] Define `EvmFamilyEcdsaSessionLane`.
- [x] Define `ReadyEvmFamilyEcdsaMaterial`.
- [x] Define `EvmFamilyEcdsaIdentityMismatch` with explicit branches:
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
- [x] Add builders:
  - `buildEvmFamilyEcdsaKeyIdentityFromKeyRef(...)`
  - `buildEvmFamilyEcdsaKeyIdentityFromRecord(...)`
  - `buildEvmFamilyEcdsaSessionLane(...)`
  - `resolveReadyEvmFamilyEcdsaMaterial(...)`
- [x] Add `deriveEvmFamilyKeyFingerprint(...)` over stable public identity
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
- [x] Ensure owner-address builders verify the address from trusted key material
      or a server-verified key ref before accepting persisted/profile/demo address
      data.
- [x] Make `resolveReadyEvmFamilyEcdsaMaterial(...)` return a result union:
  - `ready`
  - `record_only`
  - `key_ref_only`
  - `missing`
  - `identity_mismatch`
  - `stale`
- [x] Use `never` fields for invalid branch combinations in mismatch/result
      unions.
- [x] Add type fixtures proving:
  - a key identity cannot carry session ids
  - a session lane must carry a key identity
  - ready material requires both record and keyRef
  - Tempo/EVM concrete targets cannot carry different key ids under one shared
    key identity
  - a key identity cannot omit `rpId`
  - a key identity cannot use a target-specific `keyScope`

## Phase 2: Persistence And Read Model Normalization

- [x] Update `client/src/core/signingEngine/session/persistence/records.ts` so
      ECDSA record reads normalize into the shared key identity plus concrete lane.
- [x] Keep raw legacy/persistence compatibility only inside persistence
      boundary parsers.
- [x] Update `getThresholdEcdsaSessionRecordByKey(...)` and
      `getThresholdEcdsaKeyRefByKey(...)` callers to use the shared identity
      builders before control reaches operation flows.
- [x] Update available-lane read models in
      `client/src/core/signingEngine/session/availability/*` so EVM-family lanes
      expose:
  - shared key identity
  - concrete `chainTarget`
  - concrete session identity
- [x] Remove duplicate key identity fields from internal candidate shapes where
      a `key: EvmFamilyEcdsaKeyIdentity` reference can be passed.
- [x] Add a persistence negative fixture for records that claim the same
      `ecdsaThresholdKeyId` but a different owner address across EVM-family targets.
- [x] Add persistence fixtures proving restored passkey and Email OTP sealed
      ECDSA records preserve `ThresholdOwnerAddress`.
- [x] Reject current-format sealed ECDSA records that are missing owner address,
      key id, signing root, or concrete lane identity at the persistence boundary.
- [x] Add a storage cutover version for EVM-family ECDSA records. Any stored
      record from the target-scoped-key era should be deleted or rejected before it
      can become an available-lane candidate.
- [x] Add client-store and server-store uniqueness checks for one shared
      EVM-family key identity per:
  - `walletId`
  - `subjectId`
  - `rpId`
  - `keyScope`
  - `signingRootId`
  - `signingRootVersion`
- [x] Reject or delete rows where two configured EVM-family targets for the same
      shared identity point at different `ecdsaThresholdKeyId` or
      `thresholdOwnerAddress` values.

## Phase 3: HSS Bootstrap Boundary

- [x] Update `client/src/core/signingEngine/threshold/ecdsa/activation.ts` so
      activation requests carry:
  - `key: EvmFamilyEcdsaKeyIdentity`
  - `lanePolicy: EvmFamilyEcdsaSessionLanePolicy`
- [x] Update `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
      so HSS context is built from shared key identity plus concrete session policy.
- [x] Keep `chainTarget` in the HSS session policy for concrete lane/budget
      scope.
- [x] Ensure HSS stable context excludes concrete `chainTarget` from the shared
      key derivation when the target is Tempo vs Arc/EVM.
- [x] Add or extend HSS tests proving changing only `chainTarget` does not
      change the shared EVM-family key id or owner address.
- [x] Add HSS tests proving changing `rpId`, `signingRootId`,
      `signingRootVersion`, `participantIds`, or `ecdsaThresholdKeyId` does change
      the stable identity/fingerprint.
- [x] Delete any helper that reconstructs `ecdsaThresholdKeyId`,
      `signingRootId`, or owner address from optional bootstrap fields after the
      activation request has been built.
- [x] Replace broad activation/request bags with branch-specific builders:
  - `buildPasskeyRegistrationEcdsaActivation(...)`
  - `buildPasskeyReconnectEcdsaActivation(...)`
  - `buildEmailOtpSessionBootstrapEcdsaActivation(...)`
  - `buildEmailOtpPerOperationReauthEcdsaActivation(...)`
  - `buildThresholdSessionReconnectEcdsaActivation(...)`
  - `buildEcdsaExportActivation(...)`
- [x] Ensure each builder accepts the narrowest valid auth/session/key state and
      rejects invalid branch combinations with `never` fields.

## Phase 4: Email OTP HSS Branded IDs And Compile Guards

- [x] Add branded identity types for the Email OTP ECDSA HSS boundary:
  - `WalletSessionUserId`
  - `EmailOtpAuthSubjectId`
- [x] Reuse ECDSA identity brands from
      `session/identity/evmFamilyEcdsaIdentity.ts`:
  - `WalletId` / ECDSA subject identity
  - `EcdsaThresholdKeyId`
  - `SigningRootId`
  - `SigningRootVersion`
  - `ThresholdEcdsaSessionId`
  - `WalletSigningSessionId`
  - `ThresholdOwnerAddress`
- [x] Add boundary parsers/builders that convert raw strings once:
  - wallet/account id to `WalletSessionUserId`
  - provider subject such as `google:*` to `EmailOtpAuthSubjectId`
  - wallet ECDSA lane subject to `WalletId`
  - server key id to `EcdsaThresholdKeyId`
- [x] Replace raw `walletSessionUserId: string` in Email OTP HSS request and
      session policy types with `WalletSessionUserId`.
- [x] Keep provider identity out of wallet-scoped HSS fields:
  - `authSubjectId: EmailOtpAuthSubjectId`
  - `walletSessionUserId: WalletSessionUserId`
  - `subjectId: WalletId`
- [x] Split Email OTP HSS bootstrap lifecycle types:
  - [x] `EmailOtpRegistrationBootstrap` permits no preexisting
        `ecdsaThresholdKeyId`.
  - [x] `EmailOtpExistingKeyBootstrap` requires `ecdsaThresholdKeyId`.
  - [x] `SessionBootstrap` requires existing key identity and concrete lane
        policy.
  - [x] Use `never` fields to reject invalid operation/key-id combinations.
- [x] Make server-planned HSS context opaque:
  - [x] Introduce `ServerPlannedEcdsaHssContext`.
  - [x] Require Email OTP bootstrap workers to consume the context returned by
        `/threshold-ecdsa/hss/prepare`.
  - [x] Forbid local client reconstruction of stable HSS context in Email OTP
        registration/bootstrap.
- [x] Update file targets:
  - `client/src/core/signingEngine/session/emailOtp/*`
  - `client/src/core/signingEngine/threshold/ecdsa/*`
  - `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
  - `client/src/core/signingEngine/session/availability/*`
  - `server/src/core/ThresholdService/*`
- [x] Add compile-only fixtures proving:
  - [x] provider subject cannot be assigned to `walletSessionUserId`
  - [x] wallet id cannot be assigned to `authSubjectId`
  - [x] registration bootstrap cannot carry `ecdsaThresholdKeyId`
  - [x] existing-key/session bootstrap cannot omit `ecdsaThresholdKeyId`
  - [x] Email OTP bootstrap cannot pass a locally constructed HSS stable context to
        the worker
  - [x] session ids cannot appear in stable HSS key context
- [x] Add static guards:
  - [x] no raw `walletSessionUserId: string` in Email OTP HSS core types
  - [x] no `google:`/provider-shaped value assigned to wallet-scoped fields
  - [x] no `EcdsaHssStableKeyContextV1` construction inside Email OTP bootstrap
        client code outside the server prepare response parser
  - [x] no broad object spread into Email OTP HSS bootstrap request builders
- [x] Document the invariant beside the builders: provider identity authorizes
      Email OTP enrollment, wallet/session identity scopes HSS audit and session
      policy, and server-planned context is the only HSS key-context source for
      Email OTP bootstrap.

## Phase 5: Registration And Wallet Unlock Warm-Up

- [x] Update `client/src/core/SeamsPasskey/registration.ts` so registration
      emits one shared EVM-family key identity and target-specific session lanes.
- [x] Update profile continuity persistence so account signer metadata stores:
  - shared EVM-family key identity
  - concrete target membership
- [x] Update `client/src/core/SeamsPasskey/login.ts` so unlock warm-up builds
      target lanes from the shared key identity.
- [x] Keep the current ambiguity failure: multiple key ids for one EVM-family
      wallet must fail before warm-up.
- [x] Replace target-key completion logic with a builder that returns:
  - `complete_shared_key_targets`
  - `ambiguous_shared_key_targets`
  - `missing_shared_key`
- [x] Add tests for:
  - [x] fresh account registration with Tempo and Arc/EVM targets
  - [x] wallet unlock where only one target has stored metadata
  - [x] wallet unlock with conflicting stored key ids
  - [x] wallet unlock after IndexedDB cleanup

## Phase 6: EVM-Family Signing And Post-Exhaustion Reauth

- [x] Update `client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
      to delegate record/keyRef matching to
      `resolveReadyEvmFamilyEcdsaMaterial(...)`.
- [x] Update `preparedSigning.ts`, `ecdsaSelection.ts`, and `ecdsaLanes.ts` so
      prepared operations carry `ReadyEvmFamilyEcdsaMaterial` when signing can
      proceed.
- [x] Update passkey reauth in `signingFlowRuntime.ts` so reconnect returns
      ready material, not keyRef alone.
- [x] Update Email OTP reauth in `emailOtpRefresh.ts` so completion returns
      ready material from the same canonical resolver.
- [x] Centralize EVM-family fresh-auth retry policy in one classifier:
  - [x] Track side-effect state:
    - `no_auth_side_effect_started`
    - `auth_prompt_shown`
    - `auth_confirmed`
    - `threshold_reconnect_started`
  - [x] Permit fresh-auth retry only before any auth prompt/confirmation side
        effect has started.
  - [x] Reject fallback retry paths that can show a second passkey or Email OTP
        prompt for the same operation.
  - [x] Emit the retry decision and side-effect state in signing diagnostics.
- [x] Split Email OTP route authorization identity from minted signing-session
      identity:
  - [x] Rename signing-session auth-lane fields at the boundary to
        `authorizingWalletSigningSessionId` or `sourceWalletSigningSessionId`.
  - [x] Introduce branded types for
        `AuthorizingWalletSigningSessionId` and `MintedWalletSigningSessionId`.
  - [x] Add a branch-specific builder for per-operation Email OTP ECDSA minting
        that always generates the minted `walletSigningSessionId`.
  - [x] Forbid `loginWithEmailOtpEcdsaCapability` and
        `loginWithEmailOtpEcdsaCapabilityForSigning` from reading
        `routePlan.authLane.walletSigningSessionId` as the minted session identity.
  - [x] Keep signing-session route auth usable only as authorization material
        for challenge/verify and HSS bootstrap.
  - [x] Add a runtime boundary assertion that per-operation ECDSA minting never
        reuses the authorizing signing-session id as the minted signing-session id.
  - [x] Add compile-only fixtures proving auth-lane session ids cannot be passed
        where minted session ids are required.
- [x] Remove local `record + keyRef` matching logic from `signEvmFamily.ts`.
- [x] Make post-exhaustion signing compile only when the reauth branch returns
      `ReadyEvmFamilyEcdsaMaterial`.
- [x] Add tests for:
  - [x] passkey Tempo sign after ECDSA session exhaustion
  - [x] passkey Arc/EVM sign after ECDSA session exhaustion
  - [x] Email OTP Tempo sign after ECDSA session exhaustion
  - [x] Email OTP Arc/EVM sign after ECDSA session exhaustion
  - [x] Email OTP per-operation reauth mints a fresh wallet signing-session id
        when authorized by an exhausted signing-session JWT
  - [x] first post-exhaustion Email OTP Tempo attempt succeeds after one prompt
  - [x] first post-exhaustion Email OTP Arc/EVM attempt succeeds after one prompt

## Phase 7: Key Export And Recovery

- [x] Update `flows/recovery/exportLaneSelection.ts` so grouping uses
      `EvmFamilyEcdsaKeyIdentity`.
- [x] Update `ecdsaExportMaterial.ts` so export material resolution consumes
      `ReadyEvmFamilyEcdsaMaterial`.
- [x] Preserve the current behavior where multiple active session lanes for one
      shared EVM-family key are acceptable for export selection.
- [x] Add tests proving key export remains unambiguous when runtime and durable
      lanes have different session ids for the same shared key.
- [x] Add a regression where stale passkey ECDSA export lanes coexist with a
      selectable Email OTP lane, and export selects the Email OTP lane without
      ambiguity.
- [x] Update sealed recovery readback so restored ECDSA records rebuild the
      shared key identity at the boundary.
- [x] Remove duplicate export-specific identity comparison helpers after the
      shared resolver owns that logic.

## Phase 8: Budget, Session Status, And Warm Capability State

- [x] Update warm capability state in
      `client/src/core/signingEngine/session/warmCapabilities/types.ts` so ECDSA
      capability branches reference shared key identity plus lane identity.
- [x] Update budget status requests so ECDSA budget identity is always concrete
      lane identity:
  - shared key identity
  - `chainTarget`
  - `thresholdSessionId`
  - `walletSigningSessionId`
- [x] Keep server budget/session lookups curve-bound and lane-bound.
- [x] Update `BudgetCoordinator` and `budgetStatusReader.ts` to reject requests
      that only carry shared key identity without concrete session lane identity.
- [x] Model wallet signing budget lifecycle as a discriminated union:
  - [x] `PreparedNoBudget`
  - [x] `BudgetAdmitted`
  - [x] `StepUpConfirmed`
  - [x] `ReauthAdmitted`
  - [x] `Signed`
  - [x] `Finalized`
- [x] Make Email OTP/passkey reauth replace the active admitted operation before
      signing can proceed.
- [x] Make old exhausted operations impossible to pass into transaction signing
      or finalization after reauth succeeds.
- [x] Keep finalization branches explicit:
  - `reserved_success`
  - `unreserved_success`
  - `externally_consumed_success`
  - `zero_spend`
- [x] Require Email OTP externally-consumed success to name the consumed backing
      threshold session ids.
- [x] Add budget diagnostics fields to EVM-family signing/export/bootstrap
      failures:
  - [x] signing failures include these fields
  - [x] export failures include these fields
  - [x] bootstrap failures include these fields
  - `operationId`
  - `authMethod`
  - `evmFamilyKeyFingerprint`
  - `chainTargetKey`
  - `ecdsaThresholdKeyId`
  - `walletSigningSessionId`
  - `thresholdSessionId`
  - `budgetProjectionVersion`
  - retry side-effect state
- [x] Add tests for:
  - [x] fresh unlock budget status
  - [x] one spend
  - [x] exhausted lane
  - [x] passkey reauth after exhaustion
  - [x] Email OTP reauth after exhaustion
  - [x] reauth replaces the exhausted operation before signing
  - [x] finalization records spend against the refreshed operation

## Phase 9: Nonce And Sender Address Boundaries

- [x] Update EVM-family nonce identity so raw EIP-1559 paths use
      `key.thresholdOwnerAddress` as sender.
- [x] Rename address fields at cross-boundary call sites to role-specific names:
  - `thresholdOwnerAddress`
  - `chainAccountAddress`
- [x] Update `executeEvmFamilyTransaction.ts`, `transactionExecutor.ts`, and
      `nonceResolution.ts` to consume explicit sender identity.
- [x] Update demo helpers in `examples/seams-site/src/flows/demo/hooks/*` so
      funding/preflight displays the owner address used by raw EIP-1559 broadcast.
- [x] Add a regression test proving:
  - displayed funding address
  - preflight balance address
  - managed nonce sender
  - signed transaction sender
    all match for raw Arc/EVM signing.

## Phase 10: Public API And Iframe Message Shape

- [x] Update public ECDSA bootstrap/sign/export request types to expose shared
      key identity only through public-safe fields.
- [x] Keep public operation inputs wallet-session shaped.
- [x] Ensure iframe ECDSA messages carry:
  - `walletSession`
  - `subjectId`
  - concrete `chainTarget`
  - operation request
- [x] Remove public request fields that allow callers to supply partial internal
      ECDSA key identity.
- [x] Update public docs and examples:
  - `docs/threshold-ecdsa/ecdsa-threshold-signing.md`
  - `docs/threshold-ecdsa/evm-family-address-invariant.md`
  - `examples/seams-docs/src/getting-started/next-steps.md`

## Phase 11: Static Guards And Type Fixtures

- [x] Extend `tests/unit/signingEngine.refactor37.guard.unit.test.ts`.
- [x] Guard against new internal EVM-family types that duplicate shared key
      fields and session fields in one unapproved struct.
- [x] Guard against broad object spreads into `ReadyEvmFamilyEcdsaMaterial` and
      `EvmFamilyEcdsaSessionLane`.
- [x] Guard against `as ReadyEvmFamilyEcdsaMaterial`,
      `as EvmFamilyEcdsaKeyIdentity`, and `as EvmFamilyEcdsaSessionLane` outside
      builder/typecheck files.
- [x] Add compile-only fixtures for invalid branch combinations.
- [x] Add compile-only fixtures for:
  - auth-lane wallet signing-session ids rejected where minted ids are required
  - stable HSS key context rejected when session lifecycle ids are present
  - post-reauth signing rejected with the old exhausted admitted operation
- [x] Add a guard that all EVM-family configured targets map to one owner
      address in fixture registration/login flows.
- [x] Add a guard blocking raw EIP-1559 paths from calling profile or
      chain-account sender fallback helpers.
- [x] Add a guard blocking local Email OTP stable HSS context construction
      outside the server prepare response parser.

## Phase 12: Test Matrix And Manual Checks

### Runtime Tests Worth Adding Now

These are the highest-value runtime tests to add before deeper structural
cleanup. Several overlap with the phase-specific tasks above; keep this section
as the immediate implementation queue and mark the owning phase item when a test
lands.

- [x] Fresh passkey registration persists the account/profile mapping and signer
      slots before returning:
  - [x] NEAR Ed25519 signing succeeds immediately.
  - [x] Ed25519 key export finds the single-key HSS signer slot.
  - [x] ECDSA key export finds the exact EVM-family lane.
- [x] Fresh Email OTP registration and unlock use server-planned ECDSA HSS
      bootstrap context:
  - registration bootstrap permits missing `ecdsaThresholdKeyId`
  - existing-key/session bootstrap requires `ecdsaThresholdKeyId`
  - Email OTP provider subject never appears in wallet-scoped HSS fields
  - client code does not locally reconstruct stable HSS context
- [x] Existing EVM-family ECDSA key reconnect remains stable across new
      `walletSigningSessionId` and `thresholdSessionId` values:
  - Tempo reconnect succeeds
  - Arc/EVM reconnect succeeds
  - changing `rpId`, signing root, key id, or owner address fails with a typed
    mismatch
- [x] Registration with Tempo and Arc/EVM configured targets produces one shared
      `evmFamilyKeyFingerprint`:
  - same `ecdsaThresholdKeyId`
  - same `thresholdOwnerAddress`
  - target-specific session lanes and budgets
- [x] Raw Arc/EVM signing uses the threshold owner address consistently:
  - [x] displayed funding address
  - [x] preflight balance address
  - [x] managed nonce sender
  - [x] recovered signed transaction sender
  - [x] ECDSA key export address
- [x] Stale target-scoped ECDSA rows and sealed records cannot become available
      lane candidates after storage cutover.
- [x] ECDSA export is unambiguous when runtime and durable records coexist for
      the same shared key:
  - passkey runtime plus durable lane
  - Email OTP runtime plus stale passkey durable lane
  - exhausted duplicate lane plus selectable active lane
- [x] Post-exhaustion passkey signing succeeds on the first attempt for:
  - [x] Tempo
  - [x] Arc/EVM
- [x] Post-exhaustion Email OTP signing succeeds on the first attempt for:
  - [x] Tempo
  - [x] Arc/EVM
- [x] Post-exhaustion Email OTP signing shows exactly one step-up prompt per
      operation.
- [x] Per-operation Email OTP ECDSA reauth mints a fresh
      `walletSigningSessionId` distinct from the authorizing exhausted session id.
- [x] Budget consume/finalize runs against the refreshed operation after reauth:
  - [x] no `not_found` consume for Email OTP ECDSA
  - [x] old exhausted operation cannot reach signing or finalization
  - [x] externally consumed backing threshold session ids are recorded
- [x] EVM-family diagnostics include the same `evmFamilyKeyFingerprint` across:
  - [x] HSS prepare/finalize
  - [x] activation
  - [x] available-lane resolution
  - [x] signing
  - [x] export
  - [x] budget admission/finalization
  - [x] nonce resolution

- [x] Passkey account:
  - [x] wallet unlock
  - [x] NEAR signing
  - [x] Tempo signing
  - [x] Arc/EVM signing
  - [x] Ed25519 key export
  - [x] ECDSA key export
  - [x] Ed25519 signing after exhaustion
  - [x] ECDSA Tempo signing after exhaustion
  - [x] ECDSA Arc/EVM signing after exhaustion
- [x] Email OTP account:
  - [x] wallet unlock
  - [x] NEAR signing
  - [x] Tempo signing
  - [x] Arc/EVM signing
  - [x] Ed25519 key export
  - [x] ECDSA key export
  - [x] Ed25519 signing after exhaustion
  - [x] ECDSA Tempo signing after exhaustion
  - [x] ECDSA Arc/EVM signing after exhaustion
- [x] Fresh account registration:
  - [x] Tempo and Arc/EVM owner addresses match
  - [x] funding address matches broadcast sender
  - [x] key export address matches funding address
- [x] Existing account unlock:
  - [x] stored one-target metadata completes all configured EVM-family targets
  - [x] conflicting target metadata fails before warm-up

### Manual Regression Follow-ups

- [x] Add available-lane regression coverage for one stored EVM-family target
      completing missing configured targets.
- [x] Add ECDSA export regression coverage for selecting and restoring the
      concrete source lane when the requested target has only shared-key completion.
- [x] Remove request-time Postgres unique-index creation from ECDSA HSS key
      store bootstrap.
- [x] Restore passkey Ed25519 Shamir3pass material before shared NEAR
      NEP-413/delegate auth planning so restored sessions do not show step-up auth.

## Phase 13: Deletion And Cleanup

- [x] Delete duplicate identity helpers replaced by
      `evmFamilyEcdsaIdentity.ts`.
- [x] Delete stale fallback paths that choose between record/keyRef identity by
      local optional probing.
- [x] Delete compatibility comments or TODOs that reference the old target-scoped
      key-id behavior.
- [x] Shrink allowlists introduced during the refactor.
- [x] Run `rg` checks for stale field groups:
  - `ecdsaThresholdKeyId` beside `thresholdSessionId`
  - `key_ref_only`
  - `record_only`
  - `reuse_warm_ecdsa_bootstrap`
- [x] Keep remaining raw compatibility only at persistence/request boundaries.

## Phase 14: Delete Smart-Account Code And Restore One ECDSA Source Of Truth

### Problem

Manual diagnostics showed base threshold ECDSA unlock still reached the
unfinished smart-account projection path:

- wallet unlock has local per-target ECDSA key ids for Tempo and EVM targets
- those local rows do not contain canonical shared key identity
- the repair path calls `/threshold-ed25519/smart-account-signers`
- the server reads `AccountSignerStore` smart-account rows and returns zero
  records for normal threshold ECDSA wallets
- ECDSA warm-up cannot resolve `EvmFamilyEcdsaKeyIdentity`
- no ECDSA runtime or durable lanes are created
- Tempo signing, EVM signing, and ECDSA key export later fail with
  `no_candidate`

This is a design bug. Smart-account signer rows came from an unfinished feature
and looked too much like canonical ECDSA signer inventory. Normal threshold
ECDSA signing uses the threshold ECDSA owner address from the canonical
integrated key record. Base ECDSA session readiness must read
`threshold_ecdsa_keys` as the source of truth.

The confusion risk is broader than unlock warm-up. Smart-account routes,
deployment hooks, config fields, local DB fields, shared utils, tests, and
contract packages make the feature look active. They should be deleted from the
current product surface.

### Critique Of The Earlier Shape

- The previous scope, "remove from base warm-up", was too narrow. The same
  confusion can return through sync, registration, link-device, config, tests,
  recovery, or demo address reads.
- A new ECDSA key-identity route is useful only if it is the single canonical
  read model over `threshold_ecdsa_keys`. Prefer returning that inventory from
  the existing session exchange/unlock path. Add a new route only if the
  existing exchange path cannot carry the shape cleanly.
- "Delete unless required" creates an escape hatch. Any generic signer lifecycle
  code that survives should be renamed and narrowed first; smart-account-named
  code should be removed.
- A guard scoped only to base warm-up imports is too weak. The guard should
  block smart-account code across production, config, tests, and docs, with a
  tiny allowlist for this deletion phase and explicit future-plan documents.

### Target Shape

- Normal threshold ECDSA has one authoritative key-identity source:
  `ThresholdEcdsaIntegratedKeyRecord` / `threshold_ecdsa_keys`.
- Unlock warm-up resolves `EvmFamilyEcdsaKeyIdentity` from that key store using
  wallet id, subject id, RP id, signing root, participants, owner address, and
  `ecdsaThresholdKeyId`.
- Configured Tempo/EVM targets are target-specific session lanes over the same
  shared EVM-family key identity.
- Smart-account projection state is removed from current SDK, server, examples,
  config, tests, and docs.
- Public and internal ECDSA request shapes have no `smartAccount`,
  `counterfactualAddress`, `accountSigners`, deployment-mode, bundler,
  paymaster, or ERC-4337 fields.
- Current docs have no smart-account references except this deletion phase and
  future-plan docs that begin with the caveat below.

### Future Smart-Account Plan Caveat

Any future `/docs` plan that reintroduces smart accounts must start with this
status caveat:

```text
Status: future/inactive. Current product uses normal threshold ECDSA owner
addresses for Tempo and EVM-family signing. Smart-account code has been removed
from the active SDK, server, config, persistence, and test surface. This plan
does not describe current behavior and must not add active code paths, public
API fields, config fields, database tables, or tests until the feature is
explicitly reintroduced.
```

Future smart-account support must also have its own namespace, source of truth,
routes, persistence, tests, and docs. It must consume canonical threshold ECDSA
key identity as input; it must never become the source of ECDSA signing
readiness or lane selection.

### Implementation TODO

- [x] Add one normal threshold ECDSA key identity inventory read model, backed
      by the integrated key store:
  - preferred transport: existing session exchange/unlock response
  - fallback transport: one narrowly named threshold-ECDSA inventory route
  - input: authenticated wallet/session context plus target key ids or
    `ecdsaThresholdKeyId`
  - output: public canonical key identity fields only
  - source of truth: `ThresholdSigningService` integrated key record reader
  - no dependency on `AccountSignerStore`
- [x] Replace unlock ECDSA identity repair in
      `client/src/core/SeamsPasskey/login.ts`:
  - remove base warm-up calls to `/threshold-ed25519/smart-account-signers`
  - resolve missing shared key identity from the new normal ECDSA key-identity
    route after Ed25519 warm-up when local records only have key ids
  - complete all configured EVM-family targets from the shared key
  - fail before reporting wallet unlock success if configured ECDSA targets
    cannot resolve canonical identity
- [x] Split client relay inventory types:
  - keep a normal `ThresholdEcdsaKeyIdentityInventory` shape for base warm-up
  - delete `RelayThresholdEcdsaAccountSigner` from the base login/sync path
  - delete smart-account ingestion from current login/sync flows
- [x] Update `client/src/core/SeamsPasskey/syncAccount.ts` so account sync does
      not treat smart-account signer records as the source of ECDSA signing
      identity.
- [x] Update ECDSA bootstrap persistence and public capability surfaces so the
      normal bootstrap path does not accept smart-account projection fields.
- [x] Remove smart-account fields from public and internal SDK/config surfaces:
  - `smartAccount`
  - `smartAccountDeploymentMode`
  - `smartAccountDeploymentMaxAttempts`
  - `smartAccountDeployRoute`
  - `smartAccountDeploy`
  - `counterfactualAddress`
  - `undeployedSignerSet`
  - `erc4337`
  - paymaster and bundler fields
- [x] Update demo/UI address reads:
  - use wallet-session threshold ECDSA owner address for display and funding
  - stop calling `reuse_warm_ecdsa_bootstrap` just to discover the sender
    address
- [x] Ensure key export and Tempo/EVM signing read exact lanes created from the
      normal ECDSA key-identity source.

### Delete And Cleanup

- [x] Delete base ECDSA dependency on:
  - `/threshold-ed25519/smart-account-signers`
  - `listActiveSmartAccountSignersForUser(...)`
  - `listActiveSmartAccountSignersForUserWithDiagnostics(...)`
  - `RelayThresholdEcdsaAccountSigner` in base login
  - `ingestRelayThresholdEcdsaAccountSigners(...)` in base unlock/sync flows
- [x] Delete client smart-account files and references:
  - `client/src/core/signingEngine/flows/signEvmFamily/smartAccount*.ts`
  - `client/src/core/SeamsPasskey/near/linkDeviceOwnerManagement.ts`
  - smart-account branches in EVM display decoding unless they are required for
    generic contract-call display
  - smart-account config helpers and defaults
  - test helper fields such as `smartAccountDeploymentMode: 'observe'`
- [x] Delete server smart-account files, route definitions, exports, and hooks:
  - `server/src/router/smartAccount*.ts`
  - `server/src/router/evmSmartAccountDeploy.ts`
  - `server/src/router/*/routes/smartAccountDeployment.ts`
  - `server/src/core/smartAccount*.ts`
  - `server/src/core/evmSmartAccountDeploymentPlan.ts`
  - `server/src/core/SmartAccountRecoverySubjectStore.ts`
  - `smartAccountDeploy` relay hooks and route definitions
- [x] Delete shared and contract artifacts:
  - `shared/src/utils/evmSmartAccountSpec.ts`
  - `shared/src/utils/undeployedSmartAccountSignerSet.ts`
  - `contracts/evm-smart-account/**`
- [x] Delete smart-account-only helpers from the normal ECDSA path:
  - `buildRelaySignerEvmFamilyKey(...)` as a base warm-up repair source
  - smart-account `accountSigners` metadata enrichment as ECDSA readiness
  - `counterfactualAddress` fallback in normal threshold owner address flows
- [x] Delete smart-account registration/link record builders, routes, and tests.
- [x] Decide the fate of `AccountSignerStore` and local `accountSigners`:
  - server `AccountSignerStore` was smart-account-only and is deleted
  - local `accountSigners` remains as the generic signer lifecycle store
  - smart-account fields were removed from the local survivor
- [x] Add persistence-boundary cleanup:
  - local IndexedDB current schemas no longer include smart-account fields
  - server storage/schema creation no longer creates smart-account tables
- [x] Remove diagnostics that label normal ECDSA key identity as
      `smart-account-signers`.
- [x] Delete smart-account docs or mark future-only docs with the caveat above.

### Regression Coverage

- [x] Existing passkey wallet with no smart-account rows unlocks and warms ECDSA
      lanes for Tempo and all configured EVM targets.
- [x] Server diagnostics prove base ECDSA warm-up reads integrated key records
      when `AccountSignerStore` is empty.
- [x] Tempo signing succeeds after unlock for a normal threshold ECDSA wallet.
- [x] Arc/EVM signing succeeds after unlock for a normal threshold ECDSA wallet.
- [x] ECDSA key export succeeds after unlock for a normal threshold ECDSA
      wallet.
- [x] Any stale smart-account projection rows in local test fixtures cannot
      override the canonical threshold owner address from the integrated key record.
- [x] Registration, login, sync, link-device, export, EVM signing, Tempo
      signing, and demo helpers compile without smart-account config fields.
- [x] Runtime route inventory contains no `/smart-account/*` routes.
- [x] Public SDK type fixtures reject smart-account, counterfactual, paymaster,
      bundler, and ERC-4337 fields.
- [x] Static guard blocks smart-account/smart-wallet strings and imports across production,
      tests, examples, and docs, with explicit allowlist entries for this phase and
      future inactive plans that carry the caveat.
- [x] `rg -in "smart[-_ ]?(account|wallet)|smart(Account|Wallet)|counterfactual|ERC-4337|erc4337|account abstraction|paymaster|AccountSignerStore|recoveryAuthority|bundler(Url|URL|Rpc|RPC|Route|Endpoint|Policy|Mode|Config|Field)" docs client server shared tests examples contracts`
      returns only approved deletion-plan or future-plan caveat matches.

## Validation Commands

Run focused validation during implementation:

```bash
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C examples/seams-site typecheck
pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line
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
