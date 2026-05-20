# Refactor 39: Exact ECDSA Lane Consumption and Material Identity Split

Date created: 2026-05-17
Status: complete

## Problem

Refactor 37 made ECDSA signing depend on exact key and lane identity. Refactor
38 tightened session lifetime boundaries. The remaining weak spot is that some
ECDSA lifecycle operations can still be expressed as loose field-bag commands or
optional-heavy material objects.

The concrete regression was Email OTP ECDSA post-sign consumption. The old
operation marked Email OTP records consumed by `subjectId + chainTarget`. That
allowed one selected operation to consume sibling ECDSA records for the same
target. Those sibling records then appeared as multiple exhausted candidates for
the same key, often with the same `updatedAtMs`, which made export selection
ambiguous.

The same class of issue exists in broader form:

- Consumption APIs can accept lookup fields instead of exact selected lane
  identity.
- `EvmFamilyEcdsaKeyIdentity` mixes ownership, auth origin, HSS key identity,
  threshold topology, and funds address into one struct.
- `ThresholdEcdsaSecp256k1KeyRef` mixes public key identity, session identity,
  signer transport, client share handles, and export material, with many fields
  optional.
- Optional key/session/material fields allow stale or partial states to leak past
  boundaries.

## Target Invariants

- A post-sign consumption command can target only the exact selected single-use
  Email OTP ECDSA lane.
- Core consumption code cannot scan by `subjectId + chainTarget` or other broad
  lookup fields.
- Key identity, auth binding, session lane, signer transport, and export
  artifact are separate domain objects.
- Core signing code receives ready branch-specific signer material with required
  fields.
- `ThresholdEcdsaSecp256k1KeyRef` is isolated as a boundary adapter during the
  transition, then deleted or narrowed after signer call sites move to precise
  material.

## Refactor Gates

This plan has separate shipping gates. Gate A is the urgent regression fix and
should be shippable on its own. Later gates are larger identity, storage, and
SDK API redesigns.

- **Refactor 39A: exact single-use consumption.** Replace field-bag Email OTP
  ECDSA consumption with exact selected-lane commands and typed results.
- **Refactor 39B: ECDSA identity simplification.** Collapse base ECDSA
  `subjectId`, introduce opaque `keyHandle`, and migrate stores.
- **Refactor 39C: ready material and key-ref isolation.** Replace core
  `ThresholdEcdsaSecp256k1KeyRef` usage with branch-specific ready material.
- Budget and step-up invariants are intentionally out of scope for Refactor 39.
  See `docs/refactor-40.md`.

## Canonical Builders

Keep the new domain vocabulary small. Add a few canonical builders and route
call sites through them instead of introducing parallel identity shapes.

- `toExactEcdsaLaneIdentity(record | selectedLane)`
- `toConsumableEmailOtpPostSignMaterial(selectedMaterial)`
- `toVerifiedEcdsaPublicFacts(serverRecord | keyRef | durableRecord)`
- `toReadyEcdsaSignerSession(record, boundaryPayload)`
- `toSigningBudgetReservationIdentity(admission, operation)` in Refactor 40

## Phase 0: Inventory Current Escape Hatches

- [x] List every writer and caller of Email OTP ECDSA consumption APIs.
- [x] List every function/property surface that accepts
      `ThresholdEcdsaSecp256k1KeyRef` in core signing/export logic.
- [x] List every object spread that constructs `ThresholdEcdsaSecp256k1KeyRef`,
      `EvmFamilyEcdsaKeyIdentity`, `EvmFamilyEcdsaSessionLane`, or
      `SelectedEcdsaLane`.
- [x] List every optional ECDSA identity/session/material field in core paths.
- [x] Add guard coverage for broad consumption names.
- [x] Add guard coverage for direct ECDSA key-ref literal construction outside
      boundary files.
- [x] Add guard coverage for broad key-ref object spreads.
- [x] Produce a per-gate implementation checklist so 39A can land before 39B,
      39C, or Refactor 40.

Current object-spread inventory:

- Broad key-ref-to-key-ref spreads are confined to bootstrap normalization
  boundaries:
  `client/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts`,
  `client/src/core/signingEngine/session/emailOtp/routePlan.ts`,
  `client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`, and
  `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts`.
- Direct production `ThresholdEcdsaSecp256k1KeyRef` literals remain at the
  explicit boundary constructors already guarded in
  `tests/unit/signingEngine.refactor37.guard.unit.test.ts`.
- `EvmFamilyEcdsaKeyIdentity`, `EvmFamilyEcdsaSessionLane`, and ready material
  object construction stays behind the identity builders and compile-only type
  fixtures. The guard blocks direct typed construction and broad spreads outside
  those files.

Current optional-field inventory:

- Planning lane inputs in
  `client/src/core/signingEngine/session/operationState/lanes.ts` still use
  optional `backingMaterialSessionId`, `retention`, `activeSignerSlot`, and
  `sessionOrigin`. `SigningCapabilityReaderDeps` also accepts optional
  `signingRootId` and `signingRootVersion` for record/key-ref lookup.
- Resolved signing identity in
  `client/src/core/signingEngine/session/operationState/types.ts` still carries
  optional `backingMaterialSessionId`, `signingRootId`, and
  `signingRootVersion` on the shared base identity.
- ECDSA material summaries in
  `client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
  expose optional diagnostic `evmFamilyKeyFingerprint`, `signingRootId`,
  `signingRootVersion`, and `ecdsaThresholdKeyId`, while builder inputs use
  optional `record` / `keyRef` while selecting between missing and ready
  material.
- Email OTP ECDSA signing/public boundaries in
  `client/src/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession.ts`
  and `client/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts`
  still accept optional `ecdsaThresholdKeyId`, `participantIds`, session kind,
  TTL, remaining uses, route auth, and runtime policy. These are request/boundary
  compatibility surfaces and should narrow after key-handle routing lands.
- ECDSA signing flow orchestration in
  `client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts` still
  has optional `thresholdEcdsaKeyRef`, prepared-session arguments, and budget
  auth while the flow branches select cached, reauth, or fresh material.

## Phase 1 / Refactor 39A: Exact Single-Use ECDSA Consumption

The stronger consumption model is command-based. The selected material should
carry one exact runtime lane ref. Persistence should update exactly that lane
with stale-record detection by loading the stored record, recomputing the
existing `thresholdEcdsaLaneKey`, and validating the selected identity.

39A deliberately uses the existing `recordsByLane` /
`thresholdEcdsaLaneKey(record)` model. The pre-key-handle and key-handle lane
key versions belong to 39B.

39A is limited to exact selected-lane Email OTP consumption. Do not implement
budget freshness, step-up policy, projection, OTP refresh, or reservation
identity changes in this gate; those belong to Refactor 40.

### Target Types

```ts
type ThresholdEcdsaRuntimeLaneKey = string & {
  readonly __brand: 'ThresholdEcdsaRuntimeLaneKey';
};

type PositiveRemainingUses = number & {
  readonly __brand: 'PositiveRemainingUses';
};

type ExactEcdsaLaneIdentity = {
  kind: 'exact_ecdsa_lane_identity';
  walletId: WalletId;
  authMethod: 'email_otp';
  chainTarget: ThresholdEcdsaChainTarget;
  key: EvmFamilyEcdsaKeyIdentity;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

type ExactEcdsaRuntimeLaneRef = {
  kind: 'exact_ecdsa_runtime_lane_ref';
  laneKey: ThresholdEcdsaRuntimeLaneKey;
  exactIdentity: ExactEcdsaLaneIdentity;
  expectedUpdatedAtMs: number;
};

type ConsumableEmailOtpEcdsaLane = {
  kind: 'consumable_email_otp_ecdsa_lane';
  laneRef: ExactEcdsaRuntimeLaneRef;
  remainingUses: 1;
  consumedAtMs: null;
};

type SessionEmailOtpEcdsaLane = {
  kind: 'session_email_otp_ecdsa_lane';
  laneRef: ExactEcdsaRuntimeLaneRef;
  remainingUses: PositiveRemainingUses;
  consumedAtMs?: never;
};

type EmailOtpEcdsaPostSignMaterial = ConsumableEmailOtpEcdsaLane | SessionEmailOtpEcdsaLane;

type ConsumeSingleUseEmailOtpEcdsaLaneCommand = {
  kind: 'consume_single_use_email_otp_ecdsa_lane';
  lane: ConsumableEmailOtpEcdsaLane;
  uses: 1;
  subjectId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
  walletSigningSessionId?: never;
};

type ConsumeSingleUseEmailOtpEcdsaLaneResult =
  | {
      kind: 'consumed';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      consumedAtMs: number;
    }
  | {
      kind: 'already_consumed';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      consumedAtMs: number;
    }
  | {
      kind: 'missing_lane';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
    }
  | {
      kind: 'stale_record';
      laneKey: ThresholdEcdsaRuntimeLaneKey;
      reason:
        | 'lane_key_mismatch'
        | 'updated_at_mismatch'
        | 'wallet_mismatch'
        | 'key_identity_mismatch'
        | 'auth_method_mismatch'
        | 'chain_target_mismatch'
        | 'session_identity_mismatch'
        | 'retention_mismatch';
    };
```

### Tasks

- [x] Add `toExactEcdsaLaneIdentity(record | selectedLane)` at the availability
      boundary.
- [x] Add `toConsumableEmailOtpPostSignMaterial(selectedMaterial)` that returns
      `ConsumableEmailOtpEcdsaLane` only for the selected single-use Email OTP
      ECDSA lane.
- [x] Add a boundary builder that turns a normalized stored record into
      `EmailOtpEcdsaPostSignMaterial` without exposing broad persistence fields to
      core logic.
- [x] Brand the existing `thresholdEcdsaLaneKey(record)` output as
      `ThresholdEcdsaRuntimeLaneKey`.
- [x] Replace `markThresholdEcdsaEmailOtpSessionConsumedForLane` with
      `consumeSingleUseEmailOtpEcdsaLane(command)`.
- [x] Make `consumeSingleUseEmailOtpEcdsaLane` update `recordsByLane` by exact
      `laneKey`.
- [x] Recompute the canonical lane key from the stored record and require it to
      match `command.lane.laneRef.laneKey`.
- [x] Require wallet id, key identity, auth method, chain target,
      `thresholdSessionId`, `walletSigningSessionId`, source, Email OTP retention,
      and `updatedAtMs` to match `command.lane.laneRef.exactIdentity` and
      `expectedUpdatedAtMs` before consuming.
- [x] Return `ConsumeSingleUseEmailOtpEcdsaLaneResult` instead of throwing for
      expected stale, missing, or already-consumed outcomes.
- [x] Delete consumption helpers that accept `subjectId`, `chainTarget`,
      `walletSigningSessionId`, or `thresholdSessionId` as loose inputs.
- [x] Update post-sign policy to switch on `EmailOtpEcdsaPostSignMaterial.kind`.
- [x] Build consumption commands only from the actually selected signer
      material. Secondary Email OTP material is read-only reauth/display context and
      cannot create a consume command.
- [x] Add type fixtures proving session-retained Email OTP material cannot be
      passed to the consume command.
- [x] Add type fixtures proving secondary material cannot create
      `ConsumeSingleUseEmailOtpEcdsaLaneCommand`.
- [x] Add regression tests with two same-target Email OTP ECDSA records where
      only the selected exact lane is consumed.
- [x] Add regression tests for stale record, missing lane, already consumed,
      chain-target mismatch, key-identity mismatch, and updated-at mismatch.

### 39A Completion Criteria

- [x] Core consumption has no subject/target field-bag API.
- [x] Post-sign policy consumes selected material only.
- [x] Exact consume returns typed results for consumed, already consumed,
      missing lane, and stale record.
- [x] ECDSA export no longer sees ambiguous same-key exhausted candidates caused
      by sibling Email OTP record consumption.

## Phase 2 / Refactor 39B: ECDSA Identity Simplification

`EvmFamilyEcdsaKeyIdentity` already has strong branch exclusions. 39B should
avoid splitting identity for its own sake. Introduce a canonical key handle and
a boundary facade around `VerifiedEcdsaPublicFacts`, then split narrower
public/auth/target views only at call sites where the narrower input removes a
real invalid state.

This phase should also decide which IDs are real client-side invariants. The
goal is to reduce the SDK's exposure to threshold-signing internals and avoid
moving the same fields into more structs.

### Threat Model Update Required Before 39B

Refactor 37 intentionally included `subjectId` and `rpId` in shared ECDSA key
identity. 39B may collapse or relocate those fields only after documenting where
their security checks live.

- `subjectId` collapse is safe for base ECDSA only if base ECDSA has exactly one
  signing subject per wallet and every server/session route derives that subject
  from authenticated `walletId`.
- `rpId` can move out of funds-key identity only if passkey and sealed-restore
  boundaries validate it before material enters ready signing state.
- Email OTP must retain provider/user binding. `authSubjectId` and provider
  identity move into the Email OTP auth binding and are validated before worker
  material or HSS session material becomes ready.
- The funds-safety invariant remains: a key handle must verify to the expected
  wallet, participant set, public key, and threshold owner address before any
  lane is admitted.
- Public SDK request shapes should carry wallet/session/target intent once
  `keyHandle` is available.

### Current Validation Locations

Keep these checks authoritative before removing fields from the existing shared
identity:

- Client key identity builders:
  `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  validates wallet id, `subjectId`, `rpId`, threshold key id, signing root,
  participant ids, and owner address in
  `buildEvmFamilyEcdsaKeyIdentityFromRecord`,
  `buildEvmFamilyEcdsaKeyIdentityFromKeyRef`, and
  `resolveReadyEvmFamilyEcdsaMaterial`.
- Selected lane validation:
  `client/src/core/signingEngine/session/identity/laneIdentity.ts`
  `selectedEcdsaLane(...)` requires the selected lane's wallet, subject,
  threshold key id, and signing root fields to match the shared key identity.
- 39A exact Email OTP consumption:
  `client/src/core/signingEngine/session/persistence/records.ts`
  `toExactEcdsaLaneIdentity(...)` and
  `consumeSingleUseEmailOtpEcdsaLane(...)` bind selected-lane consumption to the
  exact wallet, auth method, chain target, key identity, session ids, source,
  retention, and `updatedAtMs`.
- Server integrated key records:
  `server/src/core/types.ts` `ThresholdEcdsaIntegratedKeyRecord` requires
  `thresholdEcdsaPublicKeyB64u`, `ethereumAddress`, `participantIds`,
  `subjectId`, `rpId`, threshold key id, and signing-root metadata.
  `server/src/core/ThresholdService/validation.ts`
  `parseThresholdEcdsaIntegratedKeyRecord(...)` rejects records missing those
  facts.
- Server key uniqueness and signing authorization:
  `server/src/core/ThresholdService/stores/KeyStore.ts` and
  `server/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
  guard wallet, subject, `rpId`, and signing root against threshold key id,
  owner address, and participant ids. `server/src/core/ThresholdService/`
  `ecdsaSigningHandlers.ts` checks integrated-key wallet, `rpId`,
  participant ids, signing root, and persisted public key before signing.
- Email OTP auth binding:
  server and worker storage require `authSubjectId` for device/recovery escrow,
  while client `ThresholdEcdsaEmailOtpAuthContext.authSubjectId` is still
  optional. 39B must make provider/user binding branch-specific at the Email OTP
  boundary before building `EvmFamilyEcdsaAuthBinding`.

### 39B Surface Inventory

- `ThresholdEcdsaSecp256k1KeyRef` currently flows through 32
  `client/src/core/signingEngine/**/*.ts` files. The acceptors cluster in
  boundary wiring (`SigningEngine`, assembly ports, operation deps), warm
  capability/provision planning, EVM-family signing flow selection and
  readiness, recovery/export, and identity validation.
- Concrete production `ThresholdEcdsaSecp256k1KeyRef` object construction is
  concentrated in four locations:
  `client/src/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.ts`,
  `client/src/core/signingEngine/session/persistence/records.ts`,
  `client/src/core/signingEngine/threshold/ecdsa/activation.ts`, and
  `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`.
- `EvmFamilyEcdsaKeyIdentity` / `SelectedEcdsaLane` usage spans 35
  `client/src/core/signingEngine/**/*.ts` files. The highest-leverage 39B
  targets are the identity builders, `ecdsaLanes.ts`,
  `ecdsaMaterialState.ts`, `ecdsaSelection.ts`, `ecdsaReadiness.ts`,
  `preparedSigning.ts`, and `ecdsaExportMaterial.ts`.
- The first 39B implementation slice should introduce
  `EvmFamilyEcdsaKeyHandle`, `VerifiedEcdsaPublicFacts`, and boundary builders
  from server records, key refs, and durable records. Keep existing
  `EvmFamilyEcdsaKeyIdentity` as the backing validated input while the facade
  lands, then narrow individual signing/export call sites to public facts only
  where owner/public-key/participant data is needed.
- Add guard coverage for direct key-ref literals and broad object spreads before
  deleting fields from shared key identity.

### Target Types

```ts
type EvmFamilyEcdsaKeyHandle = string & {
  readonly __brand: 'EvmFamilyEcdsaKeyHandle';
};

type VerifiedEcdsaPublicFacts = {
  kind: 'verified_ecdsa_public_facts';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  publicKeyB64u: string;
  participantIds: readonly ParticipantId[];
  thresholdOwnerAddress: ThresholdOwnerAddress;
};

type EvmFamilyEcdsaAuthBinding =
  | {
      kind: 'passkey_ecdsa_auth_binding';
      authMethod: 'passkey';
      rpId: RpId;
    }
  | {
      kind: 'email_otp_ecdsa_auth_binding';
      authMethod: 'email_otp';
      authSubjectId: string;
      providerId: EmailOtpProviderId;
    };

type ResolvedEvmFamilyEcdsaKey = {
  kind: 'resolved_evm_family_ecdsa_key';
  walletId: WalletId;
  publicFacts: VerifiedEcdsaPublicFacts;
  authBinding: EvmFamilyEcdsaAuthBinding;
};
```

### First Increment Status

- [x] Add `EvmFamilyEcdsaKeyHandle` and `VerifiedEcdsaPublicFacts`.
- [x] Add SHA-256/base64url key-handle derivation over normalized
      threshold-key and signing-root fields at the current client boundary.
- [x] Add public-facts builders from runtime records, key refs, and durable
      sealed record metadata.
- [x] Require verified compressed public-key bytes before constructing
      `VerifiedEcdsaPublicFacts`.
- [x] Reject ready ECDSA record/key-ref material when their public keys drift
      before building signing or export material.
- [x] Add type fixtures rejecting threshold-key, signing-root, `subjectId`, and
      `rpId` fields on public facts.
- [x] Add focused unit tests for key-handle derivation, public-facts builders,
      durable metadata, and invalid public-key data.
- [x] Move fresh Email OTP ECDSA export material to carry
      `VerifiedEcdsaPublicFacts` for public key and participant data.
- [x] Move ready ECDSA export material to compose signer session material with
      `VerifiedEcdsaPublicFacts`.
- [x] Move the fresh Email OTP ECDSA export dependency boundary to accept
      `VerifiedEcdsaPublicFacts` for participant data.
- [x] Move prepared EVM-family signing executor owner-address selection to
      `VerifiedEcdsaPublicFacts`.
- [x] Resolve prepared EVM-family signing executor owner facts through the
      paired ready-material public-facts builder.
- [x] Move Email OTP ECDSA signing-session refresh participant routing to
      `VerifiedEcdsaPublicFacts`.
- [x] Move the Email OTP ECDSA signing-session refresh dependency boundary to
      accept `VerifiedEcdsaPublicFacts` for participant data.
- [x] Move passkey reconnect policy participant routing to
      `VerifiedEcdsaPublicFacts`.
- [x] Move warm-session ECDSA presignature cleanup participant routing to
      `VerifiedEcdsaPublicFacts`.
- [x] Remove lane-owner echo checks from shared ECDSA record/key-ref matching;
      owner drift is covered by canonical key fingerprint comparison.
- [x] Move secp256k1 signer public-key and participant routing to
      `VerifiedEcdsaPublicFacts` at the key-ref boundary.
- [x] Remove raw participant/owner snapshots from ECDSA signing and export
      lane diagnostics; use the canonical EVM-family key fingerprint instead.
- [x] Remove raw threshold-key and signing-root fields from ECDSA material-state
      diagnostics; keep the canonical EVM-family key fingerprint.
- [x] Move signing/export call sites to accept `VerifiedEcdsaPublicFacts` where
      they only need owner/public-key/participant data.
- [x] Add `ReadyEcdsaSignerSession` with branch-specific transport auth and
      builder-owned inline vs Email OTP worker share material.
- [x] Move the secp256k1 commit path and explicit HSS export adapter onto
      `ReadyEcdsaSignerSession` after the key-ref boundary.
- [x] Require ECDSA reauth/admission results to carry ready signer-session
      material alongside the temporary key-ref boundary field.
- [x] Route signing-flow secp256k1 admission results through ready
      signer-session material.
- [x] Route signing-flow key-ref fallback through the ready material boundary
      before secp256k1 commit.
- [x] Thread budget-admitted prepared ECDSA operations into signing flow as
      ready signer-session material so admitted signing can skip key-ref fallback.
- [x] Add focused ready-signer handoff coverage proving admitted ECDSA signing
      uses ready material without requiring key-ref fallback.
- [x] Move secp256k1 key-ref fallback normalization into a named boundary
      builder; the fallback signer method now queues and signs ready material only.
- [x] Route ready ECDSA export material through the ready-material signer-session
      helper instead of constructing export signer sessions directly from key refs.
- [x] Add a ready-material public-facts builder that validates paired record and
      key-ref public facts before signer/export material receives them.
- [x] Reuse the paired record/key-ref public-facts builder for passkey ECDSA
      reconnect session-policy participant routing.
- [x] Move cached HSS export artifact provenance onto
      `ReadyEvmFamilyEcdsaMaterial` so export material no longer reads optional
      key-ref artifact fields.
- [x] Move signing-key routing context onto `ReadyEvmFamilyEcdsaMaterial` so
      material-state summaries no longer rebuild it from key refs.
- [x] Let the ready signer-session builder own secp256k1 fallback transport
      validation before canonical record transport comparisons.
- [x] Add `ReadyThresholdEcdsaSession` as the owner for ready session ids plus
      known or unavailable session-policy provenance.
- [x] Add `ResolvedEvmFamilyEcdsaKey` and branch-specific auth bindings.
- [x] Keep server/Postgres canonical key-handle migration for the later 39B
      schema slice.

### ID Collapse Decisions

- `walletId` remains the wallet and signing-budget namespace.
- `subjectId` is collapsed into `walletId` for base ECDSA. Base ECDSA has one
  protocol-neutral signing subject: the wallet. Delete `subjectId` from ECDSA
  lane keys, selected lanes, ready material, and client-side public/internal
  ECDSA request shapes.
- `rpId` moves to auth/restore binding. It is relevant for passkey origin and
  sealed restore trust, not funds-key identity.
- Email OTP auth binding carries `authSubjectId` and provider identity. Those
  fields validate the OTP worker/HSS material boundary.
- `ecdsaThresholdKeyId + signingRootId + signingRootVersion` collapse behind one
  canonical opaque `EvmFamilyEcdsaKeyHandle` in client-facing SDK code.
- `publicKeyB64u`, `participantIds`, and `thresholdOwnerAddress` remain
  verified public key facts. They validate the server-issued handle and protect
  funds-address drift.

### Base ECDSA `subjectId` Collapse

Base ECDSA should use `walletId` as the only wallet/subject namespace. This
removes the confusing state where `walletId` and `subjectId` must be checked for
equality everywhere.

#### Tasks

- [x] Define `BaseEcdsaWalletId = WalletId` as the only base ECDSA subject
      namespace.
- [x] Add a guard pinning `BaseEcdsaWalletId` before the wider lane-key
      subject collapse.
- [x] Delete `subjectId` from `ThresholdEcdsaSessionRecordKey`.
- [x] Delete `subjectId` from `thresholdEcdsaLaneKey(...)`.
- [x] Re-key runtime ECDSA records by `walletId`, key handle, auth method,
      curve, chain target, wallet signing-session id, and threshold session id.
- [x] Replace ECDSA record indexes keyed by subject with wallet-keyed indexes.
- [x] Replace `WalletSubjectId` inputs in base ECDSA signing/export/unlock flows
      with `WalletId`.
  - [x] Remove caller-supplied `subjectId` from EVM-family `signTempo` and
        `executeEvmFamilyTransaction`; derive the base ECDSA subject from
        `walletSession.walletId` inside the signing flow.
  - [x] Remove caller-supplied `subjectId` from login/prefill ECDSA warm-up
        surfaces; derive wallet identity from `walletSession.walletId`.
  - [x] Remove caller-supplied `subjectId` from the public ECDSA export UI
        request and wallet-iframe export payloads.
  - [x] Remove caller-supplied `subjectId` from internal base ECDSA export-lane
        restore/selection; derive the base subject from `walletId` at the
        persisted-lane boundary.
  - [x] Remove caller-supplied `subjectId` from fresh Email OTP ECDSA export;
        derive the base subject from `walletSession.walletId` inside the
        recovery worker handoff.
  - [x] Remove caller-supplied `subjectId` from Email OTP ECDSA public
        login/enroll, iframe payload, and per-operation signing bridge inputs;
        derive the legacy worker/persistence subject from `walletSession.walletId`
        at the Email OTP ECDSA login/enrollment boundary.
  - [x] Remove caller-supplied `subjectId` from explicit threshold ECDSA export
        HSS prepare; derive the base subject from wallet identity at the
        relayer boundary.
  - [x] Remove caller-supplied `subjectId` from `reuse_warm_ecdsa_bootstrap`
        public and signing-engine request shapes; derive the base subject from
        `walletId` at the bootstrap boundary.
  - [x] Remove caller-supplied `subjectId` from target-branch passkey fresh,
        cookie reconnect, and Email OTP ECDSA bootstrap request shapes; derive
        the base subject from `walletId` inside `ecdsaBootstrap.ts`.
  - [x] Derive the legacy base-ECDSA subject from `walletId` inside core
        exact-session bootstrap, availability, material-resolution, and export
        helpers instead of reading `key.subjectId` as independent state.
- [x] Replace base ECDSA `AccountId`-typed wallet inputs with `WalletId` at
      wallet-domain boundaries; keep `AccountId` only for true NEAR account
      semantics and persistence/request normalization boundaries.
  - [x] Tighten read-only session-public wallet-target ECDSA lookup surfaces to
        `WalletId`.
  - [x] Tighten warm ECDSA status read APIs to `WalletId`.
  - [x] Tighten warm ECDSA presign-prefill and volatile-clear wallet APIs to
        `WalletId`.
  - [x] Tighten wallet-target ECDSA clear/delete and canonical-session resolver
        APIs to `WalletId`.
  - [x] Tighten the ECDSA signing-path available-lane read input to `WalletId`
        and normalize at prepared-signing callers.
  - [x] Tighten ECDSA-only warm-capability provisioner and bootstrap-readiness
        helpers to `WalletId`; normalize at bootstrap and test-store
        boundaries.
  - [x] Tighten ECDSA-only warm-capability status, post-sign, and operation
        policy request shapes to `WalletId`; normalize at thin runtime, test,
        and explicit-export boundaries.
  - [x] Tighten the ECDSA threshold signing-session readiness wrapper to
        `WalletId`; normalize at the signing runtime and unit-test boundaries.
  - [x] Tighten remaining EVM-family ECDSA flow modules and Tempo signer
        wrappers to carry `WalletId` through planning, refresh, runtime, and
        export/status edges; normalize only at the outer wallet-session
        boundary.
  - [x] Tighten threshold ECDSA bootstrap persistence public APIs to
        `WalletId`; normalize at the IndexedDB persistence and link-device
        boundaries.
  - [x] Tighten session-public threshold ECDSA bootstrap upsert APIs to
        `WalletId`; normalize at link-device and persistence-store boundaries.
  - [x] Tighten threshold ECDSA bootstrap activation dependency callbacks to
        `WalletId`; normalize at the bootstrap request boundary.
  - [x] Tighten shared ECDSA wallet-target listing ports to `WalletId`;
        normalize at mixed EVM-family assembly boundaries.
  - [x] Tighten ECDSA-only signing lookup helper inputs to `WalletId`;
        normalize at mixed EVM-family adapters and selection-flow boundaries.
  - [x] Tighten persistence-level ECDSA signing lookup helpers to `WalletId`;
        normalize at mixed adapter and test-fixture boundaries.
  - [x] Tighten ECDSA-only warm-capability store and exact-status readers to
        `WalletId`; normalize at provision, policy, and test-fixture
        boundaries.
  - [x] Tighten the restored-Ed25519 ECDSA login bootstrap API to `WalletId`;
        keep `AccountId` only at the stored-session persistence boundary.
  - [x] Tighten internal readiness lane discovery, wallet-scoped claim reads,
        and clear-session helpers to `WalletId`; normalize at the mixed
        signing-session coordinator boundary.
  - [x] Tighten the ECDSA-only Email OTP signing-session auth reader to
        `WalletId`; reject raw wallet ids at the exported signing-session
        challenge boundary.
  - [x] Tighten the link-device threshold ECDSA bootstrap helper to
        `WalletId`; normalize at the outer link-device account boundary.
  - [x] Tighten the ECDSA Email OTP signing-session auth-lane resolver callback
        to `WalletId`; source the callback wallet id from
        `walletSession.walletId`.
  - [x] Tighten the internal Email OTP enrollment bridge to `WalletId`;
        normalize at the outer SeamsPasskey registration boundary.
  - [x] Tighten the threshold ECDSA commit-queue path to `WalletId`; normalize
        at the `SigningEngine` queue wrapper and reject raw wallet ids in queue
        helpers/tests.
  - [x] Tighten the Email OTP threshold ECDSA bootstrap commit, publication,
        and sealed-recovery commit paths to `WalletId`; normalize to
        `AccountId` only at the IndexedDB bootstrap persistence boundary.
  - [x] Tighten the Email OTP ECDSA companion-record selector to `WalletId`;
        normalize at the Ed25519 warmup boundary and reject raw wallet ids in
        companion selection fixtures.
  - [x] Tighten the Email OTP wallet-session challenge worker path to
        `WalletId`; keep NEAR account challenge handling separate and reject raw
        wallet ids in wallet-session challenge fixtures.
  - [x] Tighten Email OTP Ed25519 export recovery runtime args to normalized
        `AccountId`; keep raw-string normalization outside the export recovery
        worker helper.
  - [x] Tighten the Email OTP NEAR-account challenge runtime branch to
        normalized `AccountId`; keep wallet-session and NEAR-account challenge
        branches distinct inside the export recovery worker helper.
  - [x] Tighten the NEAR Ed25519 Email OTP export flow dependency to the exact
        `near_account_challenge` branch instead of the broader mixed challenge
        union.
  - [x] Split recovery Email OTP export authorization deps by exact branch:
        wallet-session ECDSA export helpers now require the wallet-session
        challenge callback, and NEAR Ed25519 export helpers require the
        near-account challenge callback.
  - [x] Split shared Email OTP transaction-signing challenge callbacks by exact
        branch across assembly and signing adapters: EVM-family flows now use
        the wallet-session callback shape and NEAR flows use the near-account
        callback shape.
  - [x] Tighten NEAR Email OTP transaction-signing challenge, warmup, and
        Ed25519 signing helper deps to exact `AccountId` inputs; keep request
        normalization at the outer runtime boundary.
  - [x] Tighten the ECDSA signing-session Email OTP challenge bridge to the
        exact wallet-session challenge branch; reject near-account challenge
        shapes in compile-only fixtures.
  - [x] Tighten NEAR Email OTP consumed-session, warmup, and Ed25519
        signing-runtime helpers to exact `AccountId`; normalize once at the
        mixed readiness boundary before touching persistence.
  - [x] Tighten NEAR warm-capability Ed25519 status/store readers and the
        passkey Ed25519 provision helper to exact `AccountId`; keep raw account
        normalization at the public warm-session boundary.
  - [x] Tighten internal NEAR Ed25519 persistence, reconnect, commit-queue,
        and credential-derived lifecycle helpers to exact `AccountId`; keep the
        mixed assembly/runtime edges as the remaining normalization boundary.
  - [x] Tighten internal SeamsPasskey NEAR warm-session bootstrap, restore, and
        login/registration event helpers to exact `AccountId`; keep broader
        account parsing only at true public entrypoints.
  - [x] Tighten shared internal budget projection, budget-status, readiness
        override, and transaction-intent helper shapes to exact normalized ids:
        use `AccountId` for mixed wallet/NEAR helpers and `WalletId` for
        ECDSA-only transaction/commit-queue assembly seams; keep raw parsing at
        outer public boundaries.
  - [x] Replace shared `walletId: AccountId | WalletId` helper fields with a
        discriminated owner identity, for example
        `{ curve: 'ed25519'; accountId: AccountId } |
        { curve: 'ecdsa'; walletId: WalletId }`, so shared budget/readiness
        code keeps branch identity explicit instead of relying on a mixed
        `walletId` property name.
  - [x] Thread the owner identity through shared budget status checks,
        budget consume inputs, readiness status overrides, and wallet-signing
        consume helpers; keep branch-specific callers responsible for building
        the exact owner at their normalization boundary.
  - [x] Add compile-only fixtures rejecting wrong-branch owner shapes on shared
        budget/readiness inputs, including NEAR owner with `walletId`, ECDSA
        owner with `accountId`, and owner-less status checks.
  - [x] Require strict branded NEAR owner ids at internal budget/readiness
        boundaries so compile-only fixtures reject raw account strings, while
        keeping outer public/test entrypoints normalized at boundaries.
  - [x] Rename shared helper fields and readiness internals from generic
        `walletId` to `owner` or `walletOwner` where the value may be either
        NEAR account identity or base-ECDSA wallet identity.
  - [x] Audit trace/debug payload field names that still say `walletId` for
        mixed NEAR/ECDSA owner identity and rename them only where the payload
        is not explicitly wallet-domain data.
- [x] Keep `WalletSubjectId` only for NEAR account or future multi-subject
      features that explicitly need a separate subject namespace.
  - [x] Delete dead base-ECDSA `subjectId` plumbing from internal warm-session
        key-ref listing and reusable-bootstrap helper paths.
  - [x] Delete duplicate base-ECDSA `subjectId` inputs from reconnect plan
        builders; derive reconnect subject from exact paired record/key-ref
        material.
  - [x] Delete duplicate base-ECDSA `subjectId` inputs from passkey and Email
        OTP provision builders; derive provision subject from exact key
        identity.
  - [x] Delete duplicated base-ECDSA `subjectId` from stored warm-capability
        provision plan shapes; store exact key identity where provision plans
        need a durable subject source.
  - [x] Delete caller-supplied `subjectId` from persisted base-ECDSA available
        lane and snapshot readers; derive subject from `walletId` at the
        availability boundary.
  - [x] Switch persisted base-ECDSA runtime available-lane discovery from
        subject-keyed scans to the wallet-keyed runtime lane index.
  - [x] Delete subject-scoped runtime ECDSA lane listing helpers; wallet-scoped
        runtime lane readers are now the only exported base-ECDSA path.
  - [x] Delete subject-target ECDSA session inventory and loose lane-clear
        helper usage from browser/runtime test harnesses; wallet-target session
        APIs are now the only base-ECDSA helper path there too.
  - [x] Prune conflicting current passkey runtime ECDSA records during
        bootstrap/store upsert so each wallet-target keeps one current
        passkey-backed runtime lane.
  - [x] Delete dead `subjectId` from internal ECDSA warm-capability readiness
        request shapes.
  - [x] Derive base-ECDSA subject from `walletId` inside signer adapters,
        reconnect/provision planning, passkey recovery publication, bootstrap
        record normalization, and Email OTP export/publication helpers; keep
        raw stored/request `subjectId` only at compatibility boundaries.
  - [x] Delete caller-supplied base-ECDSA `subjectId` from passkey sealed-session
        refresh and persist writes; current ECDSA sealed records now validate
        `subjectId` only when compatibility metadata is present.
  - [x] Derive base-ECDSA subject from `walletId` inside availability/readiness
        core matching and lane dedupe; keep persisted `subjectId` only for
        compatibility parsing and diagnostics.
  - [x] Stop treating persisted ECDSA sealed-record `subjectId` as required
        current state; validate it once at the sealing boundary when present,
        then normalize current sealed records and durable-lane diagnostics around
        `walletId + keyHandle + chainTarget`.
  - [x] Derive base-ECDSA subject from `walletId` inside sealed-recovery
        normalization so current passkey restore paths no longer depend on
        persisted ECDSA `subjectId`.
- [x] Delete ECDSA mismatch branches that compare `walletId` and `subjectId`.
  - [x] Remove duplicate subject comparisons from base ECDSA selected-lane,
        budget, and export matching paths; use the shared ECDSA key identity as
        the canonical subject source.
  - [x] Remove duplicate subject comparisons from persisted availability,
        reconnect material, warm-capability exactness checks, and restored-login
        ECDSA bootstrap validation.
- [x] Add type fixtures rejecting `subjectId` on base ECDSA key identity, lane
      identity, available-lane candidates, ready material, and public request
      shapes.
  - [x] Add compile-only fixtures rejecting `subjectId` on base ECDSA selected
        lane inputs and planning-lane shapes.
  - [x] Add compile-only fixtures rejecting top-level `subjectId` on base ECDSA
        available-lane candidate inputs and ready signer/material shapes.
  - [x] Add compile-only fixtures rejecting `subjectId` on public base-ECDSA
        sign, execute, export, and reusable-bootstrap request shapes.
  - [x] Add compile-only fixtures rejecting `subjectId` on the
        `ResolvedEvmFamilyEcdsaKey` facade.
  - [x] Remove `subjectId` from the legacy broad `EvmFamilyEcdsaKeyIdentity`
        shape after resolved-key propagation reaches lane/session defaults, then
        flip this parent guard item complete.
- [x] Add a guard that blocks `subjectId` in base ECDSA lane key and selected
      lane types.
  - [x] Add a guard asserting base ECDSA selected/planning lane declarations
        derive subject from shared key identity instead of carrying a duplicate
        `subjectId` field.
  - [x] Extend that guard to base ECDSA available-lane and ready signer/material
        declarations.
  - [x] Extend the same protection to internal constructor call sites so base
        ECDSA lane builders cannot be fed a duplicate `subjectId` object field.

### Canonical Opaque ECDSA Key Handle

The client should stop carrying `ecdsaThresholdKeyId`, `signingRootId`, and
`signingRootVersion` through core logic. The server should expose one opaque key
handle that already commits to the threshold key and signing-root metadata.

The server may still store and index `ecdsaThresholdKeyId`, `signingRootId`, and
`signingRootVersion` internally. Those fields should be server-side
implementation details behind `EvmFamilyEcdsaKeyHandle`.

#### Target Server Model

```ts
type EvmFamilyEcdsaKeyHandle = string & {
  readonly __brand: 'EvmFamilyEcdsaKeyHandle';
};

type ServerEcdsaKeyIdentity = {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  thresholdKeyId: string;
  signingRoot: {
    id: string;
    version: string;
  };
  participantIds: readonly number[];
  thresholdOwnerAddress: string;
  publicKeyB64u: string;
};
```

#### Canonical Key Handle Derivation

The handle must be deterministic, versioned, and domain-separated. The client
should treat it as opaque.

```ts
type EcdsaKeyHandleDerivationInput = {
  domain: 'seams.threshold_ecdsa.key_handle.v1';
  namespace: string;
  thresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
};
```

Derivation rules:

- [x] Normalize `signingRootVersion` to the server default before hashing.
- [x] Encode fields with length-prefixed UTF-8 or canonical JSON with sorted
      keys. Delimiter-concatenated strings are disallowed.
- [x] Hash with SHA-256 and encode with base64url:

  ```ts
  keyHandle = `ehss-key-${base64url(sha256(canonicalBytes(input)))}`;
  ```

- [x] Move the canonical key-handle encoder into a shared utility so client,
      server, and store migrations use one hash recipe.
- [x] Persist the derived key handle on server ECDSA key records at key-store
      write/read boundaries.
- [x] Enforce uniqueness within `namespace`.
- [x] Treat key-handle collisions as fatal server key-store integrity errors
      for in-memory, Redis, Upstash, Postgres, and Cloudflare Durable Object
      stores.
- [x] Reject persisted key handles that do not match the stored threshold key
      id and signing-root identity.
- [x] Verify public facts whenever a handle is resolved: owner address,
      participant ids, public key, threshold key id, signing-root id, and
      signing-root version must match the server record.
- Remaining SDK public cleanup is grouped under Batch 1 in the execution plan
      below.

#### Postgres Migration Plan

The current Postgres bootstrap creates `threshold_ecdsa_keys(namespace,
relayer_key_id, record_json)` and signing-root share tables keyed by
`signing_root_id + signing_root_version`. Refactor to make the ECDSA key handle
the primary application key for integrated ECDSA records.

- [x] Add `key_handle TEXT` to `threshold_ecdsa_keys` with
      `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
- [x] Backfill `key_handle` for existing records from a deterministic server
      function using the canonical derivation above.
- [x] Add `threshold_key_id TEXT`, `signing_root_id TEXT`,
      `signing_root_version TEXT`, `owner_address TEXT`, and `public_key_b64u TEXT`
      columns with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
- [x] Backfill those columns from `record_json`.
- [x] Add `NOT NULL` constraints after backfill validation passes.
- [x] Add `UNIQUE(namespace, key_handle)` after duplicate checks pass.
- [x] Add `UNIQUE(namespace, threshold_key_id, signing_root_id,
signing_root_version)` if the server should enforce one handle per concrete
      HSS root binding.
- [x] Add lookup indexes for `(namespace, owner_address)` and
      `(namespace, key_handle)`.
- [x] Update ECDSA authorize server path to resolve public `keyHandle`
      selectors through `getByKeyHandle`.
- [x] Update ECDSA presign init server path to resolve public `keyHandle`
      selectors through the key store.
- [x] Update ECDSA presign init client path to emit exactly one key selector at
      the relayer request boundary.
- [x] Move HSS bootstrap/upsert paths with signing-root metadata to key-handle
      store reads and writes.
- [x] Update remaining server key read/write paths to load by `key_handle`.
- [x] Update HSS finalize/bootstrap responses to return `keyHandle` as the
      client-facing key id.
- [x] Update signing/session JWT claims to carry `keyHandle`.
- [x] Keep threshold-key/signing-root fields only in server-private claims if
      still needed for internal validation.
- [x] Remove threshold-key identity from threshold-ECDSA session JWT claims and
      wallet-budget auth requests.
- [x] Update ECDSA authorize route/client request to accept `keyHandle`.
- [x] Update wallet signing budget status parsing to carry verified ECDSA
      `keyHandle` auth.
- [x] Validate wallet signing budget status requests against the exact
      threshold-session identity at the relayer boundary so stale threshold
      JWTs cannot satisfy a different ECDSA lane.
- [x] Update HSS session-bootstrap and explicit-export prepare paths to accept
      `keyHandle`.
- [x] Update HSS prepare client path to build request bodies from a strict
      `ThresholdEcdsaHssKeySelector`.
- [x] Resolve explicit-export HSS ceremony finalization by stored `keyHandle`.
- [x] Update session inventory routes/client parsing to accept and return
      `keyHandle`.
- [x] Verify signing init/finalize remain `mpcSessionId`/`signingSessionId`
      continuations anchored by authorize, with no separate public key selector.
- [x] Remove threshold-key-id selector support from ECDSA authorize and presign
      init, and resolve sign-init continuations by the MPC session `keyHandle`.
- [x] Remove threshold-key-id selector support from ECDSA HSS prepare and key
      identity inventory request boundaries.
- Remaining client request cleanup is grouped under Batch 1 in the execution
      plan below.
  - [x] Remove `ecdsaThresholdKeyId` from fresh Email OTP ECDSA export material
        and the Email OTP export/runtime request boundary; fresh export now uses
        `keyHandle + VerifiedEcdsaPublicFacts` only.
  - [x] Remove `ecdsaThresholdKeyId` from Email OTP existing-key bootstrap
        request args; the worker/public login-enrollment boundary now uses
        `keyHandle` as the only existing-key selector.
  - [x] Remove `ecdsaThresholdKeyId` from SeamsPasskey threshold-login warm
        inventory/bootstrap request boundaries; wallet-target warm context now
        resolves exact `keyHandle` end to end.
  - [x] Remove `signingRootId` / `signingRootVersion` from the public
        wallet-target ECDSA session inventory listing surface; client session
        listing is exact `walletId + chainTarget (+ source)` only.
  - [x] Thread canonical `keyHandle` through Email OTP sealed ECDSA rehydrate
        requests and exact session bootstrap; the worker no longer derives the
        exact restore handle inline.
  - [x] Align the top-level Email OTP worker request contract with the exact
        sealed-rehydrate restore payload so `keyHandle` is required there too.
  - [x] Derive the base ECDSA restore `subjectId` inside the worker from
        `walletId`; sealed rehydrate requests no longer ship redundant
        base-subject data.
  - [x] Derive the sealed-restore worker `userId` from `walletId`; the exact
        rehydrate request no longer carries a duplicate wallet-scoped user id.
  - [x] Split exact `session_bootstrap` away from broad
        `EvmFamilyEcdsaKeyIdentity`; sealed restore now passes only the exact
        wallet/rp/key-id/participants context the worker consumes.
  - [x] Drop `ethereumAddress` from the sealed ECDSA rehydrate request
        boundary; that field is no longer needed to reconstruct bootstrap
        identity.
  - [x] Move `signingRootId` / `signingRootVersion` off the top-level ECDSA
        rehydrate request and onto the Ed25519 companion restore branch, where
        they are actually consumed.
  - [x] Require exact ECDSA and companion-Ed25519 `participantIds` on the
        sealed rehydrate worker request boundary; the worker no longer accepts
        missing participant identity and validates it ad hoc in core flow.
  - [x] Normalize the sealed ECDSA rehydrate request once at worker entry into
        an exact restore shape before bootstrap; core restore no longer
        repeatedly re-reads raw request fields.
  - [x] Delete the dead sealed ECDSA rehydrate `derivationPath` request field;
        that payload never influenced exact restore/bootstrap.
- [x] Delete JSON parsing paths that reconstruct key identity from scattered
      threshold-key and signing-root fields at SDK boundaries.
  - [x] Remove `ecdsaThresholdKeyId` from exact sealed restore/bootstrap
        boundaries; Email OTP sealed ECDSA rehydrate now keys exact
        session-bootstrap by `keyHandle` plus exact lane/session identity.
  - [x] Remove remaining exact sealed-restore `signingRoot*` fields by deriving
        companion Ed25519 restore inputs from verified runtime policy scope
        metadata before worker rehydrate/bootstrap.
- Remaining JSON-only lookup cleanup is grouped under Batch 1 in the execution
      plan below.

Short-term migration pain is acceptable. Prefer one clean schema pass over
keeping parallel client-facing identities.

#### Store-by-Store API Changes

The key store abstraction currently exposes threshold-key-id lookup. Every store
implementation should move to handle-based APIs in the same refactor gate.

- [x] Change the shared key-store interface from
      `get(ecdsaThresholdKeyId)`-style lookup to `getByKeyHandle(keyHandle)`.
- [x] Add `getByKeyHandle(keyHandle)` to the shared key-store interface and
      implement handle-index reads across in-memory, Redis, Upstash, Postgres,
      and Cloudflare Durable Object stores.
- [x] Add `putByKeyHandle(record)` and `deleteByKeyHandle(keyHandle)`.
- [x] Postgres: use the `threshold_ecdsa_keys.key_handle` column and
      `UNIQUE(namespace, key_handle)`.
- [x] Redis: key records by `threshold_ecdsa_key:${namespace}:${keyHandle}` and
      maintain any owner-address index as a derived index.
- [x] Upstash: mirror the Redis key layout and derive indexes from
      `keyHandle`.
- [x] In-memory store: key the map by `namespace:keyHandle`.
- [x] Cloudflare Durable Object store: add handle-based operations and key
      records by `keyHandle`; signing-root share storage may keep
      `signingRootId + signingRootVersion` internally.
- Remaining store migration and invalidation cleanup is grouped under Batch 2
      in the execution plan below.

#### IndexedDB Migration Plan

The SDK currently persists ECDSA runtime/sealed records with threshold key id and
signing-root fields. IndexedDB should store the opaque handle and verified public
facts.

- [x] Add required `keyHandle` to the current ECDSA sealed/runtime record
      shape.
- [x] Rebuild ECDSA lane keys to use `walletId + keyHandle + authMethod + curve
      + chainTarget + walletSigningSessionId + thresholdSessionId`.
- Remaining persisted-record shape cleanup is grouped under Batch 2 in the
      execution plan below.
  - [x] Remove base-ECDSA `subjectId` usage from Email OTP persisted runtime
        snapshot dedupe identity; runtime snapshot dedupe is now wallet/key/session
        identity only.
  - [x] Derive base-ECDSA `subjectId` from `walletId` at session-record
        normalization and reject mismatched provided `subjectId`; persisted
        normalization no longer requires stored `subjectId`.
  - [x] Delete base-ECDSA `subjectId` from the current persisted runtime ECDSA
        record shape; record normalization still accepts legacy `subjectId` only
        to reject mismatches.
  - [x] Require canonical `verifiedPublicFacts` for persisted runtime ECDSA lane
        emission and Email OTP persisted snapshot dedupe identity; no fallback to
        top-level key/public-key fields in those runtime boundaries.
- [x] Store `participantIds`, `thresholdOwnerAddress`, and public key metadata
      as verified public facts on the record.
- Remaining `rpId` storage cleanup is grouped under Batch 2 in the execution
      plan below.
  - [x] Remove `rpId` from Email OTP persisted runtime snapshot dedupe identity;
        runtime snapshot dedupe no longer treats `rpId` as a storage identity field.
- [x] On DB upgrade, delete old ECDSA records that cannot be rehydrated to a
      server-issued `keyHandle`.
  - [x] Prune JWT-backed sealed ECDSA records at read/normalization boundaries
        when threshold-session JWT claims are not canonical (`walletId` +
        `keyHandle`), instead of preserving compatibility token shapes.
  - [x] Prune ECDSA sealed-session records that still persist top-level
        `subjectId`; current sealed ECDSA writes reject it and sealed-refresh
        recovery derives the worker subject from `walletId`.
- [x] Prefer a clean invalidation upgrade for development. If preserving records
      matters for a release, add a one-time server lookup by old key fields to fetch
      `keyHandle`, then delete the compatibility path in the next migration.
- [x] Add migration tests proving stale v-old records with scattered key fields
      do not enter core lane selection.

### Tasks

- [x] Add boundary builders for `EvmFamilyEcdsaKeyHandle`,
      `VerifiedEcdsaPublicFacts`, `EvmFamilyEcdsaAuthBinding`, and
      `ResolvedEvmFamilyEcdsaKey`.
  - [x] Make `buildResolvedEvmFamilyEcdsaKey` generic over its auth binding so
        passkey resolved-key fields retain passkey auth constraints.
- [x] Move fingerprint derivation to `VerifiedEcdsaPublicFacts` plus
      `walletId` and `authBinding.rpId` only where auth-origin binding is required.
  - [x] Move available-lane, prepared-signing, and export-selection fingerprint
        grouping onto `VerifiedEcdsaPublicFacts`; keep current lane `rpId` checks
        at selection boundaries while `ResolvedEvmFamilyEcdsaKey` propagation is
        still landing.
  - [x] Move available-lane shared-key conflict and completion grouping onto
        `VerifiedEcdsaPublicFacts.keyHandle` plus verified public facts.
  - [x] Move ready-material and budget-failure ECDSA signing diagnostics to
        record-backed verified public facts fingerprint derivation instead of
        broad key-identity fields.
- [x] Replace call sites that need only owner address with
      `VerifiedEcdsaPublicFacts`.
- [x] Replace call sites that need only HSS key routing with
      `EvmFamilyEcdsaKeyHandle`.
  - [x] Route selected-lane shared-record and shared-key-ref matching through
        normalized `keyHandle` equality; keep threshold-key/signing-root fallback
        only for compatibility key refs missing a handle at the boundary.
  - [x] Route trusted wallet-budget ECDSA lane matching and readiness lane
        dedupe keys through persisted `keyHandle` instead of threshold-key id
        string tuples.
  - [x] Route durable ECDSA threshold-session JWT lane validation through
        `walletId + keyHandle` only, and prune stale JWT-backed sealed records
        that do not carry the canonical claims.
  - [x] Route durable ECDSA export-lane recovery matching through
        `walletId + keyHandle + exact session ids`, and tighten the durable
        verified-public-facts boundary so it no longer accepts scattered
        threshold-key or signing-root fields.
  - [x] Stop Email OTP runtime export/signing-session boundaries from
        re-deriving `keyHandle` from persisted threshold-key and signing-root
        fields; they now trust the normalized persisted `record.keyHandle`.
- [x] Replace call sites that need prompt/auth constraints with
      `EvmFamilyEcdsaAuthBinding`.
  - [x] Require passkey concrete available-lane ECDSA candidates to carry
        `ResolvedEvmFamilyEcdsaKey` with a passkey auth binding; keep Email OTP
        available lanes on public facts until provider identity is available at the
        boundary.
  - [x] Add compile-only fixtures proving passkey availability lanes require
        resolved-key auth binding and Email OTP availability lanes reject unresolved
        provider-bound resolved keys.
  - [x] Route passkey available-lane grouping, reauth anchors, and
        export-selection RP ID checks through
        `ResolvedEvmFamilyEcdsaKey.authBinding.rpId`; keep Email OTP lanes on their
        current public-facts-only shape until provider identity is available at the
        boundary.
  - [x] Require availability identity keys to carry branch-specific resolved
        passkey auth binding before runtime/durable grouping.
  - [x] Route persisted runtime ECDSA duplicate filtering through the canonical
        availability identity builder instead of a raw field string.
  - [x] Add a compile-only fixture proving passkey availability lanes reject
        resolved keys with Email OTP auth bindings.
- Remaining lane resolved-key migration is grouped under Batch 3 in the
      execution plan below.
  - [x] Require ECDSA planning lanes to carry normalized `keyHandle` and thread
        it through ECDSA budget-status check builders so downstream matchers use
        strict typed handle equality without inline normalization.
- Remaining broad-identity adapter cleanup is grouped under Batch 3 in the
      execution plan below.
- [x] Add type fixtures rejecting session ids, chain target, and auth method on
      verified public facts.
- [x] Add type fixtures rejecting owner address and participant ids on auth
      binding.
- [x] Extend guard coverage so split public-facts, resolved-key, and ready
      signer-session shapes stay builder-owned outside type fixtures.

## Phase 3: Replace Optional-Heavy `ThresholdEcdsaSecp256k1KeyRef`

`ThresholdEcdsaSecp256k1KeyRef` should stop being the core ECDSA material type.
It carries identity, transport, client share, session auth, and export artifacts
in one optional-heavy object. Replace core usage with branch-specific ready
material.

### Target Types

```ts
type ThresholdEcdsaInlineClientShare = {
  kind: 'inline_client_share';
  clientAdditiveShare32B64u: string;
};

type EmailOtpWorkerShareHandle = string & {
  readonly __brand: 'EmailOtpWorkerShareHandle';
};

type ThresholdEcdsaEmailOtpWorkerShare = {
  kind: 'email_otp_worker_share';
  handle: EmailOtpWorkerShareHandle;
  laneIdentity: ExactEcdsaLaneIdentity;
};

type ThresholdEcdsaSessionTransportAuth =
  | {
      kind: 'jwt_threshold_session_auth';
      token: string;
    }
  | {
      kind: 'cookie_threshold_session_auth';
    };

type ThresholdEcdsaSignerTransport = {
  kind: 'threshold_ecdsa_signer_transport';
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  auth: ThresholdEcdsaSessionTransportAuth;
};

type ReadyThresholdEcdsaSession = {
  kind: 'ready_threshold_ecdsa_session';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  remainingUses: number;
  expiresAtMs: number;
};

type ReadyEcdsaSignerSession = {
  kind: 'ready_ecdsa_signer_session';
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ThresholdEcdsaSignerSessionIdentity;
  transport: ThresholdEcdsaSignerTransport;
  clientShare: ThresholdEcdsaInlineClientShare | ThresholdEcdsaEmailOtpWorkerShare;
  keyRef?: never;
};

type ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material';
  signerSession: ReadyEcdsaSignerSession;
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact | null;
  evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
  ecdsaThresholdKeyId?: never;
  keyRef?: never;
  readyMaterial?: never;
};
```

### Tasks

- [x] Add builders that create `ReadyEcdsaSignerSession` only from a
      validated record plus matching key-ref/boundary payload.
- [x] Add `toVerifiedEcdsaPublicFacts(serverRecord | keyRef | durableRecord)`
      and require export/owner-address reads to use that verified shape.
- [x] Require JWT auth token in the `jwt_threshold_session_auth` branch,
      `relayerKeyId`, `clientVerifyingShareB64u`, and client-share source at the
      signer-session builder boundary.
- [x] Require owner address, public key, and participant ids at the verified
      public-facts builder boundary.
- [x] Give each field one owner: session identity/budget lives in
      `ReadyThresholdEcdsaSession`, threshold-session auth lives in
      `ThresholdEcdsaSignerTransport.auth`, and public key facts live in
      `VerifiedEcdsaPublicFacts`.
- [x] Represent threshold-session auth as a union:
      `jwt_threshold_session_auth` with token or `cookie_threshold_session_auth`
      without token.
- [x] Split export material from signing material. Export flows should require
      `ReadyThresholdEcdsaExportMaterial`.
- [x] Remove top-level HSS key id from ready export material; diagnostics use
      `VerifiedEcdsaPublicFacts.keyHandle`, and fresh Email OTP export keeps the
      server key id only at the request boundary.
- [x] Build `EmailOtpWorkerShareHandle` only through a boundary builder that
      also records the exact lane identity; reject worker-share handles whose lane
      identity does not match the selected signer session.
- [x] Move `ThresholdEcdsaSecp256k1KeyRef` construction into a signer adapter
      module.
- Remaining ready-material migration is grouped under Batch 4 in the execution
      plan below.
  - [x] Route EVM-family signing-flow secp256k1 commits through
        `ReadySecp256k1SigningMaterial`, including key-ref fallback normalization.
  - [x] Split the EVM-family signing-flow engine map so secp256k1 requires
        `ReadySecp256k1Signer`.
  - [x] Delete the direct `Secp256k1Engine.sign(req, keyRef)` helper and move
        direct engine tests to ready material.
  - [x] Collapse the signing-flow secp256k1 fallback helper to return
        `ReadySecp256k1SigningMaterial`.
  - [x] Move UI signing-flow key-ref fallback behind a ready-material provider;
        `signingFlow.ts` no longer accepts `ThresholdEcdsaSecp256k1KeyRef`.
  - [x] Remove `keyRef` from the EVM-family threshold reauth result; admission
        now returns ready material, ready signer session, and admitted operation.
  - [x] Require paired record/key-ref material inside the EVM-family reauth
        replacement helper instead of optional refresh inputs.
  - [x] Split ECDSA reconnect readiness args so planned reconnect requires a
        concrete key ref and only derived reconnect may look one up.
  - [x] Rename the threshold reconnect admission hook so it advertises ready
        material instead of key-ref readiness.
- [x] Delete core helpers that read optional key-ref fields directly.
  - [x] Stop ready export material from reading optional
        `keyRef.ecdsaHssExportArtifact` directly.
  - [x] Stop ECDSA material-state summaries from rebuilding signing-key
        context from key refs.
  - [x] Stop export material resolution from exposing an exact-lane key-ref
        reader; ready material lookup owns that boundary.
  - [x] Stop EVM-family reauth budget-status auth from reading optional key-ref
        transport fields; derive it from `ReadyEcdsaSignerSession`.
  - [x] Stop ECDSA reconnect readiness from treating the ready capability's
        returned key ref as optional.
  - [x] Require passkey ECDSA reconnect provision planning to use paired
        record/key-ref material and validate signing-key context through the paired
        builder.
  - [x] Route Email OTP ECDSA provision planning through the same paired
        signing-key-context builder.
  - [x] Delete the exported optional-bag ECDSA signing-key-context helper;
        core signing-key context now comes from paired material or private
        required-input projections.
  - [x] Tighten threshold-session reconnect token and relayer-key selection to
        required paired record/key-ref material.
  - [x] Replace the Email OTP ECDSA context classifier's optional
        record/key-ref bag with branch-specific record or key-ref inputs.
  - [x] Add a guard that blocks optional `keyRef?.` and
        `thresholdEcdsaKeyRef?.` field reads in core signing-engine code.
- [x] Add type fixtures rejecting missing JWT auth token in the JWT branch,
      missing transport, missing client share, missing owner address, missing
      participant ids, and export artifact on signing-only material.
- [x] Add runtime tests for Email OTP worker-handle material and passkey inline
      material.

## Phase 4: Tighten Available Lane and Export Selection Boundaries

Available-lane read models should receive exact, normalized material from
boundary builders. Selectors should decide between precise candidates, not repair
partial objects.

### Tasks

- Remaining available-lane resolved-key cleanup is grouped under Batch 3 in the
      execution plan below.
  - [x] Add `VerifiedEcdsaPublicFacts` to concrete available-lane ECDSA
        candidates as the public-facts half of the resolved-key shape.
  - [x] Add passkey `ResolvedEvmFamilyEcdsaKey` to concrete available-lane
        ECDSA candidates.
  - [x] Thread `VerifiedEcdsaPublicFacts` from selected available lanes into
        exact ECDSA export lanes.
  - [x] Verify exact ECDSA export-lane public facts against the stored or sealed
        material before returning ready or fresh export material.
- [x] Collapse exact same-key exhausted/expired reauth anchors at the
      availability boundary.
- [x] Keep different key identities and owner-address drift ambiguous.
- [x] Ensure export selection consumes `ReadyThresholdEcdsaExportMaterial`.
- [x] Remove selector tie-breaks that rely on opaque session id ordering.
- [x] Add regression tests for duplicate exhausted Email OTP runtime lanes,
      durable/runtime duplicates, and owner-address drift.

## Phase 5: Delete Compatibility Shapes From Core

After callers move to exact commands and ready material, remove the old broad
types from core modules.

### Tasks

- [x] Delete field-bag ECDSA consumption APIs.
- Remaining compatibility-shape deletion is grouped under Batches 3 through 5
      in the execution plan below.
- [x] Add a guard test that blocks new broad consumption names such as
      `consumeForSubjectTarget`, `markForSubjectTarget`, and `markForAccount`.
- [x] Add a guard test that blocks direct `ThresholdEcdsaSecp256k1KeyRef`
      imports from signing/export core modules, except the boundary adapter.
  - [x] Add the first direct-type guard for converted signing admission and
        export APIs that already accept ready material.
  - [x] Remove the direct key-ref type import from the ready export type
        fixture; the rejection now uses an opaque value.
  - [x] Extend the direct-type guard to cover ready-material type fixtures and
        export selection.

## Validation

Run focused checks after each phase:

New focused tests to create as part of this refactor:

- `tests/unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts`

```sh
pnpm -s type-check:sdk
pnpm -C tests exec playwright test \
  ./unit/thresholdEcdsaEmailOtpConsumption.unit.test.ts \
  ./unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts \
  ./unit/exportLaneSelection.unit.test.ts \
  ./unit/signingPostSignPolicy.unit.test.ts \
  --reporter=line
```

Run broader checks before marking complete:

```sh
pnpm -s type-check
pnpm -C tests exec playwright test ./unit --reporter=line
git diff --check -- . ':(exclude)crates/ecdsa-hss/**'
```

Focused regression coverage:

- [x] ECDSA key export works after several exhausted Email OTP ECDSA lanes exist.
- [x] ECDSA signing still works for passkey and Email OTP accounts after exact
      lane consumption.
- [x] Export selection remains ambiguous when candidates have different key
      identities or owner addresses.

## Completion Criteria

- [x] Exact single-use Email OTP ECDSA consumption is represented by a branded
      command and exact lane key.
- [x] 39A ships independently before key-handle, subject-collapse, key-ref, or
      budget refactors begin.
- [x] Broad consumption by subject/target is gone from core logic.
- Remaining resolved-key end-state work is grouped under Batches 3 through 5 in
      the execution plan below.
- [x] The threat-model update documents where `subjectId`, `rpId`, and Email
      OTP provider identity are validated after the split.
- Remaining identity-surface cleanup is grouped under Batches 1, 3, and 5 in
      the execution plan below.
- [x] Postgres stores/indexes ECDSA keys by `keyHandle`.
- Remaining persistence and ready-material end-state work is grouped under
      Batches 2 through 5 in the execution plan below.

## Remaining Implementation Batches

- [x] Batch 1: finish client and SDK boundary cleanup around one opaque
      `keyHandle`.
  - [x] Remove `signingRootId` / `signingRootVersion` from the ECDSA
    signing/session lookup dependency surfaces (`EcdsaSigningLookupArgs`,
    `EcdsaSigningListLookupArgs`) and the ECDSA lane lookup wrappers that forward
    those args.
  - [x] Remove `signingRootId` / `signingRootVersion` from the
    Email OTP device-enrollment restore client seam result
    (`EmailOtpDeviceEnrollmentRestoreResult`).
  - [x] Strip legacy ECDSA threshold-key/signing-root identity fields from
    `/email-recovery/prepare` and `/link-device/prepare` route responses after
    threshold-session JWT signing.
  - [x] Strip legacy ECDSA threshold-key/signing-root identity fields from
    registration bootstrap responses after threshold-session JWT signing.
  - [x] Move link-device threshold ECDSA bootstrap parsing to require
    `keyHandle` and derive key-id/signing-root compatibility values from
    runtime policy scope at the client boundary instead of requiring
    `ecdsaThresholdKeyId/signingRoot*` in route payloads.
  - [x] Remove the last client-facing ECDSA request/public/session fields that still
    expose `ecdsaThresholdKeyId` or `signingRoot*`.
  - [x] Remove remaining SDK public signing/export/session APIs that still surface
    threshold-key or signing-root identity.
  - [x] Delete remaining JSON-only lookup and request-shaping paths that rebuild
    ECDSA identity from scattered threshold-key/signing-root fields.
  - [x] Wallet-target runtime session and key-ref lookup helpers no longer
    accept `signingRootId` / `signingRootVersion` filters.

- [x] Batch 2: finish IndexedDB/runtime/sealed ECDSA schema cleanup and
      invalidation behavior.
  - [x] Delete persisted ECDSA `subjectId` from current runtime record shapes
    (legacy `subjectId` accepted only at normalization boundaries for mismatch
    rejection).
  - [x] Stop requiring and emitting top-level ECDSA `signingRootId` /
    `signingRootVersion` in current sealed-session records; keep legacy
    `signingRoot*` fields boundary-accepted only so old payloads normalize
    without becoming the new persisted shape.
  - [x] Delete persisted ECDSA `ecdsaThresholdKeyId`, `signingRootId`, and
    `signingRootVersion` from current runtime/sealed record shapes.
    Sealed ECDSA publication now persists `runtimePolicyScope` in
    `ecdsaRestore`, and sealed recovery normalizes runtime scope from either
    restore metadata or threshold-session JWT claims before signing-root
    validation.
    Runtime identity/readiness/provision/export boundaries now resolve
    threshold-key and signing-root compatibility through canonical helpers
    (`keyHandle` fallback for threshold-key identity and runtime-policy-scope
    signing-root binding) instead of reading record fields directly.
  - [x] Keep `rpId` only in auth/restore metadata.
  - [x] Store `keyHandle + VerifiedEcdsaPublicFacts` as the persisted ECDSA
    identity surface.
  - [x] Finish migration ordering, rollback/prune behavior, and handle-deletion
    invalidation for dependent runtime sessions, sealed records, and derived
    indexes.

- [x] Batch 3: finish resolved-key lane-model migration.
  - Make lane/read-model surfaces carry `ResolvedEvmFamilyEcdsaKey` by default.
  - Make available-lane ECDSA candidates carry resolved key plus exact
    chain/session identity.
  - Restrict broad `EvmFamilyEcdsaKeyIdentity` adapters to request,
    persistence, and sealed-record boundaries only.

- [x] Batch 4: finish ready-material migration and isolate
      `ThresholdEcdsaSecp256k1KeyRef`.
  - Move the remaining core signing/export functions to branch-specific ready
    material.
  - Delete core `ThresholdEcdsaSecp256k1KeyRef` use outside the boundary
    adapter.
  - Delete broad key-ref/identity reconstruction where ready material or split
    structs already exist.

- [x] Batch 5: final core-shape deletion and invariant pass.
  - [x] Delete base-ECDSA `subjectId` from core SDK types and lane keys.
  - [x] Delete remaining optional identity/session/material fields from core
    operation inputs.
    Core `resolveReadyEvmFamilyEcdsaMaterial` inputs no longer accept redundant
    expected `subjectId`, and ready signer/session transport auth inputs now use
    a JWT-vs-cookie discriminated union so JWT auth requires a token at compile
    time.
    Available-lane rebuild now parses expired/exhausted sealed records through a
    dedicated permissive boundary mode (while restore/lookups remain strict),
    and ECDSA capability-reader lookup deps now require exact
    `keyHandle + thresholdSessionId + walletSigningSessionId` lane identity
    instead of optional passthrough fields.
    Resolved Ed25519 operation identities now reject `signingRootId` /
    `signingRootVersion` at the type level.
    Ready resolved-lane material calls now require paired
    `record + keyRef` inputs at the call boundary (no optional ready-material
    bag), and ECDSA signing preparation no longer threads the dead optional
    `ThresholdSigningReadinessInput.signingRootId` field.
    Threshold reconnect readiness now accepts only explicit planned reconnect
    inputs (exact `keyRef` + reconnect plan), and operation-state signing
    capability results now enforce branch-specific material: ECDSA success
    requires `keyRef` while Ed25519 success rejects it.
  - [x] Confirm the final end state: client-facing ECDSA identity is opaque
    `keyHandle`, core identity is resolved-key/public-facts/auth-binding based,
    persisted records use `keyHandle + verified public facts`, and broad legacy
    shapes are isolated to explicit boundaries only.
    Shared lane/key-ref matching no longer falls back to legacy
    `ecdsaThresholdKeyId + signingRoot*` comparisons when `keyHandle` is
    absent; core matching now uses `keyHandle` only.
    Material-vs-lane identity checks and operation-state selected-lane capability
    matching now compare ECDSA identity by `keyHandle` (plus exact session and
    chain identity) instead of signing-root/version comparisons.
    Core selected-lane/planning-lane ECDSA shapes no longer carry duplicated
    top-level `ecdsaThresholdKeyId + signingRoot*`; those fields stay on the
    resolved-key identity or boundary adapter shapes only.
    Refactor guard suites now validate this end state with updated ownership and
    boundary expectations (`refactor33`, `refactor36`, `refactor37`, and account
    signer lifecycle guard cases).
- [x] Type fixtures reject partial ECDSA key/session/material states.
- [x] Focused regression tests cover duplicate exhausted Email OTP ECDSA lanes.

## Batch 6: Delete Synthetic Legacy Key-Id Compatibility

Goal: remove the remaining `legacy-key-handle:${keyHandle}` compatibility path
and finish the temporary prune-code deletion after the Postgres database has
been cleaned.

- [x] Clean up every `ecdsaThresholdKeyId: legacy-key-handle:*` value that is
      paired with a missing `keyHandle`.
  - [x] Inventory production code, server routes, IndexedDB/profile
        persistence adapters, Postgres record adapters, tests, and fixtures for
        synthetic key ids.
  - [x] Replace valid fixtures and current-shape records with explicit
        `keyHandle` plus canonical `ecdsaThresholdKeyId`.
  - [x] Keep synthetic legacy ids only in boundary rejection fixtures while the
        cleanup batch is under test.
  - [x] Add a guard test that fails if production code constructs
        `legacy-key-handle:` outside the boundary parser/rejection test.
  - [x] Make any record with `ecdsaThresholdKeyId: legacy-key-handle:*` and no
        `keyHandle` invalid at the request/persistence boundary.
- [x] Delete the synthetic `legacy-key-handle:` threshold-key-id fallback from
      `evmFamilyEcdsaIdentity.ts`.
  - [x] Remove `LEGACY_KEY_HANDLE_THRESHOLD_KEY_ID_PREFIX`.
  - [x] Remove the helper that materializes `ecdsaThresholdKeyId` from
        `keyHandle`.
  - [x] Make `resolveThresholdEcdsaKeyIdFromRecord` require a canonical
        `ecdsaThresholdKeyId` at the boundary.
  - [x] Make `resolveThresholdEcdsaKeyIdFromKeyRef` reject missing
        `ecdsaThresholdKeyId`.
- [x] Remove unlock/profile continuity handling for synthetic
      `legacy-key-handle:` ids.
  - [x] Make active profile ECDSA signers require `metadata.keyHandle`.
  - [x] Fail closed when profile metadata only contains a synthetic legacy id or
        canonical key metadata without a key handle.
  - [x] Stop deriving key handles from
        `ecdsaThresholdKeyId + signingRootId + signingRootVersion` during
        unlock; profile continuity must already carry the key selector.
- [x] Harden wallet unlock ECDSA warm-up planning.
  - [x] Build an exact unlock ECDSA warm-up plan before clearing volatile
        session material.
  - [x] Model the plan as explicit states:
        `no_configured_ecdsa_targets`, `ready`, `needs_ed25519_inventory`, and
        `blocked`.
  - [x] Allow `needs_ed25519_inventory` only when every configured ECDSA target
        has an exact `keyHandle` selector and unlock only needs
        server-certified key/public facts from the Ed25519-authorized inventory
        route.
  - [x] Treat missing key handles, ambiguous key handles, missing chain targets,
        and synthetic legacy ids as `blocked`.
  - [x] Preflight the warm-up plan before
        `clearVolatileWarmSigningMaterial`; blocked plans must leave current
        volatile material intact.
  - [x] Resolve the deferred Ed25519 inventory using the preflighted key-target
        request list instead of recomputing selectors after session mutation.
  - [x] Add regression tests for missing profile key handles, synthetic legacy
        ids, deferred inventory selectors, and mutation ordering.
- [x] Refactor ECDSA bootstrap request conversion around lifecycle state.
  - [x] Replace broad auth/bootstrap-family conversion in
        `toBootstrapEcdsaSessionRequest` with lifecycle-specific command
        branches.
  - [x] Model command branches such as `register_new_key`,
        `activate_existing_key`, and `recover_existing_key`; each branch must
        carry exactly the fields needed for its protocol operation.
  - [x] Select server operation from lifecycle state:
        `register_new_key` emits `registration_bootstrap`, and
        `activate_existing_key` emits `session_bootstrap`.
  - [x] Keep auth method selection inside the chosen lifecycle branch. Auth must
        provide the proof envelope for the operation and must not choose between
        registration and existing-key activation.
  - [x] Make existing-key activation require exact `keyHandle`, canonical `key`,
        and `lanePolicy`.
  - [x] Make registration require target/key intent and reject exact-key fields.
  - [x] Delete optional/fallback fields that let exact activation degrade into a
        target-based registration request.
  - [x] Add type fixtures rejecting invalid branch combinations:
        activation without `keyHandle`, activation with `keyIntent`,
        registration with `keyHandle`, and broad object-spread construction of
        lifecycle commands.
  - [x] Add focused unit tests proving post-exhaustion passkey ECDSA
        reactivation emits `session_bootstrap`, registration emits
        `registration_bootstrap`, and existing-key activation never sends
        `keyIntent`.
- [x] Update tests that still construct or assert synthetic
      `legacy-key-handle:` values.
  - [x] Replace valid fixtures with canonical key ids plus key handles.
  - [x] Keep one boundary rejection test that proves synthetic legacy ids are
        rejected.
- [x] After the live Postgres prune has run and schema constraints are in
      place, delete temporary key-store startup prune/backfill code.
  - [x] Remove the `record_json` column backfill path for ECDSA indexed
        identity columns.
  - [x] Remove legacy-row prune branches that delete rows missing indexed
        ECDSA identity.
  - [x] Keep only schema assertions and normal current-shape reads/writes.
- [x] Run focused validation after deletion.
  - [x] ECDSA identity unit tests.
  - [x] login threshold warm-session tests.
  - [x] Postgres key-store/backfill tests, updated to assert current schema
        behavior.
  - [x] SDK type-check.
