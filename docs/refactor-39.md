# Refactor 39: Exact ECDSA Lane Consumption and Material Identity Split

Date created: 2026-05-17
Status: planned

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

- [ ] List every writer and caller of Email OTP ECDSA consumption APIs.
- [ ] List every function that accepts `ThresholdEcdsaSecp256k1KeyRef` in core
  signing/export logic.
- [ ] List every object spread that constructs `ThresholdEcdsaSecp256k1KeyRef`,
  `EvmFamilyEcdsaKeyIdentity`, `EvmFamilyEcdsaSessionLane`, or
  `SelectedEcdsaLane`.
- [ ] List every optional ECDSA identity/session/material field in core paths.
- [ ] Add guard coverage for broad consumption names and broad key-ref builders.
- [ ] Produce a per-gate implementation checklist so 39A can land before 39B,
  39C, or Refactor 40.

## Phase 1 / Refactor 39A: Exact Single-Use ECDSA Consumption

The stronger consumption model is command-based. The selected material should
carry one exact runtime lane ref. Persistence should update exactly that lane
with stale-record detection by loading the stored record, recomputing the
existing `thresholdEcdsaLaneKey`, and validating the selected identity.

39A deliberately uses the existing `recordsByLane` /
`thresholdEcdsaLaneKey(record)` model. The pre-key-handle and key-handle lane
key versions belong to 39B.

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

- [ ] Add `toExactEcdsaLaneIdentity(record | selectedLane)` at the availability
  boundary.
- [ ] Add `toConsumableEmailOtpPostSignMaterial(selectedMaterial)` that returns
  `ConsumableEmailOtpEcdsaLane` only for the selected single-use Email OTP
  ECDSA lane.
- [ ] Add a boundary builder that turns a normalized stored record into
  `EmailOtpEcdsaPostSignMaterial` without exposing broad persistence fields to
  core logic.
- [ ] Brand the existing `thresholdEcdsaLaneKey(record)` output as
  `ThresholdEcdsaRuntimeLaneKey`.
- [ ] Replace `markThresholdEcdsaEmailOtpSessionConsumedForLane` with
  `consumeSingleUseEmailOtpEcdsaLane(command)`.
- [ ] Make `consumeSingleUseEmailOtpEcdsaLane` update `recordsByLane` by exact
  `laneKey`.
- [ ] Recompute the canonical lane key from the stored record and require it to
  match `command.lane.laneRef.laneKey`.
- [ ] Require wallet id, key identity, auth method, chain target,
  `thresholdSessionId`, `walletSigningSessionId`, source, Email OTP retention,
  and `updatedAtMs` to match `command.lane.laneRef.exactIdentity` and
  `expectedUpdatedAtMs` before consuming.
- [ ] Return `ConsumeSingleUseEmailOtpEcdsaLaneResult` instead of throwing for
  expected stale, missing, or already-consumed outcomes.
- [ ] Delete consumption helpers that accept `subjectId`, `chainTarget`,
  `walletSigningSessionId`, or `thresholdSessionId` as loose inputs.
- [ ] Update post-sign policy to switch on `EmailOtpEcdsaPostSignMaterial.kind`.
- [ ] Build consumption commands only from the actually selected signer
  material. Secondary Email OTP material is read-only reauth/display context and
  cannot create a consume command.
- [ ] Add type fixtures proving session-retained Email OTP material cannot be
  passed to the consume command.
- [ ] Add type fixtures proving secondary material cannot create
  `ConsumeSingleUseEmailOtpEcdsaLaneCommand`.
- [ ] Add regression tests with two same-target Email OTP ECDSA records where
  only the selected exact lane is consumed.
- [ ] Add regression tests for stale record, missing lane, already consumed,
  chain-target mismatch, key-identity mismatch, and updated-at mismatch.

### 39A Completion Criteria

- [ ] Core consumption has no subject/target field-bag API.
- [ ] Post-sign policy consumes selected material only.
- [ ] Exact consume returns typed results for consumed, already consumed,
  missing lane, and stale record.
- [ ] ECDSA export no longer sees ambiguous same-key exhausted candidates caused
  by sibling Email OTP record consumption.

## Phase 2 / Refactor 39B: ECDSA Identity Simplification

`EvmFamilyEcdsaKeyIdentity` already has strong branch exclusions. 39B should
avoid splitting identity for its own sake. Introduce a canonical key handle and
a boundary facade, then split narrower public/auth/target views only at call
sites where the narrower input removes a real invalid state.

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

- [ ] Define `BaseEcdsaWalletId = WalletId` as the only base ECDSA subject
  namespace.
- [ ] Delete `subjectId` from `ThresholdEcdsaSessionRecordKey`.
- [ ] Delete `subjectId` from `thresholdEcdsaLaneKey(...)`.
- [ ] Re-key runtime ECDSA records by `walletId`, key handle, auth method,
  curve, chain target, wallet signing-session id, and threshold session id.
- [ ] Replace ECDSA record indexes keyed by subject with wallet-keyed indexes.
- [ ] Replace `WalletSubjectId` inputs in base ECDSA signing/export/unlock flows
  with `WalletId`.
- [ ] Keep `WalletSubjectId` only for NEAR account or future multi-subject
  features that explicitly need a separate subject namespace.
- [ ] Delete ECDSA mismatch branches that compare `walletId` and `subjectId`.
- [ ] Add type fixtures rejecting `subjectId` on base ECDSA key identity, lane
  identity, available-lane candidates, ready material, and public request
  shapes.
- [ ] Add a guard that blocks `subjectId` in base ECDSA lane key and selected
  lane types.

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

- [ ] Normalize `signingRootVersion` to the server default before hashing.
- [ ] Encode fields with length-prefixed UTF-8 or canonical JSON with sorted
  keys. Delimiter-concatenated strings are disallowed.
- [ ] Hash with SHA-256 and encode with base64url:

  ```ts
  keyHandle = `ehss-key-${base64url(sha256(canonicalBytes(input)))}`;
  ```

- [ ] Enforce uniqueness within `namespace`.
- [ ] Treat collisions as fatal server integrity errors.
- [ ] Verify public facts whenever a handle is resolved: owner address,
  participant ids, public key, threshold key id, signing-root id, and
  signing-root version must match the server record.
- [ ] Remove threshold key id and signing-root fields from SDK public
  signing/export/session APIs once handle migration is complete.

#### Postgres Migration Plan

The current Postgres bootstrap creates `threshold_ecdsa_keys(namespace,
relayer_key_id, record_json)` and signing-root share tables keyed by
`signing_root_id + signing_root_version`. Refactor to make the ECDSA key handle
the primary application key for integrated ECDSA records.

- [ ] Add `key_handle TEXT` to `threshold_ecdsa_keys` with
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
- [ ] Backfill `key_handle` for existing records from a deterministic server
  function using the canonical derivation above.
- [ ] Add `threshold_key_id TEXT`, `signing_root_id TEXT`,
  `signing_root_version TEXT`, `owner_address TEXT`, and `public_key_b64u TEXT`
  columns with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.
- [ ] Backfill those columns from `record_json`.
- [ ] Add `NOT NULL` constraints after backfill validation passes.
- [ ] Add `UNIQUE(namespace, key_handle)` after duplicate checks pass.
- [ ] Add `UNIQUE(namespace, threshold_key_id, signing_root_id,
  signing_root_version)` if the server should enforce one handle per concrete
  HSS root binding.
- [ ] Add lookup indexes for `(namespace, owner_address)` and
  `(namespace, key_handle)`.
- [ ] Update server key read/write paths to load by `key_handle`.
- [ ] Update HSS finalize/bootstrap responses to return `keyHandle` as the
  client-facing key id.
- [ ] Update signing/session JWT claims to carry `keyHandle`; keep
  threshold-key/signing-root fields only in server-private claims if still
  needed for internal validation.
- [ ] Update budget status, ECDSA authorize, signing init/finalize, export, and
  session inventory routes to accept `keyHandle`.
- [ ] Remove client request support for `ecdsaThresholdKeyId`, `signingRootId`,
  and `signingRootVersion` after all callers move to `keyHandle`.
- [ ] Delete JSON parsing paths that reconstruct key identity from scattered
  threshold-key and signing-root fields at SDK boundaries.
- [ ] Delete old JSON-only lookup paths after route and SDK callers use
  `keyHandle`.

Short-term migration pain is acceptable. Prefer one clean schema pass over
keeping parallel client-facing identities.

#### Store-by-Store API Changes

The key store abstraction currently exposes threshold-key-id lookup. Every store
implementation should move to handle-based APIs in the same refactor gate.

- [ ] Change the shared key-store interface from
  `get(ecdsaThresholdKeyId)`-style lookup to `getByKeyHandle(keyHandle)`.
- [ ] Add `putByKeyHandle(record)` and `deleteByKeyHandle(keyHandle)`.
- [ ] Postgres: use the `threshold_ecdsa_keys.key_handle` column and
  `UNIQUE(namespace, key_handle)`.
- [ ] Redis: key records by `threshold_ecdsa_key:${namespace}:${keyHandle}` and
  maintain any owner-address index as a derived index.
- [ ] Upstash: mirror the Redis key layout and derive indexes from
  `keyHandle`.
- [ ] In-memory store: key the map by `namespace:keyHandle`.
- [ ] Cloudflare Durable Object store: add handle-based operations and key
  records by `keyHandle`; signing-root share storage may keep
  `signingRootId + signingRootVersion` internally.
- [ ] Backfill order: add fields, backfill handles, validate uniqueness, switch
  reads to handle, switch writes to handle, remove threshold-key-id reads.
- [ ] Rollback behavior during development: abort failed migrations and clear
  invalid ECDSA key/session records. Avoid long-lived dual identity modes.
- [ ] Deletion behavior: deleting a key by handle must delete or invalidate its
  runtime sessions, sealed restore records, export artifacts, and derived
  owner-address indexes.

#### IndexedDB Migration Plan

The SDK currently persists ECDSA runtime/sealed records with threshold key id and
signing-root fields. IndexedDB should store the opaque handle and verified public
facts.

- [ ] Add a new ECDSA sealed/runtime record version with `keyHandle`.
- [ ] Rebuild ECDSA lane keys to use `walletId + keyHandle + authMethod + curve
  + chainTarget + walletSigningSessionId + thresholdSessionId`.
- [ ] Delete `subjectId`, `ecdsaThresholdKeyId`, `signingRootId`, and
  `signingRootVersion` from the new persisted ECDSA record shape.
- [ ] Store `participantIds`, `thresholdOwnerAddress`, and public key metadata
  as verified public facts on the record.
- [ ] Store `rpId` only in auth/restore metadata.
- [ ] On DB upgrade, delete old ECDSA records that cannot be rehydrated to a
  server-issued `keyHandle`.
- [ ] Prefer a clean invalidation upgrade for development. If preserving records
  matters for a release, add a one-time server lookup by old key fields to fetch
  `keyHandle`, then delete the compatibility path in the next migration.
- [ ] Add migration tests proving stale v-old records with scattered key fields
  do not enter core lane selection.

### Tasks

- [ ] Add boundary builders for `EvmFamilyEcdsaKeyHandle`,
  `VerifiedEcdsaPublicFacts`, `EvmFamilyEcdsaAuthBinding`, and
  `ResolvedEvmFamilyEcdsaKey`.
- [ ] Move fingerprint derivation to `VerifiedEcdsaPublicFacts` plus
  `walletId` and `authBinding.rpId` only where auth-origin binding is required.
- [ ] Replace call sites that need only owner address with
  `VerifiedEcdsaPublicFacts`.
- [ ] Replace call sites that need only HSS key routing with
  `EvmFamilyEcdsaKeyHandle`.
- [ ] Replace call sites that need prompt/auth constraints with
  `EvmFamilyEcdsaAuthBinding`.
- [ ] Update lane types to carry `ResolvedEvmFamilyEcdsaKey` by default, then
  narrow to public facts, key handle, or auth binding only at call sites that
  benefit from the narrower input.
- [ ] Preserve a temporary `EvmFamilyEcdsaKeyIdentity` adapter only at request,
  persistence, or sealed-record boundaries.
- [ ] Add type fixtures rejecting session ids, chain target, and auth method on
  verified public facts.
- [ ] Add type fixtures rejecting owner address and participant ids on auth
  binding.

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
  resolvedKey: ResolvedEvmFamilyEcdsaKey;
  chainTarget: ThresholdEcdsaChainTarget;
  session: ReadyThresholdEcdsaSession;
  transport: ThresholdEcdsaSignerTransport;
  clientShare: ThresholdEcdsaInlineClientShare | ThresholdEcdsaEmailOtpWorkerShare;
};

type ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material';
  signerSession: ReadyEcdsaSignerSession;
  publicFacts: VerifiedEcdsaPublicFacts;
  exportArtifact: ThresholdEcdsaCanonicalExportArtifact;
};
```

### Tasks

- [ ] Add builders that create `ReadyEcdsaSignerSession` only from a
  validated record plus matching key-ref/boundary payload.
- [ ] Add `toVerifiedEcdsaPublicFacts(serverRecord | keyRef | durableRecord)`
  and require export/owner-address reads to use that verified shape.
- [ ] Require JWT auth token in the `jwt_threshold_session_auth` branch,
  `relayerKeyId`, `clientVerifyingShareB64u`, and client-share source at the
  signer-session builder boundary.
- [ ] Require owner address, public key, and participant ids at the verified
  public-facts builder boundary.
- [ ] Give each field one owner: session identity/budget lives in
  `ReadyThresholdEcdsaSession`, threshold-session auth lives in
  `ThresholdEcdsaSignerTransport.auth`, and public key facts live in
  `VerifiedEcdsaPublicFacts`.
- [ ] Represent threshold-session auth as a union:
  `jwt_threshold_session_auth` with token or `cookie_threshold_session_auth`
  without token.
- [ ] Split export material from signing material. Export flows should require
  `ReadyThresholdEcdsaExportMaterial`.
- [ ] Build `EmailOtpWorkerShareHandle` only through a boundary builder that
  also records the exact lane identity; reject worker-share handles whose lane
  identity does not match the selected signer session.
- [ ] Move `ThresholdEcdsaSecp256k1KeyRef` construction into a signer adapter
  module.
- [ ] Change core signing and export functions to accept ready material instead
  of `ThresholdEcdsaSecp256k1KeyRef`.
- [ ] Delete core helpers that read optional key-ref fields directly.
- [ ] Add type fixtures rejecting missing JWT auth token in the JWT branch,
  missing transport, missing client share, missing owner address, missing
  participant ids, and export artifact on signing-only material.
- [ ] Add runtime tests for Email OTP worker-handle material and passkey inline
  material.

## Phase 4: Tighten Available Lane and Export Selection Boundaries

Available-lane read models should receive exact, normalized material from
boundary builders. Selectors should decide between precise candidates, not repair
partial objects.

### Tasks

- [ ] Make available-lane ECDSA candidates carry `ResolvedEvmFamilyEcdsaKey`
  plus exact chain/session identity.
- [ ] Collapse exact same-key exhausted/expired reauth anchors at the
  availability boundary.
- [ ] Keep different key identities and owner-address drift ambiguous.
- [ ] Ensure export selection consumes `ReadyThresholdEcdsaExportMaterial`.
- [ ] Remove selector tie-breaks that rely on opaque session id ordering.
- [ ] Add regression tests for duplicate exhausted Email OTP runtime lanes,
  durable/runtime duplicates, and owner-address drift.

## Phase 5: Delete Compatibility Shapes From Core

After callers move to exact commands and ready material, remove the old broad
types from core modules.

### Tasks

- [ ] Delete field-bag ECDSA consumption APIs.
- [ ] Delete core use of `ThresholdEcdsaSecp256k1KeyRef` outside the boundary
  adapter.
- [ ] Delete broad `EvmFamilyEcdsaKeyIdentity` core construction where split
  structs are available.
- [ ] Delete base ECDSA `subjectId` from core SDK types and lane keys.
- [ ] Delete client-facing `ecdsaThresholdKeyId`, `signingRootId`, and
  `signingRootVersion` from ECDSA signing/export/session request shapes after
  `keyHandle` is available.
- [ ] Delete optional identity/session/material fields from core operation
  inputs.
- [ ] Add a guard test that blocks new broad consumption names such as
  `consumeForSubjectTarget`, `markForSubjectTarget`, and `markForAccount`.
- [ ] Add a guard test that blocks direct `ThresholdEcdsaSecp256k1KeyRef`
  imports from signing/export core modules, except the boundary adapter.

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

Manual flows to validate:

- [ ] ECDSA key export works after several exhausted Email OTP ECDSA lanes exist.
- [ ] ECDSA signing still works for passkey and Email OTP accounts after exact
  lane consumption.
- [ ] Export selection remains ambiguous when candidates have different key
  identities or owner addresses.

## Completion Criteria

- [ ] Exact single-use Email OTP ECDSA consumption is represented by a branded
  command and exact lane key.
- [ ] 39A ships independently before key-handle, subject-collapse, key-ref, or
  budget refactors begin.
- [ ] Broad consumption by subject/target is gone from core logic.
- [ ] EVM-family ECDSA key identity uses a key handle, verified public facts,
  auth binding, and resolved-key facade.
- [ ] The threat-model update documents where `subjectId`, `rpId`, and Email
  OTP provider identity are validated after the split.
- [ ] Base ECDSA uses `walletId` as the subject namespace; `subjectId` is absent
  from ECDSA lane keys and core ECDSA material.
- [ ] Client-facing ECDSA identity uses one opaque `keyHandle`; threshold key id
  and signing-root id/version are server-side internals.
- [ ] Postgres stores/indexes ECDSA keys by `keyHandle`.
- [ ] IndexedDB ECDSA runtime/sealed records store `keyHandle` and verified
  public facts instead of scattered threshold-key/signing-root fields.
- [ ] Core signing uses branch-specific ready material instead of optional-heavy
  key refs.
- [ ] `ThresholdEcdsaSecp256k1KeyRef` is deleted or isolated to one boundary
  adapter.
- [ ] Type fixtures reject partial ECDSA key/session/material states.
- [ ] Focused regression tests cover duplicate exhausted Email OTP ECDSA lanes.
