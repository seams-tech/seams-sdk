# Refactor 40: ECDSA HSS v2 Without `subjectId`

Date created: 2026-05-23
Status: implementation complete; post-wipe cleanup pending

## Scope

Refactor 40 removes `subjectId` from the ECDSA HSS protocol transcript,
threshold-session claims, server key records, client runtime records, and public
or internal ECDSA request shapes. The replacement identity is the wallet id plus
the existing protocol-scoped fields: rp id, key scope, signing root id,
signing root version, threshold key id, key purpose, key version, and signer set.

This is a key-material breaking refactor. ECDSA HSS v2 derives different client
and relayer shares, different context bindings, different threshold public keys,
and different EVM owner addresses from v1. Existing v1 ECDSA HSS keys,
threshold sessions, sealed sessions, and cached key facts must be treated as
stale at boundaries.

`walletSubjectId` stays in registration/profile flows. `authSubjectId` stays in
Email OTP provider identity. This refactor targets the generic ECDSA/HSS
`subjectId` field only.

## Problem

ECDSA HSS v1 carries both `walletSessionUserId` and `subjectId`. Current callers
derive `subjectId` from wallet id, then validate that it matches. That duplicate
identity adds several failure modes:

- Public and internal ECDSA APIs needed temporary legacy-field tripwires during
  cutover.
- Key identity builders accept a raw subject string only to reject mismatches.
- HSS digests, key ids, JWT claims, and server records all include an identity
  field that duplicates wallet identity.
- Persistence still has boundary compatibility for matching `subjectId` values.
- Registration `walletSubjectId`, Email OTP `authSubjectId`, and ECDSA
  `subjectId` are easy to confuse.

Use HSS v2 to make wallet identity explicit and singular.

## Required Update Surfaces

This checklist is the minimum implementation surface for removing ECDSA
`subjectId` completely. The phased plan below expands each item into ordered
work.

### `crates/ecdsa-hss`

- [x] Add `EcdsaHssStableKeyContextV2` with `wallet_id`, `rp_id`,
  `key_scope`, threshold key id, signing root id, signing root version, key
  purpose, key version, and participant ids.
- [x] Add v2 context domain and scheme constants.
- [x] Encode v2 context bytes without `wallet_session_user_id` or
  `subject_id`.
- [x] Add v2 context binding, client-share derivation, relayer-share
  derivation, public identity composition, and export authorization helpers.
- [x] Add fixture vectors proving v2 context bytes and derived public identity
  differ from v1 for the same wallet/key inputs.
- [x] Keep v1 code only long enough for boundary rejection, fixture comparison,
  or stale-record classification; remove core callers after v2 cutover.

### `wasm/hss_client_signer` ECDSA Bindings

- [x] Add v2 ECDSA client bootstrap binding that accepts wallet id and rp id.
- [x] Remove `subjectId` and `walletSessionUserId` from v2 JS input parsing.
- [x] Return v2 bootstrap outputs without `subjectId` or `walletSessionUserId`.
- [x] Add v2 ECDSA export binding that reconstructs export material from v2
  context and v2 public identity.
- [x] Update TypeScript WASM wrapper types to expose v2-only ECDSA inputs and
  outputs.
- [x] Add WASM surface tests rejecting `subjectId` in v2 inputs.

### `wasm/threshold_prf`

- [x] Add v2 ECDSA relayer-share derivation using the same canonical context
  bytes as `crates/ecdsa-hss`.
- [x] Remove `subjectId` and `walletSessionUserId` from the v2 TypeScript PRF
  wrapper.
- [x] Add parity vectors proving client WASM context binding and server PRF
  relayer derivation agree.
- [x] Keep v1 derivation reachable only from stale-record classification or
  test fixtures until those callers are deleted.

### TypeScript Digest, JWT, and Persistence Layers

- [x] Version shared ECDSA HSS key-id, root-proof, passkey-bootstrap auth, and
  export-authorization digest helpers.
- [x] Replace digest inputs that currently carry `subjectId` with wallet id and
  the v2 protocol-scoped key fields.
- [x] Mint and parse `threshold_ecdsa_session_v2` JWT claims without
  `subjectId`.
- [x] Reject v1 ECDSA session claims and request payloads carrying `subjectId`
  at route/request boundaries.
- [x] Store server ECDSA HSS key records as v2 records with wallet id, rp id,
  key scope, signing root facts, threshold key id, and no subject aliases.
- [x] Remove Postgres key-store indexes and conflict guards based on
  `record_json->>'subjectId'`.
- [x] Make client sealed-session and IndexedDB ECDSA parsers reject or prune v1
  records and any record carrying raw `subjectId`.
- [x] Update ECDSA key-facts inventory parsing so only v2 key records enter
  exact lane selection.
- [x] Add type fixtures and guard tests rejecting `subjectId` in public ECDSA
  inputs, HSS bootstrap, session policy, JWT claims, persisted records, exact
  lane identity, freshness, and budget reservation identities.

## Phase 0: Current Surface Inventory

- [x] Inventory Rust ECDSA HSS context encoding in
  `crates/ecdsa-hss/src/shared/context.rs`.
- [x] Inventory threshold PRF ECDSA context inputs in
  `wasm/threshold_prf` and
  `server/src/core/ThresholdService/thresholdPrfWasm.ts`.
- [x] Inventory signer-worker ECDSA HSS inputs/outputs in
  `wasm/hss_client_signer/src/threshold_hss.rs` and
  `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`.
- [x] Inventory shared TypeScript HSS digest helpers in
  `shared/src/threshold/ecdsaHssRoleLocalBootstrap.ts`.
- [x] Inventory ECDSA HSS session policies and JWT claims in
  `client/src/core/signingEngine/threshold/sessionPolicy.ts`,
  `server/src/router/commonRouterUtils.ts`, and
  `server/src/core/ThresholdService/validation.ts`.
- [x] Inventory server key records, indexes, and conflict guards in
  `server/src/core/ThresholdService/stores/KeyStore.ts` and
  `server/src/core/ThresholdService/ThresholdSigningService.ts`.
- [x] Inventory client persistence compatibility in
  `client/src/core/signingEngine/session/persistence/records.ts`,
  `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`,
  and ECDSA key-facts inventory parsing.
- [x] Inventory docs, examples, and type fixtures that still use raw
  `subjectId` for ECDSA HSS.

## Phase 1: Define HSS v2 Identity

### Target Types

```ts
type EcdsaHssStableKeyContextV2 = {
  version: 'ecdsa_hss_stable_key_context_v2';
  walletId: WalletId;
  rpId: RpId;
  keyScope: 'evm-family';
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  keyPurpose: string;
  keyVersion: string;
  participantIds: readonly [1, 2];
};

type EcdsaHssSessionPolicyV2 = {
  version: 'threshold_session_policy_v2';
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyScope: 'evm-family';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  sessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds: readonly [1, 2];
  ttlMs: number;
  remainingUses: PositiveRemainingUses;
};
```

### Tasks

- [x] Add a single `buildEcdsaHssStableKeyContextV2(...)` boundary builder.
- [x] Require wallet id, rp id, key scope, threshold key id, signing root id,
  signing root version, key purpose, key version, and participant ids.
- [x] Reject raw `subjectId` and `walletSessionUserId` at v2 context builders.
- [x] Update exact ECDSA lane identity to depend on wallet id and key identity
  without derived subject fields.
- [x] Add type fixtures rejecting `subjectId` in HSS v2 context, session policy,
  exact lane identity, key identity, and public ECDSA API inputs.

## Phase 2: Version Rust and WASM HSS Context Encoding

### Target Rust Context

```rust
pub const ECDSA_HSS_V2_CONTEXT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:context:v2";
pub const ECDSA_HSS_V2_SCHEME_ID: &str = "ecdsa-hss-v2";

pub struct EcdsaHssStableKeyContextV2 {
    pub wallet_id: String,
    pub rp_id: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
    pub key_purpose: String,
    pub key_version: String,
}
```

### Tasks

- [x] Add `EcdsaHssStableKeyContextV2` in
  `crates/ecdsa-hss/src/shared/context.rs`.
- [x] Encode v2 context without `subject_id`.
- [x] Include `wallet_id`, `rp_id`, `key_scope`, threshold key id, signing root
  id, signing root version, key purpose, key version, and participant ids in a
  stable order.
- [x] Remove `subjectId` from `wasm/hss_client_signer` v2 JS bindings.
- [x] Return v2 outputs without `subjectId`.
- [x] Add Rust unit tests and WASM surface tests proving v2 context bytes differ
  from v1 and contain no subject field.
- [x] Update formal-verification generated boundary models only after Rust v2
  context is settled.

## Phase 3: Version Threshold PRF ECDSA Derivation

The relayer share derivation must use the same v2 context bytes as the client.

### Tasks

- [x] Add v2 ECDSA HSS PRF derivation in `wasm/threshold_prf`.
- [x] Remove the `subjectId` parameter from the v2 TypeScript wrapper in
  `server/src/core/ThresholdService/thresholdPrfWasm.ts`.
- [x] Use the same canonical v2 fields and ordering as
  `crates/ecdsa-hss/src/shared/context.rs`.
- [x] Add parity vectors proving client HSS v2 context binding and server PRF
  v2 derivation agree.
- [x] Delete direct core-code calls to v1 derivation after request/persistence
  boundaries reject v1 records.

## Phase 4: Version Shared HSS Digests and Key IDs

### Target Versions

- `threshold_ecdsa_hss_key_id_v7`
- `ecdsa-hss:role-local:first-bootstrap-root-proof:v2`
- `ecdsa-hss:role-local:passkey-bootstrap-auth:v2`

### Tasks

- [x] Replace `subjectId` with `walletId` in
  `computeEcdsaHssRoleLocalThresholdKeyId(...)`.
- [x] Remove `subjectId` from first-bootstrap root proof digest input.
- [x] Remove `subjectId` from passkey bootstrap authorization digest input.
- [x] Include version strings in every digest so v1 and v2 cannot collide.
- [x] Add digest fixtures proving v2 changes when wallet id, rp id, signing
  root, threshold key id, or session id changes.
- [x] Add type fixtures rejecting `subjectId` in all v2 digest input objects.

## Phase 5: Version Client ECDSA HSS Bootstrap and Activation

### Tasks

- [x] Replace `ThresholdEcdsaHssStableKeyContext` with a v2 context type that
  carries wallet id and no subject id.
- [x] Change `buildThresholdEcdsaClientRootSharePayload(...)` to accept v2
  context only.
- [x] Remove `subjectId` from
  `ThresholdEcdsaHssRoleLocalClientBootstrap`.
- [x] Update passkey ECDSA bootstrap, Email OTP ECDSA enrollment/login, export
  recovery, and reconnect flows to pass wallet id only.
- [x] Change `buildEvmFamilyEcdsaKeyIdentity(...)` so callers provide wallet id,
  public facts, rp/auth binding, and signing root identity with no subject input.
- [x] Remove all `deriveBaseEcdsaSubjectIdFromWalletId(...)` and
  `deriveBaseEcdsaSubjectIdFromKey(...)` usage from runtime ECDSA flows.
- [x] Add type fixtures rejecting `subjectId` in client HSS bootstrap,
  activation, reconnect, export, and ECDSA material-state inputs.

## Phase 6: Version Server HSS Records, Claims, and Routes

### Target Server Records

```ts
type EcdsaHssRoleLocalKeyRecordV2 = {
  version: 'threshold_ecdsa_hss_role_local_v2';
  ecdsaThresholdKeyId: string;
  keyHandle: string;
  walletId: string;
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  contextBinding32B64u: string;
  relayerShare32B64u: string;
  relayerPublicKey33B64u: string;
  clientPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
  publicTranscriptDigest32B64u: string;
};
```

### Target Claims

```ts
type ThresholdEcdsaSessionClaimsV2 = {
  kind: 'threshold_ecdsa_session_v2';
  sub: string;
  walletId: string;
  sessionId: string;
  walletSigningSessionId: string;
  keyScope: 'evm-family';
  keyHandle: string;
  relayerKeyId: string;
  rpId: string;
  thresholdExpiresAtMs: number;
  participantIds: readonly [1, 2];
};
```

### Tasks

- [x] Add v2 request parsers for ECDSA HSS bootstrap and export-share routes.
- [x] Reject `subjectId` in v2 request parsers.
- [x] Mint `threshold_ecdsa_session_v2` JWTs without `subjectId`.
- [x] Parse and authorize only v2 ECDSA threshold session claims in core
  signing/export paths.
- [x] Replace server key conflict guards with wallet id, rp id, signing root id,
  signing root version, and key scope.
- [x] Update Postgres `threshold_ecdsa_keys` indexes to remove
  `record_json->>'subjectId'`.
- [x] Store v2 key records with `walletId` and no `walletSessionUserId` alias.
- [x] Make v1 key records, v1 session claims, and request payloads with
  `subjectId` fail at request or persistence boundaries.
- [x] Add server unit tests for v2 parsing, JWT claims, key store indexing,
  identity mismatch, and v1 rejection.

## Phase 7: Persistence Boundary Prune

No runtime compatibility branch should load v1 ECDSA HSS keys into core signing.
The only v1 handling should classify, delete, or force re-provision at
request/persistence boundaries.

### Tasks

- [x] Mark persisted ECDSA HSS v1 key records as stale in key-store parsers.
- [x] Delete or ignore v1 `threshold_ecdsa_keys` rows on startup or first read.
- [x] Reject sealed ECDSA sessions whose restore metadata points to v1 key
  records, v1 JWT claims, or any raw `subjectId`.
- [x] Clear client IndexedDB ECDSA runtime records with `subjectId` or v1 HSS
  record versions.
- [x] Make key-facts inventory return only v2 records.
- [x] Add tests proving stale v1 key/session/sealed records do not enter exact
  lane selection or signing execution.

## Phase 8: Public API, Docs, and Examples

### Tasks

- [x] Remove `subjectId` from ECDSA public interfaces, postMessage payloads,
  examples, and docs.
- [x] Keep registration `walletSubjectId` in registration docs and route docs.
- [x] Keep Email OTP `authSubjectId` in provider-auth docs.
- [x] Update error messages so ECDSA wallet identity errors mention `walletId`.
- [x] Update refactor guard tests that search for forbidden `subjectId`.

## Validation

Focused checks:

```sh
pnpm -s type-check:sdk
pnpm -s type-check:server
pnpm -C tests exec playwright test \
  ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts \
  ./unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts \
  ./unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts \
  ./unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts \
  ./unit/thresholdEcdsa.postgresRecords.unit.test.ts \
  ./unit/thresholdSessionClaims.unit.test.ts \
  ./unit/evmFamilyEcdsaIdentity.unit.test.ts \
  ./unit/signingEngine.refactor37.guard.unit.test.ts \
  --reporter=line
```

Broader checks before completion:

```sh
pnpm -s type-check
pnpm -C tests exec playwright test ./unit --reporter=line
cargo test -p ecdsa-hss
cargo test -p threshold-prf
git diff --check -- . ':(exclude)crates/ecdsa-hss/formal-verification/**'
```

Manual flows:

- [x] New passkey ECDSA registration provisions v2 key material and returns a
  v2 owner address.
- [x] New Email OTP ECDSA enrollment/login provisions v2 key material and
  returns a v2 owner address.
- [x] Page refresh rehydrates only v2 ECDSA sealed sessions.
- [x] Existing v1 ECDSA records are pruned and trigger fresh ECDSA provisioning.
- [x] ECDSA export uses v2 context and rejects v1 key handles.

## Completion Criteria

- [x] ECDSA HSS context encoding has a v2 transcript with no subject field.
- [x] Client and server PRF derivation use the same v2 context.
- [x] HSS key ids, root proofs, passkey bootstrap auth digests, session claims,
  and server records have v2 versions with no `subjectId`.
- [x] Core ECDSA flows accept wallet id and exact lane identity with no raw
  subject strings.
- [x] Public ECDSA APIs and docs expose no `subjectId`.
- [x] Registration still uses `walletSubjectId`.
- [x] Email OTP provider identity still uses `authSubjectId`.
- [x] v1 ECDSA HSS keys, sessions, sealed records, and JWTs are rejected or
  pruned at boundaries.

## Cleanup

- [x] Wipe local IndexedDB legacy keys and accounts.
- [x] Wipe local Postgres legacy account and threshold signing state.
- [x] Test new account provisioning, rehydration, signing, and export on clean
  local state.
- [x] Remove the ECDSA v2 Rust/WASM/client/server boundary guards that reject
  `subjectId` and `walletSessionUserId`.
