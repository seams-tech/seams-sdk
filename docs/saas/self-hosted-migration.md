# Self-Hosted Migration Plan

Last updated: 2026-02-18

## Goal

Allow developers to migrate from managed threshold signing to self-hosted threshold signing without lock-in.

Primary outcome:

- A developer can move signing control to their own nodes with a deterministic cutover process and auditable proof of completion.

Secondary outcome:

- We support both low-friction migration (same key/address) and strict trust-reset migration (new key).

## Current Context

- We operate as wallet-as-a-service and hold relayer threshold signing material.
- Existing signing stack already supports threshold Ed25519 and threshold secp256k1/ECDSA flows.
- ECDSA 2-party share mapping is already implemented for the current scheme (`shared/src/threshold/secp256k1Ecdsa2pShareMapping.ts`).

## Design Principles

- No lock-in by default: migration is a first-class product path.
- Clean path only: no hidden fallback behaviors.
- Tenant isolation: no cross-tenant master-secret reuse.
- Same-key migration first, trust-reset rotation optional.
- Cryptographic operations remain WASM-first on client and signer runtime boundaries.
- Every migration is auditable end-to-end.

## Non-Goals (V1)

- Generic N-party migration for arbitrary committee sizes beyond current supported patterns.
- Zero-knowledge key injection protocols where no runtime ever observes import key material.
- Supporting legacy migration APIs or deprecated endpoint aliases.

## Migration Modes

### Mode A (Default): Same-Key Cutover

Objective:

- Preserve existing public key/address and migrate signer control to developer-hosted nodes.

Approach:

- Transfer/reshare server-side threshold shares to the target self-hosted signer set.
- Activate new key epoch on target cluster.
- Immediately disable old epoch in managed service.

Benefits:

- No account/address churn for end users.
- Minimal app-side and chain-side migration cost.

Tradeoff:

- Historical trust still includes the period where managed service held shares.

### Mode B (Optional): Trust-Reset Rotation

Objective:

- Provide strongest forward trust guarantee that managed service no longer has any usable relation to active key material.

Approach:

- Developer runs fresh DKG on self-hosted infrastructure.
- Rotate to new public key/address (or access key).
- Decommission old key epoch.

Benefits:

- Cleanest custody boundary after migration.

Tradeoff:

- Operational and UX cost (especially for EVM EOAs where address changes).

## Proxy Re-Encryption Position

- Proxy re-encryption can be used as a secure transport primitive for encrypted share payloads between console and relay services.
- PRE does not by itself solve trust-reset semantics.
- Use PRE only as an implementation detail for Mode A transfer, not as the core trust argument.

## Key Hierarchy and Tenant Isolation

### Requirements

- Each developer (tenant) gets a unique `tenant_master_secret`.
- Never use one global master secret across all developers.

### Derivation Model

- `tenant_master_secret` lives wrapped at rest.
- Per-key material is derived with strict context separation:
  - context: `tenant_id || key_id || epoch || scheme || purpose`
- This ensures independent secrets across developers and across keys/epochs.

### Storage Model

- Store only wrapped key material in application stores.
- Wrapping key (KEK) must be non-exportable in KMS/HSM.

## Backup and Recovery Plan

### Primary Durability

- Multi-region KMS/HSM KEK replicas.
- Durable DB/object backups for wrapped tenant key records and metadata.
- Point-in-time restore for key metadata stores.

### Catastrophic Recovery

- Periodic escrow re-wrap of tenant secrets under an offline backup KEK in a separate trust domain/account.
- Split-custody for backup KEK recovery material (e.g. 3-of-5 Shamir custody).
- Dual-control approval for recovery operations.

### Operational Controls

- Recovery drills on a fixed schedule:
  - restore metadata
  - unwrap representative tenant secret
  - execute test sign
  - verify signatures and produce report
- Alerting and runbooks for unwrap failures, region outages, and failed drills.

## Product Flow (Mode A)

1. Developer requests migration for specific `keyId`(s).
2. System creates migration job (`migrationId`) in `planned` state.
3. Developer registers self-hosted signer endpoints + attestation metadata.
4. Managed service exports transfer package (share payload + verification material), encrypted to target trust root.
5. Target cluster imports package and proves liveness by completing challenge-sign.
6. Control plane switches active epoch to target and locks managed epoch.
7. Managed service destroys/archives old active share according to retention policy.
8. System issues signed migration completion artifact.

## Protocol/State Model

### Key Record Fields (minimum)

- `tenantId`
- `keyId`
- `algorithm` (`ed25519` | `secp256k1`)
- `publicKey` / `address`
- `participantSet`
- `epoch`
- `status` (`active` | `migrating` | `retired` | `disabled`)
- `verificationMaterial`
- `createdAt`, `activatedAt`, `retiredAt`

### Migration Job Fields

- `migrationId`
- `tenantId`
- `keyId`
- `sourceClusterId`
- `targetClusterId`
- `mode` (`same_key_cutover` | `trust_reset_rotation`)
- `state` (`planned` | `exported` | `imported` | `verified` | `cutover_complete` | `aborted`)
- `stateTransitions[]` with actor/time metadata

## API Plan (new clean endpoints)

Namespace split:

- `/console/*` for migration orchestration/admin APIs.
- `/relay/*` for signer-runtime protocol helpers.

### Common

- `POST /console/threshold-migrations/start`
- `POST /console/threshold-migrations/:migrationId/export`
- `POST /console/threshold-migrations/:migrationId/import-ack`
- `POST /console/threshold-migrations/:migrationId/verify`
- `POST /console/threshold-migrations/:migrationId/cutover`
- `POST /console/threshold-migrations/:migrationId/abort`
- `GET /console/threshold-migrations/:migrationId`

### Scheme-Specific Helpers

- `POST /relay/threshold-ecdsa/migrations/*` for secp256k1 specific proof/metadata.
- `POST /relay/threshold-ed25519/migrations/*` for Ed25519 specific proof/metadata.

No legacy aliases:

- V1 ships only canonical endpoints above.

## Security Controls

- Two-man rule for migration cutover and abort.
- Strong developer re-auth for migration actions.
- Replay-resistant migration tokens and bounded TTL.
- Idempotent APIs with deterministic error codes.
- Strict audit log:
  - who initiated
  - what key/tenant
  - what state transition
  - cryptographic fingerprint of transferred package

## Phase Plan

### Phase 0: Contract Lock

- [ ] Finalize migration modes, state machine, and error taxonomy.
- [ ] Lock canonical API schema and event model.
- [ ] Lock key retention/deletion policy after cutover.

Definition of done:

- Engineering can implement without policy ambiguity.

### Phase 1: Control Plane and Data Model

- [ ] Add migration job store and key epoch fields.
- [ ] Add migration endpoints and authz checks.
- [ ] Add signed audit artifact generation.

Definition of done:

- Migration lifecycle is fully representable and queryable.

### Phase 2: Mode A (Same-Key Cutover) for ECDSA

- [ ] Implement export package generation for current threshold ECDSA key records.
- [ ] Implement target import verification + liveness proof.
- [ ] Implement epoch cutover + managed epoch disable.
- [ ] Add failure rollback before cutover and explicit no-rollback after cutover.

Definition of done:

- Existing ECDSA key can migrate with unchanged address and deterministic cutover.

### Phase 3: Mode A (Same-Key Cutover) for Ed25519

- [ ] Implement equivalent export/import/cutover for Ed25519 key records.
- [ ] Verify NEAR-facing key continuity and signing correctness post-cutover.

Definition of done:

- Existing Ed25519 key migrates with unchanged public key.

### Phase 4: Tenant Secret Durability Hardening

- [ ] Implement KEK-wrapped tenant secret hierarchy in KMS/HSM.
- [ ] Add multi-region replication and backup catalog.
- [ ] Add offline escrow re-wrap pipeline with split-custody procedures.
- [ ] Add automated recovery drills + reporting.

Definition of done:

- Loss of one region or one data plane does not cause permanent tenant key loss.

### Phase 5: Trust-Reset Rotation (Mode B)

- [ ] Add optional DKG-based rotation flow.
- [ ] Add chain-specific rotation helpers (NEAR access key replacement, EVM rotation guidance).
- [ ] Add migration wizard path for developers requiring strict trust reset.

Definition of done:

- Developers can choose stronger trust guarantees with explicit UX tradeoffs.

## Test and Validation Gates

- [ ] Unit: migration state machine transition validity and idempotency.
- [ ] Unit: package fingerprinting and verification integrity checks.
- [ ] Integration: export/import/verify/cutover happy path for ECDSA and Ed25519.
- [ ] Integration: target cluster liveness challenge-sign validation.
- [ ] Chaos drill: source cluster outage during `exported`/`imported` phases.
- [ ] Recovery drill: restore wrapped tenant secrets and perform test-sign.

## Open Decisions

- Exact proof format for target cluster attestation and challenge-sign policy.
- Retention window for disabled source shares after successful cutover.
- Default customer-facing recommendation for Mode A vs Mode B by chain type.

## Immediate Action Items

- [ ] Create `threshold-migrations` API contracts in server types.
- [ ] Add migration job store with explicit state enum and transition validator.
- [ ] Add signed completion artifact schema and generation path.
- [ ] Document customer runbook for self-hosted signer bootstrap and cutover day.
- [ ] Link this plan from import/signing architecture docs.
