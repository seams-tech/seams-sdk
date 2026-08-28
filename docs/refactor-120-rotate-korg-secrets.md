# Refactor 120: Per-Tenant Proactive Derivation-Root Share Refresh

Created: June 11, 2026

Rewritten: August 28, 2026

Status: proposed implementation plan. The refresh protocol is unimplemented.
Production rollout is gated on refresh-invariant Ed25519 derivation and credible
retired-share erasure.

## Outcome

Give every tenant a distinct server-side derivation root and refresh its two
Deriver shares without changing the root itself.

After the new derivation profile is active, one tenant refresh:

- changes both Deriver root shares;
- advances one `TenantRootShareEpoch`;
- preserves every wallet public key and address;
- preserves `signingRootId` and `signingRootVersion`;
- leaves wallet custody seeds, Ed25519 Yao Client roots, ECDSA client root
  shares, passkeys, local databases, signer packages, and
  `MpcMaterialActivationRef` values untouched;
- requires no WebAuthn ceremony, client message, wallet scan, or per-wallet
  activation;
- leaves normal signing available throughout the refresh.

The scalar refresh is small and well understood. The overall refactor is
moderate rather than trivial. Two parts carry most of the work:

1. Ed25519 must derive from the refresh-invariant joined tenant root instead of
   separately hashing the two role shares.
2. Retired shares must remain unrecoverable through Worker rollback, database
   history, backups, or retained wrapping keys.

## Terminology

These terms name different layers:

| Term                        | Meaning                                                                                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant derivation root      | One stable server-side secret derivation origin for one tenant                                                                                                |
| `TenantRootIdentityV1`      | Canonical server-resolved tuple of organization, project, environment, `signingRootId`, and `signingRootVersion`; it names one logical derivation root          |
| `TenantRootCustodyLineageId` | Random identifier for one deployment's custody of a logical tenant root; it changes after restore and never enters stable derivation                         |
| Deriver root share          | Deriver A or B's 2-of-2 Shamir share of that tenant root                                                                                                      |
| `signingRootId`             | Persisted identifier for the logical signing-root namespace; it is not secret material                                                                        |
| `signingRootVersion`        | Stable derivation-version metadata; changing it may select different wallet keys                                                                              |
| `TenantRootShareEpoch`      | New server-custody epoch selecting the active A/B tenant derivation-root share pair                                                                           |
| `TenantRootRecoverySetId`   | Identifier for one dedicated tenant-controlled A/B recovery sharing; it is metadata, never root or share material                                             |
| Tenant recovery share       | One role's share from a tenant-controlled recovery set; it is separate from every operational epoch share                                                     |
| `RootShareEpoch`            | Existing persisted epoch marker for durable ECDSA material; Refactor 120 does not repurpose or mutate it                                                      |
| Role operational key        | A role-local KEK, HPKE key, peer-authentication key, or service credential                                                                                    |
| Wallet custody seed         | The client-controlled secret derivation origin for owner signing roots                                                                                        |
| Active wallet signing share | Already-provisioned client or SigningWorker material used for normal signing                                                                                  |

The phrase server-seed rotation in product discussion means tenant derivation-root
share refresh. A tenant derivation-root replacement is a different operation and
normally changes deterministically derived wallet material.

## Rotation Taxonomy

| Operation                            | Client action                   | Wallet identity                   | Security effect                                           |
| ------------------------------------ | ------------------------------- | --------------------------------- | --------------------------------------------------------- |
| Role operational-key rotation        | None                            | Unchanged                         | Rewraps or replaces one role-local protection key         |
| Tenant derivation-root share refresh | None                            | Unchanged                         | Replaces both A/B shares while preserving the joined root |
| Tenant derivation-root replacement   | Wallet migration                | Usually changes                   | Replaces a root that may be fully compromised             |
| Wallet or lane share refresh         | Depends on the signing protocol | Unchanged when correctly reshared | Replaces already-active threshold signing material        |

Refactor 120 owns only tenant derivation-root creation and share refresh.
Role-key rotation remains role-local. Wallet and execution-lane share refresh
remain curve-specific lifecycle operations.

## Decisions

1. Every Router A/B tenant has a physically distinct tenant derivation root.
2. Each tenant root uses the strict Router A/B 2-of-2 policy. Deriver A and
   Deriver B each hold exactly one share.
3. One authenticated tenant maps to exactly one active root identity. Requests
   cannot select a tenant, root, share, Deriver, or epoch.
4. `signingRootId` and `signingRootVersion` remain the persisted derivation
   identity. Their serialized names remain unchanged.
5. `TenantRootShareEpoch` is a new custody type. It never enters stable wallet
   KDF input or durable signing-material activation identity.
6. The existing `RootShareEpoch` type and serialized fields remain durable ECDSA
   material metadata. A tenant-root refresh does not mutate them.
7. Refresh changes the two role shares and `TenantRootShareEpoch`. The joined
   tenant root stays constant.
8. Initial tenant-root creation is distributed. No bootstrap process, Router,
   Gateway, SigningWorker, database, or control-plane record receives the
   joined root or both shares.
9. Each role stores tenant shares only inside its private custody boundary.
   The shared Gateway and SigningWorker databases never store them.
10. Ed25519 uses a joined-root Yao derivation profile. Raw role shares enter only
    as protected circuit inputs, and the joined root remains on garbled wires.
11. ECDSA threshold-PRF evaluation uses a stable derivation context and a
    separate epoch-bound custody transcript.
12. The current derivation profile is replaced directly. Production code keeps
    no dual profile, fallback, legacy epoch KDF, or compatibility branch.
13. A refresh is O(1) in the selected tenant's wallet count. Fleet-wide rotation
    is O(number of tenants) and runs through bounded, jittered jobs.
14. Normal signing uses already-active material and remains available. Only new
    derivation ceremonies for the selected tenant are briefly fenced.
15. A refresh never changes active SigningWorker shares. Rotating those shares
    requires the corresponding wallet or lane protocol.
16. Tenant derivation-root replacement is an explicit wallet-identity migration.
    It never masquerades as a share-epoch increment.
17. Managed and self-hosted deployments create and refresh their roots
    independently. Cross-deployment device linking transfers no root share.
18. Client transparency is a release invariant. Once the new profile is
    deployed, future refreshes require zero client ceremonies or local-state
    changes.
19. Compromise-healing claims require verified destruction of retired shares
    and their epoch wrapping keys.
20. The no-client guarantee begins after the per-tenant, refresh-invariant
    derivation profile is authoritative. Converting an existing shared-root or
    epoch-dependent wallet population is a separate one-time cutover.
21. Tenant roots are created from fresh contributory randomness. They are not
    deterministically recoverable from tenant identifiers, deployment secrets,
    wallet records, or control-plane state.
22. Managed availability backup stores one role's current share per backup
    object. A backup never contains the joined tenant root or both role shares.
23. Deriver A and Deriver B managed backups use distinct encryption keys,
    restore authorizations, storage namespaces, and audit trails. No normal
    recovery process can decrypt both roles.
24. Backup activation and retirement are part of the root-share epoch
    transition. A refresh cannot claim compromise healing while a retired share
    or its backup decryption key remains recoverable.
25. Tenant-controlled recovery uses a dedicated, independently randomized 2-of-2
    sharing of the stable tenant root. It never copies an operational epoch
    share into a tenant package.
26. Deriver A and Deriver B encrypt their tenant recovery shares to separate
    tenant-controlled recipients. One package, recipient, command, or restore
    endpoint handles one role.
27. Tenant recovery sharing is versioned by `TenantRootRecoverySetId` and remains
    valid across operational-share refreshes. Replacing it creates a fresh
    sharing from the active roles and cannot revoke tenant-held copies of an old
    recovery set.
28. A complete tenant recovery set is a persistent offline recovery capability.
    Operational refresh heals exposure of retired operational shares; it cannot
    heal compromise of both shares from one tenant recovery set.
29. The root field, scalar encoding, share IDs, and commitments reuse the
    existing `threshold-prf` Ristretto255/SHA-512 suite. Refactor 120 does not
    introduce a second root algebra.
30. Every deployment copy of a logical root has a random
    `TenantRootCustodyLineageId`. Operational epochs, locks, commands, receipts,
    and erasure claims are lineage-local. Restore preserves
    `TenantRootIdentityV1` and creates a new lineage.
31. One tenant-root Durable Object is the authoritative lifecycle sequencer.
    Deriver stores hold role-private material and signed receipts; they never
    choose the active epoch independently.
32. Managed deployments claiming proactive compromise healing use independent
    Deriver A and Deriver B external KMS or HSM key-version authorities. D1 and
    Cloudflare Secrets Store alone are an operational-rotation profile because
    they do not provide the per-tenant, per-epoch destruction evidence this
    claim requires.
33. A refresh rejects an identity aggregate delta, either zero next share, a
    changed public root commitment, or any non-canonical scalar. The roles
    discard pending material and begin with fresh randomness.
34. The first release schedules each tenant every 30 days with bounded
    deployment-wide concurrency and a tenant-specific 24-hour jitter window.
    An operator may request an earlier refresh after role cleanup.
35. Managed one-role recovery restores only the authoritative current epoch and
    immediately performs a forward refresh. Tenant-controlled recovery restores
    both dedicated recovery shares into a fresh custody lineage.
36. Tenant-root deletion is an irreversible lifecycle. It fences derivation,
    destroys both online and managed-backup key versions, deletes service-held
    tenant recovery ciphertext, and retains only redacted public audit evidence.
    Tenant-held recovery copies remain outside service control.
37. The launch cutover regenerates every test, staging, or unreleased root and
    all material derived through the retired profile. Any externally relied-on
    wallet identity blocks this cutover and requires its own explicit migration;
    production keeps no dual profile.
38. One unavailable Deriver makes new derivation ceremonies unavailable for
    that tenant. Normal signing with already-active material continues. The
    service never substitutes a weaker one-role derivation path.

## Frozen Core Contracts

### Root identity and custody lineage

`TenantRootIdentityV1` contains these required UTF-8 fields in this order:

```text
orgId
projectId
envId
signingRootId
signingRootVersion
```

The authenticated server resolves all five fields. `signingRootId` must equal
the canonical project/environment signing-root identifier already stored by the
wallet server; a mismatch fails at the boundary. The canonical identity bytes
are the ASCII domain `seams/tenant-root-identity/v1`, followed by the exact UTF-8
bytes supplied by each existing authoritative ID type as a four-byte big-endian
length and field bytes. This layer performs no trimming, case folding, or
Unicode normalization; non-canonical raw inputs fail in the owning boundary
parser before identity construction.
`TenantRootIdentityDigestV1` is SHA-256 over those bytes. Empty fields,
unknown fields, caller overrides, and a second encoding are rejected.

`TenantRootCustodyLineageId` is 128 random bits encoded as unpadded base64url.
It is required in every custody store key, protocol transcript, command,
receipt, backup AAD, import envelope, and lifecycle record. It is excluded from
`StableTenantDerivationContextV2`, so a source and restored destination can hold
the same logical root under different, non-interchangeable custody histories.

`TenantRootShareEpoch` is a positive `u64`, starts at 1 in each lineage, and
increments by exactly one after a successful activation. It is never inferred
from `signingRootVersion`, `RootShareEpoch`, timestamps, row order, or a role's
local store.

### Root field and public commitments

The protocol reuses `SuiteId::Ristretto255Sha512` and the existing
`SigningRootScalar`, `SigningRootShareWire`, and
`SigningRootShareCommitment` implementations:

- scalars are canonical 32-byte little-endian values modulo the Ristretto255
  scalar order;
- a role share wire is a two-byte big-endian share ID followed by the canonical
  scalar;
- Deriver A has share ID 1 and Deriver B has share ID 2;
- commitments are canonical 32-byte compressed Ristretto points;
- the stable public root commitment is `K_pub = 2*C_A - C_B`.

Creation rejects zero A, zero B, and identity `K_pub`. Refresh samples nonzero
`rho_A` and `rho_B`, then rejects `R_A + R_B` equal to the identity, zero A',
zero B', or a changed `K_pub`. A rejection activates nothing. Both roles
zeroize the failed session and resample.

Every role proves knowledge of a committed scalar with a Ristretto Schnorr proof.
For secret `s`, the role samples nonzero `r`, publishes `T = r*G`, derives c by
reducing `SHA-512(canonicalTranscript || C || T)` with
`Scalar::from_bytes_mod_order_wide`, and returns `z = r + c*s`. Verification
checks `z*G = T + c*C`. The proof wire is the
32-byte compressed T followed by the 32-byte canonical z; identity T,
non-canonical points/scalars, and a zero challenge are rejected and resampled.

The canonical transcript binds protocol version (`tenant_root_create_v1`,
`tenant_root_refresh_v1`, or `tenant_root_recovery_reshare_v1`), operation,
identity digest, custody lineage, current and next epoch or recovery-set ID,
session ID, role, share ID, commitment, peer commitment, nonce, expiry, and role
signing-key IDs. Scalar updates use the existing
`hpke_x25519_hkdf_sha256_aes256gcm_v1` suite and repeat those public fields in
authenticated data. All messages carry an Ed25519 signature from the issuing
role. Scalars come from the platform CSPRNG through `CryptoRng + RngCore` and
the dalek rejection-sampling API. Canonical transcript fixtures are generated
from Rust and consumed by every other runtime.

Canonical transcript framing is the ASCII protocol domain followed by ordered
fields, each encoded as a four-byte big-endian length and exact bytes. Epochs,
share IDs, and issued/expiry Unix milliseconds use fixed-width big-endian
integers inside their field. Session IDs are 128 random bits and nonces are 32
random bytes. Text IDs reuse their authoritative parsed UTF-8 bytes. Unknown,
missing, duplicated, out-of-order, or trailing fields fail before proof or
signature verification. Protocol peers allow at most 60 seconds of clock skew;
larger skew fails the session and alerts operations.

### Authoritative lifecycle and crash recovery

One Durable Object keyed by `TenantRootIdentityDigestV1` and
`TenantRootCustodyLineageId` owns the operation lock, monotonic lifecycle
revision, active epoch, root commitment, and accepted role-receipt digests. A
role can install pending material only from a one-use command containing the
expected revision. Derivation requests receive a control-plane-signed active
custody binding and each Deriver accepts only that exact epoch.

Activation follows one direction:

1. both roles install pending shares and current-epoch managed backups;
2. both return signed commitment and backup receipts;
3. continuity canaries pass;
4. the Durable Object commits the next epoch as active with compare-and-swap;
5. both roles receive the signed activation receipt and retire the previous
   epoch.

Before step 4, recovery deletes pending material and keeps the old epoch active.
After step 4, recovery resumes retirement or starts another forward refresh;
rollback to the previous epoch is forbidden. Every command is idempotent by
session ID and payload digest. Repeating an identical command returns its prior
receipt; reusing an ID with different bytes fails.

Each role store and its managed backup retain the same signed activation-receipt
digest. If Durable Object state is unavailable, derivation and mutation freeze.
Control-plane reconstruction requires matching current activation receipts from
both roles. Any mismatch requires tenant-controlled restore into an empty
lineage.

### Deployment security profiles

The first release exposes two explicit deployment profiles:

| Profile | Key boundary | Permitted claim |
| --- | --- | --- |
| `managed_healing_v1` | Independent A/B external KMS or HSM providers, with a distinct non-exportable key version for every tenant, role, epoch, and managed backup | Verified proactive compromise healing after both provider destruction probes pass |
| `operational_rotation_v1` | Deployment-selected role-local encryption, including Cloudflare-native storage | Active shares rotate and rollback is prevented by application state; cryptographic erasure and compromise healing are unclaimed |

Cloudflare D1 keeps recoverable database history through Time Travel, and
Cloudflare Secrets Store is an account-level secret service rather than a
per-tenant epoch-key destruction authority. Consequently, deleting a D1 row or
rotating one shared Worker secret is insufficient evidence for
`managed_healing_v1`. Provider selection remains a deployment qualification;
the protocol depends only on versioned create, encrypt/decrypt, destroy, and
destruction-probe operations with role-separated credentials.

## Security Goal

A successful refresh limits the usefulness of one previously exposed Deriver
share.

Suppose an attacker obtains Deriver A's epoch 7 share. After both honest roles
refresh to epoch 8, erase epoch 7, and prevent rollback, that old A share cannot
combine with Deriver B's epoch 8 share. The attacker still needs both shares
from one recoverable epoch.

The guarantee holds only after:

1. the exposed role and its administrative credentials are clean;
2. both roles complete the refresh in uncompromised runtimes;
3. the next epoch is verified and activated;
4. old shares, deltas, ephemeral keys, online wrapping keys, backup ciphertexts,
   and backup key versions are destroyed;
5. Worker, database, secret, backup, and disaster-recovery rollback cannot
   recover the old epoch.

This guarantee covers managed operational shares and their availability
backups. A tenant-controlled recovery set has a separate custody policy. The
security claim assumes an adversary has not obtained both recovery packages and
both matching recovery private keys from one set.

Exposure of both shares from one recoverable epoch compromises the tenant root.
Share refresh cannot repair that event. The response is tenant derivation-root
replacement and explicit wallet migration.

Tenant roots reduce cryptographic blast radius. Compromise of both root shares
for tenant A does not reveal tenant B's root. A full compromise of both Deriver
roles can still expose every tenant that those roles serve.

This refresh protects derivation-root custody. It does not refresh active client
or SigningWorker signing shares.

## Architecture

```text
authenticated tenant
  -> stable signingRootId + signingRootVersion
       -> authoritative active TenantRootShareEpoch
            -> Deriver A private share store: A_tenant,epoch
            -> Deriver B private share store: B_tenant,epoch

stable tenant derivation root
  K_tenant = 2*A_tenant,epoch - B_tenant,epoch
  -> ECDSA threshold PRF
  -> Ed25519 joined-root Yao
  -> stable wallet server contributions
```

The Gateway resolves the tenant-root identity from authenticated deployment
configuration. The Router receives one verified tenant-root binding and exact
active epoch. A browser request cannot provide or override either value.

Each Deriver private store contains:

- tenant scope;
- `signingRootId`;
- `signingRootVersion`;
- `TenantRootShareEpoch`;
- role identity;
- sealed role share;
- share commitment;
- epoch wrapping-key reference;
- current-epoch role-backup receipt;
- lifecycle state and timestamps.

The control plane stores only public lifecycle state, commitments, transcript
digests, canary results, and receipts.

## Initial Tenant-Root Creation

Initial creation must avoid a process that observes both shares.

For fixed Shamir share IDs 1 and 2:

```text
Deriver A samples A
Deriver B samples B

K = 2*A - B
```

Any valid pair `A` and `B` defines one degree-one Shamir polynomial and its
constant `K`. If either role samples honestly, `K` is unpredictable to the
other role.

The creation ceremony:

1. Allocates the tenant-root identity and epoch 1.
2. Opens an authenticated A/B session bound to the tenant, root identity,
   epoch, roles, protocol version, nonce, and expiry.
3. Both roles commit to independently sampled nonzero shares before revealing
   public share commitments.
4. Both roles prove knowledge of their committed shares.
5. The Router computes the public tenant-root commitment
   `K_pub = 2*C_A - C_B` and rejects the identity element.
6. Each role installs its own sealed pending share.
7. Fixed ECDSA and Ed25519 canaries run against the pending epoch.
8. The control plane activates epoch 1 after both roles attest installation and
   every canary passes.

Neither scalar share crosses into the opposite role. Only commitments, proofs,
and redacted receipts leave a Deriver.

## Proactive Share Refresh

For tenant root `K`, current shares `A` and `B`, and fresh scalar `rho`:

```text
K = 2*A - B

A' = A + rho
B' = B + 2*rho

2*A' - B' = 2*A - B = K
```

Both roles contribute randomness:

```text
rho = rho_A + rho_B

Deriver A sends 2*rho_A to Deriver B.
Deriver B sends rho_B to Deriver A.

A' = A + rho_A + rho_B
B' = B + 2*rho_A + 2*rho_B
```

Before sending updates:

- A commits to `R_A = rho_A*G`;
- B commits to `R_B = rho_B*G`;
- A verifies the received B update against `R_B`;
- B verifies the received A update against `2*R_A`.

Both roles then verify that `R_A + R_B` is not the identity and that their own
next share is nonzero. Either failure aborts the session and forces fresh
contributions. This prevents a no-op refresh and prevents one next share from
collapsing the effective two-role secrecy boundary.

All scalar operations use the root field. Updates travel through the
authenticated encrypted A/B channel and remain inside the refresh session.

The complete ceremony:

1. Resolve the exact authenticated tenant and active root identity.
2. Acquire a per-tenant refresh lock.
3. Allocate the next `TenantRootShareEpoch`.
4. Fence new derivation ceremonies for that tenant.
5. Open a one-use A/B refresh transcript bound to current and next epochs.
6. Commit to independently sampled refresh contributions.
7. Exchange encrypted recipient-specific updates.
8. Verify contributions and calculate role-local next shares.
9. Seal next shares under fresh epoch wrapping keys.
10. Publish next-share commitments and proofs of possession.
11. Verify `2*C_A' - C_B' = K_pub`.
12. Run fixed ECDSA and Ed25519 continuity canaries.
13. Mark the next epoch verified.
14. Activate it for new derivations after both role receipts pass.
15. Unfence tenant derivation.
16. Destroy previous-epoch shares, refresh material, and previous-epoch wrapping
    keys.
17. Verify both destruction receipts and return the lifecycle to `active`.
18. Emit a redacted receipt and release the lock.

Normal signing continues during every step because it does not read tenant root
shares.

## Stable Derivation Boundary

### ECDSA

The legacy generic ECDSA derivation context includes `RootShareEpoch`. Refactor
120 removes that record from the threshold-PRF input. The stable input is the
existing byte-exact
`RouterAbEcdsaDerivationStableKeyContextV1::canonical_context_bytes()`:

```text
router-ab-ecdsa-derivation context domain
scheme ID
curve ID
32-byte application-binding digest
participant count
ordered u16 participant IDs
```

Refactor 120 names those bytes `StableTenantDerivationContextV2` at the
tenant-root boundary and keeps their encoding unchanged. The tenant identity is
already represented cryptographically by its unique root. Adding deployment,
lineage, epoch, ceremony, or retry metadata to this stable input would make
refresh change derived wallet material and is forbidden.

Custody uses a separate record:

```text
TenantRootCustodyBindingV1
  TenantRootIdentityDigestV1
  TenantRootCustodyLineageId
  TenantRootShareEpoch
  Deriver identities
  share commitments
  operation and session IDs
  request nonce, expiry, and transcript digest
```

Threshold-PRF evaluation depends on the stable context bytes and the selected
role share. Partial proofs, routing, share selection, replay protection,
persistence AAD, and role commands bind the custody record. `RootShareEpoch`
continues to identify already-created durable ECDSA material and is never
translated into `TenantRootShareEpoch`.

Changing only `TenantRootShareEpoch` must leave stable context bytes and
threshold-PRF output unchanged.

### Ed25519

The current Ed25519 profile hashes each role share independently before the
garbled circuit. Share refresh changes those hashes and therefore changes its
derived output.

The replacement profile freezes this function:

1. admits A and B as protected scalar inputs;
2. binds each input to the authenticated role, active epoch, and installed share
   commitment;
3. parses canonical Ristretto scalars and reconstructs `K = 2*A - B` only on
   garbled wires;
4. rejects zero K and serializes it to the canonical 32-byte scalar encoding;
5. runs the existing `signer-core` Ed25519 Yao contribution KDF twice inside
   the circuit using K as the derivation root, the existing stable application
   context, `SERVER_SOURCE_TAG`, and the existing A or B role tag;
6. preserves the existing HKDF-SHA-256 extract salt, expand-info domains, y
   output, tau reduction, and recipient package shapes byte for byte;
7. never decodes or returns K.

The required equivalence is between any two valid A/B sharings of the same K
under this joined-root profile. It is not equivalence with the retired
role-local-root profile. Pre-launch cutover regenerates its unreleased outputs.

The joined-root profile requires a new circuit manifest, protocol version,
cache identity, vectors, formal checks, and explicit performance budget.

Production must use one authoritative profile. If existing production wallets
depend on the role-local hashing profile, rollout requires one explicit
pre-cutover migration. The implementation retains no dual derivation path.

## Client Transparency

Once the stable derivation profile is deployed, a refresh causes no client
operation:

- no passkey prompt;
- no iframe or SDK callback;
- no wallet custody-seed access;
- no IndexedDB mutation;
- no Ed25519 Yao Client root or ECDSA client root share replacement;
- no signer-package download;
- no wallet-key or lane reactivation;
- no `MpcMaterialActivationRef` change.

Clients may require a normal SDK release for the one-time protocol-profile
cutover if current public wires expose derivation epochs. Every subsequent
tenant refresh is entirely server-side.

Registration and recovery re-establishment use the active epoch whenever they
invoke server derivation. They derive identical wallet-key material because the
joined tenant root and stable context remain unchanged. Factor addition, device
linking, and export do not become root-refresh ceremonies and keep their
existing client behavior.

The initial conversion from one deployment-wide root to distinct tenant roots
cannot inherit this guarantee automatically. A fresh tenant root normally
changes deterministic outputs. The clean rollout creates tenant roots before
production wallets depend on the old profile. Any existing population requires
an explicit migration plan or a documented decision to preserve its current
root profile until retirement.

## Lifecycle

The control-plane state is exhaustive and contains no secret share bytes:

```ts
type TenantRootRefreshStateV1 =
  | {
      readonly kind: 'active';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next?: never;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure?: never;
    }
  | {
      readonly kind: 'preparing';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next: PendingTenantRootEpochV1;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure?: never;
    }
  | {
      readonly kind: 'verified';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next: VerifiedTenantRootEpochV1;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure?: never;
    }
  | {
      readonly kind: 'retiring';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly previous: RetiringTenantRootEpochV1;
      readonly activation: TenantRootActivationReceiptV1;
      readonly next?: never;
      readonly failure?: never;
    }
  | {
      readonly kind: 'failed_before_activation';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next: FailedTenantRootEpochV1;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure: TenantRootRefreshFailureV1;
      readonly cleanup: TenantRootPendingCleanupReceiptV1;
    }
  | {
      readonly kind: 'cleanup_incomplete';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next: FailedTenantRootEpochV1;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure: TenantRootRefreshFailureV1;
      readonly cleanup: TenantRootPendingCleanupFailureV1;
    };
```

Boundary parsers normalize raw control-plane and role receipts once. Core
functions accept only the exact preceding branch. Every switch is exhaustive.
Type fixtures reject mixed current/next epochs, missing role receipts, direct
object-literal construction, broad spreads, and invalid activation calls.

A verified transition activates one exact next epoch and enters `retiring`.
Normal derivation uses the new current epoch while both roles destroy the
previous epoch. Destruction receipts return the lifecycle to `active`. A failed
pre-activation transition reaches `failed_before_activation` only after both
pending-share and pending-key cleanup receipts exist. Incomplete cleanup has its
own operational branch and blocks another mutation. After activation, rollback
is unavailable; remediation uses another forward refresh. A lifecycle stuck in
`retiring` remains operational and cannot claim proactive compromise healing.

The other tenant-root machines use these exhaustive branches:

- creation: `empty`, `preparing`, `verified`, `active`,
  `failed_before_activation`, `cleanup_incomplete`;
- managed role restore: `available`, `role_unavailable`, `restoring_a`,
  `restoring_b`, `verifying`, `forward_refreshing`, `cleanup_incomplete`;
- deletion: `active`, `fenced`, `destroying`, `deleted`,
  `destruction_incomplete`.

Refactor 121 freezes tenant recovery-set and source-independent restore states.
`ActiveTenantRootEpochV1` and `VerifiedTenantRootEpochV1` require either two
current-epoch role-backup receipts or the explicit
`accepted_permanent_derivation_loss` deployment policy. Optional backup receipts
would make an unsafe activation state representable.

## Storage and Erasure

Per-tenant shares cannot use one Cloudflare secret binding per epoch at fleet
scale. They require role-private indexed storage plus a destroyable wrapping-key
boundary.

Each epoch share is encrypted under a fresh epoch wrapping key. A stable role KEK
must not be able to reconstruct retired epoch keys. Otherwise D1 Time Travel,
backups, or copied ciphertext can recover old shares.

Cloudflare documents that [D1 Time
Travel](https://developers.cloudflare.com/d1/reference/time-travel/) retains
restorable database history and that [D1 encryption keys are managed by
Cloudflare](https://developers.cloudflare.com/d1/reference/data-security/).
[Secrets Store](https://developers.cloudflare.com/secrets-store/manage-secrets/)
is account-scoped and currently has low per-account production-secret limits.
These services may store ciphertext and deployment credentials. The strong
profile therefore keeps per-tenant epoch wrapping-key versions in independent
external role providers and treats D1 rollback as an expected ciphertext-replay
attempt.

The production adapter must demonstrate:

- only the owning Deriver can open its active share;
- plaintext shares are decrypted only into one request/session's zeroizing
  memory and are never cached across requests or stored in isolate globals;
- current and pending are the only usable epochs;
- old ciphertext is useless after epoch-key destruction;
- Worker rollback cannot select or recover a retired share;
- database recovery cannot restore its wrapping key;
- backups exclude plaintext shares and recoverable retired keys;
- logs, metrics, errors, and receipts contain no shares or refresh scalars.

Retirement first fences new derivation, waits for every old-epoch derivation
session to finish or expire, and only then destroys online and backup key
versions. A destruction receipt cannot be issued while an old-epoch session is
in flight.

If the selected platform cannot provide credible epoch-key destruction, the
feature may still rotate the active epoch operationally. Documentation must then
avoid the stronger proactive compromise-healing claim.

Provider qualification must also prove quota, latency, cost, create/destroy
throughput, and permanent-destruction semantics at the projected tenant count.
The capacity model includes distinct online and managed-backup key versions for
both roles, one pending epoch during rotation, and active/pending tenant-recovery
package retention keys from Refactor 121. A quota failure slows or blocks
scheduled refresh; it never falls back to a shared fleet KEK.

### Managed availability backup and role-local restore

Fresh tenant-root creation is intentionally non-deterministic. Losing either
current 2-of-2 role share makes future server derivations unavailable, even
though wallets with already-active signing material may continue normal signing.
The system therefore needs an explicit choice between role-local backup and that
loss risk before implementation begins.

Deterministically deriving tenant shares from deployment-wide A/B master seeds
would move the backup problem to two fleet-wide secrets and restore fleet-wide
blast radius. It conflicts with the physically distinct per-tenant root decision.

The production design uses role-local current-epoch backups:

- Deriver A backs up only A's current share; Deriver B does the same for B;
- each backup is bound by authenticated encryption to the tenant root identity,
  role, `TenantRootShareEpoch`, share commitment, format version, and creation
  receipt;
- A and B use distinct recovery key versions and authorization paths;
- restore writes A material only into Deriver A or B material only into Deriver B;
- no restore service, operator tool, script, or customer download reconstructs
  the joined root or receives both decrypted shares;
- after restore, the role proves that the restored share matches the active
  public commitment, then both roles immediately perform a forward refresh;
- activation of epoch N is incomplete until both role-local epoch-N backups are
  committed and their receipts are recorded;
- retirement of epoch N is incomplete until both online and backup key versions
  for epoch N are destroyed and tested as unrecoverable.

Encryption alone does not preserve separation. If one authority can decrypt both
backup objects, Router A/B separation becomes an online-runtime boundary backed
by one offline custodian. That may be an acceptable self-hosted policy, but it is
a weaker custody claim and must be labelled as such. Managed custody requires
independent recovery authorities or hardware-backed key policies for A and B.

The backup system must be forward-only. Retaining an old encrypted share together
with any key path that can still open it makes that old epoch recoverable and
invalidates proactive compromise-healing claims. Backups may retain ciphertext
for audit only when destruction of the corresponding key version is verified.

The restore ceremony must specify and test:

1. who may authorize each role restore and what quorum is required;
2. how role, tenant, root identity, epoch, and commitment substitution are
   rejected;
3. how the current control-plane epoch is recovered when the control plane is
   also unavailable;
4. how split-brain restore and stale-backup replay are rejected;
5. how backup creation, activation, restore, and destruction are audited without
   logging secret material;
6. what remains available while one role is being restored;
7. which evidence proves old backup key versions cannot be recovered through
   provider or deployment rollback.

The first release resolves that list as follows. Each provider accepts only a
role-specific workload identity and a one-use incident capability signed by the
control plane. An A capability cannot authorize B. A managed restore selects the
epoch from the authoritative signed activation receipt; a route request cannot
name an epoch. Matching activation-receipt digests from both roles are required
when rebuilding lost control-plane state. One restored role proves its share
commitment, the peer proves the matching current commitment, and the pair
forward-refreshes before derivation is unfenced. Provider destruction succeeds
only after the old key version is disabled, destroyed, and a decrypt probe over
retained test ciphertext returns the provider's permanent-key-unavailable
result.

During any one-role outage, signing with already-active wallet and lane material
continues. Registration, recovery re-establishment, add-signer derivation,
export preparation, and new lane materialization for the affected tenant return
the typed `tenant_derivation_temporarily_unavailable` result. No operation falls
back to one Deriver or another tenant's root.

### Tenant-controlled recovery backup

A tenant may also choose a source-independent recovery backup. This is distinct
from the managed current-epoch availability backups above.

The active Derivers run a contributory zero-share reshare into a dedicated
recovery namespace. The result is a fresh 2-of-2 sharing of the same stable
tenant root:

```text
recovery_A = active_A + rho_A + rho_B
recovery_B = active_B + 2*rho_A + 2*rho_B

2*recovery_A - recovery_B = K
```

The ceremony uses fresh contributions and the same nonzero, commitment,
knowledge-proof, encrypted-update, role-signature, transcript, and root-
continuity rules as operational refresh. Its transcript substitutes a random
`TenantRootRecoverySetId` and both verified recovery-recipient fingerprints for
the next operational epoch. Recovery shares are installed only in zeroizing
working memory long enough to create their role packages; they never become an
operational epoch or managed availability backup.

- Deriver A receives only recovery share A and encrypts it to the tenant's
  Deriver A recovery recipient;
- Deriver B receives only recovery share B and encrypts it to the tenant's
  Deriver B recovery recipient;
- a signed public manifest binds both ciphertext packages to the tenant root
  identity, `TenantRootRecoverySetId`, role identities, package commitments,
  and stable public root commitment;
- no role, control-plane service, browser, or supported CLI command receives
  both decrypted recovery shares;
- operational-share refresh leaves this recovery sharing unchanged;
- restore imports each role independently into an empty destination, verifies
  stable-root continuity, and immediately performs a forward operational-share
  refresh before activation.

The recovery package and manifest schemas, recipient proof of control,
destination import AAD, trust bundle, replacement transaction, and download
evidence are frozen by Refactor 121. Those product contracts cannot change the
preceding algebra or allow a component to open both role packages.

Keeping the recovery sharing stable avoids forcing a new tenant download after
every operational refresh. It also creates a long-lived recovery target. Anyone
who obtains both encrypted packages and both matching recovery private keys can
recover the tenant root regardless of later operational-share refreshes.

Recovery-set replacement creates a newly randomized sharing and new recipient
ciphertexts. The service can destroy its old ciphertext and working material.
It cannot invalidate copies and keys already controlled by the tenant. Product
copy, audit receipts, and security claims must state this limit directly.

## Root Retirement and Deletion

Deletion acquires the tenant-root operation lock, fences every new derivation,
and moves forward through `fenced`, `destroying`, and `deleted`. Deriver A and B
independently destroy active and pending share key versions, managed-backup key
versions, refresh material, and service-held tenant recovery ciphertext. The
control plane destroys outstanding commands, capabilities, restore sessions,
and provider credentials scoped only to that lineage.

The `deleted` branch requires an exhaustive evidence branch matching the
deployment profile. `managed_healing_v1` requires both role destruction receipts
and provider decrypt probes. `operational_rotation_v1` requires removal from all
active service paths and records `cryptographic_erasure_unverified`. A partial
result stays `destruction_incomplete` and remains fenced. Deletion never makes
tenant-held recovery packages or keys disappear, so the receipt says which
service-held paths were removed and makes no claim about customer copies.

Public identity, commitment, actor, time, outcome, and destruction-receipt
digests follow the existing console audit-retention policy. Ciphertext, key
references capable of decryption, shares, and recovery material are excluded
from retained audit records. Root deletion adds no separate legal-retention
archive.

## Scheduling and Isolation

Refresh jobs are tenant-scoped:

- one refresh lock per tenant root;
- bounded global concurrency;
- one scheduled refresh every 30 days with a tenant-specific 24-hour jitter
  window;
- event-triggered refresh after a role is cleaned;
- exponential retry before activation;
- forward refresh after activation;
- independent failure and audit receipts per tenant.

A refresh for tenant A never fences tenant B. Fleet-wide refresh cost grows with
tenant count, so scheduling must respect Yao capacity and role-store quotas.

The joined-root Yao release gate compares the same release build, circuit
family, inputs, topology, and warm/cold cohort against the current product
benchmark. Warm p95 wall time and peak memory may each increase by at most 25%,
serialized protocol bytes by at most 10%, and runtime circuit synthesis remains
zero. The first scheduler runs one tenant refresh at a time per deployment.
Higher concurrency requires a separate measured capacity change and is not part
of this refactor. Every measured cohort must have at least 100 successful
samples and keep 25% headroom below the selected Workers CPU and memory limits.

## Self-Hosted Wallets

[Refactor 150](../examples/self-host-cloudflare-worker/refactor-150-cloudflare-self-hosted-wallets.md)
creates a destination deployment and provisions a fresh linked authority.

Refactor 120 composes with that model:

- the managed source keeps and refreshes its own tenant root;
- the self-hosted destination creates and refreshes a separate tenant root;
- cross-deployment linking transfers fresh destination-bound signing material,
  never a source root share;
- refreshing either deployment changes no linked wallet public key;
- destination refresh requires no source availability or client participation;
- retaining the source as a backup creates no shared root or refresh lifecycle.

A migrated linked authority can contain signing material whose origin is the
cross-deployment link ceremony. Root refresh still leaves that active material
untouched. The destination tenant root governs future destination derivation
ceremonies.

Refactor 121's source-independent root restore is a different disaster-recovery
operation. It preserves one logical root under a fresh custody lineage and
records whether the source lineage survives. That operation does not migrate
wallet inventory, active SigningWorker material, application routing, RP IDs, or
wallet authorities, so it is insufficient as Refactor 122 deployment
portability by itself.

## Product Operations Follow-up

[Refactor 121](./refactor-121-tenant-derivation-root-security.md) owns the tenant
dashboard and CLI for inspecting root-share health, manually rotating
operational shares, downloading separate encrypted tenant recovery packages,
and restoring each role into an empty replacement of the same logical tenant
root. It consumes this refactor's frozen protocols and does not redefine the
cryptographic lifecycle.

## Preparation Phase: Freeze the Map Before Coding

No production implementation starts until this phase produces five reviewed
artifacts:

1. a closed specification-gap register;
2. a numbered invariant register;
3. a boundary inventory covering every runtime, wire, persistence, generated,
   deployment, and recovery boundary;
4. a test-and-guard matrix assigning one authoritative check to every invariant;
5. an accepted cutover, backup, erasure, and rollback decision record.

The preparation phase may add focused red tests, frozen vectors, type fixtures,
and benchmark harnesses. It does not add production compatibility paths or a
second derivation profile.

### Specification-closure register

The plan review closed the design choices that previously blocked coding.
Preparation still has to turn each decision into canonical vectors, type
fixtures, provider evidence, and red tests before production logic begins.

| Former gap | Resolution in this plan | Required preparation evidence |
| --- | --- | --- |
| Tenant identity | Five required server-resolved fields, one canonical byte encoding, and `TenantRootIdentityDigestV1` are frozen under **Root identity and custody lineage** | Rust canonical vectors, TS boundary fixtures, and caller-override route tests |
| Deployment clone/custody identity | Random `TenantRootCustodyLineageId` separates source and restored custody histories without changing KDF input | Cross-lineage replay and mixed-receipt rejection vectors |
| Root field and transcripts | Existing Ristretto255/SHA-512 scalar, share, commitment, proof, and HPKE primitives are reused with the exact transcript binding above | Creation and refresh vector corpus generated from Rust |
| Stable ECDSA derivation | Existing stable key-context bytes remain the only stable context; both epoch types and ceremony metadata are custody-only | Same-root cross-epoch threshold-PRF vectors and Rust/backend parity |
| Joined-root Ed25519 | The circuit reconstructs canonical K and runs the existing contribution KDF for both role tags | Circuit manifest, formal checks, cross-epoch vectors, and performance gate |
| Active epoch and locking | One lineage-scoped Durable Object owns revision, lock, activation, and crash recovery | Failure injection at every transition and matching-receipt reconstruction drill |
| Online and managed-backup keys | `managed_healing_v1` requires independent external A/B versioned KMS/HSM authorities; Cloudflare-native custody uses `operational_rotation_v1` | Provider adapter qualification and destructive rollback drill |
| Managed recovery | Restore is one-role, current-epoch-only, capability-bound, commitment-verified, and followed by refresh | Independent A and B loss drills plus control-plane-loss drill |
| Tenant recovery | Dedicated stable recovery sharing and its product/CLI protocol are frozen by Refactor 121 | Source-offline restore and mixed-set/role rejection corpus |
| Pre-launch cutover | All unreleased roots and derived material are regenerated; any externally relied-on identity blocks rollout for an explicit migration | Signed inventory proving zero externally relied-on legacy-profile identities |
| One-role availability | Existing signing continues; every operation requiring derivation returns `tenant_derivation_temporarily_unavailable` | Intended-behaviour contract covering every named operation |
| Yao resource budget | Relative p95, memory, wire, synthesis, sample-count, headroom, and initial concurrency gates are fixed under **Scheduling and Isolation** | Reproducible before/after release benchmark artifact |
| Root deletion | Forward-only deletion states, secret destruction scope, customer-copy limitation, and audit retention owner are fixed | A/B partial-failure and destructive staging drills |
| Deployment claims | `managed_healing_v1` and `operational_rotation_v1` expose distinct, test-gated claims | Configuration type fixtures and dashboard copy tests |

An implementation may choose a qualified KMS/HSM vendor or a stricter resource
budget without changing these contracts. A weaker key provider selects
`operational_rotation_v1`; it cannot silently weaken `managed_healing_v1`.

### Invariant register

Every invariant receives a stable ID so the specification, code review, tests,
release evidence, and operational runbooks refer to the same claim.

| ID       | Required invariant                                                                                                                                                                          |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R120-I01 | One canonical authenticated tenant root identity selects exactly one physical root pair and one active epoch.                                                                               |
| R120-I02 | Request bodies, browser state, wallet records, and diagnostic fields cannot select or override tenant, root, role, or epoch.                                                                |
| R120-I03 | No runtime, store, backup object, log, operator tool, or ordinary recovery ceremony obtains the joined root or both decrypted shares.                                                       |
| R120-I04 | Initial creation is contributory: one honest role makes the joined root unpredictable, both roles prove possession, and the public root commitment is non-identity.                         |
| R120-I05 | A successful refresh changes both role shares and preserves the public tenant-root commitment.                                                                                              |
| R120-I06 | Stable ECDSA derivation bytes and threshold-PRF outputs exclude `RootShareEpoch` and `TenantRootShareEpoch` and remain identical across refresh.                                            |
| R120-I07 | ECDSA custody transcripts, partials, routing, persistence AAD, and replay protection bind the exact tenant root identity and active epoch.                                                  |
| R120-I08 | Ed25519 reconstructs and consumes the joined root only on protected Yao wires and produces identical server contributions across refresh.                                                   |
| R120-I09 | Mixed, stale, future, substituted, replayed, expired, or role-swapped creation and refresh messages fail closed.                                                                            |
| R120-I10 | Pre-activation failure preserves the old epoch; post-activation recovery moves forward and never reactivates the previous epoch.                                                            |
| R120-I11 | Normal signing remains available and does not load tenant derivation-root shares.                                                                                                           |
| R120-I12 | Refresh mutates no wallet, client, signer-package, public-key, address, or `MpcMaterialActivationRef` record.                                                                               |
| R120-I13 | Refresh and root creation use approved CSPRNGs, canonical scalar decoding, nonzero checks where required, domain-separated transcripts, and constant-time secret-scalar operations.         |
| R120-I14 | Tenant A's creation, refresh, failure, backup, restore, retirement, and deletion cannot read or mutate tenant B's state.                                                                    |
| R120-I15 | Each current role share has one independently encrypted and authorized role-local backup, or the deployment explicitly accepts permanent loss of future derivation after share loss.        |
| R120-I16 | A restored share is role-, tenant-, root-, epoch-, and commitment-bound; successful restore is followed by a forward refresh.                                                               |
| R120-I17 | Retired online and managed-backup shares are unrecoverable through supported Worker, database, secret, provider, and disaster-recovery rollback paths before compromise healing is claimed. |
| R120-I18 | Generated Rust, WASM, JavaScript, TypeScript, JSON, SQL, and deployment representations agree on every identity, epoch, transcript, and lifecycle field.                                    |
| R120-I19 | Existing production identities either prove continuity under the authoritative profile or are excluded by an explicit pre-cutover decision.                                                 |
| R120-I20 | Independently created or device-linked deployments share no tenant root or role share. Explicit disaster recovery preserves the logical root under a new custody lineage and records every surviving source. |
| R120-I21 | Tenant recovery packages contain one dedicated recovery sharing, remain separate by role, and bind the same stable public root commitment without copying an operational share.             |
| R120-I22 | Operational refresh leaves tenant recovery packages usable and makes no healing claim after both shares or both recipient keys from one tenant recovery set are compromised.                |

### Boundary inventory

The inventory is organized around boundaries where one language's type checker
cannot protect the next system. Each row must record its final symbols, wire or
schema version, owning invariant IDs, planned change, authoritative test, and
review confidence.

| Boundary                              | Current locations to classify                                                                                                                                                                                                                                              | Type-system escape hatch or risk                                                                                                                                   |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Authenticated tenant and root routing | `packages/shared-ts/src/threshold/signingRootScope.ts`; `packages/wallet-server/src/router/auth/commonRouterUtils.ts`; `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthConfig.ts`; project-policy parsing in `crates/router-ab-cloudflare/src/lib.rs` | Independently normalized strings, optional request fields, JWT/policy JSON, and manually derived `projectId:envId` identifiers                                     |
| ECDSA stable derivation               | `crates/router-ab-core/src/derivation/context.rs`, `ecdsa_threshold_prf.rs`, `ecdsa_threshold_prf_backend.rs`; `crates/threshold-prf`; `crates/router-ab-ecdsa-derivation`; `crates/router-ab-core/specs/ecdsa-threshold-prf.md`                                           | Canonical bytes, PRF purpose domains, scalar suites, and downstream derivation contexts compile after a semantically wrong field remains included                  |
| ECDSA custody and protocol wires      | `crates/router-ab-core/src/protocol/ecdsa_threshold_prf_request.rs`, `payload.rs`, `output.rs`, `router_ab_ecdsa_derivation.rs`, `signer_plaintext.rs`; `crates/router-ab-ecdsa-client-protocol/src/registration.rs`, `post_registration.rs`, `recipient_proof.rs`         | Serde JSON, custom length-delimited encodings, plaintext/envelope duplication, and equality checks outside one shared type                                         |
| Ed25519 joined-root derivation        | `crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs`; `crates/signer-core/src/ed25519_yao_derivation.rs`; `crates/router-ab-core/src/protocol/ed25519_yao.rs`; `crates/router-ab-ed25519-yao-client`; `crates/router-ab-ed25519-yao-protocol`; `crates/ed25519-yao`  | Current deployment adapter independently hashes role-labelled share wires; signer-core KDF domains, circuit manifests, garbled inputs, and host adapters can drift |
| Rust/WASM/JavaScript                  | `wasm/router_ab_ecdsa_client/src/ceremony.rs`; `wasm/router_ab_ecdsa_signing_worker/src`; `wasm/wallet_custody_ceremony/src`; checked-in `wasm/*/pkg/*.d.ts`; generated Router A/B TypeScript bindings                                                                     | `serde_wasm_bindgen`, JSON strings, checked-in generated declarations, and separately regenerated WASM packages                                                    |
| Shared TypeScript protocol            | `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`, `routerAbEd25519Yao.ts`, `domainIds.ts`; generated `routerAbEd25519YaoCore.ts`                                                                                                                                  | Manual exact-key parsers and builders duplicate Rust lifecycle and canonical-wire assumptions                                                                      |
| Wallet-server orchestration           | `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`; Ed25519 registration, recovery, export, and capability domains; D1 registration and capability persistence                                                                                   | Route bodies, database rows, and service results are parsed at separate boundaries; current checks sometimes equate root epoch with signing-root version           |
| Wallet SDK and browser workers        | wallet registration, recovery, export, local material, presign-pool, relayer RPC, and worker modules under `packages/wallet/src`                                                                                                                                           | IndexedDB records, Worker messages, WASM calls, and response parsers do not share a single compiler boundary with Rust or the server                               |
| Role-private persistence              | `crates/router-ab-cloudflare/migrations/deriver-a`, `deriver-b`; `ed25519_yao_role_d1.rs`; strict Deriver runtime adapters                                                                                                                                                 | Current schemas store Yao sessions and have no tenant-root share, backup, epoch-key, receipt, or lifecycle tables                                                  |
| Control plane and coordination        | `crates/router-ab-cloudflare/src/router_coordinator.rs`, `durable_object/mod.rs`, `ecdsa_pool_lifecycle.rs`, `ed25519_yao_lifecycle.rs`                                                                                                                                    | Distributed compare-and-swap, lock, alarm, retry, and crash semantics are runtime behavior rather than static types                                                |
| Deployment and secrets                | `crates/router-ab-cloudflare/src/env.rs`; both Wrangler files; deployment key generators; `scripts/deployment-targets.mjs`; environment examples; `docs/deployment`                                                                                                        | Binding names and deployment manifests are stringly typed; current per-role root share is one deployment-wide Secret                                               |
| Local/dev parity                      | `crates/router-ab-dev/src/local_ecdsa_root_shares.rs`, local Router/worker coordinators, SQLite schema and seed scripts, strict local runtime config                                                                                                                       | Local fixtures can silently preserve the deployment-wide root model and mask Cloudflare-only failures                                                              |
| Persistence consumers                 | wallet-server D1 migrations and stores; ECDSA capability manifests; Ed25519 local metadata; device-link source contributions; recovery key manifests                                                                                                                       | Epoch and signing-root metadata are copied into durable records that remain readable after the core type changes                                                   |
| Vectors, fixtures, and generation     | `crates/router-ab-core/fixtures`; Router A/B Rust tests; Yao formal-verification fixtures; `wasm/wallet_custody_ceremony/tests/wire_fixtures.rs`; shared TypeScript and top-level test helpers                                                                             | Generated JSON and hand-written fixtures compile independently, while stale snapshots can preserve retired semantics                                               |
| Documentation and operational claims  | this plan; `docs/router-ab/protocol.md`; deployment and staging-custody docs; incident and rollback runbooks                                                                                                                                                               | Security language can overstate erasure, recovery independence, or client transparency without executable evidence                                                 |

The checked inventory must classify every hit from repository-wide searches for:

```text
RootShareEpoch | root_share_epoch | rootShareEpoch | activation_epoch
TenantRootShareEpoch | tenant_root_share_epoch | tenantRootShareEpoch
signingRootId | signing_root_id | signingRootVersion | signing_root_version
DERIVER_A_ROOT_SHARE_WIRE_SECRET | DERIVER_B_ROOT_SHARE_WIRE_SECRET
root_share_wire | root share | derivation-root/v1
```

Each hit is marked `stable derivation`, `custody binding`, `active signing`,
`persistence`, `wire`, `generated artifact`, `deployment`, `test fixture`,
`documentation`, or `unrelated`. The inventory is incomplete while any match is
unclassified. This is especially important for equality checks that currently
derive `root_share_epoch` from `signingRootVersion`; they express a semantic
coupling that Rust and TypeScript both accept.

### Test and guard matrix

The matrix is prepared before production code and names the narrowest existing or
new owner for each claim.

| Test layer                   | Required checks                                                                                                                                                                                                                                                                                                        | Intended owner                                                                                                                                                     |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Root algebra and transcripts | Creation and refresh equations; both shares change; public commitment continuity; malformed scalars; zero/identity cases; contribution, role, tenant, epoch, transcript, nonce, expiry, and replay substitution; abort and restart at every message                                                                    | New focused Rust tests in `crates/router-ab-core/tests`, plus property tests for field/scalar operations                                                           |
| Constant-time and randomness | Approved OS/Worker CSPRNG boundary; unbiased scalar sampling; secret-independent scalar operations and comparisons                                                                                                                                                                                                     | Rust review plus the existing constant-time qualification track where applicable; add a targeted test or analysis only for newly introduced secret-scalar code     |
| ECDSA stable output          | Byte-exact V2 stable context vectors; custody-binding vectors; old/new epoch output equality; mixed-epoch rejection; Rust protocol/backend parity                                                                                                                                                                      | Existing `ecdsa_threshold_prf*`, `ecdsa_derivation_protocol`, `protocol_boundaries`, and formal-verification owners in `crates/router-ab-core/tests`               |
| Ed25519 joined-root output   | Exact interpolation and KDF vectors; old/new share-pair output equality; protected-input boundary; recipient package parity; circuit-manifest anti-drift                                                                                                                                                               | `cargo yao-fv all`, Router A/B Ed25519 Rust tests, pair-digest vectors, and Cloudflare WASM vector adapters                                                        |
| Cross-runtime wires          | Rust-to-TypeScript generated bindings; Rust/WASM/JS round trips; unknown/missing field rejection; canonical JSON and custom binary encoding parity                                                                                                                                                                     | `pnpm generate:router-ab-ed25519-yao-types`, relevant signer-core generation, WASM package builds, and wallet-custody wire fixtures                                |
| Domain-state types           | Invalid lifecycle branches, broad spreads, direct object literals, missing role receipts, caller-selected identity, mixed current/next epochs, and activation from the wrong state fail to compile                                                                                                                     | Targeted `*.typecheck.ts` fixtures with `@ts-expect-error` in shared TypeScript, wallet-server, and top-level `tests/typecheck`                                    |
| Role-private stores          | Tenant/role/epoch key uniqueness; encrypted-at-rest record shape; no cross-request plaintext cache; current/pending selection; CAS transitions; crash recovery; cross-tenant denial; stale-backup rejection                                                                                                              | New Rust Cloudflare D1 adapter tests and migration tests; local SQLite parity where it exercises the same contract                                                 |
| Backup and restore           | Independent A/B key paths; exact AAD; managed current-epoch and tenant recovery namespaces; recovery reshare continuity; one-role restore; wrong-role and wrong-tenant denial; commitment verification; forward refresh; old managed-key destruction; tenant-copy non-revocation; provider and database rollback drill | New adapter integration tests plus an executable disaster-recovery runbook producing redacted receipts                                                             |
| Server orchestration         | Server-resolved tenant identity; request override rejection; per-tenant fencing; concurrency; one-role failure; activation and retirement convergence; normal signing during every state                                                                                                                               | Cloudflare lifecycle tests and focused wallet-server route/unit tests                                                                                              |
| Client transparency          | No WebAuthn prompt, SDK callback, IndexedDB mutation, signer-package fetch, wallet scan, or activation-reference change; public keys and addresses remain stable                                                                                                                                                       | One authoritative intended-behaviour contract backed by focused unit assertions at RPC/Worker boundaries                                                           |
| Deployment cutover           | Deployment-wide root bindings absent; tenant stores and key providers present only in the owning role; local and Cloudflare config parity; no root material in Router or SigningWorker environments                                                                                                                    | `crates/router-ab-cloudflare/tests/bindings.rs`, secret-material boundary tests, deployment-target tests, strict local config tests, and deployment smoke evidence |
| Erasure and security claims  | Old sessions drain before destruction; old online and backup ciphertext cannot be opened after key retirement; Worker, D1, secret, deployment, and disaster-recovery rollback cannot restore a usable old epoch; provider quota exhaustion never selects a shared fallback                                             | Destructive staging and quota drills against the selected provider; documentation claims are gated on their executable receipts                                    |
| Multi-tenant operations      | Refresh, restore, failure, deletion, schedule jitter, quota exhaustion, and audit events for tenant A leave tenant B unchanged and available                                                                                                                                                                           | Cloudflare integration tests and bounded-concurrency scheduler tests                                                                                               |

Existing source-text guards are reviewed as low-authority inventory aids. Update or
delete stale guards after classifying the invariant they encode; do not bend the
new design around them. Prefer behavioral tests, canonical vectors, type
fixtures, schema constraints, and deployment-binding tests. Relevant existing
guards include `crates/router-ab-core/tests/source_guards.rs`,
`tests/scripts/check-key-material-branding-boundaries.mjs`,
`tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, Cloudflare
binding tests, and deployment-target tests.

Before Phase 1 begins, record a green or deliberately red baseline for every
selected owner. Classify every pre-existing failure as production regression,
valid test needing update, obsolete test or fixture, or environment failure.
Frozen generated artifacts must include their regeneration command and an
anti-drift check.

### Preparation exit gate

- [ ] Materialize every specification-closure row as its named canonical
      artifact or executable check.
- [ ] Assign every invariant to at least one authoritative test or executable
      operational check.
- [ ] Classify every boundary-search hit and every generated artifact.
- [ ] Freeze byte-exact creation, refresh, ECDSA, Ed25519, backup, and lifecycle
      schemas and vectors.
- [ ] Measure the joined-root Yao slice and accept explicit resource budgets.
- [ ] Choose and exercise the online and backup key-destruction provider.
- [ ] Inventory production identities and approve a pre-launch cutover with no
      dual production profile.
- [ ] Approve the one-share-loss availability contract and restore quorum.
- [ ] Stop the refactor if stable-output vectors, joined-root performance,
      recovery separation, or erasure evidence cannot meet the release gates.

## Implementation Plan

### Phase 1: add per-tenant root custody

- [ ] Add the frozen tenant-root identity, role-share, backup-policy, creation,
      refresh, restore, and retirement state types.
- [ ] Add independent Deriver A and B private stores and role-local current-epoch
      backup adapters.
- [ ] Add distributed tenant-root creation with commitments and proofs.
- [ ] Add dedicated tenant recovery resharing, role encryption, and the signed
      public recovery manifest.
- [ ] Map each authenticated tenant to one physical root pair.
- [ ] Require current role-backup receipts, or the explicit accepted-loss branch,
      before initial activation.
- [ ] Remove deployment-wide root-share Secret bindings after tenant roots are
      active.
- [ ] Reject caller-selected tenants, roots, roles, and epochs.

### Phase 2: implement ECDSA transparent refresh

- [ ] Split stable derivation context from custody binding.
- [ ] Remove `RootShareEpoch` from threshold-PRF input bytes.
- [ ] Introduce `TenantRootShareEpoch` only in tenant-root custody bindings and
      preserve existing durable `RootShareEpoch` values.
- [ ] Add the contributory two-party zero-share refresh protocol.
- [ ] Add root-continuity commitments and proof-of-installation.
- [ ] Add mixed-epoch, replay, substitution, abort, and restart vectors.

### Phase 3: replace the Ed25519 derivation profile

- [ ] Admit authenticated raw share scalars as protected Yao inputs.
- [ ] Perform interpolation and server-contribution KDF inside the circuit.
- [ ] Preserve the current recipient package outputs.
- [ ] Version the circuit manifest, protocol, cache keys, and vectors.
- [ ] Add cross-runtime and formal evidence.
- [ ] Delete the role-local hash profile when the joined-root profile activates.

### Phase 4: add lifecycle and operations

- [ ] Add the exhaustive current/next control-plane state.
- [ ] Add per-tenant locks, fences, canaries, activation, and redacted receipts.
- [ ] Add fresh online and backup epoch key versions and verified retirement.
- [ ] Add one-role restore with commitment verification and mandatory forward
      refresh.
- [ ] Keep managed availability restore and tenant recovery restore in distinct
      exhaustive protocol branches.
- [ ] Inject failure before and after every role install and activation step.
- [ ] Prove normal signing remains available.
- [ ] Add operator-triggered refresh before scheduled refresh.

### Phase 5: release the client-transparent path

- [ ] Run refresh against tenants with Ed25519 and ECDSA wallets.
- [ ] Prove no wallet enumeration or client mutation occurs.
- [ ] Run multi-tenant concurrency, quota, and isolation tests.
- [ ] Run role-compromise, cleanup, refresh, and rollback drills.
- [ ] Run role-loss, backup restore, forward refresh, and old-backup destruction
      drills independently for A and B.
- [ ] Enable a conservative jittered schedule.
- [ ] Publish exact security claims and recovery limitations.

## Verification

The implementation is complete only when tests prove:

- tenant A and tenant B have unrelated root commitments and shares;
- neither initial creation nor refresh exposes the joined root;
- both root shares change after refresh;
- `2*A - B` and `2*A' - B'` bind to the same public root commitment;
- old and new shares produce identical ECDSA threshold-PRF outputs;
- old and new shares produce identical Ed25519 contributions and public keys;
- changing only `TenantRootShareEpoch` leaves stable derivation bytes unchanged;
- mixed current/next shares are rejected;
- stale, future, substituted, and replayed epochs are rejected;
- failure before activation leaves the current epoch usable;
- failure after one pending install exposes no mixed-epoch derivation path;
- restart from every lifecycle state converges to one defined branch;
- no wallet record, signer package, client state, public key, address, or
  activation reference changes;
- no client request, WebAuthn ceremony, or browser callback occurs;
- normal signing succeeds throughout a refresh;
- A and B backups require independent decryption and authorization paths;
- tenant recovery packages use a dedicated sharing, preserve the public root
  commitment, and remain usable across operational refreshes;
- a restored role share matches the active commitment and is immediately
  replaced by a forward refresh;
- retired operational and managed-backup shares cannot be recovered through
  supported rollback paths;
- refreshing tenant A changes no state or availability for tenant B;
- source and self-hosted destination roots refresh independently.

## Definition of Done

Refactor 120 is complete when:

1. Every tenant maps to a distinct physical tenant derivation root.
2. No process or runtime holds both root shares.
3. ECDSA stable derivation excludes `RootShareEpoch` and
   `TenantRootShareEpoch`.
4. Ed25519 derives from the joined tenant root inside Yao.
5. One server-side ceremony replaces both tenant root shares and advances the
   epoch while preserving the joined root.
6. Existing wallet public keys, addresses, client state, signer packages, and
   activation references remain unchanged.
7. Clients perform no ceremony or local-state mutation for a refresh.
8. Normal signing remains available.
9. Mixed epochs, replay, partial installation, and role substitution fail
   closed.
10. Managed availability backups preserve role separation, bind the exact active
    epoch and commitment, and restore only into the owning role.
11. Tenant-controlled recovery packages preserve role separation, bind one
    dedicated recovery set and the stable public root commitment, and remain
    usable across operational refreshes.
12. Successful restore requires commitment verification and a forward refresh.
13. Supported rollback paths cannot recover retired online or managed-backup
    shares and key versions.
14. Refreshing one tenant has no effect on another tenant.
15. Managed and self-hosted deployments can refresh independently.
16. Root replacement remains an explicit wallet-migration operation.
17. Documentation distinguishes active-epoch rotation from verified proactive
    compromise healing.

## Non-Goals

- transparent replacement of the joined tenant derivation root;
- transparent conversion of existing shared-root wallets to unrelated tenant
  roots;
- refreshing active client or SigningWorker shares;
- exporting a managed or self-hosted joined tenant root as plaintext or one
  combined backup object;
- reconstructing a joined root in a Router, Gateway, SigningWorker, control
  plane, script, or operator process;
- app-level migration or a deployment-portability package;
- carrying root shares through cross-deployment device linking;
- keeping the current role-local Ed25519 profile as a fallback;
- claiming that share refresh repairs exposure of both shares from one
  recoverable epoch;
- claiming cryptographic erasure without executable rollback evidence;

## Remaining Evidence Gates

There are no open protocol or product-policy decisions in this plan. Phase 1
still waits for the canonical schemas, vectors, type fixtures, boundary
inventory, baseline classification, and red tests named by the preparation
phase.

Production activation additionally requires measured acceptance of the frozen
resource budget, successful online-store, backup, restore, deletion, and erasure
drills, and qualification of the selected A and B key providers. Those gates may
reject an implementation or force the deployment into
`operational_rotation_v1`; they do not reopen the root algebra, identity,
lifecycle, or custody contracts.
