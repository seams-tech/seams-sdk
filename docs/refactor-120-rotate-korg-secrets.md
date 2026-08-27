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
- advances one `RootShareEpoch`;
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

| Term                        | Meaning                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------- |
| Tenant derivation root      | One stable server-side secret derivation origin for one tenant                         |
| Deriver root share          | Deriver A or B's 2-of-2 Shamir share of that tenant root                               |
| `signingRootId`             | Persisted identifier for the logical signing-root namespace; it is not secret material |
| `signingRootVersion`        | Stable derivation-version metadata; changing it may select different wallet keys       |
| `RootShareEpoch`            | Mutable custody epoch selecting the active A/B share pair                              |
| Role operational key        | A role-local KEK, HPKE key, peer-authentication key, or service credential             |
| Wallet custody seed         | The client-controlled secret derivation origin for owner signing roots                 |
| Active wallet signing share | Already-provisioned client or SigningWorker material used for normal signing           |

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
5. `RootShareEpoch` is custody metadata. It never enters stable wallet KDF
   input after this refactor.
6. Refresh changes the two role shares and `RootShareEpoch`. The joined tenant
   root stays constant.
7. Initial tenant-root creation is distributed. No bootstrap process, Router,
   Gateway, SigningWorker, database, or control-plane record receives the
   joined root or both shares.
8. Each role stores tenant shares only inside its private custody boundary.
   The shared Gateway and SigningWorker databases never store them.
9. Ed25519 uses a joined-root Yao derivation profile. Raw role shares enter only
   as protected circuit inputs, and the joined root remains on garbled wires.
10. ECDSA threshold-PRF evaluation uses a stable derivation context and a
    separate epoch-bound custody transcript.
11. The current derivation profile is replaced directly. Production code keeps
    no dual profile, fallback, legacy epoch KDF, or compatibility branch.
12. A refresh is O(1) in the selected tenant's wallet count. Fleet-wide rotation
    is O(number of tenants) and runs through bounded, jittered jobs.
13. Normal signing uses already-active material and remains available. Only new
    derivation ceremonies for the selected tenant are briefly fenced.
14. A refresh never changes active SigningWorker shares. Rotating those shares
    requires the corresponding wallet or lane protocol.
15. Tenant derivation-root replacement is an explicit wallet-identity migration.
    It never masquerades as a share-epoch increment.
16. Managed and self-hosted deployments create and refresh their roots
    independently. Cross-deployment device linking transfers no root share.
17. Client transparency is a release invariant. Once the new profile is
    deployed, future refreshes require zero client ceremonies or local-state
    changes.
18. Compromise-healing claims require verified destruction of retired shares
    and their epoch wrapping keys.
19. The no-client guarantee begins after the per-tenant, refresh-invariant
    derivation profile is authoritative. Converting an existing shared-root or
    epoch-dependent wallet population is a separate one-time cutover.

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
4. old shares, deltas, ephemeral keys, and wrapping keys are destroyed;
5. Worker, database, secret, and backup rollback cannot recover the old epoch.

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
       -> authoritative active RootShareEpoch
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
- `RootShareEpoch`;
- role identity;
- sealed role share;
- share commitment;
- epoch wrapping-key reference;
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

All scalar operations use the root field. Updates travel through the
authenticated encrypted A/B channel and remain inside the refresh session.

The complete ceremony:

1. Resolve the exact authenticated tenant and active root identity.
2. Acquire a per-tenant refresh lock.
3. Allocate the next `RootShareEpoch`.
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

The current ECDSA derivation context includes `RootShareEpoch`. Refactor 120
separates two records:

```text
StableTenantDerivationContextV2
  tenant identity
  signingRootId
  signingRootVersion
  wallet/key derivation facts

TenantRootCustodyBindingV1
  tenant-root identity
  RootShareEpoch
  Deriver identities
  share commitments
  request nonce and transcript digest
```

Threshold-PRF evaluation depends only on the stable derivation context. Partial
proofs, routing, share selection, replay protection, and persistence AAD bind
the custody record.

Changing only `RootShareEpoch` must leave stable context bytes and threshold-
PRF output unchanged.

### Ed25519

The current Ed25519 profile hashes each role share independently before the
garbled circuit. Share refresh changes those hashes and therefore changes its
derived output.

The replacement profile:

1. admits A and B as protected scalar inputs;
2. binds each input to the authenticated role, active epoch, and installed share
   commitment;
3. reconstructs `K = 2*A - B` only on garbled wires;
4. runs the domain-separated server-contribution KDF inside the circuit;
5. emits the same recipient-encrypted client and SigningWorker package shapes;
6. never decodes or returns K.

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
      readonly kind: 'failed';
      readonly identity: TenantRootIdentityV1;
      readonly current: ActiveTenantRootEpochV1;
      readonly next: FailedTenantRootEpochV1;
      readonly previous?: never;
      readonly activation?: never;
      readonly failure: TenantRootRefreshFailureV1;
    };
```

Boundary parsers normalize raw control-plane and role receipts once. Core
functions accept only the exact preceding branch. Every switch is exhaustive.
Type fixtures reject mixed current/next epochs, missing role receipts, direct
object-literal construction, broad spreads, and invalid activation calls.

A verified transition activates one exact next epoch and enters `retiring`.
Normal derivation uses the new current epoch while both roles destroy the
previous epoch. Destruction receipts return the lifecycle to `active`. A failed
pre-activation transition keeps the current epoch active and destroys pending
material. After activation, rollback is unavailable; remediation uses another
forward refresh. A lifecycle stuck in `retiring` remains operational but cannot
claim proactive compromise healing.

## Storage and Erasure

Per-tenant shares cannot use one Cloudflare secret binding per epoch at fleet
scale. They require role-private indexed storage plus a destroyable wrapping-key
boundary.

Each epoch share is encrypted under a fresh epoch wrapping key. A stable role KEK
must not be able to reconstruct retired epoch keys. Otherwise D1 Time Travel,
backups, or copied ciphertext can recover old shares.

The production adapter must demonstrate:

- only the owning Deriver can open its active share;
- current and pending are the only usable epochs;
- old ciphertext is useless after epoch-key destruction;
- Worker rollback cannot select or recover a retired share;
- database recovery cannot restore its wrapping key;
- backups exclude plaintext shares and recoverable retired keys;
- logs, metrics, errors, and receipts contain no shares or refresh scalars.

If the selected platform cannot provide credible epoch-key destruction, the
feature may still rotate the active epoch operationally. Documentation must then
avoid the stronger proactive compromise-healing claim.

## Scheduling and Isolation

Refresh jobs are tenant-scoped:

- one refresh lock per tenant root;
- bounded global concurrency;
- hourly or daily policy with tenant-specific jitter;
- event-triggered refresh after a role is cleaned;
- exponential retry before activation;
- forward refresh after activation;
- independent failure and audit receipts per tenant.

A refresh for tenant A never fences tenant B. Fleet-wide refresh cost grows with
tenant count, so scheduling must respect Yao capacity and role-store quotas.

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

## Implementation Plan

### Phase 0: prove the derivation cutover

- [ ] Inventory every place where `RootShareEpoch` enters ECDSA stable context
      bytes, TypeScript construction, persistence, and activation validation.
- [ ] Inventory every Ed25519 role-local root hash and server-contribution KDF.
- [ ] Generate fixed old/new-share vectors proving stable ECDSA outputs after
      epoch removal.
- [ ] Build one joined-root Ed25519 Yao slice and measure gates, memory, CPU,
      synthesis time, and wire size.
- [ ] Inventory production identities that depend on either current derivation
      profile.
- [ ] Prove that the per-tenant root profile can activate before production, or
      stop and define the one-time existing-wallet migration separately.
- [ ] Select the destroyable epoch wrapping-key storage boundary.
- [ ] Stop if stable-output vectors, joined-root performance, or erasure cannot
      meet the release gates.

### Phase 1: add per-tenant root custody

- [ ] Add exact tenant-root identity and role-share record types.
- [ ] Add independent Deriver A and B private stores.
- [ ] Add distributed tenant-root creation with commitments and proofs.
- [ ] Map each authenticated tenant to one physical root pair.
- [ ] Remove deployment-wide root-share Secret bindings after tenant roots are
      active.
- [ ] Reject caller-selected tenants, roots, roles, and epochs.

### Phase 2: implement ECDSA transparent refresh

- [ ] Split stable derivation context from custody binding.
- [ ] Remove `RootShareEpoch` from threshold-PRF input bytes.
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
- [ ] Add fresh epoch wrapping keys and verified retirement.
- [ ] Inject failure before and after every role install and activation step.
- [ ] Prove normal signing remains available.
- [ ] Add operator-triggered refresh before scheduled refresh.

### Phase 5: release the client-transparent path

- [ ] Run refresh against tenants with Ed25519 and ECDSA wallets.
- [ ] Prove no wallet enumeration or client mutation occurs.
- [ ] Run multi-tenant concurrency, quota, and isolation tests.
- [ ] Run role-compromise, cleanup, refresh, and rollback drills.
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
- changing only `RootShareEpoch` leaves stable derivation bytes unchanged;
- mixed current/next shares are rejected;
- stale, future, substituted, and replayed epochs are rejected;
- failure before activation leaves the current epoch usable;
- failure after one pending install exposes no mixed-epoch derivation path;
- restart from every lifecycle state converges to one defined branch;
- no wallet record, signer package, client state, public key, address, or
  activation reference changes;
- no client request, WebAuthn ceremony, or browser callback occurs;
- normal signing succeeds throughout a refresh;
- retired shares cannot be recovered through supported rollback and backup
  paths;
- refreshing tenant A changes no state or availability for tenant B;
- source and self-hosted destination roots refresh independently.

## Definition of Done

Refactor 120 is complete when:

1. Every tenant maps to a distinct physical tenant derivation root.
2. No process or runtime holds both root shares.
3. ECDSA stable derivation excludes `RootShareEpoch`.
4. Ed25519 derives from the joined tenant root inside Yao.
5. One server-side ceremony replaces both tenant root shares and advances the
   epoch while preserving the joined root.
6. Existing wallet public keys, addresses, client state, signer packages, and
   activation references remain unchanged.
7. Clients perform no ceremony or local-state mutation for a refresh.
8. Normal signing remains available.
9. Mixed epochs, replay, partial installation, and role substitution fail
   closed.
10. Retired shares and their wrapping keys are unrecoverable through supported
    rollback paths.
11. Refreshing one tenant has no effect on another tenant.
12. Managed and self-hosted deployments can refresh independently.
13. Root replacement remains an explicit wallet-migration operation.
14. Documentation distinguishes active-epoch rotation from verified proactive
    compromise healing.

## Non-Goals

- transparent replacement of the joined tenant derivation root;
- transparent conversion of existing shared-root wallets to unrelated tenant
  roots;
- refreshing active client or SigningWorker shares;
- exporting managed or self-hosted tenant roots;
- reconstructing a joined root in a Router, Gateway, SigningWorker, control
  plane, script, or operator process;
- app-level migration or a deployment-portability package;
- carrying root shares through cross-deployment device linking;
- keeping the current role-local Ed25519 profile as a fallback;
- claiming recovery after both shares from one recoverable epoch are exposed;
- claiming cryptographic erasure without executable rollback evidence;
- introducing customer-held third shares in the first implementation.

## Remaining Release Decisions

Before production activation, choose:

1. the storage system that provides destroyable per-epoch wrapping keys;
2. the maximum joined-root Yao latency, memory, CPU, and wire budgets;
3. the refresh interval and global concurrency limits;
4. the recovery policy for loss of one current share;
5. the cutover treatment for any production identity derived under the current
   ECDSA or Ed25519 profile.
