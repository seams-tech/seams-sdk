# Refactor 120: Per-Tenant Proactive Derivation-Root Share Refresh

Created: June 11, 2026

Rewritten: August 28, 2026

R103F compatibility reviewed: August 29, 2026

Ed25519 derivation architecture revised: August 29, 2026

Status: implementation in progress. Refactor 103F is complete and current
`dev` is merged into the R120 branch. The cryptographic core, strict protocol
types, tenant-root lifecycle, control-plane issuer, Router-owned public Durable
Object state, role-local D1 replay/terminalization, Deriver admission and
commitment exchange, online sealing, and authorized pending cleanup are
implemented and tested.

The active implementation path is now intentionally short: persist each
role's managed-backup artifact outside its role D1, wire creation end to end,
switch the production ECDSA and Ed25519 derivation adapters, wire refresh and
activation, then remove the replaced deployment-root path. Deployed benchmark,
provider-destruction, canary, and rollout checks are release gates; they do not
block implementation. The historical detailed ledger remains below as design
evidence and no longer determines progress.

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

The Ed25519 candidate is acceptable only when its complete warm derivation
ceremony adds no more than 10 ms at p95 relative to the baseline. The preface
uses the A/B transport session already required by Yao, adds no additional
connection or standalone readiness exchange, and never enters the
normal-signing path.

The compact local `workerd` comparison observed a 4-5 ms preface and warm
current-versus-candidate deltas no greater than 5.37 ms at the client boundary
or 6 ms in Worker elapsed time. This is enough to classify the design as
provisionally feasible. The production decision still requires the frozen
deployed cohorts and resource gates.

The scalar refresh is small and well understood. The overall refactor is
moderate rather than trivial. Two parts carry most of the work:

1. Ed25519 must derive refresh-invariant, role-separated server contribution
   roots without reconstructing the tenant root or moving HKDF-SHA-256 into the
   Yao circuit.
2. Retired shares must remain unrecoverable through Worker rollback, database
   history, backups, or retained wrapping keys.

## Terminology

These terms name different layers:

| Term                         | Meaning                                                                                                                                                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tenant derivation root       | One stable server-side secret derivation origin for one tenant                                                                                         |
| `TenantRootIdentityV1`       | Canonical server-resolved tuple of organization, project, environment, `signingRootId`, and `signingRootVersion`; it names one logical derivation root |
| `TenantRootCustodyLineageId` | Random identifier for one deployment's custody of a logical tenant root; it changes after restore and never enters stable derivation                   |
| Deriver root share           | Deriver A or B's 2-of-2 Shamir share of that tenant root                                                                                               |
| `signingRootId`              | Persisted identifier for the logical signing-root namespace; it is not secret material                                                                 |
| `signingRootVersion`         | Stable derivation-version metadata; changing it may select different wallet keys                                                                       |
| `TenantRootShareEpoch`       | New server-custody epoch selecting the active A/B tenant derivation-root share pair                                                                    |
| `TenantRootRecoverySetId`    | Identifier for one dedicated tenant-controlled A/B recovery sharing; it is metadata, never root or share material                                      |
| Tenant recovery share        | One role's share from a tenant-controlled recovery set; it is separate from every operational epoch share                                              |
| `RootShareEpoch`             | Existing persisted epoch marker for durable ECDSA material; Refactor 120 does not repurpose or mutate it                                               |
| Ed25519 target PRF output    | One refresh-invariant 32-byte threshold-PRF output combined only by its target Deriver and consumed as that role's server-contribution KDF root        |
| Role operational key         | A role-local KEK, HPKE key, peer-authentication key, or service credential                                                                             |
| Wallet custody seed          | The client-controlled secret derivation origin for owner signing roots                                                                                 |
| Active wallet signing share  | Already-provisioned client or SigningWorker material used for normal signing                                                                           |

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
10. Ed25519 uses two fixed role-targeted threshold-PRF evaluations. Deriver A
    combines only the A-target output and Deriver B combines only the B-target
    output. Raw root shares and the joined root never enter Yao; the existing
    contribution KDF remains role-local before the unchanged circuit.
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
39. Refactor 120 consumes Refactor 103F's final exact Wallet Session model.
    R103F B4 exact operation admission and B5 exact material resolution remain
    the only Wallet Session-to-runtime authorization path. Refactor 120 creates
    no parallel admission or material-resolution API.
40. The Gateway resolves `TenantRootIdentityV1` and the active
    `TenantRootShareEpoch` from authenticated deployment configuration. For an
    operation involving established material, `signingRootId` and
    `signingRootVersion` must equal the values in the authoritative material
    record resolved through R103F B5. `MpcMaterialActivationRef` remains an
    opaque reference and does not gain root fields. A Wallet Session,
    authorization, credential, or browser-record identifier never selects a
    tenant root or epoch.
41. Tenant-root custody metadata never enters
    `WalletSessionAuthorizationV2`, either operation-credential family, the V6
    browser record, `MpcMaterialActivationRef`, registration completion
    receipts, or device-link activation and acknowledgement records. Root
    refresh mutates none of those records.
42. Refactor 120 adds root-custody schema only to the role-private Deriver stores
    and tenant-root control plane. It adds no root share, root epoch, or root
    lifecycle column to R103F's signer D1 schema. An unforeseen signer-D1 change
    blocks implementation until this plan is amended against R103F's final
    schema.
43. Protocol versions remain boundary-local. Refactor 120 versions the Router
    A/B derivation protocols, threshold-PRF purposes and payloads, pair-session
    identity, and generated bindings it changes. The Yao circuit manifest,
    schedule, digest, table stream, and circuit-cache identity remain unchanged
    unless the preparation prototype disproves that boundary. Refactor 120 does
    not reuse R103F's browser record version or bump `WALLET_PROTOCOL_VERSION`
    unless the host/iframe message shape itself changes. R103F's frozen Router
    A/B `reusable_wallet_session`, ECDSA export-share authorization, and
    `consume_reusable_wallet_session` discriminators remain unchanged.
44. Refactor 120 production activation begins only after R103F completes R5 and
    every serving Wallet Session worker is exact-only. New derivation
    ceremonies are fenced and every pre-cutover derivation session reaches a
    terminal state before the first participating runtime changes. The R120
    Gateway, Router, Deriver, WASM, SDK, and iframe revisions are then verified
    before derivation resumes. Production never serves both derivation profiles.
45. The cutover drains or retires every server-side registration or recovery
    state that could still commit retired-profile derived material. An R103F
    credential-free committed registration receipt already denotes an existing
    wallet identity even when browser publication is incomplete; it enters the
    decision-37 identity inventory. Delayed replay cannot make an identity that
    the inventory retired active or usable after cutover.
46. The role-targeted threshold-PRF preface is the preferred Ed25519 architecture
    and remains a preparation-phase candidate until its production-shaped
    benchmark passes. A joined-root Yao circuit is unapproved work. A failed
    candidate gate stops Refactor 120 and requires an explicit plan amendment;
    production never implements or serves both designs.
47. The Ed25519 latency candidate uses no persistent PRF-output cache. It must
    pass with one simultaneous bidirectional A/B proof-bundle flight over the
    transport session already used by Yao, no additional connection or
    preface-only readiness exchange, zero additional client-to-service round
    trips, and no more than 10 ms added warm p95 end-to-end latency in any
    measured derivation-ceremony cohort.
48. One dedicated internal tenant-root control-plane Worker owns the routine
    R120 issuer signing key. The Router, Deriver A, Deriver B, SigningWorker,
    Durable Object storage, D1, tenant backups, and clients never receive that
    private key.
49. The control-plane Worker is not a blind signing oracle. It validates the
    exact tenant authorization, reads the authoritative identity/lineage
    Durable Object state, and constructs each canonical capability, role
    command, refresh command, or activation receipt from that verified state.
    A Router-provided raw payload is never a signable input.
50. The Router and both Derivers independently trust the same versioned public
    issuer-key set through
    `TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON`. The old
    Router-prefixed verifier configuration is deleted. The SigningWorker does
    not consume this keyset, and every issuer private-key binding remains
    forbidden outside the control-plane Worker.
51. Each Deriver reaches the Router-owned tenant-root Durable Object through a
    direct external Durable Object namespace binding whose `script_name` names
    the Router Worker for that environment. The Router remains the sole class,
    namespace, migration, and storage owner. No Router proxy route or public
    HTTP route is added.
52. Possession of the external Durable Object binding grants reachability only.
    The object derives its name from the locally verified identity digest and
    custody lineage and verifies the exact command, expected role, authority,
    revision, signatures, and public evidence before every mutation. No
    serialized `Verified*` token or caller assertion substitutes for local
    verification.
53. The routine issuer key is one versioned key per deployment environment,
    not per tenant. Retired public keys remain available for durable
    verification while the retired private key stops signing immediately.
    Accepted-loss, deletion, and issuer-key recovery keep their separate
    operator or dual-authority credentials.

## Refactor 103F Compatibility

[Refactor 103F](./refactor-103F-final-cutover.md) changes authorization,
session persistence, browser state, registration replay, device-link
installation, and runtime material resolution. It deliberately leaves MPC
cryptography unchanged. Refactor 120 owns the later derivation-profile change
and treats R103F's final exact model as its integration baseline.

The two refactors compose at one narrow boundary:

```text
operation credential
  -> R103F B4 exact operation admission
       -> R103F B5 exact MpcMaterialActivationRef
            -> authoritative material record and runtime-policy scope

authenticated deployment configuration
  -> R120 TenantRootIdentityV1 + active TenantRootShareEpoch
       -> derivation ceremony only
```

### Frozen R103F B4/B5 API snapshot

This snapshot records the exact integration surface after merging the completed
R103F tree through `bfaed2877` in R120 merge `308948c15`. R120 changes this boundary
only through the independently resolved tenant-root binding and the equality
check described below.

**B4 operation admission** is owned by
`walletExecutionAdmission.ts`:

- `resolveWalletSessionAuthorizationV2Admission` accepts an exact V2
  authorization, active authority, active auth method, requested operation,
  retirement state, and current time;
- its success branch contains the exact key family, operation kind,
  `walletKeyId`, administered signer, and opaque `MpcMaterialActivationRef`;
- `prepareOwnerWalletExecution` is the only lane execution admission and
  returns `WalletExecutionAdmissionResult`, whose success branch contains a
  `PreparedOwnerWalletExecution` built from verified wallet, key, lane,
  participant-binding, activation-receipt, and material-activation evidence;
- neither result contains a tenant-root identity, tenant-root epoch, role, or
  root-share lookup key.

**B5 material resolution** is the required
`RouterApiWalletRegistrationService` surface implemented by
`D1WalletRegistrationService`:

```ts
resolveEd25519MaterialActivation({ walletId, materialActivation });
resolveEcdsaMaterialActivation({ walletId, materialActivation });
```

Both inputs contain only the authenticated wallet ID and exact opaque
`MpcMaterialActivationRef`. Both resolve through the authoritative wallet
signer store and active capability or linked-installation projection. They do
not accept a Wallet Session, authorization, credential, browser, request-body,
tenant-root, or epoch selector.

The exact stable signing-root identity locations in the successful B5 results
are:

| Family  | Authoritative B5 fields used for the R120 equality check                                                                                                                                                  |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ECDSA   | `routerAbEcdsaDerivationNormalSigning.scope.signing_root_id` and `.signing_root_version`                                                                                                                  |
| Ed25519 | `exportIdentity.application_binding.signing_root_id` and `exportIdentity.scope.root_share_epoch`; the R120 resolver compares the latter with B5's independently parsed `runtimePolicyScope.signingRootVersion` |

The Ed25519 field name is inherited R103/R103F wire vocabulary. R120 treats its
value only as the established material's stable signing-root version. It never
uses that field as `TenantRootShareEpoch`. The active tenant-root epoch is
resolved independently from the role-private R120 custody stores.

A derivation route that also has established material must therefore perform
these checks in order:

1. complete B4 admission;
2. resolve the exact B4 `MpcMaterialActivationRef` through B5 and verify exact
   reference equality;
3. resolve `TenantRootIdentityV1` and active `TenantRootShareEpoch` from the
   authenticated deployment configuration and R120 custody control plane;
4. compare B5's stable signing-root ID and version with the corresponding
   `TenantRootIdentityV1` fields;
5. construct the versioned Router A/B derivation request only after every
   comparison succeeds.

Normal signing stops after B5. It never executes steps 3 through 5 and never
loads a tenant-root share.

The R103F signer-D1 migration tree is frozen at this snapshot. Its aggregate
SHA-256 is `670aeba976269f2142eddcb9524a7b68a4022147eb30f02ecd5e10958aaaf1b8`,
computed as SHA-256 over the concatenated raw SHA-256 digests of the 35
lexicographically ordered `packages/wallet-server/migrations/d1-signer/*.sql`
files. The boundary-inventory evidence records every ordered file digest and
recomputes this aggregate.
R120 adds no signer-D1 migration or root-custody field. Its secret custody rows
belong only in the separate Deriver A and Deriver B private stores; an observed
change to that signer-D1 digest requires explicit plan review before R120 can
continue.

Normal signing uses R103F's exact material resolution and never loads a tenant
derivation-root share. Ed25519 export resolves exact active material through B5
before it independently resolves the R120 root binding required for derivation.
Registration and recovery re-establishment use the server-resolved R120 root
binding when they require new derivation. Whenever a ceremony also refers to
established material, the stable signing-root identifiers from the root binding
and B5-resolved material record must agree. The opaque
`MpcMaterialActivationRef` is neither decoded as a root identity nor extended
with root-custody fields.

Implementation ownership is:

| Surface                                                                                                                                                                                                 | Concurrent owner                             | R120 rule                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Wallet Session authorization, credentials, signer-D1 schema, registration receipts, V6 browser records, host/iframe messages, and device-link activation/acknowledgement                                | R103F                                        | Consume the final types and verify they remain unchanged                                                                         |
| Root algebra, ECDSA custody binding, Ed25519 role-targeted threshold-PRF prototype and protocol, Deriver A/B stores and migrations, tenant-root Durable Object, KMS/HSM adapters, and refresh lifecycle | R120                                         | May proceed concurrently after the R120 preparation gate                                                                         |
| `commonRouterUtils.ts`, threshold Ed25519/ECDSA routes, and `routerAbPrivateSigningWorker.ts`                                                                                                           | R103F until its Phase 2 exit; R120 afterward | Freeze R103F B4/B5, rebase once, then add the narrow tenant-root integration without compatibility wrappers                      |
| Registration and capability persistence, device-link services, shared public/session types, wallet-custody WASM fixtures, and shared test factories                                                     | R103F until its Phase 3 exit; R120 afterward | Consume R103F's final receipt, link, recovery, and browser contracts; change only an independently versioned R120 protocol shape |
| Production rollout                                                                                                                                                                                      | R103F, then R120                             | Complete R103F R5 before the R120 derivation-profile cutover                                                                     |

R103F's request and persistence bridges remain scoped to Wallet Session drain.
They never translate a Refactor 120 root identity, epoch, protocol message, or
derivation output. R120's no-dual-profile rule therefore remains intact.

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
signature verification.

Every tenant-root identity field, role signing-key ID, and Deriver deployment
identity is one boundary identifier. A boundary identifier is non-empty, carries
no leading or trailing whitespace, contains no control characters, and is at
most 256 UTF-8 bytes. This layer never canonicalizes; a non-canonical raw input
fails instead. `TenantRootProtocolDigestV1` rejects the all-zero digest at its
constructor and at serde parsing, so no protocol transcript, custody, stable
context, or replay digest can be the zero value.

Two frozen time bounds apply to every tenant-root ceremony context and custody
binding. Peers allow at most 60 seconds of clock skew
(`TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1`); larger skew fails the session and alerts
operations. The issue-to-expiry window is at most 300 000 ms
(`TENANT_ROOT_MAX_LIFETIME_MS_V1`), so the widest acceptance window any peer can
observe is 360 seconds. Both constants live once in `router-ab-core` and are
enforced by the ceremony and custody-binding validators.

### Authoritative lifecycle and crash recovery

One Durable Object keyed by `TenantRootIdentityDigestV1` and
`TenantRootCustodyLineageId` owns the operation lock, monotonic lifecycle
revision, active epoch, root commitment, and accepted role-receipt digests. A
role can install pending material only from an issuer-authenticated, one-use
command containing the expected revision. Derivation requests receive a
control-plane-signed active custody binding and each Deriver accepts only that
exact epoch.

Activation follows one direction:

1. both roles install pending shares and current-epoch managed backups;
2. both return signed commitment and backup receipts;
3. continuity canaries pass;
4. the control plane verifies the complete evidence bundle and issues the
   control-plane-signed activation receipt;
5. the Durable Object commits the next epoch as active with compare-and-swap;
6. both roles receive the verified activation receipt and retire the previous
   epoch.

Before step 5, recovery deletes pending material and keeps the old epoch active.
After step 5, recovery resumes retirement or starts another forward refresh;
rollback to the previous epoch is forbidden. Every command is idempotent by
session ID and payload digest. Repeating an identical command returns its prior
receipt; reusing an ID with different bytes fails.

Each role store and its managed backup retain the same signed activation-receipt
digest. If Durable Object state is unavailable, derivation and mutation freeze.
Control-plane reconstruction requires matching current signed activation receipts
from both roles. Any mismatch requires tenant-controlled restore into an empty
lineage.

### Dormant activation evidence and availability branches

The activation-evidence slice now accepts one verified source bundle for each
forward-only activation transition. The bundle is assembled from exact
role-signed installation evidence, the target A/B commitments, exact role
installation-receipt digests, both ECDSA and Ed25519 provider-canary receipts,
and exactly one availability branch. The public core verifier
`verify_tenant_root_refresh_evidence_v1` checks the exact A/B refresh context,
roles, peer commitments, signatures, and stable joined-root continuity before a
refresh bundle can be built.

`TenantRootSignedActivationReceiptV1` is a strict canonical control-plane-signed
receipt derived from that bundle. Its binding includes the server-resolved
identity, custody lineage, transition, epoch or epoch pair, ceremony context
digest, A/B and joined-root commitments, installation receipts, availability
evidence, canary receipts, activation time, authority, issuer key, and validity
window. Initial creation is fixed at expected revision 2 and result revision 3;
refresh swap requires the result revision to equal the expected revision plus
one. Verification retains the exact canonical signed bytes and their digest.
Lifecycle and role-private D1 consume this verified token rather than accepting
a caller-selected receipt or digest.

The availability branch is exhaustive:

- `CurrentRoleBackups` carries two independently verified,
  source-bound `TenantRootSignedManagedBackupV1` artifacts. Each artifact binds
  identity, custody lineage, role, epoch, share commitment, installation
  receipt, provider ID, key version, role signing-key ID, and creation time in
  strict canonical signed bytes; the bundle rejects shared provider IDs, key
  versions, or role authorities.
- `AcceptedPermanentDerivationLoss` carries one exact dual-authority signed
  authorization. It binds the context, identity and root commitments, target
  epoch, installation receipts, expected and result revisions, one-use policy,
  incident scope, reason, validity window, and two distinct authority/key IDs.
  Verification consumes the authorization into the activation bundle, and the
  lifecycle transition plus its one-use D1 CAS path accept the branch once for
  its exact scope. No unresolved quorum or caller-built accepted-loss digest
  remains.

Provider canary receipts are strict scope-bound artifacts: each names the
activation transition, target epoch, role/root commitments, curve family,
provider key-version reference, completion time, authority, signing key, and
freshness window. The signed activation receipt records both canary digests.
These are dormant local contracts; no public activation route or production
provider transport consumes them yet.

### Deployment security profiles

The first release exposes two explicit deployment profiles:

| Profile                   | Key boundary                                                                                                                                | Permitted claim                                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `managed_healing_v1`      | Independent A/B external KMS or HSM providers, with a distinct non-exportable key version for every tenant, role, epoch, and managed backup | Verified proactive compromise healing after both provider destruction probes pass                                               |
| `operational_rotation_v1` | Deployment-selected role-local encryption, including Cloudflare-native storage                                                              | Active shares rotate and rollback is prevented by application state; cryptographic erasure and compromise healing are unclaimed |

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
or SigningWorker signing shares. It also does not revoke a context-scoped
Ed25519 target PRF output or server contribution that an attacker already
observed. Compromise of derived wallet or lane material follows that material's
own refresh, replacement, or migration response.

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
  -> Ed25519 A-target threshold PRF -> Deriver A contribution root
  -> Ed25519 B-target threshold PRF -> Deriver B contribution root
       -> existing role-local contribution KDF
            -> unchanged Ed25519 Yao
```

The Gateway resolves the tenant-root identity from authenticated deployment
configuration. The Router receives one verified tenant-root binding and exact
active epoch. A browser request cannot provide or override either value.

This resolver is separate from R103F B4 admission and B5 material resolution.
Normal signing stops at the exact active material projection and does not call
the tenant-root resolver. Ed25519 export first resolves its exact active
material through B5, then independently resolves the authenticated tenant root
required by its Yao derivation ceremony. Registration and recovery derivation
routes resolve the authenticated tenant root directly. Whenever a derivation
route also carries an established `MpcMaterialActivationRef`, it checks the
stable `signingRootId` and `signingRootVersion` from its authoritative B5
material record for equality before constructing the Router A/B request. No
Wallet Session, authorization, or opaque material-reference identifier is
accepted as a root lookup key.

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

### Control-plane issuer and Cloudflare binding ownership

The routine R120 issuer private key lives in one dedicated internal
`router-ab-tenant-root-control-plane` Worker. Its active signing-key ID is
non-secret configuration. Its 32-byte Ed25519 signing key is a Worker Secret
reachable only through the binding named by
`TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_BINDING`. The Router calls this
Worker through the `TENANT_ROOT_CONTROL_PLANE` service binding. The issuer
Worker has no public route.

The Worker is represented by
`CloudflareWorkerRoleV1::TenantRootControlPlane`. Extending the existing
exhaustive role enum forces every secret-visibility, peer-message, startup,
route, and deployment match to decide what this Worker may access. R120 does
not introduce a parallel role enum or boolean role flag.

The issuer Worker independently validates the exact tenant authorization and
reads the authoritative Router-owned Durable Object state before it signs. It
builds the canonical wire from the verified authorization, persisted journal
or active-state record, expected revision, identity, custody lineage, role,
session, nonce, authority, and bounded validity window. It never signs an
opaque byte string or a caller-assembled command payload. Compromise of the
Router therefore does not reveal the signing key and cannot turn the issuer
Worker into an unrestricted command-signing endpoint.

The public trust anchor is
`TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON`. The Router, Deriver A,
and Deriver B parse this bounded key-ID-to-Ed25519-key map once at their
configuration boundary. Each Deriver selects its expected role and authority
from role-local trusted configuration and locally decodes and verifies every
signed command package before generating or installing a share. A process-local
`Verified*` Rust token never crosses a Worker boundary. The SigningWorker does
not need this trust anchor.

The private signing-key binding is allowed only in the control-plane Worker and
hard-fails every other Worker at boot. The public verifier keyset is required
in the Router and both Derivers and remains forbidden in the SigningWorker.
The obsolete
`ROUTER_TENANT_ROOT_CREATION_ISSUER_VERIFYING_KEYS_JSON` configuration is
removed rather than accepted as an alias.

#### Tenant-root creation grant authority

The tenant-management/Console backend is the tenant-root creation grant
authority. It holds one environment-specific Ed25519 signing key in its own
Secret or KMS binding. The browser, dashboard client, Router, Deriver A,
Deriver B, SigningWorker, and tenant-root control-plane issuer never receive
that private key. Only the tenant-root control-plane Worker receives the
bounded public grant-authority keyset needed to verify grants.

This authority is separate from the routine control-plane issuer. The grant
authority decides whether an authenticated tenant administrator may create one
physical root lineage. The control-plane issuer turns that narrow grant into
the signed role commands needed to execute the ceremony. A grant-authority key
must not equal an issuer, role-signing, peer-signing, online-sealing, or
managed-backup key, and no configuration may let either authority sign for the
other.

Before signing, the Console backend must:

1. authenticate the administrator and authorize the exact organization,
   project, and environment;
2. resolve the canonical `TenantRootIdentityV1` server-side, including
   `signingRootId` and `signingRootVersion`;
3. allocate the custody lineage and 32-byte nonzero grant nonce from its CSPRNG;
4. distinguish initial creation from explicit root replacement or migration;
5. reject caller-supplied authority, role, epoch, session, ceremony nonce,
   signer key ID, provider key reference, or derivation context;
6. persist the exact canonical signed grant before returning it, keyed by one
   server-side creation-operation ID; and
7. return those same signed bytes for an exact retry of that operation rather
   than minting a second grant.

The grant authorizes only initial creation of the named identity and lineage.
It does not authorize refresh, restore, deletion, activation, signing, or a
second lineage. Those operations use their own lifecycle state and typed
capabilities. The request reaching the tenant-root control plane carries only
the exact signed grant; internal transport authentication does not replace its
signature or scope checks.

Grant replay semantics are fixed:

- first acceptance requires a currently fresh, valid grant from a configured
  authority;
- the exact canonical grant is the idempotency key for genesis;
- an exact grant whose creation record was already durably accepted returns the
  original record and `replayed: true`, including after grant or ceremony
  expiry;
- an unseen expired grant returns `ExpiredLocalRequest`;
- any different grant for the same identity and lineage returns
  `ConflictingPair`;
- a retry never redraws or changes the ceremony session, ceremony nonce,
  capability nonce, time window, role signer IDs, journal, or capability; and
- a lost response at any boundary converges to the same accepted record or the
  lifecycle's explicit cleanup branch.

The control plane therefore must distinguish exact durable replay before
applying first-use freshness. Deterministically deriving ceremony material from
the canonical grant is sufficient for byte-identical retries while the active
issuer and role-signing configuration is unchanged. It does not by itself
provide exact replay after expiry or configuration rotation. The live boundary
must identify the already accepted grant before minting a replacement
capability, return the stored journal/capability digests, and leave any
subsequent role-key-rotation cleanup to the lifecycle.

Grant-authority rotation is independent from issuer and Deriver rotation. The
Console backend stops issuing with the retired private key immediately. Its
public key remains in the control plane's verifier set until every grant signed
under it is expired and every accepted ceremony under it is terminal or has a
verified cleanup receipt. Only then may the old verifier and private key be
destroyed. An issuer or role-signing-key rotation drains admitted ceremonies or
burns them into the explicit cleanup branch; it never silently reissues an
existing grant under the new configuration.

The Console backend records the grant digest, authority key ID, tenant scope,
operation ID, issue/expiry window, outcome, and resulting creation-record
digest in its audit log. It records no tenant-root share, joined root, issuer
private material, or provider private reference. Production deployment must
use a dedicated least-privilege grant-authority key and service credential per
environment.

The control-plane Worker and both Derivers receive an external
`ROUTER_TENANT_ROOT_CREATION_DO` namespace binding with the Router Worker as
the environment-specific `script_name`. This grants direct access to the
Router-owned object without a Router proxy hop:

```text
Router --service binding--> tenant-root control-plane issuer
                                  |
                                  +--external DO binding--+
                                                           v
Deriver A --external DO binding----------------> Router-owned tenant-root DO
Deriver B --external DO binding----------------> Router-owned tenant-root DO
```

Only the Router manifest declares the Durable Object migration. Callers derive
the object name from the verified identity digest and custody lineage and use
the existing bounded public-evidence APIs. The object verifies all signed
authority and lifecycle inputs itself. A configured binding, shared internal
transport secret, request header, or Router assertion never authorizes a
mutation by itself.

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
8. The control plane verifies the complete evidence bundle, issues the
   control-plane-signed activation receipt, and activates epoch 1 after both
   roles attest installation and every canary passes.

Neither scalar share crosses into the opposite role. Only commitments, proofs,
and redacted receipts leave a Deriver.

### Dormant creation journal and authority

The implemented creation slice persists only a `Started` journal event. Its
canonical identity and creation-context bytes rebuild `preparing`; later
creation events are not representable. An issuer-signed
`TenantRootCreationCapabilityV1` binds the Started-journal digest, identity,
custody lineage, expected revision, deterministic Durable Object authority ID,
one-use nonce, issuer key ID, and issue/expiry window. The dormant parser
accepts a bounded issuer verifying-key set by key ID, retaining issuer keys by
ID so accepted capabilities remain verifiable across issuer-key rotation.

The Router uses the deterministic
`ROUTER_TENANT_ROOT_CREATION_DO` binding and
`router_ab_router_tenant_root_creation_v1` migration. Its object name is derived
from the identity digest and custody lineage. The internal request carries only
canonical journal and capability bytes; validation gates a single get/put at
`creation/v1/journal`. First acceptance requires a fresh capability. An exact
persisted record replays after expiry, an unseen expired capability returns
`ExpiredLocalRequest`, and any changed record returns `ConflictingPair`. Creation
capability freshness is checked only for the first `Started`-journal acceptance.
After that durable acceptance, installation progress uses
`TenantRootCeremonyContextV1::validate_at` and also requires Router time to be
no later than the nominal `expires_at_ms`, matching the lifecycle finalizer's
strict verification window. Exact persisted evidence retries remain replayable
after expiry.
A dormant crate-private Router caller derives the same object, checks the
capability authority before dispatch, and verifies the returned revision plus
both request digests. The dormant boundary accepts a bounded issuer
verifying-key set by key ID through
`TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON_ENV`; production
deployment provisioning and rotation rollout for that set remain open.

`expected_control_plane_revision` always names the exact lifecycle state from
which the control plane dispatches a role mutation. It is positive, is assigned
only by the lifecycle authority, and is authenticated by the issuer command.
The Router Durable Object must compare it with its current revision before
dispatch; role D1 treats it as an authenticated command coordinate and keeps
its own row revision as a separate CAS counter.

| Role mutation | Dispatch state | `expected_control_plane_revision` | State after accepted receipts |
| --- | --- | ---: | ---: |
| Initial pending insertion | Creation `Preparing` | 1 | 1 |
| Initial activation | Creation `Verified` | 2 | 3 (`Active`) |
| Refresh pending insertion | Refresh `Preparing` | 4 | 4 |
| Refresh swap | Refresh `Verified` | 5 | 6 (`Retiring`) |
| Pending cleanup after a failed pre-activation attempt | Current `Preparing`, `Verified`, or `CleanupIncomplete` state | The exact persisted state revision; the first attempt is 1 or 2 for creation and 4 or 5 for the first refresh | The lifecycle transition increments once after the required cleanup receipts |
| Previous-epoch destruction | Refresh `Retiring` | 6 | 7 (`Active`) |

For a later stable active revision `R`, the next refresh uses `R+1` for pending
insertion, `R+2` for swap, and `R+3` for previous-epoch destruction, producing
the next active state at `R+4`. Failed attempts also consume revisions, so the
issuer must read the persisted branch revision instead of calculating from a
fixed ceremony number. A resumed cleanup from `CleanupIncomplete` uses that
newer state revision. Initial activation cannot be issued at revision 3 and
refresh swap cannot be issued at revision 6: those revisions exist only after
the corresponding role mutations and accepted receipts complete.

Issuer authorization and role-local mutation use two deliberately distinct
digests. The issuer command authenticates a pre-handler authorization payload
made entirely from control-plane-known public facts. After the selected
Deriver generates and seals its role share, role D1 computes its existing exact
mutation digest over the complete public row payload, including the ciphertext
digest. A verified issuer command supplies the immutable command scope; it
cannot supply or impersonate the later D1 mutation digest.

### Dormant public-evidence-only installation checkpoint

`TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes`
returns `VerifiedTenantRootSignedShareInstallationEvidenceWireV1` after strict
canonical decoding and role-signature verification. The strict raw decoder
exposes `TenantRootSignedShareInstallationEvidenceV1::signing_key_id`, and
reload selects that exact ID within the evidence role before signature
verification. The crate-private
`RouterAbTenantRootCreationDurableObject::persist_installation_checkpoint`
validates that wire against the Started journal,
`TenantRootCreationRoleVerifyingKeysV1`, and
`verify_tenant_root_creation_evidence_v1`, then stores a
`CloudflareTenantRootCreationInstallationCheckpointV1` under
`TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1`. The checkpoint
stores one role's canonical signed evidence in `OneRoleReady`, or both role
evidence values plus the public root commitment in `BothRolesReady`; no scalar
share crosses this boundary. Either role may arrive first; unseen first/peer
evidence passes `require_fresh_installation_context` before nominal expiry,
while exact persisted retries replay after expiry. Substituted or corrupt
evidence fails closed.

The role-private pending record derives its installation-evidence receipt
digest from those same exact verified signed-evidence bytes. The successful
role-command receipt carries the same canonical bytes. This keeps one evidence
encoding across the Deriver, role D1, terminal receipt, and Router checkpoint;
no boundary reconstructs the evidence or accepts an independently supplied
digest.

This slice is dormant. No public route or role-runtime creation handler invokes
`persist_installation_checkpoint`, and `BothRolesReady` does not activate or cut
over an epoch. Role verification reads
`ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV`; the retained
`TenantRootCreationRoleVerifyingKeysV1` resolves each verified wire by its exact
role and `signing_key_id`. Production provisioning/configuration and deployment
rotation rollout for this role-key set remain open.

The role-key decoder rejects duplicate verifier bytes across roles or key IDs,
duplicate key IDs, malformed points, and surrounding identifier whitespace; it
never trims those values. Its keyset and binding fields are private. Both Router
and Deriver loaders apply the peer-verifier exclusion before accepting the key
set, and no raw signing-key field escapes the role-constrained signer. The role
runtime re-verifies the exact canonical installation-evidence bytes against the
configured signer before calling either provider; an adversarial
same-ID/different-key evidence value fails before either provider is invoked.

The three role-runtime prerequisites are now frozen. The
issuer-authenticated `create_pending_share` command binds the exact role,
Started journal/context, epoch, positive control-plane revision, session,
nonce, authority, and expiry. The Durable Object accepts exact role-signed
creation commitments into `OneRoleCommitted`/`BothRolesCommitted`, verifies the
pair before either installation checkpoint, and keeps scalar material outside
the rendezvous. The lifecycle authority remains the sole source of
`expected_control_plane_revision`. The next slice is the dormant Deriver
handler and private evidence-to-checkpoint caller that compose these contracts;
no public route or activation path is wired yet.

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
14. Verify the complete evidence bundle, issue the control-plane-signed
    activation receipt, and activate the next epoch only after its exact
    revision and both role receipts pass.
15. Unfence tenant derivation.
16. Destroy previous-epoch shares, refresh material, and previous-epoch wrapping
    keys.
17. Verify both destruction receipts and return the lifecycle to `active`.
18. Emit a redacted receipt and release the lock.

Normal signing continues during every step because it does not read tenant root
shares.

### Dormant refresh Durable Object checkpoints

The refresh Durable Object slice persists authoritative public state only from
an issuer-verified activation receipt. Its active-state record retains the
exact signed receipt bytes and digest, tenant identity, custody lineage, active
epoch, A/B share commitments, joined-root commitment, lifecycle revision, and
fence. An exact projection replay is accepted; conflicting state is rejected.

Each refresh attempt binds the command authority, context, session, nonce,
current and next epochs, expected revision, current A/B/root commitments, and
active activation-receipt digest. Commitment and installation checkpoints are
accepted in either role order only within that exact scope. Every mutation uses
one atomic Durable Object transaction. First-unseen checkpoints require fresh
evidence; an identical durable record replays, while a changed payload or
fence fails closed. The checkpoint fence advances only through its
open -> reserved -> executed states; terminal activation transitions remain
owned by the lifecycle activation path.

This public checkpoint slice contains no secret shares and deliberately has no
activation or cutover consumer. Public routes, production transport, live
two-role orchestration, and crash/restart coordination remain release gates.

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

The additive Rust boundary, exact-byte parity vector, and direct 2-of-2
share-refresh invariance vectors are implemented. The invariance vectors cover
`x_client_base`, `x_server_base`, and `y_server` natively and through the WASM
self-check. Switching the existing production adapter from its ceremony-bound
context to these stable bytes remains behind the R103F integration gate.

Custody uses a separate record:

```text
TenantRootCustodyBindingV1
  identityDigest: TenantRootIdentityDigestV1
  custodyLineage: TenantRootCustodyLineageId
  epoch: TenantRootShareEpoch
  deriverAIdentity
  deriverBIdentity
  deriverACommitment
  deriverBCommitment
  rootCommitment
  operationId
  sessionId
  nonce
  issuedAtMs
  expiresAtMs
  stableContextDigest
  outerTranscriptDigest
```

Operation and session IDs are separate nonzero 128-bit values. The request
nonce is a separate nonzero 256-bit value. Their JSON representations are
canonical unpadded base64url. The canonical custody-binding bytes encode the
ASCII domain `seams/tenant-root-custody-binding/v1` as the first field, followed
by every field above in order. Each value uses a four-byte big-endian length and
exact field bytes; epoch and Unix milliseconds are fixed-width big-endian
integers inside their fields. The
binding digest is SHA-256 over those canonical bytes. Only the control plane
constructs the binding from an active lifecycle state, so callers cannot supply
the identity, lineage, epoch, or commitments independently. The same frozen
60-second clock-skew allowance and 300 000 ms maximum issue-to-expiry window
used by tenant-root ceremonies apply to this record, and its Deriver identities
use the same boundary-identifier rules.

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

The preferred replacement derives one target-specific root for each Deriver
through the existing threshold-PRF algebra:

```text
R_A = ThresholdPrf(K, Ed25519DeriverAContributionRoot, stable_context)
R_B = ThresholdPrf(K, Ed25519DeriverBContributionRoot, stable_context)

server_contribution_A = ExistingEd25519ContributionKdf(R_A, role_A, stable_context)
server_contribution_B = ExistingEd25519ContributionKdf(R_B, role_B, stable_context)
```

`R_A` and `R_B` are distinct because their fixed `PrfPurpose` variants are
distinct. Both purposes use `Raw32` output and the exact existing
`Ed25519YaoStableKeyDerivationContextV1` bytes. `RootShareEpoch`,
`TenantRootShareEpoch`, custody lineage, session, retry, and transport metadata
are excluded from the PRF context.

One derivation ceremony performs this preface:

1. The control plane admits one exact server-resolved stable context and current
   tenant-root custody binding. Neither Deriver can request an arbitrary PRF
   context from its peer.
2. Deriver A evaluates its local A-target partial and one B-target partial.
   Deriver B evaluates its local B-target partial and one A-target partial.
3. A sends only its B-target partial, commitment, and DLEQ proof to B. B sends
   only its A-target proof bundle to A. Both messages are recipient-encrypted,
   role-authenticated, and bound to the exact tenant, lineage, active epoch,
   stable-context digest, source role, target role, session, nonce, and expiry.
4. The two messages travel simultaneously over the existing A/B session. A
   reverse-direction target, duplicate target, caller-selected target, or
   mismatched purpose fails before partial verification.
5. A verifies B's A-target proof and combines it with A's local A-target partial.
   B verifies A's B-target proof and combines it with B's local B-target partial.
   Each combine requires the exact fixed 2-of-2 share IDs and current
   commitments.
6. Each target converts only its own `PrfOutput32` into a role-specific zeroizing
   server-contribution-root capability and runs the existing `signer-core`
   HKDF-SHA-256 contribution KDF locally.
7. The role PRF output and intermediate root are never persisted, cached across
   requests, logged, returned, or routed through the Router. They are zeroized
   after the existing Yao role is constructed.
8. Yao receives the same role-local server contribution shapes it receives
   today. Raw root shares, threshold-PRF partials, PRF outputs, and the joined
   tenant root never enter the circuit.
9. Each role enters a typed local `preface_ready` state only after it verifies
   the incoming proof, combines its target output, and constructs its existing
   Yao role. An existing first Yao envelope may be buffered until the receiving
   role reaches that state; it cannot be processed earlier. No standalone
   readiness message or second preface flight is added. A failure or timeout
   burns the pair session, zeroizes local outputs, and retries with a new
   session, nonce, and DLEQ randomness.

The Router may route encrypted proof bundles. It cannot open a partial or
combine either target output. A has no B-target peer partial and B has no
A-target peer partial, so neither role can calculate the other's output.

The current `threshold-prf` DLEQ verifier maps every purpose through
`EcdsaPrfPurposeV1`. Preparation must separate generic threshold-PRF proof
verification from that ECDSA adapter and add the two explicit Ed25519 purposes.
The Ed25519 protocol cannot reuse an ECDSA purpose label or accept a raw purpose
string at any boundary.

The required equivalence is between any two valid A/B sharings of the same K
under this role-targeted profile. It is separate from the retired
deployment-share-hash profile. Pre-launch cutover regenerates its unreleased
outputs.

The outer Ed25519 derivation protocol, target-specific payloads, pair-session
identity, vectors, and generated server bindings change. The Yao circuit
manifest, circuit digest, schedule, table bytes, input/output schemas, and
circuit-cache identity remain byte-identical. Any prototype result requiring a
circuit change stops the candidate and requires this plan to be amended.

Production must use one authoritative profile. If existing production wallets
depend on the role-local hashing profile, rollout requires one explicit
pre-cutover migration. The implementation retains no dual derivation path.

### Ed25519 architecture-selection latency prototype

Existing threshold-PRF microbenchmarks are encouraging: the retained local
baseline reports roughly 0.10 ms native and 0.21 ms Node/V8 for a one-runtime
2-of-3 evaluation and combine, with DLEQ operations around 0.20 ms. Those
figures measure local cryptography. They do not measure the role-separated A/B
exchange, Worker scheduling, encryption, or composition with Yao. See the
[threshold-PRF benchmark record](../crates/threshold-prf/docs/benchmarks.md).

Preparation therefore builds one benchmark-only role-targeted PRF preface in
the existing `ed25519-yao-cloudflare-bench` harness before production protocol
work begins. The 10 ms limit applies to the complete current-versus-candidate
warm p95 ceremony delta, including cryptography, encryption, Worker scheduling,
and A/B transport. It is an absolute rejection ceiling for every measured
topology and ceremony. The prototype:

- runs the A-target and B-target directions simultaneously;
- sends exactly one proof bundle in each direction;
- reuses the A/B transport session required by the baseline Yao ceremony and
  creates no additional HTTP request, WebSocket, connection handshake, or
  preface-only readiness message;
- uses current threshold-PRF partial evaluation, DLEQ verification, exact 2-of-2
  combine, role encryption, and the existing local contribution KDF;
- invokes the existing activation, export, and lane-materialization Yao
  artifacts without modifying them;
- uses no persistent output cache and adds no client-facing request;
- exercises the same-account Service Binding and cross-account WebSocket
  topologies already measured by the harness;
- compares current and candidate paths from the same release build with the
  same inputs, topology, first-observation/warm cohort, and Worker placement
  where observable.

Every topology and ceremony cohort records at least 100 successful samples and
reports:

- end-to-end p50, p95, and p99 wall time;
- the PRF-preface wall time and peer-exchange time separately;
- added connection, HTTP request, WebSocket, and client-to-service round-trip
  counts, all of which must remain zero; proof-bundle flights, which must equal
  one; and standalone readiness-message flights, which must remain zero;
- per-role CPU time and sampled isolate-memory P999 for separate current and
  candidate resource windows; first-observation latency is reported separately;
- the platform-observability limitation that neither Fetch nor
  `workersInvocationsAdaptive` identifies fresh-isolate starts, so no
  cold-start-incidence claim is made;
- proof-bundle and total protocol bytes by direction;
- retry, timeout, and failure counts;
- the exact Yao circuit, manifest, schedule, and table-stream digests.

The candidate passes only when:

1. direct-reference, exact 2-of-2 combine, old/new sharing, and final recipient
   package vectors agree;
2. A cannot combine `R_B`, B cannot combine `R_A`, and the Router cannot combine
   either output;
3. the Yao artifact digests and serialized circuit bytes equal the current
   product byte for byte and runtime circuit synthesis remains zero;
4. the preface adds at most 4 KiB total serialized internal traffic;
5. warm p95 end-to-end wall time increases by no more than 10 ms in every
   topology and ceremony cohort;
6. warm p95 per-role CPU time increases by at most 5 ms, and sampled
   isolate-memory P999 increases by at most 10%; any `exceededMemory` status
   fails;
7. every cohort retains at least 25% headroom below the fixed 200 ms benchmark
   CPU limit, the 128 MiB Worker memory limit, and the 32 MiB WebSocket-message
   limit. HTTP-triggered Worker wall duration is unbounded while the client
   remains connected, so duration headroom is explicitly inapplicable.

The latency campaign interleaves current and candidate requests. Resource
analytics use separate, exclusive, non-overlapping current and candidate
windows against the same deployment because Workers invocation analytics
aggregate by script and time range and cannot group on the benchmark's profile
request header. Each resource window contains exactly 101 observations for
each of the three ceremonies and no other traffic to either script.

The offline evaluator emits an approval payload containing only fixed ASCII
identifiers, integer limits and measurements, deployment IDs, and SHA-256
artifact commitments. Its canonical JSON recursively sorts object keys,
preserves array order, uses standard JSON scalar encoding, and emits no
whitespace. `approval_payload_sha256` is SHA-256 over those exact UTF-8 bytes.
The evaluator output is a selection candidate, never an approval.

The final selection record reuses the externally pinned release-authority
model. Its policy artifact has this exact JSON shape:

```json
{
  "schema": "r120-threshold-prf-release-authority-policy-v1",
  "policy_scope": "r120_threshold_prf_architecture_selection_v1",
  "minimum_approval_sequence": 9,
  "reviewer": {
    "role": "architecture_selection_reviewer",
    "authority_id": "project-release-reviewer",
    "key_epoch": 1,
    "verifying_key_hex": "32-byte-lowercase-hex",
    "authority_key_digest": "sha256-lowercase-hex"
  }
}
```

`minimum_approval_sequence`, `approval_sequence`, and `key_epoch` are
nonnegative JSON safe integers and are encoded as big-endian `u64` in signed
bytes. `LP32(x)` means `BE32(byte_length(x)) || x`. The authority-key digest is:

```text
SHA-256(
  LP32("seams/r120-threshold-prf-release-authority-key-digest/v1")
  || LP32("architecture_selection_reviewer")
  || LP32(authority_id UTF-8)
  || LP32(BE64(key_epoch))
  || LP32(raw 32-byte Ed25519 verifying key)
)
```

The separately signed selection artifact has exactly these fields:
`schema = r120-threshold-prf-signed-architecture-selection-v1`,
`approval_payload_sha256`, `approval_sequence`, `reviewer_authority_id`,
`reviewer_key_epoch`, `reviewer_authority_key_digest`,
`signature_algorithm = ed25519`, and `signature_hex` containing exactly 64
lowercase-hex-encoded signature bytes. The signed bytes are the ASCII domain
`seams/r120-threshold-prf-architecture-selection/v1`, one zero byte, the raw
32-byte approval digest, the approval sequence and key epoch as big-endian
`u64`, a big-endian `u16` authority-ID length plus its UTF-8 bytes, and the raw
32-byte authority-key digest. Verification requires the externally pinned
authority policy, exact key digest and epoch, a sequence at or above its
rollback floor, strict Ed25519 verification, and a recomputed approval digest.
The offline verifier also commits the exact candidate, policy, and signed
artifact byte hashes into its output. Only that verifier may emit
`selection_ready = true`.

Passing evidence freezes the role-targeted threshold-PRF architecture and
authorizes production protocol work. A failed correctness, separation,
artifact, or resource gate stops Refactor 120. The joined-root HKDF-in-Yao design
is not an automatic fallback and remains unimplemented until an amended plan is
reviewed.

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

It also causes no R103F lifecycle mutation: no
`WalletSessionAuthorizationV2`, operation credential, Wallet Session quota,
registration completion receipt, device-link delivery or acknowledgement, V6
browser record, hosted child credential, or host/iframe message changes.

Clients may require a normal SDK release for the one-time protocol-profile
cutover if a boundary-local Router A/B or WASM protocol changes. That release is
built on R103F's final SDK and V6 browser model. It does not imply an IndexedDB
record-version or `WALLET_PROTOCOL_VERSION` change. Either version changes only
when its own persisted or host/iframe shape changes. Every subsequent tenant
refresh is entirely server-side.

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
      readonly activation: VerifiedTenantRootSignedActivationReceiptV1;
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

The `activation` field is the non-cloneable, issuer-verified token. The active
state projection retains only its exact signed bytes and digest.

The dormant lifecycle and role-private D1 cutover now use the exact signed
activation receipt bytes. `TenantRootActivationReceiptProjectionV1` consumes the
verified receipt token and retains its canonical bytes plus digest. The
Cloudflare role-private stores use the `tenant-root-role-private-d1/v2` schema:
activation rows persist canonical receipt bytes (base64url at the D1 boundary),
recompute their digest on load, and reject any projection or availability
branch that differs from the decoded receipt. One-use command replay rows move
forward through `reserved`, `executed`, and exactly one terminal
`completed`/`failed` state, retaining exact terminal receipt bytes and applying
the lifecycle CAS guard in the same transaction. Only the v2 schema is served;
there is no legacy receipt shape or compatibility reader.

The other tenant-root machines use these exhaustive branches:

- creation: `empty`, `preparing`, `verified`, `active`,
  `failed_before_activation`, `cleanup_incomplete`;
- managed role restore: `available`, `role_unavailable`, `restoring_a`,
  `restoring_b`, `verifying`, `forward_refreshing`, `cleanup_incomplete`;
- deletion: `active`, `fenced`, `destroying`, `deleted`,
  `destruction_incomplete`.

Refactor 121 freezes tenant recovery-set and source-independent restore states.
`ActiveTenantRootEpochV1` and `VerifiedTenantRootEpochV1` require either two
source-bound, signature-verified current-epoch role-backup artifacts or the
exact dual-authority signed `accepted_permanent_derivation_loss` authorization.
Optional backup evidence would make an unsafe activation state representable.

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
tenant count, so scheduling must respect fixed Ed25519 canary capacity,
threshold-PRF proof capacity, key-provider quotas, and role-store quotas.

The Ed25519 architecture-selection prototype owns the derivation-ceremony
resource gate. The refresh scheduler additionally measures the fixed ECDSA and
Ed25519 continuity canaries under the selected release. The first scheduler runs
one tenant refresh at a time per deployment. Higher concurrency requires a
separate measured capacity change and is outside this refactor.

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

## Historical Preparation Evidence (reference only)

This section records decisions and evidence already produced while R120 was
being designed. It is not an execution checklist. Any still-relevant production
requirement appears once in the active implementation plan below.

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

| Former gap                          | Resolution in this plan                                                                                                                                                                                                                                                                                                                                        | Required preparation evidence                                                                                                                                                                                                                         |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tenant identity                     | Five required server-resolved fields, one canonical byte encoding, and `TenantRootIdentityDigestV1` are frozen under **Root identity and custody lineage**                                                                                                                                                                                                     | Rust canonical vectors, TS boundary fixtures, and caller-override route tests                                                                                                                                                                         |
| R103F composition                   | R103F B4/B5 remains the only Wallet Session admission and exact material-resolution path; R120 independently resolves root custody from authenticated deployment configuration                                                                                                                                                                                 | One composition fixture proving exact material/root-identity agreement and rejection of every Wallet Session, authorization, credential, browser, or request-body root override                                                                       |
| Shared-boundary ownership           | R103F owns its signer-D1, browser, receipt, device-link, and shared route shapes through the named integration gates; R120 adds no signer-D1 root-custody schema                                                                                                                                                                                               | Reviewed file-ownership inventory, R103F Phase 2 API snapshot, and final-schema migration check                                                                                                                                                       |
| Cutover ordering                    | R120 activation waits for R103F R5, fences new derivation, drains every pre-cutover derivation session and delayed registration/recovery commit path, verifies one exact R120 revision set, and then resumes derivation without a dual profile                                                                                                                 | Deployed-revision manifest, mixed-revision fail-closed test, derivation-fence and replay-drain drill, committed-receipt identity inventory, and before/after exact Wallet Session signing proof                                                       |
| Deployment clone/custody identity   | Random `TenantRootCustodyLineageId` separates source and restored custody histories without changing KDF input                                                                                                                                                                                                                                                 | Cross-lineage replay and mixed-receipt rejection vectors                                                                                                                                                                                              |
| Root field and transcripts          | Existing Ristretto255/SHA-512 scalar, share, commitment, proof, and HPKE primitives are reused with the exact transcript binding above                                                                                                                                                                                                                         | Creation and refresh vector corpus generated from Rust                                                                                                                                                                                                |
| Stable ECDSA derivation             | Existing stable key-context bytes remain the only stable context; both epoch types and ceremony metadata are custody-only                                                                                                                                                                                                                                      | Same-root cross-epoch threshold-PRF vectors and Rust/backend parity                                                                                                                                                                                   |
| Role-targeted Ed25519 derivation    | Two fixed threshold-PRF purposes yield separate A-target and B-target roots; each target combines only its output and runs the existing contribution KDF locally; root shares and PRF material stay outside Yao                                                                                                                                                | Direct-reference and 2-of-2 vectors, target-separation and proof-substitution tests, recipient-package parity, and byte-identical Yao artifacts                                                                                                       |
| Ed25519 architecture selection      | The role-targeted threshold-PRF preface must pass a production-shaped benchmark before production protocol work; the joined-root circuit remains unapproved                                                                                                                                                                                                    | Same-build current/candidate Cloudflare benchmark artifacts covering both topologies, three ceremonies, first-observation/warm latency cohorts, exclusive profile-specific CPU and sampled-memory windows, wire bytes, failures, and artifact digests |
| Active epoch and locking            | One lineage-scoped Durable Object owns revision, lock, activation, and crash recovery                                                                                                                                                                                                                                                                          | Failure injection at every transition and matching-receipt reconstruction drill                                                                                                                                                                       |
| Online and managed-backup keys      | `managed_healing_v1` requires independent external A/B versioned KMS/HSM authorities; Cloudflare-native custody uses `operational_rotation_v1`                                                                                                                                                                                                                 | Provider adapter qualification and destructive rollback drill                                                                                                                                                                                         |
| Managed recovery                    | Restore is one-role, current-epoch-only, capability-bound, commitment-verified, and followed by refresh                                                                                                                                                                                                                                                        | Independent A and B loss drills plus control-plane-loss drill                                                                                                                                                                                         |
| Tenant recovery                     | Dedicated stable recovery sharing and its product/CLI protocol are frozen by Refactor 121                                                                                                                                                                                                                                                                      | Source-offline restore and mixed-set/role rejection corpus                                                                                                                                                                                            |
| Pre-launch cutover                  | All unreleased roots and derived material are regenerated; any externally relied-on identity blocks rollout for an explicit migration                                                                                                                                                                                                                          | Signed inventory proving zero externally relied-on legacy-profile identities                                                                                                                                                                          |
| One-role availability               | Existing signing continues; every operation requiring derivation returns `tenant_derivation_temporarily_unavailable`                                                                                                                                                                                                                                           | Intended-behaviour contract covering every named operation                                                                                                                                                                                            |
| Ed25519 PRF-preface resource budget | Exact circuit-artifact equality, one bidirectional proof-bundle flight on the existing A/B session, no new connection or standalone readiness exchange, a 4 KiB internal-wire cap, an absolute 10 ms warm-p95 ceremony-delta cap, CPU and memory caps, sample count, and Workers headroom are fixed under **Ed25519 architecture-selection latency prototype** | Reproducible before/after release benchmark artifact                                                                                                                                                                                                  |
| Root deletion                       | Forward-only deletion states, secret destruction scope, customer-copy limitation, and audit retention owner are fixed                                                                                                                                                                                                                                          | A/B partial-failure and destructive staging drills                                                                                                                                                                                                    |
| Deployment claims                   | `managed_healing_v1` and `operational_rotation_v1` expose distinct, test-gated claims                                                                                                                                                                                                                                                                          | Configuration type fixtures and dashboard copy tests                                                                                                                                                                                                  |

An implementation may choose a qualified KMS/HSM vendor or a stricter resource
budget without changing these contracts. A weaker key provider selects
`operational_rotation_v1`; it cannot silently weaken `managed_healing_v1`.

### Invariant register

Every invariant receives a stable ID so the specification, code review, tests,
release evidence, and operational runbooks refer to the same claim.

| ID       | Required invariant                                                                                                                                                                                                                                                                                  |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R120-I01 | One canonical authenticated tenant root identity selects exactly one physical root pair and one active epoch.                                                                                                                                                                                       |
| R120-I02 | Request bodies, browser state, wallet records, and diagnostic fields cannot select or override tenant, root, role, or epoch.                                                                                                                                                                        |
| R120-I03 | No runtime, store, backup object, log, operator tool, or ordinary recovery ceremony obtains the joined root or both decrypted shares.                                                                                                                                                               |
| R120-I04 | Initial creation is contributory: one honest role makes the joined root unpredictable, both roles prove possession, and the public root commitment is non-identity.                                                                                                                                 |
| R120-I05 | A successful refresh changes both role shares and preserves the public tenant-root commitment.                                                                                                                                                                                                      |
| R120-I06 | Stable ECDSA derivation bytes and threshold-PRF outputs exclude `RootShareEpoch` and `TenantRootShareEpoch` and remain identical across refresh.                                                                                                                                                    |
| R120-I07 | ECDSA custody transcripts, partials, routing, persistence AAD, and replay protection bind the exact tenant root identity and active epoch.                                                                                                                                                          |
| R120-I08 | Ed25519 derives separate A-target and B-target threshold-PRF outputs without reconstructing the joined root; each target output and final server contribution remain identical across operational-share refreshes.                                                                                  |
| R120-I09 | Mixed, stale, future, substituted, replayed, expired, or role-swapped creation and refresh messages fail closed.                                                                                                                                                                                    |
| R120-I10 | Pre-activation failure preserves the old epoch; post-activation recovery moves forward and never reactivates the previous epoch.                                                                                                                                                                    |
| R120-I11 | Normal signing remains available and does not load tenant derivation-root shares.                                                                                                                                                                                                                   |
| R120-I12 | Refresh mutates no wallet, client, signer-package, public-key, address, `MpcMaterialActivationRef`, R103F exact authorization, operation credential, quota, receipt, device-link acknowledgement, or V6 browser record.                                                                             |
| R120-I13 | Refresh and root creation use approved CSPRNGs, canonical scalar decoding, nonzero checks where required, domain-separated transcripts, and constant-time secret-scalar operations.                                                                                                                 |
| R120-I14 | Tenant A's creation, refresh, failure, backup, restore, retirement, and deletion cannot read or mutate tenant B's state.                                                                                                                                                                            |
| R120-I15 | Each current role share has one independently encrypted and authorized role-local backup, or the deployment explicitly accepts permanent loss of future derivation after share loss.                                                                                                                |
| R120-I16 | A restored share is role-, tenant-, root-, epoch-, and commitment-bound; successful restore is followed by a forward refresh.                                                                                                                                                                       |
| R120-I17 | Retired online and managed-backup shares are unrecoverable through supported Worker, database, secret, provider, and disaster-recovery rollback paths before compromise healing is claimed.                                                                                                         |
| R120-I18 | Generated Rust, WASM, JavaScript, TypeScript, JSON, SQL, and deployment representations agree on every identity, epoch, transcript, and lifecycle field.                                                                                                                                            |
| R120-I19 | Existing production identities either prove continuity under the authoritative profile or are excluded by an explicit pre-cutover decision.                                                                                                                                                         |
| R120-I20 | Independently created or device-linked deployments share no tenant root or role share. Explicit disaster recovery preserves the logical root under a new custody lineage and records every surviving source.                                                                                        |
| R120-I21 | Tenant recovery packages contain one dedicated recovery sharing, remain separate by role, and bind the same stable public root commitment without copying an operational share.                                                                                                                     |
| R120-I22 | Operational refresh leaves tenant recovery packages usable and makes no healing claim after both shares or both recipient keys from one tenant recovery set are compromised.                                                                                                                        |
| R120-I23 | R103F B4/B5 remains the sole Wallet Session-to-runtime authorization path; R120 root resolution accepts only authenticated deployment configuration and never session, authorization, credential, browser, or diagnostic identity.                                                                  |
| R120-I24 | R120 production activation occurs only after R103F R5, with new derivation fenced, pre-cutover derivation sessions drained, and every participating revision matched to the one authoritative derivation profile.                                                                                   |
| R120-I25 | An R103F committed registration receipt is included in the old-profile identity inventory even before browser publication, and no delayed registration or recovery replay can make retired-profile material active or usable after cutover.                                                         |
| R120-I26 | An A-target proof bundle travels only B-to-A, a B-target proof bundle travels only A-to-B, and neither Deriver nor the Router can obtain the exact peer partial set needed to combine the other target's output.                                                                                    |
| R120-I27 | Raw tenant-root shares, threshold-PRF partials and outputs, and the joined tenant root never enter Yao; the current Yao circuit manifest, digest, schedule, schemas, table bytes, and circuit-cache identity remain byte-identical.                                                                 |
| R120-I28 | Production Ed25519 protocol work begins only after the role-targeted threshold-PRF candidate passes the frozen correctness, separation, artifact, latency, CPU, memory, wire, and headroom gates.                                                                                                   |
| R120-I29 | Each role processes Yao only from its typed local `preface_ready` state; the existing first Yao envelope may wait for that state, no standalone readiness message or second preface flight exists, and preface failure or timeout burns the pair and zeroizes every role-local output before retry. |
| R120-I30 | Root-share refresh makes no claim to revoke an already exposed context-scoped target PRF output, server contribution, or active wallet or lane share.                                                                                                                                               |

### Boundary inventory

The inventory is organized around boundaries where one language's type checker
cannot protect the next system. Each row must record its final symbols, wire or
schema version, owning invariant IDs, planned change, authoritative test, and
review confidence.

| Boundary                                      | Current locations to classify                                                                                                                                                                                                                                                                                                                                                                   | Type-system escape hatch or risk                                                                                                                                                                                                                                                         |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R103F exact admission and material resolution | `packages/wallet-server/src/router/auth/commonRouterUtils.ts`; both threshold routes; `routerAbPrivateSigningWorker.ts`; the final R103F B4/B5 resolver and capability-subject repository                                                                                                                                                                                                       | A Wallet Session or authorization identifier can be mistaken for a threshold or tenant-root identity; R120 must consume the B5-resolved authoritative material record rather than reconstruct it                                                                                         |
| R103F session, browser, and link state        | signer-D1 Wallet Session migrations and stores; `d1WalletRegistrationService.ts`; device-link activation and acknowledgement stores; V6 browser persistence; host/iframe messages                                                                                                                                                                                                               | Adding root epoch or custody metadata to an exact session, receipt, delivery, acknowledgement, browser record, or iframe message would couple transparent refresh to client lifecycle                                                                                                    |
| Authenticated tenant and root routing         | `packages/shared-ts/src/threshold/signingRootScope.ts`; `packages/wallet-server/src/router/auth/commonRouterUtils.ts`; `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthConfig.ts`; project-policy parsing in `crates/router-ab-cloudflare/src/lib.rs`                                                                                                                      | Independently normalized strings, optional request fields, JWT/policy JSON, and manually derived `projectId:envId` identifiers                                                                                                                                                           |
| ECDSA stable derivation                       | `crates/router-ab-core/src/derivation/context.rs`, `ecdsa_threshold_prf.rs`, `ecdsa_threshold_prf_backend.rs`; `crates/threshold-prf`; `crates/router-ab-ecdsa-derivation`; `crates/router-ab-core/specs/ecdsa-threshold-prf.md`                                                                                                                                                                | Canonical bytes, PRF purpose domains, scalar suites, and downstream derivation contexts compile after a semantically wrong field remains included                                                                                                                                        |
| ECDSA custody and protocol wires              | `crates/router-ab-core/src/protocol/ecdsa_threshold_prf_request.rs`, `payload.rs`, `output.rs`, `router_ab_ecdsa_derivation.rs`, `signer_plaintext.rs`; `crates/router-ab-ecdsa-client-protocol/src/registration.rs`, `post_registration.rs`, `recipient_proof.rs`                                                                                                                              | Serde JSON, custom length-delimited encodings, plaintext/envelope duplication, and equality checks outside one shared type                                                                                                                                                               |
| Ed25519 role-targeted PRF preface             | `crates/threshold-prf/src/context.rs`, `prf.rs`; `crates/router-ab-ecdsa-client-protocol` public DLEQ verifier; `crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs`; `crates/router-ab-ed25519-yao/src/product.rs`; `crates/signer-core/src/ed25519_yao_derivation.rs`; `crates/router-ab-core/src/protocol/ed25519_yao.rs`; `crates/ed25519-yao`; `crates/ed25519-yao-cloudflare-bench` | The generic threshold-PRF verifier currently maps through ECDSA-only purpose types; target role, stable PRF context, epoch-bound outer AAD, output ownership, local KDF provenance, pair-session identity, and unchanged circuit artifacts cross separate type and generation boundaries |
| Rust/WASM/JavaScript                          | `wasm/router_ab_ecdsa_client/src/ceremony.rs`; `wasm/router_ab_ecdsa_signing_worker/src`; `wasm/wallet_custody_ceremony/src`; checked-in `wasm/*/pkg/*.d.ts`; generated Router A/B TypeScript bindings                                                                                                                                                                                          | `serde_wasm_bindgen`, JSON strings, checked-in generated declarations, and separately regenerated WASM packages                                                                                                                                                                          |
| Shared TypeScript protocol                    | `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`, `routerAbEd25519Yao.ts`, `domainIds.ts`; generated `routerAbEd25519YaoCore.ts`                                                                                                                                                                                                                                                       | Manual exact-key parsers and builders duplicate Rust lifecycle and canonical-wire assumptions                                                                                                                                                                                            |
| Wallet-server orchestration                   | `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`; Ed25519 registration, recovery, export, and capability domains; D1 registration and capability persistence                                                                                                                                                                                                        | Route bodies, database rows, and service results are parsed at separate boundaries; current checks sometimes equate root epoch with signing-root version                                                                                                                                 |
| Wallet SDK and browser workers                | wallet registration, recovery, export, local material, presign-pool, relayer RPC, and worker modules under `packages/wallet/src`                                                                                                                                                                                                                                                                | IndexedDB records, Worker messages, WASM calls, and response parsers do not share a single compiler boundary with Rust or the server                                                                                                                                                     |
| Role-private persistence                      | `crates/router-ab-cloudflare/migrations/deriver-a`, `deriver-b`; `tenant_root_role_d1.rs`; `ed25519_yao_role_d1.rs`; strict Deriver runtime adapters                                                                                                                                                                                                                                      | Dormant schemas now include encrypted tenant-root lifecycle rows and one-use command-replay rows with execution checkpoints and terminal receipts; provider-backed key destruction, live orchestration, and runtime fault evidence remain open                                  |
| Control plane and coordination                | `crates/router-ab-cloudflare/src/router_coordinator.rs`, `durable_object/mod.rs`, `durable_object/tenant_root_creation.rs`, `ecdsa_pool_lifecycle.rs`, `ed25519_yao_lifecycle.rs`; the future dedicated tenant-root control-plane Worker                                                                                                                                                             | The creation and refresh Durable Object binding/migration, input-gated journal, authoritative public active-state projection, and public-evidence-only A/B commitment/installation checkpoints are dormant; exact replay/fence semantics and atomic mutations are implemented. The dedicated non-blind issuer Worker, direct issuer/Deriver external DO bindings, activation consumer, live lock, alarm, retry, crash, and orchestration semantics remain runtime work |
| Deployment and secrets                        | `crates/router-ab-cloudflare/src/env.rs`; Router, Deriver A, Deriver B, SigningWorker, and future control-plane Wrangler files; deployment key generators; `scripts/deployment-targets.mjs`; environment examples; `docs/deployment`                                                                                              | The private routine issuer key must exist only in the dedicated control-plane Worker. The shared public `TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON` trust anchor belongs in Router and both Derivers, remains absent from SigningWorker, and replaces the Router-prefixed name. External DO bindings use the Router `script_name` in each environment while migrations remain Router-only. Provisioning, key rotation, boot guards, and deployment evidence remain open |
| Local/dev parity                              | `crates/router-ab-dev/src/local_ecdsa_root_shares.rs`, local Router/worker coordinators, SQLite schema and seed scripts, strict local runtime config                                                                                                                                                                                                                                            | Local fixtures can silently preserve the deployment-wide root model and mask Cloudflare-only failures                                                                                                                                                                                    |
| Persistence consumers                         | R103F final signer-D1 stores; ECDSA capability manifests; Ed25519 local metadata; device-link source contributions; recovery key manifests                                                                                                                                                                                                                                                      | Existing stable signing-root metadata must remain readable while `TenantRootShareEpoch` and custody lineage stay absent; these surfaces are verification-only unless the plan is amended after R103F                                                                                     |
| Vectors, fixtures, and generation             | `crates/router-ab-core/fixtures`; Router A/B Rust tests; Yao formal-verification fixtures; `wasm/wallet_custody_ceremony/tests/wire_fixtures.rs`; shared TypeScript and top-level test helpers                                                                                                                                                                                                  | Generated JSON and hand-written fixtures compile independently, while stale snapshots can preserve retired semantics                                                                                                                                                                     |
| Documentation and operational claims          | this plan; `docs/router-ab/protocol.md`; deployment and staging-custody docs; incident and rollback runbooks                                                                                                                                                                                                                                                                                    | Security language can overstate erasure, recovery independence, or client transparency without executable evidence                                                                                                                                                                       |

The checked inventory must classify every hit from repository-wide searches for:

```text
RootShareEpoch | root_share_epoch | rootShareEpoch | activation_epoch
TenantRoot | tenant_root | tenantRoot
TenantRootShareEpoch | tenant_root_share_epoch | tenantRootShareEpoch
signingRootId | signing_root_id | signingRootVersion | signing_root_version
DERIVER_A_ROOT_SHARE_WIRE_SECRET | DERIVER_B_ROOT_SHARE_WIRE_SECRET
root_share_wire | root share | derivation-root/v1
PrfPurpose | PrfOutput32 | EcdsaPrfPurposeV1 | server contribution root
ed25519_yao | pair_digest | root_metadata_digest | circuit_digest
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

| Test layer                   | Required checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Intended owner                                                                                                                                                                                                                                                           |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Root algebra and transcripts | Creation and refresh equations; both shares change; public commitment continuity; malformed scalars; zero/identity cases; contribution, role, tenant, epoch, transcript, nonce, expiry, and replay substitution; abort and restart at every message                                                                                                                                                                                                                                                                        | New focused Rust tests in `crates/router-ab-core/tests`, plus property tests for field/scalar operations                                                                                                                                                                 |
| Constant-time and randomness | Approved OS/Worker CSPRNG boundary; unbiased scalar sampling; secret-independent scalar operations and comparisons                                                                                                                                                                                                                                                                                                                                                                                                         | Rust review plus the existing constant-time qualification track where applicable; add a targeted test or analysis only for newly introduced secret-scalar code                                                                                                           |
| ECDSA stable output          | Byte-exact V2 stable context vectors; custody-binding vectors; old/new epoch output equality; mixed-epoch rejection; Rust protocol/backend parity                                                                                                                                                                                                                                                                                                                                                                          | Existing `ecdsa_threshold_prf*`, `ecdsa_derivation_protocol`, `protocol_boundaries`, and formal-verification owners in `crates/router-ab-core/tests`                                                                                                                     |
| Ed25519 role-targeted output | New A/B purpose vectors; direct-reference versus exact 2-of-2 output; old/new sharing equality; target outputs differ; source/target direction, proof, commitment, purpose, context, recipient, epoch, replay, and arbitrary-context rejection; each target lacks the other peer partial; typed local `preface_ready` gate with no standalone receipt; failure/timeout zeroization and pair burn; existing KDF and recipient-package parity; raw shares and PRF material absent from Yao; byte-identical circuit artifacts | `threshold-prf` and Router A/B Ed25519 Rust tests, pair-digest vectors, `cargo yao-fv all` anti-drift, and Cloudflare WASM vector adapters                                                                                                                               |
| Ed25519 latency candidate    | Current versus role-targeted candidate under same-account and cross-account topologies for activation, export, and lane materialization; first-observation/warm p50/p95/p99, absolute warm-p95 delta, preface and exchange time, connection/request/message-flight counts, exclusive-window CPU, sampled-memory P999, directional wire bytes, failures, sample count, Workers headroom, and exact circuit-artifact digests                                                                                                 | Benchmark-only changes in `crates/ed25519-yao-cloudflare-bench` plus one reviewed architecture-selection evidence record                                                                                                                                                 |
| Cross-runtime wires          | Rust-to-TypeScript generated bindings; Rust/WASM/JS round trips; unknown/missing field rejection; canonical JSON and custom binary encoding parity                                                                                                                                                                                                                                                                                                                                                                         | `pnpm generate:router-ab-ed25519-yao-types`, relevant signer-core generation, WASM package builds, and wallet-custody wire fixtures                                                                                                                                      |
| Domain-state types           | Invalid lifecycle branches, broad spreads, direct object literals, missing role receipts, caller-selected identity, mixed current/next epochs, and activation from the wrong state fail to compile                                                                                                                                                                                                                                                                                                                         | Targeted `*.typecheck.ts` fixtures with `@ts-expect-error` in shared TypeScript, wallet-server, and top-level `tests/typecheck`                                                                                                                                          |
| R103F composition            | Exact admission resolves the same `MpcMaterialActivationRef` before and after refresh; normal signing never loads a tenant root; Ed25519 export first resolves exact active material through B5 and then independently resolves the server root binding required by its derivation ceremony; no R120 custody field appears in R103F authorization, signer-D1, receipt, link, browser, or iframe shapes                                                                                                                     | Focused wallet-server composition tests, R103F B4/B5 type fixtures, signer-D1 schema inspection, and the authoritative client-transparency contract                                                                                                                      |
| Role-private stores          | Tenant/role/epoch key uniqueness; encrypted-at-rest record shape; no cross-request plaintext cache; current/pending selection; CAS transitions; one-use replay reservation, execution checkpoint, signed terminal receipt, exact retry, and conflict behavior; crash recovery; cross-tenant denial; stale-backup rejection                                                                                                                                                           | New Rust Cloudflare D1 adapter tests and migration tests; local SQLite parity where it exercises the same contract                                                                                                                                                       |
| Creation journal and authority | Started-only journal decoding/rebuild; signed object-, identity-, and lineage-bound capability; retained issuer-key verification; deterministic Durable Object binding; input-gated single-key persistence; fresh-versus-expired replay and conflict semantics                                                                                                                     | Focused `router-ab-core` journal/capability tests and Cloudflare creation-Durable-Object tests; public caller/configuration and cutover evidence remain open                                                                                                           |
| Backup and restore           | Independent A/B key paths; exact AAD; managed current-epoch and tenant recovery namespaces; recovery reshare continuity; one-role restore; wrong-role and wrong-tenant denial; commitment verification; forward refresh; old managed-key destruction; tenant-copy non-revocation; provider and database rollback drill                                                                                                                                                                                                     | New adapter integration tests plus an executable disaster-recovery runbook producing redacted receipts                                                                                                                                                                   |
| Server orchestration         | Server-resolved tenant identity; request override rejection; per-tenant fencing; concurrency; one-role failure; activation and retirement convergence; normal signing during every state                                                                                                                                                                                                                                                                                                                                   | Cloudflare lifecycle tests and focused wallet-server route/unit tests                                                                                                                                                                                                    |
| Client transparency          | No WebAuthn prompt, SDK callback, IndexedDB mutation, signer-package fetch, wallet scan, or activation-reference change; public keys and addresses remain stable                                                                                                                                                                                                                                                                                                                                                           | One authoritative intended-behaviour contract backed by focused unit assertions at RPC/Worker boundaries                                                                                                                                                                 |
| Deployment cutover           | R103F R5 complete; old-profile committed receipts inventoried; unfinished registration/recovery derivation paths drained or retired; deployment-wide root bindings absent; tenant stores and key providers present only in the owning role; derivation fenced until one R120 revision set passes preflight                                                                                                                                                                                                                 | R103F zero-state and committed-receipt inventory, delayed-replay rejection, `crates/router-ab-cloudflare/tests/bindings.rs`, secret-material boundary tests, mixed-revision rejection, deployment-target tests, strict local config tests, and deployment smoke evidence |
| Erasure and security claims  | Old sessions drain before destruction; old online and backup ciphertext cannot be opened after key retirement; Worker, D1, secret, deployment, and disaster-recovery rollback cannot restore a usable old epoch; provider quota exhaustion never selects a shared fallback                                                                                                                                                                                                                                                 | Destructive staging and quota drills against the selected provider; documentation claims are gated on their executable receipts                                                                                                                                          |
| Multi-tenant operations      | Refresh, restore, failure, deletion, schedule jitter, quota exhaustion, and audit events for tenant A leave tenant B unchanged and available                                                                                                                                                                                                                                                                                                                                                                               | Cloudflare integration tests and bounded-concurrency scheduler tests                                                                                                                                                                                                     |

### Invariant evidence ownership

Every invariant now has one named authoritative owner. `Local green` means the
current implementation has executable local evidence. The other states name the
exact future gate and do not count as release evidence.

| Invariant | Authoritative owner                                                                                                                   | Current evidence state                                                                                                |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| R120-I01  | `tenant_root.rs`, `tenant_root_lifecycle.rs`, role-private D1 lifecycle integration, and the future control-plane tenant-mapping test | Identity and role-store primitives are local green; physical control-plane mapping remains open                       |
| R120-I02  | Tenant-root TypeScript type fixtures plus the ECDSA, Ed25519, and shared identity composition tests                                   | Local green, including runtime JavaScript override rejection before B5 resolution                                     |
| R120-I03  | Tenant-root secret-material API review, role-store redaction tests, deployment bundle scan, and provider restore drill                | Rust role separation is local green; deployment and provider evidence remain open                                     |
| R120-I04  | `tenant_root_protocol.rs` creation vector and `threshold-prf` root-share proof tests                                                  | Local green                                                                                                           |
| R120-I05  | `tenant_root_protocol.rs`, `tenant_root_lifecycle.rs`, refresh algebra tests, and the minimal Verus anti-drift theorem                | Local green                                                                                                           |
| R120-I06  | `ecdsa_stable_context.rs` and the stable-purpose backend tests                                                                        | Local green for dormant V2; production adapter cutover remains open                                                   |
| R120-I07  | Custody-binding vectors, stable-purpose backend substitution tests, role replay D1 integration, and future production-wire tests      | Core and role-local replay evidence are local green; production-wire integration remains open                         |
| R120-I08  | `threshold-prf` role-target vectors, Router A/B native/WASM parity, and the Phase 0 candidate runner                                  | Local correctness is green; deployed architecture selection remains open                                              |
| R120-I09  | Tenant-root protocol, refresh-transport, strict activation-evidence/receipt, command-replay, lifecycle, and role-private D1 substitution tests | Local green, including exact receipt-byte and refresh-checkpoint replay/fence paths; transition-level runtime fault injection remains open |
| R120-I10  | Exhaustive creation/refresh recovery-plan tests, dormant refresh Durable Object checkpoints, and the future live restart matrix         | Pure state machine and dormant checkpoint path are local green; live runtime restart evidence remains open             |
| R120-I11  | Signing-engine boundary checks and the future one-role availability intended-behaviour contract                                       | Existing signing boundary is green; production failure-state contract remains open                                    |
| R120-I12  | B4/B5 composition tests, signer-D1 no-change check, and the future client-transparency intended-behaviour contract                    | Composition and schema boundary are local green; end-to-end refresh proof remains open                                |
| R120-I13  | `threshold-prf` scalar tests, HPKE/parser vectors, constant-time code-generation gate, and CSPRNG boundary review                     | Local green                                                                                                           |
| R120-I14  | Role-private D1 identity/lineage CAS tests and the future multi-tenant concurrency operating test                                     | Store isolation is local green; fleet concurrency evidence remains open                                               |
| R120-I15  | Managed-backup frozen vector, strict activation-evidence/canary and creation lifecycle activation tests, and provider backup integration | Provider-neutral artifacts and activation branches are local green; qualified provider evidence remains open          |
| R120-I16  | Managed-restore lifecycle and managed-backup cross-lineage/role/epoch/commitment substitution tests                                   | Local green; deployed forward-refresh drill remains open                                                              |
| R120-I17  | Root-deletion lifecycle tests plus destructive online/backup provider rollback drills                                                 | Pure lifecycle is local green; provider destruction evidence remains open                                             |
| R120-I18  | Rust frozen vectors, WASM adapters, TypeScript type checks, D1 migrations, and generation anti-drift commands                         | Current local representations are green; final production binding generation remains open                             |
| R120-I19  | Pre-launch production-identity inventory and signed cutover decision                                                                  | Cutover evidence required                                                                                             |
| R120-I20  | Cross-lineage lifecycle, backup, recovery-artifact, Refactor 150 linking, and Refactor 121 restore contracts                          | R120 cryptographic lineage checks are local green; product integration remains outside this phase                     |
| R120-I21  | Recovery-reshare, recovery-artifact, recipient-proof, and restore-import vector suites                                                | Local green                                                                                                           |
| R120-I22  | Recovery-reshare continuity tests and the Refactor 121 replacement operating contract                                                 | Cryptographic continuity is local green; product replacement evidence remains in Refactor 121                         |
| R120-I23  | Exact ECDSA/Ed25519 B4/B5 composition tests and tenant-root type fixtures                                                             | Local green with runtime and static selector rejection                                                                |
| R120-I24  | R103F R5 closure receipt, derivation-fence drill, revision manifest, and mixed-revision rejection test                                | Canonical five-participant manifest and mixed-revision rejection are local green; deployed cutover drill remains open |
| R120-I25  | R103F committed-registration inventory and delayed registration/recovery replay drill                                                 | Cutover evidence required                                                                                             |
| R120-I26  | `threshold-prf` role-target type and vector tests plus benchmark bundle-direction checks                                              | Local green                                                                                                           |
| R120-I27  | Yao artifact anti-drift suite, role-target source audit, and Phase 0 artifact equality check                                          | Local green; deployed selection receipt remains open                                                                  |
| R120-I28  | Phase 0 benchmark evaluator and release-signature verifier                                                                            | Local evaluator is green; deployed cohort and signature remain open                                                   |
| R120-I29  | Benchmark preface lifecycle tests and the future versioned outer-protocol `preface_ready` state test                                  | Benchmark behavior is local green; production protocol remains gated by Phase 0                                       |
| R120-I30  | Refresh/deletion security-claim tests and the published recovery-limitations review                                                   | Pure lifecycle semantics are local green; final product claims remain open                                            |

### R103F overlap ownership

The merged R103F tree is classified into three ownership branches. Changes that
cross a listed integration gate update the owning contract directly; R120 adds
no compatibility union or interim wrapper.

| Ownership                     | Exact surfaces                                                                                                                                                                                                                                                                                                                      | R120 rule and merge gate                                                                                                                                                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R103F-owned unchanged         | Wallet Session admission and exact authorization under `packages/wallet-server/src/router/auth`; signer-D1 registration, receipt, capability, and activation stores; `packages/wallet/src` browser, recovery, device-link, worker, and V6 persistence state; host/iframe messages; R103F intended-behaviour contracts               | R120 consumes these through B4/B5 and adds no custody field. The signer-D1 no-change digest, type checks, source boundaries, and eight-contract browser matrix own this branch.                                                                       |
| R120-owned                    | `crates/router-ab-core/src/derivation/tenant_root*`; tenant-root and role-target tests; `crates/threshold-prf` role targets; `crates/ed25519-yao-cloudflare-bench` candidate code; `crates/router-ab-cloudflare/src/tenant_root_role_d1.rs` and its A/B migrations; wallet-server tenant-root composition modules and type fixtures | R120 may evolve these before activation while preserving frozen R103F inputs and outputs. The local R120 crypto, store, composition, and Phase 9C/13A gates own this branch.                                                                          |
| Shared production integration | ECDSA threshold request/backend adapters; versioned Ed25519 outer protocol and pair lifecycle; Router coordinator and strict Deriver routes; generated Router A/B TypeScript bindings; wallet-server threshold routes that will invoke tenant-root composition                                                                      | Integration waits for the signed Phase 0 architecture selection. The completed R103F B4/B5 snapshot through `bfaed2877`, merged in `308948c15`, is the input contract. Final generated-binding, mixed-revision, cutover, and intended-behaviour checks own the merge. |

### Boundary-local version and cutover map

R120 changes only the boundaries listed below. An unlisted R103F boundary keeps
its current exact version and shape. A changed wire receives one new version;
the release carries no dual parser beyond an explicitly documented request or
persistence boundary.

| Boundary                                         | Frozen version decision                                                                                                                                                                         | Release evidence                                                                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Wallet Session admission and material resolution | Keep the exact R103F B4 admission and B5 activation projections at completed input `bfaed2877` from R120 merge `308948c15`. R120 adds no field to either shape.                                                               | ECDSA and Ed25519 composition tests, negative type fixtures, and the signer-D1 no-change digest                                   |
| Tenant root identity                             | `TenantRootIdentityV1` and `TenantRootIdentityDigestV1`; five required server-resolved fields and no epoch or role selector                                                                     | Rust identity vectors and TypeScript boundary fixtures                                                                            |
| Custody identity and lifecycle                   | `TenantRootCustodyLineageId`, `TenantRootShareEpoch`, `TenantRootCustodyBindingV1`, and the creation, refresh, restore, and deletion `V1` unions                                                | Tenant-root protocol and lifecycle suites                                                                                         |
| Stable ECDSA derivation                          | `StableTenantDerivationContextV2` and `MpcPrfStablePurposeBindingPlanV2`; custody epoch remains outside stable PRF bytes                                                                        | `ecdsa_stable_context.rs` and backend substitution tests                                                                          |
| ECDSA production transport                       | Replace the current ceremony-bound stable-purpose request with one exact V2 request after Phase 0 and the shared-boundary gate. Delete the prior production request in the same change.         | Rust wire vector, generated binding parity, mixed-version rejection, and before/after public-key equality                         |
| Ed25519 production transport                     | Existing `Ed25519Yao*V1` remains unchanged until Phase 0 passes. The selected preface ships as one exact V2 outer protocol and pair-session shape; V1 is deleted at activation.                 | Generated Rust/TypeScript vectors, arbitrary-context denial, pair burn/zeroization tests, and byte-identical Yao artifact digests |
| Role-private persistence                         | Deriver A and B migrations remain independent. `0002_tenant_root_role_shares.sql` owns encrypted lifecycle rows and `0003_tenant_root_command_replays.sql` owns exact one-use command receipts. | Migration parity, real `workerd` store integration, encrypted-row inspection, and schema-head manifest fields                     |
| Phase 0 evidence                                 | Phase 9C local evidence is `v2`; the deployed benchmark, selection approval payload, and release signature retain their frozen V1 schemas.                                                      | Current-source receipt digest, six raw deployed artifacts, evaluator output, and release signature verification                   |

The participating revision manifest is `r120_revision_manifest_v1`. It contains
one release ID and git commit, then one required record for each of
`wallet_server`, `router`, `deriver_a`, `deriver_b`, and `signing_worker`. Every
record contains the deployed script identity, deployment ID, source/build
digest, configuration digest, supported R120 protocol version, and role-local
migration head. The manifest also commits the B4/B5 input commit, Phase 0
selection-record digest, Yao artifact digest set, and exact derivation-profile
ID. The control plane accepts a release only when every required participant is
present, every digest is canonical, the two Derivers report their own role, and
all participants report the same release, profile, protocol, and artifact set.
A stale, missing, duplicate-role, or mixed-profile participant leaves
derivation fenced.

The derivation-fence procedure is fixed:

1. Verify R103F R5 closure, the committed-registration identity inventory, and
   the signed Phase 0 architecture-selection record.
2. Fence new registration, recovery, export, and lane-materialization
   derivations. Normal signing continues and does not consult tenant-root
   custody.
3. Drain every admitted derivation session and retire or reject every delayed
   registration or recovery commit. Record the zero-in-flight receipt.
4. Deploy the complete participant set without activating the R120 profile.
   Read back and verify `r120_revision_manifest_v1`, both role-private schema
   heads, and the absence of deployment-wide root-share bindings.
5. Run ECDSA and Ed25519 canaries plus the deliberate mixed-revision rejection
   probe while the fence remains closed.
6. Activate the one authoritative R120 profile, record its activation receipt,
   and run one exact B4/B5 Wallet Session derivation proof for each curve.
7. Unfence derivation only after all receipts agree. Rollback to the old release
   is allowed through step 5. Once the first R120-profile derivation is
   admitted, recovery is forward-only and deploys the complete R120 revision
   set again.

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

Preparation, benchmark work, R120-owned cryptographic Rust/WASM primitives,
role-private migrations, and tenant-root lifecycle work may proceed while R103F
is active. The deployed architecture-selection gate still controls production
transport integration and activation. R120 changes to R103F-owned shared files
wait for the R103F Phase 2 exit and a recorded B4/B5 API snapshot. Updates to
final browser, device-link, iframe, generated bindings, and shared fixture
surfaces wait for the R103F Phase 3 exit. The R120 branch rebases before either
integration point; it does not preserve an interim R103F shape through a
wrapper or compatibility union.

### Historical preparation snapshot

- [ ] Materialize every specification-closure row as its named canonical
      artifact or executable check.
- [x] Assign every invariant to at least one authoritative test or executable
      operational check. The invariant evidence ownership table records the
      current local proof and the exact remaining release gate for R120-I01
      through R120-I30.
- [x] Classify every boundary-search hit and every generated artifact. The
      executable inventory at
      `crates/router-ab-dev/scripts/check-r120-boundary-inventory.mjs` classifies
      every current tracked and non-ignored untracked hit with no unclassified
      path, explicitly records the two ignored local Deriver secret-binding
      boundaries without reading their contents, and records 34 generated
      artifacts with their byte length, SHA-256 digest, regeneration command,
      and verification command in
      `docs/evidence/r120-boundary-inventory-v1.json`.
- [x] Classify every R103F overlap as R103F-owned unchanged state, an R120-owned
      surface, or a shared integration point with one named merge gate. The
      ownership table fixes the exact path scopes and shared production gate.
- [x] Freeze byte-exact creation, refresh, ECDSA, Ed25519, backup, and lifecycle
      schemas and vectors. The canonical Rust suites, threshold-PRF role-target
      vectors, and five native/WASM R120 self-checks own these bytes; production
      transport versions remain gated separately.
- [x] Freeze the B4/B5 composition contract and signer-D1 no-change assertion.
- [x] Freeze the boundary-local version map, derivation-fence procedure, and
      `r120_revision_manifest_v1` participant and fail-closed contract.
- [ ] Implement the benchmark-only role-targeted threshold-PRF preface, run every
      frozen cohort, and approve one signed architecture-selection record only
      after all correctness, separation, artifact, latency, CPU, memory, wire,
      and headroom gates pass.
- [ ] Prove the selected candidate leaves every Yao circuit artifact byte-identical
      and record the current artifact digests in the selection evidence.
- [ ] Choose and exercise the online and backup key-destruction provider.
- [ ] Inventory production identities and approve a pre-launch cutover with no
      dual production profile.
- [x] Freeze the one-share-loss availability contract as an explicit branch:
      exact current-role backups or dual-authority accepted permanent loss;
      production provider qualification and restore-quorum evidence remain
      gated.
- [ ] Stop the refactor if stable-output vectors, the Ed25519 candidate gate,
      recovery separation, or erasure evidence cannot meet the release gates.

## Active Implementation Plan

This is the only execution checklist for R120. The historical ledger below is
retained as design evidence; its unchecked rows do not block implementation or
count toward progress.

### Completed foundation

- [x] Implement and verify the role-targeted threshold-PRF and proactive-share-
      refresh cryptographic core, native/WASM vectors, minimal proof, and
      latency prototype.
- [x] Implement tenant-root identity, lineage, epoch, lifecycle, recovery,
      restore, retirement, and deletion domain types.
- [x] Implement the control-plane issuer and grant boundary, Router-owned
      public Durable Object state, role-local D1 storage, replay checkpoints,
      and signed terminal receipts.
- [x] Implement Deriver admission, request-local share generation, signed A/B
      commitment exchange, finalization, online sealing, and scalar-leak tests.
- [x] Implement authorized pending cleanup with exact role, identity, lineage,
      epoch, revision, evidence, replay, and authoritative-row binding.

### Milestone 1: make tenant-root creation work end to end

- [x] Persist each already-encrypted managed-backup artifact in a separate
      role-private Cloudflare R2 bucket. Deriver A and Deriver B use different
      buckets, object namespaces, and wrapping keys. The role-private D1 row
      retains the independently sealed online share.
- [x] Reject a reserved cleanup replay immediately when its recomputed command
      digest differs from the stored digest.
- [x] Wire the private Router -> Deriver A -> Deriver B flow using the existing
      strict request/response unions and internal authentication. Keep both
      live scalars inside their owning bounded requests.
- [x] Persist B, verify B's public evidence and terminal receipt at A, persist A,
      then checkpoint both public installation evidences in the Router-owned
      Durable Object. Activation remains impossible until both role records and
      backup objects exist.
- [x] Add one isolated-workerd operating-path test covering successful creation,
      exact retry, interruption after B persistence, authorized cleanup, and a
      fresh retry. Delete dormant creation helpers made unreachable by this
      path. The test forces B's successful response to be lost after its D1,
      R2, and public installation checkpoints commit, then proves the exact B
      row and backup are removed before a new lineage succeeds.

### Milestone 2: use tenant roots for production derivation

- [x] Persist one server-authoritative custody lineage for each canonical
      tenant-root identity and resolve it through the private Console service
      binding. Browser requests, JWT claims, and signer D1 cannot select the
      identity, lineage, role, or epoch.
- [x] Make one live ECDSA registration load both active role-private shares and
      derive through `StableTenantDerivationContextV2`. Remove
      `RootShareEpoch` from threshold-PRF input bytes.
- [x] Regenerate only the ECDSA bindings and vectors changed by that operating
      path, then delete the ECDSA deployment-root adapter so registration has
      no fallback.
- [ ] Prove that ECDSA registration preserves the expected public key and
      address through the live server path.

Ed25519 outer-protocol wiring and continuity move to the next implementation
slice. Refresh, recovery, release-wide cleanup, dashboards, and broad evidence
generation remain in Milestones 3 and 4; they do not block this ECDSA vertical
path or count toward its completion.

### Milestone 3: make refresh and recovery operational

- [ ] Wire the existing refresh protocol through per-tenant locking, the
      Router-owned public checkpoint, both role-private stores, and the same
      managed-backup store used by creation.
- [ ] Keep the current epoch active until both next-epoch role records, backup
      objects, installation evidences, and the activation receipt verify.
- [ ] Resume or clean up every persisted interruption state without ever
      combining mixed epochs or regenerating a committed random share.
- [ ] Wire one-role managed restore followed immediately by forward refresh;
      keep tenant-controlled recovery packages on their existing independent
      path.
- [ ] Retire old role records and destroy old online/backup wrapping-key
      versions after activation. Record `cryptographic_erasure_unverified` when
      the selected provider cannot prove destruction.
- [ ] Add one operating-path test proving refresh preserves ECDSA and Ed25519
      outputs, normal signing stays available, and another tenant is unchanged.

### Milestone 4: release and remove the old path

- [ ] Run the deployed same-account and cross-account Ed25519 benchmark once;
      require no new connection or client round trip and at most 10 ms warm p95
      overhead before enabling the new profile.
- [ ] Exercise creation, refresh, interruption cleanup, one-role restore,
      retirement, and deletion in staging with independently provisioned A/B
      stores and keys.
- [ ] Run the authoritative Rust, WASM, TypeScript boundary, and intended-
      behaviour suites on the exact release tree.
- [ ] Fence new ceremonies, drain pre-cutover operations, activate one revision,
      and confirm wallets and clients require no migration or local mutation.
- [ ] Remove obsolete deployment-root code, bindings, Secrets, migrations that
      were never deployed, temporary allowances, dead exports, and superseded
      tests. Preserve applied migration history and immutable evidence.
- [ ] Update the architecture and operations documentation and mark R120
      complete.

### Execution rules

- Implement the next unchecked operating-path item before adding more evidence,
  guards, abstractions, or plan structure.
- Add one authoritative behavioural test for each operating path. Add another
  guard only when an observed escape is not representable by that test or the
  type system.
- Do not add dormant adapters, compatibility variants, duplicate canonical
  encoders, new inventory frameworks, or speculative provider abstractions.
- Run focused tests while implementing. Run broad suites only after a milestone
  changes shared protocol, persistence, deployment, or cryptographic behavior.
- Update progress at milestone boundaries rather than counting evidence rows.

## Historical Detailed Ledger (reference only)

### Phase 0: benchmark and freeze the Ed25519 architecture

- [x] Add a benchmark-only two-direction PRF preface to
      `ed25519-yao-cloudflare-bench`; do not add production protocol variants or
      compatibility paths.
- [x] Model B-to-A A-target delivery and A-to-B B-target delivery as exact,
      simultaneous, recipient-encrypted messages.
- [x] Reuse the baseline Yao A/B transport session, add exactly one
      bidirectional proof-bundle flight, and add no additional HTTP request,
      WebSocket, connection handshake, preface-only readiness message, or
      client round trip.
- [ ] Run current and candidate activation, export, and lane-materialization
      paths under the same-account and cross-account topologies with the frozen
      first-observation/warm cohorts.
- [ ] Reject the candidate if any warm p95 current-versus-candidate ceremony
      delta exceeds 10 ms or if normal signing can invoke the preface.
- [x] Verify direct-reference and refreshed-share output equality, strict target
      separation, existing contribution-KDF parity, recipient-package parity,
      and byte-identical Yao artifacts.
- [ ] Publish the raw benchmark artifact and signed architecture-selection
      record with every acceptance calculation reproducible from measured data.
- [ ] On success, freeze the two target purpose domains, message directions,
      resource budget, and unchanged-circuit boundary. On failure, stop and
      amend this plan before any joined-root circuit work.

Phase 0 execution status on 2026-08-29:

- **Provisional feasibility decision: pass.** Continue with the role-targeted
  threshold-PRF candidate through deployed validation. The joined-root Yao
  circuit remains outside the plan.

- The fixed role-target purposes and generic proof verifier are now normal
  `threshold-prf` primitives. The temporary feature split and production
  dependency on the ECDSA client adapter are deleted. The ECDSA adapter remains
  a dev-only parity oracle, and its existing public verifier/finalizer tests pass.
- The benchmark compares the current and candidate profiles in one Worker
  build. Both feed byte-identical fixed server contributions, client inputs,
  output coins, ceremony, chunk profile, and Yao implementation into the
  protocol. Only the candidate executes the preface.
- The preface uses the established WebSocket after its existing handshake. Each
  role sends one 342-byte HPKE-encrypted proof bundle before awaiting the peer,
  for one simultaneous bidirectional flight and 684 total bytes.
- Native tests prove direct-reference equality, refreshed-share equality,
  fixed direction and recipient separation, ciphertext rejection, existing
  contribution-KDF parity, and the 4 KiB wire budget. The Worker report records
  the authoritative circuit and schedule digests and the runner rejects any
  current/candidate digest, Yao wire-ledger, or recipient-package-size drift.
- Same-account local `workerd` smoke coverage completed for current and
  candidate activation, export, and lane materialization. Two compact repeats,
  each with one first and one warm observation per cohort, measured a 4-5 ms
  candidate preface. Across both repeats the largest client-wall delta was
  5.37 ms and the largest Worker-elapsed delta was 6 ms. The runner classifies
  this evidence as `provisionally-feasible`; these diagnostic values do not
  satisfy the frozen cohort size. The detailed local record is
  [`r120-phase0-local-smoke.md`](../crates/ed25519-yao-cloudflare-bench/docs/r120-phase0-local-smoke.md).
- Run `pnpm bench:r120` from
  `crates/ed25519-yao-cloudflare-bench` with the complete deployment environment
  and receipt. Deployed mode accepts no positional endpoint or topology; it
  derives both from the validated boundary and rejects a response with a stale
  deployment ID. `paired-latency` collects one first plus 100 warm observations
  per ceremony and profile. `resource-current` and `resource-candidate` collect
  the two exclusive resource windows required for profile-specific Workers
  analytics.
- The offline selection evaluator recomputes each latency report from raw
  samples, verifies deployment equality and non-overlapping resource windows,
  applies the 5 ms CPU-delta, 10% sampled-memory-delta, and 25% finite-limit
  headroom gates, and emits a canonical approval-payload digest. A passing
  result is `ready-for-release-signature`; `selection_ready` stays false until
  the release authority signs that exact digest.
- A read-only preflight checks that six distinct, parseable artifacts exist
  with the expected topology and profile identities before evaluation. The
  R120 same-account and independently administered cross-account environment
  examples freeze the 101-observation cohort and required output paths while
  retaining the existing non-executing deployment acknowledgements.
- The offline release verifier pins one exact authority policy, recomputes the
  approval digest, enforces the sequence floor, authority identity, key epoch,
  authority-key digest, 64-byte signature shape, and Ed25519 signature, then
  commits all three input-artifact hashes. Synthetic fixtures reject stale
  sequences, wrong signing keys, mutated evidence, and invalid signatures.
- Focused resource fixtures cover receipt/deployment mismatch, campaign and
  report profile mismatch, contaminated request counts, unavailable memory,
  and overlapping analytics windows. Missing memory remains incomplete
  evidence and cannot become a substantive architecture rejection.
- Architecture selection remains open. No Cloudflare credentials were present
  in the original execution environment. A later read-only Wrangler preflight
  found one authenticated benchmark account and produced a redacted
  same-account deployment plan for one first plus 100 warm observations per
  profile and ceremony. The deployment wrapper now accepts an exact
  `<benchmark-script>.<account-subdomain>.workers.dev` endpoint while retaining
  its receipt and cleanup boundaries. No Worker was deployed.
- A merged-tree rerun on August 31 cleared the benchmark's 25 native tests and
  13 source guards, all host/WASM Clippy targets, 186 independent verifier
  tests, 128 regenerated differential cases, 84 production formal-parity
  tests, 420 generator tests including 26 circuit tests, three artifact-policy
  tests, both Phase 5 WASM stream modes, regenerated native/WASM compute
  budgets, the constant-time code-generation gate, and the isolation audit.
  The current isolation snapshot has six exact authorized core dependents,
  zero benchmark dependents, zero references across 3,188 scanned product
  files, and 21 benchmark Wrangler configurations with zero production routes.
  After merging R103F's cutover, the direct SDK Yao TypeScript gate passes all
  17 focused files and three managed-product files. The SDK Router, WASM Client,
  wallet lifecycle, and process gate passes 159/159 on a clean detached R120
  snapshot. The local role/process lifecycle matrix, both parser mutation
  smokes, and the constant-time code-generation guard also pass when invoked
  directly against that source state. R103F commits `d805d7ec0`, `9d4df8a65`,
  `a91a5fd8a`, and `affe85e83` fixed the mixed-registration and exhausted-session
  failures. All four R120 Ed25519-Yao contracts, the shared Passkey registration
  contract, the immediate Passkey unlock contract, and the Passkey page-refresh
  contract now pass. The page-refresh contract covers warm EVM signing, budget
  exhaustion, exact-session NEAR, Tempo, and Arc step-up, and both key exports.
  R103F commit `ed02eb9f5` moved the final cold-sync contract onto its exact
  account-sync route. Commit `5a895cf8c` then authorized
  `/router-ab/ed25519/yao/recovery/admit` through the exact Ed25519 operation
  credential while preserving the durable recovery-challenge path. Commit
  `a51c73bb6` carries that exact authorization tuple through recovery execution
  and activation and rejects phase-to-phase provenance changes. Its focused
  recovery tests pass 19/19, and both wallet-server and unit-workspace
  type-checks pass. The local D1 restart fixture now preserves the selected
  challenge-based authorization mode through execute and activation; its
  focused persistence replay contract passes. The
  authoritative empty-browser-storage cold-sync contract passes in 4.7 minutes,
  and the complete eight-contract local-product matrix passes in 5.0 minutes
  after the authorization follow-up.
  The canonical `pnpm validate:yaos-ab-local` producer now clears all thirteen
  checks and emits a v2 receipt bound to the exact 2,870-file input tree. Its
  retired per-profile file handoff was deleted with the R103F serial role routes;
  lifecycle latency and wire evidence remain independently digest-bound and
  validated. The Phase 13A mutation fixtures and all thirteen local preflight
  checks pass against the refreshed bundle. The result remains
  `deployment-required` and `production_eligible: false` because deployed
  evidence is still unavailable. The protocol crate lockfile includes R120's
  Router-core crypto dependencies, and a locked parser-smoke rerun leaves it
  unchanged.
- R103F evidence tip `05e96856f` is an ancestor of R120 merge commit
  `0c6a25f1a`; its non-browser code closure is `97c3dc589`. The cross-platform,
  signing-engine architecture, and
  platform-runtime boundaries pass; the full source-guard chain passes; and the
  source Playwright suite passes 201/201. R120 includes the complete R103F
  integration history through `3e7610789` in merge `0e21234c7`; the selected
  Passkey browser acceptance and focused Google OIDC harness tests remain
  green. Final R103F closure at `0668e5d96` is merged into R120 at
  `977ed053d`; the final staging migration fix `bfaed2877` is merged at
  `308948c15`. Its authoritative intended-behaviour matrix is 47/47 green, and
  backend/frontend staging smoke checks pass.
  On that exact merged tree, the ECDSA/Ed25519 B4-to-B5 tenant-root composition
  suite passes 27/27 and the unit TypeScript typecheck passes. The B4 and B5
  shapes remain unchanged. The post-staging 35-file signer-D1 aggregate is
  `670aeba976269f2142eddcb9524a7b68a4022147eb30f02ecd5e10958aaaf1b8`.
  The cross-account cohort also
  requires a second independently administered
  Cloudflare account/profile and endpoint. Deployed cohorts, per-role CPU,
  sampled memory P999, the 25% finite-limit headroom check, raw artifact
  publication, and the signed selection record remain required. The first
  observation is retained, while cold-isolate incidence is explicitly
  unobservable at the selected platform boundary. Do not start production
  transport integration, stores, or lifecycle activation until those gates
  pass. Pure R120-owned cryptographic primitives may continue under the frozen
  role-target design.
- The Phase 13A preflight evaluator now expects the same thirteen completed
  checks emitted by the Phase 9C producer. Its stale requirement for the
  R103F-deleted managed-product source guard and serial-role lifecycle evidence
  files is removed. The v2 receipt is written only after the authoritative
  product, role/process, parser, and code-generation gates pass; the evaluator
  separately validates the digest-bound two-profile lifecycle report. The
  duplicate checkpoint evaluator is removed, leaving one aggregate lifecycle
  report and one validation receipt.

### Phase 1: add per-tenant root custody

- [x] Add the frozen tenant-root identity, identity digest, custody-lineage ID,
      and positive monotonic share-epoch primitives with strict serde boundaries.
- [x] Add role-local pending, active, and retired share lifecycle state types.
- [x] Add the backup-policy and exhaustive initial-creation state types. The
      pure Rust transition contract admits only
      `empty -> preparing -> verified -> active`, requires either both current
      role-backup receipts or the explicit accepted-loss branch, and separates
      complete from incomplete pre-activation cleanup.
- [x] Add the exhaustive refresh control-plane state types. The pure Rust
      machine keeps the current epoch active through preparation and
      verification, enters forward-only retirement after activation, requires
      both role retirement receipts to return to `active`, and permits retry
      only after complete pending cleanup with a fresh ceremony digest.
- [x] Add the managed role-restore state types. The Rust contract admits only
      one current-epoch unavailable role, binds the role-specific one-use
      capability and restored/peer commitments to the active receipt, blocks
      incomplete cleanup and capability replay, excludes the accepted-loss
      backup policy, and returns to `available` only after a forward refresh
      activates and retires the restored epoch.
- [x] Add the root-retirement and deletion state types. The pure Rust deletion
      machine advances forward through `active`, `fenced`, `destroying`, and
      `deleted`, keeps partial destruction in `destruction_incomplete`, requires
      exact active-epoch drain evidence, and separates permanent provider
      destruction from the explicit `cryptographic_erasure_unverified`
      operational claim.
- [x] Add independent Deriver A and B private stores.
- [x] Add the provider-neutral role-local current-epoch managed-backup contract.
- [x] Add the dormant Cloudflare `operational_rotation_v1` role-local HPKE
      online and managed-backup adapter with distinct key slots, info labels,
      and AAD; keep its roundtrip and provider-separation checks green.
- [ ] Qualify a provider-specific `managed_healing_v1` adapter with
      independently destroyable A/B epoch keys.
- [x] Add role-local distributed tenant-root share generation, commitments,
      transcript-bound knowledge proofs, signed installation evidence, and a
      native/WASM creation vector.
- [x] Add the Started-only creation journal and the issuer-signed,
      object/identity/lineage-bound creation capability.
- [x] Add the deterministic Router Durable Object binding/migration and its
      input-gated single-key journal persistence, including bounded issuer
      verifying-key parsing and exact fresh/expired-replay/unseen-expiry/conflict
      behavior.
- [x] Add the dormant crate-private Router caller with deterministic object,
      capability-authority, response-revision, and response-digest checks.
- [x] Add the issuer-authenticated initial role command and the signed A/B
      creation-commitment rendezvous that gates knowledge proofs and
      installation evidence.
- [x] Add the request-local, non-clone initial role-attempt token. A
      `WaitingForPeer` result stays inside the same bounded request; timeout
      drops and burns the scalar, so retry requires fresh lineage, session, and
      nonce because the public commitment is immutable.
- [x] Add the provider-neutral online role-share sealing binding with its exact
      installation-evidence digest, role commitment, and opaque epoch key
      reference. Provider ciphertext remains opaque to the core.
- [x] Add creation-specific D1 reservation, execution, and success-receipt
      paths that carry the exact verified installation-evidence bytes through
      every stage; add authenticated private Router commitment/evidence RPCs
      with first-unseen freshness and exact durable replay after expiry, using
      atomic Durable Object transactions for each mutation.
- [x] Add the dormant public-evidence-only A/B installation checkpoint:
      strictly verify `VerifiedTenantRootSignedShareInstallationEvidenceWireV1`
      against the retained role-plus-`signing_key_id` set, accept either role
      first, persist exact `OneRoleReady`/
      `BothRolesReady` state, and replay exact evidence.
- [x] Add the strict bundle-derived activation-evidence and signed-receipt
      boundary. It verifies refresh root continuity, exact result revisions,
      source-bound A/B managed-backup artifacts or the dual-authority
      accepted-loss authorization, both provider canaries, and retains the
      exact signed activation bytes for lifecycle and D1 consumption.
- [ ] Orchestrate distributed tenant-root creation through the role runtimes,
      direct external Router-owned Durable Object bindings, the dedicated
      non-blind control-plane issuer Worker, and the control-plane activation
      lifecycle. Every Worker locally verifies signed canonical inputs before
      constructing a process-local verified token.
- [ ] Provision the versioned routine control-plane issuer key only in the
      dedicated issuer Worker; provision the shared public verifier keyset in
      Router and both Derivers; keep both absent from SigningWorker as
      appropriate; delete the Router-prefixed verifier configuration; and
      integrate provider-specific key create/destroy/probe operations for
      production activation. The dormant Cloudflare operational adapter
      remains test-only.
- [x] Orchestrate dedicated tenant recovery resharing from the active shares.
- [x] Add the native role-encrypted recovery packages, externally trusted
      signatures, and signed public recovery manifest.
- [ ] Map each authenticated tenant to one physical root pair.
- [x] Add one server-resolved tenant-root adapter keyed only by authenticated
      deployment configuration; reject Wallet Session, authorization,
      credential, browser, and diagnostics identifiers at that boundary.
- [x] Require current role-backup receipts, or the explicit accepted-loss branch,
      before initial activation.
- [ ] Remove deployment-wide root-share Secret bindings after tenant roots are
      active.
- [x] Keep all root-custody rows out of signer D1 and preserve R103F's final
      schema unchanged.
- [x] Reject caller-selected tenants, roots, roles, and epochs. The shared
      TypeScript boundary rejects these fields both statically and at runtime;
      both B4/B5 composition paths fail before consulting B5 material.

Phase 1 pure lifecycle evidence on 2026-08-31:

- `cargo test --offline --manifest-path crates/router-ab-core/Cargo.toml
--test tenant_root_lifecycle` passes twenty-eight focused creation, refresh,
  custody-binding, managed one-role restore, and irreversible deletion tests.
- `cargo test --offline --manifest-path crates/router-ab-core/Cargo.toml
--all-targets` passes the complete core crate matrix.
- `cargo clippy --offline --manifest-path crates/router-ab-core/Cargo.toml
--all-targets -- -A clippy::too-many-arguments -A
clippy::needless-borrow -D warnings` passes. The two allowed lints are
  pre-existing R103F protocol/test findings; the new lifecycle module is clean
  under the remaining warning set.
- On 2026-09-01, the dormant creation boundary persists only the canonical
  Started journal,
  rebuilds `preparing`, and accepts a capability signed by a bounded issuer
  verifying-key set. The capability binds the journal digest, identity,
  custody lineage, expected revision, deterministic Durable Object authority,
  nonce, issuer key ID, and freshness window. The Router creation object uses
  the identity/lineage-derived object name and migration, validates the
  internal journal-plus-capability request before its single-key
  `creation/v1/journal` get/put, and applies exact replay semantics: a fresh
  first acceptance commits, an exact persisted record replays after expiry,
  unseen expiry returns `ExpiredLocalRequest`, and changed input returns
  `ConflictingPair`. The crate-private Router caller independently derives the
  object, checks the capability authority before dispatch, and validates the
  exact response revision and digests. Authenticated private commitment and
  evidence RPCs use bounded JSON and private service authentication. Their
  journal, rendezvous, and checkpoint get/evaluate/put paths each run in one
  atomic Durable Object transaction. The same Durable Object now persists exact
  role-signed creation commitments as `OneRoleCommitted` or
  `BothRolesCommitted`; the complete verified pair gates all installation
  evidence and its exact own/peer commitments. The public-evidence-only A/B
  checkpoint accepts `VerifiedTenantRootSignedShareInstallationEvidenceWireV1`,
  accepts either role first, persists `OneRoleReady`/`BothRolesReady` under
  `TENANT_ROOT_CREATION_INSTALLATION_CHECKPOINT_STORAGE_KEY_V1`, and replays
  exact evidence without activation. First-unseen commitment or evidence
  requires a fresh bounded command; the exact durable record replays after
  expiry. The focused command
  `cargo test --offline --manifest-path crates/router-ab-cloudflare/Cargo.toml
  --lib tenant_root_creation -- --nocapture` passes 17/17
  (`durable_object::tenant_root_creation::tests::*`, including
  `role_key_set_retains_exact_role_and_key_id_across_rotation`), and
  `cargo test --offline --manifest-path crates/router-ab-core/Cargo.toml --test
  tenant_root_installation_evidence_wire -- --nocapture` passes 7/7. Capability
  freshness is checked only for the first `Started`-journal acceptance.
  Installation progress then validates
  `TenantRootCeremonyContextV1::validate_at` through
  `require_fresh_installation_context` for unseen first/peer evidence, while
  exact persisted retries remain replayable after expiry. The broader Phase 1
  evidence remains 5/5 for the core journal and 5/5 for the core capability.
  No public route or role-runtime creation handler invokes this path. Exact
  role-plus-`signing_key_id` retention is implemented through
  `TenantRootCreationRoleVerifyingKeysV1`,
  `decode_role_verifying_keys`, and
  `ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON_ENV`; production
  role-key provisioning/configuration and deployment rotation rollout remain
  open, and no activation or cutover consumes it.
- The initial role attempt is request-local and non-cloneable: a
  `WaitingForPeer` result stays inside the same bounded request, and timeout
  drops the sampled scalar so it is burned. Because its public commitment is
  immutable, a timed-out retry requires fresh lineage, session, and nonce.
  The two-role in-process flow keeps both nonpersistable attempts live through
  exact A/B pair replay, each `finalize`, runtime `compose`, and provider
  reopen; the five focused `tenant_root_initial_role_attempt` tests pass. The
  provider-neutral online role-share sealing binding carries the exact
  installation-evidence digest, role commitment, and opaque epoch key
  reference; its two focused `tenant_root_online_sealing` tests pass.
  The runtime re-verifies exact installation evidence against the configured
  signer before either provider call, and the same-ID/different-key adversarial
  test leaves both providers untouched.
- The dormant Deriver A/B private-D1 prototype now enforces epoch-one initial
  activation, exact-revision pending cleanup, idempotent identical pending
  installation, and an atomic exact-next-epoch active swap. Startup accepts a
  matching HPKE KEK pair and fails closed on a mismatched public/private pair
  before any ciphertext is written. The real `workerd` integration now invokes
  the production Rust store methods rather than copied SQL. It covers exact
  pending retry, conflicting-share rejection, epoch-one activation, missing
  successor and stale-CAS rejection, atomic retirement/activation, exact
  cleanup, encrypted load, and role rejection. Deriver A and B use the same
  logical tenant identity and custody lineage while producing independently
  encrypted outer ciphertexts. The integration endpoint is available only in
  an explicitly enabled debug build; a release Worker build proves it is
  absent. The checklist item remains open until the role-local current-epoch
  backup persistence integration, independently destroyable epoch-key provider,
  and runtime orchestration are implemented.
- The provider-neutral managed-backup contract is now frozen in
  `tenant_root_managed_backup.rs`. A role-local provider receives a secret share
  only through a request that first proves the share matches the exact role
  commitment. Its authenticated data binds identity, custody lineage, role,
  epoch, commitment, installation receipt, backup-key version, role signing-key
  ID, and creation time. The resulting ciphertext digest is role-signed, and a
  provider-opened share is accepted only after reproducing the bound commitment.
  Three focused tests pin the AAD, ciphertext, and signed lifecycle-receipt
  digests and reject role, identity, epoch, signature, empty-ciphertext, and
  restored-share substitution. The dormant Cloudflare
  `operational_rotation_v1` adapter supplies role-local HPKE
  X25519/HKDF-SHA256/ChaCha20Poly1305 online and managed-backup
  encrypt/decrypt with distinct online/backup keys, info labels, and AAD;
  roundtrip, wrong-provider, and reused-key checks pass. Env/Wrangler
  provisioning, persistence integration, destruction probes, the
  `managed_healing_v1` adapter, provider qualification, live route, activation,
  and cutover remain open.
- The dormant activation-evidence bundle now verifies the public A/B refresh
  evidence through `verify_tenant_root_refresh_evidence_v1`, then binds exact
  installation, availability, and ECDSA/Ed25519 provider-canary artifacts into
  `TenantRootSignedActivationReceiptV1`. Refresh receipts require result
  revision `expected + 1`; initial creation is fixed at revisions 2 -> 3.
  Verification retains exact canonical signed receipt bytes and their digest.
  The availability union accepts either distinct-provider A/B managed backups
  or a consuming, dual-authority accepted-loss authorization bound to the exact
  context, root commitments, installation receipts, revisions, and one-use
  scope. These local contracts remain dormant until production role handlers,
  provider adapters, and activation orchestration are wired.
- The role-private D1 activation API accepts either a signature-verified,
  source-bound current-role backup artifact or a typed accepted-permanent-loss
  authorization from the strict availability union. Current-backup activation
  checks exact tenant, lineage, role, epoch, provider/key, and commitment
  binding before transition; accepted-loss activation checks the exact
  dual-authority bytes and scope. Both branches retain the exact activation
  receipt bytes and derived digest in the encrypted active record.
  Creation-specific reservation, execution, and success terminalization carry
  the exact verified installation-evidence bytes through every stage; the
  five initial-creation tests are included in the 29-test `workers-rs`
  role-private D1 suite. The suite also covers forward-only lifecycle,
  out-of-order evidence, backup-binding substitution, active-pair resolution,
  and typed-command payload checks. The dormant B4/B5 identity adapter derives
  its active-material types from the exact R103F resolver surface. The
  aggregate identity/composition suite remains at 27 focused behavioral
  checks, plus the authoritative unit-workspace type-check; live route wiring
  remains open.
- The shared server-resolved identity boundary and both ECDSA and Ed25519 B4/B5
  composition boundaries reject runtime JavaScript objects carrying any
  caller-selected tenant, root, role, epoch, Wallet Session, authorization,
  credential, browser, request, or diagnostics selector. The 27-test focused
  suite proves the rejection occurs before a B5 resolver call, while the
  existing type fixtures reject the same fields statically.
- Cross-lineage replay now has explicit local evidence at three independent
  layers: an active refresh rejects a next ceremony from another lineage, a
  managed restore capability from another lineage cannot enter installation,
  and a valid signed managed-backup artifact cannot verify against another
  lineage's AAD. The complete 28-test lifecycle suite and three-test managed
  backup suite pass.

- The dormant domain/store slice proves the intended resolution contract for
  one authenticated tenant and one active Deriver A/B physical root pair.
  Each role-private store answers only for itself, so the two halves meet once,
  in `resolve_active_tenant_root_pair_binding_v1`. An active role row now
  carries the public share commitment stored beside it
  (`TenantRootActiveRoleBindingV1`), and construction pins that commitment's
  embedded threshold share id to the row's own role, so a pair can never be
  assembled from one role's coordinates and another role's commitment. The pair
  itself is built through the existing `TenantRootEpochCommitmentsV1`, so the
  joined public root commitment is the pair's stable identity and a commitment
  that joins no pair is rejected rather than repaired. The resolution is
  exhaustive over unprovisioned, active, partial pair, per-role ambiguity
  (distinct lineages and duplicate rows in one lineage, including identical
  rows), custody-lineage mismatch, epoch mismatch, and commitment mismatch;
  nothing selects a winner. At the Cloudflare boundary
  `cloudflare_require_active_tenant_root_pair_v1` fails closed on every unsafe
  state, while `cloudflare_resolve_active_tenant_root_pair_v1` lets
  reconciliation observe it without deriving from it. Pair resolution consumes
  only each role's public half, so no Deriver receives its peer's opened record.
  The active-binding suite has 23 tests, the tenant-root lifecycle suite has 28,
  and the focused role-private D1 suite has 29 `workers-rs` tests. The
  authority-derived custody binding takes identity, custody lineage, epoch,
  role, and the public share commitment from the validated role-private record;
  activation matches the verified managed-backup receipt binding field-for-field
  before storing the active record. All four dormant D1 mutations—inserting a
  pending share, initial activation, active-epoch swap, and pending cleanup—now
  require branch-specific durably reserved typed commands. Their exact
  canonical non-secret payload and core scope digests jointly bind identity,
  custody lineage, role, epoch, control-plane revision, session, nonce, local
  revisions, lifecycle evidence, and timestamps; accepted-loss construction and
  mutation, reservation, and terminal APIs are crate-fenced. Exact retries
  ignore a new arrival timestamp and replay the durable terminal receipt. The
  role-local D1 mutation and its executed checkpoint run in one atomic batch,
  so this local path is crash-resumable: persisted `reserved` or `executed` rows
  reconstruct the exact local resume token after a crash. Both Deriver replay
  migrations explicitly require
  `IS NULL` or `IS NOT NULL` for each nullable lifecycle column, and the row
  parser applies the same exhaustive shape check before resuming a command. The
  private authority-bearing role-D1 wire boundary keeps branch-specific command
  fields and mutation APIs inside the adapter; identity, custody lineage, role,
  epoch, control-plane revision, session, nonce, operation, and payload digest
  come from the server-issued scope rather than the caller. The dormant refresh
  Durable Object now persists authoritative public active state and exact
  commitment/installation checkpoints with replay and fence semantics; Router/
  global control-plane issuer and current-revision authentication, two-role
  runtime orchestration, and transition-level crash injection remain open, and
  there is no production caller. The refreshed boundary inventory is recorded at
  `docs/evidence/r120-boundary-inventory-v1.json`.

### Phase 2: implement ECDSA transparent refresh

- [x] Add the independent `StableTenantDerivationContextV2` cryptographic
      boundary and prove byte equality with the existing ECDSA stable-key
      context.
- [x] Prove refreshed 2-of-2 shares reproduce identical `x_client_base`,
      `x_server_base`, and `y_server` outputs in native Rust and WASM.
- [ ] Switch the existing production threshold-PRF adapter from its
      ceremony-bound input to `StableTenantDerivationContextV2` after the R103F
      shared-boundary gate.
- [ ] Remove `RootShareEpoch` from threshold-PRF input bytes.
- [x] Introduce `TenantRootShareEpoch` only in tenant-root custody and lifecycle
      bindings and preserve existing durable `RootShareEpoch` values. The
      stable context contains neither epoch type; the epoch-bound
      `TenantRootCustodyBindingV1` is built only from the active lifecycle
      state and freezes its exact canonical digest.
- [x] Add the contributory two-party zero-share refresh algebra and its exact
      source/recipient-bound commitment and secret-contribution wires.
- [x] Add public root-continuity commitments and transcript-bound role-share
      knowledge-proof primitives.
- [x] Bind the refresh and knowledge-proof primitives to exact role-signed
      commitment, recipient-encrypted contribution, and role-signed
      installation-evidence messages covering the operation, tenant identity,
      custody lineage, epochs, session, nonce, expiry, roles, commitments, and
      role key IDs.
- [x] Add the role-local one-use replay store and encrypted wire boundary
      parser for the exact cryptographic messages, with reserved/executed
      checkpoints and signed terminal receipts.
- [x] Add the pure two-role commitment barrier required before either encrypted
      refresh contribution can be constructed.
- [x] Add the dormant refresh Durable Object authoritative public-state,
      commitment-checkpoint, and installation-checkpoint paths with exact
      replay, fence, and atomic-transaction semantics; the checkpoint slice
      has no activation consumer.
- [ ] Add live two-role runtime orchestration and abort/restart coordination
      around those persisted messages.
- [x] Implement and test the dormant stable-root identity adapter against the
      final B4/B5 material resolver without decoding `MpcMaterialActivationRef`
      or reconstructing either identity from the other. Live route wiring
      remains behind the signed Phase 0 and shared-production integration gate.
- [x] Add cryptographic mixed-epoch, replay-session, role, recipient-key,
      coefficient-commitment, peer-commitment, signature, root, and restart
      substitution vectors.
- [ ] Add lifecycle abort and crash-restart vectors at every persisted message
      transition.

Phase 2 pure crash-recovery evidence on 2026-08-31:

- The exhaustive creation and refresh unions now project one identity-,
  lineage-, and revision-bound recovery plan from every lifecycle branch.
  Preparing and verified pre-activation states can only abort the pending
  epoch; incomplete cleanup can only resume cleanup; a committed activation
  can only resume forward retirement. No recovery action can reactivate the
  previous epoch.
- Focused vectors cover all six creation states and all six refresh states. The
  role-local replay store and its atomic mutation-plus-executed-checkpoint path
  are locally covered. The dormant refresh Durable Object now persists the
  verified activation's authoritative public active state, then exact A/B
  commitment and installation checkpoints with replay/fence semantics; it
  deliberately stops before activation. Live two-role runtime orchestration,
  abort/restart coordination, and transition-level fault injection across the
  production path remain open.
- The dormant `MpcPrfStablePurposeBindingPlanV2` accepts the typed stable context
  together with an independently authenticated custody binding. Its threshold-
  PRF bytes are exactly `StableTenantDerivationContextV2::canonical_context_bytes()`;
  epoch-bound custody data contributes only to the separate custody-binding
  digest. The dormant V2 backend now evaluates real A/B partials over those
  stable bytes while binding each DLEQ challenge to the custody digest through
  a separate fixed-width proof input. Focused tests prove identical combined
  output across a share-epoch refresh, different custody-bound proofs, and
  failure after either metadata-only or proof-level custody substitution. The
  complete threshold-PRF test and committed-vector matrix remains green, so V1
  proof transcripts and outputs did not drift. `MpcPrfStableThresholdSignerInputV2`
  is now linear and constructible only from one fresh custody binding, its exact
  authoritative active A/B pair, the matching role, and an opened share whose
  derived commitment equals that role's active commitment. Substituted shares,
  stale bindings, changed activation receipts, foreign pairs, and role mismatch
  fail closed. The focused backend and lifecycle suites pass 17/17 and 33/33.
  Production request, payload, proof, and runtime wires are unchanged.
- `cargo test --manifest-path crates/router-ab-core/Cargo.toml --all-targets`
  and the full `router-ab-cloudflare` `workers-rs` test matrix pass after this
  addition. The threshold-PRF production library and router-ab-core also pass
  their warning-clean Clippy profiles.
- Refresh commitment messages now have one strict canonical signed wire with
  exact context, source role, signing-key ID, signature, canonical-byte
  retention, and wire digest. Malformed, non-canonical, context-, role-, key-,
  and signature-substituted messages fail closed; the focused transport suite
  passes 9/9 tests. Refresh contribution AAD can be constructed only from a
  verified A+B commitment pair for one exact ceremony. Fixed `deriver_a_to_b` and
  `deriver_b_to_a` builders replace the single-source constructor, so neither
  role can seal a contribution after verifying only its own commitment. The
  focused transport suite includes plaintext
  role/AAD binding, wrong-role and
  mixed-ceremony barrier rejection, strict encrypted/signed wire round trips,
  malformed-wire rejection, and authentication-role substitution. The signed
  A-to-B wire digest is frozen as
  `f8333d288e2a89d2a94a67e7dedef765415312f7561dc9bca1a4935141f4f3d7`, and the
  native/WASM outer-protocol vector remains green. The dormant refresh Durable
  Object checkpoint path now stores authoritative public state and exact
  commitment/installation evidence with replay and fence semantics, while
  two-role runtime orchestration and the crash/restart coordinator remain open.
- The issuer-signed `TenantRootRoleRefreshCommandV1` strictly binds the exact
  active A/B commitments and root, current activation receipt, refresh context,
  role, current and next epochs, dynamic control-plane revision, authority,
  issuer, and validity window. Its verified token is non-cloneable and its
  focused command suite passes 5/5 tests.
- `PendingTenantRootRefreshRoleAttemptV1` owns the opened current share,
  refresh coefficient, and role signing key as one request-local linear value.
  Finalization requires the exact verified A/B commitment pair, predicts the
  next public pair, proves the next local share, and emits exact signed
  installation evidence. The focused attempt suite passes 4/4 tests. The
  threshold public derivation rejects identity, zero, cancellation, and
  collapsed equal-role commitment pairs; its refresh suite passes 8/8 tests
  and the formal anti-drift suite passes 3/3.
- The role-private D1 refresh insertion path now consumes the exact verified
  refresh command and installation evidence through branch-specific linear
  commands. Its replay digest commits to both the exact signed command digest
  and exact public insert-row payload, so reissuing authority, active-pair,
  issuer, signature, or validity fields cannot resume an earlier operation.
  The role-store slice passes 35/35 focused tests, the full `workers-rs`
  library passes 106 tests, and the no-feature library passes 33 tests. This
  path remains dormant until the live refresh checkpoint coordinator, provider-
  backed role runtime, and activation caller are complete.
- The pure one-use command contract now distinguishes `execute`, `in_progress`,
  `replay_completed`, and `replay_failed` without making a terminal-to-running
  transition representable. Its role-local storage key binds the server-resolved
  identity, custody lineage, session, and role while retaining the nonce inside
  the authenticated record, so a same-session nonce or payload substitution
  reaches the existing row and fails with `ReplayMismatch`. Nine focused core
  command-replay tests, the full core matrix, and warning-clean Clippy pass;
  the frozen storage-key digest is
  `933a0980c47235dbb05eccd1d5f9974180c7de313bb6b71898f685b1f67c9037`.
  Deriver A and B now each have a role-constrained private-D1 replay table and a
  primary-consistent adapter that persists `reserved`, `executed`, `completed`,
  or `failed` as one forward-only row. A terminal row retains the exact signed
  public receipt bytes plus their recomputed digest; identical lost-response
  retries return
  those bytes, while nonce, payload, role, or terminal-kind substitution fails
  closed. The real `workerd` integration exercises successful and failed replay
  through both Deriver builds. On 2026-09-01, the focused signed-terminal-receipt
  suite passes 8/8 tests, the role-private D1 unit slice passes 29/29 tests, the full
  Cloudflare `workers-rs` library suite passes 100/100 tests, and `tests/bindings.rs`
  passes 225 tests. The dormant refresh Durable Object checkpoint path is
  implemented; two-role runtime orchestration and transition-level crash
  injection remain open.

### Phase 3: replace the Ed25519 derivation profile

- [x] Add fixed A-target and B-target `PrfPurpose` variants with `Raw32` output;
      accept no purpose string or target selector from a request.
- [x] Separate generic threshold-PRF DLEQ verification from the current
      ECDSA-only public-purpose adapter and preserve the ECDSA wire contract.
- [x] Add exact source/target inner protocol types: B may send only an A-target
      bundle to A, and A may send only a B-target bundle to B. Make the reverse
      directions and mixed payload combinations unrepresentable.
- [x] Bind the stable PRF context separately from the epoch-bound custody,
      recipient, session, nonce, expiry, and replay transcript.
- [x] Combine each output only inside its target Deriver, convert it through a
      role-specific zeroizing capability, and run the existing contribution KDF
      locally without persistent output caching.
- [x] Preserve current Yao role inputs, recipient package outputs, circuit
      manifest, digest, schedule, schemas, table bytes, and circuit-cache
      identity exactly.
- [ ] Version the outer Ed25519 derivation protocol, pair-session identity,
      proof-bundle payloads, generated server bindings, and vectors.
- [x] Add native/WASM frozen-vector and executable algebra evidence for purpose
      separation, fixed direction, exact 2-of-2 combine, refresh invariance, and
      unchanged Yao artifacts.
- [x] Prove the minimal refresh-continuity theorem modulo the exact Ristretto
      scalar order and bind its A=`1`, B=`2` formulas to production Rust with an
      anti-drift test. Generic t-of-N reconstruction remains a separate abstract
      proof surface.
- [ ] Enforce arbitrary-context denial at the server-resolved outer protocol
      boundary after the R103F integration gate; the generic threshold primitive
      intentionally accepts already-validated context bytes.
- [ ] Regenerate only changed Router A/B server bindings from R103F's final
      shared types; prove V6 browser, WASM/SDK, and host/iframe shapes unchanged.
- [ ] Delete the deployment-share-hash Ed25519 root adapter when the
      role-targeted profile activates.

Cryptographic Rust/WASM execution status on 2026-08-31:

- `threshold-prf` now owns exact 2-of-2 contributory refresh, public root
  continuity, role-local distributed root creation, transcript-bound
  share-knowledge proofs, fixed role-target purposes, directional inner proof
  bundles, and distinct zeroizing A-target and B-target output capabilities.
- The Cloudflare benchmark delegates DLEQ verification and exact 2-of-2 combine
  to that production-shaped core. Its 342-byte encrypted envelope and existing
  role-local contribution KDF outputs remain pinned by the benchmark tests.
- `threshold-prf-wasm-bench` exports distributed-creation,
  refresh/continuity/knowledge-proof, ECDSA refresh-invariance, and Ed25519
  role-target checks against frozen expected share and PRF output bytes. It also
  exercises the exact signed
  commit-before-contribution stage, bidirectional HPKE contribution exchange,
  signed installation proofs, and public-root continuity. These compile for
  `wasm32-unknown-unknown` and introduce no SDK, browser, wallet-custody, or
  R103F-owned generated shape.
- `router-ab-core` owns canonical tenant-root creation/refresh transcripts,
  exact role-signed coefficient commitments, verified commit-stage
  capabilities, fixed X25519/HKDF-SHA-256/AES-256-GCM contribution envelopes,
  and role-signed installation evidence. Strict canonical decoders now reject
  truncated, trailing, oversized, non-canonical, role-substituted, and malformed
  encrypted contribution wires before verification. Role-local command replay
  persistence now includes execution checkpoints and signed terminal receipts;
  pair-session replay, commit-barrier runtime state, transport orchestration,
  and activation remain later lifecycle work.
- `router-ab-core` now also owns the tenant-controlled recovery cryptographic
  path. A recovery context can be built only from the authoritative active
  lifecycle state and substitutes one random recovery-set ID plus the two
  recovery-recipient fingerprints for an operational next epoch. Each role
  commits a fresh nonzero coefficient, sends only its peer-targeted contribution
  through a role-signed X25519/HKDF-SHA-256/AES-256-GCM envelope, derives only
  its local recovery share, and signs a transcript-bound knowledge proof. The
  verified public pair must change both commitments while preserving the stable
  root before either role receives an opaque packageable capability.
- Recovery package sealing no longer accepts a role selector or raw
  `SigningRootShareWire`. It accepts only the role-local
  `VerifiedTenantRootRecoveryShareV1` produced by that ceremony and rechecks its
  identity, lineage, recovery set, recipient fingerprint, root commitment,
  share commitment, and signing-key ID against the descriptor. Canonical
  descriptors, separate A/B HPKE packages, externally rooted role and
  control-plane signatures, recipient-key proof of control, verified one-role
  package opening, and the destination-bound `SEAMSRI1` import envelope remain
  exact. The strict artifact parsers are the only public deserialization
  boundary.
- Recipient proof of control reuses the exact enrolled recovery-recipient key
  type. Destination import keys remain a separate type because they are
  short-lived, role-local restore capabilities. The native import path requires
  a manifest-verified source share and an exact destination expectation created
  before decryption; decoded envelope metadata cannot authorize itself. It never
  combines the A and B shares.
- Creation and refresh finalization accept only role-signature-verified
  installation evidence. Every X25519 public or encapsulated key rejects zero,
  high-bit, modulus, and reduced field-element aliases before HPKE decoding.
  Production sealing APIs consume caller-supplied cryptographic RNGs, and local
  Ed25519 signing keys use zeroization-enabled storage.
- The Node WASM harness now invokes all five R120 self-check exports immediately
  after loading the generated module. The post-audit optimized run measured
  187.424 microseconds for 2-of-3 evaluation/combine, 280.754 microseconds for
  3-of-5 evaluation/combine, 177.670 microseconds for DLEQ proving, 178.104
  microseconds for DLEQ verification, and 676.053 microseconds for verified
  3-of-5 combine. These figures cover local cryptography rather than Worker
  transport.
- The Verus model proves the minimal R120 continuity theorem modulo the exact
  Ristretto scalar order. Production anti-drift tests freeze the scalar modulus,
  A=`1` and B=`2` role weights, both-source contribution inclusion, refreshed
  share bytes, wire widths, and no-op/zero-next rejection. Generic t-of-N
  reconstruction remains a separate abstract trusted seam. The pinned Verus
  run passes all 29 proof obligations with zero errors.
- Full `threshold-prf`, `router-ab-core`, and Cloudflare benchmark tests pass.
  `cargo yao-fv anti-drift` passes all six production/generator comparisons.
  The broader `cargo yao-fv all` run passed its reference, vector,
  cross-language, artifact, reconciliation, and signed-record readiness stages,
  then stopped at the review-subject governance step because that step requires
  a clean checkout.
- The dedicated recovery vector starts from operational A=`12`, B=`19`, uses
  role contributions rho-A=`7` and rho-B=`11`, and freezes recovery A=`30`,
  B=`55`; both role commitments change while `2*A - B = 5` remains exact. The
  recovery context digest is
  `fdc7deffdc60f3ebee3796ab40a21bb8d9aedb3caeb0df1118a9c5665ac5f7d6`.
  Focused reshare, package, manifest, and restore-import tests pass, the complete
  `router-ab-core --all-targets` matrix passes, and the crate compiles for
  `wasm32-unknown-unknown`.
- The existing repository constant-time qualification passes at O0 and O3.
  Focused optimized ARM64 assembly for this tranche contains no division in the
  threshold refresh core. Router division instructions occur only in public JSON
  sorting and numeric parsing. Manual data-flow review found no division,
  early-exit secret comparison, or secret-indexed lookup on the valid recovery,
  proof, refresh, or import paths. The standalone analyzer could not compile the
  Cargo modules in this environment because its selected
  `aarch64-unknown-linux-gnu` standard library is not installed; the Cargo-built
  optimized assembly is the recorded fallback evidence. The new recovery
  reshare path adds no division at optimized ARM64. Its sole O0 `udiv` is Rust's
  slice `from_raw_parts` debug precondition over public length and alignment;
  secret IKM and secret-derived share comparisons use constant-time equality.

Server integration status on 2026-08-31:

- The R120 tenant-root identity adapter consumes only the narrow successful B5
  Ed25519 or ECDSA material projection. It verifies the top-level and nested
  `MpcMaterialActivationRef`, compares the established signing-root ID and
  version with the authenticated runtime-policy scope, and emits the exact
  five-field `TenantRootIdentityV1` shape shared with Rust.
- The adapter input has no wallet, root, epoch, role, Wallet Session,
  authorization, credential, browser, request-body, or diagnostics selector.
  Negative type fixtures reject those fields and a curve/result mismatch.
  Focused behavioral tests cover both curves plus activation, root-ID, and
  root-version substitution; all nine pass.
- The dormant ECDSA composition boundary now accepts only a successful B4
  Wallet Session operation admission. It derives the wallet and exact material
  activation selectors from that admission, resolves B5 once, verifies the B5
  activation, wallet, threshold public key, signing-root ID, and signing-root
  version, and returns the unchanged admission plus the full B5 material and
  five-field tenant-root identity. It has no live route importer and returns no
  R120 share epoch. Nine focused behavioral tests and the canonical unit/type
  fixture compilation pass.
- The matching dormant Ed25519 composition boundary accepts only an exact B4
  Ed25519 export admission. It resolves B5 once, verifies the top-level
  activation, both wallet bindings, the registered public key, signing-root ID,
  and signing-root version, and returns the unchanged admission plus the full
  B5 material and five-field tenant-root identity. Nine focused behavioral
  tests and the negative type fixture pass. Neither family composition has a
  live route importer, public caller, production lifecycle configuration, or
  cutover consumes either boundary, and neither returns an R120 share epoch.
- Separate Deriver A and B migrations contain the encrypted role-share rows;
  the R103F signer-D1 tree remains byte-identical to the executable 35-file
  aggregate digest
  `670aeba976269f2142eddcb9524a7b68a4022147eb30f02ecd5e10958aaaf1b8`.
  Role lifecycle transitions retain installation, exhaustive availability,
  signed activation, and signed retirement evidence inside the role-encrypted
  record. Focused Rust tests and the real `workerd` D1 suite pass.

### Phase 4: add lifecycle and operations

- [x] Add the exhaustive current/next control-plane state.
- [x] Add the pure deployment-cutover state machine with attempt-bound receipts,
      a validated revision manifest, distinct post-activation canaries, bounded
      timestamps, collision-free rollback revisions, and forward-only recovery
      actions.
- [x] Add strict provider-canary and activation-evidence receipts, including
      exact A/B/root commitments, source-bound availability, and exact signed
      bytes; add the dormant refresh Durable Object public-state and
      commitment/installation checkpoint fence.
- [ ] Add live per-tenant locks, fences, activation, and redacted production
      receipts.
- [ ] Add fresh online and backup epoch key versions and verified retirement.
- [x] Add one-role restore with commitment verification and mandatory forward
      refresh.
- [x] Keep managed availability restore and tenant recovery restore in distinct
      exhaustive protocol branches.
- [ ] Inject failure before and after every role install and activation step.
- [ ] Prove normal signing remains available.
- [ ] Add operator-triggered refresh before scheduled refresh.

Phase 4 pure cutover evidence on 2026-08-31:

- The Cloudflare control-plane boundary owns `TenantRootRevisionManifestV1` and
  `TenantRootCutoverStateV1`; deployment identities and D1 migration heads do
  not enter the cryptographic core. One random nonzero
  `TenantRootCutoverAttemptIdV1` is carried through the complete state and must
  bind every runtime-verified receipt. Fence, drain, revision verification,
  profile activation, rollback, and unfence receipts are branch-specific Rust
  types, so a receipt from one stage cannot be substituted at another stage.
  The exhaustive cutover state advances
  through `open`, `fenced`, `drained`, `revisions_verified`,
  `profile_activated`, `profile_committed`, `ready_to_unfence`, and `complete`.
  A signed rollback is representable through `profile_activated`. Admitting the
  first R120-profile derivation creates `profile_committed`, whose API exposes
  only forward completion of the other curve and then unfencing.
- Eight focused manifest and cutover tests reject mixed release commits,
  protocol/artifact sets, role slots, deployment identities, storage shapes,
  duplicate receipts, repeated curve canaries, and timestamp replay. The full
  Cloudflare `workers-rs --all-targets` matrix and warning-clean Clippy pass
  under the repository's explicit existing lint exceptions. The dormant refresh
  Durable Object persists authoritative public state and exact
  commitment/installation checkpoints with replay/fence semantics; live fences,
  participant readback, production activation, and deployed fault injection
  remain open. The canonical manifest digest is frozen at
  `3042742aca6b9f308591d79c8bed255c56dbf9be76026731038162c03e399753`.

### Current green evidence (2026-09-02)

- The `router-ab-core --all-targets` suite is green. The exact refresh
  transition derives the next pair as the authoritative active pair plus the
  accepted A/B coefficients, re-verifies the stored `BothRoles` installation
  evidence, and rejects root-preserving and coefficient-as-share substitutions.
  Core refresh-checkpoint evidence is 5/5, the independent audit is clean, and
  the activation-receipt suite passes 12/12.
- Cloudflare feature and no-feature checks and all-targets are green: the
  `workers-rs` library passes 129 tests, `tests/bindings.rs` passes 225 tests,
  and all integration targets pass. The Durable Object refresh checkpoint
  suite passes 21/21.
- The dormant A/B role-signing boundary passes 2/2, and the TypeScript unit
  typecheck is green.
- The regenerated boundary inventory records 932 files and 17,451 hits with
  34 generated artifacts; its generated-artifact digest is
  `f681b31eefbbc145b965523d81a960539eb9e59c3e116fa8897f35cf8fdc8ee4`.

These are local development results. Phase 0 remains gated because there is no
deployed signed architecture-selection record or deployed benchmark evidence;
no public activation route or production activation caller consumes the dormant
paths. Env/Wrangler provisioning, role-private persistence integration,
destruction probes, `managed_healing_v1`, provider qualification, live
orchestration, physical tenant mapping, cutover, drills, and production
role-key provisioning remain open.

### Phase 5: release the client-transparent path

- [ ] Confirm R103F R5 completion, zero legacy counters, exact-only serving
      Wallet Session revisions, and the final SDK/iframe baseline.
- [ ] Inventory every credential-free committed registration receipt as an
      existing identity; drain or retire unfinished registration and recovery
      states so a delayed replay cannot make retired-profile material active or
      usable.
- [ ] Fence new derivation ceremonies while preserving normal signing, wait for
      every pre-cutover derivation session to reach a terminal state, deploy
      every participating R120 revision, verify the revision manifest and both
      curve canaries, then resume derivation.
- [ ] Prove every old/new R120 revision mismatch fails closed and that rollback
      is allowed only before the first new-profile derivation; later recovery
      rolls forward.
- [ ] Run refresh against tenants with Ed25519 and ECDSA wallets.
- [ ] Prove no wallet enumeration or client mutation occurs.
- [ ] Run multi-tenant concurrency, quota, and isolation tests.
- [ ] Run role-compromise, cleanup, refresh, and rollback drills.
- [ ] Run role-loss, backup restore, forward refresh, and old-backup destruction
      drills independently for A and B.
- [ ] Enable a conservative jittered schedule.
- [ ] Publish exact security claims and recovery limitations.

### Phase 6: final cleanup and closure

Phase 6 is mandatory. Phase 5 proves that the selected R120 profile works;
Phase 6 proves that the repository and deployed system contain only that
profile. No compatibility alias, dual parser, dormant production branch,
obsolete fixture, retired Secret, or unowned cloud resource may remain.

Cleanup begins only after the first R120-profile derivation has committed and
the cutover has become forward-only. Before that point, cleanup must preserve
the exact Phase 5 rollback release. After that point, the prior derivation
profile is not a recovery mechanism and must be removed rather than hidden
behind a flag.

#### Entry gate

- [ ] Accept the signed Phase 0 architecture-selection record and deployed
      benchmark evidence.
- [ ] Give every Phase 1-4 creation, refresh, restore, deletion, activation, and
      signing path a live production consumer.
- [ ] Complete the Phase 5 fenced cutover, both curve canaries, and one exact
      B4/B5 derivation per curve.
- [ ] Persist the first R120-profile derivation receipt, closing rollback to the
      prior profile.
- [ ] Drive every admitted pre-cutover operation to a terminal state or a
      verified cleanup receipt.
- [ ] Sign and archive the active-tenant inventory, role-private migration
      heads, provider-key inventory, deployment revision manifest, and the
      pre-cleanup source/binding inventory.

#### Canonical cleanup manifest

Extend `docs/evidence/r120-boundary-inventory-v1.json` into the canonical
cleanup manifest. Every R120-related source, generated artifact, configuration
value, deployed resource, persisted record class, test, and document receives
exactly one disposition:

| Disposition | Meaning | Closure evidence |
| --- | --- | --- |
| `delete` | Prior-profile, intermediate, duplicated, or one-time code/data/resource | Zero runtime hits and green operating-path tests without it |
| `rename_without_alias` | Valid behavior with an obsolete ownership or semantic name | New name exists; old name and aliases have zero hits |
| `activate` | Required implementation that remains dormant, test-only, or unreachable | A production caller exercises it and dead-code suppression is gone |
| `retain_durable` | Required persisted state or immutable applied migration | Named reader, lifecycle, retention rule, and reason |
| `retain_evidence` | Immutable benchmark, vector, proof, audit, or release evidence | Recorded digest and verifier; never accepted as a runtime compatibility input |

- [ ] Record each row's exact path/symbol or resource ID, owner, phase, final
      disposition, replacement or retained reader, and closure command.
- [ ] Fail Phase 6 on any unexplained inventory hit.
- [ ] Fail Phase 6 when a `delete` or `rename_without_alias` item has a remaining
      runtime, generated-binding, deployment, or public-documentation hit.
- [ ] Permit path-scoped exceptions only for `retain_durable` and
      `retain_evidence`; each exception names the exact file and reason.

#### Cryptographic and protocol source cleanup

- [ ] Replace the ceremony-bound ECDSA threshold-PRF request with the selected
      V2 request. Delete `EcdsaThresholdPrfRequestV1`, its context/version
      builders, encoders, decoders, dispatch branches, bindings, vectors,
      fixtures, and route adapters in the same change.
- [ ] Remove `RootShareEpoch` from threshold-PRF request bytes, purpose plans,
      transcripts, proof inputs, Router/Deriver handling, and WASM adapters.
- [ ] Retain `RootShareEpoch` only where it identifies existing durable ECDSA
      material or an unchanged R103F record. List every surviving file in the
      cleanup manifest; a global symbol deletion is forbidden.
- [ ] Keep `TenantRootShareEpoch` confined to tenant-root custody,
      role-private persistence, lifecycle, refresh, restore, deletion, and
      server-side control-plane evidence.
- [ ] Prove `TenantRootShareEpoch` and custody lineage remain absent from Wallet
      Session, signer-D1, browser, SDK, iframe, device-link, registration,
      recovery, and client-facing request/response shapes.
- [ ] Replace the Ed25519 Yao V1 outer request, pair-session identity,
      proof-bundle payload, lifecycle branch, Router/Deriver dispatch,
      generated binding, local runner, and production vector with the selected
      V2 shape. Delete the V1 production decoder and mixed-version routing.
- [ ] Delete the deployment-share-hash Ed25519 root adapter plus every helper,
      fixture, export, dependency, and test that exists only to feed it.
- [ ] Preserve the seed-derived Ed25519 Yao Client root, lane-holder material,
      unchanged Yao circuit, manifests, schedules, tables, formal proofs, and
      signed Phase 0 artifact digests.
- [ ] Keep historical V1 artifacts only as `retain_evidence`. They must expose
      no production parser, public export, route, or fallback.
- [ ] Delete generic purpose-string, caller-selected target, reverse-role,
      joined-root, and arbitrary-context adapters made unreachable by the fixed
      A-target/B-target protocol.
- [ ] Delete temporary conversion helpers, duplicate canonical encoders,
      broad raw-wire constructors, unsafe domain casts, compatibility unions,
      optional identity/epoch fields, and intermediate wrappers.
- [ ] Remove unused exports and reduce retained visibility in
      `router-ab-core`, `router-ab-cloudflare`, `threshold-prf`, Ed25519 crates,
      signer-core, WASM crates, and generated TypeScript modules.
- [ ] Audit every `#[allow(dead_code)]`, `#[allow(unused_*)]`, TypeScript lint
      suppression, and unreachable match branch in R120 production modules.
      Activate or delete it. Test helpers must be under `#[cfg(test)]`.
- [ ] Remove `dormant`, `temporary`, `future`, `prototype`, and `TODO R120`
      claims from production modules. Each named path must be live or deleted.

The source inventory includes at least:

- `crates/router-ab-core/src/derivation/tenant_root*`,
  `ecdsa_threshold_prf.rs`, `ecdsa_threshold_prf_backend.rs`, and the ECDSA and
  Ed25519 protocol modules;
- `crates/threshold-prf`, `crates/router-ab-ed25519-yao*`,
  `crates/signer-core`, and their WASM bindings;
- `crates/router-ab-cloudflare/src/tenant_root*`,
  `durable_object/tenant_root_creation.rs`, Router coordination, strict Worker
  routes, ECDSA adapters, and Ed25519 lifecycle/pair/signing-worker modules;
- `crates/router-ab-dev`, `crates/ed25519-yao-cloudflare-bench`, generated
  shared TypeScript modules, wallet-server tenant-root composition, and the
  threshold ECDSA/Ed25519 transport routes.

#### Runtime and trust-boundary cleanup

- [ ] Give each retained creation, refresh, activation, restore, cleanup,
      deletion, status, and operator operation one typed route or scheduled
      caller. Delete debug routes, raw-payload routes, duplicate private RPCs,
      and superseded service-binding paths.
- [ ] Derive tenant, root, lineage, role, epoch, authority, signer identity, and
      current time from authenticated local state. Delete request fields and
      parsers that previously accepted them from callers.
- [ ] Prove A and B never share a scalar, sealing key, backup key, provider
      credential, or role-signing key. Delete transports, serializers, fixture
      helpers, and log fields capable of carrying those values across roles.
- [ ] Keep Router and the tenant-root control plane public-evidence-only.
      Delete scalar/share decoders and secret bindings visible to either.
- [ ] Keep SigningWorker unaware of tenant-root shares, lineage, epoch, issuer
      keys, role-creation keys, and provider keys. Remove accidental imports,
      request fields, persistence fields, and Env visibility.
- [ ] Enforce the final grant-authority, control-plane issuer, Router-owned DO,
      and Deriver verifier trust graph. Delete Router self-issuance,
      request-supplied verifier, shared private issuer, and peer-role fallback
      paths.
- [ ] Keep one owner for every replay and terminalization transition. Delete
      mutation helpers that bypass the typed reserved/executed token.
- [ ] Remove response and diagnostic fields exposing internal identity,
      lineage, epoch, provider/key references, commitments, or replay details
      beyond the redacted operator contract.

#### Persistence and operational-state cleanup

- [ ] Preserve applied D1 and Durable Object migration history. Never rewrite
      or delete a migration that may have run; use a forward migration to
      remove obsolete live schema.
- [ ] Re-prove the R103F signer-D1 no-change digest. Tenant-root lineage, epoch,
      receipts, shares, provider references, and cleanup state belong only in
      role-private stores and Router-owned public DO state.
- [ ] Inventory every pending share, command reservation, execution checkpoint,
      commitment rendezvous, installation checkpoint, restore attempt, cleanup
      failure, alarm, and idempotency record.
- [ ] Drive each record to active, retired, deleted, terminal failure, or
      verified cleanup before removing code that can interpret it.
- [ ] Delete abandoned pending ciphertext only through exact-revision cleanup
      commands and receipts. Never delete an active or potentially active share
      based on age alone.
- [ ] Define retention and compaction for completed/failed replay rows, terminal
      receipts, public evidence, alarms, and idempotency records. Preserve
      enough information to reject delayed replay for the full accepted
      lifetime.
- [ ] Prove delayed registration, recovery, device-link, export, and
      lane-materialization commits cannot activate old-profile material.
- [ ] Delete compatibility readers only after the inventory reports zero live
      records that require them.
- [ ] Inspect encrypted rows in both role stores and public DO records. No
      plaintext share, PRF partial/output, joined root, signing seed, provider
      private key, or issuer private key may appear in storage, logs,
      analytics, traces, errors, or deployment artifacts.

#### Secrets, keys, and providers

- [ ] Remove `DERIVER_A_ROOT_SHARE_WIRE_SECRET_BINDING` and
      `DERIVER_B_ROOT_SHARE_WIRE_SECRET_BINDING` from source, generators,
      Wrangler, workflows, local development, documentation, and deployed
      Secrets after every tenant has an active physical root pair.
- [ ] Rename shared configuration whose name still implies obsolete
      Router-only ownership, including the shared role-verifier keyset. Delete
      the old symbol, Env name, workflow input, and documentation without an
      alias.
- [ ] Confirm the retired Router-prefixed control-plane issuer verifier has zero
      hits. Retain only
      `TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON` in Router,
      Deriver A, Deriver B, and the control plane; keep it out of SigningWorker.
- [ ] Keep the issuer private binding only in the control plane. Keep each role
      creation, online epoch, managed-backup, and provider credential only in
      its owning Deriver.
- [ ] Rotate away bootstrap, development, benchmark, and pre-cutover keys.
      Revoke their Cloudflare Secrets, KMS/HSM versions, access policies,
      service tokens, CI secrets, and local values after production keys pass.
- [ ] Destroy retired online and managed-backup keys only after signed
      retirement/destruction receipts and rollback probes prove the active
      epoch remains usable.
- [ ] Record `cryptographic_erasure_unverified` when the provider cannot prove
      destruction; never upgrade that outcome through documentation.
- [ ] Keep tenant-controlled recovery packages independent of operational key
      cleanup and prove service cleanup cannot delete tenant-owned backups.
- [ ] Run a final secret scan over tracked files, generated deployment output,
      workflow/build logs, benchmark artifacts, and release bundles.

#### Deployment and cloud-resource cleanup

- [ ] Reconcile Router, A, B, SigningWorker, tenant-root control plane, wallet
      server, local runner, and benchmark manifests against the final binding
      matrix. Delete every binding with no live consumer.
- [ ] Remove obsolete Wrangler variables, Secrets, service/DO bindings,
      compatibility names, environment examples, generator fields, workflow
      inputs, and deployment-target values.
- [ ] Preserve Router-owned DO migration history and active namespaces. Remove
      superseded classes/bindings only through a supported migration after
      proving they contain no live authority or replay state.
- [ ] Undeploy benchmark-only and abandoned Workers after signed evidence is
      captured. Remove their routes, domains, bindings, tokens, datasets,
      alarms, queues, and environment values.
- [ ] Retain only benchmark source and verifier tooling required to reproduce
      or validate published Phase 0 evidence.
- [ ] Delete pre-cutover Worker revisions after the rollback window closes.
      Prove no route, binding, cron, queue consumer, or traffic split reaches
      them.
- [ ] Enforce final deployment order and independent least-privilege tokens.
      Revoke temporary broad development and staging tokens.
- [ ] Verify staging, testnet, mainnet, and self-hosted templates express the
      same role separation and secret-visibility matrix.
- [ ] Remove fixed-port, temporary-worktree, local-tunnel, and shared-service
      assumptions. Retain one collision-safe per-worktree local runner.

#### Tests, fixtures, generation, and dependencies

- [ ] Classify each failing or obsolete test before editing. Delete tests,
      snapshots, fixtures, mocks, factories, guards, and helpers that exist
      only for the retired profile or an intermediate R120 shape.
- [ ] Never add production compatibility code to preserve an obsolete test.
- [ ] Update valid factories to construct only final discriminated unions. Add
      negative type fixtures for V1 requests, optional identity/epoch fields,
      broad spreads, raw casts, mixed roles/epochs, and caller-selected context.
- [ ] Regenerate Rust-to-TypeScript bindings, ECDSA vectors, Ed25519 wires,
      WASM fixtures, Yao anti-drift evidence, schema manifests, and the boundary
      inventory using authoritative generators.
- [ ] Remove stale generated files and exports. A clean regeneration must
      produce no diff.
- [ ] Audit Cargo features, crate dependencies, package dependencies, script
      entries, build aliases, and workspace exports. Remove items used only by
      deleted adapters, benchmark Workers, or compatibility code.
- [ ] Delete source guards superseded by types, vectors, constraints, or
      operating-path tests. Update retained guards to final symbols.
- [ ] Keep historical V1 proof/release artifacts only in explicit evidence
      directories and exclude them from production packages and imports.

#### Documentation, observability, and repository cleanup

- [ ] Change this plan from proposed/in progress to complete and reconcile every
      checkbox. Remove stale R103F, dormant, future-worker, and provisioning
      claims.
- [ ] Update architecture, deployment, self-hosting, backup/restore, deletion,
      incident-response, key-rotation, and operator-refresh documentation to
      final names and trust boundaries.
- [ ] Delete superseded operating documents or mark immutable historical
      evidence so it cannot be mistaken for current guidance.
- [ ] Remove temporary rollout dashboards, old-profile counters, benchmark
      alerts, and migration-only alarms after their retention window. Keep
      redacted current-path health and security telemetry.
- [ ] Observe zero old-profile traffic, zero old-version parsing, zero
      unfinished cutover state, zero unknown tenant-root rows, zero orphaned
      provider keys, and zero unreachable cloud resources for the documented
      closure window.
- [ ] Remove temporary branches, worktrees, patches, scratch generation output,
      local deployment output, and ignored build artifacts only after commits
      and evidence are preserved. Never clean a dirty worktree broadly.
- [ ] Record one signed closure receipt containing the release commit, migration
      heads, deployment IDs, source/build/schema/generated-artifact digests,
      Phase 0 digest, provider-destruction receipts, and full test matrix.

#### Executable closure searches

Turn these inventory searches into checked-in assertions. Manual review alone
is not closure evidence.

| Search | Required final result |
| --- | --- |
| Prior ECDSA request/context symbols | Zero runtime/generated-binding hits; immutable vectors only as named evidence |
| Ed25519 V1 outer/pair protocol and deployment-share-hash adapter | Zero production, local-runner, SDK, WASM-export, and binding hits |
| `RootShareEpoch` in threshold-PRF inputs | Zero request/purpose/transcript hits; every durable survivor listed |
| `TenantRootShareEpoch` or lineage in R103F/client surfaces | Zero signer-D1, Wallet Session, browser, iframe, device-link, and client-request hits |
| Deployment-wide root-share bindings | Zero source, generator, workflow, Wrangler, environment, and deployed-secret hits |
| Superseded Router-prefixed verifier names | Zero hits after no-alias rename |
| R120 dead-code suppressions, dormant comments, unreachable routes, unused exports | Zero production hits |
| Dual-profile flags, fallback branches, V1/V2 unions, compatibility readers | Zero runtime hits outside a dated persistence-boundary removal plan |
| Private root/PRF/provider material outside the owning Deriver | Zero transport, persistence, log, analytics, and generated-public-type hits |
| R120 fields in frozen R103F B4/B5/client shapes | Zero schema diff from the recorded R103F digest |
| Obsolete tests, fixtures, mocks, guards, scripts, dependencies, exports | Zero unexplained cleanup-manifest rows |

#### Final verification matrix

- [ ] Run all router-ab-core, router-ab-cloudflare, threshold-prf, Ed25519,
      signer-core, local-dev, WASM, vector, constant-time, and formal suites on
      a clean checkout.
- [ ] Run production Rust feature combinations with warning-clean check,
      formatting, accepted Clippy policy, and `git diff --check`.
- [ ] Run TypeScript builds, no-emit checks, type fixtures, unit suites, source
      boundaries, generated-binding parity, and clean regeneration.
- [ ] Run the complete intended-behaviour matrix on the exact release tree.
- [ ] Run creation, refresh, restore, cleanup, deletion, replay,
      mixed-revision/epoch, tenant-isolation, normal-signing, and provider
      destruction drills against staging.
- [ ] Smoke-test both a fresh deployment and an upgraded deployment and compare
      their binding, migration, and trust manifests.
- [ ] Run all canonical closure assertions and require zero unexplained hits.
- [ ] Review the final diff for compatibility code, duplication, stale comments,
      debug logging, broad visibility, flags, secret exposure, and unrelated
      user work.

#### Exit gate

Refactor 120 is complete only when:

1. Every cleanup-manifest row has one satisfied terminal disposition.
2. Every deleted/renamed item has zero runtime hits; every retained item has a
   concrete reader/verifier and retention reason.
3. No production R120 module uses dead-code suppression, a dormant path, debug
   route, legacy flag, V1 fallback, or compatibility union.
4. No deployed route, revision, binding, Secret, provider key, database row,
   alarm, queue, token, or benchmark Worker sits outside the signed inventory.
5. The final verification matrix is green on the signed release commit and
   deployed revision manifest.
6. Every **Definition of Done** item is backed by a named test, receipt,
   inventory assertion, or deployed drill in the signed closure record.

## Reference Invariant Catalogue

These invariants explain the design. They do not require one test each. The
active plan names the authoritative operating-path tests; focused unit tests
remain only where they cover a distinct boundary those paths cannot reach.

The implementation is complete only when tests prove:

- tenant A and tenant B have unrelated root commitments and shares;
- neither initial creation nor refresh exposes the joined root;
- the creation journal contains only the Started event and rebuilds the exact
  preparing state;
- the creation capability is signed and binds the exact object authority,
  identity, custody lineage, journal digest, issuer key, and freshness window;
- the creation Durable Object accepts only its deterministic identity/lineage
  binding and input-gated journal key, with exact expired-replay, unseen-expiry,
  and conflict behavior;
- the dormant installation checkpoint accepts either A/B arrival order only
  after `TenantRootSignedShareInstallationEvidenceV1::decode_and_verify_canonical_bytes`
  produces `VerifiedTenantRootSignedShareInstallationEvidenceWireV1`, stores
  public evidence only, freshness-validates unseen first/peer evidence with
  `TenantRootCeremonyContextV1::validate_at`, rejects substituted or corrupt
  evidence, and replays exact persisted evidence after expiry without
  activation;
- initial role attempts are request-local and non-cloneable, keep
  `WaitingForPeer` within the same bounded request, and burn the scalar on
  timeout/drop; a retry requires fresh lineage, session, and nonce because the
  public commitment is immutable;
- the provider-neutral online seal binding carries the exact installation
  evidence and opaque key reference, while provider ciphertext remains outside
  the core's interpretation;
- creation-specific D1 reservation, execution, and success receipts preserve
  the exact evidence bytes, and authenticated private Router commitment/evidence
  RPCs require freshness for unseen input while replaying the exact durable
  record after expiry; each Durable Object mutation is atomic;
- both root shares change after refresh;
- `2*A - B` and `2*A' - B'` bind to the same public root commitment;
- old and new shares produce identical ECDSA threshold-PRF outputs;
- old and new shares produce identical A-target and B-target PRF outputs,
  Ed25519 contributions, and public keys;
- A receives only B's A-target peer bundle, B receives only A's B-target peer
  bundle, and the Router receives no plaintext partial;
- arbitrary PRF contexts, reverse target directions, mixed purposes, and
  caller-selected target roles are rejected;
- each role processes Yao only after entering its typed local `preface_ready`
  state, with no standalone readiness message or second preface flight;
- every preface failure or timeout burns the pair and zeroizes role-local
  outputs;
- raw tenant-root shares, PRF partials and outputs, and the joined root never
  enter Yao;
- current and selected-profile Yao circuit artifacts are byte-identical;
- the production-shaped Ed25519 candidate benchmark passes every frozen resource
  and headroom gate before production protocol work;
- the candidate reuses the baseline A/B session, adds exactly one bidirectional
  proof-bundle flight, adds no connection or client round trip, and increases
  warm p95 end-to-end ceremony latency by at most 10 ms in every cohort;
- changing only `TenantRootShareEpoch` leaves stable derivation bytes unchanged;
- mixed current/next shares are rejected;
- stale, future, substituted, and replayed epochs are rejected;
- failure before activation leaves the current epoch usable;
- failure after one pending install exposes no mixed-epoch derivation path;
- role-local command persistence checkpoints execution before terminalization,
  and signed terminal receipts replay with their exact canonical bytes;
- restart from every lifecycle state converges to one defined branch;
- no wallet record, signer package, client state, public key, address, or
  activation reference changes;
- no R103F authorization, operation credential, quota, registration receipt,
  device-link delivery or acknowledgement, V6 browser record, hosted child, or
  host/iframe message changes;
- no `TenantRootShareEpoch`, custody lineage, or root receipt appears in R103F
  signer-D1 or client-facing shapes;
- no client request, WebAuthn ceremony, or browser callback occurs;
- normal signing succeeds throughout a refresh;
- normal signing resolves R103F exact material without invoking the tenant-root
  resolver; Ed25519 export resolves exact material first and then obtains its
  independently server-resolved tenant-root binding;
- A and B backups require independent decryption and authorization paths;
- tenant recovery packages use a dedicated sharing, preserve the public root
  commitment, and remain usable across operational refreshes;
- a restored role share matches the active commitment and is immediately
  replaced by a forward refresh;
- retired operational and managed-backup shares cannot be recovered through
  supported rollback paths;
- refreshing tenant A changes no state or availability for tenant B;
- source and self-hosted destination roots refresh independently;
- no delayed R103F registration or recovery replay can make retired-profile
  material active or usable;
- R120 activation cannot begin before R103F R5 or while an old Wallet Session
  worker or mismatched R120 derivation revision can serve traffic.

## Historical Definition of Done (reference only)

The active implementation milestones above are the executable definition of
done. This earlier list is retained for traceability and must not create
duplicate work.

Refactor 120 is complete when:

1. Every tenant maps to a distinct physical tenant derivation root.
2. No process or runtime holds both root shares.
3. ECDSA stable derivation excludes `RootShareEpoch` and
   `TenantRootShareEpoch`.
4. Ed25519 derives separate A-target and B-target roots through the threshold
   PRF, combines each output only inside its target Deriver, runs the existing
   contribution KDF role-locally, and leaves the Yao circuit artifacts
   byte-identical.
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
18. R103F B4/B5 remains the sole Wallet Session admission and exact
    material-resolution path, and all R103F session, signer-D1, browser,
    receipt, and device-link state remains unchanged by refresh.
19. Tenant-root identity and epoch resolve only from authenticated deployment
    configuration and never from Wallet Session or client state.
20. Production activation follows R103F R5 and one derivation-fenced,
    revision-verified R120 cutover with no dual profile.
21. Committed-but-not-yet-published R103F registrations enter the old-profile
    identity inventory, and unfinished registration or recovery replay cannot
    cross the profile cutover.
22. The production-shaped role-targeted threshold-PRF prototype passes before
    production Ed25519 protocol work begins. It reuses the baseline A/B session,
    adds one bidirectional proof-bundle flight, adds no additional connection or
    standalone readiness exchange, stays outside normal signing, and adds at
    most 10 ms to warm p95 end-to-end latency in every measured ceremony cohort.
    No joined-root circuit is shipped as a fallback.

## Non-Goals

- transparent replacement of the joined tenant derivation root;
- transparent conversion of existing shared-root wallets to unrelated tenant
  roots;
- refreshing active client or SigningWorker shares;
- exporting a managed or self-hosted joined tenant root as plaintext or one
  combined backup object;
- reconstructing a joined root in a Router, Gateway, SigningWorker, control
  plane, script, or operator process;
- changing R103F Wallet Session authorization, operation credentials,
  signer-D1 schema, V6 browser records, registration receipts, hosted
  credentials, host/iframe protocol, or device-link acknowledgement lifecycle;
- app-level migration or a deployment-portability package;
- carrying root shares through cross-deployment device linking;
- keeping the deployment-share-hash Ed25519 profile or a joined-root circuit as
  a runtime fallback;
- moving raw tenant-root shares, threshold-PRF outputs, or HKDF-SHA-256 into Yao
  under the selected role-targeted architecture;
- claiming that share refresh repairs exposure of both shares from one
  recoverable epoch;
- claiming cryptographic erasure without executable rollback evidence;

## Historical Evidence-Gate Notes (reference only)

One deliberate architecture-selection gate remains before production transport
and activation integration:
the role-targeted threshold-PRF preface must pass Phase 0. A passing record
freezes that design. A failure stops Refactor 120 and reopens the Ed25519
architecture through an explicit plan amendment; it does not authorize the
joined-root circuit implicitly. The implemented R120-owned cryptographic
primitives remain pre-activation code until that record passes.

Phase 1 also waits for the canonical schemas, vectors, type fixtures, boundary
inventory, baseline classification, and red tests named by the preparation
phase.

The Started-only creation journal, signed creation capability, deterministic
Router Durable Object binding/migration, role-local replay checkpoint, signed
installation evidence, the public-evidence-only A/B installation checkpoint,
signed terminal receipts, strict bundle-derived activation evidence and
receipts, provider canaries, the public refresh-evidence verifier, the dormant
refresh Durable Object public-state/checkpoint path, constant-time secret-derive
hardening, and dormant B4/B5 composition are local implementation slices. The
activation receipt binds only verified source artifacts, enforces its exact
result revision, and retains the exact signed bytes. Its availability branch is
either source-bound A/B managed backups or a consuming dual-authority
accepted-loss authorization bound to the exact context, root commitments,
installation receipts, revisions, and one-use scope. The refresh Durable
Object's authoritative public state and commitment/installation checkpoints
have exact replay/fence semantics and no activation or cutover consumer.

These slices have no public caller or role-runtime creation handler. Exact
role-plus-`signing_key_id` retention is implemented in the dormant parser.
Production role-key provisioning/configuration and deployment rotation rollout
remain open. The dedicated non-blind control-plane issuer Worker, its exclusive
private signing-key Secret, the shared public verifier trust anchor, direct
external DO bindings for the issuer and both Derivers, provider key
create/destroy/probe integration, live Durable Object orchestration, production
transport wiring, provider qualification, and release evidence remain
required. The dormant Cloudflare `operational_rotation_v1` HPKE adapter is not
persisted or provisioned through Env/Wrangler, and no public route, production
transport, activation, or cutover consumes it. Wrangler provisioning remains
deliberately absent pending activation.

Production activation additionally requires measured acceptance of the frozen
resource budget, successful online-store, backup, restore, deletion, and erasure
drills, qualification of the selected A and B key providers, R103F R5
completion, a zero-legacy serving-revision check, and a successful fenced R120
revision-manifest drill. Those gates may reject an implementation or force the
deployment into `operational_rotation_v1`; they do not reopen the root algebra,
identity, lifecycle, custody, or R103F composition contracts.
