# Refactor 120: Proactive Router A/B Deployment-Root Refresh

Created: June 11, 2026

Last reconciled with the repository: August 5, 2026

Status: Deferred. The current custody split remains authoritative. Proactive
deployment-root refresh and joined-root Yao derivation are not planned for
implementation at this time because their protocol, lifecycle, erasure, and
operational complexity outweigh the current security benefit.

## Purpose

This document defines identity-preserving proactive refresh for the Router A/B
deployment root. A refresh replaces both Shamir shares while preserving the joined
`k_org`, every wallet public key, every address, and all client threshold material.
Once the target derivation boundary is active, the operation is O(1) in wallet count
and requires no client migration.

The filename retains the historical `k_org` term. In `threshold-prf`, `k_org` names
the underlying root scalar. Operational code exposes only role-specific signing-root
shares and treats the root as deployment custody.

The authoritative protocol and deployment documents are:

- [Router A/B protocol](router-ab/protocol.md)
- [Router A/B deployment](router-ab/deployment.md)
- [R90: modular auth and capabilities](refactor-90-modular-auth-capabilities-plan.md)
- [R102: rotatable signing lanes](refactor-102-rotatable-signing-lanes.md)
- [R115: deployment portability](refactor-115-deployment-portability.md)
- [Self-hosting plan](refactor-120-self-hosting.md)

Those documents own protocol behavior and product sequencing. This document owns the
operational distinction between deployment-root custody, deployment-root share
refresh, deployment-root replacement, and wallet-level share rotation.

## Current Decisions

1. Router A/B uses two isolated Deriver roles and a strict 2-of-2 threshold policy.
   Deriver A and Deriver B must both participate in derivation. Production places
   them in separately administered Cloudflare accounts.
2. A managed deployment currently has one deployment-level signing root. Its two root
   shares are shared infrastructure across the tenants served by that deployment.
3. `signingRootId` and `signingRootVersion` provide product scope, domain separation,
   and lifecycle selection. They do not imply a physically distinct root pair for
   every tenant.
4. Each Deriver receives only its own root-share wire secret through its role-specific
   Cloudflare secret binding:
   - `DERIVER_A_ROOT_SHARE_WIRE_SECRET`
   - `DERIVER_B_ROOT_SHARE_WIRE_SECRET`
5. The central Signer D1 root-share table has been removed. Root shares must never be
   persisted in the shared signing database.
6. The self-hosting design requires fresh operational secret material. Its production
   bootstrap remains planned work. Managed deployment root shares are outside tenant
   export and migration packages.
7. Normal signing workers do not receive either deployment-root share.
8. A successful deployment-root share refresh preserves the underlying root and every
   derived public identity. A deployment-root replacement changes the root and normally
   changes derived wallet keys and EOA addresses.
9. The refresh protocol operates on the current Shamir 2-of-2 shares. For share IDs
   `1` and `2`, a fresh zero-constant polynomial updates the shares without changing
   `k_org`.
10. ECDSA threshold-PRF derivation depends on stable wallet context and
    `signingRootVersion`. `RootShareEpoch` binds custody, transcripts, share selection,
    and replay protection; it does not enter the stable wallet KDF.
11. Ed25519 Yao receives the raw A and B Shamir scalars as protected inputs,
    reconstructs `k_org` only on garbled wires, and derives the stable server
    contributions inside the circuit. Neither Deriver, Router, Gateway, nor
    SigningWorker learns the joined root.
12. After the joined-root derivation cutover, a root-share refresh does not enumerate
    wallets, rewrite wallet records, issue new client packages, or change
    `MpcMaterialActivationRef` values. Fixed canary derivations prove continuity before
    activation.

The earlier per-project 2-of-3 construction with a customer-held recovery share and
the per-wallet contribution-migration approach are outside this design. The selected
design refreshes one deployment share pair and leaves wallet state untouched.

## Threat Model

The managed deployment assumes Deriver A and Deriver B run in separate Cloudflare
accounts with independent administrators, passkeys, recovery paths, API tokens, CI
credentials, secret stores, and deployment authority. No ordinary operator or
automation identity may control both accounts.

The proactive-refresh guarantee is epoch based. An attacker must obtain both shares
from one recoverable epoch, or compromise one role while it still retains enough
refresh state to translate a stolen share from another epoch. Exact wall-clock
simultaneity is not the boundary. A refresh heals a prior single-role exposure only
after all of these conditions hold:

1. The exposed role has been cleaned and its control-plane credentials have rotated.
2. Both roles complete an authenticated refresh in uncompromised runtimes.
3. Refresh deltas, temporary inputs, old shares, and recoverable old Worker versions
   are cryptographically erased.
4. Rollback paths cannot restore an earlier share.

Compromise of both roles during the same recoverable epoch exposes `k_org`. Share
refresh cannot remediate that event; the deployment must replace the root and migrate
the affected wallet identities. A provider-wide Cloudflare compromise is also outside
the two-account isolation guarantee. Provider diversity can strengthen a future
deployment without changing the protocol model.

Hourly refresh with jitter is the initial operational target, supplemented by an
event-triggered refresh after a role is cleaned. A one-minute interval is useful only
if installation, canary verification, secret erasure, and version retirement finish
reliably inside that cadence. Frequency cannot compensate for retained historical
shares or shared administrative authority.

## Current Secret Hierarchy

### Managed deployment

```text
managed deployment signing root
├── Deriver A root share
│   ├── Cloudflare secret binding
│   ├── Deriver A private D1 KEK
│   └── Deriver A envelope and peer-authentication keys
└── Deriver B root share
    ├── Cloudflare secret binding
    ├── Deriver B private D1 KEK
    └── Deriver B envelope and peer-authentication keys

tenant/product scope
└── signingRootId + signingRootVersion
    └── account/lane derivation context
        └── wallet public key and threshold signing material
```

The deployment root is infrastructure custody. Tenant identifiers select a derivation
domain under that root. Tenant export therefore cannot contain the managed
deployment's root shares.

### Target derivation boundary

```text
Deriver A private input: Shamir share f(1)
Deriver B private input: Shamir share f(2)

ECDSA threshold PRF
└── combines verified partial evaluations of the same stable context

Ed25519 Yao
└── protected circuit wires compute k_org = 2*f(1) - f(2)
    └── in-circuit domain-separated KDF
        ├── server/A y and tau contribution
        └── server/B y and tau contribution

public result
└── unchanged wallet public identity
```

The joined `k_org` exists only as an intermediate secret inside the Yao circuit or as
the mathematical relation reconstructed by verified threshold-PRF partials. It is
never decoded or returned.

### Self-hosted deployment

```text
self-hosted deployment
├── fresh Deriver A root share
├── fresh Deriver B root share
├── fresh role KEKs and authentication keys
└── tenant data imported through the deployment-portability contract
```

Self-hosting uses a new trust domain. The intended recovery package described by R120
is still planned work; production bootstrap and recovery ceremonies are not complete.

## Identity and Epoch Taxonomy

These values serve different purposes and must remain distinct.

| Value | Scope | Purpose | Rotation effect |
|---|---|---|---|
| Deployment signing root | One Router A/B deployment | Root PRF/derivation secret | Replacement changes derived wallet identities |
| Deriver root share | One Deriver role | One 2-of-2 share of the deployment root | Refresh can preserve the root and wallet identities |
| `signingRootId` | Product/tenant derivation domain | Selects the logical root namespace | Changing it selects a different domain |
| `signingRootVersion` | Product root lifecycle | Selects the product root version and participates in derivation bindings | Changing it can change derived key material |
| `RootShareEpoch` | Deployment-root share set | Selects shares and binds custody/transcript freshness | Incrementing it preserves stable wallet derivation |
| Wallet public key | Account or execution lane | On-chain signing identity | Changes when wallet key material changes |
| Wallet/lane share epoch | One wallet key or lane | Identifies refreshed wallet threshold shares | Incrementing it preserves the wallet public key |
| `MpcMaterialActivationRef` | Persisted wallet activation | Selects active MPC material | Changes only after successful activation |

The Rust protocol already models `RootShareEpoch` as a separate type. Current ECDSA
derivation context still includes it, and some TypeScript product paths populate
`root_share_epoch` from `signingRootVersion`. Refactor 120 removes both couplings.
Stable derivation uses `signingRootVersion`; share selection, authorization,
transcripts, persistence AAD, and replay protection use `RootShareEpoch`.

## Role Ownership

| Role | Holds deployment-root share? | Mutable persistence | Current responsibility |
|---|---:|---|---|
| Router | No | None | Request validation, routing, transcript coordination |
| Deriver A | A only | Private Deriver A D1 | A-side derivation and sealed contribution |
| Deriver B | B only | Private Deriver B D1 | B-side derivation and sealed contribution |
| Signing worker | No | Private signing D1 | Wallet signing material and signing execution |
| Gateway | No | Gateway D1 | Product ceremonies, activation results, authorization, policy, and audit state |
| Deployment control plane | No | Authoritative epoch store undecided | Deployment configuration and root-epoch coordination |
| Tenant application | No | Application data | Product lifecycle and wallet requests |
| Deployment bootstrap process | Both, transiently | Temporary process and command output | Generate the initial pair and route each share to its role |

Normal operation must preserve these boundaries. No runtime path may assemble both
root shares in one Worker, database, log stream, or administrative response.

## Implemented State

### Cryptographic and protocol primitives

- `threshold-prf` generates a signing root and splits it under a 2-of-2 policy.
- The current Shamir polynomial is evaluated at share IDs `1` and `2`.
- Root shares have typed wire encodings and proof/vector coverage.
- Root-share commitments and DLEQ proofs already bind PRF partials to committed
  scalars.
- `router-ab-core` has distinct Router, Deriver A, and Deriver B types.
- `RootShareEpoch` is included in protocol inputs and transcript validation.
- The protocol rejects role, peer, epoch, transcript, and authorization mismatches.
- Wallet derivation is bound to product/account context.

### Deployment and runtime boundaries

- `router:deploy:root-share-keygen` currently generates the root and both 2-of-2 wire
  shares in one operator-run bootstrap process, then prints the two role-specific
  secret values for separate installation. This process temporarily sees the complete
  bootstrap output and must run in an isolated operator environment with output
  capture disabled.
- Cloudflare has separate Deriver A and Deriver B Worker entry points.
- Each Worker consumes a role-specific root-share secret binding.
- Each Deriver has private D1 state and a separate KEK.
- The signing worker does not receive root-share bindings.
- The former shared `signing_root_secret_shares` D1 table is dropped by migration.
- Local development can simulate both roles and use deterministic fixture shares.

### Product binding

- Registration paths carry `signingRootId`, `signingRootVersion`, and Router A/B
  protocol inputs.
- Persisted activation records select wallet MPC material.
- Deployment portability excludes shared managed root material.

### Existing adjacent refresh surfaces

- `router-ab-core` defines wallet/account-scoped `RefreshScope` state.
- The ECDSA product path has a `server_share_refresh` operation and activation-refresh
  routing for existing wallet material.
- The Ed25519 Yao plans define wallet-key/root refresh and recovery lifecycle.
- R102 defines execution-lane creation and share refresh, while its new lane protocol
  remains unregistered.

These surfaces refresh or reactivate wallet/account material. They do not rotate the
two deployment root-share Secret bindings.

### Current Ed25519 Yao boundary

The deployed Yao preparation path hashes each raw root-share wire value into an
independent role-local root. The role-local contribution HKDF runs before the garbled
circuit, and the circuit receives already-derived `y` and `tau` contributions. A
Shamir refresh therefore changes both role roots nonlinearly and does not preserve the
joined Ed25519 output automatically.

The existing `server_share_refresh` keeps the role roots stable and applies correlated
zero-sum deltas to one wallet's persisted contributions. It proves useful lifecycle and
activation machinery, but it is not the O(1) deployment-root refresh defined here.

The joined-root Yao profile is derivation-breaking relative to this current role-local
hashing profile. Values derived as `KDF(H(A), context)` and `KDF(H(B), context)` cannot
in general be reproduced from `k_org` after A and B are refreshed. The O(1) guarantee
therefore starts only after the joined-root profile becomes authoritative. Rollout must
either happen before production Ed25519 identities depend on the current profile, or
include an explicit one-time migration for those identities. This plan does not keep a
dual legacy derivation path.

These controls implement custody isolation and epoch binding. They do not yet provide
an online rotation ceremony or distributed root generation.

## Unimplemented State

For deployment-root Secret custody, the repository does not currently implement:

- distributed refresh of Deriver A and Deriver B root shares while preserving the
  underlying deployment root;
- a public commitment to the joined deployment root and a proof that the next share
  commitments preserve it;
- a Yao input schema that accepts raw Shamir share scalars;
- binding from each protected Yao input to the installed role, share commitment, and
  active `RootShareEpoch`;
- in-circuit Shamir interpolation and server-contribution KDF;
- circuit manifests, vectors, formal evidence, and performance gates for joined-root
  Yao derivation;
- removal of `RootShareEpoch` from stable ECDSA derivation context;
- an inventory-backed cutover decision proving whether any production Ed25519
  identity depends on the current role-local hashing profile;
- a control-plane state machine for prepare, verify, activate, retire, and rollback;
- coordinated installation of a next `RootShareEpoch` across both Derivers;
- an overlap window in which active and next epochs can be verified safely;
- an explicit policy for records whose AAD binds their creation epoch versus the
  current custody epoch;
- an audited recovery runbook for loss or compromise of a Deriver root share;
- managed customer-held recovery shares;
- physically distinct deployment-root pairs per managed tenant;
- export of managed deployment root material;
- the separate [self-hosting plan](refactor-120-self-hosting.md)'s production
  bootstrap and recovery package.

Documentation and operations must describe these as gaps until executable code,
deployment automation, and tests exist.

## Rotation Operations

The word rotation covers four different operations. Operators must choose the intended
operation explicitly.

### 1. Role operational-key rotation

This rotates a Deriver KEK, envelope key, peer-authentication key, service credential,
or similar role-local secret. It does not change the deployment root or wallet keys.

Where ciphertext is protected by the rotated key, the owning role must rewrap it inside
that role's boundary. The opposite Deriver and the signing worker do not participate
unless the protocol for that key explicitly requires them.

This class of rotation is operationally feasible with the current role separation,
though individual secrets still need secret-specific deployment runbooks.

### 2. Deployment-root share refresh

This is the intended security operation for refreshing long-lived A/B custody while
preserving the same deployment signing root.

The current `threshold-prf` root uses a degree-one Shamir polynomial over the scalar
field, evaluated at share IDs `1` and `2`:

```text
f(x) = k_org + a*x
A = f(1)
B = f(2)
k_org = 2*A - B

g(x) = rho*x
A' = A + rho
B' = B + 2*rho

2*A' - B' = 2*A - B = k_org
```

The two-party form makes the contributory step concrete:

```text
rho = rho_A + rho_B

Deriver A keeps rho_A and sends 2*rho_A to Deriver B.
Deriver B keeps 2*rho_B and sends rho_B to Deriver A.

A' = A + rho_A + rho_B
B' = B + 2*rho_A + 2*rho_B
```

Before sending an update, A commits to `R_A = rho_A*G` and B commits to
`R_B = rho_B*G`. A verifies the received B update against `R_B`; B verifies its
received A update against `2*R_A`. The scalar updates travel only through the
encrypted A/B channel and live only for the ceremony.

All arithmetic is modulo the curve scalar order. Each Deriver contributes fresh
randomness to `rho` and sends only its recipient-specific zero-share update over the
authenticated role-to-role channel. A coefficient commitment lets the recipient
verify that its update is the evaluation of a zero-constant polynomial. Commitments
and proofs enter the refresh transcript; scalar deltas never enter logs, audit events,
or durable control-plane state. Ephemeral refresh material is erased after activation.

The deployment stores a public root commitment `K = k_org*G`. Given next-share
commitments `C_A'` and `C_B'`, both roles verify `2*C_A' - C_B' = K` and prove
knowledge of their installed share. This establishes continuity without reconstructing
`k_org`. The protocol needs commit-before-send ordering, authenticated encryption,
contributory randomness from both roles, and abort behavior for invalid, replayed, or
inconsistent updates.

A complete refresh ceremony needs:

1. Allocate a new `RootShareEpoch`.
2. Fence new derivation ceremonies while allowing normal signing with already-active
   wallet material.
3. Open a bounded, mutually authenticated A/B refresh session bound to deployment,
   current epoch, next epoch, nonce, protocol version, and role identities.
4. Commit to independently sampled refresh coefficients before exchanging encrypted
   recipient-specific updates.
5. Verify each received update against its coefficient commitment, then calculate and
   install the role-local next share.
6. Publish the next-share commitments and prove possession of the installed shares.
7. Verify `2*C_A' - C_B' = K` against the pinned deployment-root commitment.
8. Run fixed ECDSA threshold-PRF canaries under stable derivation contexts.
9. Run fixed Ed25519 Yao canaries with the next shares and compare all public outputs
   with the active-epoch fixtures.
10. Atomically activate the next epoch after both roles and every canary attest success.
11. Erase prior shares and ephemeral refresh state, then make the transition
    forward-only.
12. Emit a redacted audit record containing epoch IDs, transcript hashes,
    commitments, proof results, canary IDs, and destruction attestations.

Current Deriver-private D1 records use independent role-local KEKs. Deployment-root
refresh does not rotate those KEKs and does not require re-encrypting unrelated
records. Any persistence whose AAD selects the custody epoch needs a current/next
selection rule and forward-only retirement; stable wallet derivation records remain
unchanged.

Expected outcome:

- existing wallet public keys, addresses, and lane public keys remain unchanged;
- `signingRootId` and `signingRootVersion` remain unchanged;
- `RootShareEpoch` increments;
- wallet records, client threshold packages, and `MpcMaterialActivationRef` values are
  untouched;
- compromise of an old individual share no longer exposes the active share set.

This ceremony is planned and unimplemented.

### 3. Deployment-root replacement

Replacement creates a new underlying deployment signing root and a new A/B share pair.
It is required when preserving the old root is unsafe or impossible.

Replacement must be modeled as a product migration because derived keys generally
change. EVM EOAs will have new addresses. NEAR access keys and smart-contract wallet
keys may be migrated through chain-specific account-control mechanisms.

A replacement plan needs:

- a new product root version or equivalent explicit derivation namespace;
- new wallet derivation and activation records;
- chain-specific asset and authority migration;
- a rollback policy that does not silently reactivate compromised material;
- explicit retirement of the previous root and its wallet material.

Replacement cannot masquerade as a `RootShareEpoch` increment.

### 4. Wallet-key or execution-lane share refresh

R102 addresses creation and refresh of threshold shares for an individual execution
lane. The lane ID and wallet public key remain stable while the lane share epoch,
holder/server material, and activation reference change. Curve-specific wallet-key
root refresh can update every active lane package for that wallet key and remains owned
by the authoritative ECDSA and Ed25519 protocol plans.

This operates below the deployment-root layer:

```text
deployment-root custody
└── derives or authorizes wallet material
    └── wallet/lane threshold shares
        └── refreshed by R102
```

R102 remains valuable after smart-contract wallets or ERC-4337 support because share
refresh reduces exposure of long-lived off-chain signing material. Contract wallets
improve on-chain account/key indirection; they do not refresh the custody shares that
authorize signatures.

## Failure and Incident Policy

| Condition | Required response |
|---|---|
| One current Deriver share suspected exposed; peer share trusted | Halt sensitive derivation, investigate, and perform a verified share refresh when the refresh protocol exists |
| Both current Deriver shares suspected exposed | Treat the deployment root as compromised and execute root replacement |
| One Deriver share lost with no recoverable role secret | Current strict 2-of-2 deployment cannot derive new wallet material; recover from approved deployment backup or replace the root |
| Refresh fails before activation | Keep the current epoch active and destroy incomplete next-epoch material |
| Refresh fails after one role installs next material | Do not activate; restore a consistent epoch through the controlled rollback procedure |
| Canary public key changes during a claimed refresh | Abort. The operation changed the root relation or derivation inputs |
| Tenant requests managed root export | Reject the request; shared deployment root material is outside tenant export scope |

The present repository lacks the refresh and recovery control plane needed to automate
these responses. Incidents involving root-share loss or compromise require a
deployment-specific manual procedure and may require root replacement.

## Managed and Self-Hosted Boundaries

### Managed

- Root material belongs to the managed deployment trust domain.
- Tenants share the deployment root while remaining separated by authenticated
  derivation context and product scope.
- Tenant migration exports tenant-owned data and activation state.
- Tenant migration excludes Deriver root shares, role KEKs, peer keys, and other
  deployment-wide secrets.

### Self-hosted

- The planned bootstrap creates a fresh deployment root and role-local operational
  secrets.
- The host becomes responsible for backup, recovery, rotation, and destruction.
- R115 imports wallet-specific material through role-local handoff capsules and
  verifies that wallet public keys and addresses remain unchanged.
- The separate [self-hosting plan](refactor-120-self-hosting.md) requires an encrypted
  recovery package for disaster recovery within the same self-hosted trust domain.

Moving a tenant from managed to self-hosted is a deployment migration. It is not a
share refresh of the managed root.

## Implementation Plan

### Phase 0: finish the model separation

- [x] Use a strict 2-of-2 root policy.
- [x] Give each Deriver only its own root-share secret binding.
- [x] Remove central D1 persistence of root shares.
- [x] Bind `RootShareEpoch` into Router A/B protocol transcripts.
- [ ] Separate `RootShareEpoch` from `signingRootVersion` throughout TypeScript
  registration, persistence, routing, and deployment configuration.
- [ ] Remove `RootShareEpoch` from the stable ECDSA derivation context while retaining
  it in share selection, authorization, transcripts, persistence AAD, and replay
  protection.
- [ ] Represent stable derivation identity and custody epoch as separate required
  domain types.
- [ ] Add continuity vectors for existing ECDSA contexts. If the corrected stable
  encoding changes an existing production identity, cut over before production or
  perform one explicit boundary migration.

### Phase 1: implement threshold-PRF proactive refresh

- [ ] Add a typed 2-of-2 Shamir refresh protocol using zero-constant degree-one
  polynomials at the fixed share IDs `1` and `2`.
- [ ] Add commit-before-send contributory randomness and encrypted role-to-role update
  delivery.
- [ ] Pin the deployment-root commitment and verify the next-share commitment relation.
- [ ] Prove possession and correct installation of each next share.
- [ ] Define typed lifecycle states for current, preparing, verified, active,
  retiring, and failed epochs.
- [ ] Define authenticated refresh transcripts and replay protection.
- [ ] Add vectors for success, mixed epochs, invalid zero shares, malformed proofs,
  malicious updates, aborts, and replay.

### Phase 2: validate joined-root Yao feasibility

- [ ] Define protected raw-scalar inputs for Deriver A and Deriver B.
- [ ] Compute `k_org = 2*A - B` on garbled wires and prevent it from entering any
  decoded output.
- [ ] Implement one domain-separated in-circuit KDF path as a representative slice.
- [ ] Measure synthesis time, gate/table size, memory, CPU, and wire bytes against the
  active Yao profile.
- [ ] Set explicit performance gates before expanding the circuit.

### Phase 3: integrate production joined-root Yao

- [ ] Move the stable server/A and server/B `y` and `tau` contribution KDFs into the
  circuit and define their authoritative joined-root outputs.
- [ ] Version the input schema, circuit manifest, protocol profile, and cache keys.
- [ ] Bind each protected scalar input to its authenticated role, installed share
  commitment, and active epoch so substitution aborts before recipient outputs exist.
- [ ] Add Rust, Python, WASM, and cross-runtime vectors plus formal and security
  evidence for interpolation, KDF domain separation, and output privacy.
- [ ] Preserve the existing recipient output packages so wallet and client state does
  not migrate during later deployment-root refreshes.
- [ ] Inventory current-profile production identities. Cut over before production or
  execute one explicit migration; do not retain both derivation profiles.

### Phase 4: implement lifecycle and secret installation

- [ ] Add one authoritative current/next deployment epoch state machine.
- [ ] Add role-local install hooks, idempotent activation, mixed-epoch rejection, and
  fixed ECDSA and Ed25519 canaries.
- [ ] Define storage that cannot recover retired shares through secret-version history,
  Worker rollback, database time travel, backups, or the active KEK.
- [ ] Permit rollback only before activation; use a new forward refresh after
  activation.
- [ ] Emit redacted metrics, audit events, and destruction attestations.
- [ ] Exercise partial-install, crash, replay, role-loss, and compromise drills across
  two independently administered Cloudflare accounts.

### Phase 5: roll out operations and recovery

- [ ] Start with operator-triggered refresh, then enable an hourly schedule with
  jitter and event-triggered refresh after role recovery.
- [ ] Prove that refresh never scans wallet records or rewrites client packages.
- [ ] Document managed backup constraints without weakening proactive erasure.
- [ ] Implement the separate self-host recovery package.
- [ ] Add an explicit deployment-root replacement workflow.
- [ ] Add chain-specific wallet/account migration hooks.
- [ ] Exercise the both-shares-compromised replacement drill.

## Verification Requirements

A production refresh implementation is complete only when tests demonstrate:

- old and new root shares differ;
- `2*A - B` and `2*A' - B'` bind to the same pinned public root commitment;
- old and new shares produce identical threshold-PRF outputs for fixed stable contexts;
- old and new shares under the joined-root profile produce identical Ed25519 Yao `y`,
  `tau`, `d`, public key, and recipient outputs for fixed canaries;
- changing only `RootShareEpoch` leaves stable derivation input bytes unchanged;
- a mixed old/new share pair is rejected;
- a substituted Yao scalar that does not match the authenticated active share is
  rejected;
- a stale, future, or replayed `RootShareEpoch` is rejected;
- no wallet record, client threshold package, or `MpcMaterialActivationRef` changes;
- no party or decoded Yao output receives `k_org`;
- either Deriver can fail before activation without changing the active epoch;
- restart during every lifecycle state converges to a defined outcome;
- neither logs nor audit records contain share bytes, seed bytes, or plaintext wrapping
  keys;
- Router, signing worker, and control plane never receive both shares;
- retired shares and refresh deltas cannot be recovered through rollback or retained
  history;
- normal signing remains available throughout the derivation-ceremony fence;
- the joined-root Yao profile stays within its explicit latency, memory, CPU, and wire
  budget;
- deployment-root replacement produces a separately versioned wallet identity.

The current vector and protocol tests cover generation, encoding, role separation, and
transcript binding. They do not satisfy the refresh-specific requirements above.

## Open Decisions

Before implementing refresh, the project must decide:

1. The malicious-secure commit, encrypted-update, proof, abort, and transcript details
   for the two-party zero-sharing protocol.
2. The maximum acceptable gate, table, CPU, memory, and wire increase for in-circuit
   interpolation and KDF.
3. Which control-plane store is authoritative for deployment `RootShareEpoch`.
4. How current and next shares are staged and atomically selected across Cloudflare
   Workers without retaining recoverable secret history.
5. Which storage mechanism provides credible cryptographic erasure despite Worker
   version history, database recovery, backups, and operator rollback.
6. Whether any Deriver-private record truly needs custody-epoch AAD and, if so, its
   forward-only replacement rule.
7. Whether hourly refresh with jitter satisfies the measured ceremony duration and
   operational failure rate.
8. What managed disaster-recovery mechanism can coexist with the stated proactive
   compromise-recovery guarantee.
9. Whether future deployments require provider diversity in addition to separate
   Cloudflare accounts.
10. Whether any production Ed25519 identity uses the current role-local hashing
    profile and therefore needs a one-time cutover migration.
11. Whether decoupling the ECDSA custody epoch preserves current stable context bytes,
    or requires the same pre-production cutover rule.

## Non-Goals

- This document does not define wallet-level share-refresh cryptography; R102 owns it.
- It does not define tenant export payloads; R115 owns them.
- It does not define self-host bootstrap UX or packaging; the separate
  [self-hosting plan](refactor-120-self-hosting.md) owns them.
- It does not introduce per-tenant managed root pairs or customer-held third shares.
- It does not enumerate wallets, migrate client threshold shares, or reactivate wallet
  material during deployment-root refresh.
- It provides no recovery claim after both shares from one recoverable epoch are
  compromised.
- It does not claim that an epoch field alone provides rotation. Rotation requires the
  ceremony, installation, activation, erasure, and retirement controls described above.
