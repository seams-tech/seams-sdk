# Availability-First MPC Custody: K Org Secrets Plan

Date updated: 2026-04-16

## Objective

Redesign the `k_org` system around availability-first MPC custody: an
availability-first deterministic tenant-root model that:

- avoids per-wallet durable server secret state
- avoids a separate per-wallet secret database and backup surface
- keeps normal signing independent from Google Cloud KMS availability
- prioritizes resilience against accidental data loss and Cloud KMS
  misconfiguration
- keeps the passkey-derived client share independent from server-root custody
- supports later hardening without changing the derivation model

This document is a forward-looking design plan. Breaking changes are allowed.

## Decision

We are choosing availability-first MPC custody: a deterministic tenant-root
model with an explicit phased security posture.

Phase 0 intentionally stores both plaintext `k_org` and wrapped `k_org` in
Cloudflare Durable Objects.

That means:

- there is no persisted per-wallet server secret
- `k_org` is derived deterministically from a Google Cloud-held master
  derivation key
- `k_srv_wallet` is derived deterministically from `k_org`
- Cloudflare is the hot-path source for existing projects
- Google Cloud KMS is used only for project creation and recovery
- the system can later move to wrapped-only durable storage without changing
  wallet derivation semantics

This intentionally prefers signing availability and recoverability over keeping
all tenant roots durably KMS-bound from day one.

## Threat Model

The system uses threshold signing with:

- a server-side signing share derived from `k_org`
- a client-side signing share derived from passkey PRF material

Compromise of the server derivation root is serious, but it is not by itself a
complete wallet compromise. An attacker who obtains `k_org` can derive server
shares, but still needs the user's client-side passkey share to produce
signatures.

Loss or unavailability of the server derivation root is different. If the
server cannot recover `k_org`, the server cannot produce its signing share, and
users may be unable to access wallets.

For the current stage, the higher-priority catastrophic risk is:

- lost `k_org`
- lost wrapped `k_org`
- Google Cloud KMS key deletion or misconfiguration
- Google Cloud KMS outage on the signing path
- Cloudflare state loss without a recovery path

The Phase 0 design is optimized for those risks.

## Secret Hierarchy

The model uses two Google Cloud-held platform keys, one tenant root, and one
derived wallet secret.

### 1. `master_kdf_key`

A Google Cloud KMS MAC key, or equivalent Google Cloud-only derivation
primitive.

Responsibilities:

- acts as the platform master derivation root
- deterministically derives `k_org` for a project
- is used only during project creation or recovery
- is not placed in Cloudflare environment variables
- is not used directly during normal signing

Conceptually:

```text
k_org = KDF(
  key = master_kdf_key[master_kdf_key_version],
  context = encode(
    env,
    project_id,
    k_org_version,
    derivation_version
  )
)
```

With Google Cloud KMS, this should be implemented as a Cloud KMS MAC-signing
based KDF or behind a small Google Cloud provisioning service that owns the
exact derivation procedure.

### 2. `kek_key`

A Google Cloud KMS symmetric encryption key.

Responsibilities:

- wraps `k_org` as `wrapped_k_org`
- supports rewrap and future wrapped-only storage
- is used only during project creation, recovery, or explicit rewrap
- is not used directly during normal signing

Conceptually:

```text
wrapped_k_org = CloudKMS.Encrypt(
  key = kek_key[kek_key_version],
  plaintext = k_org,
  additional_authenticated_data = encode(
    env,
    project_id,
    k_org_version,
    derivation_version
  )
)
```

### 3. `k_org[v]`

A project-scoped or tenant-scoped derivation root, versioned per project.

Responsibilities:

- acts as the server custody boundary for the project
- deterministically derives per-wallet server secrets
- can be reconstructed from Google Cloud during recovery
- can be transferred to a customer during self-host migration
- defines the active tenant-root version for new wallet enrollments

In Phase 0, plaintext `k_org` is durably stored in Cloudflare Durable Objects.
That is intentional.

### 4. `k_srv_wallet`

A derived per-wallet server secret.

Responsibilities:

- acts as the wallet-specific server-side signing share input
- is derived on demand from `k_org[v]`
- is not durably persisted as standalone secret state

## Core Derivation Model

The server-side wallet secret is derived locally from `k_org` and wallet
context.

Conceptually:

```text
k_srv_wallet = HKDF(
  ikm = k_org[v],
  salt = "wallet-server-secret:v1",
  info = encode(
    env,
    project_id,
    user_id,
    rp_id,
    scheme_id,
    key_purpose,
    wallet_key_version,
    k_org_version,
    derivation_version
  )
)
```

The exact encoding can vary, but the inputs must be explicit, stable,
canonical, and unambiguous.

The client side remains independent:

- the client share comes from passkey PRF material
- passkey registration is not tied to `k_org` custody
- reusing the same passkey does not imply the same threshold public key if the
  server-side root changes

## Phase 0 Architecture

Phase 0 is the initial availability-first architecture.

### Project creation

1. A customer creates a project.
2. Cloudflare calls the Google Cloud provisioning path.
3. Google Cloud derives `k_org` from `master_kdf_key`.
4. Google Cloud wraps `k_org` with `kek_key` to produce `wrapped_k_org`.
5. Cloudflare Durable Object stores plaintext `k_org`.
6. Cloudflare Durable Object stores `wrapped_k_org`.
7. Cloudflare Durable Object stores all derivation and key locator metadata.

Google Cloud KMS is used only at this boundary.

### Signing

1. Cloudflare loads plaintext `k_org` from Durable Object storage or memory.
2. Cloudflare derives `k_srv_wallet` locally.
3. Cloudflare participates in threshold signing with the user client share.

Normal signing must not require a Google Cloud KMS call.

### Recovery

If one recovery artifact is missing, use another.

- If in-memory `k_org` is missing, load plaintext `k_org` from Durable Object
  storage.
- If plaintext `k_org` is missing but `wrapped_k_org` exists, unwrap through
  Google Cloud KMS.
- If Cloudflare Durable Object state is lost, rederive `k_org` through Google
  Cloud from `master_kdf_key`, rewrap it, and recreate the Durable Object
  record.
- If Google Cloud KMS is down, existing projects continue signing as long as
  Cloudflare still has plaintext `k_org`.

Phase 0 therefore has redundant recovery paths:

- plaintext `k_org` in Cloudflare Durable Object storage
- `wrapped_k_org` in Cloudflare Durable Object storage
- deterministic Google Cloud derivation from `master_kdf_key`

## What Is Persisted

Phase 0 persists project-level secret material and wallet metadata.

Each project record should minimally include:

- `env`
- `project_id`
- `k_org_version`
- plaintext `k_org`
- `wrapped_k_org`
- Google Cloud project id
- Google Cloud location
- Cloud KMS key ring
- `master_kdf_key_id`
- `master_kdf_key_version`
- `kek_key_id`
- `kek_key_version`
- derivation version
- wrapping additional authenticated data version
- created and updated timestamps

Cloud SQL for PostgreSQL is the Phase 0 control-plane database for dashboard
and project metadata. The initial low-cost target is:

- Cloud SQL for PostgreSQL
- `db-f1-micro`
- 20 GB SSD
- single-zone
- automated backups enabled
- deletion protection enabled

`db-f1-micro` is a low-cost shared-core Phase 0 choice, not the long-term
production database shape. Cloud SQL should not be on the signing hot path.
Existing project signing should continue from Cloudflare Durable Object state
during Cloud SQL downtime.

Each wallet record should minimally include:

- `project_id`
- `wallet_id`
- `user_id`
- `rp_id`
- `scheme_id`
- `key_purpose`
- `wallet_key_version`
- `k_org_version`
- threshold public key
- address or chain-specific public identity
- active or retired status
- created and updated timestamps

The system persists wallet metadata, not per-wallet server secret material.

## Security Boundary In Phase 0

In Phase 0, Cloudflare Durable Object storage is custody-critical.

Because plaintext `k_org` is durably stored in Cloudflare:

- `wrapped_k_org` is not the primary steady-state protection boundary
- `wrapped_k_org` is a recovery, migration, and future-hardening artifact
- compromise of Cloudflare Durable Object storage can expose `k_org`
- exposure of `k_org` alone still does not produce signatures without the
  client passkey-derived share

This is an intentional availability-first tradeoff.

The design must not imply that `wrapped_k_org` makes Cloudflare durable storage
non-sensitive while plaintext `k_org` is also stored there.

## Versioning Model

Every wallet must be explicitly bound to the tenant-root version that produced
its server-side secret.

Minimum required wallet metadata:

- `project_id`
- `wallet_id`
- `wallet_key_version`
- `k_org_version`
- derivation version

The system must always know:

- which `k_org_version` produced the active wallet key
- which wallet key version is currently active
- which project root material is required to reconstruct that key
- which derivation version encoded the inputs

`k_org_version` must be part of the derivation context or an unambiguous lookup
key into the derivation context.

## Rotation Semantics

The most important distinction is:

- rotating or rewrapping custody of the same logical secret
- replacing that logical secret with a new one

Those are not the same operation.

### Rotate `kek_key`

`kek_key` rotation is operational.

For each project:

1. load plaintext `k_org` from Cloudflare, or unwrap existing `wrapped_k_org`
2. encrypt the same `k_org` under the new `kek_key`
3. store the new `wrapped_k_org`
4. update `kek_key_id` and `kek_key_version`
5. retire the old wrapping key after verification

Result:

- same `k_org`
- same derived `k_srv_wallet`
- same threshold public keys
- same addresses
- no tenant-visible migration

### Rotate `master_kdf_key`

`master_kdf_key` rotation is operational for new projects, but not a way to
magically rederive existing `k_org` values unless the old derivation key remains
available or existing `k_org` values are already stored.

For existing projects in Phase 0:

- keep the existing `k_org`
- optionally rewrap it under a new `kek_key`
- update project metadata to record the historical `master_kdf_key_version`
  that created it

For new projects:

- derive `k_org` from the new `master_kdf_key`
- store the new `master_kdf_key_version`

If Cloudflare loses all copies of `k_org` and `wrapped_k_org`, recovery depends
on the historical `master_kdf_key_version` still being usable.

Therefore, old `master_kdf_key` versions must not be destroyed while any
project depends on them for disaster recovery.

### Rotate custody of the same `k_org[v]`

If the logical tenant root stays the same and only custody changes, then
rotation is operational.

Examples:

- moving `k_org[v]` to a new wrapping key
- moving `k_org[v]` to customer custody in self-host migration
- changing where plaintext `k_org[v]` is stored

Result:

- same `k_org[v]`
- same derived `k_srv_wallet`
- same threshold public keys
- same addresses

### Replace `k_org[v]` with `k_org[v+1]`

If the logical tenant root changes, then derived wallet secrets change.

That means:

- derived `k_srv_wallet` changes
- threshold public key changes
- address changes unless a product abstraction absorbs the change
- the operation is a wallet key migration, not an operational rotation

Use this only for:

- suspected tenant-root compromise
- tenant-root cryptographic retirement
- intentional full rekeying

## Migration Semantics

In this model, tenant-root replacement is wallet migration.

The rule is simple:

- if `k_org_version` stays the same, wallet identity stays the same
- if `k_org_version` changes for a wallet, wallet identity changes

A safe migration flow is:

1. user authenticates with the current passkey
2. the system derives the current client share from the same passkey PRF
3. the system creates a new wallet key version under `k_org[v+1]`
4. new wallet metadata is persisted with the new `wallet_key_version` and
   `k_org_version`
5. application state migrates to the new threshold identity
6. old key material is retired after verification and safety windows

Using the same passkey does not imply the same threshold public key.

It only means the client-side contribution can remain stable while the
server-side contribution changes.

## Self-Host Migration

Self-host migration needs to be explicit about whether wallet identity must stay
the same.

### Model A: same wallet identity

Transfer custody of the same logical `k_org[v]` to the customer.

Result:

- same tenant root
- same derived `k_srv_wallet`
- same threshold public keys
- same addresses
- vendor must delete its copy of `k_org[v]`

This is the only way to keep the same wallet identity in a deterministic
tenant-root model.

### Model B: fresh customer-managed root

The customer starts using a new logical root under their custody.

Result:

- same passkey can still be used
- derived server-side wallet secrets change
- threshold public keys change
- addresses change unless product abstractions absorb the change

This is a rekey migration, not a same-key custody transfer.

## Compromise Response

Compromise response depends on which layer is compromised.

### Cloudflare Durable Object compromise

Impact:

- plaintext `k_org` may be exposed for affected projects
- attacker can derive server-side wallet shares for affected projects
- attacker still needs user client passkey shares to produce signatures

Response:

1. stop enrolling new wallets on affected roots
2. rate-limit and monitor affected projects
3. decide whether to migrate affected wallets to `k_org[v+1]`
4. harden storage posture for affected projects, potentially moving them to a
   later phase

This is serious, but not automatically an immediate one-shot drain if the
attacker lacks the client-side passkey share.

### `kek_key` compromise

Impact:

- wrapped tenant roots may be exposed if encrypted records were also exposed
- in Phase 0, plaintext `k_org` already exists in Cloudflare, so `kek_key`
  compromise is not the only relevant custody concern

Response:

1. create a new `kek_key`
2. rewrap all `k_org` values
3. update key locator metadata
4. investigate whether plaintext `k_org` was also exposed

This does not automatically force wallet key migration.

### `master_kdf_key` compromise

Impact:

- attacker may derive `k_org` for any project context protected by that key
- all projects derived from that key version are in scope

Response:

1. disable project creation with the compromised key
2. create a new `master_kdf_key`
3. derive new roots only from the new key
4. evaluate whether existing projects need `k_org[v+1]` migration
5. retain old key material only as long as required for recovery, if safe

If existing `k_org` values may be exposed, this becomes a tenant-root compromise
for every affected project.

### `k_org[v]` compromise

Impact:

- every wallet derived from that tenant root is at elevated risk
- the attacker has the full server-side derivation root for that project

Response:

1. create `k_org[v+1]`
2. stop enrolling new wallets on `v`
3. begin wallet-key migration from `v` to `v+1`
4. monitor and rate-limit accounts that remain on `v`
5. retire `v` only after migration completes

Tenant-root compromise is serious, but it is not automatically an immediate
drain if the attacker still lacks the client-side passkey share. That creates a
response window, not a reason to delay migration.

## Passkey Interaction

The passkey-derived client share should remain independent from tenant-root
rotation.

That means:

- rotating `kek_key` must not require a new passkey
- rotating `master_kdf_key` for new projects must not require a new passkey
- transferring custody of the same `k_org[v]` must not require a new passkey
- replacing `k_org[v]` with `k_org[v+1]` can still reuse the same passkey

Important limitation:

- reusing the same passkey does not preserve threshold identity
- if `k_org_version` changes, the server-side derived wallet secret changes

## EVM Implication

For EVM, a new threshold key usually means a new owner identity.

That means:

- a plain EOA cannot transparently absorb tenant-root replacement
- a smart account can absorb owner rotation while preserving the stable
  user-facing account

Product consequence:

- if EVM migration without address change is required, smart-account owner
  rotation is the intended seam

## Implementation Phases

### Phase 0. Availability-first bootstrap

Use this while the product has no or very few customers and availability risk is
higher than Cloudflare durable-storage compromise risk.

1. Create `master_kdf_key` in Google Cloud KMS or equivalent Google Cloud-only
   provisioning service.
2. Create `kek_key` in Google Cloud KMS.
3. Create Cloud SQL for PostgreSQL `db-f1-micro` with 20 GB SSD for
   control-plane metadata.
4. On project creation, derive `k_org` through Google Cloud.
5. On project creation, wrap `k_org` through Google Cloud.
6. Store plaintext `k_org`, `wrapped_k_org`, and metadata in Cloudflare Durable
   Objects.
7. Store dashboard and project metadata in Cloud SQL.
8. Derive `k_srv_wallet` locally during signing.
9. Keep Google Cloud KMS and Cloud SQL out of the signing hot path.

Exit criteria:

- project metadata and wallet metadata include explicit versions
- recovery from either plaintext `k_org`, `wrapped_k_org`, or Google Cloud
  derivation is tested
- Cloud KMS key deletion is protected by IAM, alarms, and deletion waiting
  periods
- Cloud SQL deletion protection and automated backups are enabled

### Phase 1. Formalize derivation and metadata

1. Define the canonical encoding for `k_org` derivation context.
2. Define the canonical HKDF input structure for `k_srv_wallet`.
3. Add `k_org_version`, `wallet_key_version`, and derivation version to wallet
   metadata.
4. Add `master_kdf_key_version`, `kek_key_version`, and wrapping additional
   authenticated data version to project metadata.
5. Update docs and specs so the deterministic tenant-root model is the intended
   architecture.

### Phase 2. Operational recovery and rewrap tooling

1. Implement recovery from plaintext `k_org`.
2. Implement recovery from `wrapped_k_org`.
3. Implement recovery from Google Cloud deterministic derivation.
4. Implement `kek_key` rewrap.
5. Add audit logging for project creation, recovery, unwrap, rewrap, and root
   export.

### Phase 3. Wrapped-only hardening option

Move selected projects from Phase 0 to a stricter posture when needed.

1. Stop storing plaintext `k_org` durably for selected projects.
2. Store only `wrapped_k_org` durably.
3. Cache plaintext `k_org` in memory only.
4. On cache miss, unwrap through Google Cloud KMS.
5. Keep the same `k_org`, so wallet identities do not change.

This is an operational hardening step, not a wallet migration.

### Phase 4. Tenant-root replacement migration

1. Implement new-root wallet migration from `k_org[v]` to `k_org[v+1]`.
2. Reuse the same passkey-derived client share where allowed.
3. Add migration state tracking and rollback rules.
4. For EVM, integrate owner-rotation handling where a stable account identity is
   required.

This phase is needed for compromise response and intentional full rekeying.

### Phase 5. Self-host migration

1. Add same-root custody transfer flow for customers who need continuity of
   exact wallet identity.
2. Add explicit rekey flow for customers who want fresh tenant roots under
   self-host custody.
3. Add deletion and attestation procedures for vendor-side retirement of tenant
   roots after transfer.

## High-Level Implementation Steps

1. Set up Google Cloud control plane.
   Create Cloud KMS keys for `master_kdf_key` and `kek_key`, create the low-cost
   Cloud SQL PostgreSQL instance, and lock down IAM, audit logging, backups, and
   deletion safeguards.

2. Define canonical metadata and derivation specs.
   Finalize the project root record, wallet metadata fields, derivation context
   encoding, Cloud KMS additional authenticated data, and versioning model.

3. Build the project provisioning path.
   On project creation, call Google Cloud to derive `k_org`, wrap it as
   `wrapped_k_org`, and return both values plus key locator metadata.

4. Store project roots in Cloudflare Durable Objects.
   Persist plaintext `k_org`, `wrapped_k_org`, and metadata in the Durable
   Object, with in-memory caching for the normal signing path.

5. Replace server-share derivation.
   Move signing from environment-global master-secret derivation to
   deterministic `k_org -> k_srv_wallet` derivation, without adding per-wallet
   server secret storage.

6. Keep Cloud SQL and Cloud KMS out of signing.
   Store dashboard and project metadata in Cloud SQL, but ensure existing
   project signing depends only on Cloudflare Durable Object state and local
   derivation.

7. Prove recovery paths.
   Test recovery from missing memory cache, missing plaintext `k_org`, missing
   Durable Object state, Google Cloud KMS outage, and Cloud SQL outage.

8. Add hardening and migration paths later.
   Add wrapped-only storage, tenant-root replacement, and self-host migration
   only after the Phase 0 availability-first path is working and tested.

## Phased Todo List

This todo list is the concrete execution plan. Each phase should remove or
replace stale assumptions as it lands; do not leave deprecated parallel code
paths behind.

### Phase 0A. Google Cloud foundation

- Create the Google Cloud project and choose the Phase 0 region.
- Create a Cloud KMS key ring in that region.
- Create `master_kdf_key` as a Cloud KMS MAC key.
- Create `kek_key` as a Cloud KMS symmetric encryption key.
- Create a service account for the project-provisioning path.
- Grant the service account only the Cloud KMS permissions required for MAC
  signing and encrypt/decrypt.
- Enable Cloud KMS audit logs and alerts for key disable, destroy, IAM change,
  encrypt, decrypt, and MAC-sign operations.
- Configure key deletion safeguards and document the key recovery window.
- Create Cloud SQL for PostgreSQL `db-f1-micro` with 20 GB SSD.
- Enable Cloud SQL automated backups and deletion protection.
- Store Cloud SQL connection details in deployment configuration without putting
  `k_org`, `master_kdf_key`, or `kek_key` material in environment variables.

### Phase 0B. Canonical data model

- Define the canonical project root record schema.
- Define the canonical wallet metadata schema.
- Add explicit `project_id`, `k_org_version`, `wallet_key_version`, and
  derivation version fields.
- Add Google Cloud locator fields for project id, location, key ring,
  `master_kdf_key_id`, `master_kdf_key_version`, `kek_key_id`, and
  `kek_key_version`.
- Add wrapping additional authenticated data version to project metadata.
- Define `root_storage_mode = phase0_plaintext_and_wrapped`.
- Remove any code or docs that imply an environment-global master secret is the
  intended production interface.

### Phase 0C. Google Cloud provisioning service

- Implement a project-provisioning service or endpoint that owns all Google
  Cloud KMS calls.
- Implement canonical encoding for `k_org` derivation input.
- Implement `k_org` derivation using the Google Cloud KMS MAC key.
- Feed the MAC output through the project-root KDF to produce the final
  `k_org` bytes.
- Implement canonical additional authenticated data for `wrapped_k_org`.
- Implement `wrapped_k_org` creation using the Google Cloud KMS symmetric key.
- Return only `k_org`, `wrapped_k_org`, and metadata needed by Cloudflare.
- Add request authentication so Cloudflare cannot ask for arbitrary key
  operations outside project creation and recovery.
- Add audit logging for every derive, wrap, unwrap, and recovery operation.

### Phase 0D. Cloudflare root storage

- Create the Durable Object record for each project root.
- Store plaintext `k_org`, `wrapped_k_org`, and all version metadata in the
  Durable Object.
- Add an in-memory `k_org` cache inside the Durable Object or signing
  coordinator.
- Ensure normal signing reads `k_org` from Durable Object state or memory only.
- Ensure normal signing does not call Google Cloud KMS or Cloud SQL.
- Add recovery code paths for missing in-memory `k_org`, missing plaintext
  `k_org`, and missing Durable Object state.
- Add explicit failure modes when all recovery paths are unavailable.

### Phase 0E. Server-share derivation

- Define the canonical HKDF input structure for `k_srv_wallet`.
- Include `env`, `project_id`, `user_id`, `rp_id`, `scheme_id`, `key_purpose`,
  `wallet_key_version`, `k_org_version`, and derivation version.
- Replace the current environment-global master-secret derivation path with
  `k_org -> k_srv_wallet`.
- Ensure the derived server secret feeds the existing threshold signing flow
  without introducing persisted per-wallet server secrets.
- Add tests proving the same `k_org` and wallet context reproduce the same
  server share.
- Add tests proving any derivation-context change that should change the wallet
  identity actually changes the derived server share.

### Phase 0F. Control-plane persistence

- Store dashboard, project, and wallet metadata in Cloud SQL.
- Keep Cloud SQL out of the signing hot path.
- Add idempotent project creation so repeated provisioning does not create
  conflicting roots.
- Add admin views or queries for project root metadata, wallet version metadata,
  and recovery state.
- Add backup restore drills for Cloud SQL metadata.
- Add checks that Cloudflare Durable Object metadata and Cloud SQL metadata
  agree for each project.

### Phase 0G. Recovery drills

- Test recovery from missing in-memory `k_org`.
- Test recovery from missing plaintext `k_org` when `wrapped_k_org` is present.
- Test recovery from total Cloudflare Durable Object state loss using Google
  Cloud deterministic derivation.
- Test Google Cloud KMS outage behavior for existing projects.
- Test Cloud SQL outage behavior for existing project signing.
- Test accidental disablement of `kek_key` and `master_kdf_key` in staging.
- Document manual break-glass recovery steps.

### Phase 1. Hardening without wallet migration

- Add `kek_key` rewrap tooling.
- Add support for `root_storage_mode = wrapped_only`.
- Add migration from Phase 0 plaintext-and-wrapped storage to wrapped-only
  storage for selected projects.
- Keep the same `k_org` during wrapped-only hardening.
- Cache plaintext `k_org` only in memory for wrapped-only projects.
- Add cache-miss unwrap through Google Cloud KMS for wrapped-only projects.
- Add monitoring for unexpected unwrap rates.

### Phase 2. Tenant-root replacement

- Add the ability to create `k_org[v+1]` for an existing project.
- Add wallet metadata for active and retired wallet key versions.
- Implement wallet-key migration from `k_org[v]` to `k_org[v+1]`.
- Reuse the same passkey-derived client share where supported.
- Add product-level migration state and rollback rules.
- For EVM, implement smart-account owner rotation before exposing migration as
  a user-facing no-address-change flow.

### Phase 3. Self-host migration

- Implement same-root export for customers who must preserve wallet identity.
- Implement fresh-root migration for customers who want a clean custody break.
- Add customer-side import validation for `k_org`, wrapped root material, and
  derivation metadata.
- Add vendor-side deletion and attestation procedures.
- Add audit trail export for project root transfer.

## Migration From The Current Model

The current implementation can migrate incrementally.

### Existing wallets

For each existing wallet:

1. identify the current direct derivation context
2. define its current tenant root as `k_org[v1]`
3. persist explicit metadata including `wallet_key_version = v1` and
   `k_org_version = v1`
4. keep the same derivation inputs so the threshold public key and address stay
   unchanged

This does not require introducing persisted per-wallet server secrets.

### New wallets

All new wallets should enroll directly on the deterministic tenant-root model.

## Non-Goals

- persisting standalone per-wallet server secrets
- building a separate per-wallet secret database and backup system
- requiring Google Cloud KMS or Cloud SQL for normal signing in Phase 0
- pretending `wrapped_k_org` protects tenant roots while plaintext `k_org` is
  also durably stored next to it
- making tenant-root replacement transparent when that root directly determines
  wallet identity
- silently changing wallet key versions behind stable metadata

## Open Questions

- Should `k_org` exist per project, per org, per environment, or per custody
  domain?
- Should customers be allowed to bring their own tenant root from day 0?
- What is the exact canonical encoding for derivation context?
- What deletion attestation is required after self-host custody transfer?
- Do we need an offline disaster-recovery backup or escrow for
  `master_kdf_key` material, given that non-exportable KMS keys reduce
  recoverability if the Google Cloud project, key ring, or key is lost?
- For EVM, which flows must support smart-account owner rotation before
  root-replacement migration is exposed as a product feature?

## Summary

The redesigned model is:

- `master_kdf_key` deterministically derives `k_org[v]`
- `kek_key` wraps `k_org[v]` as `wrapped_k_org`
- Phase 0 stores both plaintext `k_org[v]` and `wrapped_k_org` in Cloudflare
  Durable Objects
- `k_org[v]` deterministically derives per-wallet `k_srv_wallet`
- `k_srv_wallet` is derived on demand and not durably persisted

That gives us the operational profile we want now:

- no per-wallet secret database
- no per-wallet secret backup burden
- low-cost Cloud SQL control-plane storage
- normal signing does not depend on Google Cloud KMS or Cloud SQL
- Cloudflare can keep existing projects signing during Google Cloud KMS or Cloud
  SQL outages
- Google Cloud can recreate Cloudflare project root records after Cloudflare
  state loss

It also makes the tradeoff explicit:

- Phase 0 prioritizes availability and recoverability over strict KMS-bound
  custody
- `kek_key` rotation is an operational rewrap
- `master_kdf_key` rotation affects new project derivation and disaster
  recovery semantics
- transferring custody of the same `k_org[v]` preserves wallet identity
- replacing `k_org[v]` with `k_org[v+1]` is wallet key migration
