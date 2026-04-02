# Rotate Server Root

This note defines how server-root rotation works for the shared-root Ed25519
design.

The key distinction is:

- resharing the same logical tenant root `K_org_vN`
- replacing it with a new tenant root `K_org_vN+1`

Those are not the same operation.

## Why This Matters

Server-side hidden inputs are derived from the tenant root:

- `y_relayer = HKDF_u256(K_org, "ed25519/root-share/relayer:v1", ctx)`
- `tau_relayer = HKDF_mod_l(K_org, "ed25519/tau/relayer:v1", ctx)`

If `K_org` changes, then `y_relayer` and `tau_relayer` change. That changes:

- canonical seed `d`
- canonical scalar `a`
- base signing shares
- final public key

So a true root replacement is not a transparent ops rotation. It is a key-version
change.

## Two Different Operations

### 1. Reshare The Same Root

This is the normal operational path.

- underlying secret stays the same: `K_org_vN`
- custody of that secret is redistributed across 2-3 relayers
- user keys do not change
- no account migration is needed

This is useful for:

- relayer replacement
- infrastructure refresh
- changing custody layout
- reducing blast radius after a relayer-level incident

If the relayers hold Shamir shares of the same `K_org_vN`, then a new Shamir
split of that same secret is only a reshare. It is not a new root.

### 2. Replace The Root

This is the emergency path.

- old root: `K_org_vN`
- new root: `K_org_vN+1`
- derived server inputs change
- existing account keys no longer match automatically

This must be treated as a versioned migration, not an invisible rotation.

Use this only for:

- suspected `K_org_vN` compromise
- tenant-root cryptographic retirement
- intentional full rekeying

## Required Model

Every account/key must be bound to a server-root version.

Minimum metadata:

- `org_id`
- `account_id`
- `key_purpose`
- `key_version`
- `credential_id`
- `k_org_version`

`k_org_version` must be part of the derivation context or an unambiguous lookup
key into that context. The system must always know which tenant root version was
used to derive the current account key material.

## Recommended Operational Design

### Normal Rotation

Use resharing, not root replacement.

1. Keep the logical root version unchanged: `K_org_vN`.
2. Reshare `K_org_vN` across the current relayer set.
3. Decommission old relayer shares after the new threshold set is live.

Result:

- same derived keys
- same public keys
- no user-visible migration

### Emergency Rotation

Introduce a new root version: `K_org_vN+1`.

1. Create `K_org_vN+1`.
2. Shamir-split it across the current relayer set.
3. Mark new registrations as `k_org_version = vN+1`.
4. Keep `K_org_vN` available for existing accounts until migration completes.
5. Migrate existing users explicitly from `vN` to `vN+1`.
6. Retire `K_org_vN` only after no live account depends on it.

Result:

- old accounts continue to work during migration
- new accounts start on the new root version
- no ambiguity about which root version an account belongs to

## Migration Semantics

Root-version migration is account migration.

It should not be described as transparent rotation, because the derived key
material changes.

A safe migration flow is:

1. User authenticates normally against their current key version and
   `k_org_version = vN`.
2. The system runs a controlled reconstruction or re-enrollment flow.
3. New key material is established under `k_org_version = vN+1`.
4. Account metadata is updated to point at the new key version and root version.
5. Old key material is retired after confirmation and safety windows.

Whether the public key changes depends on product policy. In the current shared
root derivation model, changing `K_org` changes the derived key path, so a new
root version should be assumed to imply a new account key lifecycle.

## Compromise Response Reality

Compromise of `K_org_vN` is serious, but it should not be treated as immediate
loss of all user funds.

`K_org_vN` only gives the attacker the server-side root input. In this design,
the attacker would still need the matching client-side contribution, which means
compromising the relevant WebAuthn / `PRF.output` path for each user they want
to target.

So a `K_org_vN` compromise should be understood as:

- an emergency
- a degradation of security for every account on `vN`
- not an automatic one-shot drain of every account

That creates a response window.

## Expected Emergency Response

If `K_org_vN` is suspected compromised:

1. Create and deploy `K_org_vN+1`.
2. Stop registering new accounts on `vN`.
3. Begin migrating existing accounts to new key versions under `vN+1`.
4. Urge or require users to rotate / re-enroll their keys.
5. Monitor and rate-limit accounts that still depend on `vN`.
6. Retire `vN` only after migration is complete.

The system should assume that accounts still on `vN` are at elevated risk,
because the attacker already has the server-side half of their derivation.

## Product Interpretation

The practical safety property is:

- `K_org_vN` compromise alone should not immediately let an attacker steal funds
  from all users
- it should, however, trigger urgent server-root rotation and per-user key
  migration

That is the main reason to design `k_org_version` and migration flows up front
instead of treating tenant-root rotation as a purely operational secret-refresh
task.

## Relayer Sharding Guidance

If you split `K_org_vN` across 2-3 relayers with Shamir sharing:

- that improves durability and operational fault tolerance
- that reduces single-relayer custody risk
- that does not remove the need for root-versioning

Shamir sharing helps with:

- relayer rotation
- share refresh
- high-availability custody

It does not make `K_org_vN -> K_org_vN+1` transparent.

## Product Guidance

The expected default should be:

- frequent resharing of the same root version when operationally useful
- rare creation of a new root version only for emergency or explicit rekey events

That gives the system:

- low-friction relayer rotation
- explicit handling for compromise response
- no accidental promise that root replacement is invisible to users

## Summary

- Resharing the same `K_org_vN` is easy and should be the normal rotation path.
- Replacing `K_org_vN` with `K_org_vN+1` is a real key-version migration.
- Server-root versioning is required if emergency root replacement must be
  supported safely.
