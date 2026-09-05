---
title: Key rotation
description: Distinguish signer rotation, custody-share refresh, envelope rewrap, and wallet rekey operations.
---

# Key rotation

Rotation covers several different operations. They should not be collapsed into
one vague "rotate keys" action.

## Taxonomy

| Operation                        | What changes                                      | Address changes |
| -------------------------------- | ------------------------------------------------- | --------------- |
| Envelope rewrap                  | Encryption around the same plaintext share.       | No              |
| Tenant-root operational-share refresh | Deriver A/B shares and their epoch; the effective tenant derivation root stays fixed. | No |
| Server internal custody rotation | How the same effective server share is protected. | No              |
| Lane share refresh               | Holder share and server share for one lane.       | No              |
| Delegated lane revocation        | Lane status and server-share admission.           | No              |
| Wallet rekey                     | Wallet key material.                              | Usually yes     |

Ed25519 Streaming Yao participates when a lifecycle operation provisions or
refreshes signing shares, activates SigningWorker material, or performs an
authorized export. Envelope rewrap stays at the storage layer when the
underlying share is unchanged. ECDSA follows its separate strict Router A/B
threshold-PRF path.

## Address-preserving refresh

### Tenant-root operational shares

Each tenant has its own randomly generated server-side derivation root, shared
between Deriver A and Deriver B. Refresh replaces those two shares and advances
their epoch while preserving the effective root and its public commitment.
Existing ECDSA addresses and Ed25519 public keys remain unchanged. Normal
signing uses already-provisioned signing material; it does not require this
refresh ceremony. New derivation ceremonies may be briefly fenced.

R120 implements one successful manual refresh per tenant per rolling hour,
with durable operation replay and a server-computed retry time. Deployment of
the throttle is pending. The R121 dashboard and fresh-step-up flow are planned;
they are not yet an available rotation UI.

Refresh does not prove destruction of historical copies. See
[tenant-root backups](/deploy-and-operate/tenant-root-backups) for the deployed
KMS retention boundary and [rotation ceremonies](/concepts/advanced/rotation-ceremonies)
for activation and interrupted-operation recovery.

### Signing-lane shares

For a two-party additive lane:

```text
h_old + s_old = wallet_key
h_new + s_new = wallet_key
delta = h_old - h_new
s_new = s_old + delta
```

The new lane epoch activates only after parity verification:

```text
H_new + S_new == existing wallet public key
```

Revocation has priority over rotation. A revoked lane must fail admission even
if stale holder material still exists.
