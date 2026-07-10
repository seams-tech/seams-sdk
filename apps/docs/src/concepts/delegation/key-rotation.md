---
title: Key Rotation
---

# Key Rotation

Rotation covers several different operations. They should not be collapsed into
one vague "rotate keys" action.

## Taxonomy

| Operation | What changes | Address changes |
| --- | --- | --- |
| Envelope rewrap | Encryption around the same plaintext share. | No |
| Server internal custody rotation | How the same effective server share is protected. | No |
| Lane share refresh | Holder share and server share for one lane. | No |
| Delegated lane revocation | Lane status and server-share admission. | No |
| Wallet rekey | Wallet key material. | Usually yes |

Ed25519 Streaming Yao participates when a lifecycle operation provisions or
refreshes signing shares, activates SigningWorker material, or performs an
authorized export. Envelope rewrap stays at the storage layer when the
underlying share is unchanged. ECDSA follows its separate strict Router A/B
threshold-PRF path.

## Address-Preserving Refresh

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
