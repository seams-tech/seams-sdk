---
title: Threshold Signing
---

# Threshold Signing

Threshold signing lets Seams split signing authority across holder-side and
server-side material. A valid signature requires the selected holder lane and
admitted server participation.

Normal signing uses signing shares produced by earlier derivation or activation
steps. The wallet key is not reconstructed for ordinary signatures.

## Mental Model

```text
holder-side share + admitted server-side share -> signature
```

Router decides whether the operation may reach signing. SigningWorker
participates only after Router admission. HSS appears in derivation and
activation ceremonies; normal signing spends the already-derived shares and
presignature state.

## Session Identity Versus Signing Authority

Threshold signing tracks two separate identities:

| Identity | Purpose |
| --- | --- |
| `thresholdSessionId` | Identifies the MPC/HSS protocol session and its signing material. Multi-round protocol state, restored holder material, and server material must all refer to this id. |
| `signingGrantId` | Identifies the Wallet Session signing grant. This is the auth and budget boundary for remaining uses, expiry, and step-up. |

The protocol session says which threshold material must be used. The signing
grant says whether the wallet is currently authorized to use it.

## Material Readiness

Worker-owned material is not sign-ready just because a persisted record mentions
it. Browser workers are runtime-local, so material must be loaded and validated
against the current Wallet Session, signing grant, threshold session, signing
root, Router A/B scope, and worker identity.

The practical states are:

| State | Meaning |
| --- | --- |
| Auth-ready | The signing grant and Wallet Session auth exist. |
| Restore-ready | Durable sealed material exists and can be restored before signing. |
| Material pending | The record has a material hint, but the worker has not validated it. |
| Sign-ready | The worker has validated the material for the exact current binding. |

Normal signing starts only from sign-ready state. Restore and step-up are
separate phases that must complete before final signing.

Read next:

- [Router A/B](/concepts/threshold-signing/router-ab)
- [HSS Key Derivation](/concepts/threshold-signing/hss-key-derivation)
- [NEAR Ed25519 HSS](/concepts/threshold-signing/near-ed25519-hss)
- [EVM ECDSA-HSS](/concepts/threshold-signing/evm-ecdsa-hss)
