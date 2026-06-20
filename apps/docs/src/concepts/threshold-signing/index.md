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

Read next:

- [Router A/B](/concepts/threshold-signing/router-ab)
- [HSS Key Derivation](/concepts/threshold-signing/hss-key-derivation)
- [NEAR Ed25519 HSS](/concepts/threshold-signing/near-ed25519-hss)
- [EVM ECDSA-HSS](/concepts/threshold-signing/evm-ecdsa-hss)
