---
title: NEAR Ed25519 HSS
---

# NEAR Ed25519 HSS

NEAR uses the Ed25519 threshold signing model. The active model derives one
canonical Ed25519 key lifecycle from holder-side and server-side contributions,
then projects that lifecycle into threshold signing shares.

## Core Idea

```text
holder contribution + server contribution
  -> HSS hidden derivation
  -> canonical Ed25519 seed and signing scalar
  -> threshold signing shares
```

The canonical key lifecycle matters because NEAR-compatible export, recovery,
and threshold signing need to agree on one public key.

## Normal Signing

Normal NEAR signing uses an already-created signing session and the selected
signing lane. HSS derivation is a setup, refresh, recovery, export, rotation,
delegation, or activation concern.

NEAR transaction signing, NEP-413 message signing, and NEP-461 delegate-action
signing should all use the selected lane and admitted signing budget.
