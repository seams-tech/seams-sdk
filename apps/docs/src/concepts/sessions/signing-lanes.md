---
title: Signing Lanes
---

# Signing Lanes

A signing lane is the exact signing capability selected for one operation.

It answers:

```text
Who is signing?
Which auth method or delegated lane owns the capability?
Which curve and chain target are being used?
Which signing grant budget is being spent?
Which threshold session and key material must be used?
```

## Lifecycle

1. Read a side-effect-free snapshot.
2. Select one concrete lane or fail with a typed error.
3. Restore only that exact lane.
4. Plan auth for that lane.
5. Admit signing budget for that lane.
6. Sign and finalize with that same lane.

Snapshot reads should not restore, prompt, consume budget, delete records, or
choose a fallback auth method.

## Examples

Lanes exist for NEAR Ed25519 transactions, ECDSA Tempo signing, ECDSA EVM
signing, passkey accounts, Email OTP accounts, VoiceID-gated intents, linked
devices, and delegated agents.
