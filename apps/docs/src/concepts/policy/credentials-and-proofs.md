---
title: Credentials And Proofs
---

# Credentials And Proofs

Proof inputs support exact authorization. They answer who is acting, what
authority they have, which intent they approved, and whether that authority is
still usable.

## Proof Inputs

Seams can use proof signals such as:

1. Passkey/WebAuthn presence.
2. Email OTP verification.
3. VoiceID owner-presence verification.
4. Wallet Session and signing grant state.
5. Device or linked-device proof.
6. Org role proof.
7. External identity, biometric, or credential proof where configured.

## Authorization Questions

```text
Who is acting?
What authority do they have?
Which intent did they approve?
Can that authority still be used right now?
```

Proofs feed policy. Policy gates execution. Wallet signatures, payments, agent
tool calls, and merchant API calls happen only after the relevant proof and
policy checks pass.
