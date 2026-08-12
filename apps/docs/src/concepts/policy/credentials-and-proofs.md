---
title: Credentials and proofs
description: Bind credential proofs to exact actors, operations, targets, freshness, and policy decisions.
---

# Credentials and proofs

Proof inputs support exact authorization. They answer who is acting, what
authority they have, which intent they approved, and whether that authority is
still usable.

## Proof inputs

Seams can use proof signals such as:

1. Passkey/WebAuthn presence.
2. Email OTP verification.
3. VoiceID owner-presence verification.
4. Wallet Session, quota, and operation-capability state.
5. Device or linked-device proof.
6. Org role proof.
7. External identity, biometric, or credential proof where configured.

## Authorization questions

```text
Who is acting?
What authority do they have?
Which intent did they approve?
Can that authority still be used right now?
```

Proofs feed policy. Policy gates execution. Wallet signatures, payments, agent
tool calls, and merchant API calls happen only after the relevant proof and
policy checks pass.
