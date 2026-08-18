---
title: Auth methods
description: Compare passkeys, email OTP, VoiceID, and other proofs across the same custody, policy, and session lifecycle.
---

# Auth methods

Auth methods are adapters over the same custody, policy, lane, and session
model.

| Method    | Role                                                            |
| --------- | --------------------------------------------------------------- |
| Passkeys  | Cryptographic authenticator and user-presence factor.           |
| Email OTP | Server-verified channel challenge and worker-owned secret flow. |
| VoiceID   | Owner-presence and spoken-intent proof for device-bound flows.  |

Read next:

- [Auth planes](/concepts/auth-planes)
- [Passkeys](/concepts/auth-methods/passkeys)
- [Email OTP](/concepts/auth-methods/email-otp)
- [VoiceID](/concepts/auth-methods/voiceid)
