---
title: Passkeys
---

# Passkeys

Passkeys provide WebAuthn user presence and, where available, PRF-derived
holder-side material.

## Role In The Model

Passkeys can:

1. prove local user presence;
2. derive or unlock holder-side material;
3. step up expired or exhausted signing grants;
4. authorize sensitive operations when policy requires a cryptographic factor.

Passkeys do not make app sessions into signing authority. Passkey results are
normalized into the same lane, Wallet Session, signing grant, and policy model
as other auth methods.
