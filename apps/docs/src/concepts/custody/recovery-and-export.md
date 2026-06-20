---
title: Recovery And Export
---

# Recovery And Export

Recovery and export prove that the user can regain control or leave the system
while ordinary signing remains share-based.

## Sealed Refresh

Sealed refresh restores an already-authenticated signing grant after accidental
iframe or page reload. It stores sealed session material in wallet-origin
IndexedDB and relies on live server participation plus valid server-side
session state.

Sealed refresh restores transaction signing capability only. Export, new device
enrollment, key rotation, and delegated-agent lane creation require fresh
operation authorization.

## Export

Export is a sensitive operation. It requires fresh operation-scoped
authorization, route policy approval, exact lane binding, audit capture, and
public-key parity checks. Export returns material only through the authorized
export path.

## Recovery

Recovery depends on the configured auth method and recovery material:

- passkey accounts use passkey-controlled material and linked devices where
  available;
- Email OTP accounts use worker-owned Email OTP material and recovery-code
  backup policy;
- delegated or organization flows use the policy and lane model.
