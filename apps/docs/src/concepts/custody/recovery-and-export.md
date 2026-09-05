---
title: Recovery and export
description: Compare recovery, key export, and the fresh authorization each high-impact operation requires.
---

# Recovery and export

Recovery and export prove that the user can regain control or leave the system
while ordinary signing remains share-based.

The flows below concern a wallet user's access and keys. Managed tenant-root
restore, planned tenant-controlled root recovery, and planned deployment
migration operate at different boundaries. See
[recovery and portability](/deploy-and-operate/recovery-and-portability).

## Sealed refresh

Sealed refresh restores sealed signing material after accidental
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

## Recovery example

Recovery synchronization returns wallet and account identity only from its
successful branch.

::: details Runnable TypeScript example

<<< ../../examples/recovery.ts

:::

## Export examples

Export resolves the exact Ed25519 or ECDSA lane before the wallet-origin viewer
discloses key material.

::: details Runnable TypeScript examples

<<< ../../examples/export-wallet.ts

:::
