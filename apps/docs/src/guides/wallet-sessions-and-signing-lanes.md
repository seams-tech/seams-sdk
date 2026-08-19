---
title: Wallet sessions and signing lanes
description: Unlock provisions a bounded signing session for low-friction signing; lanes identify the custody and policy path per operation family.
---

# Wallet sessions and signing lanes

Signing works without any session: each request opens the wallet confirmation,
and the user approves it with the wallet's auth method. Unlocking is an
optimization, not a gate. `unlock` provisions a **wallet session** — a bounded
signing capability with a use budget and expiry — so a run of requests can
sign with low friction instead of prompting for an approval every time.
Locking discards that session; it never changes wallet identity or moves key
material.

## Unlock: provision a signing session

Call `unlock` with the `walletId` returned during registration. The result has
separate NEAR and EVM-family success branches; read `nearAccountId` only from
the NEAR branch.

<<< ../examples/unlock.ts

The returned wallet session backs subsequent signing calls until it expires or
runs out of uses; unlock again to provision a fresh one. Size the session's
lifetime and budget for the burst of operations you expect, not for the
lifetime of the app.

## Before you call a signing method

A signing lane identifies the custody and policy path for one operation
family. With a session provisioned:

1. Require a ready `WalletSession`.
2. Derive its exact reference from validated wallet identity.
3. Derive the NEAR account or EVM-family chain target from validated
   configuration.
4. Confirm that the requested lane is ready, then pass the same session
   reference through the complete operation.

Start with [Signing](/examples/signing) for a complete flow.

## Handle recoverable states

- An expired or depleted session requires a fresh unlock.
- A capability that is still provisioning must reach its ready state.
- A policy or nonce lane conflict requires reconciliation before replay.
- A cancelled user-presence prompt ends the current operation without changing
  wallet identity.

Progress events describe the flow. Use the result union for control decisions.

Read [wallet sessions](/concepts/sessions/wallet-sessions) and [signing
lanes](/concepts/sessions/signing-lanes).
