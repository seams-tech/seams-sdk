---
title: Wallet sessions and signing lanes
description: Create exact wallet-session references, choose a capability lane, and handle readiness, use limits, expiry, and refresh.
---

# Wallet sessions and signing lanes

Start with [Signing](/examples/signing). A wallet session binds authenticated
wallet identity to a limited signing capability. A signing lane identifies the
custody and policy path for one operation family.

## Before you call a signing method

1. Unlock the wallet and require a ready `WalletSession`.
2. Derive its exact reference from validated wallet identity.
3. Derive the NEAR account or EVM-family chain target from validated
   configuration.
4. Confirm that the requested lane is ready, then pass the same session
   reference through the complete operation.

## Handle recoverable states

- An expired or depleted session requires fresh authentication or refresh.
- A capability that is still provisioning must reach its ready state.
- A policy or nonce lane conflict requires reconciliation before replay.
- A cancelled user-presence prompt ends the current operation without changing
  wallet identity.

Progress events describe the flow. Use the result union for control decisions.

Read [wallet sessions](/concepts/sessions/wallet-sessions) and [signing
lanes](/concepts/sessions/signing-lanes).
