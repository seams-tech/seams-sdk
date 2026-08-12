---
title: Wallet sessions and signing lanes
description: Create exact wallet-session references, choose a capability lane, and handle readiness, use limits, expiry, and refresh.
---

# Wallet sessions and signing lanes

A wallet session binds authenticated wallet identity to a limited signing
capability. A signing lane identifies the custody and policy path used for one
operation family.

## Before signing

Require a ready `WalletSession`, derive its exact reference, and derive the
NEAR account or EVM-family chain target from validated configuration. Inspect
capability readiness for the requested lane.

## Recoverable states

- An expired or depleted session requires fresh authentication or refresh.
- A capability that is still provisioning must reach its ready state.
- A policy or nonce lane conflict requires reconciliation before replay.
- A cancelled user-presence prompt ends the current operation without changing
  wallet identity.

Pass the same wallet-session reference through the complete sign operation.
Diagnostics and progress events can describe the flow; the result union owns
the control decision.

Read [wallet sessions](/concepts/sessions/wallet-sessions) and [signing
lanes](/concepts/sessions/signing-lanes).
