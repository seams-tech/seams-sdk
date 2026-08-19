---
title: Sign with policy
description: Sign NEAR, NEP-413, or EVM-family requests with exact references and per-transaction approval.
---

# Sign with policy

Each request supplies the exact wallet session reference plus the account or
chain reference that should authorize it. No unlock step is required: every
request opens the wallet confirmation, and the user approves that transaction
with the wallet's auth method. The examples below use the React context for
buttons and the `SeamsWeb` client for the signing calls.

## NEAR transaction

This example sends a `set_greeting` function call to a NEAR testnet account.
Replace the receiver, action, and execution status with values from your app.

<<< ../examples/near-signing.tsx

The example reads the wallet identity from the React login state before
building the references. Keep that check next to your sign button so a request
never starts without a known wallet.

## EVM-family transaction

Build the transaction with your EVM utilities, then pass the typed request and
an exact threshold-ECDSA chain target to Seams.

<<< ../examples/evm-signing.ts

The example targets Tempo testnet and uses placeholder transaction values.
Replace the chain, sender, recipient, fees, and data before sending a real
transaction. A successful call returns the transaction hash.

## Sign with less friction

Per-transaction approval is the right default while you integrate. When your
product needs a burst of signatures without prompting for each one, provision
a signing session with `unlock`: read [wallet sessions and signing
lanes](/guides/wallet-sessions-and-signing-lanes).

## Handle cancellation and retries

- Treat a cancelled confirmation or policy denial as the result of the current
  request and show a clear retry action.
- If broadcast status is uncertain, reconcile the transaction or nonce before
  submitting another request.
- Keep the `onEvent` callback attached while you build progress UI or audit
  logs; each canonical example shows the same event shape.

## Continue

[Link a device, export a key, or recover a wallet account](/getting-started/delegate-or-rotate).
