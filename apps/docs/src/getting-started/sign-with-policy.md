---
title: Sign with policy
description: Unlock a wallet, then sign NEAR, NEP-413, or EVM-family requests with exact references.
---

# Sign with policy

Unlock the wallet before signing. Each request supplies the exact wallet
session plus the account or chain reference that should authorize it. The
examples below use the React context for buttons and the `SeamsWeb` client for
the signing calls.

## Unlock the wallet

Call `unlock` with the `walletId` returned during registration. The result has
separate NEAR and EVM-family success branches; read `nearAccountId` only from
the NEAR branch.

<<< ../examples/unlock.ts

The returned wallet session is the authority for the signing examples. Unlock
again when the session expires or runs out of uses.

## NEAR transaction

This example sends a `set_greeting` function call to a NEAR testnet account.
Replace the receiver, action, and execution status with values from your app.

<<< ../examples/near-signing.tsx

The example checks the React login state before it creates the account and
session references. Keep that check next to your sign button so a locked wallet
cannot start a request.

## NEP-413 message

Use `signNEP413Message` when an application needs a wallet signature for a
structured off-chain message, such as a checkout quote.

<<< ../examples/nep413-signing.ts

The `recipient` and `state` values bind the message to the service and request
that created it. Generate them from your application request rather than
reusing the example values.

## EVM-family transaction

Build the transaction with your EVM utilities, then pass the typed request and
an exact threshold-ECDSA chain target to Seams.

<<< ../examples/evm-signing.ts

The example targets Tempo testnet and uses placeholder transaction values.
Replace the chain, sender, recipient, fees, and data before sending a real
transaction. A successful call returns the transaction hash.

## Handle cancellation and retries

- Treat a cancelled prompt or policy denial as the result of the current
  request and show a clear retry action.
- Unlock again when the wallet session is expired or exhausted.
- If broadcast status is uncertain, reconcile the transaction or nonce before
  submitting another request.
- Keep the `onEvent` callback attached while you build progress UI or audit
  logs; each canonical example shows the same event shape.

## Continue

[Link a device, export a key, or recover a wallet account](/getting-started/delegate-or-rotate).
