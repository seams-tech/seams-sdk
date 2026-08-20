---
title: Sign with policy
description: Sign NEAR, NEP-413, or EVM-family requests with exact references and per-transaction approval.
---

# Sign with policy

Every request names the subject that authorizes it and the chain it targets.
Omitted, both resolve to the signed-in wallet and a configured chain; pass them
explicitly when your product manages more than one wallet or chain at a time.
No unlock step is required: every request opens the wallet confirmation, and
the user approves that transaction with the wallet's auth method. The examples
below use `useWallet` for buttons and the `SeamsWeb` client for standalone
signing calls.

## NEAR transaction

This example sends a `set_greeting` function call to a NEAR testnet account.
Replace the receiver, action, and execution status with values from your app.

<<< ../examples/near-signing.tsx

`wallet.near` is `null` until the wallet has a NEAR account, so the check next
to the sign button is a type guard rather than a convention — a request cannot
start without one. For an exact subject, call `seams.near.signAndSendTransaction`
with `walletSession` and `nearAccount` built from
`walletSessionRefFromSession` and `nearAccountRefFromAccountId`.

## EVM-family transaction

`seams.evm` sends on every configured EVM-family chain — Tempo, Arc, Ethereum.
The chain comes from `chainTarget`, not from the namespace. Build the
transaction with your EVM utilities, then name the chain: a configured network
slug like `'tempo-testnet'` resolves to exactly one configured chain, and a
selector matching two throws and names both rather than picking one.
`seams.chainTarget(selector)` resolves the same value up front, and an exact
`ThresholdEcdsaChainTarget` is still accepted.

<<< ../examples/evm-signing.ts

The example targets Tempo testnet and uses placeholder transaction values.
Replace the chain, recipient, fees, and data before sending a real transaction.
`tx.chainId` is filled in from the chain target, and the RPC endpoint comes from
the chain you configured — neither is repeated on the call. A successful call
returns the transaction hash.

Use `seams.evm.sign` when your application broadcasts the payload itself; the
post-broadcast reporting lives on `seams.evm.advanced`.

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
