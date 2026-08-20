---
title: Signing
description: Sign a NEAR transaction, a NEP-413 message, or an EVM-family transaction with a wallet session.
---

# Signing

Signing calls resolve the authenticated wallet on their own; name an exact
wallet or chain when your application handles more than one. The snippets below
keep progress events visible so your UI can show what the signer is doing.

## Prerequisites

You need a configured `SeamsWebProvider` and a signed-in wallet. See [wallet
setup and authentication](/examples/wallet-setup-and-authentication) if the
wallet is still locked.

There is no unlock step before signing: every request opens the wallet
confirmation and the user approves that transaction. `unlock` provisions a
signing session when your product needs a burst of signatures without a prompt
for each one.

<<< ./unlock.ts

## Send a NEAR transaction

The example sends a `set_greeting` function call to a NEAR testnet account and
waits for `EXECUTED_OPTIMISTIC`.

<<< ./near-signing.tsx

The button resolves after the configured execution status. `useWallet` returns
`near` as `null` until the wallet has a NEAR account, so the single check before
the button renders is a type guard rather than a convention.

## Sign a NEP-413 message

Use NEP-413 for an off-chain, domain-bound message such as a checkout approval.

<<< ./nep413-signing.ts

The successful result contains the signed message data. The helper throws only
after the SDK returns `success: false`, so callers can replace the throw with an
inline error state when needed.

## Execute an EVM-family transaction

Create a typed EIP-1559 request and provide the chain target for the network
you support.

<<< ./evm-signing.ts

The sample targets Ethereum Sepolia and returns the transaction hash. Replace
the recipient, fees, and chain target with values from your app's transaction
builder before sending a real transaction. `tx.chainId` and the RPC endpoint
both come from the chain target, so neither is repeated on the call.

For Tempo's EIP-2718 typed transactions use `seams.tempo`, which mirrors this
API method for method.

## Expected result

- NEAR signing resolves after the requested transaction execution status.
- NEP-413 returns a successful signed-message result.
- EVM-family execution returns `txHash` after the transaction is submitted.

Progress callbacks receive `SigningFlowEvent` values. Use them for a status
indicator and keep the final operation identity for reconciliation.

## Recoverable failures

- A cancelled approval or policy denial ends the current request. Preserve the
  draft intent so the person can review and retry it.
- An expired or exhausted wallet session needs a fresh unlock before retrying.
- A signing or RPC failure should remain attached to the operation being
  attempted; avoid submitting a second transaction until the first hash or
  nonce state is reconciled.
- Validate chain ids, recipients, fees, and account references in your app
  before calling the SDK.

Read next: [advanced wallet operations](/examples/advanced-wallet-operations), [events and progress](/reference/events-and-progress), or [results and errors](/reference/results-and-errors).
