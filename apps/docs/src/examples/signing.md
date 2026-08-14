---
title: Signing
description: Sign a NEAR transaction, a NEP-413 message, or an EVM-family transaction with a wallet session.
---

# Signing

Unlock the wallet first, then pass an exact wallet session and chain reference
to the signing method. The snippets below keep progress events visible so your
UI can show what the signer is doing.

## Prerequisites

You need a configured `SeamsWebProvider`, a wallet session, and the account or
chain identity that matches the operation. See [wallet setup and
authentication](/examples/wallet-setup-and-authentication) if the wallet is
still locked.

## Unlock before signing

Use the unlock result to obtain the wallet session and the identity for the
selected chain.

<<< ./unlock.ts

## Send a NEAR transaction

The example sends a `set_greeting` function call to a NEAR testnet account and
waits for `EXECUTED_OPTIMISTIC`.

<<< ./near-signing.tsx

`signGreeting` resolves after the configured execution status. The button
example checks that the wallet is logged in and that a NEAR account is ready
before it starts.

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

The sample targets Tempo testnet and returns the transaction hash. Replace the
recipient, fees, and chain target with values from your app's transaction
builder before sending a real transaction.

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
