---
title: Start here
description: Install Seams, create a wallet, and sign your first operation.
---

# Start here

Get a working wallet path running before you add recovery, linked devices, or
delegated authority. You need a React app and a Seams project with a wallet
origin, relayer URL, and managed-registration credentials.

## 1. Install the SDK

```sh
pnpm add @seams/wallet
```

## 2. Mount the provider

Configure the isolated wallet origin once near the root of your app.
`seamsTestnetConfig` takes the four values a wallet cannot start without and
fills in the rest from the SDK defaults. The example reads them from
`import.meta.env`; use the same names in your own environment or replace them
with your config loader. Pass `chains` to configure different networks, or use
`defineSeamsConfig` when you are not on testnet.

<<< ./examples/setup.tsx

Render your wallet UI inside `SeamsWebProvider`. Keep the wallet service and SDK
assets on the configured wallet origin.

## 3. Create a wallet

Render the button from the registration example inside the provider. A click
opens the passkey prompt and logs progress and the branch-specific result.

<<< ./examples/registration.tsx

Read [Create a wallet](/getting-started/create-wallet) for the result branches
and retry guidance.

## 4. Sign a transaction

Registration leaves the wallet ready to sign. `useWallet()` gives you the
signed-in wallet with signing bound to it, so a call names only the
transaction. Each request opens the wallet confirmation, and the user approves
that transaction with the wallet's auth method.

To target a wallet other than the signed-in one, use `useSeams().seams` and
pass an exact `walletSession` on the call.

- [Sign a NEAR transaction](/getting-started/sign-with-policy#near-transaction)
- [Execute an EVM-family transaction](/getting-started/sign-with-policy#evm-family-transaction)

Build actions with `functionCall`, `transfer`, and friends rather than the raw
`{ type: ActionType.FunctionCall, … }` shape, and pass `logWalletEvents()` to
`onEvent` when you just want progress in the console.

`seams.evm` and `seams.tempo` mirror each other — `signTransaction`,
`executeTransaction`, `advanced` — and stay separate because an EVM
transaction is EIP-1559 and a Tempo one is EIP-2718.

There is no unlock step here. When your product needs repeated signatures
without a prompt for each one, provision a signing session: read [wallet
sessions and signing lanes](/guides/wallet-sessions-and-signing-lanes).

## Add advanced capabilities

Once the first signing path works, continue with [linked devices, key export,
and recovery](/getting-started/delegate-or-rotate). For authentication choices,
policies, and deployment boundaries, use the [guides](/guides/).
