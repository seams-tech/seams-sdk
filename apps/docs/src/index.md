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

Configure the isolated wallet origin once near the root of your app. The
example reads deployment values from `import.meta.env`; use the same names in
your own environment or replace them with your config loader.

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

Registration leaves the wallet ready to sign. Pass the wallet and account
references to a signing method; each request opens the wallet confirmation,
and the user approves that transaction with the wallet's auth method.

- [Sign a NEAR transaction](/getting-started/sign-with-policy#near-transaction)
- [Execute an EVM-family transaction](/getting-started/sign-with-policy#evm-family-transaction)

There is no unlock step here. When your product needs repeated signatures
without a prompt for each one, provision a signing session: read [wallet
sessions and signing lanes](/guides/wallet-sessions-and-signing-lanes).

## Add advanced capabilities

Once the first signing path works, continue with [linked devices, key export,
and recovery](/getting-started/delegate-or-rotate). For authentication choices,
policies, and deployment boundaries, use the [guides](/guides/).
