---
title: Start here
description: Install Seams, create a wallet, unlock it, and sign your first operation.
---

# Start here

Get a working wallet path running before you add recovery, linked devices, or
delegated authority. You need a React app and a Seams project with a wallet
origin, relayer URL, and managed-registration credentials.

## 1. Install the SDK

```sh
pnpm add @seams/sdk
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

## 4. Unlock and sign

After registration, unlock the wallet with its `walletId`, then pass the exact
wallet session and account or chain reference to a signing method.

- [Unlock and sign a NEAR transaction](/getting-started/sign-with-policy#near-transaction)
- [Sign a NEP-413 message](/getting-started/sign-with-policy#nep-413-message)
- [Execute an EVM-family transaction](/getting-started/sign-with-policy#evm-family-transaction)

## Add advanced capabilities

Once the first signing path works, continue with [linked devices, key export,
and recovery](/getting-started/delegate-or-rotate). For authentication choices,
policies, and deployment boundaries, use the [guides](/guides/).
