---
title: Wallet setup and authentication
description: Configure the Seams provider, register a wallet with a passkey, unlock it, or authenticate with Google Email OTP.
---

# Wallet setup and authentication

Use this path when adding Seams to a new app. Configure the provider once,
register a wallet, and create a wallet session before signing.

## Prerequisites

Install `@seams/wallet`, serve the configured wallet origin, and provide the
registration and relayer environment variables shown in the setup example.

## Configure the provider

Place `SeamsWebProvider` above the components that call `useSeams`.

<<< ./setup.tsx

`seamsTestnetConfig` takes the three values a wallet cannot start without and
defaults the rest — wallet service path, SDK base path, relayer account, and
chain RPC and explorer URLs. The example reads `VITE_WALLET_ORIGIN`,
`VITE_RELAYER_URL`, and `VITE_SEAMS_PUBLISHABLE_KEY` from the app environment;
use your own values in each deployment, and `defineSeamsConfig` when you are not
on testnet.

## Register with a passkey

Render `CreateWalletButton` or call `createPasskeyWallet` from your own
registration screen.

<<< ./registration.tsx

`RegistrationResult` is a typed union. A successful registration can be ready
immediately or can report pending NEAR provisioning; keep the branch handling
before reading a chain-specific capability. For the pending branch, await
`seams.registration.awaitNearReady({ walletId })` rather than polling
`getNearProvisioningState` yourself.

## Unlock an existing wallet

Pass the wallet id from your app's account record to `unlockWallet`.

<<< ./unlock.ts

The successful result creates the wallet session used by signing and export
flows. Handle both `near_wallet_unlocked` and `ecdsa_wallet_unlocked` branches
when the app supports both key families.

## Authenticate with Google Email OTP

Use the Google ID token from your identity provider, then collect the OTP in
your own UI.

<<< ./email-otp.ts

`startGoogleEmailOtpLogin` requires an existing wallet login flow. If the
account needs registration, the helper cancels the login flow and reports that
state so the app can send the person through registration first.

## Expected result

Registration returns a wallet id and its ready or pending capabilities. Unlock
returns a wallet session result with the chain identity that is ready to use.
Email OTP returns the authenticated login result after the code is accepted.

## Recoverable failures

- A cancelled passkey or OTP prompt ends the current attempt. Let the person
  start it again from the same screen.
- A failed registration or unlock result includes an error string. Display a
  concise message and keep the wallet id when the result includes one.
- A Google login flow in registration mode should continue through the
  registration screen instead of retrying login with the same wallet state.
- An expired or depleted session needs a fresh unlock before signing or export.

Read next: [signing](/examples/signing), [advanced wallet operations](/examples/advanced-wallet-operations), or [results and errors](/reference/results-and-errors).
