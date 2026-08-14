---
title: Create a wallet
description: Register a passkey wallet and handle ready, pending, and failed results.
---

# Create a wallet

Call `registerPasskey` from a user-initiated action. The SDK opens the passkey
prompt, reports progress, and returns a discriminated result that tells you
which capability is ready.

## Register a passkey wallet

Use the hook when your product owns the registration button and result UI.
Render `CreateWalletButton` inside the `SeamsWebProvider` from [Start
here](/).

<<< ../examples/registration.tsx

The example keeps the event callback small and handles every
`RegistrationResult` branch with an exhaustive switch. Adapt the button and
message copy to your app instead of reading branch-specific fields before the
branch check.

## Read the result

- `wallet_registered` means the wallet and its returned capabilities are ready.
- `ecdsa_wallet_registered_near_pending` means the EVM-family capability is
  ready while NEAR provisioning is pending or retryable.
- `near_wallet_registered_pending` means NEAR provisioning still needs to
  reach a ready state before you read a NEAR account.
- `wallet_signer_added` means a signer was added to an existing wallet.
- `success: false` contains the error text to show or log for the current
  attempt.

The returned `walletId` is the stable wallet identifier used by unlock and
other wallet-scoped operations. Keep it with your application account record;
never store passkey or holder secrets in application state.

## If registration stops

Passkey cancellation ends the current attempt. Let the person start a new
attempt from the same button. A retryable NEAR provisioning result keeps the
wallet identity, so query
`seams.registration.getNearProvisioningState({ walletId })` before offering a
retry instead of registering a second wallet. Origin, publishable-key, and
authentication errors require configuration or account changes before retrying.

## Continue

[Unlock the wallet and sign an operation](/getting-started/sign-with-policy).
