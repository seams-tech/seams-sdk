---
title: Examples
description: Start with a working Seams wallet, then add signing, recovery, device linking, exports, and theming.
---

# Examples

These examples are short paths you can copy into an application. Start with
the provider setup, register or unlock a wallet, then choose the operation your
product needs.

## Prerequisites

Install the SDK and configure the wallet origin, relayer, and registration
environment variables used by your app.

```sh
pnpm add @seams/sdk
```

<<< ./setup.tsx

The setup example keeps the provider at the application boundary. Render your
wallet UI inside `SeamsWebProvider`, then pass the `seams` instance and the
wallet identity into the operation examples.

## Choose an example

- [Set up a wallet and authenticate](/examples/wallet-setup-and-authentication)
  with passkeys, unlock, or Google Email OTP.
- [Sign transactions and messages](/examples/signing) on NEAR, with NEP-413,
  or on an EVM-family chain.
- [Manage advanced wallet operations](/examples/advanced-wallet-operations)
  with linked devices, recovery, and key export.
- [Customize wallet surfaces](/examples/ui-customization) across React and
  wallet-iframe UI.

## How to use the snippets

The `<<<` blocks import the canonical TypeScript examples from this directory.
Copy the function or component you need, then connect it to your own UI and
error reporting. Values such as `walletId`, `nearAccountId`, and Google ID
tokens come from your authenticated application state.

Every flow returns a typed success or failure result, or reports progress with
an event callback. Keep the branch handling in the examples when adapting them
so cancellation, policy denial, and expired sessions remain recoverable.

## Continue building

- [SDK reference](/reference/) for public types and entry points.
- [Results and errors](/reference/results-and-errors) for failure branches.
- [Events and progress](/reference/events-and-progress) for flow updates.
- [Concepts and security](/concepts/) when you need the protocol details
  behind a working integration.
