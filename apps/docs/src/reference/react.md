---
title: React SDK
description: Providers, hooks, components, hosted auth surfaces, and theme exports available from @seams/wallet/react.
---

# React SDK

Import React integrations from `@seams/wallet/react` and place consumers inside a
`SeamsWebProvider` or `SeamsContextProvider`.

```tsx [Import example]
import { SeamsWebProvider, SeamsAuthMenu, useSeams } from '@seams/wallet/react';
```

## Providers and hooks

| Export                                            | Purpose                                                 |
| ------------------------------------------------- | ------------------------------------------------------- |
| `SeamsWebProvider`                                | Creates and owns the SDK client for a React subtree.    |
| `SeamsContextProvider`                            | Supplies an existing context value.                     |
| `useSeams`                                        | Reads the current SDK capabilities and lifecycle state. |
| `useWallet`                                       | The signed-in wallet, with signing bound to it.         |
| `useWalletAuth`                                   | The sign-in, sign-out, and registration slice.          |
| `useWalletDevices`                                | The linked-device slice.                                |
| `useDeviceLinking`                                | Runs the approving-device side of a link flow.          |
| `useNearClient`, `useAccountInput`, `useQRCamera` | Focused integration helpers.                            |

### `useWallet`

Returns `{ status, wallet, near, evm, tempo, walletId, nearAccountId }`.
`near`, `evm`, and `tempo` are lifted to the top level so the common path is a
single check:

```tsx [Partial example]
const { near } = useWallet();
if (!near) return <SignInButton />;

await near.signAndSendTransaction({
  receiverId: 'guest-book.testnet',
  actions: [functionCall({ method: 'set_greeting', args: { greeting: 'hi' } })],
});
```

`near` is `null` both when nobody is signed in and when the signed-in wallet has
no NEAR account. Read `status` — `'signed_out' | 'no_near_account' | 'ready'` —
when the UI needs to say something different about each.

`useWalletAuth` and `useWalletDevices` are views over the same context, not a
second one; `useSeams` still exposes everything.

## Components

The stable surface includes `SeamsAuthMenu`, `HostedSeamsAuthMenu`,
`AccountMenuButton`, `ProfileSettingsButton`, `QRCodeScanner`, and `ShowQRCode`.
Use the hosted auth menu when the wallet-origin boundary owns the complete auth
experience.

Focused entrypoints are available for applications that need smaller or
SSR-specific imports:

- `@seams/wallet/react/provider`;
- `@seams/wallet/react/profile`;
- `@seams/wallet/react/seams-auth-menu` plus `/client`, `/skeleton`, and `/preload`;
- `@seams/wallet/react/hosted-seams-auth-menu`;
- `@seams/wallet/react/styles`.

## Appearance

`Theme`, `useTheme`, `LIGHT_TOKENS`, `DARK_TOKENS`, and `SHAPE_PRESETS` style
app-owned React surfaces. Send the corresponding appearance into the browser
SDK for wallet-iframe surfaces. See the [theming guide](/guides/theming).

## React boundary

Keep credential prompts and signing actions attached to a direct user action.
Render loading, success, cancelled, and recoverable failure branches from the
result union instead of collapsing them into a Boolean.
