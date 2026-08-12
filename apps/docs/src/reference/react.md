---
title: React SDK
description: Providers, hooks, components, hosted auth surfaces, and theme exports available from @seams/sdk/react.
---

# React SDK

Import React integrations from `@seams/sdk/react` and place consumers inside a
`SeamsWebProvider` or `SeamsContextProvider`.

```tsx [Import example]
import { SeamsWebProvider, SeamsAuthMenu, useSeams } from '@seams/sdk/react';
```

## Providers and hooks

| Export                                            | Purpose                                                  |
| ------------------------------------------------- | -------------------------------------------------------- |
| `SeamsWebProvider`                                | Creates and owns the SDK client for a React subtree.     |
| `SeamsContextProvider`                            | Supplies an existing context value.                      |
| `useSeams`                                        | Reads the current SDK capabilities and lifecycle state.  |
| `useDeviceLinking`                                | Runs the approving-device side of a link flow.           |
| `useGoogleEmailOtpWalletAuth`                     | Coordinates the public Google and email OTP wallet flow. |
| `useNearClient`, `useAccountInput`, `useQRCamera` | Focused integration helpers.                             |

## Components

The stable surface includes `SeamsAuthMenu`, `HostedSeamsAuthMenu`,
`AccountMenuButton`, `ProfileSettingsButton`, `QRCodeScanner`, and `ShowQRCode`.
Use the hosted auth menu when the wallet-origin boundary owns the complete auth
experience.

Focused entrypoints are available for applications that need smaller or
SSR-specific imports:

- `@seams/sdk/react/provider`;
- `@seams/sdk/react/profile`;
- `@seams/sdk/react/seams-auth-menu` plus `/client`, `/skeleton`, and `/preload`;
- `@seams/sdk/react/hosted-seams-auth-menu`;
- `@seams/sdk/react/styles`.

## Appearance

`Theme`, `useTheme`, `LIGHT_TOKENS`, `DARK_TOKENS`, and `SHAPE_PRESETS` style
app-owned React surfaces. Send the corresponding appearance into the browser
SDK for wallet-iframe surfaces. See the [theming guide](/guides/theming).

## React boundary

Keep credential prompts and signing actions attached to a direct user action.
Render loading, success, cancelled, and recoverable failure branches from the
result union instead of collapsing them into a Boolean.
