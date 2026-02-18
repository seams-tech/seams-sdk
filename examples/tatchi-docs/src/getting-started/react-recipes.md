---
title: React Recipes
---

# React Recipes

These examples assume you’ve already wrapped your app in `TatchiPasskeyProvider` as shown in the [installation](../getting-started/installation.md) guide.

The SDK provides pre-built React components which hooks up a lot of the functionality
exposed by the `TatchiPasskeyManager`.

```tsx
import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react/provider'

const config = {
  iframeWallet: { walletOrigin: 'https://wallet.web3authn.org' },
  relayer: {
    url: 'https://relay.tatchi.xyz',
  },
}

function Root() {
  return (
    <TatchiPasskeyProvider config={config}>
      <App />
    </TatchiPasskeyProvider>
  )
}
```

## Color Theming API

The SDK’s color theming is driven by `TatchiPasskeyProvider` and the `appearance.tokens` shape.

Theme precedence (highest to lowest):
1. `theme.tokens` passed to `TatchiPasskeyProvider`
2. `config.appearance.tokens`
3. built-in SDK defaults

### 1) Set default light/dark colors in config

Use `config.appearance` for app-wide defaults.

```tsx
import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react/provider'

const config = {
  appearance: {
    theme: 'dark',      // default mode at startup
    palette: 'default', // current public palette name
    tokens: {
      light: {
        colors: {
          colorBackground: '#fdf6e3',
          surface: '#eee8d5',
          textPrimary: '#586e75',
          primary: '#268bd2',
          borderPrimary: '#93a1a1',
          gradientTertiary: 'linear-gradient(120deg, #eee8d5 0%, #fdf6e3 100%)',
        },
      },
      dark: {
        colors: {
          colorBackground: '#002b36',
          surface: '#073642',
          textPrimary: '#93a1a1',
          primary: '#268bd2',
          borderPrimary: '#586e75',
          gradientTertiary: 'linear-gradient(120deg, #002b36 0%, #073642 100%)',
        },
      },
    },
  },
  iframeWallet: { walletOrigin: 'https://wallet.web3authn.org' },
  relayer: { url: 'https://relay.tatchi.xyz' },
}

function Root() {
  return (
    <TatchiPasskeyProvider config={config}>
      <App />
    </TatchiPasskeyProvider>
  )
}
```

### 2) Control theme mode from React and override colors at runtime

Use the `theme` prop when your app owns light/dark state.

```tsx
import * as React from 'react'
import { TatchiPasskeyProvider } from '@tatchi-xyz/sdk/react/provider'

export function Root() {
  const [theme, setTheme] = React.useState<'light' | 'dark'>('dark')

  return (
    <TatchiPasskeyProvider
      config={config}
      theme={{
        theme,
        setTheme,
        tokens: {
          light: { colors: { primary: '#2563eb' } },
          dark: { colors: { primary: '#60a5fa' } },
        },
      }}
    >
      <App />
    </TatchiPasskeyProvider>
  )
}
```

### 3) Read and switch theme from components

`useTheme()` exposes the active mode and optional setter.

```tsx
import { useTheme } from '@tatchi-xyz/sdk/react'

export function ThemeToggle() {
  const { theme, setTheme, isDark } = useTheme()

  return (
    <button
      onClick={() => setTheme?.(isDark ? 'light' : 'dark')}
      aria-label="Toggle theme"
    >
      Current: {theme}
    </button>
  )
}
```

### 4) Token-to-CSS mapping

Color token names are exposed as CSS custom properties:
- `colors.primary` -> `--w3a-colors-primary`
- `colors.colorBackground` -> `--w3a-colors-colorBackground`
- `colors.textPrimary` -> `--w3a-colors-textPrimary`
- `colors.gradientPrimary` -> `--w3a-colors-gradientPrimary`

You can provide any subset of these keys in `appearance.tokens.light.colors` and `appearance.tokens.dark.colors`.
Unspecified keys fall back to SDK defaults.

Full `colors` token keys:

```ts
const ALL_COLOR_TOKEN_KEYS = [
  'primary',
  'primaryHover',
  'secondary',
  'secondaryHover',
  'accent',
  'textPrimary',
  'textSecondary',
  'textMuted',
  'textButton',
  'buttonBackground',
  'buttonHoverBackground',
  'colorBackground',
  'surface',
  'surface2',
  'surface3',
  'surface4',
  'hover',
  'active',
  'focus',
  'success',
  'warning',
  'error',
  'info',
  'borderPrimary',
  'borderSecondary',
  'borderHover',
  'gradientPrimary',
  'gradientSecondary',
  'gradientTertiary',
  'grey25',
  'grey50',
  'grey75',
  'grey100',
  'grey200',
  'grey300',
  'grey400',
  'grey500',
  'grey600',
  'grey650',
  'grey700',
  'grey750',
  'grey800',
  'grey850',
  'grey900',
  'grey950',
  'slate25',
  'slate50',
  'slate75',
  'slate100',
  'slate150',
  'slate200',
  'slate300',
  'slate400',
  'slate500',
  'slate600',
  'slate700',
  'slate800',
  'slate900',
  'highlightReceiverId',
  'highlightMethodName',
  'highlightAmount',
] as const
```

This lets app CSS and SDK components share one color system:

```css
.cta {
  background: var(--w3a-colors-primary);
  color: var(--w3a-colors-textButton);
  border: 1px solid var(--w3a-colors-borderPrimary);
}
```

## PasskeyAuthMenu – register / login / sync

`PasskeyAuthMenu` is a ready‑made registration/login/account-sync menu that wires into the passkey flows exposed by `useTatchi`.

```tsx
import {
  useTatchi,
  AuthMenuMode,
  type RegistrationSSEEvent,
  type DeviceLinkingSSEEvent,
} from '@tatchi-xyz/sdk/react'
import { PasskeyAuthMenu } from '@tatchi-xyz/sdk/react/passkey-auth-menu'

export function PasskeySection() {
  const {
    tatchi,
    accountInputState,
    registerPasskey,
    loginAndCreateSession,
  } = useTatchi()

  const targetAccountId = accountInputState.targetAccountId
  const accountExists = accountInputState.accountExists

  const onRegister = () =>
    registerPasskey(targetAccountId, {
      onEvent: (event: RegistrationSSEEvent) => {
        console.log('registration event', event)
      },
    })

  const onLogin = () =>
    loginAndCreateSession(targetAccountId, {
      onEvent: (event) => {
        console.log('login event', event)
      },
    })

  const onSyncAccount = () =>
    tatchi.recovery.syncAccount({
      accountId: targetAccountId,
      options: {
        onEvent: (event) => console.log('sync event', event),
        onError: (error) => console.error('sync error', error),
      },
    })

  const onLinkDeviceEvent = (event: DeviceLinkingSSEEvent) => {
    console.log('link-device event', event)
  }

  return (
    <PasskeyAuthMenu
      defaultMode={accountExists ? AuthMenuMode.Login : AuthMenuMode.Register}
      onLogin={onLogin}
      onRegister={onRegister}
      onSyncAccount={onSyncAccount}
      emailRecoveryOptions={{
        onEvent: (event) => console.log('email-recovery event', event),
        onError: (error) => console.error('email-recovery error', error),
      }}
      linkDeviceOptions={{
        onEvent: onLinkDeviceEvent,
        onError: (error) => console.error('link-device error', error),
      }}
    />
  )
}
```

`onSyncAccount` covers passkey-based account sync (e.g. iCloud/Google Password Manager passkey sync). Email-based recovery is built in to the menu via “Recover Account with Email” and emits events through `emailRecoveryOptions`.

## AccountMenuButton – account menu + device linking

`AccountMenuButton` shows the current account, lets users export keys, link devices, toggle theme, and adjust confirmation settings.

```tsx
import {
  useTatchi,
  DeviceLinkingPhase,
  DeviceLinkingStatus,
} from '@tatchi-xyz/sdk/react'
import { AccountMenuButton } from '@tatchi-xyz/sdk/react/profile'

export function HeaderProfile() {
  const { loginState } = useTatchi()

  if (!loginState.isLoggedIn || !loginState.nearAccountId) {
    return null
  }

  return (
    <header className="app-header">
      <AccountMenuButton
        nearAccountId={loginState.nearAccountId}
        hideUsername={false}
        onLogout={() => {
          console.log('User logged out')
        }}
        deviceLinkingScannerParams={{
          fundingAmount: '0.05',
          onDeviceLinked: (result) => {
            console.log('Device linked:', result)
          },
          onEvent: (event) => {
            if (event.phase === DeviceLinkingPhase.STEP_7_LINKING_COMPLETE &&
                event.status === DeviceLinkingStatus.SUCCESS) {
              console.log('Device linking complete')
            }
          },
          onError: (error) => {
            console.error('Device linking error:', error)
          },
        }}
      />
    </header>
  )
}
```

## Transactions – custom button

```tsx
import {
  useTatchi,
  ActionType,
  TxExecutionStatus,
} from '@tatchi-xyz/sdk/react'

export function SendGreetingButton() {
  const { tatchi, loginState } = useTatchi()

  if (!loginState.isLoggedIn || !loginState.nearAccountId) {
    return null
  }

  const nearAccountId = loginState.nearAccountId
  const contractId = tatchi.configs.contractId

  return (
    <button
      onClick={async () => {
        await tatchi.near.executeAction({
          nearAccountId,
          receiverId: contractId,
          actionArgs: {
            type: ActionType.FunctionCall,
            methodName: 'set_greeting',
            args: { greeting: 'Hello from Tatchi!' },
            gas: '30000000000000',
            deposit: '0',
          },
          options: {
            confirmationConfig: { uiMode: 'drawer' },
            waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
            afterCall: (success, result) => {
              if (success) console.log('Tx result', result)
              else console.warn('Tx failed', result)
            },
            onError: (error) => console.error('Tx error', error),
          },
        })
      }}
      style={{
        color: 'white',
        background: 'var(--w3a-colors-primary)',
        borderRadius: '2rem',
        border: 'none',
        height: 44,
        paddingInline: 24,
      }}
    >
      Send Greeting
    </button>
  )
}
```

From here you can refine styling and hook `onEvent` into your own toast/notification system.
The setup above is enough to get end‑to‑end passkey registration, login, and transaction signing with React components.
