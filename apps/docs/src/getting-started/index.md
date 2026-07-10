---
title: Getting Started
---

# Getting Started

Getting Started is wallet-focused first. The shortest path is to create an
embedded wallet, sign a user-approved intent, then add recovery, delegation, or
rotation as the product matures.

The same infrastructure can later support access passes, delegated credentials,
shipping agents, embedded devices, and other policy-bound applications.

## Wallet Path

```text
create wallet -> approve intent -> sign with policy -> audit
```

1. [Create A Wallet](/getting-started/create-wallet): register a wallet key and
   bind it to the user's auth method.
2. [Sign With Policy](/getting-started/sign-with-policy): request a wallet
   signature through a typed intent, Wallet Session, signing grant, and Router
   A/B.
3. [Delegate Or Rotate](/getting-started/delegate-or-rotate): add linked
   devices, issue delegated-agent lanes, refresh shares, export, or rekey under
   policy.

## Basic Setup

Wrap the app once with `SeamsWebProvider`.

```tsx
import { SeamsWebProvider, type SeamsConfigsInput } from '@seams/sdk/react';

const seamsConfig = {
  iframeWallet: {
    walletOrigin: import.meta.env.VITE_WALLET_ORIGIN,
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
  },
  relayerAccount: 'w3a-relayer.testnet',
  relayer: {
    url: import.meta.env.VITE_SEAMS_ROUTER_URL,
  },
  chains: [
    {
      network: 'near-testnet',
      rpcUrl: 'https://rpc.testnet.near.org',
      explorerUrl: 'https://testnet.nearblocks.io',
    },
  ],
} satisfies SeamsConfigsInput;

export function App() {
  return (
    <SeamsWebProvider config={seamsConfig}>
      <WalletApp />
    </SeamsWebProvider>
  );
}
```

## Other Applications

After the wallet path is clear, the same primitives can express other authority
models:

- [iPhone Access Passes](/getting-started/iphone-access-passes)
- [Shipping Agent Credentials](/getting-started/shipping-agent-credentials)
- [Embedded Device Credentials](/getting-started/embedded-device-credentials)

## Concepts To Read First

- [Architecture](/concepts/architecture)
- [Custody Model](/concepts/custody/)
- [Streaming Yao A/B](/concepts/threshold-signing/streaming-yao-ab)
- [Auth Methods](/concepts/auth-methods/)
