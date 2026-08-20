---
title: Configuration
description: Configure hosted wallet isolation, registration, relaying, chains, and appearance with precise Seams SDK branches.
---

# Configuration

Build the configuration at the application boundary with `defineSeamsConfig`,
or `seamsTestnetConfig` for the NEAR and Tempo testnets. Both take the values a
wallet cannot start without and default everything else, and both make those
values required at the type level:

```ts [Partial example]
import { seamsTestnetConfig } from '@seams/wallet/react';

const config = seamsTestnetConfig({
  walletOrigin: import.meta.env.VITE_WALLET_ORIGIN,
  relayerUrl: import.meta.env.VITE_RELAYER_URL,
  publishableKey: import.meta.env.VITE_SEAMS_PUBLISHABLE_KEY,
});
```

`SeamsConfigsInput` remains available for a hand-built object; every field on it
is optional, so prefer the helpers unless you are constructing a partial config
for a custom runtime.

## Hosted wallet branch

Use `iframeWallet` for the isolated wallet origin. Set the HTTPS
`walletOrigin`; keep `walletServicePath` and `sdkBasePath` aligned with the
assets deployed at that origin. `rpIdOverride` changes credential scope and
needs an explicit security review.

## Registration branch

Managed registration requires the `publishableKey` issued for the current
origin. The key identifies the environment on its own — its record carries the
environment it belongs to, and the Router API builds the runtime policy scope
from the authenticated key.

`projectEnvironmentId` is an optional cross-check. Supply it when one build can
be pointed at staging or production by configuration: a key belonging to a
different environment is then rejected instead of silently working.

Keep environment identities public and keep server or custody secrets outside
browser configuration.

## Network branch

Each chain record selects one supported network; `rpcUrl` and `explorerUrl` are
optional and fall back to the SDK defaults, which carry working testnet
endpoints and RPC failover for NEAR. EVM-family chains also need their numeric
chain identity.

Signing names a chain from this configuration by network slug. The RPC endpoint
used at execution time is resolved from the configured chain, never from the
signing call.

## Relayer branch

Configure the relayer only when the chosen registration or relay flow uses it.
The app URL identifies the service; request authentication and custody secrets
stay at the server boundary.

Leave `relayerAccount` unset. It is the NEAR parent under which the Router API
creates named subaccounts (`alice` becomes `alice.<relayerAccount>`) and the
postfix the account-name input displays — not a delegated-signing credential.
Unset, the SDK discovers it from the relayer's `/healthz` response, so it always
matches the server. Setting it pins a value and skips that discovery, in which
case it must match.

## Appearance branch

Initial appearance belongs in configuration. Use `setAppearance` for runtime
theme changes. Keep the app-owned React theme and wallet-owned iframe appearance
on the same semantic palette.

See [environment variables](/deploy-and-operate/environment) for the browser and
server ownership split.
