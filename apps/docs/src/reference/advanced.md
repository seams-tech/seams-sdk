---
title: Advanced helpers
description: Low-level identity builders, RPC clients, encoding helpers, and Tempo utilities exported from @seams/wallet/advanced.
---

# Advanced helpers

`@seams/wallet/advanced` exposes low-level tools for integrations that already own
their lifecycle and trust boundaries.

```ts [Import example]
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfig,
  walletSessionRefFromSession,
} from '@seams/wallet/advanced';
```

## Identity builders

Use the exported builders to cross from validated application data into exact
SDK subjects:

- `toWalletId`;
- `walletSessionRefFromSession`;
- `nearAccountRefFromAccountId`;
- `thresholdEcdsaChainTargetFromConfig`;
- `walletIdFromWalletProfile`.

These builders preserve the relationship between wallet, session, account,
and chain. Construct the reference once, then pass it through the operation that
requires it.

## Other exports

The entrypoint also includes minimal NEAR and EVM RPC clients, transaction
encoding, base64url and hashing helpers, WebAuthn RP ID parsing, intent IDs,
threshold-session limits, and Tempo fee-token helpers.

These primitives expose more protocol detail and fewer product defaults. The
main SDK remains the preferred surface for registration, auth, signing,
recovery, and device flows.
