---
title: Embedded wallets
description: Integrate the Seams wallet iframe while keeping credential, worker, and key operations on the wallet origin.
---

# Embedded wallets

An embedded Seams wallet renders within the product while its credential and
signing runtime stays on a dedicated HTTPS origin.

## Prerequisites

- a deployed wallet service and SDK assets at the wallet origin;
- an allowed application origin;
- matching RP ID, project environment, publishable key, and network identity;
- a relayer or Router endpoint for the selected flows.

Configure `iframeWallet.walletOrigin` and keep the wallet service and SDK paths
aligned with the deployed assets. The application must not mirror those assets
under its own origin.

## Verify the boundary

Registration should open user presence inside the wallet-origin surface.
Signing should preserve the same exact wallet identity through the session and
account or chain reference. Reject unexpected message origins and stale iframe
sessions.

Continue with [hosted integration](/deploy-and-operate/hosted-integration) and
[origin and iframe boundaries](/deploy-and-operate/security-boundaries).
