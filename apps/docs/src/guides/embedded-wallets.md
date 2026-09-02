---
title: Embedded wallets
description: Integrate the Seams wallet iframe while keeping credential, worker, and key operations on the wallet origin.
---

# Embedded wallets

Start with [Wallet setup and authentication](/examples/wallet-setup-and-authentication)
to see the provider configuration. An embedded wallet renders in your product
while its credential and signing runtime stays on a dedicated HTTPS origin.

Use an embedded wallet when your application needs a persistent wallet for each
user: a marketplace balance, trading account, game inventory, payout account,
stablecoin account, reward balance, or automated onchain authority. A store
collecting a one-time payment from an existing wallet usually does not need to
provision another wallet for that shopper.

Read [platform wallets](/use-cases/platform-wallets) for the customer fit and
product boundary.

## Configure the boundary

- Deploy the wallet service and SDK assets at the wallet origin.
- Allow the application origin and use a matching RP ID.
- Set the project environment, publishable key, and network identity together.
- Configure a relayer or Router endpoint for each selected flow.
- Keep `iframeWallet.walletOrigin`, `walletServicePath`, and `sdkBasePath`
  aligned with the deployed assets.

The application must not mirror wallet service or SDK assets under its own
origin.

## Check before launch

- Registration opens user presence inside the wallet-origin surface.
- Signing preserves the exact wallet identity through the session and account or
  chain reference.
- Reject unexpected message origins and stale iframe sessions.
- Review [hosted integration](/deploy-and-operate/hosted-integration) and
  [security boundaries](/deploy-and-operate/security-boundaries) before launch.
