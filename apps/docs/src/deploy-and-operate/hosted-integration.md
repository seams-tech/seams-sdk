---
title: Hosted integration
description: Serve the Seams wallet service and SDK runtime assets from a dedicated HTTPS wallet origin and connect an allowed application origin.
---

# Hosted integration

The product application imports `@seams/sdk`. A dedicated wallet origin serves
the wallet service, SDK support assets, workers, and export viewer used by the
isolated iframe.

## Required routes

Deploy the wallet service at the configured `walletServicePath` and runtime
assets at `sdkBasePath`. Preserve asset content types, cache immutable hashed
files, and prevent stale HTML from pinning an old runtime manifest.

The application configures the absolute HTTPS wallet origin. It should not
proxy wallet routes through the application origin or serve a second copy of
the runtime assets.

## Release verification

- Load the wallet service directly and confirm the expected release identity.
- Register and unlock from an allowed app origin.
- Verify that an unlisted origin is rejected.
- Exercise one signing confirmation, cancellation, and retryable failure.
- Confirm workers and WASM load under the production CSP.
- Confirm export content remains inside the wallet-origin viewer.

Use the published `@seams/sdk/web/wallet-iframe-client-html` asset only for the
supported hosted-wallet build path. Keep package code and hosted assets on the
same compatible release.
