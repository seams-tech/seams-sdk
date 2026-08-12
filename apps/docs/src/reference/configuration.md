---
title: Configuration
description: Configure hosted wallet isolation, registration, relaying, chains, and appearance with precise Seams SDK branches.
---

# Configuration

Build a `SeamsConfigsInput` at the application boundary. Require each value for
the deployment mode you select, and validate environment strings before passing
the object to the SDK.

## Hosted wallet branch

Use `iframeWallet` for the isolated wallet origin. Set the HTTPS
`walletOrigin`; keep `walletServicePath` and `sdkBasePath` aligned with the
assets deployed at that origin. `rpIdOverride` changes credential scope and
needs an explicit security review.

## Registration branch

Managed registration requires the project-environment identity and publishable
key issued for the current origin. Keep environment identities public and keep
server or custody secrets outside browser configuration.

## Network branch

Each chain record selects one supported network and its RPC and explorer URLs.
EVM-family chains also require their numeric chain identity. Signing later uses
an exact chain or account reference derived from this validated configuration.

## Relayer branch

Configure the relayer only when the chosen registration or relay flow uses it.
The app URL identifies the service; request authentication and custody secrets
stay at the server boundary.

## Appearance branch

Initial appearance belongs in configuration. Use `setAppearance` for runtime
theme changes. Keep the app-owned React theme and wallet-owned iframe appearance
on the same semantic palette.

See [environment variables](/deploy-and-operate/environment) for the browser and
server ownership split.
