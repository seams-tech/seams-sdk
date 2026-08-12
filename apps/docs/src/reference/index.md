---
title: SDK reference
description: Choose the supported Seams SDK entrypoint for browser, React, threshold, advanced, or custom runtime integration.
---

# SDK reference

The Seams package exposes a small set of intentional entrypoints. Start with the
main browser surface or React surface. Reach for the lower-level entrypoints only
when your integration owns the corresponding runtime or protocol responsibility.

| Import path                                    | Use it for                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| [`@seams/sdk`](/reference/core)                | Browser SDK configuration, registration, authentication, signing, recovery, devices, and public result types. |
| [`@seams/sdk/react`](/reference/react)         | Providers, hooks, auth and profile components, QR flows, and theme tokens.                                    |
| [`@seams/sdk/advanced`](/reference/advanced)   | Exact identity builders, RPC clients, encoders, and other low-level integration helpers.                      |
| [`@seams/sdk/threshold`](/reference/threshold) | Stable threshold session-policy and cryptographic constants.                                                  |
| [`@seams/sdk/runtime`](/reference/runtime)     | Building a custom signing runtime from explicit platform ports.                                               |

The package also publishes focused React component subpaths and the hosted
wallet HTML asset. Those surfaces are documented on the [React
reference](/reference/react) and [hosted integration](/deploy-and-operate/hosted-integration)
pages.

## State and failure references

- [Configuration](/reference/configuration)
- [Results and recoverable errors](/reference/results-and-errors)
- [Events and progress](/reference/events-and-progress)

Public reference pages describe exported package surfaces. Internal source
modules and storage records are implementation details and can change without a
public migration path.
