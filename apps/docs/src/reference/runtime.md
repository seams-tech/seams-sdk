---
title: Custom signing runtime
description: Ports and factories exported from @seams/wallet/runtime for applications that own a complete signing runtime.
---

# Custom signing runtime

`@seams/wallet/runtime` is for hosts that supply the platform around the signing
engine. It is a lower-level integration than `SeamsWeb`.

The entrypoint exports `createSigningRuntime`,
`createSigningRuntimeStatePorts`, and types for the runtime configuration,
services, state ports, UI dependencies, and warm-session UI ports.

Platform responsibilities are explicit through ports for:

- authentication;
- time and randomness;
- HTTP transport;
- durable records and secure secrets;
- signer cryptography;
- runtime-specific UI.

Choose one `RuntimePortsKind` and provide the complete matching `RuntimePorts`
branch. Validate raw host data before constructing those ports. A custom runtime
also owns secure storage, cancellation, lifecycle restoration, and user-presence
semantics, so use the browser SDK unless those responsibilities are deliberate.

Read [architecture](/concepts/architecture) and [origin and iframe
boundaries](/deploy-and-operate/security-boundaries) first.
