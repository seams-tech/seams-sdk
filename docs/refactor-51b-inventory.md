# Refactor 51b Current Inventory

Date updated: 2026-06-04
Owner: SDK architecture
Parent plan: `docs/refactor-51b-cross-platform-3.md`

## Remaining Coupling

| Area | Current state | Remaining trigger |
| --- | --- | --- |
| Signing composition root | `SigningEngine` is a transitional web wrapper around manager assembly, browser store wiring, and the first `SigningRuntime` service. | Delete the wrapper once public web capabilities call grouped runtime services directly. |
| Browser platform barrel | `client/src/core/platform/index.ts` still exports browser adapter helpers for web assembly consumers. | Native-facing package entries must continue to avoid this barrel; browser assembly may import browser helpers directly. |
| Wallet iframe tree | `client/src/core/WalletIframe/**` remains a browser-only implementation tree, exposed publicly only through a web-owned package path. | Native, embedded, and core runtime roots must never import it. |

## Guard Ownership

| Guard | Scope |
| --- | --- |
| `refactor51bSeamsWebRename.guard.unit.test.ts` | Active source, tests, and package metadata must not reintroduce `SeamsPasskey`, `PasskeyManagerContext`, `SeamsPasskeyProvider`, or `SeamsPasskeyIframe`; historical mentions are confined to refactor docs and the guard fixture. |
| `refactor51bPlatformBoundaries.guard.unit.test.ts` | Core runtime stays free of browser surfaces; signing use cases stay free of IndexedDB persistence implementations; native and embedded roots stay free of browser surfaces; web facade, React, plugins, and `core/WalletIframe` remain explicitly browser-owned. |
| `refactor51bPackageExports.unit.test.ts` | Package exports expose web, React, runtime types, iOS contract, embedded contract, server roots, and a web-owned WalletIframe HTML path. |
| `refactor51bNativeEntryBundles.unit.test.ts` | Emitted `./runtime`, `./ios`, and `./embedded` package entries cannot resolve to browser implementation modules. |
