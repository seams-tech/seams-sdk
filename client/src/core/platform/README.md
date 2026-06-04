# Core Platform

`core/platform` defines the adapter contract used by platform-neutral runtime
services. A platform adapter supplies storage, secret handling, authenticator
assertions, signer-core execution, HTTP transport, time, and randomness.

## Branches

- `browser/`: web implementation backed by browser APIs and browser signing
  workers.
- `ios/`: iOS RP ID and native adapter contract notes.
- `embedded/`: Linux/device adapter contract and embedded runtime type export.
- `generated/`: signer-core command schemas generated from Rust.

## Rules

- Parse raw platform responses once at the adapter boundary.
- Keep browser storage and DOM APIs inside `browser/`.
- Keep native and embedded roots free of web facade, React, wallet iframe, and
  IndexedDB imports.
- Add branch-specific runtime types when a platform has a concrete adapter
  contract, such as `EmbeddedPlatformRuntime`.
