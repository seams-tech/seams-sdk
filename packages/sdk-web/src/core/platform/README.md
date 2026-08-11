# Core Platform

`core/platform` defines the TypeScript runtime port contract used by browser SDK
signing services. A runtime port bundle supplies storage, secret handling,
authenticator assertions, signer-core execution, HTTP transport, time, and
randomness without letting core signing code import browser implementations.

## Branches

- `browser/`: web implementation backed by browser APIs and browser signing
  workers.
- `embedded/`: device-local runtime notes for the separate Rust embedded SDK.
- `generated/`: signer-core command schemas generated from Rust.

## Rules

- Parse raw platform responses once at the adapter boundary.
- Keep browser storage and DOM APIs inside `browser/`.
- Keep embedded SDK implementation code out of this package; it is distributed
  through Cargo.
- Add TypeScript runtime ports only for browser SDK or TypeScript test/runtime
  behavior.
