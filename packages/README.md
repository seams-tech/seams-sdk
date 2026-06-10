# TypeScript Packages

This directory owns reusable TypeScript package source.

- `sdk-web`: browser SDK package source for `SeamsWeb`, React, browser plugins,
  browser storage, wallet iframe, and web build scripts.
- `sdk-runtime-ts`: platform-neutral runtime entrypoint. The current runtime
  source still depends on the existing signing core in `sdk-web/src/core` while
  that dependency closure is being narrowed.
- `sdk-server-ts`: server library source for route adapters, verification
  policy, storage adapters, and server wasm bindings.
- `shared-ts`: shared protocol and domain utilities consumed by web, runtime,
  server, apps, and tests.
