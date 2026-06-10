# SeamsWeb

`SeamsWeb` is the browser facade. The folder layout mirrors the call graph:

```text
app code
  -> facade
    -> publicApi
      -> operations
        -> signingSurface
          -> core/runtime
            -> core/platform
```

## Boundary

This directory may import browser platform adapters, wallet iframe modules, DOM
UI helpers, and web asset helpers. `core/**` must not import this directory.
Move shared result types, config types, and browser bridge constants into core
when core logic needs them.

iOS and embedded SDK implementations live outside this TypeScript package: iOS
ships as a Swift package, and embedded ships as a Rust crate. Do not add
`SeamsIOS`, `SeamsEmbedded`, or native signing-surface scaffolds under
`client/src`.

## Layout

- `index.ts` is the public barrel.
- `SeamsWeb.ts` owns `new SeamsWeb(...)`, config normalization, and lifecycle
  wiring. `publicApi/createPublicApi.ts` assembles the user-facing API objects.
  `index.ts` remains a barrel.
- `publicApi/` owns the concrete user-facing task API objects exposed as
  `seams.auth`, `seams.registration`, `seams.near`, `seams.evm`, `seams.tempo`,
  `seams.recovery`, `seams.devices`, `seams.keys`, and `seams.preferences`.
  The name describes the product boundary; `namespaces` only describes the
  TypeScript shape.
- `operations/` owns local browser operation implementations grouped by user
  task.
- `signingSurface/` owns the browser signing surface implementation and its
  internal signing-surface slice types.
- `assembly/` owns browser runtime construction, store construction, worker
  warmup, preconnect, and browser-only dependency wiring.
- `walletIframe/` owns the browser wallet iframe implementation.
- `core/browser/walletIframe/` owns shared browser-platform primitives used by
  core and web, such as DOM event names, CSP stylesheet helpers, host-mode
  state, and host variant config. It must not grow into wallet iframe routing,
  host runtime, overlay, or facade code.

## Assembly

Browser assembly lives under `SeamsWeb/assembly/`:

- browser `RuntimePorts` construction;
- browser store adapter construction;
- worker warmup policy;
- wallet iframe router and overlay state construction;
- wallet asset preconnect and SDK-base handling.

Keep new browser policy in assembly modules when it is needed to construct the
facade, and keep operation-specific code under `operations/`.
