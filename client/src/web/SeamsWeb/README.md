# SeamsWeb

`web/SeamsWeb` is the browser facade. It owns browser-only configuration,
wallet iframe routing, browser runtime assembly, web auth/session orchestration,
and app-facing signing capabilities.

## Boundary

This directory may import browser platform adapters, wallet iframe modules, DOM
UI helpers, and web asset helpers. Platform-neutral runtime code must live under
`core/runtime`, and chain signer modules should expose local runtime operations
that this facade can route through direct browser execution or wallet iframe
execution.

## Assembly

Browser assembly lives under `web/SeamsWeb/assembly/`:

- browser `PlatformRuntime` construction;
- browser store adapter construction;
- worker warmup policy;
- wallet iframe router and overlay state construction;
- wallet asset preconnect and SDK-base handling.

Keep new browser policy in assembly modules when it is needed to construct the
facade, and keep operation-specific code in the relevant capability module.
