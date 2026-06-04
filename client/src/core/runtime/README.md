# Core Runtime

`core/runtime` is the platform-neutral signing composition root. It builds
runtime services from injected `PlatformRuntime` capabilities, relayer clients,
UI ports, config, and explicit state ports.

## Boundary

This directory must not import browser adapters, wallet iframe modules, React,
DOM globals, or IndexedDB implementations. Browser, iOS, and embedded packages
construct platform adapters outside this directory, then pass the finished
`PlatformRuntime` into `createSigningRuntime(...)`.

## Current Services

- `createSigningRuntime(...)` wires runtime services from narrow dependencies.
- `createSigningRuntimeStatePorts(...)` creates in-memory runtime state maps that
  adapters can replace or persist through explicit state ports.
- ECDSA provisioning lives on `runtime.services.ecdsaProvisioning`.

Add new services here only after their dependencies can be expressed through
platform-neutral ports.
