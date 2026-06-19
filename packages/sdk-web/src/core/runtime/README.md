# Core Runtime

`core/runtime` is the TypeScript signing composition root. It builds runtime
services from injected `RuntimePorts` capabilities, relayer clients, UI
ports, config, and explicit state ports.

## Boundary

This directory must not import browser adapters, wallet iframe modules, React,
DOM globals, or IndexedDB implementations. Browser assembly constructs the
browser `RuntimePorts` outside this directory, then passes the finished ports
into `createSigningRuntime(...)`.

The iOS SDK is a separate Swift package and the embedded SDK is a separate Rust
crate. They bind to Rust signer-core directly instead of importing this
TypeScript runtime directory.

## Current Services

- `createSigningRuntime(...)` wires runtime services from narrow dependencies.
- `createSigningRuntimeStatePorts(...)` creates in-memory runtime state maps that
  adapters can replace or persist through explicit state ports.
- ECDSA provisioning lives on `runtime.services.ecdsaProvisioning`.

Add new services here only after their dependencies can be expressed through
runtime ports that keep browser implementation details out of core signing code.
