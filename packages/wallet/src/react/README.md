# React Entrypoint

`react` exposes the browser React integration for SeamsWeb. The public package
root is `@seams/sdk/react`.

## Exports

- `SeamsWebProvider` composes the SeamsWeb instance with theme and wallet iframe
  lifecycle wiring.
- Hooks expose browser app state, registration, login, signing, recovery, device
  linking, QR scanning, and preferences.
- Components in this tree are browser UI components and may depend on React,
  browser events, and SeamsWeb context.

## Boundary

React modules must not become dependencies of `core/runtime`, native roots, or
embedded roots. Shared domain types belong in `core/types`, `shared`, or
platform-neutral runtime modules, then this entrypoint can re-export them for
React consumers.
