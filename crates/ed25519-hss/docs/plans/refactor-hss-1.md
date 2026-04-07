# Ed25519 HSS Refactor 1

Date updated: April 7, 2026

## Summary

This note records the first major boundary-first refactor of
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

It is historical, not a forward-looking plan.

The purpose of this refactor was to make the crate structure match the actual
role and wire boundaries of the protocol, so future reviews could answer these
questions directly from the module tree:

- what is client-only
- what is server-only
- what is allowed to cross the wire
- where shared protocol rules live
- where runtime adapters stop and protocol ownership begins

This refactor was the structural groundwork for the later boundary hardening
and staged execution cleanup recorded in
[docs/plans/refactor-hss-boundary.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/refactor-hss-boundary.md).

## Why It Was Done

Before this refactor, too much of the crate surface was mixed together:

- role-private state and wire payloads were too close together
- prepared-session logic, transcript/report logic, and role APIs were not
  clearly separated
- the top-level surface was too flat, which made secret-flow review harder than
  it should have been

The protocol docs already implied clearer boundaries:

- client = evaluator
- server = garbler
- OT handles private input delivery
- HSS handles hidden computation after input delivery
- wire-visible payloads should be distinct from role-private state

Refactor 1 made the code structure reflect those boundaries.

## What Landed

The crate was reorganized into a boundary-oriented module tree:

```text
crates/ed25519-hss/src/
  shared/
  wire/
  client/
  server/
  protocol/
  ddh/
  artifact/
  runtime/
  benchmark/
```

That split established these ownership rules:

- `shared/`
  - common context, labels, reference math, shared errors
- `wire/`
  - the only cross-boundary envelopes and serialization types
- `client/`
  - evaluator-side logic and client-private state
- `server/`
  - garbler-side logic and server-private state
- `protocol/`
  - transcript rules, prepared-session helpers, invariants, reports
- `ddh/` and `artifact/`
  - the hidden-eval engine and artifact/compiler implementation
- `runtime/`
  - wasm/native adapters around the role APIs

This was the important architectural outcome:

- the crate stopped reading like one large mixed protocol implementation
- the role model became visible in the code layout
- boundary review became much easier

## Public Surface Direction That Landed

The refactor also pushed the crate toward explicit module ownership instead of
flat top-level reexports.

The intended usage became:

- `ed25519_hss::client::...`
- `ed25519_hss::server::...`
- `ed25519_hss::wire::...`
- `ed25519_hss::shared::...`

That breaking cleanup was intentional. The point was to make ownership obvious
from the path itself.

## Runtime Split That Followed

This module split was not just cosmetic. It enabled the runtime split that
followed:

- browser/client HSS runtime:
  [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- relay/server HSS runtime:
  [wasm/near_signer/pkg-server](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg-server)

That runtime separation became permanent because it materially reduced the
browser artifact:

- original broad browser HSS wasm:
  `1,163,476` bytes
- dedicated browser HSS wasm after the split:
  `472,527` bytes
- original broad browser HSS JS glue:
  `173,004` bytes
- dedicated browser HSS JS glue after the split:
  `18,414` bytes

Later work shrank the browser artifact much further, but this refactor was the
first structural step that made that possible.

## Naming And Ownership Rules Established

Refactor 1 also established the naming and ownership conventions that later
refactors relied on:

- `Client*`
  - evaluator-private state and client-facing APIs
- `Server*`
  - garbler-private state and server-facing APIs
- `Wire*` or types under `wire::`
  - boundary-crossing payloads only
- `Shared*`, `Prepared*`, `Evaluate*`
  - shared or protocol-level objects where ownership is already clear from the
    module path

That convention reduced ambiguity in later boundary reviews.

## What This Refactor Did Not Solve

Refactor 1 improved structure, not the final security model.

It did not by itself solve:

- the later `ServerInputsPacket` client-boundary problem
- the old same-process clear-input production seam
- the staged execution architecture cleanup
- broader malicious-client hardening

Those were addressed later in:

- [docs/plans/refactor-hss-boundary.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/refactor-hss-boundary.md)
- [docs/plans/malicious-security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/malicious-security.md)

## Lasting Value

The lasting value of Refactor 1 was:

- boundary ownership became visible in the codebase
- browser and relay runtime separation became practical
- later boundary fixes had a clean place to land
- duplicate mixed-role code stopped being treated as normal structure

So this refactor should be read as the foundational boundary-layout cleanup
that made the later security and staged-execution work tractable.
