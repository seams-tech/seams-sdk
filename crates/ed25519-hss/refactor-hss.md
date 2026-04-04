# Ed25519 HSS Refactor 1

Date updated: April 5, 2026

## Summary

This document records the landed boundary-first refactor of
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

The main goal is to make client/server boundaries obvious in the codebase so
that it is easy to:

- review which code is client-only
- review which code is server-only
- review which payloads are allowed to cross the wire
- detect when key material or private state crosses boundaries incorrectly
- write focused negative tests for boundary violations

This is not just a folder cleanup. It is a structural refactor intended to make
secret-flow review and boundary testing much clearer.

This plan is grounded in the active crate docs and specs:

- [crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [crates/ed25519-hss/docs/homomorphic-secret-sharing.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/homomorphic-secret-sharing.md)
- [crates/ed25519-hss/security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- [crates/ed25519-hss/succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)

The module boundaries below are meant to mirror the protocol boundaries those
docs already define.

Current status:

- the boundary split is landed
- boundary-focused tests are landed
- browser and relay runtime artifacts are split
- the remaining performance priority is browser wasm size, not legacy mixed
  module cleanup

## Why Refactor

The current crate has strong protocol logic, but the role boundaries are not
obvious enough from the module tree.

Today:

- prepared-session construction was originally concentrated inside
  [crates/ed25519-hss/src/protocol/prepared.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/prepared.rs)
- wire payloads, role-private state, and transcript/report assembly are too
  close together
- the top-level
  [crates/ed25519-hss/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/lib.rs)
  flattens too much of the crate surface
- this makes “what may cross from client to server” harder to audit than it
  should be

The refactor should make role ownership explicit in both the module tree and
type names.

## Boundary Rationale From The Specs

The specs already tell us where the boundaries should exist.

### 1. Role boundary: client = evaluator, server = garbler

[crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
states the live role model explicitly:

- server = garbler
- client = evaluator

That means the crate should not bury both roles inside one mixed module. The
filesystem and public API should make evaluator-only and garbler-only surfaces
obvious.

### 2. Primitive boundary: OT delivery vs HSS evaluation

[crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
and
[crates/ed25519-hss/succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
both define the same split:

- OT is the private input-delivery mechanism for client-owned bits
- HSS is the hidden-computation mechanism once inputs are represented as hidden
  shared values

So the refactor should avoid one giant "protocol" bucket that mixes OT
transport, role-private OT state, and the hidden-eval executor.

### 3. Layer boundary: input-share, nonlinear expansion, output-share

[crates/ed25519-hss/succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
defines three protocol layers:

- input-share layer
- nonlinear expansion layer
- output-share layer

That implies:

- `wire/` should own the input-share crossing surface and binding checks
- `ddh/` and `artifact/` should remain the nonlinear-expansion engine
- `client/outputs.rs` and `server/outputs.rs` should make the output-share
  boundary explicit

### 4. Security boundary: evaluator may compute on hidden server input, but may not decode it

The most important active rule in
[crates/ed25519-hss/succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
and
[crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
is:

- the evaluator may evaluate on hidden server input
- the evaluator must not receive enough material to decode server input into
  plaintext

The same security note is reinforced in
[crates/ed25519-hss/security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md):

- no interparty wire type may carry both halves of a hidden server-owned value
- joined hidden values must stay confined to trusted simulation, explicit
  debug/profiling paths, or internal computation states that never cross the
  evaluator/garbler boundary

This is the core reason to split `wire/` away from `client/` and `server/`,
and to keep boundary tests as a first-class part of the refactor.

### 5. Reusable public artifact vs per-run secret preprocessing

[crates/ed25519-hss/docs/homomorphic-secret-sharing.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/homomorphic-secret-sharing.md)
argues for a cleaner separation between:

- public reusable artifact data
- per-session HSS preprocessing
- evaluator-local split execution

That supports the target split here:

- `artifact/` and parts of `shared/` hold reusable public context/artifact data
- `client/state.rs` and `server/state.rs` hold per-run private state
- `ddh/` and `runtime/` execute over split/local hidden values without leaking
  them into the wire surface

## Refactor Goal

After this refactor, the crate should communicate the following clearly:

- `shared`: common context, fixed-function derivation math, labels, and errors
- `wire`: the only data allowed to cross client/server boundaries
- `client`: evaluator-side logic and client-private state
- `server`: garbler-side logic and server-private state
- `protocol`: transcript rules and cross-role invariants
- `runtime`: wasm/native adapters only

The structure should make boundary violations easier to spot before runtime.

## Landed Module Tree

```text
crates/ed25519-hss/src/
  lib.rs

  shared/
    mod.rs
    context.rs
    error.rs
    reference.rs

  wire/
    mod.rs

  client/
    mod.rs
    api.rs
    ot.rs
    outputs.rs
    state.rs

  server/
    mod.rs
    api.rs
    ot.rs
    outputs.rs
    state.rs

  protocol/
    mod.rs
    invariants.rs
    prepared.rs
    report.rs
    transcript.rs

  ddh/
    mod.rs
    ddh_hss.rs
    hidden_eval.rs
    hidden_eval_executor.rs

  artifact/
    mod.rs
    prime_order_decoder.rs
    prime_order_encoder.rs
    prime_order_trace.rs

  runtime/
    mod.rs
    client.rs
    debug.rs
    evaluation.rs
    flow.rs
    prepared.rs
    prime_order_cpu_executor.rs
    server.rs
    shared.rs
    wasm.rs

  benchmark/
    mod.rs
    cache.rs
    hidden_eval.rs
    phase1.rs

  fixtures.rs
  candidate.rs
  artifact_stub.rs
```

## Landed Runtime Split

The runtime split that this plan called for is also landed:

- browser/client HSS runtime:
  [`wasm/hss_client_signer`](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- relay/server HSS runtime:
  [`wasm/near_signer/pkg-server`](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg-server)

This means the refactor goal is no longer hypothetical. The boundary-oriented
module tree now feeds directly into separate browser and relay build surfaces.

Measured browser result from the landed split:

- original broad browser HSS wasm: `1,163,476` bytes
- current dedicated browser HSS wasm: `472,527` bytes
- original broad browser HSS JS glue: `173,004` bytes
- current dedicated browser HSS JS glue: `18,414` bytes

That reduction is large enough that the split should be treated as a permanent
part of the crate/runtime design.

## Responsibility Split

### `shared/`

Holds:

- canonical context
- fixed-function shared derivation logic
- common labels and binding helpers
- shared reference math
- common error types

Must not hold:

- role-private driver state
- wire packet codecs mixed with role-private state

### `wire/`

Holds:

- the only wire-visible envelopes and packets
- serialization/deserialization for cross-boundary payloads
- commitment and binding payloads
- explicit validation helpers for wire-safe structures

This module exists specifically because the spec says no interparty wire type
may carry both halves of a hidden server-owned value.

Must not hold:

- client-private driver state
- server-private driver state
- raw hidden roots

### `client/`

Holds evaluator-side logic only:

- client ceremony preparation
- evaluator progression
- client-private OT state
- client output opening

Must not expose:

- server-private state
- hidden server inputs

This follows the active role model in the README: client = evaluator.

### `server/`

Holds garbler-side logic only:

- server ceremony preparation
- garbler progression
- server-private OT state
- server output opening

Must not expose:

- client-private state
- hidden client inputs

This follows the active role model in the README: server = garbler.

### `protocol/`

Holds only cross-role invariants:

- transcript rules
- report assembly
- explicit cross-role validation

Must not become a generic dumping ground for role-specific code.

### `runtime/`

Holds:

- wasm bindings
- CPU/native execution adapters

Must consume the role APIs, not define the role model itself.

## Runtime Artifact Split

Yes, this crate should eventually produce distinct client and server runtime
artifacts for product builds.

Reason:

- the client only needs evaluator-side role logic plus the wire-safe payload
  surface
- the server only needs garbler-side role logic plus the wire-safe payload
  surface
- bundling both sides into one wasm/runtime package makes the browser ship
  server-only code and role-private server state machinery it should never need
- that works against the same boundary clarity this refactor is trying to
  enforce

So the target runtime shape should be:

- client artifact:
  - evaluator-side ceremony
  - client output opening
  - shared math/context
  - wire codecs
- server artifact:
  - garbler-side ceremony
  - server output opening
  - shared math/context
  - wire codecs

This should be done after the role-private code is structurally separated in
`client/` and `server/`. The runtime split should follow the module split, not
precede it.

Recommended implementation direction:

1. keep one source crate
2. split public module ownership cleanly first
3. then add feature-gated or target-specific runtime entrypoints so the client
   bundle does not pull in server-only code
4. finally, update the build scripts to emit:
   - a client/evaluator artifact
   - a server/garbler artifact

Non-goal:

- do not fork the protocol into two independent crates unless the module split
  proves insufficient

## Public API Direction

The current top-level crate surface is too flat. After refactor, the public API
should intentionally export only:

- shared context/types
- wire envelopes
- client API entrypoints
- server API entrypoints
- selected runtime/benchmark APIs where appropriate

That means the crate should stop reexporting large amounts of internal state
flat from
[crates/ed25519-hss/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/lib.rs).

Callers should use explicit module paths like:

- `ed25519_hss::client::...`
- `ed25519_hss::server::...`
- `ed25519_hss::wire::...`
- `ed25519_hss::shared::...`

This is a deliberate breaking change and should be treated as a cleanup win.

## Naming Rules

Type names should make ownership obvious.

Final boundary-owned names now follow that rule directly.

Examples:

- `protocol::PreparedSession`
- `client::ClientDriverState`
- `client::ClientSession`
- `client::ClientOtState`
- `client::ClientOutputOpener`
- `server::ServerDriverState`
- `server::ServerSession`
- `server::ServerOtState`
- `server::ServerOutputOpener`
- `wire::WireMessage`
- `wire::ClientOtOffer`
- `wire::ClientPacket`
- `wire::ServerPacket`
- `wire::EvaluationResult`
- `wire::EvaluationReport`
- `runtime::SharedRuntime`
- `runtime::ClientRuntime`
- `runtime::ServerRuntime`

Rule:

- anything crossing the boundary should be named `Wire*`
- anything client-private should be named `Client*`
- anything server-private should be named `Server*`
- shared runtime/materialization types may stay `Shared*`, `Prepared*`, or
  `Evaluate*` where that ownership is already unambiguous from the module path

## Proposed Migration Steps

### Phase 1: Create The New Skeleton

Add the new folders and `mod.rs` files without changing behavior:

- `shared/`
- `wire/`
- `client/`
- `server/`

Keep existing code compiling while the new structure is introduced.

### Phase 2: Move Shared Foundations First

Move:

- [crates/ed25519-hss/src/context.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/context.rs)
- [crates/ed25519-hss/src/error.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/error.rs)
- [crates/ed25519-hss/src/reference.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/reference.rs)

Target:

- `shared/context.rs`
- `shared/error.rs`
- `shared/reference.rs`

Keep behavior unchanged.

### Phase 3: Extract Wire Types

Pull the wire-crossing payloads out of
[crates/ed25519-hss/src/protocol/prepared.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/prepared.rs).

First move:

- message/envelope structs
- packet wrappers
- commitment/binding transport types

Target:

- `wire/mod.rs`

### Phase 4: Split Role-Private State

Move evaluator-only private state to:

- `client/state.rs`
- `client/ot.rs`
- `client/outputs.rs`

Move garbler-only private state to:

- `server/state.rs`
- `server/ot.rs`
- `server/outputs.rs`

The goal is to make it impossible to confuse wire-safe payloads with
role-private state.

### Phase 5: Split Ceremony Entry Points

Client-side API should contain:

- prepare client request
- evaluate result
- open client output
- open seed output if client-visible

Server-side API should contain:

- derive server inputs
- prepare server message
- finalize report
- open server output

This moves role behavior out of one large mixed module.

### Phase 6: Shrink `protocol/`

After the role split, keep only cross-role concerns in `protocol/`:

- transcript rules
- report assembly
- invariants

Anything that only touches one role should be moved out.

### Phase 7: Clean Up Top-Level Exports

Reduce top-level `pub use` clutter in
[crates/ed25519-hss/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/lib.rs).

Deliberately force callers to use module-qualified paths.

This is one of the main wins for boundary clarity.

### Phase 8: Update Runtime Adapters

Once internal APIs are stable, update:

- [crates/ed25519-hss/src/runtime/wasm.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/wasm.rs)

so it consumes the new `client`, `server`, `wire`, and `shared` modules
instead of reaching into mixed protocol internals.

### Phase 9: Add Boundary Tests

Add dedicated tests for:

- client-only invariants
- server-only invariants
- wire-only payload validation
- negative boundary rejection cases

Suggested layout:

```text
crates/ed25519-hss/tests/
  boundary/
    client_to_server.rs
    server_to_client.rs
    wire_only.rs
    rejection.rs
```

## Boundary Test Plan

The most important testing outcome is not just “flow still works”.

It is “the wrong data cannot cross boundaries”.

Add tests that explicitly fail if:

- raw `y_client` crosses the wire
- raw `y_relayer` crosses the wire
- raw `tau_client` crosses the wire
- raw `tau_relayer` crosses the wire
- client-private driver state is accepted as a server-visible payload
- server-private driver state is accepted as a client-visible payload
- a wire payload contains both halves of a server-owned hidden value
- malformed binding or transcript payloads are accepted

Also keep an end-to-end role separation gate:

- [crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs)

## Recommended Order

Do this in the following order:

1. `shared`
2. `wire`
3. `client/state` and `server/state`
4. `client/api` and `server/api`
5. shrink `protocol`
6. update runtime adapters
7. add boundary tests
8. remove old flat exports and old naming

## Rules For This Refactor

- no legacy compatibility aliases
- no duplicate old/new module surfaces
- no temporary alternate names kept long-term
- breaking changes are acceptable
- remove old structure as soon as the replacement is working

## Todo List

### Phase 1

- [x] Create `shared/`, `wire/`, `client/`, and `server/` module skeletons
- [x] Keep the crate compiling with the new skeleton in place

### Phase 2

- [x] Move context/error/reference into `shared/`
- [x] Update imports to use `shared::*`

### Phase 3

- [x] Extract all wire-visible message and packet types into `wire/`
- [x] Remove mixed wire/private type definitions from the old protocol module

### Phase 4

- [x] Move evaluator-private state into `client/state.rs`
- [x] Move garbler-private state into `server/state.rs`
- [x] Move role-private OT helpers into `client/ot.rs` and `server/ot.rs`
- [x] Move role-private output opener ownership into `client/outputs.rs` and
      `server/outputs.rs`

### Phase 5

- [x] Create explicit `client/api.rs` entrypoints
- [x] Create explicit `server/api.rs` entrypoints
- [x] Move public role-facing ceremony entrypoints out of `protocol/` and into
      the boundary API modules
- [x] Move remaining role-local trusted-eval helpers out of `protocol/`
- [x] Remove mixed client/server ceremony logic from the old structure

### Phase 6

- [x] Move packet/transcript validation rules into `protocol/invariants.rs`
- [x] Move report assembly helpers into `protocol/report.rs`
- [x] Move transcript digest, binding, and AAD helpers into
      `protocol/transcript.rs`
- [x] Move transport frame encode/decode and payload serialization helpers into
      `wire/`
- [x] Move shared runtime types and materialization into `runtime/shared.rs`
- [x] Move evaluation timing and trusted-eval carriers into `runtime/evaluation.rs`
- [x] Move prepared-session debug and profiling helpers into `runtime/debug.rs`
- [x] Move prepared-session flow wrappers into `runtime/flow.rs`
- [x] Move prepared-session metadata and driver-state helpers into
      `runtime/prepared.rs`
- [x] Move role-gated output packet open/decode helpers into `client/outputs.rs`
      and `server/outputs.rs`
- [x] Move sealed server-input open/decode helpers into `client/api.rs`,
      `server/api.rs`, and `wire/`
- [x] Move server-output sealing helpers fully onto `server/api.rs`
- [x] Reduce `protocol/` to transcript/report/invariant concerns only
- [x] Remove role-specific logic from `protocol/`

### Phase 7

- [x] Move current driver/example/wasm consumers to module-qualified boundary
      imports
- [x] Move current crate test modules to module-qualified boundary imports
- [x] Move current helper binaries to module-qualified boundary imports
- [x] Remove flat top-level reexports for role-private client/server state and
      output opener types
- [x] Remove flat top-level reexports for benchmark, candidate, fixture, and
      shared helper surfaces that current callers no longer use directly
- [x] Remove flat top-level reexports for artifact and artifact-stub surfaces
      that current callers no longer use directly
- [x] Remove flat top-level protocol convenience exports that current callers
      no longer use directly
- [x] Eliminate internal crate-root dependencies on the removed flat export
      surfaces
- [x] Reduce top-level flat reexports in `lib.rs`
- [x] Require callers to use module-qualified boundary-aware imports

### Phase 8

- [x] Update `runtime/wasm.rs` to use the new role APIs
- [x] Verify wasm/native behavior remains correct

### Phase 8b

- [x] Design separate client and server runtime entrypoints
- [x] Ensure the client runtime artifact excludes server-only role code
- [x] Ensure the server runtime artifact excludes client-only role code
- [x] Benchmark bundle-size impact and keep the split only if it materially
      reduces shipped client size

### Phase 9

- [x] Add boundary-focused test modules
- [x] Add negative tests for forbidden cross-boundary data flow
- [x] Keep the separated-role end-to-end gate green

### Final Cleanup

- [x] Rename remaining ambiguous types to `Client*`, `Server*`, or `Wire*`
- [x] Remove obsolete mixed-surface names and modules
- [x] Document the final boundary model in the crate README

### Phase 8b Benchmark Note

The first runtime-artifact split is now kept for the browser `near_signer`
build:

- browser `pkg` omits relay-only HSS wasm exports via
  `hss-server-exports = false`
- relay `pkg-server` enables `hss-server-exports`

Measured release artifacts on April 4, 2026:

- browser client-only `wasm_signer_worker_bg.wasm`: `1,163,957` bytes
- browser full `wasm_signer_worker_bg.wasm`: `1,222,812` bytes
- delta: `58,855` bytes smaller, about `4.8%`

The matching JS glue delta was smaller:

- browser client-only glue: `173,004` bytes
- browser full glue: `174,499` bytes
- delta: `1,495` bytes smaller

That is large enough to keep the browser-side export split.

The relay-side split is now also real:

- browser-only evaluator exports such as
  `threshold_ed25519_hss_prepare_session`,
  `threshold_ed25519_hss_prepare_client_request`,
  `threshold_ed25519_hss_evaluate_result`, and
  `threshold_ed25519_hss_open_client_output` are no longer emitted by the
  server `pkg-server` artifact
- the relay artifact keeps only the evaluator-facing export it still truly
  needs on the registration path: `threshold_ed25519_hss_open_seed_output`

Measured release artifacts on April 4, 2026:

- browser client-only `wasm_signer_worker_bg.wasm`: `1,163,940` bytes
- relay/server `wasm_signer_worker_bg.wasm`: `1,152,055` bytes

The boundary keep-gate remains part of the refactor and now uses a
non-degenerate committed fixture so it does not false-positive on the original
`y_relayer = 0x01 || 0...0` fixture.
