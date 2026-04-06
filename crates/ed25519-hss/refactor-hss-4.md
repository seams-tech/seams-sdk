# Ed25519 HSS Refactor 4

Date updated: April 6, 2026

## Summary

This document records the next follow-up refactor for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

Refactor 3 fixed the production boundary bug:

- non-export production flows no longer use the old sealed
  `ServerInputsPacket` seam
- the production staged flow now advances through server-owned stage-local
  continuations from add-stage onward
- the client no longer receives a production packet path that directly exposes
  both relayer transport halves

That landed the required production boundary correction.

The stronger follow-up in this file is now mostly landed:

- add-stage materializes only the add-stage transition and the first stored
  `message_schedule` continuation
- each `message_schedule(n)` response advances only the immediately prior
  stored schedule continuation
- the first `round_core` continuation is derived only at the real
  `message_schedule -> round_core` boundary
- each `round_core(n)` response advances only the immediately prior stored
  round-core continuation
- `output_projection` materializes final output only when that stage executes

The accepted retained-state exception remains:

- add-stage still retains the minimal `projector_inputs` needed for later
  `output_projection`

That is no longer the old “trace-backed staged executor” model. It is the
current intended staged-continuation design.

## Goal

Replace the old execution-trace-backed staged model with a true server-owned
staged executor that advances one stage at a time.

Concretely:

- the server must own real stage state
- each server response must be derived from the current stage state, not from a
  precomputed full run
- later stages must not depend on having materialized the full hidden-eval run
  in advance
- the client must still never receive enough material to reconstruct
  `y_relayer` or `tau_relayer` in non-export production flows

## Non-Goals

This refactor does **not** attempt to:

- remove the `ExplicitKeyExport` exception
- deliver a full malicious-secure OT or Beaver design
- redesign the browser export trust model
- optimize latency first

Those are separate workstreams.

## Why Do This If Refactor 3 Already Fixed The Boundary?

Because the current implementation still has a structural weakness:

- execution is staged at the transport layer
- but add-stage still seeds later continuation material ahead of the round that
  will consume it

That leaves us with:

- more server state than we actually want to persist
- less confidence that each round boundary is the true execution boundary
- more risk of future regressions where a helper quietly falls back to
  “materialize the whole run and bind digests”

The point of this follow-up is not to re-fix the same security bug.

The point is:

- make the implementation match the mental model
- make later malicious-security work easier
- reduce ambiguity in code review and future refactors

## Target Architecture

### Core Principle

The server should own a stage-specific hidden-eval continuation state, not a
full hidden-eval trace.

That means:

- after add-stage, the server stores only the continuation state needed to
  answer the next stage
- after each `message_schedule(n)` round, the server stores only the state
  needed for `message_schedule(n+1)` or the transition into `round_core(0)`
- after each `round_core(n)` round, the server stores only the state needed for
  `round_core(n+1)` or the transition into `output_projection`
- after `output_projection`, the server stores only the final output-release
  state needed for finalize
- the only accepted retained-state exception before `output_projection` is the
  minimal `projector_inputs` set listed below

Accepted retained-state exception:

- the server currently must retain projector prerequisites derived at
  add-stage:
  - add-stage bits
  - `tau_client` bits
  - relayer tau transport halves
- this is the minimum retained state required to execute `output_projection`
  later without recomputing from dropped relayer roots
- these prerequisites are not output bundles and are not treated as a finalized
  output stage; they are only deferred projector inputs
- Refactor 4 accepts this retained state as the final post-add-stage design,
  unless a later executor design can prove a strictly smaller retained state
  without reintroducing root-based recomputation

Hard requirement:

- once add-stage has succeeded, no later continuation variant may retain raw
  `y_relayer` or `tau_relayer`
- no later continuation variant may retain enough material to recompute the
  staged execution from relayer roots alone
- if a later stage needs relayer-derived influence, it must consume the
  continuation produced by the previous stage instead of falling back to
  root-based recomputation

### Server-Owned State Shape

Refactor 3 introduced:

- `ServerEvalExecutionCheckpoints`
- `execution_run: Option<DdhHiddenEvalRun>`

Refactor 4 should replace `execution_run` with a real staged continuation enum,
for example:

```rust
pub enum ServerEvalExecutionState {
    MessageSchedule(MessageScheduleState),
    RoundCore(RoundCoreState),
    OutputProjection(OutputProjectionState),
    Finalize(FinalizeState),
}
```

The exact struct names may change, but the ownership rule should not:

- each variant contains only the data required for that stage and its next
  transition
- no variant should embed the full hidden-eval run

Checkpoint rule:

- `ServerEvalExecutionCheckpoints` in its current “all future digests” form is
  transitional and should not survive unchanged
- Refactor 4 should either:
  - remove it entirely, or
  - shrink it into stage-local digest material that describes only the current
    continuation and its immediate next transition
- the server must not keep a checkpoint object whose real role is “remember the
  future full-run digest shape”

### Client-Visible Rule

The client may see:

- transcript ids
- stage ids
- stage digests
- output policy
- allowed output material for that operation

The client must not see:

- joined relayer roots
- full server-owned hidden-eval continuation state
- any serialized state that would let it reconstruct server-private stage
  values

## Execution Model

### Round 0: `ServerAssistInit`

Purpose:

- authenticate the handle
- bind the OT/init transcript
- establish server-owned relayer roots and operation policy

It should **not**:

- materialize the full hidden-eval run
- materialize later-stage continuation state

### Round 1: `AddStage`

Client sends:

- OT-selected client bundles
- add-stage commitments/digests

Server does:

- validate the add-stage request
- combine the request-carried client bundles with server-owned relayer roots
- execute only the add-stage transition
- store the first `MessageScheduleState` continuation
- drop direct root-based recomputation material from the stored continuation
- return the add-stage response derived from that transition

### Message Schedule Rounds

For each `message_schedule(n)`:

- server loads `MessageScheduleState(n)`
- executes only that schedule step or minimal batch
- stores the next continuation
- returns only the round-local response and execution-bound digest

### Round Core Rounds

For each `round_core(n)`:

- server loads `RoundCoreState(n)`
- executes only that core round or minimal batch
- stores the next continuation
- returns only the round-local response and execution-bound digest

### Output Projection

Server:

- loads `OutputProjectionState`
- computes only the output projection transition
- stores `FinalizeState`
- returns only the allowed output-release metadata for that operation

### Finalize

Server:

- loads `FinalizeState`
- emits the final delivery material allowed by policy
- clears or tombstones the handle

## Design Choice: Per-Round vs Batched Continuations

There are two plausible designs:

1. one continuation per logical round
2. one continuation per small stage batch

Recommendation:

- keep the public wire protocol as it is now
- allow the internal executor to batch several low-level operations behind one
  stage if and only if the batch boundary is still a real continuation
  boundary and does not require precomputing the full run

`wire/mod.rs` rule:

- schema changes are not the primary objective of this refactor
- changes in [wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
  should be limited to:
  - internal cleanup
  - field additions that are proven necessary for real stage-local semantics
  - removal of obsolete transitional fields after the continuation rewrite
- avoid gratuitous message-shape churn

In other words:

- internal batching is acceptable
- full-run precomputation is not

## Implementation Plan

### Phase 0. Freeze The Current Execution-Backed Baseline

- [x] add a baseline regression test for the current staged continuation shape
- [ ] add a temporary test-only assertion that later stage responses can be
  produced after deleting only the specific continuation state they need, not
  after deleting a full traced run
- [x] document the current limitation in this file and link it from
  [refactor-hss-3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/refactor-hss-3.md)

### Phase 1. Introduce Real Continuation Types

- [x] add a new staged execution enum in
  [server/state.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/state.rs)
- [x] remove `execution_run: Option<DdhHiddenEvalRun>` from `ServerEvalState`
- [x] replace it with `execution_state: Option<ServerEvalExecutionState>`
- [x] add stage-specific continuation structs:
  - `MessageScheduleState`
  - `RoundCoreState`
  - `OutputProjectionState`
  - `FinalizeState`
- [x] ensure these structs do not store the full run as continuation state
- [x] ensure these structs do not retain raw `y_relayer` / `tau_relayer` after
  add-stage
- [x] remove or shrink `ServerEvalExecutionCheckpoints` so it no longer acts as
  a full-run checkpoint object

### Phase 2. Teach The Executor To Advance One Stage At A Time

- [x] add executor entrypoints in
  [hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)
  for:
  - add-stage transition
  - message-schedule step transition
  - round-core step transition
  - output-projection transition
- [x] seed a real stored `message_schedule` continuation from add-stage
- [x] bind `message_schedule(n)` request/response chaining to that stored
  stage-local continuation instead of a generic full-run checkpoint object
- [x] seed a real stored `round_core` continuation from staged execution state
- [x] bind `round_core(n)` responses to that stored stage-local continuation
  instead of a generic future-digest placeholder
- [x] derive the first `round_core` continuation at the
  `message_schedule -> round_core` boundary from stored schedule continuation
  and the compiled hidden-eval program, rather than pre-seeding it into
  add-stage state
- [x] replace precomputed finalize/output material with stored projector
  prerequisites that carry only what the output projector actually needs
- [x] materialize final output bundles only when `output_projection` executes,
  not at add-stage
- [x] remove reliance on “trace the full run now and read later checkpoint
  digests”
- [x] make checkpoint digests derived from the per-stage transition result,
  not from a previously materialized full trace

### Phase 3. Rewire Server Handlers To Real Continuations

- [x] update add-stage handling in
  [server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
  to materialize the add-stage transition and then transition directly into the
  first stored `MessageScheduleState`
- [x] make that transition one-way: later handlers must fail if asked to
  recompute from relayer roots instead of consuming stored continuation
- [x] update message-schedule handlers to load and advance only
  `MessageScheduleState`
- [x] make `MessageScheduleState` carry real stored schedule continuation data
  rather than only future digests
- [x] update `RoundCoreState` to carry real stored round-core continuation
  data rather than only future digests
- [x] stop storing `round_core` continuation inside add-stage/message-schedule
  state before the schedule phase has actually advanced to that boundary
- [x] update `OutputProjectionState` to carry real stored output-projection
  continuation data rather than only future digests
- [x] stop storing finalized output material in add-stage/message-schedule/
  round-core state before `output_projection` runs
- [x] update round-core handlers to load and advance only `RoundCoreState`
- [x] update output-projection handling to load only `OutputProjectionState`
- [x] update finalize handling to consume only `FinalizeState`
- [x] enforce handle invalidation when a stage is replayed after final
  advancement unless that replay is explicitly idempotent by design

### Phase 4. Tighten Client Validators To Real Stage Semantics

- [x] update
  [client/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs)
  so the client validators bind to stage-local continuation digests, not to
  “full-run-derived checkpoint” assumptions
- [x] update
  [protocol/invariants.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/invariants.rs)
  to make those stage-local invariants explicit
- [x] keep message schemas stable where possible; only add fields if real stage
  semantics require them

### Phase 5. Remove Full-Run Trace Dependence

- [ ] delete the now-obsolete “trace full hidden eval and store it” path from:
  - [server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
  - [server/state.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/state.rs)
  - [runtime/flow.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/flow.rs)
- [ ] keep only the explicit debug/profile helpers that intentionally evaluate
  full clear-input runs
- [x] ensure no normal staged production path can materialize a full hidden-eval
  run just to answer later rounds

### Phase 6. Revalidate Integrations

- [x] rerun crate boundary tests
- [x] rerun crate protocol-flow tests
- [x] rerun browser HSS wasm tests
- [x] rerun relay HSS finalize scope tests
- [x] verify the browser/client bundle still does not expose reconstructable
  server-owned state

Current recorded Phase 6 results:

- crate boundary tests:
  `18 passed, 0 failed`
- crate protocol-flow tests:
  `11 passed, 0 failed, 4 ignored`
- browser HSS wasm boundary test:
  `1 passed`
- relay HSS finalize scope tests:
  `2 passed`

### Phase 7. Performance And Specs

- [x] benchmark hidden-eval latency before and after the continuation rewrite
- [x] benchmark browser HSS bundle size before and after
- [x] update:
  - [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
  - [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
  - [succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
  - [docs/semihonest-to-malicious-secure.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/semihonest-to-malicious-secure.md)
- [x] explicitly remove any wording that still describes the staged executor as
  “execution-backed from add-stage onward” if the stronger continuation design
  is now fully landed

Current recorded Phase 7 results:

- native hidden eval benchmark after the continuation rewrite:
  `293.47ms` mean, `293.49ms` median, `295.72ms` p95
- hidden eval prepare:
  `207.74ms`
- stage means:
  - input sharing: `2.05ms`
  - add stage: `2.86ms`
  - message schedule: `45.64ms`
  - round core: `152.29ms`
  - output projector: `49.28ms`
- prime-order CPU executor benchmark after the continuation rewrite:
  `2.041ms` mean, `2.041ms` median, `2.044ms` p95
- browser HSS client artifact after the continuation rewrite:
  - wasm: `262,555` bytes (`128,660` gzip)
  - JS glue: `14,028` bytes (`3,347` gzip)
  - worker JS: `21,744` bytes (`5,354` gzip)

## Specific Code Areas

Expected primary write scope:

- [server/state.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/state.rs)
- [server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
- [client/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs)
- [wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
- [protocol/invariants.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/invariants.rs)
- [protocol/transcript.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/transcript.rs)
- [runtime/flow.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/flow.rs)
- [ddh/hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)

Expected integration follow-up:

- [wasm/near_signer/src/threshold/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_hss.rs)
- [wasm/hss_client_signer/src/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_hss.rs)
- [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
- [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)

## Risks

Main risks:

- retry/idempotency regressions if continuation state is not stable
- latency regressions if per-stage execution boundaries are too granular
- accidental widening of wire payloads if continuation state leaks into
  client-visible messages
- debug/test helpers drifting back into production paths

The main discipline requirement is:

- do not reintroduce full-run hidden-eval materialization under a different
  helper name

## Exit Criteria

This plan is complete only when all of the following are true:

- no production staged path stores a full hidden-eval run as continuation state
- each staged server response is derived from real stage-local server-owned
  continuation state
- the client still cannot reconstruct `y_relayer` or `tau_relayer` in any
  non-export production flow
- retry/idempotency behavior is preserved where intentionally supported
- the browser/relay HSS integration tests still pass
- the specs describe the stronger continuation architecture accurately

## Recommended Delivery Strategy

Do not attempt this in one jump.

Recommended slices:

1. add continuation types and executor step APIs
2. convert add-stage and message-schedule
3. convert round-core
4. convert output-projection/finalize
5. delete full-run staged continuation storage
6. rerun performance and update specs

That keeps the refactor reviewable and makes it easier to detect where latency
or boundary regressions are introduced.
