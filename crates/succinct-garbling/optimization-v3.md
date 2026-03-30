# Succinct-Garbling Optimization Approaches v3

This note is the follow-on to
[`optimization-v2.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/optimization-v2.md).

v2 established two things:

- the largest wins came from changing the shape of the hottest arithmetic work,
  not from helper cleanup
- the remaining shared-path bottleneck is no longer the add-heavy carry chain;
  it is the surviving round-core kernel shape, especially on wasm

This v3 note is the implementation plan for the next class of work: a deeper
kernel rewrite.

It is not a general wishlist. It is a phased plan to replace the remaining
generic round-core helper stack with a more specialized engine while preserving
the hardened split/local security boundary.

## Task Status Legend

- `[ ]` not started
- `[x]` started or completed
- items marked `(landed)` are intended to stay
- items marked `(reverted)` are intended to be removed if the gate fails

## Purpose

Build a dedicated hidden-eval round-core kernel that:

- keeps the same production security model
- keeps one production algorithm across native and wasm
- deletes generic helper churn in the Boolean lane
- minimizes Boolean/arithmetic crossings by design
- is laid out for contiguous-memory execution rather than tiny per-bit objects

## Non-Goals

- no reopening joined hot-path helpers
- no native-only alternate algorithm
- no transport/session shortcuts that widen evaluator-visible state
- no benchmark-only hacks that do not improve the real hidden-eval path
- no legacy compatibility wrappers

## Current Constraint Summary

The current shared kernel still pays for:

- generic `SplitLocalBitWord` / `LocalBitWordSide` execution in the hot loop
- repeated per-bit local-word materialization for the remaining Boolean lane
- helper boundaries between `Sigma0`, `Sigma1`, `Ch`, `Maj`, and the arithmetic
  accumulators
- batch-gate plumbing that still wants generic width-1 local words

The arithmetic carry-through work already landed in v2. The deeper rewrite is
about the Boolean-heavy part of `round_core`.

## Success Criteria

This plan should only land if it materially improves the current hardened
baseline instead of just moving cost around.

Primary keep gate:

- browser total hidden eval improves by at least `5%`
- browser `round_core` improves by at least `8%`
- native does not regress by more than `5%`

Secondary keep gate:

- if browser total is noisy, keep only if browser hidden-eval probe total and
  browser `round_core` both improve materially and native remains within `5%`

Immediate reject conditions:

- any change that weakens the split/local security boundary
- any change that introduces divergent production algorithms by target
- any shared-kernel change that regresses browser top-line by `>3%` without an
  obviously fixable adjacent follow-up already in progress

## Design Rules

- one production path only
- keep transport semantics unchanged
- keep evaluator-visible capability unchanged
- stage boundaries may keep their current types initially, but the round-core
  internals should not be forced to use those types once inside the kernel
- if a phase lands, delete the superseded helper path instead of carrying both

## Kernel Rewrite Overview

The target shape is:

1. stage inputs enter as existing split/local words
2. `round_core` converts once into a dedicated round-state kernel layout
3. the kernel computes:
   - `Sigma1(e)`
   - `Ch(e,f,g)`
   - arithmetic `temp1`
   - `Sigma0(a)`
   - `Maj(a,b,c)`
   - arithmetic `temp2`
   - `new_a`, `new_e`
   - state rotation
4. the kernel returns the same stage output semantics as today

The key difference is that steps 2 and 3 should run on a dedicated kernel state,
not on nested generic helper types.

## Phase 0: Baseline Lock

- [ ] copy the current accepted baseline numbers from
  [`optimization-v2.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/optimization-v2.md)
  into the top of the implementation branch notes before changing code
- [ ] record the exact native and browser report files to compare against
- [ ] keep one benchmark command block at hand for native and browser so every
  phase uses the same gate
- [ ] do not mix transport/session changes into this kernel branch

Exit gate:

- [ ] all work in this branch compares against one stable baseline, not moving
  numbers from earlier failed attempts

## Phase 1: Dedicated Round-State Layout

Goal:

- introduce a private round-core kernel state below `SplitLocalBitWord`

Implementation:

- [ ] add a dedicated fixed-size round-state struct in
  [`ddh_hidden_eval_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/src/ddh_hidden_eval_executor.rs)
  for `a,b,c,d,e,f,g,h`
- [ ] represent the remaining Boolean lane with contiguous packed left/right bit
  storage plus parallel commitment/provenance storage
- [ ] keep arithmetic state in dedicated arithmetic slots, not generic helper
  wrappers
- [ ] implement conversion from existing stage inputs into the kernel state
- [ ] implement conversion back out only at the existing stage boundary
- [ ] delete temporary helper glue if the kernel state makes it dead

Rules:

- [ ] no target-specific kernel logic here
- [ ] no transport or session changes
- [ ] no duplicate fallback engine inside the hot path

Exit gate:

- [ ] correctness passes
- [ ] no measurable regression from layout-only introduction larger than `3%`
  before Phase 2 starts

## Phase 2: Boolean Lane Rewrite

Goal:

- stop expressing `Sigma0`, `Sigma1`, `Ch`, and `Maj` through generic
  `SplitLocalBitWord` helper composition

Implementation:

- [ ] implement dedicated kernel-local `Sigma0` and `Sigma1` transforms directly
  over packed round-state storage
- [ ] implement dedicated kernel-local `Ch` over the same packed storage
- [ ] implement dedicated kernel-local `Maj` over the same packed storage
- [ ] ensure all four share one scratch model instead of four separate helper
  shapes
- [ ] remove per-round `Vec<DdhHssLocalWord>` construction for Boolean
  intermediates
- [ ] reuse kernel-local scratch across all 80 rounds

Rules:

- [ ] do not reintroduce helper-level object materialization inside these
  transforms
- [ ] do not force outputs back into `SplitLocalBitWord` just to feed the next
  line of the same kernel

Exit gate:

- [ ] browser `round_core` improves or stays flat before Phase 3
- [ ] if browser regresses here, stop and inspect before adding deeper raw-gate
  work

## Phase 3: Raw Gate Path Integration

Goal:

- push the Boolean lane below the current generic batch-multiply surface

Implementation:

- [ ] add raw packed batch-gate helpers in
  [`ddh_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/src/ddh_hss.rs)
  that consume packed bits plus aligned commitment/provenance storage directly
- [ ] support raw `d/e` setup and raw output derivation in that path
- [ ] wire the kernel-local `Ch` / `Maj` implementation to the new raw helper
- [ ] keep the old generic batch path available only until the new kernel path
  is benchmarked and validated
- [ ] delete the generic hot-path call sites if this lands

Rules:

- [ ] no widening of evaluator-visible state
- [ ] no joined hidden values
- [ ] keep the same cryptographic semantics and label derivation rules

Exit gate:

- [ ] browser `round_core` shows a clear gain over Phase 2
- [ ] native stays within the keep threshold

## Phase 4: Bool/Arithmetic Crossing Collapse

Goal:

- make the round-core kernel own the Boolean/arithmetic boundary instead of
  bouncing through standalone conversion helpers

Implementation:

- [ ] identify every remaining Boolean->arithmetic and arithmetic->Boolean
  crossing inside `round_core`
- [ ] collapse crossings so they happen only where the algorithm truly changes
  domain
- [ ] keep `temp1`, `temp2`, `new_a`, and `new_e` arithmetic end-to-end once
  they enter the arithmetic side
- [ ] avoid reconstructing generic split words for values that only exist to
  feed the next arithmetic operation
- [ ] remove dead conversion helpers if the kernel no longer needs them

Exit gate:

- [ ] browser total hidden eval improves against the Phase 0 baseline
- [ ] browser hidden-eval probe total improves against the Phase 0 baseline

## Phase 5: Wasm-Friendly Memory Pass

Goal:

- keep the same kernel algorithm but make the memory layout explicitly wasm
  friendly

Implementation:

- [ ] remove remaining tiny hot-path allocations inside the kernel
- [ ] ensure all hot scratch is fixed-size and executor-owned
- [ ] prefer contiguous arrays and fixed buffers over nested vectors
- [ ] recheck that kernel-local arrays map well to linear wasm memory
- [ ] only if needed, reorder kernel-local fields for more sequential access in
  the hottest loops

Rules:

- [ ] same algorithm as native
- [ ] no wasm-only correctness path
- [ ] layout may differ internally if semantics stay identical

Exit gate:

- [ ] browser total or browser `round_core` improves materially
- [ ] native regression remains within the allowed range

## Phase 6: Browser Interface Cleanup

Goal:

- only after the kernel lands, remove remaining browser-side shaping costs that
  still sit on the real measured path

Implementation:

- [ ] re-measure the browser gap after Phase 5
- [ ] identify remaining real `session.evaluate` overhead that is not core
  hidden-eval work
- [ ] reduce JS-visible object creation only where it removes real measured work
- [ ] prefer typed arrays / binary blobs over rich object graphs only if decode
  cost does not replace the deleted shaping cost
- [ ] keep hidden-run fast-path semantics unchanged

Rules:

- [ ] no transport-semantics changes
- [ ] no evaluator-capability widening
- [ ] no JSON-byte detour retry

Exit gate:

- [ ] browser top-line improves materially without harming correctness or the
  security boundary

## Phase 7: Cleanup And Deletion

Goal:

- do not leave the codebase split between the old helper stack and the new
  kernel stack

Implementation:

- [ ] delete superseded round-core helper plumbing if the new kernel lands
- [ ] remove dead scratch structs and unused helper conversions
- [ ] remove stale benchmark-only scaffolding created during failed phases
- [ ] update docs and benchmark reports to describe the kept kernel only
- [ ] keep the implementation comprehensible enough that future security
  hardening still touches one real production path

Exit gate:

- [ ] no duplicate hot-path kernel remains

## Immediate Work Order

- [ ] Phase 0 baseline lock
- [ ] Phase 1 dedicated round-state layout
- [ ] Phase 2 Boolean lane rewrite
- [ ] stop and benchmark before Phase 3
- [ ] Phase 3 raw gate path only if Phase 2 is at least flat on browser
- [ ] Phase 4 crossing collapse
- [ ] Phase 5 wasm-friendly memory pass
- [ ] Phase 6 browser interface cleanup only after the kernel is winning
- [ ] Phase 7 deletion and doc cleanup

## What Not To Retry Inside This Plan

- [ ] do not retry helper-level `Ch` / `Maj` rewrites at the current abstraction
- [ ] do not retry `LocalBitWordSide` micro-optimizations as standalone work
- [ ] do not retry JSON-byte browser payload shaping
- [ ] do not retry native-only alternate kernels
- [ ] do not retry transport/session shortcuts in the name of kernel speed

## Deliverables

- [ ] one kept round-core kernel implementation
- [ ] refreshed native benchmark report
- [ ] refreshed browser benchmark report
- [ ] updated optimization notes with kept vs reverted kernel phases
- [ ] deleted superseded hot-path helper code
