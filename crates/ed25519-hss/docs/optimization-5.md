# Optimization v5: Executor-Wide Materialization Rewrite

Date created: June 10, 2026

Status: planned.

## Goal

Redesign the hidden-eval executor around explicit materialization boundaries so
HSS can run faster and more predictably across browser, native, iOS, and
embedded-class devices.

The immediate target is the current browser/native registration path. The later
target is constrained runtimes where CPU, memory, allocation count, and
predictability matter as much as p50 latency.

This plan preserves the current HSS trust model:

- split/local execution remains the production boundary
- evaluator-visible state does not widen
- exportability stays intact
- threshold-at-registration remains intact
- byte-equivalent transcript behavior is preferred unless a backend-versioned
  protocol change is explicitly approved

## Background

Earlier optimization work established the main lessons:

- `optimization-v3.md` showed that durable wins came from kernel shape, denser
  local storage, and fused local kernels.
- `optimization-v4.md` showed that route and Worker transport waste was largely
  removed, leaving real ceremony execution as the dominant cost.
- `refactor-64` retained two `CoreBitWordSide` slices:
  - round-core `sigma0` / `sigma1`
  - message-schedule `small_sigma0` / `small_sigma1`

Those slices worked because transient XOR intermediates did not need
commitments until a later boundary. The next rewrite should generalize that
idea across the executor instead of adding more local helper rewrites.

## Current Baseline

Latest retained refactor-64 p50 snapshots:

- native `total_hidden_eval`: about `131.8ms`
- browser hidden eval: about `201.5ms`
- product client artifact bucket: about `450ms` to `472ms`
- server HSS prepare: about `378ms` to `383ms`

The likely byte-equivalent executor-wide win is modest on desktop:

- native hidden eval: about `6ms` to `20ms`
- browser hidden eval: about `10ms` to `30ms`
- product client artifact bucket: about `20ms` to `70ms`

The same percentage may matter more on embedded-class CPUs, where the baseline
could be several times slower and allocation pressure can dominate user-visible
performance.

## Main Hypothesis

The current executor still materializes some words earlier than needed.

The rewrite should classify every internal value by what consumers truly need:

- share bits
- provenance digest
- commitment
- transport or wire material
- debug or checkpoint material

Then each kernel should accept the narrowest valid representation. Commitment
derivation should happen only at explicit consumption boundaries.

## Non-Goals

- Do not revive the insecure direct arithmetic-to-Boolean shortcut that
  reconstructs joined values.
- Do not add duplicate production kernels for fallback.
- Do not add native-only production shortcuts.
- Do not keep compatibility branches after a new executor representation
  becomes the only production path.
- Do not preserve byte-equivalence by broad casts or untyped compatibility
  shapes.
- Do not optimize diagnostics in a way that changes protocol control flow.

## Constant-Time And Security Constraints

- Loop bounds must come from public circuit shape: SHA-512 word width, round
  count, stage/window count, and validated artifact dimensions.
- No secret-dependent branches.
- No secret-dependent indexing.
- No secret-dependent allocation sizes.
- No early return based on secret share contents.
- No division or variable-time arithmetic on secret-derived values.
- No joined hidden-value reconstruction.
- No expanded evaluator-visible or client-visible secret material.
- Any backend-versioned protocol rewrite needs explicit transcript, provenance,
  and verification analysis before implementation.

## Representation Model

The executor should move toward a small set of explicit internal types.

```rust
// Packed share bits and provenance only.
// No commitments.
struct CoreBitWordSide;

// Core left/right pair for a Boolean word.
struct CoreBitWordPair;

// Share bits, provenance, and commitments.
// This is required only at commitment-consuming boundaries.
struct MaterializedBitWordSide;

// Arithmetic word pair used by add/A2B boundaries.
struct ArithmeticWordPair;

// Wire or transport-ready material.
struct TransportWord;
```

Rules:

- A helper that only needs bits and provenance accepts core values.
- A helper that feeds multiplication material accepts materialized values only
  if the multiplication transcript consumes commitments.
- A helper that emits output bundles accepts or returns transport material only
  at the output boundary.
- Conversion from core to materialized form is named, measured, and audited.
- Core logic should not accept raw strings, raw DB/request shapes, or loose
  optional lifecycle objects.

## Materialization Boundaries

The rewrite should make these boundaries explicit:

- multiplication material inputs
- A2B carry-chain inputs that consume commitments
- checkpoint digest computation
- output projector bundle emission
- validation/debug materialization
- transport/wire message construction

Every other materialization should be treated as suspicious until the
commitment-consumption graph proves it is required.

## Phase 1: Commitment-Consumption Graph

Goal:

- map where commitments are consumed and where core values are enough

Tasks:

- [ ] Add a table for every hidden-eval helper and stage:
      `input_sharing`, `add_stage`, `message_schedule`, `round_core`,
      `output_projector`, delivery/open/join, and finalization.
- [ ] Classify each helper input as bits-only, provenance-only,
      commitment-consuming, transport-consuming, or debug-only.
- [ ] Identify all current `LocalBitWordSide` materializations.
- [ ] Mark which materializations are protocol-bound.
- [ ] Mark which materializations are avoidable under byte-equivalence.
- [ ] Add a generated or manually checked graph section to this document.
- [ ] Add a source guard that prevents new implicit materialization helpers in
      hot executor code without updating the graph.

Keep gate:

- no code rewrite in this phase unless it is instrumentation or documentation
- graph must explain why `Ch`, `Maj`, A2B, and output projection are safe or
  blocked

## Phase 2: Materialization Counters

Goal:

- make materialization count and commitment derivation visible before rewriting

Tasks:

- [ ] Add debug-only counters for core words, materialized local words,
      commitment derivations, provenance derivations, and transport words.
- [ ] Add per-stage counters for `message_schedule`, `round_core`,
      `output_projector`, and delivery.
- [ ] Add counters for A2B `new_a_bits` and `new_e_bits`.
- [ ] Add counters for `Ch` and `Maj` multiplication-material paths.
- [ ] Add native benchmark output fields for these counters.
- [ ] Add browser/direct-WASM output fields for the same logical counters.
- [ ] Ensure counters are diagnostic-only and unavailable to protocol control
      flow.

Keep gate:

- counters must not change hidden-eval equivalence output
- counter-enabled timing is diagnostic only

## Phase 3: Executor IR And Type Boundaries

Goal:

- make invalid materialization states hard to express in the executor

Tasks:

- [ ] Promote the existing `CoreBitWordSide` idea into a broader executor-local
      representation module.
- [ ] Add `CoreBitWordPair` for left/right Boolean words.
- [ ] Add explicit materialization functions with names that describe the
      consuming boundary.
- [ ] Split helpers by required input type instead of accepting broad local
      word shapes.
- [ ] Delete helper overloads that exist only to preserve old calling style.
- [ ] Add tests or compile-time fixtures for invalid conversions.
- [ ] Keep all shape fields required: width, side, provenance, and circuit
      stage identity.

Keep gate:

- `hidden_eval_equivalence` must pass before any benchmark matters
- no unsafe casts or broad object-style state replacement

## Phase 4: Message Schedule End-To-End

Goal:

- finish the safest executor-wide slice first

Rationale:

- existing small-sigma `CoreBitWordSide` work already improved the message
  schedule
- message-schedule small sigma has a clear pattern where transient XOR
  commitments are not consumed before final materialization

Tasks:

- [ ] Extend core storage through message-schedule accumulation.
- [ ] Delay materialization until arithmetic addition or checkpoint boundary.
- [ ] Preserve labels, provenance input order, and emitted commitments.
- [ ] Benchmark native hidden eval.
- [ ] Benchmark direct browser/Node HSS artifact.
- [ ] Run product registration smoke only if native and direct-WASM move in the
      same direction.

Keep gate:

- improve `message_schedule` or `total_hidden_eval`
- no `round_core` or output-projector regression beyond noise

## Phase 5: Round-Core Boundary Rewrite

Goal:

- reduce round-core materialization while respecting multiplication and A2B
  proof boundaries

Tasks:

- [ ] Split round-core into explicit sub-kernels:
      `sigma`, `ch`, `maj`, `temp1`, `temp2`, `state3`, `new_a_bits`,
      `new_e_bits`.
- [ ] Keep `sigma` on core storage through the existing retained path.
- [ ] Re-evaluate `Ch` and `Maj` with the graph:
      - if transient commitments feed multiplication material, keep them
        materialized
      - if a byte-equivalent core material input exists, implement it as one
        vertical slice
- [ ] Re-evaluate `temp1` and `temp2` adders for avoidable materialization
      across arithmetic conversion boundaries.
- [ ] Re-evaluate `new_a_bits` and `new_e_bits` A2B as the largest remaining
      round sub-buckets.
- [ ] Reject local operation-count reductions unless they reduce logical
      materialization or improve direct browser worker p50.

Keep gate:

- improve `round_core` p50 in native and browser/direct-WASM
- product artifact bucket must improve before retention

## Phase 6: A2B Kernel Redesign

Goal:

- find larger wins around `round_new_a_bits` and `round_new_e_bits`

Known constraint:

- the insecure joined arithmetic-to-Boolean shortcut is permanently rejected
- the current secure carry-chain shape may require commitments in places that
  local micro-optimizations cannot remove

Tasks:

- [ ] Write a mini-spec for the current A2B proof shape.
- [ ] Identify exactly which commitments bind carry-chain state.
- [ ] Design a byte-equivalent representation rewrite if possible.
- [ ] If byte-equivalence blocks meaningful gains, draft a backend-versioned
      A2B v2 protocol candidate.
- [ ] Add equivalence tests for current backend version.
- [ ] Add negative tests for mismatched labels, provenance, carry order, and
      width.

Keep gate:

- byte-equivalent path must improve both direct-WASM and product p50
- backend-versioned path requires a protocol review before implementation

## Phase 7: Output Projector Rewrite

Goal:

- reduce output-projector logical materialization and bundle construction

Tasks:

- [ ] Use the graph to identify output-projector values that need transport
      material and values that only need core/provenance data.
- [ ] Avoid allocation-only rewrites unless logical materialization falls.
- [ ] Design a staged output projector that emits bundles once.
- [ ] Preserve output labels, masks, client-base behavior, and transcript
      binding.
- [ ] Benchmark native, direct-WASM, and product smoke.

Keep gate:

- reduce logical materializations or transport words
- improve direct browser worker p50
- no product registration regression

## Phase 8: Backend-Versioned HSS v2 Candidate

Goal:

- define the escape hatch if byte-equivalent materialization reaches a plateau

Trigger:

- the commitment-consumption graph shows most remaining commitments are
  protocol-bound
- byte-equivalent representation slices produce only small or noisy gains
- embedded or iOS profiles show HSS remains too slow or memory-heavy

Tasks:

- [ ] Define a new backend version identifier.
- [ ] Specify transcript-label changes explicitly.
- [ ] Specify provenance and commitment rules for the new kernel.
- [ ] Specify A2B v2 if needed.
- [ ] Add downgrade and mismatched-backend negative tests.
- [ ] Add wire compatibility boundaries at request/persistence edges only.
- [ ] Run formal verification and hidden-eval equivalence for the new protocol
      where applicable.

Keep gate:

- meaningful latency or memory gain beyond byte-equivalent rewrite
- clear protocol review
- no widened evaluator-visible secret material

## Phase 9: Embedded And iOS Performance Profile

Goal:

- understand whether HSS should be default, optional, or policy-driven outside
  browser contexts

Target profiles:

- desktop browser with WASM worker
- mobile Safari / iOS WebView
- native iOS Rust or Swift bridge
- low-end ARM64 Linux
- embedded-class ARM board
- memory-constrained runtime with limited allocator throughput

Tasks:

- [ ] Add a benchmark profile that reports wall time, peak memory estimate,
      allocation count, and artifact size.
- [ ] Add a native release benchmark script for ARM64 Linux.
- [ ] Add an iOS-oriented benchmark harness or documented Xcode/Swift bridge
      procedure.
- [ ] Add a low-memory stress benchmark that records allocation count and
      maximum live buffers.
- [ ] Compare native Rust executor, WASM executor, and any iOS bridge path.
- [ ] Record whether HSS should be default, optional, or disabled by policy for
      each runtime class.
- [ ] Add an explicit decision gate for embedded defaults in SDK configuration.

Expected outcome:

- browser contexts likely keep HSS as the stronger default
- iOS/native secure enclave contexts may make HSS policy-driven
- embedded-class devices may require optional HSS, precompute during setup, or
  a backend-versioned compact kernel

## Phase 10: Validation And Formal Checks

Tasks:

- [ ] Run `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
      hidden_eval_equivalence` after each slice.
- [ ] Run full `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
      before retaining any slice.
- [ ] Run `cargo hss-fv verus-check` after retained crypto-kernel changes.
- [ ] Run direct HSS WASM artifact benchmarks before product smoke.
- [ ] Run product registration smoke only after lower-level gates pass.
- [ ] Run source guards for materialization graph drift.
- [ ] Document every rejected candidate with benchmark output and reason.

## Keep And Revert Rules

Keep a slice only if:

- hidden-eval equivalence passes
- constant-time review finds no new secret-dependent behavior
- transcript labels and provenance stay byte-identical for current backend
  version
- native and direct-WASM benchmarks move in a compatible direction
- product registration smoke confirms a real artifact-path win
- complexity is proportional to the measured improvement

Revert or redesign if:

- the win is allocation-only and product timing regresses
- direct-WASM regresses materially
- the change depends on diagnostic state
- the code introduces duplicate production paths
- commitments are skipped where the graph says they are consumed
- the rewrite makes protocol review harder without measurable gain

## Current Todo

- [ ] Build the commitment-consumption graph.
- [ ] Add materialization and commitment counters.
- [ ] Define executor IR type boundaries.
- [ ] Implement the message-schedule end-to-end slice.
- [ ] Implement the round-core boundary slice only after the graph identifies a
      safe target.
- [ ] Draft A2B v2 only if byte-equivalent A2B is blocked by protocol-bound
      commitments.
- [ ] Draft output-projector rewrite only if it reduces logical
      materialization.
- [ ] Add embedded and iOS benchmark profiles.
- [ ] Decide whether embedded HSS is default, optional, or policy-gated.
