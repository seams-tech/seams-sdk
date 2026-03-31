# HSS Refactor Plan

Date updated: March 31, 2026

## Goal

Refactor `crates/ed25519-hss/src` so that:

- benchmark-related code is grouped in one folder
- the crate uses a clearer folder hierarchy by subsystem
- entrypoints are easier to discover and maintain
- the public API surface is thinner and more intentional
- legacy parallel code paths are removed as the refactor lands

This is a structural refactor, not a feature branch. The result should look as
if the new layout had always existed.

## Design Rules

- no legacy flags or deprecated symbols
- no duplicate module trees left behind “for compatibility”
- breaking internal module paths are acceptable
- `lib.rs` should become a thin entrypoint, not a dumping ground
- the secure hot path must not change behavior during pure layout moves
- benchmark and CLI surface should be reorganized around function, not
  historical file names

## Target Layout

```text
crates/ed25519-hss/src/
  lib.rs

  core/
    mod.rs
    context.rs
    error.rs
    fixtures.rs
    reference.rs

  candidate/
    mod.rs
    artifact_stub.rs
    candidate.rs

  artifact/
    mod.rs
    prime_order_encoder.rs
    prime_order_decoder.rs
    prime_order_trace.rs

  ddh/
    mod.rs
    ddh_hss.rs
    hidden_eval.rs
    hidden_eval_executor.rs

  protocol/
    mod.rs
    succinct_hss.rs
    driver.rs

  runtime/
    mod.rs
    prime_order_cpu_executor.rs
    wasm.rs

  benchmark/
    mod.rs
    phase1.rs
    cache.rs
    hidden_eval.rs

  bin/
    bench_cache.rs
    bench_hidden_eval.rs
    bench_cpu_executor.rs
    emit_browser_benchmark_bundle.rs
    emit_candidate_artifact_stub.rs
    emit_candidate_note.rs
    emit_fixture_json.rs
    emit_prime_order_artifact.rs
    prime_order_driver.rs
    profile_fixed_sha512.rs
    run_prime_order_hss.rs
```

## Why This Layout

### `core/`

Stable shared types and the executable reference path:

- context
- error
- fixtures
- reference model

This should be the least surprising part of the crate and the easiest to
depend on from anywhere else.

### `candidate/`

Candidate-model and artifact-stub logic belongs together:

- candidate sizing/specs data
- candidate note generation helpers
- artifact stub helpers

This keeps modeled/specs-only code separate from the actual protocol/runtime.

### `artifact/`

The structured prime-order artifact pipeline is one subsystem:

- encoder
- decoder
- execution trace

These files already behave like one pipeline and should live together.

### `ddh/`

The DDH primitive backend and hidden evaluator are one engine:

- DDH HSS primitive
- hidden-eval IR
- hidden-eval executor

This is the cryptographic execution core and should be grouped as such.

### `protocol/`

The session and wire-message surface is one subsystem:

- prepared session
- wire messages
- role state
- driver-facing library flow

The current driver bin should become a thin CLI wrapper over this library
layer.

### `runtime/`

Execution adapters go here:

- CPU executor
- wasm/browser runtime surface

These are not protocol definitions and should not sit at top level.

### `benchmark/`

All benchmark/report/config logic belongs together:

- phase 1 benchmark
- cache benchmark
- hidden-eval benchmark

This is the first refactor slice because it is the clearest improvement with
the least protocol risk.

## Entry Point Policy

### `lib.rs`

`lib.rs` should:

- declare top-level subsystem modules
- re-export only the intended public API
- avoid long re-export lists for internal-only helpers

Target public surface:

- `core` types needed by users
- `protocol::prepare_prime_order_succinct_hss`
- protocol session/report/wire types
- selected benchmark report/config APIs under non-wasm builds

### `src/bin`

Bins should be thin wrappers around library entrypoints.

Rename the current bins to function-first names:

- `benchmark_cache_artifacts.rs` -> `bench_cache.rs`
- `benchmark_ddh_hidden_eval.rs` -> `bench_hidden_eval.rs`
- `benchmark_prime_order_cpu_executor.rs` -> `bench_cpu_executor.rs`
- `emit_browser_cache_benchmark_bundle.rs` -> `emit_browser_benchmark_bundle.rs`
- `prime_order_succinct_hss_driver.rs` -> `prime_order_driver.rs`
- `run_prime_order_succinct_hss.rs` -> `run_prime_order_hss.rs`

The emitters can keep their current names because they already follow a
function-first pattern.

## Migration Strategy

Move code in slices that preserve behavior and keep tests green after every
step.

### Phase 0 — Freeze the move order

- [x] write this refactor plan
- [ ] agree on target module names and bin names before moving files
- [ ] keep one migration branch/series; do not maintain old and new layouts in
  parallel

### Phase 1 — Group benchmark code first

Move:

- `src/benchmark.rs` -> `src/benchmark/phase1.rs`
- `src/cache_benchmark.rs` -> `src/benchmark/cache.rs`
- `src/ddh_hidden_eval_benchmark.rs` -> `src/benchmark/hidden_eval.rs`

Tasks:

- [ ] create `src/benchmark/mod.rs`
- [ ] update `lib.rs` module declarations
- [ ] update all internal imports
- [ ] keep re-exported benchmark APIs stable where still useful
- [ ] move benchmark bins to the new names
- [ ] delete old benchmark bin files instead of leaving wrappers

Acceptance:

- `cargo test --lib` passes
- benchmark bins still build and run

### Phase 2 — Group artifact pipeline

Move:

- `src/prime_order_encoder.rs` -> `src/artifact/prime_order_encoder.rs`
- `src/prime_order_decoder.rs` -> `src/artifact/prime_order_decoder.rs`
- `src/prime_order_trace.rs` -> `src/artifact/prime_order_trace.rs`

Tasks:

- [ ] create `src/artifact/mod.rs`
- [ ] update all imports across runtime, protocol, and tests
- [ ] keep artifact-specific helper visibility as narrow as possible
- [ ] remove stale comments that still imply a flat layout

Acceptance:

- encoder/decoder/trace tests still pass
- no references remain to the old top-level files

### Phase 3 — Group DDH engine code

Move:

- `src/ddh_hss.rs` -> `src/ddh/ddh_hss.rs`
- `src/hidden_eval.rs` -> `src/ddh/hidden_eval.rs`
- `src/ddh_hidden_eval_executor.rs` -> `src/ddh/hidden_eval_executor.rs`

Tasks:

- [ ] create `src/ddh/mod.rs`
- [ ] update all imports in protocol, wasm, benchmark, and tests
- [ ] keep the secure hot path exactly behavior-preserving during the move
- [ ] delete obsolete top-level references immediately

Acceptance:

- fixture smoke still passes
- hidden-eval benchmark still builds

### Phase 4 — Group protocol/session flow

Move:

- `src/succinct_hss.rs` -> `src/protocol/succinct_hss.rs`

Add:

- `src/protocol/driver.rs`

Tasks:

- [ ] create `src/protocol/mod.rs`
- [ ] move driver-facing orchestration helpers out of the bin and into
  `protocol::driver`
- [ ] turn the process driver bin into a thin CLI wrapper
- [ ] keep wire-message, state, and report types together

Acceptance:

- process-driver test still passes
- separated e2e example still passes

### Phase 5 — Group runtime adapters

Move:

- `src/prime_order_cpu_executor.rs` -> `src/runtime/prime_order_cpu_executor.rs`
- `src/wasm.rs` -> `src/runtime/wasm.rs`

Tasks:

- [ ] create `src/runtime/mod.rs`
- [ ] update cfg-gated module declarations cleanly
- [ ] keep wasm-only exports working

Acceptance:

- native tests still pass
- wasm build still works

### Phase 6 — Group core/reference code

Move:

- `src/context.rs` -> `src/core/context.rs`
- `src/error.rs` -> `src/core/error.rs`
- `src/fixtures.rs` -> `src/core/fixtures.rs`
- `src/reference.rs` -> `src/core/reference.rs`

Tasks:

- [ ] create `src/core/mod.rs`
- [ ] make `core` the canonical home of specs/reference types
- [ ] keep public re-exports stable where intentional

Acceptance:

- fixture and reference tests still pass

### Phase 7 — Group candidate/specs-only code

Move:

- `src/candidate.rs` -> `src/candidate/candidate.rs`
- `src/artifact_stub.rs` -> `src/candidate/artifact_stub.rs`

Tasks:

- [ ] create `src/candidate/mod.rs`
- [ ] keep candidate/specs-only code separate from production protocol/runtime
- [ ] narrow the public API so internal-only candidate helpers stop leaking
  through `lib.rs`

Acceptance:

- candidate artifact/note bins still work

### Phase 8 — Thin `lib.rs`

Tasks:

- [ ] replace the current flat `pub mod ...` list with subsystem modules
- [ ] replace broad re-export dumping with a deliberate public surface
- [ ] remove re-exports that are only used by crate-local bins/tests
- [ ] document the new crate topology at the top of `lib.rs`

Acceptance:

- downstream code used by this repo still compiles
- no duplicate old/new module re-exports remain

### Phase 9 — Rename bins and clean docs

Tasks:

- [ ] rename the benchmark and runtime bins to the new function-first names
- [ ] update README/docs/examples/test invocations
- [ ] remove any doc references to old module paths
- [ ] update generated pkg README if needed

Acceptance:

- `rg` finds no stale references to deleted paths or removed bin names

## Keep / Reject Rules

Keep a refactor slice only if:

- it reduces layout ambiguity
- it does not create duplicate module paths
- it keeps tests green

Reject or revert a slice if:

- it leaves compatibility wrappers behind without strong reason
- it duplicates whole files or module trees
- it mixes layout change with unrelated behavior change

## Verification Checklist

After each phase:

- [ ] `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- [ ] `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --lib -- --nocapture`
- [ ] `cargo test --manifest-path crates/ed25519-hss/Cargo.toml tests::prime_order_succinct_hss_matches_reference_fixture_smoke -- --ignored --nocapture`
- [ ] run the process-driver end-to-end ignored test after protocol/runtime moves
- [ ] run the separated-role example after protocol/runtime moves

After all phases:

- [ ] run a final `rg` for deleted module paths and old bin names
- [ ] confirm there is no duplicate legacy layout left behind

## Immediate Work Order

1. benchmark folder reorg
2. artifact folder reorg
3. DDH folder reorg
4. protocol folder reorg
5. runtime folder reorg
6. core folder reorg
7. candidate folder reorg
8. thin `lib.rs`
9. rename bins and clean docs
