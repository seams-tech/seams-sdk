# Succinct Garbling Candidate V0

Date updated: March 25, 2026

## Purpose

This is the first Phase 2 candidate for the fixed-function succinct-garbling /
HSS implementation path in
[`succinct-garbling.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md).

It is intentionally narrow:

- one fixed hidden function:
  - `shared y_client, y_relayer -> d -> SHA-512(d) -> clamp -> a`
- one output projector:
  - `x_client_base`
  - `x_relayer_base`
  - `A = [a]B`
- one evaluator thesis:
  - reuse a context-bound template artifact across rebuild sessions,
  - reuse fixed round structure inside one evaluation,
  - keep the actual succinct/HSS hidden shared-value representation as the
    next explicit unknown.

This note defines the first candidate artifact split and message flow so later
implementations can be measured against a stable target.

## Chosen Backend

The first concrete backend family is the size-optimized prime-order-group
instantiation.

Reason:

- it is the smallest published family in the current paper-backed comparison
  set that is still plausibly relevant to our fixed-function goal
- it keeps the first backend aligned with the product question, which is
  one-time artifact size for rebuild flows

Current formula-based public-data estimates in the crate:

- prime-order size-optimized: `138,256` bytes
- Paillier compressed: `395,536` bytes
- prime-order compute-optimized: `5,320,016` bytes
- lattice RLWE: `74,885,136` bytes

These are backend-family estimates, not measured implementation artifacts.
For the default prime-order candidate, the crate now emits:

- a structured prime-order artifact of exactly `138,256` bytes,
- a deterministic stub artifact of the same size kept only as a cache/load
  benchmark control.

## Candidate Shape

Cross-session template artifact:

- canonical `context_binding`
- stable `candidate_digest`
- stable `round_template_digest`
- backend-specific `succinct_hidden_core_encoding`
  - default Candidate V0 estimate: prime-order size-optimized at `138,256`
    bytes

Default artifact:

- structured sectioned artifact encoding for the prime-order size-optimized
  backend
- explicit sections for:
  - fixed header
  - context descriptor
  - `2^256` addition template
  - message-schedule template
  - round constants
  - round-template blocks
  - clamp/reduce template
  - output-projector template
  - grouped public-data window section
- section payloads now carry fixed-function records rather than generic filler:
  - canonical-context fields
  - one-block `SHA-512` schedule structure
  - real `SHA-512` round constants
  - clamp/reduce parameters for Ed25519 scalar derivation
  - output-share projection formulas
- grouped public-data windows now use backend-specific record classes instead of
  synthetic window stubs:
  - add-lane windows
  - derived message-schedule windows
  - round-constant windows
  - round-state windows
  - output-projector windows
  - normalized participant windows

Per-run public control:

- `client_input_commitment`
- `server_input_commitment`
- `run_binding`

Private inputs:

- client: `y_client`, `tau_client`
- server: `y_relayer`, `tau_relayer`

Hidden internal state:

- `a`

Outputs:

- client: `x_client_base`
- server: `x_relayer_base`
- public: `A`

## Reuse Split

Cross-session reuse:

- context-bound candidate descriptor
- fixed one-block `SHA-512` padding schedule
- fixed output-projector layout

Structural reuse inside one evaluation:

- identical stage order for every run
- same round-template digest for a given context
- batching identical hidden-core stages when an accelerator exists

## Message Flow

1. Server publishes or reuses the cross-session template artifact for the
   canonical context.
2. Client binds `y_client` and `tau_client` into a per-run commitment.
3. Server binds `y_relayer` and `tau_relayer` into a per-run commitment and
   derives a joint `run_binding`.
4. Evaluator executes the fixed hidden core using the round template.
5. Output-share layer emits `x_client_base`, `x_relayer_base`, and `A`.

## Evaluator Plan

CPU fallback:

- rebuild-only safety path
- target latency: at or below `~2 s`

Accelerator path:

- browser WebGPU where available
- native mobile GPU / NPU where available
- target latency: at or below `~750 ms`

## Current Status

Implemented in code:

- candidate model:
  [`candidate.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/candidate.rs)
- candidate emitter:
  [`emit_candidate_note.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/emit_candidate_note.rs)
- frozen reference path for fixture conformance:
  [`reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/reference.rs)
- DDH hidden-eval IR compiler:
  [`hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/hidden_eval.rs)
  - compiles the `262` window records into a DDH-targeted hidden-eval program
  - records active windows, dependency edges, and primitive-op inventory
- DDH primitive baseline:
  [`ddh_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/ddh_hss.rs)
  - transcript-bound `KeyGen`
  - split-word `Share`
  - `EvalAdd`
  - `EvalMult`
  - `Decode`
  - group commitments over the Ed25519 basepoint
- backend-family selector with formula-based size estimates:
  - default: prime-order size-optimized
  - alternates: Paillier compressed, prime-order compute-optimized, lattice
    RLWE
- deterministic artifact stub generator and manifest:
  [`artifact_stub.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/artifact_stub.rs)
  and
  [`emit_candidate_artifact_stub.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/emit_candidate_artifact_stub.rs)
- structured prime-order encoder and manifest:
  [`prime_order_encoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/prime_order_encoder.rs)
  and
  [`emit_prime_order_artifact.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/emit_prime_order_artifact.rs)
  - current encoder version: `prime_order_encoder_v1`
  - keeps the published-size target while replacing synthetic section filler with
    deterministic fixed-function records plus deterministic padding
- browser `IndexedDB` cache benchmark harness and bundle emitter:
  [`indexeddb_cache_benchmark.html`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html)
  and
  [`emit_browser_cache_benchmark_bundle.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/emit_browser_cache_benchmark_bundle.rs)
  - consumes the same exact artifact bytes as the local cache benchmark
  - first smoke-tested in headless Chrome against generated bundle files
  - now also benchmarks structured-artifact decode and execution-trace build
    work from cached bytes
- structured artifact decoder:
  [`prime_order_decoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/prime_order_decoder.rs)
  - decodes header fields and grouped-window records
  - validates the grouped-window class counts for the current prime-order shape
- structured execution-trace builder:
  [`prime_order_trace.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/prime_order_trace.rs)
  - groups the decoded window records into seven fixed-function stages
  - reports preload counts, prime-order evaluator-op totals, derived curve-cost
    totals, and a stable trace checksum for browser/native cross-checks
- native prime-order CPU executor and benchmark:
  [`prime_order_cpu_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/prime_order_cpu_executor.rs)
  and
  [`benchmark_prime_order_cpu_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/benchmark_prime_order_cpu_executor.rs)
  - compiles deterministic point tables and bucket schedules from the decoded
    grouped-window records
  - executes real `curve25519-dalek` point/window work on CPU
  - gives the first measured native baseline against the curve-cost proxy
- browser wasm CPU executor surface:
  [`wasm.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/wasm.rs)
  and
  [`indexeddb_cache_benchmark.html`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html)
  - compiles and runs the same deterministic point/window executor shape in
    browser wasm
  - now matches the native checksum and compressed final point exactly
  - currently measures about `~1.93x` the native `ns / curve-cost-unit` on the
    same desktop host/browser stack
- saved Phase 1 browser collector and baseline reports:
  [`collect_browser_cache_benchmark.mjs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs)
  and
  [`reports/phase1`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase1)
- browser WebGPU probe in the benchmark page:
  [`indexeddb_cache_benchmark.html`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html)
  - current host/browser run reports `apple / metal-3`, kernel
    `digit_recode_v0 + window_bucket_accumulate_v0 + bucket_reduce_v0 + dependency_merge_normalize_v0`,
    `~48.1 ms` setup, and `~241.7 us` backend-shaped dispatch mean over `180`
    active steps
  - per-subkernel means now land at about `~72.9 us` for digit recode,
    `~43.7 us` for window/bucket accumulation, `~75.0 us` for bucket
    reduction, and `~50.0 us` for dependency/normalization
  - the combined bucket pipeline is currently about `~79.3%` of total proxy
    time, and the single dominant subkernel is now the bucket-reduce pass at
    about `~31.0%`
  - this is still a backend-shaped proxy kernel, not the final prime-order
    accelerator evaluator
- cache/download benchmark against approximate cached GC baseline:
  [`cache_benchmark.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/cache_benchmark.rs)
  and
  [`benchmark_cache_artifacts.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/benchmark_cache_artifacts.rs)
- main prepared-session wiring:
  [`succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/succinct_hss.rs)
  and
  [`run_prime_order_succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/run_prime_order_succinct_hss.rs)
  - prepares the context-bound prime-order artifact once
  - compiles the deterministic evaluator program, hidden-eval IR, and DDH
    backend baseline once
  - evaluates a run and emits output shares plus evaluator witness data
  - derives per-run input commitments and run binding through the DDH baseline
    instead of the candidate simulator
- compiled DDH hidden-eval executor:
  [`ddh_hidden_eval_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/ddh_hidden_eval_executor.rs)
  - executes the compiled add stage, message schedule, and round-state core as
    shared-bit DDH evaluation
  - now executes hash-prefix extraction and RFC 8032 clamp as shared-bit DDH
    evaluation
  - now executes scalar reduction mod `l` as shared-bit DDH evaluation
  - now also executes output-share projection as shared-bit DDH evaluation
  - now derives `A` from the projected output shares instead of from clear `a`
  - multiplication no longer expands local cross-terms directly inside
    `eval_mul`; it now consumes preprocessing-style triple material plus
    opened `d` / `e` deltas
  - fast debug tests now cover session preparation and backend/compiler shape,
    while end-to-end hidden-eval conformance lives behind ignored tests because
    the gate-level DDH path is materially more expensive
- delivery path status:
  [`succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/succinct_hss.rs)
  - old sealed client assist request/response flow has been removed
  - garbler now prepares OT-shaped client input offers and retains the
    matching OT sender-state bundles plus remote shares
  - evaluator no longer carries a clone of the full secret-seeded DDH backend;
    it now holds only public evaluation state plus its client-output transport
    key
  - garbler-side OT state is now explicit and role-owned; the prepared session
    exposes it separately, and server-packet generation consumes that explicit
    state instead of hidden session-internal sender-state / remote-share fields
  - the OT transcript is now split into a transmitted client request message
    plus evaluator-local receiver state, rather than one in-process packet that
    mixed both
  - OT request/response preparation is now split across explicit garbler and
    evaluator runtime sessions instead of one coordinator-shaped OT helper path
  - server packets now carry an explicit OT transcript object covering offer,
    request, response, and remote-share release bindings
  - each OT offer word now carries a DDH sender public value rather than OT
    branch ciphertext material
  - evaluator now prepares blinded receiver requests matching its client input
    bits and keeps the receiver scalar state locally
  - garbler responds with branch ciphertexts plus a transcript-bound remote
    share release
  - packet-driven evaluation reconstructs client-owned bundles by opening only
    the selected OT response branch and then joining it with the garbler-held
    transcript-bound remote share release
  - evaluator-side packet validation/open/join/evaluate now runs through the
    explicit evaluator runtime, while garbler/evaluator runtimes each seal
    their own output packet
  - shared immutable runtime state is now explicit too, so prepared-session
    delivery orchestration is mostly delegation rather than hidden coordination
  - garbler/evaluator runtimes now exchange OT offers, requests, responses,
    remote-share releases, and output return through serialized wire messages
    instead of direct Rust packet handoff
  - top-level `evaluate()` now runs through the packetized delivery path
    instead of a clear-input shortcut
  - direct joint-share relayer bundles no longer serialize across the
    interparty packet boundary:
    - `DdhHssSharedWord` and `DdhHssInputShareBundle` are now internal-only
      helpers for local simulation / execution
    - raw server-packet wire messages no longer contain `y_relayer_bundle`,
      `tau_relayer_bundle`, `left_word`, or `right_word`
    - fast negative checks now assert that those fields do not appear in
      evaluator-visible wire bytes
  - the remaining trust-boundary gap is semantic rather than raw serde shape:
    evaluator-side delivery no longer returns generic relayer joint-share
    bundles, and the executor input surface now types relayer inputs
    separately too, but the arithmetic core still operates on fully
    materialized shared words, so the protocol is not yet a full 2-party HSS
    delivery path
  - process-separated garbler/evaluator drivers now exist for that wire path:
    [`prime_order_succinct_hss_driver.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/prime_order_succinct_hss_driver.rs)
    - driver state is now serializable and materializable separately for
      garbler and evaluator roles
    - subprocess coverage now exists for both the fast OT
      offer/request/response round-trip and an ignored end-to-end finalized
      report match against `wraparound-seed`
- native DDH benchmark tool and first saved report:
  [`ddh_hidden_eval_benchmark.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/ddh_hidden_eval_benchmark.rs),
  [`benchmark_ddh_hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/benchmark_ddh_hidden_eval.rs),
  and
  [`ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json)
  - current native release baseline reports about `~1.28 s` total hidden
    eval, with the round core at about `~528.3 ms`, the output projector at
    about `~120.3 ms`, schedule accumulation at about `~138.8 ms`, and
    `temp1` at about `~228.1 ms`
- browser DDH benchmark report:
  [`browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json)
  - current desktop Chrome baseline reports about `~1.70 s` total hidden eval
  - round core still dominates at about `~590.2 ms`
  - output projector is about `~139.9 ms`
  - the new browser substage split shows schedule accumulation at about
    `~153.2 ms`, `temp1` at about `~256.1 ms`, and `temp2` at about `~62.9 ms`
  - browser/native total ratio on this host is about `~1.33x`
  - reference match: `true`
- ignored DDH conformance lane status:
  - all `4` ignored Phase 3b tests now pass
  - the full five-fixture hidden-eval milestone run currently takes about
    `334.90 s` in the debug lane
  - the ignored process-separated end-to-end driver round-trip now also passes
    in about `80.17 s` in the debug lane
  - trust-boundary status:
  - direct joint-share relayer bundles no longer serialize across the interparty
    packet boundary
  - evaluator-side delivery no longer returns generic relayer joint-share
    bundles; sealed server inputs now deserialize into a server-input-specific
    internal payload, and the executor input surface now types relayer inputs
    separately from `DdhHssInputShareBundle`
  - sealed server-input transport ciphertexts now carry one-share left/right
    `DdhHssTransportBundle` pairs instead of joint-share words, and relayer
    joint-share bundles are reconstructed only during explicit server-input
    materialization
  - shared runtime state now materializes `DdhHssEvaluator`, not
    `DdhHssBackend`
  - validation and server-input commitment hashing now also run on that
    server-input-specific executor payload
  - transport-aware relayer addition now avoids reconstituting generic shared
    words for the add stage and projector-side canonical `mod l` path
  - the remaining semantic gap is that derived intermediates still run as
    joined shared words rather than staying role-local end to end

Still intentionally missing:

- real OT/HSS-specific 2-party input/output delivery instead of the current
  OT-shaped local packet baseline built from garbler-prepared client input
  offers with DDH sender public values, garbler-held sender-state bundles,
  evaluator-created blinded requests, evaluator-local receiver state,
  garbler-returned OT branch ciphertext responses, garbler-held transcript-bound
  remote client-share release, sealed transport ciphertext output bundles,
  garbler/evaluator role-gated delivery, and `output_openers()`
  recipient-specific output opening
- network/deployment transport beyond the current local process/file driver
  boundary
- measured artifact bytes from an implementation rather than a formula-backed
  estimate

These are tracked as Phase 3b in
[`succinct-garbling.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md),
gated on Phase 1 hardware profiling confirming that the evaluator can hit the
latency targets on supported devices.

## How To Inspect

```bash
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note -- --backend paillier --json
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_artifact_stub -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_prime_order_artifact -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_cache_artifacts -- --samples 4 --warmups 1
wasm-pack build crates/succinct-garbling-proto --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/succinct-garbling-proto/web/generated
python3 -m http.server 8765 -d crates/succinct-garbling-proto/web
# then open /indexeddb_cache_benchmark.html?bundle=generated/bundle.json&autorun=1
node crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/succinct-garbling-proto/reports/phase1/browser-desktop-chrome-146.json
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_prime_order_cpu_executor -- --json
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin run_prime_order_succinct_hss -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note -- --json
```
