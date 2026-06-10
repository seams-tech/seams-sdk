# Chat 1: Refactor 64 Reduce Latency

Date: June 9, 2026

Status: active handoff.

## Goal

Reduce Ed25519 HSS registration latency while preserving the current HSS trust
model.

The chosen direction is Path A from
`docs/refactor-64-hss-protocol-runtime-latency.md`: keep exportability and
threshold-at-registration. Do not switch to a bootstrap where the client or
server temporarily materializes the full export seed or full signing scalar.

The user-visible target remains around `1500ms` maximum registration time. The
current work has already moved meaningful server work off the post-auth path and
reduced HSS runtime buckets, but the browser wallet-iframe flow is still above
that target.

## Related Plans

- `docs/refactor-59-optimize.md`: full registration benchmark and current
  product-path latency read.
- `docs/refactor-61-registration-prep-parallelism.md`: registration preparation
  orchestration and warmup overlap.
- `docs/refactor-62-hss-prepare-preauth.md`: preauth HSS prepare route split.
- `docs/refactor-64-hss-protocol-runtime-latency.md`: deeper HSS
  protocol/runtime optimization.
- `docs/refactor-65-hss-optional.md`: optional HSS profiles for runtimes where
  HSS is not mandatory.
- `crates/ed25519-hss/optimization.md`: historical crate-level HSS
  optimization notes. Check this before proposing new refactor-64 candidates.

## Trust Model Decisions

- HSS stays valuable for browser contexts because it avoids a point where the
  browser runtime can reconstruct the full export seed or signing scalar during
  registration.
- Exportability is required.
- Threshold-at-registration is required.
- Protocol/runtime changes must preserve transcript labels, provenance inputs,
  fixed public loop bounds, output binding, and no secret-dependent branching,
  indexing, allocation sizing, or variable-time arithmetic.
- Protocol redesign is a last step. First prove whether current latency comes
  from unavoidable cryptographic work or from representation/runtime overhead.

## Completed Registration-Flow Work

Refactor 62 is effectively complete for the current passkey smoke path:

- Added `/wallets/register/prepare`.
- Persisted prepared registration records separately from verified registration
  ceremonies.
- Required `registrationPreparationId` for prepared Ed25519 registration modes.
- Moved Ed25519 HSS server prepare out of `/wallets/register/start`.
- Bound prepared records to grant, digest, wallet id, rp id, signer selection,
  signing root, expected origin, participant ids, auth method, and expiry.
- Added store and route boundary validation.
- Preserved `registrationPreparationId` through combined Ed25519+ECDSA and
  Email OTP worker parser boundaries.

Latest registration smoke run:

- Run ID: `20260609-032110Z`
- Artifact: `benchmarks/registration-flow/out/20260609-032110Z/summary.md`
- Synced report: `docs/benchmarks/registration-flow.md`
- Result: all four passkey smoke scenarios passed.

Important p50 results:

- `walletRegisterPrepareWaitMs`: `0ms` p50 and p95 in all smoke scenarios.
- `registrationWarmupWaitMs`: `0ms` p50 and p95 in all smoke scenarios.
- `walletRegisterStartMs`: `4ms` to `7ms` p50.
- SDK p50:
  - wallet iframe Ed25519-only: `1989ms`
  - wallet iframe Ed25519+ECDSA: `2026ms`
  - host-origin Ed25519-only: `1636ms`
  - host-origin Ed25519+ECDSA: `1692ms`

Interpretation:

- Server HSS prepare is now hidden under the measured passkey proof window.
- Account reservation is not the next best latency lever for the current smoke
  path.
- Finer warmup sub-buckets are useful observability, but warmup wait is already
  zero in the current benchmark.
- Remaining product-path work should focus on client HSS artifact construction,
  finalize, auth proof variability, and wallet-iframe overhead.

## Completed Refactor 64 Work

Retained optimizations and instrumentation:

- Worker-resident HSS session handle removed client-side session
  materialization from the staged artifact path.
- Finalize cached-session fast path removed about `241ms` to `244ms` p50 from
  the product finalize route.
- Output-projector shared client-base candidate retained.
- Output-projector mixed shared-mask candidate retained.
- Direct Ed25519 HSS WASM artifact benchmark added at
  `benchmarks/ed25519-hss-wasm`.
- Hidden-eval logical counters added.
- Native allocation probe added:
  `crates/ed25519-hss/src/bin/benchmark_ddh_hidden_eval_alloc.rs`.
- Allocation probe artifacts added under `docs/benchmarks/refactor-64/`.
- Byte-equivalence harness added before representation rewrites.
- Server ceremony sub-bucket diagnostics added.
- Native registration-path benchmark added:
  `crates/ed25519-hss/src/bin/benchmark_prime_order_registration.rs`.
- Native benchmark artifact added:
  `docs/benchmarks/refactor-64/prime-order-registration-native.json`.

Rejected or reverted candidates:

- First output-projector algebra simplification failed protocol validation.
- A2B destination-reuse improved native p50 but did not improve browser/WASM
  worker path.
- Packed local metadata reduced allocation calls too little and regressed
  browser direct artifact timing.
- Round-state scratch reuse improved native allocation but regressed product
  client-artifact p50.
- Fused output canonicalization saved too little allocation and regressed Node
  direct artifact timing.
- Standalone output-projector label reuse improved native allocation and direct
  artifact timing but regressed product host-origin client-artifact p50.
- Output-projector select-stream reduced native allocation and direct artifact
  p50 but regressed product client-artifact p50 by `15ms` to `30ms`.
- A2B output recycling improved native allocation but regressed direct artifact
  p50 on Node and browser.

## Current Benchmark Evidence

Product registration smoke after preauth prepare and current HSS work:

- SDK p50 is roughly `1.6s` to `2.1s`.
- Browser-observed wallet-iframe p50 is still above the target.
- Client HSS artifact construction remains one of the largest stable buckets.

Native registration-path benchmark:

- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_prime_order_registration -- --samples 6 --warmup 1 --output docs/benchmarks/refactor-64/prime-order-registration-native.json`
- Result:
  - total native registration-style flow p50: `359.445ms`
  - prepare session p50: `98.852ms`
  - client request p50: `14.825ms`
  - server input delivery p50: `25.258ms`
  - client artifact p50: `220.099ms`
  - finalize report p50: `0.497ms`
  - hidden eval total p50: `212.261ms`
  - hidden eval round core p50: `125.912ms`
  - hidden eval output projector p50: `45.984ms`
  - hidden eval message schedule p50: `38.091ms`

Interpretation:

- Native HSS is much faster than browser/WASM product path, so there is a
  runtime and representation gap worth investigating.
- In native release, round core is the largest hidden-eval bucket.
- Output projector remains material, but smaller than round core in the native
  registration-style flow.
- Browser/WASM overhead and representation shape still need attribution before
  choosing the next candidate.

## Validation Already Run

Registration/refactor-62 slice:

- `pnpm -C sdk type-check`
- focused registration orchestration test: `10 passed`
- `pnpm benchmark:registration-flow:smoke`
- `pnpm test:source-guards`: `281 passed`
- `git diff --check`

Native registration benchmark slice:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo check --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_prime_order_registration`
- release benchmark command above
- `git diff --check`

## Current Worktree State

The worktree is intentionally dirty. Do not revert unrelated files.

Known relevant dirty groups:

- Refactor 61/62 registration route split, warmup instrumentation, benchmark
  docs, and registration tests.
- Refactor 64 HSS runtime and benchmark work across `crates/ed25519-hss`,
  `docs/benchmarks/refactor-64`, and
  `docs/refactor-64-hss-protocol-runtime-latency.md`.
- Unrelated dirty voiceID files under `docs/voiceID` and `voiceId/`.

New files from this chat state:

- `docs/chats/chat-1-refactor-64-reduce-latency.md`
- `crates/ed25519-hss/src/bin/benchmark_prime_order_registration.rs`
- `docs/benchmarks/refactor-64/prime-order-registration-native.json`

Other untracked refactor-64 benchmark files were already present before this
handoff document was written.

## Next Steps

1. Add native CPU/flamegraph attribution for `crates/ed25519-hss`.
   The output should separate hashing, commitment derivation, provenance
   derivation, modular arithmetic, A2B carry conversion, output projection, and
   allocator overhead.

2. Add browser/WASM Chrome Performance trace instructions for
   `build_client_owned_staged_evaluator_artifact`.
   The trace should identify WASM compute, JS/WASM boundary calls, worker
   message handling, GC, and memory growth.

3. Use that evidence to choose between:
   - broader output-projector representation rewrite
   - A2B carry-gadget specialization
   - true arena-backed stage-owned execution model

4. Keep using this gate for any candidate:
   - `hidden_eval_equivalence`
   - native allocation/profiling
   - direct WASM artifact timing
   - product `benchmark:registration-flow:smoke`

5. Avoid candidates already shown to be poor trades:
   - standalone `maj`/`ch` helper rewrites
   - allocation-only output-side changes
   - tiny output fusions that improve native allocation but regress product p50
   - native-only fast paths that do not help browser/WASM product registration

## Resume Prompt

Continue refactor-64 by adding native CPU/flamegraph attribution and browser/WASM
trace instructions, then use the evidence to choose the next representation
candidate. Preserve Path A trust model, exportability, and
threshold-at-registration. Do not revert unrelated dirty files.
