# Succinct Garbling Plan

Date updated: March 24, 2026

## Objective

Build a new fixed-function succinct-garbling protocol for the hidden
Ed25519 seed-expansion step used by the stateless shared-root model.

The implementation target is intentionally narrow:

- one fixed circuit:
  - shared `y_client`, `y_relayer`
  - `d = LE32(y_client + y_relayer mod 2^256)`
  - `h = SHA-512(d)`
  - `a = clamp(h[0..31]) mod l`
- one output type:
  - durable base FROST shares
  - public key `A = [a]B`
- one product goal:
  - beat cached-GC materially on one-time registration / rebuild cost

This is the fixed-function implementation path for hidden Ed25519 seed
expansion in the stateless shared-root model. The scope remains intentionally
narrow so the cryptographic surface stays reviewable and productionizable.

Current project decision for this note:

- focus on succinct garbling now,
- do not spend current implementation effort on mixed-circuit `edaBits` /
  `mv-edabits`,
- do not spend current implementation effort on GC-heavy backend improvements.

The broader SSR note still records those other tracks, but this document is the
active workstream for the succinct-garbling path.

## Terminology

Use the following wording in this note:

- `structured artifact encoding` for the reusable public artifact
- `hidden shared-value representation` for HSS values and hidden evaluator
  values
- `OT branch ciphertext` for encrypted OT branch material
- `sealed transport ciphertext` for sealed transport packets

Avoid bare `encoding` when it is ambiguous whether the text means the public
artifact, hidden shared values, or encrypted transport material.

## Domain Context

This work exists inside the stateless shared-root Ed25519 design in
[`stateless-shared-root-ed25519.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/stateless-shared-root-ed25519.md).

The domain-specific constraints are:

- the canonical secret must be a standard Ed25519 seed `d`,
- export must remain compatible with standard NEAR `ed25519:` private-key
  export,
- signing must use threshold / FROST shares of the Ed25519 signing scalar `a`,
- neither the client nor the server may ever see plaintext `d`,
- neither the client nor the server may ever see plaintext `a`,
- we want one Ed25519 lifecycle, not separate "export key" and "signing key"
  lifecycles.

That means this work is not solving a generic threshold-signing problem.
It is solving one specific hidden conversion problem:

- root-share domain:
  - client holds `y_client`
  - server holds `y_relayer`
- canonical seed:
  - `d = LE32(y_client + y_relayer mod 2^256)`
- signing scalar:
  - `a = clamp(SHA-512(d)[0..31])`
- threshold-signing state:
  - durable base FROST shares derived from that same `a`

This distinction matters because:

- threshold signing uses shares of `a`,
- wallet export uses canonical seed `d`,
- `d -> a` is nonlinear,
- so additive shares over `d` cannot be transformed locally into threshold
  shares over `a`.

That hidden `d -> a` step is the reason this implementation path exists at all.

## Where This Fits In The Product

This path is only relevant for the rare share-construction and rebuild
flows:

- registration,
- key rotation,
- link-device,
- recovery / rebuild after local wrapped-share loss or server cache loss.

It is not for the ordinary transaction-signing hot path.

The normal product design remains:

- server stores durable `x_relayer_base`,
- client stores durable wrapped `x_client_base`,
- unlock derives a KEK from WebAuthn PRF output and unwraps `x_client_base`
  into worker memory,
- hot-path signing uses those base shares directly.

So the benchmark question is not:

- "is this faster than everyday signing?"

It is:

- "is this materially better than cached GC for one-time registration and
  rebuild?"

## Why This Exists

The cached-GC approach is a plausible pure-crypto fallback, but it still has a
large one-time payload cost during registration / rebuild.

This work asks a narrower question:

- can we build a fixed-function succinct-garbling protocol for exactly one-block
  RFC 8032 seed expansion
- that materially reduces communication/storage cost
- without changing the SSR lifecycle

## Evaluation Thesis

The core product question is not just whether the structured artifact encoding
is smaller. It is
whether the evaluator can run it fast enough on the client devices we actually
care about.

Working thesis:

- communication reduction matters only if evaluator-side latency stays inside
  the rebuild UX budget,
- the feasibility thesis is hardware-assisted evaluation on consumer devices,
  especially mobile GPU / NPU paths where the platform exposes usable compute,
- CPU-only fallback still matters and must be measured explicitly.

Evaluation-time targets:

- preferred:
  - desktop-class evaluator latency at or below ~250 ms,
  - mobile-class evaluator latency at or below ~750 ms with the intended
    accelerator path enabled,
- acceptable rebuild-only fallback:
  - mobile-class CPU-only evaluation at or below ~2 s,
- kill threshold:
  - if supported-device evaluation remains multi-second even with the intended
    accelerator path,
  - or if the accelerator path is not actually available on the platforms we
    need to ship.

## Non-Negotiable Invariants

This implementation must preserve all of the following:

- one canonical public key per `(orgId, accountId, keyPurpose, keyVersion)`,
- one stateless shared-root lifecycle,
- one export model based on canonical seed `d`,
- one signing model based on threshold shares of `a`,
- no alternate local-only Ed25519 lifecycle,
- no server-visible plaintext `d`,
- no client-visible plaintext `d`,
- no server-visible plaintext `a`,
- no client-visible plaintext `a`.

If a candidate protocol violates any of those, it is out of scope.

## Scope

In scope:

- hidden evaluation of:
  - `m = y_client + y_relayer mod 2^256`
  - `d = LE32(m)`
  - one-block `SHA-512(d)` with fixed padding
  - `a = clamp(h[0..31]) mod l`
- hidden output as durable base FROST shares
- public verification output `A`
- benchmarking against cached GC as the baseline

Out of scope:

- general-purpose succinct garbling
- ordinary transaction-signing hot path
- export flow redesign
- enclave / TEE work
- full product integration before the remaining transport, security-review, and
  performance gates are complete

## Fixed Ideal Functionality

Freeze one ideal functionality `F_expand`.

Private inputs:

- client:
  - `y_client in Z_(2^256)`
  - `tau_client in F_l`
- server:
  - `y_relayer in Z_(2^256)`
  - `tau_relayer in F_l`

Internal computation:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`
- `A = [a]B`

Outputs:

- client learns `x_client_base`
- server learns `x_relayer_base`
- both learn `A`

Invariant:

- `a = 2 * x_client_base - x_relayer_base mod l`

Security goal:

- neither client nor server learns plaintext `d`
- neither client nor server learns plaintext `a`
- each side learns only its own durable base share plus public verification data

## Protocol Mental Model

This protocol has two hidden data paths that meet at the output-share projector.

Seed path:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

Share path:

- `tau_client + tau_relayer -> tau`

Output-share projection:

- `x_client_base = a + tau`
- `x_relayer_base = a + 2 * tau`

Important distinction:

- `d` is the canonical hidden seed,
- `a` is the canonical hidden signing scalar derived from `d`,
- `tau` is a hidden rerandomization value for the output-share projection,
- `x_client_base` and `x_relayer_base` are the actual durable signing shares.

So this protocol is not "sharing two signing secrets." It is:

- one hidden canonical secret chain `d -> a`,
- one hidden rerandomization path `tau_client + tau_relayer -> tau`,
- one projection from those hidden values into durable signing shares.

## HSS And OT In This Note

When this note says `HSS`, it means a homomorphic-secret-sharing-style hidden
evaluation surface for this fixed function.

For the current DDH baseline, that primitive surface is:

- `KeyGen`
- `Share`
- `EvalAdd`
- `EvalMult`
- `Decode`

Role split:

- OT is the private input-delivery mechanism for client-owned bits,
- HSS is the hidden-computation mechanism once the inputs are represented as
  hidden shared values.

Informally:

- OT answers: "how does the client privately inject its input bits?",
- HSS answers: "how do we compute on hidden values after those inputs are
  represented as hidden shared values?".

## High-Level Flow

Prepare once for a canonical context:

1. server prepares the context-bound artifact,
2. server compiles the artifact into a hidden-eval program,
3. server prepares the HSS backend state and evaluation key,
4. server prepares OT offer material for `y_client_bits` and `tau_client_bits`.

Per run:

1. client derives `y_client` and samples/holds `tau_client`,
2. client uses OT to request only the branches matching its actual input bits,
3. server resolves those OT requests and contributes hidden server input
   material for `y_relayer` and `tau_relayer`,
4. evaluator reconstructs the client-owned hidden bundles from the OT response
   plus garbler-held remote material,
5. evaluator executes the compiled hidden-eval program over:
   - `y_client_bits`
   - `y_relayer_bits`
   - `tau_client_bits`
   - `tau_relayer_bits`
6. output-share projection emits hidden `x_client_base` and
   `x_relayer_base`,
7. each side opens only its own output share plus public verification data.

## Security Boundary Reminder

In the intended 2-party design, the evaluator may receive only server-input
hidden shared-value representations that are sufficient to evaluate, but
insufficient to recover plaintext `y_relayer` or plaintext `tau_relayer`.

That means the final deployed protocol must not treat any same-process or local
packet baseline that exposes fully decodable server-owned share bundles as the
real security boundary.

Design rule:

- the evaluator may evaluate on hidden server input,
- the evaluator must not receive enough material to decode that server input
  into plaintext.

## Design Principles

1. Narrow the invention target.
   We are not inventing a general succinct-garbling framework. We are trying to
   build a compact fixed-function structured artifact encoding for exactly
   one-block RFC 8032
   seed expansion.

2. Keep point multiplication outside the hidden computation.
   The protocol should output hidden base shares and public `A`, not perform
   general elliptic-curve arithmetic inside the secure layer.

3. Reuse the repeated structure.
   The function shape is fixed. Padding is fixed. Only the secret shares change.
   The implementation should aggressively exploit that, but "reuse" must be split
   into:
   - cross-session artifact reuse for the same account/context,
   - internal round-template amortization inside one evaluation.

4. Benchmark against the real baseline.
   The baseline is cached GC for registration / rebuild, not generic MPC.

5. Add kill criteria early.
   If the implementation does not materially beat cached GC, stop.

## Protocol Layers

Treat the protocol as three layers.

### 1. Input-share layer

Goal:

- accept hidden `y_client` and hidden `y_relayer`
- bind them to canonical SSR context

Responsibilities:

- define input delivery
- define client/server private input API
- define context binding:
  - `orgId`
  - `accountId`
  - `keyPurpose`
  - `keyVersion`
  - `participantIds`
  - `derivationVersion`

### 2. Nonlinear expansion layer

Goal:

- evaluate the fixed hidden function:
  - `shared y_client, y_relayer -> d -> SHA-512(d) -> clamp -> a`

This is the core research problem.

Responsibilities:

- fixed one-block `SHA-512`
- fixed padding only
- clamp logic
- compact hidden shared-value representation for evaluation
- evaluation-time transcript binding
- evaluator hardware plan:
  - CPU-only fallback,
  - browser/native accelerator path if available,
  - explicit batching / parallelism assumptions

### 3. Output-share layer

Goal:

- convert the hidden result into durable base FROST shares
- expose public `A`

Responsibilities:

- apply hidden rerandomization using `tau_client`, `tau_relayer`
- emit:
  - `x_client_base`
  - `x_relayer_base`
  - `A`
- verify:
  - `A = [2 * x_client_base - x_relayer_base]B`

## Research Questions

The first questions to answer are:

1. Can we represent the fixed one-block `SHA-512 + clamp` computation in a much
   smaller structured artifact encoding than cached GC?
2. What is reusable across sessions for the same canonical context, and what is
   only reusable structurally inside one evaluation?
3. Can that structured artifact encoding plus hidden shared-value
   representation be evaluated fast enough on realistic client hardware,
   especially the mobile/browser evaluator?
4. Can accelerator paths on consumer devices actually close the evaluation gap,
   or is the browser/native compute stack too weak or too fragmented?
5. Can round-template amortization materially reduce evaluator work for the
   fixed SHA-512 shape, or does the fixed-function advantage mostly help
   artifact size?
6. Can we keep the protocol reviewable, or does the compactness make the design
   too opaque to trust?
7. Does the protocol still admit a clean active-security story?

## Phased Todo List

### Phase 0 — Freeze the ideal functionality as executable specs plus fixtures

This must happen first. Otherwise the protocol work will drift.

Tasks:

- [x] freeze `F_expand`
- [x] freeze the exact input/output types
- [x] freeze that this is a registration / rebuild-only backend experiment
- [x] freeze cached GC as the benchmark baseline
- [x] create the dedicated crate:
  - `crates/succinct-garbling-proto/`
- [x] implement a plaintext reference path for:
  - `m = y_client + y_relayer mod 2^256`
  - `d = LE32(m)`
  - `h = SHA-512(d)`
  - `a = clamp(h[0..31]) mod l`
  - `x_client_base = a + tau`
  - `x_relayer_base = a + 2 * tau`
  - `A = [a]B`
- [x] generate deterministic fixtures for:
  - `y_client`
  - `y_relayer`
  - `m`
  - `d`
  - `h`
  - `a_bytes`
  - `a`
  - `tau_client`
  - `tau_relayer`
  - `x_client_base`
  - `x_relayer_base`
  - `A`
- [x] add invariant/property tests for:
  - endianness
  - clamp bit positions
  - `a = 2 * x_client_base - x_relayer_base mod l`
  - `A = [a]B`
  - canonical-context binding
- [x] freeze the serialized fixture format so later backends must conform to it

Deliverables:

- executable reference spec
- deterministic fixture corpus
- invariant/property test suite

Status:

- completed in `crates/succinct-garbling-proto/`
- committed fixture corpus frozen at
  `crates/succinct-garbling-proto/fixtures/f_expand_v1.json`

### Phase 1 — Evaluation and hardware profiling

Only after the ideal function is frozen should we measure where the real cost
is. For this workstream, succinct garbling is the chosen implementation path,
not a deferred fallback. Mixed-circuit `edaBits` / `mv-edabits` and GC-heavy
backend improvements are intentionally out of scope for this note so the team
can drive the succinct-garbling path to completion. The gate structure of
one-block `SHA-512 + clamp` is already broadly understood. The open question is
evaluator performance on actual client hardware.

Tasks:

- [ ] benchmark evaluator-side latency on representative hardware:
  - desktop CPU
  - mobile CPU
  - mobile/browser GPU path where available
  - native mobile GPU / NPU path where available
- [ ] measure accelerator setup overhead versus steady-state batched throughput
- [ ] measure per-round / per-level concurrency actually available on target
  hardware
- [ ] measure whether round-template amortization changes evaluation cost
  materially
- [ ] separate:
  - cross-session artifact reuse,
  - internal structural reuse inside one evaluation
- [x] measure exact output width actually needed
- [x] break down the cost of:
  - addition to form `m`
  - one-block `SHA-512`
  - clamp
  - scalar reduction / packing
  - output-share derivation
  - separate hidden-core expansion from public-key derivation
- [ ] record the device/browser/runtime matrix for every benchmark result

Deliverable:

- profiler report showing whether the evaluator can hit the explicit latency
  targets on the hardware we care about

Status:

- benchmark harness implemented in `crates/succinct-garbling-proto/src/benchmark.rs`
- CLI entrypoint available via
  `crates/succinct-garbling-proto/src/bin/profile_fixed_sha512.rs`
- current native CPU runs cover:
  - output-width accounting,
  - per-component cost breakdown,
  - CPU thread-scaling,
  - thread setup versus steady-state batch timing
- the measurement boundary is now explicit:
  - hidden core (`SHA-512 + clamp + scalar reduction`) is measured separately
    from `A = [a]B`
  - current native baseline is approximately:
    - hidden core: `~172 ns/op`
    - `public_key_mul`: `~20.0 us/op`
    - full `F_expand`: `~21.7 us/op`
- target-device CPU/GPU/NPU runs are still pending

### Phase 2 — Candidate structured artifact encoding design

Tasks:

- [ ] design the smallest reusable structured artifact encoding we can for the
  fixed nonlinear core
- [ ] specify:
  - what is precomputed once
  - what is sent per run
  - what is bound to context
  - what is reusable across sessions vs only reusable structurally inside one
    evaluation
  - what the evaluator computes
  - what the hardware acceleration path is
  - what the CPU-only fallback is
- [ ] keep the design fixed-function only

Deliverables:

- protocol sketch
- message flow
- artifact inventory
- accelerator plan

Status:

- first candidate note checked in at
  [`succinct-garbling-candidate-v0.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-candidate-v0.md)
- code-level candidate model implemented in
  `crates/succinct-garbling-proto/src/candidate.rs`
- oracle-backed simulation available via
  `crates/succinct-garbling-proto/src/bin/emit_candidate_note.rs`
- first concrete backend family selected:
  - prime-order size-optimized,
  - estimated public data: `138,256` bytes from the paper-backed formula
- structured prime-order artifact now available for the default backend:
  - exact structured artifact size: `138,256` bytes
  - sectioned manifest emitted by
    `crates/succinct-garbling-proto/src/bin/emit_prime_order_artifact.rs`
  - section payloads now include fixed-function records for:
    - canonical context
    - one-block `SHA-512` schedule structure and round constants
    - Ed25519 clamp/reduce parameters
    - output-share projection formulas
    - deterministic grouped public-data window manifests
  - grouped public-data windows now use backend-specific record classes for:
    - add lanes
    - derived message-schedule words
    - round constants
    - round-state records
    - output-projector records
    - normalized participants
- deterministic stub artifact retained only as a benchmark/control artifact:
  - exact stub size: `138,256` bytes
  - cacheable manifest and digest emitted by
    `crates/succinct-garbling-proto/src/bin/emit_candidate_artifact_stub.rs`
- alternate modeled families are available for comparison:
  - Paillier compressed: `395,536` bytes
  - prime-order compute-optimized: `5,320,016` bytes
  - lattice RLWE: `74,885,136` bytes
- main prime-order prepared-session path now wired in
  [`succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/succinct_hss.rs)
  and
  [`run_prime_order_succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/run_prime_order_succinct_hss.rs)
  - prepares the context-bound prime-order artifact once
  - compiles the deterministic evaluator program once
  - binds a run and returns `x_client_base`, `x_relayer_base`, and `A`
  - includes artifact/evaluator evidence in the returned report
- real cryptographic hidden-evaluation backend code for these families is still
  intentionally missing

### Phase 2b — DDH HSS primitive baseline

The default implementation branch is now explicitly the size-optimized
prime-order / DDH family.

Reason:

- artifact size is the deciding axis for this track
- current modeled sizes are:
  - prime-order size-optimized: `138,256` bytes
  - Paillier compressed: `395,536` bytes
  - lattice RLWE: `74,885,136` bytes
- the DDH branch preserves the current `~8.7x` size win versus the cached-GC
  baseline at `~1.2 MB`
- the crate already targets prime-order groups end to end:
  - `curve25519-dalek` arithmetic,
  - prime-order encoder/decoder,
  - prime-order CPU executor,
  - prime-order prepared-session path

Tasks:

- [x] implement the concrete DDH HSS primitive surface:
  - `KeyGen`
  - `Share`
  - `EvalAdd`
  - `EvalMult`
  - `Decode`
- [x] compile the 262 window records into a gate/evaluator program that
  consumes those primitive operations
- [x] implement the per-run input delivery protocol baseline for `y_client`,
  `y_relayer`, `tau_client`, and `tau_relayer`
- [x] benchmark real per-gate DDH operations on native surface
- [ ] benchmark real per-gate DDH operations on browser surface
- [ ] stop the branch early if the real DDH hidden evaluator misses the
  latency budget badly enough that the artifact-size advantage no longer
  matters

Phase 2b DDH dependency shortlist in
`crates/succinct-garbling-proto/Cargo.toml`:

- `curve25519-dalek = { version = "=4.1.3", features = ["group", "rand_core"] }`
- `group = "0.13.0"`
- `ff = "0.13.1"`
- `rand_core = { version = "0.6.4", features = ["getrandom"] }`
- `subtle = "2.6.1"`
- `zeroize = { version = "1.8.2", features = ["zeroize_derive"] }`
- `merlin = "3.0.0"`

Intended use:

- `curve25519-dalek`: concrete prime-order point/scalar arithmetic
- `group` / `ff`: generic traits for the DDH primitive boundary
- `rand_core`: key generation and share-sampling traits
- `subtle`: constant-time conditional logic around secret-dependent paths
- `zeroize`: secret-share and key material erasure
- `merlin`: transcript binding for key generation, run binding, and proof-like
  state where needed

Status:

- DDH hidden-evaluation IR compiler now implemented in
  `crates/succinct-garbling-proto/src/hidden_eval.rs`
  - compiles the 262-window prime-order artifact into a DDH-targeted fixed
    hidden-evaluation program
  - records active windows, dependency edges, and primitive-op inventory
- first DDH primitive baseline now implemented in
  `crates/succinct-garbling-proto/src/ddh_hss.rs`
  - transcript-bound `KeyGen`
  - byte/word `Share`
  - `EvalAdd`
  - `EvalMult`
  - `Decode`
  - group commitments for the split word shares using the Ed25519 basepoint
- prime-order prepared-session path now owns the DDH baseline in
  `crates/succinct-garbling-proto/src/succinct_hss.rs`
  - prepares the compiled hidden-eval IR once
  - prepares the DDH backend and evaluation key once
  - derives per-run client/server input commitments and run binding through the
    DDH baseline instead of the candidate simulator
- this is the current concrete DDH primitive foundation for the library:
  - remaining work is final 2-party delivery semantics, security review, and
    performance hardening
- first DDH primitive and hidden-eval benchmark tooling now implemented in
  `crates/succinct-garbling-proto/src/ddh_hidden_eval_benchmark.rs`
  - runnable CLI:
    `crates/succinct-garbling-proto/src/bin/benchmark_ddh_hidden_eval.rs`
  - first saved release report:
    `crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json`
  - current native release baseline on `wraparound-seed`:
    - `share_bit`: `~44.3 us`
    - `eval_add_bit`: `~1.74 us`
    - `eval_mul_bit`: `~2.07 us`
    - prepare: `~111.2 ms`
    - total hidden eval: `~1.28 s`
    - input sharing: `~22.8 ms`
    - add stage: `~14.3 ms`
    - message schedule: `~169.7 ms`
    - round core: `~528.3 ms`
    - output projector: `~120.3 ms`
    - substage split: schedule accumulation `~138.8 ms`, `temp1` `~228.1 ms`,
      `temp2` `~56.8 ms`
  - first browser wasm DDH benchmark surface now also implemented through:
    - `crates/succinct-garbling-proto/src/wasm.rs`
    - `crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html`
    - `crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs`
  - first Chrome report saved at:
    `crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json`
  - browser wasm DDH path now benchmarks cleanly after switching the internal
    stage timers onto a wasm-safe monotonic clock
  - current desktop Chrome baseline on `wraparound-seed`:
    - prepare: `~222.0 ms`
    - total hidden eval: `~1.70 s`
    - input sharing: `~150.6 ms`
    - add stage: `~31.7 ms`
    - message schedule: `~183.6 ms`
    - round core: `~590.2 ms`
    - output projector: `~139.9 ms`
    - substage split: schedule accumulation `~153.2 ms`, `temp1` `~256.1 ms`,
      `temp2` `~62.9 ms`
    - browser/native total ratio on this host: `~1.33x`
    - reference match: `true`

### Phase 3 — Output-share integration

Tasks:

- [x] layer the base-share output protocol on top of the hidden `a` result
- [x] combine with `tau_client`, `tau_relayer`
- [x] emit:
  - `x_client_base`
  - `x_relayer_base`
  - `A`
- [x] validate against the frozen executable spec and fixture corpus

Deliverable:

- end-to-end hidden expansion path with share outputs

Status:

- end-to-end prime-order prepared-session path now implemented in
  [`succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/succinct_hss.rs)
  - `prepare_prime_order_succinct_hss(context)` builds the candidate, artifact,
    compiled hidden-eval IR, DDH backend baseline, and compiled evaluator once
  - `evaluate(input)` binds the run and returns the output shares plus evaluator
    witness data
- runnable CLI implemented in
  [`run_prime_order_succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/run_prime_order_succinct_hss.rs)
- fixture-conformance tests added in
  [`lib.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/lib.rs)
- the prepared-session path no longer depends on the candidate simulator for
  per-run bindings or input sharing
- the nonlinear stage now executes through the compiled DDH hidden-eval
  program:
  - add stage now executes as a `256`-bit shared carry chain
  - message schedule now executes over shared bits using `σ0` / `σ1` and
    shared adders instead of decoded `u64` words
  - round stages now execute over shared bits using `Σ0` / `Σ1`, `Ch`, `Maj`,
    and shared adders instead of decoded `u64` words
  - hash-prefix extraction and RFC 8032 clamp now execute over shared bits
    before decode
  - scalar reduction mod `l` now also executes over shared bits before decode
  - output-share projection now also executes over shared bits before decode
  - public-key derivation now runs from the projected output shares instead of
    from clear `a`, so the hidden scalar core is no longer decoded early for
    `A`
- the cryptographic backend is still incomplete because the remaining
  client/server delivery path is still a local bundle/commitment baseline
  rather than a real OT/HSS-specific 2-party protocol

### Phase 3b — Full hidden evaluator (gated on Phase 1 hardware results)

This phase starts only after Phase 1 hardware profiling confirms that the
evaluator can plausibly hit the latency targets on supported devices. If the
hardware benchmarks show that real group operations (not proxy kernels) miss
the targets, this phase does not start — this implementation path hits a kill
criterion instead.

Gate condition:

- measured per-curve-cost-unit latency on mobile GPU / WebGPU is within range
  of the ~750 ms mobile target given the derived curve-cost total (~62,748
  units),
- OR measured CPU-only latency on mobile is within range of the ~2 s fallback
  target.

Tasks:

- [x] extend the DDH primitive baseline into a compiled hidden evaluator:
  - remove direct interpretation of the nonlinear stage
  - execute the compiled hidden-eval program window by window
  - keep the session API bound to the same artifact and run-binding surface
- [x] implement gate-level add-lane evaluation using the existing window
  records:
  - `256`-bit carry-chain evaluator over shared bits
- [x] implement gate-level schedule-derived evaluation using the existing
  window records:
  - `σ0` / `σ1` and shared adders over the one-block `SHA-512` schedule
- [x] implement gate-level round-state core evaluation using the existing
  window records:
  - `Σ0` / `Σ1`, `Ch`, `Maj`, and shared adders
- [x] implement hidden output-projector evaluation using the existing window
  records:
  - [x] hash-prefix extraction and RFC 8032 clamp over shared bits
  - [x] reduction mod `l` over shared bits
  - [x] output-share projection over shared bits
  - [x] public-key derivation without decoding the hidden core early
- [ ] implement the 2-party input delivery protocol:
  - [x] server-side evaluation key generation from the context-bound artifact
  - [x] define what is sent per-run vs what is cached with the artifact
  - [x] baseline client/server delivery packet surface over the current local
    simulation boundary
  - [x] split the DDH transport/backend surface into explicit garbler and
    evaluator roles, with role-gated output opening
  - [x] sealed transport ciphertext envelopes for output return
  - [x] explicit garbler/evaluator role split for multiplication and delivery
    material
  - [x] remove local cross-term expansion from `eval_mul`:
    - multiplication now consumes preprocessing-style triple material
    - the evaluator no longer computes `ll + lr + rl + rr` directly
  - [x] OT-shaped client input offer/selection baseline:
    - garbler prepares per-bit client input offers plus garbler-held remote
      shares
    - evaluator selects only the local branch matching `y_client` /
      `tau_client`
    - evaluation reconstructs client-owned bundles from evaluator-selected
      local shares plus garbler-held remote shares
  - [x] cryptographically masked OT branch ciphertext baseline:
    - client OT offers no longer expose both left-share branches in clear
    - garbler now encrypts each OT branch ciphertext under per-branch
      transport keys
    - evaluator materializes only the selected local branch through the role
      API
  - [x] explicit OT selection request / garbler response baseline:
    - client delivery packet now carries branch-selection requests instead of
      resolved local shares
    - garbler resolves the selected local branch into the server packet
    - evaluator reconstructs the client-owned bundles from garbler-resolved
      local shares plus garbler-held remote shares
  - [x] DDH-style blinded OT request / response baseline:
    - offers now carry per-bit sender public values instead of OT branch
      ciphertext material
    - client packets now carry blinded receiver requests plus local receiver
      state
    - server packets now carry branch ciphertext responses plus the remote
      share half
    - evaluator opens only the selected branch from the response using its
      local receiver state
  - [x] explicit garbler-held OT sender state:
    - garbler now retains per-bit OT sender-state bundles for the prepared
      session
    - OT response generation no longer rederives sender scalars from the
      backend seed
  - [x] transcript-bound remote-share release:
    - server packets now carry transcript-bound remote-share releases instead
      of raw remote-share bundles
    - packet validation now checks offer/request/response transcript binding
      before joining evaluator-local and garbler-held shares
  - [x] split runtime ownership so the evaluator no longer clones the full
    secret-seeded backend:
    - evaluator role now carries only public evaluation state plus its
      client-output transport key
    - garbler retains the secret-seeded backend, OT sender state, and
      server-output transport ownership
  - [x] externalize garbler-side OT state into an explicit role-owned delivery
    state:
    - prepared session now exposes garbler OT state separately from the public
      client OT offer and delivery material
    - server-packet generation now consumes explicit garbler OT state instead
      of session-internal sender-state and remote-share fields
  - [x] split the OT transcript into transmitted messages plus role-local
    state:
    - client OT request packets now carry only blinded request messages
    - evaluator-local receiver state now stays local instead of crossing the
      delivery boundary
    - server-packet generation now consumes the transmitted OT request plus
      explicit garbler OT state
  - [x] split OT request/response preparation across explicit garbler/evaluator
    runtime sessions:
    - prepared session now exposes `split_runtime()` for the delivery path
    - garbler OT runtime now owns the prepared client OT offer, garbler OT
      state, and server-packet generation
    - evaluator OT runtime now owns client request preparation and evaluator
      local receiver state
  - [x] move delivery-path packet evaluation and output completion onto the
    explicit role-owned runtimes:
    - evaluator runtime now validates, opens, joins, and evaluates the client
      delivery path
    - garbler/evaluator runtimes now seal their own server/client output
      packets
    - prepared session now delegates packet-flow execution instead of owning
      the full delivery-path control flow directly
    - prepared session now exposes a shared runtime plus garbler/evaluator
      runtime sessions through `split_runtime()`
  - [x] materialize the OT exchange as an explicit transcript object:
    - server packets now carry an explicit OT transcript with offer, request,
      response, and remote-release bindings
    - garbler-held remote-share release is now validated against that explicit
      OT transcript instead of a session-local coordinator shortcut
  - [x] move the OT exchange and output return onto serialized wire messages:
    - garbler/evaluator runtimes now exchange transmitted OT offers, requests,
      responses, remote-share releases, and output return as serialized wire
      messages instead of direct Rust packet handoff
    - evaluator-local OT receiver state still stays local and does not cross
      the interparty wire boundary
  - [x] split the wire-message path across real garbler/evaluator drivers or
    processes:
    - driver state is now serializable and materializable for garbler and
      evaluator roles separately
    - `prime_order_succinct_hss_driver` now executes the OT offer/request,
      server response, evaluator result, and garbler finalize steps as
      separate process invocations over wire-message files
    - subprocess-backed tests now cover both the fast OT message round-trip
      and an ignored end-to-end report match against the frozen fixture path
  - [ ] network/deployment transport beyond the current local process/file
    driver boundary
- [x] verify hidden evaluator output matches fixtures for all 5 test vectors
- [x] measure total evaluation time and actual artifact size (not formula
  estimate)

Kill criteria for this phase:

- if per-gate HSS operation exceeds 100 μs on the target evaluator surface,
  the instantiation must change or the track stops
- if total artifact size exceeds cached GC (~1.2 MB), the size advantage is
  lost
- if the hidden evaluator cannot reproduce all 5 fixture outputs, the
  implementation is wrong

Deliverables:

- full DDH hidden evaluator for the chosen prime-order instantiation
- gate compiler that consumes the existing 262-window artifact and produces
  HSS evaluation schedules
- end-to-end hidden evaluator that replaces the remaining direct-interpretation
  path in
  `succinct_hss.rs`
- measured artifact size and evaluation latency (replacing formula estimates)

Status:

- compiled DDH hidden-eval executor now implemented in
  `crates/succinct-garbling-proto/src/ddh_hidden_eval_executor.rs`
  - executes the compiled add stage, message schedule, and round-state core as
    shared-bit DDH evaluation
  - now also executes hash-prefix extraction and RFC 8032 clamp as shared-bit
    DDH evaluation
  - now also executes scalar reduction mod `l` as shared-bit DDH evaluation
  - now also executes output-share projection as shared-bit DDH evaluation
  - now derives `A` from the projected output shares instead of from clear `a`
- explicit delivery surface now implemented in
  `crates/succinct-garbling-proto/src/succinct_hss.rs`
  - cached delivery material now separates artifact/evaluation-key state from
    per-run messages
  - DDH transport/output handling is now split across garbler/evaluator role
    views instead of one undifferentiated backend transport surface
  - evaluator role no longer carries a clone of the full secret-seeded DDH
    backend:
    - evaluator now holds only the public evaluation state plus its
      client-output transport key
    - garbler retains secret-seeded share generation, OT sender-state
      generation, and server-side transport ownership
  - garbler-side OT state is now explicit and role-owned:
    - prepared session exposes `prepare_garbler_ot_state()` alongside the
      public client OT offer
    - `prepare_server_message(...)` now consumes explicit garbler OT state
      instead of reaching into session-internal sender-state / remote-share
      fields
  - the OT transcript is now exposed as actual message/state boundaries:
    - `prepare_client_ot_request_from_offer_message(...)` now returns a
      transmitted client OT request message plus evaluator-local OT state
    - evaluator-local receiver state no longer rides inside the transmitted
      client packet
    - evaluation now consumes the client request message, evaluator-local OT
      state, and the server response message as separate inputs
    - server packets now also carry an explicit OT transcript object covering
      offer, request, response, and remote-release bindings
  - client input delivery no longer relies on client-generated remote shares or
    a sealed assist request/response pair
  - client input now uses an OT-shaped baseline:
    - garbler prepares per-bit offers for `y_client_bits` and
      `tau_client_bits` and retains the matching OT sender-state bundles
    - each offer word now carries a DDH sender public value, not plaintext or
      directly decryptable OT branch ciphertext material
    - evaluator now prepares blinded OT receiver requests matching its own
      input bits and keeps the receiver scalar state locally
    - server now returns OT branch ciphertext responses plus a transcript-bound
      remote-share release
    - evaluator reconstructs client-owned bundles by opening only the selected
      branch from the OT response and joining it with the transcript-bound
      remote-share release
  - ignored end-to-end delivery-packet evaluation still passes on this flow
  - top-level `evaluate()` now runs through the packetized delivery path
    instead of a clear-input shortcut
  - OT request/response preparation is now split across explicit role-owned
    runtime sessions:
    - prepared session exposes `split_runtime()` instead of only one
      coordinator-shaped OT surface
    - garbler OT runtime owns offer/state and server-packet generation
    - evaluator OT runtime owns client request creation and evaluator-local OT
      receiver state
  - evaluator-side packet evaluation is now also owned by the explicit runtime:
    - evaluator runtime validates/open/join/evaluates delivery packets instead
      of leaving that flow on the prepared-session coordinator
    - garbler/evaluator runtimes now seal server/client output packets
      directly, and prepared session only assembles the final report
    - shared immutable runtime state is now explicit alongside the role-owned
      runtimes, instead of being implicit inside the prepared-session
      coordinator
  - the interparty boundary is now a wire format instead of local object
    handoff:
    - garbler OT offer, evaluator OT request, server response, remote-share
      release, and output return now cross the boundary as serialized wire
      messages
    - prepared session now drives the local research harness through the same
      wire-message path
  - real process-separated drivers now exist for that wire path:
    - `prime_order_succinct_hss_driver` drives garbler and evaluator as
      separate process steps over serialized state and wire-message files
    - fast subprocess smoke coverage now verifies offer/request/response flow
      without one in-process coordinator
    - ignored subprocess end-to-end coverage now verifies the finalized report
      against the frozen `wraparound-seed` fixture
- client/server output packets are sealed as authenticated transport
  ciphertexts instead of crossing the boundary as plain serde payloads
  - output return now opens through `output_openers()` recipient-specific
    wire-message methods instead of session-global helpers that could decode all
    outputs at once
  - prepared session can now validate and consume OT-shaped client packets,
    garbler-held transcript-bound remote-share releases, and sealed output
    packets through
    `evaluate_from_transport_messages(...)` and
    `deliver_output_from_transport_messages(...)`
  - packet-driven evaluation now reconstructs client inputs from evaluator
    OT-selected local shares plus transcript-bound garbler-held remote-share
    releases instead of from a client-fabricated remote-share packet
  - this is the current OT baseline; deployed oblivious transport semantics and
    final output-return semantics are still pending
- DDH multiplication no longer computes local cross-terms inside `eval_mul`
  - multiplication now uses preprocessing-style triple material plus opened
    `d` / `e` deltas instead of directly computing `ll + lr + rl + rr`
  - that moves the trust boundary materially closer to a real 2-party
    multiplication protocol even though both roles still live in the same
    research process today
- old delivery scaffolding was removed during the refactor
  - the sealed client assist request/response path is gone
  - the old public-output transport path is gone
  - the prepared session now centers on garbler-prepared OT offers,
    garbler-held OT sender state, evaluator local selection, and
    transcript-bound garbler-held remote-share release
  - default debug test lane now keeps the expensive end-to-end DDH conformance
    runs behind ignored tests in
    `crates/succinct-garbling-proto/src/lib.rs`
  - single-fixture hidden-eval conformance is available as an ignored test
  - all `4` ignored DDH Phase 3b tests now pass
  - full five-fixture conformance now passes as an ignored Phase 3b milestone
    run, in about `334.90 s` in the current debug lane
  - process-separated driver coverage now also passes:
    - fast subprocess OT message round-trip passes in about `6.35 s` in the
      current debug lane
    - ignored subprocess end-to-end report match against
      `wraparound-seed` passes in about `74.40 s`
  - default debug coverage is now `32 passed, 4 ignored` after moving the
    full hidden-eval packet/output checks behind the ignored lane
- what remains in Phase 3b is the actual gate-level HSS layer:
  - the real OT/HSS-specific 2-party input/output delivery path instead of the
    current OT-shaped local packet baseline with garbler-held sender-state
    bundles, blinded receiver requests, transcript-bound remote-share release,
    and response ciphertexts all still generated inside one research process
  - networked/deployed interparty transport beyond the current local
    process/file driver boundary
  - per-gate and end-to-end performance measurement for the real hidden
    evaluator
  - performance work on the arithmetic core:
    - after removing local cross-term expansion from `eval_mul`, both native
      and browser hidden-eval totals regressed to a little over `3 s`
    - the 1-mul `Maj` / carry rewrite, canonical-scalar projector reduction,
      transport-boundary tightening, a lighter-weight specialized 1-bit
      multiplication path, and cached hot-path constants brought the native
      total down further to about `1.28 s` on this host and the browser total
      to about `1.70 s`
    - the output projector is no longer co-dominant; the round core still
      clearly dominates, and the new substage split still shows `temp1` plus
      schedule accumulation are the next arithmetic targets

### Phase 3c — Trust-Boundary Corrections Before Claiming HSS

This section tracks the security corrections required before the current DDH
implementation can honestly be described as a deployed 2-party HSS protocol.

Current blocker:

- the raw wire leak is fixed and evaluator-visible runtime ownership is now
  narrower, but hidden evaluation still collapses relayer inputs into
  joint-share state at the executor boundary
  - `DdhHssSharedWord` and `DdhHssInputShareBundle` are no longer serialized
    directly across the interparty packet boundary
  - `PrimeOrderSuccinctHssServerPacket` no longer carries
    `y_relayer_bundle` / `tau_relayer_bundle` as plain wire fields
  - evaluator-side delivery no longer returns generic relayer joint-share
    bundles; sealed `server_inputs` now deserialize into a server-input-
    specific internal payload, and the executor input surface now types relayer
    inputs as `DdhHiddenEvalServerInputs` instead of `DdhHssInputShareBundle`
  - sealed server-input transport ciphertexts now carry one-share left/right
    `DdhHssTransportBundle` pairs instead of joint-share words, and relayer
    joint-share bundles are reconstructed only during explicit server-input
    materialization for evaluation or test decode
  - the shared runtime now materializes `DdhHssEvaluator`, not
    `DdhHssBackend`, so evaluator-visible state is limited to public arithmetic
    state plus evaluator-owned transport keys
  - transport-aware relayer addition now avoids reconstituting generic shared
    words for the add stage and projector-side canonical `mod l` addition
  - however, once arithmetic is in flight the evaluator still carries derived
    intermediates as joined shared words, so the execution model is not yet
    role-local end to end

Tasks:

- [x] remove decodable joint-share wire types from interparty packets
  - `DdhHssSharedWord` and `DdhHssInputShareBundle` must become internal-only
    helpers
  - no wire-facing payload may contain both share halves of a hidden value
- [ ] split hidden-value types into role-local views
  - introduce distinct garbler-local and evaluator-local share types for the
    delivery path
  - keep any joint-share view restricted to trusted local simulation and test
    code only
- [ ] make server input delivery actually 2-party
  - the raw server packet wire path no longer exposes `y_relayer_bundle` /
    `tau_relayer_bundle`
  - evaluator delivery no longer returns generic joint-share bundles after
    transport
  - the executor input surface no longer types relayer inputs as generic
    joint-share bundles
  - validation and server-input commitment hashing now also run on
    server-input-specific executor types
  - sealed server-input transport ciphertexts no longer deserialize into
    joint-share words directly; they deserialize into role-local one-share
    transport bundles and only rejoin during explicit materialization
  - the remaining gap is semantic: derived intermediates still run as joined
    shared words rather than role-local per-party state
- [ ] move the evaluator execution model fully onto role-local state
  - evaluator runtime must consume only evaluator-local state plus transmitted
    garbler material
  - any object crossing the interparty boundary that contains both share halves
    is a bug
- [x] enforce the trust boundary in the type system
  - wire-safe delivery types may implement `Serialize` / `Deserialize`
  - joint-share helper types must not be serializable across the evaluator /
    garbler boundary
  - shared runtime state no longer materializes `DdhHssBackend`
- [x] keep runtime ownership split between garbler and evaluator
  - evaluator already holds only public evaluation state plus its local output
    transport key
  - garbler retains the secret-seeded backend, OT sender state, and server-side
    transport ownership
- [x] keep transcript binding and authenticated response envelopes on the OT
  path
  - offer / request / response / remote-release bindings already exist and
    should remain part of the corrected protocol
- [ ] extend malicious-client protections on top of the corrected wire model
  - bind remote-share release to the authenticated OT transcript
  - add retry / replay / consistency protections so malformed repeated
    requests cannot be used to learn extra server-side information
- [x] add negative security checks for the corrected delivery path
  - assert that evaluator-visible wire messages cannot reconstruct relayer
    plaintext
  - assert that no server-owned joint-share type accidentally implements the
    interparty wire format

Deliverable:

- a delivery path where no evaluator-visible wire message is sufficient to
  decode `y_relayer`, `tau_relayer`, or any other server-owned hidden value
- an explicit type-level separation between garbler-local, evaluator-local, and
  trusted simulation-only share representations

### Phase 4 — Security and failure analysis

Tasks:

- [ ] analyze what an honest-but-curious client learns
- [ ] analyze what an honest-but-curious server learns
- [ ] analyze replay risks
- [ ] analyze stale-artifact risks
- [ ] analyze context-mixup risks
- [ ] analyze selective-failure risks
- [ ] analyze retry-composition risks

Deliverables:

- threat analysis memo
- explicit assumptions list

### Phase 5 — Benchmark against cached GC

Tasks:

- [ ] measure total one-time artifact size
- [ ] measure per-run online bytes
- [ ] measure total registration / rebuild latency
- [ ] measure client CPU
- [ ] measure server CPU
- [ ] compare directly against cached GC

Deliverable:

- benchmark table:
- succinct implementation
  - cached GC baseline

Status:

- cache/download benchmark harness implemented in
  `crates/succinct-garbling-proto/src/cache_benchmark.rs`
- browser `IndexedDB` benchmark harness implemented at
  `crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html`
- browser bundle emitter implemented at
  `crates/succinct-garbling-proto/src/bin/emit_browser_cache_benchmark_bundle.rs`
- structured prime-order decoder implemented at
  `crates/succinct-garbling-proto/src/prime_order_decoder.rs`
- structured prime-order execution-trace builder implemented at
  `crates/succinct-garbling-proto/src/prime_order_trace.rs`
  - now reports backend-shaped evaluator ops and derived curve-cost totals for
    the prime-order candidate
- native prime-order CPU executor implemented at
  `crates/succinct-garbling-proto/src/prime_order_cpu_executor.rs`
  - compiles the decoded grouped-window records into deterministic point tables
    and bucket schedules
  - executes real `curve25519-dalek` point additions, bucket reductions,
    dependency merges, and compress/decompress normalizations
- native executor benchmark CLI implemented at
  `crates/succinct-garbling-proto/src/bin/benchmark_prime_order_cpu_executor.rs`
- browser wasm CPU executor exports implemented at
  `crates/succinct-garbling-proto/src/wasm.rs`
  - prepares the same compiled prime-order CPU program as native
  - executes the same point/window program from browser wasm
  - returns structured JSON so browser and native runs stay comparable
- browser CDP collector script implemented at
  `crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs`
  - drives the benchmark page through a remote-debugging Chrome instance
  - writes machine-readable browser benchmark reports to disk
- browser WebGPU probe implemented in
  `crates/succinct-garbling-proto/web/indexeddb_cache_benchmark.html`
  - measures adapter/device/pipeline setup against the current browser stack
  - dispatches a backend-shaped proxy kernel over active prime-order step vectors
  - is a setup/throughput proxy only, not real curve arithmetic
- committed Phase 1 baseline reports saved at
  `crates/succinct-garbling-proto/reports/phase1`
- current local proxy benchmark uses:
  - cached GC baseline: `1,200,000` bytes
  - prime-order stub artifact: `138,256` bytes
  - prime-order structured artifact: `138,256` bytes
- current local run with `--samples 4 --warmups 1` reports:
  - size ratio vs cached GC: `0.115x`
  - estimated download at `10 Mbps`: `960 ms` for cached GC vs `111 ms` for
    the prime-order artifact
  - estimated download at `25 Mbps`: `384 ms` for cached GC vs `45 ms` for the
    prime-order artifact
- latest headless-Chrome run against generated bundle files reported:
  - cached GC baseline: write `~2.64 ms`, read `~650 us`
  - prime-order stub artifact: write `~1.74 ms`, read `~162.5 us`
  - prime-order structured artifact: write `~1.11 ms`, read `~125 us`
- latest headless-Chrome structured execution smoke run against cached
  prime-order bytes reported:
  - decode mean: `~13.4 us` per iteration
  - execution-trace build mean: `~12.8 us` per iteration
  - grouped-window records: `262`
  - trace stages: `7`
  - derived curve-cost total: `62,748`
  - evaluator-op totals:
    - recoded scalar digits: `1,248`
    - precomputed window bits loaded: `16,576`
    - bucket accumulations: `3,296`
    - bucket reductions: `3,980`
    - accumulator curve additions: `712`
    - dependency merges: `448`
    - point normalizations: `184`
  - trace checksum: `4a8529`
- these measurements are still evaluator scaffolding only:
  - the decode number only measures artifact parsing
  - the trace number only measures stage/step reconstruction plus the
    prime-order evaluator op model
  - they still do not answer hidden-evaluator latency for a real succinct/HSS
    backend
- first native release benchmark of the real CPU executor reported:
  - compile/program-build time: `~40.4 ms`
  - execution mean: `~1.93 ms`
  - throughput mean: `~519.1 exec/s`
  - mean latency per curve-cost unit: `~30.8 ns`
  - deterministic executor checksum: `b075ca5b7bd494fe`
- latest headless-Chrome browser wasm CPU run of the same executor reported:
  - prepare/program-build time: `~95.6 ms`
  - execution mean: `~3.74 ms`
  - mean latency per curve-cost unit: `~59.6 ns`
  - browser/native per-unit ratio on this host: `~1.93x`
  - deterministic executor checksum: `b075ca5b7bd494fe`
  - deterministic final compressed point:
    `21fb5139b5a491423a70a42ff2725b5991cfb110b8ee529b6c532a52b24bee36`
- first browser WebGPU probe on the same host/browser stack reported:
  - adapter: `apple / metal-3`
  - proxy kernel kind:
    `digit_recode_v0 + window_bucket_accumulate_v0 + bucket_reduce_v0 + dependency_merge_normalize_v0`
  - backend-shaped setup time: `~48.1 ms`
  - backend-shaped dispatch mean: `~241.7 us`
  - per-subkernel means:
    - digit recode pass: `~72.9 us`
    - window/bucket-accumulate pass: `~43.7 us`
    - bucket reduce pass: `~75.0 us`
    - dependency/normalize pass: `~50.0 us`
    - combined bucket pipeline share: `~79.3%`
    - dominant subkernel: bucket reduce at `~31.0%`
  - backend-shaped latency per proxy unit: `~3.85 ns`
  - active step count: `180`
  - output checksum: `0000005c27563622`
  - this is promising for accelerator overhead, but it is still only a
    backend-shaped proxy kernel rather than a succinct evaluator
- cross-runtime determinism bug fixed:
  - `derive_index` in `prime_order_cpu_executor.rs` now reduces in `u64`
    before casting to `usize`
  - this avoids `wasm32` truncation changing bucket/window assignment
  - unit test added to lock the behavior
- this is the first measured point/window executor:
  - it is still not the final succinct/HSS backend
  - but it replaces the proxy-only trace with actual prime-order point
    operations on CPU, which is the right baseline before any accelerator work

### Phase 6 — Formal verification specs

This comes later, after the executable spec, fixtures, and first implementation
shape are stable. Do not start by trying to fully verify the final succinct
backend.

Tasks:

- [ ] write a machine-checkable spec for the core ideal functionality:
  - `shared y_client, y_relayer -> d -> SHA-512(d) -> clamp -> a`
- [ ] formalize the invariants:
  - canonical `d`
  - canonical `a`
  - base-share relation
  - public-key relation
- [ ] make the fixture corpus the conformance oracle for any later backend
- [ ] define backend-refinement requirements:
  - every backend must match the frozen executable spec
  - every backend must reproduce the same outputs for the same fixture set
- [ ] add negative/spec-violation tests so drift is caught immediately

Deliverables:

- formalized ideal-functionality spec
- backend conformance requirements
- drift-prevention test harness

## Kill Criteria

Stop this implementation path early if any of these hold:

- one-time artifact size does not beat cached GC materially
- evaluation time is too slow to offset communication savings
- evaluator-side latency misses the explicit desktop/mobile targets on the
  platforms we actually care about
- the intended accelerator path does not exist or is too fragmented to rely on
- the protocol becomes too complex to review confidently
- active-security overhead destroys the size advantage
- the design requires a generalized framework larger than the problem itself

## Success Criteria

This implementation is successful only if it materially improves the rebuild path over
cached GC on at least one important axis without unacceptable regressions on
others.

Preferred targets:

- one-time artifact size significantly below cached GC
- evaluator-side latency within the explicit desktop/mobile targets
- clear evidence that the acceleration thesis is real on supported devices
- clear accounting of:
  - cross-session artifact reuse,
  - internal round-template amortization,
  - what each one contributes
- no change to the SSR lifecycle
- reviewable protocol surface

## Suggested Rust Workspace Layout

Create a dedicated crate under `crates/` so this work stays isolated
from production signer code until feasibility is proven.

Suggested path:

- `crates/succinct-garbling-proto/`

Suggested scope for that crate:

- plaintext reference implementation of `F_expand`
- benchmark harness
- implementation message types
- artifact encoder / decoder work
- protocol simulations and conformance tools

Suggested non-goals for the crate:

- do not wire it into production client/server flows yet
- do not expose it as a stable SDK API
- do not let it become a second production lifecycle by accident

## First Milestones

- [x] Add the new crate and a minimal README.
- [x] Implement the plaintext `F_expand` reference path.
- [x] Freeze deterministic fixtures and invariant/property tests.
- [x] Add an evaluator/hardware profiler for fixed one-block `SHA-512 + clamp`.
- [x] Write the first compact-encoding candidate note before building any
  serious crypto machinery.
- [ ] Only after the implementation shape stabilizes, add the formalized
  ideal-functionality spec.

## Next Steps

1. Freeze the Phase 1 benchmark matrix:
   desktop CPU, mobile CPU, browser CPU, browser GPU/WebGPU where available,
   and native mobile GPU / NPU where available.
2. Save structured JSON reports for the current native and browser CPU
   baselines so later target-device runs stay machine-readable.
3. Run the same browser/native executor harness on representative mobile CPU
   targets so the non-accelerated client baseline is explicit.
4. Replace the current synthetic WebGPU probe with the first backend-shaped
   accelerator kernel so setup overhead, batching limits, and throughput are
   measured against evaluator-like work rather than generic integer mixing.
5. Use the alternate modeled backend families only as comparison points unless
   the prime-order path misses the size or evaluator-latency budget.

## Recommendation

Treat this as a bounded implementation program:

- fixed-function only
- benchmark-driven
- kill early if it does not beat cached GC materially

This does not override the broader SSR recommendation order in
[`stateless-shared-root-ed25519.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/stateless-shared-root-ed25519.md),
which still places succinct garbling behind the mixed-circuit and GC-heavy
tracks in the overall experimental queue.

Do not expand scope into a general succinct-garbling system unless the narrow
fixed-function implementation clearly succeeds first.
