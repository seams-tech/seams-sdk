# Succinct-Garbling Optimization Log

This note tracks the optimization work that has landed in the `succinct-garbling-proto` research crate, what each change did, and whether it changed the current semi-honest security story.

This is a performance log, not a full specs note. For protocol status and trust-boundary status, see:

- [/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md)
- [/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-candidate-v0.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-candidate-v0.md)

## Current Measured Baseline

- Latest native release sanity run after explicit per-gate bit-mul hardening:
  - total hidden eval: about `0.416s`
  - round core: about `136.6ms`
  - message schedule: about `43.7ms`
  - output projector: about `41.4ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json)
- Latest saved browser run before the explicit per-gate rerun:
  - total hidden eval: about `0.668s`
  - `session.evaluate`: about `0.668s`
  - hidden-eval probe total: about `0.450s`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json)

The exact percentages below are directional. Many wins compound and are not additive.

## Landed Optimizations

### 1. One-mul carry and one-mul `Maj`

- What changed:
  - the carry chain in `add_two_words_bits(...)` was rewritten from a 2-multiply form to a 1-multiply majority-style form
  - `maj_bits(...)` was also kept in the 1-multiply form
- Why it helped:
  - SHA-512 round arithmetic spends most of its time inside repeated carry propagation and `Maj`
  - halving the bit-multiply count in those paths removed a large fraction of `round_temp1` and schedule work
- Security note:
  - no change to the security model
  - this is an algebraic rewrite of Boolean identities over the same hidden shared-value representation

### 2. Canonical scalar reduction in the output projector

- What changed:
  - canonical scalar additions in the output projector were split from the full multi-round `mod l` reduction path
  - bounded canonical additions now use a one-subtract/select style reduction instead of always paying the full loop
- Why it helped:
  - `tau`, `x_client_base`, `double_tau`, and `x_relayer_base` are sums of canonical scalars, so they do not need the full repeated reduction path
- Security note:
  - no change to the security model
  - this is an arithmetic-range optimization with the same final canonical result

### 3. Constant-pool reuse for SHA-512 and `mod l`

- What changed:
  - deterministic constant material is prepared once and reused:
    - SHA-512 IV words
    - SHA-512 round constants
    - one-block schedule suffix constants
    - scalar modulus bits and common constant words
- Why it helped:
  - reduced repeated construction of the same hidden shared constants in native, wasm, and benchmark paths
- Security note:
  - no change to the security model
  - these are fixed public constants, not secret-dependent values

### 4. Fixed-arity accumulation helpers for hot add chains

- What changed:
  - generic variadic add chains were replaced in the hot paths with fixed-arity helpers:
    - 4-input accumulation for the message schedule
    - 5-input accumulation for `temp1`
- Why it helped:
  - removed generic `Vec`/swap overhead in the two hottest arithmetic paths
- Security note:
  - no change to the security model
  - only the executor control flow changed, not the hidden arithmetic semantics

### 5. Scratch-buffer reuse in round, schedule, subtraction, selection, and projector helpers

- What changed:
  - hot helpers were converted to `*_into(...)` style APIs where practical
  - output buffers and scratch buffers are reused instead of allocating fresh vectors in each round or reduction step
- Why it helped:
  - reduced allocation churn in both native and wasm, especially in the round core
- Security note:
  - no change to the security model
  - this is a memory-management optimization only

### 6. Round-state move/reuse instead of repeated deep cloning

- What changed:
  - round-state updates reuse owned vectors for `new_a`, `new_e`, and final state movement instead of cloning multiple 64-bit shared-word vectors per round
- Why it helped:
  - lowered per-round copying overhead in the SHA-512 core
- Security note:
  - no change to the security model
  - the hidden values do not change shape or exposure

### 7. Direct sigma helper computation

- What changed:
  - sigma helpers stopped allocating rotated temporary words first and now compute their XOR outputs directly into destination buffers
- Why it helped:
  - trimmed some temporary vector construction around the schedule and round setup
- Security note:
  - no change to the security model

### 8. Dedicated 1-bit add fast path

- What changed:
  - `eval_add_mod_2_pow_n(...)` now special-cases width-1 words
  - 1-bit addition now uses a direct XOR-based derived shared word instead of the generic wider-word builder
- Why it helped:
  - most hidden-eval Boolean logic is 1-bit arithmetic, so removing generic-width overhead was a large win
- Security note:
  - no change to the security model
  - bit addition in this representation is XOR, so this is just a specialized implementation of the same rule

### 9. Dedicated bit-multiply derivation path

- What changed:
  - `eval_mul_bit_for_key(...)` no longer constructs the older masked-word / split / digest chain used by the generic multiplication path
  - it derives 1-bit Beaver-style material directly
- Why it helped:
  - bit multiplication is the hot primitive in `Ch`, `Maj`, carry propagation, subtraction, and selection
  - removing generic-width machinery from the bit path produced one of the largest single wins
- Security note:
  - still semi-honest only
  - the security requirement here is fresh, pseudorandom material per multiplication gate

### 10. Replacing Merlin transcript derivation in hot per-gate paths

- What changed:
  - hot derived-word and bit-multiply material stopped using a Merlin transcript
  - the crate now uses domain-separated hash derivation instead
- Why it helped:
  - Merlin transcript setup and message appends were the dominant per-gate overhead
  - this was the step-change optimization that cut total runtime dramatically
- Security note:
  - sequential transcript binding was removed
  - that is acceptable for the current semi-honest model
  - it would not by itself satisfy stronger extractability-style goals

### 11. `blake3` for hot derivation and derived commitments

- What changed:
  - hot provenance digests, derived commitments, and bit-mul material derivation now use `blake3`
- Why it helped:
  - these digests are on the critical path for nearly every hidden gate
  - moving to a faster hash reduced both native and browser cost materially
- Security note:
  - acceptable for the current semi-honest model because the derivations remain domain-separated and session-bound
  - the important property is pseudorandom, collision-resistant derivation under the evaluation key, not transcript extractability

### 12. Explicit per-gate key in bit-multiply derivation

- What changed:
  - `eval_mul_bit_for_key(...)` now includes an explicit gate key
  - the executor threads the existing stage/round/op labels into all hot multiplication sites
- Why it helped:
  - this was a security hardening step, not a speed optimization
  - performance impact is small but real because labels are now part of the derivation input
- Security note:
  - this closes the main caveat from the transcript removal
  - bit-mul material is now unique per multiplication gate instead of only per operand-state pair

### 13. Binary transport framing with `bincode`

- What changed:
  - OT and delivery wire messages moved from JSON framing to binary framing
- Why it helped:
  - cut local message encoding/decoding cost in process-separated and browser paths
- Security note:
  - no change to the cryptographic model
  - the authenticated payload semantics stay the same; only the framing changed

### 14. Typed in-process local evaluation path

- What changed:
  - local prepared-session evaluation stopped round-tripping its own wire messages when both roles are in the same process
  - typed packet objects are used directly for the local path
- Why it helped:
  - removed local encode/decode overhead that was not part of the real hidden-eval arithmetic
- Security note:
  - no change to the wire/process path
  - only the trusted in-process shortcut changed

### 15. Cached prepared session runtime and role views

- What changed:
  - `PrimeOrderSuccinctHssPreparedSession` now caches:
    - shared runtime
    - garbler session
    - evaluator session
  - `evaluate()` uses those cached objects instead of rebuilding cloned views every call
- Why it helped:
  - reduced local orchestration overhead in both native and wasm
- Security note:
  - no change to the security model
  - this reuses immutable prepared state; it does not broaden what either role can access

### 16. Browser wasm export cleanup

- What changed:
  - browser-facing wasm exports switched from JSON strings to direct `JsValue` objects
  - benchmark loops use fast exports that avoid shaping detailed result objects inside the timed path
- Why it helped:
  - reduced JS/wasm boundary overhead and report-shaping overhead in browser benchmarks
- Security note:
  - no protocol impact
  - benchmark plumbing only

### 17. Browser timing-model cleanup

- What changed:
  - the benchmark page and collector now report separate wall-clock, probe, and detailed-run timing fields more explicitly
- Why it helped:
  - not a protocol optimization by itself, but it made the remaining browser overhead measurable instead of ambiguous
- Security note:
  - no protocol impact

## Security Posture Of The Current Optimization Set

- Safe under the current semi-honest research model:
  - arithmetic rewrites
  - constant reuse
  - scratch reuse
  - binary framing
  - cached prepared-session/runtime reuse
  - hash-based material derivation with explicit domain separation and per-gate keys
- Not claimed here:
  - malicious security
  - transcript extractability
  - production network hardening
- Important current rule:
  - the bit-mul path now includes an explicit per-gate key
  - that means fresh multiplication material is no longer dependent only on operand provenance/commitment reuse

## Changes Tried And Removed

These were tested and intentionally backed out, so they are not part of the current code:

- local-only trusted server-eval packet shortcut in `session.evaluate()`
  - reason removed: regressed native and browser
- some deeper fixed-arity scratch rewrites that were flat or worse
  - reason removed: no stable benchmark win
- wider-word lift attempts for the bit-shared hot path
  - reason removed: wrong fit for the hidden shared-value representation

## Practical Takeaway

The biggest wins came from reducing hot per-gate overhead:

- fewer multiplications in carry and `Maj`
- faster bit-specialized arithmetic
- replacing transcript-heavy derivation with fast domain-separated hashing
- removing local harness serialization and rebuild costs

At the current baseline, further wins are likely to come more from protocol hardening and measurement cleanup than from another round of blind arithmetic micro-tuning.
