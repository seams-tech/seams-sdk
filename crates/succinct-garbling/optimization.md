# Succinct-Garbling Optimization Log

This note tracks the optimization work that has landed in the `succinct-garbling` crate, what each change did, and whether it changed the current semi-honest security story.

This is a performance log, not a full specs note. For protocol status and trust-boundary status, see:

- [/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md)
- [/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-candidate-v0.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-candidate-v0.md)

## Current Measured Baselines

### Current post-hardening checkpoint

- Native release benchmark:
  - prepare: about `86.4ms`
  - total hidden eval: about `0.551s`
  - input sharing: about `1.9ms`
  - add stage: about `2.6ms`
  - message schedule: about `91.9ms`
  - round core: about `307.1ms`
  - output projector: about `87.7ms`
  - substage split: schedule accumulation `79.4ms`, `temp1` `132.2ms`,
    `temp2` `32.8ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json)
- Browser run:
  - prepare: about `148.5ms`
  - total hidden eval: about `0.774s`
  - `session.evaluate`: about `0.767s`
  - hidden-eval probe total: about `0.661s`
  - input sharing: about `10.7ms`
  - add stage: about `3.7ms`
  - message schedule: about `122.0ms`
  - round core: about `406.5ms`
  - output projector: about `118.4ms`
  - substage split: schedule accumulation `106.1ms`, `temp1` `175.8ms`,
    `temp2` `43.5ms`
- reference match: `true`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json)

## Campaign Status

- Current status: paused at the published post-hardening checkpoint above
- Kept candidates:
  - paired local xor provenance derivation
  - paired local add in Beaver `d`/`e` setup
  - Beaver-material reuse across bounded local slices
- Reverted candidates:
  - scratch reuse in hot add-chain accumulators
  - batched local xor derivation across slices
  - constant-aware `temp1` round-constant add
  - loop-label buffer reuse in hot add/sub helpers
  - trusted local-word accessor fast path in packed executor storage
  - direct batched `Ch`/`Maj` multiply outputs without split-word round-trip
  - balanced add tree for 4-word and 5-word local accumulation
- Deferred candidates:
  - reintroduce scratch reuse inside packed split/local arithmetic helpers
  - fuse additional packed split/local kernels only where benchmarks show a
    real bottleneck
  - reduce allocation and cloning in output bundle reconstruction if it shows
    up in measured profiles

### Performance-first checkpoint

- Native release benchmark:
  - total hidden eval: about `0.270s`
  - round core: about `128.9ms`
  - message schedule: about `40.5ms`
  - output projector: about `29.4ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json)
- Browser run:
  - total hidden eval: about `0.380s`
  - `session.evaluate`: about `0.382s`
  - hidden-eval probe total: about `0.257s`
  - `ot_open_join`: about `124.3ms`
  - `server_input_open`: about `4.6ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json)

### Earlier security-first checkpoint

- Native release benchmark:
  - total hidden eval: about `0.595s`
  - round core: about `385.2ms`
  - message schedule: about `109.7ms`
  - output projector: about `33.6ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json)
- Browser run:
  - total hidden eval: about `0.800s`
  - `session.evaluate`: about `0.789s`
  - hidden-eval probe total: about `0.680s`
  - `ot_open_join`: about `106.5ms`
  - `server_input_open`: about `4.5ms`
  - source: [/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json)

The first checkpoint is the best performance-first state before the latest
security-boundary work. The second checkpoint is an earlier local/split
security-first measurement before the current post-hardening optimization
campaign. The new top checkpoint is the current published baseline for the
hardened split/local executor.

## Current Optimization Gate Notes

These are accepted step-by-step optimization results gathered during the
post-refactor campaign. The current published baseline above includes the
accepted steps listed here.

### Accepted quick native gate: paired local xor provenance derivation

- What changed:
  - hot executor paths that already operate on left/right local pairs now use a
    paired local xor helper instead of issuing two independent local xor calls
  - this lets the pair share one provenance digest derivation while still
    emitting side-specific commitments
- Why it helped:
  - the output projector, round core, and schedule all spend substantial time
    in repeated left/right bitwise xor over matching local pairs
  - the previous path hashed the same provenance inputs twice for those paired
    operations
- Quick native gate result on the same single-sample release run:
  - total hidden eval improved from about `0.671s` to about `0.611s`
  - output projector improved from about `108.1ms` to about `100.4ms`
  - round core improved from about `383.0ms` to about `343.1ms`
  - message schedule improved from about `112.5ms` to about `102.9ms`
- Security note:
  - no change to the split/local security boundary
  - the output pair still carries side-specific commitments with the same
    provenance semantics; the implementation now avoids recomputing equivalent
    provenance material twice

### Accepted quick native gate: paired local add in Beaver `d`/`e` setup

- What changed:
  - the local bit-multiply path now computes the paired `d` and `e` openings
    with one paired local add helper instead of two independent local add calls
- Why it helped:
  - Beaver multiplication setup is on the hot path for the round core, output
    projector subtraction/select logic, and other split/local boolean kernels
  - the previous path was deriving equivalent pair metadata twice for every
    `d` and `e` open
- Quick native gate result on the same single-sample release run:
  - total hidden eval improved from about `0.611s` to about `0.565s`
  - output projector improved from about `100.4ms` to about `90.7ms`
  - round core improved from about `343.1ms` to about `317.4ms`
  - message schedule improved from about `102.9ms` to about `94.5ms`
- Security note:
  - no change to the split/local security boundary
  - Beaver material and output commitments remain gate-specific; the
    implementation now avoids duplicating pair-level add derivation work

### Accepted quick native gate: Beaver-material reuse across bounded local slices

- What changed:
  - the executor now batches independent-bit local multiplications for
    `select`, `Ch`, and `Maj`
  - the batch helper reuses one initialized material-derivation base across the
    whole local slice, then derives each gate-specific Beaver digest by cloning
    that base and appending the gate label
- Why it helped:
  - the previous path repeated the same shared hashing setup for every single
    bit gate even when the slice-level provenance inputs already aligned
  - these independent-bit kernels sit directly on the round-core and projector
    hot path
- Quick native gate result on the same single-sample release run:
  - total hidden eval improved from about `0.565s` to about `0.558s`
  - output projector improved from about `90.7ms` to about `90.4ms`
  - round core improved from about `317.4ms` to about `314.1ms`
  - message schedule held about flat at `94.5ms` to `94.46ms`
- Security note:
  - no change to the split/local security boundary
  - Beaver outputs and commitments remain gate-specific; only the reusable
    slice-level material-derivation prefix is shared

### Rejected quick native gate: scratch reuse in hot add-chain accumulators

- What changed:
  - tried reusing temporary split/local buffers inside the staged add-chain
    helpers that feed `temp1` and schedule accumulation
- Result:
  - total hidden eval regressed from about `0.565s` to about `0.572s`
  - round core regressed from about `317.4ms` to about `320.7ms`
  - output projector regressed from about `90.7ms` to about `92.5ms`
- Outcome:
  - reverted
  - this allocator-focused rewrite did not beat the current kept baseline

### Rejected quick native gate: batched local xor derivation across slices

- What changed:
  - tried batching slice-wide local xor derivation in `add_two`, `select`,
    `Ch`, and `Maj`
- Result:
  - total hidden eval regressed from about `0.565s` to about `0.591s`
  - round core regressed from about `317.4ms` to about `338.6ms`
  - output projector regressed from about `90.7ms` to about `97.7ms`
- Outcome:
  - reverted
  - extra staging and vector materialization cost more than the saved digest
    prefix reuse

### Rejected benchmark gate: constant-aware `temp1` round-constant add

- What changed:
  - tried replacing the hidden-hidden add against the SHA-512 round constant in
    `temp1` with a public-constant-specialized ripple path
  - also removed the split/local round-constant pool on that path so the round
    core used `SHA512_ROUND_CONSTANTS` directly
- Result:
  - quick native gate improved:
    - total hidden eval from about `0.558s` to about `0.554s`
    - round core from about `314.1ms` to about `311.9ms`
    - output projector from about `90.4ms` to about `89.8ms`
  - browser gate regressed:
    - total hidden eval from about `0.774s` to about `0.790s`
    - round core from about `406.5ms` to about `419.8ms`
    - hidden-eval probe total from about `0.661s` to about `0.678s`
- Outcome:
  - reverted
  - the public-constant specialization was not portable enough across native
    and browser execution

### Rejected benchmark gate: loop-label buffer reuse in hot add/sub helpers

- What changed:
  - tried replacing repeated `format!` label construction in the per-bit add
    and subtract loops with reusable byte buffers
  - scoped the change to the split/local add, add-with-transport, and subtract
    carry/borrow helpers
- Result:
  - quick native gate improved:
    - total hidden eval from about `0.558s` to about `0.538s`
    - round core from about `314.1ms` to about `297.7ms`
    - output projector from about `90.4ms` to about `88.5ms`
  - browser gate regressed:
    - total hidden eval from about `0.774s` to about `0.796s`
    - round core from about `406.5ms` to about `433.9ms`
    - hidden-eval probe total from about `0.661s` to about `0.716s`
- Outcome:
  - reverted
  - the lower-allocation label path helped native but was not a stable win in
    the browser runtime

### Rejected quick native gate: trusted local-word accessor fast path in packed executor storage

- What changed:
  - tried adding unchecked width/side/index fast paths on the packed
    `LocalBitWordSide` container
  - rewired hot executor loops to use those trusted accessors instead of the
    checked `local_word(...)` and `push_local_word(...)` paths
- Result:
  - quick native gate regressed:
    - total hidden eval from about `567.2ms` to about `637.0ms`
    - round core from about `316.1ms` to about `357.9ms`
    - message schedule from about `94.4ms` to about `106.2ms`
    - output projector from about `90.0ms` to about `103.0ms`
    - round `temp1` from about `136.3ms` to about `154.4ms`
- Outcome:
  - reverted
  - skipping the guard path did not remove real work; it produced worse code
    shape across the main executor hot loops

### Rejected native gate: direct batched `Ch`/`Maj` outputs without split-word round-trip

- What changed:
  - tried removing the intermediate split-word packing/unpacking layer inside
    `Ch` and `Maj`
  - kept the batched multiply outputs as local-word vectors and XORed them
    directly into the final packed result instead of round-tripping through a
    `SplitLocalBitWord`
- Result:
  - native release gate regressed:
    - total hidden eval from about `567.2ms` to about `599.4ms`
    - round core from about `316.1ms` to about `334.0ms`
    - message schedule from about `94.4ms` to about `100.0ms`
    - output projector from about `90.0ms` to about `95.4ms`
- Outcome:
  - reverted
  - removing this round-trip did not translate into a faster executor shape;
    the extra vector traffic and indexing cost more than the packing work it
    replaced

### Rejected native gate: balanced add tree for 4-word and 5-word local accumulation

- What changed:
  - tried rebalancing `add_four_local_bit_words` from `((a+b)+c)+d` into
    `(a+b)+(c+d)`
  - tried rebalancing `add_five_local_bit_words` from a pure left-deep chain
    into `((a+b)+(c+d))+e`
- Result:
  - native release gate regressed:
    - total hidden eval from about `567.2ms` to about `602.2ms`
    - round core from about `316.1ms` to about `338.4ms`
    - message schedule from about `94.4ms` to about `101.5ms`
    - output projector from about `90.0ms` to about `96.7ms`
- Outcome:
  - reverted
  - the balanced tree changed the dependency shape, but it did not reduce the
    real per-bit work enough to beat the current left-deep add chain

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

Current status:

- the production constant pool now stores split/local stage values directly
- this preserves the same constant reuse win while avoiding runtime conversion back out of a joined hidden-word pool

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

Status note:

- some of the older `*_into(...)` scratch-reuse helpers were removed as the executor was rewritten around split/local stage values
- Phase 6 should reintroduce reuse where it helps inside the hardened split/local model, not by reviving deprecated joined helpers

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

### 18. `session.evaluate` timing split for OT, server-input open, finalization, and assembly

- What changed:
  - the detailed wasm DDH path now reports:
    - `ot_open_join`
    - `server_input_open`
    - `output_sealing_finalization`
    - `result_assembly`
- Why it helped:
  - not a direct runtime win, but it made it clear that the remaining browser overhead sat mostly in OT/open/join rather than output sealing or report assembly
  - that prevented more blind tuning in the SHA-512 executor
- Security note:
  - no protocol impact
  - measurement only

## Next optimization checkpoint

The next performance work should target the hardened split/local model directly:

- denser storage than helper-composed `DdhHssLocalBitSlice`
- fused split/local stage kernels
- Beaver-material reuse across bounded local slices
- lower-overhead provenance/commitment derivation inside local kernels

Do not spend optimization effort reopening joined production helpers just to
recover earlier benchmark numbers.

### 19. Fused evaluator OT open+join and direct server-input commitment from opened bundles

- What changed:
  - evaluator-side client OT reconstruction stopped building an intermediate left transport bundle before joining with the released right bundle
  - server-input commitment checks now hash directly from the opened transport bundles instead of first materializing a heavier hidden-eval server-input object
- Why it helped:
  - reduced representation churn in the prepared-session evaluator path
  - this produced a modest browser improvement and shrank `ot_open_join` and `server_input_open` slightly
- Measured effect:
  - browser total hidden eval improved from about `0.651s` to about `0.647s`
  - `ot_open_join` improved from about `242.1ms` to about `238.2ms`
  - `server_input_open` improved from about `46.8ms` to about `46.2ms`
- Security note:
  - no change to the security model
  - these are structural rewrites that preserve the same commitment checks and validation inputs

### 20. Fixed-width OT branch payload encoding and stack AAD

- What changed:
  - OT branch payload seal/open stopped using `bincode`
  - the branch payload now uses a fixed-width manual encoding
  - OT branch AAD moved from heap `Vec<u8>` construction to fixed-size stack bytes
- Why it helped:
  - this was meant to remove serialization overhead from the hot per-branch decrypt/open path
- Measured effect:
  - effectively flat
  - `ot_open_join` stayed around `238ms`
- Security note:
  - no change to the security model
  - the authenticated bytes and domain separation remain the same

### 21. OT reconstruction sub-profiling

- What changed:
  - OT reconstruction now reports:
    - branch key derivation
    - branch decrypt
    - point/scalar reconstruction
    - commitment verification
- Why it helped:
  - this showed that the remaining OT cost was not in AEAD or branch-key derivation
  - it let the next optimization target move from `open_ot_branch_with_key(...)` to the broader OT session path
- Measured result:
  - at the time of measurement, OT reconstruction buckets explained only about `49ms` of an `~240ms` `ot_open_join`
  - that meant most of the remaining OT time was outside branch decrypt
- Security note:
  - no protocol impact
  - measurement only

### 22. Batched OT request randomness and removal of repeated prepared-session garbler OT validation

- What changed:
  - evaluator OT request preparation now fills receiver scalars from one batched RNG buffer instead of calling `OsRng.fill_bytes` once per bit
  - cached garbler OT offer/state validation now happens once at session preparation instead of on every prepared-session evaluation
- Why it helped:
  - removed deterministic repeated work from the hot local session path
  - reduced browser OT/open/join materially
- Measured effect:
  - native total hidden eval improved from about `0.383s` to about `0.365s`
  - browser total hidden eval improved from about `0.618s` to about `0.582s`
  - `ot_open_join` improved from about `213.3ms` to about `190.3ms`
  - this was the step that brought browser OT/open/join below the `~200ms` target
- Security note:
  - no change to the security model
  - the same OT values and validations are used; only the placement of deterministic validation changed

### 23. Split-once server-input sealing path

- What changed:
  - relayer bundles are now split once before server-input packet sealing
  - server-input payload serialization now borrows the transport bundles instead of cloning four bundles into a temporary payload object
- Why it helped:
  - reduced needless transport-bundle cloning in the server-input path
  - trimmed both browser `server_input_open` and total browser wall clock
- Measured effect:
  - native total hidden eval stayed roughly flat in the `0.369s` band
  - browser total hidden eval improved from about `0.582s` to about `0.569s`
  - `ot_open_join` improved from about `190.3ms` to about `187.0ms`
  - `server_input_open` improved from about `45.2ms` to about `44.2ms`
- Security note:
  - no change to the security model
  - this is serialization and ownership cleanup only

### 24. Bit-commitment fast path for client/server `0` and `1`

- What changed:
  - kept the bit-commitment fast path in `ddh_hss.rs`
  - `commit_word(...)` now special-cases client/server words `0` and `1`
  - instead of doing full scalar multiplication for every shared bit, it returns:
    - the identity commitment for `0`
    - the basepoint commitment for `1`
- Why it helped:
  - relayer and client bit sharing create many width-1 words
  - the old path was paying full curve scalar multiplication even when the committed word was only `0` or `1`
  - cutting that unnecessary curve math produced a step-change in both native and browser performance
- Measured effect:
  - native total hidden eval improved from about `0.369s` to about `0.270s`
  - browser total hidden eval improved from about `0.569s` to about `0.380s`
  - browser `ot_open_join` improved from about `187.0ms` to about `124.3ms`
  - browser `server_input_open` improved from about `44.2ms` to about `4.6ms`
- Security note:
  - this is secure
  - for client/server commitments, `0*G` and `1*G` are exactly the same group elements as the generic path would produce
  - it only removes unnecessary curve math

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
- a naive deeper server-input trust-boundary rewrite that threaded role-local transport state farther into normal execution
  - reason removed: real browser regression without enough security gain for the cost
- wrapper-only runtime type splits for garbler/evaluator server-input state
  - reason removed: measurable regression without changing actual evaluator capability

## Practical Takeaway

The biggest wins came from reducing hot per-gate overhead:

- fewer multiplications in carry and `Maj`
- faster bit-specialized arithmetic
- replacing transcript-heavy derivation with fast domain-separated hashing
- removing local harness serialization and rebuild costs
- then, later, removing repeated OT/session work in the prepared-session browser path

At the current baseline, the remaining browser overhead is now much narrower:

- `ot_open_join` is still the largest session-layer bucket, but it is down to about `124ms`
- `server_input_open` is down to about `5ms`
- output sealing/finalization and result assembly are negligible

That means future wins are most likely to come from:

- carefully chosen OT/session cleanup
- the remaining round-core and `round_temp1` arithmetic hot spots
- and only after that, another round of hidden-eval arithmetic tuning if the session layer flattens out
