# Succinct-Garbling Optimization Approaches v2

This note is the follow-on to
[`optimization.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/optimization.md).
That earlier note records what was tried and what landed, including several
performance-first changes made before and during the security refactor.

This v2 note is different:

- it is a strategy note, not a historical log
- it assumes the hardened split/local executor is the only production path worth
  optimizing
- it treats evaluator-capability cleanup as part of optimization sequencing, not
  as an optional side quest

For broader protocol status and security-boundary work, see:

- [`docs/succinct-garbling-security-refactor.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling-security-refactor.md)
- [`crates/succinct-garbling/security.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/security.md)
- [`docs/succinct-garbling.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md)

## Task Status Legend

- `[ ]` not tried yet
- `[x]` tried already
- items marked `(landed)` were kept
- items marked `(reverted)` were measured and rejected

## Purpose

Use the next optimization pass to improve the real hardened protocol, not to
recover old numbers by reviving deprecated joined execution seams.

That means:

- no optimization work should reopen joined hot-path helpers
- no optimization work should add compatibility wrappers that blur whether a
  path is really split/local
- no optimization work should make the evaluator more capable just because it is
  convenient for benchmarking

## Current Measured Speeds

These numbers summarize the current published post-hardening checkpoint and the
optimization campaign state as of `2026-03-29`.

### Native release hidden eval

Command:

```bash
cargo run --release --manifest-path crates/succinct-garbling/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json
```

Measured means:

- prepare: about `110.9ms`
- total hidden eval: about `0.387s`
- input sharing: about `2.0ms`
- add stage: about `2.7ms`
- message schedule: about `49.1ms`
- round core: about `232.0ms`
- output projector: about `45.1ms`
- message schedule accumulation: about `36.0ms`
- round `temp1`: about `46.0ms`
- round `temp2`: about `35.0ms`
- reference match: `true`

Source:

- [`crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json)

### Browser hidden eval

Commands:

```bash
wasm-pack build crates/succinct-garbling --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/succinct-garbling/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/succinct-garbling/web/generated
python3 -m http.server 8765 -d crates/succinct-garbling/web
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-port=57514 --user-data-dir=/tmp/codex-chrome-bench --no-first-run --no-default-browser-check about:blank
node crates/succinct-garbling/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json
```

Measured means:

- total hidden eval: about `0.568s`
- `session.evaluate`: about `0.571s`
- detailed result total: about `0.576s`
- hidden-eval probe total: about `0.467s`
- input sharing: about `10.8ms`
- add stage: about `14.7ms`
- message schedule: about `69.0ms`
- round core: about `328.4ms`
- output projector: about `54.6ms`
- message schedule accumulation: about `53.2ms`
- round `temp1`: about `65.3ms`
- round `temp2`: about `53.5ms`
- OT open/join: about `102.5ms`
- OT point-scalar reconstruction: `0`
- server input open: about `4.1ms`
- server input seal: `0`
- result assembly: `0`
- output materialization: about `4.6ms`
- reference match: `true`

Source:

- [`crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/reports/phase3/browser-ddh-hidden-eval-chrome.json)

## Biggest Gains

The largest wins so far have not come from helper cleanup. They came from
changing the shape of the hottest work.

- [x] Phase A executor-local arithmetic path for `temp1` accumulation `(landed)`
  - this is the biggest single win so far
  - native total hidden eval improved from about `0.504s` to about `0.387s`
  - browser total hidden eval improved from about `0.774s` to about `0.568s`
  - native `round_temp1` dropped from about `148.2ms` to about `46.0ms`
  - browser `round_temp1` dropped from about `231.8ms` to about `65.3ms`
  - native `round_core` dropped from about `343.4ms` to about `232.0ms`
  - browser `round_core` dropped from about `514.5ms` to about `328.4ms`
- [x] Phase A executor-local arithmetic path for message-schedule accumulation
  `(landed)`
  - native total hidden eval improved from about `0.524s` to about `0.504s`
  - browser total hidden eval improved from about `0.844s` to about `0.774s`
  - native message schedule dropped from about `95.8ms` to about `51.3ms`
  - browser message schedule dropped from about `152.6ms` to about `75.0ms`
  - native message-schedule accumulation dropped from about `83.0ms` to about
    `37.7ms`
  - browser message-schedule accumulation dropped from about `135.2ms` to about
    `57.4ms`
- [x] fixed-modulus output-projector subtraction `(landed)`
  - native output projector dropped from about `90.0ms` to about `46.7ms`
  - browser output projector dropped from about `117.2ms` to about `59.3ms`
- [x] browser hidden-run measurement and prepared-session cleanup `(landed)`
  - removed browser-only report-assembly and output-delivery shaping from the
    measured path
  - removed OT point-scalar reconstruction from the browser OT open/join path
  - collapsed `result_assembly_duration_ns` and
    `output_sealing_finalization_duration_ns` to `0`

## Current Performance Position

Against the old pre-security-refactor performance-first checkpoint in
[`optimization.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling/optimization.md),
the current hardened checkpoint is still slower overall, but the gap is much
smaller now:

- old native checkpoint: about `0.270s`
- current native checkpoint: about `0.387s`
- old browser checkpoint: about `0.380s`
- current browser checkpoint: about `0.568s`

The remaining cost is still concentrated in `round_core`, but it is no longer
overwhelmingly dominated by `temp1`:

- native `round_core`: about `232.0ms`
- browser `round_core`: about `328.4ms`
- native `round_temp1`: about `46.0ms`
- browser `round_temp1`: about `65.3ms`
- native `message_schedule_accumulation`: about `36.0ms`
- browser `message_schedule_accumulation`: about `53.2ms`
- native `round_temp2`: about `35.0ms`
- browser `round_temp2`: about `53.5ms`

## Findings So Far

The current v2 result is:

- eleven bounded optimizations were accepted and are already reflected in the
  current checkpoint
- several later candidates were measured, rejected, and reverted
- the remaining bottleneck is still structural round-core work, but it is now
  spread across `temp2`, `new_a` / `new_e`, and the remaining Boolean-heavy
  round path rather than being dominated by the old `temp1` ripple chain

### Accepted candidates

- [x] paired local xor provenance derivation `(landed)`
  - quick native gate: total hidden eval `0.671s -> 0.611s`
  - round core `383.0ms -> 343.1ms`
  - output projector `108.1ms -> 100.4ms`
- [x] paired local add in Beaver `d`/`e` setup `(landed)`
  - quick native gate: total hidden eval `0.611s -> 0.565s`
  - round core `343.1ms -> 317.4ms`
  - output projector `100.4ms -> 90.7ms`
- [x] Beaver-material reuse across bounded local slices `(landed)`
  - quick native gate: total hidden eval `0.565s -> 0.558s`
  - round core `317.4ms -> 314.1ms`
  - output projector `90.7ms -> 90.4ms`
- [x] fixed-modulus output-projector subtraction `(landed)`
  - native: total hidden eval `0.567s -> 0.550s`
  - browser: total hidden eval `0.776s -> 0.762s`
  - output projector: native `90.0ms -> 46.7ms`, browser `117.2ms -> 59.3ms`
- [x] cached OT receiver shared-point state `(landed)`
  - native: total hidden eval `0.550s -> 0.532s`
  - browser: total hidden eval `0.762s -> 0.743s`
  - browser OT point-scalar reconstruction: `23.5ms -> 0`
- [x] trusted timed evaluator reuses split server-input bundles directly `(landed)`
  - native: total hidden eval `0.532s -> 0.513s`
  - browser: total hidden eval `0.743s -> 0.728s`
  - browser `session.evaluate`: `0.738s -> 0.721s`
- [x] prepared-session final report seals output directly from the hidden run `(landed)`
  - measured against the reverted current diagnostic baseline, not the older
  published checkpoint
  - native diagnostic run: total hidden eval `0.586s -> 0.580s`
  - browser diagnostic run: `session.evaluate` `0.853s -> 0.839s`
  - browser diagnostic hidden-eval probe total `0.757s -> 0.733s`
- [x] prepared-session trusted evaluate path skips building transport-only
  server-input ciphertext `(landed)`
  - native: total hidden eval `0.580s -> 0.549s`
  - browser: `session.evaluate` `0.839s -> 0.832s`
  - browser hidden-eval probe total `0.733s -> 0.727s`
  - browser server-input seal timing: `0.6ms -> 0`
- [x] prepared-session caches the CPU execution witness instead of recomputing it
  during report assembly `(landed)`
  - native: total hidden eval `0.549s -> 0.529s`
  - browser: total hidden eval `0.842s -> 0.828s`
  - browser: `session.evaluate` `0.832s -> 0.824s`
  - browser hidden-eval probe total `0.727s -> 0.707s`
  - browser result assembly timing: `3.7ms -> 0`
- [x] wasm hidden-run benchmark export bypasses full report assembly and output
  opener shaping in the measured browser detailed-result path `(landed)`
  - this was an architecture refactor first, not a headline arithmetic win
  - fresh browser run on the new path:
    `0.844s -> 0.808s`
  - browser `session.evaluate`:
    `0.834s -> 0.808s`
  - browser estimated JS/wasm gap:
    `108.6ms -> 68.3ms`
  - `result_assembly_duration_ns = 0`
  - `output_sealing_finalization_duration_ns = 0`
  - `output_materialization_duration_ns ≈ 4.2ms`
  - the browser benchmark now measures a hidden-run export directly instead of
    forcing the detailed path through report assembly and delivery shaping
- [x] Phase A executor-local arithmetic path for message-schedule accumulation
  `(landed)`
  - current bounded slice only moves message-schedule accumulation onto an
    executor-local arithmetic representation
  - this is not yet a general mixed Boolean/arithmetic conversion gadget, and
    it still relies on executor-local access to the split share state for the
    first conversion seam
  - native: total hidden eval `0.524s -> 0.504s`
  - browser: total hidden eval `0.844s -> 0.774s`
  - native message schedule `95.8ms -> 51.3ms`
  - browser message schedule `152.6ms -> 75.0ms`
  - native message-schedule accumulation `83.0ms -> 37.7ms`
  - browser message-schedule accumulation `135.2ms -> 57.4ms`
  - browser hidden-eval probe total `0.729s -> 0.660s`
- [x] Phase A executor-local arithmetic path for `temp1` accumulation `(landed)`
  - still keeps `Sigma1` and `Ch` on the Boolean side and converts only the
    five add operands plus the final `temp1` result
  - native: total hidden eval `0.504s -> 0.387s`
  - browser: total hidden eval `0.774s -> 0.568s`
  - native round core `343.4ms -> 232.0ms`
  - browser round core `514.5ms -> 328.4ms`
  - native round `temp1` `148.2ms -> 46.0ms`
  - browser round `temp1` `231.8ms -> 65.3ms`
  - browser hidden-eval probe total `0.660s -> 0.467s`
  - the old width-1 ripple add-chain for `temp1` is no longer on the hot path

### Rejected and reverted candidates

- [x] scratch reuse in hot add-chain accumulators `(reverted)`
  - native: total hidden eval `0.565s -> 0.572s`
- [x] batched local xor derivation across slices `(reverted)`
  - native: total hidden eval `0.565s -> 0.591s`
- [x] constant-aware `temp1` round-constant add `(reverted)`
  - native improved slightly, but browser regressed:
    total hidden eval `0.774s -> 0.790s`
- [x] loop-label buffer reuse in hot add/sub helpers `(reverted)`
  - native improved, but browser regressed:
    total hidden eval `0.774s -> 0.796s`
- [x] trusted local-word accessor fast path in packed executor storage `(reverted)`
  - native: total hidden eval `567.2ms -> 637.0ms`
- [x] direct batched `Ch`/`Maj` outputs without split-word round-trip `(reverted)`
  - native: total hidden eval `567.2ms -> 599.4ms`
- [x] selector-path repeated-left batch multiply helper `(reverted)`
  - native: total hidden eval `567.2ms -> 583.8ms`
- [x] allocation-free local-mul `"/d"` and `"/e"` suffix labels `(reverted)`
  - native: total hidden eval `567.2ms -> 591.2ms`
- [x] fused `temp1` carry-chain kernel without intermediate 64-bit words `(reverted)`
  - native improved slightly: total hidden eval `550.4ms -> 545.9ms`
  - browser regressed overall: total hidden eval `762.1ms -> 766.9ms`
- [x] balanced add tree for 4-word and 5-word local accumulation `(reverted)`
  - native: total hidden eval `567.2ms -> 602.2ms`
- [x] direct `Ch`/`Maj` batch multiply from prebuilt local-word vectors `(reverted)`
  - native: total hidden eval `0.513s -> 0.533s`
  - round core `312.5ms -> 325.9ms`
  - round `temp1` `134.8ms -> 140.7ms`
- [x] trusted timed split-server-input executor without bundle revalidation `(reverted)`
  - native: total hidden eval `0.513s -> 0.523s`
  - round core `312.5ms -> 321.9ms`
  - output projector `43.7ms -> 44.9ms`
- [x] remove cloned client input word vectors before split-local conversion `(reverted)`
  - native: total hidden eval `0.513s -> 0.530s`
  - round core `312.5ms -> 321.5ms`
  - output projector `43.7ms -> 44.8ms`
- [x] borrow SHA-512 IV and round-constant pool directly in round-core setup `(reverted)`
  - native: total hidden eval `0.513s -> 0.517s`
  - round core `312.5ms -> 316.3ms`
- [x] direct packed-bit access in sigma transform helpers `(reverted)`
  - native: total hidden eval `0.513s -> 0.521s`
  - round core `312.5ms -> 318.9ms`
  - message schedule `94.4ms -> 95.0ms`
- [x] paired split-word sigma xor derivation `(reverted)`
  - native: total hidden eval `0.513s -> 0.526s`
  - round sigma1 improved `8.0ms -> 5.5ms`, but round core worsened
    `312.5ms -> 323.2ms`
- [x] cached evaluator OT sender-point decompression in prepared session `(reverted)`
  - native: total hidden eval `0.513s -> 0.559s`
  - round core `312.5ms -> 335.9ms`
  - this targeted browser/session OT prep, but it failed the native gate first
- [x] direct three-input sigma xor primitive `(reverted)`
  - native: total hidden eval `0.513s -> 0.524s`
  - round sigma1 improved `8.0ms -> 4.8ms`, but total round core still worsened
    `312.5ms -> 323.1ms`
- [x] direct three-input xor for local add `sum` lane `(reverted)`
  - native: total hidden eval `0.513s -> 0.542s`
  - round temp1 worsened `134.8ms -> 144.0ms`
  - round core worsened `312.5ms -> 334.1ms`
- [x] cached local-mul material-base reuse inside add carry-gates `(reverted)`
  - targeted the freshly profiled carry-gate hotspot directly
  - diagnostic native run regressed: total hidden eval `0.584s -> 0.595s`
  - diagnostic round core regressed `359.5ms -> 358.4ms` only slightly, but the
    top-line keep gate still lost badly
- [x] trusted prepared-session path skips unused OT transcript construction
  `(reverted)`
  - native: total hidden eval `0.529s -> 0.536s`
  - message schedule `98.0ms -> 98.2ms`
  - round core `327.6ms -> 329.8ms`
  - output projector `45.1ms -> 45.4ms`
  - browser was not run because the native keep gate already failed
- [x] narrower local-word accessor and output-push fast path in hot add helpers
  `(reverted)`
  - native stayed effectively flat on the keep gate:
    total hidden eval `0.536s -> 0.535s`
  - browser hidden-eval work regressed:
    `session.evaluate` `0.812s -> 0.817s`
  - browser hidden-eval probe total `0.713s -> 0.715s`
  - browser message schedule `148.7ms -> 154.3ms`
  - browser round core `490.4ms -> 494.1ms`
- [x] fused `temp1` kernel that computes `Sigma1`, `Ch`, and the 5-word add
  without materializing intermediate split words `(reverted)`
  - native improved:
    total hidden eval `0.536s -> 0.529s`
  - native round core improved `329.6ms -> 327.4ms`
  - native round sigma1 improved `8.6ms -> 5.3ms`
  - browser regressed:
    total hidden eval `0.818s -> 0.833s`
  - browser hidden-eval probe total `0.713s -> 0.724s`
  - browser round core `490.4ms -> 498.3ms`
  - browser round temp1 `219.8ms -> 225.5ms`

### Main takeaway

- accepted wins came from removing duplicated derivation work that already
  existed on the hot path or from deleting generic arithmetic in a fixed-shape
  seam
- rejected wins mostly tried to rearrange the same arithmetic work rather than
  removing it
- browser is the stricter gate; several candidates that helped native still
  lost once wasm was measured
- the first kept Phase 4 win came from deleting repeated OT reconstruction work
  entirely, not from trying to shave small amounts off the same session path
- the next kept Phase 4 win came from deleting a joined server-input clone in
  the timed evaluator path and reusing the already split server-input bundles
- not every vector-churn deletion in hot arithmetic is a win; the `Ch`/`Maj`
  local-word batch rewrite still lost in native despite removing conversions
- not every trusted-path validation deletion is a win either; skipping split
  bundle revalidation in the timed evaluator path regressed native and was
  reverted
- even obvious-looking data-copy deletions need measurement; removing cloned
  client input word vectors before split-local conversion also regressed native
  and was reverted
- future work should assume that broad wrapper, allocation, or tree-shape
  rewrites are low-probability unless a fresh profile identifies a much narrower
  seam
- after the accepted projector specialization, the practical next target is
  `round_core`, not more projector micro-work
- a fresh fine-grained add profile now shows that carry-gate multiply dominates
  both remaining add-heavy hot seams, so more xor-lane micro-tuning is unlikely
  to land
- the latest kept session-layer win came from deleting an internal
  server-output serialize/deserialize round-trip in the prepared-session path,
  not from shaving more helper overhead
- the newest kept session-layer win deleted another transport-only step in the
  prepared-session path by skipping server-input packet sealing that the trusted
  evaluator never consumed
- the latest kept session-layer win deleted repeated CPU execution-program work
  from prepared-session evaluation by caching the witness once per prepared
  artifact/runtime
- even a dead-looking transport-side deletion still needs measurement; removing
  unused OT transcript construction from the trusted prepared-session path
  regressed native and was reverted
- tiny local accessor/output-builder churn was not the bottleneck either; a
  narrowed fast path in the hot add helpers was flat in native and worse in the
  browser hidden-eval path
- even a real temp1-specific structural rewrite is not enough if it shifts more
  work into the wasm/browser path; the fused `Sigma1`/`Ch`/`temp1` kernel helped
  native but still failed the browser gate

### Fresh add-path profiling

This was a diagnostic native release run on `2026-03-29` with extra
per-substep timers added to the hidden-eval profiling path. The absolute
end-to-end numbers are therefore not directly comparable to the accepted
baseline above; the point of this run was seam attribution, not a new published
checkpoint.

Measured means from that profiling run:

- total hidden eval: about `0.584s`
- message schedule accumulation: about `93.0ms`
- message schedule accumulation `carry_gate`: about `61.4ms`
- message schedule accumulation `xor_ab`: about `6.1ms`
- message schedule accumulation `sum`: about `6.0ms`
- message schedule accumulation `a_xor_carry`: about `6.6ms`
- message schedule accumulation `next_carry`: about `6.4ms`
- round `temp1`: about `155.6ms`
- round `temp1` `carry_gate`: about `102.6ms`
- round `temp1` `xor_ab`: about `10.1ms`
- round `temp1` `sum`: about `10.0ms`
- round `temp1` `a_xor_carry`: about `10.9ms`
- round `temp1` `next_carry`: about `10.7ms`

Immediate implication:

- about two thirds of the measured add-heavy time is in the carry-gate multiply,
  not in the surrounding xor lanes
- this rules out spending more blind effort on `sum`, sigma-xor, or label-only
  rewrites as the main optimization lane for `temp1`

## Optimization Guardrails

### 1. Security boundary first when capability is affected

If a performance idea depends on the evaluator holding both share halves, or on
the evaluator carrying plaintext server output farther than necessary, reject it.

The next pass should assume these remaining boundary goals:

- [ ] server input delivery becomes actually 2-party
- [ ] evaluator-visible plaintext server-output payloads go away
- [ ] joined hidden values remain boundary-only and trusted-only

### 2. One production path only

Do not keep:

- a fast legacy path
- a secure path
- a benchmark-only path that behaves differently from production

If a new optimization needs a forked production implementation to look good, it
is probably the wrong optimization.

### 3. Benchmark-gated changes only

Every candidate should be:

1. small
2. measurable
3. kept only if it improves the accepted baseline or is neutral with a clear
   secondary win such as lower memory traffic

Native-only wins that regress the browser path are not accepted by default.

### 4. Prefer deletion over layering

If a helper becomes obsolete after a better kernel lands, delete it. Do not keep
both versions around for optional reuse later.

## What v2 Should Optimize

The next pass should focus on four layers, in order.

## Layer 0: Capability-Safe Boundary Cleanup

This is not pure performance work, but it directly determines which later
optimizations are valid.

### Goals

- [ ] stop decrypting server-input material into an evaluator-owned shape that
  exposes both transport sides
- [ ] stop carrying plaintext server-output payload bytes inside the evaluator
  result object
- [ ] keep boundary objects narrow enough that later arithmetic optimization does
  not accidentally widen evaluator visibility again

### Why this comes first

Without this cleanup, performance work risks polishing the wrong interfaces and
locking in an execution model we still intend to delete.

### Desired optimization shape

- [ ] transport-layer parsing should yield role-local views, not a joined
  convenience container
- [ ] server-input validation should hash and verify directly over role-local
  transport material
- [ ] output delivery should seal the server payload as early as possible in the
  server-owned path rather than serializing plaintext for later resealing

## Layer 1: Executor Data Layout

The hardened executor now has the right semantics. The next major wins are
likely to come from reducing representation churn and improving cache behavior.

### Main direction

Keep optimizing around executor-local packed storage rather than reconstructing
temporary `DdhHssLocalWord` objects more often than necessary.

### Hard constraint

- [ ] do not assume the current width-1 local bit shares can be packed into a
  width-64 local word and fed directly into the existing local word-add helper;
  the current bit-packing helper and the existing word-share add semantics are
  not interchangeable

### Candidate approaches

- [x] introduce narrower read-only bit views so hot kernels can consume packed side
  storage without cloning a local word per bit `(reverted so far)`
- [ ] add write-focused builders for packed output words so kernels do not push
  commitments, provenance, and share bits through repeated tiny helper calls
- [ ] reduce metadata fanout by handling provenance and commitment derivation at the
  pair or slice level when semantics permit
- [ ] prefer structure-of-arrays style access in hot kernels over helper patterns
  that bounce between packed storage and richer wrapper objects
- [ ] prototype a chunked local representation for add-heavy seams such as
  `temp1`, `temp2`, and message-schedule accumulation, for example `4`-bit or
  `8`-bit lanes instead of width-1 everywhere
- [ ] prototype a dual representation that keeps Boolean-style split/local words
  for `Sigma`, `Ch`, and `Maj`, but converts into an add-focused representation
  for `temp1`, `temp2`, and schedule accumulation
- [ ] evaluate a true arithmetic-share representation for add-heavy seams, not
  just chunked Boolean packing, if the dual-representation prototype shows that
  carry work is still the dominant blocker
- [ ] add a wasm-oriented raw-array round-core kernel shape that operates on flat
  side buffers and preallocated scratch rather than reconstructing
  `DdhHssLocalWord` objects inside the hottest loops

### Good signs

- fewer per-bit object constructions
- fewer tiny allocations
- less conversion between storage shapes

### Bad signs

- new adapters that reintroduce legacy slice models
- wrapper-only refactors with no measured reduction in allocations or CPU
- extra staging buffers needed only to satisfy generic helper APIs

## Layer 2: Arithmetic Kernel Fusion

The remaining hot spots are still centered in round-core work, especially
`temp1`, carry propagation, and selection-heavy Boolean logic.

### Main direction

Fuse work only at seams that are already proven hot in measured output.

### Candidate approaches

- [ ] carry-specific fusion inside split/local add helpers so `xor_ab`, `sum`,
  `carry_gate`, and `next_carry` pay less per-bit setup overhead
- [ ] a `temp1`-specific accumulation kernel that avoids repeated helper boundaries
  while keeping the same semantics
- [ ] a block carry-lookahead or parallel-prefix adder for split/local words so
  the carry path is no longer a 64-step serial ripple in the hottest seams
- [ ] a compressor or carry-save style accumulator for `temp1` and message
  schedule with one final carry-propagate stage, but only if the implementation
  deletes real carry work rather than just moving it between helpers
- [ ] an add-focused arithmetic kernel that reduces the number of Beaver-gated
  bit multiplies rather than only lowering the helper overhead around the same
  multiply count
- [ ] build a dedicated fixed-shape `round_core` kernel IR for the SHA-512 round
  so `Sigma1`, `Ch`, `h + K[t] + W[t]`, `Sigma0`, `Maj`, and state rotation are
  expressed as one specialized round program rather than a stack of generic
  split/local helpers
- [ ] explore algebraic reformulations of `temp1` and schedule accumulation only
  if they reduce the number of secure carry computations instead of just
  changing helper boundaries
- [ ] narrower fused subtraction-plus-select paths for canonical `mod l` reduction
  in the output projector
- [ ] slice-local `Ch` and `Maj` kernels that reuse one measured-good derivation
  prefix strategy without reviving the previously rejected broad xor batching

### Things to avoid

- whole-slice fusion done only because it is aesthetically cleaner
- constant-aware rewrites that help native and hurt wasm
- broad speculative batching across many helpers at once

## Layer 3: Derivation and Label Overhead

The old log already showed that provenance, commitments, and gate-derivation
cost dominate when the arithmetic shape is otherwise reasonable.

### Main direction

Reduce repeated setup work, but only in ways that preserve per-gate uniqueness
and survive both native and browser measurement.

### Candidate approaches

- [ ] replace repeated dynamic label construction in the hottest loops with cheaper
  stable-prefix assembly
- [ ] reuse initialized digest prefix state inside one kernel invocation when the
  remaining suffix data still uniquely identifies the gate `(reverted so far in
  add carry-gates)`
- [ ] keep pair-level derivation reuse where left/right operations already share the
  same semantic prefix
- [ ] push more constant label material out of inner loops and into precomputed
  kernel-local state
- [ ] if the specs can tolerate it, evaluate per-kernel provenance derivation
  plus deterministic per-lane expansion as a replacement for some current
  per-gate derivation work

### Hard rule

Do not trade away per-gate uniqueness or domain separation to save hashing work.

## Layer 4: Session and Wasm Overhead

Once the arithmetic core plateaus again, the next wins will come from the
session layer and the JS/wasm boundary.

### Candidate approaches

- [x] remove redundant validation from repeated prepared-session evaluation when the
  same invariant was already checked at preparation time `(reverted)`
- [ ] reduce serialization and cloning in the remaining packet-delivery seams
- [ ] tighten wasm-facing result shaping so timed paths avoid report-formatting work
- [ ] make output assembly and sealing consume borrowed views wherever possible
- [x] add a minimal wasm hidden-run or probe export that measures the hot hidden
  evaluator path without also paying for full report shaping, output opening,
  public-key derivation, hex encoding, and JS serialization `(landed in part)`
- [ ] introduce a wasm32-specific round-core execution path that uses flat
  linear-memory buffers and preallocated scratch for the measured hot kernels
- [ ] if wasm still loses after the kernel shape is flattened, evaluate a
  dedicated browser execution strategy such as worker-isolated hidden-eval runs
  before considering larger platform-specific offload work
- [ ] if browser overhead remains material after the hot path is flattened, move
  the hidden evaluator behind a dedicated worker with a minimal binary request
  and response surface instead of keeping the benchmark on the main-thread JS
  boundary

### Important rule

Do not create a benchmark-only shortcut that bypasses real production shaping
unless the same shortcut is also the intended production path.

## What Not To Retry Blindly

The earlier campaign already taught us that several broad ideas are poor fits
for this codebase. Treat them as low-priority unless a fresh profile points to a
very narrow version of the same idea.

### Avoid by default

- broad scratch-plumbing rewrites in hot add chains
- slice-wide local xor batching
- native-only label-buffer or constant-specialization rewrites
- wrapper-only type splits that do not reduce evaluator capability
- any optimization that depends on reviving joined execution helpers

## Suggested Work Order

- [ ] finish the remaining capability-boundary cleanup that affects server-input
  and server-output handling
- [ ] reprofile native release and browser runs on that narrower boundary
- [ ] choose one executor data-layout candidate from the hottest measured seam
- [x] use the fresh add-path profile to confirm whether xor-lane or carry-gate
  work dominates `(done)`
- [ ] choose one arithmetic-fusion candidate only after the new profile confirms
  the seam is still dominant
- [ ] decide explicitly whether the next big step is
  `chunked/dual-representation`,
  `prefix-adder round-core kernel`,
  or `wasm-specific flat-memory kernel`, and reject the other two for the
  current pass to keep scope bounded
- [ ] move to label and digest overhead only after the storage and kernel shape
  are stable again
- [ ] revisit session-layer and wasm shaping only when arithmetic gains flatten

## Ranked Next Candidates

This is the concrete ranked queue I would use from the current measured state.
The ranking favors split/local-safe changes with a realistic chance of helping
both native and browser runs.

### Rank 1: dual Boolean/arithmetic representation for add-heavy seams

- [ ] keep Boolean split/local words for `Sigma`, `Ch`, and `Maj`
- [ ] introduce an arithmetic-share representation for `temp1`, `temp2`,
  `new_a`, `new_e`, and message-schedule accumulation
- [ ] measure whether the conversion seams are cheaper than the current carry-gate
  multiply budget they replace
- expected reason to help:
  this is the only lane with a real chance to remove most of the current
  carry-gate multiply cost instead of just reshaping it
- scope:
  `crates/succinct-garbling/src/ddh_hidden_eval_executor.rs`
  and `crates/succinct-garbling/src/ddh_hss.rs`

### Rank 2: chunked-lane representation for add-heavy seams

- [ ] prototype `4`-bit or `8`-bit chunked lanes for `temp1`, `temp2`, and
  schedule accumulation instead of 64 width-1 carry steps
- [ ] introduce only the chunk-local gadgets actually needed for the add-heavy
  seams
- [ ] reject the idea quickly if chunk conversion or gadget cost swamps the
  shorter carry depth
- expected reason to help:
  this is the highest-upside fallback if full arithmetic-share conversion is too
  invasive, because it still attacks carry depth directly
- scope:
  `crates/succinct-garbling/src/ddh_hidden_eval_executor.rs`
  and `crates/succinct-garbling/src/ddh_hss.rs`

### Rank 3: dedicated fixed-shape SHA-512 round-core kernel

- [ ] stop expressing the hot round path as a stack of generic helper calls
- [ ] build one fixed-shape round kernel that directly handles `Sigma1`, `Ch`,
  `h + K[t] + W[t]`, `Sigma0`, `Maj`, `temp2`, state rotation, and the chosen
  add representation
- [ ] keep this tightly bound to SHA-512 round structure rather than trying to
  generalize it into a new generic helper layer
- expected reason to help:
  any big representation win will leak away if the round still bounces through
  generic helper boundaries and conversion seams
- scope:
  `crates/succinct-garbling/src/ddh_hidden_eval_executor.rs`
  and `crates/succinct-garbling/src/ddh_hss.rs`

### Rank 4: browser/session overhead deletion once arithmetic stalls

- [ ] revisit OT/open/join and result shaping only where work can be deleted
  outright from the browser path
- [ ] add a minimal wasm hidden-run export so browser measurement can isolate the
  hot core from report, open, and encoding work
- [ ] if the browser gate is still dominated by round-core after that, build a
  wasm-specific flat-memory kernel for the hot arithmetic path rather than
  reusing the object-heavy native shape unchanged
- [ ] if browser still loses after the wasm-specific kernel shape lands, move
  the hidden evaluator into a dedicated worker before considering larger
  platform-specific offload work
- expected reason to help:
  browser still pays real non-arithmetic cost after the accepted evaluator-side
  cleanup, and this lane has already produced landed wins
- scope:
  `crates/succinct-garbling/src/succinct_hss.rs`,
  `crates/succinct-garbling/src/wasm.rs`,
  and `crates/succinct-garbling/src/ddh_hss.rs`

## High-Impact Phased Todo List

This is the dedicated track for ideas that could materially cut latency rather
than just shave helper overhead. Only one phase should be active at a time.

This section is intentionally more aggressive than the rest of the plan.
The goal is to stop spending cycles on tiny helper cleanups and instead attack
the arithmetic shape that is still dominating runtime.

Rules for this track:

- [ ] do not run side quests while one of these phases is active
- [ ] allow breaking internal refactors if they simplify the winning path
- [ ] delete superseded helper plumbing as soon as a replacement path is
  validated instead of carrying legacy executor shapes forward
- [ ] measure stage deltas for `round_core`, `round_temp1`, and message-schedule
  accumulation on every iteration
- [ ] reject a phase quickly if it does not show a plausible path to a
  double-digit reduction in total hidden-eval latency

The current numbers say the remaining problem is not projector cleanup or
session polish. The remaining problem is that the remaining add-heavy seams
inside `round_core` still pay too much work:

- `round_core` is still about `232.0ms` native and about `328.4ms` browser
- `round_temp1` is now down to about `46.0ms` native and about `65.3ms`
  browser, so the first Phase A arithmetic slice did what it needed to do
- message-schedule accumulation is now down to about `36.0ms` native and about
  `53.2ms` browser
- the next big target inside `round_core` is no longer the old `temp1` ripple
  chain; it is the remaining add-heavy seams such as `temp2`, `new_a`, and
  `new_e`, plus any repeated Boolean/arithmetic boundary crossings that remain

That means the purpose of the next three phases is simple:

- reduce the number of carry-dependent secure operations
- reduce the number of conversions and generic helper boundaries in the hottest
  round path
- keep only the architecture that wins in both native and browser runs

### Phase A: Dual Boolean/arithmetic representation

Objective:
replace the current width-1 Boolean ripple-add path in the hottest seams with
an arithmetic-share path so `temp1`, `temp2`, `new_a`, `new_e`, and schedule
accumulation stop paying most of their cost as carry-gated bit multiplies.

Why this is worth doing:

- this is the only lane that can plausibly remove a large fraction of the
  current add cost instead of merely reshaping it
- `Sigma`, `Ch`, and `Maj` can stay Boolean at first, which keeps the first
  prototype bounded
- if it works, it gives both native and browser a new execution model rather
  than another helper tweak

Architecture tasks:

- [x] define one executor-internal arithmetic-share word type for add-heavy
  seams only
- [x] define the minimal Boolean-to-arithmetic and arithmetic-to-Boolean
  conversion seams for the first executor-local prototype
  - landed slice is still executor-local and not yet a reusable mixed-domain
    specs primitive
- [ ] forbid repeated conversions inside the same round; each hot value should
  cross the representation boundary at most once in and once out
- [x] keep `Sigma`, `Ch`, and `Maj` on the Boolean side for the first cut
- [ ] move only `temp1`, `temp2`, `new_a`, `new_e`, and message-schedule
  accumulation onto the arithmetic side first
  - landed slices now cover message-schedule accumulation and `temp1`
  - `temp2`, `new_a`, and `new_e` are still pending
- [x] introduce dedicated arithmetic accumulators for 4-word and 5-word sums
  instead of trying to make the existing generic helpers do both jobs

Implementation order:

- [x] start with message-schedule accumulation, because it is simpler than full
  round-state rotation and still large enough to measure clearly
- [x] add an arithmetic `temp1` accumulator next, keeping `Sigma1` and `Ch`
  production on the Boolean side and converting only their outputs
- [ ] add arithmetic `temp2`, then `new_a` and `new_e`, only after `temp1`
  proves conversion is not swamping the gain
- [ ] keep the first version executor-local and do not generalize it into a new
  public abstraction

Measurement and kill criteria:

- [ ] count how many Boolean carry-gate multiplies disappear from
  `round_temp1` and message-schedule accumulation
- [ ] measure conversion cost separately from arithmetic accumulation cost
- [ ] keep the phase only if it shows a credible path to cutting `round_temp1`
  and message-schedule accumulation by roughly a third or better
- [ ] stop immediately if conversion dominates or if the representation bounces
  values back and forth more than once per hot seam

Cleanup if it lands:

- [x] delete superseded width-1 add-chain plumbing for the adopted seams
  - message-schedule accumulation no longer uses the old chained 4-word local
    ripple helper
- [ ] remove any temporary adapter layer that exists only to keep the generic
  path alive in parallel
- [ ] update the browser-focused phase list so future work builds on the new
  arithmetic path instead of re-targeting deprecated Boolean ripple helpers

### Next optimization steps

- [ ] extend the same Phase A arithmetic representation to `temp2`
  - this is the next highest-probability win because it is still a simple
    2-word add that sits directly inside `round_core`
- [ ] move `new_a` and `new_e` onto the arithmetic side immediately after
  `temp2` if the value can stay arithmetic across the handoff
  - the goal is to stop converting `temp1` back to Boolean only to re-enter an
    add-heavy seam one step later
- [ ] explicitly track round-local representation crossings
  - every hot round value should cross at most once in and once out
- [ ] re-measure `round_core` after `temp2`, `new_a`, and `new_e` move
  - if the arithmetic lane keeps winning, continue Phase A before reopening any
    chunked-lane or fused-kernel work
- [ ] only reopen Phase B chunked lanes if a later seam cannot be moved cleanly
  onto the arithmetic side
  - the first `4`-bit schedule prototype already failed badly and should not be
    retried in the same shape
- [ ] postpone more browser/session cleanup until the next arithmetic lane is
  exhausted
  - browser is already benefiting from the same `temp1` arithmetic win, so the
    highest leverage remains hot arithmetic rather than JS-side plumbing

### Phase B: Chunked-lane representation

Objective:
replace 64 width-1 carry steps with a smaller number of wider chunk steps in
the add-heavy seams without taking on the full complexity of a dual arithmetic
model.

Why this is worth doing:

- it attacks carry depth directly even if a full arithmetic-share path proves
  too invasive
- it is the best fallback that still changes the shape of the work materially
- it may suit wasm better than the current object-heavy width-1 loop structure

Architecture tasks:

- [x] prototype `4`-bit chunk lanes first; do not jump to `8`-bit lanes until
  `4`-bit lanes are measured
  - first attempt targeted message-schedule accumulation only and was reverted
  - native `message_schedule` regressed from about `51.3ms` to about `166.3ms`
  - native `message_schedule_accumulation` regressed from about `37.7ms` to
    about `152.6ms`
  - native `total_hidden_eval` regressed from about `0.504s` to about `0.612s`
- [x] keep the first attempt local to `temp1` and message-schedule accumulation
  rather than the full executor
  - first attempt stayed local to message-schedule accumulation and failed the
    native gate before any browser run
- [ ] introduce only the chunk-local gadgets required for add-heavy seams
- [ ] keep `Sigma`, `Ch`, and `Maj` on the existing Boolean side for the first
  version unless a conversion hotspot proves that a chunk-native variant is
  necessary
- [ ] represent chunk data in flat arrays or packed executor-local buffers, not
  as nested per-bit helper objects

Implementation order:

- [x] build one chunked accumulator for schedule accumulation first
  - reverted; chunk-local setup cost overwhelmed the shorter carry chain
- [ ] build one chunked accumulator for `temp1` second
- [ ] compare `4`-bit chunk depth reduction against the extra gadget and
  conversion cost before even considering `8`-bit lanes
- [ ] only extend chunking to `temp2`, `new_a`, and `new_e` if the first two
  seams already show clear browser and native wins

Measurement and kill criteria:

- [ ] measure chunk conversion cost, chunk gadget cost, and total carry-depth
  reduction separately
- [ ] reject the phase if chunk setup outweighs the shorter carry path
- [ ] reject the phase if chunking helps native but expands wasm/browser memory
  traffic enough to erase the gain
- [ ] keep the phase only if it produces a cleaner follow-on path to a
  fixed-shape round kernel than the current width-1 model

Cleanup if it lands:

- [ ] delete width-1 add plumbing from the seams that move to chunked
  accumulation
- [ ] do not keep both chunked and width-1 variants alive for the same seam
  unless there is a measured platform split that justifies it
- [ ] update the ranked queue so the next arithmetic work targets the chunked
  path directly instead of retrying abandoned ripple-add ideas

### Phase C: Dedicated SHA-512 round-core kernel

Objective:
stop expressing the hottest SHA-512 round path as a stack of generic helper
calls and instead build one fixed-shape kernel around the winning add
representation from Phase A or Phase B.

Why this is worth doing:

- any big representation win will leak away if the round still bounces through
  generic helper boundaries and temporary word objects
- the round shape is fixed, so the kernel should exploit that fact aggressively
- browser performance is now sensitive to kernel shape, not just total work

Architecture tasks:

- [ ] do not start this phase until Phase A or Phase B has produced a clear
  winner
- [ ] build one dedicated round kernel that directly handles `Sigma1`, `Ch`,
  `h + K[t] + W[t]`, `temp1`, `Sigma0`, `Maj`, `temp2`, `new_a`, `new_e`, and
  state rotation
- [ ] keep round constants, IV layout, and state rotation in the exact order
  the hot kernel consumes them
- [ ] move hot round storage onto flat arrays or packed buffers instead of
  repeatedly reconstructing tiny local-word helper objects
- [ ] keep the kernel tightly bound to SHA-512 structure rather than trying to
  turn it into another generic abstraction layer

Implementation order:

- [ ] build a dedicated kernel for `temp1` and `temp2` production first
- [ ] extend the same kernel to state rotation and write-back second
- [ ] only then fold message-schedule consumers into the same fixed-shape flow
  if the profile says helper-boundary churn is still material
- [ ] keep the old generic round path only long enough to validate parity, then
  remove it from the adopted seams

Measurement and kill criteria:

- [ ] benchmark the fixed-shape kernel against the generic helper stack at the
  stage level, not just top-line totals
- [ ] keep the phase only if the fixed-shape kernel preserves the arithmetic win
  from Phase A or Phase B in both native and browser runs
- [ ] reject any version that merely inlines helpers without changing object
  churn, buffer layout, or conversion count
- [ ] reject any version that duplicates the old round path indefinitely just to
  avoid cleanup

Cleanup if it lands:

- [ ] delete obsolete generic helper plumbing introduced only for the old round
  path
- [ ] collapse temporary adapters and one-off bridge types used during the
  migration
- [ ] treat the fixed-shape round kernel as the production path and optimize
  from there, not from the deprecated generic stack

## Browser-Focused Phased Todo List

If the v2 campaign is reopened specifically to reduce browser runtime, use this
phased list instead of picking broad ideas opportunistically. Each phase should
land only if it clears the benchmark gate for both native and browser runs.

### Phase 1: Reduce arithmetic depth in the hottest add chains

- [x] replace the serial ripple-add structure used by `temp1` with a carry-save
  style accumulation tree in
  `crates/succinct-garbling/src/ddh_hidden_eval_executor.rs` `(reverted so far)`
- [ ] prototype a block carry-lookahead or parallel-prefix carry kernel for the
  same `temp1` and message-schedule seams before trying more fused ripple-adder
  variants
- [ ] if Boolean-only add kernels keep failing, prototype a chunked or dual
  Boolean/arithmetic representation for add-heavy round-core work instead of
  spending more attempts on width-1 helper reshaping
- [ ] if the generic-helper path still resists improvement, build one dedicated
  fixed-shape SHA-512 round kernel rather than applying more local helper
  surgery
- [ ] apply the same shape to message-schedule accumulation if `temp1` proves the
  approach is browser-positive
- [ ] keep the implementation local to the measured hot seams rather than
  generalizing every add helper up front
Current status:
both the attempted `temp1` carry-save rewrite and the balanced add-tree
rewrite regressed and were reverted; a later fused `temp1` carry-chain rewrite
helped native slightly but regressed browser overall and was also reverted.

### Phase 2: Remove dynamic label work from hot kernels

- [x] replace dynamic string label construction in the hottest loops with compact
  encoded labels or stable prefix assembly `(reverted so far)`
- [ ] push reusable hashed prefix state into kernel-local setup so the inner loop
  only appends the truly gate-unique suffix `(reverted so far in add
  carry-gates)`
- [ ] keep per-gate uniqueness and domain separation intact while lowering wasm-side
  formatting and hashing overhead
Current status:
broad loop-label buffer reuse improved native but regressed browser and was
reverted; a later narrower attempt to remove `"/d"` and `"/e"` label
allocations inside local multiply also regressed native and was reverted.

### Phase 3: Lower derivation setup cost inside local arithmetic helpers

- [x] extend the existing paired-derivation approach so hot helpers reuse more
  digest setup without reviving broad batching that already regressed browser
  `(landed)`
- [ ] target the helpers behind packed split/local xor, add, select, and Beaver
  paths in `crates/succinct-garbling/src/ddh_hss.rs`
- [ ] reject any version that introduces extra staging or wrapper churn just to make
  reuse possible
- [ ] if a future specs revision allows it, test per-kernel provenance
  compression against the same correctness and security boundary checks before
  attempting more local digest-prefix reuse
Current status:
paired local xor, paired local add, and bounded Beaver-material reuse landed;
the next candidate here must be narrower than the rejected broader fast-path
and batching attempts. A later carry-gate-specific material-base reuse attempt
also regressed in the freshly profiled add hotspot and was reverted.

### Phase 4: Reduce session-layer browser overhead

- [x] profile and trim `ot_open_join`, point-scalar reconstruction, and remaining
  packet-delivery cloning in
  `crates/succinct-garbling/src/ddh_hss.rs` and
  `crates/succinct-garbling/src/succinct_hss.rs` `(landed in part; one follow-up reverted)`
- [x] add a wasm-facing hidden-run or probe entry point that avoids paying for
  full report shaping, output opening, public-key derivation, and presentation
  encoding on the measured browser hot path `(landed)`
- [ ] keep reconstruction and validation in Rust/wasm longer so less work is paid at
  the JS boundary
- [ ] prefer fewer open/join boundaries and borrowed result shaping over benchmark-
  only shortcuts
- [ ] if the main-thread JS boundary remains noisy after the hot path is flat,
  move browser hidden eval into a dedicated worker with a minimal binary
  interface
Current status:
caching the evaluator OT shared point in receiver state landed and removed
point-scalar reconstruction from the measured browser evaluate path; a follow-on
change also landed that reuses split server-input bundles directly in the timed
evaluator path instead of cloning a joined server-input container. A later
prepared-session fast path also landed that finalizes output delivery directly
from the hidden run instead of serializing and immediately re-opening the
server-output payload in-process. The newest browser-path refactor now exposes a
hidden-run wasm export and routes the browser benchmark through that lighter
path, so the measured detailed-result path no longer pays report assembly or
output-opener shaping. `round_core` is still the larger remaining bottleneck.

### Phase 5: Specialize the output projector for the fixed scalar shape

- [x] replace generic reduction structure in the output projector with a
  fixed-width, fixed-modulus path that matches the production scalar layout
  `(landed)`
- [x] focus on the measured reduction and select seams in
  `crates/succinct-garbling/src/ddh_hidden_eval_executor.rs` `(landed)`
- [x] keep the same split/local security boundary and avoid reintroducing generic
  helper layering if the narrower projector path is measurably faster `(landed)`
Current status:
a fixed-modulus projector subtraction rewrite landed and cut the projector
roughly in half in both native and browser runs; the next bottleneck moved back
to `round_core`.

### Phase 6: Revisit kernel fusion and wasm build tuning last

- [x] try only narrow fusion that removes whole intermediate words in measured hot
  seams such as `temp1`, `Ch`, `Maj`, or projector reduction `(reverted so far)`
- [ ] if the browser gate is still worse after arithmetic-depth work, build a
  wasm32-specific flat-memory kernel for round-core rather than assuming the
  native object-heavy kernel shape is the right browser shape
- [ ] if that still stalls, evaluate worker-isolated browser execution before
  larger platform-specific offload work
- [ ] do not retry broad slice-wide batching, native-only constant specialization,
  or wrapper-only refactors that already lost in browser
- [ ] after arithmetic and session changes plateau, test wasm build settings such as
  stronger LTO, `panic=abort`, `wasm-opt`, and `simd128` only if the target
  environment can actually use them
Current status:
direct `Ch`/`Maj` round-trip removal and packed trusted-accessor rewrites
both regressed in native and were reverted.

### Phase Gate For Every Step

- [ ] implement one bounded change only
- [ ] run correctness tests first
- [ ] run native and browser benchmarks
- [ ] keep the change only if browser improves and native is not meaningfully
  worse
- [ ] record the outcome before moving to the next phase item

### Recommended reopen order

- [ ] Phase 1 round-core work around `temp1`
- [ ] Phase 4 session-layer browser overhead reductions after `round_core`
  changes stop landing
- [ ] Phase 3 helper-level derivation setup reductions only in a proven hot seam
- [ ] Phase 6 narrow fusion only after a fresh profile shows a tighter seam
- [ ] Phase 2 compact labels only where a profile proves formatting cost matters
- [ ] wasm build tuning only after arithmetic and session work flatten out

## Benchmark Discipline

Every accepted step should record:

- [ ] correctness status
- [ ] native release delta
- [ ] browser delta
- [ ] stage-level impact if available
- [ ] whether the change touched evaluator capability or only local execution cost

Recommended gate:

```bash
cargo test --manifest-path crates/succinct-garbling/Cargo.toml --lib -- --nocapture
cargo test --manifest-path crates/succinct-garbling/Cargo.toml --lib prime_order_succinct_hss_matches_reference_fixture_smoke -- --ignored --nocapture
cargo run --release --manifest-path crates/succinct-garbling/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/succinct-garbling/reports/phase3/ddh-hidden-eval-native-release.json
```

Browser reruns should remain part of the keep/revert decision, not a later
sanity check.

## Exit Criteria For A v2 Campaign

The next optimization pass is successful only if all of the following are true:

- it improves the hardened split/local production path directly
- it does not reopen deprecated joined execution seams
- it does not increase evaluator visibility of server secrets
- accepted changes are backed by measured native and browser results
- rejected ideas are removed rather than left behind as optional helpers

## Practical Takeaway

The right v2 mindset is:

- narrow the capability boundary first
- optimize data layout second
- fuse only measured hot kernels third
- tune derivation and session overhead last

If a candidate does not fit that order, it needs a strong measured reason to
jump the queue.
