# Succinct-Garbling Optimization Approaches v3

This is the canonical optimization note for
[`crates/ed25519-hss`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).
It consolidates the still-relevant context from the earlier optimization logs
and records the active phased kernel rewrite plan.

The earlier notes established two things:

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

## Baseline Lock

The current accepted kernel baseline for this plan is:

- native total hidden eval: about `0.305s`
- native `round_core`: about `151.1ms`
- browser total hidden eval: about `0.415s`
- browser `session.evaluate`: about `0.414s`
- browser hidden-eval probe total: about `0.318s`
- browser `round_core`: about `185.4ms`

Comparison reports:

- [`crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json)
- [`crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json)

## Consolidated Historical Context

Older optimization notes are being retired, but the useful context from them is:

- the old performance-first watermark before the hardened split/local path was
  about `0.270s` native and about `0.380s` browser
- the early hardened checkpoint was much slower, roughly `0.595s` native and
  `0.800s` browser
- the biggest durable wins came from changing arithmetic representation and
  kernel shape, not from helper cleanup
- browser-only transport or runtime cleanup mattered, but only after the core
  kernel was already under control

Current secure position versus the old fast watermark:

- native: about `0.270s -> 0.266s`
- browser: about `0.380s -> 0.364s`

Key classes of landed wins that are still relevant:

- arithmetic carry-through in message-schedule accumulation and the `temp1` /
  `temp2` path
- deeper raw packed Boolean-lane gate helpers for `Ch` / `Maj`
- secure raw packed A2B improvements for `new_a` / `new_e`
- garbler-side OT/open/join reductions that did not widen evaluator-visible
  state

Key classes of rejected work that should stay dead:

- helper-level `Ch` / `Maj` rewrites at the old abstraction boundary
- native-only kernel divergence
- browser JSON-byte shaping detours
- evaluator-visible shortcut paths that reconstruct hidden intermediate values

Security lesson from the campaign:

- the insecure direct arithmetic-to-Boolean shortcut for `new_a` / `new_e`
  looked excellent in benchmarks, but it reconstructed the combined arithmetic
  word and re-shared bits as `(bit, 0)`, so it was reverted
- secure improvements must preserve the split/local boundary even when they are
  materially slower than a local plaintext shortcut

Latest landed Phase 2 slice on this branch:

- native total hidden eval: about `0.323s -> 0.323s` (`322.6ms`)
- native `round_core`: about `170.2ms -> 170.8ms`
- browser total hidden eval: about `0.475s -> 0.474s`
- browser `session.evaluate`: about `0.475s -> 0.474s`
- browser hidden-eval probe total: about `0.375s -> 0.374s`
- browser `round_core`: about `235.0ms -> 233.8ms`

This is a small keep. The main value is architectural: the Boolean lane now
has a private kernel-local representation and helper boundary below the generic
`SplitLocalBitWord` scratch flow.

Latest rejected follow-up on this branch:

- reusable `Ch` / `Maj` batch-gate output buffers in `ddh_hss` and the executor
- native total hidden eval regressed: `0.323s -> 0.338s`
- native `round_core` regressed: `170.2ms -> 178.9ms`
- browser gate was not run because the native keep gate already failed

Latest rejected follow-up after that:

- fused `Ch` / `Maj` batch-gate plus final output `xor` in one pass
- native total hidden eval regressed: `0.323s -> 0.340s`
- native `round_core` regressed: `170.2ms -> 181.3ms`
- browser gate was not run because the native keep gate already failed

Latest rejected follow-up after that:

- raw `Ch` gate path with right-hand xor operands kept below the width-1 local-word vector layer
- native total hidden eval regressed: `0.323s -> 0.344s`
- native `round_core` regressed: `170.2ms -> 180.2ms`
- native `round_ch` regressed: `29.0ms -> 31.0ms`
- browser gate was not run because the native keep gate already failed

Latest rejected follow-up after that:

- precompute arithmetic schedule words and arithmetic round constants so `temp1`
  consumes fewer Boolean-to-arithmetic crossings per round
- native total hidden eval regressed: `0.323s -> 0.342s`
- native `round_core` regressed: `170.2ms -> 175.9ms`
- native `round_temp1` improved: `4.6ms -> 2.8ms`
- browser total hidden eval regressed: `0.475s -> 0.492s`
- browser `round_core` regressed: `235.0ms -> 240.5ms`
- browser `round_temp1` improved: `5.4ms -> 3.4ms`
- message schedule regressed enough on both targets to lose overall, so the
  attempt was reverted

Latest rejected follow-up after that:

- borrow the SHA-512 IV and round-constant tables directly inside
  `execute_round_stages` instead of cloning them on entry
- native total hidden eval regressed: `0.323s -> 0.333s`
- native `round_core` regressed: `170.2ms -> 175.9ms`
- browser total hidden eval regressed: `0.485s -> 0.496s`
- browser `round_core` regressed: `247.5ms -> 248.9ms`
- browser hidden-eval probe total regressed: `0.383s -> 0.399s`
- this is the wrong seam; deleting the clone does not delete the real hot work,
  so the attempt was reverted

Latest landed follow-up after that:

- replace the generic transform-descriptor path in `big_sigma0` / `big_sigma1`
  with dedicated kernel-local rotate/xor transforms over packed round-state
  storage
- native total hidden eval improved: `0.351s -> 0.336s`
- native `round_core` improved: `183.2ms -> 176.0ms`
- native `round_sigma1` improved: `8.1ms -> 7.9ms`
- browser total hidden eval improved: `0.500s -> 0.490s`
- browser `session.evaluate` improved: `0.495s -> 0.485s`
- browser hidden-eval probe total improved: `0.404s -> 0.391s`
- browser `round_core` improved: `251.2ms -> 245.7ms`
- browser `round_sigma1` improved: `10.4ms -> 9.1ms`

Latest rejected follow-up after that:

- cache width-1 local-word views inside `RoundKernelState` so `Ch` / `Maj`
  stop rebuilding the same state words every round
- native total hidden eval regressed: `0.336s -> 0.338s`
- native `round_core` regressed: `176.0ms -> 179.1ms`
- native `round_ch` regressed: `30.5ms -> 31.0ms`
- browser gate was not run because the native keep gate already failed

Latest rejected follow-up after that:

- replace the generic transform-descriptor path in message-schedule
  `small_sigma0` / `small_sigma1` with dedicated rotate/shift xor transforms
- native total hidden eval was roughly flat but not compelling: `0.337s -> 0.345s`
- native `message_schedule` and `message_schedule_accumulation` both regressed
- browser total hidden eval regressed: `0.490s -> 0.516s`
- browser hidden-eval probe total regressed: `0.391s -> 0.407s`
- browser `message_schedule` regressed: `73.7ms -> 74.9ms`
- browser `round_core` regressed: `245.7ms -> 254.4ms`
- the direct schedule-sigma transform path was reverted

Latest rejected follow-up after that:

- fuse the `Ch` / `Maj` batch gate with the final xor-with-base inside `ddh_hss`
  so the executor stops materializing the intermediate gated vectors
- native total hidden eval regressed: `0.336s -> 0.342s`
- native `round_core` regressed: `176.0ms -> 181.8ms`
- native `round_ch` regressed: `30.5ms -> 31.6ms`
- browser gate was not run because the native keep gate already failed

Latest rejected follow-up after that:

- combine `Ch` and `Maj` into one 128-lane round-core batch-gate submission so
  the Boolean lane pays for one gate dispatch instead of two
- native total hidden eval regressed: `0.336s -> 0.351s`
- native `round_core` regressed: `176.0ms -> 188.7ms`
- browser gate was not run because the native keep gate already failed
- the combined submission added enough batch-prep and output handling overhead
  that it lost despite deleting one helper invocation, so it was reverted

Latest landed follow-up after that:

- add a raw packed width-1 batch-gate helper in `ddh_hss` and wire `Ch` / `Maj`
  to feed it from kernel-local Boolean storage instead of building input
  `Vec<DdhHssLocalWord>` batches
- native total hidden eval improved: `0.336s -> 0.303s`
- native `round_core` improved: `176.0ms -> 154.2ms`
- native `round_ch` improved: `30.5ms -> 22.4ms`
- browser total hidden eval improved: `0.490s -> 0.453s`
- browser `session.evaluate` improved: `0.485s -> 0.454s`
- browser hidden-eval probe total improved: `0.391s -> 0.355s`
- browser `round_core` improved: `245.7ms -> 214.6ms`
- browser `round_ch` improved materially to `28.3ms`

Latest rejected follow-up after that:

- precompute only the arithmetic round constants for `temp1` so the round core
  deletes one remaining bool-to-arith conversion without reopening schedule-wide
  precompute
- native total hidden eval regressed: `0.303s -> 0.307s`
- native `round_core` regressed: `154.2ms -> 156.0ms`
- browser total hidden eval regressed: `0.453s -> 0.466s`
- browser `round_core` regressed: `214.6ms -> 217.6ms`
- browser hidden-eval probe total regressed: `0.355s -> 0.361s`
- the narrower constants-only crossing cut was reverted

Latest rejected follow-up after that:

- make the raw `Ch` / `Maj` xor-base helper return packed side storage directly
  instead of `Vec<DdhHssLocalWord>` outputs, so the kernel can skip rebuilding
  output words only to push them back into scratch
- native total hidden eval regressed: `0.306s -> 0.322s`
- native `round_core` regressed: `155.2ms -> 162.0ms`
- native `round_ch` regressed: `22.5ms -> 23.7ms`
- browser gate was not run because the native keep gate already failed
- the direct packed-side return changed the runtime shape in the wrong
  direction, so it was reverted

Latest rejected follow-up after that:

- profile the remaining `round_core` crossings, then replace the naive
  arithmetic-to-Boolean rebuild for `new_a` / `new_e` with a direct local-share
  bit decomposition instead of converting both arithmetic sides separately and
  running a full local bit add
- native total hidden eval improved: `0.303s -> 0.199s`
- native `round_core` improved: `154.2ms -> 79.9ms`
- native `round_new_a_bits` dropped to `3.0ms`
- native `round_new_e_bits` dropped to `3.0ms`
- browser total hidden eval improved: `0.453s -> 0.297s`
- browser `session.evaluate` improved: `0.454s -> 0.296s`
- browser hidden-eval probe total improved: `0.355s -> 0.198s`
- browser `round_core` improved: `214.6ms -> 106.4ms`
- this shortcut was correct but insecure for production because it reconstructed
  the combined arithmetic word and re-shared bits as a degenerate `(bit, 0)`
  Boolean split, so it was reverted

Latest landed follow-up after that:

- move `Maj` onto a dedicated raw helper in `ddh_hss` so the kernel no longer
  materializes `x xor y` and `x xor z` as round-local scratch vectors before
  the gate
- native total hidden eval improved: `0.199s -> 0.197s`
- native `round_core` improved: `79.9ms -> 78.7ms`
- browser total hidden eval improved: `0.297s -> 0.294s`
- browser `session.evaluate` improved: `0.296s -> 0.289s`
- browser hidden-eval probe total improved: `0.198s -> 0.194s`
- browser `round_core` improved: `106.4ms -> 102.0ms`

Latest landed follow-up after that:

- replace the insecure direct `new_a` / `new_e` arithmetic-to-Boolean shortcut
  with a secrecy-preserving A2B gadget that decomposes each arithmetic share
  separately and recombines them through the existing Boolean carry add
- native total hidden eval regressed back to the secure checkpoint:
  `0.197s -> 0.320s`
- native `round_core` regressed: `78.7ms -> 165.0ms`
- native `round_new_a_bits` and `round_new_e_bits` each returned to about
  `43ms`
- browser total hidden eval regressed back to the secure checkpoint:
  `0.294s -> 0.466s`
- browser `session.evaluate` regressed: `0.289s -> 0.467s`
- browser hidden-eval probe total regressed: `0.194s -> 0.363s`
- browser `round_core` regressed: `102.0ms -> 222.7ms`
- this is the current production-safe checkpoint because it restores a real
  split-preserving A2B boundary

Latest rejected follow-up after that:

- cache the immutable trusted-OT sender decode once per garbler session and
  feed trusted OT resolve from that prepared state instead of re-decoding the
  sender scalar/public point bundle on every evaluation
- native total hidden eval regressed: `0.197s -> 0.209s` on the insecure
  shortcut branch, and it still was not worth reopening on the secure path
- native `round_core` regressed: `78.7ms -> 87.1ms`
- browser gate was not run because the native keep gate already failed
- the extra prepared-session state and different resolve shape lost overall, so
  the attempt was reverted

Latest landed follow-up after that:

- specialize the secure `new_a` / `new_e` A2B path for its real input shape:
  one left-only Boolean share decomposition plus one right-only decomposition,
  then run the same secure carry recurrence without materializing zero-sided
  split words or calling generic `local_word()` extraction on every bit
- native total hidden eval improved: `0.320s -> 0.316s`
- native `round_core` improved: `165.0ms -> 160.8ms`
- native `round_new_a_bits` improved: `43.1ms -> 41.7ms`
- native `round_new_e_bits` improved: `43.4ms -> 41.6ms`
- browser total hidden eval improved: `0.466s -> 0.451s`
- browser `session.evaluate` improved: `0.467s -> 0.447s`
- browser hidden-eval probe total improved: `0.363s -> 0.345s`
- browser `round_core` improved: `222.7ms -> 204.1ms`
- browser OT/open/join stayed roughly flat, confirming this win came from the
  secure round-core path and not from boundary shortcuts

Latest rejected follow-up after that:

- run `new_a` and `new_e` through one dual-word secure A2B kernel so the two
  carry chains share one 128-lane round-local pass and batch the carry gates
  per bit position
- native total hidden eval regressed: `0.316s -> 0.322s`
- native `round_core` regressed: `160.8ms -> 164.4ms`
- native `round_new_a_bits` regressed: `41.7ms -> 43.0ms`
- native `round_new_e_bits` regressed: `41.6ms -> 43.0ms`
- browser gate was not run because the native keep gate already failed
- the extra dual-word batching did not delete enough carry work to offset the
  added batch plumbing, so the attempt was reverted

Latest landed follow-up after that:

- push the secure A2B carry recurrence below the generic width-1 batch-helper
  boundary into a raw packed helper in `ddh_hss.rs`, then let the executor only
  wrap the returned secure bit pairs back into local bit sides
- native total hidden eval improved: `0.316s -> 0.305s`
- native `round_core` improved: `160.8ms -> 151.1ms`
- native `round_new_a_bits` improved: `41.7ms -> 35.7ms`
- native `round_new_e_bits` improved: `41.6ms -> 35.7ms`
- browser total hidden eval improved: `0.451s -> 0.415s`
- browser `session.evaluate` improved: `0.447s -> 0.414s`
- browser hidden-eval probe total improved: `0.345s -> 0.318s`
- browser `round_core` improved: `204.1ms -> 185.4ms`
- browser OT/open/join stayed roughly flat, confirming this win again came from
  the secure round-core path rather than from boundary shortcuts

Latest rejected follow-up after that:

- try returning owned raw bit-slice outputs directly from the secure A2B helper
  instead of `Vec<DdhHssLocalWord>` results, then wrap those raw slices back
  into `LocalBitWordSide` in the executor
- native total hidden eval improved slightly: `0.305s -> 0.301s`
- native `round_core` improved slightly: `151.1ms -> 149.1ms`
- native `round_new_a_bits` improved slightly: `35.7ms -> 35.2ms`
- native `round_new_e_bits` improved slightly: `35.7ms -> 35.2ms`
- browser total hidden eval regressed: `0.415s -> 0.444s`
- browser `session.evaluate` regressed: `0.414s -> 0.432s`
- browser hidden-eval probe total regressed: `0.318s -> 0.326s`
- browser `round_core` regressed: `185.4ms -> 189.6ms`
- browser OT/open/join regressed: `104.1ms -> 108.8ms`
- the owned-raw output seam still made wasm do more work overall, so the
  attempt was reverted

Latest rejected follow-up after that:

- cache immutable OT sender-public decompressions once per evaluator session
  and feed OT request prep from that prepared sender-point state
- native total hidden eval improved: `0.305s -> 0.301s`
- native `round_core` improved slightly: `151.1ms -> 149.5ms`
- browser total hidden eval regressed: `0.415s -> 0.444s`
- browser `session.evaluate` regressed: `0.414s -> 0.432s`
- browser hidden-eval probe total regressed: `0.318s -> 0.326s`
- browser `round_core` regressed: `185.4ms -> 189.6ms`
- browser OT/open/join regressed: `104.1ms -> 108.8ms`
- the extra evaluator-session cache state was not worth it, so the attempt was
  reverted

Latest landed follow-up after that:

- keep OT request prep semantically identical, but replace the per-bit
  `ED25519_BASEPOINT_POINT * receiver_scalar` path with
  `ED25519_BASEPOINT_TABLE * &receiver_scalar`
- native total hidden eval improved: `0.305s -> 0.289s`
- browser total hidden eval improved: `0.415s -> 0.408s`
- browser `session.evaluate` improved: `0.414s -> 0.408s`
- browser hidden-eval probe total regressed slightly: `0.318s -> 0.324s`
  because the kernel-side stages were noisy on the same run, but OT/open/join
  itself improved materially
- browser OT/open/join improved: `104.1ms -> 91.5ms`
- browser estimated JS/wasm gap improved: `~97.0ms -> ~84.5ms`
- this is the current kept OT/open/join checkpoint because it improves the real
  browser boundary cost without changing payload semantics or widening the
  evaluator boundary

Latest rejected follow-up after that:

- replace per-bit arithmetic-share decomposition through a full local-word pair
  builder with a same-side local-bit builder, then feed the same secure carry
  A2B path from those narrower local words
- native total hidden eval regressed: `0.289s -> 0.295s`
- native `round_core` regressed: `145.1ms -> 147.3ms`
- native `round_new_a_bits` regressed: `34.2ms -> 35.2ms`
- native `round_new_e_bits` regressed: `34.6ms -> 35.2ms`
- browser gate was not rerun because the native keep gate already failed
- the same-side builder removed one discarded half per bit, but still did not
  delete enough secure A2B work to beat the current kept path, so it was
  reverted

Latest landed follow-up after that:

- collapse secure arithmetic-share decomposition and the carry recurrence into
  one raw packed helper in `ddh_hss.rs`, so `new_a` / `new_e` no longer build
  intermediate `LocalBitWordSide` buffers before secure A2B
- native total hidden eval improved: `0.297s -> 0.295s`
- native `round_core` improved slightly: `148.6ms -> 148.4ms`
- native `round_new_a_bits` improved: `35.2ms -> 34.5ms`
- native `round_new_e_bits` improved: `35.2ms -> 34.4ms`
- browser total hidden eval improved: `0.408s -> 0.402s`
- browser `session.evaluate` improved: `0.408s -> 0.406s`
- browser hidden-eval probe total improved: `0.324s -> 0.316s`
- browser `round_core` improved: `187.8ms -> 183.7ms`
- browser OT/open/join regressed slightly: `91.5ms -> 94.3ms`, but the kernel
  win still improved the browser top line overall
- the old secure bit-slice carry helper became dead on this path and was
  removed

Latest landed follow-up after that:

- precompute per-word sender-state curve invariants once per garbler session
  and use them on the trusted OT resolve path, so each bit computes
  `receiver_public * sender_scalar` once and derives the alternate branch by
  subtracting the precomputed `sender_public * sender_scalar` point instead of
  doing a second scalar multiply
- native total hidden eval improved: `0.295s -> 0.271s`
- native `round_core` improved: `148.4ms -> 140.9ms`
- browser total hidden eval improved: `0.402s -> 0.364s`
- browser `session.evaluate` improved: `0.406s -> 0.363s`
- browser hidden-eval probe total improved: `0.316s -> 0.302s`
- browser `round_core` improved: `183.7ms -> 175.5ms`
- browser OT/open/join improved materially: `94.3ms -> 68.5ms`
- browser estimated JS/wasm gap improved: `~85.6ms -> ~62.5ms`
- the wire payloads and evaluator-visible semantics stayed unchanged because
  this is a private prepared-session cache on the garbler side only

Latest landed follow-up after that:

- add a trusted internal OT reconstruct path that skips recomputing bundle-level
  OT commitments and transcript bindings already guaranteed by the same
  prepared session, while keeping per-branch payload verification intact
- native total hidden eval improved: `0.271s -> 0.266s`
- native `round_core` improved: `141.1ms -> 137.7ms`
- browser total hidden eval improved slightly: `0.364s -> 0.364s` (`363.9ms -> 363.6ms`)
- browser `session.evaluate` regressed slightly: `0.363s -> 0.364s`
- browser hidden-eval probe total improved: `0.302s -> 0.300s`
- browser OT/open/join improved: `68.5ms -> 67.0ms`
- browser OT commitment verification improved: `2.5ms -> 1.4ms`
- the old unused timed reconstruct wrapper was deleted after this landed

Benchmark commands:

```bash
cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json

wasm-pack build crates/ed25519-hss --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/ed25519-hss/web/generated
python3 -m http.server 8765 -d crates/ed25519-hss/web
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-port=9222 --user-data-dir=/tmp/codex-chrome-bench about:blank
node crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs --debug-port 9222 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json
```

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

- [x] copy the accepted baseline numbers into the top of this note before
  changing code
- [x] record the exact native and browser report files to compare against
- [x] keep one benchmark command block at hand for native and browser so every
  phase uses the same gate
- [x] do not mix transport/session changes into this kernel branch

Exit gate:

- [x] all work in this branch compares against one stable baseline, not moving
  numbers from earlier failed attempts

## Phase 1: Dedicated Round-State Layout

Goal:

- introduce a private round-core kernel state below `SplitLocalBitWord`

Implementation:

- [x] add a dedicated fixed-size round-state struct in
  [`ddh_hidden_eval_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hidden_eval_executor.rs)
  for `a,b,c,d,e,f,g,h`
- [ ] represent the remaining Boolean lane with contiguous packed left/right bit
  storage plus parallel commitment/provenance storage
- [x] start replacing generic `SplitLocalBitWord` scratch inside `round_core`
  with a private kernel-local Boolean word type over left/right packed storage
- [x] keep arithmetic state in dedicated arithmetic slots, not generic helper
  wrappers
- [x] implement conversion from existing stage inputs into the kernel state
- [x] implement conversion back out only at the existing stage boundary
- [x] try cached width-1 local-word views inside `RoundKernelState` for `Ch` /
  `Maj` `(tried, reverted)`
- [ ] delete temporary helper glue if the kernel state makes it dead

Rules:

- [x] no target-specific kernel logic here
- [x] no transport or session changes
- [x] no duplicate fallback engine inside the hot path

Exit gate:

- [x] correctness passes
- [x] no measurable regression from layout-only introduction larger than `3%`
  before Phase 2 starts

## Phase 2: Boolean Lane Rewrite

Goal:

- stop expressing `Sigma0`, `Sigma1`, `Ch`, and `Maj` through generic
  `SplitLocalBitWord` helper composition

Implementation:

- [x] implement dedicated kernel-local `Sigma0` and `Sigma1` transforms directly
  over packed round-state storage `(landed)`
- [x] start routing `Sigma0` and `Sigma1` through a kernel-local Boolean word
  type instead of generic split-word scratch
- [x] start routing `Ch` over the same packed left/right storage
- [x] start routing `Maj` over the same packed left/right storage
- [x] ensure the current four operations share one kernel-local scratch model
  instead of four separate helper shapes
- [ ] remove per-round `Vec<DdhHssLocalWord>` construction for Boolean
  intermediates
- [x] try reusable `Ch` / `Maj` batch-gate output buffers `(tried, reverted)`
- [x] try fused `Ch` / `Maj` batch-gate plus xor-with-base in `ddh_hss`
  `(tried, reverted)`
- [x] try one combined 128-lane `Ch` / `Maj` batch submission per round
  `(tried, reverted)`
- [x] reuse kernel-local scratch across all 80 rounds

Rules:

- [ ] do not reintroduce helper-level object materialization inside these
  transforms
- [ ] do not force outputs back into `SplitLocalBitWord` just to feed the next
  line of the same kernel

Exit gate:

- [x] browser `round_core` improves or stays flat before Phase 3
- [x] if browser regresses here, stop and inspect before adding deeper raw-gate
  work

## Phase 3: Raw Gate Path Integration

Goal:

- push the Boolean lane below the current generic batch-multiply surface

Implementation:

- [ ] add raw packed batch-gate helpers in
- [x] add raw packed batch-gate helpers in
  [`ddh_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hss.rs)
  that consume packed bits plus aligned commitment/provenance storage directly
- [x] support raw `d/e` setup and raw output derivation in that path
- [x] wire the kernel-local `Ch` / `Maj` implementation to the new raw helper
- [x] try a narrower raw `Ch` gate path below the width-1 local-word vector
  layer `(tried, reverted)`
- [x] try returning packed side storage directly from the raw xor-base helper
  instead of `Vec<DdhHssLocalWord>` outputs `(tried, reverted)`
- [x] keep the old generic batch path available only until the new kernel path
  is benchmarked and validated
- [x] delete the generic hot-path call sites if this lands

Rules:

- [x] no widening of evaluator-visible state
- [x] no joined hidden values
- [x] keep the same cryptographic semantics and label derivation rules

Exit gate:

- [x] browser `round_core` shows a clear gain over Phase 2
- [x] native stays within the keep threshold

## Phase 4: Bool/Arithmetic Crossing Collapse

Goal:

- make the round-core kernel own the Boolean/arithmetic boundary instead of
  bouncing through standalone conversion helpers

Implementation:

- [x] identify every remaining Boolean->arithmetic and arithmetic->Boolean
  crossing inside `round_core`
- [x] add round-core profiling for `sigma0`, `Maj`, `state3`, `new_a_bits`, and
  `new_e_bits` to force the next cut to hit measured residual cost
- [ ] collapse crossings so they happen only where the algorithm truly changes
  domain
- [ ] keep `temp1`, `temp2`, `new_a`, and `new_e` arithmetic end-to-end once
  they enter the arithmetic side
- [ ] avoid reconstructing generic split words for values that only exist to
  feed the next arithmetic operation
- [x] try precomputing arithmetic schedule words and arithmetic round constants
  to reduce round-local crossings `(tried, reverted)`
- [x] try precomputing only arithmetic round constants for `temp1`
  `(tried, reverted)`
- [x] replace naive `new_a` / `new_e` arithmetic-to-Boolean conversion with a
  direct local-share bit decomposition `(tried, reverted insecure)`
- [x] replace that shortcut with a secure A2B gadget: decompose each
  arithmetic share separately, then recombine through the existing Boolean
  carry add `(landed)`
- [x] specialize that secure A2B gadget for left-only/right-only share inputs
  so it skips zero-sided split-word materialization and generic per-bit
  `local_word()` extraction `(landed)`
- [x] try a dual-word secure A2B kernel for `new_a` and `new_e` together
  `(tried, reverted)`
- [x] push the secure A2B carry recurrence below the generic width-1 helper
  boundary into a raw packed `ddh_hss` helper `(landed)`
- [x] try returning owned raw bit-slice outputs directly from that secure A2B
  helper instead of `Vec<DdhHssLocalWord>` outputs `(tried, reverted)`
- [x] try same-side local-bit construction for arithmetic-share decomposition
  instead of building and discarding a full local-word pair per bit
  `(tried, reverted)`
- [x] collapse arithmetic-share decomposition and secure carry A2B into one raw
  packed `ddh_hss` helper so the executor skips intermediate bit-slice buffers
  `(landed)`
- [ ] remove dead conversion helpers if the kernel no longer needs them

Exit gate:

- [x] browser total hidden eval improves against the Phase 0 baseline
- [x] browser hidden-eval probe total improves against the Phase 0 baseline

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

- [x] re-measure the browser gap after Phase 5
- [x] identify remaining real `session.evaluate` overhead that is not core
  hidden-eval work
- [x] try evaluator-session OT sender-point decompression caching
  `(tried, reverted)`
- [x] replace OT request-prep basepoint multiplication with
  `ED25519_BASEPOINT_TABLE * &receiver_scalar` while keeping the same wire
  payload semantics `(landed)`
- [x] precompute per-word sender-state curve invariants for trusted OT resolve
  so the garbler-side response path replaces one scalar multiply per bit with a
  point subtraction while keeping the same wire payload semantics `(landed)`
- [x] add a trusted internal OT reconstruct path that skips redundant
  bundle-level commitment / transcript rehashing while preserving per-branch
  payload verification `(landed)`
- [ ] reduce JS-visible object creation only where it removes real measured work
- [ ] prefer typed arrays / binary blobs over rich object graphs only if decode
  cost does not replace the deleted shaping cost
- [ ] keep hidden-run fast-path semantics unchanged

Rules:

- [ ] no transport-semantics changes
- [ ] no evaluator-capability widening
- [ ] no JSON-byte detour retry

Exit gate:

- [x] browser top-line improves materially without harming correctness or the
  security boundary

## Phase 7: Cleanup And Deletion

Goal:

- do not leave the codebase split between the old helper stack and the new
  kernel stack

Implementation:

- [x] delete the superseded timed trusted OT reconstruct wrapper after the
  trusted internal reconstruct path lands
- [x] delete the redundant untimed OT reconstruct wrapper and call the timed
  implementation directly for the public evaluator path
- [ ] delete remaining superseded round-core helper plumbing if the new kernel
  no longer needs it
- [x] remove dead scratch structs and unused helper conversions where the kept
  path no longer uses them
- moved the single-share local add helper behind `#[cfg(test)]` because it is
  now test-only
- moved scalar-modulus helper materialization behind `#[cfg(test)]` because it
  is only exercised by reduction tests now
- removed stale `allow(dead_code)` noise from live local-word and local-mul
  helpers that remain on the kept path
- deleted the thin word-based arithmetic wrapper helpers in the executor where
  the kept path now calls the pair-based implementation directly
- pruned zero-valued carry-substage benchmark reporting that only existed for
  reverted add-path experiments
- [ ] remove stale benchmark-only scaffolding created during failed phases
- [x] update docs and benchmark reports to describe the kept kernel only
- [ ] keep the implementation comprehensible enough that future security
  hardening still touches one real production path

Exit gate:

- [ ] no duplicate hot-path kernel remains

## Immediate Work Order

- [x] Phase 0 baseline lock
- [x] Phase 1 dedicated round-state layout
- [x] Phase 2 Boolean lane rewrite
- [x] stop and benchmark before Phase 3
- [x] Phase 3 raw gate path only if Phase 2 is at least flat on browser
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

- [x] one kept round-core kernel implementation
- [x] refreshed native benchmark report
- [x] refreshed browser benchmark report
- [x] updated optimization notes with kept vs reverted kernel phases
- [x] deleted superseded hot-path helper code that the compiler proved dead
