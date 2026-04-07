# Optimization v3 History

Date updated: April 7, 2026

This note is a shortened historical record of the `ed25519-hss` optimization
campaign that produced the current kept hidden-eval kernel.

It is not the current optimization entrypoint. For the current hot path,
benchmarks, and active constraints, see
[optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md).

## Purpose

The purpose of the v3 optimization effort was to improve the real production
hidden-eval path without weakening the hardened split/local boundary.

The main target was the `round_core` kernel, with secondary work on browser OT
and session-shaping overhead once the kernel was in a good place.

## Non-Goals

The v3 work explicitly avoided:

- reopening joined hidden-value execution in production
- target-specific production algorithms
- transport shortcuts that widened evaluator-visible state
- keeping duplicate legacy paths around after a new path landed
- performance hacks that only improved benchmark-only code

## Main Constraint

The durable lesson from this campaign was simple:

- the biggest wins came from changing kernel shape
- helper cleanup alone was not enough
- any optimization that crossed the crypto boundary unsafely had to be
  reverted, even when the benchmark numbers looked excellent

## Historical Before / After Benchmarks

### Early Hardened Checkpoint vs Kept v3 Result

This is the broadest before/after view of the campaign:

- native total hidden eval:
  about `0.595s -> 0.266s`
- browser total hidden eval:
  about `0.800s -> 0.364s`

### Secure Pre-v3 Checkpoint vs Kept v3 Result

This is the more relevant kernel-era comparison:

- native total hidden eval:
  about `0.320s -> 0.266s`
- native `round_core`:
  about `165.0ms -> 137.7ms`
- browser total hidden eval:
  about `0.466s -> 0.364s`
- browser hidden-eval probe total:
  about `0.363s -> 0.300s`

### Old Fast Watermark vs Final Secure Result

This is the useful “did we regain the old speed without the old boundary
shape?” comparison:

- native total hidden eval:
  about `0.270s -> 0.266s`
- browser total hidden eval:
  about `0.380s -> 0.364s`

So the lasting performance story was:

- the secure kept path ended up roughly back in the band of the old fast
  watermark
- the huge early hardened regression was mostly recovered
- the recovery came from kernel and runtime-shape work, not from reviving
  unsafe shortcuts

## What Landed

These classes of work produced durable wins and survived:

- dedicated browser HSS wasm package instead of a broad mixed runtime bundle
- split/local arithmetic execution through the production hot path
- dedicated kernel-local storage and transforms for the SHA-512 boolean-heavy
  lane
- raw packed gate helpers for `Ch` and `Maj`
- secure A2B improvements for `new_a` and `new_e`
- garbler-side OT/open/join reductions that did not widen evaluator-visible
  state

The overall result was:

- better browser latency
- better native latency
- much smaller browser HSS artifacts
- no reopening of the old unsafe boundary

## What Failed

These classes of work repeatedly lost and should stay dead:

- helper-level `Ch` / `Maj` rewrites at the old abstraction boundary
- native-only alternate kernels
- browser payload-shaping detours that did not improve the actual kernel
- returning owned raw side-storage where wasm ended up doing more work overall
- evaluator-visible shortcuts that reconstructed hidden intermediate values

The biggest rejected temptation was the insecure direct arithmetic-to-Boolean
shortcut for `new_a` / `new_e`:

- it benchmarked extremely well
- it reconstructed the combined arithmetic word
- it re-shared bits in a degenerate way
- it was therefore reverted and should not be revived

That failed experiment is still worth remembering because it is the clearest
example of a “fast but invalid” direction.

## Kernel Lessons

The durable kernel lessons from v3 were:

- keep one real production path
- keep the boolean-heavy round-core work below generic helper composition
- move crossings only when the algorithm truly changes domain
- prefer kernel-local contiguous storage over tiny helper-owned objects
- delete old helper plumbing once the new hot path lands

The end state after the campaign was:

- `round_core` stayed the dominant cost center
- the production path was materially faster than the earlier hardened
  checkpoint
- the remaining future wins were more likely to come from denser executor-local
  storage and fused local kernels than from more helper churn

## Browser Lessons

The browser-specific lessons were:

- browser size and latency both matter
- the runtime/package split was one of the highest-leverage changes
- OT/open/join cleanup mattered, but only after the kernel shape was already
  under control
- many wasm regressions came from extra allocations or object shaping, even
  when native looked fine

## Keep / Reject Policy

The v3 keep policy that proved useful was:

- keep only work that improved the real hidden-eval path
- reject work that widened the boundary or made the code harder to reason about
- reject work that only won on one target unless the other target stayed within
  a small regression budget

That policy should continue to apply to future optimization work.

## What Not To Retry

The following directions should not be retried without a materially new idea:

- helper-level `Ch` / `Maj` rewrites at the old abstraction layer
- JSON-byte browser payload shaping as a performance strategy
- native-only production kernels
- duplicate legacy runtime paths “for fallback”
- insecure arithmetic-to-Boolean shortcuts that reconstruct joined values

## Remaining Useful Follow-On Ideas

If optimization work resumes, the most promising directions are still:

- denser executor-local storage
- fused local kernels around `round_core`
- better amortization of local Beaver/triple-adjacent material
- careful constant-time review of any new low-level arithmetic helper

Those future directions are now tracked in
[optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md).
