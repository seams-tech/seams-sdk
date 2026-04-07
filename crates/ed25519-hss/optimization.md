# Optimization Notes

This file is the optimization-focused entrypoint for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).
Historical optimization plans live in
[docs/plans/optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v3.md).

## Current Hot Path

The dominant runtime cost is still the hidden-eval executor, especially:

- `message_schedule`
- `round_core`
- `output_projection`

The most expensive stage remains `round_core`.

Latest local benchmark snapshot:

- hidden eval prepare:
  `108.87ms`
- hidden eval total:
  `305.66ms` mean, `308.59ms` median, `310.17ms` p95
- stage means:
  - input sharing:
    `2.14ms`
  - add stage:
    `2.95ms`
  - message schedule:
    `46.70ms`
  - round core:
    `160.14ms`
  - output projector:
    `52.25ms`
- CPU executor:
  `2.040ms` mean, `2.041ms` median, `2.057ms` p95

## Current Bundle Sizes

Latest browser HSS artifacts:

- wasm:
  `262,555` bytes
- JS glue:
  `14,028` bytes
- worker JS:
  `21,744` bytes

These sizes are now stable enough that future protocol or runtime changes
should be judged partly on bundle-size impact, not just runtime speed.

## Durable Optimization Wins

The main durable gains that survived the refactor are:

- dedicated browser HSS wasm package instead of a broad mixed runtime bundle
- staged production seam without duplicate legacy runtime paths
- split/local arithmetic execution through the production hot path
- dedicated kernel-local paths for the SHA-512 boolean-heavy work
- removing repeated conversions and joined-value materialization from the hot
  execution path

The key result is that the hardened staged boundary landed without meaningful
bundle-size growth and without a material hidden-eval regression.

## Constant-Time Constraints

Performance changes are constrained by the crypto boundary.

Optimization work must not:

- add secret-dependent branches
- add secret-dependent division or modulo
- reconstruct joined hidden values in production hot paths
- reopen evaluator-visible clear-input shortcuts
- introduce target-specific production algorithms that diverge in behavior

Recent constant-time cleanup:

- the round-core local bit-pair arithmetic split no longer branches on a
  secret `cross` bit
- the same path no longer reduces with `%`; it now uses masking and wrapping
  arithmetic

## Accepted Retained State

The staged server-owned executor now keeps one explicit minimal retained-state
exception after add-stage:

- `projector_inputs`

That retained state is accepted because:

- raw relayer roots are dropped after add-stage
- `output_projection` still needs server-owned projector prerequisites later
- recomputing those prerequisites from scratch would violate the intended
  boundary model

This is an optimization and architecture tradeoff, not a client-visible
shortcut.

## What To Avoid

These classes of work have repeatedly been bad trades and should stay dead:

- helper-level rewrites that do not change the real hot-kernel shape
- native-only fast paths
- browser-only serialization detours that leave the kernel untouched
- evaluator-visible shortcuts that reconstruct hidden intermediate values
- duplicate legacy runtime paths kept “just in case”

## Next Optimization Directions

If performance work resumes, the highest-value directions are:

- denser executor-local storage for the split/local staged continuations
- fused local kernels around `round_core`
- better amortization of local Beaver/triple-adjacent material
- constant-time review of any new low-level arithmetic helper before it lands

The detailed phased history remains in
[docs/plans/optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v3.md).
