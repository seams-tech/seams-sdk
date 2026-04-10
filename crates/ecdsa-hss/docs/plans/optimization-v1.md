# Optimization V1

Date created: April 9, 2026
Last updated: April 9, 2026

## Purpose

This plan is the active optimization backlog for `ecdsa-hss`.

It converts the current benchmark evidence into a ranked list of refactors to
test one by one, with explicit keep/reject criteria.

The detailed benchmark ledger lives in
[optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md).

## Current Performance Picture

Native:

- derivation, bootstrap, and export are already sub-millisecond
- full sign path is roughly `~39-42 ms`
- the hotspot is the presign/triples roundtrip before `start_presign()`

WASM:

- derivation, bootstrap, and export are also sub-millisecond
- full non-export sign is roughly `~120 ms`
- profiled sign runs show:
  - parse input: `~0 ms`
  - prepare session: `~1 ms`
  - presign roundtrip: `~118-120 ms`
  - client share compute: `~0 ms`
  - finalize signature: `~1 ms`

So the optimization target is now clear:

- not JS decode/encode
- not export/bootstrap
- not final signature assembly
- almost entirely the upstream triples/presign path

## Constraints

- keep `wasm/eth_signer` on `opt-level = "z"`
- preserve the one-key invariant
- preserve the export/signing policy boundary
- prefer low-risk runtime-path reductions over protocol reshaping
- reject any optimization that does not move the measured sign hotspot

## Acceptance Rule

An attempt is accepted only if all of these are true:

1. it preserves the current specs and one-key invariant
2. it does not weaken the export/signing boundary
3. it passes:
   - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
4. it improves at least one of the real hotspot buckets without materially
   regressing the others:
   - native:
     - `sign_bridge_full`
     - `presign_protocol_roundtrip`
     - `presign_before_start`
   - wasm:
     - `sign_non_export_wasm`
     - `sign_presign_roundtrip_wasm`

## Benchmark Commands

Native focused sign benchmarks:

```bash
cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'
```

WASM benchmark and sign-stage split:

```bash
pnpm benchmark:ecdsa-hss:wasm
```

## Ranked Refactor Candidates

### 1. Upstream triples preallocation for `N=2`

Why it ranks first:

- `do_generation_many::<2>` is the dominant hotspot
- the code builds many small `Vec`s in lockstep for exactly two triples
- this is the lowest-risk backend-level reduction that matches the measured
  hotspot

Expected change shape:

- use `Vec::with_capacity(N)` consistently in the `N=2` path
- reduce repeated small reallocations for:
  - commitments
  - randomizers
  - polynomials
  - proof nonce vectors
  - per-participant private share bundles

### 2. Reduce clone pressure in the triples stage

Why it ranks second:

- `do_generation_many::<2>` repeatedly clones commitment/polynomial structures
- `start_presign()` also clones the first two triples into `PresignArguments`
- clone-heavy paths are a plausible wasm penalty even when native impact is
  smaller

Expected change shape:

- avoid unnecessary `clone()` calls on the hot path
- move or borrow where the protocol shape allows it
- keep serialization and proof behavior unchanged

### 3. Fixed-size collection cleanup for the 2-party seam

Why it ranks third:

- the current backend seam is fixed to `{1, 2}`
- some paths still use general `Vec` / `ParticipantMap` machinery where a
  tighter 2-party shape may remove overhead
- this can help both native and wasm if done without changing protocol
  semantics

Expected change shape:

- specialize internal handling around the fixed `{1, 2}` case where safe
- reduce general-purpose collection churn in the presign driver or triples
  stage

### 4. Reduce transcript/proof setup churn inside triples generation

Why it ranks fourth:

- triples generation repeatedly forks transcripts and builds nonce/proof
  vectors
- wasm may amplify that allocation/setup cost
- this is somewhat riskier because it touches proof/transcript plumbing

Expected change shape:

- keep the transcript semantics exactly the same
- reduce temporary allocation churn around nonce/proof bundle creation

### 5. Deeper protocol-driver restructuring inside upstream triples

Why it ranks last:

- this is the highest-risk option
- previous deeper driver rewrites mostly regressed
- it should be attempted only if the lower-risk candidates stall

Expected change shape:

- only after concrete evidence that the remaining hotspot is still dominated by
  avoidable driver overhead instead of unavoidable protocol work

## Todo List

### Baseline Freeze

- [x] rerun and record the current native focused sign benchmark before the
      next backend-level attempt
- [x] rerun and record the current wasm sign benchmark before the next
      backend-level attempt

### Candidate 1: Upstream triples preallocation for `N=2`

- [x] inspect `do_generation_many::<2>` and list the hot small-`Vec`
      allocation sites to target first
- [x] patch the first preallocation cleanup in the upstream triples stage
- [x] rerun:
  - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
  - native focused sign benchmark
  - wasm benchmark
- [x] accept or reject the change in
      [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)

Current result:

- rejected and reverted
- obvious `Vec::with_capacity(N)` tuning in the upstream triples stage
  regressed both native and wasm sign latency

### Candidate 2: Reduce clone pressure in triples/presign setup

- [x] inspect clone-heavy paths in:
  - upstream `do_generation_many::<2>`
  - `start_presign()` in
    [threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
- [x] patch the smallest low-risk clone reduction
- [x] rerun:
  - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
  - native focused sign benchmark
  - wasm benchmark
- [x] accept or reject the change in
      [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)

Current result:

- rejected and reverted
- the first low-risk clone reduction moved native full-sign slightly in the
  right direction, but the presign hotspot stayed near noise and the wasm sign
  path stayed effectively flat
- clone-only cleanup in the upstream triples path does not yet look like a
  meaningful wasm win by itself

### Candidate 3: Fixed-size collection cleanup for the `{1, 2}` seam

- [x] identify one concrete internal collection path where the fixed 2-party
      scope can remove general-purpose overhead without changing semantics
- [x] implement the smallest safe fixed-size cleanup
- [x] rerun:
  - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
  - native focused sign benchmark
  - wasm benchmark
- [x] accept or reject the change in
      [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)

Current result:

- rejected and reverted
- the first fixed-size 2-party cleanup targeted repeated
  `recv_from_others(...)` gathering in the upstream presign/triples path
- it regressed both native and wasm sign latency, so the next candidate should
  move to transcript/proof setup churn rather than more helper-level 2-party
  specialization

### Candidate 4: Transcript/proof setup churn

- [x] inspect transcript fork and proof-nonce setup inside the triples stage
- [x] attempt one low-risk allocation/setup reduction that keeps transcript
      semantics unchanged
- [x] rerun:
  - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
  - native focused sign benchmark
  - wasm benchmark
- [x] accept or reject the change in
      [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)

Current result:

- rejected and reverted
- pre-forking per-label participant transcripts in the upstream triples stage
  did not produce a meaningful native hotspot improvement and regressed wasm
  sign latency
- there is no evidence yet that transcript setup churn is the real remaining
  bottleneck

### Candidate 5: Deeper driver restructuring

- [x] only attempt this if Candidates 1-4 fail to move the measured hotspot
- [x] write down the exact remaining hotspot evidence before changing driver
      structure
- [x] patch one deeper driver-level refactor
- [x] rerun:
  - `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
  - native focused sign benchmark
  - wasm benchmark
- [x] accept or reject the change in
      [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)

Current result:

- rejected and reverted
- the first deeper driver refactor added an owned-message path to move outgoing
  protocol payloads directly between the two same-process sessions
- it helped one native presign sub-bucket but did not improve full native sign
  and significantly regressed the wasm sign path
- there is no accepted Candidate 5 win yet, and the remaining options are now
  high-risk relative to the current `~120 ms` wasm baseline

## Stop Conditions

Stop the pass if any of these become true:

- wasm sign latency falls into an acceptable band for the product target
- repeated backend-level attempts are flat or regressive
- the next available candidate would require protocol-risky reshaping rather
  than runtime-path cleanup

## Current Recommendation

Proceed in this order:

1. upstream triples preallocation for `N=2`
2. clone reduction in triples/presign setup
3. fixed-size `{1, 2}` collection cleanup
4. transcript/proof setup cleanup
5. only then consider deeper protocol-driver restructuring
