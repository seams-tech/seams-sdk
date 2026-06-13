# `threshold-prf` `t-of-N` Refactor Preparation Plan

Date created: June 12, 2026
Last updated: June 13, 2026

## Current Status

The API-neutral preparation work is complete. The crate now exposes the active
configurable threshold protocol through `threshold_prf`, including generic
policy validation, split/reconstruct, partial-combine, verified-combine,
fixtures, WASM exports, benchmarks, and formal-verification models.

The old fixed-pair threshold-prf public surface, vectors, local benchmark
baselines, WASM exports, and FV anti-drift paths have been deleted. Remaining
`V1` names in Router/A/B and server SDK code must be treated as serialized
Router/A/B or persistence-boundary version names unless the Phase 7 audit marks
them for rename.

## Scope

This plan tracks work that prepared
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf)
for configurable `t-of-N` use without changing downstream public request shapes
prematurely. Public protocol/API migration details now live in
[threshold-prf-t-of-n-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/threshold-prf-t-of-n-spec.md).

## Completed Phases

### Phase 1: Localize Fixed Assumptions

- [x] Document the former fixed `2-of-3` policy before refactoring.
- [x] Add focused tests around subset size, duplicate IDs, and share-ID domain.
- [x] Route fixed-pair validation through narrow internal helpers.
- [x] Isolate interpolation math behind a generic Lagrange-at-zero helper.
- [x] Add private `3-of-5`, `5-of-7`, `1-of-N`, and `N-of-N` interpolation
      coverage before exposing the API.

### Phase 2: Add Public Canonical `t-of-N` API

- [x] Add `ThresholdPolicy`, `ThresholdShareId`, and
      `ValidatedThresholdSet`.
- [x] Add `SigningRootShare`, `SigningRootShareWire`, partial wires,
      commitments, and proof-bundle wires.
- [x] Add public split/reconstruct APIs with `2-of-3`, `3-of-5`, and invalid
      policy tests.
- [x] Add direct evaluation, partial evaluation, verified combine, and DLEQ
      proof verification APIs.
- [x] Add committed fixture corpora and anti-drift tests.

### Phase 3: Add Boundaries And Downstream Prep

- [x] Expose WASM HSS bindings for flattened policy-shaped share wires.
- [x] Expose WASM distributed-combine bindings for partial wires and proof
      bundles.
- [x] Add `just threshold-prf-wasm-test` and `just threshold-prf-wasm-smoke`.
- [x] Add server SDK threshold-prf HSS wrapper functions.
- [x] Add hosted and self-hosted server SDK signing-root resolver boundaries.
- [x] Move active server SDK ECDSA and Ed25519 HSS callers to policy-shaped
      resolver inputs.
- [x] Migrate Router/A/B Candidate A backend code to `threshold_prf` with
      the current `2-of-3` policy and wire widths.
- [x] Refresh Router/A/B contract, payload, and wire fixtures after the backend
      migration.

### Phase 4: Measure And Verify

- [x] Record native, local WASM, and production WASM size baselines before the
      canonical API cleanup.
- [x] Extend native Criterion and local smoke timing harnesses with `2-of-3`
      and `3-of-5` coverage.
- [x] Extend the local Node/V8 WASM benchmark harness with Option A and
      DLEQ proof/verify/combine paths.
- [x] Add a repeatable production WASM bundle-size command for before/after
      comparisons. Bundle size remains informational because this crate runs
      server-side.
- [x] Extend FV prep with a threshold-policy/subset model and anti-drift
      parity for committed fixtures.

### Phase 5: Remove Obsolete Fixed-Pair Threshold-Prf Surfaces

- [x] Remove direct fixed-pair imports from active Router/A/B benchmark, library,
      and test code.
- [x] Remove fixed-pair committed-vector verification from the `threshold-prf`
      vector test target.
- [x] Remove fixed-pair formal-verification anti-drift paths.
- [x] Remove server SDK fixed-pair sealed-share resolver config, public exports,
      and resolver-only tests.
- [x] Remove server SDK and Cloudflare unit-test dependencies on the deleted
      fixed-pair fixture corpus.
- [x] Move the ECDSA presign benchmark harness to the fixture and
      policy-shaped resolver.
- [x] Remove native and local WASM fixed-pair benchmark baselines, exports, and
      guard labels while retaining `2-of-3` and `3-of-5` benchmark coverage.
- [x] Delete fixed-pair fixture generators and fixture corpora.
- [x] Delete obsolete fixed-pair Rust APIs, helper structs, protocol tests, and
      the old FV abstract model.
- [x] Rename the Router/A/B Candidate A threshold-prf suite id to the active suite id and refresh downstream fixtures.
- [x] Replace stale implementation, FV, spec, benchmark, and sealing docs with
      current records.

## Validation

- [x] `cargo test --manifest-path crates/threshold-prf/Cargo.toml`
- [x] `cargo test --manifest-path crates/router-ab-core/Cargo.toml`
- [x] `pnpm -C packages/sdk-server-ts type-check`
- [x] focused server SDK resolver/WASM Playwright script tests
- [x] `just threshold-prf-fv`
- [x] `just threshold-prf-wasm-smoke`
- [x] `git diff --check`

## Remaining Work

1. Defer deployed Worker benchmarks until live Cloudflare testing resumes.
2. Complete the Phase 7 naming audit in
   [threshold-prf-t-of-n-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/threshold-prf-t-of-n-spec.md):
   retain `V1` suffixes only for active serialized Router/A/B request,
   payload, route, purpose-label, and persistence boundaries.
3. Plan any downstream Router/A/B expansion beyond the current `2-of-3` policy
   as a separate protocol-shape change.
