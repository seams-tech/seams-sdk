# Threshold Ed25519 Option A Active-Path Reference

Date updated: April 1, 2026

## Scope

This document is the current performance and verification reference for the
active single-key threshold-ed25519 path.

It replaces the deleted dual-key microbenchmark story. The active path is:

- sessionless registration HSS for threshold-ed25519 bootstrap
- threshold-ed25519 session mint plus HSS share reconstruction
- signer worker input restricted to `xClientBaseB64u`
- controlled `near-ed25519-seed-v1` export bound to the same canonical public
  key

## Current Performance Reference

The kept secure performance checkpoint for the active hidden-eval step is:

- native hidden eval total: about `0.305 s`
- browser hidden eval total: about `0.415 s`

Those numbers are the current active-path reference for the `d -> a` hidden
conversion and share projection step used by Option A HSS.

Interpretation:

- this is acceptable for registration, unlock, and signing-session creation
- it is not intended to run on every signature
- once a threshold session exists, ordinary signing reuses the session instead
  of rerunning the full hidden conversion

## Current Verification Reference

The kept verification surface for the active Option A path is:

- [thresholdEd25519.optionAActivePath.script.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.optionAActivePath.script.unit.test.ts)
  - active signing/share reconstruction
  - controlled seed export
  - canonical public-key binding
  - fail-closed export behavior
  - route/session segregation checks
- [threshold-ed25519.scope.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/threshold-ed25519.scope.test.ts)
  - threshold-ed25519 route auth/scope behavior
  - active session/bootstrap gating assumptions
- [thresholdEd25519.\*.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e)
  - route-driven threshold-ed25519 session/signing behavior on the active
    single-key path

## What This Is Not

This document is not a multi-wallet capacity benchmark.

It does not yet answer:

- `50/100/250/500` wallet throughput
- cross-node coordinator saturation
- relayer-cosigner topology capacity under sustained traffic

That work remains in the actor-based load-testing plan at
[load-testing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/load-testing.md).

## Current Operator Reading

For threshold-ed25519 today:

- use this document for the active Option A hidden-eval checkpoint and the
  current verification keep-gates
- use
  [stateless-shared-root-ed25519.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/stateless-shared-root-ed25519.md)
  for the architecture and runtime interpretation
- use
  [auth-gating-routes.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/auth-gating-routes.md)
  for the live route/auth split
- use [load-testing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/load-testing.md)
  for the future multi-wallet capacity plan
