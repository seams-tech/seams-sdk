# Threshold ECDSA Current Checklist

Last reviewed: 2026-06-08

This checklist replaces the May 2026 issue plan. It tracks only current runtime-safety, test-coverage, and dependency-drift work.

## Implemented

- [x] Preserve MPC authorization on `pool_empty`.
  - `ecdsaSignInit` now reads the MPC session before presignature reservation and claims/deletes it only after a presignature is reserved.
  - `pool_empty` leaves the same `mpcSessionId` reusable until expiry.
  - A lost MPC claim after presignature reservation discards the reserved presignature and returns an authorization failure.

- [x] Tighten `pool_empty` and claim-race coverage.
  - The high-level retry test no longer accepts `mpcSessionId expired or invalid`.
  - Focused server tests cover empty-pool preservation, successful retry after refill, and reserved-presignature discard when the MPC claim loses a race.

- [x] Add upstream `threshold-signatures` participant anti-drift coverage.
  - Pin that `Participant::from(1)` and `Participant::from(2)` still produce the coordinates assumed by the 2P mapping.
  - Pin that the `{1, 2}` Lagrange coefficients used by the backend remain `{client=3, relayer=-2}` in signer-core.

## Hardening

- [x] Add structured security logs for terminal server-side ECDSA presign failures.
  - Logs now cover malformed presign messages, protocol rejections, replay or missing burned sessions, and scope mismatches.
  - Log fields include wallet session user, relayer key, RP ID, presign pool key, signing-root metadata when present, and request origin when available.
  - Client-side `bigR` mismatch remains covered by client reuse-prevention tests.

- [x] Add replay-after-burn regression coverage.
  - A malformed `presign/step` burns the session.
  - A second `presign/step` for the same `presignSessionId` returns a terminal failure and emits the replay/missing-session security event.

## Already Covered

- [x] Secure ECDSA capability IDs.
  - Threshold service session IDs now use `secureRandomIdFragment()`, backed by WebCrypto `getRandomValues`.
  - The service fails closed when secure randomness is unavailable.
  - `ThresholdSigningService.ts` no longer contains `Math.random()` threshold capability ID fallback code.

- [x] Core malicious-client burn behavior.
  - Scope mismatches delete owned presign sessions and evict live WASM state.
  - Malformed incoming presign messages burn the server presign session.
  - Client-side `bigR` mismatch prevents local presignature reuse.
  - Presignature reservation and consume paths are single-use.

- [x] Rust/WASM additive-share mapping path.
  - Production client and server mapping calls use Rust/WASM helpers.
  - The runtime TypeScript BigInt mapper is gone from production paths.
  - Verus coverage exists for the local `map_additive_share_to_threshold_signatures_share_2p` formula under the current fixed `{client=1, relayer=2}` model.

## Out Of Active Backlog

- [ ] Full threshold ECDSA formal verification track.
  - Keep this as a separate funded audit/proof project.
  - The old theorem IDs in the May plan are stale; `FV-SIGNER-CORE-006` through `FV-SIGNER-CORE-008` now refer to Ed25519 work.
  - Prefer executable anti-drift and protocol-boundary regression tests until a formal proof deliverable is explicitly scheduled.
