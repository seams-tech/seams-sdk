# Threshold ECDSA Issue Fix Plan

This plan covers the threshold ECDSA issues identified in the May 2026 review:

- P1-A: ECDSA bearer session IDs have a weak randomness fallback.
- P1-B: `pool_empty` consumes the one-time ECDSA MPC authorization before retry.
- P1-C: malicious-client presign attempts need explicit burn, alerting, and blast-radius controls.
- P2: Additive-to-threshold share mapping depends on pinned `near/threshold-signatures` internals.
- P3: Cait-Sith integration needs a formal verification track for our Rust/WASM glue and lifecycle assumptions.

## Scope

The fixes should be implemented as direct behavior changes. No compatibility layer is needed for old session IDs, old retry behavior, or alternate participant layouts.

The target participant set for this implementation remains fixed at `{client=1, relayer=2}` until a later protocol version introduces a new typed participant set and a new proof target.

Fix P1-A and P1-B first. Secure bearer session IDs and correct one-time MPC authorization handling are prerequisites for relying on the signing lifecycle during malicious-client hardening.

Formal verification work should focus on our implementation boundary: Rust/WASM share mapping, threshold ECDSA adapter algebra, HSS integration, and the signing lifecycle model. Treat upstream Cait-Sith/`near/threshold-signatures` malicious-security guarantees as assumptions unless a separate upstream proof project is started.

## P1-A: Secure ECDSA Capability IDs

### Problem

`ThresholdSigningService` creates ECDSA `mpcSessionId` and `signingSessionId` values with `globalThis.crypto.randomUUID()` when available, then falls back to `Date.now()` plus `Math.random()`.

Those IDs are bearer capabilities for:

- `/threshold-ecdsa/sign/init`
- `/threshold-ecdsa/sign/finalize`

Weak fallback randomness makes those capabilities guessable in runtimes where Web Crypto is unavailable or incorrectly shimmed.

### Code To Change

- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - `createThresholdEcdsaMpcSessionId`
  - `createThresholdEcdsaSigningSessionId`
  - any adjacent threshold signing capability ID helper with the same fallback
- Add a shared helper near the threshold service, for example:
  - `server/src/core/ThresholdService/secureCapabilityId.ts`

### Implementation Steps

1. Add `createSecureCapabilityId(args)` with required fields:
   - `prefix: string`
   - `byteLength: number`

2. Generate opaque bytes with secure randomness only:
   - Prefer `globalThis.crypto.getRandomValues` when present.
   - Use Node `randomBytes` in Node runtimes.
   - Throw a typed `unsupported` error when no secure RNG exists.

3. Encode IDs as `prefix + base64url(randomBytes)`.

4. Replace ECDSA ID generation:
   - `ecdsa-mpc-...`
   - `ecdsa-sign-...`

5. Replace matching threshold capability IDs that still use `Math.random()` in the same service. This keeps the threshold service on one capability-ID policy.

6. Remove all `Math.random()` fallback code from threshold signing capability generation.

### Acceptance Criteria

- ECDSA `mpcSessionId` and `signingSessionId` are generated from secure random bytes in every supported runtime.
- The service fails closed when secure randomness is unavailable.
- `rg -n "Math.random\\(" server/src/core/ThresholdService/ThresholdSigningService.ts` finds no threshold signing capability ID fallback.
- Generated IDs keep their existing public prefixes.

### Tests

Add focused unit tests:

- secure helper returns the requested prefix and expected entropy length.
- helper uses `globalThis.crypto.getRandomValues` in Web Crypto runtimes.
- helper uses Node `randomBytes` when Web Crypto is unavailable in Node.
- helper throws when both secure RNG sources are unavailable.
- ECDSA authorize and sign-init paths still return valid `mpcSessionId` and `signingSessionId` prefixes.

## P1-B: Preserve MPC Authorization On `pool_empty`

### Problem

`ecdsaSignInit` calls `takeMpcSession(mpcSessionId)` before reserving a relayer presignature. When the relayer pool is empty, the server returns `pool_empty` after deleting the one-time MPC session. The client then refills presigning and retries `sign/init` with the same `mpcSessionId`, which can only fail after the server has consumed the authorization.

The current high-level test allows this failure by accepting `mpcSessionId expired or invalid` in the `pool_empty` retry case.

### Code To Change

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
  - `ecdsaSignInit`
- `server/src/core/ThresholdService/stores/SessionStore.ts`
  - in-memory, Upstash, Redis TCP, Postgres session store implementations
- `server/src/router/cloudflare/durableObjects/thresholdStore.ts`
- `server/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
- `client/src/core/signingEngine/threshold/ecdsa/presignPool.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`

### Implementation Steps

1. Extend the threshold session store API with an atomic read-and-claim model for MPC sessions:
   - `readMpcSession(id)` returns `{ record, version }`.
   - `takeMpcSessionVersion(id, version)` deletes and returns the same record only when the stored version still matches.

2. Implement the new API for every backing store:
   - In-memory: keep a monotonically increasing version or stable stored JSON fingerprint.
   - Redis/Upstash: use a Lua or REST script that compares the stored payload/version and deletes atomically.
   - Postgres: use a conditional `DELETE ... WHERE session_id = $id AND version = $version RETURNING ...`.
   - Durable Objects: perform compare-and-delete inside the DO transaction.

3. Rewrite `ecdsaSignInit` flow:
   - Parse request.
   - Read the MPC session without consuming it.
   - Validate expiry, relayer key, digest, participant IDs, and integrated key scope.
   - Reserve the requested presignature or the next available presignature.
   - Return `pool_empty` without mutating the MPC session when reservation fails.
   - Claim the MPC session with `takeMpcSessionVersion`.
   - If claim fails, discard the reserved presignature and return a race/unauthorized result.
   - Create the signing session and return relayer round 1.

4. Keep presignature reservation single-use:
   - On any failure after reservation, call `discard`.
   - On successful finalize, keep the existing `consume` behavior.

5. Keep the existing client retry shape:
   - Refill presignatures on `pool_empty`.
   - Retry `sign/init` with the same `mpcSessionId`.

6. Tighten the high-level retry test:
   - Remove acceptance of `mpcSessionId expired or invalid`.
   - Require the retry to complete signing successfully after a forced `pool_empty`.

### Acceptance Criteria

- A `pool_empty` response leaves the MPC session usable until expiry.
- Retrying `sign/init` with the same `mpcSessionId` succeeds after refill.
- Two concurrent `sign/init` calls using the same `mpcSessionId` cannot both create signing sessions.
- A reserved presignature is discarded when the MPC session claim loses a race.
- Tests fail if the client retry path accepts `mpcSessionId expired or invalid`.

### Tests

Add or update targeted tests:

- server unit: empty pool returns `pool_empty` and preserves the MPC session.
- server unit: after a forced `pool_empty`, inserting a presignature lets the same `mpcSessionId` succeed.
- store tests for read-and-claim semantics across in-memory, Redis/Upstash, Postgres, and Durable Object stores.
- race test: two `sign/init` calls with the same `mpcSessionId`; exactly one succeeds.
- client high-level test: forced `pool_empty` path refills and completes signing.

## P1-C: Malicious Client Presign Hardening

### Problem

The client is an MPC participant and must be treated as malicious. A client can send malformed presign protocol messages, abort after seeing server responses, retry handshakes, and attempt to force partial protocol-state reuse. A cryptographic protocol bug in this area should be scoped to the client's own threshold key, and the service should still burn failed presign state aggressively.

### Security Invariant

Per-user blast radius is a hard security property:

```text
No request path may allow user A to run ECDSA MPC against user B's relayer share.
```

This invariant must hold for presign init, presign step, sign init, sign finalize, owner forwarding, Durable Object routing, and every persistence backend.

### Code To Review

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
  - `ecdsaPresignInit`
  - `ecdsaPresignStep`
  - `ecdsaSignInit`
  - `ecdsaSignFinalize`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`
- `server/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
- `server/src/router/cloudflare/durableObjects/thresholdStore.ts`
- `client/src/core/signingEngine/threshold/ecdsa/presignPool.ts`
- `crates/signer-core/src/threshold_ecdsa.rs`
- `wasm/eth_signer/src/threshold.rs`

### Implementation Steps

1. Add an explicit malicious-client review pass for:
   - malformed presign messages
   - repeated aborts
   - retry behavior
   - session cleanup
   - no reuse of failed triple or presign state

2. Define terminal failure handling for presign sessions:
   - malformed incoming protocol message burns the presign session
   - protocol assertion failure burns the presign session
   - `bigR` mismatch burns both local and server-side presign material
   - expired presign session is deleted before any further protocol step
   - owner-forwarding failure cannot leave a resumable local session

3. Ensure failed presign sessions cannot be resumed:
   - evict the live WASM session from memory
   - delete or tombstone the persisted presign session record
   - refuse subsequent `presign/step` calls for the same `presignSessionId`
   - do not persist a relayer presignature after any terminal error

4. Ensure every new presign attempt starts with fresh protocol state:
   - construct a new `ThresholdEcdsaPresignSession`
   - call fresh `generate_triple_many::<2>`
   - never reuse triples, `k`, `sigma`, `bigR`, entropy, or outgoing protocol messages after an error

5. Add rate-limiting and alerting for presign failures. Key counters by:
   - `walletSessionUserId`
   - `ecdsaThresholdKeyId`
   - client IP or device identifier
   - `relayerKeyId`

6. Emit structured security events for:
   - malformed presign message
   - protocol assertion failure
   - repeated aborts
   - `bigR` mismatch
   - presign session replay after burn
   - cross-user or cross-key scope mismatch

7. Keep scope checks at every boundary:
   - threshold session token wallet/RP/signing-root scope
   - `ecdsaThresholdKeyId`
   - participant IDs
   - persisted client verifying share
   - persisted relayer backend input
   - persisted threshold public key
   - `relayerKeyId`

### Acceptance Criteria

- A malformed presign message burns the server presign session.
- A repeated `presign/step` call against a burned session fails with a terminal error.
- No failed presign path persists a relayer presignature.
- New presign handshakes always use fresh triple and presign state.
- Presign failure counters and alerts are emitted with wallet, key, client, and relayer dimensions.
- Cross-user and cross-key attempts cannot reach `ThresholdEcdsaPresignSession::message`.

### Tests

Add targeted regression tests:

- invalid protocol message burns the server presign session.
- replaying a burned `presignSessionId` fails.
- repeated aborts trigger rate-limit or alert instrumentation.
- `bigR` mismatch clears local client presign material and burns server-side presign material.
- user A cannot start or step ECDSA MPC against user B's `ecdsaThresholdKeyId`.
- user A cannot use a valid `presignSessionId` under a different wallet session token.

## P2: Pin And Prove Additive Share Mapping

### Problem

Our HSS flow derives additive shares:

```text
x = x_client + x_relayer mod n
```

`near/threshold-signatures` expects Shamir-style shares and linearizes each party's share with a Lagrange coefficient at zero. For the pinned implementation and participant IDs `{1,2}`, upstream maps participant IDs to scalar coordinates `{2,3}`. The corresponding coefficients are:

```text
lambda_client = 3
lambda_relayer = -2
```

Our mapper feeds:

```text
backend_share_i = additive_share_i * inverse(lambda_i)
```

This makes upstream linearization recover the original additive shares. The math is correct for the pinned upstream semantics. The risk is implementation drift if the `threshold-signatures` participant-coordinate convention changes.

### Code To Change

- `crates/signer-core/src/secp256k1.rs`
- `shared/src/threshold/secp256k1Ecdsa2pShareMapping.ts`
- `crates/signer-core/formal-verification/verus/src/secp256k1/mapping.rs`
- `formal-verification/docs/proof-inventory.md`
- `crates/signer-core/Cargo.toml`
- `wasm/eth_signer/Cargo.toml`
- tests that use the TypeScript BigInt mapper directly

### Implementation Steps

1. Make Rust/WASM the single production implementation of additive share mapping.

2. Remove the runtime TypeScript BigInt mapper from production paths. Keep a test-only fixture helper only if it is needed for vector readability.

3. Add a Rust anti-drift test against the pinned upstream crate:
   - Assert `Participant::from(1).scalar() == 2`.
   - Assert `Participant::from(2).scalar() == 3`.
   - Assert `ParticipantList([1,2]).lagrange(1) == 3`.
   - Assert `ParticipantList([1,2]).lagrange(2) == -2`.
   - Assert mapped client and relayer shares linearize back to their additive inputs.

4. Add committed cross-language vectors:
   - additive share input
   - mapped client backend share
   - mapped relayer backend share
   - expected linearized client share
   - expected linearized relayer share

5. Verify vectors in:
   - Rust signer-core tests
   - WASM replay tests
   - any remaining TypeScript test fixture helper

6. Complete `FV-SECP-2P-001`:
   - Prove inverse-Lagrange mapping preserves `x_client + x_relayer`.
   - Update `formal-verification/docs/proof-inventory.md` from `planned` to `proven` when checked in CI.

7. Add a dependency update gate:
   - Any change to the `threshold-signatures` git revision must update the anti-drift vectors.
   - The upstream participant-coordinate test must pass against the new revision.
   - `FV-SECP-2P-001` must still pass.

### Acceptance Criteria

- Production client and server mapping calls use Rust/WASM.
- The TypeScript BigInt mapper is removed from runtime code.
- CI fails if the pinned upstream participant-coordinate convention changes.
- CI fails if `{client=1, relayer=2}` no longer yields Lagrange coefficients `{3, -2}`.
- `FV-SECP-2P-001` is proven or the dependency update gate explicitly blocks `threshold-signatures` revision changes until it is proven.

### Tests

Add or update targeted tests:

- Rust signer-core anti-drift test for upstream participant scalars and Lagrange coefficients.
- Rust signer-core mapping roundtrip tests for multiple committed vectors.
- WASM replay test that validates the same vectors through `map_additive_share_to_threshold_signatures_share_2p`.
- Existing HSS signing roundtrip remains green.

## P3: Formal Verification For Cait-Sith Integration

### Problem

Most scalar arithmetic and threshold ECDSA glue runs in Rust/WASM, which is a good fit for the existing Verus and Lean/Aeneas verification tracks. The proof target should be our integration with Cait-Sith rather than the full upstream MPC protocol.

The useful verification boundary is:

```text
Assume Cait-Sith presign outputs satisfy the expected algebra.
Prove our share mapping, signature-share computation, finalization, and lifecycle model preserve the intended ECDSA key and per-user scope.
```

### Rust Formal Verification Crate

Use a formal-verification-only Rust crate or facade. The repo already has this pattern:

- `crates/signer-core/formal-verification/verus`
- `crates/ecdsa-hss/formal-verification/verus`
- `crates/ecdsa-hss/formal-verification/lean-boundary`

Start by extending `crates/signer-core/formal-verification/verus`. A new crate is only needed if the threshold ECDSA proof dependencies make the current Verus crate hard to keep small. Add a narrow Lean/Aeneas boundary after the Rust facade is stable. If the extraction target becomes too broad, create a dedicated facade module under `crates/signer-core/src/` with only proof-friendly pure functions and state transitions.

Do not add verification annotations to production crypto code unless a proof cannot be maintained in the standalone verification crate.

### Code To Model

- `crates/signer-core/src/secp256k1.rs`
  - additive-to-threshold share mapping
  - scalar domain parsing assumptions
- `crates/signer-core/src/threshold_ecdsa.rs`
  - `threshold_ecdsa_compute_signature_share`
  - `threshold_ecdsa_finalize_signature`
  - low-S normalization and recovery-ID assumptions as postconditions
- `crates/ecdsa-hss/src/shared/derive.rs`
  - HSS canonical secret to additive shares
  - additive shares to mapped backend shares
- lifecycle model extracted from:
  - `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
  - `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`

### Proof Crate Layout

Extend `crates/signer-core/formal-verification/verus/src/lib.rs` with:

```rust
pub mod threshold_ecdsa;
```

Add these proof modules:

- `threshold_ecdsa/backend_assumptions.rs`
  - named Cait-Sith assumptions for presign correctness and rerandomization
  - pinned participant-coordinate assumptions
- `threshold_ecdsa/signing_algebra.rs`
  - scalar model for `h`, `r`, `k`, `sigma`, `x`, and `s`
  - signature-share sum theorem
- `threshold_ecdsa/lifecycle.rs`
  - presign/sign state-machine model
  - burn, reserve, consume, and retry transitions
- `threshold_ecdsa/scope.rs`
  - wallet/RP/signing-root/key/participant/relayer scope model
  - per-user blast-radius theorem
- `threshold_ecdsa/vectors.rs`
  - spec-facing committed vectors shared with anti-drift tests

Keep executable anti-drift tests under `crates/signer-core/formal-verification/verus/tests/`. These tests should call production `signer-core` APIs and, where needed, the pinned `near/threshold-signatures` dependency.

### Implementation Steps

1. Extend the Verus crate dependency surface:
   - keep `signer-core-verus` as the implementation-proof crate
   - enable the `threshold-ecdsa` feature for executable anti-drift tests
   - keep Verus proof modules independent from upstream async MPC internals
   - add a `threshold_ecdsa` module tree under the Verus crate

2. Add a proof-facing Rust model for secp256k1 scalar arithmetic:
   - scalar addition modulo curve order
   - scalar multiplication modulo curve order
   - nonzero scalar domain
   - additive share relation
   - inverse-Lagrange mapping for `{client=1, relayer=2}`

3. Promote the existing mapping proof into the threshold ECDSA theorem set:
   - `mapped_client * 3 = x_client`
   - `mapped_relayer * (-2) = x_relayer`
   - Cait-Sith linearization reconstructs `x_client + x_relayer`
   - unsupported participant IDs cannot enter the 2P mapping model

4. Add anti-drift tests for upstream participant semantics:
   - `Participant::from(1)` maps to scalar coordinate `2`
   - `Participant::from(2)` maps to scalar coordinate `3`
   - the two-party Lagrange coefficients are `3` and `-2`
   - production mapping vectors match the Verus model
   - the test fails on any `near/threshold-signatures` revision that changes these conventions

5. Add a proof-facing model for Cait-Sith presign assumptions:
   - `sum(lambda_i * k_i) = k`
   - `sum(lambda_i * sigma_i) = k * x`
   - `R = (1 / k) * G`, or the rerandomized equivalent exposed by the backend
   - rerandomization preserves the signing equation for the given digest, public key, participants, and entropy

6. Add a proof-facing model for our signer-core signature-share code:
   - model `threshold_ecdsa_compute_signature_share`
   - prove each modeled share is `s_i = h * k_i + r * sigma_i`
   - prove `client_s_i + relayer_s_i = k * (h + r * x)` under the backend assumptions
   - prove the model uses the same participant lambdas as the mapping proof

7. Add a proof-facing model for finalization:
   - model relayer share computation
   - model adding the client share
   - model low-S normalization as ECDSA-equivalent scalar negation
   - state recovery ID selection as an executable postcondition checked by tests, not a core algebra theorem
   - prove final output corresponds to the persisted group public key under the signing-algebra assumptions

8. Add a lifecycle state-machine model:
   - `PresignFresh`
   - `PresignActive`
   - `PresignBurned`
   - `PresignDone`
   - `SigningReserved`
   - `SigningConsumed`

9. Prove lifecycle invariants:
   - burned presign sessions cannot transition to done
   - done presignatures can be reserved once
   - consumed presignatures cannot be reused
   - failed protocol steps burn the session
   - `pool_empty` leaves the MPC authorization usable until expiry
   - retries after `pool_empty` preserve the same authorization scope

10. Add a user/key scope model:
   - model wallet session, RP ID, signing root, `ecdsaThresholdKeyId`, participant IDs, and `relayerKeyId`
   - prove a session can reach `ThresholdEcdsaPresignSession::message` only when all scope fields match the persisted integrated key
   - prove user A cannot run MPC against user B's relayer share in the model
   - prove a signing session can only finalize for the same persisted public key selected at sign init

11. Add implementation-facing bridge tests:
   - signer-core mapping vectors match Verus expected values
   - HSS-derived additive shares map to backend shares with the same vectors
   - local two-party presign/sign roundtrip verifies against the canonical public key
   - malformed protocol message test burns the session at the server boundary
   - cross-user `ecdsaThresholdKeyId` misuse does not reach the WASM presign message handler

12. Add theorem inventory entries:
   - `FV-SIGNER-CORE-006`: Cait-Sith participant-coordinate anti-drift
   - `FV-SIGNER-CORE-007`: threshold ECDSA signing-share algebra
   - `FV-SIGNER-CORE-008`: threshold ECDSA finalization algebra
   - `FV-SIGNER-CORE-009`: presign lifecycle burn/single-use model
   - `FV-SIGNER-CORE-010`: per-user relayer-share blast-radius model

13. Add proof commands:
   - `just signer-core-fv-threshold-ecdsa`
   - include it in `just signer-core-fv`
   - keep vector cleanliness checks in the same command path

14. Add a Lean track after the Verus model stabilizes:
   - extract the narrow Rust facade with Charon/Aeneas
   - mirror the HSS Lean boundary pattern
   - prove algebraic lemmas for the share mapping and signing equation
   - keep upstream Cait-Sith properties as named assumptions

15. Update proof inventory:
   - add theorem IDs for share mapping, signing algebra, lifecycle burn behavior, single-use presignatures, and per-user blast radius
   - mark dependency on the pinned `near/threshold-signatures` participant-coordinate convention

### Acceptance Criteria

- The existing `signer-core` formal-verification Rust crate includes a `threshold_ecdsa` proof module tree, or a dedicated formal-verification-only crate exists with a documented reason.
- `FV-SECP-2P-001` is proven in Verus.
- Upstream participant-coordinate anti-drift tests run against the pinned `near/threshold-signatures` revision.
- The signing algebra proof states its Cait-Sith presign assumptions explicitly.
- The lifecycle model proves burn, reserve, consume, and `pool_empty` behavior.
- The scope model proves user/key isolation for relayer share access.
- The Lean track has a narrow extraction boundary before any large proof effort starts.

### Tests And Proof Commands

Add command targets mirroring the HSS proof flow:

- signer-core threshold ECDSA Verus proofs
- signer-core threshold ECDSA anti-drift vectors
- optional Lean boundary extraction/build
- combined `signer-core` formal verification command that runs proofs and vector cleanliness checks

## Validation Order

Run the cheapest checks first:

1. TypeScript unit tests for secure IDs and `pool_empty` retry behavior.
2. Store-specific unit tests for MPC session read-and-claim.
3. Rust signer-core mapping tests.
4. signer-core threshold ECDSA Verus proofs.
5. WASM replay vector test.
6. HSS signing roundtrip.
7. Optional Lean boundary extraction/build after the Rust proof facade stabilizes.
8. Full relayer threshold ECDSA integration tests after the store API changes are complete.

Full build/test runs are justified for this work because the changes touch authentication capabilities, threshold signing lifecycle, store semantics, WASM boundaries, crypto share mapping, and formal verification gates.
