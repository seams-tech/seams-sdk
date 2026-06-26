# Auto Audit Report

- Timestamp: `2026-06-18T08:05:26Z`
- Target file: `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- Flow: `Router A/B ECDSA-HSS registration, export, recovery, refresh, and normal-signing boundary`

## Scope / Call Graph Summary

This audit focused on [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs), with the adjacent server and SDK boundaries that consume its typed outputs.

- Direct local imports inside the target file:
  - `crate::protocol::envelope::{role_encrypted_envelope_digest_v1, RoleEncryptedEnvelopeV1}`
  - `crate::protocol::error::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult}`
  - `crate::protocol::gate::ExpensiveWorkKindV1`
  - `crate::protocol::identity::{ServerIdentityV1, SignerIdentityV1, SignerSetV1}`
  - `crate::protocol::lifecycle::LifecycleScopeV1`
  - `crate::protocol::public_request::{PublicRouterRequestContextV1, PublicRouterRequestV1}`
  - `crate::derivation::{CandidateId, PublicDigest32, Role}`

- Direct internal callees used by the target file:
  - `validate_lifecycle_for_context`
  - `validate_lifecycle_work_kind`
  - `decode_secp256k1_public_key33_b64u`
  - `role_encrypted_envelope_digest_v1`
  - `PublicRouterRequestContextV1::new`
  - `PublicRouterRequestV1::new`
  - `router_ab_ecdsa_hss_active_state_session_id_v1`

- Direct local callers / consumers:
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/mod.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/mod.rs) re-exports the whole ECDSA-HSS boundary.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/strict_worker.rs) parses the public request bodies for `/router-ab/ecdsa-hss/bootstrap`, `/export/share`, `/sign/prepare`, and `/sign`.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs) derives active-signing-worker lookups from `RouterAbEcdsaHssNormalSigningScopeV1`.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts) mirrors the normal-signing wire contract and computes matching digests/session ids on the wallet SDK side.
  - Tests: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs) and [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/source_guards.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/source_guards.rs).

- Relevant transitive local imports:
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/public_request.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/public_request.rs) carries `lifecycle.work_kind` into transcript and request transport.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/gate.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/gate.rs) defines the authoritative `ExpensiveWorkKindV1` mapping.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/identity.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/identity.rs) validates signer/server identity shells used in the target file.

## Security Findings

### 1. High: registration and export requests accept mismatched lifecycle work kinds

- Evidence:
  - Registration validation checks context, signer set, replay nonce, expiry, and envelope roles, but never calls `validate_lifecycle_work_kind`: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:932`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:932)
  - Export validation has the same gap: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1108`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1108)
  - Recovery and refresh do enforce route-specific work kinds: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1259`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1259), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1412`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1412)
  - Deriver plaintext validation already assumes the stronger invariant and enforces the expected work kind later: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:476`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:476), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:510`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:510)
  - Current tests cover wrong lifecycle kind only for recovery and refresh, not registration or export: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs:693`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs:693), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs:779`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/tests/ecdsa_hss_protocol.rs:779)

- Impact:
  - A request sent to the registration or export route can carry the wrong `lifecycle.work_kind` and still survive the protocol parser.
  - That mismatched lifecycle then feeds `PublicRouterRequestContextV1` and `PublicRouterRequestV1`, which bind work kind into transcript and AAD decisions downstream.
  - The result is route-level and transcript-level drift inside a security-sensitive boundary. It becomes easier to misclassify quota, audit, or downstream request handling.

- Recommendation:
  - Add `validate_lifecycle_work_kind(..., ExpensiveWorkKindV1::RegistrationPrepare)` to registration validation.
  - Add `validate_lifecycle_work_kind(..., ExpensiveWorkKindV1::KeyExport)` to export validation.
  - Add rejection tests that mirror the existing recovery/refresh coverage.

### 2. High: active-state session ids are collision-prone because they join unconstrained fields with `:`

- Evidence:
  - Rust derives the active-state session id with `format!("{}:{}:{}:{}" ...)`: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:740`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:740)
  - The input fields only require non-empty ASCII. They do not reject `:`: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:688`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:688), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:2218`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:2218)
  - Cloudflare uses that derived string as the lookup key for active signing-worker state: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:1953`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:1953)
  - The wallet SDK mirrors the same delimiter-joined algorithm, so the ambiguity is duplicated client-side: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:908`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:908), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:195`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:195)

- Impact:
  - Two different tuples can collapse to the same session id whenever any component contains `:`.
  - That alias can point unrelated contexts at the same active-signing-worker state lookup, which is a direct correctness and isolation risk for ECDSA-HSS signing state.

- Recommendation:
  - Replace the delimiter-joined format with a length-prefixed canonical encoding plus digest, or a typed struct serialized once at the boundary.
  - If the string format must stay for now, reject `:` in every session-id component at the parser boundary and add fixed tests proving the rejection.

### 3. Medium: the shared TS boundary parser accepts malformed secp256k1 points that Rust rejects

- Evidence:
  - Rust enforces compressed secp256k1 shape on public identity keys and `server_big_r33_b64u`: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:806`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:806), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1886`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1886), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:2322`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:2322)
  - The TS mirror only checks `33` decoded bytes and never checks the compressed-key prefix for:
    - `client_public_key33_b64u`
    - `server_public_key33_b64u`
    - `threshold_public_key33_b64u`
    - `server_big_r33_b64u`
  - Evidence in the TS parser: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:320`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:320), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1046`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1046)

- Impact:
  - Malformed wallet-session JWT state, persisted state, or relay responses can be accepted into the SDK boundary even when the Rust protocol would reject them.
  - The drift widens the trusted surface in the wallet SDK and makes failures show up later, deeper in the signing flow.

- Recommendation:
  - Add a single `requireCompressedSecp256k1PublicKey33B64u` helper in `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`.
  - Reuse it for all three public identity keys plus `server_big_r33_b64u` and pool-fill `bigR` shapes.

## Refactor / Slimming Findings

### 1. Rust request validation has repeated near-clones that already drifted

- The registration, export, recovery, and refresh validators repeat the same skeleton with small branch-specific differences: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:932`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:932), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1108`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1108), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1256`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1256), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1409`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1409)
- The missing work-kind checks on registration/export are a direct result of this duplication.
- Slimming target:
  - Extract a shared validator for the common request shell and require each branch to pass an explicit `ExpensiveWorkKindV1`.
  - Keep branch-specific data checks separate.

### 2. The TS wire mirror repeats the same 33-byte parser in multiple places

- Repeated `requireBase64UrlFixed(..., 33)` calls appear across scope parsing, prepare responses, presignature pool requests, and receipts: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:337`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:337), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1077`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1077), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1289`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1289), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1324`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1324)
- One helper would delete repeated logic and align the SDK boundary with the Rust parser.

## Recommended Next Audit Candidates

1. `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
   - Follow the Rust/TS contract drift through JWT parsing, persisted session rehydration, and relay response parsing.

2. `crates/router-ab-cloudflare/src/lib.rs`
   - Audit the ECDSA-HSS prepare/finalize handlers end-to-end, especially active-state lookup, credential binding, and request/response digest checks.

3. `crates/router-ab-cloudflare/src/durable_object.rs`
   - Audit the active-signing-worker lookup and ECDSA presignature pool state because both consume the session-id derivation reviewed here.

## Finding Counts

- Security findings: `3`
- Refactor/slimming findings: `2`
- Total findings: `5`
