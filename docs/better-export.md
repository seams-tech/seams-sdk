# Better Key Export Plan (Per-Account Shares + Homomorphic Export)

Date updated: February 26, 2026

## Objective

Implement private-key export such that:

- server uses **per-account** server shares (not per-organization shared secrets),
- server never receives plaintext client share or plaintext full private key,
- client reconstructs/exports inside wallet-iframe worker memory only.

## Core Model

For each account/version, maintain threshold secret shares over curve order `q`:

- `x = (x_client + x_server) mod q`
- `x_client`: client secret share
- `x_server`: per-account server secret share

Export uses additive homomorphic encryption:

- client sends `Enc_pkc(x_client)`,
- server evaluates `Enc_pkc(x_client + x_server)`,
- client decrypts to recover `x`.

## Non-Negotiable Invariants

1. No global/master Shamir points are exposed via export.
2. Server share is scoped to `(orgId, accountId, keyPurpose, keyVersion)`.
3. Export is an explicit privileged action (step-up auth + audit + rate limit).
4. Reconstructed private key exists only transiently in wallet worker memory.
5. Plaintext shares/keys are never persisted in `sessionStorage`, `localStorage`, or IndexedDB.

## Protocol Plan

### 1) Export Init

- Client requests export ticket (`exportId`) after step-up auth (passkey/TouchID).
- Server issues one-time token bound to:
  - user/account identity,
  - keyVersion,
  - short TTL,
  - anti-replay nonce.

### 2) Homomorphic Combine

- Client worker generates ephemeral HE keypair `(pk_c, sk_c)`.
- Client worker computes `C = Enc_pk_c(x_client)`.
- Client sends `{ exportId, accountId, keyVersion, pk_c, C }`.
- Server validates auth, ticket, ownership, TTL, and replay constraints.
- Server loads `x_server(accountId, keyVersion)` and computes `C' = HE_AddConst(C, x_server)`.
- Server returns `{ exportId, keyVersion, C' }`.

### 3) Client Finalize

- Client worker decrypts `x = Dec_sk_c(C')`.
- Client worker exports encrypted key artifact for user download.
- Client worker zeroizes `x`, `x_client`, `sk_c`, temporary buffers.
- Server marks `exportId` consumed and writes audit record.

## Security Controls

### Server

- Store per-account server shares under KMS/HSM envelope encryption.
- Enforce one-time export tickets with strict TTL (e.g., <= 60s).
- Apply per-account and per-user rate limits.
- Log structured audit events (who, when, accountId, keyVersion, outcome), never ciphertext/share values.
- Deny cross-account access and stale keyVersion requests.

### Client

- Run combine/finalize only in wallet-iframe worker.
- Zeroize all sensitive buffers after use.
- Keep export flow opt-in and explicit in UX.
- Do not cache reconstructed private key.

## Critical Caveat

Homomorphic combine prevents server from seeing plaintext client share, but export still grants enough material to reconstruct the full key on client. Treat export as a **de-threshold event** for that account.

Recommended post-export policy:

- immediately rotate to a fresh threshold keyset for ongoing threshold operations, or
- explicitly mark account as “exported/manual custody” and disable threshold guarantees until rotation.

## Implementation Architecture

### Client Placement

- Keep HE export orchestration in the existing secure-confirm worker:
  - `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- Do **not** implement HE export logic in chain workers (`near-signer.worker.ts`, `eth-signer.worker.ts`, `tempo-signer.worker.ts`).
- Add worker message contracts in:
  - `client/src/core/types/secure-confirm-worker.ts`
- Keep export feature opt-in and lazy-loaded from the client side.

### Shared Rust HE Stack

- Create a shared Rust crate for HE primitives (for example `crates/homo-enc-core`) with:
  - HE key generation,
  - encrypt/decrypt for client runtime,
  - add-constant operation primitives,
  - strict serialization/deserialization and domain validation.
- Build a WASM wrapper package (for example `wasm/homo-enc-runtime`) that imports `homo-enc-core`.
- Use this WASM package from:
  - client secure-confirm worker (full keygen/encrypt/decrypt),
  - server export module (ciphertext validation + add-constant only).
- Keep default SDK slim by dynamically importing/lazy-loading HE runtime only when export is enabled.

### Server Placement

- Implement HE export as a standalone module under threshold export namespace:
  - `server/src/threshold/export/homoEncKeyExport/`
- Keep this module separate from `prfSessionSeal` and separate from core threshold signing routes.
- Use the same modular structure style already used in `prfSessionSeal`:
  - `crypto/`
  - `policy/`
  - `transport/`
  - `observability/`
  - `tickets/`
  - `service.ts`
  - `routesOptions.ts`
  - `types.ts`
  - `index.ts`

### Router + SDK Integration

- Add optional router option in server SDK:
  - `RelayRouterOptions.homoEncKeyExport?: HomoEncKeyExportRoutesOptions | null`
- Register routes conditionally in both router stacks:
  - `server/src/router/express/createRelayRouter.ts`
  - `server/src/router/cloudflare/createCloudflareRouter.ts`
- Fail closed when module/config is absent (no implicit enablement).

### Runtime Security Boundary

- Server runtime must expose **only** the operation needed server-side (`add_const` / combine), never HE decrypt.
- Client worker holds ephemeral private HE keys for decrypt/finalize and zeroizes after use.
- Enforce strict context binding and one-time ticket semantics on every combine request.

## Implementation Phases

### Phase A — Per-Account Share Foundation

- [ ] Replace per-organization server shares with per-account server shares.
- [ ] Add domain-separated derivation/storage keying by `(orgId, accountId, keyPurpose, keyVersion)`.
- [ ] Add migration path for existing accounts and keyVersion rollover support.

### Phase B — Rust HE Runtime Foundation

- [ ] Create `crates/homo-enc-core` with minimal HE interfaces and deterministic serialization rules.
- [ ] Add WASM wrapper package (for example `wasm/homo-enc-runtime`) for browser/server runtimes.
- [ ] Add runtime guards for domain/range/encoding validation.
- [ ] Add fixture vectors shared by client and server tests.

### Phase C — Export Server Module

- [ ] Add standalone module at `server/src/threshold/export/homoEncKeyExport/`.
- [ ] Implement `init` + `combine` endpoints first; keep finalize client-side.
- [ ] Add ticket issuance + one-time consume semantics.
- [ ] Add HE adapter interface with server-safe boundary (`parse/validate/add-const`; no decrypt).
- [ ] Add policy hooks (authz, rate limit, audit, replay protection).
- [ ] Add router option wiring + conditional registration in Express and Cloudflare routers.

### Phase D — Client Worker Export Flow

- [ ] Integrate HE only in `passkey-confirm.worker.ts`.
- [ ] Add lazy-loaded HE runtime wrapper in worker.
- [ ] Implement export init/combine/finalize calls from worker.
- [ ] Implement encrypted export artifact generation.
- [ ] Add explicit zeroization and failure cleanup paths.

### Phase E — Hardening + Tests

- [ ] Unit tests for ticket replay/expiry/ownership checks.
- [ ] Integration tests for full export happy path in browser-worker + server.
- [ ] Negative tests for malformed ciphertext, wrong keyVersion, cross-account attempts.
- [ ] Security tests for “no plaintext persistence at rest”.

## Phased TODO List (Execution Order)

### Phase 1 — Architecture Freeze

- [ ] Freeze placement: client in secure-confirm worker, server in `threshold/export/homoEncKeyExport`, shared Rust HE crate.
- [ ] Freeze route names, payload schema, and ticket lifecycle states.
- [ ] Freeze Ed25519 export representation (`scalar` vs `seed`) and document non-convertibility constraints.

### Phase 2 — Shared HE Crate + WASM

- [ ] Implement `crates/homo-enc-core` with serialization, domain checks, and add-constant primitives.
- [ ] Build `wasm/homo-enc-runtime` and expose minimal JS bindings.
- [ ] Add baseline cross-runtime test vectors.

### Phase 3 — Server Module + Routing

- [ ] Scaffold `homoEncKeyExport` module folders and types.
- [ ] Implement `POST /export/init` and `POST /export/combine`.
- [ ] Wire optional module config into `RelayRouterOptions` and both router implementations.
- [ ] Add audit/rate-limit/replay protections and KMS-backed per-account share loading.

### Phase 4 — Client Worker Integration (Opt-In)

- [ ] Add export worker messages and runtime loading gates.
- [ ] Implement init/combine/finalize flow entirely in secure-confirm worker.
- [ ] Ensure zeroization and fail-closed behavior on all error paths.
- [ ] Keep feature disabled by default unless explicit opt-in config is set.

### Phase 5 — Verification + Rollout

- [ ] Run integration tests for ECDSA and Ed25519 export flows.
- [ ] Run adversarial tests (replay, stale keyVersion, cross-account, malformed ciphertext).
- [ ] Validate memory/at-rest constraints and logging redaction.
- [ ] Roll out behind staged feature flag and monitor audit metrics.

## Suggested Touchpoints

- `server/src/threshold/export/homoEncKeyExport/`
- `server/src/router/relay.ts`
- `server/src/router/express/createRelayRouter.ts`
- `server/src/router/cloudflare/createCloudflareRouter.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/types/secure-confirm-worker.ts`
- `crates/homo-enc-core/`
- `wasm/homo-enc-runtime/`
