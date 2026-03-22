# Homomorphic Key Export Plan (ECDSA)

Date updated: March 22, 2026

## Objective

Design and implement an ECDSA key-export flow where:

- the server never sees plaintext `clientShare`,
- the server never sees plaintext `fullPrivateKey`,
- the client reconstructs/exports only inside wallet worker memory,
- the flow supports ECDSA keys only (`secp256k1`, `P-256`),
- the HE runtime is worker-scoped and lazy-loaded only for export.

## Scope

This document defines:

- cryptographic construction for additive-share reconstruction using additive HE,
- ECDSA-specific scalar export constraints,
- server/client protocol boundaries,
- required controls, test strategy, and formal-verification targets.

Out of scope:

- Ed25519 export semantics,
- changing threshold signing protocol internals,
- making export non-custodial risk-free (export is still a privileged de-threshold event),
- using this as XSS defense.

Ed25519 is tracked separately in `docs/homomorphic-key-export-ED25519.md`.

## Core Construction

Assume per-account additive shares over scalar field order `q`:

- `x = (x_client + x_server) mod q`

Homomorphic export flow:

1. Client creates ephemeral additive-HE keypair `(pk_c, sk_c)`.
2. Client computes `C = Enc_pk_c(x_client)`.
3. Server computes `C' = AddConst(C, x_server)` (homomorphic addition by plaintext constant).
4. Server returns `C'`.
5. Client decrypts `x = Dec_sk_c(C')`.

Result: server learns neither `x_client` nor `x`.

## Trust Model and Correctness Boundary

This export flow assumes:

- the server is trusted to load the correct scoped `x_server` and apply add-constant correctly,
- the client is trusted to submit an encryption of the intended share material,
- the protocol goal is confidentiality of `x_client` and `x`, not a zero-knowledge proof that the ciphertext contains the canonical `x_client`.

Important consequence:

- the server cannot verify whether `ciphertext` encrypts the canonical `x_client` or any other client-chosen scalar, because HE intentionally hides the plaintext,
- this is acceptable for export under this trust model,
- if the client sends the wrong plaintext, or if the server combines incorrectly, the failure is a correctness/availability failure rather than a plaintext-exposure failure.

Required correctness check:

- before emitting any export artifact, the client must derive the public key from decrypted private material and compare it to the expected public key bound to `(orgId, accountId, keyPurpose, keyVersion)`,
- any mismatch fails closed and aborts export.

## HE Primitive Choice

Use an additive homomorphic scheme in integers modulo a large composite (Paillier-family / Damgard-Jurik style):

- supports `Enc(m1) ⊕ m2 = Enc(m1 + m2)`,
- efficient server operation for add-constant,
- mature literature and implementation patterns.

Baseline requirements:

- `n` (HE modulus) sized so plaintext space safely contains scalar domain and blinding margin,
- ciphertext integrity via protocol-level binding (ticket, nonce, account, keyVersion, PK binding),
- authenticated channel (TLS + session auth),
- strict replay prevention and one-time use tickets.

## ECDSA Construction Notes

Export target: scalar private key `x in [1, q-1]`.

- additive-share reconstruction is direct in scalar field `Z_q`,
- exported encoding should be canonical fixed-width big-endian scalar bytes,
- finalize must reject zero, out-of-range, or public-key-mismatched results before artifact generation.

## Protocol Shape (Server + Client)

### 1) `POST /export/init`

Server validates step-up auth and issues one-time `exportId` bound to:

- `orgId`, `accountId`, `keyPurpose`, `keyVersion`,
- client auth context,
- short TTL (for example <= 60s),
- anti-replay nonce.

Server response should also include the expected public key (or equivalent public-key fingerprint) for the exact `(orgId, accountId, keyPurpose, keyVersion)` being exported so finalize can perform a strict public-key consistency check.

### 2) `POST /export/combine`

Client sends:

- `exportId`,
- `pk_c`,
- `ciphertext = Enc_pk_c(x_client)`,
- context fields (`accountId`, `keyVersion`).

Server:

- validates ticket ownership/state/TTL/replay,
- loads per-account `x_server`,
- computes `ciphertext' = AddConst(ciphertext, x_server)`,
- marks ticket consumed (or moves to finalize state),
- returns `ciphertext'`.

### 3) Client finalize

Client worker:

- decrypts `x = Dec_sk_c(ciphertext')`,
- validates scalar in correct range/domain,
- derives the public key from `x` and compares it to the expected public key from init,
- aborts export on any mismatch,
- builds export artifact (always encrypted/wrapped for download),
- zeroizes `x`, `x_client`, `sk_c`, intermediate buffers.

## Security Invariants

1. No org-global/master shares are used for export combine.
2. Server share is strictly per-account and per-key-version.
3. Export route is privileged, auditable, rate-limited, and step-up authenticated.
4. Full private key reconstruction occurs only in worker memory.
5. Plaintext full key is never persisted to `sessionStorage`, `localStorage`, IndexedDB, logs, or analytics.
6. Export is treated as a de-threshold event; policy must rotate or isolate that account afterwards.
7. Finalize must reject any reconstructed key whose derived public key does not match the expected bound public key.
8. HE runtime must not load in the default client path unless export is explicitly requested.

## Threats and Required Mitigations

### Replay / Ticket abuse

- one-time ticket state machine,
- strict TTL,
- nonce binding,
- idempotent consume semantics.

### Cross-account substitution

- bind every request to `(orgId, accountId, keyPurpose, keyVersion)` at issuance and verification.

### Malformed ciphertext / domain confusion

- validate ciphertext structure before combine,
- enforce scalar range checks after decrypt,
- enforce derived-public-key equality before artifact generation,
- reject keyVersion mismatch and stale version requests.

### Incorrect client plaintext / incorrect server combine

- protocol does not require zero-knowledge proof that ciphertext contains the canonical `x_client`,
- server-side correctness is an operational trust assumption for export,
- client detects wrong-share / wrong-combine outcomes by deriving the public key and comparing it to the expected public key,
- any mismatch aborts export without producing an artifact.

### Oracle amplification

- tight per-user/account rate limits,
- audit every attempt,
- require recent step-up auth.

### Client bundle and runtime cost

- HE code must live only in the secure export worker path,
- the worker must lazy-load the HE runtime only after explicit export start,
- unsupported devices or worker-init failures must fail closed before artifact generation.

## Data Model Requirements

- `serverShare` is stored per `(orgId, accountId, keyPurpose, keyVersion)`,
- storage uses KMS/HSM envelope encryption,
- export tickets stored with status transitions (`issued -> consumed|expired|revoked`),
- immutable audit events for init/combine/finalize results.

## Phased Execution Plan

### Phase A — Spec + Crypto Baseline

- [ ] Freeze export format (`ecdsa-scalar`).
- [ ] Freeze protocol payloads and ticket state machine.
- [ ] Define HE parameter profile and key sizes.
- [ ] Define invariants and failure codes.
- [ ] Freeze worker-only lazy-load behavior for the HE runtime.

### Phase B — Server Module

- [ ] Implement standalone export module with `init` and `combine`.
- [ ] Add authz, replay checks, TTL checks, and policy hooks.
- [ ] Add per-account share resolver and keyVersion enforcement.
- [ ] Add structured audit + rate-limit integration.

### Phase C — Worker Finalize + Export Artifact

- [ ] Implement worker-side HE keygen/encrypt/decrypt wrappers.
- [ ] Implement finalize path with scalar validation, expected-public-key verification, and zeroization.
- [ ] Implement encrypted export artifact generation (never plaintext at rest).
- [ ] Add explicit cleanup for all error paths.

### Phase D — Validation + Hardening

- [ ] Unit tests for ticket and policy logic.
- [ ] Integration tests for ECDSA export happy paths.
- [ ] Negative tests (replay, ownership mismatch, malformed ciphertext, stale keyVersion).
- [ ] Add finalize tests that reject wrong-share / wrong-combine outputs via public-key mismatch.
- [ ] Add worker-load tests that verify HE code is not loaded outside explicit export.
- [ ] Memory-lifetime and no-persistence assertions in worker tests.

### Phase E — Formal Verification + Research Repo

- [ ] Create separate research repo for papers, proof notes, and model artifacts.
- [ ] Encode protocol state machine and invariants for machine-checking.
- [ ] Add property tests for algebraic correctness (`Dec(AddConst(Enc(a), b)) = a+b mod q`).
- [ ] Document assumption boundary (HE security, authenticated channel, endpoint policy).

## Formal Methods Targets

Minimum properties to verify:

1. **Correctness**: combine/decrypt recovers expected scalar modulo `q`.
   This property is scoped to honest inputs: the client encrypted the intended share and the server applied the intended add-constant with the correct scoped `x_server`.
2. **Context binding**: ticket/context mismatch cannot progress protocol.
3. **Single use**: consumed ticket cannot be reused.
4. **No plaintext server exposure**: server interfaces never require plaintext `x_client`.
5. **Fail-closed semantics**: any validation failure terminates export without partial success.
6. **Public-key consistency**: finalize rejects if reconstructed key material does not derive the expected public key for the bound export context.

## Open Decisions

1. Which HE runtime/provider is used in production for client worker + server module.
2. Post-export policy default: forced key rotation vs explicit exported-custody mode.

## Citations

1. Paillier, P. "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes," EUROCRYPT 1999. DOI: `10.1007/3-540-48910-X_16`
   - https://www.iacr.org/cryptodb/data/paper.php?pubkey=2681
2. Damgard, I.; Jurik, M. "A Generalisation, a Simplification and some Applications of Paillier's Probabilistic Public-Key System," BRICS RS-00-45, 2000.
   - https://www.brics.dk/RS/00/45/
3. Lindell, Y. "Fast Secure Two-Party ECDSA Signing," IACR ePrint 2017/552.
   - https://eprint.iacr.org/2017/552
4. Gennaro, R.; Goldfeder, S. "Fast Multiparty Threshold ECDSA with Fast Trustless Setup," IACR ePrint 2019/114.
   - https://eprint.iacr.org/2019/114
5. Canetti, R.; Gennaro, R.; Goldfeder, S.; Makriyannis, N.; Peled, U. "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts," IACR ePrint 2021/060.
   - https://eprint.iacr.org/2021/060
6. FIPS 186-5: "Digital Signature Standard (DSS)," NIST, 2023.
   - https://csrc.nist.gov/pubs/fips/186-5/final
