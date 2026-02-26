# Homomorphic Key Export Plan (Ed25519 + ECDSA)

Date updated: February 26, 2026

## Objective

Design and implement a key-export flow where:

- the server never sees plaintext `clientShare`,
- the server never sees plaintext `fullPrivateKey`,
- the client reconstructs/exports only inside wallet worker memory,
- the flow supports both ECDSA keys and Ed25519-based keys with explicit format rules.

## Scope

This document defines:

- cryptographic construction for additive-share reconstruction using additive HE,
- curve-specific constraints for ECDSA and Ed25519,
- server/client protocol boundaries,
- required controls, test strategy, and formal-verification targets.

Out of scope:

- changing threshold signing protocol internals,
- making export non-custodial risk-free (export is still a privileged de-threshold event),
- using this as XSS defense.

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

## HE Primitive Choice

Use an additive homomorphic scheme in integers modulo a large composite (Paillier-family / Damgård–Jurik style):

- supports `Enc(m1) ⊕ m2 = Enc(m1 + m2)`,
- efficient server operation for add-constant,
- mature literature and implementation patterns.

Baseline requirements:

- `n` (HE modulus) sized so plaintext space safely contains scalar domain and blinding margin,
- ciphertext integrity via protocol-level binding (ticket, nonce, account, keyVersion, PK binding),
- authenticated channel (TLS + session auth),
- strict replay prevention and one-time use tickets.

## Curve-Specific Construction Notes

### ECDSA (`secp256k1`, `P-256`)

Export target: scalar private key `x in [1, q-1]`.

- additive-share reconstruction is direct in scalar field `Z_q`,
- exported encoding should be canonical fixed-width big-endian scalar bytes,
- enforce range checks before wrapping/export artifact generation.

### Ed25519

Ed25519 commonly starts from a 32-byte seed, then hashes/clamps to secret scalar.

Important implication:

- if threshold shares are over the scalar domain, HE export yields scalar-form private material, not necessarily original seed bytes.

Plan decision:

- define export format explicitly as one of:
  - scalar/expanded form (recommended for mathematical consistency), or
  - seed form (requires separate seed-management design; not recoverable from scalar alone).

Do not mix seed semantics and scalar semantics in a single API.

## Protocol Shape (Server + Client)

### 1) `POST /export/init`

Server validates step-up auth and issues one-time `exportId` bound to:

- `orgId`, `accountId`, `keyPurpose`, `keyVersion`,
- client auth context,
- short TTL (for example <= 60s),
- anti-replay nonce.

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
- builds export artifact (always encrypted/wrapped for download),
- zeroizes `x`, `x_client`, `sk_c`, intermediate buffers.

## Security Invariants

1. No org-global/master shares are used for export combine.
2. Server share is strictly per-account and per-key-version.
3. Export route is privileged, auditable, rate-limited, and step-up authenticated.
4. Full private key reconstruction occurs only in worker memory.
5. Plaintext full key is never persisted to `sessionStorage`, `localStorage`, IndexedDB, logs, or analytics.
6. Export is treated as a de-threshold event; policy must rotate or isolate that account afterwards.

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
- reject keyVersion mismatch and stale version requests.

### Oracle amplification

- tight per-user/account rate limits,
- audit every attempt,
- require recent step-up auth.

## Data Model Requirements

- `serverShare` is stored per `(orgId, accountId, keyPurpose, keyVersion)`,
- storage uses KMS/HSM envelope encryption,
- export tickets stored with status transitions (`issued -> consumed|expired|revoked`),
- immutable audit events for init/combine/finalize results.

## Phased Execution Plan

### Phase A — Spec + Crypto Baseline

- [ ] Freeze export formats (`ecdsa-scalar`, `ed25519-scalar` or explicit alternative).
- [ ] Freeze protocol payloads and ticket state machine.
- [ ] Define HE parameter profile and key sizes.
- [ ] Define invariants and failure codes.

### Phase B — Server Module

- [ ] Implement standalone export module with `init` and `combine`.
- [ ] Add authz, replay checks, TTL checks, and policy hooks.
- [ ] Add per-account share resolver and keyVersion enforcement.
- [ ] Add structured audit + rate-limit integration.

### Phase C — Worker Finalize + Export Artifact

- [ ] Implement worker-side HE keygen/encrypt/decrypt wrappers.
- [ ] Implement finalize path with scalar validation and zeroization.
- [ ] Implement encrypted export artifact generation (never plaintext at rest).
- [ ] Add explicit cleanup for all error paths.

### Phase D — Validation + Hardening

- [ ] Unit tests for ticket and policy logic.
- [ ] Integration tests for ECDSA and Ed25519 export happy paths.
- [ ] Negative tests (replay, ownership mismatch, malformed ciphertext, stale keyVersion).
- [ ] Memory-lifetime and no-persistence assertions in worker tests.

### Phase E — Formal Verification + Research Repo

- [ ] Create separate research repo for papers, proof notes, and model artifacts.
- [ ] Encode protocol state machine and invariants for machine-checking.
- [ ] Add property tests for algebraic correctness (`Dec(AddConst(Enc(a), b)) = a+b mod q`).
- [ ] Document assumption boundary (HE security, authenticated channel, endpoint policy).

## Formal Methods Targets

Minimum properties to verify:

1. **Correctness**: combine/decrypt recovers expected scalar modulo `q`.
2. **Context binding**: ticket/context mismatch cannot progress protocol.
3. **Single use**: consumed ticket cannot be reused.
4. **No plaintext server exposure**: server interfaces never require plaintext `x_client`.
5. **Fail-closed semantics**: any validation failure terminates export without partial success.

## Open Decisions

1. Ed25519 export format: scalar-only vs separate seed export flow.
2. Which HE runtime/provider is used in production for client worker + server module.
3. Post-export policy default: forced key rotation vs explicit exported-custody mode.

## Citations

1. Paillier, P. “Public-Key Cryptosystems Based on Composite Degree Residuosity Classes,” EUROCRYPT 1999. DOI: `10.1007/3-540-48910-X_16`  
   - https://www.iacr.org/cryptodb/data/paper.php?pubkey=2681
2. Damgård, I.; Jurik, M. “A Generalisation, a Simplification and some Applications of Paillier's Probabilistic Public-Key System,” BRICS RS-00-45, 2000.  
   - https://www.brics.dk/RS/00/45/
3. Lindell, Y. “Fast Secure Two-Party ECDSA Signing,” IACR ePrint 2017/552.  
   - https://eprint.iacr.org/2017/552
4. Gennaro, R.; Goldfeder, S. “Fast Multiparty Threshold ECDSA with Fast Trustless Setup,” IACR ePrint 2019/114.  
   - https://eprint.iacr.org/2019/114
5. Canetti, R.; Gennaro, R.; Goldfeder, S.; Makriyannis, N.; Peled, U. “UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts,” IACR ePrint 2021/060.  
   - https://eprint.iacr.org/2021/060
6. RFC 8032: “Edwards-Curve Digital Signature Algorithm (EdDSA),” IETF, 2017.  
   - https://www.rfc-editor.org/rfc/rfc8032
7. RFC 8410: “Algorithm Identifiers for Ed25519, Ed448, X25519, and X448,” IETF, 2018.  
   - https://www.rfc-editor.org/rfc/rfc8410
8. FIPS 186-5: “Digital Signature Standard (DSS),” NIST, 2023.  
   - https://csrc.nist.gov/pubs/fips/186-5/final
