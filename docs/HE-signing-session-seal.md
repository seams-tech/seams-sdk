# HE-Based Signing Session Seal (Design Note)

Date updated: February 26, 2026

## Goal

Describe exactly how to seal and rehydrate a client-side PRF secret using additive homomorphic encryption (HE), while keeping plaintext `x_c` out of server visibility.

This document is a design explanation, not the default recommendation for production session persistence.

## Entities and Notation

- `x_c`: client PRF secret (or PRF-derived client share) held in wallet worker memory.
- `x_s`: per-account server mask secret (`(orgId, accountId, keyPurpose, keyVersion)` scoped).
- `N`: HE plaintext ring modulus (for example, Paillier-family plaintext ring).
- `Enc_pk(m)`: probabilistic HE encryption of message `m`.
- `Dec_sk(C)`: HE decryption.
- `AddConst(C, k)`: homomorphic add-constant operation producing encryption of `m + k` in ring `N`.
- `m`: persisted masked value stored in client `sessionStorage`.

Property used by protocol:

- `Dec_sk(AddConst(Enc_pk(a), b)) = a + b (mod N)`

## What This Is (and Is Not)

- `m = x_c + x_s` is a server-origin mask construction.
- It is not “encrypted with server key” ciphertext in the usual authenticated-encryption sense.
- To keep server blind to `x_c`, sealing must be HE-assisted; client cannot send plaintext `x_c` for masking.

## Domain Design

### Scalar mode (recommended for threshold share material)

- Define secrets in scalar field domain (`Z_q`) if `x_c` is already a share scalar.
- Compute/store `m` in that algebraic domain.
- On rehydrate, recover scalar directly and validate expected range.

### Raw-byte mode (if exact PRF bytes are required)

- Do not blindly map through curve order `q`.
- Define an explicit reversible byte-to-integer encoding and decoding contract.
- Define exact arithmetic domain and inverse operation in the spec before implementation.

If exact-byte preservation is required, this contract must be frozen and tested separately from curve-share math.

## Full Protocol

### A. Seal (write path during login/bootstrap)

1. Worker obtains `x_c` in memory after passkey/WebAuthn flow.
2. Worker requests `seal-init` (or one-time ticket) using authenticated fetch (`HttpOnly` cookie with `credentials: include` or bearer JWT).
3. Worker generates ephemeral HE keypair `(pk_1, sk_1)`.
4. Worker computes `C_1 = Enc_{pk_1}(x_c)`.
5. Worker sends `combine-seal` payload:
   - `ticketId`,
   - `pk_1`,
   - `C_1`,
   - context: `orgId`, `accountId`, `keyPurpose`, `keyVersion`, `sessionId`.
6. Server validates auth, ticket state, ownership, TTL, replay, context binding.
7. Server loads `x_s` for exact scoped key context.
8. Server computes `C_2 = AddConst(C_1, +x_s)`.
9. Server returns `C_2` (and metadata such as `expiresAtMs`, `remainingUses`, `keyVersion`).
10. Worker decrypts `m = Dec_{sk_1}(C_2)`.
11. Worker persists `m` (plus metadata) to wallet-origin `sessionStorage`.
12. Worker zeroizes `x_c` temporary copies, `sk_1`, and intermediate ciphertext buffers not needed further.

Result: persisted value is masked (`m`), while server never saw plaintext `x_c`.

### B. Rehydrate (read path after refresh)

1. Main thread reads persisted record and passes masked value `m` to worker.
2. Worker requests `rehydrate-init` (or one-time ticket).
3. Worker generates fresh ephemeral HE keypair `(pk_2, sk_2)`.
4. Worker computes `C_3 = Enc_{pk_2}(m)`.
5. Worker sends `combine-unseal` payload:
   - `ticketId`,
   - `pk_2`,
   - `C_3`,
   - same bound context fields.
6. Server validates auth/ticket/context and reloads same scoped `x_s`.
7. Server computes `C_4 = AddConst(C_3, -x_s)`.
8. Server returns `C_4`.
9. Worker decrypts `x_c = Dec_{sk_2}(C_4)`.
10. Worker validates domain/range and repopulates PRF cache in worker memory.
11. Worker zeroizes `sk_2` and temporary buffers.

Result: `x_c` is restored in worker memory, without passkey prompt on refresh.

## Correctness Sketch

Seal:

- `m = Dec_{sk_1}(AddConst(Enc_{pk_1}(x_c), x_s))`
- `m = x_c + x_s (mod N)`

Rehydrate:

- `x'_c = Dec_{sk_2}(AddConst(Enc_{pk_2}(m), -x_s))`
- `x'_c = m - x_s = x_c (mod N)`

Given consistent domain definition and context-bound `x_s`, recovered `x'_c` equals original `x_c`.

## What Each Side Learns

### Server learns

- authenticated identity and export/session metadata,
- ciphertexts `C_1`, `C_3` and operation outcomes,
- never plaintext `x_c` and never plaintext reconstructed key.

### Client learns

- masked value `m`,
- rehydrated plaintext `x_c` in worker memory only.

If attacker has only `m` but not `x_s`, recovering `x_c` is infeasible under mask secrecy assumptions and endpoint controls.

## Required Security Controls

1. One-time tickets with short TTL and explicit consumed state.
2. Strict context binding to `(orgId, accountId, keyPurpose, keyVersion, sessionId)`.
3. Per-account/per-user rate limits and anomaly monitoring.
4. Structured audits without logging ciphertext payloads or secret material.
5. Worker-only plaintext handling; no plaintext `x_c` in storage or logs.
6. Fail-closed behavior: invalid/malformed/expired state deletes persisted record and forces fresh passkey auth.

## Failure Handling Rules

- Ticket invalid/expired/replayed -> reject, clear persisted record, require re-auth.
- Key version mismatch -> reject and clear persisted record.
- Decrypt/domain validation failure -> reject and clear persisted record.
- Account/session mismatch -> reject and clear persisted record.

No soft fallback to stale masked records.

## Tradeoffs vs `shamir3pass`

### Performance and UX

- `shamir3pass` is usually much faster on client devices because it relies on ECC operations instead of large-integer modular exponentiation.
- HE adds expensive ephemeral key generation and bigger encrypt/decrypt work, which can increase refresh-time latency.
- On lower-end mobile devices, HE overhead is more likely to become user-visible.

### Network and Storage Footprint

- `shamir3pass` payloads are typically compact.
- HE ciphertexts and key material are substantially larger, increasing request/response size and session-storage footprint.
- Larger payloads also increase tail latency and failure sensitivity on poor networks.

### Client Bundle Size

- `shamir3pass` WASM/runtime is typically smaller.
- HE stacks usually require heavier big-integer dependencies, increasing download and initialization cost.

### Implementation and Operations Complexity

- `shamir3pass` is simpler for session sealing/rehydration and aligns well with existing flows.
- HE introduces more parameterization and validation complexity (key sizes, modulus/domain mapping, ciphertext handling).
- Both approaches require strong authz/replay controls, but HE adds more crypto-specific failure modes to test and monitor.

### Security Properties and Product Fit

- For session sealing alone, `shamir3pass` usually provides the best simplicity/performance tradeoff.
- HE is most compelling when you intentionally want one unified primitive across multiple features (for example: export + session rehydrate).
- If unification is not a hard requirement, keeping session sealing on `shamir3pass` is the lower-risk choice.

## Recommendation

HE mask sealing is algebraically correct and implementable, but operationally heavier than `shamir3pass`. Keep `shamir3pass` as default for session persistence, and treat HE session sealing as an optional advanced mode only if unified-primitive strategy is a hard product requirement.
