# HSS Export / Key Lifecycle

Date updated: April 2, 2026

## Status

This is the one active document for threshold key export and HSS-backed key
lifecycle behavior.

Current status:

- Ed25519 single-key HSS is the implemented default path.
- ECDSA homomorphic export is still a planned export lane, not the active
  product default.

## Scope

This document defines:

- the active Ed25519 single-key HSS lifecycle,
- the planned ECDSA homomorphic export model,
- shared security invariants,
- registration/session performance lessons from the HSS rollout,
- the current recommendation for the live HSS/export surface.

## Active Ed25519 Model

### Objective

The active Ed25519 architecture is one canonical key lifecycle:

- one canonical Ed25519 seed `d`
- one canonical signing scalar `a`
- one canonical public key `A`
- threshold signing and controlled export both bound to that same lifecycle

This is the active product direction because it preserves a single-key model
across signing, export, and future multi-chain extension.

### Core Model

Let:

- `y_client` be the client root share derived from WebAuthn `prf.output`
- `y_relayer` be the server root share derived from server root material

Define:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `A = [a]B`

Threshold signing uses shares of hidden `a`.

Controlled export reconstructs canonical seed `d`.

Those are two views over one canonical key lifecycle, not two separate keys.

### HSS Role Separation

Under the current HSS architecture:

- the client re-derives hidden inputs from passkey PRF material on demand
- the server re-derives hidden inputs from server root material on demand
- HSS performs the hidden `d -> a` conversion when the product needs fresh
  signing-share reconstruction
- the active route/session flow keeps raw client and server secret inputs
  segregated

The client never receives raw server root material or raw server base-share
material, and the server never receives raw client root material.

### Export Rule

Ed25519 export means seed export.

Supported artifact:

- `near-ed25519-seed-v1`

That means:

- reconstruct canonical seed `d`
- derive the public key from `d`
- fail closed if the derived public key does not match the bound account key
- emit standard NEAR `ed25519:` encoding only after that check

Do not treat scalar export as equivalent to seed export.

### Current Product State

The active product path now does all of the following:

- reconstructs Ed25519 signing-share state through the single-key HSS ceremony
- uses one canonical public key for both signing and export verification
- runs registration, warm-session minting, sync-account, link-device, and
  recovery through the single-key HSS session seam
- keeps the active signer worker free of bootstrap-share baggage from older
  designs
- keeps the export lane on verified `near-ed25519-seed-v1` output only

Verification gates now include:

- the active-path script gate in
  [tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts)
- the separated-role keep-gate in
  [tests/unit/thresholdEd25519.separatedRoles.script.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.separatedRoles.script.unit.test.ts)
- the real role-separated example in
  [crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs)

### Active Invariant

The Ed25519 single-key HSS migration is complete. What that means in practice:

- the active code path no longer depends on `recoveryPublicKey` as a second
  active Ed25519 key or on bootstrap-package worker paths
- old code, tests, benchmarks, and docs were removed instead of being
  left behind as dormant baggage

## Planned ECDSA Homomorphic Export Model

### Objective

The ECDSA export design is an additive-share homomorphic export flow where:

- the server never sees plaintext `clientShare`
- the server never sees plaintext `fullPrivateKey`
- the client reconstructs/exports only inside wallet worker memory
- the flow supports ECDSA keys only (`secp256k1`, `P-256`)
- the HE runtime is worker-scoped and lazy-loaded only for export

This design is for ECDSA only. Ed25519 uses the canonical HSS seed path above.

### Core Construction

Assume per-account additive shares over scalar field order `q`:

- `x = (x_client + x_server) mod q`

Homomorphic export flow:

1. Client creates ephemeral additive-HE keypair `(pk_c, sk_c)`.
2. Client computes `C = Enc_pk_c(x_client)`.
3. Server computes `C' = AddConst(C, x_server)`.
4. Server returns `C'`.
5. Client decrypts `x = Dec_sk_c(C')`.

Result: server learns neither `x_client` nor `x`.

### Trust Model

This export flow assumes:

- the server is trusted to load the correct scoped `x_server` and apply the
  add-constant correctly
- the client is trusted to submit an encryption of the intended share material
- the protocol goal is confidentiality of `x_client` and `x`, not a
  zero-knowledge proof that the ciphertext contains the canonical `x_client`

Required correctness check:

- before emitting any export artifact, the client must derive the public key
  from decrypted private material and compare it to the expected public key
  bound to `(orgId, accountId, keyPurpose, keyVersion)`
- any mismatch fails closed and aborts export

### ECDSA Protocol Shape

#### 1. `POST /export/init`

Server validates step-up auth and issues one-time `exportId` bound to:

- `orgId`, `accountId`, `keyPurpose`, `keyVersion`
- client auth context
- short TTL
- anti-replay nonce

The response must also include the expected public key or public-key
fingerprint for the exact export target.

#### 2. `POST /export/combine`

Client sends:

- `exportId`
- `pk_c`
- `ciphertext = Enc_pk_c(x_client)`
- bound context fields

Server:

- validates ticket ownership/state/TTL/replay
- loads the scoped `x_server`
- computes `ciphertext' = AddConst(ciphertext, x_server)`
- marks the ticket consumed or advanced
- returns `ciphertext'`

#### 3. Client finalize

Client worker:

- decrypts `x = Dec_sk_c(ciphertext')`
- validates scalar range/domain
- derives the public key from `x`
- compares it to the expected public key from init
- aborts on mismatch
- builds the export artifact
- zeroizes `x`, `x_client`, `sk_c`, and intermediate buffers

### ECDSA Security Invariants

1. No org-global or master shares are used for export combine.
2. Server share is strictly per-account and per-key-version.
3. Export is privileged, auditable, rate-limited, and step-up authenticated.
4. Full private key reconstruction occurs only in worker memory.
5. Plaintext full key is never persisted to browser storage, logs, or
   analytics.
6. Finalize must reject any reconstructed key whose derived public key does not
   match the expected bound public key.
7. The HE runtime must not load in the default client path unless export is
   explicitly requested.

### ECDSA Open Work

The ECDSA HE export lane is still planned work.

The remaining implementation work is:

- freeze export format and state machine
- implement server `init` and `combine`
- implement worker-side HE keygen/encrypt/decrypt wrappers
- implement finalize with public-key verification and zeroization
- add replay, ownership, malformed-ciphertext, and stale-key-version tests
- keep HE runtime lazy-loaded and export-only

## Shared Security Rules

Across both Ed25519 and ECDSA:

- signing and export must verify against the expected bound public key
- any mismatch must fail closed
- raw client and server secret inputs must remain segregated
- privileged export paths must be auditable and step-up authenticated
- no inactive legacy path should remain in the active implementation surface

## Registration And HSS Performance Notes

### Root Causes Of Registration Lag

We traced the long single-key HSS registration delay to a mix of client-side and
server-side HSS packaging/runtime issues.

The main problems were:

1. the relay HSS hot path was loading the wrong WASM build
2. the bootstrap-grant route was triggering expensive warmup on the request
   path
3. the browser HSS path was using an unoptimized NEAR signer WASM build in
   development

### Was The Server Using A Debug Build?

Yes.

Before the fix, the relay HSS path was effectively falling back to the
source-tree browser/dev package:

- `wasm/near_signer/pkg/wasm_signer_worker_bg.wasm`

That package had been built with `wasm-pack --dev --no-opt`, which inflated HSS
timings into multi-second territory.

The fix was to make the relay load the dedicated optimized server package from:

- `sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm`

using the build/runtime wiring in:

- [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
- [sdk/scripts/build/build-sdk.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-sdk.sh)
- [sdk/scripts/build/build-wasm.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-wasm.sh)
- [sdk/scripts/build/build-prod.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-prod.sh)

### Was The Server Building The WASM Worker Dynamically?

Not by recompiling Rust on every request.

But it was lazily loading and compiling the WASM module at runtime on first use,
and that still mattered. The real problem was that this expensive warmup had
been kicked off from the bootstrap-grant route path.

The fix was:

- remove registration warmup from bootstrap-grant request handling
- keep warmup as an explicit startup concern instead of piggy-backing it onto
  the first user request

### Client-Side Fix

The browser HSS path and `near-signer.worker` were also using the dev browser
package:

- `wasm/near_signer/pkg`

That package was also being built with `wasm-pack --dev --no-opt`.

The fix was to build the active browser NEAR signer package in release mode
even in the dev SDK build.

After that:

- the browser NEAR signer WASM asset dropped from roughly `10.2MB` to `1.2MB`
- the large client-side gap before HSS `prepare` collapsed

### Healthy HSS Timing Envelope

After those fixes, registration HSS timings dropped into the expected range:

- registration HSS `prepare`: about `360ms`
- registration HSS `finalize`: about `986ms`
- post-registration session HSS `prepare`: about `335ms`
- post-registration session HSS `finalize`: about `531ms`

At that point, the remaining registration time was mostly real NEAR account
creation and access-key visibility checks, not HSS itself.

## Active Dependencies

The active Ed25519 HSS path depends on:

- [crates/ed25519-hss/succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
- [crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [crates/ed25519-hss/optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization-v3.md)

## References

1. Paillier, P. "Public-Key Cryptosystems Based on Composite Degree Residuosity
   Classes," EUROCRYPT 1999.
   [IACR entry](https://www.iacr.org/cryptodb/data/paper.php?pubkey=2681)
2. Damgard, I.; Jurik, M. "A Generalisation, a Simplification and some
   Applications of Paillier's Probabilistic Public-Key System," BRICS RS-00-45, 2000.
   [Paper](https://www.brics.dk/RS/00/45/)
3. Lindell, Y. "Fast Secure Two-Party ECDSA Signing," IACR ePrint 2017/552.
   [ePrint](https://eprint.iacr.org/2017/552)
4. Gennaro, R.; Goldfeder, S. "Fast Multiparty Threshold ECDSA with Fast
   Trustless Setup," IACR ePrint 2019/114.
   [ePrint](https://eprint.iacr.org/2019/114)
5. Canetti, R.; Gennaro, R.; Goldfeder, S.; Makriyannis, N.; Peled, U.
   "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts,"
   IACR ePrint 2021/060.
   [ePrint](https://eprint.iacr.org/2021/060)
