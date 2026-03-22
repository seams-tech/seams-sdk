# Homomorphic Key Export Support Plan (Ed25519)

Date updated: March 22, 2026

## Objective

Define a separate Ed25519 homomorphic key-export plan that does not conflate:

- threshold scalar reconstruction,
- canonical NEAR private-key export,
- custom internal import/export artifacts.

Goals:

- keep the server blind to plaintext `clientShare` and plaintext reconstructed private material,
- keep finalize and artifact generation inside wallet worker memory only,
- keep the HE runtime worker-scoped and lazy-loaded only for export,
- make Ed25519 artifact semantics explicit,
- fail closed on public-key mismatch or unsupported account state.

## Current Repo Constraints

Current code paths use two different private-material representations:

- `crates/signer-core/src/near_ed25519.rs` exports NEAR private keys in seed-based form: `ed25519:` + base58(`seed || publicKey`),
- `crates/signer-core/src/near_threshold_frost.rs` and `crates/signer-core/src/near_threshold_ed25519.rs` use FROST signing shares in scalar form.

Important consequence:

- HE over the current threshold Ed25519 share model reconstructs signing-scalar material,
- it does not reconstruct the original 32-byte Ed25519 seed,
- it also does not reconstruct a full Ed25519 expanded secret,
- therefore the ECDSA export plan cannot be reused unchanged for Ed25519.

## Problem Statement

For Ed25519, "private key" is overloaded:

- standard wallet/tooling flows often expect a seed-based private key representation,
- threshold signing flows work naturally over scalar shares,
- these are related, but they are not interchangeable encodings.

The repo's current NEAR export/import behavior is seed-based. That means:

- reconstructing only the scalar is not enough to emit the current canonical `ed25519:` private-key string,
- the seed cannot be recovered from the scalar after the fact,
- any doc or API that says "Ed25519 export" must state whether it means `scalar` or `seed`.

Do not use "expanded" as an export format label in this plan. Use only `scalar` or `seed`.

## Trust Model and Correctness Boundary

This export flow assumes:

- the server is trusted to load the correct scoped share material and apply add-constant correctly,
- the client is trusted to submit an encryption of the intended share material for the chosen artifact mode,
- the protocol goal is confidentiality of client-held share material and reconstructed private material, not a zero-knowledge proof that the ciphertext contains the canonical client share.

Important consequence:

- the server cannot verify whether the ciphertext encrypts the intended client contribution or some other client-chosen value,
- this is acceptable for export under this trust model,
- wrong plaintext or wrong combine is a correctness/availability failure rather than a plaintext-exposure failure.

Required correctness check:

- before emitting any export artifact, the client must derive the public key from the decrypted private material and compare it to the expected public key bound to `(orgId, accountId, keyPurpose, keyVersion)`,
- any mismatch fails closed and aborts export.

## Supported Artifact Modes

### Mode A — `ed25519-scalar-v1`

This mode exports scalar-form signing material only.

- artifact contains reconstructed Ed25519 signing scalar plus the expected public key and version metadata,
- artifact is valid only for controlled importers that explicitly understand `ed25519-scalar-v1`,
- artifact must not be emitted as a standard NEAR `ed25519:` private-key string,
- finalize derives the public key directly from the scalar and rejects any mismatch before wrapping/export.

Properties:

- works with the current threshold scalar-share model,
- keeps the HE construction close to the ECDSA path,
- does not provide standard wallet compatibility.

### Mode B — `near-ed25519-seed-v1`

This mode exports a canonical seed-based Ed25519 private key compatible with the repo's existing NEAR key format.

- artifact contains a canonical 32-byte Ed25519 seed,
- finalize derives the Ed25519 signing key and public key from that seed,
- only after public-key verification may the client emit `ed25519:` + base58(`seed || publicKey`),
- this seed cannot be recovered from the current scalar shares alone.

Properties:

- matches current NEAR private-key expectations,
- requires a separate seed-backed lifecycle design,
- is a larger project than scalar-only export.

## Recommended Strategy

1. Retire existing scalar-only Ed25519 threshold accounts instead of carrying them forward into the export design.
2. Refactor Ed25519 threshold enrollment/rotation so every new threshold account is created with a canonical seed-backed export lifecycle.
3. Treat standard seed-compatible Ed25519 export as the primary goal; keep `ed25519-scalar-v1` only if a named internal caller still requires it. Otherwise remove it from product scope entirely.

## Seed-Backed Design Requirements (Mode B)

A standard NEAR-compatible export path requires new lifecycle guarantees:

- create and bind a canonical export seed at Ed25519 enrollment or rotation time,
- ensure that the threshold public key and the export seed are bound to the same account/key version,
- protect export-seed material under a client/server split suitable for HE reconstruction,
- keep export-seed semantics separate from threshold signing-share semantics,
- reconstruct the seed only inside worker memory during export,
- derive the public key from the reconstructed seed and reject on mismatch before emitting the `ed25519:` private-key string.

Critical rule:

- never attempt to recover or synthesize a canonical seed from a reconstructed scalar after the fact.

## Required Threshold Signing Refactor Before HE Export

Before any HE export work, Ed25519 threshold signing should be refactored so the threshold signer and the standard NEAR private-key export are two views over one canonical key lifecycle.

### Canonical key material

At enrollment or rotation time, the client worker generates one canonical Ed25519 seed:

- `d in {0,1}^256`

Derive standard Ed25519 signing state:

- `h = SHA-512(d)`
- `a = clamp(h[0..31])`
- `prefix = h[32..63]`
- `A = [a]B`

Where:

- `d` is the canonical exportable private-key seed,
- `a` is the scalar the threshold signer must realize,
- `A` is the public key that must match both the threshold signer and the exported NEAR key.

The exported NEAR private key is then:

- `ed25519:` + base58(`d || A`)

### Threshold signing shares

FROST signing should continue to operate on shares of `a`, not on shares of `d`.

For a signer set with participant ids `i in S`, define signing shares `x_i` such that:

- `a = sum(lambda_i * x_i) mod l`

Where:

- `l` is the Ed25519 subgroup order,
- `lambda_i` are the standard Lagrange coefficients for recovery at zero for the active signer set,
- `X_i = [x_i]B` are the verifying-share points,
- `A = sum(lambda_i * X_i)`.

For the current 2-of-2 participant default `(1, 2)`, this becomes:

- `lambda_client = 2`
- `lambda_relayer = -1 mod l`
- `a = 2*x_client - x_relayer mod l`

So if the client chooses `x_client`, the relayer signing share must be:

- `x_relayer = 2*x_client - a mod l`

The threshold public key computed from verifying shares must equal the public key derived from the canonical seed `d`.

### Export-seed shares

Standard NEAR export must reconstruct `d`, not `a`.

Define an independent export-secret split for the seed:

- `m = LE256(d)`
- choose client export share `y_client in Z_(2^256)`
- set relayer export share `y_relayer = m - y_client mod 2^256`

This produces two parallel secret domains bound to the same key version:

- signing domain: FROST shares of `a` (`x_client`, `x_relayer`)
- export domain: additive shares of `d` (`y_client`, `y_relayer`)

Signing uses only the signing domain. Export uses only the export domain.

### Share derivation ownership

The seed-backed design should keep canonical private material inside the client worker only.

- `d` must be generated uniformly at random in the client worker for each new Ed25519 threshold enrollment or rotation,
- `d` must not be derived from WebAuthn PRF output,
- the client worker derives `a`, `m`, `x_client`, `y_client`, `x_relayer`, and `y_relayer`,
- the relayer must never receive plaintext `d`, plaintext `m`, plaintext `a`, or plaintext `prefix`,
- the relayer should receive only relayer-side share material plus public metadata bound to the key version,
- the client should not persist `d`, `x_client`, or `y_client`; those are re-derived or re-created in worker memory when needed.

Important consequence:

- the current relayer-side "derive relayer share from master secret and client verifying share" construction is not the right lifecycle for seed-backed Ed25519 export,
- seed-backed enrollment should instead submit a prepared relayer-share package computed by the client worker from the canonical seed lifecycle.

### Required invariants after the refactor

- every new threshold Ed25519 account must be created from a canonical seed `d`,
- the threshold signing public key derived from `x_i` shares must equal the public key derived from `d`,
- signing shares and export-seed shares must be stored as separate materials with separate type labels and code paths,
- `prefix` is derived from `d` during export verification only; it is not a threshold share,
- no new scalar-only Ed25519 threshold accounts may be created after this refactor.

### Enrollment / rotation output contract

After the refactor, Ed25519 enrollment or rotation should output and bind all of the following under one `(orgId, accountId, keyPurpose, keyVersion)`:

- canonical public key `A`,
- client share derivation contract for signing-share recovery,
- client share derivation contract for export-share recovery,
- relayer signing share material,
- relayer export-seed share material,
- participant-id set and derivation version,
- explicit artifact compatibility metadata indicating that standard `near-ed25519-seed-v1` export is supported.

Clarification:

- client-side shares remain ephemeral and deterministic from WebAuthn PRF output,
- relayer-side shares are the only share materials that need persistent backend storage,
- client IndexedDB should persist only metadata required to re-derive client shares and to request export for the correct key version.

### Why this refactor comes before HE export

Without this lifecycle change, HE export would only reconstruct scalar-form threshold signing material.

With this lifecycle change, HE export can reconstruct the canonical seed:

1. worker reconstructs `d` from export-seed shares,
2. worker derives `a`, `prefix`, and `A` from `d`,
3. worker verifies `A` matches the bound threshold public key,
4. worker emits the standard NEAR private key string.

This keeps threshold signing mathematically aligned with FROST while making standard NEAR-wallet export possible.

## Retirement Policy For Scalar-Only Accounts

Existing scalar-only Ed25519 threshold accounts are out of scope for this design:

- they should be retired rather than migrated into standard seed export support,
- they must not block the new seed-backed threshold lifecycle,
- `near-ed25519-seed-v1` applies only to accounts created or rotated under the refactored lifecycle described above.

No silent downgrade from `seed` export to `scalar` export.

## Protocol Shape

### Common Init

`POST /export/init` should return:

- `exportId`,
- bound context `(orgId, accountId, keyPurpose, keyVersion)`,
- expected public key (or equivalent fingerprint),
- explicit `artifactKind` (`ed25519-scalar-v1` or `near-ed25519-seed-v1`),
- short TTL and anti-replay metadata.

### Mode A Finalize

Client worker:

1. decrypts scalar-form private material,
2. validates scalar/domain constraints,
3. derives the Ed25519 public key from the scalar,
4. compares it to the expected public key,
5. emits wrapped `ed25519-scalar-v1` artifact only on match,
6. zeroizes all private material.

### Mode B Finalize

Client worker:

1. decrypts seed-form private material,
2. validates seed encoding/length contract,
3. derives the Ed25519 signing key and public key from the seed,
4. compares it to the expected public key,
5. emits wrapped `near-ed25519-seed-v1` artifact, and only then the canonical `ed25519:` string if the product surface needs it,
6. zeroizes all private material.

## Threats and Required Mitigations

### Format confusion

- artifact kind must be explicit and mandatory,
- seed export and scalar export must not share one ambiguous API label,
- standard `ed25519:` string output is allowed only for verified seed-based export.

### Wrong plaintext / wrong combine

- protocol does not require zero-knowledge proof that ciphertext contains the canonical client share,
- server-side correctness is an operational trust assumption for export,
- client detects wrong-share / wrong-combine outcomes by deriving the public key and comparing it to the expected public key,
- any mismatch aborts export without producing an artifact.

### Migration ambiguity

- accounts not enrolled into a seed-backed export lifecycle must reject `near-ed25519-seed-v1`,
- capability checks must happen before expensive worker/export steps proceed.

### Client bundle and runtime cost

- HE code must live only in the secure export worker path,
- the worker must lazy-load the HE runtime only after explicit export start,
- unsupported devices or worker-init failures must fail closed before artifact generation.

## Remaining Spec Ambiguities To Freeze

The plan is materially clearer than the original version, but these items should still be frozen before implementation starts.

### 1. Product artifact surface

- default product target should be `near-ed25519-seed-v1`,
- keep `ed25519-scalar-v1` only if there is a named internal importer that still needs it,
- if there is no such caller, remove scalar-export code and docs instead of shipping two Ed25519 artifact modes.

### 2. Canonical seed ownership

- `d` should be generated in the client worker, not by the relayer,
- `d` should be uniformly random per key version, not deterministically derived from PRF output,
- the client worker should compute `x_relayer` and `y_relayer` locally and send only relayer-side shares to the backend,
- the backend should never observe plaintext `d`, `m`, `a`, or `prefix`.

### 3. Deterministic client-share derivation contract

The current threshold signer derives the client signing share from `prf.first`. The seed-backed design should freeze the same model for both client-side share domains:

- `x_client` should be derived from `prf.first` via HKDF-SHA256 with a dedicated signing-share label,
- `y_client` should be derived from `prf.first` via HKDF-SHA256 with a separate export-share label,
- the HKDF info layout should explicitly bind `nearAccountId`, `keyVersion`, participant ids, and derivation path,
- rotation must change `keyVersion`, so a rotated account cannot silently reuse the old client-share derivation context.

### 4. Integer and byte encoding contract

- `d` is exactly 32 bytes,
- `m = LE256(d)` is the canonical unsigned integer encoding of the seed,
- `y_client` and `y_relayer` live in `Z_(2^256)`,
- export finalize must decode the decrypted value as `m mod 2^256`, then re-encode it as 32 little-endian bytes before deriving the Ed25519 key,
- the standard NEAR wallet artifact remains `ed25519:` + base58(`d || A`).

### 5. v1 participant scope

- v1 should be explicit 2-of-2 only,
- v1 should freeze participant ids `(1, 2)` unless there is a concrete need to support configurable ids immediately,
- if configurable ids are retained, the exact participant-id tuple must be part of both enrollment metadata and export validation context,
- do not build a fake-general n-party API until there is an actual n-party Ed25519 requirement.

### 6. Persistent storage schema

- client storage should distinguish seed-backed threshold Ed25519 material from the current scalar-only record shape,
- relayer storage should separate signing-share material from export-seed-share material,
- both sides should bind those materials to the same `keyVersion` and public key,
- capability metadata such as `near-ed25519-seed-v1` support must be stored explicitly and checked before export begins.

### 7. Export route contract

- `init` must return capability, expected public key, artifact kind, participant ids, and `keyVersion`,
- the relayer combine step should operate only on export-seed share material for `near-ed25519-seed-v1`,
- accounts without seed-backed capability must be rejected before HE initialization,
- stale `keyVersion`, stale `exportId`, or mismatched participant metadata must fail closed.

### 8. Worker/runtime boundary

- Ed25519 export must stay worker-owned end to end,
- main-thread TypeScript must never hold plaintext `d`, `a`, `m`, `x_client`, `y_client`, or the emitted private key string,
- the current export worker shortcut that falls back to `recoverKeypairFromPasskey()` for Ed25519 should not remain the threshold export path,
- HE code must remain lazy-loaded and scoped to the export worker only.

### 9. NEAR wallet interoperability target

- the output must be accepted by the repo's own `ed25519:` parser,
- the output should also be validated against at least one external NEAR-compatible import/parser surface before this plan is considered complete,
- the doc should record exactly which compatibility targets are required for sign-off.

## Comprehensive Phased Implementation Spec

### Phase 0 — Scope Freeze And Breaking Cleanup

- [ ] Freeze `near-ed25519-seed-v1` as the product target for Ed25519 export.
- [ ] Decide whether `ed25519-scalar-v1` survives as an internal-only artifact. If not, remove it from the implementation plan and codebase.
- [ ] Freeze v1 scope as seed-backed 2-of-2 threshold Ed25519 only.
- [ ] Remove ambiguous "expanded secret" language everywhere in code and docs.
- [ ] Remove any remaining Ed25519 export assumptions that rely on legacy local-signer recovery or scalar-only threshold accounts.

### Phase 1 — Crypto And Serialization Spec Freeze

- [ ] Freeze the canonical seed derivation math:
  - `d in {0,1}^256`
  - `h = SHA-512(d)`
  - `a = clamp(h[0..31])`
  - `prefix = h[32..63]`
  - `A = [a]B`
- [ ] Freeze the client signing-share derivation:
  - HKDF-SHA256 from `prf.first`
  - dedicated signing-share salt/version label
  - 64-byte OKM reduced with `from_bytes_mod_order_wide`
- [ ] Freeze the client export-share derivation:
  - HKDF-SHA256 from `prf.first`
  - dedicated export-share salt/version label
  - 32-byte OKM interpreted as little-endian integer in `Z_(2^256)`
- [ ] Freeze the default 2-of-2 share formulas:
  - `x_relayer = 2*x_client - a mod l`
  - `y_relayer = m - y_client mod 2^256`
- [ ] Freeze the exact HKDF info layout. Minimum fields should include `nearAccountId`, `keyVersion`, participant ids, and derivation path.
- [ ] Freeze the seed export encoding as `ed25519:` + base58(`d || A`).
- [ ] Publish fixed test vectors for `d`, `a`, `A`, `x_client`, `x_relayer`, `y_client`, `y_relayer`, and the final `ed25519:` string.

### Phase 2 — Rust / Wasm Core Refactor

- [ ] Add pure core helpers to:
  - derive `a`, `prefix`, and `A` from `d`
  - derive `x_client` and `y_client` from `prf.first`
  - compute `x_relayer` and `y_relayer`
  - verify that the threshold public key equals the seed-derived public key
  - encode and parse the standard NEAR `ed25519:` private key format
- [ ] Add explicit types for seed-backed Ed25519 key material rather than reusing scalar-only names.
- [ ] Remove or replace the current relayer-share derivation path that starts from relayer master secret plus client verifying share for new seed-backed accounts.
- [ ] Add unit tests for all byte-order, modulo, and public-key consistency boundaries.

### Phase 3 — Enrollment / Rotation Refactor

- [ ] Generate canonical seed `d` inside the client worker during Ed25519 threshold enrollment and rotation.
- [ ] Derive `a`, `A`, `x_client`, `y_client`, `x_relayer`, and `y_relayer` inside the same worker session.
- [ ] Send only relayer-side shares plus public metadata to the relayer enrollment route.
- [ ] Ensure relayer enrollment persists both:
  - relayer signing share material
  - relayer export-seed share material
- [ ] Ensure client storage persists only metadata and derivation versions, not plaintext client shares or `d`.
- [ ] Bind the on-chain access key, relayer share records, and client metadata to the same `keyVersion` and public key.
- [ ] Rotation must replace the old share package completely; no new scalar-only Ed25519 accounts may be created after this phase.

### Phase 4 — Client And Relayer Data-Model Break

- [ ] Replace the current client IndexedDB record shape with a seed-backed threshold Ed25519 material type.
- [ ] Add explicit fields for:
  - `keyVersion`
  - `artifactKind`
  - `seedExportCapable`
  - client signing-share derivation version
  - client export-share derivation version
  - participant ids
  - relayer key reference / share reference
- [ ] Update all mappers, stores, and worker payload assemblers to use the new type.
- [ ] Update relayer persistence so signing-share state and export-seed-share state are stored as separate, typed materials.
- [ ] Remove old scalar-only Ed25519 material names and branches once callers are migrated.

### Phase 5 — Export API And HE Protocol

- [ ] Define `POST /export/init` for seed-backed Ed25519 export. Response should include:
  - `exportId`
  - `artifactKind = near-ed25519-seed-v1`
  - `keyVersion`
  - expected public key
  - participant ids
  - HE profile / parameter version
  - TTL / anti-replay metadata
- [ ] Add a relayer combine route that:
  - loads the relayer export-seed share for the bound key version
  - applies homomorphic add-constant to the client ciphertext
  - returns the combined ciphertext
  - never exposes plaintext share material
- [ ] Define the client worker finalize contract:
  - derive `y_client`
  - HE-encrypt `y_client`
  - submit ciphertext to combine route
  - decrypt `m`
  - reduce mod `2^256`
  - decode `d`
  - derive `A`
  - compare `A` to expected public key
  - emit `ed25519:` + base58(`d || A`) only on match
- [ ] Freeze the plaintext-capacity requirement for the HE scheme so a 256-bit seed share can be encoded safely without ambiguity.
- [ ] Reject unsupported key material before HE runtime load.

### Phase 6 — Worker, UI, And Runtime Refactor

- [ ] Change `EXPORT_PRIVATE_KEYS_WITH_UI` inputs so the worker receives concrete threshold export capability metadata, not only `hasThresholdKeyMaterial`.
- [ ] Remove the current Ed25519 threshold-export fallback that reconstructs a local keypair via `recoverKeypairFromPasskey()`.
- [ ] Keep the entire seed reconstruction and `ed25519:` string emission inside secure worker memory only.
- [ ] Lazy-load the HE runtime only after explicit export confirmation and capability preflight.
- [ ] Update export UI copy to state that the output is a standard NEAR Ed25519 private key and that export fails closed on any public-key mismatch.

### Phase 7 — Verification, Interop, And Negative Tests

- [ ] Add fixed-vector tests that prove:
  - seed-derived public key equals threshold public key
  - `x_client` / `x_relayer` recombine to `a`
  - `y_client` / `y_relayer` recombine to `m`
- [ ] Add cross-runtime tests so Rust core, Wasm worker, and TypeScript orchestration agree on public key, share derivation, and export string.
- [ ] Add end-to-end tests for:
  - enroll seed-backed threshold Ed25519 key
  - sign successfully with threshold flow
  - export successfully with HE
  - parse/import the resulting `ed25519:` key in at least the repo's parser and one external NEAR-compatible parser/import surface
- [ ] Add failure tests for:
  - wrong public key
  - wrong participant ids
  - stale `keyVersion`
  - stale `exportId`
  - malformed ciphertext
  - unsupported account material
  - worker HE initialization failure
- [ ] Add tests proving the HE bundle is not loaded during normal signing or app startup.

### Phase 8 — Cleanup And Cutover

- [ ] Delete old scalar-only Ed25519 enrollment, storage, and export branches that no longer serve the seed-backed design.
- [ ] Delete any remaining worker or API branches that assume legacy local NEAR Ed25519 export for threshold accounts.
- [ ] Remove dead docs once `near-ed25519-seed-v1` is the only supported product export path.
- [ ] Record the final compatibility matrix and link the published test vectors.

## Decision Gates Before Coding

1. Is `ed25519-scalar-v1` deleted now, or kept for one named internal caller?
2. What are the exact HKDF labels and info layout for `x_client` and `y_client`?
3. Does v1 lock participant ids to `(1, 2)`, or support configurable ids immediately?
4. Do we use a shared export route with strict `artifactKind`, or a dedicated Ed25519 seed-export endpoint?
5. Which external NEAR-compatible import/parser surface is required for compatibility sign-off?

## Notation and Math Appendix

### `LE256(d)`

`LE256(d)` means:

- interpret the 32-byte seed `d` as a 256-bit integer in little-endian byte order,
- this gives a reversible integer encoding `m in [0, 2^256 - 1]`,
- the export-share split operates on this integer form.

### `A = [a]B`

`B` is the standard Ed25519 base point on the curve.

- mathematically, `B` is a curve point,
- in code, it is typically represented as an Edwards-point structure,
- `[a]B` means scalar multiplication of the base point by the secret scalar `a`,
- the result `A` is the public-key point corresponding to `a`.

When serialized for Ed25519 public keys, `A` is usually compressed to 32 bytes using the standard Edwards-Y compressed encoding.

### `clamp(h[0..31])`

This is the standard Ed25519 bit-masking step applied to the first 32 bytes of `SHA-512(d)` before interpreting them as the signing scalar.

In byte form:

```text
s[0]  &= 248
s[31] &= 63
s[31] |= 64
```

Meaning:

- clear the lowest 3 bits of byte 0,
- clear the highest bit of byte 31,
- set the second-highest bit of byte 31.

This is a standard part of Ed25519 key derivation, not a project-specific convention.

## Citations

1. RFC 8032: "Edwards-Curve Digital Signature Algorithm (EdDSA)," IETF, 2017.
   - https://www.rfc-editor.org/rfc/rfc8032
2. RFC 8410: "Algorithm Identifiers for Ed25519, Ed448, X25519, and X448," IETF, 2018.
   - https://www.rfc-editor.org/rfc/rfc8410
3. Paillier, P. "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes," EUROCRYPT 1999. DOI: `10.1007/3-540-48910-X_16`
   - https://www.iacr.org/cryptodb/data/paper.php?pubkey=2681
4. Damgard, I.; Jurik, M. "A Generalisation, a Simplification and some Applications of Paillier's Probabilistic Public-Key System," BRICS RS-00-45, 2000.
   - https://www.brics.dk/RS/00/45/
