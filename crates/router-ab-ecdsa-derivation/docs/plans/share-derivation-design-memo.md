# Design Memo: Threshold Share Derivation Options

Date created: April 8, 2026

Removal note: this memo predates the v2 invalidation. The active crate removed
the old Router A/B ECDSA derivation context version and retains only v2 role-local derivation.

## Scope

This memo compares only the two serious `router-ab-ecdsa-derivation` design options for
turning a canonical hidden secp256k1 secret into threshold-signing material for
the current EVM-compatible threshold ECDSA signer.

The goal is not to restate the entire `router-ab-ecdsa-derivation` plan. The goal is to answer
one question:

How should `router-ab-ecdsa-derivation` derive threshold signing shares from a canonical hidden
secret while preserving:

- standard ECDSA compatibility
- the single-key invariant
- server-blindness
- acceptable signing performance

## Non-Negotiable Goal

Both options are being evaluated against the same invariant:

- exported private key = canonical secp256k1 secret `x`
- threshold signing public key = `x * G`
- Ethereum address used for signing/export is derived from that same public key

If an option cannot preserve that, it is rejected.

## Current Backend Context

The current threshold ECDSA stack already gives us an important integration
seam:

- the signer core accepts externally provided private-share material and public
  key material in
  [threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
- the codebase already maps additive 2-party secp256k1 shares into the
  `near/threshold-signatures` share encoding in
  [secp256k1.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/secp256k1.rs)
- current ECDSA presign/sign performance is already acceptable enough that we
  should avoid replacing the backend unless reuse fails

That means the default assumption should be:

- reuse the current backend if possible
- do not write a new threshold ECDSA library first

## Option 1: Direct Additive-Share Derivation From Canonical `x`

### Shape

1. `router-ab-ecdsa-derivation` derives one canonical hidden secp256k1 secret `x`.
2. `router-ab-ecdsa-derivation` deterministically derives additive 2-party shares:
   - `x_client`
   - `x_relayer`
   such that:
   - `x = x_client + x_relayer mod n`
3. Each additive share is mapped into the current `near/threshold-signatures`
   share encoding via the existing 2-party mapping layer.
4. The existing presign/sign backend operates on those mapped shares.
5. Export returns canonical `x`.

### What This Preserves

- one canonical exportable secret
- one threshold signing public key
- one Ethereum address
- the current presign/sign backend

### Why It Is Attractive

This option is the closest fit to the current codebase.

The strongest local reason is that the existing backend is already designed to
work from additive-share inputs after mapping:

- additive 2P shares are a first-class concept in the current codebase
- the mapping from additive shares into `threshold-signatures` already exists
- signer-core already takes externally supplied share/public-key inputs
- that mapping is currently a fixed 2-party seam for participant IDs `{1, 2}`

So this path does not require a new threshold ECDSA engine. It requires:

- a new canonical-key derivation layer
- deterministic additive-share derivation from that canonical key
- integration into the existing mapping and signing flow

### Security Story

This option has the cleanest single-key story.

The proof obligation is conceptually simple:

- if `x = x_client + x_relayer mod n`
- and the backend consumes shares that reconstruct to the same public key
- then threshold signing and export refer to the same logical key

The main proof burden is:

- show the additive-share derivation is correct
- show the mapping into `threshold-signatures` preserves the same group secret
- show the server never learns `x`

This aligns well with the existing proof inventory item around additive-share
mapping in
[proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md).

### Performance Expectation

This option should have the lowest steady-state overhead.

Why:

- sign-time presign/sign flows remain unchanged
- no extra resharing protocol is required before signing
- the main new work is during bootstrap and export, not every sign

So the expected performance shape is:

- registration/bootstrap: slower than current ECDSA bootstrap because it now
  includes hidden derivation
- sign: close to current presign/sign performance
- export: explicit hidden-derivation-backed export flow

This is the best option if we want to preserve current EVM sign performance as
much as possible.

### Main Risk

The main risk is not performance. The main risk is whether deterministic
additive-share derivation from canonical `x` is compatible with the current
backend without hidden assumptions.

The design only works if:

- the backend really can consume these derived additive shares as the one true
  group secret
- the mapping layer does not introduce a second-key mismatch

## Option 2: Canonical `x` Plus Public-Key-Preserving Resharing

### Shape

1. `router-ab-ecdsa-derivation` derives one canonical hidden secp256k1 secret `x`.
2. `router-ab-ecdsa-derivation` derives an initial sharing of `x`.
3. A public-key-preserving resharing step transforms that sharing into the
   exact share representation preferred by the current backend.
4. The current presign/sign backend operates on the reshared material.
5. Export still returns canonical `x`.

### What This Preserves

- one canonical exportable secret
- one threshold signing public key
- one Ethereum address
- reuse of the current backend after resharing

### Why It Is Attractive

This is the strongest fallback if direct additive-share derivation does not fit
the current backend cleanly.

It gives us more flexibility because:

- the Router A/B derivation side can choose the most natural hidden sharing for the canonical
  key
- the backend can keep its preferred internal share format
- resharing is the bridge between them

### Security Story

This option can still preserve the single-key invariant, but it has more moving
parts.

The proof obligation is now:

- Router A/B hidden sharing corresponds to canonical `x`
- resharing preserves the same public key
- backend share format corresponds to the same public key
- export still returns `x`

So the core invariant is still achievable, but it is harder to state and prove
than Option 1.

### Performance Expectation

This option is likely slower than Option 1 at bootstrap/session setup.

Why:

- it adds a resharing phase or resharing logic
- it adds more state and more protocol surface before signing can start

Steady-state signing might still be similar after resharing completes, because
the same backend is still doing the actual presign/sign work. But:

- registration/bootstrap overhead will be higher
- complexity is higher
- implementation and verification cost are higher

So this option is best treated as a fallback for compatibility, not the default
path.

### Main Risk

This option risks turning a clean one-key design into an overcomplicated
multi-stage derivation story.

That does not make it wrong, but it does mean:

- more state to audit
- more equivalence conditions to prove
- more places to accidentally recreate the current two-key problem

## Direct Comparison

### 1. Single-Key Clarity

Winner: Option 1

Why:

- additive shares of canonical `x` are a direct statement of the one-key model
- fewer transformations means less ambiguity

### 2. Integration With The Current Backend

Winner: Option 1, unless proven incompatible

Why:

- the current backend already has additive-share mapping machinery
- signer-core already accepts external share/public-key inputs

Option 2 remains viable if direct additive-share inputs do not fit the backend
cleanly enough.

### 3. Verification Burden

Winner: Option 1

Why:

- fewer equivalence layers
- easier to tie export, public key, and threshold signing together

### 4. Performance

Winner: Option 1

Why:

- no resharing stage
- no extra setup ceremony beyond Router A/B hidden evaluation and direct share derivation
- steady-state sign path should remain closest to the current baseline

### 5. Flexibility If The Backend Is Awkward

Winner: Option 2

Why:

- resharing is the escape hatch if the backend cannot consume directly derived
  additive shares without distortion

## Ranking

### 1. Direct additive-share derivation from canonical `x`

This is the preferred design.

It gives the cleanest one-key model, the lowest expected performance overhead,
and the best chance of reusing the current `near/threshold-signatures`
backend without writing a new threshold ECDSA library.

### 2. Canonical `x` plus public-key-preserving resharing

This is the fallback design.

It should only be used if we discover that the current backend cannot cleanly
consume directly derived additive shares.

## Recommendation

The implementation plan should assume:

- Option 1 is the primary design target
- Option 2 is the compatibility fallback

That means the next design work should focus on one question:

Can `router-ab-ecdsa-derivation` derive additive 2-party shares from canonical hidden `x` in a
way that plugs directly into the current additive-share mapping layer and
preserves the threshold public key?

If the answer is yes, we should not introduce resharing.

If the answer is no, then resharing becomes the next design layer, but only as
needed.

## Working v1 Contract

To make Option 1 implementable, the working v1 contract is:

- canonical key object: secp256k1 scalar `x`
- canonical derivation:
  - `m = y_client + y_relayer mod 2^256`
  - `d = LE32(m)`
  - `h_x = SHA-512("router-ab-ecdsa-derivation:v1:canonical-x" || context || d)`
  - `x = 1 + (BE512(h_x) mod (n - 1))`
- additive-share derivation:
  - derive `x_client` from
    `SHA-512("router-ab-ecdsa-derivation:v1:additive-share:client" || context || BE32(counter) || BE32(x))`
  - set
    `x_client = 1 + (BE512(h_share) mod (n - 1))`
  - reject only when `x_client == x`
  - set `x_relayer = (x - x_client) mod n`

That gives:

- a deterministic share derivation contract
- domain separation between canonical-key derivation and share derivation
- a deterministic non-zero/retry rule
- a fixture-ready reference shape for the first implementation pass

## Remaining Questions

1. Does the current additive-share mapping layer preserve exactly the public
   key we need for the fixed v1 signer set `{client=1, relayer=2}`?
2. Is the current 2-party mapping enough for the intended deployment model, or
   do we need a generalized share-mapping story only after v1 lands?
3. Can the current threshold ECDSA session/bootstrap flow accept the new share
   source without dragging old two-key assumptions along with it?

## Sources

- [Secure Two-party Threshold ECDSA from ECDSA Assumptions](https://eprint.iacr.org/2018/499)
- [Threshold ECDSA from ECDSA Assumptions: The Multiparty Case](https://eprint.iacr.org/2019/523)
- [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552)
- [On the Security of ECDSA with Additive Key Derivation and Presignatures](https://eprint.iacr.org/2021/1330.pdf)
- [Non-interactive Distributed Key Generation and Key Resharing](https://eprint.iacr.org/2021/339)
- local backend references:
  - [ethSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ethSignerWasm.ts)
  - [threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
  - [ecdsa_threshold_signing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/ecdsa_threshold_signing.md)
  - [proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md)
