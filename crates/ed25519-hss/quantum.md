# Quantum Roadmap

This file records how the ideas in
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
might evolve toward a post-quantum threshold signer.

It is a future-work note, not a current security claim.

## Current Status

`ed25519-hss` is not post-quantum secure today.

There are two separate reasons:

- the signing side is Ed25519/FROST-style threshold signing, which is not
  post-quantum
- the hidden-eval/HSS machinery in this crate is built on classical
  DDH/OT-style assumptions, which are also not post-quantum

So a real post-quantum version would need both:

- a post-quantum threshold signing backend
- a post-quantum replacement for the current hidden-eval/HSS substrate

## What Should Carry Over

The core idea is the architecture:
- client and server jointly derive a deterministic exportable secret path
- the server can help with signing and recovery flows without seeing the
  canonical exportable secret
- export is explicit and policy-bound, not an accidental side effect of
  signing

That architecture should survive a move to a lattice-based signer.

## Best Post-Quantum Target

A clean target is:
- define a canonical exportable seed for the post-quantum signer
- derive that seed through a server-blind hidden joint computation
- deterministically expand it into the threshold signer's secret material

For ML-DSA, that likely means treating the internal key-generation seed as the
exportable object, not the fully expanded secret-key bytes. FIPS 204 defines
`ML-DSA.KeyGen_internal` over a 32-byte seed, which makes a seed-first export
format much more natural than trying to export expanded polynomial state.

Why this is the right shape:

- it matches what this crate already does for Ed25519:
  export the canonical secret root, not a random session artifact
- it gives one stable export format across devices
- it lets threshold state be re-derived from a deterministic source instead of
  trying to serialize every internal share structure

## What Would Need To Change

### 1. Replace the current HSS substrate

The current hidden-eval path is not post-quantum.

A real post-quantum version would need a different underlying secure-compute
layer, for example:

- LWE/RLWE-based OT and correlated OT
- a lattice-based or otherwise post-quantum garbling/2PC layer
- a different MPC/HSS-style construction whose security is not tied to DDH

This is the biggest research and engineering change. Reusing the current
wire/runtime structure is possible, but reusing the cryptographic assumptions
is not.

### 2. Redefine the fixed function

Today the fixed function is:

- `y_client + y_server -> d -> SHA-512(d) -> clamp -> a`

A post-quantum version would instead need a function more like:

- `y_client + y_server -> xi`
- `xi -> ML-DSA keygen internal state`
- `ML-DSA internal state -> public key + threshold signing state`

The exact fixed function depends on the post-quantum signer.

For ML-DSA specifically, the likely export target is the canonical keygen seed
that deterministically expands into the public key and secret material.

### 3. Redesign the threshold signing backend

The current system benefits from Schnorr/FROST linearity.

ML-DSA and other lattice-based schemes do not have the same simple linear
secret-scalar structure, so the threshold signing layer needs a different
protocol.

That means the future design should be:

- HSS-shaped deterministic hidden seed derivation
- separate threshold ML-DSA signing protocol
- explicit binding between the hidden exportable seed and the threshold
  public key

## Applying This To ML-DSA

The most plausible ML-DSA direction is:

1. Define a canonical exportable seed `xi`.
2. Jointly derive `xi` from client/server root shares through a post-quantum
   hidden-eval protocol.
3. Use deterministic ML-DSA key expansion from `xi`.
4. Derive threshold signing state from that deterministic ML-DSA secret
   material.
5. Keep export as "release `xi`" instead of "release every expanded secret
   polynomial/share object."

That keeps the same product property this crate has today:

- deterministic export
- server-blind signing/recovery
- one canonical secret root

## Applying This To `FSwA-threshold`

Reference repo:

- [peitalin/FSwA-threshold](https://github.com/peitalin/FSwA-threshold)

### Can `FSwA-threshold` export private keys today?

Not in the sense this crate means by export.
- threshold secret-share material exists
- a first-class deterministic private-key export path does not appear to exist

### Could it be used with the HSS idea?

In principle, yes, but not as a drop-in combination.

The current repo generates threshold shares directly from randomness during
keygen. That is a different model from `ed25519-hss`, where there is a
canonical deterministic exportable secret path and threshold signing state is
derived around it.

So to combine the ideas cleanly, `FSwA-threshold` would likely need one of
these redesigns:

- add deterministic key generation from an exportable canonical seed
- add a seed-first threshold key-derivation mode
- or add a proven a-posteriori share-generation path from a canonical
  ML-DSA/FSwA secret

Without one of those, HSS export would not line up with the threshold signer's
actual long-term secret state.

### Best fit with the HSS approach

The best fit is:

- HSS exports a canonical post-quantum seed
- the threshold lattice signer is redesigned so its party shares are derived
  deterministically from that seed


## Recommended Future Steps

1. Keep `ed25519-hss` as an Ed25519-specific crate.
2. Treat the post-quantum effort as a sibling design, not an in-place rename.
3. Write a separate post-quantum design note that fixes:
   - canonical export object
   - threshold backend
   - post-quantum hidden-eval substrate
4. If ML-DSA is the target, prefer a seed-first deterministic design.
5. If `FSwA-threshold` is the target backend, first verify whether it can be
   refactored into deterministic seed-driven key generation without breaking
   its threshold security model.


A successor post-quantum design would ideally have:

- a post-quantum hidden deterministic derivation layer
- a threshold lattice-signing backend
- a canonical export format, most likely a deterministic seed
- explicit proof that export, public-key derivation, and threshold signing all
  refer to the same logical key

## References

- NIST FIPS 204:
  [Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- FIPS 204 PDF:
  [NIST.FIPS.204.pdf](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)
- NIST/related note on seed-based ML-DSA key format:
  [draft-connolly-cfrg-ml-dsa-security-considerations-02](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-ml-dsa-security-considerations-02)
- Threshold lattice signing scaffold:
  [peitalin/FSwA-threshold](https://github.com/peitalin/FSwA-threshold)
