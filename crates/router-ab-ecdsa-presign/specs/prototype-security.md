# Presign prototype security boundary

Status: implementation checkpoint 8. This document records the current claim
boundary and analysis gaps. The Phase 4 normative security review remains
pending.

## Implemented slice

The crate implements the two presign rounds beginning with validated committed
triple shares. Client and SigningWorker roles are separate Rust types. Their
participant coordinates and Lagrange coefficients are compile-time choices.
Runtime APIs expose no participant vector, participant identifier, threshold,
or role selector.

The implementation enforces:

- canonical 32-byte secp256k1 scalars;
- compressed 33-byte non-identity secp256k1 public points;
- one pair-context digest across both triples and every peer message;
- additive wallet-share binding through `beta G = X + B`;
- non-zero opened `e` shares;
- `e G = E`, `alpha G = K + A`, and `beta G = X + B`;
- controlled errors for every implemented rejection; and
- zeroization of owned secret inputs, in-flight states, messages, and outputs.

The deterministic test vector matches the pinned NEAR implementation exactly
for each role's `R`, `k`, and `sigma` output.

Checkpoint 2 adds context-bound Schnorr DLog and Chaum-Pedersen DLogEq kernels.
Their exact equations, transcript fields, upstream mapping, and confidence
scores are recorded in `proof-kernel-v1.md`. Production callers cannot create
`ValidatedTriple` values from raw scalars; the checked triple finalizer owns
that constructor.

Checkpoint 3 adds the fixed polynomial shape used before multiplication. Each
role creates degree-one `E` and `F`, a degree-zero random `L` value that becomes
the final product-sharing slope, and an opening digest
bound to the signing scope, pair, triple index, and prover role. Opening
verification returns an opaque value that retains those bindings. Private
share verification accepts only that value and checks `E(z) = eG` and
`F(z) = fG` at the fixed recipient coordinate. Exact source mappings and the
purpose-built transcript are recorded in `polynomial-commitments-v1.md`.

Checkpoint 4 adds fixed 128-instance Diffie-Hellman base random OT in both
Client/SigningWorker role directions. Outputs remain sealed for the malicious
OT extension, peer points reject invalid and degenerate inputs, and the KDF
binds the full session and role context. Exact equations and source mappings
are recorded in `base-rot-v1.md`.

Checkpoint 5 adds the corrected fixed-size malicious random-OT extension. It
releases 768 correlated scalar OTs from 1024 internal rows, verifies all 128
KOS-style correlation-consistency equations before sender output, and requires
an authenticated acceptance transition before receiver output. Keyed row
expansion, session and role bindings, exact source mappings, and the deliberate
NEAR divergence are recorded in `random-ot-extension-v1.md`.

Checkpoint 6 adds fixed MTA and multiplication-share generation for exactly two
triples. Each direction consumes 768 random OTs as two 384-OT MTA instances,
and fixed Triple 0/1 roles eliminate runtime ordering. Exact equations,
tampering boundaries, and pinned-source mappings are recorded in
`fixed-mta-v1.md`.

Checkpoint 7 integrates the polynomial shares, DLog and DLogEq proofs, sealed
MTA outputs, and random product-sharing slopes. Each raw MTA share stays local;
the peer receives only its masked evaluation of the sender's product-sharing
polynomial. Both roles require the terminal public product equation and the
recipient-specific private `c`-share equation before the state machine emits
an opaque `ValidatedTriple`. Exact equations and source mappings are recorded
in `committed-triple-finalization-v1.md`.

Checkpoint 8 drives the generated triples through fixed-role presign and the
purpose-built online Client and SigningWorker kernels. The resulting Client
signature share and final recoverable low-`s` signature match the pinned NEAR
oracle exactly for the frozen fixture. This establishes the complete isolated
cryptographic happy path from base OT through final signature verification.

## Critical upstream OT-extension divergence

The pinned NEAR source is unsafe as an exact-output oracle for OT row
expansion. `triples/bits.rs:320-327` absorbs each base key into `hasher_row`,
then finalizes a separate clone of the unkeyed prefix. Every expanded base row
is therefore independent of its base-OT key. In the correlated-OT receiver,
this makes `t0` and `t1` equal and reduces `u = t0 xor t1 xor x` to the private
choice matrix `x`.

Severity is critical and finding confidence is `1.00`. The purpose-built
malicious extension implements keyed expansion and carries a regression
proving sensitivity to every base key. NEAR remains evidence for
the intended IKNP/KOS equations and consistency abort structure. Its extension
bytes are excluded from parity claims.

## Assumed inputs and deferred claims

The isolated crate now generates proof-checked committed triples and feeds only
opaque validated values into presign and online signing. Transport transcript
authentication, persistence, one-use tombstones, timeouts, joint entropy
commit/reveal, and the complete malicious negative corpus remain outside this
checkpoint.
The crate is unsuitable for production until those layers and the Phase 4
review gates are complete.

## Constant-time review

Secret-bearing scalar and group operations use `k256` arithmetic. The source
contains no division or remainder on secret values, secret-indexed table, or
variable-size secret loop. Scalar inversion uses `k256::Scalar::invert`.

Branches cover fixed public roles, boundary canonicality, opened protocol
values, public point equations, and terminal validity checks. The zero-share
branches reveal whether an invalid zero share was supplied; this is an explicit
abort condition in the protocol. They do not branch on a recoverable bit of a
valid wallet or triple secret.

Polynomial generation retries only when a fresh random coefficient is zero.
The retry decision depends on discarded CSPRNG output. Polynomial evaluation
has a fixed two-coefficient shape. Commitment digests use constant-time byte
comparison, and private-share equations use constant-time projective-point
comparison.

The OT extension uses fixed public bounds for expansion, transposition,
carry-less multiplication, hashing, and all 128 consistency equations. Secret
bits use constant-time selection. A single terminal branch reveals only the
aggregate proof validity required by the protocol.

The optimized native arm64 assembly audit analyzed 21 OT-extension functions
with zero errors. Its single warning is the bounds branch in
`ChoiceBits::bit`; its index is a fixed public loop counter. Wasm compiled
constant-time evidence remains open under assumption `A-CT`.

The checkpoint 6 native arm64 audit analyzed 12 MTA functions with zero errors.
Seven warnings map to public context/index/role and two-triple bundle checks or
canonical parsing of peer-supplied response values. No warning depends on local
operands, masks, OT choices, or output shares.

Checkpoint 7 source review found no secret division, remainder, indexing,
variable-length loop, or secret-dependent control-flow branch in the triple
finalizer. Optimized arm64 inspection covered nine emitted finalization and
boundary functions with zero errors and eight warnings. The warnings map to
public role dispatch, malformed/identity rejection, peer-proof validity, and
terminal accept/abort. Generic preparation functions and Wasm output remain
open under assumption `A-CT`.
