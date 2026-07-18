# Fixed malicious random-OT extension v1

Status: implemented and integrated. MTA consumes the sealed extension output in
the fixed backend. Independent review of the corrected malicious composition
remains mandatory before production promotion.

## Fixed shape

Each role runs the extension once as sender and once as receiver for each
triple-generation session. The shape is compile-time fixed:

- 128 base random OTs;
- 768 released random OTs, covering two `256 + 128` MTA directions;
- 1024 internal rows, consisting of 768 released rows and 256 consistency
  rows; and
- 128-bit rows and 256-bit unreduced consistency products.

The APIs encode Client and SigningWorker roles in separate state and message
types. Every transition consumes its prior state. Outputs remain sealed for
the MTA layer; extraction exists only under `test-utils`.

## Protocol

Let the extension sender's base-OT choices form `delta`, and let the extension
receiver hold base-key pairs `(k0_j, k1_j)`. Corrected keyed expansion creates
the transposed matrices `T0` and `T1`. For extension choice row `x_i`, the
receiver sends:

```text
U_i = T0_i xor T1_i xor x_i
```

The sender expands its selected base keys into `T` and computes:

```text
Q_i = T_i xor (U_i and delta)
    = T0_i xor (x_i and delta)
```

After receiving `U`, the sender samples and sends a fresh 32-byte challenge.
The transcript derives eight 128-bit values `chi_i`. The receiver returns:

```text
small_x   = xor_i (x_i * chi_i)
small_t_j = xor_i (T0_i[j] * chi_i), for j in 0..127
```

Multiplication is unreduced carry-less multiplication over binary
polynomials. The sender accepts only when all 128 equations hold:

```text
small_q_j = small_t_j xor (delta_j * small_x)
```

All equations are accumulated into one constant-time validity bit before the
terminal branch. Sender output is unavailable on failure. Receiver output is
held in an awaiting-acceptance state until it receives the digest produced
after the sender verifies the proof. This final message depends on the
authenticated private transport for origin authentication.

The first 768 rows produce scalar pairs:

```text
sender:   (H(i, Q_i), H(i, Q_i xor delta))
receiver: (x_i, H(i, T0_i))
```

`H` is SHA-512 reduced modulo the secp256k1 scalar order. It binds the signing
scope, pair context, triple index, sender role, output index, suite, and row.

## Keyed expansion correction

Each 16-byte base key is absorbed into SHA-256 together with the signing
scope, pair context, triple index, extension-sender role, base index, branch,
block index, domain, and suite. Four blocks create one 1024-bit expanded row.

The pinned NEAR `bits.rs:320-327` updates `hasher_row` with a base key and then
finalizes a separate clone of the unkeyed prefix. Its expanded rows are
independent of every base key. This makes both branch matrices equal and
reveals the receiver choice matrix through `U = T0 xor T1 xor X`.

The purpose-built implementation deliberately diverges at this point. An
exhaustive regression changes each of the 256 base-key branches and requires
its expansion to change. Exact NEAR extension bytes are excluded from parity
claims.

## Pinned source alignment

| Purpose-built behavior | Pinned NEAR source | Disposition | Confidence |
| --- | --- | --- | ---: |
| Pad 768 requests to 1024 rows | `random_ot_extension.rs:35-43` | Preserved with fixed sizes | 1.00 |
| `U`, `Q`, and correlation equation | `correlated_ot_extension.rs:12-60` | Preserved | 1.00 |
| Fresh post-correlation challenge | `random_ot_extension.rs:86-98`, `171-180` | Preserved with a context-bound derivation | 1.00 |
| 128 consistency equations | `random_ot_extension.rs:100-120`, `182-199` | Preserved with fixed arrays and one terminal validity branch | 1.00 |
| Random-OT scalar correlation | `random_ot_extension.rs:21-32`, `122-131`, `201-208` | Preserved equation; domain-separated hash transcript replaces NEAR's transcript RNG | 0.98 |
| Carry-less consistency multiplication | `bits.rs:106-135` | Preserved | 1.00 |
| Base-key row expansion | `bits.rs:303-338` | Corrected; exact-output parity forbidden | 1.00 finding confidence |
| Receiver output release | No upstream acceptance round | Hardened state-machine addition | 1.00 |

The mapping establishes high-confidence behavioral correspondence for the
intended IKNP/KOS equations. It does not establish a standalone security proof
for the complete ECDSA construction.

## Enforced aborts

- signing scope or pair-context mismatch;
- triple-index mismatch;
- role reflection or wrong base-ROT direction;
- any failed correlation-consistency equation; and
- missing, substituted, or altered sender acceptance.

Fixed message arrays reject malformed lengths by construction after boundary
decoding. The canonical eleven-round codec and authenticated Router A/B
transport carry these messages with fixed role, round, context, and length
bindings.

## Secret handling and constant-time boundary

Base keys, extension choices, expanded matrices, `delta`, output scalars, and
in-flight secret states zeroize on drop. Matrix construction, transposition,
carry-less multiplication, output hashing, and all 128 consistency checks run
with fixed public bounds. Selection on secret bits uses constant-time
primitives. The only secret-derived branch is the terminal aggregate
consistency result, which is an explicit protocol abort.

Source review found no secret-indexed lookup or secret-sized loop in this
layer. Native release analysis reports zero division or square-root errors for
the complete presign crate, and the release Wasm scan reports zero unapproved
variable-time operators. Conditional branch dataflow and target-runtime timing
remain explicit non-claims under `A-CT-BRANCH-DATAFLOW` and `A-CT-RUNTIME`.

## Claim boundary

This layer emits sealed random-OT material and makes no standalone ECDSA
security claim. Fixed-size MTA, product-share proofs, terminal committed-triple
checks, authenticated transport, persistent one-use destruction, and online
signing are integrated in the complete local path. Independent review of their
composition remains the production-promotion gate.
