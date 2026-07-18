# Fixed base random OT v1

Status: implemented and integrated. The malicious OT extension, MTA, proof
integration, and terminal triple finalization consume the sealed outputs in the
complete fixed backend. Independent cryptographic review remains the promotion
gate.

## Source mapping

The behavioral source is NEAR `threshold-signatures` commit
`db609be5021eb9d794f577601f422818fbdfe246`, Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`.

| ID | Pinned source evidence | Purpose-built implementation | Alignment | Confidence |
| --- | --- | --- | --- | --- |
| `BROT-PARAM-01` | `src/crypto/constants.rs` fixes `SECURITY_PARAMETER = 128`; `batch_random_ot.rs:76-100` and `232-257` run one exchange per security bit | `src/triples/base_rot.rs:16-18,322-371,374-417` uses fixed arrays of exactly 128 OTs and 16-byte keys | Full fixed-parameter match | `1.00` |
| `BROT-SENDER-01` | `batch_random_ot.rs:56-112` samples `y`, sends `Y = yG`, and derives branches from `yX` and `yX - yY` | `src/triples/base_rot.rs:298-320,374-417` computes `Y = yG`, `K0 = H(yX)`, and `K1 = H(y(X-Y))` | Full mathematical match | `1.00` |
| `BROT-RECV-01` | `batch_random_ot.rs:206-262` samples choice `d` and `x`, sends `X = xG + dY`, and derives `H(xY)` | `src/triples/base_rot.rs:322-371` uses constant-time point selection for the same equation and derives the chosen key from `xY` | Full mathematical match | `1.00` |
| `BROT-POINT-01` | `batch_random_ot.rs:227-229` relies on point deserialization to reject the identity | `src/triples/base_rot.rs:114-166,374-390,505-511` parses all received points as non-identity and also rejects `X - Y = identity` | Code is stronger at the boundary | `0.98` |
| `BROT-BIND-01` | `batch_random_ot.rs:22-51` hashes the OT index, `X`, `Y`, and the Diffie-Hellman point under a fixed domain | `src/triples/base_rot.rs:449-481` binds those values plus scope, pair, triple index, sender role, and branch in a tagged SHA-256 transcript | Full KDF inputs with stronger session and role binding; deliberate domain divergence | `1.00` |
| `BROT-STATE-01` | NEAR routes the exchange through generic asynchronous channels | `src/triples/base_rot.rs:175-266` exposes consuming Client and SigningWorker role states and fixed message types; the eleven-round driver and canonical codec carry them through the fixed transport | Full purpose-built state and transport specialization | `0.98` |

Line numbers refer to the pinned source and the checkpoint-4 formatted source.
Later edits must update this table alongside the code.

## Equations

For each `i` in `0..128`, the sender samples non-zero `y` once and the receiver
samples a private choice bit `d_i` and safe non-zero `x_i`:

```text
Y = yG
X_i = x_i G + d_i Y

sender key 0 = H(context, i, 0, Y, X_i, y X_i)
sender key 1 = H(context, i, 1, Y, X_i, y (X_i - Y))
receiver key = H(context, i, d_i, Y, X_i, x_i Y)
```

When `d_i = 0`, `yX_i = x_iY`. When `d_i = 1`,
`y(X_i - Y) = x_iY`. The receiver therefore learns exactly its selected key
under the Diffie-Hellman assumption and random-oracle model inherited from the
pinned construction.

## Boundary and state invariants

- `Y`, every `X_i`, and every `X_i - Y` must be non-identity curve points.
- Receiver sampling excludes `x_i G = Y` and `x_i G = -Y` before applying the
  secret choice. The rejection branch is independent of `d_i`.
- All peer messages bind the signing-scope digest, presign-pair digest, and
  triple index before cryptographic processing.
- Separate Client and SigningWorker message/state types prevent role confusion.
- The KDF additionally binds the base-ROT sender role, so reflected public
  messages produce unrelated keys.
- Sender secrets, receiver choices, and all derived keys zeroize on drop.
- Outputs expose no production key extraction API. The malicious OT extension
  consumes the sealed output types inside the crate.

## Transcript registry

Every field is absorbed as `tag_u16_be || length_u32_be || value`.

| Tag | Value |
| --- | --- |
| `1` | `seams/router-ab-ecdsa-presign/base-rot/v1` |
| `2` | `secp256k1+sha256` |
| `3` | 32-byte signing-scope digest |
| `4` | 32-byte presign-pair digest |
| `5` | triple index: `0` or `1` |
| `6` | base-ROT sender role: Client `1`, SigningWorker `2` |
| `7` | two-byte big-endian OT index |
| `8` | sender branch or receiver choice: `0` or `1` |
| `16` | compressed `Y` |
| `17` | compressed `X_i` |
| `18` | compressed Diffie-Hellman point |

The 32-byte SHA-256 result is truncated to 16 bytes, matching the 128-bit base
OT security parameter.

## Claim boundary

This layer implements base random OT. Active security for the final
multiplication path depends on the integrated malicious OT-extension
consistency check used before MTA. No triple can be emitted from base-ROT output
alone.
