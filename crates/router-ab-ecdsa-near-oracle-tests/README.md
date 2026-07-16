# Router A/B ECDSA NEAR oracle tests

This crate owns dev-only compatibility evidence for the purpose-built fixed
two-party ECDSA implementation. Production crates have no dependency on this
package or on `threshold-signatures`.

The oracle is frozen to NEAR commit
`db609be5021eb9d794f577601f422818fbdfe246` and Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`. The lockfile records the exact Git
source.

Run the current deterministic presign corpus:

```sh
cargo test --locked
```

Reproduce dependency resolution with a fresh Cargo home:

```sh
CARGO_HOME="$(mktemp -d)" cargo test --locked
```

The first vector starts at validated committed triple shares and compares the
fixed Client and SigningWorker `R`, `k`, and `sigma` outputs exactly. OT, MTA,
triple generation, rerandomization, and online signing vectors remain Phase 5
work.

The second vector freezes the context-bound production DLog and DLogEq proof
outputs. Pinned NEAR proof fixtures additionally confirm that both transcript
profiles implement the same Schnorr and Chaum-Pedersen verification equations.

The third vector freezes the fixed Client polynomial commitment and opening.
It checks the NEAR private-share equations `E(3) = eG` and `F(3) = fG` for the
SigningWorker recipient coordinate.

The fourth vector freezes the 128-instance Diffie-Hellman base random OT. It
checks that each receiver key equals exactly the sender key selected by the
receiver's private choice bit.

The fifth vector freezes the corrected 768-output random-OT extension. It
checks every sender/receiver correlation and records the extension choices,
post-correlation challenge, verified-acceptance digest, and boundary output
scalars. This is a purpose-built corrected-construction vector; exact NEAR
byte parity does not apply to it.

The sixth vector freezes fixed MTA over the corrected Client-sender extension
output. It records boundary ciphertexts, receiver seeds and first
coefficients, and both additive multiplication shares. Their sum reconstructs
`(a_client + a_worker) * (b_client + b_worker)`.

The pinned NEAR OT-extension row-expansion bytes are intentionally excluded.
The pinned `triples/bits.rs:320-327` finalizes an unkeyed hasher clone and makes
the expanded rows independent of their base-OT keys. The purpose-built
extension must use corrected keyed expansion and a key-sensitivity regression.
