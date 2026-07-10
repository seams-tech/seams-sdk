# Ed25519 Yao Generator

This crate is a host-only reference oracle and test-vector generator for the
fixed Ed25519 derivation functionality. It is intentionally isolated from the
Router, Cloudflare Workers, SDK, transport, oblivious transfer, garbling, and
production protocol code.

The oracle evaluates:

```text
y_A = y_client_A + y_server_A mod 2^256
y_B = y_client_B + y_server_B mod 2^256
d = y_A + y_B mod 2^256, using little-endian addition
h = SHA-512(d)
a_bytes = clamp(h[0..32])
a = a_bytes mod l
tau_A = tau_client_A + tau_server_A mod l
tau_B = tau_client_B + tau_server_B mod l
tau = tau_A + tau_B mod l
x_client_base = a + tau mod l
x_server_base = a + 2*tau mod l
X_client = [x_client_base]B
X_server = [x_server_base]B
A_pub = Ed25519PublicKey(d)
```

Each Deriver input requires all four contributions: `y_client`, `y_server`,
`tau_client`, and `tau_server`. All four tau contributions must use canonical
scalar encodings. Validation errors identify the Deriver role and contribution
side. Callers populate named `RawDeriverAContribution` and
`RawDeriverBContribution` boundary values, which are consumed into validated,
field-specific domain types before evaluation. The oracle also checks the
intended algebra in tests:

```text
2*X_client - X_server = A_pub
```

`ActivationOracleOutput` has no seed field or seed accessor.
`ExportOracleOutput` always contains the reconstructed seed. Separate result
types keep lifecycle output states distinct without optional secret fields.

## Stable context and portable vectors

`StableKeyDerivationContext` freezes the first Yao-era context encoding as:

```text
"seams/router-ab/ed25519-yao/stable-key-context/v1"
|| application_binding_digest[32]
|| participant_id_0_u16_be
|| participant_id_1_u16_be
```

The constructor accepts exactly two distinct, non-zero participant identifiers
and stores them in ascending order. The binding is SHA-256 over
`"seams/router-ab/ed25519-yao/stable-key-context-binding/v1" || encoding`.
Deployment, transport, ticket, request-kind, and authorization values are
excluded because they must not rotate wallet identity.

The committed portable corpus associates one synthetic clear-arithmetic case
with each canonical request kind: registration, activation, recovery, refresh,
and export. Its tagged case union makes an authorized seed result representable
only for export. A separately named `clear_reference_trace` records joined
host-only oracle values for differential implementations; those fields are not
party-visible protocol outputs. The trace includes `y_A`, `y_B`, joined `d`,
`tau_A`, `tau_B`, SHA-512 and clamp intermediates, both scalar bases, public
commitments, and the Ed25519 public key. RFC 8032 seeds and arithmetic wrap
boundaries are present in the portable cases.

Regenerate or check it with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json
```

Generate a larger deterministic differential corpus from public test material
with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-differential \
  --seed-hex 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a \
  --cases 128 \
  --output /tmp/ed25519-yao-differential-v1.json
```

For case index `i` and one-byte field tag `t`, the generator computes
`SHA-512(domain || 0x00 || public_test_seed[32] || BE32(i) || t)`. Tags `0x01`
through `0x08` produce the four `y` and four `tau` inputs; tag `0x09` produces
the application-binding digest. A `y` input uses the first 32 digest bytes. A
`tau` input reduces all 64 digest bytes modulo `l`. The request kind cycles in
registration, activation, recovery, refresh, export order. Differential seeds
are public reproducibility inputs and are never wallet material.

The contribution KDF uses HKDF-SHA256 with frozen extract/expand domains and
fixed A/B, client/server, and `y`/`tau` tags. Its expand info ends with the
stable-context binding digest. A single synthetic client root produces the two
role-separated client contributions; separate synthetic A and B roots each
produce only their own server contribution. The committed
`vectors/ed25519-yao-kdf-v1.json` corpus records the three public synthetic
roots, all eight derived contributions, and the resulting public identity.

The five-case arithmetic corpus continues to record caller-supplied synthetic
contributions. The KDF continuity corpus connects the frozen context and roots
to the same oracle in a separate strict schema. Role-input provenance,
registration anti-bias, recovery/refresh transitions, executable party views,
and active-protocol semantics remain Phase 1 work. The lifecycle boundary is
specified in `docs/ideal-functionalities-v1.md`; its explicit blockers prevent
the fixture corpus from being mistaken for a complete lifecycle model.

This crate must never be linked into a production Worker or exposed as a
protocol API. It contains no message formats, network handlers, persistence,
or production negotiation surface. A `wasm32` build is rejected at compile
time.

Only synthetic inputs and published test-vector material are allowed. These
host-only reference types do not promise zeroization. Real wallet seeds,
derivation contributions, scalar shares, or other production secrets are
forbidden.

Run its checks directly:

```sh
cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml
```
