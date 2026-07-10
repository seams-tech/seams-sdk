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
