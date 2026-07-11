# Host-only output-sharing reference v1

Status: frozen executable-reference specification

This document fixes the deterministic host-only arithmetic used to test
randomized output sharing for the Ed25519 Router A/B functionality. It defines
typed reference inputs, exact share equations, and a strict six-case JSON
corpus. The implementation belongs to generator, test, and formal-evidence
code only.

The reference establishes arithmetic reconstruction and request-family type
separation. Active-protocol randomness, private output translation, output
authentication, recipient encryption, anti-equivocation, package construction,
receipts, and wire encodings remain outside this specification.

All inputs, coins, joined values, and shares in this reference are public
synthetic evidence. Variable-time host arithmetic is permitted here. Production
secret processing cannot depend on the generator crate.

## 1. Domains and byte order

- Scalar values are canonical 32-byte little-endian encodings in
  `Z_l`, where
  `l = 2^252 + 27742317777372353535851937790883648493`.
- Seed values are 32-byte little-endian encodings in `Z_(2^256)`.
- Every hexadecimal field is lowercase and has exactly 64 characters.
- A scalar coin or scalar share with an integer encoding greater than or equal
  to `l` is invalid.
- Every 32-byte seed coin is valid.
- A canonical zero scalar coin or resulting individual additive scalar share is
  valid. Its public verification-point commitment is the Edwards identity.
  Semantic package validation rejects identity only after A/B shares are joined
  into the final client or SigningWorker signing share.

## 2. Activation-family sharing

Registration, recovery, and refresh use the activation-family joined outputs
from the fixed clear arithmetic:

```text
x_client_base = a + tau mod l
x_server_base = a + 2*tau mod l
```

The host-only reference accepts two independently typed fixture coins:

```text
R_client <- Z_l
R_signing_worker <- Z_l
```

It computes:

```text
client_A = R_client
client_B = x_client_base - R_client mod l

signing_worker_A = R_signing_worker
signing_worker_B = x_server_base - R_signing_worker mod l
```

Reconstruction must satisfy:

```text
client_A + client_B mod l = x_client_base
signing_worker_A + signing_worker_B mod l = x_server_base
```

The client and SigningWorker coins, shares, and reconstruction helpers use
different Rust types. Deriver A and Deriver B shares also use different Rust
types. Activation-family outputs contain no seed share.

Activation continuation consumes already-created pending metadata and samples
zero new output shares, so it has no case in this corpus.

## 3. Export sharing

Authorized export uses the joined RFC 8032 seed `d` from the fixed clear
arithmetic. For a host-only fixture coin `U`:

```text
U <- Z_(2^256)
d_A = U
d_B = d - U mod 2^256
d_A + d_B mod 2^256 = d
```

The export API accepts `ExportOracleOutput`. Its result contains only the two
seed-share types. SigningWorker scalar shares cannot be represented in that
result.

## 4. Core API boundary

The non-serializable reference API has two disjoint entrypoints:

```rust
pub fn share_host_only_activation_outputs_v1(
    output: &ActivationOracleOutput,
    coins: HostOnlyActivationOutputCoinsV1,
) -> HostOnlyActivationOutputSharesV1;

pub fn share_host_only_export_seed_v1(
    output: &ExportOracleOutput,
    coin: HostOnlySeedOutputCoinV1,
) -> HostOnlySeedExportSharesV1;
```

All core coin, share, role-view, and aggregate types omit Serde. Share
constructors are private. Fixture byte access is explicit. The module contains
no operating-system randomness or deterministic pseudo-random generator.

The portable corpus DTO is opaque and `Serialize`-only. Its sole parser accepts
bytes only when they equal the canonical pretty-printed six-case corpus with
exactly one trailing LF. This exact-byte boundary rejects invalid UTF-8, BOMs,
CRLF, reordered or duplicate fields, whitespace drift, malformed hex,
noncanonical scalars, changed headers or cases, and missing or extra final
newlines. General JSON deserialization into the corpus domain type is absent.

## 5. Strict portable corpus

The committed corpus is
`vectors/ed25519-yao-output-sharing-v1.json` with:

```text
schema = seams:router-ab:ed25519-yao:output-sharing-vectors:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = host_only_deterministic_output_sharing_v1
```

Top-level field order is:

```text
schema, protocol_id, evidence_scope, cases
```

Each case is a closed tagged union with `output_family` and `vector`.

### 5.1 Activation case shape

`output_family = activation`. Vector field order is:

```text
case_id
request_kind
host_only_source_reference
host_only_joined_outputs
host_only_reference_randomness
role_output_shares
```

`request_kind` is exactly one of `registration`, `recovery`, or `refresh`.
The source reference contains an existing arithmetic `case_id` and a complete
copy of its eight `VectorInputsV1` fields. The remaining shapes are:

```text
host_only_joined_outputs:
  x_client_base_hex
  x_server_base_hex

host_only_reference_randomness:
  r_client_hex
  r_signing_worker_hex

role_output_shares:
  deriver_a:
    client_scalar_share_hex
    signing_worker_scalar_share_hex
  deriver_b:
    client_scalar_share_hex
    signing_worker_scalar_share_hex
```

### 5.2 Export case shape

`output_family = export`. Vector field order is:

```text
case_id
host_only_source_reference
host_only_joined_output
host_only_reference_randomness
role_output_shares
```

The branch-specific shapes are:

```text
host_only_joined_output:
  joined_seed_hex

host_only_reference_randomness:
  u_hex

role_output_shares:
  deriver_a:
    seed_share_hex
  deriver_b:
    seed_share_hex
```

Unknown, missing, null, reordered, duplicated, or cross-family fields are
invalid.

## 6. Canonical cases

The corpus contains exactly these cases in this order:

| # | Case id | Family / request | Source arithmetic case | Host-only coins |
|---:|---|---|---|---|
| 1 | `registration_activation_shares_zero_coins_v1` | activation / registration | `registration_rfc8032_vector_one_v1` | client `0`, SigningWorker `0` |
| 2 | `recovery_activation_shares_small_coins_v1` | activation / recovery | `recovery_clear_arithmetic_v1` | client `1`, SigningWorker `2` |
| 3 | `refresh_activation_shares_boundary_coins_v1` | activation / refresh | `refresh_clear_arithmetic_v1` | client `l - 1`, SigningWorker `l - 2` |
| 4 | `export_seed_shares_zero_coin_v1` | export | `export_rfc8032_vector_two_v1` | `U = 0` |
| 5 | `export_seed_shares_one_coin_v1` | export | `export_rfc8032_vector_two_v1` | `U = 1` |
| 6 | `export_seed_shares_max_coin_v1` | export | `export_rfc8032_vector_two_v1` | `U = 2^256 - 1` |

Each source input copy makes the corpus independently reproducible without
loading another committed JSON file. The verifier recomputes `d`, SHA-512,
clamping, reduction modulo `l`, `tau`, `x_client_base`, and
`x_server_base` from those inputs before checking the sharing equations.

## 7. Evidence claim and blockers

Passing Rust and independent Python verification establishes:

- strict branch shapes and exact case order;
- canonical scalar-domain parsing;
- activation and export arithmetic reconstruction;
- export-only seed sharing at the serialized and Rust type boundaries;
- deterministic boundary coverage for zero, small, and wraparound coins.

It does not establish coin unpredictability, unbiased distributed sampling,
party-view privacy in a running protocol, output authenticity, ciphertext
recipient binding, malicious security, or deployable serialization. Those
claims require the selected active Yao construction and remain Phase 4/6B
work.
