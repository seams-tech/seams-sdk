# Ed25519 Yao Passive Benchmark Suite V1

Status: **benchmark-only, passive/semi-honest, non-promotable**

Suite identifier:

```text
ed25519_yao_phase3_passive_benchmark_v1
```

This suite exists to measure the real symmetric-key Yao kernel before
production hardening. It is compile-time fixed and has no runtime negotiation or
conversion into a production suite.

## Labels and free XOR

- Security parameter and label width: 128 bits / 16 bytes.
- Label byte order: byte 0 is most significant for GF(2^128) doubling.
- Point-and-permute select bit: bit 0 of byte 15.
- The circuit-global delta is sampled as 16 bytes and bit 0 of byte 15 is set.
- For every wire, `W1 = W0 XOR delta`.
- XOR: `C0 = A0 XOR B0`; evaluation returns `A XOR B`.
- INV: `C0 = A0 XOR delta`; evaluation retains the active input label.
- Labels and delta zeroize on drop and expose no raw public serialization API.

## Public gate tweaks

Each Half-Gates hash call receives a unique 128-bit public tweak:

```text
BE64(session_domain) || BE64((gate_ordinal << 1) | half)
```

`session_domain` is nonzero and unique for the benchmark execution.
`gate_ordinal` is a canonical schedule ordinal restricted to `0..2^63`.
`half = 0` selects the generator half and `half = 1` selects the evaluator
half. The encoding is injective over the tuple.

## Garbling hash

The benchmark instantiates the Half-Gates paper's ideal-permutation hash with
AES-128 under the all-zero public fixed key:

```text
K = double_gf128(label) XOR tweak
H(label, tweak) = AES-128-fixed-key(K) XOR K
```

`double_gf128` uses the polynomial `x^128 + x^7 + x^2 + x + 1`, big-endian
bytes, and branchless reduction by `0x87`. The RustCrypto `aes` dependency is
pinned and supplies hardware AES where available or its portable constant-time
implementation. Native and generated-WASM output require separate inspection.

For this benchmark, fixed-key AES is modeled as a random permutation and the
construction relies on the circular-correlation robustness used by free-XOR and
Half-Gates. This is a benchmark assumption, not a production proof claim. Phase
6A must either justify and review it for the selected composition or replace the
benchmark hash. See the [Half-Gates analysis](https://eprint.iacr.org/2014/756)
and the [circular-correlation robustness analysis](https://eprint.iacr.org/2019/074).

## Half-Gates AND

For zero labels `A0`, `B0`, delta `R`, select bits `pa`, `pb`, and distinct
tweaks `j`, `j'`:

```text
A1  = A0 XOR R
B1  = B0 XOR R
TG  = H(A0,j) XOR H(A1,j) XOR (pb * R)
WG0 = H(A0,j) XOR (pa * TG)
TE  = H(B0,j') XOR H(B1,j') XOR A0
WE0 = H(B0,j') XOR (pb * (TE XOR A0))
C0  = WG0 XOR WE0
```

The table is exactly `TG || TE`, or 32 bytes per AND gate.

For active labels `A`, `B` with select bits `sa`, `sb`:

```text
WG = H(A,j) XOR (sa * TG)
WE = H(B,j') XOR (sb * (TE XOR A))
C  = WG XOR WE
```

All multiplication by a bit is implemented as branchless conditional XOR.

## Randomness and scope

Deterministic labels, delta, and session domains are permitted only in vectors
and known-answer tests. Every benchmark run outside those fixtures must use OS
cryptographic randomness. This version supplies functional and performance
evidence only. It claims no malicious security, active correctness, OT
security, input consistency, private-output security, replay protection,
transport authentication, production constant-time property, or release
authority.
