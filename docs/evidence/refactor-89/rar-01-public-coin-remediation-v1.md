# RAR-01 public-coin remediation receipt

Recorded: 2026-07-17

Status: implementation and local verification complete; independent rereview
pending.

## Remediation

The prior production path let the SigningWorker choose all online
rerandomization entropy. The remediated prepare/finalize flow realizes a
two-role public coin while retaining the same two network calls:

1. The Client samples a uniform 32-byte contribution and sends the
   domain-separated SHA-256 commitment in prepare.
2. After prepare admission, the SigningWorker samples its uniform 32-byte
   contribution, persists it in the reserved one-use record, and reveals it in
   the prepare response.
3. The Client computes its signature share from the XOR of both contributions
   and sends its commitment opening in finalize.
4. The SigningWorker derives the commitment from that opening and reconstructs
   the prepare digest. A mismatch reaches the existing terminal
   binding-rejection transition before committed presign material is read.
5. Both roles pass the same XOR result to the unchanged context-bound
   HKDF-SHA3-256 rerandomizer.

The commitment domain is
`router-ab-ecdsa-derivation/client-rerandomization-commitment/v1`. The frozen
Rust/TypeScript vector for 32 bytes of `0x44` is
`S9FX5zM9m3vAn8E1xDn0YqbRjAG_nibOaiphjxKGhmw`.

If either role supplies uniform randomness hidden when the peer selects its
contribution, the XOR remains unpredictable to the corrupt peer. The Client
commitment prevents adaptive opening after the SigningWorker reveal. Selective
abort remains an availability behavior outside the cryptographic claim.

## Verification

| Check | Result |
| --- | --- |
| `cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_derivation_protocol` | 57 passed |
| `cargo test --manifest-path crates/router-ab-ecdsa-online/Cargo.toml` | 2 runtime and 5 compile-fail tests passed |
| `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml` | 332 passed |
| `cargo test --manifest-path crates/router-ab-dev/Cargo.toml` | 77 passed |
| `cargo test --manifest-path crates/router-ab-ecdsa-near-oracle-tests/Cargo.toml` | 20 passed |
| Focused Router A/B ECDSA browser matrix | 43 passed |
| `pnpm build:prod` in `packages/sdk-web` | passed |
| SDK web and server TypeScript checks | passed |
| Router A/B derivation and signing-identity source guards | passed |
| Purpose-built online Wasm budget | 31,615 gzip-9 bytes; 40,000-byte ceiling; passed |
| Native ARM64 online scan | 629 functions; 4,194 instructions; 0 errors; 93 heuristic branch warnings retained as non-claims |
| Fixed-role Wasm opcode scan | all three kernels passed |

The focused browser matrix includes the generated-worker pool-hit waterfall.
It initially caught a stale generated worker calling the previous one-entropy
Wasm API. Rebuilding the production SDK artifacts corrected that drift, and the
same test then passed.

## Current artifacts

| Artifact | SHA-256 | Raw bytes | gzip-9 | Brotli-11 |
| --- | --- | ---: | ---: | ---: |
| Online Client Wasm | `05f441332aa7c410207e3df2fb8d1d73e1c874d351af9e92ac106655a2dab657` | 68,810 | 31,615 | 26,327 |
| Online Client worker | `25c2cb8601e9835a44752821bb9ad610a751de737508af5bc20005cf4a41fcce` | 28,733 | 8,312 | 7,288 |
| Online ARM64 assembly | `e5bdf51abc1c758f1af74e22c7d56cf2fb56fb035559a6b276cebc1f95337eab` | — | — | — |

The digest-pinned corpus guard must be repinned only by the superseding
independent review decision. Until then, its mismatch is expected and prevents
the rejected receipt from being treated as current approval.
