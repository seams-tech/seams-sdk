# Refactor 89 client bundle-size improvements

Date: July 17, 2026

This note summarizes the client-visible transfer-size improvements from the
fixed 2-of-2 ECDSA refactor. Measurements use gzip level 9 and Brotli level 11
against production release artifacts.

## Operation-level results

| Client lifecycle | Historical gzip path | Current gzip path | Reduction |
| --- | ---: | ---: | ---: |
| Normal pool-hit signing | 329,411 bytes | 39,927 bytes | 289,484 bytes, or 87.9% |
| First registration | approximately 250,506 bytes | 102,165 bytes | 148,341 bytes, or 59.2% |

The normal-signing comparison is conservative. The historical figure contains
the two required Wasm modules and excludes their JavaScript workers. The
current figure includes both the online Wasm and its production worker.

## Normal pool-hit signing

The historical ECDSA client loaded the mixed `eth_signer` Wasm and the separate
role-local ECDSA client Wasm. Their explicitly stripped artifacts totaled
329,411 gzip bytes:

| Historical artifact | Raw | gzip-9 |
| --- | ---: | ---: |
| Mixed `eth_signer` Wasm | 553,854 bytes | 209,954 bytes |
| Role-local ECDSA client Wasm | 324,148 bytes | 119,457 bytes |
| Combined | 878,002 bytes | 329,411 bytes |

The current pool-hit path loads only the purpose-built online Client:

| Current artifact | Raw | gzip-9 | Brotli-11 |
| --- | ---: | ---: | ---: |
| Online Client Wasm | 68,810 bytes | 31,615 bytes | 26,327 bytes |
| Online Client worker | 28,733 bytes | 8,312 bytes | 7,288 bytes |
| Combined | 97,543 bytes | 39,927 bytes | 33,615 bytes |

This removes 289,484 gzip bytes from the normal-signing path, an 87.9%
reduction. Presign code is absent from the pool-hit worker dependency graph and
is fetched only for explicit pool creation or observable background refill.

## First registration

The historical registration dependency used the 243,600-byte gzip mixed
derivation Wasm and its 6,906-byte gzip worker, approximately 250,506 gzip
bytes in total.

The current registration-only path is:

| Current artifact | Raw | gzip-9 | Brotli-11 |
| --- | ---: | ---: | ---: |
| Registration Wasm | 218,036 bytes | 92,334 bytes | 76,739 bytes |
| Registration worker | 46,718 bytes | 9,831 bytes | 8,699 bytes |
| Combined | 264,754 bytes | 102,165 bytes | 85,438 bytes |

This removes 148,341 gzip bytes from first registration, a 59.2% reduction.
The browser waterfall test proves registration fetches the registration Wasm
and makes zero requests for the deferred export Wasm.

## Deferred and lifecycle-specific artifacts

- Explicit recovery and key export load the separate export Wasm only when
  needed. It is 201,962 gzip bytes and 169,324 Brotli bytes.
- Presigning loads only during initial pool creation or background refill. The
  Client presign Wasm and worker total 84,621 gzip bytes.
- A normal pool hit loads neither the presign artifacts nor public EVM utility
  Wasm.

The complete SDK distribution contains more individual files after the split.
That inventory is not the client transfer cost for a single operation.
Operation-selective loading makes registration and routine signing materially
smaller while retaining independently cacheable lifecycle artifacts.

## Source evidence

- `phase0-phase1-wasm-baseline-v1.json` freezes the historical mixed artifacts.
- `phase-e-local-artifacts-v1.json` records the role-specific Wasm and worker
  measurements.
- `registration-package-delta-review-v1.md` records the registration-only
  package split and browser waterfall.
- `final-local-test-receipt-v1.md` records the final production build and
  bundle-budget checks.
