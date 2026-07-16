# Fixed 2-of-2 ECDSA Online Lifecycle v1

Status: checkpoint 10 implementation map. The persistent lifecycle contract is
complete; production promotion remains blocked on its concrete adapters and
the other integration requirements identified below.

## Scope and roles

The online kernel has exactly two roles:

- Client emits one signature share; and
- SigningWorker combines that share with its local share, verifies the final
  signature, and returns the recoverable 65-byte signature.

Participant identifiers, threshold, role ordering, and Lagrange coefficients
are fixed by the implementation. The public API has no generic participant
collection, threshold, or role selector.

## One-use state machine

Each role follows the same consuming lifecycle:

```text
available material
    -> reserved material
    -> committed-use material
    -> output or error
    -> dropped and zeroized
```

`reserve` consumes available material. `commit` consumes reserved material and
binds it to the online request's expected presignature point `R`. The share and
finalization entrypoints consume committed-use material. A failed transition
also consumes its input, so the same Rust value cannot re-enter the protocol.

The kernel deliberately has no reusable completed-session value.
`router-ab-ecdsa-pool` now defines the exact persistent record key, revisions,
forward-only transitions, terminal reasons, and compare-and-swap mutations.
The browser and SigningWorker adapters must atomically apply that contract
before releasing an online output. They must retain a tombstone after timeouts,
ambiguous delivery, crashes, and peer aborts.

## Requirement-to-code map

| ID | Requirement | Implementation evidence | Classification | Confidence |
| --- | --- | --- | --- | --- |
| OL-STATE-01 | Client and SigningWorker use fixed, role-specific one-use states. | `src/lib.rs:68-81`, `src/lib.rs:83-122`, `src/lib.rs:185-203` | Full in-kernel | 1.00 |
| OL-STATE-02 | Online output is reachable only from committed-use material and consumes that state. | `src/lib.rs:215-273` | Full in-kernel | 1.00 |
| OL-BIND-01 | A committed use is bound to the presignature point selected by the request. | `src/lib.rs:205-213` | Full in-kernel | 1.00 |
| OL-INPUT-01 | Points and scalars are parsed once into precise internal values; identity points, non-canonical scalars, and zero `k` shares are rejected. | `src/lib.rs:124-183`, `src/lib.rs:330-349` | Full in-kernel | 1.00 |
| OL-ZEROIZE-01 | Secret material, digest, entropy, and HKDF candidates are zeroized when their owner is dropped or the derivation finishes. | `src/lib.rs:60-66`, `src/lib.rs:136-144`, `src/lib.rs:299-320` | Full in-kernel | 0.99 |
| OL-SHARE-01 | The fixed Client and SigningWorker equations reproduce the pinned NEAR semantic outputs. | `src/lib.rs:223-257`; `../router-ab-ecdsa-near-oracle-tests/tests/online_parity.rs` | Full for the pinned valid trace | 1.00 |
| OL-LOW-S-01 | Finalization selects low-`s` without a secret-dependent branch. | `src/lib.rs:256-257` | Full in-kernel | 1.00 |
| OL-FINAL-01 | SigningWorker verifies the final prehash signature and derives a recovery ID for the registered group public key before output. | `src/lib.rs:259-290` | Full in-kernel | 1.00 |
| OL-PERSIST-01 | Reserve, commit, consumption, and destruction survive crashes and ambiguous delivery. | `../router-ab-ecdsa-pool/src/lib.rs:183-202`, `../router-ab-ecdsa-pool/src/lib.rs:213-698`; concrete browser and SigningWorker adapters remain absent. | Partial; adapter integration blocker | 1.00 |
| OL-REGISTRY-01 | The group public key and role shares are bound to the authenticated root-share commitment registry. | The kernel accepts the already-resolved group public key. Registry verification remains upstream. | Missing integration; production blocker | 1.00 |
| OL-CONTEXT-01 | Wallet, account, scope, pair, and request identities bind the pool record and online receipt. | The online kernel binds `R`, digest, group key, entropy, and fixed participant IDs. `../router-ab-ecdsa-pool/src/lib.rs:11-181` and `:331-346` bind persistent wallet, account, scope, pair, role, epochs, protocol, request, and reservation identities. Boundary codecs and adapters remain absent. | Partial; adapter integration blocker | 1.00 |
| OL-CORPUS-01 | Valid and invalid behavior matches the complete NEAR oracle corpus. | One exact valid trace and three high-value negative cases are implemented. | Partial | 1.00 |

Line references describe checkpoint 10 and must be refreshed when the source
layout changes.

## Security boundary

The Rust type system establishes one-use behavior for a value inside one
process execution. The persistent lifecycle crate establishes the valid record
states and mutations. Database transactions and Durable Object execution must
establish atomicity across retries and crashes. The storage integration must
own:

1. authenticated lookup of the exact wallet, account, scope, role, and pair;
2. atomic transition from available to reserved before either party starts;
3. terminal consumption before any signature share or final signature crosses
   the process boundary;
4. permanent tombstoning for success, rejection, timeout, crash recovery, and
   ambiguous delivery; and
5. rejection of cross-wallet, cross-account, cross-scope, cross-pair, and
   cross-request substitution.

These are production requirements. The record schema and atomic transition API
are isolated for review in
`../router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md`. Concrete
adapter evidence is still required.

## Verification evidence

Checkpoint 10 records all checkpoint 9 evidence plus:

- a dependency-free persistent pool lifecycle crate with exact bindings,
  monotonic revisions, forward-only consuming transitions, and absorbing
  tombstones;
- eight unit tests covering the valid lifecycle, stale compare-and-swap,
  timeout, substitution, crash, ambiguous delivery, peer abort, expiry, and
  epoch retirement;
- a compile-fail test proving terminal tombstones expose no revival path; and
- expanded production dependency/source guards covering the pool crate.

Checkpoint 9 also records:

- online unit test: exact frozen Client share and final signature, plus altered
  share, mismatched `R`, and wrong-public-key rejection;
- online compile-fail tests: no direct use from available material and no
  second commit of a consumed reservation;
- oracle test: exact Client share and final signature parity against the pinned
  NEAR implementation;
- automated normal and Wasm resolved-graph guards: no `threshold-signatures`,
  `signer-core`, futures family, generic threshold runtime, or unrelated curve
  library in the isolated production crates and online Client wrapper;
- browser Wasm release: 68,477 bytes raw, 31,430 bytes gzip-9, and 26,282 bytes
  Brotli-11; and
- ARM64 release static constant-time scan: zero errors; warnings are confined
  to public boundary parsing and public commitment mismatch control flow.

The static constant-time scanner is heuristic. Compiled-Wasm inspection and
target-runtime timing evidence remain required before production promotion.
The current NEAR-backed presign Client and SigningWorker wrappers are outside
the promotion graph and must be replaced before these guards expand to the
complete deployed surface.
