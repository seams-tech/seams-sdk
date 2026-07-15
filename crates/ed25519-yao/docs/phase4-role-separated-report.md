# Phase 4 Role-Separated Passive Ceremony Report

Date: 2026-07-12

Status: local viability evidence only. The implementation is benchmark-only,
semi-honest, and unavailable to production routes.

## Implemented composition

The Phase 4 activation and export circuits use fresh joint output coins from A
and B. Circuit outputs are ordered as A shares followed by B shares. A retains
translation material only for its output wires. B receives translation bits
only for its output wires and returns A's selected labels without a semantic
mapping.

Evaluator inputs use direct A labels and fresh Chou-Orlandi/IKNP selected B
labels. A is always the garbler and OT-extension sender. B is always the
evaluator and OT-extension receiver. There is no runtime family/profile
negotiation in the cryptographic core.

The online dependency order is:

1. B sends the fresh base-OT offer.
2. A sends base-OT choices and its direct input labels.
3. B sends the IKNP correction matrix.
4. A sends masked B-input labels, B-output translation bits, and the garbled
   table. The table follows OT completion and is ready for Phase 5 streaming.
5. B sends only A's opaque selected output labels.

Both roles hash the returned-label message into the same terminal transcript.
Each role then constructs only its own typed recipient packages. Activation
produces separate Client and SigningWorker packages; export produces one
export-recipient seed package. The process API no longer returns raw decoded
shares. These benchmark packages are plaintext and deliberately non-production;
recipient encryption and full identity/lifecycle binding remain Phase 6B
stop-ships.

## Frozen circuit results

| Family | Inputs | Outputs | AND gates | Table bytes | Schedule bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Activation | 3,072 | 1,024 | 65,780 | 2,104,960 | 2,676,456 |
| Export | 1,536 | 512 | 1,275 | 40,800 | 56,382 |

Activation adds 98,048 table bytes, or about 4.9%, over the Phase 3 joined-output
baseline. Its table is about 2.008 MiB.

## Exact local protocol bytes

| Component | Activation | Export |
| --- | ---: | ---: |
| Four OT frames, including OT headers | 82,112 | 45,248 |
| A direct-label role message | 24,732 | 12,444 |
| B-output translation role message | 220 | 188 |
| Garbled table payload | 2,104,960 | 40,800 |
| Returned A-label role message | 8,348 | 4,252 |
| Local total before process-frame prefixes | 2,220,372 | 102,932 |
| Two-process harness total with eight 4-byte prefixes | 2,220,404 | 102,964 |

After the A/B exchange, each activation role emits two distinct 216-byte
recipient packages. Each export role emits one 184-byte package. These 864
activation bytes or 368 export bytes are recipient-output artifacts and are not
part of the direct A-to-B totals above.

Phase 5 will replace the whole-table process frame with the canonical bounded
stream grammar. These numbers therefore describe the Phase 4 binary harness,
not final transport bytes.

## Native two-process wall latency

Environment: Apple arm64 host, optimized Rust release build, two child OS
processes connected by a local Unix domain socket, 20 iterations per family.
Process startup is included.

| Family | p50 | p95 |
| --- | ---: | ---: |
| Activation | 90.498 ms | 91.658 ms |
| Export | 32.977 ms | 33.394 ms |

Per-role CPU uses `/usr/bin/time -p` user plus system time. Its 10 ms display
resolution makes this a coarse distribution:

| Family/role | CPU p50 | CPU p95 |
| --- | ---: | ---: |
| Activation A | 30 ms | 30 ms |
| Activation B | 40 ms | 40 ms |
| Export A | < 10 ms | < 10 ms |
| Export B | < 10 ms | < 10 ms |

These measurements include terminal recipient-package construction and
serialization. They are local-host evidence, not a Cloudflare Worker or
cross-account latency claim. Phase 9 must replace them with Worker CPU and wall
distributions.

## Isolation and correctness evidence

- Activation and export pass in two independently spawned OS processes.
- Each child is constructed with only its role input and prints only its typed,
  role-specific recipient packages.
- The parent recipient harness strictly parses the distinct packages, validates
  each scalar-to-point commitment, reconstructs the committed activation
  outputs or export seed only after both children exit, and checks
  `2 * X_client - X_server = A_pub`.
- Fixed codecs reject wrong lengths, oversized frames, malformed family/session
  bindings, trailing bytes, cross-family messages, and cross-session replay.
- Package codecs additionally reject role, recipient, family, output-kind,
  transcript, canonical-scalar, canonical-point, subgroup, commitment, and
  public-relation mismatches.
- Symmetric non-uniqueness tests exhibit multiple valid opposite-role package
  views for one fixed A view and for one fixed B view. Source guards keep raw or
  joined output fields out of every completed-role type and benchmark facade.
- Activation outputs are parsed as canonical scalars before release.
- The full native suite, strict Clippy, generator parity, and WASM build pass.

## Constant-time qualification

The original source-level qualification missed an optimizer-introduced secret
branch in IKNP row selection. Optimized ARM64 emitted `tbz` on a base-OT choice,
and the exact Deriver A Worker WASM emitted `i32.eqz; br_if` around the row XOR.
That invalidated the earlier branchless-OT statement.

The kernel now routes secret label, IKNP row, output-label, and GF reduction
selection through optimizer-resistant `subtle::Choice` and
`ConditionallySelectable` operations. Zero random scalars are repaired through
the same constant-time selection path instead of secret-dependent resampling.
`scripts/check_constant_time_codegen.mjs` clean-builds optimized host Phase 9
assembly and the exact cross-account Deriver A/B Worker WASM artifacts. It
checks source-mapped label and IKNP selection, rejects the vulnerable WASM
load/shift/mask/branch shape, requires the retained mask sequence in Deriver A,
and qualifies its matcher against safe and intentionally vulnerable fixtures.

The complete optimized ARM64 library scan reports zero analyzer error-level
variable-time instructions. The focused native and Worker-WASM codegen gate
passes. This is benchmark-kernel evidence; production constant-time and
microarchitectural review remain attached to the Phase 6B-selected suite and
runtime.

## Phase 4 closure and production boundary

The local Phase 4 viability gate is closed. A specification-to-code audit found
the joint-coin circuits, fresh passive OT, private-output split, transcript
binding, separate-process execution, package boundaries, public relation, and
party-view evidence aligned with the Phase 4 benchmark claim.

This does not promote the in-house OT or package format to production. Recipient
encryption, complete wallet/account/key/epoch/authorization/replay binding,
authenticated transport, package-digest receipts, Deriver signatures, and
review of the selected production OT/composition remain explicit Phase 6B
requirements.
