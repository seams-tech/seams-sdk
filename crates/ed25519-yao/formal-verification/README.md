# Ed25519 Yao Formal Verification

Status: **FV1 local mechanical scaffold; clean-checkout bootstrap pending; no
protocol-security claim**

This directory contains isolated verification infrastructure for the parts of
Ed25519 Yao that exist today. The checked surface is deliberately narrow:

- frozen protocol, circuit, output-schema, and manifest identifiers;
- draft-manifest digest roles and metric shape;
- the visible-ASCII four-field application-binding encoder, including positive
  immutable `keyCreationSignerSlot`, stable-context encoding, role-local
  contribution KDF, five-case arithmetic corpus, and one-case KDF-continuity
  corpus;
- host-only synthetic same-root client-KDF continuity and opposite-delta refresh
  arithmetic evidence;
- a strict four-case host lifecycle-continuity corpus covering recovery,
  recovery-origin activation, refresh, and refresh-origin activation;
- nonserializable five-branch semantic lifecycle types and a narrow synthetic
  activation-metadata continuation, with the other four evaluators absent;
- the proof-system-neutral provenance statement and epoch contract, which has
  no proof-artifact implementation yet;
- 128 deterministic differential cases regenerated and checked by an
  independent standard-library Python implementation;
- the clear generator's `wrapping_add_le_256` and `clamp_rfc8032` boundaries;
- executable production-to-mirror anti-drift checks.

There is no garbled-circuit engine, streaming protocol, active-security suite,
ticket state machine, or privacy theorem in this scaffold. A passing command
does not establish Yao security.

## Tracks

- [`verus/`](verus/README.md) contains the standalone unpublished Verus mirror.
- [`lean-boundary/`](lean-boundary/README.md) contains the pinned Aeneas/Charon
  extraction of two implemented pure generator helpers.
- [`lean-model/`](lean-model/README.md) contains a model-only rehearsal of the
  manifest family and field-count shape. It has no production anti-drift bridge
  yet.
- [`tasks/`](tasks/Cargo.toml) owns host-only command orchestration. Production
  crates have no dependency on this task runner or on the clear oracle.
- `tools/ed25519-yao-verifier` is a standard-library Python implementation that
  independently reproduces the application binding, stable-context binding,
  contribution KDF, clear arithmetic, and Edwards25519 point encodings.
- [`docs/`](docs/) records sources, obligations, assumptions, and the current
  compliance baseline.

The tracks are complementary. Verus checks an executable Rust-shaped mirror
whose proved constants are compared with production, Aeneas checks a narrow
Rust-to-Lean translation boundary, and Lean checks explicit model-only
statements. No track upgrades the others into a cryptographic security proof.

## Commands

Run focused checks from the repository root:

```sh
cargo yao-fv vectors-check
cargo yao-fv cross-language-check
cargo yao-fv parity
cargo yao-fv anti-drift
cargo yao-fv lean-check
cargo yao-fv aeneas-check
cargo yao-fv verus-check
```

`anti-drift` is intentionally independent of Verus discovery. It remains
usable with an ordinary Rust toolchain.

`cross-language-check` runs the Python mutation suite, verifies the committed
five-case arithmetic, one-case KDF-continuity, and four-case host
lifecycle-continuity corpora, generates 128 deterministic public-test cases,
independently regenerates every input from the fixed seed, and verifies every
output. The application-binding checks cover `walletId`,
`nearEd25519SigningKeyId`, `signingRootId`, and positive immutable
`keyCreationSignerSlot`. `nearAccountId`, mutable/current signer slots,
versions, and epochs are absent from that binding.

The full local gate is:

```sh
cargo yao-fv all
make -C crates/ed25519-yao/formal-verification check
just ed25519-yao-fv
```

The full gate requires the exact source and verifier pins recorded in
[`toolchain.toml`](toolchain.toml). Missing or mismatched tools are failures.
Bootstrap Aeneas and Charon with:

```sh
crates/ed25519-yao/formal-verification/lean-boundary/scripts/setup-aeneas.sh
```

The bootstrap currently resolves its OCaml packages through the ambient opam
repository. Locking that package environment and reproducing the entire gate
from empty caches remain the final FV1 reproducibility tasks.

The repository-wide `check:formal-verification` command still owns the HSS
gate. Yao joins that CI aggregate after the clean-checkout Aeneas installation
path is added; HSS remains until hard cutover.

## Evidence and scope

- [Spec corpus](docs/spec-corpus.md)
- [Proof obligations](docs/proof-obligations.md)
- [Assumption ledger](docs/assumption-ledger.md)
- [Compliance baseline](docs/compliance-baseline.md)
- [Full phased plan](../docs/formal-verification-plan.md)
- [Protocol implementation plan](../../../docs/yaos-ab.md)

Generated Lean files are committed. Charon LLBC remains a transient intermediate
because its internal identifier ordering is nondeterministic even when the
resulting Lean is stable. `aeneas-check` regenerates the Lean files, compares
them byte for byte, builds both named targets, and requires their `.olean`
outputs. Focused source guards reject `sorry`, `admit`, and `axiom` in
project-owned Lean plus unchecked Verus declaration attributes in the mirror.
