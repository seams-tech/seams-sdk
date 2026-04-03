# Formal Verification Workspace

This directory isolates all formal verification assets from product/runtime code.

Current proof scope covers `signer-core` cryptographic composition/encoding targets and the low-level fixed-function expansion pipeline in `ed25519-hss`.

## Layout

- `coq/`: theorem sources and Coq build files
- `vectors/generated/`: generated proof vectors consumed by Rust parity tests
- `scripts/`: deterministic generation/check scripts
- `docs/`: model boundary and proof inventory docs

## Commands

- `make -C formal-verification check`: run all formal verification gates (proof checks + vector checks).
- `make -C formal-verification proofs`: build Coq proofs.
- `make -C formal-verification coqchk`: kernel re-check compiled Coq artifacts.
- `make -C formal-verification vectors`: regenerate deterministic vector artifacts.
- `make -C formal-verification parity`: run Rust parity tests used by formal gates for in-scope crates.
