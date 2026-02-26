# Formal Verification Workspace

This directory isolates all formal verification assets from product/runtime code.

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
- `make -C formal-verification parity`: run signer-core parity tests used by formal gates.
