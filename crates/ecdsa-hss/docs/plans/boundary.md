# Boundary Note

Date created: April 9, 2026

## Purpose

This note records the intended ownership boundaries inside `ecdsa-hss`.

The goal is to keep client, server, wire, and shared code separated enough for
audit and proof work.

## Module Ownership

### `src/client/`

Owns:

- client-visible output shapes
- client-side derivation views
- client-facing non-export vs explicit-export distinctions

Must not own:

- server-retained continuation state
- server-only finalize checks

### `src/server/`

Owns:

- staged server session state
- prepare/respond/finalize server transitions
- retained-state enforcement
- finalize-envelope validation

Must not own:

- client-only export delivery semantics

### `src/wire/`

Owns:

- shared payload structures crossing the client/server seam
- operation labels
- serialization-shape decisions that both sides must agree on

Must not own:

- hidden derivation internals
- server retention policy

### `src/shared/`

Owns:

- boundary-neutral fixed-function helpers
- canonical context encoding
- canonical secret derivation helpers
- additive-share derivation helpers

Must not own:

- client-only session semantics
- server-only lifecycle control

## Audit Rule

If a module mixes:

- client-visible export behavior
- server-retained state
- wire payload shapes

in one place, it should be split before the crate grows further.

This boundary rule exists to make both manual audits and formal verification
simpler.
