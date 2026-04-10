# Refactor 1

Date created: April 9, 2026

## Scope

This refactor tracks the first crate-structure cleanup pass for `ecdsa-hss`.

## Goal

Make the crate boundary-first before deeper protocol or audit work continues.

## Landed Shape

The crate is now organized around:

- `src/client/`
- `src/server/`
- `src/wire/`
- `src/shared/`

with root-level modules reserved for the public API surface and truly shared
types only.

## What Changed

- boundary-neutral fixed-function helpers moved under `src/shared/`
- client-visible logic moved under `src/client/`
- server-owned staged logic moved under `src/server/`
- transitional boundary-mixing layout was removed

## Why It Matters

This refactor was required so the next phases could reason about:

- server-blindness
- retained-state rules
- export-policy boundaries
- crate-local proof scopes

without a mixed ownership layout.
