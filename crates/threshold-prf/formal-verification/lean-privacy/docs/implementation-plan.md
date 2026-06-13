# `threshold-prf` Lean Privacy Implementation Plan

Last updated: 2026-04-17

This track implements the narrow structural Lean privacy model for one-server
and two-server threshold-PRF execution-state visibility.

## Current Status

- [x] production `threshold-prf` state boundaries are stable enough for the
  abstract visibility model
- [x] one-server and two-server public/private state fields are explicit
- [x] `PrfPartialWire` payload shape is stable enough for visibility modeling
- [x] root/share/partial/output types are modeled structurally
- [x] remaining trust assumptions are documented

## Implemented Scope

- [x] define one-server execution state
- [x] define two-server participant execution state
- [x] define combiner execution state
- [x] define public output state
- [x] prove one-server mode observes enough shares to reconstruct `k_org`
- [x] prove one two-server participant state does not contain enough material to
  reconstruct `k_org`
- [x] prove combiner state excludes plaintext root and share scalars
- [x] prove public output state excludes root scalars, share scalars, and
  reconstructed `k_org`
- [x] document that this privacy model does not prove remote partial correctness
  without DLEQ, TEE attestation, or an equivalent mechanism

## Build Command

```bash
just threshold-prf-fv-privacy
```

## Non-Goals

- runtime isolation
- transport confidentiality
- side-channel resistance
- malicious partial correctness
- DLEQ soundness
