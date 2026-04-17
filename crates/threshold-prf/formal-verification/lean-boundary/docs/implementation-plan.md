# `threshold-prf` Lean Boundary Implementation Plan

Last updated: 2026-04-16

This track is deferred until the Rust-facing boundary is stable.

## Deferred Preconditions

- production `threshold-prf` API and `PrfPartialWireV1` are frozen
- first Verus model exists
- committed JSON vectors exist
- boundary candidate is stable enough to freeze
- extraction would prove something not already covered by Verus and vectors

## Deferred Scope

- freeze one narrow Rust boundary
- add Aeneas/Charon extraction scripts
- commit generated Lean artifacts only if they are stable and reviewable
- add handwritten Lean model for the same boundary
- prove generated boundary matches the handwritten model
- wire a dedicated justfile command

## Deferred Candidates

- context encoding boundary
- share/partial wire encoding boundary, especially context-tag transport
- direct reference wrapper boundary
- partial-combine wrapper boundary
