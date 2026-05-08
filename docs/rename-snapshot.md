# Rename Signing Session Snapshot To AvailableSigningLanes

Status: implemented

## Goal

Rename signing-session “snapshot” terminology to `AvailableSigningLanes`.

The current name is technically defensible, but it is too abstract for new
contributors. The object is a point-in-time, read-only view of signing lanes
that are currently visible from runtime and durable sources. The name should say
that directly.

## Target Names

Use these names:

- `SigningSessionSnapshot` -> `AvailableSigningLanes`
- `readSigningSessionSnapshot(...)` -> `readAvailableSigningLanes(...)`
- `readPersistedSigningSessionSnapshot(...)` -> `readPersistedAvailableSigningLanes(...)`
- `AvailableSigningLanesLane` -> `AvailableSigningLane`
- `AvailableSigningLanesCandidate` -> `AvailableSigningLaneCandidate`
- `ed25519AvailableLaneIdentityKey(...)` -> `ed25519AvailableLaneIdentityKey(...)`
- `ecdsaAvailableLaneIdentityKey(...)` -> `ecdsaAvailableLaneIdentityKey(...)`

Keep names short at call sites. Avoid `AvailableSigningLanesSnapshot`; the read
function and a short type doc can carry the point-in-time meaning.

## Required Semantics

The rename must preserve and clarify these rules:

1. `AvailableSigningLanes` is a read-only projection.
2. It is created on demand and discarded by the caller.
3. It can go stale immediately after creation.
4. It must not restore durable material.
5. It must not select or prefer a lane.
6. It must not derive ECDSA `subjectId` from a NEAR account id.
7. It must not expose collapsed ECDSA buckets.
8. It must compare lanes with exact identity keys.

The reader may merge runtime records and durable sealed records into candidates.
It may dedupe exact duplicate candidates by exact lane identity. It must not
choose between distinct identities.

## Implementation Instructions

1. Rename the owning module if the current file name still says `snapshot`.
   Prefer:

   ```text
   client/src/core/signingEngine/session/availability/availableSigningLanes.ts
   ```

2. Update exported types and functions in one pass. Do not leave aliases such as
   `type AvailableSigningLanes = AvailableSigningLanes`.

3. Update all imports directly to the new module and symbols. Do not create a
   compatibility barrel or forwarding file.

4. Keep exact identity helpers colocated with the availability reader only if
   they are used only for read-model dedupe. If signing/export exact lookup also
   needs them, move the canonical helper to the identity module and import it
   from both places.

5. Update tests by intent:

   - Rewrite useful behavior tests to the new names.
   - Delete tests whose only value was asserting the old `snapshot` terminology.
   - Keep ambiguity and exact-identity coverage.

6. Update docs that refer to “snapshot” in signing-session context. Use
   “available signing lanes” unless the text is explaining a point-in-time read
   model explicitly.

## Guardrails To Add Or Update

Add focused guards only where they protect architecture:

1. No production symbol named `SigningSessionSnapshot`.
2. No production import from the old snapshot module path.
3. No ECDSA availability shape with collapsed `evm` or `tempo` buckets.
4. No availability reader code that calls restore/write/delete APIs.
5. No availability reader code that calls `toWalletSubjectId(...)` from a NEAR
   account id.

Do not add broad string-search tests for every new name. Keep guards tied to
real regressions.

## Acceptance Criteria

1. No production availability path uses signing-session `snapshot` terminology.
2. Signing/export/readiness callers import `readAvailableSigningLanes(...)`.
3. ECDSA candidates are keyed by full exact identity.
4. Runtime and durable exact duplicates are collapsed only within the same exact
   lane identity.
5. Ambiguous distinct lanes remain ambiguous.
6. The refactor does not introduce compatibility aliases or forwarding modules.
7. The focused signing-session availability tests pass.
