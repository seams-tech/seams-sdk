# session/persistence

## Owns

Threshold session record normalization and sealed-session persistence storage.

## May Import

Identity types, neutral signing interfaces, threshold policy primitives, and
IndexedDB boundaries.

## Must Not Import

Operation flows, prompt/runtime orchestration, or warm-session lifecycle logic
outside persistence-specific helpers.

## Entrypoints

- `records.ts`
- `sealedSessionStore.ts`
