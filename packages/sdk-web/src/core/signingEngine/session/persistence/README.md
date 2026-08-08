# session/persistence

## Owns

Sealed-session persistence storage and transport authorization boundaries.

## May Import

Identity types, neutral signing interfaces, threshold policy primitives, and
IndexedDB boundaries.

## Must Not Import

Operation flows, prompt/runtime orchestration, or warm-session lifecycle logic
outside persistence-specific helpers.

## Entrypoints

- `sealedSessionTransportAuth.ts`
- `sealedSessionStore.ts`
