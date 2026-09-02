# session/planning

## Owns

Signing-session plan construction, operation fingerprinting, and caller
operation-id binding for deduplication.

## May Import

Shared operation-state and lane types from `session/operationState/*` plus
neutral digest helpers.

## Must Not Import

Operation flows, `SigningEngine.ts`, assembly construction, persistence writes,
threshold protocol entrypoints, or warm-session lifecycle modules.

## Entrypoints

- `planner.ts`
- `operationFingerprint.ts`
- `operationIdBinding.ts`
