# session/availability

## Owns

Available-lane read models, persisted availability reads, lane readiness, and
derived candidate state.

## May Import

Identity types, persistence records, sealed-session persistence, warm-signing
read models, signing-session planning/budget primitives, and runtime status
ports.

## Must Not Import

Operation flows, `SigningEngine.ts`, assembly construction, or threshold
protocol entrypoints.

## Entrypoints

- `availableSigningLanes.ts`
- `persistedAvailableSigningLanes.ts`
- `readiness.ts`
