# session/sealedRecovery

## Owns

Persisted-session restore coordination and shared sealed-recovery request/result
types.

## May Import

Sealed-session persistence boundaries, exact session identity types, and shared
primitive session types.

## Must Not Import

Operation flows, signing protocol entrypoints, prompt/runtime modules, or
method-specific recovery/provisioning implementation.

## Entrypoints

- `types.ts`
- `exactRecordLookup.ts`
- `policy.ts`
- `companionSessions.ts`
- `readback.ts`
- `restoreCoordinator.ts`
