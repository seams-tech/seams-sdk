# session/sealedRecovery

## Owns

ECDSA persisted-session restore coordination and shared sealed-recovery
request/result types.

## May Import

Sealed-session persistence boundaries, exact session identity types, and shared
primitive session types.

## Must Not Import

Operation flows, signing protocol entrypoints, prompt/runtime modules, or
method-specific recovery/provisioning implementation.

## Entrypoints

- `sealedRecovery.types.ts`
- `exactRecordLookup.ts`
- `recoveryRecord.ts`
- `readback.ts`
- `restoreCoordinator.ts`
