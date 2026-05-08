# session/warmSigning

## Owns

Warm signing-session material lifecycle: PRF.first cache keys, sealed-refresh
persistence, Ed25519/ECDSA warm capability provisioning, capability read models,
status readers, runtime claims, transitions, and warm-session cleanup.

## May Import

Primitive identity, record, and planning types from `session/*`; protocol entry
points needed to provision warm sessions; and concrete runtime ports required
to persist or claim warm material.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, chain operation modules, or UI
prompt construction modules.

## Entrypoints

- `public.ts`
- `runtime.ts`
- `statusReader.ts`
- `capabilityReader.ts`
- `persistence.ts`
- `ed25519SessionProvision.ts`
- `ecdsaSessionProvision.ts`
- `ecdsaWarmCapabilityBootstrap.ts`
