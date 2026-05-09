# session/warmCapabilities

## Owns

Generic warm signing-session material lifecycle: status readers, capability read
models, transitions, warm-session cleanup, generic bootstrap persistence,
shared readiness helpers, and generic presign prefill scheduling.

## May Import

Primitive identity, record, and planning types from `session/*`; protocol entry
points needed to provision warm sessions; and concrete runtime ports required
to persist or claim warm material.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, chain operation modules, or UI
prompt construction modules.

## Entrypoints

- `public.ts`
- `statusReader.ts`
- `capabilityReader.ts`
- `persistence.ts`
- `ecdsaBootstrapPersistence.ts`
- `ecdsaLoginPrefill.ts`
