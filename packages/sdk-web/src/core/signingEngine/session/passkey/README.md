# session/passkey

## Owns

Passkey-specific warm-session claim, PRF cache, and capability provisioning
helpers. Passkey reconnect and restore-before-claim paths use the shared
`session/sealedRecovery/*` orchestration boundary through
`restorePersistedSessionForSigning`.

## May Import

`session/warmCapabilities/*`, `session/persistence/*`,
`session/operationState/*`, `session/identity/*`, and primitive interface or
threshold types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `stepUpConfirmation/*`, or
`session/emailOtp/*`.

## Entrypoints

- `public.ts`
- `prfCache.ts`
- `prfClaim.ts`
- `runtime.ts`
- `ecdsaProvisioner.ts`
- `ed25519Provisioner.ts`
- `ecdsaBootstrap.ts`
- `ecdsaWarmCapabilityBootstrap.ts`
- `ecdsaRecovery.ts`
- `ecdsaSessionProvision.ts`
- `ed25519BudgetRefresh.ts`
- `ed25519SessionProvision.ts`

## ECDSA Flow Rule

`passkey/*` no longer owns a separate ECDSA bootstrap-request adapter layer.
The public boundary is `ecdsaBootstrap.ts`. `EcdsaBootstrapRequest`
normalization lives in `ecdsaWarmCapabilityBootstrap.ts`. Strict
plan-driven reuse and reconnect activation lives in `ecdsaProvisioner.ts`.
Activation and persistence handoff lives in `ecdsaSessionProvision.ts`.

`prfCache.ts` is the browser-runtime cache boundary for warm-session PRF
material. It reuses the shared warm-session material transport contract instead
of defining a passkey-local lifecycle transport shape.
