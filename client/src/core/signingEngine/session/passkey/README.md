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
- `ed25519Recovery.ts`
- `ed25519SessionProvision.ts`
- `ecdsaBootstrapRequest.ts`
