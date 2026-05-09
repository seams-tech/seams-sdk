# session/emailOtp

## Owns

Email OTP-specific session recovery, worker-coordinated bootstrap commit,
worker request construction, signing-share claims, and Email OTP method
helpers that sit under the session domain. Generic companion sealed-record
contracts, restore purpose types, readback verification, and policy checks live
under `session/sealedRecovery/*`. Email OTP restore uses that same shared
sealed-recovery boundary and adds method-specific worker/bootstrap logic on top.

## May Import

`session/sealedRecovery/*`, `session/warmCapabilities/*`,
`session/persistence/*`, `session/identity/*`, `stepUpConfirmation/otpPrompt/*`, `threshold/*`,
`workerManager/*`, and primitive interface or chain types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, broad `stepUpConfirmation/*` imports outside
`otpPrompt/*`, or
`session/passkey/*`.

## Entrypoints

- `companionSessions.ts`
- `EmailOtpThresholdSessionCoordinator.ts`
- `appSessionJwtCache.ts`
- `ecdsaRecovery.ts`
- `ed25519Recovery.ts`
- `ecdsaBootstrapCommit.ts`
- `ed25519LocalMetadata.ts`
- `exportRecovery.ts`
- `provisioning.ts`
- `routePlan.ts`
- `status.ts`
- `workerRequests.ts`
