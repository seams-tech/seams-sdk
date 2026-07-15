# session/emailOtp

## Owns

Email OTP-specific ECDSA session recovery, worker-coordinated bootstrap commit,
worker request construction, signing-share claims, and active Yao Ed25519 lane
authority. Generic sealed-record contracts, restore purpose types, readback
verification, and policy checks live under `session/sealedRecovery/*`.

## May Import

`session/sealedRecovery/*`, `session/warmCapabilities/*`,
`session/persistence/*`, `session/identity/*`, `stepUpConfirmation/otpPrompt/*`, `threshold/*`,
`workerManager/*`, and primitive interface or chain types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, broad `stepUpConfirmation/*` imports outside
`otpPrompt/*`, or
`session/passkey/*`.

## Entrypoints

- `EmailOtpWalletSessionCoordinator.ts`
- `appSessionJwtCache.ts`
- `ecdsaRecovery.ts`
- `ecdsaBootstrapCommit.ts`
- `ed25519SigningLane.ts`
- `ed25519SigningSessionAuthority.ts`
- `exportRecovery.ts`
- `routePlan.ts`
- `status.ts`
- `workerRequests.ts`
