# sessionEmailOtp

## Owns

Email OTP threshold-session provisioning, restoration, and warm-session status
coordination.

## May Import

`stepUpConfirmation/*`, `interfaces/*`, `session/*`, `threshold/*`,
`uiConfirm/*`, and `workerManager/*`.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `chains/*`, `nonce/*`, or old
folders.

## Entrypoints

Current entrypoint: `EmailOtpThresholdSessionCoordinator.ts`.

Facade-facing ECDSA Email OTP public methods live under
`flows/signEvmFamily/emailOtpPublic.ts` because they are operation-specific
entrypoints that delegate into this coordinator.
