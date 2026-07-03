# stepUpConfirmation

## Owns

Human step-up confirmation contracts, intent-digest preparation, and passkey
and Email OTP prompt/auth-plan flows.

## May Import

`webauthnAuth/*` passkey browser primitives and `interfaces/*` shared contracts.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, session lifecycle modules,
`session/emailOtp/*`, `threshold/*`, `chains/*`, `nonce/*`, `workerManager/*`,
or concrete `uiConfirm/*` runtime internals.

## Entrypoints

Current entrypoints: `confirmOperation.ts`, `types.ts`, `channel/confirmTypes.ts`,
`intentDigestPreparation.ts`, `walletAuthPolicyError.ts`, `passkeyPrompt/*`,
and `otpPrompt/*`.

## Auth Method Rule

Auth methods start as `<method>Prompt/` folders under `stepUpConfirmation/`.
Durable method session folders are added only when a method owns cross-operation
lifecycle state. `session/emailOtp/` exists for that reason; passkey code stays in
`passkeyPrompt/` and `webauthnAuth/` until it needs a comparable coordinator.

## ECDSA Boundary

`stepUpConfirmation/*` stops at typed authorization payloads. ECDSA session
selection, reconnect planning, and bootstrap activation belong to
`flows/signEvmFamily/*` and `session/passkey/*`.
