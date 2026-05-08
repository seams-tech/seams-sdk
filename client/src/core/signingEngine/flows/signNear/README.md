# signNear

## Owns

NEAR signing operation flows for transactions, delegate actions, and NEP-413
messages. The folder sequences selected Ed25519 signing-session state,
step-up confirmation, threshold admission, worker request assembly, and result
normalization.

## May Import

`flows/shared/*`, `session/*`, `stepUpConfirmation/*`, `threshold/ed25519/*`,
`chains/near/*`, `workers/*`, `workerManager/*`, and `interfaces/*`.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, EVM-family operation modules, old `api/*`, or
old `orchestration/*`.

## Entrypoints

Current entrypoint: `signNear.ts`.

Supporting entrypoints: `signTransactions.ts`, `signDelegate.ts`,
`signNep413.ts`, and `nearSigningFlow.ts`.

## Stage Order

1. Input normalization: `signNear.ts`.
2. Lane selection and auth mode: `shared/thresholdAuthMode.ts`,
   `shared/thresholdSessionAuth.ts`.
3. Auth planning and confirmation: `signTransactions.ts`, `signDelegate.ts`,
   `signNep413.ts`.
4. Threshold admission: `nearSigningFlow.ts`.
5. Payload and worker request assembly: `shared/signingMaterials.ts`,
   `chains/near/*`.
6. Signing: selected transaction, delegate, or NEP-413 flow entrypoint.
7. Finalization: flow-local result normalization and event emission.
