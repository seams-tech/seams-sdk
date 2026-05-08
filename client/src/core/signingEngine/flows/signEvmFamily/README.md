# signEvmFamily

## Owns

Tempo and EVM-family signing operation flows, including operation planning,
selected ECDSA lane usage, EVM/Tempo nonce lifecycle commands, and finalization.

## May Import

`flows/shared/*`, `session/*`, `stepUpConfirmation/*`, `threshold/ecdsa/*`,
`chains/evm/*`, `chains/tempo/*`, `workers/*`, and `nonce/*`.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, NEAR operation modules, old `api/*`, or old
`orchestration/*`.

## Entrypoints

Current entrypoint: `signEvmFamily.ts`.

Supporting entrypoints: `signingFlow.ts`, `signEvmWithUiConfirm.ts`,
`signTempoWithUiConfirm.ts`, `nonceLifecycleAdapter.ts`,
`emailOtpPublic.ts`, and
`smartAccountDeployment.ts`.

## Stage Order

1. Input normalization: `signEvmFamily.ts`, `types.ts`, `addresses.ts`.
2. Lane selection: `ecdsaLanes.ts`, `ecdsaSelection.ts`, `ecdsaReadiness.ts`.
3. Auth planning: `authPlanning.ts`, `emailOtpSigningSession.ts`,
   `emailOtpRefresh.ts`, `emailOtpPublic.ts`, `freshEmailOtpRetry.ts`,
   `requireEvmFamilyStepUpAuth.ts`.
4. Confirmation: `signingFlow.ts`, `signEvmWithUiConfirm.ts`,
   `signTempoWithUiConfirm.ts`.
5. Threshold admission: `thresholdAdmission.ts`, `budgetSpending.ts`,
   `warmSessionServices.ts`.
6. Payload preparation: `preparedSigning.ts`, `smartAccount.ts`,
   `smartAccountDeployment*.ts`.
7. Nonce: `nonceLifecycleAdapter.ts`, `evmNonceLifecycle.ts`,
   `tempoNonceLifecycle.ts`, `nonceResolution.ts`, `nonceMetrics.ts`.
8. Signing: `signingFlowRuntime.ts`, `transactionExecutor.ts`,
   `signerLoader.ts`, `signers/*`.
9. Finalization: `postSignFinalization.ts`, `postSignPolicy.ts`,
   `events.ts`, `operationIds.ts`.
