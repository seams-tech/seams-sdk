# Registration Flow Benchmark Report

Generated: 2026-06-10T04:40:57.134Z
Run ID: `20260610-043955Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 2287.0 | 2652.0 | 1665.0 | 1734.0 | 20 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 2380.0 | 2648.0 | 1727.0 | 1734.0 | 20 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 1694.0 | 1755.0 | 1307.0 | 1365.0 | 20 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 1714.0 | 1869.0 | 1326.0 | 1460.0 | 20 | 18 | 23 |

## passkey_ed25519_only_wallet_iframe

- Description: Passkey registration, Ed25519 only, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 823.0 | 856.0 | 856.0 | 813.6 | 856.0 |
| `browserRunDurationMs` | 5 | 2287.0 | 2652.0 | 2652.0 | 2406.0 | 2652.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 23.0 | 28.0 | 28.0 | 22.6 | 28.0 |
| `ed25519ClientRequestMs` | 5 | 132.0 | 137.0 | 137.0 | 132.8 | 137.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 465.0 | 481.0 | 481.0 | 469.4 | 481.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 9.0 | 11.0 | 11.0 | 8.6 | 11.0 |
| `inputValidationMs` | 5 | 2.0 | 4.0 | 4.0 | 2.6 | 4.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 17.0 | 23.0 | 23.0 | 18.4 | 23.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 12.0 | 12.0 | 5.4 | 12.0 |
| `passkeyAuthConfirmationMs` | 5 | 823.0 | 856.0 | 856.0 | 813.6 | 856.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 204.0 | 204.0 | 202.0 | 204.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 621.0 | 655.0 | 655.0 | 611.2 | 655.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 823.0 | 856.0 | 856.0 | 813.4 | 856.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 621.0 | 654.0 | 654.0 | 610.4 | 654.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 621.0 | 654.0 | 654.0 | 610.8 | 654.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 4.0 | 4.0 | 1.6 | 4.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 4.0 | 4.0 | 1.6 | 4.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 621.0 | 655.0 | 655.0 | 611.2 | 655.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 2.0 | 2.0 | 0.4 | 2.0 |
| `registrationIntentMs` | 5 | 6.0 | 8.0 | 8.0 | 6.0 | 8.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 6.0 | 6.0 | 2.0 | 6.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationWarmupMs` | 5 | 2.0 | 7.0 | 7.0 | 2.6 | 7.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkTotalMs` | 5 | 1665.0 | 1734.0 | 1734.0 | 1664.6 | 1734.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `totalMs` | 5 | 2287.0 | 2652.0 | 2652.0 | 2406.0 | 2652.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 9.0 | 13.0 | 13.0 | 9.8 | 13.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 679.0 | 1010.0 | 1010.0 | 784.6 | 1010.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 5 | 879.0 | 1163.0 | 1163.0 | 962.4 | 1163.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 5 | 35.0 | 45.0 | 45.0 | 36.2 | 45.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 3.0 | 21.0 | 21.0 | 7.6 | 21.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 3.0 | 21.0 | 21.0 | 7.6 | 21.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2287.0 | 2651.0 | 2651.0 | 2405.8 | 2651.0 |
| `walletRegisterFinalizeMs` | 5 | 56.0 | 62.0 | 62.0 | 57.2 | 62.0 |
| `walletRegisterHssRespondMs` | 5 | 90.0 | 98.0 | 98.0 | 90.8 | 98.0 |
| `walletRegisterPrepareMs` | 5 | 391.0 | 487.0 | 487.0 | 408.6 | 487.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 8.0 | 139.0 | 139.0 | 33.8 | 139.0 |
| `walletStateActivationMs` | 5 | 1.0 | 5.0 | 5.0 | 1.8 | 5.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 49.0 | 53.0 | 53.0 | 49.2 | 53.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 48.0 | 51.0 | 51.0 | 48.2 | 51.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 18.0 | 18.0 | 16.4 | 18.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 77.0 | 87.0 | 87.0 | 79.4 | 87.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 49.0 | 52.0 | 52.0 | 49.8 | 52.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 1.8 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 6.0 | 6.0 | 6.0 | 5.6 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 86.0 | 86.0 | 79.2 | 86.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 58.0 | 62.0 | 62.0 | 58.4 | 62.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 378.0 | 465.0 | 465.0 | 395.0 | 465.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 363.0 | 382.0 | 382.0 | 366.0 | 382.0 |
| `registrationHssServerInputDeriveMs` | 5 | 372.0 | 375.0 | 375.0 | 311.0 | 375.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 365.0 | 449.0 | 449.0 | 381.0 | 449.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 378.0 | 464.0 | 464.0 | 394.4 | 464.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 135.0 | 135.0 | 27.8 | 135.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 134.0 | 134.0 | 27.6 | 134.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 386.0 | 396.0 | 386.0 | 396.0 | 383 | 23046 |
| `respond` | 5 | 89.0 | 91.0 | 88.0 | 90.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 465.0 | 481.0 | 0.0 | 0.0 | 465.0 | 480.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 124.0 | 136.0 | 0.0 | 0.0 | 124.0 | 136.0 | 0.0 | 22956 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 458.0 | 473.0 | 462.2 | 473.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 2.0 | 1.4 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.6 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentDerivations` | 5 | 2048.0 | 2048.0 | 2048.0 | 2048.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentMaterializations` | 5 | 17928.0 | 17928.0 | 17928.0 | 17928.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelFormatAllocations` | 5 | 265.0 | 265.0 | 265.0 | 265.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelWrites` | 5 | 57128.0 | 57128.0 | 57128.0 | 57128.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLocalWordMaterializations` | 5 | 12800.0 | 12800.0 | 12800.0 | 12800.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestDerivations` | 5 | 13824.0 | 13824.0 | 13824.0 | 13824.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestMaterializations` | 5 | 15360.0 | 15360.0 | 15360.0 | 15360.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalSharedWordMaterializations` | 5 | 1024.0 | 1024.0 | 1024.0 | 1024.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalTransportWordMaterializations` | 5 | 1536.0 | 1536.0 | 1536.0 | 1536.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 23.0 | 24.0 | 23.2 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 38.0 | 39.0 | 38.0 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 54.0 | 56.0 | 54.2 | 56.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 25.0 | 26.0 | 25.0 | 26.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 147.0 | 152.0 | 147.8 | 152.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 19.0 | 21.0 | 19.4 | 21.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 59.0 | 60.0 | 58.8 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 24.0 | 26.0 | 24.0 | 26.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 233.0 | 243.0 | 235.8 | 243.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 32.0 | 35.0 | 32.2 | 35.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 24.0 | 25.0 | 23.8 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 23.0 | 26.0 | 23.8 | 26.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.4 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 7.0 | 8.0 | 7.4 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 5.0 | 4.2 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 420.0 | 434.0 | 424.6 | 434.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_wallet_iframe

- Description: Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 841.0 | 870.0 | 870.0 | 819.0 | 870.0 |
| `browserRunDurationMs` | 5 | 2380.0 | 2648.0 | 2648.0 | 2458.6 | 2648.0 |
| `ecdsaClientBootstrapMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 10.0 | 47.0 | 47.0 | 16.2 | 47.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 22.0 | 22.0 | 20.8 | 22.0 |
| `ed25519ClientRequestMs` | 5 | 135.0 | 139.0 | 139.0 | 135.4 | 139.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 472.0 | 481.0 | 481.0 | 472.4 | 481.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 12.0 | 13.0 | 13.0 | 11.6 | 13.0 |
| `inputValidationMs` | 5 | 2.0 | 3.0 | 3.0 | 2.4 | 3.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 20.0 | 25.0 | 25.0 | 20.2 | 25.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 10.0 | 10.0 | 5.0 | 10.0 |
| `passkeyAuthConfirmationMs` | 5 | 841.0 | 870.0 | 870.0 | 819.0 | 870.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 202.0 | 202.0 | 201.6 | 202.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 638.0 | 669.0 | 669.0 | 617.0 | 669.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 841.0 | 870.0 | 870.0 | 818.6 | 870.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 638.0 | 668.0 | 668.0 | 616.0 | 668.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 638.0 | 668.0 | 668.0 | 616.0 | 668.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 638.0 | 669.0 | 669.0 | 616.8 | 669.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 6.0 | 9.0 | 9.0 | 6.0 | 9.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationWarmupMs` | 5 | 2.0 | 2.0 | 2.0 | 1.8 | 2.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkTotalMs` | 5 | 1727.0 | 1734.0 | 1734.0 | 1711.8 | 1734.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2380.0 | 2648.0 | 2648.0 | 2458.6 | 2648.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 9.0 | 13.0 | 13.0 | 10.0 | 13.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 680.0 | 978.0 | 978.0 | 783.0 | 978.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 5 | 895.0 | 1130.0 | 1130.0 | 962.6 | 1130.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 5 | 38.0 | 45.0 | 45.0 | 40.0 | 45.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 7.0 | 16.0 | 16.0 | 7.6 | 16.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 7.0 | 16.0 | 16.0 | 7.6 | 16.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2379.0 | 2648.0 | 2648.0 | 2458.2 | 2648.0 |
| `walletRegisterFinalizeMs` | 5 | 58.0 | 68.0 | 68.0 | 60.8 | 68.0 |
| `walletRegisterHssRespondMs` | 5 | 103.0 | 175.0 | 175.0 | 115.6 | 175.0 |
| `walletRegisterPrepareMs` | 5 | 395.0 | 465.0 | 465.0 | 408.4 | 465.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 8.0 | 96.0 | 96.0 | 24.6 | 96.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 50.0 | 57.0 | 57.0 | 52.2 | 57.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 49.0 | 56.0 | 56.0 | 51.2 | 56.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 17.0 | 19.0 | 19.0 | 17.2 | 19.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 6.0 | 6.0 | 5.0 | 6.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 91.0 | 163.0 | 163.0 | 104.0 | 163.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 80.0 | 80.0 | 24.8 | 80.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 49.0 | 50.0 | 50.0 | 49.2 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 7.0 | 7.0 | 7.0 | 6.8 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 1.8 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 7.0 | 7.0 | 7.0 | 6.6 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.4 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 79.0 | 83.0 | 83.0 | 79.2 | 83.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 58.0 | 60.0 | 60.0 | 58.0 | 60.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 383.0 | 450.0 | 450.0 | 395.0 | 450.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 365.0 | 371.0 | 371.0 | 366.2 | 371.0 |
| `registrationHssServerInputDeriveMs` | 5 | 376.0 | 379.0 | 379.0 | 313.6 | 379.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 369.0 | 437.0 | 437.0 | 381.4 | 437.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 383.0 | 449.0 | 449.0 | 394.8 | 449.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 91.0 | 91.0 | 19.0 | 91.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 90.0 | 90.0 | 18.8 | 90.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 394.0 | 398.0 | 393.0 | 395.0 | 388 | 23053 |
| `respond` | 5 | 91.0 | 96.0 | 87.0 | 95.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 471.0 | 480.0 | 0.0 | 0.0 | 471.0 | 480.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 123.0 | 135.0 | 0.0 | 0.0 | 123.0 | 135.0 | 0.0 | 22963 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 465.0 | 473.0 | 465.4 | 473.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 1.0 | 1.0 | 0.8 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 3.0 | 4.0 | 3.2 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentDerivations` | 5 | 2048.0 | 2048.0 | 2048.0 | 2048.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentMaterializations` | 5 | 17928.0 | 17928.0 | 17928.0 | 17928.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelFormatAllocations` | 5 | 265.0 | 265.0 | 265.0 | 265.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelWrites` | 5 | 57128.0 | 57128.0 | 57128.0 | 57128.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLocalWordMaterializations` | 5 | 12800.0 | 12800.0 | 12800.0 | 12800.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestDerivations` | 5 | 13824.0 | 13824.0 | 13824.0 | 13824.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestMaterializations` | 5 | 15360.0 | 15360.0 | 15360.0 | 15360.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalSharedWordMaterializations` | 5 | 1024.0 | 1024.0 | 1024.0 | 1024.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalTransportWordMaterializations` | 5 | 1536.0 | 1536.0 | 1536.0 | 1536.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 24.0 | 24.0 | 23.8 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 38.0 | 39.0 | 38.4 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 54.0 | 56.0 | 54.4 | 56.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 25.0 | 26.0 | 25.2 | 26.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 149.0 | 153.0 | 149.2 | 153.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 20.0 | 20.0 | 19.8 | 20.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 59.0 | 62.0 | 59.6 | 62.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 24.0 | 24.0 | 23.6 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 237.0 | 238.0 | 236.6 | 238.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 33.0 | 34.0 | 32.8 | 34.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 23.0 | 25.0 | 23.4 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 24.0 | 25.0 | 24.4 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 7.0 | 7.0 | 6.8 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.6 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 427.0 | 434.0 | 427.4 | 434.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_only_host_origin

- Description: Passkey registration, Ed25519 only, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 201.0 | 204.0 | 204.0 | 201.6 | 204.0 |
| `browserRunDurationMs` | 5 | 1694.0 | 1755.0 | 1755.0 | 1703.2 | 1755.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 197.0 | 257.0 | 257.0 | 171.8 | 257.0 |
| `ed25519ClientRequestMs` | 5 | 212.0 | 217.0 | 217.0 | 181.0 | 217.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 465.0 | 480.0 | 480.0 | 466.6 | 480.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 3.0 | 8.0 | 8.0 | 4.6 | 8.0 |
| `inputValidationMs` | 5 | 2.0 | 5.0 | 5.0 | 2.8 | 5.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 6.0 | 11.0 | 11.0 | 7.0 | 11.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 12.0 | 12.0 | 4.4 | 12.0 |
| `passkeyAuthConfirmationMs` | 5 | 201.0 | 203.0 | 203.0 | 201.4 | 203.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 201.0 | 202.0 | 202.0 | 201.2 | 202.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 201.0 | 203.0 | 203.0 | 201.4 | 203.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptUserMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 4.0 | 8.0 | 8.0 | 4.6 | 8.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 2.0 | 4.0 | 4.0 | 2.4 | 4.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 1.0 | 5.0 | 5.0 | 1.8 | 5.0 |
| `registrationWarmupMs` | 5 | 10.0 | 392.0 | 392.0 | 86.6 | 392.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 7.0 | 385.0 | 385.0 | 82.2 | 385.0 |
| `registrationWarmupWaitMs` | 5 | 2.0 | 385.0 | 385.0 | 78.4 | 385.0 |
| `sdkTotalMs` | 5 | 1307.0 | 1365.0 | 1365.0 | 1317.4 | 1365.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `totalMs` | 5 | 1694.0 | 1755.0 | 1755.0 | 1703.2 | 1755.0 |
| `walletRegisterFinalizeMs` | 5 | 52.0 | 59.0 | 59.0 | 53.6 | 59.0 |
| `walletRegisterHssRespondMs` | 5 | 85.0 | 88.0 | 88.0 | 85.6 | 88.0 |
| `walletRegisterPrepareMs` | 5 | 385.0 | 454.0 | 454.0 | 399.0 | 454.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 53.0 | 97.0 | 97.0 | 52.0 | 97.0 |
| `walletStateActivationMs` | 5 | 1.0 | 5.0 | 5.0 | 1.8 | 5.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 48.0 | 53.0 | 53.0 | 48.4 | 53.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 47.0 | 51.0 | 51.0 | 47.6 | 51.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 17.0 | 17.0 | 16.0 | 17.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 5.0 | 5.0 | 4.4 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 77.0 | 82.0 | 82.0 | 78.4 | 82.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 49.0 | 50.0 | 50.0 | 49.0 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 7.0 | 7.0 | 7.0 | 6.6 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 7.0 | 7.0 | 7.0 | 6.6 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.4 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 82.0 | 82.0 | 78.4 | 82.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 59.0 | 59.0 | 57.8 | 59.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 381.0 | 450.0 | 450.0 | 394.8 | 450.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 366.0 | 373.0 | 373.0 | 367.0 | 373.0 |
| `registrationHssServerInputDeriveMs` | 5 | 376.0 | 379.0 | 379.0 | 313.8 | 379.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 368.0 | 439.0 | 439.0 | 381.8 | 439.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 381.0 | 448.0 | 448.0 | 394.4 | 448.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 93.0 | 93.0 | 19.6 | 93.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 92.0 | 92.0 | 19.2 | 92.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1191.0 | 1197.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 51.0 | 55.0 | 51.0 | 53.0 | 154690 | 39461 |
| `prepare` | 5 | 382.0 | 385.0 | 381.0 | 384.0 | 381 | 23043 |
| `respond` | 5 | 83.0 | 85.0 | 81.0 | 83.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 463.0 | 479.0 | 0.0 | 0.0 | 463.0 | 479.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 90.0 | 91.0 | 0.0 | 0.0 | 90.0 | 91.0 | 0.0 | 40079 | 86 |
| `prepare_client_request` | 10 | 123.0 | 134.0 | 0.0 | 0.0 | 123.0 | 134.0 | 0.0 | 22953 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 461.0 | 473.0 | 460.7 | 473.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 2.0 | 3.0 | 2.2 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentDerivations` | 9 | 2048.0 | 2048.0 | 2048.0 | 2048.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentMaterializations` | 9 | 17928.0 | 17928.0 | 17928.0 | 17928.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelFormatAllocations` | 9 | 265.0 | 265.0 | 265.0 | 265.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelWrites` | 9 | 57128.0 | 57128.0 | 57128.0 | 57128.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLocalWordMaterializations` | 9 | 12800.0 | 12800.0 | 12800.0 | 12800.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestDerivations` | 9 | 13824.0 | 13824.0 | 13824.0 | 13824.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestMaterializations` | 9 | 15360.0 | 15360.0 | 15360.0 | 15360.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalSharedWordMaterializations` | 9 | 1024.0 | 1024.0 | 1024.0 | 1024.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalTransportWordMaterializations` | 9 | 1536.0 | 1536.0 | 1536.0 | 1536.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 23.0 | 24.0 | 23.0 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 37.0 | 38.0 | 37.2 | 38.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 56.0 | 56.0 | 55.6 | 56.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 24.0 | 25.0 | 24.2 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 150.0 | 152.0 | 150.2 | 152.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 19.0 | 20.0 | 19.1 | 20.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 60.0 | 61.0 | 60.0 | 61.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 24.0 | 25.0 | 24.1 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 236.0 | 244.0 | 236.4 | 244.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 33.0 | 34.0 | 32.9 | 34.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 24.0 | 25.0 | 24.2 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 24.0 | 25.0 | 24.1 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 6.0 | 7.0 | 6.3 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.7 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 427.0 | 435.0 | 426.4 | 435.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_host_origin

- Description: Passkey registration, Ed25519 plus ECDSA, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 202.0 | 203.0 | 203.0 | 202.4 | 203.0 |
| `browserRunDurationMs` | 5 | 1714.0 | 1869.0 | 1869.0 | 1751.4 | 1869.0 |
| `ecdsaClientBootstrapMs` | 5 | 83.0 | 89.0 | 89.0 | 52.4 | 89.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 7.0 | 9.0 | 9.0 | 7.0 | 9.0 |
| `ed25519ClientMaterialMs` | 5 | 206.0 | 254.0 | 254.0 | 174.4 | 254.0 |
| `ed25519ClientRequestMs` | 5 | 206.0 | 212.0 | 212.0 | 178.0 | 212.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 465.0 | 479.0 | 479.0 | 469.2 | 479.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 6.0 | 12.0 | 12.0 | 7.2 | 12.0 |
| `inputValidationMs` | 5 | 2.0 | 7.0 | 7.0 | 3.6 | 7.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 8.0 | 10.0 | 10.0 | 7.6 | 10.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 8.0 | 8.0 | 3.8 | 8.0 |
| `passkeyAuthConfirmationMs` | 5 | 202.0 | 203.0 | 203.0 | 202.4 | 203.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 202.0 | 202.0 | 202.0 | 202.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 202.0 | 203.0 | 203.0 | 202.2 | 203.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptUserMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 3.0 | 11.0 | 11.0 | 5.0 | 11.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 4.0 | 4.0 | 1.8 | 4.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 1.0 | 4.0 | 4.0 | 1.4 | 4.0 |
| `registrationWarmupMs` | 5 | 11.0 | 392.0 | 392.0 | 86.8 | 392.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 8.0 | 386.0 | 386.0 | 83.0 | 386.0 |
| `registrationWarmupWaitMs` | 5 | 1.0 | 387.0 | 387.0 | 78.0 | 387.0 |
| `sdkTotalMs` | 5 | 1326.0 | 1460.0 | 1460.0 | 1358.6 | 1460.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |
| `totalMs` | 5 | 1714.0 | 1869.0 | 1869.0 | 1751.4 | 1869.0 |
| `walletRegisterFinalizeMs` | 5 | 55.0 | 61.0 | 61.0 | 56.8 | 61.0 |
| `walletRegisterHssRespondMs` | 5 | 95.0 | 158.0 | 158.0 | 106.8 | 158.0 |
| `walletRegisterPrepareMs` | 5 | 384.0 | 453.0 | 453.0 | 397.8 | 453.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 54.0 | 108.0 | 108.0 | 55.6 | 108.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 49.0 | 53.0 | 53.0 | 49.8 | 53.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 47.0 | 51.0 | 51.0 | 48.2 | 51.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 2.0 | 2.0 | 2.0 | 1.8 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 17.0 | 17.0 | 16.2 | 17.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 89.0 | 151.0 | 151.0 | 101.2 | 151.0 |
| `registrationEcdsaRespondMs` | 5 | 12.0 | 68.0 | 68.0 | 23.0 | 68.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 49.0 | 50.0 | 50.0 | 48.8 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 7.0 | 7.0 | 7.0 | 6.6 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 7.0 | 7.0 | 7.0 | 6.6 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.4 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 83.0 | 83.0 | 78.2 | 83.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 59.0 | 59.0 | 57.6 | 59.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 381.0 | 447.0 | 447.0 | 394.4 | 447.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 366.0 | 371.0 | 371.0 | 366.8 | 371.0 |
| `registrationHssServerInputDeriveMs` | 5 | 377.0 | 379.0 | 379.0 | 314.2 | 379.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 368.0 | 438.0 | 438.0 | 381.8 | 438.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 381.0 | 447.0 | 447.0 | 394.4 | 447.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 2.0 | 97.0 | 97.0 | 20.8 | 97.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 96.0 | 96.0 | 20.0 | 96.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1197.0 | 1207.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 51.0 | 53.0 | 51.0 | 52.0 | 154690 | 39461 |
| `prepare` | 5 | 383.0 | 392.0 | 383.0 | 392.0 | 386 | 23050 |
| `respond` | 5 | 84.0 | 86.0 | 83.0 | 85.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 465.0 | 478.0 | 0.0 | 0.0 | 465.0 | 478.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 90.0 | 91.0 | 0.0 | 0.0 | 90.0 | 91.0 | 0.0 | 40086 | 86 |
| `prepare_client_request` | 10 | 123.0 | 132.0 | 0.0 | 0.0 | 123.0 | 132.0 | 0.0 | 22960 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 463.0 | 472.0 | 463.3 | 472.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 1.0 | 0.9 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 2.0 | 3.0 | 2.3 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentDerivations` | 9 | 2048.0 | 2048.0 | 2048.0 | 2048.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalCommitmentMaterializations` | 9 | 17928.0 | 17928.0 | 17928.0 | 17928.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelFormatAllocations` | 9 | 265.0 | 265.0 | 265.0 | 265.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLabelWrites` | 9 | 57128.0 | 57128.0 | 57128.0 | 57128.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalLocalWordMaterializations` | 9 | 12800.0 | 12800.0 | 12800.0 | 12800.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestDerivations` | 9 | 13824.0 | 13824.0 | 13824.0 | 13824.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalProvenanceDigestMaterializations` | 9 | 15360.0 | 15360.0 | 15360.0 | 15360.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalSharedWordMaterializations` | 9 | 1024.0 | 1024.0 | 1024.0 | 1024.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalLogicalTransportWordMaterializations` | 9 | 1536.0 | 1536.0 | 1536.0 | 1536.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 23.0 | 24.0 | 23.2 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 38.0 | 39.0 | 37.8 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 56.0 | 58.0 | 56.0 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 25.0 | 26.0 | 24.8 | 26.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 152.0 | 154.0 | 152.0 | 154.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 19.0 | 20.0 | 19.3 | 20.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 61.0 | 62.0 | 60.8 | 62.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 24.0 | 25.0 | 24.1 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 237.0 | 243.0 | 236.6 | 243.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 33.0 | 34.0 | 32.9 | 34.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 24.0 | 25.0 | 24.1 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 24.0 | 25.0 | 24.1 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 7.0 | 7.0 | 6.7 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 6.0 | 7.0 | 6.1 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.7 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.9 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 429.0 | 434.0 | 428.8 | 434.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
