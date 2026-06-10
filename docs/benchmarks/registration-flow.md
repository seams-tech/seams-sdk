# Registration Flow Benchmark Report

Generated: 2026-06-10T02:46:20.242Z
Run ID: `20260610-024516Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 2480.0 | 2735.0 | 1807.0 | 1846.0 | 20 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 2502.0 | 2895.0 | 1869.0 | 1933.0 | 20 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 1852.0 | 1898.0 | 1480.0 | 1523.0 | 20 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 1895.0 | 2018.0 | 1511.0 | 1642.0 | 20 | 18 | 23 |

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
| `authProofMs` | 5 | 823.0 | 836.0 | 836.0 | 807.0 | 836.0 |
| `browserRunDurationMs` | 5 | 2480.0 | 2735.0 | 2735.0 | 2545.6 | 2735.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 25.0 | 25.0 | 21.6 | 25.0 |
| `ed25519ClientRequestMs` | 5 | 132.0 | 132.0 | 132.0 | 132.0 | 132.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 466.0 | 468.0 | 468.0 | 465.6 | 468.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 5.0 | 7.0 | 7.0 | 5.4 | 7.0 |
| `inputValidationMs` | 5 | 2.0 | 5.0 | 5.0 | 2.8 | 5.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 18.0 | 21.0 | 21.0 | 18.6 | 21.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 12.0 | 12.0 | 6.2 | 12.0 |
| `passkeyAuthConfirmationMs` | 5 | 823.0 | 836.0 | 836.0 | 806.8 | 836.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 203.0 | 203.0 | 201.8 | 203.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 621.0 | 634.0 | 634.0 | 604.6 | 634.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 822.0 | 836.0 | 836.0 | 806.4 | 836.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 620.0 | 633.0 | 633.0 | 603.6 | 633.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 620.0 | 633.0 | 633.0 | 603.6 | 633.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 621.0 | 633.0 | 633.0 | 604.4 | 633.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 2.0 | 2.0 | 0.4 | 2.0 |
| `registrationIntentMs` | 5 | 6.0 | 7.0 | 7.0 | 5.4 | 7.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationWarmupMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkTotalMs` | 5 | 1807.0 | 1846.0 | 1846.0 | 1817.4 | 1846.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 4.0 | 4.0 | 1.4 | 4.0 |
| `totalMs` | 5 | 2480.0 | 2735.0 | 2735.0 | 2545.6 | 2735.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 10.0 | 13.0 | 13.0 | 10.2 | 13.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 698.0 | 999.0 | 999.0 | 777.0 | 999.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 5 | 898.0 | 1108.0 | 1108.0 | 957.0 | 1108.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 5 | 45.0 | 50.0 | 50.0 | 42.8 | 50.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 3.0 | 22.0 | 22.0 | 6.6 | 22.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 3.0 | 22.0 | 22.0 | 6.6 | 22.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2480.0 | 2735.0 | 2735.0 | 2545.4 | 2735.0 |
| `walletRegisterFinalizeMs` | 5 | 217.0 | 222.0 | 222.0 | 217.6 | 222.0 |
| `walletRegisterHssRespondMs` | 5 | 101.0 | 112.0 | 112.0 | 104.0 | 112.0 |
| `walletRegisterPrepareMs` | 5 | 378.0 | 466.0 | 466.0 | 394.4 | 466.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 8.0 | 115.0 | 115.0 | 28.8 | 115.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 209.0 | 213.0 | 213.0 | 209.2 | 213.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 209.0 | 212.0 | 212.0 | 208.8 | 212.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 | 4.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 91.0 | 103.0 | 103.0 | 93.8 | 103.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 91.0 | 103.0 | 103.0 | 93.8 | 103.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 72.0 | 80.0 | 80.0 | 73.4 | 80.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 365.0 | 450.0 | 450.0 | 380.8 | 450.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 350.0 | 361.0 | 361.0 | 350.8 | 361.0 |
| `registrationHssServerInputDeriveMs` | 5 | 358.0 | 361.0 | 361.0 | 301.2 | 361.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 352.0 | 436.0 | 436.0 | 367.4 | 436.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 365.0 | 450.0 | 450.0 | 380.6 | 450.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 110.0 | 110.0 | 22.8 | 110.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 109.0 | 109.0 | 22.6 | 109.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 369.0 | 376.0 | 369.0 | 373.0 | 383 | 23046 |
| `respond` | 5 | 101.0 | 103.0 | 100.0 | 101.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 465.0 | 468.0 | 0.0 | 0.0 | 465.0 | 468.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 125.0 | 131.0 | 0.0 | 0.0 | 125.0 | 131.0 | 0.0 | 22956 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 459.0 | 461.0 | 459.0 | 461.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 2.0 | 2.0 | 1.6 | 2.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 23.0 | 23.0 | 22.6 | 23.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 40.0 | 40.0 | 39.8 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 4.0 | 5.0 | 4.4 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 53.0 | 54.0 | 53.4 | 54.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 25.0 | 25.0 | 24.8 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 147.0 | 150.0 | 147.2 | 150.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 19.0 | 20.0 | 19.4 | 20.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 59.0 | 60.0 | 58.8 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 23.0 | 24.0 | 23.4 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 233.0 | 234.0 | 232.6 | 234.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 32.0 | 33.0 | 32.2 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 23.0 | 24.0 | 23.0 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 23.0 | 24.0 | 23.0 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 7.0 | 8.0 | 7.2 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.8 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 3.6 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 423.0 | 425.0 | 422.2 | 425.0 |
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
| `authProofMs` | 5 | 845.0 | 858.0 | 858.0 | 819.4 | 858.0 |
| `browserRunDurationMs` | 5 | 2502.0 | 2895.0 | 2895.0 | 2611.8 | 2895.0 |
| `ecdsaClientBootstrapMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 7.0 | 11.0 | 11.0 | 8.0 | 11.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 21.0 | 21.0 | 20.6 | 21.0 |
| `ed25519ClientRequestMs` | 5 | 134.0 | 143.0 | 143.0 | 136.2 | 143.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 471.0 | 487.0 | 487.0 | 473.8 | 487.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 12.0 | 16.0 | 16.0 | 12.6 | 16.0 |
| `inputValidationMs` | 5 | 3.0 | 3.0 | 3.0 | 2.8 | 3.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 19.0 | 20.0 | 20.0 | 19.0 | 20.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 13.0 | 13.0 | 6.2 | 13.0 |
| `passkeyAuthConfirmationMs` | 5 | 845.0 | 858.0 | 858.0 | 819.2 | 858.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 205.0 | 205.0 | 202.4 | 205.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 644.0 | 655.0 | 655.0 | 616.4 | 655.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 845.0 | 857.0 | 857.0 | 818.8 | 857.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 643.0 | 654.0 | 654.0 | 615.2 | 654.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 643.0 | 655.0 | 655.0 | 615.6 | 655.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 644.0 | 655.0 | 655.0 | 616.4 | 655.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 8.0 | 8.0 | 2.6 | 8.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationWarmupMs` | 5 | 2.0 | 9.0 | 9.0 | 3.2 | 9.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkTotalMs` | 5 | 1869.0 | 1933.0 | 1933.0 | 1878.6 | 1933.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2502.0 | 2895.0 | 2895.0 | 2611.8 | 2895.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 9.0 | 34.0 | 34.0 | 15.0 | 34.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 666.0 | 1009.0 | 1009.0 | 775.6 | 1009.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 4 | 870.0 | 1113.0 | 1113.0 | 933.3 | 1113.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 4 | 38.0 | 44.0 | 44.0 | 40.5 | 44.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 3.0 | 59.0 | 59.0 | 14.4 | 59.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 3.0 | 59.0 | 59.0 | 14.2 | 59.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2502.0 | 2875.0 | 2875.0 | 2607.4 | 2875.0 |
| `walletRegisterFinalizeMs` | 5 | 216.0 | 224.0 | 224.0 | 218.6 | 224.0 |
| `walletRegisterHssRespondMs` | 5 | 115.0 | 186.0 | 186.0 | 128.4 | 186.0 |
| `walletRegisterPrepareMs` | 5 | 379.0 | 459.0 | 459.0 | 395.4 | 459.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 8.0 | 103.0 | 103.0 | 26.2 | 103.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 209.0 | 216.0 | 216.0 | 211.2 | 216.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.4 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 209.0 | 214.0 | 214.0 | 210.2 | 214.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 5.0 | 5.0 | 4.4 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 102.0 | 174.0 | 174.0 | 116.4 | 174.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 77.0 | 77.0 | 24.2 | 77.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 91.0 | 96.0 | 96.0 | 92.0 | 96.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 72.0 | 74.0 | 74.0 | 72.0 | 74.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 367.0 | 442.0 | 442.0 | 381.4 | 442.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 352.0 | 362.0 | 362.0 | 352.8 | 362.0 |
| `registrationHssServerInputDeriveMs` | 5 | 361.0 | 365.0 | 365.0 | 301.8 | 365.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 353.0 | 429.0 | 429.0 | 367.6 | 429.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationPreauthHssPrepareMs` | 5 | 367.0 | 441.0 | 441.0 | 380.8 | 441.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 97.0 | 97.0 | 20.2 | 97.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 97.0 | 97.0 | 20.0 | 97.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 372.0 | 378.0 | 372.0 | 378.0 | 388 | 23053 |
| `respond` | 5 | 102.0 | 103.0 | 101.0 | 102.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 470.0 | 486.0 | 0.0 | 0.0 | 470.0 | 486.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 124.0 | 133.0 | 0.0 | 0.0 | 124.0 | 133.0 | 0.0 | 22963 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 464.0 | 478.0 | 466.0 | 478.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 2.0 | 1.4 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 0.0 | 1.0 | 0.4 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 40.0 | 42.0 | 40.4 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 54.0 | 55.0 | 54.2 | 55.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 3.8 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 25.0 | 27.0 | 25.0 | 27.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 148.0 | 151.0 | 148.2 | 151.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 20.0 | 22.0 | 20.0 | 22.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 59.0 | 60.0 | 58.8 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 24.0 | 25.0 | 24.2 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 235.0 | 244.0 | 237.2 | 244.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 33.0 | 33.0 | 32.4 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 24.0 | 25.0 | 23.8 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 24.0 | 24.0 | 23.8 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 7.8 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.2 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 7.0 | 8.0 | 7.2 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 427.0 | 440.0 | 429.0 | 440.0 |
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
| `authProofMs` | 5 | 202.0 | 206.0 | 206.0 | 203.0 | 206.0 |
| `browserRunDurationMs` | 5 | 1852.0 | 1898.0 | 1898.0 | 1862.2 | 1898.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 218.0 | 241.0 | 241.0 | 221.8 | 241.0 |
| `ed25519ClientRequestMs` | 5 | 210.0 | 213.0 | 213.0 | 195.6 | 213.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 466.0 | 476.0 | 476.0 | 467.0 | 476.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 3.0 | 8.0 | 8.0 | 4.6 | 8.0 |
| `inputValidationMs` | 5 | 2.0 | 5.0 | 5.0 | 3.0 | 5.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 5.0 | 10.0 | 10.0 | 6.6 | 10.0 |
| `managedRegistrationGrantMs` | 5 | 2.0 | 14.0 | 14.0 | 4.4 | 14.0 |
| `passkeyAuthConfirmationMs` | 5 | 202.0 | 206.0 | 206.0 | 203.0 | 206.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 205.0 | 205.0 | 202.6 | 205.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 202.0 | 205.0 | 205.0 | 202.6 | 205.0 |
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
| `registrationIntentMs` | 5 | 3.0 | 7.0 | 7.0 | 3.4 | 7.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 2.0 | 4.0 | 4.0 | 2.4 | 4.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationWarmupMs` | 5 | 7.0 | 16.0 | 16.0 | 9.6 | 16.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 4.0 | 11.0 | 11.0 | 6.2 | 11.0 |
| `registrationWarmupWaitMs` | 5 | 2.0 | 6.0 | 6.0 | 2.4 | 6.0 |
| `sdkTotalMs` | 5 | 1480.0 | 1523.0 | 1523.0 | 1489.4 | 1523.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `totalMs` | 5 | 1852.0 | 1898.0 | 1898.0 | 1862.2 | 1898.0 |
| `walletRegisterFinalizeMs` | 5 | 217.0 | 219.0 | 219.0 | 215.8 | 219.0 |
| `walletRegisterHssRespondMs` | 5 | 96.0 | 101.0 | 101.0 | 97.0 | 101.0 |
| `walletRegisterPrepareMs` | 5 | 377.0 | 439.0 | 439.0 | 388.0 | 439.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 53.0 | 101.0 | 101.0 | 62.2 | 101.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 208.0 | 212.0 | 212.0 | 208.8 | 212.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 208.0 | 211.0 | 211.0 | 208.6 | 211.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 91.0 | 96.0 | 96.0 | 92.0 | 96.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 | 5.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 91.0 | 96.0 | 96.0 | 92.0 | 96.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 71.0 | 74.0 | 74.0 | 71.6 | 74.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 370.0 | 435.0 | 435.0 | 383.2 | 435.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 359.0 | 359.0 | 355.8 | 359.0 |
| `registrationHssServerInputDeriveMs` | 5 | 366.0 | 368.0 | 368.0 | 304.8 | 368.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 357.0 | 425.0 | 425.0 | 370.4 | 425.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 370.0 | 434.0 | 434.0 | 382.8 | 434.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 98.0 | 98.0 | 20.6 | 98.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 97.0 | 97.0 | 20.4 | 97.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1191.0 | 1200.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 51.0 | 52.0 | 50.0 | 51.0 | 154690 | 39461 |
| `prepare` | 5 | 368.0 | 368.0 | 367.0 | 367.0 | 381 | 23043 |
| `respond` | 5 | 97.0 | 101.0 | 96.0 | 100.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 465.0 | 475.0 | 0.0 | 0.0 | 465.0 | 475.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 89.0 | 90.0 | 0.0 | 0.0 | 89.0 | 90.0 | 0.0 | 40079 | 86 |
| `prepare_client_request` | 10 | 122.0 | 131.0 | 0.0 | 0.0 | 122.0 | 131.0 | 0.0 | 22953 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 462.0 | 469.0 | 462.8 | 469.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.3 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 22.0 | 23.0 | 22.4 | 23.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 39.0 | 40.0 | 39.4 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 5.0 | 5.0 | 4.8 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 55.0 | 57.0 | 55.3 | 57.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 24.0 | 25.0 | 23.9 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 149.0 | 151.0 | 148.9 | 151.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 19.0 | 20.0 | 19.0 | 20.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 60.0 | 61.0 | 59.6 | 61.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 24.0 | 25.0 | 23.9 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 236.0 | 242.0 | 237.9 | 242.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 33.0 | 34.0 | 32.7 | 34.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 24.0 | 25.0 | 23.9 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 24.0 | 25.0 | 23.9 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 2.0 | 3.0 | 2.3 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 7.0 | 8.0 | 7.4 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 427.0 | 434.0 | 428.8 | 434.0 |
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
| `authProofMs` | 5 | 202.0 | 204.0 | 204.0 | 202.4 | 204.0 |
| `browserRunDurationMs` | 5 | 1895.0 | 2018.0 | 2018.0 | 1913.0 | 2018.0 |
| `ecdsaClientBootstrapMs` | 5 | 88.0 | 88.0 | 88.0 | 70.6 | 88.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 10.0 | 11.0 | 11.0 | 8.8 | 11.0 |
| `ed25519ClientMaterialMs` | 5 | 215.0 | 239.0 | 239.0 | 218.0 | 239.0 |
| `ed25519ClientRequestMs` | 5 | 211.0 | 217.0 | 217.0 | 196.8 | 217.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 466.0 | 484.0 | 484.0 | 467.4 | 484.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 9.0 | 12.0 | 12.0 | 8.4 | 12.0 |
| `inputValidationMs` | 5 | 4.0 | 8.0 | 8.0 | 4.2 | 8.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 5.0 | 10.0 | 10.0 | 6.0 | 10.0 |
| `managedRegistrationGrantMs` | 5 | 8.0 | 9.0 | 9.0 | 6.2 | 9.0 |
| `passkeyAuthConfirmationMs` | 5 | 202.0 | 204.0 | 204.0 | 202.4 | 204.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 203.0 | 203.0 | 202.0 | 203.0 |
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
| `registrationIntentMs` | 5 | 3.0 | 13.0 | 13.0 | 5.0 | 13.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 2.0 | 10.0 | 10.0 | 3.8 | 10.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 1.0 | 7.0 | 7.0 | 1.8 | 7.0 |
| `registrationWarmupMs` | 5 | 13.0 | 17.0 | 17.0 | 11.8 | 17.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 5.0 | 11.0 | 11.0 | 6.0 | 11.0 |
| `registrationWarmupWaitMs` | 5 | 2.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `sdkTotalMs` | 5 | 1511.0 | 1642.0 | 1642.0 | 1534.8 | 1642.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 3.0 | 3.0 | 1.2 | 3.0 |
| `totalMs` | 5 | 1895.0 | 2018.0 | 2018.0 | 1913.0 | 2018.0 |
| `walletRegisterFinalizeMs` | 5 | 219.0 | 223.0 | 223.0 | 218.2 | 223.0 |
| `walletRegisterHssRespondMs` | 5 | 112.0 | 178.0 | 178.0 | 124.0 | 178.0 |
| `walletRegisterPrepareMs` | 5 | 375.0 | 440.0 | 440.0 | 386.0 | 440.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 52.0 | 116.0 | 116.0 | 65.2 | 116.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 212.0 | 215.0 | 215.0 | 211.0 | 215.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `registrationHssFinalizeMs` | 5 | 211.0 | 213.0 | 213.0 | 209.8 | 213.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 104.0 | 171.0 | 171.0 | 117.0 | 171.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 76.0 | 76.0 | 24.2 | 76.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 | 5.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 93.0 | 95.0 | 95.0 | 92.8 | 95.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 72.0 | 74.0 | 74.0 | 72.6 | 74.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 371.0 | 434.0 | 434.0 | 381.4 | 434.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 355.0 | 360.0 | 360.0 | 354.4 | 360.0 |
| `registrationHssServerInputDeriveMs` | 5 | 364.0 | 367.0 | 367.0 | 303.2 | 367.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 357.0 | 425.0 | 425.0 | 368.8 | 425.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 371.0 | 433.0 | 433.0 | 381.0 | 433.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 2.0 | 108.0 | 108.0 | 23.2 | 108.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 101.0 | 101.0 | 21.2 | 101.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 6.0 | 6.0 | 1.2 | 6.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1193.0 | 1207.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 51.0 | 51.0 | 51.0 | 51.0 | 154690 | 39461 |
| `prepare` | 5 | 370.0 | 376.0 | 370.0 | 370.0 | 386 | 23050 |
| `respond` | 5 | 96.0 | 100.0 | 95.0 | 99.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 464.0 | 483.0 | 0.0 | 0.0 | 464.0 | 483.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 90.0 | 91.0 | 0.0 | 0.0 | 90.0 | 91.0 | 0.0 | 40086 | 86 |
| `prepare_client_request` | 10 | 122.0 | 132.0 | 0.0 | 0.0 | 122.0 | 132.0 | 0.0 | 22960 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 462.0 | 476.0 | 462.9 | 476.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 0.9 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 3.0 | 3.0 | 2.6 | 3.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 22.0 | 23.0 | 22.4 | 23.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 39.0 | 40.0 | 38.9 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 56.0 | 57.0 | 55.6 | 57.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 3.8 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 24.0 | 25.0 | 24.2 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 150.0 | 153.0 | 149.4 | 153.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 19.0 | 19.0 | 19.0 | 19.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 60.0 | 62.0 | 60.0 | 62.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 24.0 | 25.0 | 23.8 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 237.0 | 249.0 | 237.3 | 249.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 32.0 | 34.0 | 32.2 | 34.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 23.0 | 25.0 | 23.6 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 23.0 | 25.0 | 23.6 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 7.9 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.6 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 7.0 | 8.0 | 7.3 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 5.0 | 4.1 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 429.0 | 438.0 | 428.7 | 438.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
