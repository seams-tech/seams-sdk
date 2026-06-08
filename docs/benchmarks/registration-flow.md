# Registration Flow Benchmark Report

Generated: 2026-06-08T09:23:12.305Z
Run ID: `20260608-092157Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 3334.0 | 4177.0 | 1997.0 | 2548.0 | 15 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 3115.0 | 3890.0 | 2036.0 | 2265.0 | 15 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 2594.0 | 2797.0 | 1717.0 | 1973.0 | 15 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 2635.0 | 2902.0 | 1750.0 | 2014.0 | 15 | 18 | 23 |

## passkey_ed25519_only_wallet_iframe

- Description: Passkey registration, Ed25519 only, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 15
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 517.0 | 856.0 | 856.0 | 637.4 | 856.0 |
| `browserRunDurationMs` | 5 | 3334.0 | 4177.0 | 4177.0 | 3470.2 | 4177.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 22.0 | 26.0 | 26.0 | 22.4 | 26.0 |
| `ed25519ClientRequestMs` | 5 | 134.0 | 140.0 | 140.0 | 135.0 | 140.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 573.0 | 574.0 | 574.0 | 572.8 | 574.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 5.0 | 11.0 | 11.0 | 6.6 | 11.0 |
| `inputValidationMs` | 5 | 3.0 | 7.0 | 7.0 | 4.2 | 7.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 18.0 | 23.0 | 23.0 | 19.6 | 23.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 11.0 | 11.0 | 5.4 | 11.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 2.0 | 2.0 | 0.4 | 2.0 |
| `registrationIntentMs` | 5 | 4.0 | 5.0 | 5.0 | 3.8 | 5.0 |
| `sdkTotalMs` | 5 | 1997.0 | 2548.0 | 2548.0 | 2162.2 | 2548.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `totalMs` | 5 | 3334.0 | 4177.0 | 4177.0 | 3470.2 | 4177.0 |
| `walletRegisterFinalizeMs` | 5 | 226.0 | 229.0 | 229.0 | 225.4 | 229.0 |
| `walletRegisterHssRespondMs` | 5 | 109.0 | 115.0 | 115.0 | 109.0 | 115.0 |
| `walletRegisterStartMs` | 5 | 383.0 | 565.0 | 565.0 | 418.6 | 565.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 216.0 | 220.0 | 220.0 | 216.0 | 220.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 216.0 | 220.0 | 220.0 | 215.8 | 220.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 95.0 | 99.0 | 99.0 | 95.4 | 99.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 94.0 | 99.0 | 99.0 | 95.2 | 99.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 73.0 | 76.0 | 76.0 | 73.8 | 76.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 376.0 | 560.0 | 560.0 | 412.4 | 560.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 114.0 | 114.0 | 23.4 | 114.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 375.0 | 446.0 | 446.0 | 389.0 | 446.0 |
| `registrationHssPrepareSessionMs` | 5 | 359.0 | 365.0 | 365.0 | 360.0 | 365.0 |
| `registrationHssServerInputDeriveMs` | 5 | 371.0 | 434.0 | 434.0 | 383.0 | 434.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 361.0 | 373.0 | 373.0 | 363.2 | 373.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 380.0 | 382.0 | 379.0 | 382.0 | 383 | 23046 |
| `respond` | 5 | 107.0 | 109.0 | 106.0 | 107.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 571.0 | 574.0 | 571.0 | 574.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 125.0 | 133.0 | 125.0 | 133.0 | 0.0 | 22956 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 565.0 | 568.0 | 565.8 | 568.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 2.0 | 2.0 | 1.8 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.6 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 41.0 | 42.0 | 41.4 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 58.0 | 60.0 | 58.6 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 6.0 | 6.0 | 6.0 | 6.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 55.0 | 56.0 | 55.4 | 56.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 7.0 | 7.0 | 7.0 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 40.0 | 40.0 | 40.0 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 169.0 | 170.0 | 169.2 | 170.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 31.0 | 32.0 | 31.4 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 58.0 | 59.0 | 58.2 | 59.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 8.0 | 9.0 | 8.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 32.0 | 32.0 | 31.8 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 294.0 | 297.0 | 294.8 | 297.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 39.0 | 39.0 | 38.6 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 46.0 | 47.0 | 45.8 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 46.0 | 46.0 | 45.8 | 46.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 7.0 | 8.0 | 7.4 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.2 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 5.0 | 4.2 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 526.0 | 530.0 | 527.4 | 530.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_wallet_iframe

- Description: Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 15
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 538.0 | 540.0 | 540.0 | 528.4 | 540.0 |
| `browserRunDurationMs` | 5 | 3115.0 | 3890.0 | 3890.0 | 3271.0 | 3890.0 |
| `ecdsaClientBootstrapMs` | 5 | 3.0 | 5.0 | 5.0 | 3.4 | 5.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 12.0 | 28.0 | 28.0 | 13.2 | 28.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 28.0 | 28.0 | 23.0 | 28.0 |
| `ed25519ClientRequestMs` | 5 | 136.0 | 139.0 | 139.0 | 136.6 | 139.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 569.0 | 591.0 | 591.0 | 573.2 | 591.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 12.0 | 14.0 | 14.0 | 10.6 | 14.0 |
| `inputValidationMs` | 5 | 2.0 | 3.0 | 3.0 | 2.2 | 3.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 18.0 | 22.0 | 22.0 | 19.4 | 22.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 9.0 | 9.0 | 4.2 | 9.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 6.0 | 6.0 | 6.0 | 5.6 | 6.0 |
| `sdkTotalMs` | 5 | 2036.0 | 2265.0 | 2265.0 | 2080.8 | 2265.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 2.0 | 2.0 | 1.0 | 2.0 |
| `totalMs` | 5 | 3115.0 | 3890.0 | 3890.0 | 3271.0 | 3890.0 |
| `walletRegisterFinalizeMs` | 5 | 221.0 | 230.0 | 230.0 | 223.4 | 230.0 |
| `walletRegisterHssRespondMs` | 5 | 118.0 | 186.0 | 186.0 | 130.6 | 186.0 |
| `walletRegisterStartMs` | 5 | 377.0 | 537.0 | 537.0 | 409.2 | 537.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 213.0 | 221.0 | 221.0 | 215.0 | 221.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 212.0 | 218.0 | 218.0 | 213.4 | 218.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 106.0 | 174.0 | 174.0 | 118.8 | 174.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 77.0 | 77.0 | 24.2 | 77.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 94.0 | 97.0 | 97.0 | 94.6 | 97.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 74.0 | 75.0 | 75.0 | 74.4 | 75.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 372.0 | 532.0 | 532.0 | 404.2 | 532.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 90.0 | 90.0 | 18.8 | 90.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 370.0 | 373.0 | 373.0 | 296.8 | 373.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 370.0 | 441.0 | 441.0 | 384.6 | 441.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 365.0 | 365.0 | 357.2 | 365.0 |
| `registrationHssServerInputDeriveMs` | 5 | 366.0 | 431.0 | 431.0 | 379.2 | 431.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 357.0 | 372.0 | 372.0 | 360.0 | 372.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 379.0 | 381.0 | 379.0 | 380.0 | 388 | 23053 |
| `respond` | 5 | 103.0 | 105.0 | 102.0 | 104.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 569.0 | 589.0 | 569.0 | 589.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 125.0 | 133.0 | 125.0 | 133.0 | 0.0 | 22963 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 563.0 | 583.0 | 566.4 | 583.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 2.0 | 1.4 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.8 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 5.0 | 5.0 | 4.8 | 5.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 41.0 | 41.0 | 40.6 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 58.0 | 58.0 | 58.0 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 6.0 | 6.0 | 6.0 | 6.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 56.0 | 57.0 | 56.0 | 57.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 7.0 | 7.0 | 7.0 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 40.0 | 41.0 | 40.2 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 168.0 | 172.0 | 169.0 | 172.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 31.0 | 32.0 | 31.2 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 58.0 | 60.0 | 58.6 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 8.0 | 9.0 | 8.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 31.0 | 33.0 | 31.8 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 294.0 | 310.0 | 296.8 | 310.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 38.0 | 41.0 | 38.6 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 46.0 | 47.0 | 45.6 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 45.0 | 47.0 | 45.6 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.4 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 3.6 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 525.0 | 544.0 | 528.8 | 544.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_only_host_origin

- Description: Passkey registration, Ed25519 only, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 15
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 208.0 | 261.0 | 261.0 | 218.0 | 261.0 |
| `browserRunDurationMs` | 5 | 2594.0 | 2797.0 | 2797.0 | 2583.4 | 2797.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 56.0 | 318.0 | 318.0 | 102.2 | 318.0 |
| `ed25519ClientRequestMs` | 5 | 123.0 | 132.0 | 132.0 | 125.0 | 132.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 563.0 | 568.0 | 568.0 | 564.2 | 568.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 4.0 | 12.0 | 12.0 | 5.4 | 12.0 |
| `inputValidationMs` | 5 | 2.0 | 4.0 | 4.0 | 2.2 | 4.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 3.0 | 13.0 | 13.0 | 6.0 | 13.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 10.0 | 10.0 | 4.0 | 10.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentMs` | 5 | 2.0 | 27.0 | 27.0 | 7.6 | 27.0 |
| `sdkTotalMs` | 5 | 1717.0 | 1973.0 | 1973.0 | 1802.6 | 1973.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2594.0 | 2797.0 | 2797.0 | 2583.4 | 2797.0 |
| `walletRegisterFinalizeMs` | 5 | 220.0 | 223.0 | 223.0 | 219.6 | 223.0 |
| `walletRegisterHssRespondMs` | 5 | 99.0 | 107.0 | 107.0 | 100.2 | 107.0 |
| `walletRegisterStartMs` | 5 | 424.0 | 535.0 | 535.0 | 445.6 | 535.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 213.0 | 218.0 | 218.0 | 213.4 | 218.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.4 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 212.0 | 217.0 | 217.0 | 212.6 | 217.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 5.0 | 5.0 | 4.4 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 92.0 | 99.0 | 99.0 | 93.6 | 99.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.4 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 92.0 | 99.0 | 99.0 | 93.6 | 99.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 73.0 | 76.0 | 76.0 | 73.4 | 76.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 374.0 | 531.0 | 531.0 | 404.2 | 531.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 94.0 | 94.0 | 19.6 | 94.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 372.0 | 437.0 | 437.0 | 384.2 | 437.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 361.0 | 361.0 | 357.0 | 361.0 |
| `registrationHssServerInputDeriveMs` | 5 | 367.0 | 370.0 | 370.0 | 306.4 | 370.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 358.0 | 427.0 | 427.0 | 371.6 | 427.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1297.0 | 1301.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 51.0 | 52.0 | 50.0 | 52.0 | 154690 | 39461 |
| `prepare` | 5 | 375.0 | 377.0 | 374.0 | 375.0 | 381 | 23043 |
| `respond` | 5 | 98.0 | 100.0 | 97.0 | 99.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 562.0 | 568.0 | 562.0 | 568.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 91.0 | 92.0 | 91.0 | 92.0 | 0.0 | 40079 | 86 |
| `prepare_client_request` | 10 | 123.0 | 131.0 | 123.0 | 131.0 | 0.0 | 22953 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 560.0 | 564.0 | 558.4 | 564.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.1 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 1.0 | 1.0 | 0.6 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 4.0 | 5.0 | 4.1 | 5.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 40.0 | 41.0 | 40.0 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 56.0 | 58.0 | 56.6 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 6.0 | 6.0 | 6.0 | 6.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 57.0 | 58.0 | 56.9 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 7.0 | 7.0 | 7.0 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 39.0 | 39.0 | 38.8 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 170.0 | 172.0 | 169.7 | 172.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 30.0 | 31.0 | 30.1 | 31.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 60.0 | 60.0 | 59.3 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 31.0 | 33.0 | 31.1 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 293.0 | 298.0 | 293.3 | 298.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 38.0 | 39.0 | 38.0 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 45.0 | 47.0 | 45.3 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 45.0 | 47.0 | 45.4 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.9 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.7 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 525.0 | 528.0 | 523.9 | 528.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_host_origin

- Description: Passkey registration, Ed25519 plus ECDSA, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 15
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 208.0 | 211.0 | 211.0 | 208.6 | 211.0 |
| `browserRunDurationMs` | 5 | 2635.0 | 2902.0 | 2902.0 | 2679.6 | 2902.0 |
| `ecdsaClientBootstrapMs` | 5 | 1.0 | 4.0 | 4.0 | 2.0 | 4.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 10.0 | 11.0 | 11.0 | 10.4 | 11.0 |
| `ed25519ClientMaterialMs` | 5 | 58.0 | 68.0 | 68.0 | 51.8 | 68.0 |
| `ed25519ClientRequestMs` | 5 | 123.0 | 140.0 | 140.0 | 126.8 | 140.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 563.0 | 567.0 | 567.0 | 561.6 | 567.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 5.0 | 19.0 | 19.0 | 7.8 | 19.0 |
| `inputValidationMs` | 5 | 2.0 | 20.0 | 20.0 | 5.8 | 20.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 5.0 | 19.0 | 19.0 | 7.2 | 19.0 |
| `managedRegistrationGrantMs` | 5 | 6.0 | 33.0 | 33.0 | 10.2 | 33.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 3.0 | 9.0 | 9.0 | 4.2 | 9.0 |
| `sdkTotalMs` | 5 | 1750.0 | 2014.0 | 2014.0 | 1796.8 | 2014.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2635.0 | 2902.0 | 2902.0 | 2679.6 | 2902.0 |
| `walletRegisterFinalizeMs` | 5 | 219.0 | 258.0 | 258.0 | 227.8 | 258.0 |
| `walletRegisterHssRespondMs` | 5 | 111.0 | 175.0 | 175.0 | 123.4 | 175.0 |
| `walletRegisterStartMs` | 5 | 428.0 | 536.0 | 536.0 | 449.0 | 536.0 |
| `walletStateActivationMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 213.0 | 238.0 | 238.0 | 218.0 | 238.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeMs` | 5 | 212.0 | 236.0 | 236.0 | 217.2 | 236.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 104.0 | 169.0 | 169.0 | 117.0 | 169.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 72.0 | 72.0 | 23.4 | 72.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 93.0 | 97.0 | 97.0 | 93.6 | 97.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 72.0 | 75.0 | 75.0 | 72.8 | 75.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 375.0 | 531.0 | 531.0 | 405.6 | 531.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 96.0 | 96.0 | 19.8 | 96.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 372.0 | 375.0 | 375.0 | 298.6 | 375.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 3.0 | 3.0 | 1.6 | 3.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 371.0 | 435.0 | 435.0 | 384.4 | 435.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 362.0 | 362.0 | 357.8 | 362.0 |
| `registrationHssServerInputDeriveMs` | 5 | 367.0 | 426.0 | 426.0 | 379.4 | 426.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 358.0 | 370.0 | 370.0 | 360.8 | 370.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1300.0 | 1311.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 52.0 | 52.0 | 51.0 | 52.0 | 154690 | 39461 |
| `prepare` | 5 | 376.0 | 380.0 | 376.0 | 379.0 | 386 | 23050 |
| `respond` | 5 | 98.0 | 99.0 | 97.0 | 98.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 561.0 | 567.0 | 561.0 | 567.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 90.0 | 91.0 | 90.0 | 91.0 | 0.0 | 40086 | 86 |
| `prepare_client_request` | 10 | 122.0 | 136.0 | 122.0 | 136.0 | 0.0 | 22960 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 559.0 | 565.0 | 558.0 | 565.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 4.0 | 5.0 | 4.1 | 5.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 40.0 | 40.0 | 39.8 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 56.0 | 57.0 | 56.4 | 57.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 6.0 | 6.0 | 6.0 | 6.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 57.0 | 63.0 | 57.7 | 63.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 7.0 | 7.0 | 7.0 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 38.0 | 39.0 | 38.3 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 170.0 | 176.0 | 170.4 | 176.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 30.0 | 31.0 | 30.1 | 31.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 60.0 | 60.0 | 59.8 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 8.0 | 9.0 | 8.1 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 31.0 | 32.0 | 31.2 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 292.0 | 297.0 | 292.9 | 297.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 38.0 | 38.0 | 37.7 | 38.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 45.0 | 45.0 | 44.8 | 45.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 45.0 | 46.0 | 45.1 | 46.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.7 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 523.0 | 532.0 | 523.7 | 532.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
