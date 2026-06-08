# Registration Flow Benchmark Report

Generated: 2026-06-08T05:32:04.303Z
Run ID: `20260608-053047Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 3210.0 | 4314.0 | 2112.0 | 2625.0 | 15 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 3228.0 | 3981.0 | 2134.0 | 2359.0 | 15 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 2816.0 | 2969.0 | 1933.0 | 2076.0 | 15 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 2845.0 | 2978.0 | 1958.0 | 2079.0 | 15 | 18 | 23 |

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
| `authProofMs` | 5 | 552.0 | 837.0 | 837.0 | 655.0 | 837.0 |
| `browserRunDurationMs` | 5 | 3210.0 | 4314.0 | 4314.0 | 3526.0 | 4314.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 25.0 | 27.0 | 27.0 | 23.6 | 27.0 |
| `ed25519ClientRequestMs` | 5 | 133.0 | 141.0 | 141.0 | 134.2 | 141.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 668.0 | 677.0 | 677.0 | 669.0 | 677.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 5.0 | 8.0 | 8.0 | 5.4 | 8.0 |
| `inputValidationMs` | 5 | 2.0 | 6.0 | 6.0 | 3.0 | 6.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 19.0 | 24.0 | 24.0 | 19.6 | 24.0 |
| `managedRegistrationGrantMs` | 5 | 6.0 | 14.0 | 14.0 | 6.6 | 14.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 2.0 | 2.0 | 0.4 | 2.0 |
| `registrationIntentMs` | 5 | 4.0 | 6.0 | 6.0 | 4.0 | 6.0 |
| `sdkTotalMs` | 5 | 2112.0 | 2625.0 | 2625.0 | 2263.8 | 2625.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 3210.0 | 4314.0 | 4314.0 | 3526.0 | 4314.0 |
| `walletRegisterFinalizeMs` | 5 | 224.0 | 225.0 | 225.0 | 223.4 | 225.0 |
| `walletRegisterHssRespondMs` | 5 | 107.0 | 113.0 | 113.0 | 108.0 | 113.0 |
| `walletRegisterStartMs` | 5 | 376.0 | 551.0 | 551.0 | 411.2 | 551.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 213.0 | 217.0 | 217.0 | 213.8 | 217.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.4 | 4.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 213.0 | 216.0 | 216.0 | 213.0 | 216.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationKeygenMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 94.0 | 100.0 | 100.0 | 95.2 | 100.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.4 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 94.0 | 100.0 | 100.0 | 95.2 | 100.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 73.0 | 76.0 | 76.0 | 73.4 | 76.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 371.0 | 545.0 | 545.0 | 405.4 | 545.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 92.0 | 92.0 | 19.2 | 92.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareMs` | 5 | 370.0 | 453.0 | 453.0 | 386.2 | 453.0 |
| `registrationHssPrepareSessionMs` | 5 | 354.0 | 363.0 | 363.0 | 355.8 | 363.0 |
| `registrationHssServerInputDeriveMs` | 5 | 366.0 | 444.0 | 444.0 | 381.2 | 444.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 356.0 | 372.0 | 372.0 | 359.2 | 372.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 376.0 | 389.0 | 376.0 | 389.0 | 383 | 23046 |
| `respond` | 5 | 102.0 | 114.0 | 102.0 | 109.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 667.0 | 674.0 | 667.0 | 674.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 126.0 | 139.0 | 126.0 | 139.0 | 0.0 | 22956 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 661.0 | 669.0 | 662.0 | 669.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 2.0 | 2.0 | 1.6 | 2.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 41.0 | 41.0 | 40.6 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 58.0 | 58.0 | 57.8 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 267.0 | 273.0 | 268.0 | 273.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 31.0 | 32.0 | 31.0 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 292.0 | 299.0 | 293.4 | 299.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 38.0 | 39.0 | 38.0 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 45.0 | 47.0 | 45.6 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 46.0 | 47.0 | 45.6 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.4 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 9.0 | 7.8 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 624.0 | 629.0 | 624.4 | 629.0 |
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
| `authProofMs` | 5 | 520.0 | 540.0 | 540.0 | 525.6 | 540.0 |
| `browserRunDurationMs` | 5 | 3228.0 | 3981.0 | 3981.0 | 3378.6 | 3981.0 |
| `ecdsaClientBootstrapMs` | 5 | 4.0 | 7.0 | 7.0 | 4.4 | 7.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 8.0 | 10.0 | 10.0 | 8.2 | 10.0 |
| `ed25519ClientMaterialMs` | 5 | 24.0 | 25.0 | 25.0 | 23.0 | 25.0 |
| `ed25519ClientRequestMs` | 5 | 139.0 | 141.0 | 141.0 | 138.2 | 141.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 673.0 | 683.0 | 683.0 | 674.2 | 683.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 11.0 | 13.0 | 13.0 | 10.6 | 13.0 |
| `inputValidationMs` | 5 | 3.0 | 6.0 | 6.0 | 3.4 | 6.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 18.0 | 20.0 | 20.0 | 18.2 | 20.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 12.0 | 12.0 | 5.6 | 12.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 4.0 | 5.0 | 5.0 | 4.0 | 5.0 |
| `sdkTotalMs` | 5 | 2134.0 | 2359.0 | 2359.0 | 2177.8 | 2359.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 5.0 | 5.0 | 1.6 | 5.0 |
| `totalMs` | 5 | 3228.0 | 3981.0 | 3981.0 | 3378.6 | 3981.0 |
| `walletRegisterFinalizeMs` | 5 | 222.0 | 230.0 | 230.0 | 222.2 | 230.0 |
| `walletRegisterHssRespondMs` | 5 | 119.0 | 184.0 | 184.0 | 132.2 | 184.0 |
| `walletRegisterStartMs` | 5 | 377.0 | 535.0 | 535.0 | 409.0 | 535.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 215.0 | 221.0 | 221.0 | 214.8 | 221.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 214.0 | 218.0 | 218.0 | 213.4 | 218.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.8 | 5.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 106.0 | 170.0 | 170.0 | 118.4 | 170.0 |
| `registrationEcdsaRespondMs` | 5 | 12.0 | 73.0 | 73.0 | 24.0 | 73.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 94.0 | 97.0 | 97.0 | 94.4 | 97.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 74.0 | 75.0 | 75.0 | 73.8 | 75.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 373.0 | 530.0 | 530.0 | 404.4 | 530.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 93.0 | 93.0 | 19.4 | 93.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 371.0 | 374.0 | 374.0 | 297.8 | 374.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 371.0 | 437.0 | 437.0 | 384.2 | 437.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 363.0 | 363.0 | 357.2 | 363.0 |
| `registrationHssServerInputDeriveMs` | 5 | 367.0 | 428.0 | 428.0 | 379.4 | 428.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 357.0 | 371.0 | 371.0 | 360.0 | 371.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 378.0 | 380.0 | 378.0 | 380.0 | 388 | 23053 |
| `respond` | 5 | 104.0 | 110.0 | 103.0 | 104.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 672.0 | 678.0 | 672.0 | 678.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 124.0 | 135.0 | 124.0 | 135.0 | 0.0 | 22963 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 667.0 | 672.0 | 667.0 | 672.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 2.0 | 1.2 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 41.0 | 45.0 | 41.6 | 45.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 58.0 | 65.0 | 59.4 | 65.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 268.0 | 270.0 | 268.8 | 270.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 32.0 | 32.0 | 31.6 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 296.0 | 303.0 | 296.8 | 303.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 39.0 | 40.0 | 38.6 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 46.0 | 48.0 | 46.2 | 48.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 45.0 | 46.0 | 45.0 | 46.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.8 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 9.0 | 7.8 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 5.0 | 4.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 629.0 | 635.0 | 629.4 | 635.0 |
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
| `authProofMs` | 5 | 210.0 | 216.0 | 216.0 | 211.6 | 216.0 |
| `browserRunDurationMs` | 5 | 2816.0 | 2969.0 | 2969.0 | 2841.4 | 2969.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 161.0 | 176.0 | 176.0 | 135.2 | 176.0 |
| `ed25519ClientRequestMs` | 5 | 124.0 | 133.0 | 133.0 | 125.4 | 133.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 666.0 | 688.0 | 688.0 | 668.6 | 688.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 6.0 | 16.0 | 16.0 | 7.0 | 16.0 |
| `inputValidationMs` | 5 | 2.0 | 18.0 | 18.0 | 6.0 | 18.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 7.0 | 17.0 | 17.0 | 8.6 | 17.0 |
| `managedRegistrationGrantMs` | 5 | 2.0 | 57.0 | 57.0 | 13.2 | 57.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 2.0 | 8.0 | 8.0 | 3.4 | 8.0 |
| `sdkTotalMs` | 5 | 1933.0 | 2076.0 | 2076.0 | 1956.0 | 2076.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2816.0 | 2969.0 | 2969.0 | 2841.4 | 2969.0 |
| `walletRegisterFinalizeMs` | 5 | 219.0 | 225.0 | 225.0 | 219.6 | 225.0 |
| `walletRegisterHssRespondMs` | 5 | 101.0 | 105.0 | 105.0 | 101.0 | 105.0 |
| `walletRegisterStartMs` | 5 | 424.0 | 573.0 | 573.0 | 454.2 | 573.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 214.0 | 219.0 | 219.0 | 213.6 | 219.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 213.0 | 217.0 | 217.0 | 212.8 | 217.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 94.0 | 98.0 | 98.0 | 94.6 | 98.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 93.0 | 98.0 | 98.0 | 94.4 | 98.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 73.0 | 75.0 | 75.0 | 73.4 | 75.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 373.0 | 545.0 | 545.0 | 407.2 | 545.0 |
| `registrationAuthorityVerifyMs` | 5 | 2.0 | 102.0 | 102.0 | 21.6 | 102.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareMs` | 5 | 372.0 | 443.0 | 443.0 | 385.6 | 443.0 |
| `registrationHssPrepareSessionMs` | 5 | 357.0 | 365.0 | 365.0 | 357.8 | 365.0 |
| `registrationHssServerInputDeriveMs` | 5 | 368.0 | 430.0 | 430.0 | 380.0 | 430.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 359.0 | 372.0 | 372.0 | 360.8 | 372.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1407.0 | 1416.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 52.0 | 55.0 | 51.0 | 55.0 | 154690 | 39461 |
| `prepare` | 5 | 374.0 | 377.0 | 373.0 | 376.0 | 381 | 23043 |
| `respond` | 5 | 98.0 | 102.0 | 97.0 | 101.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 666.0 | 687.0 | 666.0 | 687.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 90.0 | 91.0 | 90.0 | 91.0 | 0.0 | 40079 | 86 |
| `prepare_client_request` | 10 | 122.0 | 132.0 | 122.0 | 132.0 | 0.0 | 22953 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 664.0 | 681.0 | 665.4 | 681.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.1 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.3 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 40.0 | 42.0 | 40.2 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 57.0 | 59.0 | 57.0 | 59.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 274.0 | 281.0 | 274.7 | 281.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 31.0 | 32.0 | 31.2 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 294.0 | 300.0 | 294.9 | 300.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 38.0 | 39.0 | 38.0 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 46.0 | 47.0 | 45.8 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 46.0 | 47.0 | 45.7 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.9 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 629.0 | 643.0 | 630.8 | 643.0 |
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
| `authProofMs` | 5 | 210.0 | 215.0 | 215.0 | 210.4 | 215.0 |
| `browserRunDurationMs` | 5 | 2845.0 | 2978.0 | 2978.0 | 2873.4 | 2978.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 3.0 | 3.0 | 0.8 | 3.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 6.0 | 13.0 | 13.0 | 7.0 | 13.0 |
| `ed25519ClientMaterialMs` | 5 | 158.0 | 177.0 | 177.0 | 136.6 | 177.0 |
| `ed25519ClientRequestMs` | 5 | 126.0 | 136.0 | 136.0 | 127.2 | 136.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 668.0 | 671.0 | 671.0 | 668.0 | 671.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 9.0 | 20.0 | 20.0 | 10.0 | 20.0 |
| `inputValidationMs` | 5 | 2.0 | 4.0 | 4.0 | 2.4 | 4.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 10.0 | 18.0 | 18.0 | 10.2 | 18.0 |
| `managedRegistrationGrantMs` | 5 | 2.0 | 8.0 | 8.0 | 3.2 | 8.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 3.0 | 7.0 | 7.0 | 4.2 | 7.0 |
| `sdkTotalMs` | 5 | 1958.0 | 2079.0 | 2079.0 | 1984.0 | 2079.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `totalMs` | 5 | 2845.0 | 2978.0 | 2978.0 | 2873.4 | 2978.0 |
| `walletRegisterFinalizeMs` | 5 | 220.0 | 229.0 | 229.0 | 221.4 | 229.0 |
| `walletRegisterHssRespondMs` | 5 | 112.0 | 181.0 | 181.0 | 125.4 | 181.0 |
| `walletRegisterStartMs` | 5 | 427.0 | 559.0 | 559.0 | 454.4 | 559.0 |
| `walletStateActivationMs` | 5 | 1.0 | 6.0 | 6.0 | 2.0 | 6.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 213.0 | 220.0 | 220.0 | 214.8 | 220.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.4 | 4.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 213.0 | 218.0 | 218.0 | 213.6 | 218.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 5.0 | 5.0 | 4.4 | 5.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 107.0 | 176.0 | 176.0 | 120.0 | 176.0 |
| `registrationEcdsaRespondMs` | 5 | 12.0 | 76.0 | 76.0 | 24.2 | 76.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 94.0 | 100.0 | 100.0 | 95.6 | 100.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 75.0 | 77.0 | 77.0 | 74.2 | 77.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 373.0 | 554.0 | 554.0 | 410.2 | 554.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 113.0 | 113.0 | 23.4 | 113.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 371.0 | 378.0 | 378.0 | 298.6 | 378.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 371.0 | 441.0 | 441.0 | 385.8 | 441.0 |
| `registrationHssPrepareSessionMs` | 5 | 356.0 | 364.0 | 364.0 | 358.2 | 364.0 |
| `registrationHssServerInputDeriveMs` | 5 | 367.0 | 431.0 | 431.0 | 380.8 | 431.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 358.0 | 371.0 | 371.0 | 361.2 | 371.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1418.0 | 1422.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 53.0 | 57.0 | 52.0 | 56.0 | 154690 | 39461 |
| `prepare` | 5 | 379.0 | 389.0 | 379.0 | 388.0 | 386 | 23050 |
| `respond` | 5 | 100.0 | 102.0 | 99.0 | 101.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 667.0 | 670.0 | 667.0 | 670.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 91.0 | 92.0 | 91.0 | 92.0 | 0.0 | 40086 | 86 |
| `prepare_client_request` | 10 | 123.0 | 132.0 | 123.0 | 132.0 | 0.0 | 22960 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 665.0 | 668.0 | 663.9 | 668.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.1 | 2.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 40.0 | 41.0 | 40.2 | 41.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 57.0 | 58.0 | 56.9 | 58.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 275.0 | 276.0 | 273.4 | 276.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 31.0 | 32.0 | 31.0 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 294.0 | 297.0 | 294.3 | 297.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 38.0 | 38.0 | 37.8 | 38.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 45.0 | 46.0 | 45.2 | 46.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 45.0 | 45.0 | 45.0 | 45.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 9.0 | 8.1 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 11.0 | 8.3 | 11.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.9 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.9 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 631.0 | 634.0 | 629.0 | 634.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
