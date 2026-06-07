# Registration Flow Benchmark Report

Generated: 2026-06-07T15:22:40.903Z
Run ID: `20260607-152114Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 3454.0 | 4442.0 | 2347.0 | 2838.0 | 10 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 3769.0 | 4290.0 | 2410.0 | 2715.0 | 10 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 3379.0 | 3402.0 | 2493.0 | 2516.0 | 10 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 3402.0 | 3434.0 | 2513.0 | 2529.0 | 10 | 18 | 23 |

## passkey_ed25519_only_wallet_iframe

- Description: Passkey registration, Ed25519 only, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 10
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 521.0 | 810.0 | 810.0 | 579.4 | 810.0 |
| `browserRunDurationMs` | 5 | 3454.0 | 4442.0 | 4442.0 | 3647.0 | 4442.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 26.0 | 26.0 | 22.0 | 26.0 |
| `ed25519ClientRequestMs` | 5 | 133.0 | 134.0 | 134.0 | 133.2 | 134.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 677.0 | 683.0 | 683.0 | 677.8 | 683.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 5.0 | 13.0 | 13.0 | 6.4 | 13.0 |
| `inputValidationMs` | 5 | 3.0 | 6.0 | 6.0 | 3.2 | 6.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 20.0 | 24.0 | 24.0 | 21.0 | 24.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 11.0 | 11.0 | 5.8 | 11.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 2.0 | 2.0 | 0.4 | 2.0 |
| `registrationIntentMs` | 5 | 4.0 | 11.0 | 11.0 | 5.4 | 11.0 |
| `sdkTotalMs` | 5 | 2347.0 | 2838.0 | 2838.0 | 2443.8 | 2838.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 3454.0 | 4442.0 | 4442.0 | 3647.0 | 4442.0 |
| `walletRegisterFinalizeMs` | 5 | 467.0 | 469.0 | 469.0 | 465.2 | 469.0 |
| `walletRegisterHssRespondMs` | 5 | 109.0 | 111.0 | 111.0 | 108.0 | 111.0 |
| `walletRegisterStartMs` | 5 | 380.0 | 551.0 | 551.0 | 414.6 | 551.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 455.0 | 460.0 | 460.0 | 455.4 | 460.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeMs` | 5 | 454.0 | 458.0 | 458.0 | 454.4 | 458.0 |
| `registrationKeygenMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 373.0 | 545.0 | 545.0 | 407.2 | 545.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 98.0 | 98.0 | 20.2 | 98.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareMs` | 5 | 372.0 | 446.0 | 446.0 | 386.6 | 446.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 381.0 | 408.0 | 381.0 | 408.0 | 383 | 23046 |
| `respond` | 5 | 104.0 | 108.0 | 102.0 | 107.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 676.0 | 679.0 | 676.0 | 679.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 129.0 | 133.0 | 129.0 | 133.0 | 0.0 | 22956 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 670.0 | 673.0 | 669.8 | 673.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 2.0 | 2.0 | 1.6 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 5.0 | 5.0 | 4.8 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 42.0 | 42.0 | 41.4 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 59.0 | 59.0 | 58.8 | 59.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 270.0 | 272.0 | 270.4 | 272.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 32.0 | 32.0 | 31.4 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 296.0 | 299.0 | 296.2 | 299.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 38.0 | 39.0 | 38.2 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 46.0 | 46.0 | 45.6 | 46.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 45.0 | 47.0 | 45.4 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 9.0 | 8.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.6 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 9.0 | 9.0 | 8.6 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 5.0 | 4.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 631.0 | 634.0 | 631.2 | 634.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_wallet_iframe

- Description: Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 10
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 507.0 | 805.0 | 805.0 | 566.2 | 805.0 |
| `browserRunDurationMs` | 5 | 3769.0 | 4290.0 | 4290.0 | 3879.8 | 4290.0 |
| `ecdsaClientBootstrapMs` | 5 | 4.0 | 9.0 | 9.0 | 5.0 | 9.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 10.0 | 13.0 | 13.0 | 10.2 | 13.0 |
| `ed25519ClientMaterialMs` | 5 | 20.0 | 27.0 | 27.0 | 21.0 | 27.0 |
| `ed25519ClientRequestMs` | 5 | 139.0 | 147.0 | 147.0 | 140.2 | 147.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 693.0 | 699.0 | 699.0 | 692.4 | 699.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 11.0 | 18.0 | 18.0 | 12.2 | 18.0 |
| `inputValidationMs` | 5 | 2.0 | 3.0 | 3.0 | 2.2 | 3.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 21.0 | 40.0 | 40.0 | 24.6 | 40.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 12.0 | 12.0 | 5.6 | 12.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 5.0 | 5.0 | 1.6 | 5.0 |
| `registrationIntentMs` | 5 | 6.0 | 10.0 | 10.0 | 6.4 | 10.0 |
| `sdkTotalMs` | 5 | 2410.0 | 2715.0 | 2715.0 | 2510.4 | 2715.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 5.0 | 5.0 | 1.8 | 5.0 |
| `totalMs` | 5 | 3769.0 | 4290.0 | 4290.0 | 3879.8 | 4290.0 |
| `walletRegisterFinalizeMs` | 5 | 467.0 | 474.0 | 474.0 | 468.8 | 474.0 |
| `walletRegisterHssRespondMs` | 5 | 122.0 | 190.0 | 190.0 | 135.4 | 190.0 |
| `walletRegisterStartMs` | 5 | 392.0 | 549.0 | 549.0 | 420.4 | 549.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 459.0 | 464.0 | 464.0 | 460.4 | 464.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 2.0 | 2.0 | 0.8 | 2.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 458.0 | 462.0 | 462.0 | 459.0 | 462.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 383.0 | 544.0 | 544.0 | 414.0 | 544.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 95.0 | 95.0 | 19.8 | 95.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 379.0 | 384.0 | 384.0 | 304.6 | 384.0 |
| `registrationHssPrepareMs` | 5 | 382.0 | 449.0 | 449.0 | 393.4 | 449.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 385.0 | 391.0 | 384.0 | 391.0 | 388 | 23053 |
| `respond` | 5 | 104.0 | 127.0 | 104.0 | 126.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 690.0 | 693.0 | 690.0 | 693.0 | 0.0 | 464361 | 154567 |
| `prepare_client_request` | 10 | 132.0 | 137.0 | 132.0 | 137.0 | 0.0 | 22963 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 684.0 | 687.0 | 683.4 | 687.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 2.0 | 2.0 | 1.6 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.8 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 5 | 5.0 | 5.0 | 4.8 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 41.0 | 42.0 | 41.4 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 59.0 | 60.0 | 59.2 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 280.0 | 284.0 | 279.0 | 284.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 31.0 | 33.0 | 31.8 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 301.0 | 303.0 | 301.4 | 303.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 38.0 | 39.0 | 38.2 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 46.0 | 47.0 | 46.2 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 46.0 | 47.0 | 46.2 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 8.0 | 9.0 | 8.0 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.6 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 3.8 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 646.0 | 649.0 | 645.6 | 649.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_only_host_origin

- Description: Passkey registration, Ed25519 only, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 10
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 211.0 | 212.0 | 212.0 | 210.2 | 212.0 |
| `browserRunDurationMs` | 5 | 3379.0 | 3402.0 | 3402.0 | 3353.2 | 3402.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 184.0 | 201.0 | 201.0 | 153.0 | 201.0 |
| `ed25519ClientRequestMs` | 5 | 126.0 | 137.0 | 137.0 | 127.8 | 137.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 682.0 | 697.0 | 697.0 | 685.2 | 697.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 4.0 | 13.0 | 13.0 | 5.4 | 13.0 |
| `inputValidationMs` | 5 | 8.0 | 16.0 | 16.0 | 7.2 | 16.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 6.0 | 16.0 | 16.0 | 8.4 | 16.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 68.0 | 68.0 | 16.0 | 68.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 3.0 | 7.0 | 7.0 | 4.2 | 7.0 |
| `sdkTotalMs` | 5 | 2493.0 | 2516.0 | 2516.0 | 2463.8 | 2516.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 6.0 | 6.0 | 2.0 | 6.0 |
| `totalMs` | 5 | 3379.0 | 3402.0 | 3402.0 | 3353.2 | 3402.0 |
| `walletRegisterFinalizeMs` | 5 | 472.0 | 500.0 | 500.0 | 476.6 | 500.0 |
| `walletRegisterHssRespondMs` | 5 | 103.0 | 111.0 | 111.0 | 105.0 | 111.0 |
| `walletRegisterStartMs` | 5 | 680.0 | 681.0 | 681.0 | 660.8 | 681.0 |
| `walletStateActivationMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 467.0 | 493.0 | 493.0 | 469.8 | 493.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 466.0 | 492.0 | 492.0 | 469.2 | 492.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 381.0 | 571.0 | 571.0 | 418.2 | 571.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 123.0 | 123.0 | 25.6 | 123.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareMs` | 5 | 379.0 | 448.0 | 448.0 | 392.4 | 448.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1685.0 | 1700.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 300.0 | 302.0 | 300.0 | 300.0 | 154690 | 39461 |
| `prepare` | 5 | 380.0 | 386.0 | 380.0 | 385.0 | 381 | 23043 |
| `respond` | 5 | 102.0 | 103.0 | 101.0 | 102.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 681.0 | 697.0 | 681.0 | 697.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 91.0 | 91.0 | 91.0 | 91.0 | 0.0 | 40079 | 86 |
| `prepare_client_request` | 10 | 125.0 | 136.0 | 125.0 | 136.0 | 0.0 | 22953 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 678.0 | 695.0 | 682.1 | 695.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.1 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.3 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 4.0 | 5.0 | 4.1 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 41.0 | 42.0 | 41.2 | 42.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 59.0 | 59.0 | 58.6 | 59.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 280.0 | 287.0 | 280.4 | 287.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 32.0 | 33.0 | 32.0 | 33.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 301.0 | 308.0 | 301.4 | 308.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 39.0 | 40.0 | 38.9 | 40.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 46.0 | 48.0 | 46.6 | 48.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 46.0 | 49.0 | 46.4 | 49.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 9.0 | 8.1 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 3.0 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 644.0 | 658.0 | 646.4 | 658.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## passkey_ed25519_and_ecdsa_host_origin

- Description: Passkey registration, Ed25519 plus ECDSA, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 10
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMs` | 5 | 208.0 | 213.0 | 213.0 | 209.4 | 213.0 |
| `browserRunDurationMs` | 5 | 3402.0 | 3434.0 | 3434.0 | 3381.8 | 3434.0 |
| `ecdsaClientBootstrapMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 6.0 | 10.0 | 10.0 | 7.2 | 10.0 |
| `ed25519ClientMaterialMs` | 5 | 182.0 | 192.0 | 192.0 | 151.0 | 192.0 |
| `ed25519ClientRequestMs` | 5 | 126.0 | 135.0 | 135.0 | 128.0 | 135.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 684.0 | 695.0 | 695.0 | 687.8 | 695.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 9.0 | 18.0 | 18.0 | 9.4 | 18.0 |
| `inputValidationMs` | 5 | 2.0 | 26.0 | 26.0 | 7.6 | 26.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 10.0 | 19.0 | 19.0 | 10.8 | 19.0 |
| `managedRegistrationGrantMs` | 5 | 2.0 | 37.0 | 37.0 | 9.8 | 37.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 4.0 | 7.0 | 7.0 | 4.6 | 7.0 |
| `sdkTotalMs` | 5 | 2513.0 | 2529.0 | 2529.0 | 2487.6 | 2529.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 11.0 | 11.0 | 3.0 | 11.0 |
| `totalMs` | 5 | 3402.0 | 3434.0 | 3434.0 | 3381.8 | 3434.0 |
| `walletRegisterFinalizeMs` | 5 | 470.0 | 477.0 | 477.0 | 471.0 | 477.0 |
| `walletRegisterHssRespondMs` | 5 | 114.0 | 193.0 | 193.0 | 129.4 | 193.0 |
| `walletRegisterStartMs` | 5 | 679.0 | 683.0 | 683.0 | 655.4 | 683.0 |
| `walletStateActivationMs` | 5 | 1.0 | 5.0 | 5.0 | 2.0 | 5.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 463.0 | 469.0 | 469.0 | 463.2 | 469.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 462.0 | 468.0 | 468.0 | 461.8 | 468.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 381.0 | 551.0 | 551.0 | 414.8 | 551.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 99.0 | 99.0 | 20.6 | 99.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 379.0 | 381.0 | 381.0 | 303.6 | 381.0 |
| `registrationHssPrepareMs` | 5 | 377.0 | 452.0 | 452.0 | 392.6 | 452.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1678.0 | 1706.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 297.0 | 300.0 | 297.0 | 299.0 | 154690 | 39461 |
| `prepare` | 5 | 383.0 | 397.0 | 381.0 | 397.0 | 386 | 23050 |
| `respond` | 5 | 102.0 | 106.0 | 101.0 | 105.0 | 22268 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 683.0 | 691.0 | 683.0 | 691.0 | 0.0 | 464361 | 154567 |
| `open_client_output` | 4 | 91.0 | 92.0 | 91.0 | 92.0 | 0.0 | 40086 | 86 |
| `prepare_client_request` | 10 | 125.0 | 132.0 | 125.0 | 132.0 | 0.0 | 22960 | 45041 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 682.0 | 689.0 | 681.1 | 689.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 1.1 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 4.0 | 5.0 | 4.1 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalInputSharingMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationAXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationCarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 41.0 | 43.0 | 41.1 | 43.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 58.0 | 61.0 | 58.4 | 61.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 281.0 | 286.0 | 281.1 | 286.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 32.0 | 32.0 | 31.9 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 301.0 | 302.0 | 300.0 | 302.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 39.0 | 39.0 | 38.7 | 39.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 46.0 | 47.0 | 46.3 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 46.0 | 47.0 | 46.1 | 47.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 8.0 | 9.0 | 8.1 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 3.0 | 3.0 | 2.9 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 647.0 | 654.0 | 645.6 | 654.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
