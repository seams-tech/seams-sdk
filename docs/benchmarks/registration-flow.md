# Registration Flow Benchmark Report

Status: archived historical report from the retired registration-flow benchmark.

Commands embedded below are provenance only. The Playwright runner and mocked
managed-registration harness they target were removed during Refactor 88.
Current lifecycle and replacement latency checks should run through the
Refactor 88 intended-behaviour topology, which exercises the public SDK/UI flow
against the real Router API, wallet iframe, IndexedDB, D1/DO, and workers.

Generated: 2026-06-11T04:14:14.540Z
Run ID: `20260611-041314Z`

## Scenario Summary

| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `passkey_ed25519_only_wallet_iframe` | Passkey registration, Ed25519 only, wallet iframe runtime | ok | 5 / 5 | 2257.0 | 2558.0 | 1616.0 | 1649.0 | 20 | 10 | 15 |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime | ok | 5 / 5 | 2529.0 | 2924.0 | 1643.0 | 1739.0 | 20 | 10 | 15 |
| `passkey_ed25519_only_host_origin` | Passkey registration, Ed25519 only, host-origin runtime | ok | 5 / 5 | 1624.0 | 1734.0 | 1236.0 | 1338.0 | 20 | 18 | 23 |
| `passkey_ed25519_and_ecdsa_host_origin` | Passkey registration, Ed25519 plus ECDSA, host-origin runtime | ok | 5 / 5 | 1644.0 | 1830.0 | 1261.0 | 1436.0 | 20 | 18 | 23 |

## passkey_ed25519_only_wallet_iframe

- Description: Passkey registration, Ed25519 only, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- Wallet iframe transport diagnostics captured: 5
- Registration route payload diagnostics captured: 25
- Browser memory diagnostics captured: 5
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMinusPasskeyPromptDecisionWaitMs` | 5 | 203.0 | 205.0 | 205.0 | 203.2 | 205.0 |
| `authProofMs` | 5 | 835.0 | 849.0 | 849.0 | 818.2 | 849.0 |
| `browserRunDurationMs` | 5 | 2257.0 | 2558.0 | 2558.0 | 2360.0 | 2558.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 26.0 | 27.0 | 27.0 | 24.0 | 27.0 |
| `ed25519ClientRequestMs` | 5 | 134.0 | 135.0 | 135.0 | 133.4 | 135.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 430.0 | 433.0 | 433.0 | 430.4 | 433.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 7.0 | 10.0 | 10.0 | 6.8 | 10.0 |
| `inputValidationMs` | 5 | 3.0 | 4.0 | 4.0 | 2.8 | 4.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 17.0 | 20.0 | 20.0 | 18.0 | 20.0 |
| `managedRegistrationGrantMs` | 5 | 5.0 | 13.0 | 13.0 | 6.6 | 13.0 |
| `passkeyAuthConfirmationMs` | 5 | 835.0 | 849.0 | 849.0 | 818.0 | 849.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 202.0 | 202.0 | 202.0 | 201.8 | 202.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 633.0 | 647.0 | 647.0 | 615.4 | 647.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 834.0 | 848.0 | 848.0 | 817.2 | 848.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 632.0 | 646.0 | 646.0 | 614.4 | 646.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 633.0 | 646.0 | 646.0 | 615.0 | 646.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 4.0 | 4.0 | 1.6 | 4.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 3.0 | 3.0 | 1.4 | 3.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 633.0 | 647.0 | 647.0 | 615.2 | 647.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 3.0 | 3.0 | 0.6 | 3.0 |
| `registrationIntentMs` | 5 | 4.0 | 7.0 | 7.0 | 5.2 | 7.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 6.0 | 6.0 | 2.2 | 6.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupMs` | 5 | 2.0 | 6.0 | 6.0 | 2.8 | 6.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkMinusPasskeyPromptDecisionWaitMs` | 5 | 978.0 | 1124.0 | 1124.0 | 1006.2 | 1124.0 |
| `sdkTotalMs` | 5 | 1616.0 | 1649.0 | 1649.0 | 1621.2 | 1649.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 4.0 | 4.0 | 1.6 | 4.0 |
| `totalMs` | 5 | 2257.0 | 2558.0 | 2558.0 | 2360.0 | 2558.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 9.0 | 13.0 | 13.0 | 10.2 | 13.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 669.0 | 1011.0 | 1011.0 | 785.4 | 1011.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 5 | 886.0 | 1132.0 | 1132.0 | 968.4 | 1132.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 5 | 36.0 | 49.0 | 49.0 | 39.6 | 49.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 3.0 | 20.0 | 20.0 | 6.8 | 20.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 3.0 | 20.0 | 20.0 | 6.8 | 20.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2256.0 | 2558.0 | 2558.0 | 2359.6 | 2558.0 |
| `walletIframeTransportBootHintWaitMs` | 5 | 56.0 | 58.0 | 58.0 | 55.6 | 58.0 |
| `walletIframeTransportConnectTotalMs` | 5 | 90.0 | 92.0 | 92.0 | 90.4 | 92.0 |
| `walletIframeTransportHandshakeAttempts` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `walletIframeTransportHandshakeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletIframeTransportIframeLoadWaitMs` | 5 | 33.0 | 36.0 | 36.0 | 33.2 | 36.0 |
| `walletIframeTransportIframeMountMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `walletRegisterFinalizeMs` | 5 | 56.0 | 62.0 | 62.0 | 56.8 | 62.0 |
| `walletRegisterHssRespondMs` | 5 | 88.0 | 104.0 | 104.0 | 91.2 | 104.0 |
| `walletRegisterPrepareMs` | 5 | 392.0 | 478.0 | 478.0 | 408.0 | 478.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 7.0 | 104.0 | 104.0 | 25.8 | 104.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 48.0 | 54.0 | 54.0 | 49.2 | 54.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeMs` | 5 | 48.0 | 52.0 | 52.0 | 48.6 | 52.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 18.0 | 18.0 | 16.6 | 18.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 78.0 | 89.0 | 89.0 | 79.8 | 89.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 49.0 | 50.0 | 50.0 | 49.0 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 | 5.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 78.0 | 89.0 | 89.0 | 79.8 | 89.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 60.0 | 60.0 | 57.8 | 60.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 377.0 | 462.0 | 462.0 | 394.4 | 462.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 360.0 | 384.0 | 384.0 | 365.6 | 384.0 |
| `registrationHssServerInputDeriveMs` | 5 | 371.0 | 376.0 | 376.0 | 309.8 | 376.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 362.0 | 449.0 | 449.0 | 380.2 | 449.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 376.0 | 461.0 | 461.0 | 393.8 | 461.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 99.0 | 99.0 | 20.6 | 99.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 99.0 | 99.0 | 20.4 | 99.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Registration Route Payload Sizes

| Route | Count | total p50 (ms) | request p50 | request p95 | response p50 | response p95 |
|---|---:|---:|---:|---:|---:|---:|
| `/wallets/register/finalize` | 5 | 56.0 | 151.7 KiB | 151.7 KiB | 3.1 KiB | 3.1 KiB |
| `/wallets/register/hss/respond` | 5 | 88.0 | 21.9 KiB | 21.9 KiB | 410.6 KiB | 410.6 KiB |
| `/wallets/register/intent` | 5 | 4.0 | 429 B | 429 B | 886 B | 886 B |
| `/wallets/register/prepare` | 5 | 392.0 | 878 B | 878 B | 23.7 KiB | 23.7 KiB |
| `/wallets/register/start` | 5 | 7.0 | 1.8 KiB | 1.8 KiB | 24.1 KiB | 24.1 KiB |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 383.0 | 386.0 | 382.0 | 386.0 | 383 | 23290 |
| `respond` | 5 | 88.0 | 90.0 | 87.0 | 89.0 | 22393 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 429.0 | 432.0 | 0.0 | 0.0 | 429.0 | 432.0 | 0.0 | 464548 | 154811 |
| `prepare_client_request` | 10 | 124.0 | 134.0 | 0.0 | 0.0 | 124.0 | 134.0 | 0.0 | 23200 | 45228 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 423.0 | 425.0 | 423.0 | 425.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.8 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 24.0 | 25.0 | 24.2 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 31.0 | 32.0 | 31.4 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 55.0 | 55.0 | 55.0 | 55.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 14.0 | 14.0 | 14.0 | 14.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 139.0 | 140.0 | 139.2 | 140.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 8.0 | 9.0 | 8.2 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 60.0 | 60.0 | 60.0 | 60.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 12.0 | 13.0 | 12.0 | 13.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 212.0 | 215.0 | 212.6 | 215.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 29.0 | 30.0 | 29.2 | 30.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 21.0 | 22.0 | 21.2 | 22.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 21.0 | 22.0 | 21.0 | 22.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 7.0 | 7.0 | 6.8 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 3.0 | 3.0 | 2.6 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 8.0 | 8.0 | 7.6 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 4.0 | 4.0 | 3.8 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 385.0 | 388.0 | 385.8 | 388.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

### Browser Memory Diagnostics

| Bucket | Count | p50 | p95 | Mean | Max |
|---|---:|---:|---:|---:|---:|
| `jsHeapSizeLimitBytes` | 5 | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB |
| `sampleCount` | 5 | 92 | 103 | 96 | 103 |
| `totalJSHeapSizePeakBytes` | 5 | 77.63 MiB | 77.63 MiB | 77.63 MiB | 77.63 MiB |
| `usedJSHeapSizeAfterBytes` | 5 | 68.86 MiB | 68.86 MiB | 68.86 MiB | 68.86 MiB |
| `usedJSHeapSizeBeforeBytes` | 5 | 68.86 MiB | 68.86 MiB | 68.86 MiB | 68.86 MiB |
| `usedJSHeapSizeDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |
| `usedJSHeapSizePeakBytes` | 5 | 68.86 MiB | 68.86 MiB | 68.86 MiB | 68.86 MiB |
| `usedJSHeapSizePeakDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |

## passkey_ed25519_and_ecdsa_wallet_iframe

- Description: Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / wallet_iframe
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- Wallet iframe transport diagnostics captured: 5
- Registration route payload diagnostics captured: 25
- Browser memory diagnostics captured: 5
- HSS client timings captured: 10
- HSS worker diagnostics captured: 15

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMinusPasskeyPromptDecisionWaitMs` | 5 | 203.0 | 208.0 | 208.0 | 204.8 | 208.0 |
| `authProofMs` | 5 | 845.0 | 863.0 | 863.0 | 821.0 | 863.0 |
| `browserRunDurationMs` | 5 | 2529.0 | 2924.0 | 2924.0 | 2512.4 | 2924.0 |
| `ecdsaClientBootstrapMs` | 5 | 3.0 | 5.0 | 5.0 | 3.4 | 5.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 10.0 | 12.0 | 12.0 | 10.0 | 12.0 |
| `ed25519ClientMaterialMs` | 5 | 21.0 | 24.0 | 24.0 | 22.0 | 24.0 |
| `ed25519ClientRequestMs` | 5 | 135.0 | 137.0 | 137.0 | 135.4 | 137.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 431.0 | 433.0 | 433.0 | 431.2 | 433.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 8.0 | 15.0 | 15.0 | 9.8 | 15.0 |
| `inputValidationMs` | 5 | 2.0 | 7.0 | 7.0 | 3.6 | 7.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 17.0 | 21.0 | 21.0 | 17.8 | 21.0 |
| `managedRegistrationGrantMs` | 5 | 4.0 | 11.0 | 11.0 | 5.0 | 11.0 |
| `passkeyAuthConfirmationMs` | 5 | 845.0 | 863.0 | 863.0 | 821.0 | 863.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 203.0 | 206.0 | 206.0 | 203.4 | 206.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 642.0 | 661.0 | 661.0 | 617.0 | 661.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 845.0 | 863.0 | 863.0 | 820.4 | 863.0 |
| `passkeyAuthPrfExtractionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptConfirmEventMs` | 5 | 641.0 | 660.0 | 660.0 | 616.0 | 660.0 |
| `passkeyAuthPromptDecisionWaitMs` | 5 | 641.0 | 660.0 | 660.0 | 616.2 | 660.0 |
| `passkeyAuthPromptElementDefineMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthPromptHostFirstUpdateMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptHostInteractiveMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `passkeyAuthPromptMountMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `passkeyAuthPromptUserMs` | 5 | 642.0 | 661.0 | 661.0 | 616.8 | 661.0 |
| `passkeyAuthRequestSetupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerReadyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerRequestRoundTripMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthWorkerResponseValidationMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentMs` | 5 | 5.0 | 6.0 | 6.0 | 5.0 | 6.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkMinusPasskeyPromptDecisionWaitMs` | 5 | 1004.0 | 1221.0 | 1221.0 | 1047.0 | 1221.0 |
| `sdkTotalMs` | 5 | 1643.0 | 1739.0 | 1739.0 | 1663.2 | 1739.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `totalMs` | 5 | 2529.0 | 2924.0 | 2924.0 | 2512.4 | 2924.0 |
| `walletIframeAutoConfirmAttempts` | 5 | 13.0 | 16.0 | 16.0 | 12.0 | 16.0 |
| `walletIframeAutoConfirmFirstButtonVisibleMs` | 5 | 906.0 | 1282.0 | 1282.0 | 893.2 | 1282.0 |
| `walletIframeAutoConfirmFirstClickDispatchMs` | 5 | 1125.0 | 1319.0 | 1319.0 | 1071.8 | 1319.0 |
| `walletIframeAutoConfirmFirstClickDurationMs` | 5 | 44.0 | 45.0 | 45.0 | 39.8 | 45.0 |
| `walletIframeAutoConfirmFirstFrameResolvedMs` | 5 | 4.0 | 22.0 | 22.0 | 8.0 | 22.0 |
| `walletIframeAutoConfirmFirstIframeAttachedMs` | 5 | 4.0 | 22.0 | 22.0 | 8.0 | 22.0 |
| `walletIframeAutoConfirmTotalMs` | 5 | 2529.0 | 2924.0 | 2924.0 | 2512.2 | 2924.0 |
| `walletIframeTransportBootHintWaitMs` | 5 | 51.0 | 207.0 | 207.0 | 81.8 | 207.0 |
| `walletIframeTransportConnectTotalMs` | 5 | 94.0 | 361.0 | 361.0 | 147.0 | 361.0 |
| `walletIframeTransportHandshakeAttempts` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `walletIframeTransportHandshakeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletIframeTransportIframeLoadWaitMs` | 5 | 42.0 | 152.0 | 152.0 | 63.0 | 152.0 |
| `walletIframeTransportIframeMountMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `walletRegisterFinalizeMs` | 5 | 56.0 | 67.0 | 67.0 | 58.0 | 67.0 |
| `walletRegisterHssRespondMs` | 5 | 100.0 | 186.0 | 186.0 | 117.0 | 186.0 |
| `walletRegisterPrepareMs` | 5 | 390.0 | 483.0 | 483.0 | 409.0 | 483.0 |
| `walletRegisterPrepareWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `walletRegisterStartMs` | 5 | 7.0 | 95.0 | 95.0 | 24.2 | 95.0 |
| `walletStateActivationMs` | 5 | 1.0 | 6.0 | 6.0 | 2.0 | 6.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 48.0 | 55.0 | 55.0 | 49.4 | 55.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.4 | 4.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 47.0 | 53.0 | 53.0 | 48.4 | 53.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 2.0 | 2.0 | 2.0 | 1.6 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 18.0 | 18.0 | 16.4 | 18.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 88.0 | 173.0 | 173.0 | 104.6 | 173.0 |
| `registrationEcdsaRespondMs` | 5 | 10.0 | 88.0 | 88.0 | 25.8 | 88.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 48.0 | 50.0 | 50.0 | 48.6 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 6.0 | 7.0 | 7.0 | 6.4 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 85.0 | 85.0 | 78.8 | 85.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 60.0 | 60.0 | 57.4 | 60.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 376.0 | 465.0 | 465.0 | 393.8 | 465.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareSessionMs` | 5 | 360.0 | 384.0 | 384.0 | 364.6 | 384.0 |
| `registrationHssServerInputDeriveMs` | 5 | 371.0 | 372.0 | 372.0 | 309.2 | 372.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 363.0 | 452.0 | 452.0 | 380.0 | 452.0 |
| `registrationIntentDigestMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 376.0 | 465.0 | 465.0 | 393.2 | 465.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 1.0 | 90.0 | 90.0 | 19.0 | 90.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 89.0 | 89.0 | 18.4 | 89.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Registration Route Payload Sizes

| Route | Count | total p50 (ms) | request p50 | request p95 | response p50 | response p95 |
|---|---:|---:|---:|---:|---:|---:|
| `/wallets/register/finalize` | 5 | 56.0 | 151.8 KiB | 151.8 KiB | 5.5 KiB | 5.5 KiB |
| `/wallets/register/hss/respond` | 5 | 99.0 | 23.0 KiB | 23.0 KiB | 413.0 KiB | 413.0 KiB |
| `/wallets/register/intent` | 5 | 5.0 | 717 B | 717 B | 1.2 KiB | 1.2 KiB |
| `/wallets/register/prepare` | 5 | 391.0 | 1.2 KiB | 1.2 KiB | 23.7 KiB | 23.7 KiB |
| `/wallets/register/start` | 5 | 7.0 | 2.1 KiB | 2.1 KiB | 25.6 KiB | 25.6 KiB |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `prepare` | 5 | 383.0 | 384.0 | 383.0 | 384.0 | 388 | 23296 |
| `respond` | 5 | 91.0 | 92.0 | 89.0 | 91.0 | 22393 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 5 | 429.0 | 432.0 | 0.0 | 0.0 | 429.0 | 432.0 | 0.0 | 464548 | 154811 |
| `prepare_client_request` | 10 | 125.0 | 133.0 | 0.0 | 0.0 | 125.0 | 133.0 | 0.0 | 23206 | 45228 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 5 | 423.0 | 427.0 | 423.2 | 427.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 5 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 5 | 1.0 | 1.0 | 0.8 | 1.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 5 | 23.0 | 24.0 | 23.4 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 5 | 31.0 | 32.0 | 31.2 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 5 | 5.0 | 6.0 | 5.2 | 6.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 5 | 55.0 | 55.0 | 55.0 | 55.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 5 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 5 | 14.0 | 14.0 | 14.0 | 14.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 5 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 5 | 139.0 | 141.0 | 139.6 | 141.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 5 | 8.0 | 9.0 | 8.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 5 | 61.0 | 61.0 | 60.6 | 61.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 5 | 11.0 | 12.0 | 11.4 | 12.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 5 | 212.0 | 214.0 | 212.0 | 214.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 5 | 30.0 | 30.0 | 29.8 | 30.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 5 | 21.0 | 22.0 | 21.2 | 22.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 5 | 21.0 | 21.0 | 20.6 | 21.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 5 | 7.0 | 8.0 | 7.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 5 | 7.0 | 7.0 | 6.8 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 5 | 2.0 | 3.0 | 2.4 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 5 | 7.0 | 9.0 | 7.4 | 9.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 5 | 3.0 | 4.0 | 3.4 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 5 | 385.0 | 389.0 | 385.6 | 389.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 |

### Browser Memory Diagnostics

| Bucket | Count | p50 | p95 | Mean | Max |
|---|---:|---:|---:|---:|---:|
| `jsHeapSizeLimitBytes` | 5 | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB |
| `sampleCount` | 5 | 102 | 118 | 102 | 118 |
| `totalJSHeapSizePeakBytes` | 5 | 73.05 MiB | 73.05 MiB | 73.05 MiB | 73.05 MiB |
| `usedJSHeapSizeAfterBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeBeforeBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |
| `usedJSHeapSizePeakBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizePeakDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |

## passkey_ed25519_only_host_origin

- Description: Passkey registration, Ed25519 only, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_only / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- Wallet iframe transport diagnostics captured: 0
- Registration route payload diagnostics captured: 25
- Browser memory diagnostics captured: 5
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMinusPasskeyPromptDecisionWaitMs` | 5 | 203.0 | 210.0 | 210.0 | 204.8 | 210.0 |
| `authProofMs` | 5 | 203.0 | 210.0 | 210.0 | 204.8 | 210.0 |
| `browserRunDurationMs` | 5 | 1624.0 | 1734.0 | 1734.0 | 1643.8 | 1734.0 |
| `ecdsaClientBootstrapMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519ClientMaterialMs` | 5 | 159.0 | 249.0 | 249.0 | 174.6 | 249.0 |
| `ed25519ClientRequestMs` | 5 | 210.0 | 215.0 | 215.0 | 195.4 | 215.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 422.0 | 441.0 | 441.0 | 425.0 | 441.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 3.0 | 8.0 | 8.0 | 4.6 | 8.0 |
| `inputValidationMs` | 5 | 2.0 | 4.0 | 4.0 | 2.4 | 4.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 9.0 | 11.0 | 11.0 | 7.8 | 11.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 11.0 | 11.0 | 4.8 | 11.0 |
| `passkeyAuthConfirmationMs` | 5 | 203.0 | 210.0 | 210.0 | 204.8 | 210.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 203.0 | 210.0 | 210.0 | 204.6 | 210.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 203.0 | 210.0 | 210.0 | 204.6 | 210.0 |
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
| `registrationIntentMs` | 5 | 7.0 | 8.0 | 8.0 | 5.8 | 8.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationWarmupMs` | 5 | 10.0 | 15.0 | 15.0 | 9.8 | 15.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 8.0 | 13.0 | 13.0 | 7.6 | 13.0 |
| `registrationWarmupWaitMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `sdkMinusPasskeyPromptDecisionWaitMs` | 5 | 1236.0 | 1338.0 | 1338.0 | 1256.8 | 1338.0 |
| `sdkTotalMs` | 5 | 1236.0 | 1338.0 | 1338.0 | 1256.8 | 1338.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 5.0 | 5.0 | 1.8 | 5.0 |
| `totalMs` | 5 | 1624.0 | 1734.0 | 1734.0 | 1643.8 | 1734.0 |
| `walletRegisterFinalizeMs` | 5 | 53.0 | 61.0 | 61.0 | 54.6 | 61.0 |
| `walletRegisterHssRespondMs` | 5 | 85.0 | 88.0 | 88.0 | 85.6 | 88.0 |
| `walletRegisterPrepareMs` | 5 | 390.0 | 451.0 | 451.0 | 399.8 | 451.0 |
| `walletRegisterPrepareWaitMs` | 5 | 24.0 | 32.0 | 32.0 | 21.2 | 32.0 |
| `walletRegisterStartMs` | 5 | 59.0 | 111.0 | 111.0 | 67.2 | 111.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 47.0 | 53.0 | 53.0 | 48.2 | 53.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 4.0 | 4.0 | 3.2 | 4.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 47.0 | 52.0 | 52.0 | 48.0 | 52.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 17.0 | 17.0 | 16.2 | 17.0 |
| `registrationHssFinalizeReportMs` | 5 | 4.0 | 5.0 | 5.0 | 4.4 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relaySessionMintMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 77.0 | 82.0 | 82.0 | 78.0 | 82.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 48.0 | 50.0 | 50.0 | 48.4 | 50.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 6.0 | 7.0 | 7.0 | 6.2 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 6.0 | 7.0 | 7.0 | 6.2 | 7.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 5.0 | 5.0 | 5.0 | 5.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 82.0 | 82.0 | 78.0 | 82.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 59.0 | 59.0 | 57.4 | 59.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 383.0 | 445.0 | 445.0 | 394.0 | 445.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 367.0 | 371.0 | 371.0 | 366.8 | 371.0 |
| `registrationHssServerInputDeriveMs` | 5 | 374.0 | 382.0 | 382.0 | 313.0 | 382.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 368.0 | 436.0 | 436.0 | 381.0 | 436.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 383.0 | 445.0 | 445.0 | 394.0 | 445.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 2.0 | 107.0 | 107.0 | 22.4 | 107.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 106.0 | 106.0 | 21.8 | 106.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Registration Route Payload Sizes

| Route | Count | total p50 (ms) | request p50 | request p95 | response p50 | response p95 |
|---|---:|---:|---:|---:|---:|---:|
| `/wallets/register/finalize` | 5 | 52.0 | 151.7 KiB | 151.7 KiB | 3.1 KiB | 3.1 KiB |
| `/wallets/register/hss/respond` | 5 | 85.0 | 21.9 KiB | 21.9 KiB | 410.6 KiB | 410.6 KiB |
| `/wallets/register/intent` | 5 | 7.0 | 429 B | 429 B | 882 B | 882 B |
| `/wallets/register/prepare` | 5 | 390.0 | 874 B | 874 B | 23.7 KiB | 23.7 KiB |
| `/wallets/register/start` | 5 | 59.0 | 1.8 KiB | 1.8 KiB | 24.1 KiB | 24.1 KiB |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1176.0 | 1187.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 76.0 | 89.0 | 75.0 | 84.0 | 154934 | 39524 |
| `prepare` | 5 | 380.0 | 383.0 | 379.0 | 383.0 | 381 | 23287 |
| `respond` | 5 | 82.0 | 85.0 | 81.0 | 84.0 | 22393 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 421.0 | 440.0 | 0.0 | 0.0 | 421.0 | 440.0 | 0.0 | 464548 | 154811 |
| `open_client_output` | 4 | 90.0 | 91.0 | 0.0 | 0.0 | 90.0 | 91.0 | 0.0 | 40261 | 86 |
| `prepare_client_request` | 10 | 123.0 | 132.0 | 0.0 | 0.0 | 123.0 | 132.0 | 0.0 | 23197 | 45228 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 419.0 | 433.0 | 420.2 | 433.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 2.0 | 0.9 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.1 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 2.0 | 3.0 | 2.1 | 3.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 23.0 | 25.0 | 23.6 | 25.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 30.0 | 32.0 | 30.6 | 32.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 56.0 | 61.0 | 56.7 | 61.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 3.9 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 13.0 | 14.0 | 13.1 | 14.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 141.0 | 148.0 | 141.7 | 148.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 62.0 | 62.0 | 61.7 | 62.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 11.0 | 11.0 | 11.0 | 11.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 211.0 | 212.0 | 210.8 | 212.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 29.0 | 30.0 | 29.2 | 30.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 21.0 | 21.0 | 21.0 | 21.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 21.0 | 21.0 | 21.0 | 21.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 6.0 | 7.0 | 6.4 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 6.0 | 7.0 | 6.2 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 2.0 | 3.0 | 2.3 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 8.0 | 8.0 | 7.8 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 385.0 | 395.0 | 385.8 | 395.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

### Browser Memory Diagnostics

| Bucket | Count | p50 | p95 | Mean | Max |
|---|---:|---:|---:|---:|---:|
| `jsHeapSizeLimitBytes` | 5 | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB |
| `sampleCount` | 5 | 51 | 55 | 52 | 55 |
| `totalJSHeapSizePeakBytes` | 5 | 73.05 MiB | 73.05 MiB | 73.05 MiB | 73.05 MiB |
| `usedJSHeapSizeAfterBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeBeforeBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |
| `usedJSHeapSizePeakBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizePeakDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |

## passkey_ed25519_and_ecdsa_host_origin

- Description: Passkey registration, Ed25519 plus ECDSA, host-origin runtime
- Status: ok
- Command: `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line`
- Scenario mode: ed25519_and_ecdsa / host_origin
- Runs requested: 5
- Successful runs: 5
- Failed runs: 0
- Relay diagnostics captured: 20
- Wallet iframe transport diagnostics captured: 0
- Registration route payload diagnostics captured: 25
- Browser memory diagnostics captured: 5
- HSS client timings captured: 18
- HSS worker diagnostics captured: 23

### Registration Timing Buckets

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `authProofMinusPasskeyPromptDecisionWaitMs` | 5 | 203.0 | 205.0 | 205.0 | 203.6 | 205.0 |
| `authProofMs` | 5 | 203.0 | 205.0 | 205.0 | 203.6 | 205.0 |
| `browserRunDurationMs` | 5 | 1644.0 | 1830.0 | 1830.0 | 1680.2 | 1830.0 |
| `ecdsaClientBootstrapMs` | 5 | 90.0 | 93.0 | 93.0 | 72.4 | 93.0 |
| `ecdsaRegistrationPersistenceMs` | 5 | 8.0 | 11.0 | 11.0 | 7.8 | 11.0 |
| `ed25519ClientMaterialMs` | 5 | 161.0 | 251.0 | 251.0 | 178.4 | 251.0 |
| `ed25519ClientRequestMs` | 5 | 212.0 | 219.0 | 219.0 | 197.6 | 219.0 |
| `ed25519CompletionParseMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `ed25519EvaluationArtifactMs` | 5 | 420.0 | 440.0 | 440.0 | 423.8 | 440.0 |
| `emailOtpEnrollmentMaterialMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `emailOtpRecoveryCodeBackupMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `immediateSigningLaneAssertionMs` | 5 | 8.0 | 11.0 | 11.0 | 7.6 | 11.0 |
| `inputValidationMs` | 5 | 5.0 | 8.0 | 8.0 | 4.6 | 8.0 |
| `localWalletRegistrationPersistenceMs` | 5 | 8.0 | 12.0 | 12.0 | 7.8 | 12.0 |
| `managedRegistrationGrantMs` | 5 | 3.0 | 17.0 | 17.0 | 5.6 | 17.0 |
| `passkeyAuthConfirmationMs` | 5 | 203.0 | 205.0 | 205.0 | 203.6 | 205.0 |
| `passkeyAuthCredentialCreateMs` | 5 | 203.0 | 204.0 | 204.0 | 203.2 | 204.0 |
| `passkeyAuthCredentialCreateStartMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialRedactionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthCredentialSerializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthDuplicateRetryCount` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `passkeyAuthMainThreadTotalMs` | 5 | 203.0 | 205.0 | 205.0 | 203.4 | 205.0 |
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
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentMs` | 5 | 3.0 | 7.0 | 7.0 | 4.4 | 7.0 |
| `registrationWarmupAuthenticatedWalletStateMs` | 5 | 1.0 | 4.0 | 4.0 | 2.0 | 4.0 |
| `registrationWarmupKeyMaterialReadMs` | 5 | 0.0 | 2.0 | 2.0 | 0.6 | 2.0 |
| `registrationWarmupMs` | 5 | 7.0 | 18.0 | 18.0 | 9.8 | 18.0 |
| `registrationWarmupNoncePrefetchMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupSignerWorkerPrewarmMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationWarmupUiConfirmPrewarmMs` | 5 | 5.0 | 13.0 | 13.0 | 6.8 | 13.0 |
| `registrationWarmupWaitMs` | 5 | 1.0 | 2.0 | 2.0 | 1.0 | 2.0 |
| `sdkMinusPasskeyPromptDecisionWaitMs` | 5 | 1261.0 | 1436.0 | 1436.0 | 1295.0 | 1436.0 |
| `sdkTotalMs` | 5 | 1261.0 | 1436.0 | 1436.0 | 1295.0 | 1436.0 |
| `thresholdEd25519SessionPersistenceMs` | 5 | 1.0 | 1.0 | 1.0 | 0.6 | 1.0 |
| `totalMs` | 5 | 1644.0 | 1830.0 | 1830.0 | 1680.2 | 1830.0 |
| `walletRegisterFinalizeMs` | 5 | 56.0 | 61.0 | 61.0 | 56.4 | 61.0 |
| `walletRegisterHssRespondMs` | 5 | 97.0 | 164.0 | 164.0 | 109.6 | 164.0 |
| `walletRegisterPrepareMs` | 5 | 384.0 | 451.0 | 451.0 | 397.0 | 451.0 |
| `walletRegisterPrepareWaitMs` | 5 | 16.0 | 25.0 | 25.0 | 15.0 | 25.0 |
| `walletRegisterStartMs` | 5 | 60.0 | 108.0 | 108.0 | 69.2 | 108.0 |
| `walletStateActivationMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

### Relay Route Diagnostics: wallets_register_finalize

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `nearAccountCreateMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registerFinalizeTotalMs` | 5 | 48.0 | 54.0 | 54.0 | 49.4 | 54.0 |
| `registrationCeremonyLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaBootstrapVerifyMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationEmailOtpEnrollmentPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationFinalizeReplayCacheMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeDecodeArtifactMs` | 5 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| `registrationHssFinalizeDeriveRelayerVerifyingShareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeDeriveSeedKeypairMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationHssFinalizeEncodeReportMs` | 5 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 |
| `registrationHssFinalizeKeyStorePutMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssFinalizeMs` | 5 | 47.0 | 51.0 | 51.0 | 48.0 | 51.0 |
| `registrationHssFinalizeOpenSeedOutputMs` | 5 | 1.0 | 2.0 | 2.0 | 1.4 | 2.0 |
| `registrationHssFinalizeOpenServerOutputMs` | 5 | 16.0 | 18.0 | 18.0 | 16.6 | 18.0 |
| `registrationHssFinalizeReportMs` | 5 | 5.0 | 5.0 | 5.0 | 4.6 | 5.0 |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationKeygenMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayGoogleEmailOtpActivationPlanMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `relayPersistenceMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `relaySessionMintMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_hss_respond

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerHssRespondTotalMs` | 5 | 88.0 | 157.0 | 157.0 | 102.0 | 157.0 |
| `registrationEcdsaRespondMs` | 5 | 11.0 | 72.0 | 72.0 | 23.4 | 72.0 |
| `registrationHssRespondDecodeMessagesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryOtOpenJoinMs` | 5 | 48.0 | 52.0 | 52.0 | 49.0 | 52.0 |
| `registrationHssRespondDeliveryServerInputCommitmentMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondDeliveryServerInputOpenMs` | 5 | 6.0 | 7.0 | 7.0 | 6.2 | 7.0 |
| `registrationHssRespondDeliveryServerInputSealMs` | 5 | 2.0 | 2.0 | 2.0 | 2.0 | 2.0 |
| `registrationHssRespondDeliveryServerInputShareMs` | 5 | 6.0 | 6.0 | 6.0 | 6.0 | 6.0 |
| `registrationHssRespondDeliveryServerInputTranscriptMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondEncodeDeliveryMs` | 5 | 5.0 | 6.0 | 6.0 | 5.2 | 6.0 |
| `registrationHssRespondMaterializeSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssRespondMs` | 5 | 77.0 | 84.0 | 84.0 | 78.4 | 84.0 |
| `registrationHssRespondPrepareDeliveryMs` | 5 | 57.0 | 62.0 | 62.0 | 57.8 | 62.0 |

### Relay Route Diagnostics: wallets_register_prepare

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerPrepareTotalMs` | 5 | 381.0 | 445.0 | 445.0 | 393.6 | 445.0 |
| `registrationHssPrepareCachePreparedSessionMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareClientOfferMessageMs` | 5 | 1.0 | 1.0 | 1.0 | 0.8 | 1.0 |
| `registrationHssPrepareEncodeStatesMs` | 5 | 1.0 | 2.0 | 2.0 | 1.2 | 2.0 |
| `registrationHssPrepareExtractDriverStatesMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationHssPrepareSessionMs` | 5 | 364.0 | 372.0 | 372.0 | 365.4 | 372.0 |
| `registrationHssServerInputDeriveMs` | 5 | 375.0 | 377.0 | 377.0 | 311.4 | 377.0 |
| `registrationHssServerSessionPrepareTotalMs` | 5 | 366.0 | 436.0 | 436.0 | 379.6 | 436.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.4 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreauthHssPrepareMs` | 5 | 380.0 | 444.0 | 444.0 | 392.8 | 444.0 |
| `registrationPreparationPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Relay Route Diagnostics: wallets_register_start

| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `registerStartTotalMs` | 5 | 2.0 | 95.0 | 95.0 | 20.4 | 95.0 |
| `registrationAuthorityVerifyMs` | 5 | 1.0 | 95.0 | 95.0 | 20.0 | 95.0 |
| `registrationCeremonyPersistMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationEcdsaPrepareMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationIntentDigestMs` | 5 | 0.0 | 1.0 | 1.0 | 0.2 | 1.0 |
| `registrationIntentLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationConsumeMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationLoadMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| `registrationPreparationScopeCheckMs` | 5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |

### Registration Route Payload Sizes

| Route | Count | total p50 (ms) | request p50 | request p95 | response p50 | response p95 |
|---|---:|---:|---:|---:|---:|---:|
| `/wallets/register/finalize` | 5 | 56.0 | 151.8 KiB | 151.8 KiB | 5.4 KiB | 5.4 KiB |
| `/wallets/register/hss/respond` | 5 | 97.0 | 23.0 KiB | 23.0 KiB | 413.0 KiB | 413.0 KiB |
| `/wallets/register/intent` | 5 | 3.0 | 717 B | 717 B | 1.2 KiB | 1.2 KiB |
| `/wallets/register/prepare` | 5 | 383.0 | 1.2 KiB | 1.2 KiB | 23.7 KiB | 23.7 KiB |
| `/wallets/register/start` | 5 | 60.0 | 2.0 KiB | 2.0 KiB | 25.6 KiB | 25.6 KiB |

### HSS Client Timings

| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `ceremony` | 4 | 1176.0 | 1181.0 | n/a | n/a | n/a | n/a |
| `finalize` | 4 | 74.0 | 81.0 | 73.0 | 80.0 | 154934 | 39524 |
| `prepare` | 5 | 378.0 | 382.0 | 378.0 | 381.0 | 386 | 23294 |
| `respond` | 5 | 82.0 | 84.0 | 81.0 | 84.0 | 22393 | 419361 |

### HSS Worker Diagnostics

| Operation | Count | total p50 | total p95 | wasm init p50 | wasm init p95 | wasm call p50 | wasm call p95 | queue p95 | request bytes p50 | response bytes p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | 9 | 420.0 | 437.0 | 0.0 | 0.0 | 420.0 | 437.0 | 0.0 | 464548 | 154811 |
| `open_client_output` | 4 | 92.0 | 96.0 | 0.0 | 0.0 | 92.0 | 96.0 | 0.0 | 40268 | 86 |
| `prepare_client_request` | 10 | 123.0 | 131.0 | 0.0 | 0.0 | 123.0 | 131.0 | 0.0 | 23204 | 45228 |

### HSS Worker WASM Substep Timings

| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|---:|
| `build_client_owned_staged_evaluator_artifact` | `buildArtifactMs` | 9 | 418.0 | 430.0 | 419.8 | 430.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientOutputMaskMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeClientRequestMessageMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorDriverStateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeEvaluatorOtStateMs` | 9 | 0.0 | 1.0 | 0.2 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `decodeServerInputDeliveryMs` | 9 | 1.0 | 1.0 | 1.0 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `encodeArtifactMs` | 9 | 0.0 | 1.0 | 0.4 | 1.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalAddStageMs` | 9 | 2.0 | 3.0 | 2.1 | 3.0 |
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
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationMs` | 9 | 23.0 | 24.0 | 23.3 | 24.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationNextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationSumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleAccumulationXorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalMessageScheduleMs` | 9 | 30.0 | 31.0 | 30.1 | 31.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorBundleBuildMs` | 9 | 5.0 | 5.0 | 4.9 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClampAMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientBaseMs` | 9 | 56.0 | 57.0 | 56.2 | 57.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorClientOutputMs` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorCoreMs` | 9 | 13.0 | 14.0 | 13.1 | 14.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorLocalWordMaterializations` | 9 | 2560.0 | 2560.0 | 2560.0 | 2560.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskAddMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMaskShareMs` | 9 | 2.0 | 2.0 | 2.0 | 2.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorMs` | 9 | 141.0 | 143.0 | 141.3 | 143.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorReduceAMs` | 9 | 8.0 | 8.0 | 8.0 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorRelayerOutputMs` | 9 | 61.0 | 62.0 | 61.4 | 62.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauDoubleMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalOutputProjectorTauMs` | 9 | 5.0 | 5.0 | 5.0 | 5.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundChMs` | 9 | 11.0 | 12.0 | 11.1 | 12.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundCoreMs` | 9 | 211.0 | 219.0 | 211.7 | 219.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundMajMs` | 9 | 29.0 | 30.0 | 29.1 | 30.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewABitsMs` | 9 | 21.0 | 21.0 | 21.0 | 21.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundNewEBitsMs` | 9 | 21.0 | 22.0 | 21.1 | 22.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma0Ms` | 9 | 7.0 | 7.0 | 6.6 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundSigma1Ms` | 9 | 6.0 | 7.0 | 6.1 | 7.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundState3Ms` | 9 | 2.0 | 3.0 | 2.3 | 3.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1AXorCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1CarryGateMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1Ms` | 9 | 7.0 | 8.0 | 7.4 | 8.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1NextCarryMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1SumMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp1XorAbMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalRoundTemp2Ms` | 9 | 4.0 | 4.0 | 4.0 | 4.0 |
| `build_client_owned_staged_evaluator_artifact` | `hiddenEvalTotalMs` | 9 | 384.0 | 393.0 | 385.6 | 393.0 |
| `build_client_owned_staged_evaluator_artifact` | `materializeSessionMs` | 9 | 0.0 | 0.0 | 0.0 | 0.0 |

### Browser Memory Diagnostics

| Bucket | Count | p50 | p95 | Mean | Max |
|---|---:|---:|---:|---:|---:|
| `jsHeapSizeLimitBytes` | 5 | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB | 3585.82 MiB |
| `sampleCount` | 5 | 52 | 59 | 53 | 59 |
| `totalJSHeapSizePeakBytes` | 5 | 73.05 MiB | 73.05 MiB | 73.05 MiB | 73.05 MiB |
| `usedJSHeapSizeAfterBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeBeforeBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizeDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |
| `usedJSHeapSizePeakBytes` | 5 | 64.85 MiB | 64.85 MiB | 64.85 MiB | 64.85 MiB |
| `usedJSHeapSizePeakDeltaBytes` | 5 | 0 B | 0 B | 0 B | 0 B |

## Notes

- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.
- Relay route diagnostics are observational response metadata and contain bucket durations only.
- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.
- Browser memory diagnostics use Chromium heap counters when available; unsupported browsers report no memory rows.
