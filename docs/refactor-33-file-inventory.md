# Refactor 33 File Inventory

Date captured: 2026-05-07

Generated Phase 0 inventory for `client/src/core/signingEngine`. Classification is intentionally execution-oriented: it identifies what a file owns now and why it should survive only until its target owner absorbs it.

## Classification Counts

| Classification | Files |
| --- | ---: |
| auth boundary | 1 |
| boundary contract | 4 |
| canonical state type | 1 |
| chain display | 7 |
| confirmation boundary | 20 |
| confirmation crypto helper | 7 |
| confirmation UI | 28 |
| confirmation/provisioning boundary | 2 |
| documentation | 1 |
| init/construction | 4 |
| internal barrel to delete | 16 |
| nonce boundary | 1 |
| operation flow | 17 |
| operation helper | 32 |
| operation target scaffolding | 3 |
| ownership note | 11 |
| public facade | 1 |
| public package export | 1 |
| pure chain serialization | 7 |
| signing algorithm boundary | 3 |
| state owner | 36 |
| threshold boundary | 2 |
| threshold crypto boundary | 3 |
| threshold policy boundary | 3 |
| threshold protocol boundary | 9 |
| threshold/session boundary | 7 |
| UI/component-local export | 10 |
| worker RPC | 14 |
| worker/WASM boundary | 4 |
| wrapper | 3 |

## File Map

| File | Classification | Reason To Exist During Refactor | Old-Layout Import Count |
| --- | --- | --- | ---: |
| `client/src/core/signingEngine/README.md` | documentation | Current pre-refactor architecture note. | 0 |
| `client/src/core/signingEngine/SigningEngine.ts` | public facade | SDK-facing method surface and temporary internal delegation point. | 41 |
| `client/src/core/signingEngine/api/evmFamily/accountAuth.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 0 |
| `client/src/core/signingEngine/api/evmFamily/addresses.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 0 |
| `client/src/core/signingEngine/api/evmFamily/authPlanning.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 9 |
| `client/src/core/signingEngine/api/evmFamily/budgetSpending.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 4 |
| `client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 5 |
| `client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 2 |
| `client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 5 |
| `client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 2 |
| `client/src/core/signingEngine/api/evmFamily/errors.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 0 |
| `client/src/core/signingEngine/api/evmFamily/events.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 2 |
| `client/src/core/signingEngine/api/evmFamily/evmNonceLifecycle.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 1 |
| `client/src/core/signingEngine/api/evmFamily/freshEmailOtpRetry.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 3 |
| `client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts` | wrapper | Adapter over nonce lifecycle functions. | 2 |
| `client/src/core/signingEngine/api/evmFamily/nonceMetrics.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 1 |
| `client/src/core/signingEngine/api/evmFamily/nonceResolution.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 3 |
| `client/src/core/signingEngine/api/evmFamily/operationIds.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 2 |
| `client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 1 |
| `client/src/core/signingEngine/api/evmFamily/preparedSigning.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 5 |
| `client/src/core/signingEngine/api/evmFamily/signerLoader.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 6 |
| `client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts` | wrapper | Command wrapper around the partial EVM-family state-machine path. | 10 |
| `client/src/core/signingEngine/api/evmFamily/tempoNonceLifecycle.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 1 |
| `client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 10 |
| `client/src/core/signingEngine/api/evmFamily/types.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 5 |
| `client/src/core/signingEngine/api/evmFamily/warmSessionServices.ts` | operation helper | Current EVM-family operation helper that should move with the vertical slice. | 3 |
| `client/src/core/signingEngine/api/evmSigning.ts` | operation flow | Current EVM-family public operation implementation. | 13 |
| `client/src/core/signingEngine/api/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/api/nearSigning.ts` | operation flow | Current NEAR public operation implementation. | 12 |
| `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts` | operation flow | Current key export/recovery operation implementation. | 2 |
| `client/src/core/signingEngine/api/registration/registrationAccountLifecycle.ts` | operation flow | Current registration operation implementation. | 1 |
| `client/src/core/signingEngine/api/registration/registrationSession.ts` | operation flow | Current registration operation implementation. | 2 |
| `client/src/core/signingEngine/api/session/emailOtpDeviceEnrollmentEscrowStore.ts` | state owner | Current signing-session state helper. | 0 |
| `client/src/core/signingEngine/api/session/signingSessionState.ts` | state owner | Current signing-session state helper. | 0 |
| `client/src/core/signingEngine/api/tempoSigning.ts` | wrapper | Tempo alias over EVM-family signing and nonce lifecycle. | 6 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdCommitQueueShared.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 0 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 2 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 1 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 2 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519CommitQueue.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 0 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 2 |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts` | threshold/session boundary | Current threshold lifecycle, activation, queue, or normalization helper. | 5 |
| `client/src/core/signingEngine/session/persistence/records.ts` | state owner | Current raw threshold session record store and runtime-lane indexes. | 3 |
| `client/src/core/signingEngine/api/userPreferences.ts` | state owner | User preference persistence/manager. | 0 |
| `client/src/core/signingEngine/walletAuth/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/walletAuth/walletAuthModeResolver.ts` | auth boundary | Wallet auth policy and mode resolution. | 0 |
| `client/src/core/signingEngine/assembly/createManagers.ts` | init/construction | Constructs managers, runtime dependency bundles, and warmup behavior. | 5 |
| `client/src/core/signingEngine/assembly/createPorts.ts` | init/construction | Constructs managers, runtime dependency bundles, and warmup behavior. | 23 |
| `client/src/core/signingEngine/assembly/createSigningEngineRuntime.ts` | init/construction | Constructs managers, runtime dependency bundles, and warmup behavior. | 1 |
| `client/src/core/signingEngine/assembly/warmup.ts` | init/construction | Constructs managers, runtime dependency bundles, and warmup behavior. | 1 |
| `client/src/core/signingEngine/chainAdaptors/evm/bytes.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 0 |
| `client/src/core/signingEngine/chainAdaptors/evm/evmAdapter.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 1 |
| `client/src/core/signingEngine/chainAdaptors/evm/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/chainAdaptors/evm/types.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 0 |
| `client/src/core/signingEngine/chainAdaptors/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/chainAdaptors/near/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/chainAdaptors/near/nearAdapter.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 0 |
| `client/src/core/signingEngine/chainAdaptors/tempo/feeToken.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 0 |
| `client/src/core/signingEngine/chainAdaptors/tempo/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/chainAdaptors/tempo/tempoAdapter.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 1 |
| `client/src/core/signingEngine/chainAdaptors/tempo/types.ts` | pure chain serialization | Current chain request, digest, and serialization adaptor. | 0 |
| `client/src/core/signingEngine/chains/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/confirmation/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts` | confirmation/provisioning boundary | Email OTP auth lane and threshold-session provisioning coordinator. | 14 |
| `client/src/core/signingEngine/emailOtp/authLane.ts` | confirmation/provisioning boundary | Email OTP auth lane and threshold-session provisioning coordinator. | 1 |
| `client/src/core/signingEngine/index.ts` | public package export | Current package-facing signing engine export. | 0 |
| `client/src/core/signingEngine/interfaces/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/interfaces/near.ts` | boundary contract | Shared runtime and signing contracts. | 4 |
| `client/src/core/signingEngine/interfaces/nearKeyOps.ts` | boundary contract | Shared runtime and signing contracts. | 0 |
| `client/src/core/signingEngine/interfaces/runtime.ts` | boundary contract | Shared runtime and signing contracts. | 2 |
| `client/src/core/signingEngine/interfaces/signing.ts` | boundary contract | Shared runtime and signing contracts. | 1 |
| `client/src/core/signingEngine/nonce/NonceCoordinator.ts` | nonce boundary | Durable nonce lease and lane coordination. | 2 |
| `client/src/core/signingEngine/nonce/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/flows/README.md` | operation target scaffolding | Refactor 33 target operation ownership and canonical operation state. | 0 |
| `client/src/core/signingEngine/flows/shared/operationState.ts` | operation target scaffolding | Refactor 33 target operation ownership and canonical operation state. | 1 |
| `client/src/core/signingEngine/flows/signEvmFamily/README.md` | operation target scaffolding | Refactor 33 target operation ownership and canonical operation state. | 0 |
| `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts` | operation flow | Current EVM/Tempo operation orchestration. | 3 |
| `client/src/core/signingEngine/orchestration/evm/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/orchestration/near/delegateFlow.ts` | operation flow | Current NEAR operation orchestration. | 3 |
| `client/src/core/signingEngine/orchestration/near/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/orchestration/near/nearSigningFlow.ts` | operation flow | Current NEAR operation orchestration. | 2 |
| `client/src/core/signingEngine/orchestration/near/nep413Flow.ts` | operation flow | Current NEAR operation orchestration. | 2 |
| `client/src/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase.ts` | operation flow | Current NEAR operation orchestration. | 3 |
| `client/src/core/signingEngine/orchestration/near/shared/repairThresholdEd25519MissingRelayerKey.ts` | operation flow | Current NEAR operation orchestration. | 0 |
| `client/src/core/signingEngine/orchestration/near/shared/signingMaterials.ts` | operation flow | Current NEAR operation orchestration. | 2 |
| `client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts` | operation flow | Current NEAR operation orchestration. | 5 |
| `client/src/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.ts` | operation flow | Current NEAR operation orchestration. | 1 |
| `client/src/core/signingEngine/orchestration/near/shared/workerRequestAssembly.ts` | operation flow | Current NEAR operation orchestration. | 0 |
| `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts` | operation flow | Current NEAR operation orchestration. | 9 |
| `client/src/core/signingEngine/orchestration/shared/evmFamilySigningFlow.ts` | operation helper | Shared current orchestration helper. | 8 |
| `client/src/core/signingEngine/orchestration/shared/thresholdEcdsaTransactionAdmission.ts` | operation helper | Shared current orchestration helper. | 2 |
| `client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionReadiness.ts` | operation helper | Shared current orchestration helper. | 1 |
| `client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts` | operation helper | Shared current orchestration helper. | 4 |
| `client/src/core/signingEngine/orchestration/tempo/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts` | operation flow | Current EVM/Tempo operation orchestration. | 4 |
| `client/src/core/signingEngine/orchestration/thresholdActivation.ts` | operation helper | Current cross-cutting orchestration helper. | 2 |
| `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts` | threshold boundary | Wallet-origin threshold ECDSA coordination. | 2 |
| `client/src/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef.ts` | threshold boundary | Wallet-origin threshold ECDSA coordination. | 1 |
| `client/src/core/signingEngine/session/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/session/SigningSessionCoordinator.ts` | state owner | Session lifecycle, persistence, available signing lanes, and restore behavior. | 0 |
| `client/src/core/signingEngine/session/identity/laneIdentity.ts` | canonical state type | Target selected-lane identity type owner. | 0 |
| `client/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts` | state owner | Session lifecycle, persistence, available signing lanes, and restore behavior. | 0 |
| `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts` | state owner | Session lifecycle, persistence, available signing lanes, and restore behavior. | 0 |
| `client/src/core/signingEngine/session/budget/budget.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/budget/budgetFinalizer.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/budget/budgetProjection.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/operationState/execution.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/operationState/lanes.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 1 |
| `client/src/core/signingEngine/session/planning/operationFingerprint.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/planning/operationIdBinding.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/planning/planner.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/operationState/postSignPolicy.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 1 |
| `client/src/core/signingEngine/session/operationState/preparedOperation.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/availability/readiness.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 1 |
| `client/src/core/signingEngine/session/operationState/trace.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/operationState/transactionState.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 0 |
| `client/src/core/signingEngine/session/operationState/types.ts` | state owner | Current signing-session planner, transaction state, budget, readiness, execution, and trace types. | 1 |
| `client/src/core/signingEngine/session/availability/availableSigningLanes.ts` | state owner | Session lifecycle, persistence, available signing lanes, and restore behavior. | 1 |
| `client/src/core/signingEngine/session/warmCapabilities/capabilityReader.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 0 |
| `client/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 2 |
| `client/src/core/signingEngine/session/passkey/ecdsaBootstrapRequest.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 0 |
| `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 2 |
| `client/src/core/signingEngine/session/passkey/ed25519Provisioner.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 0 |
| `client/src/core/signingEngine/session/warmCapabilities/persistence.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 2 |
| `client/src/core/signingEngine/session/warmCapabilities/postSignPolicyAdapter.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 1 |
| `client/src/core/signingEngine/session/warmCapabilities/readModel.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 1 |
| `client/src/core/signingEngine/session/passkey/runtime.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 1 |
| `client/src/core/signingEngine/session/warmCapabilities/statusReader.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 1 |
| `client/src/core/signingEngine/session/warmCapabilities/store.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 1 |
| `client/src/core/signingEngine/session/warmCapabilities/transitions.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 0 |
| `client/src/core/signingEngine/session/warmCapabilities/types.ts` | state owner | Warm signing read model, provisioning, persistence, status, and transitions. | 5 |
| `client/src/core/signingEngine/signers/algorithms/ed25519.ts` | signing algorithm boundary | Current algorithm-level signing implementation. | 0 |
| `client/src/core/signingEngine/signers/algorithms/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/signers/algorithms/secp256k1.ts` | signing algorithm boundary | Current algorithm-level signing implementation. | 4 |
| `client/src/core/signingEngine/signers/algorithms/webauthnP256.ts` | signing algorithm boundary | Current algorithm-level signing implementation. | 0 |
| `client/src/core/signingEngine/signers/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/signers/wasm/ethSignerWasm.ts` | worker/WASM boundary | Current WASM-backed chain or HSS worker wrappers. | 2 |
| `client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts` | worker/WASM boundary | Current WASM-backed chain or HSS worker wrappers. | 0 |
| `client/src/core/signingEngine/signers/wasm/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/signers/wasm/nearSignerWasm.ts` | worker/WASM boundary | Current WASM-backed chain or HSS worker wrappers. | 0 |
| `client/src/core/signingEngine/signers/wasm/tempoSignerWasm.ts` | worker/WASM boundary | Current WASM-backed chain or HSS worker wrappers. | 1 |
| `client/src/core/signingEngine/signers/webauthn/cose/coseP256.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/cose/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/credentials/credentialExtensions.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/credentials/helpers.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/credentials/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/device/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/device/signerSlot.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/fallbacks/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/signers/webauthn/fallbacks/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/fallbacks/safari-fallbacks.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/signers/webauthn/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/prompt/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/signers/webauthn/prompt/touchIdPrompt.ts` | confirmation crypto helper | WebAuthn prompt, credential, and fallback helper. | 0 |
| `client/src/core/signingEngine/threshold/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/threshold/ed25519WrapKeySalt.ts` | threshold crypto boundary | Threshold PRF, salt, and WebAuthn crypto helpers. | 0 |
| `client/src/core/signingEngine/threshold/prfSalts.ts` | threshold crypto boundary | Threshold PRF, salt, and WebAuthn crypto helpers. | 0 |
| `client/src/core/signingEngine/threshold/session/ed25519AuthSession.ts` | threshold policy boundary | Threshold relayer session policy and auth-session helpers. | 1 |
| `client/src/core/signingEngine/threshold/session/ed25519RelayerHealth.ts` | threshold policy boundary | Threshold relayer session policy and auth-session helpers. | 0 |
| `client/src/core/signingEngine/threshold/session/sessionPolicy.ts` | threshold policy boundary | Threshold relayer session policy and auth-session helpers. | 1 |
| `client/src/core/signingEngine/threshold/webauthn.ts` | threshold crypto boundary | Threshold PRF, salt, and WebAuthn crypto helpers. | 2 |
| `client/src/core/signingEngine/threshold/workflows/authorizeEcdsa.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 0 |
| `client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 3 |
| `client/src/core/signingEngine/threshold/workflows/connectEcdsaSession.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 1 |
| `client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 1 |
| `client/src/core/signingEngine/threshold/workflows/httpRequest.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 0 |
| `client/src/core/signingEngine/threshold/workflows/keygenEcdsa.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 1 |
| `client/src/core/signingEngine/threshold/workflows/signEcdsa.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 0 |
| `client/src/core/signingEngine/threshold/workflows/thresholdClientSecretSource.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 0 |
| `client/src/core/signingEngine/threshold/workflows/thresholdEcdsaHssTransport.ts` | threshold protocol boundary | Relayer protocol workflows for threshold signing/session setup. | 0 |
| `client/src/core/signingEngine/touchConfirm/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 3 |
| `client/src/core/signingEngine/touchConfirm/awaitUserConfirmation.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/confirmationReadinessRegistry.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/calldata.ts` | chain display | Transaction display formatting for confirmation UI. | 0 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/evmTx.ts` | chain display | Transaction display formatting for confirmation UI. | 3 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/functionSelectors.ts` | chain display | Transaction display formatting for confirmation UI. | 0 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/gas.ts` | chain display | Transaction display formatting for confirmation UI. | 0 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/nearTx.ts` | chain display | Transaction display formatting for confirmation UI. | 1 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/normalization.ts` | chain display | Transaction display formatting for confirmation UI. | 0 |
| `client/src/core/signingEngine/touchConfirm/displayFormat/tempoTx.ts` | chain display | Transaction display formatting for confirmation UI. | 2 |
| `client/src/core/signingEngine/touchConfirm/handlers/determineConfirmationConfig.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/handlers/flowOrchestrator.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/adapters/adapters.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 2 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/adapters/request.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 1 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/localOnly.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/registration.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 1 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/requestRegistrationCredentialConfirmation.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 3 |
| `client/src/core/signingEngine/touchConfirm/handlers/handlePromptFromWorker.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 0 |
| `client/src/core/signingEngine/touchConfirm/intentDigestPreparationRegistry.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 1 |
| `client/src/core/signingEngine/touchConfirm/shared/confirmCommon.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 1 |
| `client/src/core/signingEngine/touchConfirm/shared/displayModel.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/shared/forbiddenMainThreadSecrets.typecheck.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/shared/normalization.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 0 |
| `client/src/core/signingEngine/touchConfirm/types.ts` | confirmation boundary | Touch/passkey confirmation runtime and contracts. | 3 |
| `client/src/core/signingEngine/touchConfirm/ui/confirm-ui-types.ts` | confirmation UI | Secure confirmation UI runtime/components. | 2 |
| `client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/export-viewer-host.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/Drawer/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/Drawer/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/iframe-host.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/viewer.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/HaloBorder/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/HaloBorder/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirm-content.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts` | confirmation UI | Secure confirmation UI runtime/components. | 2 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts` | confirmation UI | Secure confirmation UI runtime/components. | 3 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts` | confirmation UI | Secure confirmation UI runtime/components. | 3 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/LitElementWithProps.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/PasskeyHaloLoading/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/README-lit-elements.md` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/abi/abiDecode.ts` | confirmation UI | Secure confirmation UI runtime/components. | 2 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/abi/enrichDisplayModelWithAbi.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/index.ts` | UI/component-local export | Colocated component or WebAuthn helper export. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/evm.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/fallback.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/near.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/tempo.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/types.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/tx-tree-themes.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/tx-tree-utils.ts` | confirmation UI | Secure confirmation UI runtime/components. | 1 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/asset-base.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/common/PadlockIcon.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/common/formatters.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/css/README-css-vars.md` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/css/css-loader.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/lit-events.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/touchConfirm/ui/registry.ts` | confirmation UI | Secure confirmation UI runtime/components. | 0 |
| `client/src/core/signingEngine/workerManager/executeWorkerOperation.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 2 |
| `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts` | internal barrel to delete | Broad re-export that hides concrete dependencies. | 2 |
| `client/src/core/signingEngine/workerManager/session.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/validation.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 1 |
| `client/src/core/signingEngine/workerManager/workerTransport.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workerTypes.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 4 |
| `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 5 |
| `client/src/core/signingEngine/workerManager/workers/email-otp/fetch.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/hss-client.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 4 |
| `client/src/core/signingEngine/workerManager/workers/shamir3pass.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/shamir3pass/runtime.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workerManager/workers/tempo-signer.worker.ts` | worker RPC | Worker transport, operation execution, worker messages, and runtimes. | 0 |
| `client/src/core/signingEngine/workers/README.md` | ownership note | Folder ownership contract for Refactor 33. | 0 |

## Old-Layout Imports By File

This section inventories imports from old folders listed in Phase 0. It groups every matching import specifier by importer so reviewers can see which files still depend on old layout paths.

| Importer | Import Specifiers |
| --- | --- |
| `client/src/core/signingEngine/SigningEngine.ts` | `./api/userPreferences`<br>`./orchestration/thresholdActivation`<br>`./emailOtp/authLane`<br>`./touchConfirm/types`<br>`./touchConfirm/shared/confirmTypes`<br>`./session/operationState/types`<br>`./session/budget/budget`<br>`./signers/webauthn/prompt/touchIdPrompt`<br>`./signers/webauthn/credentials`<br>`./chainAdaptors/evm/types`<br>`./chainAdaptors/evm/evmAdapter`<br>`./chainAdaptors/tempo/types`<br>`./chainAdaptors/tempo/tempoAdapter`<br>`./signers/webauthn/credentials/credentialExtensions`<br>`./api/thresholdLifecycle/thresholdSessionActivation`<br>`./api/thresholdLifecycle/thresholdEd25519Lifecycle`<br>`./api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence`<br>`./session/persistence/records`<br>`./session/operationState/ecdsaChainTarget`<br>`./api/thresholdLifecycle/thresholdEcdsaLoginPrefill`<br>`./threshold/session/sessionPolicy`<br>`./api/nearSigning`<br>`./api/tempoSigning`<br>`./api/evmFamily/types`<br>`./api/session/signingSessionState`<br>`./api/thresholdLifecycle/thresholdEcdsaCommitQueue`<br>`./api/thresholdLifecycle/thresholdEd25519CommitQueue`<br>`./api/recovery/privateKeyExportRecovery`<br>`./signers/webauthn/device/signerSlot`<br>`./touchConfirm/ui/export-viewer-host`<br>`./api/registration/registrationSession`<br>`./api/registration/registrationAccountLifecycle`<br>`./signers/wasm/hssClientSignerWasm`<br>`./orchestration/near/shared/ensureThresholdEd25519HssClientBase`<br>`./emailOtp/EmailOtpThresholdSessionCoordinator`<br>`./session/operationState/trace`<br>`./session/availability/readiness`<br>`./orchestration/thresholdActivation`<br>`./emailOtp/EmailOtpThresholdSessionCoordinator`<br>`./api/nearSigning`<br>`./api/thresholdLifecycle/thresholdEcdsaLoginPrefill` |
| `client/src/core/signingEngine/api/evmFamily/authPlanning.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`../../emailOtp/authLane`<br>`../../session/availability/readiness`<br>`../../session/operationState/trace`<br>`../../session/operationState/types`<br>`../../session/operationState/types`<br>`../../session/operationState/preparedOperation`<br>`../../orchestration/shared/touchConfirmSigning`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/budgetSpending.ts` | `../../session/budget/budgetFinalizer`<br>`../../session/budget/budget`<br>`../../session/operationState/types`<br>`../../session/operationState/transactionState` |
| `client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts` | `../../session/operationState/lanes`<br>`../../emailOtp/authLane`<br>`../../session/operationState/lanes`<br>`../../session/operationState/types`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts` | `../../session/operationState/types`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts` | `../../session/operationState/types`<br>`../../session/operationState/trace`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts` | `../../session/operationState/types`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/events.ts` | `../../session/operationState/execution`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/evmNonceLifecycle.ts` | `../../chainAdaptors/evm/types` |
| `client/src/core/signingEngine/api/evmFamily/freshEmailOtpRetry.ts` | `../../chainAdaptors/evm/evmAdapter`<br>`../../chainAdaptors/tempo/tempoAdapter`<br>`../../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts` | `../../chainAdaptors/evm/evmAdapter`<br>`../../chainAdaptors/tempo/tempoAdapter` |
| `client/src/core/signingEngine/api/evmFamily/nonceMetrics.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/nonceResolution.ts` | `../../chainAdaptors/evm/types`<br>`../../chainAdaptors/tempo/types` |
| `client/src/core/signingEngine/api/evmFamily/operationIds.ts` | `../../session/operationState/types`<br>`../../session/planning/operationIdBinding` |
| `client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/preparedSigning.ts` | `../../session/budget/budget`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/ecdsaChainTarget`<br>`../../session/operationState/preparedOperation`<br>`../../session/operationState/trace` |
| `client/src/core/signingEngine/api/evmFamily/signerLoader.ts` | `../../chainAdaptors/evm/evmAdapter`<br>`../../chainAdaptors/tempo/tempoAdapter`<br>`../../signers/algorithms/secp256k1`<br>`../../signers/algorithms/webauthnP256`<br>`../../orchestration/evm/evmSigningFlow`<br>`../../orchestration/tempo/tempoSigningFlow` |
| `client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts` | `../../orchestration/shared/thresholdSigningSessionReadiness`<br>`../../session/operationState/types`<br>`../../session/operationState/execution`<br>`../../session/operationState/trace`<br>`../../chainAdaptors/evm/types`<br>`../../chainAdaptors/tempo/types`<br>`../../signers/webauthn/credentials/credentialExtensions`<br>`../../threshold/session/sessionPolicy`<br>`../../orchestration/shared/thresholdEcdsaTransactionAdmission`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/tempoNonceLifecycle.ts` | `../../chainAdaptors/tempo/types` |
| `client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts` | `../../session/operationState/types`<br>`../../session/operationState/execution`<br>`../../chainAdaptors/evm/evmAdapter`<br>`../../chainAdaptors/evm/types`<br>`../../chainAdaptors/tempo/tempoAdapter`<br>`../../chainAdaptors/tempo/types`<br>`../../session/budget/budget`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/ecdsaChainTarget`<br>`../../orchestration/shared/thresholdEcdsaTransactionAdmission` |
| `client/src/core/signingEngine/api/evmFamily/types.ts` | `../../chainAdaptors/evm/evmAdapter`<br>`../../chainAdaptors/evm/types`<br>`../../chainAdaptors/tempo/tempoAdapter`<br>`../../chainAdaptors/tempo/types`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmFamily/warmSessionServices.ts` | `../../orchestration/thresholdActivation`<br>`../../orchestration/walletOrigin/thresholdEcdsaCoordinator`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/evmSigning.ts` | `../chainAdaptors/evm/types`<br>`../chainAdaptors/evm/evmAdapter`<br>`../chainAdaptors/tempo/types`<br>`../chainAdaptors/tempo/tempoAdapter`<br>`../session/operationState/types`<br>`../session/operationState/trace`<br>`../session/planning/operationFingerprint`<br>`../session/budget/budget`<br>`../orchestration/thresholdActivation`<br>`../emailOtp/authLane`<br>`../session/operationState/ecdsaChainTarget`<br>`../touchConfirm/shared/confirmTypes`<br>`../session/operationState/transactionState` |
| `client/src/core/signingEngine/api/nearSigning.ts` | `../emailOtp/authLane`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`../orchestration/near/nearSigningFlow`<br>`../threshold/session/sessionPolicy`<br>`../session/operationState/types`<br>`../session/operationState/lanes`<br>`../session/operationState/ecdsaChainTarget`<br>`../session/budget/budget`<br>`../orchestration/shared/touchConfirmSigning`<br>`../session/operationState/trace`<br>`../session/operationState/preparedOperation`<br>`../session/operationState/transactionState` |
| `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts` | `../../signers/webauthn/device/signerSlot`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/registration/registrationAccountLifecycle.ts` | `../../signers/webauthn/device/signerSlot` |
| `client/src/core/signingEngine/api/registration/registrationSession.ts` | `../../signers/webauthn/prompt/touchIdPrompt`<br>`../../signers/webauthn/credentials` |
| `client/src/core/signingEngine/api/tempoSigning.ts` | `../chainAdaptors/evm/types`<br>`../chainAdaptors/evm/evmAdapter`<br>`../chainAdaptors/tempo/types`<br>`../chainAdaptors/tempo/tempoAdapter`<br>`../session/operationState/types`<br>`../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence.ts` | `../../orchestration/thresholdActivation`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts` | `../../orchestration/walletOrigin/thresholdEcdsaCoordinator`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts` | `../../signers/webauthn/credentials/credentialExtensions`<br>`../../signers/wasm/hssClientSignerWasm` |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts` | `../../signers/webauthn/prompt/touchIdPrompt`<br>`../../orchestration/thresholdActivation`<br>`../../threshold/session/sessionPolicy`<br>`../../session/operationState/types`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/session/persistence/records.ts` | `../interfaces/signing`<br>`../orchestration/thresholdActivation`<br>`./signingSession/ecdsaChainTarget`<br>`../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/assembly/createManagers.ts` | `../touchConfirm/TouchConfirmManager`<br>`../touchConfirm/types`<br>`../signers/webauthn/prompt/touchIdPrompt`<br>`../api/userPreferences`<br>`../api/userPreferences` |
| `client/src/core/signingEngine/assembly/createPorts.ts` | `../touchConfirm/types`<br>`../chainAdaptors/evm/types`<br>`../chainAdaptors/evm/evmAdapter`<br>`../chainAdaptors/tempo/types`<br>`../chainAdaptors/tempo/tempoAdapter`<br>`../signers/webauthn/prompt/touchIdPrompt`<br>`../api/nearSigning`<br>`../api/recovery/privateKeyExportRecovery`<br>`../api/registration/registrationAccountLifecycle`<br>`../api/registration/registrationSession`<br>`../api/session/signingSessionState`<br>`../api/tempoSigning`<br>`../api/thresholdLifecycle/thresholdEd25519Lifecycle`<br>`../api/evmFamily/accountAuth`<br>`../session/persistence/records`<br>`../api/thresholdLifecycle/thresholdSessionActivation`<br>`../orchestration/thresholdActivation`<br>`../emailOtp/authLane`<br>`../api/userPreferences`<br>`../touchConfirm/ui/confirm-ui`<br>`../session/budget/budget`<br>`../session/operationState/ecdsaChainTarget`<br>`../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/assembly/createSigningEngineRuntime.ts` | `../api/userPreferences` |
| `client/src/core/signingEngine/assembly/warmup.ts` | `../signers/webauthn/device/signerSlot` |
| `client/src/core/signingEngine/chainAdaptors/evm/evmAdapter.ts` | `../../signers/wasm/ethSignerWasm` |
| `client/src/core/signingEngine/chainAdaptors/tempo/tempoAdapter.ts` | `../../signers/wasm/tempoSignerWasm` |
| `client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts` | `@/core/signingEngine/signers/webauthn/prompt/touchIdPrompt`<br>`@/core/signingEngine/touchConfirm/types`<br>`@/core/signingEngine/session/persistence/records`<br>`@/core/signingEngine/session/persistence/records`<br>`@/core/signingEngine/orchestration/thresholdActivation`<br>`@/core/signingEngine/session/operationState/ecdsaChainTarget`<br>`@/core/signingEngine/session/availability/readiness`<br>`@/core/signingEngine/threshold/session/sessionPolicy`<br>`@/core/signingEngine/threshold/session/sessionPolicy`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/signers/wasm/hssClientSignerWasm`<br>`@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle`<br>`@/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase`<br>`@/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence` |
| `client/src/core/signingEngine/emailOtp/authLane.ts` | `@/core/signingEngine/session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/interfaces/near.ts` | `../touchConfirm/shared/confirmTypes`<br>`../session/operationState/types`<br>`../session/persistence/records`<br>`../session/operationState/transactionState` |
| `client/src/core/signingEngine/interfaces/runtime.ts` | `../signers/webauthn/prompt/touchIdPrompt`<br>`../api/userPreferences` |
| `client/src/core/signingEngine/interfaces/signing.ts` | `../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/nonce/NonceCoordinator.ts` | `../session/operationState/types`<br>`../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/flows/shared/operationState.ts` | `../../session/operationState/types` |
| `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts` | `@/core/signingEngine/chainAdaptors/evm/evmAdapter`<br>`@/core/signingEngine/chainAdaptors/evm/types`<br>`@/core/signingEngine/touchConfirm/displayFormat/evmTx` |
| `client/src/core/signingEngine/orchestration/near/delegateFlow.ts` | `@/core/signingEngine/threshold/session/sessionPolicy`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`../../session/planning/planner` |
| `client/src/core/signingEngine/orchestration/near/nearSigningFlow.ts` | `@/core/signingEngine/chainAdaptors/near/nearAdapter`<br>`@/core/signingEngine/signers/algorithms/ed25519` |
| `client/src/core/signingEngine/orchestration/near/nep413Flow.ts` | `@/core/signingEngine/threshold/session/sessionPolicy`<br>`../../session/planning/planner` |
| `client/src/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase.ts` | `@/core/signingEngine/session/persistence/records`<br>`@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle`<br>`@/core/signingEngine/signers/wasm/hssClientSignerWasm` |
| `client/src/core/signingEngine/orchestration/near/shared/signingMaterials.ts` | `@/core/signingEngine/signers/webauthn/credentials/credentialExtensions`<br>`@/core/signingEngine/signers/webauthn/device/signerSlot` |
| `client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/session/operationState/lanes`<br>`@/core/signingEngine/session/operationState/trace`<br>`@/core/signingEngine/session/operationState/types`<br>`@/core/signingEngine/session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.ts` | `@/core/signingEngine/session/persistence/records` |
| `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`../../session/persistence/records`<br>`@/core/signingEngine/threshold/session/sessionPolicy`<br>`../../session/operationState/types`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/trace`<br>`../../session/budget/budget`<br>`../../session/budget/budgetFinalizer`<br>`../../session/planning/operationFingerprint` |
| `client/src/core/signingEngine/orchestration/shared/evmFamilySigningFlow.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/chainAdaptors/evm/bytes`<br>`@/core/signingEngine/signers/webauthn/credentials/helpers`<br>`@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry`<br>`../../session/budget/budget`<br>`../../session/operationState/transactionState`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/orchestration/shared/thresholdEcdsaTransactionAdmission.ts` | `../../session/operationState/transactionState`<br>`../../touchConfirm/shared/confirmTypes` |
| `client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionReadiness.ts` | `@/core/signingEngine/session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/session/operationState/types`<br>`@/core/signingEngine/session/operationState/types`<br>`@/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy` |
| `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts` | `@/core/signingEngine/chainAdaptors/tempo/tempoAdapter`<br>`@/core/signingEngine/chainAdaptors/tempo/types`<br>`@/core/signingEngine/touchConfirm/displayFormat/tempoTx`<br>`@/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef` |
| `client/src/core/signingEngine/orchestration/thresholdActivation.ts` | `@/core/signingEngine/threshold/session/sessionPolicy`<br>`@/core/signingEngine/session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts` | `../../signers/wasm/ethSignerWasm`<br>`../../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef.ts` | `../../signers/webauthn/cose/coseP256` |
| `client/src/core/signingEngine/session/operationState/lanes.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/operationState/postSignPolicy.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/availability/readiness.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/operationState/types.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/availability/availableSigningLanes.ts` | `../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts` | `../../emailOtp/authLane`<br>`../../session/persistence/records` |
| `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts` | `../../session/persistence/records`<br>`../../orchestration/thresholdActivation` |
| `client/src/core/signingEngine/session/warmCapabilities/persistence.ts` | `../../session/persistence/records`<br>`../../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/session/warmCapabilities/postSignPolicyAdapter.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/warmCapabilities/readModel.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/passkey/runtime.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/warmCapabilities/statusReader.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/warmCapabilities/store.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/session/warmCapabilities/types.ts` | `../../api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence`<br>`../../session/persistence/records`<br>`../../emailOtp/authLane`<br>`../../orchestration/thresholdActivation`<br>`../../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/signers/algorithms/secp256k1.ts` | `../../orchestration/walletOrigin/thresholdEcdsaCoordinator`<br>`../../orchestration/walletOrigin/thresholdEcdsaCoordinator`<br>`../../session/operationState/ecdsaChainTarget`<br>`../../threshold/session/sessionPolicy` |
| `client/src/core/signingEngine/signers/wasm/ethSignerWasm.ts` | `../../chainAdaptors/evm/types`<br>`../../chainAdaptors/evm/bytes` |
| `client/src/core/signingEngine/signers/wasm/tempoSignerWasm.ts` | `../../chainAdaptors/tempo/types` |
| `client/src/core/signingEngine/threshold/session/ed25519AuthSession.ts` | `../../session/persistence/records` |
| `client/src/core/signingEngine/threshold/session/sessionPolicy.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/threshold/webauthn.ts` | `../signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u`<br>`../signers/webauthn/credentials/credentialExtensions` |
| `client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts` | `@/core/signingEngine/api/session/signingSessionState`<br>`../../signers/wasm/hssClientSignerWasm`<br>`../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/threshold/workflows/connectEcdsaSession.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts` | `@/core/signingEngine/api/session/signingSessionState` |
| `client/src/core/signingEngine/threshold/workflows/keygenEcdsa.ts` | `../../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts` | `../session/persistence/records`<br>`../threshold/session/sessionPolicy`<br>`../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/touchConfirm/displayFormat/evmTx.ts` | `@/core/signingEngine/chainAdaptors/evm/types`<br>`@/core/signingEngine/chainAdaptors/evm/bytes`<br>`@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/displayFormat/nearTx.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/displayFormat/tempoTx.ts` | `@/core/signingEngine/chainAdaptors/tempo/types`<br>`@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/adapters/adapters.ts` | `@/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u`<br>`@/core/signingEngine/session/operationState/types` |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/adapters/request.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/registration.ts` | `@/core/signingEngine/signers/webauthn/credentials/helpers` |
| `client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts` | `@/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u`<br>`@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry`<br>`@/core/signingEngine/touchConfirm/confirmationReadinessRegistry` |
| `client/src/core/signingEngine/touchConfirm/intentDigestPreparationRegistry.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/types.ts` | `../signers/webauthn/prompt/touchIdPrompt`<br>`../api/userPreferences`<br>`../session/operationState/ecdsaChainTarget` |
| `client/src/core/signingEngine/touchConfirm/ui/confirm-ui-types.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes` |
| `client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/viewer.ts` | `@/core/signingEngine/touchConfirm/shared/confirmTypes` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirm-content.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel`<br>`@/core/signingEngine/touchConfirm/shared/confirmTypes`<br>`@/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/abi/abiDecode.ts` | `@/core/signingEngine/chainAdaptors/evm/types`<br>`@/core/signingEngine/chainAdaptors/evm/bytes` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/abi/enrichDisplayModelWithAbi.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/evm.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/fallback.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/near.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/tempo.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/renderers/types.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/touchConfirm/ui/lit-components/TxTree/tx-tree-utils.ts` | `@/core/signingEngine/touchConfirm/shared/displayModel` |
| `client/src/core/signingEngine/workerManager/index.ts` | `../signers/webauthn/prompt/touchIdPrompt`<br>`../api/userPreferences` |
| `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts` | `@/core/signingEngine/signers/wasm/nearSignerWasm`<br>`@/core/signingEngine/signers/wasm/hssClientSignerWasm` |
| `client/src/core/signingEngine/workerManager/validation.ts` | `@/core/signingEngine/signers/webauthn/credentials/helpers` |
| `client/src/core/signingEngine/workerManager/workerTypes.ts` | `../orchestration/thresholdActivation`<br>`../session/operationState/ecdsaChainTarget`<br>`../threshold/session/sessionPolicy`<br>`../emailOtp/authLane` |
| `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts` | `@/core/signingEngine/orchestration/thresholdActivation`<br>`@/core/signingEngine/session/operationState/ecdsaChainTarget`<br>`@/core/signingEngine/threshold/session/sessionPolicy`<br>`../../emailOtp/authLane`<br>`../../api/session/emailOtpDeviceEnrollmentEscrowStore` |
| `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts` | `@/core/signingEngine/session/operationState/ecdsaChainTarget`<br>`../../chainAdaptors/evm/bytes`<br>`../../touchConfirm/awaitUserConfirmation`<br>`../../touchConfirm/shared/confirmTypes` |

## Wrapper Files Already Identified

- `client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts`: Adapter over nonce lifecycle functions.
- `client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts`: Command wrapper around the partial EVM-family state-machine path.
- `client/src/core/signingEngine/api/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/api/tempoSigning.ts`: Tempo alias over EVM-family signing and nonce lifecycle.
- `client/src/core/signingEngine/walletAuth/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/chainAdaptors/evm/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/chainAdaptors/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/chainAdaptors/near/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/chainAdaptors/tempo/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/interfaces/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/orchestration/evm/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/orchestration/near/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/orchestration/tempo/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/signers/algorithms/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/signers/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/signers/wasm/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/touchConfirm/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/workerManager/index.ts`: Broad re-export that hides concrete dependencies.
- `client/src/core/signingEngine/workerManager/nearKeyOps/index.ts`: Broad re-export that hides concrete dependencies.

## Inventory Status

- Every `.ts` and `.md` file under `client/src/core/signingEngine` is listed above.
- Every import specifier matching the old Phase 0 folders is grouped above.
- Files classified as `wrapper` or `internal barrel to delete` should be deleted as their owning slice moves.
