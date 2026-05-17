# Refactor 33 Inventory

Date captured: 2026-05-07

This is the Phase 0 execution inventory for
`client/src/core/signingEngine`. It records the current public surface, the
old-layout dependency hotspots, wrapper candidates, and the minimum verification
set to keep near the refactor.

## Current SigningEngine Entrypoints

`SigningEnginePublic` currently exposes more than signing operations. For the
folder reorganization, treat these groups differently.

Public signing and signing-adjacent operation entrypoints:

| Entrypoint | Current implementation path | Target owner |
| --- | --- | --- |
| `signNear` | `SigningEngine.ts` -> `api/nearSigning.ts` -> `orchestration/near/*` | `operations/signNear/*` |
| `signTempo` | `SigningEngine.ts` -> `api/tempoSigning.ts` -> `api/evmSigning.ts` -> `api/evmFamily/*` -> `orchestration/shared/evmFamilySigningFlow.ts` | `operations/signEvmFamily/*` |
| `reportTempoBroadcastAccepted` | `SigningEngine.ts` -> `api/tempoSigning.ts` -> `api/evmFamily/tempoNonceLifecycle.ts` | `operations/signEvmFamily/nonceLifecycle.ts` |
| `reportTempoBroadcastRejected` | Same as above | `operations/signEvmFamily/nonceLifecycle.ts` |
| `reportTempoFinalized` | Same as above | `operations/signEvmFamily/nonceLifecycle.ts` |
| `reportTempoDroppedOrReplaced` | Same as above | `operations/signEvmFamily/nonceLifecycle.ts` |
| `reconcileTempoNonceLane` | Same as above | `operations/signEvmFamily/nonceLifecycle.ts` |
| `exportKeypairWithUI` | `SigningEngine.ts` plus `api/recovery/privateKeyExportRecovery.ts` | `operations/exportKey/*` |
| `exportNearEd25519SeedArtifactWithUI` | `api/recovery/privateKeyExportRecovery.ts` | `operations/exportKey/*` |
| `exportThresholdEd25519SeedFromHssReport` | `SigningEngine.ts` plus `api/thresholdLifecycle/thresholdEd25519Lifecycle.ts` | `operations/exportKey/*` and `threshold/ed25519/*` |
| `signTransactionWithKeyPair` | `SigningEngine.ts` -> `enginePorts.nearKeyOpsDeps` -> `workerManager/nearKeyOps/*` | `workers/*` with a public operation wrapper if it remains SDK-facing |
| `requestRegistrationCredentialConfirmation` | `api/registration/registrationSession.ts` plus `touchConfirm/*` | `operations/registration/*` and `confirmation/*` |

Session, registration, restore, and threshold lifecycle public methods remain
public SDK surface, while most of their implementation should move to
`operations/registration`, `operations/recovery`, `session`, or `threshold`.

## Old-Layout Import Hotspots

Current scan command:

```sh
rg "from ['\"][^'\"]*(api/|orchestration/|chainAdaptors/|signers/|touchConfirm/|emailOtp/|threshold/session/|session/signingSession/)[^'\"]*['\"]" client/src/core/signingEngine -g '*.ts' -n
```

The scan currently finds 389 old-layout imports. Highest-churn importers:

| Importer | Count | Notes |
| --- | ---: | --- |
| `SigningEngine.ts` | 44 | Public facade still reaches directly into almost every old folder. |
| `init/createPorts.ts` | 23 | Builds callback-heavy dependency bags over old API modules. |
| `emailOtp/EmailOtpThresholdSessionCoordinator.ts` | 16 | Mixes OTP, threshold session provisioning, UI confirmation, and session state. |
| `api/evmSigning.ts` | 15 | EVM-family operation flow imports chain, session, threshold, confirmation, and orchestration helpers. |
| `api/nearSigning.ts` | 12 | NEAR operation flow imports session selection, threshold policy, touch confirmation, and orchestration. |
| `orchestration/shared/evmFamilySigningFlow.ts` | 10 | Runtime signing path still depends on old API/session modules. |
| `orchestration/near/transactionsFlow.ts` | 10 | NEAR flow still uses request-specific orchestration and transaction lane structs. |
| `api/evmFamily/transactionExecutor.ts` | 10 | Partial state-machine finalization remains under `api`. |
| `api/evmFamily/signingFlowRuntime.ts` | 10 | Runtime command wrapper layer over the state-machine concept. |
| `api/evmFamily/authPlanning.ts` | 10 | Auth planning still uses old session and confirmation types. |

These hotspots set the migration order: canonical state first, then the
EVM-family vertical slice, then NEAR.

## Current File Classification

Execution-critical files by role:

| Role | Current files/folders |
| --- | --- |
| Public facade | `SigningEngine.ts`, `index.ts`, `SigningEnginePublic` type |
| Operation flow | `api/nearSigning.ts`, `api/evmSigning.ts`, `api/tempoSigning.ts`, `api/recovery/*`, `api/registration/*`, `orchestration/near/*`, `orchestration/evm/*`, `orchestration/tempo/*`, `orchestration/shared/evmFamilySigningFlow.ts` |
| State owner | `session/*`, `session/signingSession/*`, `api/session/signingSessionState.ts`, `session/persistence/records.ts`, `api/thresholdLifecycle/*CommitQueue.ts` |
| Confirmation boundary | `touchConfirm/*`, `emailOtp/authLane.ts`, confirmation worker runtime files |
| Threshold boundary | `threshold/session/*`, `threshold/workflows/*`, `threshold/prfSalts.ts`, `threshold/webauthn.ts`, `api/thresholdLifecycle/thresholdSessionActivation.ts`, `api/thresholdLifecycle/thresholdEd25519Lifecycle.ts` |
| Chain serialization/display | `chainAdaptors/*`, `touchConfirm/displayFormat/*`, chain-specific WASM wrappers under `signers/wasm/*` |
| Worker RPC | `workerManager/*`, `workerManager/workers/*`, `workerManager/nearKeyOps/*`, `workerManager/workerTransport.ts` |
| Init/construction | `bootstrap/*`, constructor and warmup sections in `SigningEngine.ts` |
| Internal barrels | `api/index.ts`, `chainAdaptors/index.ts`, `signers/index.ts`, `workerManager/index.ts`, old orchestration per-chain `index.ts` files |
| UI component-local exports | `touchConfirm/ui/lit-components/*/index.ts`, `signers/webauthn/*/index.ts` |

The exhaustive file-by-file inventory remains open because it should be
generated after the first slice chooses the concrete moved file set.

## Wrapper Candidates

Delete these when their last caller moves:

| Candidate | Reason |
| --- | --- |
| `api/tempoSigning.ts` | Thin alias over EVM-family signing and Tempo nonce reports. |
| `init/createPorts.ts` callback bags | Many fields only route sibling modules through `SigningEngine` or old `api/*` modules. |
| `api/evmFamily/signingFlowRuntime.ts` | Wraps state-machine commands that should become the machine port contract. |
| `api/evmFamily/nonceLifecycleAdapter.ts` | Adapter layer around nonce lifecycle functions that can live beside the EVM-family operation. |
| `orchestration/evm/index.ts`, `orchestration/tempo/index.ts`, `orchestration/near/index.ts` | Barrels that hide the concrete operation module. |
| `chainAdaptors/*/index.ts` | Barrels around chain-specific modules. |
| `signers/wasm/index.ts` | Barrel over chain-specific worker/WASM wrappers. |
| `workerManager/index.ts` | Broad worker boundary barrel. |

Delete duplicate lane/session identity shapes as their callers move to
`SelectedLane` and `operations/shared/operationState.ts`.

## Minimum Verification Set

Run this focused guard during every phase:

```sh
pnpm -C tests exec playwright test ./unit/signingEngine.refactor33.guard.unit.test.ts --reporter=line
```

Before moving a vertical slice, run the relevant unit set:

| Flow | Minimum tests |
| --- | --- |
| NEAR transactions | `nearSigning.sessionSelection.unit.test.ts`, `thresholdEd25519.nearSigningQueue.guard.unit.test.ts`, `nearClient.sendTransaction.retryInvalidNonce.unit.test.ts`, `nonceCoordinator.nearContext.test.ts` |
| NEAR delegate | `multichain.nearAdapter.unit.test.ts`, `walletFlowEvent.signing.unit.test.ts` |
| NEP-413 | `nearSigning.sessionSelection.unit.test.ts`, `touchConfirm.displayModel.unit.test.ts` |
| EVM signing | `evmSigning.thresholdReconnectEvents.unit.test.ts`, `thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts`, `thresholdEcdsa.authorizePolicyHint.unit.test.ts`, `evmFamilyOperationIds.unit.test.ts` |
| Tempo signing | `thresholdEcdsa.tempoHighLevel.unit.test.ts`, `tempo.broadcastNonceLifecycle.unit.test.ts`, `multichain.tempoTxHash.unit.test.ts`, `walletIframeHost.signTempoCancel.unit.test.ts` |
| Key export | `keyExport.behavior.guard.unit.test.ts`, `privateKeyExportRecovery.binding.unit.test.ts`, `privateKeyExportRecovery.hardening.unit.test.ts`, `passkeyConfirm.exportFlow.unit.test.ts` |
| Registration | `thresholdEcdsa.registrationBootstrapParity.unit.test.ts`, `configs.registrationTransport.test.ts`, `relayApiKeyRegistration.unit.test.ts` |
| Recovery | `recoveryExecutionTracking.unit.test.ts`, `recoverySessionStore.unit.test.ts`, `deviceRecoveryDomain.emailRecovery.unit.test.ts`, `emailOtpRecoveryKey.shared.unit.test.ts` |
| Passkey confirmation | `awaitSecureConfirmationV2.test.ts`, `handleSecureConfirmRequest.test.ts`, `touchConfirm.orchestrationBridge.unit.test.ts`, `touchConfirm.signingAuthPlanValidation.unit.test.ts` |
| Email OTP confirmation | `emailOtpAuthLane.unit.test.ts`, `emailOtpThresholdSessionCoordinator.unit.test.ts`, `seamsPasskey.emailOtp.unit.test.ts`, `emailOtpSigningSession.deviceEscrow.behavior.guard.unit.test.ts` |

Whole-SDK type check:

```sh
pnpm -C sdk run type-check
```

The current repo has unrelated type-check failures in existing tests and
fixtures, so the focused guard is the reliable check for the Phase 0 and Phase 1
scaffolding changes.
