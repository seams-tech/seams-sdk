# Refactor 51 Cross-Platform Implementation Inventory

Date accepted: 2026-06-01
Source plan: `docs/refactor-51-cross-platform-2.md`
Behavior contract: `docs/intended-behaviours.md`

This file is the Phase -1 inventory and regression baseline for Refactor 51.
It replaces the original Refactor 50 boundary sketch with implementation rows
that later phases can cite when changing code, tests, schemas, routes, worker
messages, records, and guards.

## Inventory Format

Each row records:

- area and workflow
- current module path or artifact
- symbol, record, route, worker message, or test name
- current owner and target owner
- Refactor 51 owner phase
- action: `move`, `wrap`, `replace`, `delete`, or `leave`
- public behavior covered
- intended-behavior rows affected from `docs/intended-behaviours.md`
- identity, auth, session, signing, export, restore, or protocol fields carried
- raw boundary involved
- current tests and validation commands
- missing regression tests or release notes
- guard or conformance suite
- compatibility register row and deletion trigger, when applicable

## Public Workflow Baseline

| Workflow | Primary modules and symbols | Action | Owner phase | Public behavior and intended-behavior rows | Fields carried | Current tests and evidence | Missing regression task |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Passkey registration | `client/src/core/SeamsPasskey/registration.ts`; `client/src/core/SeamsPasskey/passkeyRegistrationAuthority.ts`; `client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts`; `RegisterWalletUseCase` | wrap | Phase 5 | Passkey registration creates wallet/auth rows, NEAR Ed25519, and configured ECDSA lanes; passkey registration never sends Email OTP. Rows: Registration / Passkey Account, Test Matrix, Validation Mapping registration rows. | `walletId`, `rpId`, credential id, wallet signing session id, threshold session ids, configured `chainTarget` values | `tests/unit/addWalletSigner.orchestration.unit.test.ts`; `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts`; `tests/unit/provisionEcdsaUseCase.unit.test.ts`; `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts` | Release browser smoke note for immediate post-registration signing remains required when UI code changes. |
| Email OTP registration | `client/src/core/SeamsPasskey/registration.ts`; `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`; `RegisterWalletUseCase`; relayer Email OTP challenge routes | wrap | Phase 5 | Sends one registration OTP per active attempt, allows reroll only with matching proof fields, creates Email OTP Ed25519 and ECDSA lanes, and never creates passkey-owned runtime material. Rows: Registration / Email OTP Account, Page Refresh During Registration, Validation Mapping OTP rows. | `walletId`, provider subject, challenged email, challenge id, org, app-session version, auth method, wallet signing session id, ECDSA `chainTarget` | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts`; `tests/unit/emailOtpOperationSplit.guard.unit.test.ts`; `tests/unit/provisionEcdsaUseCase.unit.test.ts`; relayer route coverage | Release browser smoke note for reroll UX remains required when UI code changes. |
| Passkey unlock | `client/src/core/SeamsPasskey/login.ts`; `client/src/core/signingEngine/session/passkey/*`; `UnlockWalletUseCase` | wrap | Phase 5 | Uses registered credential directly when known, warms NEAR Ed25519 and configured ECDSA lanes, and never sends Email OTP. Rows: Wallet Unlock / Passkey Account, Page Refresh After Unlock. | `walletId`, `rpId`, credential id, auth method, threshold session ids, wallet signing session id, budget policy | `tests/unit/seamsPasskey.loginThresholdWarm.unit.test.ts`; `tests/unit/browserPlatformRuntime.signerCrypto.unit.test.ts`; `tests/unit/platformAdapter.conformance.unit.test.ts` | Release browser smoke note for platform WebAuthn chooser behavior remains required when browser WebAuthn code changes. |
| Email OTP unlock | `client/src/core/SeamsPasskey/login.ts`; `client/src/core/SeamsPasskey/near/emailRecovery.ts`; `client/src/core/signingEngine/session/emailOtp/*`; `UnlockWalletUseCase` | wrap | Phase 5 | Sends one wallet-unlock OTP, warms exact Email OTP lanes, never calls WebAuthn or passkey PRF restore. Rows: Wallet Unlock / Email OTP Account, Validation Mapping Email OTP path rows. | `walletId`, provider subject, challenge id, auth method, threshold session ids, wallet signing session id, budget policy | `tests/unit/seamsPasskey.loginThresholdWarm.unit.test.ts`; `tests/unit/emailOtpThresholdSessionCoordinator.unit.test.ts`; `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` | Release browser smoke note for OTP delivery UX remains required when UI code changes. |
| Reconnect restore | `client/src/core/signingEngine/session/availability/*`; `client/src/core/signingEngine/session/persistence/records.ts`; `RestorePersistedSessionsUseCase` | replace | Phase 8 | Rehydrates only exact valid persisted/sealed sessions and requires unlock or step-up for missing, expired, exhausted, or mismatched state. Rows: Page Refresh After Unlock, Page Refresh Before Signing. | `walletId`, auth method, curve, `chainTarget`, session ids, budget identity, restore source | `tests/unit/ecdsaSelection.restorable.unit.test.ts`; `tests/unit/activateSigningSessionUseCase.unit.test.ts`; `tests/unit/platformAdapter.conformance.unit.test.ts` | None for Refactor 51. |
| Warm-session restore | `client/src/core/signingEngine/session/warmCapabilities/*`; `client/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts`; `RestorePersistedSessionsUseCase` | replace | Phase 8 | Restores exact valid lanes without creating authority or switching auth method. Rows: Page Refresh After Unlock, Page Refresh Before Signing, Test Matrix page-refresh column. | auth method, curve, chain target, threshold session id, wallet signing session id, remaining uses, expiry | `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts`; `tests/unit/ecdsaSelection.restorable.unit.test.ts`; `tests/unit/activateSigningSessionUseCase.unit.test.ts` | None for Refactor 51. |
| NEAR signing | `client/src/core/signingEngine/flows/signNear/*`; NEAR signer worker; `SignNearUseCase` | wrap | Phase 5 | Uses exact warm Ed25519 lane, consumes one use per transaction, plans same-method step-up when budget is expired or exhausted. Rows: Transaction Signing / Passkey Account, Transaction Signing / Email OTP Account. | `walletId`, auth method, NEAR account id, threshold session id, wallet signing session id, transaction count, budget | `tests/unit/seamsPasskey.loginThresholdWarm.unit.test.ts`; `tests/unit/useCaseLifecycle.unit.test.ts`; intended-behavior validation mapping | Release browser smoke note for NEAR transaction flow remains required when UI request shape changes. |
| NEP-413 signing | `client/src/core/signingEngine/flows/signNear/*`; signer worker `SignNep413Message` | wrap | Phase 5 | Preserves message digest binding and exact Ed25519 lane selection. Rows: Transaction Signing, Step-Up Auth. | `walletId`, auth method, NEP-413 message, recipient, nonce, session ids | `tests/unit/signingEngine.refactor36.guard.unit.test.ts`; signer worker unit coverage | Release smoke note remains required when public NEP-413 API changes. |
| Delegate signing | `client/src/core/signingEngine/flows/signNear/*`; signer worker `SignDelegateAction` | wrap | Phase 5 | Preserves delegate scope binding and budget finalization semantics. Rows: Transaction Signing, Step-Up Auth. | `walletId`, auth method, delegate action scope, session ids, budget identity | `tests/unit/signingEngine.refactor36.guard.unit.test.ts`; signer worker unit coverage | Release smoke note remains required when delegate request shape changes. |
| EVM signing | `client/src/core/signingEngine/flows/signEvmFamily/*`; `Secp256k1Engine`; `SignEvmFamilyUseCase` | replace | Phase 5 and Phase 6 | Selects exact EVM `chainTarget`, uses warm budget without prompt, consumes one use per request, and signs via ready-state blob or worker handle. Rows: Transaction Signing / ECDSA, Step-Up Auth, ECDSA chain-target invariant. | `walletId`, auth method, ECDSA key handle, `chainTarget`, threshold key id, participant ids, session ids, public key facts | `tests/unit/ecdsaMaterialState.unit.test.ts`; `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`; `tests/relayer/threshold-ecdsa.signature-harness.test.ts`; `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts` | None for Refactor 51. |
| Tempo signing | `client/src/core/signingEngine/flows/signEvmFamily/*`; Tempo chain target records; `SignEvmFamilyUseCase` | replace | Phase 5 and Phase 6 | Selects exact Tempo `chainTarget`, may source shared EVM-family material while preserving target-specific readiness and budget. Rows: Transaction Signing / ECDSA, ECDSA chain-target invariant. | Tempo `chainTarget`, shared ECDSA key facts, session ids, budget identity | `tests/helpers/thresholdEcdsaTempoFlow.ts`; `tests/unit/ecdsaSelection.restorable.unit.test.ts`; `tests/relayer/threshold-ecdsa.signature-harness.test.ts` | None for Refactor 51. |
| ECDSA export | `client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts`; `ecdsaHssExport.ts`; relayer export route | replace | Phase 7 | Requires fresh export-scoped auth, selects exact ECDSA export material, opens viewer only after material preparation. Rows: Key Export / Passkey Account, Key Export / Email OTP Account. | export authorization digest, `walletId`, auth method, `chainTarget`, ready record, public facts, export artifact | `tests/unit/ecdsaExportMaterial.unit.test.ts`; `tests/unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts`; `tests/relayer/threshold-ecdsa.signature-harness.test.ts`; `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts` | None for Refactor 51. |
| Ed25519 export | `client/src/core/signingEngine/flows/recovery/*`; hss-client worker seed export | wrap | Phase 7 | Requires fresh export-scoped auth and rejects wallet-unlock, registration, and transaction-step-up authority. Rows: Key Export, Validation Mapping export rows. | export auth method, threshold session id, wallet signing session id, export artifact | `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts`; `tests/unit/ecdsaExportMaterial.unit.test.ts`; export guard coverage | None for Refactor 51. |
| Recovery | `client/src/core/SeamsPasskey/near/emailRecovery.ts`; recovery/export viewer handoff modules | wrap | Phase 7 | Recovers only after operation-scoped authorization and preserves auth-method separation. Rows: Key Export, Page Refresh During Export. | recovery artifact, export authorization, auth method, wallet id | `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts`; `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` | Release browser smoke note remains required for recovery viewer UI changes. |
| Malformed-record cleanup | `client/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`; `records.ts`; durable store adapter | replace then delete compatibility | Phase 4 and Phase 9 | Malformed legacy/current ECDSA records return cleanup decisions and cannot reach ready-only signing or export functions. Rows: Page Refresh, Transaction Signing failure behavior, malformed cleanup baseline. | storage key, auth method, wallet id, `chainTarget`, malformed raw record metadata | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; `tests/unit/platformAdapter.conformance.unit.test.ts`; `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts` | None for Refactor 51. |

## Implementation Surface Inventory

| Surface | Current modules or artifacts | Action | Owner phase | Target owner | Behavior and fields | Tests, guards, or conformance |
| --- | --- | --- | --- | --- | --- | --- |
| Public SDK entrypoints | `SeamsPasskey`, `SigningEngine`, wallet iframe router, registration/login/email OTP/NEAR/EVM/Tempo/export/recovery entrypoints | wrap | Phase 5 | use-case services plus public adapters | Wallet id, auth method, chain target, export authority, session ids, budget | `tests/unit/useCaseLifecycle.unit.test.ts`; `tests/unit/signingEngine.refactor36.guard.unit.test.ts`; SDK typecheck |
| Use-case candidates | `client/src/core/signingEngine/useCases/*` | move | Phase 5 and Phase 8 | use-case service modules | `Deps`, `Input`, `Result`, retryable failure codes, lifecycle state | `tests/unit/provisionEcdsaUseCase.unit.test.ts`; `tests/unit/activateSigningSessionUseCase.unit.test.ts`; `tests/unit/useCaseLifecycle.unit.test.ts` |
| Platform ports | `client/src/core/platform/types.ts`; browser runtime adapter; command adapters | replace | Phase 3, Phase 5, Phase 8, Phase 10 | platform contract modules | `PlatformRuntime`, `SignerCryptoPort`, `AuthenticatorPort`, `DurableRecordStore`, `HttpTransport`, clock, random, secret store | `tests/unit/platformAdapter.conformance.unit.test.ts`; `tests/unit/browserPlatformRuntime.signerCrypto.unit.test.ts` |
| Storage records | `records.ts`; `ecdsaRoleLocalRecords.ts`; sealed-session stores | replace | Phase 3 and Phase 4 | persistence boundary parser and durable record store | `EcdsaRoleLocalReadyRecord`, malformed cleanup result, sealed session, public facts, backend binding | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`; raw record guard |
| Worker messages | `client/src/core/types/signer-worker.ts`; `workerTypes.ts`; hss-client, near-signer, email-otp workers | replace | Phase 2, Phase 6, Phase 7 | signer crypto adapter and worker implementation files | signer-core commands, threshold signing, export, timeout/failure frames | `tests/unit/thresholdEcdsa.hssWasmSurface.unit.test.ts`; `tests/unit/browserPlatformRuntime.signerCrypto.unit.test.ts`; worker construction guard |
| Relayer routes | threshold ECDSA bootstrap/signing/export, threshold Ed25519 session/signing, signing-session seal, Email OTP challenge, wallet registration | wrap | Phase 5, Phase 6, Phase 7 | typed relayer clients and route parsers | auth mode, route input/result, failure code, retryability, public facts | `tests/relayer/threshold-ecdsa.signature-harness.test.ts`; `tests/unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts`; route policy tests |
| Rust command structs | `crates/signer-core/src/threshold_ecdsa_hss/command.rs`; generated schemas | replace | Phase 2 and Phase 6 | `crates/signer-core` and generated TS schema file | prepare/finalize/open/export commands, command errors, opaque state blob | `cargo test --features threshold-ecdsa-hss`; schema export tests; native readiness vectors |
| WASM bindings | `wasm/hss_client_signer`; `wasm/near_signer`; `wasm/eth_signer` | replace | Phase 6 and Phase 7 | WASM command binding modules | signer-core command invocation, worker response mapping, opaque blobs | `cargo test` in `wasm/hss_client_signer`; `tests/unit/thresholdEcdsa.hssWasmSurface.unit.test.ts` |
| Opaque blob envelopes | signer-core ready-state blob; ECDSA pending blob; sealed session artifacts | replace | Phase 3, Phase 4, Phase 6 | Rust command output plus TS boundary parsers | `stateBlobB64u`, public facts, producer, curve, encoding, storage key | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; platform conformance; Phase 9 raw-field scans |
| Parser modules | `ecdsaRoleLocalRecords.ts`; relayer client parsers; command adapters | move and replace | Phase 4, Phase 6, Phase 7 | boundary parsers only | raw persistence/request/worker shapes normalized once | parser unit tests; raw DB record guard; unexpected bootstrap field rejection |
| Lifecycle unions | platform types, signing interfaces, use-case lifecycle modules | replace | Phase 3 and Phase 5 | domain lifecycle modules | provisioning, registration, unlock, activation, signing, export, restore state | type fixtures; `tests/unit/useCaseLifecycle.unit.test.ts`; SDK typecheck |
| Guard tests | `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts`; `tests/unit/signingEngine.refactor36.guard.unit.test.ts` | leave and extend | Phase 1 and owner phases | guard suites | obsolete symbols, raw fields, platform leakage, worker construction, schema drift | guard suite validation commands |

## Spec Closure Inventory

| Area | Required contract owner | Owner phase | Status | Evidence |
| --- | --- | --- | --- | --- |
| Lifecycle unions | domain lifecycle modules and type fixtures | Phase 3 and Phase 5 | Accepted and implemented | `tests/unit/useCaseLifecycle.unit.test.ts`; `client/src/core/platform/types.typecheck.ts` |
| Shared ECDSA domain types | ECDSA identity, signing, platform, persistence modules | Phase 3 | Accepted and implemented | `client/src/core/signingEngine/interfaces/signing.ts`; `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts` |
| Use-case contracts | use-case services under `client/src/core/signingEngine/useCases` | Phase 5 | Accepted and implemented for Refactor 51 scope | `tests/unit/provisionEcdsaUseCase.unit.test.ts`; `tests/unit/activateSigningSessionUseCase.unit.test.ts` |
| Export API | export material and recovery modules | Phase 7 | Accepted and implemented | `tests/unit/ecdsaExportMaterial.unit.test.ts`; `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts` |
| Session activation and sealing | activation service, durable store, sealed-session writer | Phase 8 | Accepted and implemented | `tests/unit/activateSigningSessionUseCase.unit.test.ts`; platform conformance |
| Relayer clients | typed relayer client modules | Phase 5, Phase 6, Phase 7 | Accepted and implemented for touched routes | relayer harness; HSS parser/export policy tests |
| Rust command structs | `crates/signer-core` command structs and generated TS schemas | Phase 2 and Phase 6 | Accepted and implemented | cargo tests; schema generation tests; native-readiness vectors |
| HTTP transport | `HttpTransport` port and browser adapter | Phase 5 and Phase 10 | Accepted and implemented | `tests/unit/platformAdapter.conformance.unit.test.ts` |
| Authenticator results | `AuthenticatorPort` and browser adapter | Phase 5 and Phase 10 | Accepted and implemented | `tests/unit/platformAdapter.conformance.unit.test.ts`; signer crypto adapter tests |
| Chain target normalization | ECDSA chain target interfaces and storage keys | Phase 3 and Phase 4 | Accepted and implemented | `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`; `tests/unit/ecdsaRoleLocalRecords.unit.test.ts` |
| Storage serialization | persistence parser and durable store | Phase 4 and Phase 9 | Accepted and implemented | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; platform conformance; raw-field guard |
| Schema wrappers | signer-core generated commands and adapters | Phase 2 | Accepted and implemented | SDK typecheck; schema drift guard; cargo schema tests |

## ECDSA Compatibility Data Inventory

| Compatibility data | Action | Owner phase | Target owner | Current status | Tests and guard | Deletion trigger |
| --- | --- | --- | --- | --- | --- | --- |
| `ecdsa_role_local_ready_record_v1` current unbranched ready rows | delete | Phase 9 | persistence parser | Deleted from active production paths; branch-specific ready records are required | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; platform conformance | Phase 9 data reset and parser deletion complete |
| Legacy raw role-local rows | delete | Phase 9 | persistence parser | Deleted from active production paths; raw rows now fail closed or cleanup at boundary | `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`; raw DB record guard | Phase 9 data reset and parser deletion complete |
| TypeScript-owned ECDSA blob payload kinds | delete | Phase 9 | signer-core ready-state blob | Deleted from production TypeScript decoding paths | raw HSS field guard; state-blob decode guard; production scans | Phase 6 data reset plus Phase 9 compatibility deletion complete |
| Raw HSS share fields in production TS | delete | Phase 9 | signer-core and worker boundary | Deleted from production TS domain and parser surfaces | `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts`; production raw-field scan | Phase 9 guard allowlist empty |
| Single-call HSS bootstrap worker helper | delete | Phase 9 | signer-core prepare/finalize/open commands | Deleted from active worker contracts | HSS WASM surface tests; worker construction guard | Phase 9 helper deletion complete |

Compatibility register status: no active compatibility branches remain for
ECDSA role-local state. New compatibility code must add a register row in
`docs/refactor-51-cross-platform-2.md` before implementation.

## Intended-Behavior Evidence Mapping

| Intended-behavior validation row | Refactor 51 touched workflows | Current evidence |
| --- | --- | --- |
| Email OTP registration with zero rerolls uses one OTP code | Email OTP registration | Relayer route/auth-service coverage; `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Email OTP registration with one reroll uses the original OTP code | Email OTP registration | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Email OTP registration with multiple rerolls uses the original OTP code | Email OTP registration | Relayer route coverage plus release browser smoke note |
| Wrong Email OTP provider subject is rejected | Email OTP registration, Email OTP unlock | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Wrong Email OTP challenged email is rejected | Email OTP registration, Email OTP unlock | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Registration and unlock produce equivalent runtime lanes | registration, unlock, restore | `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts`; `tests/unit/provisionEcdsaUseCase.unit.test.ts`; activation tests |
| Immediate passkey registration signs NEAR, Tempo, and Arc/EVM | passkey registration, signing | Client signing/unit coverage plus release browser smoke note |
| Immediate Email OTP registration signs NEAR, Tempo, and Arc/EVM | Email OTP registration, signing | Client signing/unit coverage plus release browser smoke note |
| Passkey step-up signs NEAR, Tempo, and Arc/EVM | step-up, signing | `tests/unit/ecdsaSelection.restorable.unit.test.ts`; lifecycle tests |
| Email OTP step-up signs NEAR, Tempo, and Arc/EVM | step-up, signing | `tests/unit/ecdsaSelection.restorable.unit.test.ts`; lifecycle tests |
| Passkey Ed25519 and ECDSA export require fresh export auth | export/recovery | `tests/unit/ecdsaExportMaterial.unit.test.ts`; `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts` |
| Email OTP Ed25519 and ECDSA export require fresh export auth | export/recovery | `tests/unit/ecdsaExportMaterial.unit.test.ts`; `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts` |
| Page refresh restores only exact valid lanes | reconnect restore, warm-session restore | `tests/unit/ecdsaSelection.restorable.unit.test.ts`; `tests/unit/activateSigningSessionUseCase.unit.test.ts` |
| Email OTP paths never call passkey credential lookup or PRF restore | Email OTP registration, unlock, export, signing | `tests/unit/emailOtpOperationSplit.guard.unit.test.ts`; `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts` |
| ECDSA budget checks are exact to chain target | EVM signing, Tempo signing, restore | `tests/unit/ecdsaSelection.restorable.unit.test.ts`; `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`; relayer signature harness |

## Baseline Validation Commands

Use these exact commands for Refactor 51 baseline and closeout validation:

```sh
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit --pretty false
pnpm -C tests exec playwright test ./unit/refactor5xCrossPlatform.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/platformAdapter.conformance.unit.test.ts ./unit/browserPlatformRuntime.signerCrypto.unit.test.ts ./unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts ./unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts ./unit/signingEngine.refactor36.guard.unit.test.ts ./unit/refactor5xCrossPlatform.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/evmFamilyEcdsaIdentity.unit.test.ts ./unit/ecdsaMaterialState.unit.test.ts ./unit/ecdsaRoleLocalRecords.unit.test.ts ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/ecdsaExportMaterial.unit.test.ts ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts ./unit/privateKeyExportRecovery.hardening.unit.test.ts ./unit/provisionEcdsaUseCase.unit.test.ts ./unit/activateSigningSessionUseCase.unit.test.ts ./unit/useCaseLifecycle.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.scripts.config.ts ./unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts ./unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line
cargo test --manifest-path crates/signer-core/Cargo.toml --features threshold-ecdsa-hss
cargo test --manifest-path wasm/hss_client_signer/Cargo.toml
git diff --check
```

The Phase -1 open-question scan from `docs/refactor-51-cross-platform-2.md`
should return no matches for this inventory.
