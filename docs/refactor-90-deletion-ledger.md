# Refactor 90 Deletion Ledger

Created: July 22, 2026. Reconstituted from the pre-slim plan at commit
`f5eb4ace9` after the July 22 slimming removed the symbol-level lists while the
symbols were still live in source.

Rules:

- Delete an entry in the same change that replaces its behavior
  (no third implementation, no compatibility alias).
- When an entry is deleted, strike it here and record the commit in the
  [journal](./refactor-90-journal.md).
- Phases add newly discovered targets here instead of growing prose in the
  [plan](./refactor-90-modular-auth-capabilities-plan.md).

## Foundation B / Phase 18 — legacy ECDSA record family

Replacement: the required-field `active | retired` ECDSA capability record,
exact parser, and two-state activation journal.

- `ThresholdEcdsaSessionRecordCore`
- `NormalizedThresholdEcdsaSessionRecordShared`
- `NormalizedThresholdEcdsaSessionRecord`
- `ThresholdEcdsaSessionRecord`
- `ReadyPasskeyEcdsaSessionRecord`
- `EmailOtpEcdsaSessionRecord`
- `OperationUsableThresholdEcdsaSessionRecord`
- `buildOperationUsableThresholdEcdsaSessionRecord`
- `PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY`, Passkey material ranking, and
  newest-record selection
- `recordsByLane` and module-level record maps as persistence or selection
  authority (a runtime registry may keep manifest-keyed hot observations)
- ECDSA `restorable` as a core lifecycle label (use the hydration outcomes)
- authority/lifecycle inference from `source`, provider identity, optional
  field presence, record timestamps, or diagnostics
- registration-only and unlock-only capability publication paths (both call the
  canonical activation commit port)
- obsolete IndexedDB ECDSA session records (reject and clear at the boundary;
  no dual-schema reader)

## Foundation A — tactical unions replaced by the shared hydration plan

- `ExactEcdsaExportSession` (the `current session | public reauth authority`
  union)
- `EcdsaPublicReauthLane`
- `EvmFamilySharedEcdsaState`
- Near material-inspection unions superseded by the shared outcomes

## Phase 1 boundary residue — registration modes

- `ed25519_only`, `ecdsa_only`, `ed25519_and_ecdsa` in core registration,
  quota, session, and signing state (quota data shapes die in Phase 18/20)
- `combined_registration` D1 ceremony state outside any named temporary
  boundary parser

## Phase 3 delete-candidate carryover

- AuthService-era wallet registration authority branches → D1 registration
  route services (Phase 9 / Refactor 82B)
- Passkey-only Ed25519 authority checks inside shared session paths →
  `WalletAuthAuthorityRef` boundary parsers (Phase 17)
- AuthService generic registration bootstrap/finalize surfaces used by
  Cloudflare D1 routes (Phase 9)
- parallel wallet-ID allocation copy in the D1 registration intent service
  beside `walletRegistrationPlanning.ts` (Phase 9)

## Phase 4 — subject and session-read residue

- `WalletSessionReadSubject` / `wallet_near_subject` sibling aliases
- `WalletSessionReadResolution` (replaced by
  `WalletCapabilitySubjectResolution`)
- the `login.publicKey ? 'passkey' : null` auth-method inference fallback
- silent signer-slot defaults in restore/session-read paths (boundary parse
  failures instead)
- fallback paths inferring a wallet from `nearAccountId` outside explicit
  boundary parsers

## Phase 5 — role-local material identity

- `evmFamilySigningKeySlotId` in runtime paths (audit first: delete, or rename
  to `EvmFamilyEcdsaProvisioningReservationId` confined to
  registration/bootstrap). Forbidden in `ExactSigningLaneIdentity`,
  `WalletUnlockSubject`, Wallet Session claims, Router A/B normal-signing
  scope, `EcdsaRoleLocalPublicFacts`, sealed recovery records, and material
  handles/digests.
- `clientVerifyingShareB64u` on ECDSA role-local surfaces (rename to
  `clientVerifyingPublicKey33B64u`; Ed25519 out of scope)
- `chainTarget`, `thresholdSessionId`, `activeStateId`/`routerAbStateSessionId`,
  `signingGrantId`, `CapabilityGrantId`, `MpcWalletSigningQuotaId`, and
  remaining-use/expiry fields inside `EcdsaRoleLocalMaterialBinding`, its
  binding digest, and material handle
- the legacy regression test expecting Tempo and ARC to produce different
  role-local worker material handles for the same material (replace with a
  cross-chain lane-mismatch rejection test)

## Phase 17 — interim authority adapters

- `signingGrantAdmissionAuthorityKeyFromAuth`
- the branch-specific queue-key helper covered by Refactor 82B Phase 10D tests

## Phase 18 — durable restore fields and shared-type residue

- `walletSessionJwt`, `providerSubjectId`, `emailHashHex`,
  `registrationAuthorityId`, and `signingGrantId` in durable Ed25519 restore
  records
- ambiguous `remainingUses` / `expiresAtMs` rows (classify each: branded
  recovery policy, quota, grant, session transport — never migrate ambiguously)
- every `signingGrantId` occurrence (classify: delete, map to operation grant,
  or map to `MpcWalletSigningQuotaId`; never a mechanical rename, never
  material identity)
- `WalletSessionId = SigningGrantId`; replace it atomically with a distinct
  branded `WalletSessionId` and boundary parser
- interim shared exports of `SignerAuthMethod` / `WalletAuthMethod` only if a
  capability-local move ships both halves in one cut (Refactor 91's stable leaf
  module stays until then)

## Phases 18-20 — session-shaped material identity

Replacement: branded `MpcMaterialActivationId`, exact
`MpcMaterialActivationRef`, and an operation scope that carries an independent
`authorizationSessionId`.

- `ActiveMpcMaterialSessionRef`
- `ActiveEcdsaMaterialSession`
- `rehydrate_active_session`
- `active_state_session_id`
- ambiguous normal-signing `session_id` fields that represent authorization;
  the replacement wire field is `authorization_session_id`
- `authorizationSessionId: SeamsSessionId` on MPC operation scopes; reusable
  wallet authorization uses `WalletSessionId`, while operation grants retain
  their independent `SeamsSessionId` binding
- every `thresholdSessionId` or Wallet Session ID used as a material activation
  locator, persistence key, worker-state key, or hydration identity
- compatibility aliases between authorization session IDs and material
  activation IDs

## Phases 18-23 — Refactor 92 lifecycle migration residue

Replacement: the frozen Refactor 92 classifier, canonical invalidator,
structured server result, secure-origin state/event transport, and
single-operation same-method step-up, composed with the new branded identities.

- any recreated expiry inference from JWT presence, optional session IDs,
  optional timestamps, diagnostics, or message text
- any capability-specific expiry/exhaustion classifier added beside the
  Refactor 92 classifier for NEAR, Tempo, EVM, delegate signing, or key export
- any step-up path that creates a reusable Wallet Session
- any expiry path that enters Yao recovery, device linking, or material
  reactivation
- any React/Lit host path that declares the wallet unlocked before exact iframe
  initialization or independently parses Wallet Session lifecycle
- fixtures that equate Wallet Session, signing grant, quota, threshold session,
  or material activation IDs solely to preserve pre-cutover behavior

## Phase 19 — Email OTP patch tactical surface

Replacement: capability-local Near/ECDSA material adapters, generic session
ports, and the two-state recovery journal.

- `EmailOtpUnlockMaterialPlan` and every combined two-curve request/result/
  commit object
- `EmailOtpEd25519YaoSessionMaterialRequestV1`
- `EmailOtpEd25519YaoExactLocalSessionBootstrapV1`
- `WalletUnlockEmailOtpSessionIntentV1`
- `RouterAbEd25519YaoEmailOtpSessionRequestV1`
- `RouterAbEd25519YaoEmailOtpLocalSessionRequestV1`
- `RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1`
- `activateColdEmailOtpEd25519YaoLocalSessionV1`
- `recoverEd25519YaoEmailOtpWalletSession` (split into session-provisioning and
  recovery ports)
- `email_otp_exact_local_material`, `email_otp_no_ed25519_session`
- `router_ab_ed25519_yao_email_otp_local_session_v1`
- `router_ab_ed25519_yao_email_otp_recovery_session_v1`
- `shared_email_otp_recovery_wallet_session_v1`
- `ecdsa_and_ed25519_yao_local_session`
- the implicit omitted-`sessionIntent` branch (explicit requested-capability
  set instead)

## Phase 19 — committed lanes, step-up, and resolvers

- `PasskeyEcdsaCommittedLane`, `EmailOtpEcdsaCommittedLane`, their ready
  aliases and method-specific builders
- `EmailOtpEcdsaCommittedLaneStateError`
- `EvmFamilyEcdsaAuthMethod`
- Passkey source-priority and material-selection types
- the Email OTP ECDSA authority resolver
- method-specific reauth and restore assembly ports
- old signing step-up types/files and the passkey-only restore branch
- `reauth_required/missing_hot_material` as an implicit restore signal

## Phase 19 — Yao capability sources and reconnect hooks

- `NearPasskeyEd25519ReconnectHook`, `NearEmailOtpEd25519ReconnectHook`
- `NearEd25519PasskeyReconnect`, `NearEd25519EmailOtpReconnect`
- `recoverPasskeyEd25519YaoCapabilityForSigning`
- `NearEd25519YaoCapabilitySource`, `nearEd25519YaoCapabilitySource`
- `NearEd25519YaoSigningCapability` (replace with the branded committed shape;
  no broad source aggregate)
- `emailOtpNearEd25519LaneRequiresFreshAuth`
- `RouterAbEd25519YaoClientRootFactorV1`
- `RouterAbEd25519YaoBudgetRefreshAuthorizationV1`
- factor-labelled Yao root/export transport unions

## Phase 19 — sealed-refresh tactical surface

- `EmailOtpEd25519YaoSilentRecoveryResultV1`
- `EmailOtpEd25519YaoSilentRecoveryPorts`
- `EmailOtpEd25519YaoBudgetRecoveryResult`
- `PreparedEmailOtpEd25519YaoRecoveryV1`, `PreparedColdEmailOtpEd25519YaoRecoveryV1`
- `recoverEmailOtpEd25519YaoFromSealedSessionV1`
- `recoverEmailOtpEd25519CapabilityForSigningV1`
- `recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning`
- `requestRehydrateEmailOtpEd25519YaoFactor` and the
  `rehydrateEmailOtpEd25519YaoFactor` worker operation
- Email-OTP-specific Yao root purpose/scope/handle shapes
- method-specific Browser recovery singleflight maps

## Phase 19 — export coordinator surface

- `PasskeyEd25519YaoLocalMaterialLocatorV1` (checkpoint shape embeds
  `signingGrantId` and refresh scope; replaced by the canonical sealed
  active-Client record)
- `Ed25519YaoExportFlowDeps.recoverPasskeyCapability` and the nested
  `emailOtp.resolveExportContext` callback bag
- `exportEd25519YaoKeyWithFreshPasskey`, `exportEd25519YaoKeyWithFreshEmailOtp`
- `ExactPasskeyEd25519SigningLaneIdentity`,
  `ExactEmailOtpEd25519SigningLaneIdentity`
- `EmailOtpEd25519YaoExportSubjectV1`, `EmailOtpEd25519YaoExportContextV1`,
  `EmailOtpEd25519YaoExportContextPorts`
- `recoverExactPasskeyEd25519YaoCapabilityForExport`
- `resolveEmailOtpEd25519YaoExportContext` and matching Browser/assembly port
  aliases
- the `laneIdentity.auth.kind` dispatch in `exportKeypairOperation.ts`
- `EmailOtpEd25519YaoActiveCapabilityDescriptorV1` (destructive replace at the
  generic lifecycle/export-context boundary; strip `signingGrantId`, raw
  provider subject, and bearer JWT from the worker payload)
- `signingGrantId` in export subject/context/worker requests (the exact
  `near.export_key` grant lives only in operation authorization/claim state)

## Phase 19 — factor-labelled assembly ports and Browser shortcuts

- `refreshPasskeyEd25519CapabilityForSigning`
- `requestEmailOtpEd25519SigningChallenge`
- `recoverEmailOtpEd25519CapabilityForSigning`
- `resolveAccountAuthMethodForSigning`
- `ensureNearEd25519YaoCapabilityForSigning`
- `resolveActiveNearEd25519YaoSigningLane`
- `hasPasskeyAuthenticatorForNearEd25519Subject`
- `recoverNearEd25519YaoCapabilityForSigning`
- `recoverExactPasskeyEd25519YaoCapabilityForSigning`
- `recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning`
- `recoverExactEd25519YaoCapability`
- `hasNearEd25519YaoPublicReference`
- `recoverNearEd25519YaoCapabilityFromSealedSession`
- `recoverNearEd25519YaoCapabilityWithPasskey`
- `readNearEd25519RuntimeRecordForSelectedLane`
- `publishNearEd25519RuntimeIdentityForRecord`
- `resolveNearTransactionPlannerReadiness`
- control-flow use of `getWarmThresholdEd25519SessionStatusForSession`
- `resolveThresholdEd25519SessionIdForNearAccount`
- the broad `resolveActiveEd25519YaoSigningCapability` port
- `withThresholdEd25519CommitQueue`, `ThresholdEd25519CommitQueueByKey`,
  `resolveThresholdEd25519CommitQueueKey`
- the `forceFreshAuth` and `retryingFreshAuth` planner booleans
- all `CreateSigningEnginePortsArgs` aliases/wiring for the ports above
- stale cross-curve companion envelopes, including
  `ecdsa_and_ed25519_yao_recovery` (capability-specific material requests
  instead)

## Phase 19 — tests and fixtures (migrate valid assertions, then delete)

- `nearRefreshYaoOrdering.guard.unit.test.ts` (source-text ordering guard;
  replace with port-spy behavior tests)
- `ed25519YaoSealedRefreshWiring.guard.unit.test.ts`
- `emailOtpEd25519YaoBudgetRecovery.unit.test.ts` (migrate continuity,
  monotonic-policy, and cleanup assertions; delete grant/budget fixtures and
  the tactical sealed-recovery typecheck fixture)
- `emailOtpEd25519YaoExportRefresh.unit.test.ts` (migrate page-refresh,
  zero-Passkey-callback, durable-context, continuity, and zeroization
  assertions)
- `passkeyEd25519YaoExportRefresh.unit.test.ts` (migrate stale-grant/
  current-grant, current-credential, no-intervening-transaction, and
  authenticator-drift assertions)
- `ed25519YaoExportFlow.typecheck.ts` (replace with authority/adapter
  substitution fixtures that name no factor lane)
- obsolete positive capability-source fixtures in `nearSigning.typecheck.ts`

## Phase 20 — signing budget subsystem

Replacement: exact operation grants plus `MpcWalletSigningQuota` claims.

- `BudgetCoordinator`, `budgetProjection`, `budgetFinalizer`,
  `budgetStatusReader`
- `signingEngine/session/budget/**`
- `DelegatedBudgetReservationStore`
- router reserve/commit/release budget methods
- old development `signingGrantId` budget rows (reject and clear at the
  persistence boundary; never fan one remaining-use count into multiple
  balances)
- the transitional blanket readmission path after recovery
- the legacy projection path copying `signingGrantId` or other operation
  authorization across EVM/Tempo targets
- keep only client-side concurrent-operation fingerprinting from the old
  subsystem

## Phase 21 — worker and WASM residue

- generic-named passkey-only WASM sessions (destructive rename to
  `WasmPasskeyClientRegistrationSessionV1` /
  `WasmPasskeyClientRecoverySessionV1`; no aliases)
- combined ECDSA enrollment and `ecdsa_and_ed25519_yao_recovery` unlock worker
  requests (capability-specific commands; shared OTP/WebAuthn interaction is
  verified evidence satisfying two exact requirements)
- replaced worker entrypoints, loaders, asset-manifest rows,
  `UiConfirmManager` factor branches, and adapter wrappers

## Phase 27 — final sweep

- `SigningAuthPlan` and signer-auth aliases
- remaining `signing-session` terminology and old route planes
  (`threshold_session`, `user_session` on migrated surfaces)
- wallet-only `AuthMethod` usages outside capability-local modules
- auto-signer registration paths
- public exports implying wallet-only auth/sessions/grants
- source guards and fixtures whose invariant became structural during the
  slices
