# Stricter Union Types Audit for `signingEngine`

Date created: 2026-05-27
Status:

## Scope

Reviewed `client/src/core/signingEngine/` for optional fields that model auth, session, signing, threshold material, budget, recovery, worker protocol, and lifecycle state. The scan covered all 399 files under the folder, then focused on the optional-heavy and security-sensitive modules.

This document separates acceptable optionals from places where stricter Rust-like TypeScript would reduce invalid states.

## Summary

The codebase already has good strict-state patterns in newer areas:

- `flows/signEvmFamily/ecdsaMaterialState.ts` models ECDSA material as `public_identity_unavailable`, `public_identity_available`, `reauth_required`, and `ready_to_sign`.
- `flows/signEvmFamily/ecdsaSelection.ts`, `thresholdAdmission.ts`, `provisionPlan.ts`, and multiple `*.typecheck.ts` files use discriminants and `never` guards.
- `session/budget/budget.ts` uses several branch-specific budget unions with `never` fields.
- `session/warmCapabilities/ecdsaProvisionPlan.ts` and `session/passkey/ecdsaSessionProvision.ts` already reject many invalid auth/provisioning combinations.

The remaining weak spots are mostly older boundary-shaped types that still leak into core logic. The highest-impact targets are available-lane/readiness types, persistence records, Email OTP enrollment/login argument bags, worker/HSS result types, and some budget/projection status objects.

## Keep Optional

These optionals are low risk and should generally stay optional:

- UI/display/config fields: `title`, `body`, `theme`, `variant`, explorer URLs, CSS token overrides, and Lit component properties.
- Callback hooks and instrumentation: `onEvent`, `onProgress`, `onTrace`, `shouldAbort`, `beforeProvision`, `assertNotCancelled`.
- Public SDK convenience options at the outermost boundary, provided they are normalized immediately into stricter internal inputs.
- Raw inbound parsing shapes that use `unknown` and optional fields only inside a boundary parser.
- `?: never` fields in discriminated unions. These are desirable invalid-branch guards.

When this document recommends tightening optional fields, it means optional data fields such as auth/session/material/readiness fields. It does not mean removing `?: never` branch-exclusion fields. Those should usually remain because they make mixed union branches fail at compile time.

## P1 Findings

### 1. Available Lanes Still Allow Half-Concrete States

Files:

- `client/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `client/src/core/signingEngine/session/availability/readiness.ts`
- `client/src/core/signingEngine/session/operationState/lanes.ts`

Examples:

- `AvailableEd25519SigningLane` allows `state: 'ready'` while `authMethod`, `walletSigningSessionId`, and `thresholdSessionId` are optional.
- `AvailableSigningLanesRuntimeEd25519Record` has optional `walletSigningSessionId`, `remainingUses`, and `expiresAtMs`.
- `AvailableSigningLanesRuntimeEcdsaRecord` has optional `resolvedKey`, `keyHandle`, and `verifiedPublicFacts`, even though later paths often need verified public facts to treat the lane as concrete.

Recommended tightening:

- Split lane types by lifecycle:
  - `MissingAvailableEd25519SigningLane`
  - `ConcreteAvailableEd25519SigningLane`
  - `ConcreteAvailableEcdsaSigningLane`
  - `RestorableAvailableEcdsaSigningLane` if public identity exists but signer material is intentionally absent
- Require session identity on every concrete lane.
- Make readiness a discriminated union where `ready` and `exhausted` carry required status fields, while `missing` and `unavailable` forbid them with `never`.
- Keep `public_identity_available` separate from `ready_to_sign`; public key facts should never imply signing readiness.

Useful static checks:

- `state: 'ready'` without `thresholdSessionId` should fail.
- `state: 'ready'` without `walletSigningSessionId` should fail.
- ECDSA shared-family lanes should require both requested target and source target when they differ.

### 2. Persistence Records Mix Raw Storage, Public Identity, and Hot Signer Material

Files:

- `client/src/core/signingEngine/session/persistence/records.ts`
- `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `client/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`

Examples:

- `ThresholdEcdsaSessionRecord` includes optional `clientAdditiveShare32B64u`, `clientAdditiveShareHandle`, `ecdsaHssRoleLocalClientState`, `thresholdSessionAuthToken`, `emailOtpAuthContext`, `verifiedPublicFacts`, and legacy-compatible `rpId`.
- The same record type represents passkey, Email OTP, durable, runtime, sealed, public-only, and hot-material-bearing states.

Recommended tightening:

- Keep a raw persistence type at the IndexedDB boundary.
- Normalize immediately into internal unions:
  - `PublicEcdsaSessionRecord`
  - `ReadyPasskeyEcdsaSessionRecord`
  - `ReadyEmailOtpEcdsaSessionRecord`
  - `ReauthRequiredEmailOtpEcdsaSessionRecord`
  - `LegacyOrInvalidEcdsaSessionRecord` only inside migration/cleanup code
- Make `authMethod`/`source` branch-specific:
  - passkey records require passkey auth binding and local WebAuthn-compatible material references.
  - Email OTP records require `emailOtpAuthContext` and the relevant worker/session reference.
- Move compatibility handling for `rpId` and older record shapes into one parser.

This would prevent a repeat of public identity plus key reference being treated as signer readiness.

### 3. Email OTP ECDSA Enrollment/Login Args Are Still Broad Optional Bags

Files:

- `client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts`
- `client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession.ts`

Examples:

- Enrollment/login inputs include optional `routeAuth`, `keyHandle`, `participantIds`, `sessionKind`, `routePlan`, `runtimePolicyScope`, `registrationAttemptId`, `authLane`, `record`, and `challengeId`.
- Some of these are public-boundary convenience fields, but the same broad shape is used near core provisioning logic.

Recommended tightening:

- Split Email OTP ECDSA internal inputs into explicit modes:
  - `EmailOtpEcdsaRegistrationBootstrapInput`
  - `EmailOtpEcdsaLoginReconnectInput`
  - `EmailOtpEcdsaTransactionStepUpInput`
  - `EmailOtpEcdsaExportStepUpInput`
- Require the mode-specific identity/auth fields:
  - registration requires `registrationAttemptId` and role-local key identity.
  - transaction step-up requires an auth lane or a selected reauth authority.
  - export requires export authorization context.
  - existing-session reconnect requires exact record/key identity.
- Keep optional defaults only in the public API wrapper, then build one of the strict internal inputs.

Useful static checks:

- A transaction step-up input without `authLane` or explicit reauth authority should fail.
- A registration bootstrap input without role-local identity should fail.
- A login reconnect input should not accept `registrationAttemptId`.

### 4. HSS Lifecycle Results Use `success: boolean` Plus Optional Payloads

Files:

- `client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts`

Examples:

- `DeriveThresholdEd25519ClientVerifyingShareResult`
- `PrepareThresholdEd25519HssClientCeremonyResult`
- `CompleteThresholdEd25519HssClientCeremonyResult`
- `OpenThresholdEd25519HssSeedOutputResult`
- `BuildThresholdEd25519SeedExportArtifactResult`

These result types use `success: boolean` with optional `error`, `preparedSession`, `finalizedReport`, `clientOutput`, `seedOutput`, or `artifact`.

Recommended tightening:

- Convert each to a `Result`-style union:
  - `{ ok: true; ...requiredSuccessPayload }`
  - `{ ok: false; code: ...; message: string; ...failureContext }`
- Use exhaustive switches in callers.
- Add type fixtures rejecting `ok: true` without its required payload and `ok: false` with success-only payload.

This is a high-value cleanup because HSS code carries cryptographic material and ceremony state.

### 5. Worker Protocol Types Allow Optional Request Fields Inside Core Maps

Files:

- `client/src/core/signingEngine/workerManager/workerTypes.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp/fetch.ts`
- `client/src/core/types/signer-worker.ts`

Examples:

- Email OTP worker requests have optional `keyHandle`, `roleLocalKeyIdentity`, `participantIds`, `sessionId`, `walletSigningSessionId`, `routeAuth`, `runtimePolicyScope`, and `thresholdSessionAuthToken`.
- `thresholdEcdsaPresignSessionStep` accepts optional `incomingMessages`, which is likely acceptable only if an empty array is semantically distinct from omitted.

Recommended tightening:

- Treat worker messages as a protocol boundary.
- Parse raw worker payloads into strict request unions per operation:
  - `EmailOtpEnrollRequest`
  - `EmailOtpLoginRequest`
  - `EmailOtpEcdsaBootstrapRequest`
  - `EmailOtpEd25519ReconstructRequest`
  - `EmailOtpExportRequest`
- Use operation-specific required fields after parsing.
- For presign steps, decide whether `incomingMessages` may be empty. If empty is valid, require `incomingMessages: ArrayBuffer[]` and pass `[]`.

Useful static checks:

- Worker bootstrap request without route auth should fail unless the request kind explicitly represents a no-auth boundary operation.
- HSS reconstruction request without `thresholdSessionAuthToken` should fail unless the branch is a public read.

## P2 Findings

### 6. Budget Projection and Trace Events Have Optional Status Bags

Files:

- `client/src/core/signingEngine/session/budget/budget.ts`
- `client/src/core/signingEngine/session/budget/budgetProjection.ts`
- `client/src/core/signingEngine/session/budget/budgetFinalizer.ts`
- `client/src/core/signingEngine/session/budget/budgetStatusReader.ts`

The budget module is already stronger than many areas, but some status/projection/trace objects still use optional bags:

- trace event `status?`, `error?`, `zeroSpendReason?`
- projection `remainingUses?`, `expiresAtMs?`, `effectiveRemainingUses?`
- budget finalizer `spend?` and `signingSessionBudget?`

Recommended tightening:

- Split trace events by `event` so success events carry status and failure events carry error.
- Split projection into `known`, `unknown`, `expired`, and `missing`.
- Split finalizer input into `with_budget` and `no_budget` branches, with `spend` required only for spend-bearing branches.

### 7. Near Signing Still Mixes Public API Options With Prepared Core State

Files:

- `client/src/core/signingEngine/flows/signNear/signNear.ts`
- `client/src/core/signingEngine/flows/signNear/signTransactions.ts`
- `client/src/core/signingEngine/flows/signNear/signDelegate.ts`
- `client/src/core/signingEngine/flows/signNear/signNep413.ts`

Examples:

- Public signing args include optional UI text and callbacks, which is fine.
- Core-ish state also uses optional `sessionId`, `emailOtpSigning`, `signingSessionCoordinator`, `ed25519Warmup`, `availableLanes`, and `currentRuntimeLane`.

Recommended tightening:

- Keep public API options separate.
- Normalize into:
  - `NearSigningWithPreparedSession`
  - `NearSigningNeedsStepUp`
  - `NearSigningNeedsWarmup`
  - `NearSigningCannotProceed`
- Require the exact dependency set for each branch.

### 8. Export Flow Has Fresh Material Branches With Optional Identity

Files:

- `client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts`
- `client/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts`
- `client/src/core/signingEngine/session/emailOtp/exportRecovery.ts`
- `client/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts`

Examples:

- `FreshEmailOtpEcdsaExportMaterial` has optional `authSubjectId` and `runtimePolicyScope`.
- Export helpers accept optional `authLane`, `routeAuth`, `chainTarget`, and `runtimePolicyScope`.

Recommended tightening:

- Split export material into:
  - `ReadyThresholdEcdsaExportMaterial`
  - `FreshEmailOtpEcdsaExportMaterialWithRouteAuth`
  - `FreshEmailOtpEcdsaExportMaterialNeedsChallenge`
- Require `runtimePolicyScope` at the point a route needs role-local/server authorization.
- Keep missing auth as an explicit branch that drives step-up, not as optional fields on an otherwise usable export material.

### 9. Capability Reader Ports Use Optional Dependencies

Files:

- `client/src/core/signingEngine/session/warmCapabilities/capabilityReader.ts`
- `client/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `client/src/core/signingEngine/session/availability/readiness.ts`
- `client/src/core/signingEngine/interfaces/operationDeps.ts`

Optional ports are reasonable at composition boundaries, but core readers should receive a narrower configured dependency object.

Recommended tightening:

- Build `WarmCapabilityReaderPortsConfigured` and `WarmCapabilityReaderPortsNoRuntimeStatus`.
- Normalize optional public/composition deps once.
- Avoid repeated `typeof dep === 'function'` checks in core readiness logic.

## Suggested Implementation Order

1. **Available lane/readiness unions**
   Tighten `AvailableEd25519SigningLane`, runtime lane records, and readiness output. This directly protects signing admission and step-up decisions.

2. **Email OTP ECDSA internal input modes**
   Replace broad login/enrollment bags with mode-specific internal inputs. Keep public wrappers flexible, but core functions should require strict shapes.

3. **Worker and HSS result unions**
   Convert `success: boolean` result types and worker operation payloads into strict boundary-parsed unions.

4. **Persistence normalization**
   Introduce raw persisted record types plus normalized internal record unions. Keep migration/compatibility code at the IndexedDB boundary.

5. **Budget projections and trace events**
   Split status/projection/trace events so observability cannot accidentally become control-flow state.

6. **Near and export flow cleanup**
   Separate public option bags from prepared core execution state.

## Todo

- [x] Tighten available lane/readiness unions so concrete `ready` lanes require session identity, auth method, and required status fields.
- [x] Add type fixtures rejecting ready Ed25519 lanes without `authMethod`, `walletSigningSessionId`, or `thresholdSessionId`.
- [x] Add type fixtures rejecting ready ECDSA lanes without verified public facts and exact lane identity.
- [x] Split Email OTP ECDSA internal inputs into mode-specific registration, login reconnect, transaction step-up, and export step-up inputs.
- [x] Add type fixtures rejecting Email OTP registration bootstrap without role-local identity and registration attempt.
- [x] Add type fixtures rejecting Email OTP transaction step-up without auth lane or explicit reauth authority.
- [x] Convert HSS lifecycle `success: boolean` results into `Result`-style discriminated unions.
- [x] Add type fixtures rejecting HSS success results without success payloads and HSS failure results with success-only payloads.
- [x] Parse raw worker messages into operation-specific strict request unions at the worker boundary.
- [x] Decide whether ECDSA presign step `incomingMessages` may be omitted; if empty is valid, require `incomingMessages: ArrayBuffer[]`.
- [x] Introduce raw persisted record types plus normalized internal ECDSA record unions.
- [x] Keep persistence compatibility handling isolated to IndexedDB/request boundary parsers.
- [x] Split budget trace events by event kind so success events require status and failure events require error.
- [x] Split budget projections into explicit `known`, `unknown`, `expired`, and `missing` states.
- [x] Split Near signing public option bags from prepared core execution states.
- [x] Split ECDSA export fresh-material states into route-auth-ready and needs-challenge branches.
- [x] Normalize optional capability reader ports once into configured dependency unions.
- [x] Add static checks that public ECDSA identity cannot satisfy `ReadyEcdsaMaterial`.
- [x] Add static checks that diagnostics objects are never accepted by selection/admission builders.
- [x] Review remaining `?:` usage after each phase and leave `?: never` branch-exclusion guards intact.

## Static Type Fixture Checklist

Add or extend `*.typecheck.ts` files for these guarantees:

- Ready Ed25519 lane requires `authMethod`, `walletSigningSessionId`, and `thresholdSessionId`.
- Ready ECDSA lane requires verified public facts and exact lane identity.
- Public ECDSA identity does not satisfy `ReadyEcdsaMaterial`.
- Email OTP registration bootstrap requires role-local identity and registration attempt.
- Email OTP transaction step-up requires an auth lane or explicit reauth authority.
- HSS `ok: true` results require their success payloads.
- HSS `ok: false` results reject success-only payloads.
- Worker ECDSA bootstrap request rejects missing route/session auth.
- Budget success trace requires status; budget failure trace requires error.
- Diagnostics objects remain observational and are never accepted by selection/admission builders.

## Notes

This should be done incrementally. The code already has strong patterns to copy, especially `EcdsaMaterialState`, `EcdsaExportMaterial`, `ecdsaProvisionPlan`, and the operation-state typecheck files. The biggest win is to keep raw optional shapes at persistence/request/worker boundaries, then convert them once into strict internal unions.
