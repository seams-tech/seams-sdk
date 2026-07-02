# Refactor 82B: Auth Authority Typing Cleanup

Date created: July 2, 2026

Status: planning.

Parent plan: [Cloudflare D1 Migration Plan](./refactor-82-cloudflare-D1-migration.md)

Related plan: [Modular Auth And Capability Refactor Plan](./refactor-87-modular-auth-capabilities-plan.md)

## Relationship To Refactor 87

This plan is a prerequisite cleanup for Refactor 87. Refactor 87 splits auth
methods and capabilities into modular surfaces; Refactor 82B first makes the
current D1 registration, unlock, signing, export, sealed-session, and warm-session
authority types explicit enough that the later module split does not inherit
Passkey-specific assumptions.

Refactor 82B should finish before broad Refactor 87 implementation work touches
auth-method capability boundaries. The expected handoff is:

- `WalletAuthAuthority` becomes the common stable auth identity for Refactor 87
  auth modules.
- `RegistrationAuthProof` stays at Refactor 87 registration/request boundaries.
- Signer capability modules consume stable authority plus capability identity,
  never one-time proof IDs.
- Email OTP and Passkey paths are represented as peer authority branches before
  capability-specific registration, unlock, signing, and export code is split.

## Goal

Make Passkey and Email OTP authority explicit across registration, wallet
unlock, signing, key export, sealed sessions, and warm sessions.

The current D1/DO runtime has the correct broad architecture, but several shared
session paths still model Passkey as the default authority and bolt Email OTP
onto that shape. This created repeated regressions:

- Email OTP registration/unlock rejected by `passkey_rp` checks.
- Email OTP ECDSA signing failing with missing signing-session authority.
- Email OTP key export failing provider-user matching.
- OTP registration reroll blocked by app-session wallet binding checks.
- Long-lived session identity polluted by one-time registration proof IDs.

## Current Regression Notes

The July 2026 OTP registration/signing regressions were hard to fix because the
same ECDSA signing session state was represented through several parallel shapes:

- registration bootstrap output;
- runtime session records;
- durable sealed session records;
- warm capability records;
- exact lane candidates;
- wallet-session authority records.

Those shapes were individually typed, but the bridge functions allowed partial
success states such as "session record exists, worker material exists, authority
JWT missing". The signing selector then collapsed distinct failures into one
generic "Email OTP signing-session authority is unavailable" error.

Refactor 82B must make that state atomic:

- Email OTP ECDSA registration, unlock, recovery, export, and step-up all commit
  through the same `EmailOtpEcdsaSessionCommit` path.
- A committed Email OTP ECDSA lane must contain session identity, key identity,
  wallet-session authority, warm material status, and durable restore metadata as
  one strict object.
- Selection must consume the strict committed lane object. It should not rebuild
  authority by probing multiple stores.
- Diagnostics may report which strict object failed to parse, but diagnostics
  must not influence control flow.

## Review Findings Incorporated

The first plan review found these design issues, and this document treats them
as scope constraints:

- The canonical `EcdsaCommittedLane` must be introduced before companion-lane
  work. Companion selection must consume committed lanes, rather than creating a
  temporary `ReadyEmailOtpEcdsaSessionRecord` selector that Phase 7 later deletes.
- Registration proof is only one boundary. Unlock, step-up, recovery, and key
  export also need explicit request-boundary proof unions that resolve to stable
  `WalletAuthAuthority` before core code runs.
- AuthService cleanup must name the public adapter boundary. Routes keep using
  the public facade during the mechanical split, and stale AuthService internals
  become delete candidates for the D1/AuthService cleanup phase.
- Compatibility parsing must list exact accepted legacy fields at each boundary
  and must have deletion tasks. Compatibility parsing cannot become a permanent
  shadow API.
- `WalletAuthAuthorityDigest` must define canonical serialization, digest
  algorithm, and whether `walletId` is part of the digest input.

## Core Rule

Long-lived authority is stable auth identity. One-time proof data stays at the
request boundary.

Stable authority:

```ts
type WalletAuthAuthority =
  | {
      kind: 'passkey';
      rpId: WebAuthnRpId;
      credentialIdB64u: WebAuthnCredentialIdB64u;
    }
  | {
      kind: 'email_otp';
      provider: 'google' | 'email';
      providerUserId: EmailOtpProviderUserId;
    };
```

Email address is display and enrollment metadata. It is not part of stable
authority identity.

```ts
type EmailOtpAuthorityProfile = {
  kind: 'email_otp_authority_profile';
  authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>;
  email: VerifiedEmailAddress;
};

type WalletAuthAuthorityRef = {
  kind: 'wallet_auth_authority_ref';
  walletId: WalletId;
  authorityDigest: WalletAuthAuthorityDigest;
};
```

Boundary proofs:

```ts
type RegistrationAuthProof =
  | {
      kind: 'passkey_registration';
      webauthnRegistration: WebAuthnRegistrationCredential;
    }
  | {
      kind: 'email_otp_challenge';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    }
  | {
      kind: 'google_sso_email_otp_registration';
      registrationAttemptId: GoogleEmailOtpRegistrationAttemptId;
      registrationOfferId: GoogleEmailOtpRegistrationOfferId;
      registrationCandidateId: GoogleEmailOtpRegistrationCandidateId;
      appSessionJwt: AppSessionJwt;
    };

type WalletUnlockAuthProof =
  | {
      kind: 'passkey_unlock';
      assertion: WebAuthnAuthenticationAssertion;
    }
  | {
      kind: 'email_otp_unlock';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    };

type StepUpAuthProof =
  | {
      kind: 'passkey_step_up';
      assertion: WebAuthnAuthenticationAssertion;
    }
  | {
      kind: 'email_otp_step_up';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    };

type RecoveryAuthProof =
  | {
      kind: 'email_otp_recovery';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    };

type KeyExportAuthProof =
  | {
      kind: 'passkey_key_export';
      assertion: WebAuthnAuthenticationAssertion;
    }
  | {
      kind: 'email_otp_key_export';
      challengeId: EmailOtpChallengeId;
      otpCode: EmailOtpCode;
      appSessionJwt: AppSessionJwt;
    };

type AuthBoundaryProof =
  | RegistrationAuthProof
  | WalletUnlockAuthProof
  | StepUpAuthProof
  | RecoveryAuthProof
  | KeyExportAuthProof;
```

Core session, key, and lane objects carry `WalletAuthAuthority` or a narrowed
branch of it. Budget and sealed material objects carry `WalletAuthAuthorityRef`
when they only need to bind back to the stable authority. Route parsers and
request services consume `AuthBoundaryProof`, validate it once, then emit stable
authority.

Canonical home:

- Brands and primitive IDs live in `packages/shared-ts/src/utils/domainIds.ts`.
- `WalletAuthAuthority`, `WalletAuthAuthorityRef`, parsers, builders, and digest
  helpers live in one shared authority module.
- `WalletAuthAuthorityDigest` uses deterministic JSON over `{ walletId,
  authority }`, with sorted object keys, base64url SHA-256 output, and no display
  fields such as email address.

## Typing Constraints

These are non-negotiable for this refactor:

- `WalletAuthAuthority` is the only long-lived auth identity in session, key,
  lane, and export state.
- `WalletAuthAuthorityRef` is the only long-lived auth reference in budget and
  sealed material state.
- Email address is display/enrollment metadata. Core authority matching uses
  `provider` and `providerUserId`.
- `RegistrationAuthProof` is request-boundary data. Proof IDs must not appear in
  persisted key identity, threshold session policy, signing lanes, sealed
  sessions, budget records, or export records.
- Unlock, step-up, recovery, and key export proofs are request-boundary data.
  They resolve to `WalletAuthAuthority` or a branch-specific authenticated use
  object before core code runs.
- Core types must not carry loose sibling fields such as `rpId`,
  `providerUserId`, `authSubjectId`, `challengeId`, or
  `googleEmailOtpRegistrationAttemptId` when those fields are part of an auth
  authority or boundary proof.
- Raw request, D1, IndexedDB, worker, and token shapes are parsed once into
  strict internal types. Core functions receive branch-specific domain objects.
- Material, budget, registration candidate, and auth-use lifecycle state must be
  discriminated unions. Optional identity/auth/session fields are boundary-only.
- Generic helpers must switch exhaustively on `authority.kind`. Helpers that
  require `rpId` or WebAuthn credential data must be named `Passkey`.
- Type fixtures must reject every known escape hatch from the regressions that
  triggered this plan.

## Inventory

This is the working inventory for implementation. Update it as files are edited.

### Shared Authority And Registration Types

Update:

- `packages/sdk-server-ts/src/core/types.ts`
  - `ThresholdEd25519AuthorityScope`
  - session/key record types carrying `authorityScope`
  - `WalletRegistrationStartAuthority`
  - `AddAuthMethodAuthority`
- `packages/shared-ts/src/utils/registrationIntent.ts`
  - `RegistrationAuthority`
  - `RegistrationEd25519AuthorityScope`
  - `registrationEd25519AuthorityScope`
  - registration intent parser branches carrying `challengeId` or
    `googleEmailOtpRegistration*` IDs
- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
  - `parseThresholdEd25519AuthorityScope`
  - `thresholdEd25519AuthorityScopesMatch`
  - key/session parsers that currently parse `authorityScope`
- `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
  - `Ed25519AuthorityScope`
  - `Ed25519SessionPolicyAuthority`
  - `ed25519AuthorityScopeFromPolicyAuthority`
  - `buildThresholdEd25519WalletSessionPolicy`
  - `buildThresholdEcdsaWalletSessionPolicy`

Target:

- Add the shared stable `WalletAuthAuthority`.
- Add request-boundary `RegistrationAuthProof`.
- Replace `authorityScope` in core session/key/lane policy with `authority`.
- Keep proof IDs inside registration/request parsers and audit records only.

### Server Registration And D1 Boundary

Update:

- `packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch.ts`
  - `d1ThresholdEd25519AuthorityScopeFromRegistrationScope`
  - `d1RegistrationIntentThresholdEd25519AuthorityScope`
  - `validateD1WalletRegistrationRequestedSessionPolicy`
  - `parseD1WalletRegistrationReadyEd25519Session`
- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
  - Ed25519 authority construction around registration prepare/start/finalize
  - `walletRegistrationFinalizeAuthMethodFromAuthority` call sites
  - candidate wallet validation for OTP reroll
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
  - `parseD1RegistrationAuthority`
  - `parseD1PasskeyRegistrationAuthority`
  - `parseD1EmailOtpRegistrationAuthority`
  - `parseD1GoogleSsoEmailOtpRegistrationAuthority`
  - ceremony record parsing that currently stores `authorityScope`
- `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`
  - legacy ceremony parsing and equality helpers using
    `RegistrationEd25519AuthorityScope`
- `packages/sdk-server-ts/src/core/AuthService.ts`
  - stale AuthService registration authority helpers
  - passkey-only session-policy validation still reachable from current tests

Target:

- D1 registration resolves `RegistrationAuthProof` into `WalletAuthAuthority`
  once.
- OTP wallet-name reroll validates `RegistrationWalletCandidate`.
- AuthService-era paths are deleted or owned by the public AuthService facade
  until route ports replace that facade. Routes must not import split
  `authService/*` internals during the mechanical module split.

### Server Session, Route, And Store Boundary

Update:

- `packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation.ts`
  - `parseEd25519AuthorityScope`
  - `parseThresholdEd25519SessionPolicyBody`
- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
  - wallet session auth parsing and session policy builders
- `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.ts`
  - `VerifiedWalletSessionAuth.authorityScope`
- `packages/sdk-server-ts/src/router/routerApi.ts`
  - Router API request/response types carrying `rpId`, `authorityScope`, or
    optional Email OTP subject fields
- `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
  - private worker request types carrying `authorityScope`
- `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionCore.ts`
  - `ed25519AdmissionAuthorityScopeKey`
- `packages/sdk-server-ts/src/router/bootstrapGrantBroker.ts`
  - bootstrap grant authority payload parsing
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
  - Ed25519 route session policy parsing
- `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - passkey-only authority checks at ECDSA inventory/session routes
- `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/routes/syncAccount.ts`
  - passkey authority construction
- `packages/sdk-server-ts/src/router/express/routes/syncAccount.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types.ts`
  - sealed session policy authority branch
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`
  - sealed session policy parser
- `packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts`
  - persisted recovery authority parsing
- `packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore.ts`
  - stored key identity shape
- `packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts`
  - stored threshold session identity shape
- `packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts`
  - wallet budget/session authority shape
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - DO persisted session and budget projection authority fields

Target:

- Route parsers accept raw/compatibility shapes and emit strict authority.
- Durable records persist stable authority, with compatibility readers confined
  to persistence boundaries.
- Shared routes switch on `authority.kind`; passkey-only routes say `Passkey`.

### Web Registration And Warm Session Boundary

Update:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
  - `thresholdEd25519AuthorityScopeFromRegistrationScope`
  - `registrationEd25519SessionPolicyAuthority`
  - `registrationAuthorityScopeKey`
  - `registrationBootstrapGrantAuthority`
  - registration finalize payload construction
- `packages/sdk-web/src/SeamsWeb/operations/registration/createAccountRouterApiServer.ts`
  - managed bootstrap grant payload identity
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
  - Email OTP/Passkey login wallet binding authority
  - Ed25519 login material resolution
- `packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts`
  - passkey authority assumptions
- `packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts`
  - recovery authority session construction
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
  - `ThresholdEd25519WorkerMaterialRestoreContext`
  - `ThresholdEd25519LoginMaterialPendingSessionRecord`
  - `Ed25519ReusableWorkerMaterialSelector`
  - `resolveReusableEd25519WorkerMaterialForLoginSession`
  - `persistEd25519LoginSessionFromReusableWorkerMaterial`
  - `persistEmailOtpRegisteredThresholdEd25519WorkerMaterial`
  - `reconstructThresholdEd25519SigningMaterialFromWarmSession`

Target:

- Registration creates proof data at the boundary and stable authority in core.
- Warm-session bootstrap consumes `WalletAuthAuthority` and material state
  unions.
- Login resolution returns a branch of `Ed25519LoginMaterialResolution`, with no
  fallback hydration path hidden behind nullable records.

### Web ECDSA Email OTP Authority

Update:

- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts`
  - `ThresholdEcdsaEmailOtpAuthContext`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `ReadyEmailOtpEcdsaSessionRecord`
  - `thresholdEcdsaEmailOtpAuthContext`
  - `normalizeThresholdEcdsaEmailOtpAuthContext`
  - `toEcdsaEmailOtpRuntimeLaneRef`
  - `EmailOtpEcdsaPostSignMaterial`
  - `consumeSingleUseEmailOtpEcdsaLane`
  - `markThresholdEd25519EmailOtpSessionConsumedForWallet`
  - ECDSA session upsert/restore helpers carrying `emailOtpAuthContext`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts`
  - `CommitEmailOtpThresholdEcdsaSessionArgs`
  - `CommitEmailOtpEvmFamilyThresholdEcdsaSessionsArgs`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
  - `EmailOtpEcdsaLoginReconnectInput`
  - `EmailOtpEcdsaTransactionStepUpInput`
  - login/step-up context builders
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`
  - `EmailOtpEcdsaSealedRecoveryRecordInput`
  - restore source selection
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts`
  - companion ECDSA context copy
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts`
  - fresh export step-up inputs
  - `resolveEmailOtpEcdsaFreshLoginExportStepUpInput`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts`
  - `ExportEcdsaKeyWithFreshEmailOtpLaneArgs`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ports.ts`
  - `EmailOtpEcdsaSessionPorts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts`
  - public Email OTP ECDSA login/enroll bridge functions
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts`
  - single-use consumed checks
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
  - Email OTP ECDSA step-up and post-sign consumption
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts`
  - budget readiness and auth planning inputs
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
  - prepared budget/auth state
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts`
  - `authSubjectId` digest inputs
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
  - worker-local Email OTP handle authority fields

Target:

- Replace loose `authSubjectId` with
  `authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>` where the
  value is long-lived.
- Keep `challengeId` and registration attempt IDs in route/worker proof
  messages.
- Model Email OTP use with `EmailOtpAuthUse`.

### Web Ed25519 Worker Material State

Update:

- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `RouterAbEd25519RestorableWorkerMaterialIdentity`
  - `Ed25519WorkerMaterialValidationKey`
  - `routerAbEd25519WorkerMaterialIdentityFromPersistedState`
  - `classifyRouterAbEd25519PersistedSigningRecord`
  - `hasEd25519SealedWorkerMaterial`
  - runtime validation helpers
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `ThresholdEd25519SessionRecord`
  - `ThresholdEd25519MaterialReadySessionRecord`
  - `ThresholdEd25519MaterialPendingSessionRecord`
  - material field normalizers and upsert helpers
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - `CurrentEd25519RestoreMetadata`
  - `CurrentEd25519SealedSessionRecord`
  - `CurrentEcdsaSealedSessionRecord`
  - sealed restore parsing/building
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts`
  - `RouterAbEd25519WorkerMaterialRestoreAuthorization`
  - `RouterAbEd25519ReadySigningMaterialState`
  - `requireLoadedOrRestoreRouterAbEd25519SigningMaterial`
  - `tryRequireLoadedRouterAbEd25519SigningMaterial`
  - `restoreRouterAbEd25519SigningMaterial`
  - `buildExpectedWorkerMaterialBindingForRestore`
  - `sealedMaterialTransportFromRecord`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts`
  - `resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential`
  - `resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
  - selected exact lane material checks
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
  - `ed25519MaterialRestoreIdentityForExportLane`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
  - material availability in lane candidates
- `packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
  - persisted Ed25519 lane construction
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
  - warm-session material state projection
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
  - warm capability persistence builders
- `packages/sdk-web/src/core/signingEngine/interfaces/near.ts`
  - Ed25519 session/material public internal interface

Target:

- Replace flat material fields with `Ed25519WorkerMaterialState`.
- Make lane selection consume material state instead of parallel predicates.
- Keep flat IndexedDB columns only at persistence read/write boundaries.

### Budget And First Step-Up Signing

Update:

- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
  - `WalletSigningBudgetStatusRequest`
  - `parseWalletSigningBudgetStatusExpectations`
  - `parseEcdsaWalletSigningBudgetStatusRequest`
  - `parseEd25519WalletSigningBudgetStatusRequest`
  - `parseWalletSigningBudgetStatusRequest`
- `packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts`
  - `handleSigningBudgetStatus`
  - `VerifiedSigningBudgetStatus`
- `packages/sdk-server-ts/src/router/express/routes/sessions.ts`
  - Express equivalent
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - `authBudgetProjection`
  - `parseAuthBudgetReserveInput`
  - `parseAuthBudgetCommitInput`
  - reserve/commit/release handlers
- `packages/sdk-web/src/core/signingEngine/session/budget/budget.ts`
  - `SigningBudgetFinalizationResult`
  - `SigningSessionBudgetReserveResult`
  - `SigningSessionBudgetStatusCheck`
  - `SigningSessionBudgetStatusReader`
  - `SigningSessionBudgetStatusAuth`
- `packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator.ts`
  - `reserve`
  - `getAvailableStatus`
  - `recordSuccess`
  - `syncStatusForSuccessfulSpend`
  - `budgetStatusUnavailable`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
  - HTTP response parser
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.ts`
  - client-side projection state
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
  - `EcdsaBudgetAdmissionAuthority`
  - `trustedBudgetStatusAuthFromBudgetAdmissionAuthority`
  - `trustedBudgetStatusAuthForEcdsaBudgetOperation`
  - `assertPreparedEcdsaBudgetAdmitted`
  - budget reservation and finalization call sites
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/budgetSpending.ts`
  - `reserveEvmFamilySigningGrantBudget`
  - `createEvmFamilyTransactionBudgetFinalizer`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
  - prepared budget state and `budget_unknown` branches
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
  - Ed25519 budget readiness state
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`
  - Ed25519 transaction budget finalizer

Target:

- Parse budget status once into `SigningBudgetStatus`.
- Budget records and budget APIs carry `SigningBudgetAuthority`.
- Budget records and budget APIs do not carry `ThresholdEcdsaEmailOtpAuthContext`
  or Email OTP proof fields.
- Signing paths branch on `available`, `exhausted`, `requires_step_up`, or
  `unavailable`.
- First transaction after step-up must receive trusted status auth from the new
  session before signing starts.
- Concurrent EVM operations reserve independent operation IDs and do not reject
  because another operation is in flight.

### Tests And Type Fixtures

Update or add:

- Server authority/type fixtures:
  - `packages/sdk-server-ts/src/core/ThresholdService/thresholdEd25519AuthorityScope.typecheck.ts`
  - `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.typecheck.ts`
  - `packages/sdk-server-ts/src/router/signingBudgetStatus.typecheck.ts`
  - `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.typecheck.ts`
  - `packages/sdk-server-ts/src/core/registrationRequests.typecheck.ts`
- Web authority/session fixtures:
  - `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.typecheck.ts` if
    absent, add it.
  - `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.typecheck.ts` if
    absent, add it.
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer.typecheck.ts`
  - `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.typecheck.ts`
- Runtime regression tests:
  - `tests/unit/registrationIntentDigest.unit.test.ts`
  - `tests/unit/relayWalletRegistration.boundary.unit.test.ts`
  - `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
  - `tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts`
  - `tests/unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts`
  - `tests/unit/ed25519TransactionLaneSelection.unit.test.ts`
  - `tests/unit/exportLaneSelection.unit.test.ts`
  - `tests/unit/sealedSessionStore.unit.test.ts`
  - `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts`
  - `tests/unit/signingSessionCoordinator.ecdsaStepUp.unit.test.ts`
  - `tests/unit/evmFamilyBudgetSpending.unit.test.ts`
  - `tests/unit/walletSessionBudgetReservation.store.unit.test.ts`
  - `tests/relayer/cloudflare-router.test.ts`
  - `tests/relayer/express-router.test.ts`
  - `tests/relayer/email-otp.routes.test.ts`
  - `tests/relayer/email-otp.bootstrap-integration.test.ts`

Delete stale tests that only preserve:

- `authorityScope` proof IDs in core session policy.
- Passkey-only ECDSA session inventory.
- Optional Email OTP provider subject in ECDSA session records.
- Flat optional Ed25519 material bags in lane selection.

## Target Types

### Stable Auth Authority

`WalletAuthAuthority` replaces scattered auth identity fields. Long-lived
objects store this exact branch, a narrowed branch of it, or a reference when
the object only needs authority binding.

```ts
type WalletAuthAuthority =
  | {
      kind: 'passkey';
      rpId: WebAuthnRpId;
      credentialIdB64u: WebAuthnCredentialIdB64u;
    }
  | {
      kind: 'email_otp';
      provider: EmailOtpProvider;
      providerUserId: EmailOtpProviderUserId;
    };

type EmailOtpAuthorityProfile = {
  kind: 'email_otp_authority_profile';
  authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>;
  email: VerifiedEmailAddress;
};

type WalletAuthAuthorityRef = {
  kind: 'wallet_auth_authority_ref';
  walletId: WalletId;
  authorityDigest: WalletAuthAuthorityDigest;
};
```

### Ed25519 Authority

```ts
type ThresholdEd25519Authority = WalletAuthAuthority;

type ThresholdEd25519SessionPolicy = {
  version: 'threshold_session_v1';
  walletId: WalletId;
  nearAccountId: NearAccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  authority: ThresholdEd25519Authority;
  routerKeyId: RouterEd25519KeyId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingGrantId: SigningGrantId;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  participantIds: readonly ParticipantId[];
  ttlMs: PositiveMilliseconds;
  remainingUses: PositiveUseCount;
};
```

### ECDSA Authority

```ts
type ThresholdEcdsaSessionAuthority = WalletAuthAuthority;

type EmailOtpAuthUse =
  | {
      kind: 'session';
      reason: 'login' | 'sign';
    }
  | {
      kind: 'single_use_pending';
      reason: 'sign';
    }
  | {
      kind: 'single_use_consumed';
      reason: 'sign';
      consumedAtMs: UnixMilliseconds;
    };

type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  authMethod: 'email_otp';
  authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>;
  use: EmailOtpAuthUse;
};
```

`authority.providerUserId` is the stable match key used by runtime warm
sessions, sealed sessions, key export, and signing-session auth lanes.

### Boundary Mapping

```ts
type RegistrationAuthorityResolution =
  | {
      kind: 'resolved_passkey_authority';
      authority: Extract<WalletAuthAuthority, { kind: 'passkey' }>;
    }
  | {
      kind: 'resolved_email_otp_authority';
      authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>;
      proofAuditRef: RegistrationAuthProofAuditRef;
    };
```

Route handlers, D1 registration services, and worker messages may carry
`AuthBoundaryProof`. Core session builders receive only
`RegistrationAuthorityResolution['authority']` or a branch-specific authenticated
use object created by the boundary parser.

### Registration Candidate Wallet

Registration candidates are separate from active wallet sessions. OTP wallet
name reroll uses this type until finalize mints the wallet.

```ts
type RegistrationWalletCandidate = {
  kind: 'registration_wallet_candidate';
  walletId: WalletId;
  registrationAttemptId: RegistrationAttemptId;
};

type ActiveWalletSession = {
  kind: 'active_wallet_session';
  walletId: WalletId;
  authority: WalletAuthAuthority;
  walletSessionJwt: WalletSessionJwt;
};
```

### Worker Material State

Material identity must move as one object. Core code should never read
`materialKeyId`, `bindingDigest`, or sealed refs independently from a flat
optional bag.

```ts
type Ed25519WorkerMaterialIdentity = {
  materialKeyId: Ed25519WorkerMaterialKeyId;
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
};

type Ed25519WorkerMaterialState =
  | {
      kind: 'material_pending';
    }
  | {
      kind: 'sealed_material';
      identity: Ed25519WorkerMaterialIdentity;
      sealed: Ed25519SealedWorkerMaterial;
    }
  | {
      kind: 'loaded_material';
      identity: Ed25519WorkerMaterialIdentity;
      handle: Ed25519WorkerMaterialHandle;
    };
```

### Signing Budget State

Signing code should consume a parsed budget state. It must not proceed from
`budget_unknown`.

Budget state models whether an already-authorized session can spend. It does
not model Email OTP proof, provider user matching, or ECDSA auth lane selection.

```ts
type SigningBudgetAuthority =
  | {
      kind: 'ed25519_budget_authority';
      walletId: WalletId;
      thresholdSessionId: ThresholdEd25519SessionId;
      signingGrantId: SigningGrantId;
      authorityRef: WalletAuthAuthorityRef;
    }
  | {
      kind: 'ecdsa_budget_authority';
      walletId: WalletId;
      thresholdSessionId: ThresholdEcdsaSessionId;
      signingGrantId: SigningGrantId;
      chainTarget: EvmFamilyChainTarget;
      authorityRef: WalletAuthAuthorityRef;
    };
```

```ts
type SigningBudgetStatus =
  | {
      kind: 'available';
      remainingUses: PositiveUseCount;
    }
  | {
      kind: 'exhausted';
    }
  | {
      kind: 'requires_step_up';
    }
  | {
      kind: 'unavailable';
      reason: SigningBudgetUnavailableReason;
    };
```

## Phase 1: Inventory And Type Boundary

Status: pending.

Do:

- Inventory every `passkey_rp`, `rpId`, `authorityScope`, `emailOtpAuthContext`,
  `authSubjectId`, `googleEmailOtpRegistrationAttemptId`, and
  `challengeId` use in auth/session/signing code.
- Classify each use as one of:
  - boundary proof
  - stable authority
  - display data
  - legacy/obsolete
- Add `WalletAuthAuthority` and branch-specific parser/builders in shared
  domain code.
- Add request-boundary proof unions for registration, unlock, step-up, recovery,
  and key export.
- Add `RegistrationWalletCandidate` and `ActiveWalletSession` so registration
  reroll cannot be validated as an active wallet session.
- Define `WalletAuthAuthorityDigest` canonical serialization and hash algorithm.
- Document exact compatibility fields accepted at each request/persistence
  boundary, with a deletion task for every field.
- Add type fixtures rejecting proof IDs inside session/key/lane policy objects.
- Add type fixtures rejecting loose auth fields beside `WalletAuthAuthority`.

Exit criteria:

- The inventory is documented in this file.
- Boundary proofs and stable authority have separate exported types.
- Compatibility field lists exist only under boundary parser tasks.
- Static checks reject proof IDs in long-lived session policy objects.
- Static checks reject direct object-literal construction of session policies
  with `rpId`, `authSubjectId`, or provider proof fields outside authority
  branches.

## Phase 2: Ed25519 Session Policy Conversion

Status: pending.

Do:

- Replace `ThresholdEd25519AuthorityScope` in Ed25519 session policy with stable
  `ThresholdEd25519Authority`.
- Delete or boundary-confine `authorityScope` once equivalent stable authority
  parsing exists.
- Keep request compatibility parsing at route/persistence boundaries only.
- Update:
  - `packages/sdk-server-ts/src/core/types.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
  - `packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts`
- Ed25519 warm-session bootstrap and recovery callers.
- Replace “passkey authority” checks with exhaustive switches over authority.
- Rename passkey-only helpers so their names say `Passkey`.

Exit criteria:

- Ed25519 session policy has one authority field.
- OTP session policy never contains `rpId`.
- Passkey code accesses `rpId` only inside `authority.kind === 'passkey'`.
- Email OTP code accesses provider identity only inside
  `authority.kind === 'email_otp'`.

## Phase 3: Registration Authority Resolution

Status: pending.

Do:

- Convert registration intent auth proof into stable authority once in D1
  registration services.
- Move these fields out of long-lived registration/session identity:
  - `challengeId`
  - `googleEmailOtpRegistrationAttemptId`
  - `googleEmailOtpRegistrationOfferId`
  - `googleEmailOtpRegistrationCandidateId`
- Store proof/audit references separately from session/key identity.
- Update registration signing-key derivation so `nearEd25519SigningKeyId` is
  derived from stable authority.
- Preserve wallet-name reroll for OTP registration by validating candidate
  ownership against the registration attempt, then minting the chosen wallet ID.
- Make registration services accept `RegistrationWalletCandidate` for candidate
  validation and `ActiveWalletSession` only after finalize.

Exit criteria:

- OTP registration can reroll wallet IDs before finalization.
- Stable Email OTP authority survives unlock and step-up auth.
- Registration attempt IDs never appear in Ed25519 session policy digests.
- No registration candidate path calls an active-wallet-session validator.

## Phase 4: ECDSA Email OTP Session Authority

Status: pending.

Do:

- Replace `ThresholdEcdsaEmailOtpAuthContext.authSubjectId` with
  `authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>` and
  `use: EmailOtpAuthUse`.
- Make `ReadyEmailOtpEcdsaSessionRecord` require:
  - `source: 'email_otp'`
  - `thresholdSessionKind: 'jwt'`
  - `walletSessionJwt`
  - `emailOtpAuthContext.authority`
  - `emailOtpAuthContext.use`
- Keep `EmailOtpEcdsaSigningSessionAuthLaneResolver` required for ECDSA
  selection.
- Update sealed-session records so Email OTP ECDSA restore always contains
  provider subject identity.
- Add tests for:
  - runtime session auth lane resolution
  - durable sealed auth lane resolution
  - missing provider subject rejected at parse time

Exit criteria:

- Tempo and EVM signing after OTP unlock use the same Email OTP stable authority
  as registration.
- ECDSA Email OTP authority never carries budget status, budget reservations, or
  budget finalization state.

## Phase 4B: Exact Companion Lane Typing

Status: pending.

Recent OTP step-up signing exposed a missing type distinction: a wallet can have
multiple ECDSA companion lanes for one Email OTP signing grant when those
lanes represent different chain targets. That is valid. Multiple lanes for
the same chain target are duplicate authority and must fail closed.

Do:

- Replace overloaded `exact_match` companion-selection results with a domain
  union that distinguishes:
  - one companion lane
  - a chain-distinct companion lane set
  - duplicate lanes for the same chain target
  - missing companion lanes
- Model the selected companion lane as a wallet-scoped capability, not as a
  provider-subject lookup result.
- Consume `EcdsaCommittedLane` directly. Do not introduce a
  `ReadyEmailOtpEcdsaSessionRecord` companion selector as an intermediate core
  authority shape.

Target shape:

```ts
type EmailOtpEcdsaCommittedLane = Extract<
  EcdsaCommittedLane,
  { kind: 'email_otp_ecdsa_committed_lane' }
>;

type EmailOtpEcdsaCompanionForEd25519Signing =
  | {
      kind: 'single_companion_lane';
      lane: EmailOtpEcdsaCommittedLane;
    }
  | {
      kind: 'chain_distinct_companion_lanes';
      primaryLane: EmailOtpEcdsaCommittedLane;
      lanes: readonly EmailOtpEcdsaCommittedLane[];
    };

type EmailOtpEcdsaCompanionSelection =
  | {
      kind: 'ready';
      companion: EmailOtpEcdsaCompanionForEd25519Signing;
    }
  | {
      kind: 'not_found';
    }
  | {
      kind: 'duplicate_chain_lanes';
      chainTargetKey: string;
      count: number;
    };
```

- Update `EmailOtpEd25519Warmup.loginForSigning` to consume the `ready`
  companion branch explicitly.
- Keep `signingGrantId` and `walletId` required selector inputs.
- Keep `chainTarget` inside ECDSA capability identity; do not use provider
  subject identity as the lane selector.
- Add type fixtures proving callers cannot treat multi-chain companion sets as
  a single exact lane without selecting `primaryLane`.
- Add unit coverage for:
  - same wallet, same grant, Tempo + Arc lanes: succeeds
  - same wallet, same grant, duplicate Tempo lanes: fails closed
  - same Gmail/provider subject across different wallet IDs: does not collide

Exit criteria:

- The OTP Ed25519 step-up path has no `exact_match` branch that hides
  multi-lane state.
- Duplicate detection is chain-target-specific.
- Shared Email OTP authority is stable across wallets, while wallet capability
  selection remains wallet-scoped.
- Companion selection never accepts session records, sealed records, warm
  capability records, or exact lane candidates as authority inputs.

## Phase 4C: Budget Authority And First Step-Up Signing

Status: pending.

Budget state answers one question: whether an authorized signing session has
usable remaining spend. It must not encode Email OTP provider identity,
challenge proof state, or ECDSA auth-lane resolution.

Do:

- Replace `budget_unknown` control flow with `SigningBudgetStatus` parsing at
  the budget-status response boundary.
- Introduce `SigningBudgetAuthority` as a separate domain object that contains:
  - wallet ID
  - threshold session ID
  - signing grant ID
  - chain target for ECDSA budget lanes
  - `WalletAuthAuthorityRef`
- Keep `ThresholdEcdsaEmailOtpAuthContext` out of budget admission, reservation,
  and finalization APIs.
- Make ECDSA first step-up signing consume:
  - `ThresholdEcdsaEmailOtpAuthContext` for auth authority
  - `SigningBudgetAuthority` for budget binding
  - `SigningBudgetStatus` for spend state
- Remove any code path where `budget_unknown` triggers Email OTP step-up
  behavior by inference.
- Add tests for:
  - first EVM/Tempo transaction immediately after step-up succeeds
  - concurrent EVM submissions reserve distinct budget operations
  - budget unavailable does not mutate Email OTP auth context
  - Email OTP auth unavailable does not produce `budget_unknown`

Exit criteria:

- The first step-up transaction after budget exhaustion succeeds.
- Concurrent EVM submissions no longer fail due to stale budget authority state.
- EVM/Tempo signing code cannot proceed from `SigningBudgetStatus.kind ===
  'unavailable'`.
- Budget failures report budget errors. Email OTP authority failures report auth
  errors.

## Phase 5: Route Surface Cleanup

Status: pending.

Do:

- Audit routes that currently reject non-`passkey_rp` wallet sessions.
- For each route, choose one:
  - make it authority-generic
  - rename and restrict it as passkey-only
  - delete it if obsolete
- Start with:
  - `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
  - sync-account routes
  - wallet unlock routes
  - key export routes
- Remove duplicate AuthService-era route semantics that still imply Passkey
  authority.

Exit criteria:

- Shared wallet-session routes accept `WalletAuthAuthority`.
- Passkey-only routes are named passkey-only.
- OTP unlock/sign/export never calls a passkey-only route.

## Phase 6: Sealed Session And IndexedDB Cleanup

Status: pending.

Do:

- Normalize sealed session records into discriminated unions at read time.
- Remove optional identity/auth/session fields from core sealed-session types.
- Make Email OTP sealed records require stable provider subject identity.
- Replace flat Ed25519 material fields with `Ed25519WorkerMaterialState` in core
  lane/session selection.
- Make sealed material restore builders accept `sealed_material` only, and make
  runtime signing paths accept `loaded_material` only.
- Remove direct reads of `materialKeyId`, `bindingDigest`, `sealedWorkerMaterialRef`,
  and worker handles from flat session records in core signing code.
- Remove stale compatibility fields after parsers are updated.
- Update Refactor 85 if any IndexedDB schema cut is required.

Exit criteria:

- Core signing code never reads optional auth identity fields.
- Ed25519 signing and export lane selection read material through
  `Ed25519WorkerMaterialState`.
- Compatibility parsing stays inside IndexedDB/D1 boundary parsers.
- Sealed-session restore for Passkey and Email OTP uses one authority union.
- Sealed material builders accept only `Ed25519WorkerMaterialState` branches that
  actually contain material.

## Phase 7: Replace Loose Session Shapes With One Canonical Committed Lane

Status: pending.

Implementation note: do this immediately after Phase 1 creates shared authority
types. Phase 4, Phase 4B, and Phase 4C consume this object instead of creating
temporary selectors that later need deletion.

Do:

- Make `EcdsaCommittedLane` the single canonical authority object for ECDSA
  signing, export, step-up, and restore. The committed lane is created once from
  boundary data and then passed through core flows directly.
- Delete loose ECDSA session-authority shapes after the committed lane owns the
  signing path:
  - registration bootstrap-as-authority objects;
  - runtime session records used directly as authority;
  - durable sealed records used directly as authority;
  - warm capability records used directly as authority;
  - exact lane candidates that rebuild wallet-session authority;
  - wallet-session authority probes that search multiple stores.
- Replace all ECDSA signing/export/step-up inputs with this strict committed-lane
  union:

```ts
type EcdsaCommittedLane =
  | {
      kind: 'passkey_ecdsa_committed_lane';
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      authority: Extract<WalletAuthAuthority, { kind: 'passkey' }>;
      key: EcdsaKeyIdentity;
      session: SigningSessionAuthority;
      material: EcdsaReadyMaterial;
      durableRestore: EcdsaDurableRestoreRef;
    }
  | {
      kind: 'email_otp_ecdsa_committed_lane';
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      authority: Extract<WalletAuthAuthority, { kind: 'email_otp' }>;
      key: EcdsaKeyIdentity;
      session: SigningSessionAuthority;
      material: EcdsaReadyMaterial;
      durableRestore: EcdsaDurableRestoreRef;
    };
```

- Move compatibility parsing into boundary readers only:
  - D1 route parsers;
  - IndexedDB record readers;
  - worker response parsers;
  - sealed-session readers.
- In each boundary reader, list the exact compatibility fields accepted and the
  planned deletion checkpoint for those fields.
- Delete core helpers that independently answer the same authority question:
  - `resolveEmailOtpSigningSessionAuthLane` style probing in signing flows;
  - broad `get*SessionRecordForSigning` authority reads;
  - candidate-to-authority rebuild helpers;
  - wallet-session JWT fallback readers;
  - runtime/warm-capability authority selectors.
- Keep diagnostics as observability only. Diagnostics must report why boundary
  parsing failed and must not drive signing control flow.
- Add source guards that fail on new authority-path imports of loose shapes once
  the committed-lane builder is in place.

Exit criteria:

- ECDSA signing/export/step-up functions accept `EcdsaCommittedLane`, not
  session records, sealed records, warm capability records, or lane candidates.
- Exactly one builder creates `EcdsaCommittedLane` from boundary data.
- `EcdsaCommittedLane` is the only object that combines auth authority, key
  identity, session authority, material readiness, and durable restore identity.
- No core authority path probes multiple stores to reconstruct wallet-session
  authority.
- Loose persistence/request shapes appear only in boundary parser files.
- Each loose persistence/request field has an explicit deletion checkbox in this
  plan.
- The generic error `Email OTP signing-session authority is unavailable` is
  replaced by typed boundary parse failures or committed-lane state failures.

## Phase 8: Tests And Guards

Status: pending.

Do:

- Add type fixtures for invalid authority combinations:
  - `rpId` on Email OTP authority
  - OTP proof IDs in session policy
  - missing Email OTP provider subject
  - Passkey session without credential ID
  - Email OTP authority carrying `rpId`
  - sealed worker material missing `materialKeyId`
  - registration candidate passed to active wallet-session code
  - core lifecycle object with `authSubjectId` beside `authority`
- Update unit coverage for:
  - Passkey registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - Google SSO Email OTP registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - Email OTP challenge registration -> unlock -> NEAR/EVM/Tempo sign -> export
  - step-up auth first transaction after exhaustion
  - concurrent EVM signing requests
- Delete tests that preserve obsolete AuthService/passkey-only behavior.

Exit criteria:

- Tests protect both authority branches.
- No tests depend on legacy `authorityScope` proof IDs in core session state.

## Phase 9: Cleanup And Line Count Closure

Status: pending.

Do:

- Remove deleted authority names and stale comments:
  - passkey authority in shared code
  - relayer wording in router-owned paths
  - compatibility helpers outside request/persistence boundaries
- Manually remove duplicate proof-to-authority conversion helpers after the
  canonical boundary parsers are in place.
- Document line count change for non-doc code.
- Mark completed tasks in this file and parent Refactor 82.

Exit criteria:

- No duplicate proof-to-authority conversion paths.
- No legacy authority fields in core session/key/lane types.
- Net code growth is explained and minimized.

## Tracking

Tracking is ordered by implementation priority. Phase numbering stays stable for
cross-reference history; implementation starts with the shared boundary model,
then introduces the canonical committed lane before branch-specific cleanup.

- [ ] Phase 1: Inventory and type boundary
  - [ ] Inventory all Passkey-specific shared authority assumptions.
  - [ ] Inventory all Email OTP proof shapes used past the proof boundary.
  - [ ] Inventory all wallet-session, signing-session, and recovery-grant
        identity fields.
  - [ ] Classify each raw/persistence/request shape as boundary-only or core.
  - [ ] Add request-boundary proof unions for registration, unlock, step-up,
        recovery, and key export.
  - [ ] Define `WalletAuthAuthorityDigest` canonical serialization and hash
        algorithm.
  - [ ] List exact compatibility fields accepted at each boundary parser.
- [ ] Phase 7: Replace loose session shapes with one canonical committed lane
  - [ ] Add the canonical `EcdsaCommittedLane` union.
  - [ ] Add exactly one committed-lane builder from boundary-normalized data.
  - [ ] Make ECDSA signing/export/step-up functions accept
        `EcdsaCommittedLane`.
  - [ ] Delete runtime session records as authority inputs.
  - [ ] Delete durable sealed records as authority inputs.
  - [ ] Delete warm capability records as authority inputs.
  - [ ] Delete exact lane candidate authority rebuilders.
  - [ ] Delete wallet-session authority probes across multiple stores.
  - [ ] Add deletion checkpoints for every accepted loose compatibility field.
  - [ ] Keep diagnostics observability-only.
- [ ] Phase 2: Ed25519 session policy conversion
  - [ ] Replace Passkey-only Ed25519 session policy inputs with
        `WalletAuthAuthority`.
  - [ ] Move `rpId` to the Passkey authority branch only.
  - [ ] Move Email OTP proof IDs out of reusable session policy state.
  - [ ] Add branch-specific Ed25519 session policy builders.
- [ ] Phase 3: Registration authority resolution
  - [ ] Normalize registration authority once at D1/router request boundaries.
  - [ ] Keep Email OTP registration proof data at the registration-proof
        boundary.
  - [ ] Persist stable Email OTP provider subject identity for later sessions.
  - [ ] Delete AuthService-era registration authority branches.
  - [ ] Keep routes on the public AuthService facade during the mechanical
        module split.
  - [ ] Record split AuthService internals that remain as D1 cleanup delete
        candidates.
- [ ] Phase 4: ECDSA Email OTP session authority
  - [x] Remove the OTP registration ECDSA manual persistence bypass and route
        registration through the canonical Email OTP ECDSA commit path.
  - [x] Rename the Email OTP ECDSA commit input from `primaryChain` to
        `chainTarget`.
  - [x] Add diagnostics for Email OTP ECDSA commit and exact authority
        resolution failures.
  - [ ] Make Email OTP ECDSA registration, unlock, recovery, export, and step-up
        emit the same canonical committed-lane state.
  - [ ] Delete multi-store ECDSA authority probing from core signing paths.
  - [ ] Replace generic Email OTP authority-unavailable errors with typed
        committed-lane parse/state failures.
- [ ] Phase 4B: Exact companion lane typing
  - [ ] Define the companion-lane subject union over `EcdsaCommittedLane`.
  - [ ] Make companion-lane identity branch-specific for Passkey and Email OTP.
  - [ ] Remove duplicate companion-lane candidate records from runtime selection.
  - [ ] Add type fixtures for invalid mixed-chain or mixed-auth lane state.
- [ ] Phase 4C: Budget authority and first step-up signing
  - [ ] Split budget authority from Email OTP auth authority.
  - [ ] Ensure first EVM/Tempo transaction after step-up waits for committed
        budget readiness.
  - [ ] Allow concurrent EVM signing operations to reserve distinct budget
        operations.
  - [ ] Add coverage for first transaction after step-up and concurrent EVM
        submissions.
- [ ] Phase 5: Route surface cleanup
  - [ ] Audit routes that still require `passkey_rp`.
  - [ ] Make shared wallet-session routes accept `WalletAuthAuthority`.
  - [ ] Rename true Passkey-only routes as Passkey-only.
  - [ ] Delete obsolete AuthService/passkey-only route semantics.
- [ ] Phase 6: Sealed session and IndexedDB cleanup
  - [ ] Normalize sealed session records into discriminated unions at read time.
  - [ ] Remove optional identity/auth/session fields from core sealed-session
        types.
  - [ ] Replace flat Ed25519 material fields with `Ed25519WorkerMaterialState`.
  - [ ] Keep IndexedDB compatibility parsing inside record readers only.
  - [ ] Delete stale compatibility fields after readers are strict.
- [ ] Phase 8: Tests and guards
  - [ ] Add type fixtures for invalid Passkey/Email OTP authority combinations.
  - [ ] Add type fixtures for missing required material/session identity.
  - [ ] Add runtime coverage for Passkey registration, unlock, sign, and export.
  - [ ] Add runtime coverage for Google SSO Email OTP registration, unlock, sign,
        and export.
  - [ ] Add runtime coverage for direct Email OTP challenge registration, unlock,
        sign, and export.
  - [ ] Delete tests that preserve obsolete AuthService/passkey-only behavior.
- [ ] Phase 9: Cleanup and line count closure
  - [ ] Remove stale “passkey authority” wording from shared code.
  - [ ] Replace remaining “relayer” wording in router-owned paths.
  - [ ] Remove duplicate proof-to-authority conversion helpers.
  - [ ] Run source searches for loose authority/session shapes after cleanup.
  - [ ] Document non-doc line count changes.
  - [ ] Mark completed tasks in this file and parent Refactor 82.
