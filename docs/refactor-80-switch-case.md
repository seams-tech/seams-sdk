# Refactor 80: Exhaustive Domain State With Switch/Case

Date created: June 22, 2026

Status: implemented and validated on June 25, 2026.

Related plans:

- [refactor-74-login-no-hss.md](./refactor-74-login-no-hss.md)
- [refactor-75-simplify-ed25519.md](./refactor-75-simplify-ed25519.md)
- [refactor-76-branded-keys.md](./refactor-76-branded-keys.md)
- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-78-wallet-capability-bindings.md](./refactor-78-wallet-capability-bindings.md)
- [refactor-79-exact-signing-lane.md](./refactor-79-exact-signing-lane.md)

## Goal

Make signing and session lifecycle code behave more like Rust data types plus
`match`: domain state should be represented as discriminated unions, and core
logic should use exhaustive `switch` statements with `assertNever`.

This refactor targets logic where broad optional objects, `if/else` chains,
truthy checks, and fallback field mixing can hide invalid lifecycle states.

Primary outcomes:

- every auth, restore, signing, budget, and session readiness branch is named;
- callers must handle all current branches at compile time;
- adding a new state breaks type fixtures or exhaustive switches until handled;
- persistence/request compatibility remains isolated at boundary parsers;
- core signing/session code accepts precise internal domain types;
- public, iframe, React, and server-facing wrappers either expose strict
  discriminated results or parse into them before core code runs.

## Authority Model Dependency

Refactors 77, 78, and 79 established the authority identities this plan must
preserve. Refactor 80 is the lifecycle/state-modeling layer on top of those
bindings. Authority-bearing unions in signing, restore, budget, session
planning, and Email OTP flows must sit behind canonical exact lane identity.

The canonical exact-lane type lives in:

```text
packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts
```

Rules:

- do not create another public `ExactSigningLaneIdentity` type or module;
- lifecycle unions may carry exact identity, exact identity keys, or private
  projections derived from canonical exact identity;
- NEAR Ed25519 authority uses `walletId`, `nearAccountId`, and
  `nearEd25519SigningKeyId` from Refactor 78/79;
- ECDSA authority uses `walletId`, `chainTarget`, `keyHandle`, full key
  identity, `signingGrantId`, and `thresholdSessionId`;
- `SelectedSigningLaneIdentity`, `ResolvedSigningSessionIdentity`,
  `EcdsaSessionIdentity`, `ExactEcdsaLaneIdentity`,
  `ExactEcdsaRuntimeLaneRef`, and export-specific lane structs must become
  private projections or aliases during 79 reconciliation;
- threshold-session-only lookups, account-wide reads, newest/latest selection,
  and first-candidate fallback are boundary display/repair tools only.

## Bundle Size Impact

Adding TypeScript discriminated union types does not increase SDK bundle size
when the modules are imported with `import type` and contain no runtime exports.
Type aliases, interfaces, `never` fields, and `@ts-expect-error` fixtures are
erased by the TypeScript build.

Runtime code can affect bundle size only when we add value-level helpers,
builders, parsers, or `assertNever` functions. The target is to replace existing
`if/else` and fallback logic with `switch` branches, not add a parallel runtime
system. Any new runtime helper must remove ambiguity or meaningful duplication.

Rules:

- type-only domain modules must be consumed with `import type`;
- boundary parsers/builders may be runtime code and should stay narrow;
- do not add a global enum runtime object when string-literal unions are enough;
- prefer local `assertNeverX()` helpers or one tiny shared helper if repeated
  broadly;
- include bundle-size validation only if runtime helper churn is non-trivial.

## Boundary Parser And Exhaustiveness Rules

Refactor 80 separates untrusted/raw boundaries from internal domain logic.

Raw boundaries:

- iframe messages;
- public SDK arguments and results;
- worker messages;
- persisted records;
- decoded JWTs and WebAuthn responses;
- server route bodies and RPC responses;
- user preferences and confirmation config loaded from storage.

Rules:

- raw boundaries may return `invalid_request`, `unknown_external_code`,
  `worker_error`, or equivalent typed parser failures;
- raw boundaries must parse once into strict internal unions before core code
  observes the data;
- raw parser modules may use `return null` only as a local parse failure that is
  immediately converted to a typed result at the boundary;
- internal lifecycle switches must call an `assertNeverX(value)` helper in the
  exhaustive branch;
- internal lifecycle logic must not switch on raw strings, optional identity
  fields, diagnostics objects, or public compatibility shapes.

## Type Organization Strategy

Do not create one broad `typings/` folder for all lifecycle states. A global
folder would make domain ownership less clear and encourage large cross-module
imports.

Use co-located domain modules:

```text
packages/sdk-web/src/core/signingEngine/session/planning/planning.types.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.types.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/emailOtpSession.types.ts
packages/sdk-web/src/core/signingEngine/nonce/nonceLifecycle.types.ts
packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmationDecision.types.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/nearSigning.types.ts
packages/sdk-web/src/core/types/confirmationConfig.ts
packages/sdk-web/src/core/types/sdkPublicResults.types.ts
packages/sdk-web/src/SeamsWeb/operations/auth/login.types.ts
packages/sdk-web/src/SeamsWeb/walletIframe/client/walletIframe.types.ts
packages/sdk-web/src/react/reactDisplayState.types.ts
packages/sdk-server-ts/src/router/routerCommand.types.ts
```

Guidelines:

- Put a type next to the code that owns the lifecycle transition.
- Use `*.types.ts` for type-only domain unions.
- Use `*.typecheck.ts` for compile-time rejection fixtures.
- Use `*.builders.ts` only when branch construction needs runtime validation.
- Keep request/persistence compatibility shapes in boundary modules, then parse
  once into strict internal types.
- Avoid exporting internal lifecycle unions from the public SDK API unless the
  public surface genuinely needs them.
- Domain modules such as
  `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/nearSigning.types.ts`
  may define operation lifecycle unions, but must import canonical exact-lane
  identity types instead of defining competing lane identity structs.
- Server route command unions should live next to the route family that owns the
  transition. They must parse raw request bodies before calling AuthService,
  Router A/B workers, or threshold services.

### Naming Pattern

Use branch names that describe authority and lifecycle, not implementation
details:

```ts
type MaterialReadiness =
  | { kind: 'runtime_validated'; material: RuntimeValidatedMaterial }
  | { kind: 'restore_available'; sealed: SealedMaterialRef }
  | { kind: 'unseal_authorization_required'; bindingDigest: MaterialBindingDigest }
  | { kind: 'missing_sealed_material'; reason: MissingMaterialReason }
  | { kind: 'worker_restore_failed'; message: string };
```

Prefer `kind` for domain unions. Use `status` only where an existing public type
already uses `status`, such as `SigningSessionStatus`.

Every switch must end with an exhaustive branch:

```ts
function assertNeverMaterialReadiness(value: never): never {
  throw new Error(`Unsupported material readiness state: ${String((value as any)?.kind || '')}`);
}
```

## Current Risk Inventory

These are the signing/session surfaces most likely to benefit from exhaustive
unions.

### 1. Signing Session Planning

Files:

```text
packages/sdk-web/src/core/signingEngine/session/planning/planner.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts
```

Current risk:

- `readiness.status` checks are split across `if` blocks.
- plan construction can discard future readiness states unless every branch is
  audited manually.
- email/passkey/auth-unavailable paths overlap with budget and material states.

Target:

- introduce `SigningSessionPlanningInput` as a discriminated union;
- introduce `SigningSessionPlanningResult` with `ready`, `step_up_required`,
  `material_restore_required`, `budget_rejected`, and `not_ready`;
- make the planner switch over every readiness branch.

Acceptance:

- no authority-bearing planning function switches through optional bags;
- adding a `SigningSessionReadiness` branch breaks planner type fixtures;
- tests cover `ready`, `auth_unavailable`, `status_unavailable`,
  `budget_unknown`, `expired`, `exhausted`, and material-pending branches.

### 2. Budget Admission And Finalization

Files:

```text
packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator.ts
packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.ts
packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.ts
```

Current risk:

- several paths compare `status.status` with `if` conditions;
- reservation/finalization commands can be mixed through broad object shapes;
- zero-spend, reserved-spend, and externally-consumed spend are semantically
  different states.
- admission and finalization can drift when budget inputs carry session ids
  separately from the exact lane authority.

Target:

- model finalization as a strict union:

```ts
type WalletBudgetFinalizationCommand =
  | { kind: 'reserved_success'; reservation: WalletBudgetReservation; spend: WalletBudgetSpend }
  | { kind: 'unreserved_success'; spend: WalletBudgetSpend }
  | { kind: 'externally_consumed_success'; spend: ExternallyConsumedWalletBudgetSpend }
  | { kind: 'zero_spend_success'; spend: ZeroWalletBudgetSpend }
  | { kind: 'failure_release'; reservation: WalletBudgetReservation; error: Error };
```

- switch over every command in finalization and sync code;
- require `TrustedActiveSigningBudgetStatus` for admission;
- run budget unions after exact lane admission from Refactor 79;
- derive reservation `thresholdSessionIds` from `ExactSigningLaneIdentity`;
- use implicit NEAR `walletId` as the budget owner and `nearAccountId` only for
  NEAR signing.

Acceptance:

- no admission code reads display-only `policyHint`;
- no finalization branch uses optional `reservation?` to imply behavior;
- no caller-provided threshold-session list can alter exact lane reservation;
- duplicate exact-lane record lookup blocks budget admission;
- type fixtures reject `reserved_success` without a reservation and
  `zero_spend_success` with positive spend.

### 3. Ed25519 Material Readiness And Restore

Files:

```text
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PreConfirmMaterialReadiness.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts
packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
```

Current risk:

- persisted record optionals can look signable unless classified;
- pending, restoreable, stale, and runtime-validated material can be conflated;
- current durable restore requires exact grant/session/material checks;
- Ed25519 material branches can become ambiguous after implicit accounts unless
  they carry exact `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId`.

Target:

- keep `RouterAbEd25519PersistedSigningRecordState` as the boundary classifier;
- downstream readiness branches carry or derive
  `ExactEd25519SigningLaneIdentity`;
- define narrow downstream inputs:
  - `Ed25519RuntimeValidatedSigningMaterial`
  - `Ed25519RestoreableMaterial`
  - `Ed25519UnsealAuthorizationRequired`
  - `Ed25519MaterialUnavailable`
- convert every material readiness decision to exhaustive switches.

Acceptance:

- final signing accepts only runtime-validated material;
- lazy restore accepts only restoreable material plus unseal authorization;
- exact restore checks wallet id, NEAR account id, Ed25519 key scope id,
  signing grant, threshold session, and material binding facts;
- guards reject truthy material handle checks as signing authority.

### 4. NEAR Transaction, NEP-413, And Delegate Signing

Files:

```text
packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts
```

Current risk:

- step-up authorization branches mix passkey, Email OTP, and warm-session
  behavior through nested `if/else`;
- retry and repair errors are handled locally in three flows;
- modal/auth/material behavior can drift between the three paths.

Target:

- create shared `NearEd25519SigningOperation`:

```ts
type NearEd25519SigningOperation =
  | {
      kind: 'near_transaction';
      signing: ExactEd25519SigningLaneIdentity;
      requiredSignatureUses: number;
      payload: NearTxPayload;
    }
  | {
      kind: 'nep413_message';
      signing: ExactEd25519SigningLaneIdentity;
      requiredSignatureUses: 1;
      payload: Nep413Payload;
    }
  | {
      kind: 'delegate_action';
      signing: ExactEd25519SigningLaneIdentity;
      requiredSignatureUses: 1;
      payload: DelegatePayload;
    };
```

- create shared `NearSigningStepUpResult`:

```ts
type NearSigningStepUpResult =
  | { kind: 'warm_session_reused'; auth: WarmSessionAuth }
  | { kind: 'passkey_reauthenticated'; credential: WebAuthnAuthenticationCredential }
  | { kind: 'email_otp_reauthenticated'; auth: EmailOtpSigningAuth }
  | { kind: 'unavailable'; reason: SigningSessionAuthUnavailableReason };
```

- centralize post-step-up material restoration and error mapping.

Acceptance:

- all three flows call one shared operation helper after operation-specific
  payload construction;
- shared NEAR helpers receive the exact Ed25519 signing context, including
  `walletId`, `nearAccountId`, and `nearEd25519SigningKeyId`;
- no duplicated material-repair `if` blocks remain in the three signing files;
- one test matrix covers all operation kinds.

### 5. Confirmation Config, UI Request, And Step-Up Result Lifecycle

Files:

```text
packages/sdk-web/src/core/types/signer-worker.ts
packages/sdk-web/src/core/signingEngine/stepUpConfirmation/channel/confirmTypes.ts
packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts
packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmOperation.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/determineConfirmationConfig.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flowOrchestrator.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/adapters/adapters.ts
packages/sdk-web/src/core/signingEngine/uiConfirm/ui/confirm-ui.ts
packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/preferences.ts
```

Current risk:

- flat `ConfirmationConfig` conflates visible confirmation behavior with silent
  mode. In silent mode, current code accepts `behavior` and `autoProceedDelay`
  but ignores them;
- iframe and preference handlers merge raw partial config into SDK state;
- confirmation decisions use `confirmed: boolean` plus optional credential, OTP,
  nonce, and transaction fields;
- passkey, Email OTP, and warm-session auth routes are rejected by runtime
  assertions instead of branch-specific input types.

Target:

```ts
type NormalizedConfirmationConfig =
  | { kind: 'silent'; uiMode: 'none'; behavior?: never; autoProceedDelay?: never }
  | {
      kind: 'interactive';
      uiMode: 'modal' | 'drawer';
      behavior: 'requireClick';
      autoProceedDelay?: never;
    }
  | {
      kind: 'auto_proceed';
      uiMode: 'modal' | 'drawer';
      behavior: 'skipClick';
      autoProceedDelay: number;
    };

type UserConfirmDecision =
  | { kind: 'confirmed_transaction'; transactionContext: TransactionContext; auth: StepUpAuthResult }
  | { kind: 'confirmed_signature_only'; auth: StepUpAuthResult }
  | { kind: 'confirmed_intent_digest'; intentDigest: string; auth: StepUpAuthResult }
  | { kind: 'cancelled'; reason: UserCancelledReason }
  | { kind: 'failed'; error: string };

type SigningConfirmationAuthRoute =
  | { kind: 'warm_session'; plan: WarmSessionAuthPlan }
  | { kind: 'passkey_reauth'; plan: PasskeyReauthPlan; webauthnChallenge: WebAuthnChallenge }
  | { kind: 'email_otp_reauth'; plan: EmailOtpReauthPlan; prompt: EmailOtpPrompt };
```

Acceptance:

- raw iframe/preference confirmation config is parsed once at the boundary;
- raw `uiMode: 'none'` normalizes to the silent branch regardless of supplied
  `behavior` or `autoProceedDelay`;
- no core code reads `behavior` or `autoProceedDelay` from the silent branch;
- interactive require-click config cannot carry auto-proceed delay;
- confirmation UI mapping uses exhaustive switches;
- passkey reauth cannot carry an Email OTP prompt;
- Email OTP reauth cannot carry a WebAuthn challenge;
- warm-session reuse cannot carry fresh reauth prompts;
- type fixtures reject invalid config and auth-route combinations.

### 6. Nonce Lease And Lane Lifecycle

Files:

```text
packages/sdk-web/src/core/signingEngine/nonce/NonceCoordinator.ts
packages/sdk-web/src/core/signingEngine/nonce/nonceTypes.ts
packages/sdk-web/src/core/signingEngine/nonce/nonceLeaseState.ts
packages/sdk-web/src/core/signingEngine/nonce/nearNonceLane.ts
packages/sdk-web/src/core/signingEngine/nonce/evmNonceLane.ts
```

Current risk:

- nonce leases use a broad state string with shared fields for every state;
- NEAR and EVM lane state uses nullable mutable bags;
- lease transitions are centralized, but invalid transitions are still
  representable at the type level;
- direct NEAR execution readiness can drift from nonce/access-key lifecycle.

Target:

```ts
type NonceLeaseLifecycle =
  | { kind: 'reserved'; lease: ReservedNonceLease }
  | { kind: 'signed'; lease: SignedNonceLease }
  | { kind: 'broadcast_accepted'; lease: BroadcastAcceptedNonceLease }
  | { kind: 'broadcast_rejected'; lease: BroadcastRejectedNonceLease }
  | { kind: 'finalized'; lease: FinalizedNonceLease }
  | { kind: 'released'; lease: ReleasedNonceLease }
  | { kind: 'expired'; lease: ExpiredNonceLease };

type NearNonceLaneLifecycle =
  | { kind: 'uninitialized' }
  | { kind: 'access_key_lookup_pending'; walletId: WalletId; nearAccountId: NearAccountId }
  | { kind: 'implicit_unfunded'; walletId: WalletId; nearAccountId: ImplicitNearAccountId }
  | { kind: 'access_key_bound'; context: NearAccessKeyBoundContext }
  | { kind: 'lookup_failed'; error: NearAccountLookupFailure };
```

Acceptance:

- lease transitions switch over current lifecycle and requested transition;
- impossible transitions return typed rejection results;
- NEAR lane state cannot contain account data while marked uninitialized;
- implicit unfunded readiness is a first-class lane branch;
- direct transaction signing consumes a nonce/access-key-ready branch.

### 7. Passkey Credential Boundary And PRF/Unseal Authorization

Files:

```text
packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts
packages/sdk-web/src/core/signingEngine/session/passkey/prfCache.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts
packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts
packages/sdk-web/src/core/signingEngine/session/passkey/warmSessionHydration.ts
```

Current risk:

- setup/export PRF handling and signing restore unseal authorization are close
  enough that legacy helpers can be accidentally reused;
- some helpers return raw strings or optional values instead of branch-specific
  capabilities.

Target:

```ts
type PasskeyCredentialBoundaryCapability =
  | { kind: 'setup_export_prf_handle'; handle: WorkerOwnedPrfHandle }
  | { kind: 'material_seal_authorization'; authorization: MaterialSealAuthorization }
  | { kind: 'material_unseal_authorization'; authorization: MaterialUnsealAuthorization }
  | { kind: 'credential_unavailable'; reason: CredentialUnavailableReason };
```

Acceptance:

- signing restore cannot import setup/export PRF helpers;
- unseal authorization is represented as an opaque capability branch;
- type fixtures reject raw `prfFirstB64u` in normal signing restore modules.

### 8. Email OTP Session And Restore Lifecycle

Files:

```text
packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/coordinatorRuntime.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedSessionRegistry.ts
```

Current risk:

- Email OTP account-control state, signing-session auth, ECDSA companion state,
  and Ed25519 material state have different meanings;
- fallback source branches can mix current and sealed records if not typed
  strictly;
- optional companion attachment must remain observable and non-authoritative;
- app-session JWT reuse can accidentally influence signing material if the
  lifecycle branch does not also carry exact lane identity.

Target:

- keep `EmailOtpEcdsaRestoreSource` as a strict source union;
- add a higher-level `EmailOtpSigningSessionLifecycle`:

```ts
type EmailOtpSigningSessionLifecycle =
  | { kind: 'account_control_verified'; routeAuth: AppOrWalletSessionAuth }
  | {
      kind: 'signing_session_ready';
      identity: ExactSigningLaneIdentity;
      auth: EmailOtpSigningSessionAuth;
    }
  | { kind: 'companion_restore_available'; source: EmailOtpEcdsaRestoreSource }
  | {
      kind: 'ed25519_reconstruction_required';
      identity: ExactEd25519SigningLaneIdentity;
      recovery: RecoveryCodeAuthorization;
    }
  | { kind: 'not_available'; reason: EmailOtpSessionUnavailableReason };
```

Acceptance:

- Email OTP direct signing restore receives opaque unseal authorization only;
- every Email OTP branch that can influence signing material carries exact lane
  identity;
- wallet-scoped app-session JWT cache reuse cannot change the exact lane used
  for signing/export;
- companion attachment diagnostics cannot become material readiness;
- current/sealed branch mixing remains rejected by type fixtures.

### 9. Sealed Recovery And Durable Restore

Files:

```text
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts
packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts
```

Current risk:

- accepted, rejected, not-applicable, deferred, ready, and restored states cross
  persistence boundaries;
- successful-restore cache and account-wide restore must not suppress exact
  record writes;
- current code has some typed unions already, but call sites still use broad
  counters and optional record branches;
- restore code can re-enter broad account/session lookup after a duplicate exact
  record result.

Target:

- preserve `NormalizeSealedRecoveryRecordResult`;
- introduce `RestoreAttemptOutcome`:

```ts
type RestoreAttemptOutcome =
  | { kind: 'restored'; identity: MaterialRestoreIdentity; record: SealedRecoveryRecord }
  | { kind: 'already_ready'; identity: MaterialRestoreIdentity; record: SealedRecoveryRecord }
  | {
      kind: 'deferred';
      identity: MaterialRestoreIdentity;
      record: SealedRecoveryRecord;
      reason: RestoreDeferredReason;
    }
  | { kind: 'rejected'; rejection: RejectedSealedRecoveryRecord }
  | {
      kind: 'duplicate_records';
      identity: MaterialRestoreIdentity;
      details: DuplicateRecordSummary[];
    }
  | { kind: 'not_applicable'; identity?: MaterialRestoreIdentity };
```

Acceptance:

- exact restore loops switch over `RestoreAttemptOutcome`;
- counters are derived from outcomes, not incremented by scattered `if` blocks;
- duplicate exact restore records return a typed `duplicate_records` outcome and
  stop the authority path;
- restore retry keeps the original exact identity;
- successful cache keys include durable record version and exact purpose.

### 10. Login, Wallet Unlock, And Local Session Restoration

Files:

```text
packages/sdk-web/src/SeamsWeb/operations/auth/login.ts
packages/sdk-web/src/SeamsWeb/operations/auth/walletAuth.ts
packages/sdk-web/src/SeamsWeb/operations/session/restoreLocalLoginState.ts
packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
```

Current risk:

- login has several nested lifecycle checks;
- unlock failure must not commit active SDK state;
- local restore/display state must not imply active signing readiness.

Target:

```ts
type WalletUnlockLifecycle =
  | { kind: 'preflight' }
  | { kind: 'wallet_authorized'; session: WalletAuthorization }
  | { kind: 'signing_lanes_warming'; authorization: WalletAuthorization }
  | { kind: 'active_session_ready'; walletSession: WalletSession }
  | { kind: 'failed_before_commit'; error: Error }
  | { kind: 'cancelled_by_user' };
```

Acceptance:

- active session commit only accepts `active_session_ready`;
- failure branches cannot call session commit helpers;
- display-only restored local state remains separate from signing authority.

### 11. React SDK Flow And Display-Only State

Files:

```text
packages/sdk-web/src/react/types.ts
packages/sdk-web/src/react/context/useSDKFlowRuntime.ts
packages/sdk-web/src/react/context/useLoginStateRefresher.ts
packages/sdk-web/src/react/context/useWalletIframeLifecycle.ts
packages/sdk-web/src/react/components/AccountMenuButton
packages/sdk-web/src/react/components/PasskeyAuthMenu
```

Current risk:

- React SDK flow state is a flat `kind` plus `status` object;
- success, error, account, and event fields can be combined in invalid ways;
- display-only login state can accidentally become a source of signing
  authority if wallet and NEAR account identity are collapsed;
- old tests can keep invalid display shapes alive.

Target:

```ts
type SDKFlowState =
  | { kind: 'idle'; seq: number; eventsText: '' }
  | { kind: 'running'; flow: 'login' | 'register' | 'sync'; seq: number; accountId?: string; eventsText: string }
  | { kind: 'succeeded'; flow: 'login' | 'register' | 'sync'; seq: number; accountId?: string; eventsText: string }
  | { kind: 'failed'; flow: 'login' | 'register' | 'sync'; seq: number; accountId?: string; eventsText: string; error: string };
```

Acceptance:

- React flow state is display-only and cannot be passed to core signing APIs;
- success states cannot carry an error;
- failure states require an error;
- account menu subcomponents consume explicit wallet/session bindings rather
  than deriving wallet identity from NEAR account display values.

### 12. Wallet Iframe Payload Boundaries

Files:

```text
packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts
packages/sdk-web/src/SeamsWeb/walletIframe/host/requestRouter.ts
packages/sdk-web/src/SeamsWeb/walletIframe/host/runtimeLoader.ts
packages/sdk-web/src/SeamsWeb/walletIframe/coordinator.ts
```

Current risk:

- iframe payloads are untrusted request/response boundaries;
- broad route payload parsing can discard new states;
- activation payloads have historically been easy to treat as loosely typed.

Target:

- parse every iframe request/result once into strict route unions;
- use exhaustive switch in host/client routers;
- keep unknown payload fields out of core session state.

Acceptance:

- every wallet iframe request type has an exhaustive switch;
- every activation `READY` / `STARTED` payload parser returns a discriminated
  result;
- type fixtures reject missing route discriminants and invalid branch combos.

### 13. ECDSA Tempo/EVM Signing And HSS Boundaries

Files:

```text
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily
packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts
packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts
packages/sdk-web/src/core/signingEngine/threshold/ecdsa
```

Current risk:

- ECDSA provision, reconnect, export, and signing lifecycle states overlap;
- EVM and Tempo signing share ECDSA authority but differ in request shape;
- first-candidate or fallback record selection is risky in authority paths.

Target:

```ts
type EcdsaSigningLifecycle =
  | { kind: 'runtime_validated'; record: EcdsaRuntimeValidatedRecord }
  | { kind: 'reconnect_available'; auth: EcdsaReconnectAuth }
  | { kind: 'fresh_provision_required'; reason: EcdsaProvisionReason }
  | { kind: 'sealed_restore_available'; source: EcdsaRestoreSource }
  | { kind: 'not_available'; reason: EcdsaUnavailableReason };
```

Acceptance:

- reconnect and fresh provision are separate states;
- authority-bearing JWT selection is exact or fails closed;
- Tempo/EVM signing cannot borrow fields from display or stale records.

### 14. Public SDK Result Boundaries

Files:

```text
packages/sdk-web/src/core/types/seams.ts
packages/sdk-web/src/core/types/sdkPublicResults.ts
packages/sdk-web/src/SeamsWeb/publicApi/types.ts
packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts
packages/sdk-web/src/SeamsWeb/operations/auth/login.ts
packages/sdk-web/src/SeamsWeb/operations/near
packages/sdk-web/src/SeamsWeb/operations/recovery
```

Current risk:

- public result shapes use `success: boolean` or status strings with optional
  data fields;
- success branches can omit required wallet, session, or operation data;
- failure branches can carry success-only fields;
- internal strict unions can be flattened back into ambiguous public shapes.

Target:

- convert public SDK results to discriminated unions where breaking changes are
  acceptable;
- where a compatibility wrapper is intentionally retained at a public boundary,
  isolate it in one adapter and keep strict internal results behind it;
- parse public command inputs into strict internal unions once.

Acceptance:

- `LoginResult`, `RegistrationResult`, `ActionResult`, `SigningSessionStatus`,
  NEP-413 results, and recovery/export results cannot represent success with
  missing required data;
- failure branches carry explicit error data and cannot carry success payloads;
- public adapters cannot feed flattened result objects back into core logic.

### 15. Server Route And Router A/B Authority Boundaries

Files:

```text
packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
packages/sdk-server-ts/src/router/emailOtpRouteHandlers.ts
packages/sdk-server-ts/src/router/signingBudgetStatus.ts
packages/sdk-server-ts/src/core/AuthService.ts
packages/sdk-server-ts/src/core/ThresholdService
```

Current risk:

- server route bodies are untrusted raw shapes;
- Router A/B admission and Email OTP routes use sequential validation chains
  that can drift as lifecycle states are added;
- budget/status and threshold service admission must preserve exact lane
  identity from Refactor 79;
- server code can reintroduce wallet/NEAR/account/rp identity collapse if
  branch-specific route commands are absent.

Target:

- parse route bodies into strict route command unions at the router boundary;
- use exhaustive switches for Router A/B worker admission outcomes;
- keep AuthService and ThresholdService inputs narrow and already parsed;
- make server budget/status responses discriminated and exact-lane aware.

Acceptance:

- raw route bodies do not reach core AuthService or ThresholdService methods;
- Router A/B signing admission has explicit accepted, rejected, duplicate,
  unavailable, and malformed branches;
- Email OTP route commands distinguish account-control, signing auth, recovery,
  and restore flows;
- server guards cover authority-bearing route files or the plan explicitly
  marks a path display/repair-only.

## Implementation Phases

### Phase 1: Inventory And Guard Baseline

Add a guard file:

```text
tests/unit/refactor80SwitchCase.guard.unit.test.ts
```

Initial guard duties:

- list all current lifecycle hotspots by file and marker;
- fail if new broad fallback markers appear in signing/session code;
- allow existing markers only through an explicit inventory with owner phase.

Initial grep terms:

```bash
rg -n "\\bif \\(|else if|\\.kind ===|\\.kind !==|\\.status ===|\\.status !==|\\?\\?|\\?\\.|as any|catch \\(.*\\).*return|candidates\\[0\\]|\\|\\| .*record|policyHint" \
  packages/sdk-web/src/core/signingEngine \
  packages/sdk-web/src/SeamsWeb/operations/auth \
  packages/sdk-web/src/SeamsWeb/operations/session \
  packages/sdk-web/src/SeamsWeb/walletIframe \
  packages/sdk-web/src/react \
  packages/sdk-server-ts/src/router \
  packages/sdk-server-ts/src/core/ThresholdService \
  -g '*.ts'
```

This grep is intentionally noisy. The guard should only pin high-risk control
flow markers. Parser boundary files may keep local null checks when they
immediately return typed parse failures.

### Phase 2: Shared Exhaustiveness Utilities

Audit existing `assertNever` helpers. Either:

- keep local `assertNeverX()` helpers where error messages need domain context;
  or
- add one tiny internal helper:

```text
packages/sdk-web/src/core/types/assertNever.ts
```

Do not export it publicly.

Acceptance:

- no `default: return null` in domain lifecycle switches;
- default branches call `assertNeverX(value)`;
- type fixtures prove future branch additions break switch sites.

### Phase 3: Confirmation Config And Step-Up Decision Lifecycle

Tasks:

- replace flat `ConfirmationConfig` with a strict union;
- parse raw iframe/preference confirmation config at the boundary;
- convert `UserConfirmDecision` and worker confirmation responses into result
  unions;
- make `SigningConfirmationAuthRoute` branch-specific for warm session,
  passkey reauth, and Email OTP reauth;
- delete runtime assertions that duplicate type-level branch constraints after
  the boundary parser.

Validation:

```bash
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line \
  unit/confirmTxFlow.defensivePaths.test.ts \
  unit/walletIframe.preferences.unit.test.ts
```

### Phase 4: Planning And Budget

Start with planning and budget because they control admission.

Tasks:

- convert `planner.ts` readiness handling to exhaustive switch;
- convert `BudgetCoordinator` finalization to command-specific switch;
- add `budget.typecheck.ts` fixtures for invalid branch combinations.

Validation:

```bash
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line \
  unit/walletSessionReadiness.gate.unit.test.ts \
  unit/walletSessionBudgetReservation.store.unit.test.ts
```

### Phase 5: Nonce Lease And Lane Lifecycle

Tasks:

- convert `NonceLease` into lifecycle-specific branches;
- convert NEAR and EVM nonce lane state from nullable bags to lifecycle unions;
- make invalid lease transitions return typed rejection results;
- connect direct NEAR transaction execution to the access-key-ready nonce lane
  branch.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/nearNonceLane.unit.test.ts \
  unit/nonceCoordinator.unit.test.ts
```

If these exact unit files do not exist yet, add focused nonce lifecycle tests
next to the current nonce coverage.

### Phase 6: Ed25519 Material And NEAR Signing

Tasks:

- convert material readiness branches to strict unions;
- centralize NEAR tx / NEP-413 / delegate operation handling;
- delete duplicated repair/auth fallback branches where shared helpers can
  switch over operation kind.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/nearSigning.sessionSelection.unit.test.ts \
  unit/refactor74LegacyFallbacks.guard.unit.test.ts \
  unit/refactor74LoginNoHss.guard.unit.test.ts
```

### Phase 7: Passkey Credential Boundary And PRF/Unseal Authorization

Tasks:

- split setup/export PRF handles from signing material seal/unseal
  authorization;
- ensure signing restore consumes opaque unseal authorization capabilities;
- add guards that reject raw PRF strings in normal signing restore modules.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/passkeyPrfClaim.unit.test.ts \
  unit/thresholdWarmSessionBootstrap.unit.test.ts
```

If these exact files differ, run the nearest passkey PRF and warm-session
bootstrap unit suites.

### Phase 8: Email OTP And Sealed Recovery

Tasks:

- finish Email OTP lifecycle unions around account-control versus signing auth;
- convert sealed recovery restore loops to outcome unions;
- add type fixtures for companion attachment and restore source branches.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/emailOtpWalletSessionCoordinator.unit.test.ts \
  unit/sealedRecovery.methodAdapters.unit.test.ts \
  unit/signingSessionRestoreCoordinator.unit.test.ts
```

### Phase 9: Login And Local Session Restoration

Tasks:

- model wallet unlock lifecycle as a union;
- isolate display-only restored local state from active signing authority;
- require active-session commit helpers to accept only the ready branch;
- update recovery/sync/link-device callers to pass resolved wallet bindings.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/signingSession.state.unit.test.ts
```

Run browser evidence when this phase changes wallet unlock.

### Phase 10: React SDK Flow And Display State

Tasks:

- convert React `SDKFlowState` to a display lifecycle union;
- ensure React login state carries wallet/session identity explicitly;
- update account-menu and auth-menu subcomponents to consume explicit
  wallet/session bindings;
- delete or rewrite tests that rely on invalid display state combinations.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/recoveryCodesModal.behavior.unit.test.ts \
  unit/seamsWeb.emailOtpIframe.unit.test.ts
```

### Phase 11: Wallet Iframe Boundaries

Tasks:

- parse iframe request/result payloads into strict route unions;
- convert host and client routers to exhaustive switches;
- add runtime parsers for serialized exact signing/export identity payloads;
- reject missing route discriminants and invalid branch combinations at the
  iframe boundary.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/walletIframe.export.unit.test.ts \
  unit/seamsWeb.emailOtpIframe.unit.test.ts
```

Run browser evidence when this phase changes iframe activation or wallet unlock.

### Phase 12: ECDSA Tempo/EVM Lifecycle

Tasks:

- split reconnect, fresh provision, sealed restore, and runtime-validated states;
- convert Tempo/EVM signing admission to exhaustive ECDSA lifecycle switches;
- make exact route/JWT selection branch-specific.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/evmFamilyEcdsaIdentity.unit.test.ts \
  unit/walletSessionBudgetReservation.store.unit.test.ts
```

### Phase 13: Public SDK Result Boundaries

Tasks:

- convert public `success: boolean` and status-plus-optional results to
  discriminated unions;
- keep compatibility adapters only at explicit public boundaries;
- ensure public adapters cannot feed flattened public result objects back into
  core logic;
- update README/type fixtures that use old result shapes.

Validation:

```bash
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line \
  unit/sdkPublicResults.typecheck.test.ts \
  unit/walletRegistration.typecheck.test.ts
```

If the exact typecheck tests do not exist, add them with the public result type
fixtures in this phase.

### Phase 14: Server Route And Router A/B Authority Boundaries

Tasks:

- parse Router A/B and Email OTP route bodies into strict route command unions;
- convert Router A/B signing admission outcomes to exhaustive switches;
- ensure server budget/status responses preserve exact lane identity;
- add guards for raw route bodies reaching AuthService or ThresholdService.

Validation:

```bash
pnpm -C packages/sdk-server-ts run type-check
pnpm -C tests exec playwright test --reporter=line \
  unit/routerAbEd25519.walletSessionState.unit.test.ts \
  unit/emailSubjectParsing.test.ts
```

### Phase 15: Bundle And Type-Only Import Audit

Tasks:

- run a source guard that rejects non-type imports from `*.types.ts`;
- inspect generated bundle diff only if runtime helpers were added broadly;
- verify no internal lifecycle union leaked into public API unintentionally.

Suggested grep:

```bash
rg -n "from '.*\\.types'|from \\\".*\\.types\\\"" packages/sdk-web/src -g '*.ts'
```

Expected:

- `import type` for type-only modules;
- value imports only from `*.builders.ts`, `*.parsers.ts`, or established
  runtime modules.

### Phase 16: Test And Fixture Cleanup

Tasks:

- delete tests that protect invalid flat lifecycle shapes;
- rewrite fixtures that use broad object spreads, unsafe casts, or old
  confirmation config combinations;
- keep compatibility coverage only at intentional public/request/persistence
  boundaries;
- add `@ts-expect-error` fixtures for each rejected branch combination.

Validation:

```bash
pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
pnpm -C tests exec playwright test --reporter=line unit/refactor80SwitchCase.guard.unit.test.ts
```

## Type Fixture Plan

Add or extend fixtures:

```text
packages/sdk-web/src/core/signingEngine/session/planning/planning.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts
packages/sdk-web/src/core/types/confirmationConfig.typecheck.ts
packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmationDecision.typecheck.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/nearSigning.typecheck.ts
packages/sdk-web/src/core/signingEngine/nonce/nonceLifecycle.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.typecheck.ts
packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/evmSigningLifecycle.typecheck.ts
packages/sdk-web/src/core/types/sdkPublicResults.typecheck.ts
packages/sdk-web/src/SeamsWeb/walletIframe/client/walletIframe.typecheck.ts
packages/sdk-web/src/react/reactDisplayState.typecheck.ts
packages/sdk-server-ts/src/router/routerCommand.typecheck.ts
```

Fixture rules:

- use `@ts-expect-error` for invalid branch combinations;
- assert every switch over exported domain unions is exhaustive;
- reject broad object spreads for authority-bearing lifecycle objects;
- reject optional identity/auth/session/material fields in core domain inputs;
- reject normalized silent confirmation branches that carry `behavior` or
  `autoProceedDelay`;
- accept raw boundary confirmation config with `uiMode: 'none'` plus either
  behavior, then prove it normalizes to the silent branch;
- reject require-click UI branches that carry auto-proceed delay;
- reject `UserConfirmDecision` branches that omit the required payload for the
  decision kind;
- reject nonce lease lifecycle branches carrying fields from another state;
- reject public success results with missing success payloads and public failure
  results carrying success payloads;
- reject React display states that can be passed to core signing APIs.

## Source Guard Plan

`tests/unit/refactor80SwitchCase.guard.unit.test.ts` should check:

- domain lifecycle switches call an `assertNever` helper;
- no new `as any` casts appear in signing/session lifecycle directories;
- `*.types.ts` modules are imported with `import type`;
- authority-bearing functions do not accept public/persistence raw shapes;
- authority-bearing functions do not accept raw iframe payloads, raw public SDK
  inputs, raw route bodies, raw worker messages, or raw decoded JWT payloads;
- display-only helpers include `Display` or `Ui` in the name;
- repair-only helpers include `Repair` in the name;
- `policyHint` appears only in display helpers;
- `candidates[0]` appears only inside display/repair helpers or
  `selectOnly*` helpers that first prove exactly one candidate;
- helpers with `Exact` in the name cannot use `candidates[0]` unless they return
  a typed duplicate result before selecting;
- confirmation config code cannot merge raw or partial confirmation config into
  SDK state outside the boundary parser;
- internal confirmation lifecycle code cannot read `behavior` or
  `autoProceedDelay` from the silent branch;
- confirmation decision code cannot branch on `confirmed: boolean` in core
  lifecycle modules;
- nonce lane state cannot use nullable `walletId`, `accountId`, `publicKey`,
  `transactionContext`, or in-flight flags as lifecycle authority;
- public result adapters cannot expose `success: boolean` plus success-only
  optional fields after Phase 13;
- React display state cannot be imported by core signing/session modules;
- server route handlers cannot pass raw request bodies directly to AuthService
  or ThresholdService.

Guard inventory must cover:

```text
packages/sdk-web/src/core/signingEngine
packages/sdk-web/src/core/types
packages/sdk-web/src/SeamsWeb/operations
packages/sdk-web/src/SeamsWeb/publicApi
packages/sdk-web/src/SeamsWeb/walletIframe
packages/sdk-web/src/react
packages/sdk-server-ts/src/router
packages/sdk-server-ts/src/core/ThresholdService
```

Parser-boundary allowlists must be narrow and named. Acceptable boundary names
include `parse*`, `normalize*Boundary*`, `decode*`, `fromRaw*`, and
`toPublic*Result`. Core lifecycle files should not appear in parser allowlists.

## Done Criteria

- [x] Signing/session lifecycle hotspots have discriminated domain states.
- [x] Core signing, restore, budget, and auth planning functions switch
  exhaustively over those states.
- [x] Boundary parsers convert raw request/persistence data into strict internal
  types once.
- [x] Authority-bearing lifecycle types import canonical exact-lane identity and do
  not define parallel lane identity structs.
- [x] Confirmation config, confirmation decisions, nonce leases, public results,
  React display state, and server route commands have strict branch-specific
  types.
- [x] Type fixtures reject invalid branch combinations.
- [x] Source guards prevent high-risk fallback patterns from returning.
- [x] Existing Refactor 74, 76, 78, and 79 evidence still passes.
- [x] Bundle audit confirms type-only modules are erased or only runtime helpers
  that replaced existing logic remain.

## Review: Implementation Pass, 2026-06-25

Implemented:

- confirmation config normalization and confirmation decisions use
  branch-specific internal state;
- nonce lease lifecycle, React SDK display state, public result shapes, and
  sealed recovery exact restore inputs have strict unions and type fixtures;
- server route bodies for sync-account, link-device, email-recovery, auth, and
  Router A/B threshold ECDSA key identities parse into command unions before
  service calls;
- stale Router A/B Ed25519 HSS email OTP registration requests are rejected by
  discriminant instead of falling into generic HSS finalize parsing;
- source guards cover confirmation config, nonce lifecycle, React display
  state, public result shapes, server route parser boundaries, and legacy
  Ed25519 HSS command rejection.

Validation run:

```bash
pnpm -C packages/sdk-web -s type-check
pnpm -C packages/sdk-server-ts -s type-check
pnpm -C tests exec playwright test --reporter=line unit/refactor80SwitchCase.guard.unit.test.ts
pnpm -C tests exec playwright test -c playwright.relayer.config.ts --reporter=line \
  relayer/express-router.test.ts \
  relayer/cloudflare-router.test.ts \
  relayer/link-device.prepare.test.ts \
  relayer/email-recovery.prepare.test.ts \
  relayer/threshold-ed25519.scheme-dispatch.test.ts
pnpm -C tests exec playwright test --reporter=line \
  unit/emailOtpWalletSessionCoordinator.unit.test.ts \
  unit/sealedRecovery.methodAdapters.unit.test.ts \
  unit/signingSessionRestoreCoordinator.unit.test.ts
pnpm -C tests exec playwright test --reporter=line \
  unit/recoveryCodesModal.behavior.unit.test.ts \
  unit/seamsWeb.emailOtpIframe.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/evmFamilyEcdsaIdentity.unit.test.ts
pnpm -C tests exec playwright test --reporter=line \
  unit/confirmationConfig.normalization.unit.test.ts \
  unit/confirmTxFlow.determineConfirmationConfig.test.ts \
  unit/touchConfirm.orchestrationBridge.unit.test.ts \
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts
pnpm -C tests exec playwright test --reporter=line \
  unit/walletSessionReadiness.gate.unit.test.ts \
  unit/walletSessionBudgetReservation.store.unit.test.ts \
  unit/nonceCoordinator.unit.test.ts
pnpm -C tests exec playwright test --reporter=line \
  unit/nearSigning.sessionSelection.unit.test.ts \
  unit/refactor74LegacyFallbacks.guard.unit.test.ts \
  unit/refactor74LoginNoHss.guard.unit.test.ts \
  unit/routerAbEd25519.walletSessionState.unit.test.ts
pnpm -C tests exec playwright test --reporter=line unit/emailSubjectParsing.test.ts
```

Results:

- package type-checks passed;
- Refactor 80 guard passed: 14 tests;
- relayer router coverage passed: 172 tests;
- focused SDK/session/signing coverage passed with the expected skipped backend
  contract cases in the nonce/budget cluster.
