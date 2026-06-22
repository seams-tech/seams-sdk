# Refactor 77: Exhaustive Domain State With Switch/Case

Date created: June 22, 2026

Status: planned

Related plans:

- [refactor-74-login-no-hss.md](./refactor-74-login-no-hss.md)
- [refactor-75-simplify-ed25519.md](./refactor-75-simplify-ed25519.md)
- [refactor-76-branded-keys.md](./refactor-76-branded-keys.md)

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
- core signing/session code accepts precise internal domain types.

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
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/nearSigning.types.ts
packages/sdk-web/src/SeamsWeb/operations/auth/login.types.ts
packages/sdk-web/src/SeamsWeb/walletIframe/client/walletIframe.types.ts
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
- require `TrustedActiveSigningBudgetStatus` for admission.

Acceptance:

- no admission code reads display-only `policyHint`;
- no finalization branch uses optional `reservation?` to imply behavior;
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
- current durable restore requires exact grant/session/material checks.

Target:

- keep `RouterAbEd25519PersistedSigningRecordState` as the boundary classifier;
- define narrow downstream inputs:
  - `Ed25519RuntimeValidatedSigningMaterial`
  - `Ed25519RestoreableMaterial`
  - `Ed25519UnsealAuthorizationRequired`
  - `Ed25519MaterialUnavailable`
- convert every material readiness decision to exhaustive switches.

Acceptance:

- final signing accepts only runtime-validated material;
- lazy restore accepts only restoreable material plus unseal authorization;
- exact restore checks wallet, signing grant, threshold session, and material
  binding facts where available;
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
  | { kind: 'near_transaction'; requiredSignatureUses: number; payload: NearTxPayload }
  | { kind: 'nep413_message'; requiredSignatureUses: 1; payload: Nep413Payload }
  | { kind: 'delegate_action'; requiredSignatureUses: 1; payload: DelegatePayload };
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
- no duplicated material-repair `if` blocks remain in the three signing files;
- one test matrix covers all operation kinds.

### 5. Passkey Credential Boundary And PRF/Unseal Authorization

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

### 6. Email OTP Session And Restore Lifecycle

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
- optional companion attachment must remain observable and non-authoritative.

Target:

- keep `EmailOtpEcdsaRestoreSource` as a strict source union;
- add a higher-level `EmailOtpSigningSessionLifecycle`:

```ts
type EmailOtpSigningSessionLifecycle =
  | { kind: 'account_control_verified'; routeAuth: AppOrWalletSessionAuth }
  | { kind: 'signing_session_ready'; auth: EmailOtpSigningSessionAuth }
  | { kind: 'companion_restore_available'; source: EmailOtpEcdsaRestoreSource }
  | { kind: 'ed25519_reconstruction_required'; recovery: RecoveryCodeAuthorization }
  | { kind: 'not_available'; reason: EmailOtpSessionUnavailableReason };
```

Acceptance:

- Email OTP direct signing restore receives opaque unseal authorization only;
- companion attachment diagnostics cannot become material readiness;
- current/sealed branch mixing remains rejected by type fixtures.

### 7. Sealed Recovery And Durable Restore

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
  counters and optional record branches.

Target:

- preserve `NormalizeSealedRecoveryRecordResult`;
- introduce `RestoreAttemptOutcome`:

```ts
type RestoreAttemptOutcome =
  | { kind: 'restored'; record: SealedRecoveryRecord }
  | { kind: 'already_ready'; record: SealedRecoveryRecord }
  | { kind: 'deferred'; record: SealedRecoveryRecord; reason: RestoreDeferredReason }
  | { kind: 'rejected'; rejection: RejectedSealedRecoveryRecord }
  | { kind: 'not_applicable' };
```

Acceptance:

- exact restore loops switch over `RestoreAttemptOutcome`;
- counters are derived from outcomes, not incremented by scattered `if` blocks;
- successful cache keys include durable record version and exact purpose.

### 8. Login, Wallet Unlock, And Local Session Restoration

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

### 9. Wallet Iframe Payload Boundaries

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

### 10. ECDSA Tempo/EVM Signing And HSS Boundaries

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

## Implementation Phases

### Phase 1: Inventory And Guard Baseline

Add a guard file:

```text
tests/unit/refactor77SwitchCase.guard.unit.test.ts
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
  -g '*.ts'
```

This grep is intentionally noisy. The guard should only pin high-risk control
flow markers, not every null check.

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

### Phase 3: Planning And Budget

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

### Phase 4: Ed25519 Material And NEAR Signing

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

### Phase 5: Email OTP And Sealed Recovery

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

### Phase 6: Login And Wallet Iframe Boundaries

Tasks:

- model wallet unlock lifecycle as a union;
- isolate display-only restored local state from active signing authority;
- parse iframe request/result payloads into strict unions at the boundary.

Validation:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/signingSession.state.unit.test.ts
```

Run browser evidence when this phase changes wallet unlock or iframe activation.

### Phase 7: ECDSA Tempo/EVM Lifecycle

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

### Phase 8: Bundle And Public API Audit

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

## Type Fixture Plan

Add or extend fixtures:

```text
packages/sdk-web/src/core/signingEngine/session/planning/planning.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/nearSigning.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.typecheck.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.typecheck.ts
packages/sdk-web/src/SeamsWeb/walletIframe/client/walletIframe.typecheck.ts
```

Fixture rules:

- use `@ts-expect-error` for invalid branch combinations;
- assert every switch over exported domain unions is exhaustive;
- reject broad object spreads for authority-bearing lifecycle objects;
- reject optional identity/auth/session/material fields in core domain inputs.

## Source Guard Plan

`tests/unit/refactor77SwitchCase.guard.unit.test.ts` should check:

- domain lifecycle switches call an `assertNever` helper;
- no new `as any` casts appear in signing/session lifecycle directories;
- `*.types.ts` modules are imported with `import type`;
- authority-bearing functions do not accept public/persistence raw shapes;
- display-only helpers include `Display` or `Ui` in the name;
- `policyHint` appears only in display helpers;
- `candidates[0]` appears only inside helpers whose name includes `Exact`,
  `Sorted`, or `Display`.

## Done Criteria

- Signing/session lifecycle hotspots have discriminated domain states.
- Core signing, restore, budget, and auth planning functions switch
  exhaustively over those states.
- Boundary parsers convert raw request/persistence data into strict internal
  types once.
- Type fixtures reject invalid branch combinations.
- Source guards prevent high-risk fallback patterns from returning.
- Existing Refactor 74 and Refactor 76 evidence still passes.
- Bundle audit confirms type-only modules are erased or only runtime helpers
  that replaced existing logic remain.

