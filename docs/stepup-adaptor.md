# Step-Up Adaptor Refactor Plan

Date created: 2026-05-07
Status: in progress

Current path note: earlier `sessionEmailOtp/` references now map to
`session/emailOtp/`.

## Purpose

Main transaction signing flows should ask for signing authorization through one
operation-facing boundary. They should not route directly to Email OTP, passkey,
or future auth methods.

This plan assumes the preferred naming end state:

- `webauthnAuth/`: low-level WebAuthn/passkey browser primitives only
- `stepUpConfirmation/`: method selection plus prompt/auth-plan orchestration
- `session/emailOtp/`: Email OTP durable lifecycle coordination

Do not begin code moves toward a mixed `walletAuth/` and `webauthnAuth/` state.
The split to `webauthnAuth/` is part of this refactor plan.

The target API is:

```ts
const stepUp = await requireStepUpAuth({
  operation,
  selectedLane,
  policy,
  confirmation,
  methods,
});
```

`requireStepUpAuth` chooses the required auth method from the selected signing
lane, operation policy, readiness state, and available method runners. It then
builds the correct prompt/auth plan, invokes the concrete confirmation runtime,
and returns a narrow authorization result.

## Goals

1. Keep transaction flows linear and auth-method agnostic.
2. Treat passkey, Email OTP, authenticator OTP, magic links, password, and future
   methods through the same operation-facing contract.
3. Keep method-specific prompt/auth-plan construction under
   `stepUpConfirmation/`.
4. Keep method-specific lifecycle coordination in the real owner:
   operation-local code, `session/emailOtp/`, generic `session/`, or a future
   method session folder when it owns durable lifecycle state.
5. Delete direct operation imports of `otpPrompt/*`, `passkeyPrompt/*`, and
   auth-plan enum switches after call sites move.
6. Avoid adapter classes and registries unless they own state or enforce an
   external boundary.
7. Split generic auth-method routing from low-level WebAuthn primitives by
   replacing `walletAuth/` with `webauthnAuth/` plus step-up method selection
   under `stepUpConfirmation/`.

## Target Structure

```text
client/src/core/signingEngine/
  flows/
    signEvmFamily/
      requireEvmFamilyStepUpAuth.ts
      emailOtpSigningSession.ts
      signingFlow.ts
    signNear/
      requireNearStepUpAuth.ts
      signNear.ts
    shared/
      signingStateMachine.ts

  stepUpConfirmation/
    requireStepUpAuth.ts
    methodSelection.ts
    methodRunners.ts
    types.ts
    passkeyPrompt/
      touchIdPrompt.ts
      webauthnKeyRef.ts
    otpPrompt/
      authLane.ts
      signingPrompt.ts
      exportAuthorization.ts
      promptText.ts
    authenticatorOtpPrompt/
    magicLinkPrompt/
    passwordPrompt/

  session/
    ...

  session/
    emailOtp/
      EmailOtpThresholdSessionCoordinator.ts

  webauthnAuth/
    credentials/
    device/
    helpers/

  uiConfirm/
    UiConfirmManager.ts
```

The operation folders may keep small operation-specific builders such as
`requireEvmFamilyStepUpAuth.ts` when they assemble chain-specific method
runners. Shared routing and prompt contracts stay under `stepUpConfirmation/`.
`webauthnAuth/` owns browser credential primitives and nothing above that
level.

## Call Graph

```mermaid
flowchart TD
  SE["SigningEngine.ts"] --> FLOW["flows/signEvmFamily or flows/signNear"]
  FLOW --> PREPARE["prepare operation and select lane"]
  PREPARE --> STEPUP["stepUpConfirmation/requireStepUpAuth"]
  STEPUP --> SELECT["methodSelection"]
  STEPUP --> PROMPT["<method>Prompt/*"]
  STEPUP --> CONFIRM["confirmSigningOperation"]
  CONFIRM --> UI["uiConfirm/*"]
  STEPUP --> RUNNER["method runner port"]
  RUNNER --> EMAILSESSION["session/emailOtp/*"]
  RUNNER --> WEBAUTHN["webauthnAuth/*"]
  FLOW --> THRESHOLD["threshold/*"]
  FLOW --> CHAINS["chains/*"]
  FLOW --> NONCE["nonce/*"]
```

Runtime calls may pass through a method runner to `session/emailOtp/` or
`webauthnAuth/`. Import direction stays controlled by defining runner interfaces
in `stepUpConfirmation/` and passing implementations in from the operation or
assembly layer.

## Dependency Contract

| From | May import | Must not import |
| --- | --- | --- |
| `flows/*` | `stepUpConfirmation/requireStepUpAuth`, `stepUpConfirmation/types`, operation-local runner builders | `stepUpConfirmation/*Prompt`, `SigningAuthPlanKind` switches, concrete `uiConfirm/*` internals |
| `stepUpConfirmation/requireStepUpAuth.ts` | `methodSelection`, `types`, prompt builders, `confirmOperation` | `flows/*`, `SigningEngine.ts`, concrete session lifecycle modules |
| `stepUpConfirmation/*Prompt` | prompt-local types, primitive auth/display types, and `webauthnAuth/*` browser primitives | operation flows, `SigningEngine.ts`, threshold protocol execution |
| `session/emailOtp/*` | `stepUpConfirmation` Email OTP contracts, `session/*`, `threshold/*`, `workerManager/*` | operation flows, `SigningEngine.ts`, passkey prompt internals |
| `webauthnAuth/*` | reusable WebAuthn/passkey browser primitives only | `stepUpConfirmation/*` orchestration logic, operation flows, session lifecycle modules |
| `uiConfirm/*` | confirmation contracts and concrete UI runtime dependencies | operation flows, `SigningEngine.ts` |

## Core Data Types

The adaptor needs explicit state shapes. Required lifecycle fields must be
required on the relevant branch.

```ts
type StepUpMethod =
  | 'passkey'
  | 'email_otp'
  | 'authenticator_otp'
  | 'magic_link'
  | 'password';
```

```ts
type RequireStepUpAuthRequest =
  | RequireEcdsaStepUpAuthRequest
  | RequireEd25519StepUpAuthRequest;

type RequireEcdsaStepUpAuthRequest = {
  curve: 'ecdsa';
  operation: EvmFamilySigningOperationContext;
  selectedLane: SelectedEcdsaSigningLane;
  policy: StepUpAuthPolicy;
  confirmation: StepUpConfirmationRequest;
  methods: StepUpMethodRunners;
};

type RequireEd25519StepUpAuthRequest = {
  curve: 'ed25519';
  operation: NearSigningOperationContext;
  selectedLane: SelectedEd25519SigningLane;
  policy: StepUpAuthPolicy;
  confirmation: StepUpConfirmationRequest;
  methods: StepUpMethodRunners;
};
```

```ts
type StepUpAuthRoute =
  | {
      method: 'passkey';
      prompt: PasskeyPromptPlan;
      runner: PasskeyStepUpRunner;
    }
  | {
      method: 'email_otp';
      prompt: EmailOtpPromptPlan;
      authLane: EmailOtpAuthLane;
      runner: EmailOtpStepUpRunner;
    }
  | {
      method: 'authenticator_otp';
      prompt: AuthenticatorOtpPromptPlan;
      runner: AuthenticatorOtpStepUpRunner;
    }
  | {
      method: 'magic_link';
      prompt: MagicLinkPromptPlan;
      runner: MagicLinkStepUpRunner;
    }
  | {
      method: 'password';
      prompt: PasswordPromptPlan;
      runner: PasswordStepUpRunner;
    };
```

```ts
type StepUpAuthResult =
  | {
      method: 'passkey';
      authorization: PasskeyStepUpAuthorization;
    }
  | {
      method: 'email_otp';
      authorization: EmailOtpStepUpAuthorization;
    }
  | {
      method: 'authenticator_otp';
      authorization: AuthenticatorOtpStepUpAuthorization;
    }
  | {
      method: 'magic_link';
      authorization: MagicLinkStepUpAuthorization;
    }
  | {
      method: 'password';
      authorization: PasswordStepUpAuthorization;
    };
```

During migration, `requireStepUpAuth` may also return an existing warm-session
authorization branch if that keeps the first slice small. The final shape should
make warm-session reuse a session-planning result and reserve step-up branches
for reauth methods.

## Method Runner Pattern

`requireStepUpAuth` should own routing and prompt sequencing. Method runners own
side effects that belong outside generic confirmation routing.

```ts
type StepUpMethodRunners = {
  passkey?: PasskeyStepUpRunner;
  emailOtp?: EmailOtpStepUpRunner;
  authenticatorOtp?: AuthenticatorOtpStepUpRunner;
  magicLink?: MagicLinkStepUpRunner;
  password?: PasswordStepUpRunner;
};
```

Example Email OTP runner:

```ts
type EmailOtpStepUpRunner = {
  prepareChallenge(input: EmailOtpPrepareChallengeInput): Promise<EmailOtpChallenge>;
  complete(input: EmailOtpCompleteInput): Promise<EmailOtpStepUpAuthorization>;
  resend?(input: EmailOtpResendInput): Promise<EmailOtpChallenge>;
};
```

Example passkey runner:

```ts
type PasskeyStepUpRunner = {
  prepare(input: PasskeyPrepareInput): Promise<PasskeyPromptPlan>;
  complete(input: PasskeyCompleteInput): Promise<PasskeyStepUpAuthorization>;
};
```

This keeps `stepUpConfirmation` free of operation-specific Email OTP refresh
logic while still giving operations a single `requireStepUpAuth` call.

## Naming Decision

The preferred naming decision is now fixed:

- Use `webauthnAuth/`.
- Delete `walletAuth/` after its low-level WebAuthn primitives move and its
  higher-level auth-selection logic is absorbed by `stepUpConfirmation/` or
  operation-local step-up helpers.
- Do not preserve compatibility barrels or a mixed folder state.

## Target Flow

```mermaid
sequenceDiagram
  participant Flow as Operation flow
  participant Step as requireStepUpAuth
  participant Select as methodSelection
  participant Prompt as method prompt
  participant UI as uiConfirm
  participant Runner as method runner

  Flow->>Step: operation, selectedLane, policy, confirmation, runners
  Step->>Select: route from lane and policy
  Select-->>Step: StepUpAuthRoute
  Step->>Prompt: build prompt/auth plan
  Prompt-->>Step: prompt request
  Step->>UI: confirmSigningOperation
  UI-->>Step: user response
  Step->>Runner: complete method-specific auth
  Runner-->>Step: StepUpAuthResult
  Step-->>Flow: authorization
```

## Phased Todo List

### Phase 0: Inventory Current Direct Auth Routing

- [ ] List every flow importing `stepUpConfirmation/otpPrompt/*`.
- [ ] List every flow importing `stepUpConfirmation/passkeyPrompt/*`.
- [ ] List every flow switching on `SigningAuthPlanKind`.
- [ ] List every flow that builds Email OTP challenge, resend, or completion
      closures.
- [ ] Identify EVM-family, Tempo, NEAR, recovery, and export call sites that
      should call `requireStepUpAuth`.

Exit criteria:

- [ ] Inventory names exact files, imported symbols, and replacement owner.
- [ ] No implementation changes in this phase.

### Phase 1: Split `walletAuth/` Into `webauthnAuth/`

- [x] Create `client/src/core/signingEngine/webauthnAuth/`.
- [x] Move low-level WebAuthn/passkey browser primitives from `walletAuth/` to
      `webauthnAuth/`:
      credential collection, credential helpers, credential extensions,
      signer-slot/device helpers, and other browser-only WebAuthn utilities.
- [x] Move `stepUpConfirmation/passkeyPrompt/*`, `threshold/*`, `flows/*`,
      `uiConfirm/*`, and `workerManager/*` imports to `webauthnAuth/*`.
- [x] Move the EVM-family direct auth-method selection out of `walletAuth/*`
      wrappers and into operation-local planning plus `stepUpConfirmation/*`
      contracts.
- [x] Move neutral account-auth metadata out of `walletAuth/*` and into
      `interfaces/accountAuthMetadata.ts`.
- [x] Remove passkey-only gate flows from `walletAuth/*` adapter routing:
      recovery export confirmation, Ed25519 session mint, and passkey login
      session exchange now request passkey authorization directly.
- [ ] Move remaining generic auth-method selection and wallet-policy logic out of
      `walletAuth/` and into either:
      `stepUpConfirmation/methodSelection.ts`,
      `stepUpConfirmation/types.ts`, or
      operation-local EVM-family step-up helpers.
- [ ] Delete `walletAuth/` with no compatibility exports.
- [ ] Add guard coverage blocking new imports from `walletAuth/*`.

Exit criteria:

- [ ] `webauthnAuth/` owns only low-level WebAuthn/passkey primitives.
- [ ] Generic auth routing is no longer owned by `walletAuth/*`.
- [ ] `walletAuth/` is deleted.

### Phase 2: Define The Adaptor Contract

- [x] Add `stepUpConfirmation/requireStepUpAuth.ts`.
- [x] Add `stepUpConfirmation/methodSelection.ts`.
- [x] Add `stepUpConfirmation/methodRunners.ts`.
- [ ] Replace shared optional auth fields with discriminated route/result
      branches.
- [ ] Keep existing `SigningAuthPlan` only where the UI confirmation runtime
      still consumes it during migration.
- [x] Add tests for method selection from selected lane, policy, and available
      runners.

Exit criteria:

- [x] The adaptor compiles without moving operation flows.
- [x] Type tests or unit tests prove missing method runners fail before UI
      confirmation starts.
- [ ] No new internal barrel files are introduced.

### Phase 3: EVM-Family Vertical Slice

This is the first implementation slice. It is intentionally EVM-family only.
Do not move NEAR, recovery, or export flows in this phase.

- [x] Add `flows/signEvmFamily/requireEvmFamilyStepUpAuth.ts` to centralize the
      EVM-family confirmation-side step-up contract.
- [x] Move EVM-family Email OTP challenge, resend, and completion wiring out of
      broad auth-planning code into `flows/signEvmFamily/emailOtpSigningSession.ts`.
- [x] Change `flows/signEvmFamily/signingFlow.ts` to call the new
      operation-local helper.
- [x] Change `flows/signEvmFamily/signingFlowRuntime.ts` to consume a narrower
      step-up contract shape and stop carrying legacy auth-plan details.
- [x] Remove direct imports of `otpPrompt/*` from moved EVM-family call sites.
- [x] Remove direct imports of `passkeyPrompt/*` from moved EVM-family call
      sites.
- [x] Keep threshold signing and nonce sequencing in the existing operation
      flow.
- [x] Replace the operation-local helper internals so it calls the shared
      `stepUpConfirmation/prepareStepUpAuth` route instead of importing prompt
      builders directly. The helper still returns the current confirmation
      payload shape while the UI runtime consumes `SigningAuthPlan`.
- [x] Move EVM-family account-auth resolution out of `walletAuth/` and into
      `flows/signEvmFamily/accountAuth.ts`.
- [ ] Move `signEvmFamily.ts` off the remaining wallet-auth naming and result
      wrappers.
- [ ] Delete EVM-family `SigningAuthPlanKind` switching once threshold-admission
      and confirmation runtime inputs are narrowed.
- [x] Remove direct `SigningAuthPlanKind` imports from the moved EVM-family flow
      modules by replacing them with narrow auth-plan predicates from
      `stepUpConfirmation/types.ts`.

Exit criteria:

- [x] EVM-family transaction confirmation now has one operation-local step-up
      helper call site.
- [x] EVM-family operation code imports the operation-local helper with no
      direct OTP prompt-module imports at the moved confirmation boundary.
- [x] Tempo uses the same EVM-family helper path without separate method
      routing.
- [ ] Existing EVM-family signing tests pass.

### Phase 4: NEAR Vertical Slice

- [x] Add `flows/signNear/requireNearStepUpAuth.ts`.
- [x] Remove NEAR transaction passkey/Email OTP adapter wrappers from
      `signNear.ts`; keep direct Email OTP challenge/completion closures local
      until the shared NEAR helper exists.
- [x] Move NEAR transaction Email OTP prompt setup into the NEAR helper or a
      shared runner builder if it is auth-method neutral.
- [x] Route NEAR transaction, delegate, and NEP-413 signing through the same
      adaptor shape.
- [ ] Keep NEAR-specific Ed25519 threshold material resolution in `signNear` or
      `threshold/ed25519`.

Exit criteria:

- [ ] NEAR operation code has one step-up entrypoint.
- [ ] NEAR imports no prompt modules directly.
- [ ] NEAR still uses the shared signing state machine.

### Phase 5: Recovery And Export Flows

- [x] Use a narrower `requireExportStepUpAuth` wrapper over the shared
      `requireStepUpAuth` engine.
- [ ] Define export-specific request and result types for
      `requireExportStepUpAuth`:
      export intent only,
      export-valid auth policy only,
      export-specific authorization result only.
- [ ] Keep `requireExportStepUpAuth` as a thin operation wrapper:
      export policy shaping,
      export prompt/display assembly,
      export-capable runner wiring,
      then delegate shared method selection/execution to
      `stepUpConfirmation/requireStepUpAuth.ts`.
- [ ] Move key-export Email OTP and passkey confirmation routing to the adaptor.
- [ ] Keep export-specific display and policy data in the recovery/export flow
      folders.

Exit criteria:

- [ ] Recovery/export flows share lower-level method routing with transaction
      signing.
- [ ] Export-specific auth policy remains explicit in the export wrapper
      request.
- [ ] Export flows do not accept the broad transaction-signing step-up request
      shape.

### Phase 6: Future Auth Method Slots

- [ ] Add compile-time placeholders only as types or tests. Avoid empty runtime
      folders for methods without implementation.
- [ ] Document how to add a method:
      `StepUpMethod` branch, prompt module, runner interface, method-selection
      branch, operation runner implementation, and tests.
- [ ] Add a sample test-only fake method to verify the routing extension point
      if useful.

Exit criteria:

- [ ] Adding authenticator OTP or magic link requires no transaction-flow
      rewrites.
- [ ] New methods require explicit runner implementations and tests.

### Phase 7: Delete Old Routing Paths And Guards

- [ ] Delete `flows/emailOtp/` after its files move.
- [ ] Delete direct operation imports of:
      `stepUpConfirmation/otpPrompt/*`,
      `stepUpConfirmation/passkeyPrompt/*`,
      and `SigningAuthPlanKind`.
- [ ] Delete direct imports of `walletAuth/*` from signing-engine production
      code. `webauthnAuth/*` is the only remaining low-level WebAuthn owner.
- [ ] Add guard tests for the deleted paths and blocked imports.
- [ ] Update ownership READMEs and `docs/refactor-33.md` cross references.

Exit criteria:

- [ ] Main signing flows call one step-up boundary.
- [ ] Prompt modules are method-local implementation details.
- [ ] Email OTP and passkey are symmetric at the flow boundary.
- [ ] `walletAuth/` is deleted and blocked from reintroduction.
- [ ] Refactor 33 guard tests and `pnpm build:sdk` pass.

## Guard Tests

Add or extend `tests/unit/signingEngine.refactor33.guard.unit.test.ts`:

- [ ] `flows/*` cannot import `stepUpConfirmation/otpPrompt/*`.
- [ ] `flows/*` cannot import `stepUpConfirmation/passkeyPrompt/*`.
- [ ] `flows/*` cannot switch on `SigningAuthPlanKind`.
- [ ] `flows/emailOtp/` is a deleted path.
- [ ] `flows/passkey/` is a blocked path.
- [ ] `walletAuth/` is a deleted path.
- [ ] `stepUpConfirmation/*` may import low-level `webauthnAuth/*` primitives,
      but `webauthnAuth/*` cannot import `stepUpConfirmation/*`.
- [ ] `stepUpConfirmation/requireStepUpAuth.ts` cannot import `flows/*`,
      `SigningEngine.ts`, or concrete session lifecycle modules.
- [ ] Auth-method runner interfaces live under `stepUpConfirmation/`.
- [ ] Operation-specific runner implementations live under the operation folder
      or the real lifecycle owner.

## Success Metrics

1. Each main signing operation has exactly one step-up auth call.
2. EVM-family, Tempo, and NEAR use the same `requireStepUpAuth` contract.
3. Adding authenticator OTP, magic link, or password does not require changing
   transaction signing flow control.
4. Method-specific lifecycle code has one owner.
5. Prompt modules are no longer imported by operation flows.
6. `webauthnAuth/*` is the only low-level WebAuthn owner.
7. Refactor guards enforce the import direction and deleted paths.
8. `pnpm build:sdk` and the relevant signing-flow suites pass.

## Remaining Decisions

1. Keep `requireStepUpAuth` as the operation-facing API, or rename it to
   `resolveSigningAuth` if warm-session reuse remains in the same function.
2. Return method-specific authorization directly, or return a normalized
   signing authorization consumed by threshold admission.
3. Keep flat folders like `otpPrompt/` and `passkeyPrompt/`, or move to
   `stepUpConfirmation/authMethods/<method>/` once the number of methods grows.
