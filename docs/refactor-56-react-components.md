# Refactor 56: React Components and Headless Auth Flows

Date created: 2026-05-31
Status: implementation-ready plan
Owner: SDK React and auth UX

## Dependency

Start this refactor after the Router A/B signing cleanup in
`docs/router-a-b-cleanup.md` is implemented and validated.

Reason: Router A/B cleanup changes warm Ed25519 session behavior after unlock.
This plan simplifies React login and registration surfaces, so it should build
on the post-cleanup warm-session semantics.

This refactor should also stay aligned with `docs/refactor-51-cross-platform-2.md`:
React components call public/headless SDK flows, while SDK internals own use-case
state, auth branch selection, warm-session readiness, and persistence routing.

## Problem

`examples/seams-site/src/flows/demo/PasskeyLoginMenu.tsx` contains application
UI code and SDK workflow orchestration in the same component. The worst example
is `onGoogleSsoEmailOtp(...)`, which currently handles:

- Google client configuration lookup
- Google Identity script loading
- Google ID token request
- Google session exchange
- registration vs login resolution from `googleEmailOtpResolution`
- app session JWT plumbing
- `runtimePolicyScope` plumbing
- OTP challenge request selection for enrollment vs login
- OTP resend behavior
- registration reroll behavior
- direct Email OTP wallet registration
- direct Email OTP ECDSA capability login
- `walletSessionRefFromSession(...)`
- demo-specific `chainTarget` selection
- login state refresh
- wallet-session readiness checks
- toast/error formatting

That forces app developers to understand SDK concepts that should be internal:

- ECDSA capability login
- warm signing session readiness
- wallet session user id
- runtime policy scope
- app session JWT ownership
- Email OTP registration vs unlock internals
- challenge route choice
- configured ECDSA target readiness
- local signing-session readiness verification

The React example should compose a UI flow. It should not reconstruct SDK
registration, unlock, ECDSA provisioning, and session readiness logic.

## Goals

- Make `PasskeyAuthMenu` social auth integration a thin UI adapter.
- Add a headless SDK flow for Google SSO plus Email OTP wallet auth.
- Keep Google Identity browser interaction app-owned or adapter-owned, based on
  explicit API choice.
- Internalize Email OTP challenge selection, registration/login resolution,
  ECDSA readiness, session refresh, and wallet-session validation.
- Keep advanced low-level Email OTP methods available for custom integrations,
  with names and docs that make their advanced status clear.
- Reduce `PasskeyLoginMenu.tsx` to UI copy, toasts, Google token acquisition, and
  `onLoggedIn`.
- Provide reusable React helpers so app examples do not copy protocol workflow
  code.

## Non-Goals

- Replace Google Identity with a bundled provider SDK.
- Remove low-level Email OTP APIs in this refactor.
- Redesign the visual layout of `PasskeyAuthMenu`.
- Change public passkey login/register behavior.
- Implement a generic OAuth provider framework for all providers.
- Move app-specific toast styling or copy into core SDK.

## Current Leaks To Remove From App Code

The demo app should no longer call these methods directly for the Google SSO
Email OTP auth path:

- `seams.auth.exchangeGoogleEmailOtpSession(...)`
- `seams.auth.requestEmailOtpChallenge(...)`
- `seams.registration.requestEmailOtpEnrollmentChallenge(...)`
- `seams.auth.loginWithEmailOtpEcdsaCapability(...)`
- `seams.near.registerNearWallet(...)` for this social flow
- `seams.auth.getWalletSession(...)` for post-submit readiness validation
- `refreshLoginState(...)` for post-submit readiness validation
- `walletSessionRefFromSession(...)`

These remain valid advanced APIs, but the standard React/social-auth path should
call a higher-level flow.

## Ownership Rules

### App Owns

- visual placement of `PasskeyAuthMenu`
- toast rendering and copy overrides
- Google Identity UI adapter when the app chooses to own it
- final `onLoggedIn(walletId)` callback
- demo-specific chain-target policy only when overriding the SDK default

### React Package Owns

- `PasskeyAuthMenu` OTP prompt rendering
- social-login prompt state
- resend/reroll/submit button state
- hook wrappers that connect React UI to headless SDK flows
- UI-safe prompt contracts

### Core SDK Owns

- Google Email OTP session exchange parsing
- registration vs login resolution
- Email OTP challenge selection
- app session JWT and runtime policy scope routing
- Email OTP registration submission
- Email OTP unlock submission
- configured ECDSA target warmup/readiness
- wallet-session refresh and readiness validation
- same-method auth separation
- SDK event emission

## Contract Decisions Before Implementation

These decisions close the ambiguity that would otherwise create mismatched direct
browser and wallet-iframe implementations.

### Flow Completion

`PasskeyAuthMenu` must surface successful headless-flow completion to the app.
The component owns OTP UI state, but the app still owns the final product action,
for example `onLoggedIn(walletId)` and toast copy.

Add an optional completion callback to the social-login result:

```ts
type PasskeyAuthMenuSocialCompletion = (result: {
  walletId: WalletId;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  session: WalletSession;
}) => void | Promise<void>;
```

When `socialLogin.google` returns `{ kind: 'otp_flow', flow, onComplete }`,
`PasskeyAuthMenu` submits the OTP through the flow and calls `onComplete` only
after a successful `submit` result. Existing custom `otpPrompt` integrations may
also provide `onComplete`; the component calls it after the custom prompt submit
resolves.

### Flow Lifecycle

Model the flow as a discriminated union. The public challenge object represents
exactly one active OTP challenge. Reroll and resend return a fresh active flow
object instead of mutating hidden public state.

```ts
type GoogleEmailOtpWalletAuthRequestedMode = 'register' | 'login';
type GoogleEmailOtpWalletAuthResolvedMode = 'register' | 'login';
type GoogleEmailOtpWalletAuthDelivery = 'sent' | 'reused';

type GoogleEmailOtpWalletAuthEcdsaTargets =
  | { kind: 'configured' }
  | { kind: 'none' }
  | {
      kind: 'explicit';
      targets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
    };

type GoogleEmailOtpWalletAuthFailureCode =
  | 'google_exchange_failed'
  | 'email_otp_challenge_failed'
  | 'email_otp_invalid_code'
  | 'email_otp_expired'
  | 'email_otp_rate_limited'
  | 'registration_failed'
  | 'unlock_failed'
  | 'recovery_code_backup_incomplete'
  | 'local_signing_session_not_ready'
  | 'wallet_iframe_unavailable'
  | 'flow_cancelled'
  | 'flow_expired';

type GoogleEmailOtpWalletAuthFailure = {
  code: GoogleEmailOtpWalletAuthFailureCode;
  message: string;
  retryAfterMs?: number;
};

type GoogleEmailOtpWalletAuthResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: GoogleEmailOtpWalletAuthFailure };

type GoogleEmailOtpWalletAuthPromptCopy = {
  title: string;
  description: string;
  submitLabel: string;
  helperText: string;
};

type GoogleEmailOtpWalletAuthBaseFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  state: 'challenge_sent';
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  walletId: WalletId;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  delivery: GoogleEmailOtpWalletAuthDelivery;
  expiresAtMs: number;
  resend(): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
  submit(input: {
    otpCode: string;
  }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess>>;
  cancel(): Promise<void>;
};

type GoogleEmailOtpWalletAuthRegistrationFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  mode: 'register';
  reroll(): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
};

type GoogleEmailOtpWalletAuthLoginFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  mode: 'login';
  reroll?: never;
};

type GoogleEmailOtpWalletAuthFlow =
  | GoogleEmailOtpWalletAuthRegistrationFlow
  | GoogleEmailOtpWalletAuthLoginFlow;

type GoogleEmailOtpWalletAuthSubmitSuccess = {
  walletId: WalletId;
  session: WalletSession;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
};
```

`mode: 'register'` may resolve to a login flow when the Google identity already
maps to an existing wallet. In that case `requestedMode` stays `register`,
`mode` is `login`, and `reroll` is absent.

### OTP Challenge Binding And Reroll

Reroll may reuse the current email code only when the relay session explicitly
keeps the same active registration attempt and the challenge is still bound to
the same Google email identity. Otherwise the SDK must request a new challenge.
The implementation must avoid inferring reuse from a local `challengeId` alone.

### Recovery-Code Backup

Email OTP registration success must include recovery-code backup before the
headless flow reports completion.

- Direct browser mode invokes the existing Email OTP recovery-code backup UI,
  acknowledges backup, and strips `recoveryKeys` from the public submit success.
- Wallet-iframe mode keeps recovery-code display and acknowledgement inside the
  wallet origin and returns only non-secret completion metadata to the app
  origin.
- A user closing or failing the backup UI returns
  `recovery_code_backup_incomplete`; the flow remains incomplete.

### Wallet Iframe Flow Handles

Wallet iframe parity uses host-owned opaque handles. The app origin must never
receive `appSessionJwt`, `runtimePolicyScope`, `walletSessionUserId`, ECDSA
bootstrap material, recovery codes, challenge secrets, or registration attempt
internals.

Add these RPC messages:

```ts
type ParentToChildType =
  | 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL';
```

The host stores a short-lived record keyed by `flowHandleId`, bound to:

- parent origin
- requested mode and resolved mode
- wallet id
- Google email identity
- active challenge id
- active registration attempt when present
- app session JWT and runtime policy scope, host-owned only
- ECDSA target policy
- expiry timestamp

Every handle operation must verify the record is active, unexpired, same-origin,
and same-wallet before doing work. Submit and cancel burn the handle. Reroll
burns the old handle and returns a new handle-backed flow.

### ECDSA Target Readiness

`ecdsaTargets` defaults to `{ kind: 'configured' }`. `{ kind: 'explicit' }` must
contain at least one target. `{ kind: 'none' }` is allowed only for integrations
that do not require an ECDSA signing session after auth. Submit succeeds only
after all required targets are locally ready; otherwise it returns
`local_signing_session_not_ready`.

## Target Public SDK API

Add a high-level headless flow under `AuthCapability`:

```ts
type GoogleEmailOtpWalletAuthStartInput = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthRequestedMode;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

interface AuthCapability {
  beginGoogleEmailOtpWalletAuth(
    input: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
}
```

Rules:

- `beginGoogleEmailOtpWalletAuth(...)` requests the first Email OTP challenge
  before returning an `ok: true` flow.
- `mode: 'register'` may return a login flow when the Google identity already
  maps to an existing wallet.
- `reroll` exists only for an active registration flow and returns a fresh flow.
- `resend` selects enrollment or login challenge internally and returns a fresh
  flow.
- `submit` performs registration or unlock internally.
- `submit` refreshes local login state and verifies `WalletSession.login.isLoggedIn`.
- `submit` provisions/restores all configured ECDSA targets required by SDK
  config, unless `ecdsaTargets` is explicitly provided.
- recoverable failures return typed `ok: false` outcomes.
- App code never receives `appSessionJwt`, `runtimePolicyScope`,
  `walletSessionUserId`, or ECDSA bootstrap objects.

## Optional React Hook

Add a React hook for apps that want the SDK to own the headless flow but keep
provider token acquisition app-owned:

```ts
type UseGoogleEmailOtpWalletAuthOptions = {
  getGoogleIdToken(input: { mode: GoogleEmailOtpWalletAuthRequestedMode }): Promise<string>;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

type UseGoogleEmailOtpWalletAuthResult = {
  start(input: {
    mode: GoogleEmailOtpWalletAuthRequestedMode;
  }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
  busy: boolean;
  error: GoogleEmailOtpWalletAuthFailure | null;
};
```

Canonical file:

```text
client/src/react/hooks/useGoogleEmailOtpWalletAuth.ts
```

This hook should be convenience glue only. Core workflow decisions stay in the
headless SDK method.

## PasskeyAuthMenu Social Contract

Keep the current `socialLogin.google` capability, but allow it to return a
headless flow directly:

```ts
type PasskeyAuthMenuSocialLoginResult =
  | {
      kind?: 'otp_prompt';
      username?: string;
      otpPrompt?: PasskeyAuthMenuOtpPrompt;
      onComplete?: PasskeyAuthMenuSocialCompletion;
    }
  | {
      kind: 'otp_flow';
      flow: GoogleEmailOtpWalletAuthFlow;
      onComplete?: PasskeyAuthMenuSocialCompletion;
    };
```

`PasskeyAuthMenu` maps `GoogleEmailOtpWalletAuthFlow` to `PasskeyAuthMenuOtpPrompt`
internally:

- `username` from `flow.walletId`
- prompt copy from `flow.prompt`
- `onResend` from `flow.resend`
- `onRerollAccount` from `flow.reroll`
- `onSubmit` from `flow.submit`
- `onBack` and menu reset from `flow.cancel`
- `onComplete` after an `ok: true` submit result

The React adapter stores the active flow object. Successful `resend` and
`reroll` replace that active flow with the fresh flow returned by the SDK, so
the next submit uses the latest challenge and handle.

This preserves the current customizable prompt path while removing SDK-specific
logic from app components.

## Target Demo Code Shape

After this refactor, `PasskeyLoginMenu.tsx` should look like this for Google SSO:

```ts
const onGoogleSsoEmailOtp = async (args: {
  mode: AuthMenuMode;
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
}) => {
  const idToken = await requestDemoGoogleIdToken();
  const flow = await seams.auth.beginGoogleEmailOtpWalletAuth({
    idToken,
    mode: args.mode === AuthMenuMode.Register ? 'register' : 'login',
    relayUrl: relayerBaseUrl,
    sessionKind: 'jwt',
    emailOtpAuthPolicy: args.emailOtpAuthPolicy,
    onEvent: handleGoogleEmailOtpEvent,
  });

  if (!flow.ok) throw new Error(flow.error.message);

  return {
    kind: 'otp_flow',
    flow: flow.value,
    onComplete: ({ walletId }) => props.onLoggedIn?.(walletId),
  };
};
```

The demo may keep toast formatting around Google SSO startup/failure. It should
not select challenge routes, build wallet-session refs, call ECDSA capability
methods, or validate local wallet-session readiness.

## Files To Touch

Core SDK:

- `client/src/SeamsWeb/publicApi/types.ts`
- `client/src/SeamsWeb/publicApi/auth.ts`
- `client/src/SeamsWeb/SeamsWeb.ts`
- `client/src/SeamsWeb/operations/authMethods/emailOtp/challenge.ts`
- `client/src/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup.ts`
- `client/src/SeamsWeb/walletIframe/shared/messages.ts`
- `client/src/SeamsWeb/walletIframe/client/router.ts`
- `client/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts`
- `client/src/SeamsWeb/walletIframe/SeamsWebIframe.ts`

React package:

- `client/src/react/components/PasskeyAuthMenu/types.ts`
- `client/src/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.ts`
- `client/src/react/components/PasskeyAuthMenu/adapters/seams.ts`
- `client/src/react/index.ts`
- `client/src/react/hooks/useGoogleEmailOtpWalletAuth.ts`

Demo:

- `examples/seams-site/src/flows/demo/PasskeyLoginMenu.tsx`
- optionally extract demo Google token helpers into a smaller local adapter if
  needed

Tests:

- `tests/unit/passkeyAuthMenu.googleEmailOtpFlow.unit.test.ts`
- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- existing Email OTP registration/unlock tests
- wallet iframe message tests
- public type fixtures

## Implementation Shape Suggestions

Apply these while implementing the phases. They are intentionally concrete so
the refactor does not add another wrapper layer.

- Add the headless workflow as an operation module:
  `client/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`.
  `SeamsWeb.ts` should wire dependencies and delegate; it should not grow the
  workflow body.
- Use a narrow dependency object for the operation, for example
  `GoogleEmailOtpWalletAuthDeps`. Do not pass `SeamsWebContext`,
  `SeamsWebSigningSurface`, or the whole `SeamsWeb` instance into the flow.
- Keep `publicApi/auth.ts` as API assembly only. It may expose
  `beginGoogleEmailOtpWalletAuth`, but should not own flow state or iframe
  handle state.
- Direct browser mode can return closure-backed flow objects. Wallet iframe mode
  must return equivalent public flow objects backed by opaque host-owned
  `flowHandleId` records.
- Implement direct browser mode first with full unit coverage, then implement
  iframe parity against the same public type fixtures.
- Registration submit should use the current wallet-registration path with an
  internally built `email_otp` auth method and SDK default signer selection. App
  code must not choose challenge routes, signer selection, runtime policy scope,
  app-session JWT routing, or wallet-session refs for this standard flow.
- Low-level Email OTP methods remain available for advanced integrations in this
  refactor. Mark them as advanced in docs rather than moving namespaces during
  the same implementation pass.
- Avoid new capability classes or same-layer forwarding modules. Add a helper
  only when it validates a boundary, owns lifecycle state, or removes duplicated
  protocol branching.
- Prefer type fixtures before broad runtime tests for public API secrecy:
  app code should not compile when it tries to access `appSessionJwt`,
  `runtimePolicyScope`, `walletSessionUserId`, recovery codes, or ECDSA
  bootstrap material from the headless flow.

## Regression Prevention Strategy

This refactor touches public SDK types, React component control flow, wallet
iframe routing, Email OTP registration, and ECDSA session readiness. Treat it as
an auth/session refactor, not a UI-only cleanup.

### Implementation Order

Land the work in this order to keep failures localized:

1. Public types and type fixtures.
2. Direct browser headless flow with unit tests.
3. React adapter support with existing custom `otpPrompt` compatibility tests.
4. Demo simplification after the SDK and React tests pass.
5. Wallet iframe parity with handle lifecycle tests.
6. Documentation and source guards.

Do not switch the demo to the new flow before the direct browser flow, React
adapter, and public type fixtures are passing.

### Source Guards

Add `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts` with these checks:

- `examples/seams-site/src/flows/demo/PasskeyLoginMenu.tsx` standard Google
  Email OTP path does not call:
  - `exchangeGoogleEmailOtpSession`
  - `requestEmailOtpChallenge`
  - `requestEmailOtpEnrollmentChallenge`
  - `loginWithEmailOtpEcdsaCapability`
  - `registerNearWallet`
  - `getWalletSession`
  - `walletSessionRefFromSession`
- `client/src/react/**` does not branch on `googleEmailOtpResolution`.
- `client/src/react/**` does not import `walletSessionRefFromSession`.
- `client/src/SeamsWeb/publicApi/**` does not store or mutate flow handle
  records.
- `client/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`
  does not import `SeamsWebContext`, `SeamsWebSigningSurface`, or
  `BrowserSigningSurface`.
- wallet iframe client-visible result types do not expose `appSessionJwt`,
  `runtimePolicyScope`, `walletSessionUserId`, `recoveryKeys`, or ECDSA
  bootstrap material.

### Type Fixtures

Add public type fixtures that compile only when:

- login-mode flow has `reroll?: never`;
- explicit ECDSA target input rejects an empty target list;
- app code must branch on `ok` before reading a flow or submit success;
- submit success exposes `walletId`, `mode`, and `session` only;
- app code cannot read `appSessionJwt`, `runtimePolicyScope`,
  `walletSessionUserId`, `recoveryKeys`, `recoveryCodesIssuedAtMs`,
  `bootstrap`, or `warmCapability` from the headless flow;
- `onComplete` receives only UI-safe completion data.

### Direct And Iframe Parity Matrix

The same behavior must be tested in direct browser mode and wallet-iframe mode:

| Case | Direct | Iframe |
| --- | --- | --- |
| register begins with enrollment challenge | required | required |
| login begins with login challenge | required | required |
| register request resolves to existing-wallet login | required | required |
| resend replaces active flow | required | required |
| reroll replaces active flow and burns old flow | required | required |
| submit burns active flow | required | required |
| stale submit fails closed | required | required |
| recovery-code backup completes before register success | required | required |
| recovery codes never reach app-visible result | required | required |
| local signing readiness failure returns typed failure | required | required |
| event callbacks preserve old phase semantics | required | required |

### React Regression Matrix

Add targeted component/controller tests for:

- existing `{ username, otpPrompt }` custom integrations still work;
- `{ kind: 'otp_flow', flow, onComplete }` renders prompt copy and submits;
- `ok: false` submit leaves the OTP prompt open and shows the error;
- successful submit calls `onComplete` exactly once;
- resend/reroll success replaces the active flow used by submit;
- back/reset/start-different-method calls `flow.cancel()` and suppresses
  unhandled rejection if cancel fails;
- resend debounce still applies after the flow adapter changes;
- recovery-key prompt support remains unchanged for custom `otpPrompt` flows.

### Event And Session Readiness Invariants

Tests must assert these postconditions rather than only asserting method calls:

- registration path emits registration events and never unlock-only completion
  events before registration completes;
- existing-wallet login from register mode emits unlock events after resolution;
- successful submit refreshes local login state exactly once;
- submit success requires `WalletSession.login.isLoggedIn === true`;
- configured ECDSA targets are checked through the same readiness helper used by
  current low-level flows;
- `ecdsaTargets: { kind: 'none' }` skips ECDSA readiness only for the explicit
  no-ECDSA branch.

### Validation Gates

Run the cheapest gate after each phase:

```sh
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C tests exec playwright test \
  tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts \
  tests/unit/passkeyAuthMenu.googleEmailOtpFlow.unit.test.ts \
  tests/unit/refactor56HeadlessAuth.guard.unit.test.ts \
  --reporter=line
```

Run the broader gate before closeout:

```sh
pnpm -C sdk type-check
pnpm -C tests run test:source-guards
pnpm -C tests exec playwright test \
  tests/unit/seamsWeb.emailOtp.unit.test.ts \
  tests/unit/seamsWeb.emailOtpIframe.unit.test.ts \
  tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts \
  tests/unit/passkeyAuthMenu.fouc.unit.test.ts \
  tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts \
  tests/unit/passkeyAuthMenu.googleEmailOtpFlow.unit.test.ts \
  --reporter=line
```

## Phase Plan

### Phase 0: Inventory Current Social Auth Surface

Tasks:

- [x] Inventory every call made by `onGoogleSsoEmailOtp(...)`.
- [x] Classify each call as app-owned, React-owned, or SDK-owned.
- [x] Confirm Refactor 52 warm Ed25519 session behavior is stable after unlock.
- [x] Identify wallet iframe parity requirements for the new high-level auth method.
- [x] Confirm the existing wallet-registration helper path that should be reused for
  standard Google Email OTP registration.
- [x] Record the pre-refactor event sequence for register, existing-wallet login,
  resend, reroll, and submit so the new flow can preserve observable events.

Acceptance:

- The inventory maps every leaked SDK concept to a target owner.
- The direct and iframe parity matrix has a concrete test owner for each row.
- No implementation changes.

Validation:

- Documentation review only.

### Phase 1: Add Headless SDK Flow Types

Tasks:

- [x] Add `GoogleEmailOtpWalletAuthFlow` and related input/result types.
- [x] Add `beginGoogleEmailOtpWalletAuth(...)` to `AuthCapability`.
- [x] Add the narrow `GoogleEmailOtpWalletAuthDeps` contract for the operation
  module.
- [x] Add public type fixtures proving app code cannot access internal JWT,
  runtime-policy, ECDSA bootstrap, or wallet-session user-id fields from the new
  flow.
- [x] Add type fixtures proving login flows reject `reroll`, explicit ECDSA target
  lists reject empty arrays, and submit failures are handled as `ok: false`.
- [x] Add type fixtures proving app code cannot access recovery-code or bootstrap
  material from flow, submit, resend, or reroll results.

Acceptance:

- The public type surface exposes only wallet id, email hint, prompt copy, and
  `resend`/`reroll`/`submit`/`cancel`.
- Existing low-level methods remain available.

Validation:

- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`
- targeted type fixture tests
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`

### Phase 2: Implement Headless SDK Flow

Tasks:

- [x] Implement `beginGoogleEmailOtpWalletAuth(...)` in `SeamsWeb`.
- [x] Implement the workflow body in
  `operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`.
- [x] Reuse existing low-level helpers internally:
  `exchangeGoogleEmailOtpSession`, challenge request helpers,
  Email OTP registration, and Email OTP ECDSA login.
- [x] Internalize registration/login resolution.
- [x] Internalize app session JWT and runtime policy scope routing.
- [x] Internalize configured ECDSA target readiness.
- [x] Internalize login state refresh and wallet-session readiness validation.
- [x] Return typed user-facing failures.
- [x] Invoke recovery-code backup and acknowledgement before registration submit
  completes.
- [ ] Add an explicit relay-to-SDK reroll delivery contract if the UI must
  distinguish reused-code vs newly-sent-code after reroll. The current relay
  exchange result exposes registration attempt identity and expiry, but no
  app-visible code-reuse flag for `GoogleEmailOtpWalletAuthFlow.delivery`.
- [x] Keep low-level Email OTP APIs callable, but stop using them from the demo
  standard Google path.
- [x] Add stale-flow protections for double submit, submit after cancel, submit
  after reroll replacement, and submit after expiry.
- [x] Add direct-mode parity tests for every row in the direct/iframe matrix before
  starting iframe implementation.

Acceptance:

- App code can complete register and login paths without calling low-level Email
  OTP challenge or ECDSA capability APIs.
- Registration reroll works through `flow.reroll`.
- Resend works through `flow.resend`.
- Submit works for new registration and existing-wallet login.
- The flow emits the same registration/unlock events as the old sequence.
- Registration submit never returns recovery codes to app code.
- Submit burns or completes the active challenge flow so stale submit cannot be
  repeated.
- Direct browser mode satisfies the direct column of the parity matrix.

Validation:

- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- existing Email OTP registration/unlock tests
- wallet-session readiness regression tests
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`

### Phase 3: Wallet Iframe Parity

Tasks:

- [x] Add wallet iframe RPC messages for `beginGoogleEmailOtpWalletAuth`, `resend`,
  `reroll`, `submit`, and `cancel` using host-owned flow handles.
- [x] Ensure app-origin iframe mode does not receive secrets, app session JWT, or
  internal bootstrap material.
- [x] Preserve event emission across iframe boundaries.
- [x] Store flow handle records with expiry and same-wallet/mode checks. Same-origin remains
  enforced by the existing iframe messaging boundary.
- [x] Burn handles after submit, cancel, expiry, or reroll replacement.
- [x] Keep wallet-iframe handle state in wallet-iframe code, not in `publicApi`.
- [x] Add explicit stale-handle tests for wrong wallet, wrong mode, expired
  handle, cancelled handle, submitted handle, and rerolled handle. Wrong-origin
  checks stay at the iframe messaging boundary, outside the Email OTP handler
  map.
- [x] Add iframe parity tests that reuse the same public flow assertions as direct
  mode wherever possible.

Acceptance:

- App-origin mode can use the same public API.
- Flow handles cannot be confused across wallets or auth modes.
- Internal session material stays wallet-origin owned.
- Registration recovery-code backup UI stays wallet-origin owned.
- Wallet iframe mode satisfies the iframe column of the parity matrix.

Validation:

- wallet iframe router tests
- iframe Email OTP auth flow tests
- source guard proving public API does not own iframe flow-handle state

### Phase 4: React Flow Adapter

Tasks:

- [x] Extend `PasskeyAuthMenuSocialLoginResult` with `{ kind: 'otp_flow'; flow }`.
- [x] Map `GoogleEmailOtpWalletAuthFlow` to the existing OTP prompt controller.
- [x] Add `useGoogleEmailOtpWalletAuth(...)`.
- [x] Export the hook and public types from `client/src/react/index.ts`.
- [x] Keep existing `otpPrompt` custom handler support for advanced apps.
- [x] Add `onComplete` handling for both `{ kind: 'otp_flow' }` and custom
  `otpPrompt` results.
- [x] Convert `ok: false` flow outcomes to OTP prompt errors without collapsing the
  prompt state.
- [x] Replace the active flow after successful `resend` or `reroll` results.
- [x] Call `flow.cancel()` when the user backs out, resets the menu, or starts a
  different auth method.
- [x] Preserve all existing custom `otpPrompt` behaviors, including recovery-key
  prompts and resend debounce.
- [x] Keep `runtime.refreshLoginState` behavior for custom `otpPrompt` flows while
  avoiding duplicate refreshes for headless flow submit success.

Acceptance:

- `PasskeyAuthMenu` accepts a headless OTP flow without app-level prompt wiring.
- Existing custom `otpPrompt` integrations keep working.
- React controller owns only UI state: busy, code input, resend, reroll, submit,
  error display, and back navigation.
- App callbacks run only after a successful submit result.
- Back/reset cancels the active headless flow.
- Existing FOUC and prompt-state tests keep passing.

Validation:

- `tests/unit/passkeyAuthMenu.googleEmailOtpFlow.unit.test.ts`
- `tests/unit/passkeyAuthMenu.fouc.unit.test.ts`
- React typecheck

### Phase 5: Simplify Demo

Tasks:

- [x] Replace `onGoogleSsoEmailOtp(...)` in `PasskeyLoginMenu.tsx` with the target
  shape.
- [x] Keep Google Identity token acquisition local to the demo.
- [x] Keep demo toast copy local to the demo.
- [x] Delete app-level calls to low-level Email OTP challenge, registration, ECDSA
  capability, refresh, and readiness APIs from this flow.
- [x] Remove `walletSessionRefFromSession` import from `PasskeyLoginMenu.tsx`.
- [x] Add or update a guard proving the standard Google Email OTP path does not call
  the low-level methods listed in "Current Leaks To Remove From App Code".

Acceptance:

- `PasskeyLoginMenu.tsx` no longer contains SDK workflow branching for Google
  Email OTP.
- The component remains responsible for UI copy and `onLoggedIn`.
- The demo code is short enough to serve as user-facing integration guidance.
- Low-level Email OTP APIs remain available outside the standard Google path.

Validation:

- demo typecheck
- unit test or component test for social Google OTP prompt path
- manual browser smoke test for register and login if the demo app is running
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`

### Phase 6: Documentation And API Guidance

Tasks:

- [x] Document the preferred Google SSO + Email OTP integration path.
- [x] Mark low-level Email OTP methods as advanced in docs.
- [x] Add examples for app-owned Google token acquisition and SDK-owned wallet auth.
- [x] Document wallet iframe behavior.

Acceptance:

- New users can implement Google SSO Email OTP wallet auth without seeing ECDSA,
  runtime policy, wallet-session refs, app-session JWT routing, or challenge
  route selection.

Validation:

- docs review

### Phase 7: Post-Review Lifecycle And Target-Policy Tightening

Tasks:

- [x] Fix wallet-iframe flow-handle burn semantics for recoverable failures.
  `submit`, `resend`, and `reroll` should read and validate the active handle,
  call the flow method, and burn the handle only after a successful operation
  that consumes or replaces the flow. `cancel` and expiry still burn immediately.
- [x] Keep the fix local to the iframe Email OTP handler. Do not add a generic
  flow manager, lifecycle registry abstraction, or public API wrapper unless it
  removes real duplicated logic across at least two wallet-iframe flow families.
- [x] Add iframe tests proving invalid OTP, rate-limited submit, failed resend,
  and failed reroll return `ok: false` while leaving the same handle usable for
  a later retry or cancel.
- [x] Tighten direct and iframe parity coverage so failed operations match the
  React contract: prompt-visible errors do not collapse active prompt state, and
  successful resend/reroll replaces the active flow.
- [x] Make ECDSA target policy semantics explicit for both login and
  registration. If `ecdsaTargets: { kind: 'explicit' }` remains public, it must
  be honored for registration signer selection as well as login readiness. If
  registration cannot support explicit targets cleanly, split the input type so
  explicit target policy is accepted only by login-mode flows.
- [x] Fix login readiness to cover every required ECDSA target, not only the
  first target. Reuse the existing Email OTP ECDSA capability path per target or
  factor the smallest operation-local helper needed to iterate targets and fail
  closed when any required target is not ready.
- [x] Keep registration signer selection and login readiness in one coherent
  target-policy model. Avoid separate helper paths that can diverge on
  `configured`, `explicit`, or `none`.
- [x] Replace stale relay-mode fixtures with the normalized `existing_wallet`
  value, and add a direct test for register-request-to-existing-wallet login
  resolution using the real boundary value.
- [x] Audit the new tests for obsolete behavior before keeping them. Tests should
  protect current lifecycle and target-policy semantics only.

Acceptance:

- Iframe mode and direct mode have the same recoverable-failure behavior for
  submit, resend, and reroll.
- A failed iframe OTP attempt does not make the active prompt unrecoverable.
- `ecdsaTargets` has one documented, type-enforced meaning across registration
  and login.
- All required ECDSA targets are ready before login submit succeeds. Registration
  can explicitly select no-ECDSA; login with no ECDSA target fails closed because
  this flow has no pure OTP local-session activation path.
- The fix does not introduce another facade layer, registry abstraction, or
  wrapper module around the public flow.

Validation:

- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts`
- `tests/unit/passkeyAuthMenu.fouc.unit.test.ts`
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`

### Phase 8: Reroll Delivery Contract And Closeout

Tasks:

- [x] Fix Google Email OTP registration prompt mode so a new registration renders
  registration copy, `Create wallet`, and the shuffle/reroll account-name control.
  It must render the unlock menu only when the relay explicitly resolves the
  Google identity to an existing wallet.
- [x] Add a regression test for register-mode Google Email OTP showing the
  registration OTP prompt with `flow.mode === 'register'`, including the
  shuffle/reroll account-name button.
- [x] Add a regression test for register-mode Google Email OTP that resolves to an
  existing wallet and intentionally renders the unlock prompt without the
  shuffle/reroll button.
- [x] Define the relay-to-SDK reroll delivery contract for whether a rerolled
  registration flow reused the current Email OTP code or sent a new code.
- [x] Add a normalized boundary field for that contract instead of inferring reuse
  from challenge ids, registration-attempt ids, timestamps, or UI state.
- [x] Update `GoogleEmailOtpWalletAuthFlow.delivery` to reflect only verified
  relay-provided delivery state.
- [x] Add direct-mode tests for reroll delivery state: new code, reused code, and
  missing/unknown relay delivery metadata.
- [x] Add iframe-mode tests proving reroll delivery state survives wire
  serialization without exposing app-session JWTs, runtime policy scope,
  recovery codes, or bootstrap material.
- [x] Re-review app-visible direct and iframe flow results for secret leakage after
  the delivery contract lands.
- [x] Run the broad Refactor 56 validation gate from this plan, including existing
  Email OTP registration/unlock tests and iframe Email OTP tests.
- [x] Clean local generated artifacts before commit, including `.playwright-mcp/`
  and `tmp/` unless they are intentionally needed.
- [ ] Commit the completed Refactor 56 slice after the broader gate is green.

Acceptance:

- `GoogleEmailOtpWalletAuthFlow.delivery` is relay-backed and does not guess.
- New-registration OTP prompts are visibly distinct from existing-wallet unlock
  prompts.
- Registration reroll UI can distinguish reused-code and new-code states without
  app code reading relay internals.
- Direct and iframe flows expose the same delivery state.
- Closeout validation is green and the worktree contains only intended source,
  doc, and test changes before commit.

Validation:

- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts`
- existing Email OTP registration/unlock tests
- iframe Email OTP tests
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`
- `git diff --check`

## Regression Coverage

Required tests:

- `beginGoogleEmailOtpWalletAuth` register path sends enrollment challenge.
- `beginGoogleEmailOtpWalletAuth` login path sends login challenge.
- register mode with existing wallet returns login-mode prompt.
- registration reroll returns a fresh flow, burns the old flow, updates wallet
  id, and preserves valid code-delivery state only when the relay authorizes
  reuse.
- resend calls the correct internal challenge route for the active flow mode.
- submit register path calls internal Email OTP registration and provisions
  configured ECDSA targets.
- submit login path calls internal Email OTP unlock and restores/provisions
  configured ECDSA targets.
- submit register path completes recovery-code backup and strips recovery codes
  from all app-visible results.
- submit refreshes wallet session and fails closed when local readiness is absent.
- app-origin iframe mode never exposes internal JWT/runtime-policy/bootstrap
  fields.
- app-origin iframe mode never exposes recovery codes.
- iframe flow handle cannot be submitted from another wallet, origin, mode, or
  after expiry.
- `PasskeyAuthMenu` maps flow prompt copy, resend, reroll, and submit correctly.
- `PasskeyAuthMenu` calls `onComplete` once after successful submit.
- `PasskeyAuthMenu` replaces active flow state after resend and reroll.
- `PasskeyAuthMenu` cancels active flow state on back/reset.
- existing `otpPrompt` custom integration remains compatible.

## Review Checklist

- Does app code receive only UI-safe flow data?
- Does any React component branch on `googleEmailOtpResolution`?
- Does any demo code call Email OTP challenge APIs for the standard Google path?
- Does any demo code call `loginWithEmailOtpEcdsaCapability` for the standard
  Google path?
- Does any demo code construct `WalletSessionRef` for this flow?
- Does the SDK own configured ECDSA target readiness?
- Does wallet iframe mode preserve secret/session ownership?
- Does wallet iframe mode burn stale handles?
- Does registration completion include recovery-code backup and ACK?
- Are low-level Email OTP APIs still available for advanced integrations?

## Final Target State

- `PasskeyLoginMenu.tsx` is a thin UI adapter.
- `PasskeyAuthMenu` can consume a headless OTP flow directly.
- Google SSO token acquisition remains pluggable.
- SDK internals own Email OTP registration/login resolution, challenge routing,
  ECDSA readiness, session refresh, and wallet-session validation.
- Developers integrating the standard React component do not need to understand
  ECDSA capability login, runtime policy scope, wallet-session refs, app session
  JWT routing, or local signing-session readiness checks.
