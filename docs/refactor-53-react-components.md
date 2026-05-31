# Refactor 53: React Components and Headless Auth Flows

Date created: 2026-05-31
Status: draft plan
Owner: SDK React and auth UX

## Dependency

Start this refactor after `docs/refactor-52-ed25519-presign-pool-plan.md` is
implemented and validated.

Reason: Refactor 52 changes warm Ed25519 session behavior after unlock. This
plan simplifies React login and registration surfaces, so it should build on the
post-Refactor-52 warm-session semantics.

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
- `seams.auth.requestEmailOtpEnrollmentChallenge(...)`
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

## Target Public SDK API

Add a high-level headless flow under `AuthCapability`:

```ts
type GoogleEmailOtpWalletAuthMode = 'register' | 'login';

type GoogleEmailOtpWalletAuthPromptCopy = {
  title: string;
  description: string;
  submitLabel: string;
  helperText?: string;
};

type GoogleEmailOtpWalletAuthStartInput = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthMode;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: 'configured' | readonly ThresholdEcdsaChainTarget[];
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

type GoogleEmailOtpWalletAuthRerollResult = {
  walletId: WalletId;
  emailHint?: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  codeDelivery: 'sent' | 'reused';
};

type GoogleEmailOtpWalletAuthSubmitResult = {
  walletId: WalletId;
  session: WalletSession;
  mode: GoogleEmailOtpWalletAuthMode;
};

type GoogleEmailOtpWalletAuthFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  walletId: WalletId;
  emailHint?: string;
  mode: GoogleEmailOtpWalletAuthMode;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  resend(): Promise<{ challengeId: string; emailHint?: string }>;
  reroll?: () => Promise<GoogleEmailOtpWalletAuthRerollResult>;
  submit(input: { otpCode: string }): Promise<GoogleEmailOtpWalletAuthSubmitResult>;
};

interface AuthCapability {
  beginGoogleEmailOtpWalletAuth(
    input: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthFlow>;
}
```

Rules:

- `beginGoogleEmailOtpWalletAuth(...)` requests the first Email OTP challenge
  before returning the flow.
- `mode: 'register'` may return a login flow when the Google identity already
  maps to an existing wallet.
- `reroll` exists only for an active registration flow.
- `resend` selects enrollment or login challenge internally.
- `submit` performs registration or unlock internally.
- `submit` refreshes local login state and verifies `WalletSession.login.isLoggedIn`.
- `submit` provisions/restores all configured ECDSA targets required by SDK
  config, unless `ecdsaTargets` is explicitly provided.
- `submit` returns a typed failure for incomplete local signing-session readiness.
- App code never receives `appSessionJwt`, `runtimePolicyScope`,
  `walletSessionUserId`, or ECDSA bootstrap objects.

## Optional React Hook

Add a React hook for apps that want the SDK to own the headless flow but keep
provider token acquisition app-owned:

```ts
type UseGoogleEmailOtpWalletAuthOptions = {
  getGoogleIdToken(input: { mode: GoogleEmailOtpWalletAuthMode }): Promise<string>;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: 'configured' | readonly ThresholdEcdsaChainTarget[];
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

type UseGoogleEmailOtpWalletAuthResult = {
  start(input: { mode: GoogleEmailOtpWalletAuthMode }): Promise<GoogleEmailOtpWalletAuthFlow>;
  busy: boolean;
  error: Error | null;
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
      username?: string;
      otpPrompt?: PasskeyAuthMenuOtpPrompt;
    }
  | {
      kind: 'otp_flow';
      flow: GoogleEmailOtpWalletAuthFlow;
    };
```

`PasskeyAuthMenu` maps `GoogleEmailOtpWalletAuthFlow` to `PasskeyAuthMenuOtpPrompt`
internally:

- `username` from `flow.walletId`
- prompt copy from `flow.prompt`
- `onResend` from `flow.resend`
- `onRerollAccount` from `flow.reroll`
- `onSubmit` from `flow.submit`

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

  return { kind: 'otp_flow', flow };
};
```

The demo may keep toast formatting around Google SSO startup/failure. It should
not select challenge routes, build wallet-session refs, call ECDSA capability
methods, or validate local wallet-session readiness.

## Files To Touch

Core SDK:

- `client/src/core/SeamsPasskey/interfaces.ts`
- `client/src/core/SeamsPasskey/index.ts`
- `client/src/core/SeamsPasskey/emailOtp.ts`
- `client/src/core/WalletIframe/shared/messages.ts`
- wallet iframe router/client files that proxy `AuthCapability`

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

## Phase Plan

### Phase 0: Inventory Current Social Auth Surface

Tasks:

- Inventory every call made by `onGoogleSsoEmailOtp(...)`.
- Classify each call as app-owned, React-owned, or SDK-owned.
- Confirm Refactor 52 warm Ed25519 session behavior is stable after unlock.
- Identify wallet iframe parity requirements for the new high-level auth method.

Acceptance:

- The inventory maps every leaked SDK concept to a target owner.
- No implementation changes.

Validation:

- Documentation review only.

### Phase 1: Add Headless SDK Flow Types

Tasks:

- Add `GoogleEmailOtpWalletAuthFlow` and related input/result types.
- Add `beginGoogleEmailOtpWalletAuth(...)` to `AuthCapability`.
- Add public type fixtures proving app code cannot access internal JWT,
  runtime-policy, ECDSA bootstrap, or wallet-session user-id fields from the new
  flow.

Acceptance:

- The public type surface exposes only wallet id, email hint, prompt copy, and
  `resend`/`reroll`/`submit`.
- Existing low-level methods remain available.

Validation:

- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`
- targeted type fixture tests

### Phase 2: Implement Headless SDK Flow

Tasks:

- Implement `beginGoogleEmailOtpWalletAuth(...)` in `SeamsPasskey`.
- Reuse existing low-level helpers internally:
  `exchangeGoogleEmailOtpSession`, challenge request helpers,
  Email OTP registration, and Email OTP ECDSA login.
- Internalize registration/login resolution.
- Internalize app session JWT and runtime policy scope routing.
- Internalize configured ECDSA target readiness.
- Internalize login state refresh and wallet-session readiness validation.
- Return typed user-facing failures.

Acceptance:

- App code can complete register and login paths without calling low-level Email
  OTP challenge or ECDSA capability APIs.
- Registration reroll works through `flow.reroll`.
- Resend works through `flow.resend`.
- Submit works for new registration and existing-wallet login.
- The flow emits the same registration/unlock events as the old sequence.

Validation:

- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- existing Email OTP registration/unlock tests
- wallet-session readiness regression tests

### Phase 3: Wallet Iframe Parity

Tasks:

- Add wallet iframe RPC messages for `beginGoogleEmailOtpWalletAuth`, `resend`,
  `reroll`, and `submit`, or define a host-owned flow handle protocol.
- Ensure app-origin iframe mode does not receive secrets, app session JWT, or
  internal bootstrap material.
- Preserve event emission across iframe boundaries.

Acceptance:

- App-origin mode can use the same public API.
- Flow handles cannot be confused across wallets or auth modes.
- Internal session material stays wallet-origin owned.

Validation:

- wallet iframe router tests
- iframe Email OTP auth flow tests

### Phase 4: React Flow Adapter

Tasks:

- Extend `PasskeyAuthMenuSocialLoginResult` with `{ kind: 'otp_flow'; flow }`.
- Map `GoogleEmailOtpWalletAuthFlow` to the existing OTP prompt controller.
- Add `useGoogleEmailOtpWalletAuth(...)`.
- Export the hook and public types from `client/src/react/index.ts`.
- Keep existing `otpPrompt` custom handler support for advanced apps.

Acceptance:

- `PasskeyAuthMenu` accepts a headless OTP flow without app-level prompt wiring.
- Existing custom `otpPrompt` integrations keep working.
- React controller owns only UI state: busy, code input, resend, reroll, submit,
  error display, and back navigation.

Validation:

- `tests/unit/passkeyAuthMenu.googleEmailOtpFlow.unit.test.ts`
- React typecheck

### Phase 5: Simplify Demo

Tasks:

- Replace `onGoogleSsoEmailOtp(...)` in `PasskeyLoginMenu.tsx` with the target
  shape.
- Keep Google Identity token acquisition local to the demo.
- Keep demo toast copy local to the demo.
- Delete app-level calls to low-level Email OTP challenge, registration, ECDSA
  capability, refresh, and readiness APIs from this flow.
- Remove `walletSessionRefFromSession` import from `PasskeyLoginMenu.tsx`.

Acceptance:

- `PasskeyLoginMenu.tsx` no longer contains SDK workflow branching for Google
  Email OTP.
- The component remains responsible for UI copy and `onLoggedIn`.
- The demo code is short enough to serve as user-facing integration guidance.

Validation:

- demo typecheck
- unit test or component test for social Google OTP prompt path
- manual browser smoke test for register and login if the demo app is running

### Phase 6: Documentation And API Guidance

Tasks:

- Document the preferred Google SSO + Email OTP integration path.
- Mark low-level Email OTP methods as advanced in docs.
- Add examples for app-owned Google token acquisition and SDK-owned wallet auth.
- Document wallet iframe behavior.

Acceptance:

- New users can implement Google SSO Email OTP wallet auth without seeing ECDSA,
  runtime policy, wallet-session refs, app-session JWT routing, or challenge
  route selection.

Validation:

- docs review

## Regression Coverage

Required tests:

- `beginGoogleEmailOtpWalletAuth` register path sends enrollment challenge.
- `beginGoogleEmailOtpWalletAuth` login path sends login challenge.
- register mode with existing wallet returns login-mode prompt.
- registration reroll updates wallet id and preserves valid code-delivery state.
- resend calls the correct internal challenge route for the active flow mode.
- submit register path calls internal Email OTP registration and provisions
  configured ECDSA targets.
- submit login path calls internal Email OTP unlock and restores/provisions
  configured ECDSA targets.
- submit refreshes wallet session and fails closed when local readiness is absent.
- app-origin iframe mode never exposes internal JWT/runtime-policy/bootstrap
  fields.
- `PasskeyAuthMenu` maps flow prompt copy, resend, reroll, and submit correctly.
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
