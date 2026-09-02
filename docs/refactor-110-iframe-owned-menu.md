# Wallet-Iframe-Owned Seams Auth Menu

Date created: August 3, 2026

Status: complete on `dev` as of August 6, 2026. The wallet-iframe-owned Lit
surface, React lifecycle adapter, consumer migration, compact iframe surfaces,
and focused validation are landed. Device linking remains deferred under the
scope defined below.

## Decision

Move the complete interactive `SeamsAuthMenu` into the wallet iframe and render
it as a Lit component. The wallet iframe bundle remains React-free.

The public React `SeamsAuthMenu` export becomes a small lifecycle adapter. It
opens one typed wallet-iframe auth-menu surface, forwards serializable
configuration, brokers the few app-owned external-auth interactions, and
reports typed outcomes. It renders no interactive auth-menu controls in the app
document.

This refactor applies to the hosted wallet-iframe mode. Headless `SeamsWeb`
methods remain available for custom and direct integrations. A mounted
`SeamsAuthMenu` requires a configured wallet iframe; it fails with a clear
configuration error when the wallet iframe is unavailable.

## Goal

Give registration and sign-in one compact wallet-origin interaction surface:

```text
React app mounts SeamsAuthMenu
  -> wallet iframe opens modal_auth_menu
  -> Lit auth menu prepares the selected operation
  -> wallet-origin CTA becomes enabled
  -> user clicks inside the wallet iframe
  -> navigator.credentials.create() or get() starts from that activation
  -> wallet host completes the operation
  -> typed outcome returns to the React adapter
```

The final passkey click and the WebAuthn ceremony share the same wallet-origin
event chain. Passkey registration initiated through `SeamsAuthMenu` therefore
needs no second registration-confirmation button.

## R110 Scope: Device Linking Deferred

Device-link and QR UI are excluded from Refactor 110. The current Refactor-84
device-link runtime fails closed with an explicit `UNSUPPORTED` result, so R110
does not advertise or add a host-owned device-link continuation, view, test, or
acceptance criterion. Device linking remains deferred until the Refactor-103 v4
runtime and protocol are implemented.

## Required Invariants

1. React and ReactDOM are absent from every wallet-iframe host entry and its
   static import graph.
2. Every visible and interactive auth-menu element belongs to the wallet-origin
   document.
3. The app origin cannot provide a WebAuthn credential, claim user activation,
   choose an RP ID, or invoke a prepared wallet-origin continuation.
4. Passkey registration and unlock prepare every asynchronous prerequisite
   before enabling their CTA. The CTA starts WebAuthn before its first `await`.
5. An auth-menu session, external-auth request, passkey preparation, and final
   outcome carry exact correlated identities.
6. The wallet host validates raw MessagePort payloads once and converts them
   into precise internal types. Core auth-menu logic never accepts raw objects.
7. One wallet-iframe foreground surface owns visibility, focus, cancellation,
   and cleanup for the complete auth-menu session.
8. Theme and appearance come through the existing normalized
   `AppearanceConfig`; arbitrary CSS, React elements, and DOM selectors do not
   cross the iframe boundary.
9. Direct `registerWallet()`, `addWalletSigner()`, and `unlock()` calls retain
   their wallet-origin confirmation surfaces because they have no auth-menu CTA.
10. The current React-rendered menu, callback-driven operation controller,
    styles, skeleton, fixtures, and compatibility exports are deleted at
    cutover. There is one auth-menu UI implementation.

## Current State

The current implementation splits one interaction across two documents:

- `packages/wallet/src/react/components/SeamsAuthMenu/client.tsx` renders the
  visible menu in the app document;
- `useSeamsAuthMenuController.ts` owns mode, account lookup, registration draft,
  social, OTP, and callback-driven operation state;
- `SeamsAuthMenuProps` accepts functions, React elements, style objects, and
  class names that cannot cross `postMessage`;
- `PM_REGISTER_WALLET` and `PM_UNLOCK` expand the wallet iframe into separate
  confirmation surfaces;
- `UiConfirmManager.openRegistrationPreparationModal()` mounts a loading
  registration modal and later hands it to the passkey confirmer;
- the wallet host already runs `SeamsWeb`, owns WebAuthn and workers, applies
  appearance tokens, and mounts Lit confirmation components;
- the client router already derives iframe visibility from the typed
  `WalletIframeSurface` union.

The infrastructure is sufficient. The missing pieces are an auth-menu surface,
a wallet-host controller, a serializable public boundary, and direct prepared
continuations for clicks originating in the auth menu.

## Target Ownership And Bundle Boundaries

### App-Origin React Adapter

The React adapter owns only:

- mounting and closing an auth-menu session with component lifecycle;
- mapping public props into a serializable open request;
- invoking an app-owned external identity-provider broker when requested;
- forwarding progress and the terminal result to application callbacks;
- exact cleanup during unmount, React Strict Mode remounts, and iframe
  reconnection.

It must not own input state, registration drafts, account availability,
passkey readiness, OTP prompts, or waiting screens.

### Wallet-Iframe Host

The wallet host owns:

- the auth-menu session state machine;
- all rendered menu content and focus management;
- login/register mode and account/passkey-name input;
- account availability and recent-unlock lookup;
- registration and unlock preparation;
- passkey login and account-sync continuation;
- WebAuthn invocation;
- Google Email OTP wallet-auth flow state;
- OTP, registration-completion, progress, and error views;
- cancellation and terminal cleanup;
- result projection back to the app.

### Shared Code

Shared code contains only framework-independent domain types, parsers, builders,
formatters, and pure decision functions. It imports neither React nor Lit.

Lit rendering stays in the wallet-host UI folder. The React adapter imports the
shared wire contract and the existing React context only.

## Auth-Menu Surface

Add an auth-menu branch to the existing surface model:

```ts
type ModalAuthMenuSurface = {
  kind: 'modal_auth_menu';
  connectionId: WalletIframeConnectionId;
  identity: RequestSurfaceIdentity;
  authMenuSessionId: HostedAuthMenuSessionId;
};
```

Add matching reducer events for opening, cancelling, completing, and closing the
session. The client renderer maps this branch to one viewport modal with a focus
trap and an accessible title.

`PM_OPEN_AUTH_MENU` remains pending until the user completes or closes the menu.
The request owns the surface throughout all internal views. Registration and OTP
subviews do not open competing client-router surfaces.

Direct SDK operations continue to use `modal_registration_confirm`,
`modal_unlock_confirm`, and the other existing request-owned surfaces.

## Boundary Contract

Use branded identities and explicit result branches:

```ts
type HostedAuthMenuSessionId = string & {
  readonly __hostedAuthMenuSessionId: unique symbol;
};

type HostedAuthMenuOpenRequest = {
  kind: 'hosted_auth_menu_open_v1';
  authMenuSessionId: HostedAuthMenuSessionId;
  initialMode: 'login' | 'register';
  registrationAccountInput: 'implicit_wallet' | 'sponsored_named_near_account';
  showRegistrationInput: boolean;
  showProgress: boolean;
  copy: HostedAuthMenuCopy;
  enabledExternalProviders: HostedAuthMenuExternalProvider[];
};

type HostedAuthMenuOutcome =
  | {
      kind: 'authenticated';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
      method: 'passkey' | 'google_email_otp';
    }
  | {
      kind: 'registered';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
      method: 'passkey' | 'google_email_otp';
    }
  | {
      kind: 'account_synced';
      authMenuSessionId: HostedAuthMenuSessionId;
      walletId: WalletId;
    }
  | {
      kind: 'cancelled';
      authMenuSessionId: HostedAuthMenuSessionId;
      reason: 'close_button' | 'component_unmounted' | 'connection_closed';
    }
  | {
      kind: 'failed';
      authMenuSessionId: HostedAuthMenuSessionId;
      code: HostedAuthMenuFailureCode;
      message: string;
    };
```

Normalize copy at the app-origin boundary so the host receives required strings
with defaults already applied. Normalize configuration again at the wallet-host
trust boundary before constructing the internal session.

The open request carries display configuration only. RP ID, wallet origin,
relay authority, sessions, challenges, credentials, capability state, and
registration preparation remain wallet-host internal.

## Internal Lifecycle

Model the host controller with an exhaustive union. A representative shape is:

```ts
type HostedAuthMenuState =
  | { state: 'starting'; session: HostedAuthMenuSession }
  | { state: 'choosing'; session: HostedAuthMenuSession; view: AuthMenuChoiceView }
  | {
      state: 'preparing_passkey';
      session: HostedAuthMenuSession;
      operation: HostedAuthMenuPasskeyOperation;
    }
  | {
      state: 'passkey_ready';
      session: HostedAuthMenuSession;
      prepared: PreparedHostedAuthMenuPasskeyOperation;
    }
  | {
      state: 'performing_passkey';
      session: HostedAuthMenuSession;
      operation: ActiveHostedAuthMenuPasskeyOperation;
    }
  | {
      state: 'awaiting_external_auth';
      session: HostedAuthMenuSession;
      request: HostedAuthMenuExternalAuthRequest;
    }
  | {
      state: 'otp_prompt';
      session: HostedAuthMenuSession;
      flow: HostedAuthMenuOtpFlow;
    }
  | { state: 'complete'; outcome: HostedAuthMenuOutcome };
```

Use branch-specific builders. The controller accepts only the narrow state
needed by each transition and switches exhaustively with `assertNever`.
Diagnostics and progress events project from lifecycle state and never control
it.

Changing mode, changing the passkey name, rerolling an implicit wallet, closing
the menu, or losing the connection invalidates the previous prepared operation.
Late preparation results are ignored and disposed by exact preparation identity.

## Passkey Activation Path

### Registration

Registration mode allocates and validates the exact wallet draft before the CTA
is enabled. Preparation includes:

1. resolved wallet ID and account policy;
2. effective wallet-origin RP ID;
3. registration intent and WebAuthn challenge;
4. signer selection and registration-specific client warm-up;
5. WebAuthn prompt reservation;
6. loaded Lit component and style assets.

The enabled Lit CTA atomically consumes the prepared state. Its event handler
starts `navigator.credentials.create()` before its first `await`, serializes the
credential inside the wallet origin, and continues the existing registration
protocol with that exact prepared authority.

This requires a narrow host-only continuation extracted from the current
registration flow. It must accept a consumed prepared-registration object and a
wallet-origin credential. It must not be exported through `SeamsWebIframe`, the
public SDK, or the MessagePort protocol.

`PM_REGISTER_WALLET` keeps the current preparation/confirmation path for direct
API callers.

### Login And Account Sync

Passkey login and sync follow the same rule: resolve the exact wallet and every
asynchronous prerequisite before the Lit CTA becomes enabled. The click starts
`navigator.credentials.get()` directly and hands the credential to a narrow
wallet-host continuation.

The auth-menu path does not call the public proxy and reopen
`modal_unlock_confirm`. Direct `PM_UNLOCK` calls retain that confirmation.

## External Identity Providers

The app may still own acquisition of a third-party credential because Google
Identity or another provider can require app-origin configuration and callbacks.
That ownership does not move the menu UI out of the iframe.

Use a correlated broker protocol:

```text
Lit provider button
  -> AUTH_MENU_EXTERNAL_AUTH_REQUEST(sessionId, externalAuthRequestId, provider, mode)
  -> React adapter invokes the configured app provider broker
  -> PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH(sessionId, externalAuthRequestId, evidence)
  -> wallet host validates evidence and owns the wallet-auth flow
```

For Google, the app broker returns the ID token or a typed cancellation/failure.
The wallet host calls the existing Google Email OTP wallet-auth runtime and owns
the registration-ready, OTP, resend, reroll, submit, and completion views.

Each enabled provider requires a first-class, validated evidence branch.
Arbitrary handlers that return React-era prompt objects or executable flow
objects are removed. Providers without an implemented evidence branch are not
advertised by the iframe menu.

External-auth messages require the active connection, surface, auth-menu
session, and external-auth request identities. Late responses cannot update a
new menu session.

## Lit UI Contract

Create the internal element under the wallet host, for example:

```text
packages/wallet/src/SeamsWeb/walletIframe/host/lit-ui/auth-menu/
  seams-auth-menu-surface.ts
  auth-menu-controller.ts
  auth-menu-domain.ts
  auth-menu-boundary.ts
  auth-menu.css
```

The exact split should stay small; merge files when a separate module does not
remove real complexity.

The first UI preserves the agreed compact design:

- theme-aware light and dark rendering through existing appearance tokens;
- compact modal geometry with responsive width and safe mobile insets;
- one header row containing the Lucide Link glyph, relying-party hostname, and
  top-right close button;
- no verification tick;
- short mode-specific heading and subtitle;
- registration displays the editable passkey/account name and the `Passkey
  name` label;
- no redundant explanatory paragraph or secondary Cancel button;
- one clear primary CTA;
- the existing `w3a-passkey-halo-loading` fingerprint halo and animation during
  preparation and WebAuthn;
- visible focus, keyboard operation, labelled close control, modal semantics,
  focus restoration, reduced-motion support, and 44px minimum targets.

Vendor the small Lucide Link SVG path as an internal Lit icon. Do not add
`lucide-react` or another React dependency to the SDK or wallet-host graph.

The element receives a normalized view model and emits typed intent events. It
does not call `postMessage`, parse raw config, or reach into React state.

## Public React API

Replace operation-driving callbacks with outcome callbacks. The target public
surface should be approximately:

```ts
type SeamsAuthMenuProps = {
  initialMode?: 'login' | 'register';
  registrationAccountInput?: SeamsAuthMenuRegistrationAccountInput;
  showRegistrationInput?: boolean;
  showProgress?: boolean;
  copy?: HostedAuthMenuCopyInput;
  externalAuthBroker?: HostedAuthMenuExternalAuthBroker | null;
  onOutcome: (outcome: HostedAuthMenuOutcome) => void;
};
```

UI configuration fields may keep ergonomic optional defaults at the React
boundary. The normalized wire request uses required fields.

Remove these React-era capabilities:

- `header: ReactElement`;
- arbitrary `style` and `className` for iframe contents;
- `onLogin`, `onRegister`, and `onSyncAccount` as operation executors;
- prompt objects containing callback methods;
- arbitrary `socialLogin.google/x/apple` flow handlers;
- `loadingScreenDelayMs` and React waiting-screen behavior;
- direct `SeamsAuthMenuClient`, skeleton, and preload exports.

Applications style the hosted menu through `AppearanceConfig`. Applications
observe results through `onOutcome` and existing SDK lifecycle events.

The React component stays SSR-safe. Server rendering produces one inert host
marker with no interactive menu or React skeleton. Client mounting opens the
iframe surface. Unmounting cancels only the exact session created by that
component instance.

## Implementation Phases

### Phase 0: Record Contracts And Baselines

1. Record current wallet-host raw, gzip, and Brotli sizes with
   `check:bundle-size`.
2. Capture the current public `SeamsAuthMenu` exports and every app/docs usage.
3. Classify existing SeamsAuthMenu tests as current behavior, valid tests that
   need migration, or obsolete React implementation coverage.
4. Add the intended one-click iframe-owned registration and login behavior to
   `docs/intended-behaviours.md` before changing production behavior.

### Phase 1: Domain And Message Boundaries

1. Add branded auth-menu and external-auth request identities.
2. Define open config, progress, external-auth request/result, and terminal
   outcome unions in the wallet-iframe shared protocol.
3. Add boundary parsers/builders and type fixtures for invalid identities,
   invalid branch combinations, broad object literals, and callback-bearing
   payloads.
4. Add `PM_OPEN_AUTH_MENU`, exact cancellation, and external-auth resolution to
   the request router and handler maps.
5. Add `modal_auth_menu` to the surface reducer and renderer.

### Phase 2: Lit Surface And Host Controller

1. Implement the framework-independent host lifecycle controller.
2. Implement `<seams-auth-menu-surface>` and its compact styles.
3. Reuse the existing appearance normalization and
   `w3a-passkey-halo-loading` element.
4. Mount the element directly from the wallet-host auth-menu handler; do not
   expose it through the generic app-configurable UI registry.
5. Keep account lookup, mode switching, waiting, OTP, and account-sync state
   inside the active auth-menu session.

### Phase 3: Prepared Passkey Continuations

1. Extract registration preparation from the current modal presentation so one
   prepared authority can feed either the direct modal or the hosted auth menu.
2. Add the host-only registration continuation that consumes an iframe CTA
   activation and prepared authority exactly once.
3. Add the equivalent host-only login/sync continuation.
4. Ensure preparation invalidation closes prompt reservations and worker
   resources on edits, reroll, mode changes, cancellation, timeout, and
   connection loss.
5. Preserve the existing direct API confirmation branches.

### Phase 4: External Auth And Secondary Views

1. Implement the external-auth request/result broker with exact correlation.
2. Move Google Email OTP flow presentation and control into the Lit controller.
3. Render OTP, Google registration completion, recent unlocks, and account sync
   inside the same auth-menu surface.
4. Add first-class evidence types before enabling any additional provider.

### Phase 5: React Adapter And Product Migration

1. Replace the current React client and controller with the small mount/unmount
   adapter.
2. Change the public props to serializable config, external-auth broker, and
   typed outcomes.
3. Update `apps/seams-site`, SDK examples, package README, and theming docs.
4. Keep the public React package entry SSR-safe while removing the client,
   skeleton, and preload subpath exports.
5. Update the status of `refactor-8X-iframe-registration-button.md` and the
   hosted-wallet README text where Refactor 110 supersedes the two-click menu
   path.

### Phase 6: Delete Superseded Code

Delete, rather than retain as compatibility code:

- React auth-menu UI components and CSS;
- the React auth-menu controller, hydration context, theme scope, skeleton, and
  preload path;
- prompt/callback types that existed only for the React controller;
- React-specific account availability badges and social rendering;
- tests and fixtures that assert React DOM structure, skeleton markup, or the
  previous callback-driven flow;
- SeamsAuthMenu-specific use of the registration preparation modal;
- stale docs describing an app-origin auth menu with a second iframe confirm
  click.

Keep shared account and registration decision logic only when the Lit
controller uses it. Move such logic to a neutral folder and delete the React
copy in the same phase.

## Testing Strategy

### Type And Unit Coverage

- auth-menu lifecycle rejects invalid state combinations;
- open/config/result boundary parsers reject functions, unknown branches,
  malformed identities, and caller-supplied authority;
- exact session and external-auth correlation ignores late responses;
- changing input or mode invalidates the previous preparation;
- close/unmount/connection loss cleans up once;
- direct registration and unlock still select their confirmation surfaces;
- auth-menu registration and login select their prepared host continuation.

### Lit Component Coverage

Add focused tests under `tests/lit-components/` for:

- light and dark appearance propagation;
- compact header, Lucide Link icon, hostname, and accessible close button;
- registration passkey-name label and value;
- CTA disabled during preparation and enabled only for the exact ready state;
- fingerprint halo loading and reduced motion;
- login, registration, OTP, account-sync, error, and progress views;
- keyboard traversal, focus trap, close behavior, and focus restoration.

### Wallet-Iframe Browser Coverage

Add focused tests under `tests/wallet-iframe/` proving:

- the app document contains no interactive auth-menu controls;
- the full visible menu belongs to the wallet-origin iframe;
- registration needs one auth-menu click after preparation and reaches
  `navigator.credentials.create()` from that click;
- login reaches `navigator.credentials.get()` from its iframe CTA;
- no nested registration or unlock confirmation appears;
- direct API registration still shows `modal_registration_confirm`;
- external-auth responses require exact session/request correlation;
- closing or unmounting hides only the matching surface;
- competing foreground surfaces receive the existing typed busy rejection.

### Intended Behavior

Extend the passkey registration and unlock intended-behavior contracts to cover
the hosted auth-menu entry point while preserving the existing wallet,
capability, lifecycle-event, and prompt-count invariants.

### Bundle Checks

After the production build:

1. compare wallet-host raw, gzip, and Brotli sizes with the Phase 0 baseline;
2. run `check:runtime-entry-bundles` and `check:bundle-size`;
3. inspect the wallet-host static import graph and fail if it contains `react`,
   `react-dom`, `lucide-react`, or a React auth-menu module;
4. confirm Lit and the halo component are shared chunks rather than duplicated
   in the host entry.

Use the narrowest test file while implementing. Run the broader commands after
the public types, message schema, and lifecycle behavior have landed:

```text
pnpm test:lit-components
pnpm test:wallet-iframe
pnpm test:intended
pnpm -C packages/wallet type-check
pnpm -C packages/wallet build:rolldown
pnpm -C packages/wallet check:runtime-entry-bundles
pnpm -C packages/wallet check:bundle-size
```

## Acceptance Criteria

- The complete interactive `SeamsAuthMenu` renders inside the wallet iframe as
  Lit.
- The app-origin React component contains no auth inputs, provider buttons,
  passkey CTA, OTP prompt, registration prompt, or waiting UI.
- The wallet iframe production graph contains no React, ReactDOM, or
  `lucide-react` code.
- Passkey registration initiated through the menu uses one enabled
  wallet-origin CTA and opens no second Seams confirmation modal.
- Passkey login and sync use their wallet-origin auth-menu CTA without opening a
  second unlock confirmation.
- Direct SDK registration, signer addition, unlock, signing, export, and
  recovery retain their required wallet-origin confirmation behavior.
- Registration and login CTAs remain disabled until their exact prepared
  operation is ready and unexpired.
- WebAuthn starts before the CTA handler's first `await`.
- Editing or rerolling the passkey name cannot submit stale preparation.
- Theme changes propagate through `AppearanceConfig`; light mode is the light
  design and dark mode remains supported.
- The compact header uses the Lucide Link glyph, hostname, and close button,
  with no verification tick or secondary Cancel action.
- The existing fingerprint halo icon and animation remain in loading and
  WebAuthn states.
- External identity-provider results are typed, validated, and correlated; no
  executable callback or flow object crosses the iframe protocol.
- React-era auth-menu implementation files, exports, tests, and documentation
  are removed at cutover.
- Focused Lit, wallet-iframe, type, intended-behavior, build, and bundle checks
  pass.
