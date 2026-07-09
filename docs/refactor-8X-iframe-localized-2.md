# Localized Wallet Iframe Surfaces

Date created: July 10, 2026

Status: planning.

## Goal

Replace fullscreen iframe open/close as the normal wallet iframe control plane
with localized, typed iframe surfaces.

The iframe remains required for interoperable wallet passkeys. WebAuthn
credentials are scoped to the RP ID that runs `navigator.credentials.create()`
and `navigator.credentials.get()`. Running WebAuthn on the app origin would
tether the passkey to that app's domain and break embedded-wallet reuse across
sites. The wallet iframe must stay the wallet-origin RP boundary for passkey
registration, unlock, and signing authorization.

The change is about iframe presentation and lifecycle:

- keep wallet-origin WebAuthn, IndexedDB, signing workers, and activation proofs
- make iframe visibility a state-derived surface, not scattered imperative
  `showFullscreen()` / `hide()` calls
- use button-sized or confirmer-sized iframe surfaces where the required user
  activation can be localized
- reserve viewport modal surfaces for flows where the wallet must own the full
  confirmation UI
- remove fullscreen preflight behavior from passkey registration

## Relationship To Existing Plans

- `docs/refactor-8X-iframe-registration-button.md` owns the first localized
  surface: wallet-origin passkey registration activation over the
  `SeamsAuthMenu` CTA.
- `docs/refactor-84a-iframe-walletId.md` owns wallet ID binding for visible
  iframe passkey registration.
- This plan owns the router and overlay architecture that makes localized
  surfaces the default model across wallet iframe flows.

## Problem

The current iframe overlay lifecycle is imperative and event-sensitive:

- router preflight logic decides whether to show fullscreen before sending a
  request
- progress events can independently show or hide the iframe
- sticky state can suppress hides
- registration submit messages can force fullscreen
- geometry helpers can try to anchor the iframe while fullscreen locks ignore
  anchored updates

That makes correctness depend on event ordering and side effects across the
router, progress bus, overlay controller, host messages, and UI components.
Concurrency is especially fragile:

- one request can hide the iframe while another request still needs activation
- a stale progress event can affect the current surface
- fullscreen locks can outlive the request that created them
- app-visible state can drift from iframe hit-target state
- registration can regress to fullscreen when activation should stay localized

The UI cost is also high. A fullscreen iframe blocks the whole app during
activation, creates visual flicker, and forces product UX around wallet-owned
modals even when the app already has a well-placed CTA.

## Decision

Introduce a single wallet iframe surface state in the client router. The router
will render the iframe from that state and every inbound or outbound message
must correlate with the active surface before it can affect visibility,
geometry, focus, or activation.

The target model:

- one active surface at a time
- every surface carries the request, activation, or flow identity required to
  validate future messages
- direct overlay mutations happen only inside the surface renderer
- progress events update request content and diagnostics; surface transitions
  are explicit typed events
- stale, mismatched, expired, and disposed surface messages are ignored or
  rejected at the boundary

## Non-Goals

- Do not move wallet WebAuthn to the app origin.
- Do not create app-scoped passkeys for the embedded wallet path.
- Do not keep compatibility flags for the old fullscreen registration
  activation path.
- Do not pass React components into the wallet iframe.
- Do not let app-origin code mint activation proofs.
- Do not redesign signing protocol semantics in this plan.

## Surface State

Model iframe presentation as a discriminated union with required branch fields.
Core router and overlay code should accept the narrow branch they need.

```ts
type WalletIframeSurface =
  | HiddenWalletIframeSurface
  | AnchoredRegistrationActivationSurface
  | ModalRegistrationConfirmSurface
  | ModalTransactionConfirmSurface
  | ModalKeyExportConfirmSurface
  | ModalUnlockConfirmSurface;

type HiddenWalletIframeSurface = {
  kind: 'hidden';
  surfaceId?: never;
  requestId?: never;
  activationId?: never;
};

type AnchoredRegistrationActivationSurface = {
  kind: 'anchored_registration_activation';
  surfaceId: WalletIframeSurfaceId;
  activationId: RegistrationActivationId;
  requestId: RequestId;
  wallet: { kind: 'provided'; walletId: WalletId };
  presentation: RegistrationActivationButtonPresentation;
  targetRect: RegistrationActivationTargetRect;
  expiresAtMs: number;
  focus: 'proxy' | 'iframe_button';
};

type ModalRegistrationConfirmSurface = {
  kind: 'modal_registration_confirm';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  wallet: RegisterWalletInput;
  rpId: WebAuthnRpId;
  userActivation: 'wallet_confirm_button_required';
};

type ModalTransactionConfirmSurface = {
  kind: 'modal_transaction_confirm';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  chain: ChainId;
  transactionDigest: TransactionDigest;
  userActivation: 'wallet_confirm_button_required';
};

type ModalKeyExportConfirmSurface = {
  kind: 'modal_key_export_confirm';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  exportKind: 'near_keypair' | 'threshold_ed25519_seed_from_hss_report';
  userActivation: 'wallet_confirm_button_required';
};

type ModalUnlockConfirmSurface = {
  kind: 'modal_unlock_confirm';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  unlockKind: 'passkey' | 'device_link';
  userActivation: 'wallet_confirm_button_required';
};
```

The initial implementation may keep viewport modal surfaces visually fullscreen.
They should still be represented as modal surface state as the replacement for
ad hoc fullscreen overlay state. That gives modal flows request correlation,
focus ownership, and deterministic cleanup immediately, while allowing later UI
work to make those surfaces smaller or anchored.

## Surface Renderer

Replace direct `OverlayController` calls with one renderer:

```ts
type WalletIframeSurfaceRenderMode =
  | { kind: 'hidden' }
  | { kind: 'anchored'; rect: DOMRectLike; title: string }
  | { kind: 'viewport_modal'; title: string; focusTrap: true };

function renderWalletIframeSurface(surface: WalletIframeSurface): WalletIframeSurfaceRenderMode {
  switch (surface.kind) {
    case 'hidden':
      return { kind: 'hidden' };
    case 'anchored_registration_activation':
      return {
        kind: 'anchored',
        rect: surface.targetRect,
        title: surface.presentation.accessibleLabel,
      };
    case 'modal_registration_confirm':
      return { kind: 'viewport_modal', title: 'Confirm passkey registration', focusTrap: true };
    case 'modal_transaction_confirm':
      return { kind: 'viewport_modal', title: 'Confirm transaction', focusTrap: true };
    case 'modal_key_export_confirm':
      return { kind: 'viewport_modal', title: 'Confirm key export', focusTrap: true };
    case 'modal_unlock_confirm':
      return { kind: 'viewport_modal', title: 'Unlock wallet', focusTrap: true };
    default:
      return assertNever(surface);
  }
}
```

`OverlayController` can remain as the low-level DOM/CSS writer during the first
phase. Its public surface should shrink to render modes:

- `applyHidden()`
- `applyAnchored(rect, accessibility)`
- `applyViewportModal(accessibility)`

The router should own `WalletIframeSurface`. The overlay controller should own
only DOM effects derived from a surface render mode.

## Transition Events

Surface transitions should be explicit domain events:

```ts
type WalletIframeSurfaceEvent =
  | {
      kind: 'registration_activation_prepared';
      surfaceId: WalletIframeSurfaceId;
      activationId: RegistrationActivationId;
      requestId: RequestId;
      wallet: { kind: 'provided'; walletId: WalletId };
      presentation: RegistrationActivationButtonPresentation;
      targetRect: RegistrationActivationTargetRect;
      expiresAtMs: number;
    }
  | {
      kind: 'registration_activation_target_rect_changed';
      surfaceId: WalletIframeSurfaceId;
      activationId: RegistrationActivationId;
      targetRect: RegistrationActivationTargetRect;
    }
  | {
      kind: 'registration_activation_cancelled';
      surfaceId: WalletIframeSurfaceId;
      activationId: RegistrationActivationId;
      reason: RegistrationActivationCancellationReason;
    }
  | {
      kind: 'modal_request_started';
      surfaceId: WalletIframeSurfaceId;
      requestId: RequestId;
      modalKind: 'registration_confirm' | 'transaction_confirm' | 'key_export_confirm' | 'unlock_confirm';
    }
  | {
      kind: 'request_finished';
      surfaceId: WalletIframeSurfaceId;
      requestId: RequestId;
    }
  | {
      kind: 'request_cancelled';
      surfaceId: WalletIframeSurfaceId;
      requestId: RequestId;
    };
```

Every reducer branch must compare the event identity to the active surface
identity before mutating state. For example, a
`registration_activation_target_rect_changed` event with the wrong
`activationId` cannot move the iframe.

## Router Invariants

- The router has exactly one `WalletIframeSurface` value.
- The hidden state owns no request, activation, or surface identity.
- Anchored registration activation must have a provided wallet ID.
- Anchored registration activation must have a non-expired activation ID.
- Modal surfaces must have a request ID.
- Only the active surface can update iframe geometry.
- Only the active surface can make the iframe focusable.
- Progress events cannot directly show or hide the iframe.
- Parent-window messages cannot transition surfaces without matching
  `surfaceId`, `requestId`, or `activationId`.
- Host-origin messages cannot mint `walletIframeActivation`.
- App-origin API calls cannot supply trusted activation proofs.
- Cleanup is owned by the surface that installed listeners, timers, geometry
  observers, focus proxies, and state mirrors.

## Registration Path

`docs/refactor-8X-iframe-registration-button.md` should become the first
localized surface implementation.

Activation-button registration:

1. `SeamsAuthMenu` builds a wallet-bound registration draft.
2. `createPasskeyRegistrationActivationSurface()` creates a surface ID and
   activation ID.
3. The router transitions to `anchored_registration_activation`.
4. The renderer positions the iframe over the CTA border box.
5. The wallet iframe renders the real registration button.
6. The user click lands in wallet-origin DOM.
7. The host mints `walletIframeActivation`.
8. Registration calls WebAuthn from the trusted iframe event chain.
9. The active surface finishes and transitions to `hidden`.

Code-only registration:

1. App-origin code calls `registration.registerPasskey()`.
2. The router transitions to `modal_registration_confirm`.
3. The wallet iframe renders a registration-specific confirmation modal.
4. The user clicks the wallet-origin confirm button.
5. WebAuthn starts from the wallet-origin event chain.
6. The active surface finishes and transitions to `hidden`.

Registration must never force fullscreen through a separate router lock. The
modal path can use a viewport modal render mode, but it must still be owned by
`modal_registration_confirm` state.

## Transaction And Signing Path

Signing flows should move to the same surface model after registration is stable.

Initial target:

- request starts a `modal_transaction_confirm` surface
- wallet iframe owns the transaction confirmation UI
- confirm button starts wallet-origin WebAuthn or signing authorization
- request completion or cancellation hides only the matching surface
- stale progress events update diagnostics only

Future target:

- app-owned custom confirmers can request a wallet-origin activation surface for
  the final confirm CTA
- the activation proof is scoped to the request ID, wallet ID, chain, and
  transaction digest
- the iframe activation surface covers only the final confirm button or the
  wallet-owned confirmer region
- app UI can control copy and layout around the CTA, while the wallet-origin
  button owns the activation click

This future API must be designed separately from registration because signing
proofs bind to transaction content and replay boundaries.

## Security Contract

The localized model preserves wallet-origin authority:

- passkeys remain wallet-origin credentials
- app-origin code cannot create wallet-scoped WebAuthn credentials
- activation proofs are minted only after wallet-origin DOM receives a trusted
  activation event
- activation proofs are unguessable, short-lived, single-use, and scoped to the
  active surface
- caller-supplied activation proofs are stripped at request boundaries
- style payloads are parsed once before iframe DOM application
- app-controlled visual styling cannot affect iframe position, pointer routing,
  stacking, transforms, URLs, or animation
- hidden or effectively invisible target elements cannot host an active
  activation surface
- request digests and wallet IDs are bound before authorization begins

For public activation APIs, app-origin UI becomes part of the user-intent trust
base. Public docs should say this plainly. SDK-owned components such as
`SeamsAuthMenu` should be the first supported surface.

## Accessibility Contract

Each active surface must expose one logical control model:

- anchored activation surfaces use an app-domain focus proxy and an iframe-owned
  real button
- focus movement from proxy to iframe button is explicit and test-covered
- the app-domain proxy and iframe button must not be announced as duplicate
  unrelated controls
- modal surfaces use wallet-origin focus management
- hidden iframe state is inert, `aria-hidden`, and unfocusable
- cleanup restores only attributes changed by the active surface

## Geometry Contract

Anchored surfaces must:

- measure with `target.getBoundingClientRect()`
- reject zero-size targets
- reject detached targets
- reject `display: none`
- reject `visibility: hidden`
- reject effective `opacity: 0`, including hidden ancestors where practical
- update on `ResizeObserver`
- update on document scroll
- update on scrollable ancestor movement
- update on `visualViewport` scroll and resize
- align within 1 CSS pixel in browser tests
- cancel when the target becomes unavailable

The renderer should centralize all fixed-position iframe geometry. Router code
should set surface state, then let the renderer apply the resulting mode.

## Implementation Phases

### Phase 0: Inventory And Guardrails

- [ ] List all direct calls to `showFullscreen()`, `showAnchored()`,
      `setOverlayVisible()`, `setOverlayBounds()`, `setSticky()`, and
      `forceFullscreen`.
- [ ] Classify each call site as registration activation, registration modal,
      transaction confirm, key export, unlock, device link, or diagnostics.
- [ ] Add source-guard coverage preventing new direct fullscreen calls outside
      the surface renderer.
- [ ] Document current request types that require wallet-origin user activation.
- [ ] Delete obsolete comments that describe fullscreen as the default
      activation mechanism after a call site moves to surfaces.

### Phase 1: Introduce Surface Domain Types

- [ ] Add `WalletIframeSurface` and `WalletIframeSurfaceEvent` unions.
- [ ] Add branch-specific builders for each surface.
- [ ] Add an exhaustive reducer that applies transition events.
- [ ] Add `assertNever` coverage for surface and event switches.
- [ ] Add type fixtures rejecting invalid states:
      - hidden with request ID
      - anchored registration without activation ID
      - anchored registration with `server_allocated` wallet
      - modal transaction without request ID
      - broad object-spread construction that smuggles incompatible branch
        fields
- [ ] Keep raw postMessage payload parsing at router and host boundaries.
- [ ] Convert parsed payloads into precise internal surface events immediately.

### Phase 2: Surface Renderer

- [ ] Add a renderer that maps `WalletIframeSurface` to hidden, anchored, or
      viewport-modal render modes.
- [ ] Restrict `OverlayController` to low-level DOM writes derived from render
      modes.
- [ ] Remove router-level `forceFullscreen` from new surface paths.
- [ ] Make focusability, `aria-hidden`, iframe title, pointer events, and
      geometry derived from the render mode.
- [ ] Add unit tests proving each surface renders the expected overlay mode.
- [ ] Add cleanup tests proving stale render modes cannot revive an old surface.

### Phase 3: Convert Registration Activation

- [ ] Route `createPasskeyRegistrationActivationSurface()` through
      `anchored_registration_activation`.
- [ ] Carry `surfaceId`, `activationId`, provided wallet, presentation, expiry,
      and target geometry in the active surface.
- [ ] Move geometry observer ownership into the active surface cleanup.
- [ ] Implement hidden and effective-opacity target cancellation.
- [ ] Ensure target rect updates match the active `surfaceId` and
      `activationId`.
- [ ] Ensure duplicate clicks, expired activations, disposed activations, and
      wrong activation IDs cannot start registration.
- [ ] Keep WebAuthn start synchronous from the wallet-origin click handler.
- [ ] Remove fullscreen fallback from activation-button registration.

Validation:

- [ ] Unit: reducer rejects stale registration activation geometry events.
- [ ] Unit: disposed activation cannot move or show the iframe.
- [ ] Component: iframe registration button starts once from pointer and
      keyboard activation.
- [ ] Browser: CTA rect and iframe rect match within 1 CSS pixel.
- [ ] Browser: hidden, zero-size, detached, and opacity-zero targets cancel.
- [ ] Browser: WebAuthn starts without mounting transaction confirmation UI.
- [ ] Browser: Chromium and WebKit/Safari cover the trusted activation path.

### Phase 4: Convert Code-Only Registration Modal

- [ ] Route ordinary app-domain `registerPasskey()` through
      `modal_registration_confirm` when iframe user activation is required.
- [ ] Render the wallet-origin registration modal from modal surface state.
- [ ] Bind wallet ID, rpID, request ID, and registration digest before the modal
      confirm button can start WebAuthn.
- [ ] Remove registration-specific fullscreen locks and preflight overlay show.
- [ ] Ensure modal cancellation hides only the matching request surface.
- [ ] Keep server-allocated wallet behavior only for direct/headless
      registration where no wallet ID was shown to the user.

Validation:

- [ ] Unit: code-only registration creates `modal_registration_confirm`.
- [ ] Unit: stale modal result cannot hide a newer active surface.
- [ ] Browser: modal displays intended user name and rpID.
- [ ] Browser: WebAuthn starts only after wallet-origin confirm click.

### Phase 5: Convert Request Modal Flows

- [ ] Convert transaction signing requests to `modal_transaction_confirm`.
- [ ] Convert key export requests to `modal_key_export_confirm`.
- [ ] Convert unlock and device-link requests to `modal_unlock_confirm` or a
      more specific branch if the flows differ materially.
- [ ] Replace progress-bus show/hide authority with typed surface transitions.
- [ ] Keep progress events for content, diagnostics, and app callbacks.
- [ ] Remove sticky overlay state after all modal request flows use surfaces.
- [ ] Remove request preflight fullscreen demand after all activation-required
      request types use surfaces.

Validation:

- [ ] Unit: concurrent request attempts choose one active surface deterministically.
- [ ] Unit: finishing request A cannot hide request B's surface.
- [ ] Unit: timeout for request A cannot cancel request B's surface.
- [ ] Unit: progress events cannot show or hide the iframe directly.
- [ ] Browser: modal surfaces focus trap only while active.
- [ ] Browser: hidden iframe never blocks clicks.

### Phase 6: Design Signing Activation Surfaces

- [ ] Draft a separate API plan for app-owned custom transaction confirmers.
- [ ] Bind signing activation proofs to request ID, wallet ID, chain, and
      transaction digest.
- [ ] Define whether the localized signing surface covers only the final CTA or
      a larger wallet-owned confirmation region.
- [ ] Add app-facing docs that explain app-origin UI as part of user-intent
      trust.
- [ ] Keep the wallet-origin modal confirmer as the default for apps that do not
      opt into localized signing activation.

This phase should start after registration proves the browser activation model
across Chromium and Safari/WebKit.

### Phase 7: Delete Imperative Overlay Paths

- [ ] Remove `forceFullscreen`.
- [ ] Remove sticky overlay suppression if no remaining surface needs it.
- [ ] Remove `showFrameForActivation()` and `hideFrameForActivation()` after
      progress-bus ownership is gone.
- [ ] Remove `computeOverlayIntent()` fullscreen preflight.
- [ ] Remove `REGISTER_BUTTON_SUBMIT` fullscreen forcing.
- [ ] Remove compatibility comments and tests that assert fullscreen
      registration activation.
- [ ] Keep only boundary compatibility that is still required for persisted
      records or public request payloads.

## Testing Strategy

Use the cheapest checks that cover the risk in each phase.

Required static and unit coverage:

- surface union type fixtures
- reducer transition tests
- stale event rejection tests
- request correlation tests
- parser tests for raw postMessage payloads
- source guards for direct overlay mutation

Required browser coverage:

- registration activation geometry
- trusted activation to WebAuthn from iframe button
- WebKit/Safari transient activation behavior
- focus forwarding and keyboard activation
- modal focus management
- hidden iframe click-through behavior
- scroll, resize, nested scroll containers, visual viewport changes

Run full SDK build when shared public types, message schemas, registration
flows, signing flows, or overlay controller APIs change.

## Acceptance Criteria

- `SeamsAuthMenu` passkey registration uses a button-sized wallet-origin iframe
  activation surface.
- Code-only passkey registration uses a typed wallet-origin modal registration
  surface.
- Registration no longer uses fullscreen preflight or fullscreen submit locks.
- Router visibility is derived from one `WalletIframeSurface` value.
- Progress events no longer directly show or hide the iframe.
- Stale request, activation, and progress messages cannot affect the active
  surface.
- Hidden iframe state cannot block app clicks or receive focus.
- WebAuthn remains wallet-origin for interoperable embedded wallet passkeys.
- Chromium and Safari/WebKit browser validation cover the registration
  activation path before release.
