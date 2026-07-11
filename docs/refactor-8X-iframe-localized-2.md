# Localized Wallet Iframe Surfaces

Date created: July 10, 2026

Status: Phases 0-3 implemented. Cross-browser validation remains open.

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
type WalletIframeSurfaceId = string & {
  readonly __walletIframeSurfaceId: unique symbol;
};

type RequestId = string & {
  readonly __requestId: unique symbol;
};

type RegistrationActivationId = string & {
  readonly __registrationActivationId: unique symbol;
};

type RequestSurfaceIdentity = {
  kind: 'request_surface_identity_v1';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  activationId?: never;
};

type RegistrationActivationSurfaceIdentity = {
  kind: 'registration_activation_surface_identity_v1';
  surfaceId: WalletIframeSurfaceId;
  requestId: RequestId;
  activationId: RegistrationActivationId;
};

type ProvidedPasskeyRegistrationWallet = {
  kind: 'provided';
  walletId: WalletId;
};

type ResolvedPasskeyRegistrationWallet =
  | ProvidedPasskeyRegistrationWallet
  | { kind: 'server_allocated_resolved'; walletId: WalletId };

type PasskeyRegistrationPreparationReceipt = {
  kind: 'passkey_registration_preparation_receipt_v1';
  expiresAtMs: number;
};

type PasskeyRegistrationPreparationData<
  Wallet extends ResolvedPasskeyRegistrationWallet = ResolvedPasskeyRegistrationWallet,
> = {
  wallet: Wallet;
  rpId: WebAuthnRpId;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  challengeB64u: string;
  display: PasskeyRegistrationConfirmDisplay;
  expiresAtMs: number;
};

type WalletIframePreparedPasskeyRegistration =
  | {
      kind: 'wallet_iframe_prepared_activation_registration_v1';
      data: PasskeyRegistrationPreparationData<ProvidedPasskeyRegistrationWallet>;
      confirmation: {
        kind: 'iframe_activation_confirmation_armed';
        requiredProof: 'wallet_iframe_activation';
      };
      warmup: {
        kind: 'complete';
        registrationWarmup: 'complete';
        activationElement: 'defined_or_fallback_ready';
      };
    }
  | {
      kind: 'wallet_iframe_prepared_modal_registration_v1';
      data: PasskeyRegistrationPreparationData;
      confirmation: {
        kind: 'wallet_confirm_button_required';
      };
      warmup: {
        kind: 'complete';
        registrationWarmup: 'complete';
        modal: 'rendered_and_focusable';
      };
    };

type WalletIframeSurface =
  | HiddenWalletIframeSurface
  | AnchoredRegistrationActivationSurface
  | ModalRegistrationConfirmSurface
  | ModalTransactionConfirmSurface
  | ModalKeyExportConfirmSurface
  | ModalUnlockConfirmSurface;

type HiddenWalletIframeSurface = {
  kind: 'hidden';
  identity?: never;
};

type AnchoredRegistrationPlacement =
  | {
      kind: 'interactive';
      targetRect: RegistrationActivationTargetRect;
    }
  | {
      kind: 'suspended';
      reason: 'ancestor_clipped';
      lastTargetRect: RegistrationActivationTargetRect;
    };

type AnchoredRegistrationFocusOwner =
  | { kind: 'outside' }
  | { kind: 'proxy' }
  | { kind: 'iframe_button' };

type AnchoredRegistrationActivationSurface = {
  kind: 'anchored_registration_activation';
  identity: RegistrationActivationSurfaceIdentity;
  wallet: ProvidedPasskeyRegistrationWallet;
  preparation: PasskeyRegistrationPreparationReceipt;
  presentation: RegistrationActivationButtonPresentation;
  placement: AnchoredRegistrationPlacement;
  focusOwner: AnchoredRegistrationFocusOwner;
};

type ModalRegistrationConfirmSurface = {
  kind: 'modal_registration_confirm';
  identity: RequestSurfaceIdentity;
  preparation: PasskeyRegistrationPreparationReceipt;
  userActivation: 'wallet_confirm_button_required';
};

type ModalTransactionConfirmSurface = {
  kind: 'modal_transaction_confirm';
  identity: RequestSurfaceIdentity;
  chain: ChainId;
  transactionDigest: TransactionDigest;
  userActivation: 'wallet_confirm_button_required';
};

type ModalKeyExportConfirmSurface = {
  kind: 'modal_key_export_confirm';
  identity: RequestSurfaceIdentity;
  exportKind: 'near_keypair' | 'threshold_ed25519_seed_from_hss_report';
  userActivation: 'wallet_confirm_button_required';
};

type ModalUnlockConfirmSurface = {
  kind: 'modal_unlock_confirm';
  identity: RequestSurfaceIdentity;
  unlockKind: 'passkey' | 'device_link';
  userActivation: 'wallet_confirm_button_required';
};
```

`WalletIframePreparedPasskeyRegistration` is wallet-iframe host state and never
enters the app-origin router. The router receives only
`PasskeyRegistrationPreparationReceipt`, whose expiry supports parent-side
cleanup. The wallet iframe rechecks its authoritative expiry and complete
prepared record when activation occurs. The receipt cannot authorize WebAuthn
or reconstruct the prepared registration.

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
  | { kind: 'anchored_interactive'; rect: DOMRectLike; title: string }
  | { kind: 'anchored_suspended'; title: string }
  | { kind: 'viewport_modal'; title: string; focusTrap: true };

function renderAnchoredRegistrationActivationSurface(
  surface: AnchoredRegistrationActivationSurface,
): WalletIframeSurfaceRenderMode {
  switch (surface.placement.kind) {
    case 'interactive':
      return {
        kind: 'anchored_interactive',
        rect: surface.placement.targetRect,
        title: surface.presentation.accessibleLabel,
      };
    case 'suspended':
      return {
        kind: 'anchored_suspended',
        title: surface.presentation.accessibleLabel,
      };
    default:
      return assertNever(surface.placement);
  }
}

function renderWalletIframeSurface(surface: WalletIframeSurface): WalletIframeSurfaceRenderMode {
  switch (surface.kind) {
    case 'hidden':
      return { kind: 'hidden' };
    case 'anchored_registration_activation':
      return renderAnchoredRegistrationActivationSurface(surface);
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
- `applyAnchoredSuspended(accessibility)`
- `applyViewportModal(accessibility)`

`applyAnchoredSuspended()` keeps surface ownership and geometry observers alive
while setting the iframe hidden, inert, unfocusable, and unable to receive
pointer events. It never reuses the ownerless `hidden` surface state.

The router should own `WalletIframeSurface`. The overlay controller should own
only DOM effects derived from a surface render mode.

## Transition Events

Surface transitions should be explicit domain events:

```ts
type WalletIframeSurfaceEvent =
  | {
      kind: 'registration_activation_prepared';
      identity: RegistrationActivationSurfaceIdentity;
      wallet: ProvidedPasskeyRegistrationWallet;
      preparation: PasskeyRegistrationPreparationReceipt;
      presentation: RegistrationActivationButtonPresentation;
      placement: AnchoredRegistrationPlacement;
    }
  | {
      kind: 'registration_activation_placement_changed';
      identity: RegistrationActivationSurfaceIdentity;
      placement: AnchoredRegistrationPlacement;
    }
  | {
      kind: 'registration_activation_focus_owner_changed';
      identity: RegistrationActivationSurfaceIdentity;
      focusOwner: AnchoredRegistrationFocusOwner;
    }
  | {
      kind: 'registration_activation_cancelled';
      identity: RegistrationActivationSurfaceIdentity;
      reason: RegistrationActivationCancellationReason;
    }
  | {
      kind: 'registration_activation_finished';
      identity: RegistrationActivationSurfaceIdentity;
    }
  | {
      kind: 'registration_modal_request_started';
      identity: RequestSurfaceIdentity;
      preparation: PasskeyRegistrationPreparationReceipt;
    }
  | {
      kind: 'transaction_modal_request_started';
      identity: RequestSurfaceIdentity;
      chain: ChainId;
      transactionDigest: TransactionDigest;
    }
  | {
      kind: 'key_export_modal_request_started';
      identity: RequestSurfaceIdentity;
      exportKind: 'near_keypair' | 'threshold_ed25519_seed_from_hss_report';
    }
  | {
      kind: 'unlock_modal_request_started';
      identity: RequestSurfaceIdentity;
      unlockKind: 'passkey' | 'device_link';
    }
  | {
      kind: 'request_finished';
      identity: RequestSurfaceIdentity;
    }
  | {
      kind: 'request_cancelled';
      identity: RequestSurfaceIdentity;
    };
```

Every reducer branch must compare the event identity to the active surface
identity before mutating state. For example, a
`registration_activation_placement_changed` event with the wrong
`activationId` cannot move the iframe.

## Message Identity Contract

Every message that can affect iframe visibility, geometry, focus, activation, or
modal completion must parse into a typed identity before reaching the reducer.

```ts
type WalletIframeConnectionId = string & {
  readonly __walletIframeConnectionId: unique symbol;
};

type WalletIframeWireMessageIdentity =
  | RegistrationActivationSurfaceIdentity
  | RequestSurfaceIdentity;

type TrustedWalletIframeInboundIdentity = {
  kind: 'trusted_wallet_iframe_inbound_identity_v1';
  connectionId: WalletIframeConnectionId;
  wireIdentity: WalletIframeWireMessageIdentity;
};
```

Rules:

- `connectionId` is created by the active wallet iframe handshake. It is trusted
  transport metadata and never appears in serialized postMessage payloads.
- The router authenticates the owning `MessagePort`, parses the wire identity,
  and attaches `connectionId` exactly once before creating internal events.
- A reconnected wallet iframe receives a new `connectionId`; messages from the
  old connection become stale.
- Parent-to-child messages include the complete wire identity for the active
  branch.
- Registration activation messages use
  `RegistrationActivationSurfaceIdentity`; other request surfaces use
  `RequestSurfaceIdentity` and cannot carry `activationId`.
- Child-to-parent messages that lack the active identity are ignored.
- Messages with matching `requestId` and mismatched `surfaceId` are stale.
- Messages with matching `surfaceId` and mismatched `requestId` are stale.
- `PM_CANCEL` carries the complete wire identity required by the target surface.
- Core surface logic has no identity-free global cancel. Connection teardown is
  a separate trusted event carrying `connectionId`; it may clear only the active
  surface owned by that connection.
- Raw postMessage payloads are parsed once at the router or host boundary.
  Internal code consumes typed surface events.
- Router-local geometry and focus events carry the complete surface identity but
  have no `connectionId`, because they did not arrive from the iframe transport.

## Surface Arbitration

The router has one foreground surface. A foreground surface is any surface that
can make the iframe visible, focusable, or able to receive pointer events.

Arbitration returns a result instead of throwing an untyped exception:

```ts
type ForegroundWalletIframeSurface = Exclude<
  WalletIframeSurface,
  HiddenWalletIframeSurface
>;

type WalletIframeSurfaceBusyError = {
  kind: 'wallet_iframe_surface_busy';
  activeSurfaceKind: ForegroundWalletIframeSurface['kind'];
  attemptedSurfaceKind: ForegroundWalletIframeSurface['kind'];
  retry: 'after_active_surface_finishes';
};

type BeginForegroundWalletIframeSurfaceResult =
  | { kind: 'started'; surface: ForegroundWalletIframeSurface }
  | { kind: 'idempotent'; surface: ForegroundWalletIframeSurface }
  | { kind: 'rejected'; error: WalletIframeSurfaceBusyError };
```

The public error excludes active request, wallet, transaction, and activation
identifiers. Internal diagnostics may record those values after boundary
redaction rules are applied.

Arbitration policy:

- `hidden` may transition to any foreground surface.
- A second foreground request with the same complete branch identity is an
  idempotent replay and returns the current surface state.
- A second foreground request with any different identity field is rejected with
  a typed `wallet_iframe_surface_busy` error.
- Background/read-only requests may run while a foreground surface is active
  only when they do not request iframe visibility, focus, pointer events, or
  user activation.
- Background progress events may call app callbacks and update diagnostics.
  They cannot mutate `WalletIframeSurface`.
- Completion, timeout, or cancellation for request A can hide the iframe only
  when request A owns the active surface.
- A timeout for the active surface sends best-effort cancel for that surface and
  transitions to `hidden`.
- A timeout for a background request leaves the active surface unchanged.
- The first implementation should reject competing foreground surfaces instead
  of queueing them. Queueing can be added later with an explicit queue state.
- Rejection leaves the active surface, timers, observers, focus state, and
  cleanup ownership unchanged. The attempted surface installs no resources.
- Direct APIs return the typed rejected result through their existing
  recoverable-error channel.
- `SeamsAuthMenu` maps a busy rejection to a non-interactive waiting state and
  retries surface construction when the router returns to `hidden`, provided the
  mounted component, mode, and wallet identity still match. This consumer-level
  retry does not add a router queue.

## Router Invariants

- The router has exactly one `WalletIframeSurface` value.
- The hidden state owns no request, activation, or surface identity.
- Every active surface stores identity once in its branch-specific `identity`
  field. Wallet-iframe prepared registration stores no surface or request
  identity.
- Anchored registration activation must have a provided wallet ID.
- Anchored registration activation receives a preparation receipt only after the
  wallet iframe has stored registration intent, challenge, rpID, display model,
  and authoritative expiry.
- Anchored registration activation must have a non-expired activation ID.
- Modal registration surfaces must have a preparation receipt before they become
  visible. The wallet iframe must still have complete prepared registration data
  before enabling its confirm button.
- Wallet-iframe modal prepared state contains a provided wallet or a resolved
  server allocation with a concrete wallet ID.
- Wallet-iframe prepared registration owns the authoritative expiry. The surface
  receipt reports that expiry for cleanup and supplies no independent authority.
- Modal surfaces must have a request ID and surface ID.
- Only the active surface can update iframe geometry.
- Only the active surface can make the iframe focusable.
- Progress events cannot directly show or hide the iframe.
- Parent-window messages cannot transition surfaces unless every identity field
  required by the active branch matches.
- Child-window messages cannot transition surfaces without matching
  `connectionId`, `surfaceId`, and `requestId`.
- Registration child messages also require matching `activationId`.
- `connectionId` comes from the authenticated transport and is absent from wire
  payloads.
- Host-origin messages cannot mint `walletIframeActivation`.
- App-origin API calls cannot supply trusted activation proofs.
- Cleanup is owned by the surface that installed listeners, timers, geometry
  observers, focus proxies, and state mirrors.

## Registration Path

`docs/refactor-8X-iframe-registration-button.md` is the first localized surface
reference implementation. This plan migrates that working flow into the shared
surface reducer and renderer. It must preserve the registration protocol, UI,
prompt reservation, activation timing, and security behavior rather than
rebuilding them in parallel.

Activation-button registration:

1. `SeamsAuthMenu` builds a wallet-bound registration draft.
2. `createPasskeyRegistrationActivationSurface()` creates a surface ID and
   activation ID.
3. The host prepares wallet ID, rpID, registration intent digest, WebAuthn
   challenge, display data, warmup, and no-UI confirmation.
4. The wallet iframe stores prepared registration under the complete activation
   identity and sends `READY` with identity and expiry only.
5. The router transitions to `anchored_registration_activation` only after the
   prepared registration is ready.
6. The renderer positions the iframe over the CTA border box.
7. The wallet iframe renders the real registration button.
8. The user click lands in wallet-origin DOM.
9. The host atomically consumes prepared state and mints
   `walletIframeActivation`.
10. `continuePreparedIframePasskeyRegistration()` calls WebAuthn before its
    first `await`.
11. The active surface finishes and transitions to `hidden`.

Code-only registration:

1. App-origin code calls `registration.registerPasskey()`.
2. The host resolves a provided or server-allocated wallet ID, then prepares
   rpID, registration intent digest, WebAuthn challenge, display data, and
   expiry.
3. The router transitions to `modal_registration_confirm`.
4. The wallet iframe renders a registration-specific confirmation modal.
5. The user clicks the wallet-origin confirm button.
6. WebAuthn starts from the wallet-origin event chain.
7. The active surface finishes and transitions to `hidden`.

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
- Tab and Shift+Tab leave the iframe through a typed focus-exit bridge and
  continue relative to the app-domain proxy's visual tab position
- the app-domain proxy and iframe button must not be announced as duplicate
  unrelated controls
- modal surfaces use wallet-origin focus management
- hidden iframe state is inert, `aria-hidden`, and unfocusable
- cleanup restores only attributes changed by the active surface
- focus-entry and focus-exit events carry complete active-surface identity and
  are ignored after release
- cleanup restores focus to the proxy only while focus still belongs to the
  released iframe surface

## Geometry Contract

Anchored surfaces must:

- measure with `target.getBoundingClientRect()`
- reject targets narrower than `44` CSS pixels or shorter than `44` CSS pixels
- reject detached targets
- reject `display: none`
- reject `visibility: hidden` or `visibility: collapse`
- reject `content-visibility: hidden` and inert targets or ancestors
- reject effective target-and-ancestor opacity below `0.1`
- identify clipping ancestors from `overflow-x` and `overflow-y` values of
  `hidden`, `clip`, `auto`, or `scroll`
- transition placement to `suspended/ancestor_clipped` while any clipping
  ancestor hides part of the target border box
- keep suspended surfaces hidden, inert, unfocusable, and unable to receive
  pointer events while retaining ownership and geometry observers
- resume an unexpired suspended surface only when the complete target border box
  is visible inside every clipping ancestor
- update on `ResizeObserver`
- update on document scroll
- update on scrollable ancestor movement
- update on `visualViewport` scroll and resize
- align within 1 CSS pixel in browser tests
- cancel when the target becomes unavailable

The renderer should centralize all fixed-position iframe geometry. Router code
should set surface state, then let the renderer apply the resulting mode.

## Implementation Phases

### Phase 0 Inventory

Direct overlay mutation is currently confined to the legacy paths in
`walletIframe/client/router.ts` and the low-level writes in
`walletIframe/client/overlay/overlay-controller.ts`. The surface renderer owns
all registration activation writes. A source guard caps the remaining router
calls so later work can remove them without allowing new imperative call sites.

| Current call site | Classification | Phase |
| --- | --- | --- |
| `REGISTER_BUTTON_SUBMIT` window-message handler | legacy registration modal submit | 4 |
| `registerWallet()` and `addWalletSigner()` | registration modal | 4 |
| `post()` fullscreen preflight | transaction, signing, key export, unlock, and device link | 5 |
| progress-bus show/hide adapters | foreground request progress | 5 |
| `setOverlayVisible()` and `setOverlayBounds()` | public diagnostics/tools | 7 |
| registration activation renderer | anchored registration activation | complete in Phase 3 |

Current request types requiring wallet-origin user activation are
`PM_EXPORT_KEYPAIR_UI`, `PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI`,
`PM_UNLOCK`, `PM_SIGN_AND_SEND_TX`, `PM_EXECUTE_ACTION`, `PM_SEND_TRANSACTION`,
`PM_SIGN_TX_WITH_ACTIONS`, `PM_SIGN_DELEGATE_ACTION`, `PM_SIGN_NEP413`,
`PM_SIGN_TEMPO`, `PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION`,
`PM_LINK_DEVICE_WITH_SCANNED_QR_DATA`, `PM_SHOW_EMAIL_OTP_RECOVERY_CODES`, and
`PM_ROTATE_EMAIL_OTP_RECOVERY_CODES`. They remain legacy foreground requests
until Phase 5. Registration activation is the first reducer-owned foreground
surface. Other request types remain background/read-only unless a future phase
gives them an explicit foreground surface event; their progress cannot mutate
the reducer-owned registration surface.

### Phase 0: Inventory And Guardrails

- [x] List all direct calls to `showFullscreen()`, `showAnchored()`,
      `setOverlayVisible()`, `setOverlayBounds()`, `setSticky()`, and
      `forceFullscreen`.
- [x] Classify each call site as registration activation, registration modal,
      transaction confirm, key export, unlock, device link, or diagnostics.
- [x] Add source-guard coverage preventing new direct fullscreen calls outside
      the surface renderer.
- [x] Document current request types that require wallet-origin user activation.
- [x] Document which current requests are foreground surfaces and which remain
      background/read-only while a surface is active.
- [x] Delete obsolete comments that describe fullscreen as the default
      activation mechanism after a call site moves to surfaces.

### Phase 1: Introduce Surface Domain Types

- [x] Add `WalletIframeSurface` and `WalletIframeSurfaceEvent` unions.
- [x] Add branded `WalletIframeSurfaceId`, `WalletIframeConnectionId`,
      `RequestId`, and `RegistrationActivationId` boundary parsers.
- [x] Add branch-specific builders for each surface.
- [x] Add an exhaustive reducer that applies transition events.
- [x] Add foreground surface arbitration with a typed
      `wallet_iframe_surface_busy` rejection.
- [x] Return `started`, `idempotent`, and `rejected` arbitration branches; busy
      rejection must install no resources and preserve the active owner.
- [x] Split serialized wire identity from trusted inbound identity and attach
      `connectionId` from the authenticated `MessagePort` at the boundary.
- [x] Add `assertNever` coverage for surface and event switches.
- [x] Add type fixtures rejecting invalid states:
      - hidden with request ID
      - anchored registration without activation ID
      - anchored registration with `server_allocated_resolved` wallet
      - anchored registration without a preparation receipt
      - code-only registration modal without a preparation receipt
      - wallet-iframe prepared registration with unresolved `server_allocated`
      - app-origin surface state containing challenge, intent digest, or
        confirmation state
      - surface branches with an independent expiry outside the preparation
        receipt
      - modal transaction without request ID
      - broad object-spread construction that smuggles incompatible branch
        fields
- [x] Keep raw postMessage payload parsing at router and host boundaries.
- [x] Convert parsed payloads into precise internal surface events immediately.
- [x] Add stale-message tests for mismatched `connectionId`, `surfaceId`,
      `requestId`, and `activationId`.
- [x] Add parser tests proving serialized payloads cannot supply
      `connectionId`.

### Phase 2: Surface Renderer

- [x] Add a renderer that maps `WalletIframeSurface` to hidden,
      anchored-interactive, anchored-suspended, or viewport-modal render modes.
- [x] Restrict `OverlayController` to low-level DOM writes derived from render
      modes.
- [x] Remove router-level `forceFullscreen` from new surface paths.
- [x] Make focusability, `aria-hidden`, iframe title, pointer events, and
      geometry derived from the render mode.
- [x] Add unit tests proving each surface renders the expected overlay mode.
- [x] Add cleanup tests proving stale render modes cannot revive an old surface.
- [x] Prove anchored-suspended retains surface ownership while removing iframe
      visibility, focusability, and pointer events.

### Phase 3: Migrate The Registration Reference Surface

The registration-button implementation is the behavioral baseline for this
phase. Keep its public API, host protocol, prepared-registration lifecycle,
WebAuthn prompt coordinator, iframe button, geometry policy, focus behavior,
and wallet-origin-only registration policy. Do not add a second registration
surface implementation or a compatibility switch between old and new paths.

Existing reference behavior to preserve:

- [x] `createPasskeyRegistrationActivationSurface()` exposes only
      `outline_overlay` with a provided wallet identity.
- [x] The host prepares registration and acquires the activation-owned WebAuthn
      reservation before `READY`; `READY` exposes identity and expiry only.
- [x] The builder-only activated continuation consumes prepared state and starts
      `navigator.credentials.create()` inline from the wallet-origin click.
- [x] Target geometry enforces size, visibility, opacity, inert, detached, and
      clipping rules, including suspension and recovery.
- [x] Duplicate, expired, disposed, replaced, and stale activations cannot start
      registration; resource ownership is identity-scoped and single-release.
- [x] Registration never falls back to parent-domain WebAuthn creation.

Migration tasks:

- [x] Represent the existing activation lifecycle as
      `anchored_registration_activation` reducer state and typed surface events.
- [x] Adapt the existing registration identity, prepared state, reservation,
      presentation, and cancellation types to the shared surface domain without
      introducing duplicate registration-specific lifecycle types.
- [x] Route activation mount, readiness, geometry, focus, suspension, start,
      completion, cancellation, expiry, replacement, and failure through the
      shared foreground-surface arbitration and reducer.
- [x] Move the existing geometry observers, focus proxy, mirrored attributes,
      timers, and message subscriptions into the active surface cleanup owner.
- [x] Make the shared renderer the only code that applies anchored, suspended,
      or hidden overlay DOM state for registration activation.
- [x] Remove the activation-specific anchored overlay lease after equivalent
      ownership and busy rejection are enforced by the shared surface domain.
- [x] Delete direct registration overlay mutations and obsolete registration
      surface state after the reducer-backed path is complete.

Migration validation:

- [x] Unit: reducer rejects stale registration geometry, focus, readiness, and
      completion events by connection, surface, request, and activation identity.
- [x] Unit: competing foreground requests preserve the active registration
      surface and install no loser-owned effects.
- [x] Unit: disposal and replacement clean only the matching surface and stale
      cleanup cannot hide or move its successor.
- [ ] Regression: all registration-button type, host, component, router,
      geometry, accessibility, origin-policy, and Chromium activation checks pass
      unchanged against the reducer-backed implementation.
- [ ] Browser: each supported WebKit/Safari version covers the existing native
      wallet-origin success path or typed unsupported branch without a parent
      bridge request.

### Phase 4: Convert Code-Only Registration Modal

- [ ] Route ordinary app-domain `registerPasskey()` through
      `modal_registration_confirm` when iframe user activation is required.
- [ ] Render the wallet-origin registration modal from modal surface state.
- [ ] Bind wallet ID, rpID, request ID, and registration digest before the modal
      confirm button can start WebAuthn.
- [ ] Bind WebAuthn challenge and expiry before enabling the modal confirm
      button.
- [ ] Reserve the shared WebAuthn prompt coordinator before enabling the modal
      confirm button and release it on every terminal modal transition.
- [ ] Resolve server allocation to a concrete wallet ID before constructing
      prepared modal state or enabling confirm.
- [ ] Remove registration-specific fullscreen locks and preflight overlay show.
- [ ] Ensure modal cancellation hides only the matching request surface.
- [ ] Keep pending server allocation outside renderable modal surface state.

Validation:

- [ ] Unit: code-only registration creates `modal_registration_confirm`.
- [ ] Unit: stale modal result cannot hide a newer active surface.
- [ ] Unit: modal confirm after prepared registration expiry rejects before
      WebAuthn.
- [ ] Type fixture: modal prepared state rejects unresolved server allocation.
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
- [ ] Unit: public busy errors expose surface kinds without request, wallet,
      activation, or transaction identifiers.
- [ ] Unit: finishing request A cannot hide request B's surface.
- [ ] Unit: timeout for request A cannot cancel request B's surface.
- [ ] Unit: background/read-only request progress cannot mutate the active
      foreground surface.
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

This phase should start after registration proves the native browser activation
model in Chromium and the supported Safari/WebKit matrix, including the typed
unsupported branch with no parent-domain registration fallback.

### Phase 7: Delete Imperative Overlay Paths

- [ ] Remove `forceFullscreen`.
- [ ] Remove sticky overlay suppression if no remaining surface needs it.
- [ ] Remove `showFrameForActivation()` and `hideFrameForActivation()` after
      progress-bus ownership is gone.
- [ ] Remove `computeOverlayIntent()` fullscreen preflight.
- [ ] Remove `REGISTER_BUTTON_SUBMIT` fullscreen forcing.
- [ ] Remove compatibility comments and tests that assert fullscreen
      registration activation.
- [ ] Delete obsolete public request and fullscreen compatibility paths. Retain
      persisted-record compatibility only when an owned deletion condition is
      documented at that boundary.

## Testing Strategy

Use the cheapest checks that cover the risk in each phase.

Required static and unit coverage:

- surface union type fixtures
- reducer transition tests
- stale event rejection tests
- request correlation tests
- parser tests for raw postMessage payloads
- tests proving `connectionId` comes from authenticated transport metadata and
  cannot be supplied on the wire
- arbitration result and resource-ownership tests
- prepared-registration type fixtures for resolved wallet, complete surface
  identity, wallet-authoritative expiry, receipt-only app state, and narrow
  continuation input
- WebAuthn prompt reservation ownership and exact-once cleanup tests
- source guards preventing registration from using the parent-domain WebAuthn
  create bridge
- source guards for direct overlay mutation

Required browser coverage:

- registration activation geometry
- trusted activation to WebAuthn from iframe button
- WebKit/Safari native wallet-origin success and typed unsupported behavior
- focus forwarding and keyboard activation
- forward and reverse Tab egress relative to the app-domain focus proxy
- modal focus management
- hidden iframe click-through behavior
- scroll, resize, nested scroll containers, visual viewport changes
- clipping-ancestor suspension and recovery

Run full SDK build when shared public types, message schemas, registration
flows, signing flows, or overlay controller APIs change.

## Acceptance Criteria

- `SeamsAuthMenu` passkey registration uses a button-sized wallet-origin iframe
  activation surface.
- Code-only passkey registration uses a typed wallet-origin modal registration
  surface.
- Registration no longer uses fullscreen preflight or fullscreen submit locks.
- Router visibility is derived from one `WalletIframeSurface` value.
- Foreground surface arbitration rejects competing visible/focusable surfaces
  with a typed, redacted error while preserving the active owner's resources.
- Progress events no longer directly show or hide the iframe.
- Stale request, activation, and progress messages cannot affect the active
  surface.
- Serialized surface messages carry complete branch-specific wire identity.
  Trusted inbound boundary records additionally carry the `connectionId`
  attached from the authenticated `MessagePort`; the boundary validates it
  before constructing a reducer event.
- Active surfaces store identity once. Wallet-iframe prepared registration owns
  the authoritative expiry; app-origin surface state receives an expiry-only
  preparation receipt.
- Server-allocated registration becomes renderable only after allocation
  resolves to a concrete wallet ID.
- Registration `READY` messages expose identity and expiry while prepared
  challenge, intent, confirmation, and warmup state remain wallet-iframe
  internal.
- Registration `READY` also requires a live WebAuthn prompt reservation owned by
  the active surface identity.
- Activation-button registration reaches `navigator.credentials.create()` from a
  narrow, pre-armed wallet-origin continuation before its first `await` in
  Chromium and every supported Safari/WebKit version.
- Registration never delegates credential creation to the app-origin parent.
  Unsupported Safari/WebKit versions return
  `wallet_origin_webauthn_unavailable` and create no app-origin credential.
- Hidden iframe state cannot block app clicks or receive focus.
- Clipped anchored targets suspend iframe visibility and pointer routing until
  the complete CTA is visible again.
- Tab and Shift+Tab leave anchored surfaces at the app proxy's visual tab
  position.
- WebAuthn remains wallet-origin for interoperable embedded wallet passkeys.
- Chromium validation and the supported Safari/WebKit matrix cover the
  registration activation path before release.
