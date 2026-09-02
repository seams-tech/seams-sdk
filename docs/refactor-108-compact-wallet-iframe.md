# Refactor 108: Compact Wallet-Iframe Geometry

Date created: August 6, 2026

Status: implementation landed on `refactor-108`; focused gates and live browser
recheck are passing. The remaining broad-gate caveats are recorded below.

## Goal

Render every foreground Lit surface in a compact cross-origin iframe while
keeping wallet-origin UI and actions authoritative:

- centered compact modal for registration, transaction, key export, unlock,
  recovery, and device-link confirmation when the resolved presentation is
  `modal`;
- compact bottom drawer for surfaces whose normalized confirmation presentation is
  `drawer`;
- centered compact modal for the wallet-origin `SeamsAuthMenu` surface;
- hidden state with no footprint, pointer events, or focusability;
- a responsive viewport fallback when a compact rectangle cannot fit the
  visual viewport or the child cannot provide a safe measurement yet.

The app document owns the iframe's geometry, top-layer placement, backdrop,
inertness, and focus restoration. The wallet iframe owns all interactive Lit
content, WebAuthn activation, operation state, and close actions. The two
documents communicate through the existing authenticated wallet-iframe bridge.

## Current anchors

The compact renderer now owns the complete surface union and calls the native
dialog controller for every active surface:

- `packages/wallet/src/SeamsWeb/walletIframe/client/surface/domain.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/surface/renderer.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/router.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/overlay/overlay-controller.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/overlay/overlay-styles.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/transport/iframe-transport-dom.ts`

The wallet host has two relevant mounting paths:

- `packages/wallet/src/SeamsWeb/walletIframe/host/lit-ui/iframe-lit-elem-mounter.ts`
  supports `iframe` and `viewport` anchoring and owns generic registry mounts;
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/session.ts` mounts
  `seams-auth-menu-surface` directly. Refactor 110 owns this path, so the auth
  menu remains outside `WalletUIRegistry` while reusing
  `host/lit-ui/surface-measurement-reporter.ts`.

Foreground request and export surfaces bind that same reporter through the
required `UiConfirmSurfaceMeasurementBinding` passed by `host/runtimeContext.ts`;
the generic registry mounter remains responsible for registry mounts and its
existing anchor enter/leave events. It does not derive foreground surface
identity from a component id.

The Lit roots now paint content shells. Modal and drawer backdrops remain only
for standalone, document-owned confirmations; wallet-iframe surfaces use the
parent dialog backdrop.

## Decision: host-owned native dialog

Create one parent-document native `<dialog>` wrapper for the active wallet
iframe. The dialog is a top-layer child of the app document and contains the
iframe as its only surface child; it is reused across surface generations.
Create the iframe directly inside this dialog before the CONNECT/READY
handshake. Reparenting a connected iframe reloads its document and invalidates
the authenticated `MessagePort`.

- Modal and auth-menu surfaces call `dialog.showModal()`. The native top layer,
  `::backdrop`, background inerting, Escape `cancel`, and focus restoration are
  the default behavior.
- Drawers also use `showModal()` because confirmation drawers block competing
  app interaction. Their `::backdrop` is transparent by default, preserving
  bottom-sheet semantics without allowing accidental clicks through the drawer.
  A product decision can make the backdrop visibly dim later without changing
  ownership or correlation.
- `dialog` has transparent border, padding, and background. Its explicit width
  and height match the iframe rectangle. The iframe is a block child with
  `width: 100%`, `height: 100%`, no border, and a transparent document surface.
- `dialog::backdrop` belongs to the host document and spans the full viewport
  independently of the compact iframe rectangle. The iframe cannot paint this
  backdrop across its parent document.
- The dialog `cancel` event is prevented while the exact active cancellation is
  sent. Backdrop dismissal records a `pointerdown` (including its
  `pointerId`) and accepts dismissal only when the matching `pointerup` is also
  outside the dialog/iframe content bounds. A drag that starts inside the
  iframe, crosses the edge, and ends outside never dismisses the surface.
  Clicks inside the iframe never become host dismissals.
- The host calls the existing correlated bridge only:
  `router.cancelRequest(requestId)` for request surfaces, or
  `router.cancelHostedAuthMenu({ authMenuSessionId })` for the auth menu. The
  request/surface/session identity is captured by the active generation. The
  controller supplies the complete internal identity to the router, which
  rechecks the active surface before invoking either existing method; the wire
  cancellation then carries the existing request ID (and auth-menu session plus
  request ID for `PM_CANCEL_AUTH_MENU`). There is no identity-free `cancelAll`
  path for backdrop or Escape.
- A child close button, success, failure, or timeout follows the existing
  terminal response path. The router transitions the matching surface to
  `hidden`; the controller then calls `dialog.close()`, disconnects observers,
  and restores focus for that generation.

Removing the backdrop was evaluated and is rejected as the default. A compact
cross-origin iframe cannot dim or inert the parent document. Removing the
backdrop leaves underlying controls visually and operationally available while
the wallet is asking for confirmation, leaks modal focus semantics, and makes
outside-click behavior ambiguous. The host `::backdrop` remains required for
modal and auth-menu surfaces. The drawer's transparent `::backdrop` provides
blocking semantics with no visual dimming.

The implementation assumes the supported browser/WebView matrix provides
`HTMLDialogElement.showModal()` and `::backdrop`. The host currently fails fast
when native dialog support is absent. A feature-detected fallback is separate
follow-up work and must use the same `WalletIframeSurfaceRenderMode` and exact
identity callbacks; no second fullscreen implementation belongs in this
refactor.

## Domain and wire contracts

### Surface presentation

Normalize request presentation at the existing request boundary. Core surface
logic receives a required branch, even when a public request supplies an
optional confirmation setting.

```ts
type WalletIframeSurfacePresentation =
  | { kind: 'modal'; title: string }
  | { kind: 'drawer'; title: string; edge: 'bottom' }
  | { kind: 'auth_menu_modal'; title: string };
```

`modal_auth_menu` always selects `auth_menu_modal`. Registration, transaction,
key export, unlock, recovery, and device-link requests derive `modal` or
`drawer` from the normalized confirmation configuration and retain their
existing operation-specific title. The surface branch stores the presentation
required by its renderer; hidden stores no presentation or identity.

### Geometry union

Keep geometry pure and serializable. `surface/geometry.ts` owns the union,
boundary parser, clamps, and rectangle calculation.

```ts
type WalletIframeSurfaceGeometry =
  | { kind: 'hidden' }
  | {
      kind: 'provisional_centered_modal';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'centered_modal';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'provisional_bottom_drawer';
      edge: 'bottom';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'bottom_drawer';
      edge: 'bottom';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    }
  | {
      kind: 'viewport_fallback';
      reason: 'small_visual_viewport' | 'measurement_unavailable';
      widthCssPx: number;
      heightCssPx: number;
      topCssPx: number;
      leftCssPx: number;
    };
```

The render mode carries accessibility and correlation alongside geometry:

```ts
type WalletIframeSurfaceRenderMode =
  | { kind: 'hidden' }
  | {
      kind: 'compact_request_modal';
      presentation: Extract<WalletIframeSurfacePresentation, { kind: 'modal' }>;
      geometry: Extract<
        WalletIframeSurfaceGeometry,
        { kind: 'provisional_centered_modal' | 'centered_modal' | 'viewport_fallback' }
      >;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId?: never;
    }
  | {
      kind: 'compact_request_drawer';
      presentation: Extract<WalletIframeSurfacePresentation, { kind: 'drawer' }>;
      geometry: Extract<
        WalletIframeSurfaceGeometry,
        { kind: 'provisional_bottom_drawer' | 'bottom_drawer' | 'viewport_fallback' }
      >;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId?: never;
    }
  | {
      kind: 'compact_auth_menu';
      presentation: Extract<WalletIframeSurfacePresentation, { kind: 'auth_menu_modal' }>;
      geometry: Extract<
        WalletIframeSurfaceGeometry,
        { kind: 'provisional_centered_modal' | 'centered_modal' | 'viewport_fallback' }
      >;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId: HostedAuthMenuSessionId;
    };
```

The implementation may use named `ModalGeometry`, `DrawerGeometry`, and
`AuthMenuGeometry` aliases to make the `Extract` branches readable. Exhaustive
switches and `assertNever` are required. Invalid combinations are rejected by
the branch-specific presentation and geometry types plus `never` fields:
hidden with identity, auth-menu mode without a session identity, a drawer
presentation in the modal branch, or a centered-modal geometry in the drawer
branch. Negative or non-finite numeric sizes are runtime boundary cases for the
parser and tests; they are not type-fixture cases.

### Child measurement protocol

The child reports content size; the parent chooses the final rectangle. Add one
authenticated child-to-parent message branch in `shared/messages.ts`:

```ts
type WalletIframeSurfaceMeasurement =
  | {
      kind: 'measured_v1';
      requestId: WalletIframeRequestId;
      authMenuSessionId?: never;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    }
  | {
      kind: 'measured_auth_menu_v1';
      requestId: WalletIframeRequestId;
      authMenuSessionId: HostedAuthMenuSessionId;
      sequence: number;
      widthCssPx: number;
      heightCssPx: number;
    };
```

The wire parser accepts only plain records with the exact branch keys. It
validates the request ID, the auth-menu session when present, a positive safe
sequence, finite positive CSS sizes, and a hard measurement cap (for example
`4096` CSS px per axis). `surfaceId` stays parent-internal and never crosses
the wire. The router accepts a measurement only from the authenticated
connection, looks up the active surface by request ID, requires the matching
auth-menu session when applicable, and attaches the full parent identity before
passing the event to the pure geometry reducer. Unknown, stale, mismatched, or
malformed measurements are ignored at the router boundary.

The message travels on the existing authenticated `MessagePort` envelope. The
generic mounter's `postToParent` adapter continues to carry registry events and
never invents a foreground identity from a component id. Request confirmation
and export roots pass their exact request binding to the shared reporter;
`SeamsAuthMenu` stays direct-mounted and passes its exact request/session
binding.

## Geometry rules

Use the parent `visualViewport` when available, with `innerWidth`/`innerHeight`
as the boundary fallback. All values are CSS pixels.

- Insets: `16px` on each side, including safe-area padding through host CSS.
- Compact modal: width is the measured content width clamped to
  `[280px, min(560px, viewportWidth - 2 * inset)]`; height is clamped to the
  available viewport height. Center it within the visual viewport.
- Bottom drawer: width is clamped to
  `[280px, min(384px, viewportWidth - 2 * inset)]`; measured content height is
  capped at the available viewport height. Center it horizontally and align its
  bottom edge to the visual viewport's bottom inset. Preserve the Lit drawer's
  internal scroll, vertical drag, and close actions inside that rectangle.
- Mobile/small viewport: when either axis cannot satisfy the compact minimum,
  emit `viewport_fallback` with the visual viewport rectangle minus safe insets.
  The iframe content scrolls internally; no child backdrop is required.
- Measurement pending: render a presentation-specific provisional compact
  rectangle. A modal/auth-menu starts at its content width cap (for example
  `560px`, clamped to the viewport inset) and conservative height; a drawer
  starts at its `384px` content width cap and conservative height. Measured
  content may shrink below those seeds, while the cap lets wider content settle
  without being constrained by the provisional rectangle. The controller may
  gate the dialog with `visibility: hidden` until the first valid measurement
  to avoid exposing a reflow. It never uses a fullscreen rectangle for this
  first paint.
- Measurement unavailable: after one `ResizeObserver` callback plus at most two
  animation frames (bounded by a small timeout), use `viewport_fallback` with
  the visual viewport rectangle. A missing `ResizeObserver` gets one
  synchronous measurement attempt before entering this fallback.
- Clamp before DOM writes. Round to whole CSS pixels for stable placement and
  treat changes below `1px` as equal.

The parent never forwards its rectangle to the child. The child observes the
rendered surface root with `ResizeObserver`, coalesces notifications into one
`requestAnimationFrame`, and sends a measurement only when rounded width or
height changes. It observes content, not the outer iframe, so moving the dialog
cannot create a parent/child resize loop. The reporter disconnects on unmount,
close, connection loss, and surface replacement.

The controller writes a rectangle only when it differs from the last applied
rectangle by at least `1px`; it ignores a measurement sequence that is not
newer than the active one. A bounded two-frame settle check covers content
wrapping after the parent width clamp. No timer or repeated style write may
keep a closed surface alive.

Content inside a measured modal must not animate its own layout height. The
controller eases the box to each measured→measured change (`startSurfaceResize`,
`SURFACE_RESIZE_DURATION_MS`, from the box's current visual rectangle), so a child transition that
streams one measurement per frame makes the box chase a moving target and
trail the card, which is clipped at the iframe edge until the ease lands. A
tree node therefore hands its height motion to the confirmer host first
(`lit-tree-resize-begin`, `ui/confirm-surface-resize.ts`): the host pins its
own height to the size the card is heading for — one measurement, one ease —
and feeds the node's body height back from the iframe viewport frame by frame,
so the card fills exactly the room the box has made. A box that does not hug
the host (clamped, full-viewport fallback, standalone surface) leaves the tree
to its own transition, which cannot be clipped there.

For the same reason, nothing inside a measured modal may size itself in
viewport units: inside the iframe the viewport _is_ the box the parent just
sized to the content, so a `max-height: 40vh` block grows on every ease, posts
a larger measurement, and the box chases it while the interior re-lays out
instantly (`tx-confirmer.css` pins those caps to rem values under
`data-w3a-confirm-surface='wallet-iframe'`).

Invariants for anything that changes the height of a measured modal:

1. The parent's ease is the only size motion. Content never animates its own
   layout height while the box hugs it; it announces the target and then fills
   the box the parent has made, frame by frame.
2. One measurement per change. The host pins itself to the target so the
   reporter posts the destination once; a stream of intermediate sizes makes
   the box chase a moving target.
3. Content height is intrinsic. No `vh`/`vw` caps and no viewport media
   queries inside the surface; the viewport is derived from the content.
4. Never trust a single frame of the box. The parent lays out the destination
   before its ease starts and the frame receives that size for one frame;
   landing requires intermediate sizes or a box that stays put.
5. Prove it across the real boundary. Same-process harnesses cannot see the
   destination blip; `wallet-iframe/confirmSurface.treeGrowth.integration.test.ts`
   samples both sides per frame with the real router, iframe origin, and
   confirmer.

## Ownership and lifecycle

1. The router normalizes a request's presentation, allocates its existing
   request/surface identity, and enters the foreground reducer.
2. The renderer creates or reuses the host `<dialog>`, sets the accessible
   title, and opens the top layer with a presentation-specific provisional
   compact rectangle. It binds the active generation and may keep the dialog
   visually gated until the first valid measurement.
3. The child mounts the existing modal, drawer, or direct auth-menu Lit root,
   removes its viewport backdrop, and starts its identity-bound reporter.
4. A valid measurement reaches the router, passes identity and sequence
   checks, and updates only the active generation's geometry.
5. Child actions remain wallet-origin. Child terminal responses, request
   cancellation, timeout, connection close, and surface replacement all pass
   through the existing reducer and render `hidden` only when their complete
   identity owns the active surface.
6. Host Escape or backdrop dismissal is debounced per generation and dispatches
   the exact existing cancellation bridge. It never calls a global cancel or
   closes a replacement surface.
7. On hidden, the controller removes the dialog from the top layer, clears
   width/height/title/ARIA attributes it owns, disconnects the measurement
   reporter/listeners, and lets native dialog focus restoration return focus to
   the element that opened the surface. Native dialog support is a requirement
   of this implementation; no parallel fallback controller is retained.
8. `dispose()`, iframe replacement, and connection loss perform the same close
   path once. Late child measurements, late terminal responses, and late
   backdrop events are ignored by generation and identity.

## Implementation phases and file ownership

This crosses more than five files and introduces one shared geometry protocol.
The scope is justified by the cross-origin boundary: geometry, backdrop,
child measurement, and lifecycle correlation must change together or the
compact iframe would expose inconsistent focus and dismissal behavior. Keep the
design to one geometry union, one dialog controller, and one measurement
reporter; do not create per-surface overlay systems.

### Phase 0 — contracts and pure geometry

- [x] Add `surface/geometry.ts` with the geometry union, parser, clamps,
      viewport calculation, and rectangle equality helper.
- [x] Extend `surface/domain.ts` builders/events with required normalized
      presentation and preserve the existing request/surface/session identity
      checks.
- [x] Replace `viewport_modal` in `surface/renderer.ts` with exhaustive
      `compact_request_modal`, `compact_request_drawer`, `compact_auth_menu`, and
      hidden mappings. Restrict each branch to its matching presentation and
      geometry subtype. Keep titles and operation branches unchanged.
- [x] Add the measurement payload, parser, and `ChildToParentType` branch to
      `walletIframe/shared/messages.ts`. Reject raw measurements before router
      state or DOM code sees them.
- [x] Add type fixtures for invalid geometry branches, missing identities,
      invalid measurements, broad spreads, and unsafe casts. These live beside
      package types in `surface/domain.typecheck.ts` and
      `shared/messages.typecheck.ts`; package type-check compiles them instead
      of using a separate `tests/typecheck/` tree.

### Phase 1 — parent dialog and router integration

- [x] Refactor `client/overlay/overlay-controller.ts` to own one native dialog
      wrapper, its generation, `showModal()`/close lifecycle, title/ARIA, backdrop
      hit testing, and exact cancellation callbacks.
- [x] Replace fullscreen CSS in `client/overlay/overlay-styles.ts` with dialog,
      iframe, compact-modal, drawer, fallback, and hidden rules. Delete unused
      selectors.
- [x] Remove the old `overlay.css`/fullscreen selectors after the import and
      source-guard audit.
- [x] Update `client/router.ts` to dispatch parsed measurements, derive
      presentation before beginning a surface, and expose diagnostics as
      `hidden | compact_modal | bottom_drawer | viewport_fallback`.
- [x] Update `client/transport/iframe-transport-dom.ts` only as needed to keep
      the iframe transparent and allow the controller to place it inside the
      dialog; preserve the existing origin, permission, and handshake attributes.
- [x] Remove every `applyViewportModal()` call and any progress-path visibility
      mutation. Surface transitions remain the sole visibility owner.

### Phase 2 — child measurement and Lit shells

- [x] Add the identity-bound `ResizeObserver` reporter in
      `host/lit-ui/surface-measurement-reporter.ts`. Generic registry mounts in
      `iframe-lit-elem-mounter.ts` retain `iframe`/`viewport` anchoring; request
      confirmations and export viewers bind the reporter through the required
      `UiConfirmSurfaceMeasurementBinding`.
- [x] Update `host/runtimeContext.ts` to give foreground reporters an
      authenticated `MessagePort` sender. Generic registry anchor enter/leave
      notifications may keep their existing window-message adapter; measurement
      events use the typed port branch and never derive identity from a component
      id.
- [x] Reuse the reporter from the direct `host/auth-menu/session.ts` mount. Do
      not register `seams-auth-menu-surface` in `WalletUIRegistry`.
- [x] Update `host/lit-ui/auth-menu/seams-auth-menu-surface.ts` and
      `auth-menu.css` so the root reports its content box and the card remains the
      authoritative interactive UI without a viewport-sized backdrop.
- [x] Update the modal/drawer Lit entrypoints and
      `core/signingEngine/uiConfirm/ui/lit-components/css/tx-confirmer.css` and
      `drawer.css`: remove child viewport backdrops/fixed viewport ownership,
      preserve card, drawer scroll/drag, focus, close, and action behavior, and
      ensure the outer custom element has a stable measurable box.
- [x] Disconnect reporters on all existing unmount, terminal, and connection
      cleanup paths. A direct auth-menu mount remains the only owner of its element.

### Phase 3 — focused validation and cleanup

- [x] Update `tests/unit/walletIframeSurfaceDomain.unit.test.ts` and add a
      geometry unit test for parser rejection, clamping, modal centering, drawer
      bottom placement, fallback, stale sequence, and sub-pixel deduplication.
- [x] Update `tests/unit/overlayController.test.ts` to assert native dialog
      open/close, viewport-spanning `::backdrop`, Escape cancellation, paired
      pointerdown/pointerup (same pointer ID) outside-click bounds, focus restoration, and hidden
      iframe inertness.
- [x] Add type fixtures for the geometry/render-mode union beside the package
      types (`surface/domain.typecheck.ts`, `shared/messages.typecheck.ts`).
- [x] Extend `tests/wallet-iframe/` with compact auth-menu measurements,
      malformed/stale and mismatched payloads, replacement races, and the mobile
      visual-viewport fallback. Existing focused confirmation and export tests
      cover the request-surface bindings; a complete per-operation browser matrix
      remains follow-up coverage.
- [x] Add browser coverage for malformed/stale measurement messages, exact
      replacement identity, connection teardown, and mobile fallback. Unit
      coverage exercises child `ResizeObserver` coalescing and deduplication;
      browser coverage for every dynamic content transition (error text, account
      selection, OTP, and drawer expansion) remains follow-up work.
- [ ] Add the remaining per-operation and dynamic-content browser matrix for
      registration, transaction, key export, unlock, recovery, device link, OTP,
      and drawer expansion.
- [x] Delete stale fullscreen assertions, inner-backdrop fixtures, and the old
      `overlay.css` path after the focused behavior tests took ownership of the
      compact contract. An unrelated legacy source-guard failure is recorded in
      the validation notes below.

## Narrow validation commands

Run the smallest relevant checks during each phase:

```text
pnpm -C packages/wallet type-check
pnpm -C tests exec playwright test unit/walletIframeSurfaceDomain.unit.test.ts unit/overlayController.test.ts --reporter=line
pnpm -C tests exec playwright test lit-components/auth-menu.surface.test.ts --reporter=line
pnpm -C tests exec playwright test wallet-iframe/auth-menu.host.integration.test.ts --reporter=line
pnpm test:wallet-iframe
pnpm test:source-guards
pnpm test:intended
```

Run `pnpm test:intended` after the public request/presentation normalization
lands. Run the production build and wallet-host bundle checks after the child
Lit entrypoints and dialog controller are cut over.

### Validation status (August 6, 2026)

The package type-check, SDK/full production build, wallet-host boundary guards,
focused geometry/domain/overlay/reporter tests, compact measurement integration,
auth-menu host integration, and focused Lit auth-menu/confirmation tests pass on
this worktree.

The live Codex browser recheck at
`https://localhost/wallet?theme=paper` also passes: the native dialog contains
the directly mounted `seams-auth-menu-surface` with its sign-in controls, and
the dialog plus iframe measure exactly `416x356` in a `1280x720` viewport,
centered at `(432,182)`. Switching to Create wallet works. Closing with `X`
leaves zero open dialogs and one hidden reusable iframe.

Broad-gate caveats remain:

- The compact measurement integration passes 3/3, the handshake suite passes
  3/3 after updating its timeout wording, and the cancellation fixture updates
  pass. The full wallet-iframe suite has one unrelated session-expiry lifecycle
  baseline failure remaining.
- The source-guard chain reports an unchanged Ed25519-Yao export-flow
  `indexedDB` import guard. That guard predates this refactor.
- The intended-behavior browser suite stops before execution when the local
  Google ID-token prerequisite is absent. This is an environment setup issue.
- The full Lit suite is 38/40 with an environment-specific COEP strict-header
  failure and an unrelated drawer close-event timing failure outside compact
  geometry.

## Acceptance criteria

- Every foreground surface maps to `hidden`, compact centered modal, bottom
  drawer, or typed viewport fallback. No active path calls
  `applyViewportModal()` or renders an unbounded fullscreen iframe by default.
- The host document contains exactly one active native dialog wrapper containing
  the iframe. `dialog::backdrop` spans the viewport independently of the compact
  iframe rectangle. Modal and auth-menu `showModal()` calls provide that
  backdrop, inert background, Escape handling, and focus restoration. Drawer
  backdrop opacity is transparent while pointer blocking remains active.
- The wallet iframe document contains authoritative Lit controls and actions,
  no parent backdrop, and no app-origin callbacks or secrets.
- Modal and auth-menu rectangles are centered and drawer rectangles are bottom
  aligned within `1px` of the clamped visual-viewport calculation. The initial
  measurement-pending state is presentation-specific provisional compact
  geometry, never a fullscreen flash. Small viewports or an unsafe measurement
  after the bounded attempt use the fallback union and remain usable with
  internal scrolling and safe-area insets.
- Child measurements accept only the active complete identity, strictly newer
  sequence, finite bounded CSS sizes, and no unknown fields. Malformed or stale
  messages cannot move, close, or resize a current surface.
- Resize updates converge without a feedback loop, and all observers/listeners
  are disconnected after close, replacement, unmount, timeout, and connection
  loss.
- Backdrop and Escape dismissal call only the matching existing cancellation
  bridge. Backdrop dismissal requires the same pointer ID's pointerdown and
  pointerup to be outside the dialog/iframe bounds. A stale dismissal cannot
  cancel a replacement request or auth-menu session.
- Direct-mounted `SeamsAuthMenu` remains outside the generic UI registry and
  still owns its wallet-origin lifecycle. Generic Lit mounts retain their
  existing `iframe`/`viewport` anchoring semantics.
- Focused unit, type, Lit auth-menu/confirmation, compact wallet-iframe, and
  production bundle checks pass. Broad-suite caveats are recorded in the
  validation status above; they do not change the compact surface contract.

## Risks and open concern

- Native dialog support and `::backdrop` behavior differ in older WebViews.
  The current path requires native `showModal()` support and fails fast when it
  is absent. Confirm the supported browser matrix before adding a separate
  feature-detected fallback.
- `showModal()` makes drawers inert to the app. The current confirmation model
  favors blocking behavior; product review should confirm this remains correct.
  If a non-blocking drawer is required, introduce it as an explicit
  presentation decision with `dialog.show()` and a separately tested focus
  contract rather than silently weakening the modal path.
- Standalone Lit confirmations retain their own document-owned backdrop. Wallet-
  iframe surfaces set their wallet-iframe mode and remove child viewport
  ownership. Visual tests must assert one host backdrop for the compact path.
- Child content can wrap after the parent width clamp, especially on mobile.
  The sequence/epsilon/rAF protocol and bounded settle check must remain in one
  controller to avoid geometry oscillation.
- Native dialog focus restoration and iframe WebAuthn activation need Chromium
  and supported WebKit validation. A host close must never steal the activation
  event from a wallet-origin CTA.
