# Iframe Registration Button

Date created: June 20, 2026

Status: planned

## Goal

Define the wallet iframe registration UX for two supported paths:

1. `PasskeyAuthMenu` can provide a one-click passkey registration flow:
   - the app renders the registration card and surrounding UI
   - the visible `Create with Passkey` CTA occupies app layout exactly where the
     product wants it
   - the actual clickable button is wallet-origin iframe DOM
   - clicking the CTA directly opens the browser passkey ceremony
   - no intermediate wallet confirmation popup appears
2. Ordinary app-domain registration API calls show a polished wallet-origin
   registration modal that supplies the required iframe click before WebAuthn.

For the one-click path, the iframe boundary must match the button hit target
exactly. The wallet iframe must not cover the rest of the page during the
activation step.

## Current Behavior

`PasskeyAuthMenu` currently renders an app-domain React button. Clicking it calls
the app's `onRegister`, which calls `registerPasskey`. In wallet iframe mode the
registration request enters the wallet iframe, then
`determineConfirmationConfig` clamps registration and device-link flows to:

```ts
{ uiMode: 'modal', behavior: 'requireClick' }
```

That modal is the extra popup. It supplies the wallet-origin user activation
required before WebAuthn/TouchID runs inside the iframe.

There is already a narrow escape hatch:

- `createPasskeyRegistrationActivationSurface`
- `PM_REGISTRATION_ACTIVATION_PREPARE`
- `walletIframeActivation`

The host strips caller-supplied `walletIframeActivation` proofs from normal
registration calls, and only the iframe activation surface can mint the proof
that allows registration to skip the second confirmation UI.

## Two Registration Paths

Support two passkey registration paths with different UX and the same wallet
iframe security boundary.

### Code-Only Registration

The app calls the ordinary registration API from an app-domain control:

```tsx
function handleCreatePasskeyClick(): void {
  void seams.registerPasskeyAccount();
}

<AppDomainButton onClick={handleCreatePasskeyClick}>Create with Passkey</AppDomainButton>
```

The app-domain click cannot activate WebAuthn inside the wallet iframe. This
path must show a wallet-origin registration modal in the iframe. The user clicks
the wallet-origin confirm button, and that iframe click starts WebAuthn.

This path keeps the existing safety clamp:

```ts
{ uiMode: 'modal', behavior: 'requireClick' }
```

The modal should be visually polished and registration-specific. It must show:

- intended user name
- rpID
- visible passkey/fingerprint affordance
- cancel and confirm actions
- loading/busy state after confirm

### Activation Button Registration

The app renders `.seams-passkey-registration-btn`, and the SDK anchors the
wallet iframe directly over that CTA. The visible click lands in the iframe
button, so the flow can mint `walletIframeActivation` and skip the modal:

```ts
{ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 }
```

This path exists for polished app-owned registration UI. The code-only path
exists for simple integrations that call the registration API directly.

Activation source matrix:

| Path | First app action | Wallet-origin activation | Modal |
| --- | --- | --- | --- |
| Code-only registration | App-domain button calls the registration API | User clicks confirm in the wallet iframe modal | Required |
| Activation button registration | User clicks the iframe-owned CTA button | Same iframe button click starts WebAuthn | Skipped |

## Browser Constraint

For a passkey ceremony that runs in the wallet iframe, the trusted user gesture
must land in the wallet iframe. An app-domain click cannot be transformed into a
wallet-origin activation by `postMessage`, synthetic clicks, or a click-through
transparent iframe.

That makes the CTA itself the security boundary:

- mouse, touch, keyboard, and pointer activation go to the iframe button
- app-domain UI around the CTA remains ordinary React/CSS
- the iframe remains button-sized
- the wallet iframe starts registration from the iframe button click

## Recommended DOM Model

Use an app-domain visual outline with a wallet-origin transparent activation
layer:

```html
<div
  class="seams-passkey-registration-btn"
  data-seams-registration-button
  aria-label="Create with Passkey"
>
  <span class="button-label" aria-hidden="true">Create with Passkey</span>
</div>
```

The SDK-managed wallet iframe is a sibling under `document.body`, positioned by
`OverlayController` with viewport-fixed geometry. It is shown here separately
because it is not a DOM child of `.seams-passkey-registration-btn`:

```html
<iframe class="seams-wallet-overlay" title="Create with Passkey">
  <!-- wallet origin document -->
  <seams-passkey-registration-btn>
    <button type="button" aria-label="Create with Passkey"></button>
  </seams-passkey-registration-btn>
</iframe>
```

The effective structure must match this model:

- the app-domain `.seams-passkey-registration-btn` owns layout and visual styling
- the SDK-managed iframe is positioned over the outline using the outline's
  `getBoundingClientRect()`
- the iframe viewport is exactly the CTA border box
- the iframe document background is transparent
- the iframe button fills the iframe viewport
- the iframe button owns the activation click

Use this outline-overlay structure for the default React component. CSS effects
such as `box-shadow` can extend outside the button border box, while iframe
content clips to its viewport. Keeping shadows and decorative visuals on
`.seams-passkey-registration-btn` lets app CSS render them normally. The iframe
remains an exact hit target over the visible control.

## Styling Model

Support two presentation modes.

### Outline Overlay

This is the default for `PasskeyAuthMenu`.

The app styles `.seams-passkey-registration-btn` using normal CSS:

```css
.seams-passkey-registration-btn {
  position: relative;
  display: grid;
  place-items: center;
  inline-size: 100%;
  min-block-size: 64px;
  border-radius: 999px;
  background: #579daa;
  color: #fff;
  box-shadow: 0 18px 40px rgba(30, 72, 84, 0.22);
}
```

The wallet iframe renders a transparent custom element and internal button:

```css
seams-passkey-registration-btn,
seams-passkey-registration-btn button {
  display: block;
  inline-size: 100%;
  block-size: 100%;
}

seams-passkey-registration-btn button {
  appearance: none;
  border: 0;
  margin: 0;
  padding: 0;
  background: transparent;
  color: transparent;
  cursor: pointer;
}
```

The parent outline displays label, radius, shadows, hover color, loading copy,
and disabled state. The iframe button supplies the trusted click and accessible
button semantics.

The iframe must mirror state to the parent so app CSS can style the outline while
the iframe owns events:

- `data-seams-registration-button-active="true"`
- `data-seams-registration-button-hovered="true"`
- `data-seams-registration-button-focused="true"`
- `data-seams-registration-button-pressed="true"`
- `data-seams-registration-button-busy="true"`
- `data-seams-registration-button-disabled="true"`

Do not rely on parent `:hover`, `:active`, or `:focus-visible` for the anchored
iframe case. Pointer, focus, keyboard, drag, and click events land in the iframe
document. They do not naturally bubble to the app-domain outline. The wallet
iframe must mirror every interaction state needed for app-domain styling.

### Iframe Visual Button

This mode is useful for non-React consumers or fully SDK-rendered UI. The iframe
renders the visible button itself.

The app passes a standard CSS declaration object using normal CSS property names:

```ts
{
  kind: 'iframe_button',
  label: 'Create with Passkey',
  busyLabel: 'Creating your passkey...',
  accessibleLabel: 'Create wallet with passkey',
  iframeVisualStyle: {
    minHeight: '64px',
    borderRadius: '999px',
    background: '#579daa',
    color: '#fff',
    boxShadow: '0 18px 40px rgba(30, 72, 84, 0.22)',
    fontSize: '20px',
    fontWeight: '700',
  },
}
```

When this mode uses `box-shadow`, the iframe viewport needs explicit shadow
padding. That means the iframe boundary becomes larger than the button hit
target. Use this mode only when exact button-only iframe bounds are less
important than fully wallet-rendered visuals.

## Design Decision

Use the existing SDK-managed wallet iframe as the activation layer and anchor it
to the app-domain button outline with viewport-fixed geometry. The app owns the
visual button shell. The wallet iframe owns the trusted activation button.

The preferred runtime shape is:

```text
App domain
  PasskeyAuthMenu
    div.seams-passkey-registration-btn[data-seams-registration-button]
      span[aria-hidden="true"] "Create with Passkey"

Wallet iframe
  position: fixed
  top/left/width/height = target.getBoundingClientRect()
  document body transparent
  seams-passkey-registration-btn
    button[data-seams-registration-activation-start]
```

The iframe is not reparented into the outline by default. Reparenting iframes
can reload the iframe document or disturb long-lived wallet state. Anchored
fixed positioning uses the current `OverlayController` model and keeps iframe
ownership centralized in the wallet router.

The wallet-origin activation control should live under the SDK Lit component
tree and be organized like the other SDK-owned UI surfaces. The app-domain
outline class remains `.seams-passkey-registration-btn`; the wallet iframe
renders a `<seams-passkey-registration-btn>` custom element that owns the real
transparent `<button>`.

This component is colocated with Lit components for ownership, asset, style, and
entrypoint consistency. It must stay independent from the transaction confirmer
runtime and should remain a tiny activation element. If the final implementation
uses `LitElement`, it should use only the shared base/style infrastructure needed
for this element. If a plain custom element is smaller, keep it in the same
folder and document that it is intentionally dependency-light.

## Scope

This spec covers passkey registration UX in wallet iframe mode:

- activation-button registration from `PasskeyAuthMenu`
- code-only registration from ordinary app-domain registration API calls

In scope:

- one-click passkey registration from `PasskeyAuthMenu`
- improved code-only passkey registration modal in wallet iframe mode
- button-sized iframe activation surface
- app-domain CSS for the visible CTA outline
- iframe-origin transparent button for WebAuthn activation
- iframe-minted `walletIframeActivation` proof
- state mirroring from iframe button to app outline
- removal of the fullscreen registration activation popup for this flow
- a wallet-origin `<seams-passkey-registration-btn>` component under the
  `lit-components` tree

Out of scope:

- moving passkey/WebAuthn calls to the app domain
- passing React components into the wallet iframe
- changing transaction confirmation UX
- changing normal app-domain `registerPasskey` safety behavior
- supporting old activation button payloads after replacement
- coupling registration activation to `seams-tx-confirmer` or tx-confirm Lit
  state

## Existing Code Touchpoints

- `packages/sdk-web/src/SeamsWeb/publicApi/types.ts`
  - owns `CreatePasskeyRegistrationActivationSurfaceArgs`
  - owns `RegistrationActivationSurfaceState`
  - owns `WalletIframeRegistrationActivationSurface`
- `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts`
  - exposes `createPasskeyRegistrationActivationSurface`
  - creates the router-backed surface
- `packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts`
  - currently ignores `mount(target)` for activation surfaces
  - currently forces fullscreen activation UI
  - owns `OverlayController`
- `packages/sdk-web/src/SeamsWeb/walletIframe/client/overlay/overlay-controller.ts`
  - already supports anchored iframe geometry
- `packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts`
  - owns `PM_REGISTRATION_ACTIVATION_PREPARE`
  - needs typed presentation payloads
- `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts`
  - currently renders the fullscreen activation panel
  - mints `walletIframeActivation`
  - strips caller-supplied activation proofs on normal registration
- `packages/sdk-web/src/core/types/secure-confirm.ts`
  - currently carries `UserConfirmSecurityContext.rpId`
  - needs a precise registration display branch for rpID and intended username
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/`
  - new home for the wallet-origin `seams-passkey-registration-btn` component
  - should share component organization with the Lit refactor without importing
    tx-confirm surfaces
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts`
  - currently renders the registration modal through the tx confirmer path
  - needs a registration-specific modal layout
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts`
  - should stay consistent if drawer registration remains reachable
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/determineConfirmationConfig.ts`
  - clamps iframe registration/link flows
  - accepts iframe-minted activation proof for registration
- `packages/sdk-web/src/react/components/PasskeyAuthMenu/client.tsx`
  - currently renders the app-domain `Create with Passkey` button
- `packages/sdk-web/src/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.ts`
  - owns menu state and registration intent transitions
- `packages/sdk-web/src/react/components/PasskeyAuthMenu/PasskeyAuthMenu.css`
  - owns visual CTA styles

## Relationship To `refactor-8X-lit`

This plan follows the same wallet-origin customization rules as
`docs/refactor-8X-lit.md`:

- typed customization data only
- no app-provided render callbacks
- no HTML strings
- no scriptable templates
- raw iframe/postMessage payloads parsed once at the boundary

The ownership boundary is narrower. `refactor-8X-lit.md` owns transaction
confirmation, export-key UI, shared Lit primitives, and Lit asset budgets. This
plan owns only the passkey registration activation button and its iframe
geometry/proof flow.

The registration button should be added to the Lit component tree for
organization and asset ownership. It should not depend on tx-confirm state,
transaction display models, export-key UI, or modal/drawer containers.

## Target Directory Structure

Add a small registration activation component subtree:

```text
packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/
  passkey-registration-btn/
    entrypoints/
      seams-passkey-registration-btn.ts
    components/
      seams-passkey-registration-btn-element.ts
    state/
      passkey-registration-button-state.ts
      passkey-registration-button-builders.ts
      assert-never.ts
    styles/
      seams-passkey-registration-btn.css
    index.ts
    README.md
```

Directory ownership:

1. `entrypoints/` defines the custom element and is the only module imported by
   the wallet iframe handler.
2. `components/` owns rendering the transparent iframe button and emitting
   component events.
3. `state/` owns the element lifecycle union and builders.
4. `styles/` owns iframe-internal button styles only. App-domain outline styles
   remain in `PasskeyAuthMenu.css`.
5. `README.md` documents why this component lives with Lit components while
   keeping the runtime intentionally small.

The cross-frame message protocol remains in
`packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts`. The wallet
iframe host may import the component entrypoint dynamically before creating the
element.

## Build And Entrypoint Contract

The registration button component lives in the Lit component tree, but it is a
separate activation asset from transaction confirmation.

Requirements:

- add a `seams-passkey-registration-btn` tag constant
- add an entrypoint that defines only `<seams-passkey-registration-btn>`
- make the wallet iframe host dynamically import that entrypoint during
  `PM_REGISTRATION_ACTIVATION_PREPARE`
- ensure the entrypoint is loaded and the custom element is defined before
  `PM_REGISTRATION_ACTIVATION_READY`
- keep the entrypoint out of the tx-confirm, export-key, modal, and drawer
  bundles
- include the entrypoint in build output and size reporting if the build system
  requires explicit Lit asset registration
- add a source guard proving the entrypoint does not import React wrappers,
  tx-confirm containers, export-key UI, or modal/drawer primitives

## Runtime Lifecycle

1. `PasskeyAuthMenu` enters register mode with a valid account id.
2. React renders an app-domain outline element for `Create with Passkey`.
3. React asks `seams.registration.createPasskeyRegistrationActivationSurface`
   for an activation surface.
4. React mounts the activation surface with the outline element.
5. The wallet router measures the outline element.
6. The wallet router shows the SDK-managed iframe in anchored mode at the exact
   outline rectangle.
7. The wallet router sends `PM_REGISTRATION_ACTIVATION_PREPARE` to the wallet
   iframe with `presentation.kind === 'outline_overlay'`.
8. The wallet iframe dynamically loads the
   `seams-passkey-registration-btn` entrypoint.
9. The wallet iframe renders `<seams-passkey-registration-btn>`, which renders a
   full-size transparent button.
10. The iframe verifies the custom element is defined, focusable, and connected.
11. The iframe sends `PM_REGISTRATION_ACTIVATION_READY`.
12. The user clicks the visible CTA.
13. The click lands on the transparent iframe button.
14. The iframe disables the button, sends `PM_REGISTRATION_ACTIVATION_STARTED`,
    mints `walletIframeActivation`, and calls `registerPasskey`.
15. `determineConfirmationConfig` sees the iframe-minted proof and returns:

    ```ts
    { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 }
    ```

16. WebAuthn/TouchID starts from the same iframe-origin activation chain.
17. Registration completes, fails, expires, or is disposed.
18. The router hides the iframe and removes mirrored state from the outline.

## Activation Timing Contract

The iframe click must reach WebAuthn with minimal work in between. Browsers are
sensitive to transient activation timing, especially on Safari and mobile.

Required constraints:

- no dynamic import after the activation click
- no custom-element definition after the activation click
- no UI mounting after the activation click
- no app-domain round trip before `registerPasskey`
- no timer before `navigator.credentials.create`
- warmup and registration preparation should happen before the iframe reports
  `PM_REGISTRATION_ACTIVATION_READY`
- after click, the iframe path is:
  `button handler -> PM_REGISTRATION_ACTIVATION_STARTED -> registerPasskey -> determineConfirmationConfig(uiMode: none) -> navigator.credentials.create`

The current registration flow already supports the critical end of this path:
`determineConfirmationConfig` returns `uiMode: 'none'` for an iframe-minted
activation proof, and the `uiMode: 'none'` confirmation adapter returns
`confirmed: true` without mounting confirmation UI.

## Code-Only Modal Contract

The code-only path uses the wallet-origin registration modal. This modal is the
secure user-activation surface for integrations that call the registration API
from an ordinary app-domain button.

The modal should be purpose-built for passkey registration instead of looking
like a generic transaction confirmation with zero operations.

Display model:

```ts
export type PasskeyRegistrationConfirmDisplay = {
  kind: 'passkey_registration_confirm_display_v1';
  intendedUserName: string;
  accountId: string;
  rpId: string;
  signerSlot: number;
};
```

Field rules:

- `intendedUserName` is the human-readable user/account name shown to the user.
- `accountId` is the wallet/account id being registered.
- `rpId` is the WebAuthn relying party id from the wallet iframe runtime.
- `signerSlot` is shown only in development/debug details unless product UI
  needs it.
- `intendedUserName` should default to `accountId` when no narrower display name
  exists.
- The WebAuthn `user.name` / `displayName` passed to
  `navigator.credentials.create` should match `intendedUserName` when the
  authenticator operation can safely carry a display name separate from the
  stable user handle.

Visual requirements:

- Use a registration-specific heading, for example `Create your passkey`.
- Use a compact passkey/fingerprint visual consistent with the existing
  `PasskeyHaloLoading`/halo style.
- Show two primary detail rows:
  - `Account` -> `intendedUserName`
  - `Relying party` -> `rpId`
- Keep account/rpID rows visible before the confirm click.
- Use the existing modal theme tokens, spacing, button shapes, and light/dark
  behavior.
- Keep the confirm action visually primary and cancel secondary.
- On confirm, switch to a busy state such as `Creating passkey...` while the
  browser prompt is being requested.
- Avoid transaction-specific copy, empty transaction tree space, and generic
  zero-operation layout.

Modal layout:

1. Header area:
   - passkey/fingerprint visual on the left or centered above the title,
     matching the current rounded/halo treatment
   - title: `Create your passkey`
   - body copy: `Use Touch ID or your device passkey to create credentials for
     this account.`
2. Identity panel:
   - two compact rows with stable labels and selectable values
   - `Account` row displays `intendedUserName`
   - `Relying party` row displays `rpId`
   - long values wrap on small screens and may use middle truncation only when
     the full value is also available through `title` or copy selection
3. Action row:
   - primary button: `Create passkey`
   - secondary button: `Cancel`
   - primary button text changes to `Creating passkey...` while the browser
     prompt is being requested
   - both buttons become disabled after confirm until WebAuthn returns or fails
4. Theme behavior:
   - use the existing modal surface, text, border, focus, and action tokens
   - keep the modal width and responsive behavior aligned with the current
     tx-confirm modal shell
   - add no new one-off color palette for this surface
   - support light and dark themes with the same token names used by existing
     iframe UI

Security requirements:

- The modal remains wallet-origin UI.
- Confirm click must happen inside the iframe.
- rpID displayed in the modal must be the same rpID used for WebAuthn.
- Intended username displayed in the modal must be the same username/display
  name passed to WebAuthn when that field is available.
- The modal must not accept app-provided HTML, callbacks, or scriptable
  templates for these rows.
- The modal may accept typed copy overrides for title/body only after boundary
  parsing.

Implementation shape:

- Add a registration display builder near the registration confirmation flow.
- Pass the display model through `securityContext` or a new narrow confirm
  render-state branch.
- Prefer a discriminated confirm render state over optional bags:

  ```ts
  export type ConfirmRenderState =
    | { kind: 'passkey_registration'; display: PasskeyRegistrationConfirmDisplay }
    | { kind: 'transaction_confirm'; /* existing precise tx fields */ }
    | { kind: 'email_otp_confirm'; /* existing precise otp fields */ };
  ```

- Render the registration branch in modal/drawer components without mounting the
  transaction tree.
- Keep this modal path separate from `<seams-passkey-registration-btn>`.


## Public API Shape

Replace the current loose `button` bag with a discriminated presentation type:

```ts
export type RegistrationActivationButtonCssProperty =
  | 'width'
  | 'height'
  | 'minWidth'
  | 'minHeight'
  | 'maxWidth'
  | 'maxHeight'
  | 'padding'
  | 'border'
  | 'borderColor'
  | 'borderRadius'
  | 'background'
  | 'backgroundColor'
  | 'color'
  | 'boxShadow'
  | 'fontFamily'
  | 'fontSize'
  | 'fontWeight'
  | 'lineHeight'
  | 'letterSpacing'
  | 'textAlign'
  | 'cursor'
  | 'outline'
  | 'outlineColor'
  | 'outlineOffset'
  | 'outlineWidth';

export type RegistrationActivationButtonCss = Partial<
  Record<RegistrationActivationButtonCssProperty, string>
>;

export type RegistrationActivationButtonPresentation =
  | {
      kind: 'outline_overlay';
      label: string;
      busyLabel: string;
      accessibleLabel: string;
      iframeButtonStyle?: RegistrationActivationButtonCss;
      iframeVisualStyle?: never;
      shadowPaddingPx?: never;
    }
  | {
      kind: 'iframe_button';
      label: string;
      busyLabel: string;
      accessibleLabel: string;
      iframeVisualStyle: RegistrationActivationButtonCss;
      shadowPaddingPx: number;
      iframeButtonStyle?: never;
    };

export type CreatePasskeyRegistrationActivationSurfaceArgs = {
  nearAccountId: string;
  options?: RegistrationHooksOptions;
  presentation: RegistrationActivationButtonPresentation;
};
```

`outline_overlay` is the default used by `PasskeyAuthMenu`. It gives apps normal
CSS control over sizing, border radius, shadows, typography, and responsive
states while keeping the wallet-origin click target in the iframe.

Do not pass React components across the iframe boundary. React stays in the app
domain. The wallet iframe receives strings, style declarations, state, and
registration options.

## Message Protocol

Replace the current optional `button` payload with required `presentation`.

```ts
export interface PMRegistrationActivationPreparePayload {
  activationId: string;
  nearAccountId: string;
  expiresAtMs: number;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
  presentation: RegistrationActivationButtonPresentation;
}

export interface PMRegistrationActivationReadyPayload {
  activationId: string;
  expiresAtMs: number;
}

export interface PMRegistrationActivationStartedPayload {
  activationId: string;
}

export interface PMRegistrationActivationFocusPayload {
  activationId: string;
}

export interface PMRegistrationActivationButtonStatePayload {
  activationId: string;
  state: RegistrationActivationButtonInteractionState;
}
```

Add a child-to-parent state message:

```ts
export type RegistrationActivationButtonInteractionState = {
  kind: 'registration_activation_button_interaction_state_v1';
  hovered: boolean;
  focused: boolean;
  pressed: boolean;
  busy: boolean;
  disabled: boolean;
};
```

The router maps state booleans onto independent target attributes:

```text
data-seams-registration-button-active="true"
data-seams-registration-button-hovered="true"
data-seams-registration-button-focused="true"
data-seams-registration-button-pressed="true"
data-seams-registration-button-busy="true"
data-seams-registration-button-disabled="true"
```

Add a parent-to-child focus message:

```ts
export type ParentToChildRegistrationActivationFocusEnvelope = RpcEnvelope<
  'PM_REGISTRATION_ACTIVATION_FOCUS',
  PMRegistrationActivationFocusPayload
>;
```

The app-facing surface state remains operation-level state:

```ts
export type RegistrationActivationSurfaceState =
  | { kind: 'idle' }
  | { kind: 'mounting'; activationId: string }
  | { kind: 'ready'; activationId: string; expiresAtMs: number }
  | { kind: 'starting'; activationId: string }
  | { kind: 'completed'; activationId: string; result: RegistrationResult }
  | {
      kind: 'cancelled';
      activationId: string;
      reason: 'user_cancelled' | 'expired' | 'disposed' | 'target_unavailable';
    }
  | { kind: 'failed'; activationId: string; error: string };
```

All external/raw payloads are parsed at the iframe boundary before core logic
uses them. Internal code consumes the narrow discriminated unions above.

State messages from the iframe must be applied only when all of these match the
active surface:

- `event.origin`
- `event.source`
- `activationId`
- router instance id, when present

Messages that fail those checks are ignored.

## CSS Boundary Rules

The iframe host must parse style declarations at the postMessage boundary before
applying them to wallet-origin DOM.

Allowed standard CSS properties:

- `width`
- `height`
- `minWidth`
- `minHeight`
- `maxWidth`
- `maxHeight`
- `padding`
- `border`
- `borderColor`
- `borderRadius`
- `background`
- `backgroundColor`
- `color`
- `boxShadow`
- `fontFamily`
- `fontSize`
- `fontWeight`
- `lineHeight`
- `letterSpacing`
- `textAlign`
- `cursor`
- `outline`
- `outlineColor`
- `outlineOffset`
- `outlineWidth`

Rejected properties:

- positioning: `position`, `inset`, `top`, `right`, `bottom`, `left`
- stacking: `zIndex`
- visibility: `display`, `visibility`, `opacity`
- pointer routing: `pointerEvents`
- transforms and filters: `transform`, `filter`, `backdropFilter`,
  `clipPath`, `mask`
- content loading: `backgroundImage`, `content`, any `url(...)`
- animation hooks: `animation`, `transition`

The wallet iframe decides the final hit target geometry. App CSS can control the
outline's visual design, and iframe CSS can control only the button internals
inside that geometry.

## Normal Element Behavior Contract

`.seams-passkey-registration-btn` must behave like a normal HTML button-like
element from the app developer's point of view, even though the trusted events
land inside the iframe.

App developers must be able to style ordinary interaction states using stable
selectors on the outline element:

```css
.seams-passkey-registration-btn[data-seams-registration-button-hovered='true'] {
  background: #4f929e;
}

.seams-passkey-registration-btn[data-seams-registration-button-pressed='true'] {
  box-shadow: 0 10px 24px rgba(30, 72, 84, 0.18);
}

.seams-passkey-registration-btn[data-seams-registration-button-focused='true'] {
  outline: 3px solid rgba(87, 157, 170, 0.35);
  outline-offset: 3px;
}

.seams-passkey-registration-btn[data-seams-registration-button-busy='true'],
.seams-passkey-registration-btn[data-seams-registration-button-disabled='true'] {
  cursor: progress;
  opacity: 0.72;
}
```

Required mirrored event mapping:

- iframe `pointerenter` -> `hovered: true`
- iframe `pointerleave` -> `hovered: false`, `pressed: false`
- iframe `pointerdown` -> `pressed: true`
- iframe `pointerup` inside button -> `pressed: false`, `hovered: true`
- iframe `pointerup` outside button -> `pressed: false`, `hovered: false`
- iframe `pointercancel` -> `pressed: false`
- iframe `dragstart` -> `pressed: true`
- iframe `dragend` -> `pressed: false`, with `hovered` based on pointer
  position
- iframe `focus` / `focusin` -> `focused: true`
- iframe `blur` / `focusout` -> `focused: false`, `pressed: false`
- keyboard Space or Enter press -> `pressed: true`
- keyboard Space or Enter release without start -> `pressed: false`
- activation start -> `busy: true`, `disabled: true`
- completion, cancellation, failure, or dispose -> remove all mirrored
  interaction attributes

The router applies state to the same element passed to
`createPasskeyRegistrationActivationSurface(...).mount(target)`. It sets
`data-seams-registration-button-active="true"` while the activation surface is
mounted and removes that attribute on release. Apps can use that attribute for
base active-surface styling without depending on current state.

The iframe button must update its own cursor because the iframe sits above the
app outline. The parent outline's `cursor` declaration does not affect the
actual pointer target.

On `pointerdown`, the iframe button must call
`setPointerCapture(event.pointerId)` when available. This keeps `pointerup` and
`pointercancel` handling coherent when the user presses and drags outside the
button rectangle.

Native DOM events from inside the iframe are not re-dispatched into the app
domain. Re-dispatching synthetic `click` or pointer events would be misleading
because they are not trusted browser activation events. The supported app-facing
contract is mirrored attributes plus operation state callbacks.

## Geometry Contract

For `outline_overlay`, the iframe boundary must equal the target outline's
border box:

```ts
type RegistrationActivationTargetRect = {
  top: number;
  left: number;
  width: number;
  height: number;
};
```

Rules:

- measure with `target.getBoundingClientRect()`
- round to device-pixel-aware CSS pixels only at the final style assignment
- reject zero-size targets
- reject detached targets
- update on `ResizeObserver`
- update on document scroll
- update on every scrollable ancestor of the target
- update on `visualViewport` scroll/resize
- run a short `requestAnimationFrame` alignment loop while active if scrollable
  ancestor detection misses a moving target
- update before showing the iframe
- hide or cancel when the target becomes unavailable

The anchored iframe style should remain centralized in `OverlayController`.
`router.ts` should call `showAnchored(rect)` for the activation surface instead
of `showFullscreen()`.

For `iframe_button`, geometry may include shadow padding:

```ts
type RegistrationIframeVisualGeometry = {
  targetRect: RegistrationActivationTargetRect;
  shadowPaddingPx: number;
};
```

The hit target remains the inner button. The iframe viewport is larger by
`shadowPaddingPx` on each side so iframe-rendered shadows are visible.

## Accessibility Contract

The visible app outline is the app-facing focus proxy while the activation
surface is mounted. The iframe button is the real activation control.

Requirements:

- app outline has `role="button"` while iframe activation is mounted
- app outline has `tabindex="0"` while iframe activation is mounted
- app outline has `aria-label={accessibleLabel}` or an equivalent accessible
  name while iframe activation is mounted
- iframe has `title={accessibleLabel}`
- iframe removes `aria-hidden` while active
- iframe button has `aria-label={accessibleLabel}`
- iframe button is keyboard focusable
- focus on the app outline immediately asks the router to focus the iframe
  button, so the user's subsequent Enter or Space key event lands in the wallet
  iframe
- Enter and Space events that already landed on the app outline only move focus
  into the iframe. They must not start registration.
- Enter and Space inside the iframe button trigger registration from the iframe
  document
- app outline gets mirrored focus state for visual styling
- disposing the surface returns the iframe to hidden/inert state
- if activation surface cannot mount, the app must fall back to normal
  registration behavior or show an error state controlled by `PasskeyAuthMenu`

Focus should move naturally through the page. Do not trap focus for the anchored
button. Fullscreen/modal focus trapping belongs to transaction confirmation UI.

## Focus Bridge Contract

Because the SDK-managed iframe is appended under `document.body`, its natural tab
position may differ from the visual CTA position. The app outline therefore acts
as a focus proxy.

Required behavior:

- mounting sets `tabindex="0"` on the app outline when it is not already
  keyboard focusable
- focus on the app outline synchronously sends a router command to focus the
  iframe button
- blur from the iframe button mirrors `focused: false` back to the app outline
- Enter and Space from the app outline focus the iframe button and do not start
  registration. The iframe-owned key handler owns activation.
- router cleanup restores any original `tabindex`, `role`, and ARIA attributes
  it changed on the app outline
- tests cover keyboard registration from the visual CTA position

## Security Contract

The anchored activation surface is the only path that can skip the registration
confirmation modal in wallet iframe mode.

Required guarantees:

- normal `PM_REGISTER` continues to strip caller-supplied
  `walletIframeActivation`
- `determineConfirmationConfig` continues to clamp iframe registration without
  iframe-minted activation proof
- activation ids are unguessable, short-lived, and single-use
- duplicate clicks are ignored after the first start
- expired activation records reject before calling WebAuthn
- disposed activation surfaces cancel pending records
- style payloads are parsed and normalized before DOM application
- rejected style properties cannot affect iframe position, visibility, pointer
  routing, stacking, transforms, URLs, or animation
- app-domain code cannot call a public API that mints
  `walletIframeActivation`
- mirrored state messages are accepted only from the active wallet iframe
  window, trusted wallet origin, and active `activationId`

The outline overlay mode intentionally gives the app control over visual styling
only. It does not give the app control over the activation proof or the WebAuthn
call.

## Error And Cancellation Behavior

Cancellation reasons:

```ts
type RegistrationActivationCancellationReason =
  | 'user_cancelled'
  | 'expired'
  | 'disposed'
  | 'target_unavailable';
```

Error handling rules:

- user cancellation maps to `cancelled/user_cancelled`
- expiry maps to `cancelled/expired`
- component unmount maps to `cancelled/disposed`
- detached or zero-size target maps to `cancelled/target_unavailable`
- parser rejection maps to `failed` with a stable error message
- WebAuthn errors propagate through the existing registration result/error path
- completion hides the iframe and clears target data attributes
- failure hides the iframe and clears target data attributes

## React Integration Shape

`PasskeyAuthMenu` should keep registration lifecycle decisions in the existing
controller. The view layer only renders the outline slot and binds that slot to
the activation surface.

Implementation shape:

- create a top-level `mountPasskeyRegistrationActivationSurface` helper
- pass it the `SeamsWeb` instance, account id, target element, labels, and event
  hooks
- have the helper create the activation surface, mount it, and return a dispose
  function
- call that helper from the component effect
- render `.seams-passkey-registration-btn` as the outline slot with a visual
  `<span>Create with Passkey</span>`
- mirror `ready`, `starting`, `completed`, `cancelled`, and `failed` into the
  controller's existing waiting/error behavior

Keep callback construction out of the component body where practical. The final
implementation should follow the existing `PasskeyAuthMenu` controller patterns
instead of adding an ad hoc lifecycle state bag in the view.

## Phased Todo List

### Phase 0: Guardrails And Baseline

- [ ] Confirm current failing UX with a browser trace:
  `Create with Passkey` -> iframe confirmation popup -> TouchID.
- [ ] Add a focused regression test that detects transaction confirmer mounting
  during iframe passkey registration.
- [ ] Keep existing tests that prove normal iframe registration is clamped.
- [ ] Keep existing tests that prove caller-supplied activation proofs are
  stripped from `PM_REGISTER`.

### Phase 1: Types And Protocol

- [ ] Replace `button?: { label?: string; busyLabel?: string }` with required
  `presentation: RegistrationActivationButtonPresentation`.
- [ ] Add a tag constant for `seams-passkey-registration-btn`.
- [ ] Add `RegistrationActivationButtonCssProperty`.
- [ ] Add `RegistrationActivationButtonCss`.
- [ ] Add `RegistrationActivationButtonInteractionState`.
- [ ] Add `PasskeyRegistrationConfirmDisplay`.
- [ ] Add or reuse a precise `ConfirmRenderState` branch for passkey
  registration modal rendering.
- [ ] Add `PM_REGISTRATION_ACTIVATION_BUTTON_STATE`.
- [ ] Add `PM_REGISTRATION_ACTIVATION_FOCUS`.
- [ ] Add `target_unavailable` to activation cancellation reasons.
- [ ] Add type fixtures that reject mixed presentation branches.
- [ ] Delete tests or fixtures that depend on the old optional `button` payload.

### Phase 2: Boundary Parsing

- [ ] Add a postMessage boundary parser for
  `PM_REGISTRATION_ACTIVATION_PREPARE`.
- [ ] Normalize `label`, `busyLabel`, and `accessibleLabel` to required strings.
- [ ] Normalize registration modal display data into
  `PasskeyRegistrationConfirmDisplay`.
- [ ] Require `rpId` and `intendedUserName` before rendering the code-only modal.
- [ ] Normalize `shadowPaddingPx` for `iframe_button`.
- [ ] Parse CSS declaration objects against the allowed property list.
- [ ] Reject raw unknown style keys.
- [ ] Reject `url(...)` in all CSS values.
- [ ] Return a `Result`-style parse result.
- [ ] Add parser tests for accepted sizing, radius, shadows, typography, and
  outline styles.
- [ ] Add parser tests for rejected positioning, z-index, opacity,
  pointer-events, transform, filter, clip-path, URL, transition, and animation.

### Phase 3: Router Geometry And Overlay

- [ ] Update `createPasskeyRegistrationActivationSurface(...).mount(target)` to
  store the target element.
- [ ] Measure the target with `getBoundingClientRect()`.
- [ ] Use `OverlayController.showAnchored(rect)` instead of fullscreen for
  `outline_overlay`.
- [ ] Add a geometry observer that updates anchored rect on resize, scroll, and
  visual viewport changes.
- [ ] Track every scrollable ancestor of the target.
- [ ] Add a short `requestAnimationFrame` alignment loop while active for moving
  targets that observer/listener coverage misses.
- [ ] Cancel with `target_unavailable` when the target detaches or becomes
  zero-size.
- [ ] Set `data-seams-registration-button-active="true"` on the target while the
  activation surface is mounted.
- [ ] Apply mirrored button interaction attributes to the target element.
- [ ] Validate mirrored-state messages by origin, source, router id when
  present, and `activationId`.
- [ ] Clear target data attributes on completion, cancellation, failure, and
  dispose.
- [ ] Clear `data-seams-registration-button-active` on completion, cancellation,
  failure, and dispose.
- [ ] Keep the existing hidden iframe state after release.

### Phase 4: Wallet Iframe Host Rendering

- [ ] Add the
  `lit-components/passkey-registration-btn/` component subtree.
- [ ] Add the `seams-passkey-registration-btn` entrypoint.
- [ ] Register the entrypoint in the SDK build if explicit Lit asset
  registration is required.
- [ ] Define the wallet-origin custom element before mounting activation UI.
- [ ] Keep dynamic import and element definition before the iframe reports
  `PM_REGISTRATION_ACTIVATION_READY`.
- [ ] Send `PM_REGISTRATION_ACTIVATION_READY` only after the element is defined,
  connected, and focusable.
- [ ] Replace fullscreen `renderRegistrationActivationButton` panel rendering
  for `outline_overlay`.
- [ ] Render `<seams-passkey-registration-btn>` instead of inline panel DOM.
- [ ] Have the component render only a full-size transparent wallet-origin
  `<button>`.
- [ ] Set `aria-label` from `accessibleLabel`.
- [ ] Set the initial text content to the label for assistive tech fallback,
  while visual text remains transparent.
- [ ] Disable the button on first activation.
- [ ] Update text content to `busyLabel` after start.
- [ ] Emit mirrored interaction-state messages for hovered, focused, pressed,
  busy, and disabled.
- [ ] Handle `PM_REGISTRATION_ACTIVATION_FOCUS` by focusing the internal iframe
  button for the matching `activationId`.
- [ ] Mirror pointerenter, pointerleave, pointerdown, pointerup, pointercancel,
  dragstart, dragend, focus, blur, and keyboard Space/Enter press/release into
  parent state.
- [ ] Call `setPointerCapture(event.pointerId)` on pointerdown when available.
- [ ] Keep the component independent from `seams-tx-confirmer`, tx-confirm state,
  export-key UI, and modal/drawer containers.
- [ ] Preserve iframe-minted `walletIframeActivation`.
- [ ] Preserve duplicate-click protection.
- [ ] Preserve expiry cancellation.

### Phase 5: Code-Only Registration Modal

- [ ] Build `PasskeyRegistrationConfirmDisplay` during registration
  confirmation setup.
- [ ] Populate `rpId` from the same runtime value used for WebAuthn.
- [ ] Populate `intendedUserName`, defaulting to the account id when no narrower
  display name exists.
- [ ] Add a registration-specific modal render branch.
- [ ] Remove empty transaction-tree space from the registration modal.
- [ ] Add visible detail rows for `Account` and `Relying party`.
- [ ] Keep signer slot in debug/development details only unless product UI needs
  it.
- [ ] Update modal copy to registration-specific language.
- [ ] Use existing modal theme tokens, spacing, radius, passkey/fingerprint
  visual treatment, and light/dark behavior.
- [ ] Show a busy state after confirm while WebAuthn is being requested.
- [ ] Keep the code-only modal confirm click as the wallet-origin user
  activation source.
- [ ] Keep typed title/body overrides isolated at the request boundary.
- [ ] Ensure no app-provided HTML, callbacks, or scriptable templates enter the
  modal.
- [ ] If WebAuthn user display names are supported separately from the stable
  user handle, pass `intendedUserName` to `navigator.credentials.create` as
  `user.name` / `displayName`.

### Phase 6: Registration Flow

- [ ] Ensure click-started registration passes:
  `{ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 }`.
- [ ] Ensure no dynamic import, element definition, UI mount, app-domain round
  trip, or timer happens after click and before WebAuthn creation.
- [ ] Ensure `walletIframeActivation` is included only in the iframe-started
  registration path.
- [ ] Ensure `determineConfirmationConfig` accepts the iframe proof and skips
  modal UI.
- [ ] Ensure plain `registerPasskey` from app-domain code still shows the
  improved wallet-origin registration modal.
- [ ] Ensure WebAuthn is called in the same iframe activation chain as the
  button click.

### Phase 7: PasskeyAuthMenu Integration

- [ ] Add a top-level helper for mounting the registration activation surface.
- [ ] Render an outline slot in register mode when wallet iframe mode is active.
- [ ] Keep the existing app-domain button path for non-iframe runtime.
- [ ] Wire surface state into existing controller waiting/error state.
- [ ] Dispose the surface on mode change, account id change, route unmount, and
  provider teardown.
- [ ] Add CSS state selectors for the outline data attributes.
- [ ] Style hover, pressed, focused, busy, and disabled via mirrored
  attributes so `.seams-passkey-registration-btn` behaves like a normal
  button-like element.
- [ ] Add the app-outline focus proxy and restore original focus-related
  attributes on cleanup.
- [ ] Send `PM_REGISTRATION_ACTIVATION_FOCUS` when the outline receives focus.
- [ ] Ensure app-outline Enter/Space focuses the iframe button and does not
  start registration from app-origin key events.
- [ ] Keep app-domain visual styles in `PasskeyAuthMenu.css`.
- [ ] Ensure the outline has stable dimensions before the iframe mounts.

### Phase 8: Tests

- [ ] Unit: `determineConfirmationConfig` still clamps iframe registration
  without `walletIframeActivation`.
- [ ] Unit: `determineConfirmationConfig` skips only with iframe activation
  proof.
- [ ] Unit: `PM_REGISTER` strips caller-supplied activation proofs.
- [ ] Unit: activation button mints the proof and uses `skipClick`.
- [ ] Unit: duplicate click starts registration once.
- [ ] Unit: expiry rejects before WebAuthn.
- [ ] Unit: dispose cancels pending activation.
- [ ] Unit: CSS parser allowlist and reject list.
- [ ] Type fixture: invalid presentation unions are rejected.
- [ ] Unit or component: `seams-passkey-registration-btn` emits activation
  intent once and mirrors hover/focus/pressed/busy/disabled state.
- [ ] Unit or component: pointer cancel, drag end, blur, and keyboard release
  return the mirrored state to the correct non-pressed state.
- [ ] Unit or component: pointerdown captures the pointer when
  `setPointerCapture` is available.
- [ ] Source guard: `seams-passkey-registration-btn` does not import
  tx-confirm, export-key UI, modal/drawer containers, or React wrappers.
- [ ] Unit: router ignores state messages with wrong origin, source, router id,
  or `activationId`.
- [ ] Unit/component: code-only registration modal renders account/intended user
  name and rpID from `PasskeyRegistrationConfirmDisplay`.
- [ ] Unit/component: registration modal does not render an empty transaction
  tree.
- [ ] Unit/component: registration modal busy state appears after confirm.
- [ ] Unit: rpID displayed in the modal matches the rpID passed to WebAuthn.
- [ ] Browser: iframe rect equals target rect within 1 CSS pixel.
- [ ] Browser: `Create with Passkey` opens WebAuthn without mounting
  a transaction confirmer element.
- [ ] Browser: code-only registration opens the improved wallet-origin modal,
  displays intended user name and rpID, then opens WebAuthn after confirm.
- [ ] Browser: app-domain `box-shadow` remains visible outside iframe boundary.
- [ ] Browser: keyboard focus and Enter start registration.
- [ ] Browser: app-domain outline styling changes for hovered, pressed,
  focused, busy, and disabled mirrored states.
- [ ] Browser: unmount removes iframe hit target and target data attributes.
- [ ] Browser: target resize, document scroll, scrollable ancestor movement, and
  visual viewport changes keep iframe aligned.

### Phase 9: Cleanup And Documentation

- [ ] Delete the old fullscreen registration activation panel path used by the
  activation-surface flow.
- [ ] Delete old optional `button` payload compatibility.
- [ ] Update README or SDK docs for `PasskeyAuthMenu` one-click registration.
- [ ] Document the code-only registration modal path.
- [ ] Document the `seams-passkey-registration-btn` modal-skipping path.
- [ ] Add `lit-components/passkey-registration-btn/README.md`.
- [ ] Update `docs/refactor-8X-lit.md` relationship notes if that plan's target
  directory structure changes first.
- [ ] Document that React components do not cross the iframe boundary.
- [ ] Document `outline_overlay` as the default styling model.
- [ ] Document `iframe_button` as an advanced mode with shadow padding tradeoff.
- [ ] Run the cheapest focused test suite covering wallet iframe registration,
  confirmation config, and `PasskeyAuthMenu`.

## Acceptance Criteria

- Code-only app-domain registration shows a wallet-origin registration modal.
- The code-only modal displays intended user name and rpID before confirm.
- The code-only modal uses registration-specific copy and does not show empty
  transaction content.
- Confirming the code-only modal opens the passkey prompt from a wallet-origin
  click.
- One click on the `seams-passkey-registration-btn` activation path opens the
  passkey prompt in wallet iframe mode.
- The extra registration confirmation popup is absent for
  `seams-passkey-registration-btn` activation-surface registration.
- The iframe boundary covers only the registration CTA.
- App CSS can style the visible button outline with normal CSS, including size,
  radius, shadows, typography, hover, pressed, focus, busy, and disabled states.
- The wallet iframe owns the actual activation button and the WebAuthn call.
- Normal app-domain registration calls still require wallet-origin confirmation.
