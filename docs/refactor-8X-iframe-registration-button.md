# Iframe Registration Button

Date created: June 20, 2026

Status: implemented with focused Chromium coverage. Real WebKit/Safari
wallet-origin registration evidence and the full hidden-target/accessibility
browser matrix remain release gates before claiming Safari support.

## Current Status

This plan started as a spec and now also tracks implementation evidence. Checked
items record behavior covered by focused type, unit, component, browser, build,
or source-guard checks. Unchecked browser-evidence items remain release
blocking.

Do not reintroduce compatibility for the old optional activation `button`
payload. The replacement API is the required discriminated `presentation`
payload.

## Goal

Define the wallet iframe registration UX for two supported paths:

1. `SeamsAuthMenu` can provide a one-click passkey registration flow:
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

`SeamsAuthMenu` currently renders an app-domain React button. Clicking it calls
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
  void seams.registration.registerPasskey();
}

<AppDomainButton onClick={handleCreatePasskeyClick}>Create with Passkey</AppDomainButton>;
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

| Path                           | First app action                             | Wallet-origin activation                       | Modal    |
| ------------------------------ | -------------------------------------------- | ---------------------------------------------- | -------- |
| Code-only registration         | App-domain button calls the registration API | User clicks confirm in the wallet iframe modal | Required |
| Activation button registration | User clicks the iframe-owned CTA button      | Same iframe button click starts WebAuthn       | Skipped  |

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

Ship one public presentation mode and retain one internal research mode.

### Outline Overlay

This is the default for `SeamsAuthMenu`.

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
  SeamsAuthMenu
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

- activation-button registration from `SeamsAuthMenu`
- code-only registration from ordinary app-domain registration API calls

In scope:

- one-click passkey registration from `SeamsAuthMenu`
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
- `packages/sdk-web/src/react/components/SeamsAuthMenu/client.tsx`
  - currently renders the app-domain `Create with Passkey` button
- `packages/sdk-web/src/react/components/SeamsAuthMenu/controller/useSeamsAuthMenuController.ts`
  - owns menu state and registration intent transitions
- `packages/sdk-web/src/react/components/SeamsAuthMenu/SeamsAuthMenu.css`
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
  css/
    seams-passkey-registration-btn.css
  passkey-registration-btn/
    entrypoints/
      seams-passkey-registration-btn.ts
    components/
      seams-passkey-registration-btn-element.ts
    state/
      passkey-registration-button-state.ts
      passkey-registration-button-builders.ts
      assert-never.ts
    index.ts
    README.md
```

Directory ownership:

1. `entrypoints/` defines the custom element and is the only module imported by
   the wallet iframe handler.
2. `components/` owns rendering the transparent iframe button and emitting
   component events.
3. `state/` owns the element lifecycle union and builders.
4. The shared Lit `css/` folder owns iframe-internal button styles only. App-domain
   outline styles remain in `SeamsAuthMenu.css`.
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

1. `SeamsAuthMenu` enters register mode with a valid account id.
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
- no app-domain round trip before the prepared WebAuthn continuation
- no timer before `navigator.credentials.create`
- warmup and registration preparation should happen before the iframe reports
  `PM_REGISTRATION_ACTIVATION_READY`
- after click, the iframe path is:
  `button handler -> consumePreparedActivation -> continuePreparedIframePasskeyRegistration -> navigator.credentials.create`

Precise activation rule:

- The iframe click handler must start the registration call synchronously from
  the trusted iframe event handler.
- The click handler may send `PM_REGISTRATION_ACTIVATION_STARTED` and mirrored
  busy/disabled state messages as fire-and-forget side effects.
- The click handler must not `await` a parent-window, app-domain, React, router
  layout, analytics, or style response before the registration flow reaches the
  WebAuthn credential creation call.
- Any telemetry or app-facing state callback that needs parent acknowledgement
  must run after the WebAuthn request has already been made, or after the
  registration promise settles.
- If registration cannot be prepared before the ready event, the surface should
  fail or fall back to the code-only modal path instead of doing delayed
  preparation inside the trusted click.

The current registration flow already supports the policy end of this path.
After it verifies an iframe-minted activation proof,
`determineConfirmationConfig` can return `uiMode: 'none'`, and the no-UI adapter
can produce `confirmed: true` without mounting confirmation UI. The
timing-sensitive work below is the stricter requirement for reaching WebAuthn
from the trusted iframe activation chain.

## Pre-Armed Registration Contract

The activation-button path must prepare every slow or asynchronous input before
the iframe reports `PM_REGISTRATION_ACTIVATION_READY`. The click handler should
only mark activation as started, mint the iframe activation proof, and enter a
registration continuation that can reach `navigator.credentials.create()` without
waiting on app-origin UI, parent acknowledgement, dynamic imports, custom element
definition, or fresh registration intent setup.

Prepared state:

```ts
export type PreparedIframePasskeyRegistration = {
  kind: 'prepared_iframe_passkey_registration_v1';
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  rpId: WebAuthnRpId;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  challengeB64u: string;
  display: PasskeyRegistrationConfirmDisplay;
  expiresAtMs: number;
  confirmation: {
    kind: 'iframe_activation_confirmation_armed';
    requiredProof: 'wallet_iframe_activation';
  };
  warmup: {
    kind: 'complete';
    registrationWarmup: 'complete';
    activationElement: 'defined_or_fallback_ready';
  };
};

export type PreparedIframePasskeyRegistrationRecord = {
  kind: 'prepared_iframe_passkey_registration_record_v1';
  identity: RegistrationActivationMessageIdentity;
  prepared: PreparedIframePasskeyRegistration;
  promptReservation: ReservedRegistrationWebAuthnPrompt<
    Extract<RegistrationWebAuthnPromptOwner, { kind: 'registration_activation' }>
  >;
};

export type ActivatedPreparedIframePasskeyRegistration = {
  kind: 'activated_prepared_iframe_passkey_registration_v1';
  record: PreparedIframePasskeyRegistrationRecord;
  activationProof: WalletIframeActivationProof;
  activatedAtMs: number;
};
```

Lifecycle:

```ts
export type PreparedIframePasskeyRegistrationState =
  | { kind: 'preparing'; identity: RegistrationActivationMessageIdentity }
  | { kind: 'ready'; record: PreparedIframePasskeyRegistrationRecord }
  | { kind: 'activated'; activated: ActivatedPreparedIframePasskeyRegistration }
  | {
      kind: 'credential_create_requested';
      activated: ActivatedPreparedIframePasskeyRegistration;
      requestedAtMs: number;
    }
  | {
      kind: 'completed';
      activated: ActivatedPreparedIframePasskeyRegistration;
      result: RegistrationResult;
    }
  | {
      kind: 'cancelled';
      identity: RegistrationActivationMessageIdentity;
      reason: 'user_cancelled' | 'expired' | 'disposed' | 'target_unavailable';
    }
  | { kind: 'failed'; identity: RegistrationActivationMessageIdentity; error: string };
```

Preparation requirements:

- Resolve wallet ID, rpID, signer slot, display data, registration intent digest,
  and WebAuthn challenge before `READY`.
- Wait for registration warmup before `READY`.
- Define `<seams-passkey-registration-btn>` or prepare the fallback button before
  `READY`.
- Prepare the no-UI confirmation branch before `READY`; the activation path must
  never mount confirmation UI after the click. Armed confirmation is incomplete
  until the wallet-origin handler supplies its single-use activation proof.
- Store one `PreparedIframePasskeyRegistrationRecord` under its complete
  `identity`. The prepared payload carries no duplicate identity.
- Acquire a single-use `ReservedRegistrationWebAuthnPrompt` before `READY` and
  store it in the prepared record. A record without a live reservation cannot
  enter `ready`.
- Expire the prepared registration at `expiresAtMs`; an expired prepared state
  rejects before WebAuthn.
- Treat duplicate activation for the same `activationId` as a no-op after the
  first `activated` transition.

The post-click path must use a narrow continuation instead of the general
`registerPasskey()` entrypoint:

```ts
export function continuePreparedIframePasskeyRegistration(
  activated: ActivatedPreparedIframePasskeyRegistration,
): Promise<RegistrationResult>;
```

`ActivatedPreparedIframePasskeyRegistration` can be built only by the
wallet-origin button handler after it atomically verifies expiry and consumes the
single-use activation record. The continuation accepts no raw options, wallet
draft, confirmation config, or unresolved preparation state. It must call
`navigator.credentials.create()` before its first `await`. General registration
setup, challenge allocation, warmup, UI selection, parent acknowledgement, and
telemetry stay outside this function.

Add instrumentation in browser tests that records when
`navigator.credentials.create()` is called relative to the iframe button event.
Chromium must show that the call is still inside the trusted activation chain.
Each supported WebKit/Safari version must show the same native wallet-origin
success path. Unsupported versions must return the typed wallet-origin error
without attempting parent-domain registration.

## WebAuthn Prompt Reservation Contract

Replace the promise-tail `webAuthnPromptQueue` with an explicit coordinator:

```ts
export type WebAuthnPromptCoordinatorState =
  | { kind: 'idle' }
  | {
      kind: 'reserved';
      reservation: ReservedRegistrationWebAuthnPrompt;
    }
  | {
      kind: 'running';
      operationId: WebAuthnPromptOperationId;
      owner: WebAuthnPromptOwner;
    };

export type RegistrationWebAuthnPromptOwner =
  | {
      kind: 'registration_activation';
      identity: RegistrationActivationMessageIdentity;
    }
  | {
      kind: 'registration_modal';
      requestId: RequestId;
    };

export type WebAuthnPromptOwner =
  | RegistrationWebAuthnPromptOwner
  | {
      kind: 'wallet_request';
      requestId: RequestId;
    };

export type ReservedRegistrationWebAuthnPrompt<
  Owner extends RegistrationWebAuthnPromptOwner = RegistrationWebAuthnPromptOwner,
> = {
  kind: 'reserved_registration_webauthn_prompt_v1';
  reservationId: WebAuthnPromptReservationId;
  owner: Owner;
  expiresAtMs: number;
};
```

Reservation rules:

- Registration preparation waits for the coordinator to become `idle`, then
  atomically transitions it to `reserved` before reporting `READY`.
- The reservation owner must equal the complete active surface identity.
- While reserved, no registration, authentication, unlock, or signing flow may
  start another WebAuthn operation.
- The wallet-origin click atomically consumes the reservation and calls
  `navigator.credentials.create()` inline before returning control to the event
  loop or scheduling a promise continuation.
- The resulting credential promise may be awaited only after the browser call
  has been made and the coordinator has entered `running`.
- Expiry, cancellation, disposal, preparation failure, surface replacement, and
  synchronous credential-creation failure release the reservation exactly once.
- A mismatched, expired, released, or reused reservation rejects before WebAuthn.
- Waiting for a busy coordinator happens only before `READY`. The trusted click
  never waits for the queue.
- Other gesture-bound WebAuthn paths must use the same coordinator. Keep no
  parallel promise-tail queue or compatibility path.

## Safari Wallet-Origin Registration Policy

Passkey registration must preserve the wallet RP and keep credential creation
inside a wallet-origin browsing context.

Policy:

- Registration calls `navigator.credentials.create()` natively in the wallet
  iframe after a wallet-origin activation.
- Registration must not use `WindowParentDomainWebAuthnClient` or emit
  `WALLET_WEBAUTHN_CREATE` to ask the app-origin parent to create a credential.
- This restriction applies to activation-button and code-only modal
  registration. Authentication `get` behavior is outside this plan.
- Related Origin Requests and app-origin parent execution are outside this
  release. They require a separate security review covering RP allowlists,
  wallet interoperability, PRF exposure, and activation semantics.
- If WebKit/Safari rejects native wallet-iframe creation because of ancestor or
  focus restrictions, return a typed `wallet_origin_webauthn_unavailable` error,
  release the prompt reservation, and create no app-origin credential.
- Claim Safari one-click support only after a real WebKit/Safari test proves the
  native call starts from the iframe activation and uses the wallet RP ID.
- If that test fails, keep the one-click path unsupported for the affected
  Safari versions until a separately designed wallet-origin top-level flow
  exists. Do not silently fall back to parent-origin WebAuthn.

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

Prepared modal state:

```ts
export type PreparedCodeOnlyPasskeyRegistrationConfirm = {
  kind: 'prepared_code_only_passkey_registration_confirm_v1';
  requestId: RequestId;
  wallet:
    | { kind: 'provided'; walletId: WalletId }
    | { kind: 'server_allocated_resolved'; walletId: WalletId };
  rpId: WebAuthnRpId;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  challengeB64u: string;
  display: PasskeyRegistrationConfirmDisplay;
  expiresAtMs: number;
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
- `registrationIntentDigestB64u`, `challengeB64u`, and `expiresAtMs` are hidden
  binding fields. They bind the confirm button to the prepared registration and
  protect against stale modal confirmation.
- A server allocation must resolve to a concrete `walletId` before this prepared
  state can be built or rendered. Pending allocation is an earlier lifecycle
  state and cannot enable the confirm button.
- `display.accountId` must be derived from the resolved wallet identity by the
  prepared-state builder.

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
    | { kind: 'transaction_confirm' /* existing precise tx fields */ }
    | { kind: 'email_otp_confirm' /* existing precise otp fields */ };
  ```

- Render the registration branch in modal/drawer components without mounting the
  transaction tree.
- Keep this modal path separate from `<seams-passkey-registration-btn>`.

## Public API Shape

Replace the current loose `button` bag with a discriminated presentation type:

```ts
type InternalRegistrationActivationButtonCssProperty =
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

type InternalRegistrationActivationButtonCss = Partial<
  Record<InternalRegistrationActivationButtonCssProperty, string>
>;

export type RegistrationActivationButtonPresentation = {
  kind: 'outline_overlay';
  label: string;
  busyLabel: string;
  accessibleLabel: string;
  iframeButtonStyle?: never;
  iframeVisualStyle?: never;
  shadowPaddingPx?: never;
};

type InternalRegistrationActivationButtonPresentation =
  | RegistrationActivationButtonPresentation
  | {
      kind: 'iframe_button';
      label: string;
      busyLabel: string;
      accessibleLabel: string;
      iframeVisualStyle: InternalRegistrationActivationButtonCss;
      shadowPaddingPx: number;
      iframeButtonStyle?: never;
    };

export type CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  options?: RegistrationHooksOptions;
  presentation: RegistrationActivationButtonPresentation;
};
```

`outline_overlay` is the default used by `SeamsAuthMenu`. It gives apps normal
CSS control over sizing, border radius, shadows, typography, and responsive
states while keeping the wallet-origin click target in the iframe.

`iframe_button` remains internal research scope. It is excluded from
`CreatePasskeyRegistrationActivationSurfaceArgs` and public documentation until
parser tests and Chromium/WebKit geometry tests prove that the padded iframe
places the inner wallet-origin hit target over the intended app-domain button
rect. Promoting it requires an explicit public API revision.

The public `outline_overlay` branch accepts no iframe button style payload. The
wallet iframe always renders a full-size transparent button with SDK-owned CSS;
the app styles the visible outline in its own document.

Public API naming rules:

- The direct registration API is `seams.registration.registerPasskey(options)`
  for implicit NEAR registration.
- The activation-surface API is
  `seams.registration.createPasskeyRegistrationActivationSurface(args)`.
- Activation-surface registration is wallet-bound before WebAuthn. See
  [refactor-84a-iframe-walletId.md](./refactor-84a-iframe-walletId.md): visible
  iframe registration must pass a provided wallet ID through the public API,
  postMessage payload, host parser, registration call, and WebAuthn
  `user.name` / `user.displayName`.
- Do not document or add a parallel `registerPasskeyAccount()` API unless the
  public API is intentionally renamed in a separate refactor.
- Public examples must use the real `registration` namespace, because the
  difference between direct registration and activation-surface registration is
  security-relevant.

Do not pass React components across the iframe boundary. React stays in the app
domain. The wallet iframe receives strings, style declarations, state, and
registration options.

Public activation-surface trust policy:

- `SeamsAuthMenu` is the first supported activation-surface consumer.
- Direct `createPasskeyRegistrationActivationSurface()` usage is advanced and
  assumes the app-origin UI truthfully represents passkey registration for the
  provided wallet.
- The app-controlled visible CTA becomes part of the user-intent trust base.
  App copy should clearly indicate passkey creation and the wallet/account being
  registered.
- The SDK should reject or cancel targets that are hidden, effectively
  transparent, detached, smaller than `44x44` CSS pixels, or made inert by an
  ancestor.
- `SeamsAuthMenu` and direct public usage must use the same `44x44` CSS-pixel
  minimum. Production APIs expose no size override; test harnesses may inject a
  lower threshold through test-only construction.
- The public API must not expose any method that accepts a caller-supplied
  `walletIframeActivation` proof.

## Message Protocol

Replace the current optional `button` payload with required `presentation`,
required provided `wallet`, and explicit surface identity.

```ts
export type WalletIframeSurfaceId = string & {
  readonly __walletIframeSurfaceId: unique symbol;
};

export type RegistrationActivationId = string & {
  readonly __registrationActivationId: unique symbol;
};

export type RequestId = string & {
  readonly __requestId: unique symbol;
};

export type RegistrationActivationMessageIdentity = {
  surfaceId: WalletIframeSurfaceId;
  activationId: RegistrationActivationId;
  requestId: RequestId;
};

export interface PMRegistrationActivationPreparePayload extends RegistrationActivationMessageIdentity {
  expiresAtMs: number;
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  presentation: RegistrationActivationButtonPresentation;
}

export interface PMRegistrationActivationReadyPayload extends RegistrationActivationMessageIdentity {
  expiresAtMs: number;
}

export interface PMRegistrationActivationStartedPayload extends RegistrationActivationMessageIdentity {}

export interface PMRegistrationActivationFocusPayload extends RegistrationActivationMessageIdentity {}

export interface PMRegistrationActivationFocusExitPayload extends RegistrationActivationMessageIdentity {
  direction: 'forward' | 'backward';
}

export interface PMRegistrationActivationButtonStatePayload extends RegistrationActivationMessageIdentity {
  state: RegistrationActivationButtonInteractionState;
}
```

The wallet iframe stores `PreparedIframePasskeyRegistrationRecord` internally.
`PM_REGISTRATION_ACTIVATION_READY` acknowledges that the record exists and
reports its expiry for parent-side lifecycle display.
It must not send the challenge, registration intent digest, confirmation state,
warmup state, or activation proof to the app-origin parent.

Activation prepare carries no caller-controlled confirmation policy or generic
options bag. Public hooks remain app-side, and wallet-owned preparation derives
the exact no-UI policy internally. Any future protocol option must be a required,
branch-specific parsed field.

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

export type ChildToParentRegistrationActivationFocusExitEnvelope = RpcEnvelope<
  'PM_REGISTRATION_ACTIVATION_FOCUS_EXIT',
  PMRegistrationActivationFocusExitPayload
>;
```

The app-facing surface state remains operation-level state:

```ts
export type RegistrationActivationSurfaceState =
  | { kind: 'idle' }
  | { kind: 'mounting'; identity: RegistrationActivationMessageIdentity }
  | {
      kind: 'ready';
      identity: RegistrationActivationMessageIdentity;
      expiresAtMs: number;
    }
  | { kind: 'starting'; identity: RegistrationActivationMessageIdentity }
  | {
      kind: 'completed';
      identity: RegistrationActivationMessageIdentity;
      result: RegistrationResult;
    }
  | {
      kind: 'cancelled';
      identity: RegistrationActivationMessageIdentity;
      reason: 'user_cancelled' | 'expired' | 'disposed' | 'target_unavailable';
    }
  | {
      kind: 'failed';
      identity: RegistrationActivationMessageIdentity;
      error: string;
    };
```

All external/raw payloads are parsed at the iframe boundary before core logic
uses them. Internal code consumes the narrow discriminated unions above.

State messages from the iframe travel over the established wallet `MessagePort`.
They must be applied only when all of these match the active surface:

- `activationId`
- `surfaceId`
- `requestId`
- router instance id, when present
- the authenticated wallet iframe connection that owns the `MessagePort`

Messages that fail those checks are ignored.

Message acceptance rules:

- Only the `MessagePort` created by the active wallet iframe handshake can
  mutate activation surface state.
- `connectionId` is trusted transport metadata attached by the router after it
  authenticates the owning `MessagePort`. It is never serialized in a
  postMessage payload or accepted from app-origin input.
- The router must compare the message's `activationId` to the currently mounted
  activation id and compare `surfaceId` to the active wallet iframe surface
  before applying any state.
- The router must compare `requestId` when a registration request has already
  been allocated. Messages with a matching activation id and mismatched request
  id are stale and ignored.
- If the router tracks a wallet router id, the message must match the active
  router id as well as the activation id.
- Button-state messages received before `ready`, after `completed`, after
  `cancelled`, after `failed`, or after `dispose()` are ignored.
- Malformed interaction-state payloads are ignored and may emit a diagnostic;
  they must not change outline attributes.
- `PM_REGISTRATION_ACTIVATION_STARTED` is single-use. A second `started` message
  for the same activation id is ignored after the surface enters `starting`.
- Focus messages are parent-to-child only. Child-to-parent messages cannot cause
  app-domain synthetic click or keyboard events to be re-dispatched.
- Parser failures for `PM_REGISTRATION_ACTIVATION_PREPARE` fail the surface
  before host UI mount and return a stable `failed` state.

## CSS Boundary Rules

The following style boundary applies only to the internal `iframe_button`
research mode. Public `outline_overlay` registration sends no iframe style
payload. The iframe host must parse internal style declarations at the
postMessage boundary before applying them to wallet-origin DOM.

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
- reject targets narrower than `44` CSS pixels or shorter than `44` CSS pixels
- reject detached targets
- reject a target or ancestor with `display: none`, `visibility: hidden`,
  `visibility: collapse`, `content-visibility: hidden`, or `inert`
- reject a target when the product of target and ancestor computed opacity is
  less than `0.1`
- update on `ResizeObserver`
- update on document scroll
- update on every scrollable ancestor of the target
- update on `visualViewport` scroll/resize
- run a short `requestAnimationFrame` alignment loop while active if scrollable
  ancestor detection misses a moving target
- update before showing the iframe
- hide or cancel when the target becomes unavailable
- compute clipping ancestors from `overflow-x` and `overflow-y` values of
  `hidden`, `clip`, `auto`, or `scroll`
- suspend iframe visibility, focusability, and pointer events while the target
  border box is partially clipped by any clipping ancestor; retain prepared
  state and resume only when the complete border box is visible again

Edge cases:

- A target partially offscreen remains valid. The iframe rect is clipped by the
  browser viewport naturally, and the visible hit target remains aligned to the
  visible portion of the outline.
- A target fully outside the visual viewport remains mounted and aligned to its
  offscreen rect. The browser naturally exposes no visible hit target until the
  outline re-enters the viewport. Do not cancel solely because the target is
  scrolled out of view.
- A target with `display: none`, insufficient dimensions, detached DOM, no
  client rect, hidden visibility, hidden content visibility, inert ancestry, or
  effective opacity below `0.1` cancels with `target_unavailable`.
- Ancestor clipping suspends the anchored render mode without releasing surface
  ownership. Geometry observers continue running. Expiry or disposal while
  suspended releases the surface normally.
- CSS transforms are measured through `getBoundingClientRect()`. Non-rectangular
  visual transforms are unsupported; the iframe uses the transformed bounding
  box. Browser validation should cover the ordinary non-transformed path.
- Browser zoom and device pixel ratio are accepted as long as the final CSS rect
  matches `getBoundingClientRect()` within 1 CSS pixel.
- `visualViewport.offsetLeft` and `visualViewport.offsetTop` must be considered
  on mobile browsers when fixed-position geometry would otherwise drift.
- Layout shifts while the surface is active must update the anchored rect before
  the next user-visible frame when possible.

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

`iframe_button` release scope:

- `outline_overlay` is the default and the required release path for
  `SeamsAuthMenu`.
- `iframe_button` is internal research scope for this release.
- A future public API revision requires parser tests and Chromium/WebKit browser
  geometry tests proving the padded iframe still places the inner hit target
  over the intended button rect.
- `iframe_button` must not weaken the security boundary: app CSS can style
  wallet-origin visuals through typed CSS declarations, but cannot affect
  positioning, pointer routing, stacking, transforms, URLs, or animation.

## Accessibility Contract

The visible app outline is the app-facing focus proxy while the activation
surface is mounted. The iframe button is the real activation control.

Screen reader and keyboard model:

- The app outline is an accessible focus proxy for visual placement and tab
  order.
- The wallet-origin iframe button is the only element that may start
  registration.
- The mounted activation surface should expose one logical control to users:
  focus moves from the app outline to the iframe button immediately, and the
  iframe button owns the accessible button semantics during activation.
- The app outline may have `role="button"`, `tabindex="0"`, and
  `aria-label={accessibleLabel}` as a focus waypoint. Its visible text
  descendants should be `aria-hidden="true"` while the iframe activation surface
  is mounted, so assistive tech does not announce both visible labels as
  unrelated controls.
- If a screen reader announces the app outline before focus forwarding
  completes, the outline's accessible name must match the iframe button's
  `accessibleLabel`.
- The iframe button remains the activation control. App-outline keyboard events
  only forward focus.

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
- Tab and Shift+Tab from the iframe button leave the localized surface in the
  same order the app-domain outline would have used
- app outline gets mirrored focus state for visual styling
- disposing the surface returns the iframe to hidden/inert state
- if activation surface cannot mount, the app must fall back to normal
  registration behavior or show an error state controlled by `SeamsAuthMenu`
- cleanup restores only attributes that the router changed; existing app
  `role`, `tabindex`, `aria-label`, and `aria-describedby` values must be
  preserved and restored exactly
- cleanup removes iframe focusability, hides the iframe, removes mirrored
  outline state attributes, and disconnects focus listeners
- browser accessibility checks should verify one tab stop for the visual CTA in
  the ordinary keyboard path and matching accessible names when focus forwarding
  is observable
- completion, cancellation, failure, and disposal restore focus to the outline
  only when focus was still inside the iframe; an app-selected focus target must
  never be stolen

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
- The iframe button handles Tab and Shift+Tab through a typed focus-exit bridge.
  The parent resolves the next or previous tabbable element relative to the app
  outline at message time and moves focus there. This bridge never dispatches a
  synthetic activation event.
- Focus-entry and focus-exit messages carry the active surface identity and are
  ignored after release.
- The ordinary keyboard acceptance sequence is: Tab reaches the outline, focus
  transfers to the iframe button, one subsequent Enter or Space starts
  registration, and the following Tab continues from the outline's visual
  position.
- router cleanup restores any original `tabindex`, `role`, and ARIA attributes
  it changed on the app outline
- tests cover keyboard registration from the visual CTA position

## Security Contract

The anchored activation surface is the only path that can skip the registration
confirmation modal in wallet iframe mode.

Required guarantees:

- activation prepare strips caller-supplied `walletIframeActivation`
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
- mirrored state messages are accepted only from the established wallet
  `MessagePort` and active `activationId`

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
- detached, undersized, hidden, inert, or effectively transparent target maps to
  `cancelled/target_unavailable`
- ancestor clipping suspends the anchored render mode and is not a cancellation
- `wallet_iframe_surface_busy` keeps the current surface unchanged and reaches
  `SeamsAuthMenu` as a retryable waiting state
- parser rejection maps to `failed` with a stable error message
- WebAuthn errors propagate through the existing registration result/error path
- completion hides the iframe and clears target data attributes
- failure hides the iframe and clears target data attributes

## React Integration Shape

`SeamsAuthMenu` should keep registration lifecycle decisions in the existing
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
implementation should follow the existing `SeamsAuthMenu` controller patterns
instead of adding an ad hoc lifecycle state bag in the view.

## Phased Todo List

### Phase 0: Guardrails And Baseline

- [x] Confirm current failing UX with a browser trace:
      `Create with Passkey` -> iframe confirmation popup -> TouchID.
      If current main no longer reproduces the old popup because this plan is
      partially implemented, attach a saved historical trace/screenshot or mark
      this item superseded by the regression test that proves the popup no
      longer mounts on the activation-button path.
- [x] Add a focused regression test that detects transaction confirmer mounting
      during iframe passkey registration.
- [x] Keep existing tests that prove normal iframe registration is clamped.
- [x] Keep existing tests that prove caller-supplied activation proofs are
      stripped from activation prepare.
- [x] Record every caller of `enqueueWebAuthnPrompt()` and classify whether it
      requires a live user activation.
- [x] Record every registration `create` path through
      `executeWebAuthnWithParentFallbacksSafari()` and the parent bridge.
- [x] Add a source guard that identifies new registration calls to
      `WindowParentDomainWebAuthnClient` or `WALLET_WEBAUTHN_CREATE`.

### Phase 1: Types And Protocol

- [x] Replace `button?: { label?: string; busyLabel?: string }` with required
      `presentation: RegistrationActivationButtonPresentation`.
- [x] Add a tag constant for `seams-passkey-registration-btn`.
- [x] Add the CSS property and declaration types used by `iframe_button`.
- [x] Add `RegistrationActivationButtonInteractionState`.
- [x] Add `PasskeyRegistrationConfirmDisplay`.
- [x] Add or reuse a precise `ConfirmRenderState` branch for passkey
      registration modal rendering.
- [x] Add `PM_REGISTRATION_ACTIVATION_BUTTON_STATE`.
- [x] Add `PM_REGISTRATION_ACTIVATION_FOCUS`.
- [x] Add `PM_REGISTRATION_ACTIVATION_FOCUS_EXIT` with required direction and
      complete surface identity.
- [x] Restrict the public presentation union to `outline_overlay` and move
      `iframe_button` plus its CSS types to internal scope.
- [x] Remove public `iframeButtonStyle`; keep the outline-overlay iframe button
      full-size, transparent, and SDK styled.
- [x] Remove caller-controlled `confirmationConfig` and generic `options` from
      activation prepare; derive the armed no-UI policy inside the wallet iframe.
- [x] Add branded `WebAuthnPromptReservationId` and `WebAuthnPromptOperationId`
      boundary builders.
- [x] Add `WebAuthnPromptCoordinatorState` and
      `ReservedRegistrationWebAuthnPrompt` discriminated types.
- [x] Require a live prompt reservation in
      `PreparedIframePasskeyRegistrationRecord`.
- [x] Add typed `webauthn_prompt_busy`, `webauthn_prompt_reservation_expired`,
      `webauthn_prompt_reservation_mismatch`, and
      `wallet_origin_webauthn_unavailable` failures.
- [x] Add `target_unavailable` to activation cancellation reasons.
- [x] Add type fixtures that reject mixed presentation branches.
- [x] Make activated prepared registration builder-only, bind its reservation
      owner to the same activation identity, and add a type fixture that rejects
      raw activated object literals.
- [x] Delete tests or fixtures that depend on the old optional `button` payload.

### Phase 2: Boundary Parsing

- [x] Add a postMessage boundary parser for
      `PM_REGISTRATION_ACTIVATION_PREPARE`.
- [x] Normalize `label`, `busyLabel`, and `accessibleLabel` to required strings.
- [x] Normalize registration modal display data into
      `PasskeyRegistrationConfirmDisplay`.
- [x] Require `rpId` and `intendedUserName` before rendering the code-only modal.
- [x] Delete public and host parsing for `iframe_button`, `shadowPaddingPx`, and
      wallet-origin visual style declarations.
- [x] Return boundary parse failures before host UI mount.
- [x] Replace obsolete CSS parser tests with boundary tests that reject all
      wallet-origin visual style fields and the internal iframe-button mode.

### Phase 3: Router Geometry And Overlay

- [x] Update `createPasskeyRegistrationActivationSurface(...).mount(target)` to
      store the target element.
- [x] Make public activation-surface mounting single-use across concurrent mount
      calls so only one router surface and listener can be created.
- [x] Measure the target with `getBoundingClientRect()`.
- [x] Use `OverlayController.showAnchored(rect)` instead of fullscreen for
      `outline_overlay`.
- [x] Add a geometry observer that updates anchored rect on resize, scroll, and
      visual viewport changes.
- [x] Track every scrollable ancestor of the target.
- [x] Add a short `requestAnimationFrame` alignment loop while active for moving
      targets that observer/listener coverage misses.
- [x] Cancel with `target_unavailable` when the target detaches or becomes
      zero-size.
- [x] Enforce the public `44x44` CSS-pixel minimum and effective opacity `0.1`
      threshold across the target and its ancestors.
- [x] Suspend iframe rendering while a clipping ancestor partially clips the
      target, and resume only after the complete target border box is visible.
- [x] Cancel targets hidden by display, visibility, content visibility, or inert
      ancestry.
- [x] Set `data-seams-registration-button-active="true"` on the target while the
      activation surface is mounted.
- [x] Apply mirrored button interaction attributes to the target element.
- [x] Validate mirrored-state messages through the established wallet iframe
      `MessagePort` and matching `activationId`.
- [x] Clear target data attributes on completion, cancellation, failure, and
      dispose.
- [x] Clear `data-seams-registration-button-active` on completion, cancellation,
      failure, and dispose.
- [x] Keep the existing hidden iframe state after release.

### Phase 4: Wallet Iframe Host Rendering

- [x] Add the
      `lit-components/passkey-registration-btn/` component subtree.
- [x] Add the `seams-passkey-registration-btn` entrypoint.
- [x] Register the entrypoint in the SDK build if explicit Lit asset
      registration is required.
- [x] Define the wallet-origin custom element before mounting activation UI.
- [x] Keep dynamic import and element definition before the iframe reports
      `PM_REGISTRATION_ACTIVATION_READY`.
- [x] Send `PM_REGISTRATION_ACTIVATION_READY` only after the element is defined,
      connected, and focusable.
- [x] Keep the prepared registration in wallet-iframe state and remove it from
      the `PM_REGISTRATION_ACTIVATION_READY` wire payload.
- [x] Gate `READY` on both activation-element readiness and complete internal
      registration preparation.
- [x] Gate `READY` on external activation stylesheet loading and the element's
      first render without inline layout styles.
- [x] Recheck registration cancellation after asynchronous element definition,
      stylesheet loading, and element readiness before publishing `READY`.
- [x] Reserve the WebAuthn prompt coordinator before `READY`; keep the activation
      button disabled while preparation is waiting for the coordinator.
- [x] Bind the reservation owner to `surfaceId`, `requestId`, and `activationId`.
- [x] Release the reservation on expiry, cancellation, disposal, render failure,
      preparation failure, and surface replacement.
- [x] Replace fullscreen `renderRegistrationActivationButton` panel rendering
      for `outline_overlay`.
- [x] Render `<seams-passkey-registration-btn>` instead of inline panel DOM.
- [x] Have the component render only a full-size transparent wallet-origin
      `<button>`.
- [x] Set `aria-label` from `accessibleLabel`.
- [x] Set the initial text content to the label for assistive tech fallback,
      while visual text remains transparent.
- [x] Disable the button on first activation.
- [x] Update text content to `busyLabel` after start.
- [x] Emit mirrored interaction-state messages for hovered, focused, pressed,
      busy, and disabled.
- [x] Handle `PM_REGISTRATION_ACTIVATION_FOCUS` by focusing the internal iframe
      button for the matching `activationId`.
- [x] Handle Tab and Shift+Tab through the typed focus-exit bridge and preserve
      the app outline's forward and reverse tab order.
- [x] Mirror pointerenter, pointerleave, pointerdown, pointerup, pointercancel,
      dragstart, dragend, focus, blur, and keyboard Space/Enter press/release into
      parent state.
- [x] Call `setPointerCapture(event.pointerId)` on pointerdown when available.
- [x] Keep the component independent from `seams-tx-confirmer`, tx-confirm state,
      export-key UI, and modal/drawer containers.
- [x] Preserve iframe-minted `walletIframeActivation`.
- [x] Preserve duplicate-click protection.
- [x] Preserve expiry cancellation.

### Phase 5: Code-Only Registration Modal

- [x] Build `PasskeyRegistrationConfirmDisplay` during registration
      confirmation setup.
- [x] Populate `rpId` from the same runtime value used for WebAuthn.
- [x] Populate `intendedUserName`, defaulting to the account id when no narrower
      display name exists.
- [x] Add a registration-specific modal render branch.
- [x] Remove empty transaction-tree space from the registration modal.
- [x] Add visible detail rows for `Account` and `Relying party`.
- [x] Keep signer slot in debug/development details only unless product UI needs
      it.
- [x] Update modal copy to registration-specific language.
- [x] Use existing modal theme tokens, spacing, radius, passkey/fingerprint
      visual treatment, and light/dark behavior.
- [x] Show a busy state after confirm while WebAuthn is being requested.
- [x] Keep the code-only modal confirm click as the wallet-origin user
      activation source.
- [x] Keep typed title/body overrides isolated at the request boundary.
- [x] Ensure no app-provided HTML, callbacks, or scriptable templates enter the
      modal.
- [x] If WebAuthn user display names are supported separately from the stable
      user handle, pass `intendedUserName` to `navigator.credentials.create` as
      `user.name` / `displayName`.
- [ ] Resolve server-allocated wallet identity before constructing renderable
      prepared modal state; bind `display.accountId` to the resolved identity.
- [x] Reserve the WebAuthn prompt coordinator before enabling the code-only modal
      confirm button.
- [x] Release the modal reservation on cancel, expiry, unmount, replacement, and
      preparation failure.

### Phase 6: Registration Flow

- [x] Ensure click-started registration passes:
      `{ uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 }`.
- [x] Ensure no dynamic import, element definition, UI mount, app-domain round
      trip, or timer happens after click and before WebAuthn creation.
- [x] Ensure `walletIframeActivation` is included only in the iframe-started
      registration path.
- [x] Ensure `determineConfirmationConfig` accepts the iframe proof and skips
      modal UI.
- [x] Ensure plain `registerPasskey` from app-domain code still shows the
      improved wallet-origin registration modal.
- [x] Add `continuePreparedIframePasskeyRegistration()` with the activated,
      single-use prepared state as its only input.
- [x] Ensure the continuation calls `navigator.credentials.create()` before its
      first `await`.
- [x] Ensure WebAuthn is called in the same iframe activation chain as the
      button click.
- [x] Replace the promise-tail `webAuthnPromptQueue` with the explicit
      `idle`/`reserved`/`running` coordinator.
- [x] Make reservation consumption and the transition to `running` atomic and
      single-use.
- [x] Start the reserved registration operation inline; remove `.then()` or
      microtask dispatch between the trusted click and
      `navigator.credentials.create()`.
- [x] Route every gesture-bound WebAuthn operation through the coordinator and
      delete the old queue implementation.
- [x] Add a registration-specific wallet-origin execution policy that disables
      `WindowParentDomainWebAuthnClient` and `WALLET_WEBAUTHN_CREATE` for
      `navigator.credentials.create()`.
- [x] Map Safari ancestor-origin and unrecoverable focus failures to
      `wallet_origin_webauthn_unavailable` without invoking the parent bridge.
- [x] Keep registration RP ID validation tied to the wallet iframe runtime before
      native credential creation.

### Phase 7: SeamsAuthMenu Integration

- [x] Add a top-level helper for mounting the registration activation surface.
- [x] Render an outline slot in register mode when wallet iframe mode is active.
- [x] Keep the existing app-domain button path for non-iframe runtime.
- [x] Wire surface state into existing controller waiting/error state.
- [x] Dispose the surface on mode change, account id change, route unmount, and
      provider teardown.
- [x] Add CSS state selectors for the outline data attributes.
- [x] Style hover, pressed, focused, busy, and disabled via mirrored
      attributes so `.seams-passkey-registration-btn` behaves like a normal
      button-like element.
- [x] Add the app-outline focus proxy and restore original focus-related
      attributes on cleanup.
- [x] Send `PM_REGISTRATION_ACTIVATION_FOCUS` when the outline receives focus.
- [x] Ensure app-outline Enter/Space focuses the iframe button and does not
      start registration from app-origin key events.
- [x] Keep app-domain visual styles in `SeamsAuthMenu.css`.
- [x] Ensure the outline has stable dimensions before the iframe mounts.

### Phase 8: Tests

- [x] Unit: `determineConfirmationConfig` still clamps iframe registration
      without `walletIframeActivation`.
- [x] Unit: `determineConfirmationConfig` skips only with iframe activation
      proof.
- [x] Unit: activation prepare injects iframe-owned activation proofs.
- [x] Unit: activation button mints the proof and uses `skipClick`.
- [x] Unit: duplicate click starts registration once.
- [x] Unit: expiry rejects before WebAuthn.
- [x] Unit: dispose cancels pending activation.
- [x] Unit: disposal after activation aborts the started WebAuthn/registration
      operation and removes the wallet-origin button immediately.
- [x] Unit/browser: a ready anchored activation owns an overlay lease; unrelated
      fullscreen work returns `wallet_iframe_surface_busy`, and existing visible
      surfaces prevent lease acquisition.
- [x] Unit: CSS parser allowlist and reject list.
- [x] Type fixture: invalid presentation unions are rejected.
- [x] Type fixture: activation prepare cannot omit `wallet`, `surfaceId`,
      `requestId`, or `activationId`.
- [x] Unit/browser: stale messages with wrong `surfaceId`, `requestId`, or
      `activationId` cannot mutate app outline state.
- [x] Unit: prepared registration expires before WebAuthn when `expiresAtMs`
      passes before activation.
- [ ] Type fixture: the continuation rejects preparing, ready, expired, reused,
      and raw registration inputs.
- [x] Unit: `PM_REGISTRATION_ACTIVATION_READY` contains identity and expiry only;
      prepared challenge and digest state remain wallet-iframe internal.
- [x] Type fixture: activation prepare rejects confirmation-policy and generic
      options bags.
- [ ] Unit: code-only prepared modal state cannot contain unresolved server
      allocation.
- [ ] Type fixture: a ready prepared record cannot omit its prompt reservation.
- [ ] Type fixture: activation prepared records reject modal and generic wallet
      request reservation owners.
- [x] Type fixture: coordinator state rejects mixed idle, reserved, and running
      fields.
- [x] Unit: coordinator transitions `idle -> reserved -> running -> idle` for one
      successful registration.
- [x] Unit: reservation owner mismatch, expiry, and reuse reject before WebAuthn;
      double release is a deterministic no-op.
- [ ] Unit: cancellation, disposal, replacement, preparation failure, and
      synchronous credential-creation failure each release exactly once.
- [x] Unit: a second WebAuthn operation cannot start while registration owns the
      reservation.
- [ ] Unit: a busy coordinator delays `READY`; the click path never waits for
      coordinator availability.
- [x] Unit: reserved registration invokes the credential-create function inline
      before returning its running promise.
- [x] Source guard: no promise `.then()` dispatch remains between reserved click
      handling and `navigator.credentials.create()`.
- [x] Unit: registration `create` never invokes
      `WindowParentDomainWebAuthnClient`, including ancestor-origin and focus
      error branches.
- [x] Unit: Safari registration errors map to
      `wallet_origin_webauthn_unavailable`, release the reservation, and do not
      emit `WALLET_WEBAUTHN_CREATE`.
- [ ] Unit: registration rejects a native credential attempt whose RP ID differs
      from the wallet iframe RP ID.
- [x] Regression: authentication `get` fallback behavior remains covered
      separately and is unchanged by the registration policy.
- [x] Unit or component: `seams-passkey-registration-btn` emits activation
      intent once and mirrors hover/focus/pressed/busy/disabled state.
- [x] Unit or component: pointer cancel, drag end, blur, and keyboard release
      return the mirrored state to the correct non-pressed state.
- [x] Unit or component: pointerdown captures the pointer when
      `setPointerCapture` is available.
- [x] Source guard: `seams-passkey-registration-btn` does not import
      tx-confirm, export-key UI, modal/drawer containers, or React wrappers.
- [x] Unit/integration: router ignores activation state messages that do not
      arrive through the established `MessagePort` for the active `activationId`.
- [x] Unit/component: code-only registration modal renders account/intended user
      name and rpID from `PasskeyRegistrationConfirmDisplay`.
- [x] Unit/component: registration modal does not render an empty transaction
      tree.
- [x] Unit/component: registration modal busy state appears after confirm.
- [x] Unit: rpID displayed in the modal matches the rpID passed to WebAuthn.
- [x] Browser: iframe rect equals target rect within 1 CSS pixel.
- [x] Browser: `Create with Passkey` opens WebAuthn without mounting
      a transaction confirmer element.
- [x] Browser: code-only registration opens the improved wallet-origin modal,
      displays intended user name and rpID, then opens WebAuthn after confirm.
- [x] Browser: app-domain `box-shadow` remains visible outside iframe boundary.
- [x] Browser: keyboard focus and Enter start registration.
- [x] Browser: app-domain outline styling changes for hovered, pressed,
      focused, busy, and disabled mirrored states.
- [x] Browser: unmount removes iframe hit target and target data attributes.
- [x] Browser: target resize, document scroll, scrollable ancestor movement, and
      visual viewport changes keep iframe aligned.
- [ ] Browser: `navigator.credentials.create()` is requested from the iframe
      click activation chain in Chromium.
- [ ] Browser: the coordinator is reserved before `READY`, and the Chromium
      iframe click calls `navigator.credentials.create()` before the next
      microtask checkpoint.
- [ ] Browser: WebKit/Safari native registration either starts from the iframe
      click with the wallet RP ID or returns
      `wallet_origin_webauthn_unavailable` without a parent bridge request.
- [ ] Browser: no registration run creates an app-origin credential or emits
      `WALLET_WEBAUTHN_CREATE`.
- [ ] Browser: claim Safari one-click support only for versions where the native
      wallet-origin success branch passes.
- [x] Browser: hidden, detached, undersized, visibility-hidden, inert, and
      low-opacity targets cancel without leaving an iframe hit target.
- [x] Browser: clipping ancestors suspend the iframe hit target and restore it
      only when the complete CTA border box is visible.
- [ ] Browser accessibility: the visual CTA presents one ordinary keyboard focus
      path, forwards focus to the iframe button, preserves Tab and Shift+Tab
      egress, and uses matching accessible names.

Browser validation matrix:

- Run at least Chromium desktop for release gating.
- Add WebKit/Safari coverage before claiming mobile Safari support for the
  one-click path.
- Treat native wallet-origin credential creation as the Safari success criterion.
  Parent-domain bridge success does not satisfy this plan.
- Release gating must include at least one browser test hook or instrumented
  `navigator.credentials.create()` wrapper that proves credential creation is
  requested before transient activation is lost.
- Use a virtual authenticator or a WebAuthn test hook that can distinguish:
  - app-domain click opened code-only modal
  - iframe modal confirm opened WebAuthn
  - iframe activation button opened WebAuthn without mounting modal/tx UI
- For geometry assertions, compare:
  - `target.getBoundingClientRect()`
  - iframe `getBoundingClientRect()`
  - inner button `getBoundingClientRect()` in iframe coordinates
    The outline-overlay iframe rect must match the target rect within 1 CSS pixel
    for top, left, width, and height.
- For transaction-confirm absence, assert that no `seams-tx-confirmer`,
  tx-confirm modal/drawer wrapper, transaction tree, or generic transaction
  confirmation portal mounts during activation-button registration.
- For code-only modal, assert the wallet-origin modal contains the intended user
  name and rpID before the confirm click, and that WebAuthn starts only after
  the iframe confirm button click.
- For mirrored styling, assert attributes, not CSS implementation details:
  hovered, pressed, focused, busy, disabled, and active must appear and clear on
  the app-domain outline at the specified transitions.
- For cleanup, assert unmount/dispose removes the iframe hit target from the CTA
  rect, clears outline attributes, and restores original `role`, `tabindex`, and
  ARIA attributes.
- For alignment, test document scroll, nested scrollable ancestor movement,
  target resize, and visual viewport resize/scroll where the browser exposes
  `window.visualViewport`.

### Phase 9: Cleanup And Documentation

- [x] Delete the old fullscreen registration activation panel path used by the
      activation-surface flow.
      Target cleanup: remove the activation-surface-only fullscreen panel
      renderer in `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts`
      after browser tests prove `outline_overlay` is the only activation-surface
      path. Keep the code-only wallet-origin registration modal.
- [x] Delete old optional `button` payload compatibility.
- [x] Update README or SDK docs for `SeamsAuthMenu` one-click registration.
      Required docs snippet:

      ```tsx
      <SeamsAuthMenu />
      ```

      Explain that in wallet-iframe mode the built-in `Create with Passkey`
      CTA uses `seams-passkey-registration-btn` automatically, so one click can
      open the passkey prompt without an intermediate registration modal.

      Direct API calls remain supported:

      ```tsx
      <button onClick={() => void seams.registration.registerPasskey()}>
        Create with Passkey
      </button>
      ```

      Explain that direct app-domain registration calls intentionally show the
      wallet-origin modal so the user can click inside the iframe before
      TouchID/passkey creation.

- [x] Document the code-only registration modal path.
- [x] Document the `seams-passkey-registration-btn` modal-skipping path.
- [x] Add `lit-components/passkey-registration-btn/README.md`.
- [x] Update `docs/refactor-8X-lit.md` relationship notes if that plan's target
      directory structure changes first.
- [x] Document that React components do not cross the iframe boundary.
- [x] Document `outline_overlay` as the default styling model.
- [x] Remove `iframe_button` from public docs and exports. Any future internal
      research must introduce a new parsed contract.
- [x] Document that activation surfaces become `ready` only after they own a
      WebAuthn prompt reservation and may remain in preparation while another
      prompt is active.
- [ ] Document the Safari support matrix from real browser evidence.
- [x] Document `wallet_origin_webauthn_unavailable` and state that registration
      never falls back to app-origin credential creation.
- [x] Remove or correct fallback documentation that presents parent-domain
      registration as compatible with wallet-origin passkeys.
- [x] Run the cheapest focused validation covering wallet iframe registration,
      SDK type checking, and bundle entry emission.

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
- The wallet iframe retains prepared challenge, intent, confirmation, and warmup
  state; `READY` exposes only correlation identity and expiry.
- The trusted click consumes prepared state and enters the narrow continuation;
  the general `registerPasskey()` setup path does not run after activation.
- `READY` requires a live, identity-bound WebAuthn prompt reservation.
- The trusted click consumes that reservation once and invokes
  `navigator.credentials.create()` inline before any promise-tail dispatch.
- Every terminal path releases the prompt coordinator exactly once.
- Registration never delegates `navigator.credentials.create()` to the
  app-origin parent or creates an app-origin passkey.
- Safari one-click support is enabled only where native wallet-origin iframe
  registration passes the browser gate; unsupported versions return the typed
  wallet-origin-unavailable failure.
- Public activation surfaces expose only `outline_overlay` and enforce the
  `44x44` CSS-pixel size, visibility, opacity, inert, and clipping contracts.
- Forward and reverse keyboard navigation leave the iframe at the app outline's
  visual tab position.
