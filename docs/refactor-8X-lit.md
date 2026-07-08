# Refactor 8X: Lit Component Rewrite, Public Composition, And Bundle Size

Date created: June 10, 2026

Status: implementation-ready plan

Owner: SDK UI, wallet iframe, and browser asset graph

## Goal

Make the SDK Lit component surface safer, easier to evolve, and smaller on the
wire.

This refactor focuses on the transaction confirmer, key export viewer, shared
Lit base utilities, React wrappers around custom elements, and the SDK browser
asset build for those components.

This is a replacement-style rewrite. Build the new final module layout and
typed contracts first, cut each public surface over once, then delete the old
implementation for that surface in the same phase. Temporary duplicate code is
allowed only inside an active phase. Do not leave a long-lived legacy path,
compatibility branch, or `v2` layer.

The target state:

1. Secret-bearing iframe messages use a narrow, typed, origin-checked boundary.
2. Confirmation UI state is represented by discriminated unions with required
   branch fields.
3. Transaction display models and tree nodes reject invalid combinations at
   compile time.
4. Modal and drawer variants share domain/rendering logic while keeping their
   container-specific behavior local.
5. Detached components release global listeners, timers, and observers.
6. Production SDK Lit assets are built with production defines, measured by
   budgets, and split where splitting creates real load-time wins.
7. React wrappers expose the actual custom-element event contract with minimal
   runtime dependency weight.
8. The architecture keeps shared primitives, containers, state, and entrypoints
   separated so future public checkout UI composition is straightforward.

## Non-Goals

- Redesign the visual UI.
- Change transaction-confirmation business behavior.
- Add compatibility shims for older optional-bag confirm states.
- Preserve deprecated public props after their replacements land.
- Move wallet-origin secret ownership into the app origin.
- Replace Lit with React or another component runtime.
- Allow arbitrary app-origin JavaScript or HTML to run inside wallet-origin
  final confirmation or private-key export surfaces.

## Relationship To Existing Plans

- `docs/refactor-44-bundle-size-optimization.md` owns the wallet iframe boot and
  runtime split. This plan owns the Lit-specific asset graph, production defines,
  and size budgets.
- `docs/refactor-56-react-components.md` owns React auth flow simplification.
  This plan owns React wrappers around Lit custom elements and their dependency
  footprint.
- `docs/refactor-8X-iframe-registration-button.md` owns the wallet-origin
  `seams-passkey-registration-btn` activation component and the app-domain
  `.seams-passkey-registration-btn` wrapper. That component intentionally lives
  under `lit-components/passkey-registration-btn`, but it stays independent from
  the transaction confirmer, export-key, modal, and drawer graphs.
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/README-lit-elements.md`
  should be updated after the component entrypoints and shared modules settle.

## Current Read

High-risk areas identified in the Lit component review:

- `ExportPrivateKey/iframe-host.ts` posts secret-bearing messages with wildcard
  target origin and accepts parent-window messages without checking source.
- `ExportPrivateKey/iframe-export-bootstrap-script.ts` accepts broad messages in
  the child frame and posts back through a permissive target-origin path.
- `confirm-ui-types.ts`, `confirm-ui.ts`, and
  `IframeTxConfirmer/tx-confirmer-wrapper.ts` carry optional identity, model,
  auth, and security fields deep into rendering.
- `interfaces/display.ts` models every chain with one loose `TxDisplayModel`.
- `TxTree/tx-tree-utils.ts` and `TxTree/index.ts` use casts where tree/action
  type boundaries should carry the rendering contract.
- `IframeTxConfirmer/viewer-modal.ts` and `viewer-drawer.ts` duplicate OTP,
  security, heading, chain-label, and layout behavior.
- `Drawer/index.ts` registers a bound resize listener that cannot be removed.
- `TxTree/index.ts` starts timers and does not centralize cleanup.
- `sdk/scripts/build/build-prod.sh` passes production settings to the Rolldown
  phase, then runs direct Bun Lit asset builds without explicit production
  defines.
- Existing bundle reports do not budget the Lit JS/CSS entries.
- React Lit wrappers use `@lit/react` for a small wrapper surface and one wrapper
  maps events that do not match the drawer event contract.
- Appearance propagation has crossed multiple layers as theme-name setters,
  config-shaped updates, root document attributes, component attributes, and
  iframe bootstrap messages. The durable contract should be one normalized
  appearance state that fans out only at runtime/document boundaries.

## Design Rules

1. Parse raw request, route, iframe, DOM, and persistence shapes once at the
   boundary.
2. Core render functions receive precise state. They should not accept partial
   external shapes.
3. Required identity, auth, session, signing, and security fields stay required
   inside the SDK.
4. Use discriminated unions, branch-specific builders, `never` fields, and
   exhaustive `switch` statements for lifecycle and display state.
5. Add type fixtures for invalid object-literal construction, broad spreads,
   unsafe casts, and invalid branch combinations whenever shared state types
   change.
6. Keep compatibility parsing only at request and persistence boundaries.
7. Delete obsolete tests, fixtures, and guards that encode the old optional-bag
   behavior after the replacement state is in place.
8. Treat appearance as a domain state object. Normalize raw config, React props,
   RPC payloads, and iframe bootstrap data into a single internal
   `AppearanceState` before touching Lit elements or documents.

## Rewrite Strategy

Implement this as a clean replacement, not as incremental surgery on the old
component graph.

Order of work:

1. Create the new final module layout under `lit-components/`.
2. Define the new internal contracts first:
   - `ConfirmRenderState`
   - chain-specific `TxDisplayModel`
   - typed `TreeNode`
   - export-key iframe message unions
   - future-ready composition boundaries
3. Rebuild the smallest public primitives first:
   - drawer
   - halo border
   - passkey loading
   - transaction tree
4. Rebuild confirmer containers on top of shared components and controllers.
5. Rebuild export-key iframe messaging with the secure protocol.
6. Point existing public tags and SDK entrypoints at the new modules.
7. Delete the old `IframeTxConfirmer`, old `TxTree` state shape, old optional
   confirm update paths, and obsolete tests in the same phase that cuts over the
   replacement.
8. Add public subpath exports and size budgets after the new entrypoint graph
   exists.

Rules for the rewrite:

- Do not create a persistent `v2` namespace.
- Do not keep old and new confirmers available as runtime mode choices.
- Do not keep deprecated props after the new public contract is wired.
- Do not copy the old implementation into a checked-in `legacy/` or
  `reference/` folder. Use git history, temporary local branches, screenshots,
  size baselines, and behavior fixtures to compare old behavior.
- Keep request-boundary normalization if existing app calls still enter through
  `mountConfirmUI()` or `awaitConfirmUIDecision()`.
- Internal components receive only new precise state types.
- Avoid editing `crates/ed25519-hss/**` during this work because concurrent
  coding is expected there.

## Target Directory Structure

The new directory layout should mirror public entrypoints, internal contracts,
and bundle boundaries:

```text
lit-components/
  base/
    LitElementWithProps.ts
    asset-base.ts
    css-loader.ts
    define-element.ts
    events.ts

  registry/
    tags.ts
    loaders.ts

  primitives/
    drawer/
      drawer-element.ts
      drawer-controller.ts
      index.ts
    halo-border/
      halo-border-element.ts
      index.ts
    passkey-halo-loading/
      passkey-halo-loading-element.ts
      index.ts
    padlock-icon/
      padlock-icon-element.ts

  tx-confirm/
    entrypoints/
      w3a-tx-confirmer.ts
      w3a-modal-tx-confirmer.ts
      w3a-drawer-tx-confirmer.ts
      tx-confirm-ui.ts

    state/
      confirm-render-state.ts
      confirm-render-builders.ts
      confirm-render-parser.ts
      assert-never.ts

    display/
      tx-display-model.ts
      normalize-display-model.ts
      operation-types.ts

    components/
      tx-confirm-content.ts
      confirm-shell.ts
      confirm-header.ts
      security-details.ts
      email-otp-panel.ts
      passkey-prompt.ts
      confirm-actions.ts

    containers/
      modal-tx-confirmer.ts
      drawer-tx-confirmer.ts
      tx-confirmer-wrapper.ts

    controllers/
      email-otp-confirm-controller.ts
      lifecycle-timers.ts

    tree/
      tx-tree-element.ts
      tree-node-types.ts
      tree-builders.ts
      renderers/
        near.ts
        evm.ts
        tempo.ts
        fallback.ts

    abi/
      tx-confirm-abi-entry.ts
      enrich-display-model-with-abi.ts
      abi-decode.ts

  export-key/
    entrypoints/
      export-private-key-viewer.ts
      export-key-iframe-host.ts
      iframe-export-bootstrap.ts
    protocol/
      export-key-messages.ts
      export-key-message-parser.ts
      export-key-channel.ts
    components/
      export-key-viewer.ts
      export-key-iframe-host-element.ts

  styles/
    appearance-state.ts
    appearance-parser.ts
    apply-appearance.ts
    tx-confirmer.css
    tx-tree.css
    drawer.css
    export-viewer.css
    export-iframe.css
    halo-border.css
    passkey-halo-loading.css
```

Directory ownership:

1. `entrypoints/` files are the only modules that should become stable SDK JS
   assets.
2. `state/` and `display/` own type correctness and boundary normalization.
3. `components/` expose public composable pieces where their props are stable.
4. `containers/` own modal and drawer mechanics.
5. `abi/` stays isolated so ABI decoding can be a lazy chunk.
6. `export-key/protocol/` owns all cross-frame message parsing and validation.

## Future UI Composition Direction

This refactor should organize the Lit architecture so public checkout and
payment-review composition can be added later without another rewrite. It does
not ship ecommerce checkout components or a headless public confirmation API.

The future SDK surface should support three customization layers.

### Theme-Only Customization

This layer is safe for direct browser and wallet iframe modes.

Future theme customization can expose:

- light and dark themes
- token overrides
- component CSS variables
- density, radius, typography, and spacing tokens
- merchant name, logo URL, and safe display copy
- order/payment labels that become typed display data

Theme-only customization is the default for wallet-origin final confirmation.
It lets merchants match checkout branding while preserving wallet-origin control
over the final signing decision.

### Future Public Composable Components

Keep the module layout ready for stable component subpaths so SDK users can
eventually build checkout and payment review UIs without pulling the full
confirmer:

```ts
import '@seams/sdk/ui/tx-tree';
import '@seams/sdk/ui/drawer';
import '@seams/sdk/ui/halo-border';
import '@seams/sdk/ui/confirm-shell';
import type { TxDisplayModel } from '@seams/sdk/ui/types';
```

Candidate public elements:

```text
<w3a-confirm-shell>
<w3a-confirm-header>
<w3a-security-details>
<w3a-email-otp-panel>
<w3a-passkey-prompt>
<w3a-tx-tree>
<w3a-confirm-actions>
<w3a-drawer>
<w3a-halo-border>
```

The first rewrite should keep these components internally composable, with
typed props and clean entrypoint boundaries. It should avoid publishing public
checkout-specific components.

### Future Headless Confirmation API

Keep state and controller ownership compatible with a future headless API for
direct-browser integrations and app-owned preview flows:

```ts
const session = await seams.ui.createConfirmationSession({
  request,
  mode: 'headless',
});

session.subscribe((state) => {
  // App renders React, Lit, Vue, or custom UI from typed state.
});

await session.confirm();
await session.cancel();
```

The session state should be a discriminated union:

```ts
type ConfirmSessionState =
  | {
      kind: 'review';
      model: TxDisplayModel;
      security: SecurityContext;
    }
  | {
      kind: 'email_otp';
      prompt: EmailOtpPrompt;
      model: TxDisplayModel;
      security: SecurityContext;
    }
  | {
      kind: 'passkey';
      model: TxDisplayModel;
      security: SecurityContext;
    }
  | { kind: 'signing' }
  | { kind: 'complete'; result: SignedResult }
  | { kind: 'failed'; error: ConfirmUiError };
```

Mode boundaries:

1. Direct browser mode can support full app-owned confirmation UI through the
   future headless session API.
2. Wallet iframe mode can support app-owned preview UI plus wallet-origin final
   confirmation rendered from typed customization data.
3. Private-key export supports theme and copy customization only.
4. App-provided render callbacks, HTML strings, and scriptable templates do not
   cross into wallet-origin confirmation or export-key iframes.

## Phase 0: Baseline, Rewrite Scaffold, And Guardrails

Capture the current behavior and size baseline, then create the new final module
layout before changing behavior.

Implementation tasks:

1. [ ] Record current production Lit asset sizes after `pnpm -C sdk build:prod`:
   - `sdk/dist/esm/sdk/w3a-tx-confirmer.js`
   - `sdk/dist/esm/sdk/tx-confirm-ui.js`
   - `sdk/dist/esm/sdk/export-private-key-viewer.js`
   - `sdk/dist/esm/sdk/iframe-export-bootstrap.js`
   - `sdk/dist/esm/sdk/halo-border.js`
   - `sdk/dist/esm/sdk/passkey-halo-loading.js`
   - Lit CSS assets under `sdk/dist/esm/sdk/*.css`
2. [ ] Add a temporary notes section to this document with the measured raw,
   gzip, and brotli sizes.
3. [ ] Inventory current Lit custom-element definitions from
   `client/src/core/signingEngine/uiConfirm/ui/registry.ts` and
   `client/src/core/signingEngine/uiConfirm/ui/lit-components`.
4. [ ] Create the new final directory scaffold under
   `client/src/core/signingEngine/uiConfirm/ui/lit-components/`:
   - `base/`
   - `registry/`
   - `primitives/`
   - `tx-confirm/`
   - `export-key/`
   - `styles/`
5. [ ] Move or re-export only stable helpers into the scaffold at first:
   - asset-base resolution
   - CSS loading
   - custom-element definition helpers
   - shared event helpers
6. [ ] Add type-only placeholder modules for the new contracts so follow-up
   phases can compile against final paths:
   - `tx-confirm/state/confirm-render-state.ts`
   - `tx-confirm/display/tx-display-model.ts`
   - `tx-confirm/tree/tree-node-types.ts`
   - `export-key/protocol/export-key-messages.ts`
7. [ ] Add or update source guards that fail on:
   - `@lit/*/development` in production SDK browser outputs
   - wildcard target origin on secret-bearing export-key iframe messages
   - `as unknown as` in Lit tree renderers after Phase 3 lands
8. [ ] Add a test/type-fixture location for Lit compile-time contracts, for
   example `tests/types/lit-components/*.test-d.ts` or the repo's existing type
   fixture convention if one exists.
9. [ ] Add a temporary migration map in this document that lists each old module
   and its final replacement path. Delete that map when the rewrite completes.

Acceptance criteria:

1. [ ] Baseline size numbers are committed in this document.
2. [ ] The new scaffold compiles without changing runtime behavior.
3. [ ] The guardrail tests fail on the known bad patterns before later phases
   update the implementation.
4. [ ] The validation command list at the end of this document matches the
   existing package scripts.

## Initial Replacement Map

Use this map during the rewrite, then delete it when the old modules are gone.
The old code remains available through git history and temporary local branches.

| Old path | Replacement path |
| --- | --- |
| `lit-components/LitElementWithProps.ts` | `lit-components/base/LitElementWithProps.ts` |
| `lit-components/asset-base.ts` | `lit-components/base/asset-base.ts` |
| `lit-components/css/css-loader.ts` | `lit-components/base/css-loader.ts` |
| `ui/registry.ts` | `lit-components/registry/tags.ts` and `lit-components/registry/loaders.ts` |
| `lit-components/Drawer/index.ts` | `lit-components/primitives/drawer/drawer-element.ts` |
| `lit-components/HaloBorder/index.ts` | `lit-components/primitives/halo-border/halo-border-element.ts` |
| `lit-components/PasskeyHaloLoading/index.ts` | `lit-components/primitives/passkey-halo-loading/passkey-halo-loading-element.ts` |
| `lit-components/common/PadlockIcon.ts` | `lit-components/primitives/padlock-icon/padlock-icon-element.ts` |
| `lit-components/TxTree/index.ts` | `lit-components/tx-confirm/tree/tx-tree-element.ts` |
| `lit-components/TxTree/tx-tree-utils.ts` | `lit-components/tx-confirm/tree/tree-builders.ts` |
| `lit-components/TxTree/renderers/*` | `lit-components/tx-confirm/tree/renderers/*` |
| `lit-components/TxTree/abi/*` | `lit-components/tx-confirm/abi/*` |
| `lit-components/IframeTxConfirmer/tx-confirm-content.ts` | `lit-components/tx-confirm/components/tx-confirm-content.ts` |
| `lit-components/IframeTxConfirmer/viewer-modal.ts` | `lit-components/tx-confirm/containers/modal-tx-confirmer.ts` |
| `lit-components/IframeTxConfirmer/viewer-drawer.ts` | `lit-components/tx-confirm/containers/drawer-tx-confirmer.ts` |
| `lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts` | `lit-components/tx-confirm/containers/tx-confirmer-wrapper.ts` |
| `lit-components/ExportPrivateKey/iframe-host.ts` | `lit-components/export-key/components/export-key-iframe-host-element.ts` |
| `lit-components/ExportPrivateKey/viewer.ts` | `lit-components/export-key/components/export-key-viewer.ts` |
| `lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts` | `lit-components/export-key/entrypoints/iframe-export-bootstrap.ts` |
| `lit-components/css/*` | `lit-components/styles/*` |

## Phase 0A: Single Appearance Propagation Contract

Theme and token propagation should have one SDK state transition, with small
applicators at each runtime boundary. The SDK still needs separate DOM writes
because React scopes, wallet-host documents, Lit custom elements, and export-key
iframes can live in different documents. Those writes should all consume the
same normalized `AppearanceState`.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/styles/appearance-state.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/styles/appearance-parser.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/styles/apply-appearance.ts`
- `client/src/SeamsWeb/SeamsWeb.ts`
- `client/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`
- `client/src/SeamsWeb/walletIframe/client/router.ts`
- `client/src/SeamsWeb/walletIframe/host/context.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/*`
- React provider/context theme files
- wallet iframe and Lit theme propagation tests

Implementation tasks:

1. [ ] Define a normalized internal state:

```ts
type AppearanceState = {
  kind: 'appearance_state_v1';
  theme: 'light' | 'dark';
  tokens: ThemeTokenOverridesInput;
};
```

2. [ ] Add boundary parsers/builders for:
   - SDK config `ui.appearance`
   - React provider theme props
   - `seams.setAppearance(...)` input
   - wallet iframe `PM_SET_CONFIG` payloads
   - export-key iframe bootstrap messages
3. [ ] Keep `seams.setTheme(theme)` only as a convenience wrapper that builds
   `AppearanceState` through the same parser/builder as `setAppearance`.
4. [ ] Use `PM_SET_CONFIG` with `appearance` for wallet iframe updates. Keep the
   wallet protocol free of a theme-only RPC.
5. [ ] Give `SeamsWeb`, `SeamsWebIframe`, `BrowserSigningSurface`, and the
   wallet host one internal `applyAppearance(state)` entrypoint each.
6. [ ] Store the current appearance state in the signing surface so local key
   export always reads the latest tokens.
7. [ ] Make Lit element `theme` attributes and root `data-w3a-theme` attributes
   derived writes from `AppearanceState`.
8. [ ] Make export-key iframe initial HTML use the current `AppearanceState`
   during first paint, then accept only parsed appearance updates from its
   message protocol.
9. [ ] Delete theme-only host handlers, message types, and tests once the
   appearance route is wired.
10. [ ] Add tests proving:
   - React provider token changes reach `SeamsWeb` and the signing surface
   - `seams.setTheme('light')` uses the same propagation path as
     `seams.setAppearance({ theme: 'light' })`
   - wallet iframe theme/token updates travel through `PM_SET_CONFIG`
   - tx confirmer modal, tx confirmer drawer, and export-key drawer all render
     with the same token overrides
   - token-only updates do not clear the current theme

Acceptance criteria:

1. [ ] `rg "PM_SET_THEME|router\\.setTheme|signingEngine\\.setTheme"` returns
   no production source references.
2. [ ] There is exactly one internal appearance state type used by Lit
   confirmer, export-key, wallet iframe host, and direct-browser signing UI.
3. [ ] Theme-name convenience APIs call the appearance state builder and have no
   separate wallet/DOM propagation logic.
4. [ ] Visual parity tests cover light and dark token overrides for modal and
   drawer surfaces.

## Phase 1: Secure Export-Key Iframe Messaging

Treat private-key display as the highest-risk Lit path. The parent and child
frames need a small typed protocol, strict source checks, and explicit origin
ownership.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-messages.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-message-parser.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-channel.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/components/export-key-iframe-host-element.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/components/export-key-viewer.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/entrypoints/export-key-iframe-host.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/entrypoints/export-private-key-viewer.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/entrypoints/iframe-export-bootstrap.ts`
- `tests/lit-components/*export*` or a new focused Playwright/unit test file

Implementation tasks:

1. [ ] Define parent-to-child and child-to-parent message unions:

```ts
type ExportKeyParentMessage =
  | { type: 'EXPORT_KEY_INIT'; parentOrigin: string }
  | { type: 'EXPORT_KEY_SET_PRIVATE_KEY'; privateKey: string };

type ExportKeyChildMessage =
  | { type: 'EXPORT_KEY_READY' }
  | { type: 'EXPORT_KEY_CONFIRM' }
  | { type: 'EXPORT_KEY_CANCEL' }
  | { type: 'EXPORT_KEY_COPY' };
```

2. [ ] Add boundary parsers that return Result-style unions for raw
   `MessageEvent.data`.
3. [ ] Store the expected child `contentWindow` in the host and require
   `event.source === expectedChildWindow` before handling child messages.
4. [ ] Store the expected parent origin in the child and require
   `event.origin === expectedParentOrigin` before handling parent messages.
5. [ ] Replace wildcard target origin for private-key posts with the known child
   origin. If the frame is `srcdoc` or otherwise opaque, redesign the bootstrap
   so the parent can still use a deterministic safe target for secret-bearing
   posts.
6. [ ] Ensure navigation or replacement of the iframe invalidates the active
   message channel.
7. [ ] Wire existing public export-key tags and SDK bundle names to the new
   entrypoints.
8. [ ] Delete the old `ExportPrivateKey/` implementation after the new
   entrypoints pass the export-key behavior tests.
9. [ ] Add tests proving:
   - wrong source window is ignored
   - wrong origin is ignored
   - malformed messages are ignored or rejected with a typed failure
   - private-key post uses the expected target origin
   - confirm/cancel/copy still work from the valid child

Acceptance criteria:

1. [ ] No secret-bearing `postMessage` call uses `'*'`.
2. [ ] Parent and child message handlers use typed parsers.
3. [ ] Source and origin checks are covered by tests.
4. [ ] Export viewer behavior remains unchanged for valid users.

## Phase 2: Replace Optional Confirm State With Unions

Move the confirmer from partial host props to explicit render states. This is
the main correctness refactor for preventing invalid lifecycle combinations.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/confirm-ui-types.ts`
- `client/src/core/signingEngine/uiConfirm/ui/confirm-ui.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/state/confirm-render-state.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/state/confirm-render-builders.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/state/confirm-render-parser.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/entrypoints/tx-confirm-ui.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/entrypoints/w3a-tx-confirmer.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/tx-confirmer-wrapper.ts`
- `tests/lit-components/confirm-ui.handle.test.ts`
- new Lit type fixtures

Implementation tasks:

1. [ ] Introduce internal render-state unions:

```ts
type ConfirmRenderState =
  | { kind: 'empty' }
  | { kind: 'loading'; title: string }
  | {
      kind: 'passkey_confirm';
      model: ConfirmDisplayModel;
      securityContext: ConfirmSecurityContext;
      prompt: PasskeyConfirmPrompt;
    }
  | {
      kind: 'email_otp_confirm';
      model: ConfirmDisplayModel;
      securityContext: ConfirmSecurityContext;
      prompt: EmailOtpConfirmPrompt;
    }
  | { kind: 'error'; error: ConfirmUiError };
```

2. [ ] Add branch-specific builders for host updates:
   - `buildEmptyConfirmState`
   - `buildPasskeyConfirmState`
   - `buildEmailOtpConfirmState`
   - `buildConfirmLoadingState`
   - `buildConfirmErrorState`
3. [ ] Keep raw `ConfirmUIUpdate` parsing at the host boundary only. Convert it
   immediately into `ConfirmRenderState`.
4. [ ] Narrow custom-element properties so modal/drawer/content components
   receive valid branch state rather than many optional fields.
5. [ ] Replace default empty-string identity/auth props with required values in
   the branches that need them.
6. [ ] Remove casts such as `props as ConfirmUIInternalUpdate` by routing
   through a parser or builder.
7. [ ] Replace boolean-mode checks with exhaustive switches on `state.kind`.
8. [ ] Add `assertNever` coverage for all render-state switches.
9. [ ] Update tests that used `as any` setup objects to construct valid branch
   states through builders.
10. [ ] Delete test fixtures that exist only for the old optional-bag behavior.
11. [ ] Delete old optional-bag internal paths after public boundary parsing is
   routed through `ConfirmRenderState`.

Acceptance criteria:

1. [ ] Core confirmer rendering cannot be called with missing model/security
   state for active transaction confirmation.
2. [ ] Email OTP branches cannot exist without an OTP prompt/challenge.
3. [ ] Passkey branches cannot carry Email OTP-only fields.
4. [ ] Type fixtures reject invalid direct object literals and broad spread
   construction.
5. [ ] Runtime tests still cover handle update, close, cancel, confirm, and OTP
   flows.

## Phase 3: Make Transaction Display And Tree Types Precise

Replace loose display and tree contracts with chain-specific and node-specific
unions.

Target files:

- `client/src/core/signingEngine/interfaces/display.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/display/tx-display-model.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/display/normalize-display-model.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/display/operation-types.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/tx-tree-element.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/tree-node-types.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/tree-builders.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/renderers/*`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/abi/*`
- transaction display model builders/converters
- Lit type fixtures and focused TxTree tests

Implementation tasks:

1. [ ] Split `TxDisplayModel` into chain-specific branches:

```ts
type TxDisplayModel =
  | NearTxDisplayModel
  | EvmTxDisplayModel
  | TempoTxDisplayModel
  | RawTxDisplayModel;
```

2. [ ] Require chain-specific fields at the type level. Examples:
   - EVM/Tempo branches require `chainId` where explorer, ABI, and display logic
     need it.
   - NEAR branches require signer/account fields that the renderer assumes.
   - raw/unknown branches carry explicit raw display data and cannot masquerade
     as chain-decoded transactions.
3. [ ] Normalize raw route/request transaction data into these branches once at
   the conversion boundary.
4. [ ] Replace broad action casts in `TxTree/index.ts` with typed action
   variants.
5. [ ] Split tree nodes:

```ts
type TreeNode = FolderTreeNode | FileTreeNode;

type FolderTreeNode = {
  kind: 'folder';
  label: string;
  children: readonly TreeNode[];
  content?: never;
};

type FileTreeNode = {
  kind: 'file';
  label: string;
  content: TreeNodeContent;
  children?: never;
};
```

6. [ ] Update tree renderers to return precise node branches without
   `rendered as TreeNode`.
7. [ ] Add exhaustive switches for operation and action rendering.
8. [ ] Add type fixtures rejecting:
   - EVM display models without required chain data
   - NEAR display models without signer/account data
   - file tree nodes with `children`
   - folder tree nodes with file-only content
   - unsafe spread objects that combine branch fields
9. [ ] Add source guard coverage for remaining `as unknown as` casts in the Lit
   tree path.
10. [ ] Wire `<w3a-tx-tree>` to the new tree element entrypoint and delete the
   old `TxTree/` implementation after rendering parity tests pass.

Acceptance criteria:

1. [ ] Invalid chain display states are rejected at compile time.
2. [ ] Tree renderers no longer need broad casts.
3. [ ] Existing NEAR, EVM, Tempo, and raw transaction fixtures render the same
   user-visible content.
4. [ ] Adding a new operation branch forces compile-time renderer updates.

## Phase 4: Extract Shared Confirm UI Modules

Reduce modal/drawer duplication by extracting pure domain/view helpers and small
shared render components.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/*`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/modal-tx-confirmer.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/drawer-tx-confirmer.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/tx-confirmer-wrapper.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/controllers/*`

Implementation tasks:

1. [ ] Extract pure helpers to `confirm-view-model.ts`:
   - title/heading text
   - chain label
   - security details text
   - explorer affordance labels
   - OTP display labels
2. [ ] Extract Email OTP state transitions to
   `email-otp-confirm-controller.ts` or small pure functions:
   - resend pending/success/failure
   - submit pending/success/failure
   - error formatting
   - resend animation timers
3. [ ] Extract shared header/security rendering to either:
   - a small Lit element with precise props, or
   - a pure render helper if a custom element adds no value.
4. [ ] Keep modal-only behavior in `modal-tx-confirmer.ts`:
   - backdrop
   - focus behavior
   - modal sizing
5. [ ] Keep drawer-only behavior in `drawer-tx-confirmer.ts`:
   - drawer mechanics
   - drag/resize behavior
   - mobile viewport handling
6. [ ] Keep `tx-confirm-content.ts` focused on transaction tree, ABI enrichment
   affordances, and confirm/cancel action controls.
7. [ ] Rebuild `modal-tx-confirmer.ts` and `drawer-tx-confirmer.ts` on the new
   shared modules, then route existing public custom-element tags to them.
8. [ ] Delete the old `IframeTxConfirmer/` implementation after modal and drawer
   parity tests pass.
9. [ ] Add unit tests for extracted pure helpers where they carry branching
   behavior.
10. [ ] Keep Playwright visual/behavior tests on the public custom elements.

Acceptance criteria:

1. [ ] Modal and drawer no longer duplicate OTP state-machine logic.
2. [ ] Modal and drawer no longer duplicate chain/security label logic.
3. [ ] Container-specific behavior remains local to the container files.
4. [ ] Tests cover extracted helper branches without relying only on DOM tests.

## Phase 5: Fix Component Lifecycle Cleanup

Make repeated mount/unmount safe for dialogs, drawers, and transaction trees.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/primitives/drawer/drawer-element.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/primitives/drawer/drawer-controller.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/tx-tree-element.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/controllers/lifecycle-timers.ts`
- related tests under `tests/lit-components`

Implementation tasks:

1. [ ] Replace inline bound global listeners with stable private handler fields.
2. [ ] Remove all global listeners in `disconnectedCallback`.
3. [ ] Centralize timer IDs in components that start delayed updates.
4. [ ] Clear timers in `disconnectedCallback`.
5. [ ] Ensure observers are disconnected exactly once.
6. [ ] Rebuild `<w3a-drawer>` on the new primitive path and delete the old
   `Drawer/` implementation after event and layout tests pass.
7. [ ] Add tests for repeated mount/unmount:
   - drawer resize listener does not call into detached instances
   - TxTree copy/animation timers do not request updates after detach
   - repeated open/close cycles keep event behavior stable

Acceptance criteria:

1. [ ] Detached drawers do not respond to future `resize` events.
2. [ ] Detached transaction trees do not run pending timer callbacks.
3. [ ] Existing drawer event tests still pass.

## Phase 6: Prepare Future Public UI Composition Boundaries

Keep the rewrite organized so public checkout and payment-review composition can
be added later without reworking the component graph. This phase does not ship
checkout-specific components, public UI subpath exports, or headless
confirmation APIs.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/confirm-shell.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/confirm-header.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/security-details.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/email-otp-panel.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/passkey-prompt.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/confirm-actions.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/state/*`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/display/*`
- docs for future public UI composition boundaries

Implementation tasks:

1. [ ] Keep shared UI pieces small and prop-driven:
   - confirm shell
   - confirm header
   - security details
   - Email OTP panel
   - passkey prompt
   - transaction content
   - confirm actions
2. [ ] Keep modal and drawer containers as composition hosts around those shared
   pieces rather than embedding transaction-specific layout directly in each
   container.
3. [ ] Keep component props typed in terms of `ConfirmRenderState`,
   `TxDisplayModel`, security state, and safe theme tokens.
4. [ ] Avoid component APIs that require parent knowledge of modal/drawer
   mechanics.
5. [ ] Keep future public entrypoints possible by avoiding imports from:
   - export-key UI
   - modal-only container code
   - drawer-only container code
   - ABI decoding unless explicitly requested
   - React wrappers
6. [ ] Document future public subpaths as non-shipping candidates:
   - `@seams/sdk/ui/tx-tree`
   - `@seams/sdk/ui/drawer`
   - `@seams/sdk/ui/halo-border`
   - `@seams/sdk/ui/confirm-shell`
   - `@seams/sdk/ui/types`
7. [ ] Document wallet iframe customization limits:
   - typed theme/customization data only
   - no app-provided render callbacks
   - no HTML strings
   - no scriptable templates
8. [ ] Add source or import-graph checks where cheap to prove shared components
   do not import containers, export-key UI, or React wrappers.
9. [ ] Update `README-lit-elements.md` with the future composition boundaries
   and wallet-origin customization limits.

Acceptance criteria:

1. [ ] Shared confirmer pieces are internally composable and prop-driven.
2. [ ] Modal and drawer containers do not own duplicated transaction/auth
   rendering logic.
3. [ ] The import graph would allow future public subpath exports without pulling
   export-key UI, React wrappers, or unused containers.
4. [ ] Wallet iframe customization limits are documented.
5. [ ] Checkout-specific components and headless public APIs remain future work.

## Phase 7: Reduce Lit Asset Size

Make the rewritten Lit bundles smaller without changing user-visible behavior.

Target files:

- `sdk/scripts/build/build-prod.sh`
- `sdk/scripts/build/build-sdk.sh`
- `sdk/scripts/checks/report-wallet-iframe-bundle-size.mjs`
- `sdk/scripts/reports/report-lite-bundle-sizes.mjs` or a new Lit-specific size
  report if that keeps ownership cleaner
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/entrypoints/*`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/abi/*`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/registry/*`
- `sdk/package.json`

Implementation tasks:

1. [ ] Pass production defines/env to every Bun-built Lit browser asset in
   `build-prod.sh`.
2. [ ] Decide whether dev `build-sdk.sh` should keep development diagnostics or
   also use production Lit runtime for local SDK packaging. Document that choice.
3. [ ] Add Lit JS/CSS entries to size reporting:
   - raw
   - gzip
   - brotli if the existing reporter supports it
4. [ ] Add explicit budgets for Lit entries. Start with measured baselines plus
   a small allowance, then tighten after splitting.
5. [ ] Make the ABI enrichment path a real split chunk if first-load size matters:
   - build with splitting and an output directory, or
   - emit a separate ABI asset and load it by URL from the component.
6. [ ] Ensure dynamic ABI chunks resolve from wallet-origin and app-origin SDK
   asset bases.
7. [ ] Split modal and drawer entrypoints if one variant can avoid loading the
   other:
   - `w3a-modal-tx-confirmer.js`
   - `w3a-drawer-tx-confirmer.js`
   - a tiny `w3a-tx-confirmer.js` wrapper/loader if the public wrapper remains
8. [ ] Keep entrypoint boundaries compatible with future subpath UI assets:
   - `ui/tx-tree`
   - `ui/drawer`
   - `ui/halo-border`
   - `ui/confirm-shell`
   - `ui/types`
9. [ ] Keep future headless UI type candidates free of Lit runtime imports if
   any internal design types are introduced.
10. [ ] Load CSS per element or entrypoint. Avoid a catch-all stylesheet for
   entries that only need one primitive.
11. [ ] Make `registry.ts` exhaustive over all public component tags and bundle
   loaders.
12. [ ] Add a source guard proving production SDK Lit outputs do not contain
   development Lit modules.

Acceptance criteria:

1. [ ] Production Lit assets use production Lit runtime code.
2. [ ] Bundle reports include all Lit JS/CSS assets.
3. [ ] Size budgets fail CI when Lit assets regress.
4. [ ] ABI decode code is loaded only when ABI enrichment is requested, if this
   phase keeps the split candidate.
5. [ ] Modal-only and drawer-only consumers can avoid loading the unused variant,
   if separate entrypoints are retained.
6. [ ] Internal entrypoint/import graph does not block future public UI subpaths.

## Phase 8: Tighten React Wrappers

Keep React wrappers aligned with the actual custom-element contract and reduce
dependency cost where the wrapper surface is simple.

Target files:

- `client/src/react/components/LitDrawer.tsx`
- `client/src/react/components/LitHaloBorder.tsx`
- `client/src/react/components/LitPasskeyHaloLoading.tsx`
- `client/src/react/components/AccountMenuButton/PasskeyHaloLoading.tsx`
- `client/src/react/index.ts`
- `sdk/package.json`

Implementation tasks:

1. [ ] Fix wrapper event names so React props map to emitted custom events.
2. [ ] Remove unused React imports from Lit wrapper files.
3. [ ] Evaluate replacing `@lit/react` wrappers with small hand-written wrappers
   that assign properties through refs and wire events in `useEffect`.
4. [ ] If hand-written wrappers are smaller and type-safe, remove `@lit/react`
   from the dependency graph.
5. [ ] If `@lit/react` remains, move wrappers behind subpath exports so consumers
   that do not use them avoid the dependency.
6. [ ] Add wrapper tests for event forwarding and property assignment.
7. [ ] Add a package-size check or import-graph assertion if dependency removal
   is part of the retained implementation.

Acceptance criteria:

1. [ ] React drawer callbacks fire for the events emitted by `<w3a-drawer>`.
2. [ ] React wrappers expose typed props that match custom-element properties.
3. [ ] The React package graph avoids `@lit/react` unless the retained wrapper
   design explicitly needs it.

## Phase 9: Base Class And Style Boundary Cleanup

Tighten the shared Lit base class after component state is narrower.

Target files:

- `client/src/core/signingEngine/uiConfirm/ui/lit-components/base/LitElementWithProps.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/base/css-loader.ts`
- `client/src/core/signingEngine/uiConfirm/ui/lit-components/base/define-element.ts`
- component style-token types
- style injection tests if present

Implementation tasks:

1. [ ] Review broad catch blocks that swallow child-definition and stylesheet
   errors.
2. [ ] Preserve production resilience for stylesheet failures while surfacing
   dev/test diagnostics through typed results, logged diagnostics, or test hooks.
3. [ ] Trim long comments that restate implementation after the code is simpler.
4. [ ] Keep broad style maps only at public boundaries. Use narrower
   component-specific style token types internally where practical.
5. [ ] Add focused tests for strict child-definition failure behavior.

Acceptance criteria:

1. [ ] Strict child-definition mode fails visibly in tests.
2. [ ] Stylesheet injection failures are observable in dev/test paths.
3. [ ] Public style customization remains source-compatible where it is still an
   intended public boundary.

## Phase 10: Rename `w3a` UI Prefixes To `seams`

Rename every retained SDK UI prefix from `w3a`/`W3A` to `seams`/`SEAMS` after
the rewritten component graph is in place. This is a breaking development-time
cleanup. Do not leave duplicate custom elements, compatibility aliases, legacy
CSS selectors, or old public asset names.

Target files and surfaces:

- Lit custom-element tag constants and registry entries
- Lit entrypoint filenames and build outputs
- `ui/registry.ts`
- `lit-components/**`
- `lit-components/css/**`
- React wrappers around Lit custom elements
- wallet iframe host selectors and portal ids
- tests, snapshots, fixtures, and source guards
- README and docs references
- package exports and build config entries for Lit UI assets

Rename mapping:

- `<w3a-tx-confirmer>` -> `<seams-tx-confirmer>`
- `<w3a-modal-tx-confirmer>` -> `<seams-modal-tx-confirmer>`
- `<w3a-drawer-tx-confirmer>` -> `<seams-drawer-tx-confirmer>`
- `<w3a-tx-tree>` -> `<seams-tx-tree>`
- `<w3a-drawer>` -> `<seams-drawer>`
- `<w3a-halo-border>` -> `<seams-halo-border>`
- `<w3a-confirm-shell>` -> `<seams-confirm-shell>`
- `<w3a-confirm-header>` -> `<seams-confirm-header>`
- `<w3a-security-details>` -> `<seams-security-details>`
- `<w3a-email-otp-panel>` -> `<seams-email-otp-panel>`
- `<w3a-passkey-prompt>` -> `<seams-passkey-prompt>`
- `<w3a-confirm-actions>` -> `<seams-confirm-actions>`
- `w3a-confirm-portal` -> `seams-confirm-portal`
- `w3a-*` CSS class names -> `seams-*`
- `--w3a-*` CSS variables -> `--seams-*`
- `W3A_*` constants -> `SEAMS_*`
- `w3a-*.js` Lit asset filenames -> `seams-*.js`

Implementation tasks:

1. [ ] Add a tag/asset/name inventory before editing:
   - custom elements
   - CSS classes
   - CSS variables
   - DOM ids
   - event names
   - package export keys
   - generated asset names
   - test selectors
2. [ ] Rename custom-element tags and tag constants to `seams-*`.
3. [ ] Rename Lit entrypoint files and build output names to `seams-*`.
4. [ ] Rename portal ids and selectors, including `w3a-confirm-portal`.
5. [ ] Rename CSS classes and CSS variables to `seams-*` / `--seams-*`.
6. [ ] Rename DOM data attributes only when they are SDK-private UI identifiers.
   Keep protocol or product terms that are not UI-prefix branding.
7. [ ] Rename event names emitted by custom elements where they carry the `w3a`
   prefix.
8. [ ] Update React wrappers and wrapper tests to use the new custom-element
   tags and event names.
9. [ ] Update wallet iframe host mounting and registry loading to use the new
   names.
10. [ ] Update package exports, build scripts, size reports, and bundle budgets
   for renamed Lit assets.
11. [ ] Update docs, READMEs, and examples to use `seams-*`.
12. [ ] Delete obsolete tests, fixtures, snapshots, and source guards that encode
   the old `w3a` names.
13. [ ] Add source guards proving retained Lit UI code does not define,
   register, export, import, or query `w3a-*` names after the rename.

Acceptance criteria:

1. [ ] No retained Lit UI custom element uses a `w3a-*` tag.
2. [ ] No retained Lit UI CSS class or CSS variable uses a `w3a` prefix.
3. [ ] No retained Lit UI public asset is named `w3a-*.js`.
4. [ ] React wrappers, wallet iframe registry, and tests use `seams-*` names.
5. [ ] Source guards fail on reintroduced `w3a` UI prefixes.
6. [ ] No compatibility aliases remain for old `w3a` UI names.

## Validation Plan

Use the cheapest check that covers the phase being changed.

Per-phase checks:

1. Phase 0:

```sh
rtk pnpm -C sdk type-check
```

2. Phase 1:

```sh
rtk pnpm -C tests test:lit-components
```

3. Phases 2 and 3:

```sh
rtk pnpm -C sdk type-check
rtk pnpm -C tests test:lit-components
```

4. Phase 4:

```sh
rtk pnpm -C tests test:lit-components
```

5. Phase 5:

```sh
rtk pnpm -C tests test:lit-components
```

6. Phase 6:

```sh
rtk pnpm -C sdk type-check
rtk pnpm -C tests test:lit-components
```

7. Phase 7:

```sh
rtk pnpm -C sdk build:prod
rtk pnpm -C sdk check:bundle-size
rtk pnpm -C sdk size:lite:check
```

8. Phase 8:

```sh
rtk pnpm -C sdk type-check
rtk pnpm -C tests test:lit-components
```

9. Phase 9:

```sh
rtk pnpm -C sdk type-check
rtk pnpm -C tests test:lit-components
```

10. Phase 10:

```sh
rtk pnpm -C sdk type-check
rtk pnpm -C tests test:lit-components
rtk pnpm -C tests test:wallet-iframe
rtk pnpm -C sdk build:prod
```

Run broader wallet iframe tests when changing registry loading, asset-base
resolution, iframe message protocols, or SDK build output paths:

```sh
rtk pnpm -C tests test:wallet-iframe
```

Run full SDK production build and size checks before marking this refactor
complete.

## Completion Criteria

This refactor is complete when:

1. [ ] Export-key iframe secret transfer uses typed, source/origin-checked
   messages.
2. [ ] Active confirmer rendering is driven by discriminated unions with required
   branch fields.
3. [ ] Transaction display and tree node types reject invalid branch
   combinations at compile time.
4. [ ] Modal/drawer duplicate logic is extracted into shared helpers or
   components.
5. [ ] Drawer and TxTree lifecycle cleanup is covered by tests.
6. [ ] Shared UI primitives are internally composable and can be promoted to
   public subpath exports later without another rewrite.
7. [ ] Wallet iframe customization boundaries are documented and reject
   app-provided scriptable rendering.
8. [ ] Production Lit assets are measured and budgeted.
9. [ ] Production Lit assets do not include Lit development modules.
10. [ ] ABI enrichment and modal/drawer variant loading are split where retained
   size measurements justify the complexity.
11. [ ] React wrappers match the custom-element event contract.
12. [ ] Old implementations are deleted after each replacement phase cuts over.
13. [ ] Obsolete tests and fixtures for the old optional-bag behavior are deleted.
14. [ ] Retained Lit UI tags, CSS, public assets, wrappers, and tests use
   `seams` prefixes. No `w3a` prefixes or compatibility aliases remain.

## Open Decisions

1. Should `seams-tx-confirmer.js` remain the only public transaction confirmer
   entrypoint, or should modal and drawer have public direct entrypoints?
2. Should ABI enrichment be split into a separate URL-loaded asset, or should the
   first implementation keep it inside the confirmer until size budgets require
   the split?
3. Should dev SDK builds keep Lit development runtime diagnostics, or should SDK
   packaging always use production Lit runtime for closer size parity?
4. Should React wrappers stay as first-class root exports, or move behind
   explicit subpath exports?
5. Which checkout fields belong in a future public checkout context branch:
   merchant logo, item images, shipping/tax rows, fiat totals, token totals, or
   only the minimal order summary?
6. Should a future headless confirmation API be available only for direct-browser
   mode at first, or should wallet iframe expose a preview-only headless state as
   well?
7. Should future public UI subpaths ship CSS automatically through JS entrypoints, or
   require explicit CSS imports for maximum bundler control?

## Future Work

These items should remain out of the first rewrite unless a concrete SDK
customer requirement pulls them forward.

### Checkout Display Context

A future checkout context can be a display-only discriminated union:

```ts
type CheckoutDisplayContext =
  | {
      kind: 'ecommerce_order';
      merchantName: string;
      orderId: string;
      lineItems: readonly CheckoutLineItem[];
      total: MoneyDisplay;
    }
  | {
      kind: 'generic_payment';
      title: string;
      rows: readonly DisplayRow[];
    };
```

It must never override the signed transaction model, security context, auth
mode, or final signing result.

Candidate future elements:

```text
<w3a-checkout-summary>
<w3a-merchant-card>
<w3a-order-total>
<w3a-payment-route>
```

### Headless Confirmation API

A future direct-browser API can expose typed state for app-owned UI:

```ts
const session = await seams.ui.createConfirmationSession({
  request,
  mode: 'headless',
});

session.subscribe((state) => {
  // App renders React, Lit, Vue, or custom UI from typed state.
});

await session.confirm();
await session.cancel();
```

The future session state should remain a discriminated union and should preserve
the wallet iframe rule that app-provided render callbacks, HTML strings, and
scriptable templates do not cross into wallet-origin confirmation or export-key
iframes.

## Notes

Initial review-only size probes found that production defines are material for
small Lit assets. A temporary isolated `HaloBorder` build dropped from roughly
`13.4 KB` gzip with minification alone to roughly `9.2 KB` gzip with
`NODE_ENV=production`. Re-measure from the real SDK production build before
setting final budgets.
