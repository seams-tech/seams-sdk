# Refactor 9X: Lit UI Security, Typed State, Appearance, And Asset Graph

Date created: July 9, 2026

Status: proposed replacement plan for `docs/refactor-8X-lit.md`

Owner: SDK UI, wallet iframe, Lit assets, and React wrappers

## Goal

Make the SDK Lit UI safer, easier to evolve, and smaller on the wire.

This plan covers:

- transaction confirmation modal and drawer
- transaction tree rendering
- private-key export viewer and iframe protocol
- shared Lit primitives
- theme and appearance propagation
- React wrappers for custom elements
- Lit-specific production asset build and size checks

This is a replacement-style refactor. Build the final contracts and module
layout, cut each surface over once, then delete the old implementation for that
surface in the same phase. Temporary duplicate code is allowed only inside the
active phase that is cutting over a surface.

## Current Repo Anchors

Use the current workspace paths. Do not copy the old `client/src` or `sdk`
paths from earlier plans.

Primary source paths:

- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/`
- `packages/sdk-web/src/SeamsWeb/`
- `packages/sdk-web/src/react/`
- `packages/sdk-web/scripts/`
- `tests/lit-components/`
- `tests/wallet-iframe/`
- `tests/types/`
- `tests/scripts/`

Primary validation commands:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
pnpm -C tests test:wallet-iframe
pnpm -C packages/sdk-web build:prod
pnpm -C packages/sdk-web check:bundle-size
pnpm -C packages/sdk-web size:lite:check
```

## Non-Goals

- Visual redesign of the confirmer or export-key viewer.
- New checkout components.
- Public headless confirmation API.
- Compatibility aliases for replaced internal Lit paths.
- Compatibility aliases for old optional-bag confirm state.
- Moving wallet-origin secrets into app-origin ownership.
- Allowing app-origin render callbacks, HTML strings, or scriptable templates
  inside wallet-origin confirmation or export-key iframes.
- Renaming every `w3a` UI prefix to `seams` in this refactor.

## Separate Future Refactor: `w3a` UI Prefix Rename

The `w3a` to `seams` rename is repo-wide and should be its own refactor after
the Lit component graph and asset graph settle.

That future refactor should inventory and rename:

- custom-element tags
- CSS classes
- CSS variables
- DOM ids
- event names
- package export keys
- generated asset names
- test selectors
- documentation examples

This plan may create new internal files with neutral names, but it should keep
retained public tags and CSS variables stable until the rename refactor starts.

## Design Rules

1. Parse raw request, route, iframe, DOM, and persistence shapes once at the
   boundary.
2. Core render functions receive precise internal state.
3. Required identity, auth, session, signing, and security fields stay required
   inside SDK logic.
4. Use discriminated unions, branch-specific builders, `never` fields, and
   exhaustive switches for lifecycle and display state.
5. Add type fixtures for invalid object-literal construction, broad spreads,
   unsafe casts, and invalid branch combinations when shared state changes.
6. Keep compatibility parsing at request and persistence boundaries.
7. Delete tests and fixtures that only protect obsolete optional-bag behavior.
8. Treat appearance as a normalized SDK state object. DOM attributes, CSS custom
   properties, component properties, and iframe messages are runtime writes
   derived from that state.
9. Use source guards with explicit allowlists while old code still exists. The
   guard should pass in every phase and its allowlist should shrink as old code
   is replaced.

## System Boundary Invariants

This refactor hooks into systems outside Lit. These invariants must hold in
every phase.

1. Appearance-only updates must not recreate wallet-host `SeamsWeb`, clear warm
   signing sessions, reset preferences, or change the wallet runtime reset
   fingerprint.
2. React provider theme props, SDK config, `seams.setAppearance(...)`, wallet
   iframe `PM_SET_CONFIG`, and export-key iframe bootstrap messages must
   normalize through the same appearance parser before writing DOM attributes or
   CSS custom properties.
3. React app-origin, wallet-host, and export-key iframe style writers may remain
   separate runtime applicators because they live in different documents. They
   must consume the same normalized appearance state and share one token
   serialization implementation.
4. CSP and asset-loading behavior must remain compatible with hosted wallet
   deployments. Do not introduce inline scripts or inline styles into export-key
   iframe HTML.
5. Export-key iframe sandbox and permissions behavior must remain explicit:
   `allow-scripts`, current origin assumptions, clipboard permissions, and
   wallet-origin asset loading need tests when the protocol changes.
6. Confirm UI host orchestration must preserve portal stacking, drawer close
   fallback, diagnostics, explorer URL inference, `handle.update(...)`, and
   intent-digest guard behavior.
7. Chain/domain display types should not move under Lit if non-Lit signing,
   chain, or public API code depends on them. Lit can own view/tree
   normalization over canonical domain display models.
8. Build changes must preserve hosted wallet static asset emission,
   static-asset assertions, build freshness hashing, and asset-base resolution.
9. Source guards introduced by this refactor must be wired into
   `pnpm -C tests test:source-guards` in the phase that adds them.

## Target Module Layout

Create the final module layout under:

```text
packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/
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

  styles/
    appearance-state.ts
    appearance-parser.ts
    apply-appearance.ts
    token-css-vars.ts
    tx-confirmer.css
    tx-tree.css
    drawer.css
    export-viewer.css
    export-iframe.css
    halo-border.css
    passkey-halo-loading.css

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
      tx-display-view-model.ts
      normalize-display-view-model.ts
      operation-view-types.ts
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
```

Directory rules:

- `entrypoints/` files are stable browser asset entrypoints.
- `state/`, `display/`, and `protocol/` own internal correctness.
- `components/` are prop-driven shared render pieces.
- `containers/` own modal/drawer mechanics.
- `abi/` is isolated so it can become a lazy asset.
- `styles/` owns appearance normalization and CSS-var application.
- `tx-confirm/display/` owns Lit view models derived from canonical display
  domain types. Canonical signing/chain display types stay outside
  `lit-components` when they are consumed by non-Lit code.

## Initial Replacement Map

Use this map during the rewrite. Delete each row when the old module is gone.

| Current path | Target path |
| --- | --- |
| `lit-components/LitElementWithProps.ts` | `lit-components/base/LitElementWithProps.ts` |
| `lit-components/asset-base.ts` | `lit-components/base/asset-base.ts` |
| `lit-components/css/css-loader.ts` | `lit-components/base/css-loader.ts` |
| `ui/lit-events.ts` | `lit-components/base/events.ts` |
| `ui/registry.ts` | `lit-components/registry/tags.ts` and `lit-components/registry/loaders.ts` |
| `lit-components/appearance-token-vars.ts` | `lit-components/styles/token-css-vars.ts` |
| `lit-components/Drawer/index.ts` | `lit-components/primitives/drawer/drawer-element.ts` |
| `lit-components/HaloBorder/index.ts` | `lit-components/primitives/halo-border/halo-border-element.ts` |
| `lit-components/PasskeyHaloLoading/index.ts` | `lit-components/primitives/passkey-halo-loading/passkey-halo-loading-element.ts` |
| `lit-components/common/PadlockIcon.ts` | `lit-components/primitives/padlock-icon/padlock-icon-element.ts` |
| `lit-components/TxTree/index.ts` | `lit-components/tx-confirm/tree/tx-tree-element.ts` |
| `lit-components/TxTree/tx-tree-utils.ts` | `lit-components/tx-confirm/display/normalize-display-view-model.ts` and `lit-components/tx-confirm/tree/tree-builders.ts` |
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

## Phase 0: Repo Alignment, Baseline, And Passing Guardrails

Prepare the refactor without changing runtime behavior.

Tasks:

1. [ ] Inventory current custom-element definitions from:
   - `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/registry.ts`
   - `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/**`
2. [ ] Record production Lit asset sizes after:

```sh
pnpm -C packages/sdk-web build:prod
```

3. [ ] Record raw, gzip, and brotli sizes for current Lit JS and CSS assets.
4. [ ] Add a temporary size baseline section to this document.
5. [ ] Create the target directory scaffold with placeholder type-only modules.
6. [ ] Move stable helpers into `base/` only when imports can be updated in the
   same patch.
7. [ ] Add a replacement map from current modules to target modules.
8. [ ] Add source guards with allowlists for:
   - wildcard target origins in secret-bearing export-key messages
   - `@lit/*/development` in production Lit outputs
   - broad `as unknown as` casts in Lit tree renderers
   - old optional-bag confirm state imports after Phase 2 lands
9. [ ] Add type-fixture locations under `tests/types/lit-components/`.
10. [ ] Wire the Lit source guard into `pnpm -C tests test:source-guards`.
11. [ ] Confirm validation commands in this document match package scripts.

Acceptance criteria:

1. [ ] Scaffold compiles without behavior changes.
2. [ ] Source guards pass with explicit allowlists.
3. [ ] The allowlist entries are tied to replacement phases.
4. [ ] Baseline size numbers are committed in this document.
5. [ ] `pnpm -C tests test:source-guards` includes the Lit source guard.

### Source Guard Allowlist Contract

Lit source guards should use the repo's existing audited allowlist style rather
than failing on known current code. Add a single guard script unless a narrower
guard is simpler:

- `tests/scripts/check-lit-ui-boundaries.mjs`
- `tests/unit/litUiBoundaries.sourceGuard.allowlist.json`

Allowlist shape:

```json
{
  "allow": [
    {
      "file": "packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/ExportPrivateKey/iframe-host.ts",
      "pattern": "postMessage",
      "count": 1,
      "reason": "Phase 1 replaces export-key iframe messaging with a typed channel.",
      "removeInPhase": "Phase 1",
      "disposition": "Delete the old host after export-key channel tests pass."
    }
  ]
}
```

Rules:

1. [ ] Every entry has `file`, `pattern`, `count`, `reason`, `removeInPhase`,
   and `disposition`.
2. [ ] The guard fails if a pattern count changes.
3. [ ] The guard fails on any matching pattern outside the allowlist.
4. [ ] The guard fails when an allowlisted file disappears and the entry remains.
5. [ ] Phase completion requires removing entries for that phase.

## Phase 0A: Single Appearance Contract

Theme and color propagation should have one normalized SDK state transition.
React scopes, wallet-host documents, Lit custom elements, and export-key iframes
still need separate runtime writes because they can live in different documents.
Those writes should all consume the same `AppearanceConfig`.

Architectural choices:

- `ThemeId` is an open `string`. Application theme names are end-user defined.
- `ThemeMode` is the SDK-owned contrast/default axis: `'light' | 'dark'`.
- `ThemeMode` selects default renderer token sets and root/document selectors.
- Theme ids do not drive SDK behavior.
- CSS custom properties are derived writes. They are not a source of truth.

Target internal model:

```ts
type ThemeMode = 'light' | 'dark';
type ThemeId = string;
type ThemePaletteName = 'default';

type AppearanceColorKey = string;
type AppearanceColorValue = string;

type AppearanceTheme = {
  id: ThemeId;
  mode: ThemeMode;
  colors: Readonly<Record<AppearanceColorKey, AppearanceColorValue>>;
};

type AppearanceConfig = {
  theme: AppearanceTheme;
  palette: ThemePaletteName;
};
```

Public input model:

```ts
type AppearanceThemeInput =
  | { id?: ThemeId; mode?: ThemeMode; colors?: Record<string, string> }
  | ThemeMode;

type AppearanceConfigInput = {
  theme?: AppearanceThemeInput;
  palette?: ThemePaletteName;
  tokens?: {
    light?: { colors?: Record<string, string> };
    dark?: { colors?: Record<string, string> };
  };
};
```

`AppearanceConfigInput` is a boundary type. Internal SDK code consumes
`AppearanceConfig` only. The legacy `tokens` bucket is accepted only at public
config/request boundaries and normalized immediately.

Boundary parser requirements:

1. `theme.id` must be a non-empty string.
2. `theme.mode` must be `'light'` or `'dark'`.
3. Color keys must be valid token suffixes for `--w3a-colors-${key}`.
4. Color values must be strings suitable for CSS color or CSS color-like token
   values. Reject values containing statement delimiters or malformed CSS var
   writes.
5. Missing `colors` means "preserve or use defaults"; inside
   `AppearanceConfig`, `colors` is always present.
6. Raw token-bucket shapes are accepted only at public/config boundaries and are
   normalized immediately.

Exact parser contract:

1. `ThemeId` normalization trims whitespace and rejects the empty string.
2. Color key regex is `/^[A-Za-z][A-Za-z0-9_-]*$/`. Unknown valid keys are
   preserved so applications can define future token names without SDK releases.
3. Color values are trimmed non-empty strings with a maximum length of 256
   characters.
4. Color values may be:
   - hex colors
   - `transparent` or `currentColor`
   - CSS color functions such as `rgb`, `rgba`, `hsl`, `hsla`, `hwb`, `lab`,
     `lch`, `oklab`, `oklch`, `color`, and `color-mix`
   - `var(...)` references
5. Color values are rejected when they contain `;`, `{`, `}`, `<`, `>`,
   `@import`, `url(`, `expression(`, or `!important`.
6. Initial config normalization merges input colors over built-in defaults for
   the selected mode.
7. Runtime `setAppearance({ theme: { colors } })` overlays provided colors onto
   the current normalized color map.
8. Runtime `setAppearance({ theme: { mode } })` changes mode, loads that mode's
   default color map, then applies the current theme id and any provided colors.
9. There is no color deletion operation in this refactor. A reset API can be
   added later as a separate explicit state branch.
10. React, wallet-host, and export-key style writers import the same token-key
    and token-value parser/serializer instead of each maintaining local
    sanitizers.
11. `!important` precedence for app-provided Lit overrides is preserved unless
    Phase 0A explicitly proves generated component CSS always loads earlier.

Target files:

- `packages/sdk-web/src/core/types/seams.ts`
- `packages/sdk-web/src/core/config/configBuilder.ts`
- `packages/sdk-web/src/core/config/configHelpers.ts`
- `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts`
- `packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`
- `packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts`
- `packages/sdk-web/src/SeamsWeb/walletIframe/host/context.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/styles/appearance-state.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/styles/appearance-parser.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/styles/apply-appearance.ts`
- `packages/sdk-web/src/react/context/SeamsWebProvider.tsx`
- `packages/sdk-web/src/react/components/theme/**`

Tasks:

1. [ ] Keep exactly one internal `AppearanceConfig` type.
2. [ ] Add parsers/builders for:
   - SDK config `appearance`
   - React provider theme props
   - `seams.setAppearance(...)`
   - wallet iframe `PM_SET_CONFIG` payloads
   - export-key iframe bootstrap messages
3. [ ] Keep `seams.setTheme(mode)` as a convenience wrapper that updates
   `AppearanceConfig.theme.mode` through the same builder as `setAppearance`.
4. [ ] Use `PM_SET_CONFIG` with `appearance` for wallet iframe appearance
   changes.
5. [ ] Give `SeamsWeb`, `BrowserSigningSurface`, wallet iframe host, and export
   key host one `applyAppearance(state)` entrypoint each.
6. [ ] Store the latest appearance in the signing surface so local key export
   uses current colors.
7. [ ] Make Lit `theme` attributes and root `data-w3a-theme` attributes derived
   from `AppearanceConfig.theme.mode`.
8. [ ] Make CSS custom properties derived from `AppearanceConfig.theme.colors`.
9. [ ] Delete mode-only propagation handlers after the appearance path is wired.
10. [ ] Preserve wallet-host runtime-reset behavior: appearance-only
   `PM_SET_CONFIG` updates do not recreate `SeamsWeb`, reset preferences, or
   clear warm signing sessions.
11. [ ] Delete duplicated token sanitizer/serializer functions from React
   provider, wallet host, and export-key iframe once they consume shared
   `styles/token-css-vars.ts`.
12. [ ] Add tests proving:
   - React provider colors reach `SeamsWeb`
   - React provider colors reach direct-browser signing UI
   - wallet iframe appearance changes travel through `PM_SET_CONFIG`
   - modal confirmer, drawer confirmer, and export-key drawer receive the same
     token overrides
   - color-only updates preserve current theme id and mode
   - `seams.setTheme('light')` and `seams.setAppearance(...)` use the same
     propagation path after normalization
   - appearance-only wallet-host config updates do not trigger runtime reset

Acceptance criteria:

1. [ ] There is one internal appearance state type across SDK runtime domains.
2. [ ] Theme ids are open strings and never drive SDK branches.
3. [ ] `ThemeMode` only drives light/dark defaults and selectors.
4. [ ] CSS variable writes are derived from normalized state.
5. [ ] No production source has a separate mode-only wallet appearance RPC.
6. [ ] React provider, wallet-host, and export-key style writers share token
   parsing/serialization.
7. [ ] Appearance-only updates preserve warm wallet runtime state.

## Phase 1: Secure Export-Key Iframe Protocol

Treat private-key display as the highest-risk Lit surface.

Target files:

- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-messages.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-message-parser.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/protocol/export-key-channel.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/components/export-key-iframe-host-element.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/components/export-key-viewer.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/export-key/entrypoints/*`
- `tests/lit-components/*export*`
- `tests/wallet-iframe/*export*` if wallet-host behavior is affected

Protocol requirements:

1. Parent and child messages are discriminated unions.
2. Parsers return Result-style unions for raw `MessageEvent.data`.
3. The host stores the expected child `WindowProxy`.
4. Child messages require `event.source === expectedChildWindow`.
5. Child messages require the expected child origin when the child has a stable
   origin.
6. Parent messages require the expected parent origin in the child.
7. Secret-bearing private-key transfer must not use `'*'`.
8. If the child is `srcdoc` or opaque-origin, use a verified channel design:
   - child posts ready to parent
   - parent validates source
   - parent transfers a `MessagePort`
   - secret messages travel over that port
   - channel id or nonce binds the active iframe instance
9. Replacing or navigating the iframe invalidates the active channel.
10. Export-key iframe HTML remains strict-CSP friendly:
   - no inline scripts
   - no inline styles
   - external module scripts only
   - external stylesheets only
11. Sandbox and permissions stay explicit:
   - `allow-scripts`
   - current origin/same-origin behavior is documented by test
   - `allow="clipboard-read; clipboard-write"` is preserved unless replaced by
     an equivalent tested flow

Protocol state machine:

```ts
type ExportKeyChannelState =
  | { kind: 'uninitialized' }
  | {
      kind: 'child_ready';
      channelId: string;
      childWindow: WindowProxy;
      parentOrigin: string;
      childOrigin: string | 'opaque';
    }
  | {
      kind: 'port_established';
      channelId: string;
      port: MessagePort;
      childWindow: WindowProxy;
      parentOrigin: string;
      childOrigin: string | 'opaque';
    }
  | {
      kind: 'secret_sent';
      channelId: string;
      port: MessagePort;
      childWindow: WindowProxy;
      parentOrigin: string;
      childOrigin: string | 'opaque';
    }
  | { kind: 'closed'; reason: 'confirmed' | 'cancelled' | 'iframe_replaced' | 'error' };
```

State transition rules:

1. [ ] `EXPORT_KEY_READY` is accepted only from `uninitialized`.
2. [ ] Port transfer is accepted only from `child_ready`.
3. [ ] Secret delivery is accepted only from `port_established`.
4. [ ] Confirm/cancel/copy messages are accepted only from `secret_sent`.
5. [ ] Replaced iframe, navigation, close, or host disconnect transitions to
   `closed` and closes the active port.
6. [ ] Every transition checks `channelId`.
7. [ ] Every switch over `ExportKeyChannelState` is exhaustive.

Tasks:

1. [ ] Define parent-to-child, child-to-parent, and channel message unions.
2. [ ] Add parser tests for malformed and unknown messages.
3. [ ] Implement a channel object that owns source/origin/channel-id checks.
4. [ ] Route existing export-key host/viewer through the channel.
5. [ ] Make export-key first paint consume current `AppearanceConfig`.
6. [ ] Delete old permissive message handlers in the same phase.
7. [ ] Add tests for wrong source, wrong origin, malformed data, replaced iframe,
   valid confirm, valid cancel, valid copy, and valid private-key display.
8. [ ] Add type fixtures rejecting secret delivery before `port_established` and
   confirm/cancel handling before `secret_sent`.
9. [ ] Add tests proving the `srcdoc` bootstrap still loads external CSS and
   module assets from the configured SDK asset base.
10. [ ] Add tests proving clipboard permission behavior is unchanged for copy
   actions.

Acceptance criteria:

1. [ ] No secret-bearing `postMessage` call uses `'*'`.
2. [ ] All export-key iframe messages pass through typed parsers.
3. [ ] Source and origin/channel checks are tested.
4. [ ] Valid export-key behavior is unchanged.
5. [ ] Export-key iframe remains compatible with strict CSP and hosted wallet
   static assets.

## Phase 2: Replace Optional Confirm State With Render Unions

Move confirmer rendering from partial host props to explicit internal render
states.

`ConfirmUIUpdate` may remain a permissive public/host-boundary update type so
existing orchestration can call `handle.update(...)`. The host boundary must
parse and normalize those updates immediately before passing state into Lit
rendering.

Target files:

- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/confirm-ui-types.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/confirm-ui.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/state/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/entrypoints/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/*`
- `tests/lit-components/confirm-ui.handle.test.ts`
- `tests/types/lit-components/*confirm*`

Target internal model:

```ts
type ConfirmRenderState =
  | { kind: 'empty' }
  | { kind: 'loading'; title: string }
  | {
      kind: 'passkey_confirm';
      model: TxDisplayModel;
      securityContext: ConfirmSecurityContext;
      prompt: PasskeyConfirmPrompt;
    }
  | {
      kind: 'email_otp_confirm';
      model: TxDisplayModel;
      securityContext: ConfirmSecurityContext;
      prompt: EmailOtpConfirmPrompt;
    }
  | { kind: 'error'; error: ConfirmUiError };
```

Tasks:

1. [ ] Add branch-specific builders.
2. [ ] Parse raw `ConfirmUIUpdate` at the host boundary.
3. [ ] Convert `ConfirmUIUpdate` immediately into `ConfirmRenderState`.
4. [ ] Narrow Lit element properties to valid render branches.
5. [ ] Remove default empty-string identity/auth props from active branches.
6. [ ] Replace boolean-mode rendering branches with exhaustive switches.
7. [ ] Add `assertNever` coverage for render-state switches.
8. [ ] Update tests to use builders.
9. [ ] Add type fixtures rejecting missing model/security state, mixed auth
   prompts, broad spreads, and invalid direct object literals.
10. [ ] Delete optional-bag internal paths after the replacement is wired.
11. [ ] Add screenshot or DOM parity coverage for:
   - modal review
   - drawer review
   - funding-required state
   - Email OTP prompt
   - error state
   - mobile drawer viewport
12. [ ] Preserve host orchestration semantics:
   - portal stacking and `--w3a-confirm-stack-index`
   - drawer close fallback event and timeout
   - `ConfirmUIPromptDiagnostics`
   - `handle.update(...)`
   - explorer URL inference from model/chain config
   - intent-digest guard
   - wallet-host open/close DOM events

Acceptance criteria:

1. [ ] Active confirmation rendering cannot be called without model and security
   context.
2. [ ] Email OTP render state cannot exist without an OTP prompt.
3. [ ] Passkey render state cannot carry Email OTP-only fields.
4. [ ] Runtime tests still cover handle update, close, cancel, confirm, and OTP
   flows.
5. [ ] Modal and drawer parity cases render stable DOM roles and user-visible
   labels.
6. [ ] Confirm host tests prove portal stacking, diagnostics, and intent-digest
   guard behavior are unchanged.

## Phase 3: Precise Transaction Display And Tree Types

Replace loose transaction display and tree node contracts with chain-specific
and node-specific unions.

Target files:

- `packages/sdk-web/src/core/signingEngine/interfaces/display.ts`
- chain-specific display builders outside Lit
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/display/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/abi/*`
- `tests/types/lit-components/*tx-display*`
- `tests/lit-components/*tx-tree*`

Target domain model direction:

```ts
type TxDisplayModel =
  | NearTxDisplayModel
  | EvmTxDisplayModel
  | TempoTxDisplayModel
  | RawTxDisplayModel;
```

This canonical transaction display model belongs outside `lit-components` if
signing, chain adapters, tests, or public APIs consume it. Lit owns a derived
view model for rendering and tree construction:

```ts
type TxDisplayViewModel =
  | NearTxDisplayViewModel
  | EvmTxDisplayViewModel
  | TempoTxDisplayViewModel
  | RawTxDisplayViewModel;

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

Tasks:

1. [ ] Decide ownership for canonical `TxDisplayModel` before moving files:
   - keep shared canonical types outside Lit when consumed by non-Lit code
   - keep Lit-only tree/view types under `lit-components/tx-confirm/display`
2. [ ] Require chain-specific fields at the canonical domain type level where
   non-Lit code benefits from the invariant.
3. [ ] Normalize route/request transaction data once at the chain/display
   conversion boundary.
4. [ ] Convert canonical display models into Lit `TxDisplayViewModel` at the UI
   boundary.
5. [ ] Replace broad action casts with typed action variants.
6. [ ] Update tree renderers to return precise node branches.
7. [ ] Add exhaustive switches for operation and action rendering.
8. [ ] Add type fixtures rejecting:
   - EVM display models without required chain data
   - NEAR display models without signer/account data
   - file tree nodes with `children`
   - folder tree nodes with file-only content
   - unsafe branch-spread combinations
9. [ ] Add a source guard for remaining broad casts in Lit tree paths.
10. [ ] Wire `<w3a-tx-tree>` to the new tree element entrypoint.
11. [ ] Delete the old `TxTree/` implementation after parity tests pass.
12. [ ] Add expanded/collapsed visual or DOM parity for:
   - NEAR action tree
   - EVM call with ABI decode
   - Tempo transaction
   - raw/fallback bytes view
   - file-content mode toggle

Acceptance criteria:

1. [ ] Invalid chain display states are rejected at compile time.
2. [ ] Tree renderers no longer require broad casts.
3. [ ] Existing NEAR, EVM, Tempo, and raw fixtures render the same user-visible
   content.
4. [ ] Adding a new operation branch forces renderer updates.
5. [ ] The `bytes` toggle and expanded tree controls keep accessible labels.
6. [ ] Non-Lit signing/chain code does not import from `lit-components`.

## Phase 4: Shared Confirm Components And Controllers

Reduce modal/drawer duplication by extracting pure view helpers, shared render
pieces, and small controllers.

Target files:

- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/components/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/containers/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/controllers/*`

Tasks:

1. [ ] Extract pure view-model helpers:
   - title text
   - chain label
   - security details
   - explorer affordance labels
   - OTP labels
2. [ ] Extract Email OTP state transitions:
   - resend pending/success/failure
   - submit pending/success/failure
   - error formatting
   - resend timers
3. [ ] Extract shared header/security rendering as a Lit element or pure render
   helper based on import graph and bundle cost.
4. [ ] Keep modal-only backdrop, focus, and sizing behavior in the modal
   container.
5. [ ] Keep drawer-only mechanics, drag, resize, and mobile viewport behavior in
   the drawer container.
6. [ ] Keep `tx-confirm-content.ts` focused on transaction content, ABI
   enrichment affordances, and confirm/cancel controls.
7. [ ] Route existing public tags to the new containers.
8. [ ] Delete the old `IframeTxConfirmer/` implementation after modal and drawer
   parity tests pass.
9. [ ] Add unit tests for extracted branch-heavy helpers.
10. [ ] Preserve modal accessibility behavior:
   - role and accessible name
   - focus enters the dialog on open
   - focus returns to the invoking element on close
   - Escape closes when cancellation is allowed
   - background content is inert or hidden from assistive technology
11. [ ] Preserve drawer accessibility behavior:
   - role and accessible name
   - close affordance is keyboard reachable
   - drag handle has an accessible label when interactive
   - reduced-motion settings disable non-essential animation
12. [ ] Add tests for focus restore, Escape handling, and reduced-motion behavior
   where the current test harness can observe them.

Acceptance criteria:

1. [ ] Modal and drawer no longer duplicate OTP state-machine logic.
2. [ ] Modal and drawer no longer duplicate chain/security label logic.
3. [ ] Container-specific behavior stays local to container files.
4. [ ] Shared components do not import modal-only, drawer-only, export-key, or
   React modules.
5. [ ] Modal and drawer keep keyboard and assistive-technology behavior.

## Phase 5: Lifecycle Cleanup

Make repeated mount/unmount safe for drawers, dialogs, and transaction trees.

Target files:

- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/primitives/drawer/*`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/tree/tx-tree-element.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/tx-confirm/controllers/lifecycle-timers.ts`
- `tests/lit-components/*lifecycle*`

Tasks:

1. [ ] Replace inline bound global listeners with stable handler fields.
2. [ ] Remove all global listeners in `disconnectedCallback`.
3. [ ] Centralize timer ids.
4. [ ] Clear timers in `disconnectedCallback`.
5. [ ] Disconnect observers exactly once.
6. [ ] Add repeated mount/unmount tests for drawer resize and TxTree timers.
7. [ ] Add a host-disconnect test for export-key iframe channel cleanup if Phase
   1 introduces a `MessagePort`.

Acceptance criteria:

1. [ ] Detached drawers do not respond to future resize events.
2. [ ] Detached transaction trees do not run pending timer callbacks.
3. [ ] Repeated open/close cycles keep event behavior stable.
4. [ ] Detached export-key hosts close the active channel port.

## Phase 6: Lit Asset Graph And Size Budgets

Make production Lit assets measurable and smaller where splitting creates real
load-time wins.

Target files:

- `packages/sdk-web/scripts/build/build-prod.sh`
- `packages/sdk-web/scripts/build/build-sdk.sh`
- `packages/sdk-web/scripts/build/emit-static-wallet-assets.mjs`
- `packages/sdk-web/scripts/checks/assert-static-wallet-assets.mjs`
- `packages/sdk-web/scripts/checks/report-wallet-iframe-bundle-size.mjs`
- `packages/sdk-web/scripts/reports/report-lite-bundle-sizes.mjs`
- `packages/sdk-web/rolldown.config.ts`
- `packages/sdk-web/package.json`
- Lit entrypoints under `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/**/entrypoints/`

Tasks:

1. [ ] Pass production defines/env to every Bun-built Lit browser asset in
   `build-prod.sh`.
2. [ ] Decide whether dev SDK packaging uses Lit development diagnostics or
   production Lit runtime.
3. [ ] Add Lit JS/CSS entries to size reporting.
4. [ ] Add explicit Lit budgets from measured baselines plus a small allowance.
5. [ ] Split ABI enrichment only if measured first-load savings justify it.
6. [ ] Ensure dynamic chunks resolve from wallet-origin and app-origin SDK asset
   bases.
7. [ ] Split modal and drawer entrypoints only if consumers can avoid loading the
   unused variant.
8. [ ] Load CSS per element or per entrypoint.
9. [ ] Make registry loading exhaustive over public component tags and loaders.
10. [ ] Add a production-output guard for Lit development modules.
11. [ ] Resolve the entrypoint decision before splitting:
   - keep only `w3a-tx-confirmer.js`
   - or publish direct `w3a-modal-tx-confirmer.js` and
     `w3a-drawer-tx-confirmer.js`
12. [ ] Resolve the ABI split decision before changing the build graph:
   - keep ABI inside the confirmer
   - or emit a URL-loaded ABI asset with documented asset-base resolution
13. [ ] Update hosted wallet static asset emission for every renamed/moved Lit
   asset.
14. [ ] Keep `assert-static-wallet-assets.mjs` and hosted wallet docs in sync
   with new Lit asset names.
15. [ ] Preserve build freshness hashing inputs so Lit asset graph changes
   invalidate stale builds.
16. [ ] Add tests or checks for app-origin and wallet-origin asset-base
   resolution when dynamic chunks or URL-loaded ABI assets are introduced.

Acceptance criteria:

1. [ ] Production Lit assets use production Lit runtime code.
2. [ ] Bundle reports include Lit JS and CSS.
3. [ ] Lit budgets fail CI on regressions.
4. [ ] ABI and modal/drawer splitting decisions are backed by measured size
   data.
5. [ ] Public asset names and package exports match the resolved entrypoint
   decision.
6. [ ] Hosted wallet static asset emission and assertions pass after Lit asset
   graph changes.
7. [ ] Build freshness checks include new Lit entrypoints and dynamic assets.

## Phase 7: React Wrapper Tightening

Align React wrappers with actual custom-element contracts and reduce dependency
cost where the wrapper surface is simple.

Target files:

- `packages/sdk-web/src/react/components/LitDrawer.tsx`
- `packages/sdk-web/src/react/components/LitHaloBorder.tsx`
- `packages/sdk-web/src/react/components/LitPasskeyHaloLoading.tsx`
- `packages/sdk-web/src/react/components/AccountMenuButton/PasskeyHaloLoading.tsx`
- `packages/sdk-web/src/react/index.ts`
- `packages/sdk-web/package.json`

Tasks:

1. [ ] Fix wrapper event names so React props map to emitted custom events.
2. [ ] Remove unused React imports from Lit wrapper files.
3. [ ] Evaluate hand-written wrappers that assign properties through refs and
   wire events in effects.
4. [ ] Remove `@lit/react` if hand-written wrappers are smaller and type-safe.
5. [ ] If `@lit/react` remains, put wrappers behind explicit subpath exports so
   unrelated consumers avoid the dependency.
6. [ ] Add wrapper tests for event forwarding and property assignment.
7. [ ] Add a package-size or import-graph assertion if dependency removal lands.
8. [ ] Resolve root-export vs subpath-export ownership before changing wrapper
   imports.

Acceptance criteria:

1. [ ] React drawer callbacks fire for emitted drawer events.
2. [ ] React wrappers expose typed props matching custom-element properties.
3. [ ] The retained wrapper design has an explicit dependency-size rationale.
4. [ ] Root exports or subpath exports match the resolved wrapper decision.

## Phase 8: Docs, Guards, And Completion

Finish by deleting old paths, updating docs, and locking the architecture.

Tasks:

1. [ ] Delete old implementation folders after their replacement phases land:
   - `lit-components/Drawer/`
   - `lit-components/HaloBorder/`
   - `lit-components/PasskeyHaloLoading/`
   - `lit-components/TxTree/`
   - `lit-components/IframeTxConfirmer/`
   - `lit-components/ExportPrivateKey/`
2. [ ] Delete obsolete tests and fixtures for optional-bag confirm state.
3. [ ] Remove source-guard allowlist entries whose old paths are gone.
4. [ ] Update:
   - `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/README-lit-elements.md`
   - `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/css/README-css-vars.md`
   - public SDK React docs where wrappers change
5. [ ] Document wallet-origin customization limits:
   - typed appearance data
   - safe copy/display fields
   - no app render callbacks
   - no HTML strings
   - no scriptable templates
6. [ ] Document future public UI subpaths as candidates only:
   - `@seams/sdk/ui/tx-tree`
   - `@seams/sdk/ui/drawer`
   - `@seams/sdk/ui/halo-border`
   - `@seams/sdk/ui/confirm-shell`
   - `@seams/sdk/ui/types`
7. [ ] For each deleted old folder, prove cutover with:
   - no production imports from the old folder
   - no tests importing the old folder
   - no registry entries loading the old folder
   - no build entrypoint referencing the old folder
   - no source-guard allowlist entry for the old folder

Acceptance criteria:

1. [ ] Old implementations are gone.
2. [ ] Source guards pass without stale allowlist entries.
3. [ ] Lit docs describe the final module graph and appearance contract.
4. [ ] Wallet-origin customization limits are explicit.
5. [ ] Cutover proof exists for every deleted old folder.

## Validation Matrix

Use the cheapest check that covers the changed phase.

Phase 0:

```sh
pnpm -C packages/sdk-web type-check
```

Phase 0A:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
pnpm -C tests test:wallet-iframe
```

Phase 1:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
pnpm -C tests test:wallet-iframe
```

Phases 2 and 3:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
```

Phases 4 and 5:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
```

Phase 6:

```sh
pnpm -C packages/sdk-web build:prod
pnpm -C packages/sdk-web check:bundle-size
pnpm -C packages/sdk-web size:lite:check
pnpm -C packages/sdk-web check:static-wallet-assets
```

Phase 7:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
```

Phase 8:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests test:lit-components
pnpm -C tests test:wallet-iframe
pnpm -C packages/sdk-web build:prod
```

Run `pnpm -C tests test:source-guards` when changing source guards or deleting
guard allowlists.

## Completion Criteria

This refactor is complete when:

1. [ ] Export-key iframe secret transfer uses typed, source/origin/channel
   checked messages.
2. [ ] Active confirmer rendering is driven by discriminated unions with
   required branch fields.
3. [ ] Transaction display and tree node types reject invalid branches at
   compile time.
4. [ ] Modal and drawer share domain/rendering logic.
5. [ ] Drawer and TxTree lifecycle cleanup is tested.
6. [ ] Appearance has one normalized SDK state and derived runtime writes.
7. [ ] Wallet iframe customization boundaries reject scriptable app rendering.
8. [ ] Production Lit assets are measured and budgeted.
9. [ ] Production Lit assets do not include Lit development modules.
10. [ ] React wrappers match the custom-element event contract.
11. [ ] Old implementations and obsolete tests are deleted.
12. [ ] Documentation matches current repo paths and final architecture.

## Open Decisions To Resolve Before Implementation

| Decision | Blocks | Resolution point |
| --- | --- | --- |
| Should `w3a-tx-confirmer.js` remain the only public transaction confirmer entrypoint, or should modal/drawer direct entrypoints be public? | Phase 6 asset graph and package exports | Before splitting entrypoints |
| Should ABI enrichment become a separate URL-loaded asset immediately, or only after size measurements justify it? | Phase 6 build graph and asset-base tests | After Phase 0 size baseline |
| Should dev SDK packaging use production Lit runtime for closer size parity? | Phase 6 build-prod/build-sdk changes | Before editing build scripts |
| Should React wrappers stay root exports or move behind explicit subpaths? | Phase 7 wrapper exports and dependency graph | Before wrapper import changes |
| Which source-guard allowlist format should Lit use so Phase 0 can pass while blocking new bad patterns? | Phase 0 source guard implementation | Resolved by the Source Guard Allowlist Contract above unless implementation finds a repo-standard alternative |

Phase 0 can start with only the source-guard allowlist decision settled. Phase
0A and Phase 1 can start before asset-entrypoint, ABI-split, and React-wrapper
export decisions are final.

## Future Work

### UI Prefix Rename

Rename retained `w3a` UI tags, CSS variables, classes, event names, asset names,
and docs to `seams` in a separate refactor.

### Checkout Display Context

A future checkout context can be a display-only discriminated union. It must not
override signed transaction model, security context, auth mode, or final signing
result.

### Headless Confirmation API

A future direct-browser API can expose typed confirmation state for app-owned UI.
Wallet iframe mode can expose app-owned preview state only; wallet-origin final
confirmation keeps typed customization data and SDK-owned rendering.
