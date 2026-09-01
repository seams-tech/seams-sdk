# Refactor 119: Wallet-Origin Settings App

Date created: August 29, 2026

Status: proposed implementation plan.

## Decision

Add a first-party settings application to the dedicated wallet origin. Serve
the application at `/` and `/settings`; keep `/wallet-service` as the separate
embeddable iframe document.

Enable the application only for a deployment profile that has proven the
top-level settings document and embedded wallet document use the same browser
storage bucket. Cross-site hosted wallet origins commonly receive partitioned
IndexedDB, so matching URL origins alone is insufficient. A partitioned
deployment renders a stable unavailable page and omits the launcher link until
an explicit wallet-authority handoff design lands.

The settings application owns the complete settings experience currently
spread across `AccountMenuButton`, its expandable rows, React modals, and the
app-origin QR scanner. It renders with Lit and runs against one wallet-origin
`SeamsWeb` instance. React stays absent from the wallet-origin production graph.

In the enabled shared-storage profile, keep `AccountMenuButton` as a compact
app-origin launcher with two actions:

1. **Wallet settings** opens `${walletOrigin}/settings` in a new tab.
2. **Lock wallet** locks the wallet and closes the menu.

Remove the remaining settings rows and app-origin settings workflows at
cutover. Headless public capabilities remain available for custom product
interfaces.

## Goal

Give every hosted wallet one canonical management surface that works without a
dapp page:

```text
user visits wallet origin
  -> settings document loads same-origin public runtime configuration
  -> wallet origin discovers known wallet locators
  -> user selects and unlocks a wallet when required
  -> settings app derives authority from the authenticated Wallet Session
  -> user manages accounts, security, devices, and transaction preferences
```

Opening settings from an application follows the same path:

```text
AccountMenuButton
  -> https://wallet.example/settings#/overview
  -> standalone wallet-origin runtime
  -> existing wallet-origin records and authentication ceremonies
```

The URL may select a settings destination. It grants no wallet authority. The
authenticated Wallet Session remains the only source of the active wallet
identity for privileged operations.

## Dependencies And Scope

This refactor builds on:

- Refactor 86 for the static wallet-origin asset and header manifests;
- Refactor 108 for existing compact iframe surfaces;
- Refactor 109D for device inventory, linking, and revocation operations;
- Refactor 110 for the React-free wallet-origin Lit runtime and auth menu;
- Refactor 113 for fresh verification before recovery-code reveal.

The shell, accounts, devices, preferences, export, and launcher migration can
land independently of Refactor 113. The Recovery Codes action must retain its
existing flow until Refactor 113 lands, then call the hardened public operation.
Refactor 119 must not create a second recovery authorization path.

This plan owns:

- the standalone wallet settings document and runtime entry;
- the versioned, public, same-origin settings bootstrap contract;
- wallet discovery, selection, unlock, and authenticated settings lifecycle;
- Lit settings navigation and content views;
- moving product settings workflows out of app-origin React;
- the compact React launcher and its breaking prop cleanup;
- cross-document lock and preference synchronization on the wallet origin;
- static asset, deployment header, documentation, and test updates.

This plan does not add transaction history, asset balances, sending, swapping,
onboarding, application authentication, or a general wallet dashboard.

## Storage-Partitioning Release Gate

Refactor 86 records the unresolved browser behavior: wallet-origin IndexedDB
and sealed material can be partitioned by top-level site. A wallet iframe under
an application and a directly visited wallet page may therefore share an
origin string while seeing different records and `BroadcastChannel` scopes.

Refactor 119 must not infer storage continuity from hostname comparison. Its
public bootstrap contains a required deployment capability:

```ts
type StandaloneWalletSettingsAvailability =
  | { readonly kind: 'shared_wallet_origin_storage_v1' }
  | {
      readonly kind: 'disabled_partitioned_storage_v1';
      readonly reason: 'cross_site_storage_partition';
    };
```

Before enabling the first branch, run a real-browser matrix that writes an
opaque sentinel in the embedded wallet document and reads it from the
top-level settings document, then repeats in the other direction. Cover the
supported Chrome, Safari, and Firefox versions for:

- a same-site dedicated wallet origin;
- the managed cross-site wallet origin;
- normal and private browsing where supported.

The sentinel contains no wallet data and is deleted after the probe. The
matrix also proves `BroadcastChannel` scope between the two documents.

The first Refactor 119 release supports only
`shared_wallet_origin_storage_v1`. For the disabled branch:

- `/` and `/settings` explain that standalone management is unavailable for
  this deployment;
- `AccountMenuButton` retains Lock wallet and does not render Wallet settings;
- embedded wallet behavior remains unchanged.

A future cross-partition design may use an explicit device-link or encrypted
wallet-authority handoff. Copying IndexedDB rows, holder material, Wallet
Session tokens, or custody seeds between partitions is outside this refactor.

## Required Invariants

1. Standalone management is enabled only for the proven shared-storage
   deployment branch. Partitioned deployments fail closed as described above.
2. `/wallet-service` remains the only embeddable wallet document. `/` and
   `/settings` use `frame-ancestors 'none'`.
3. The standalone settings graph contains no React, ReactDOM, app-origin
   context, parent callback, or `MessagePort` dependency.
4. The embedded host and standalone app share wallet-origin domain services.
   They have separate document entries and presentation lifecycles.
5. Raw bootstrap JSON, URL fragments, query values, persisted rows, camera
   results, and network responses are parsed once at their boundaries.
6. A URL wallet locator can preselect an unlock ceremony. It cannot establish
   an authenticated wallet or authorize a settings operation.
7. Privileged settings functions require an authenticated Wallet Session for
   the exact wallet. `preferences.getCurrentWalletId()` remains display and
   selection state only.
8. Recovery codes and exported key material stay inside wallet-origin surfaces.
   They never enter the opener, app-origin state, analytics, URLs, logs, or
   cross-document synchronization messages.
9. Authentication-method addition, removal, device revocation, recovery-code
   reveal, and key export reuse the existing domain operations and proof
   requirements.
10. Within the shared-storage profile, locking from any wallet document clears
    volatile wallet authority in every live wallet document that receives the
    lock event.
11. Within the shared-storage profile, transaction preference writes become
    visible to live iframe hosts and parent preference mirrors without a
    reload.
12. The production wallet-origin graphs remain React-free and keep current
    worker, WASM, and key-isolation boundaries.
13. The old React settings modals, expanded menu sections, QR product flow,
    props, styles, tests, and fixtures are deleted after cutover.

## Current State

The current settings experience is app-origin React:

- `packages/wallet/src/react/components/AccountMenuButton/index.tsx` builds the
  flat menu, derives account explorer rows, starts export and recovery flows,
  edits preferences, and owns local modal state;
- `ProfileDropdown.tsx` renders expandable Accounts, Export Keys, and
  Transaction Settings sections;
- `AuthenticationMethodsModal.tsx` loads the active device authority and runs
  add/revoke operations;
- `LinkedDevicesModal.tsx` loads the wallet device inventory and runs
  factor-backed revocation;
- `QRCodeScanner` owns the app-origin camera and device-link scanner flow;
- the wallet iframe already owns IndexedDB, authentication ceremonies,
  workers, recovery-code display, export display, preferences, and the actual
  signing runtime;
- `/wallet-service` receives runtime configuration through `PM_SET_CONFIG` and
  waits for a parent connection;
- the static wallet asset build emits `/wallet-service`, `/sdk/*`, worker
  assets, and route header metadata. It emits no top-level wallet application.

This split gives the app document substantial wallet-management UI and leaves
the wallet origin without a direct product surface. It also duplicates
presentation lifecycle around operations that already execute on the wallet
origin.

## Product Information Architecture

### Routes

Use one static settings document and fragment routing. Fragment routes survive
reloads on plain static hosting and require no SPA rewrite rule.

```text
/                         canonical direct entry; renders Overview
/settings                 canonical link target from applications
/settings#/overview
/settings#/accounts
/settings#/security
/settings#/security/authentication
/settings#/security/recovery
/settings#/security/export
/settings#/devices
/settings#/devices/link
/settings#/transactions
```

Both HTML documents load the same settings entry. Navigation normalizes the
current destination to an exact union:

```ts
type WalletSettingsDestination =
  | { readonly section: 'overview' }
  | { readonly section: 'accounts' }
  | {
      readonly section: 'security';
      readonly panel: 'summary' | 'authentication' | 'recovery' | 'export';
    }
  | { readonly section: 'devices'; readonly panel: 'list' | 'link' }
  | { readonly section: 'transactions' };
```

Unknown or malformed fragments resolve to `overview`. Route parsing never
returns a partial destination or arbitrary string.

### Page Structure

The top-level navigation contains four product groups:

- **Accounts** — configured chain accounts and explorer links;
- **Security** — authentication methods, recovery codes, and key export;
- **Devices** — device inventory, removal, and the Link a device action;
- **Transaction preferences** — confirmation mode, click behavior, and delay.

The header shows the wallet ID, resolved account display data, lock status, and
the Lock wallet action. Export receives destructive visual treatment inside
Security. It does not appear as a primary navigation destination.

“Scan and Link Device” becomes the primary action on the Devices page. It no
longer competes with “Linked Devices” as a peer navigation row.

### Adaptive Layout

Use the existing wallet appearance tokens and plain wallet CSS.

- Wide containers render a navigation rail and one content column.
- Narrow containers render a page header, section list, and routed detail view
  in document order.
- The layout changes when the rail plus readable content column no longer fit;
  it does not depend on a device-name breakpoint.
- Text and controls remain inside logical inline margins and safe-area insets.
- Group sections primarily with space. Inter-group spacing is at least twice
  the spacing within a group.
- Content containers use max widths and wrapping. Fixed heights are forbidden
  for rows containing user, device, account, or translated text.
- The page reflows at 320 CSS pixels and 200% zoom without horizontal document
  scrolling.

## Standalone Runtime Architecture

### Separate Document Entries

Add a dedicated production entry such as:

```text
packages/wallet/src/SeamsWeb/walletSettings/index.ts
  -> bootstrap standalone document
  -> fetch and parse wallet runtime config
  -> create wallet-origin SeamsWeb runtime
  -> mount <seams-wallet-settings-app>
```

Keep the existing embedded entry:

```text
packages/wallet/src/SeamsWeb/walletIframe/host/index.ts
  -> transparent iframe bootstrap
  -> CONNECT / MessagePort
  -> PM_SET_CONFIG
  -> request router and foreground surfaces
```

Do not select these modes with `window.top === window` inside one entry. The
HTML document selects one precise runtime at build time.

Extract the narrow wallet-origin runtime construction currently embedded in
`walletIframe/host/context.ts` so both entries can create `SeamsWeb` with:

- canonical wallet-origin IndexedDB;
- nested iframe routing disabled;
- same-origin worker and WASM asset resolution;
- normalized runtime configuration;
- appearance and lifecycle subscriptions;
- explicit disposal.

The shared constructor contains no parent messaging, transparent-document
styles, overlay geometry, or standalone navigation.

### Public Bootstrap Contract

The standalone document has no parent to send `PM_SET_CONFIG`. Require one
deployment-owned, public, same-origin document:

```text
GET /wallet-runtime-config.json
Cache-Control: no-store
Content-Type: application/json
```

The fetched value is untrusted. Parse it into a precise internal
`WalletOriginRuntimeConfig` before constructing `SeamsWeb`:

```ts
type WalletOriginRuntimeConfig = {
  readonly kind: 'wallet_origin_runtime_config_v1';
  readonly standaloneSettings: StandaloneWalletSettingsAvailability;
  readonly chains: readonly ChainConfig[];
  readonly relayer: RelayerConfig;
  readonly relayerAccount: string;
  readonly registration: RegistrationConfig;
  readonly signing: WalletOriginSigningConfig;
  readonly webauthn: WalletOriginWebAuthnConfig;
  readonly appearance: AppearanceConfig;
  readonly assetsBaseUrl: string;
};
```

The actual implementation should reuse the repository's normalized config
types and builders. The shape above records the ownership boundary. All fields
needed by the deployed feature set are required after parsing. Truly unused
feature configuration stays absent through a discriminated capability branch
instead of an optional bag.

The document contains public browser runtime values only. It must never contain
API secrets, Wallet Session tokens, custody material, provider client secrets,
server shares, console credentials, or application sessions.

Add one deployment helper that derives this JSON from the same normalized
public configuration used by the embedding application. Repo-owned deployments
and examples must call that helper. Do not add environment-variable reads to
the browser entry or accept runtime configuration from URL parameters.

Bootstrap failures render a stable wallet-origin error page with release and
public error code. They never fall back to direct defaults or wait for a parent.
The disabled partitioned-storage branch renders its specific unavailable state
without constructing `SeamsWeb` or reading a different storage bucket.

### Settings Lifecycle

Model the application controller as an exhaustive union:

```ts
type WalletSettingsAppState =
  | { readonly state: 'loading_config' }
  | { readonly state: 'discovering_wallets'; readonly runtime: WalletOriginRuntime }
  | {
      readonly state: 'choosing_wallet';
      readonly runtime: WalletOriginRuntime;
      readonly wallets: readonly WalletLocator[];
    }
  | {
      readonly state: 'locked';
      readonly runtime: WalletOriginRuntime;
      readonly wallet: WalletLocator;
    }
  | {
      readonly state: 'unlocking';
      readonly runtime: WalletOriginRuntime;
      readonly wallet: WalletLocator;
    }
  | {
      readonly state: 'ready';
      readonly runtime: AuthenticatedWalletOriginRuntime;
      readonly destination: WalletSettingsDestination;
    }
  | { readonly state: 'fatal'; readonly code: WalletSettingsFatalCode };
```

`AuthenticatedWalletOriginRuntime` is built only from a successfully parsed
authenticated Wallet Session. Privileged page controllers accept that narrow
branch. They cannot accept a locator, current preference, or signed-out
session.

Discovery uses `auth.getRecentUnlocks()` and the current authenticated session:

1. Use the exact authenticated wallet when one is active.
2. Use the last-used local wallet as the default locked locator.
3. Show a chooser when several local locators exist and no active session
   selects one.
4. Show a signed-out state when the origin has no known wallet locator. This
   state may accept a wallet ID as an unlock locator through an explicitly
   labeled form; it does not add registration in Refactor 119.

After selection, call the existing `auth.unlock(walletId)` operation. A
successful result must be reread through `auth.getWalletSession(walletId)` and
parsed before the controller enters `ready`.

## Feature Ownership

### Accounts

Build account rows from authenticated wallet identity plus configured chain
metadata. Reuse `resolvePrimaryExplorerUrl` and the existing precise NEAR and
EVM-family identity helpers. External explorer navigation uses native anchors
with `target="_blank"` and `rel="noopener noreferrer"`.

The page displays only configured accounts that resolve for the authenticated
wallet. Missing or pending provisioning is an explicit status branch.

### Security

Move the current authentication-method inventory and add/revoke lifecycles out
of `AuthenticationMethodsModal.tsx`. Keep their domain decisions in
framework-independent standalone functions and render them in Lit.

The Security page provides:

- current device authority and its active methods;
- Add passkey and Add Email OTP actions when supported;
- exact removal confirmation with the existing last-method protection;
- recovery-code status and the existing backup/reveal operation;
- NEAR and EVM-family key export choices based on resolved lanes.

Passkey creation starts from the wallet-origin button activation. Email OTP
forms keep exact challenge identity and use the existing operation. Export
continues through the wallet-origin confirmer and key viewer. Plaintext export
and recovery values never become properties of the settings application
element.

### Devices

Move device inventory projection, removal lifecycle, and proof collection out
of `LinkedDevicesModal.tsx`. Keep the existing server operations and proof
bindings.

Port the QR camera/decoder shell to a wallet-origin Lit view. Reuse the existing
decoder and device-link domain functions where they are framework-independent.
The scanned payload crosses one parser and enters the Refactor 109D target flow
as a typed link invitation.

Camera permission denial, unsupported decoding, invalid QR content, expired
invitation, cancellation, and successful linking are distinct result branches.
Stopping or leaving the link route always stops active media tracks.

### Transaction Preferences

Read and write the existing `ConfirmationConfig` through
`seams.preferences`. Preserve its current valid combinations and names:

- UI mode;
- `requireClick` or `skipClick` behavior;
- auto-proceed delay.

Use a precise form state derived from a complete `ConfirmationConfig`. Avoid a
second settings schema and avoid optimistic object spreads over partial domain
state. Write the narrow patch through the established preference methods, then
render the confirmed complete value.

### Lock

The standalone header and React launcher both call the existing lock operation.
Add a small same-origin `BroadcastChannel` coordinator for state that must
update live wallet documents in the proven shared-storage profile:

```ts
type WalletOriginDocumentEvent =
  | {
      readonly kind: 'wallet_locked_v1';
      readonly eventId: WalletOriginDocumentEventId;
      readonly emittedAtMs: number;
    }
  | {
      readonly kind: 'confirmation_preferences_changed_v1';
      readonly eventId: WalletOriginDocumentEventId;
      readonly walletId: WalletId;
      readonly emittedAtMs: number;
    };
```

Messages carry no tokens, proofs, keys, recovery data, device invitations, or
raw preference objects. A preference event tells each runtime to reload the
authoritative wallet-origin preference record and emit its established local
subscription. A lock event clears hosted session handles and calls the local
lock path once without rebroadcasting.

Close and dispose the channel with each document runtime. Deduplicate exact
event IDs and ignore malformed events.

## React Launcher Cutover

`AccountMenuButton` remains an app-origin React convenience component. Reduce
its implementation to:

- profile trigger and wallet identity display;
- a native Wallet settings link derived from configured wallet origin;
- Lock wallet;
- controlled open/close state and normal styling hooks.

The settings link uses `target="_blank"` and `rel="noopener noreferrer"`. It is
unavailable with a clear configuration error when no hosted wallet origin
exists.

Delete props used only by the removed settings implementation, including
explorer overrides, export callbacks, QR-scanner callbacks, portal targets,
highlighted settings rows, and menu-specific toggle colors. Preserve a prop
only when the compact launcher still consumes it. Update public declarations,
examples, and consumers in the same cutover; add no deprecated alias or hidden
compatibility branch.

Custom apps continue to use the public `seams.auth`, `seams.keys`,
`seams.recovery`, `seams.registration`, `seams.devices`, and
`seams.preferences` capabilities for custom management UI.

## Static Assets And Security Headers

Extend the static build with:

```text
dist/public/index.html
dist/public/settings/index.html
dist/public/sdk/wallet-settings-app.js
dist/public/sdk/wallet-settings.css
```

Both settings HTML documents contain external styles and scripts only. They use
normal opaque page styles; `wallet-service.css` keeps the embedded document
transparent.

Add settings document routes to `wallet-assets.manifest.json` and split document
header classes in `headers.manifest.json`:

- `/wallet-service`: existing authorized `frame-ancestors` policy and current
  iframe-compatible cross-origin headers;
- `/` and `/settings`: `frame-ancestors 'none'`,
  `Cross-Origin-Opener-Policy: same-origin`, `Referrer-Policy: no-referrer`,
  `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`;
- `/wallet-runtime-config.json`: JSON MIME and `Cache-Control: no-store`.

Do not apply the standalone COOP policy to `/wallet-service`. Preserve the
existing iframe embedding and WebAuthn delegation behavior.

The launcher computes the settings URL from the normalized wallet origin. It
never accepts a full settings URL from arbitrary component input.

## Accessibility Contract

- Use native anchors for section navigation and external accounts; use native
  buttons for actions.
- Render one `main`, one page `h1`, coherent section headings, and a first-focus
  skip link when navigation precedes content.
- Route changes update the document title, move focus to the detail heading,
  and announce the new section through a stable polite status region.
- Every control has a visible label or accessible name. Decorative icons are
  hidden from assistive technology.
- Use `:focus-visible` with a visible two-pixel-or-equivalent indicator and
  preserve forced-colors behavior.
- Controls meet at least the 24-by-24 CSS-pixel WCAG target baseline; touch
  actions aim for 44 by 44 pixels without overlapping hit areas.
- Forms validate on submit, focus the first invalid field, and connect inline
  errors with `aria-invalid` and `aria-describedby`. Paste remains enabled for
  OTP input.
- Destructive confirmations use an explicit heading and two clearly named
  actions. Focus returns to the initiating control after dismissal.
- Camera state and async operation progress use stable polite announcements.
  Urgent failures use an alert and retain actionable error text until the user
  dismisses it or retries.
- Motion runs only under `prefers-reduced-motion: no-preference`; reduced-motion
  mode has no sliding navigation or pulsing status animation.
- Every flow remains operable with keyboard only at 320 CSS pixels and 200%
  zoom.

## Implementation Phases

### Phase 0: Contract And Behavior Baseline

1. Run the storage-bucket and `BroadcastChannel` matrix defined by the release
   gate. Record supported deployment/browser combinations.
2. Add the required standalone-settings availability branch to the bootstrap
   contract. Keep managed cross-site hosting disabled unless the matrix proves
   shared storage.
3. Add the standalone wallet-settings behavior to
   `docs/intended-behaviours.md`.
4. Record current wallet host, React profile entry, and static asset bundle
   sizes.
5. Inventory every `AccountMenuButton` consumer and current public prop.
6. Classify existing tests before editing:
   - settings behavior that moves to the wallet origin is
     `valid_test_needs_update`;
   - React modal DOM, expandable-row animation, portal, and source-shape tests
     are `obsolete_test_or_fixture`;
   - failures in the existing domain operations remain potential
     `production_regression` findings.
7. Freeze the exact route union, bootstrap schema, and document header classes.

Exit criterion: at least one supported deployment profile proves shared
storage across the embedded and top-level documents, and every deleted React
behavior has an explicit owner. If no supported profile passes, stop Refactor
119 before production UI work and write the separate authority-handoff plan.

### Phase 1: Wallet-Origin Runtime And Static Documents

1. Extract the framework-neutral wallet-origin runtime constructor from the
   iframe host context.
2. Add the bootstrap JSON parser and versioned internal config type.
3. Add the standalone entry, fatal bootstrap view, and runtime disposal.
4. Emit `/`, `/settings`, settings JS/CSS, and route-specific header metadata.
5. Add the repo-local `/wallet-runtime-config.json` deployment fixture through
   the shared config emitter.
6. Extend static asset and runtime-entry bundle checks. Fail when the settings
   entry imports React, ReactDOM, app React context, iframe client routing, or a
   parent-message adapter.

Exit criterion: visiting the wallet origin renders a React-free standalone
shell from valid same-origin config, while `/wallet-service` still completes
its existing handshake.

### Phase 2: Authenticated Shell And Navigation

1. Implement the application lifecycle union and boundary builders.
2. Discover recent wallet locators and resolve the exact active Wallet Session.
3. Add wallet selection, locked, unlocking, ready, empty, and fatal views.
4. Implement fragment parsing, semantic navigation, responsive shell, focus
   movement, document titles, and route announcements.
5. Add Overview and Accounts using authenticated identity only.
6. Add exact type fixtures rejecting direct construction of `ready` from a
   locator, current preference, raw session, or broad object spread.

Exit criterion: a known wallet can be unlocked and its Accounts page opened by
direct navigation, with no parent window or app-origin state.

### Phase 3: Preferences And Cross-Document State

1. Implement the Transaction Preferences page with existing preference APIs.
2. Add the exact same-origin document event parser and coordinator.
3. Reload preferences on cross-document preference events.
4. Propagate lock across settings pages and live iframe hosts without loops.
5. Prove parent preference mirrors receive the established
   `PREFERENCES_CHANGED` event after a settings-page write.

Exit criterion: a setting changed in the standalone page affects the next
confirmation and is reflected in an already-open application; standalone lock
invalidates a live embedded host.

### Phase 4: Security And Devices

1. Move authentication-method inventory and lifecycle decisions into
   framework-independent wallet-origin modules.
2. Implement Lit authentication, recovery, and export views.
3. Move linked-device inventory and revocation lifecycle out of React.
4. Port the QR scanner presentation to Lit and reuse the existing decoder and
   Refactor 109D link operation.
5. Add route-leave cleanup for camera tracks, challenges, prepared operations,
   plaintext surfaces, and listeners.
6. Keep recovery reveal behind the Refactor 113 operation; delete any older
   unrestricted read path when that dependency lands.

Exit criterion: every former menu workflow completes from the standalone
wallet-origin page and sensitive values remain within their existing guarded
surfaces.

### Phase 5: Compact Launcher And Deletion

1. Reduce `AccountMenuButton` to Wallet settings and Lock wallet.
2. Update `apps/seams-site` and docs examples to the reduced props.
3. Delete React expandable sections, Authentication Methods modal, Linked
   Devices modal, app-origin product QR scanner usage, obsolete icons/styles,
   and settings-only helpers.
4. Delete deprecated component props, aliases, fixtures, and tests in the same
   change. Retain `ProfileSettingsButton` only if it remains an intentional
   current name for the compact launcher; otherwise remove it and update all
   consumers.
5. Replace the old linked-device operating-path selectors with wallet-settings
   page behavior. Delete modal implementation tests instead of recreating their
   DOM assertions around Lit.

Exit criterion: the app document offers one settings link and one lock action;
there is one product settings UI implementation.

### Phase 6: Deployment, Documentation, And Broad Verification

1. Update hosted integration docs with the root/settings routes, public config
   document, distinct framing policies, and direct-release smoke.
2. Update theming docs for the standalone page and wallet-origin appearance.
3. Update package README and React reference for the launcher breaking change.
4. Add local Caddy/static routes without changing unrelated deployment work.
5. Run focused tests first, then the intended behavior, source guard, type,
   build, bundle, and static asset gates.

Exit criterion: repo-local and hosted deployment documentation can serve and
verify both document modes from one wallet origin.

## Primary Code Map

Expected new or extracted ownership:

```text
packages/wallet/src/SeamsWeb/walletOrigin/
  runtime.ts                         shared wallet-origin SeamsWeb construction
  runtimeConfig.ts                   bootstrap parser and normalized config
  documentEvents.ts                  lock/preference BroadcastChannel contract

packages/wallet/src/SeamsWeb/walletSettings/
  index.ts                           standalone production entry
  controller.ts                      exhaustive application lifecycle
  routes.ts                          fragment parser and route builders
  seams-wallet-settings-app.ts       Lit application shell
  settings.css                       opaque responsive page styles
  accounts.ts                        authenticated account projection
  security.ts                        auth/recovery/export lifecycle
  devices.ts                         device inventory/link lifecycle
  preferences.ts                     complete confirmation-config form state
```

Expected existing owners to change:

```text
packages/wallet/src/SeamsWeb/walletIframe/host/context.ts
packages/wallet/src/SeamsWeb/walletIframe/host/index.ts
packages/wallet/src/SeamsWeb/walletIframe/host/hostedWalletSeamsSession.ts
packages/wallet/src/react/components/AccountMenuButton/
packages/wallet/scripts/build/emit-static-wallet-assets.mjs
packages/wallet/scripts/checks/assert-static-wallet-assets.mjs
packages/wallet/scripts/checks/assert-runtime-entry-bundles.mjs
packages/wallet/rolldown.config.ts
apps/seams-site/src/components/SeamsProfileSettingsButton.tsx
apps/seams-site/Caddyfile
```

Use this map as routing guidance. Keep the implementation smaller when an
existing domain module already owns the exact operation. Do not add a generic
settings framework, client router dependency, state-management library, or
second UI registry.

## Testing Strategy

### Type And Unit Coverage

- bootstrap parsing rejects unknown versions, missing required capabilities,
  cross-origin asset bases, secrets, and malformed chain/runtime fields;
- the shared and partitioned availability branches reject each other's fields;
- route parsing is exhaustive and normalizes unknown fragments;
- locator, preference, raw session, and signed-out branches cannot construct an
  authenticated settings runtime;
- accounts derive from the authenticated wallet and configured chains;
- security and device state unions reject invalid concurrent operations;
- document events reject payload data beyond their exact branches and
  deduplicate event IDs;
- lock handling cannot rebroadcast indefinitely;
- preference events reload stored state instead of trusting message content.

### Lit Component Coverage

Add focused tests under `tests/lit-components/` for:

- overview and section navigation in light and dark appearance;
- one `h1`, landmarks, skip link, heading order, and native link/button roles;
- route focus, visible focus state hooks, and polite announcements;
- wallet chooser, locked, unlocking, ready, empty, and fatal views;
- authentication add/remove, recovery, export, devices, QR errors, and
  transaction preference states;
- form labels, invalid-field focus, described errors, and OTP paste behavior;
- reduced motion and route-leave camera cleanup.

### Wallet-Origin Browser Coverage

Add a dedicated settings browser suite under `tests/wallet-settings/` proving:

- `/` and `/settings` boot without a parent and `/wallet-service` still
  handshakes as an iframe;
- shared-storage profiles pass the bidirectional sentinel and document-channel
  probe; partitioned profiles render the unavailable state and no launcher
  link;
- standalone routes refuse framing while the configured app can frame
  `/wallet-service`;
- the settings document and static graph contain no React controls or imports;
- a known wallet unlocks and privileged actions bind to its authenticated
  session;
- an untrusted route or locator cannot change operation authority;
- export and recovery plaintext remain in wallet-origin guarded surfaces;
- camera tracks stop on success, cancellation, error, and navigation;
- settings lock clears a simultaneously open embedded wallet session;
- preference changes affect a simultaneously open iframe confirmation;
- direct external links have no opener and send no referrer.

### Existing Test Migration

- migrate the user-facing device and export paths in
  `tests/e2e/linked-device.operating-path.test.ts` to the wallet settings page;
- delete `tests/unit/linkedDevicesModal.unit.test.ts` after its still-valid
  domain cases move to neutral unit coverage;
- delete React menu DOM and animation tests that own the retired
  implementation;
- preserve Refactor 109D protocol and intended-behavior contracts;
- preserve wallet-iframe export, recovery, auth-menu, preference, and geometry
  coverage;
- update static wallet asset checks for both document classes.

### Verification Commands

Use the narrowest new test file during each phase. Run the broad gates after
the public React API, static asset contract, or wallet lifecycle changes:

```text
pnpm -C packages/wallet type-check
pnpm -C packages/wallet build:rolldown
pnpm -C packages/wallet check:runtime-entry-bundles
pnpm -C packages/wallet check:static-wallet-assets
pnpm -C packages/wallet check:bundle-size
pnpm test:lit-components
pnpm test:wallet-iframe
pnpm test:intended
pnpm test:source-guards
pnpm check
git diff --check
```

Add the dedicated wallet-settings Playwright command to `tests/package.json`
when the suite lands, then include it in the final gate.

Manual browser verification covers:

- keyboard-only completion of every settings flow;
- VoiceOver or another target screen reader for navigation, forms, dynamic
  status, and destructive confirmations;
- 320 CSS pixels, 200% zoom, long wallet/device/account strings, and RTL;
- light, dark, reduced-motion, and forced-colors modes;
- camera allow, deny, retry, and route-leave behavior;
- direct root visit, `/settings` visit, launcher-opened tab, and concurrent
  dapp iframe state.

## Deletion List

Delete after the corresponding Lit behavior passes:

- `ProfileDropdown` and settings-only menu item construction;
- `AccountsSection`, `ExportKeysSection`, and `TransactionSettingsSection`;
- `AuthenticationMethodsModal` and `LinkedDevicesModal` React implementations;
- app-origin product QR scanner mounting from `AccountMenuButton`;
- settings-only React icons, portal helpers, lifecycle hooks, CSS, props, and
  callbacks;
- fixtures and tests whose invariant is the retired React DOM, portal, or
  expansion behavior;
- docs that instruct applications to host wallet settings UI or pass settings
  workflow callbacks into `AccountMenuButton`.

Keep framework-independent QR decoding and exact domain decision helpers only
when the wallet-origin implementation uses them. Move each helper once and
delete its previous copy.

## Non-Goals

- A transaction/activity feed, portfolio, token balance, send, receive, swap,
  fiat, or dapp browser.
- New registration or account-recovery entry points on the settings root.
- Managing application profiles, application sessions, tenant settings, or
  console administration.
- Changing recovery-code formats, device-link protocol, key-export protocol,
  signing confirmation policy, or wallet custody proofs.
- Passing executable callbacks, app themes, parent DOM anchors, or arbitrary
  CSS across the wallet boundary.
- A router framework, service worker, offline shell, notification system, or
  general cross-tab event bus.
- Cross-partition storage migration, Storage Access API adoption, automatic
  device linking, or a wallet-authority handoff protocol.
- Compatibility rendering for the deleted full React settings menu.

## Acceptance Criteria

- In the enabled shared-storage profile, visiting the wallet origin root
  directly renders the wallet settings overview; `/settings` renders the same
  application. The disabled profile renders the explicit unavailable state.
- `/wallet-service` remains embeddable by configured applications and retains
  its current protocol handshake and foreground-surface behavior.
- `/` and `/settings` cannot be framed.
- The standalone settings runtime parses a versioned same-origin public config
  and fails closed on missing or invalid configuration.
- Standalone management is enabled only under the proven shared-storage
  capability branch; partitioned deployments expose no misleading settings
  link or empty-wallet experience.
- The settings and iframe host production graphs contain no React or ReactDOM.
- The page offers Accounts, Security, Devices, and Transaction Preferences with
  the information architecture defined above.
- All privileged actions derive wallet identity from an authenticated Wallet
  Session for the exact wallet.
- Authentication-method management, recovery-code backup/reveal, key export,
  device listing/linking/removal, explorer links, preference changes, and lock
  complete from the wallet-origin page.
- Recovery codes, exported keys, factor proofs, OTPs, session tokens, and device
  invitations never cross into app-origin state or document-event messages.
- A settings-page lock clears live same-origin iframe authority, and a settings
  preference write updates a live iframe without reload.
- `AccountMenuButton` contains only Wallet settings and Lock wallet; removed
  settings props and compatibility paths are absent.
- React settings modals, expandable sections, app-origin product QR flow, stale
  tests, and obsolete fixtures are deleted.
- The page completes every flow by keyboard, reflows at 320 CSS pixels and 200%
  zoom, preserves visible focus, labels forms, announces async state, and
  respects reduced motion.
- Focused type, Lit, wallet-settings, wallet-iframe, intended-behavior, static
  asset, bundle, source-guard, and repository checks pass.
