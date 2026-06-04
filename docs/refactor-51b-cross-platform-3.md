# Refactor 51b: Web Facade And Native Runtime Split

Date created: 2026-06-03
Status: implementation complete
Owner: SDK architecture

## Purpose

Refactor 51 established the cross-platform port model, signer-core command
ownership, browser adapter conformance, and native-readiness handoff. This plan
turns that readiness into a concrete SDK shape:

- rename the browser public facade from `SeamsPasskey` to `SeamsWeb`;
- extract a platform-neutral signing runtime that receives platform ports;
- remove browser IndexedDB assumptions from shared signing assembly;
- add distinct web, iOS, and embedded facade boundaries;
- keep wallet iframe routing out of native packages;
- record the production `seams.sh` relying-party identity across web and iOS
  passkeys through native Associated Domains without hardcoding it into local
  development defaults.

The intent is a breaking cleanup. No `SeamsPasskey` compatibility alias, legacy
flag, or dual facade should remain after the rename phase completes.

## Relationship To Existing Plans

This document extends:

- `docs/refactor-51-cross-platform-2.md`
- `docs/refactor-51-native-readiness.md`

Refactor 51 remains the source of truth for signer-core command schemas,
boundary parser rules, opaque ECDSA state blobs, platform adapter conformance,
and compatibility deletion policy. This plan owns the SDK facade split and the
native composition root.

## Current State

The lower SDK layers are already close to the target:

- `client/src/core/platform/types.ts` defines `PlatformRuntime`,
  `AuthenticatorPort`, `SignerCryptoPort`, `DurableRecordStore`,
  `HttpTransport`, `SecureSecretStore`, `ClockPort`, and `RandomSource`.
- `client/src/core/platform/browser/createBrowserPlatformRuntime.ts` wires the
  current browser adapter over IndexedDB, WebAuthn, workers, fetch, clock, and
  browser crypto.
- `tests/unit/platformAdapter.conformance.unit.test.ts` exports conformance
  helpers that browser and future native adapters must pass.
- `tests/unit/crossPlatformBoundaries.guard.unit.test.ts` protects
  `PlatformRuntime` and raw crypto material from leaking into use-case modules.

The remaining browser coupling is above and around those ports:

- `client/src/web/SeamsWeb/index.ts` is the public browser SDK facade and owns
  wallet iframe routing.
- `client/src/web/SeamsWeb/assembly/BrowserSigningSurface.ts` owns browser
  signing assembly state and exposes the structural `SeamsWebSigningSurface`.
- `client/src/core/runtime/createSigningRuntime.ts` builds platform-neutral
  runtime services from explicit platform, worker, store, UI, and relayer ports.
- Shared signing assembly receives explicit store ports; browser IndexedDB
  construction is isolated under `client/src/web/SeamsWeb/assembly/`.

## SDK Simplification Workstream

Treat the native/runtime split as a deletion and simplification pass. Each phase
should reduce the number of public concepts, dependency entrypoints, and
browser-shaped assumptions that future platforms must understand.

| Cleanup target | Owner phase | Expected simplification |
| --- | --- | --- |
| Browser facade naming | Phase 1 | `SeamsWeb` becomes the only browser public facade; old `SeamsPasskey` symbols, aliases, docs, and error prefixes are deleted. |
| Browser signing assembly surface | Phase 2 | `SigningRuntime` becomes the neutral composition root; `SeamsWeb` receives a structural `SeamsWebSigningSurface` from browser assembly. |
| Browser IndexedDB coupling | Phase 3 | Shared assembly receives explicit store ports instead of recovering `IndexedDBManager` from a browser runtime. |
| Wallet iframe routing | Phase 4 | Iframe routing becomes a web facade decorator; core chain signers and runtime services receive direct operation dependencies. |
| Runtime and web config | Phase 3, Phase 7 | Platform-neutral runtime config is split from `SeamsWeb` browser config, including `iframeWallet`, DOM UI, browser WebAuthn, and React settings. |
| `client/src/core/platform/types.ts` size | Phase 8 | Ports, secret-source builders, ECDSA role-local record types, HTTP types, and runtime aggregate types move into focused modules. |
| Package exports and metadata | Phase 7 | `sdk/package.json`, `client/src/index.ts`, and React entrypoints expose web-named APIs and reserve native roots without pulling browser chunks. |

Simplification rules:

- Delete obsolete wrappers, aliases, and tests in the same phase that replaces
  the behavior.
- Convert broad dependency bags into named port groups only when the port group
  is consumed by more than one operation or platform.
- Prefer grouped runtime services over long public capability member lists.
- Keep compatibility handling at request and persistence boundaries with an
  owner phase and deletion trigger.
- Split large files after dependencies point at the new boundaries, so file
  movement does not hide behavior changes.

## Target Architecture

```mermaid
flowchart TD
  WEB["SeamsWeb browser facade"] --> WEBASM["Web assembly"]
  REACT["SeamsWeb React facade"] --> WEB
  IFRAME["Wallet iframe router"] --> WEB

  IOS["SeamsIos facade"] --> NATIVEASM["Native assembly"]
  EMBED["SeamsEmbedded facade"] --> EMBEDASM["Embedded assembly"]

  WEBASM --> RUNTIME["SigningRuntime"]
  NATIVEASM --> RUNTIME
  EMBEDASM --> RUNTIME

  RUNTIME --> USECASES["Use-case services"]
  RUNTIME --> PORTS["Platform ports"]
  RUNTIME --> RELAYER["Relayer clients"]

  PORTS --> BROWSER["BrowserPlatformRuntime"]
  PORTS --> IOSPORTS["IosPlatformRuntime"]
  PORTS --> EMBEDPORTS["EmbeddedPlatformRuntime"]

  USECASES --> CORE["crates/signer-core commands"]
```

## Naming Contract

### Browser Names

`SeamsWeb` is the browser facade. It owns browser-only surfaces:

- DOM and React integration;
- WebAuthn through browser `navigator.credentials`;
- wallet iframe mode;
- wallet-origin deployment config;
- web-specific asset preconnect and embedded UI behavior;
- browser storage assembly.

Required renames:

| Current | Target |
| --- | --- |
| `SeamsPasskey` | `SeamsWeb` |
| `client/src/core/SeamsPasskey/` | `client/src/web/SeamsWeb/` or `client/src/core/SeamsWeb/` if the build cannot yet move the directory |
| `SeamsPasskeyProvider` | `SeamsWebProvider` |
| `SeamsPasskeyProviderProps` | `SeamsWebProviderProps` |
| `SeamsPasskeyProviderThemeProps` | `SeamsWebProviderThemeProps` |
| `PasskeyManagerContext` | `SeamsWebContext` |
| `SeamsPasskeyIframe` | `SeamsWebIframe` |
| `WalletIframeCoordinator.getSeamsPasskey` style names | `getSeamsWeb` |

Rules:

- The rename is hard. Do not export `SeamsPasskey` as an alias.
- Test names, docs, comments, and error prefixes move to `SeamsWeb`.
- Existing passkey/auth domain terms remain as domain vocabulary. Only the
  browser facade name changes.

### Platform-Neutral Names

Use `SigningRuntime` for the platform-neutral composition root. It owns:

- use-case construction;
- relayer clients;
- lifecycle orchestration;
- signing session restore and budget services once their dependencies are
  port-shaped;
- typed domain inputs and results.

`SigningRuntime` must not import:

- `WalletIframe`;
- React;
- DOM globals;
- `navigator`;
- `window`;
- `document`;
- `IndexedDBManager`;
- `createBrowserPlatformRuntime`;
- `getBrowserPlatformIndexedDB`.

## RP ID And iOS Passkey Contract

The production web wallet currently uses `seams.sh` as the relying-party
identity. Native iOS must use that same relying-party identifier for production
passkey interoperability with the web wallet, but the SDK must keep the current
localhost RP IDs for local development defaults. `seams.sh` is a deployment
contract, not a hardcoded SDK default.

Facts to encode in implementation docs and tests:

- iOS native passkeys use a domain string as the relying-party identifier.
- The app must prove authority for that domain through the Associated Domains
  entitlement and an `apple-app-site-association` file.
- The production iOS app must use `webcredentials:seams.sh`.
- `https://seams.sh/.well-known/apple-app-site-association` must contain the
  app identifier under the `webcredentials` service.
- The iOS `AuthenticatorPort` uses `ASAuthorizationPlatformPublicKeyCredentialProvider`
  with `relyingPartyIdentifier: "seams.sh"`.
- The server verifies the same WebAuthn artifacts as the web path: challenge,
  credential id, signature, `rawClientDataJSON`, authenticator data, expected
  origin policy, and `rpIdHash` for the configured RP ID.
- A `WKWebView` or `ASWebAuthenticationSession` path is an integration fallback.
  Native `AuthenticationServices` is the SDK happy path.

WebAuthn origin policy:

- Every server route that verifies passkey assertions or registrations must pass
  an expected origin or typed native-origin policy into the WebAuthn verifier.
  Letting the verifier default to the origin contained in `clientDataJSON` is a
  boundary gap for managed, wallet-origin, and native-sensitive flows.
- Browser and wallet-iframe routes should use the normalized request origin or
  the wallet-origin override already bound into the request.
- Native iOS routes should use a typed `ios_associated_domain` policy that binds
  the configured RP ID, Team ID, bundle ID, AASA app identifier, and expected
  native `clientDataJSON.origin` shape. The first native adapter spike must
  record the exact iOS origin string observed from `AuthenticationServices`
  before enabling production native verification.
- Route tests should fail if a passkey verifier call omits expected-origin or
  native-origin policy in registration, add-signer, session exchange, threshold
  ECDSA bootstrap, threshold Ed25519 session, and future native-auth routes.

External references:

- Apple `ASAuthorizationPlatformPublicKeyCredentialProvider.relyingPartyIdentifier`:
  https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider/relyingpartyidentifier
- Apple Associated Domains:
  https://developer.apple.com/documentation/Xcode/supporting-associated-domains
- Apple passkey sample:
  https://developer.apple.com/documentation/authenticationservices/connecting_to_a_service_with_passkeys
- WebAuthn RP ID and mobile app association:
  https://web.dev/articles/webauthn-rp-id
- WebAuthn Permissions Policy and RP ID rules:
  https://w3c.github.io/webauthn/

## Package Boundaries

### Web Package Boundary

The web build may import:

- `client/src/web/SeamsWeb/**`;
- `client/src/core/runtime/**`;
- `client/src/core/platform/browser/**`;
- `client/src/core/WalletIframe/**`;
- React packages through `client/src/react/**`.

The web build owns the default `@seams/sdk` export until native packages exist:

```ts
export { SeamsWeb } from './web/SeamsWeb';
```

React exports become:

```ts
export { SeamsWebProvider } from './react/context/SeamsWebProvider';
```

### Native Package Boundary

Future native packages may import:

- `client/src/core/runtime/**`;
- `client/src/core/platform/types.ts`;
- generated signer-core schemas;
- relayer route parsers and domain clients that have no browser imports;
- conformance fixtures that are explicitly platform-neutral.

Future native packages must not import:

- `client/src/web/SeamsWeb/**`;
- `client/src/core/WalletIframe/**`;
- `client/src/react/**`;
- `client/src/core/platform/browser/**`;
- browser plugins, browser asset paths, iframe host code, or DOM UI code.

### Embedded Package Boundary

The embedded package should prefer Rust-local code:

- signer-core through native Rust, C ABI, or authenticated local daemon;
- durable records in SQLite or atomic filesystem records;
- FIDO2 hmac-secret, TPM, kernel keyring, libsecret, or reviewed
  hardware-backed storage;
- bounded command payloads and no long-lived raw secret buffers.

Embedded packages must not depend on a browser iframe, `WKWebView`, React, or
browser storage semantics.

## Target File Layout

Use this layout unless a phase updates this table first.

| Area | Target location |
| --- | --- |
| Browser facade | `client/src/web/SeamsWeb/` |
| React provider | `client/src/react/context/SeamsWebProvider.tsx` |
| Wallet iframe browser modules | `client/src/web/SeamsWeb/walletIframe/` or existing `client/src/core/WalletIframe/` behind web-only guards |
| Platform-neutral runtime | `client/src/core/runtime/` |
| Runtime assembly entry | `client/src/core/runtime/createSigningRuntime.ts` |
| Runtime dependency types | `client/src/core/runtime/types.ts` |
| Browser runtime assembly | `client/src/web/SeamsWeb/assembly/createBrowserSigningRuntime.ts` |
| Runtime config types | `client/src/core/runtime/config.ts` |
| Web config types | `client/src/web/SeamsWeb/config.ts` |
| Platform ports | `client/src/core/platform/ports.ts` |
| Platform secret sources | `client/src/core/platform/secretSources.ts` |
| ECDSA role-local record types | `client/src/core/platform/ecdsaRoleLocalRecords.ts` |
| Platform HTTP transport types | `client/src/core/platform/http.ts` |
| Platform runtime aggregate | `client/src/core/platform/runtime.ts` |
| iOS adapter contract | `client/src/core/platform/ios/README.md` until native package exists |
| Embedded adapter contract | `client/src/core/platform/embedded/README.md` until native package exists |
| Platform import guards | `tests/unit/refactor51bPlatformBoundaries.guard.unit.test.ts` |
| Public rename guards | `tests/unit/refactor51bSeamsWebRename.guard.unit.test.ts` |
| RP ID contract tests/docs | `tests/unit/refactor51bRpIdContract.unit.test.ts` and this file |

## Implementation Phases

### Phase 0: Inventory And Guard Lock

Goals:

- inventory every `SeamsPasskey`, `PasskeyManagerContext`, `WalletIframe`,
  `createBrowserPlatformRuntime`, `getBrowserPlatformIndexedDB`, and
  `IndexedDBManager` reference that sits on an intended shared path;
- add failing guards before moving code.

Tasks:

- [x] Add `docs/refactor-51b-inventory.md` with rows for public exports, React
  exports, facade files, iframe files, signing assembly files, storage
  dependencies, and tests.
- [x] Add simplification inventory rows for:
  - [x] `client/src/core/SeamsPasskey/index.ts` public facade responsibilities;
  - [x] former `SigningEngine` constructor ownership and public member list;
  - [x] `client/src/core/signingEngine/assembly/createPorts.ts` browser storage
    assumptions;
  - [x] `client/src/core/platform/types.ts` type groups that should split after the
    runtime boundary is stable;
  - [x] `sdk/package.json`, `client/src/index.ts`, and `client/src/react/index.ts`
    export surfaces.
- [x] Add a guard that rejects `WalletIframe`, `SeamsWeb`, React, DOM globals, and
  browser platform adapter imports inside `client/src/core/runtime/**`.
- [x] Add a guard that rejects `SeamsPasskey` symbols after the rename phase.
- [x] Add a guard that rejects `getBrowserPlatformIndexedDB(...)` outside browser
  assembly.
- [x] Add a guard that rejects `client/src/core/WalletIframe/**` imports from
  future native or embedded package roots.
- [x] Use the existing source-guard allow-list pattern for expected current
  violations: every allow-list row must include an owner and reason, and the
  inventory must record the owner phase and deletion trigger.

Acceptance:

- Inventory exists and includes all known current coupling points.
- Inventory identifies which cleanups are deletion-only, rename-only, or
  behavior-preserving extraction work.
- New guards fail for unlisted violations. Expected current violations are
  listed with owner and reason fields, and the inventory records their owner
  phase and deletion trigger.

Validation:

- `pnpm -C tests run test:source-guards`
- targeted Playwright unit guard file

### Phase 1: Rename Browser Facade To SeamsWeb

Goals:

- make browser identity explicit before extracting native runtime;
- delete `SeamsPasskey` public symbols.

Tasks:

- [x] Rename `client/src/core/SeamsPasskey` to the chosen web facade path.
- [x] Rename exported class `SeamsPasskey` to `SeamsWeb`.
- [x] Rename `PasskeyManagerContext` to `SeamsWebContext`.
- [x] Rename React provider files and symbols from `SeamsPasskeyProvider` to
  `SeamsWebProvider`.
- [x] Rename `SeamsPasskeyIframe` to `SeamsWebIframe`.
- [x] Update `client/src/index.ts`, `client/src/react/index.ts`, `sdk/package.json`
  export descriptions, docs, README snippets, tests, and error prefixes.
- [x] Move `sdk/package.json` `./react/provider` to `SeamsWebProvider` in this
  phase because package consumers hit this export immediately after the rename.
- [x] Delete stale `sdk/package.json` `./components/modal` and
  `./components/embedded` WebAuthn manager exports unless current web-owned
  component paths replace them.
- [x] Delete all compatibility aliases and old symbol re-exports.
- [x] Delete passkey-manager naming in comments, provider examples, type names, and
  package descriptions unless the text refers to passkey authentication as a
  domain concept.
- [x] Rename or delete tests that only protect old `SeamsPasskey` public symbols.
- [x] Narrow the legacy-name guard allow-list to explicit historical refactor
  files and update active docs that still referenced `SeamsPasskey`.

Acceptance:

- `rg "SeamsPasskey|PasskeyManagerContext|SeamsPasskeyProvider|SeamsPasskeyIframe"`
  returns only this plan, explicitly allow-listed historical docs, and guard
  fixtures.
- Public import examples use `SeamsWeb`.
- Wallet iframe host creates a `SeamsWeb` instance.
- No public package entrypoint exports `SeamsPasskey`, `SeamsPasskeyProvider`,
  or `PasskeyManagerContext`.

Validation:

- `pnpm -C sdk type-check`
- `pnpm -C tests run test:unit -- ./unit/refactor51bSeamsWebRename.guard.unit.test.ts`
- existing wallet iframe unit tests that cover host/client routing

### Phase 2: Extract SigningRuntime

Goals:

- make `SigningRuntime` the platform-neutral composition root;
- stop constructing `createBrowserPlatformRuntime(...)` inside shared signing
  code.

Target contract:

```ts
type SigningRuntimeDeps = {
  platformRuntime: PlatformRuntime;
  relayers: SigningRuntimeRelayerClients;
  ui: SigningRuntimeUiPorts;
  config: SigningRuntimeConfig;
};

function createSigningRuntime(deps: SigningRuntimeDeps): SigningRuntime;
```

Rules:

- `SigningRuntime` receives `PlatformRuntime`.
- `PlatformRuntime.storage` is the only low-level durable storage entrypoint on
  the runtime dependency aggregate. Domain-specific store adapters may be built
  in platform/web assembly and passed through named service dependencies, but
  `SigningRuntimeDeps` must not contain a second generic `stores` bag.
- Browser code calls `createBrowserPlatformRuntime(...)` only in browser
  assembly.
- Use-case services receive only narrow dependencies.
- Runtime dependency objects use discriminated unions for platform-specific
  branches.
- Raw browser credentials, raw DB records, and native binding responses are
  parsed once at platform/request boundaries.

Tasks:

- [x] Add `client/src/core/runtime/types.ts`.
- [x] Add `client/src/core/runtime/createSigningRuntime.ts`.
- [x] Move use-case construction from `SigningEngine` into `SigningRuntime`.
- [x] Change `SigningEngine` into either a thin web wrapper around `SigningRuntime`
  or delete it once `SeamsWeb` calls the runtime directly.
- [x] Move relayer-client assembly into runtime dependencies.
- [x] Keep iframe routing in `SeamsWeb`, outside `SigningRuntime`.
- [x] Replace the long `signingEnginePublicMembers` tuple with grouped runtime
  services, such as registration, auth/session, near signing, EVM-family
  signing, recovery/export, preferences, and diagnostics.
- [x] Move `createBrowserPlatformRuntime(...)` construction into
  `client/src/web/SeamsWeb/assembly/createBrowserSigningRuntime.ts`.
- [x] Move in-memory ECDSA session/export artifact maps into explicit runtime
  state ports.
- [x] Rename the old NEAR/worker `SigningRuntimeDeps` context to
  `NearSigningRuntimeDeps` so it no longer conflicts with the platform-neutral
  `SigningRuntime` contract.
- [x] Delete `SigningEngine` public methods as soon as an equivalent runtime service
  owns the operation.

Acceptance:

- `client/src/core/runtime/**` imports no browser adapter, iframe, React, DOM, or
  IndexedDB modules.
- `SigningRuntime` can be constructed in tests with an in-memory
  `PlatformRuntime`.
- ECDSA provisioning uses the injected `SignerCryptoPort`,
  `AuthenticatorPort`, `DurableRecordStore`, and relayer client.
- `SigningEngine` is either gone or documented as a temporary web-only wrapper
  with no browser runtime construction.
- Runtime consumers call grouped services instead of a broad public member pick.

Validation:

- `pnpm -C tests run test:unit -- ./unit/provisionEcdsaUseCase.unit.test.ts`
- `pnpm -C tests run test:unit -- ./unit/platformAdapter.conformance.unit.test.ts`
- new runtime construction unit tests

### Phase 3: Replace Browser IndexedDB Assumptions With Store Ports

Goals:

- remove `getBrowserPlatformIndexedDB(...)` from shared signing assembly;
- make every durable store dependency an explicit port.

Tasks:

- [x] Define store ports for remaining flows that currently require
  `UnifiedIndexedDBManager` directly.
- [x] Move browser `IndexedDBManager` access into browser store adapters.
  - [x] Inject the browser IndexedDB singleton from `SeamsWeb` into the
    transitional `SigningEngine` wrapper instead of importing it from shared
    signing code.
  - [x] Move the nonce lane IndexedDB adapter construction out of manager
    assembly and into the browser wrapper store wiring.
  - [x] Move browser signing store bundle construction into
    `client/src/web/SeamsWeb/assembly/createBrowserSigningStores.ts`, then pass
    required store bundles into the transitional `SigningEngine` wrapper.
- [x] Update `createSigningEnginePorts(...)` or its replacement runtime assembly to
  receive store ports instead of deriving IndexedDB from `PlatformRuntime`.
- [x] Convert sealed-session, nonce, user-preference, registration, and recovery
  storage dependencies into typed ports as each path is touched.
  - [x] Convert `UserPreferencesManager` from a module-level browser IndexedDB
    singleton to an explicit injected store dependency.
  - [x] Narrow `UserPreferencesManager` from a broad
    `UnifiedIndexedDBManager` dependency to a preference/profile-selection
    store port.
  - [x] Convert worker-resource warmup from full IndexedDB access to a narrow
    profile/key-material store port.
  - [x] Convert EVM-family account-auth and WebAuthn P-256 key selection from
    full IndexedDB access to wallet-signer and passkey-authenticator store
    ports.
  - [x] Rename threshold-ECDSA bootstrap persistence from an IndexedDB-shaped
    dependency to a `ThresholdEcdsaBootstrapStorePort` and pass it through
    warm-signing and email-OTP commit assembly.
  - [x] Convert threshold-ECDSA session activation assembly from an
    IndexedDB-named dependency to an explicit WebAuthn credential store
    dependency.
  - [x] Narrow threshold-ECDSA session activation dependencies from
    `UnifiedIndexedDBManager` to the shared threshold credential-store port.
  - [x] Convert lower-level threshold-ECDSA bootstrap, keygen, and connect-session
    WebAuthn dependencies from IndexedDB-named ports to credential-store ports,
    then delete the unused IndexedDB-named threshold WebAuthn aliases.
  - [x] Convert passkey Ed25519 session provisioning and connector assembly from
    IndexedDB-named dependencies to explicit WebAuthn credential store
    dependencies.
  - [x] Update immediate Ed25519 signing fallback fixtures to provide the
    `nearKeyMaterialStore` port and current one-RTT near-signer worker response
    shapes.
  - [x] Convert private-key recovery/export and NEAR single-key HSS export from
    full IndexedDB access to a recovery key-material store port.
  - [x] Convert registration account lifecycle persistence from full IndexedDB
    access to a registration account store port.
  - [x] Convert UI-confirm WebAuthn credential collection from broad
    `ctx.indexedDB` access to a WebAuthn credential store port.
  - [x] Convert UI-confirm Tempo WebAuthn P-256 key selection from broad
    `ctx.indexedDB` access to an EVM-family passkey authenticator store port.
  - [x] Delete the broad `indexedDB` field from `UiConfirmContext` after
    WebAuthn credential and passkey-authenticator stores replaced the remaining
    UI-confirm database access.
  - [x] Convert NEAR signing material resolution from broad `ctx.indexedDB`
    access to a NEAR key-material store port.
  - [x] Narrow shared signing assembly helper inputs from broad
    `UnifiedIndexedDBManager` parameters to branch-specific credential,
    bootstrap, key-material, account, and warmup store ports where those
    contracts already exist.
  - [x] Narrow NEAR and EVM-family signing assembly from full
    `UnifiedIndexedDBManager` parameters to wallet-signer and
    passkey-authenticator store ports.
  - [x] Narrow `SignerWorkerManager` from full IndexedDB access to the NEAR
    key-material store port exposed on the worker context.
  - [x] Convert `createManagerAssembly(...)` from a broad IndexedDB dependency
    to named user-preference, nonce-lane, WebAuthn credential,
    passkey-authenticator, and NEAR key-material store ports.
  - [x] Replace the raw `indexedDB` field on `CreateSigningEnginePortsArgs`
    and `SigningEnginePorts` with a typed signing-engine store bundle.
  - [x] Name the ECDSA role-local ready-record maps as an explicit warm-signing
    store port group.
  - [x] Inject sealed signing-session persistence into step-up runtime as an
    explicit sealed-session store port group.
- [x] Define domain store port groups with required branch-specific ports for:
  - [x] wallet profile and signer records;
  - [x] ECDSA role-local ready records;
  - [x] sealed signing-session records;
  - [x] nonce lane coordination;
  - [x] user preferences;
  - [x] recovery and device-linking records.
- [x] Split `SeamsConfigsReadonly` into a platform-neutral runtime config and
  `SeamsWeb` browser config. Keep `iframeWallet`, browser authenticator options,
  DOM UI, asset paths, and React-facing settings out of the runtime config.
- [x] Keep raw DB parsing in persistence boundary modules.

Acceptance:

- `getBrowserPlatformIndexedDB(...)` is used only in browser assembly or deleted.
- `client/src/core/runtime/**` and use-case modules do not import
  `IndexedDBManager` or `UnifiedIndexedDBManager`.
- Browser tests still prove wallet-origin persistence behavior.
- Runtime config can be instantiated without iframe, DOM, React, or browser
  WebAuthn config fields.
- Store ports are required fields in runtime assembly; core functions do not
  accept partial persistence objects.

Validation:

- storage unit tests for each moved port
- `tests/unit/crossPlatformBoundaries.guard.unit.test.ts`
- new `refactor51bPlatformBoundaries.guard.unit.test.ts`

### Phase 4: Add Browser Assembly And Web Facade Boundary

Goals:

- make browser assembly the only place that combines `SeamsWeb`,
  `BrowserPlatformRuntime`, wallet iframe routing, React, and browser stores.

Tasks:

- [x] Add `createBrowserSigningRuntime(...)`.
- [x] Move browser-specific worker warmup, wallet-origin storage disabling, iframe
  readiness, asset preconnect, and UI overlay behavior into web assembly.
  - [x] Move browser IndexedDB mode selection and wallet-origin storage disabling
    policy into `client/src/web/SeamsWeb/assembly/configureBrowserIndexedDB.ts`.
  - [x] Move browser worker prewarm eligibility out of shared signing assembly
    and into
    `client/src/web/SeamsWeb/assembly/browserWorkerWarmupPolicy.ts`.
  - [x] Move worker base-origin initialization, embedded base change handling,
    and app-origin iframe-mode preference loading policy into
    `client/src/web/SeamsWeb/assembly/initializeBrowserSigningRuntime.ts`.
  - [x] Move wallet iframe asset preconnect, modulepreload, WASM prefetch, and
    embedded SDK base calculation into
    `client/src/web/SeamsWeb/assembly/preconnectWalletAssets.ts`.
  - [x] Move lazy wallet iframe router construction and same-origin iframe
    warning policy into
    `client/src/web/SeamsWeb/assembly/createWalletIframeRouter.ts`.
  - [x] Move app-facing wallet iframe overlay-state construction into
    `client/src/web/SeamsWeb/assembly/createWalletIframeOverlayState.ts`.
- [x] Keep `WalletIframeCoordinator` under the web facade boundary.
- [x] Keep direct browser mode and wallet iframe mode as `SeamsWeb` branches.
- [x] Move `routeWalletIframeOrLocal(...)` usage up to the `SeamsWeb` capability
  layer. Chain signer modules should expose local runtime operations that can be
  called directly by web or native facades.
  - [x] Move EVM registration and ECDSA bootstrap wallet-iframe routing from
    the EVM signer module into `SeamsWeb` capability wiring; keep the EVM
    signer local-only.
  - [x] Move Tempo signing, ECDSA bootstrap, and nonce-lifecycle wallet-iframe
    routing from the Tempo signer module into `SeamsWeb` capability wiring;
    keep the Tempo signer local-only.
- [x] Move NEAR registration, transaction, delegate, and NEP-413 wallet-iframe
  routing from the NEAR signer module into `SeamsWeb` capability wiring; keep
  the NEAR signer local-only.
- [x] Keep wallet iframe preference mirroring and login-status events in web-only
  modules.
- [x] Delete iframe-aware dependency fields from chain signer constructors once the
  web facade owns routing.

Acceptance:

- `SeamsWeb` can construct the browser runtime in direct mode and iframe mode.
- `SigningRuntime` has no iframe branch.
- Wallet iframe tests still cover origin-isolated browser execution.
- Near, Tempo, and EVM-family core signing modules have no
  `WalletIframeCoordinator`, `WalletIframeRouter`, or `routeWalletIframeOrLocal`
  dependency.

Validation:

- wallet iframe unit tests
- selected e2e wallet iframe tests
- browser platform conformance tests

### Phase 5: Add iOS Adapter Contract And RP ID Fixtures

Goals:

- make the iOS platform path explicit without shipping a full iOS SDK yet;
- record how production `seams.sh` passkeys are shared between web and iOS.

Tasks:

- [x] Add `client/src/core/platform/ios/README.md` with:
  - [x] `AuthenticationServices` mapping for `AuthenticatorPort`;
  - [x] `ASAuthorizationPlatformPublicKeyCredentialProvider` usage with
    `relyingPartyIdentifier: "seams.sh"`;
  - [x] Associated Domains entitlement example using `webcredentials:seams.sh`;
  - [x] required `apple-app-site-association` `webcredentials` shape;
  - [x] PRF extension expectations and typed unsupported fallback;
  - [x] Keychain-backed `SecureSecretStore` requirements;
  - [x] native signer-core binding requirements.
- [x] Add `refactor51bRpIdContract.unit.test.ts` for config/domain constants that
  must stay stable in the repo.
- [x] Add server-side verification notes for expected browser and iOS/native
  origins, including the route-level requirement to pass expected-origin or
  native-origin policy into every WebAuthn verification call.
- [x] Add route tests that fail when passkey verifier calls omit expected-origin
  or native-origin policy for registration, add-signer, session exchange,
  threshold ECDSA bootstrap, threshold Ed25519 session, and future native-auth
  routes.
- [x] Remove server verifier fallbacks that inferred `expectedOrigin` from
  `clientDataJSON.origin`; AuthService verification now requires route-provided
  expected-origin policy before invoking WebAuthn verifiers.
- [x] Extend origin-policy guards to cover AuthService and threshold Ed25519 route
  wrappers.
- [x] Add a native replay fixture task for every signer-core command the iOS adapter
  will call.

Acceptance:

- The plan for iOS passkey interoperability is implementable without a web
  iframe.
- `seams.sh` is the documented production RP ID for web/iOS interop unless a
  future plan explicitly changes it, while local defaults keep the current
  localhost RP IDs.
- iOS unsupported PRF behavior returns a typed failure before signer-core sees an
  invalid secret source.
- Server verification docs and tests require an expected-origin or native-origin
  policy for every passkey verification route.

Validation:

- `pnpm -C tests run test:unit -- ./unit/refactor51bRpIdContract.unit.test.ts`
- signer-core native readiness replay tests

### Phase 6: Add Embedded Adapter Contract

Goals:

- define the embedded path around Rust/local platform capabilities;
- keep web containers out of robot, device, and daemon deployments.

Tasks:

- [x] Add `client/src/core/platform/embedded/README.md`.
- [x] Define `EmbeddedPlatformRuntime` requirements:
  - [x] FIDO2 hmac-secret, TPM, or reviewed platform secret source;
  - [x] signer-core through Rust crate, C ABI, or authenticated local daemon;
  - [x] SQLite or atomic filesystem durable records;
  - [x] TLS transport with bounded timeouts;
  - [x] resource limits and replay-vector expectations.
- [x] Add guard tests proving embedded roots do not import `WalletIframe`, React, DOM
  UI, or browser storage modules.

Acceptance:

- Embedded implementation can be assigned without interpreting browser iframe
  concepts.
- The embedded plan reuses signer-core command schemas and conformance fixtures.

Validation:

- source guard tests
- signer-core replay tests on the lowest supported CPU class once hardware
  targets exist

### Phase 7: Public Export And Package Split

Goals:

- make public exports match the new architecture;
- keep native builds away from web-only files by construction.

Tasks:

- [x] Update `sdk/package.json` exports:
  - [x] `.` exports `SeamsWeb` for the browser package while this repo ships only
    the web SDK.
  - [x] `./react` exports `SeamsWebProvider` and browser React hooks.
  - [x] add `./runtime` only if it exposes platform-neutral types without browser
    dependencies.
  - [x] reserve future `./ios` and `./embedded` entries for packages or generated
    bindings that do not bundle browser code.
- [x] Move or delete the direct `./WalletIframe/client/html` export during Phase
  4. If it remains public for web hosts, rename it under a web-owned export path
  and guard it from platform-neutral, iOS, and embedded roots.
- [x] Update type declarations and build checks to prevent native packages from
  pulling browser chunks.
- [x] Add bundle inspection tests for native-target package entries once they exist.
- [x] Update package description and keywords so browser, runtime, server, and
  native-facing surfaces are described separately.
- [x] Remove stale component exports that point at deleted or renamed browser-only
  WebAuthn manager paths.
- [x] Add package export smoke tests for `.`, `./react`, `./runtime`, and any
  reserved native roots.

Acceptance:

- Browser imports are clear and web-named.
- Native package roots cannot import iframe/browser implementation files.
- No legacy `SeamsPasskey` export remains.
- `sdk/package.json` exports do not expose browser-only modules from
  platform-neutral or reserved native roots.

Validation:

- `pnpm -C sdk build`
- package export smoke tests
- bundle boundary checks

### Phase 8: Final Simplification Sweep

Goals:

- split oversized boundary files after runtime dependencies have stabilized;
- remove temporary wrappers introduced during the extraction;
- keep the final SDK surface small enough that native implementers can audit it.

Tasks:

- [x] Split `client/src/core/platform/types.ts` into focused modules:
  - [x] `ports.ts` for `AuthenticatorPort`, `SignerCryptoPort`,
    `DurableRecordStore`, `SecureSecretStore`, `HttpTransport`, `ClockPort`,
    and `RandomSource`;
  - [x] `secretSources.ts` for client secret-source brands, builders, and parsers;
  - [x] `ecdsaRoleLocalRecords.ts` for role-local ready/pending record shapes and
    parse results;
  - [x] `http.ts` for HTTP transport request/result types;
  - [x] `runtime.ts` for `PlatformRuntime` and platform-kind aggregates.
- [x] Keep ECDSA role-local record primitives platform-owned by moving role-local
  identity brands and ECDSA chain-target shapes out of signing-engine modules.
- [x] Move ECDSA registration bootstrap prepare/finalize construction into
  `SigningRuntime.services.ecdsaRegistrationBootstrap` so the web facade no
  longer calls `platformRuntime.signerCrypto` directly.
- [x] Delete the passkey ECDSA registration prepare wrappers from
  `SigningEngine` after SeamsWeb registration, link-device, and email-recovery
  call `SigningRuntime.services.ecdsaRegistrationBootstrap` directly.
- [x] Delete the combined ECDSA registration persistence/finalization wrapper
  from `SigningEngine`; SeamsWeb registration now finalizes through
  `SigningRuntime.services.ecdsaRegistrationBootstrap` and uses narrow session
  persistence methods.
- [x] Delete the Email OTP ECDSA registration prepare wrapper from
  `SigningEngine`; SeamsWeb registration now prepares Email OTP client
  bootstraps through `SigningRuntime.services.ecdsaRegistrationBootstrap`.
- [x] Delete the ECDSA wallet signer-record persistence wrappers from
  `SigningEngine`; SeamsWeb registration, link-device, and email-recovery now
  store ECDSA wallet records through `SigningRuntime.services.ecdsaWalletRecords`.
- [x] Delete the ECDSA registration session persistence wrappers from
  `SigningEngine`; SeamsWeb registration now persists registration sessions
  through `SigningRuntime.services.ecdsaRegistrationSessions`.
- [x] Delete the warm-session hydration wrapper from `SigningEngine`; Ed25519
  registration and bootstrap hydration now use
  `SigningRuntime.services.warmSessions`.
- [x] Delete the NEAR key-operation wrappers from `SigningEngine`; device-linking
  now signs temporary key-swap transactions and generates ephemeral keypairs via
  `SigningRuntime.services.nearKeyOperations`.
- [x] Delete the registration account lifecycle wrappers from `SigningEngine`;
  SeamsWeb auth, login, registration, recovery, sync, and device-linking now use
  `SigningRuntime.services.registrationAccounts`.
- [x] Move direct NEAR transaction/delegate/NEP-413 signing and Tempo/EVM-family
  signing/nonce-lifecycle calls from web capability methods to
  `SigningRuntime.services.nearSigning` and
  `SigningRuntime.services.evmFamilySigning`.
- [x] Narrow remaining direct web-module dependencies on `SigningEnginePublic`;
  auth/session, registration, and wallet-iframe coordination now accept
  branch-specific signing capability slices instead of the full wrapper surface.
- [x] Delete the exported `SigningEnginePublic` compatibility surface; the
  web context now declares a structural `SeamsWebSigningSurface` from core
  runtime/session/signing types.
- [x] Move registration-account, ECDSA wallet-record, ECDSA registration-session,
  and ECDSA registration-bootstrap runtime services under the registration flow
  boundary, and move warm-session hydration under the passkey session boundary,
  so `useCases` no longer imports flow, worker-manager, or UI-confirm modules.
- [x] Move the warm-session material writer contract under the passkey session
  boundary so session/passkey modules do not import UI-confirm internals.
- [x] Delete temporary `SigningEngine` wrappers once all public web capability
  methods call `SigningRuntime` services.
- [x] Delete temporary inventory TODO rows and guard allow-list entries created for
  phases that have completed.
- [x] Audit tests, fixtures, and snapshots for old facade names, iframe assumptions
  in shared runtime tests, and IndexedDB assumptions outside browser adapter
  tests.
- [x] Update file-level README docs for `core/runtime`, `core/platform`, `web`, and
  React entrypoints.

Acceptance:

- `client/src/core/platform/types.ts` remains only as a barrel export or is
  deleted.
- No temporary wrapper exists solely to bridge old `SigningEngine` call sites.
- Guard allow-lists contain only intentional boundary files with owner and
  reason fields.
- Typecheck fixtures cover the split platform secret-source and runtime config
  modules.

Validation:

- `pnpm -C sdk type-check`
- `pnpm -C tests run test:source-guards`
- focused unit tests for split platform modules

## Guard Tests

Add or update guards for:

- no `SeamsPasskey` public symbols after Phase 1;
- no iframe imports from `client/src/core/runtime/**`;
- no React imports from `client/src/core/runtime/**`;
- no DOM global usage from `client/src/core/runtime/**`;
- no browser adapter imports from native or embedded roots;
- no `getBrowserPlatformIndexedDB(...)` outside browser assembly;
- no `WalletIframeRouter` in iOS or embedded files;
- no `WKWebView` as the primary iOS authenticator implementation;
- no passkey verifier route call without expected-origin or typed native-origin
  policy after Phase 5;
- no `SigningEngine` public wrapper after Phase 8;
- no `client/src/core/platform/types.ts` implementation body after Phase 8 if it
  has become a barrel export;
- no runtime config fields named `iframeWallet`, `walletServicePath`,
  `sdkBasePath`, `walletHostVariant`, or React provider props.

## Compatibility Register

No compatibility branches are accepted for the facade rename.

| Compatibility path | Parser/module | Owner phase | Deletion trigger | Guard |
| --- | --- | --- | --- | --- |
| _No active compatibility branches._ | | | | |

## Review Checklist

Before merging any phase:

- Does this change move browser-only behavior toward `SeamsWeb` or browser
  assembly?
- Does `SigningRuntime` remain free of iframe, DOM, React, browser adapter, and
  IndexedDB imports?
- Are platform dependencies expressed as required ports?
- Did this phase delete the wrapper, alias, guard allow-list entry, fixture, or
  test that became obsolete?
- Did broad config or dependency bags shrink into runtime, web, or platform
  groups with clear ownership?
- Are any auth, identity, session, signing, restore, export, or lifecycle fields
  optional in core contracts?
- Do production iOS passkey paths use the configured `seams.sh` domain RP ID
  through Associated Domains while local development keeps localhost defaults?
- Does native PRF or secure-secret behavior normalize once at the platform
  boundary?
- Are unsupported platform capabilities typed failures?
- Do conformance tests cover each port touched by the phase?
- Are stale `SeamsPasskey` docs, tests, comments, and errors deleted?
- Do guard allow-list entries include owner and reason fields, and did the phase
  remove entries that became obsolete?

## Final Target State

- `SeamsWeb` is the browser SDK facade.
- Browser iframe routing exists only under the web facade boundary.
- `SigningRuntime` is platform-neutral and receives all platform capabilities
  through typed ports.
- Shared runtime and use-case modules have no browser storage, DOM, React, or
  iframe imports.
- Store dependencies are explicit runtime ports rather than recovered
  IndexedDB managers.
- Platform types live in focused modules with barrel exports only where useful.
- Package exports expose web, React, server, and platform-neutral roots with
  clear boundaries.
- Browser direct mode and wallet iframe mode remain fully supported.
- Production iOS uses native `AuthenticationServices` with `seams.sh` as the RP
  ID through Associated Domains, while local development keeps localhost RP IDs.
- Embedded uses Rust/native platform capabilities and never handles iframe
  abstractions.
- The source guards make these boundaries mechanically enforceable.
