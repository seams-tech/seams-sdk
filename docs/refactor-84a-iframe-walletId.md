# Iframe Wallet ID Binding Plan

Date created: June 30, 2026

Status: implemented for visible iframe passkey registration and server-side
route assertion coverage.

## Problem

`SeamsAuthMenu` can show one generated wallet ID while the browser passkey
prompt shows another. The root cause is two independent identity sources:

- React UI state generated and displayed a readable wallet ID.
- The iframe activation path called `registerPasskey()` without that wallet, so
  registration fell back to server allocation and WebAuthn used a different
  `intent.walletId`.

This is unacceptable for user-visible registration. Once the user sees a wallet
ID, every registration step must use that exact wallet ID.

## Decision

Make user-visible iframe passkey registration wallet-bound before WebAuthn.

The SeamsAuthMenu should own a single registration draft object. The UI renders
from that draft, the iframe activation message carries that draft's wallet, and
the WebAuthn options are derived from the same wallet-bound registration intent.

Direct/headless registration APIs may still use server allocation when no wallet
ID has been shown to the user. Visible activation surfaces must not.

Boundary responsibility:

- Client/UI code builds WebAuthn `PublicKeyCredentialCreationOptions`; it must
  set and verify `user.name` and `user.displayName` from the draft wallet ID
  before calling `navigator.credentials.create()`.
- Server registration routes verify the registration intent, digest, challenge,
  rpId, origin, and stored ceremony state. The WebAuthn registration response
  does not echo `user.name` or `user.displayName`, so server code must not claim
  to validate those display fields.

## Non-Goals

- Do not redesign all registration signer selection in this plan.
- Do not remove `server_allocated` from direct/headless registration APIs.
- Do not add compatibility paths for old activation payloads.
- Do not persist new wallet draft state in IndexedDB.

## Invariants

- User-visible registration has exactly one wallet ID before WebAuthn starts.
- `SeamsAuthMenu` display value equals the wallet sent to iframe activation.
- Iframe activation accepts only a provided wallet ID.
- Browser WebAuthn creation derives `user.name` and `user.displayName` exactly
  from the draft wallet ID.
- Client-side WebAuthn creation rejects options whose visible username differs
  from the expected wallet ID.
- Server registration start/finalize paths verify the stored intent wallet,
  registration digest, WebAuthn challenge, rpId, origin, and ceremony state all
  agree before touching signer state.
- Rerolling a wallet name replaces the registration draft before the activation
  surface mounts or remounts.

## Target Shape

```ts
type PasskeyRegistrationDraft = {
  kind: 'passkey_registration_draft';
  wallet: { kind: 'provided'; walletId: WalletId };
};
```

The UI renders `draft.wallet.walletId`. The iframe activation surface receives
`draft.wallet`. Registration submits the same `draft.wallet`. Auth method and
signer selection stay in the existing SeamsWeb registration boundary, because
the mismatch being fixed is the visible wallet ID shown before WebAuthn.

## Phase 0: Tactical Activation Fix

- [x] Add `wallet: Extract<RegisterWalletInput, { kind: 'provided' }>` to
  `CreatePasskeyRegistrationActivationSurfaceArgs`.
- [x] Add the same required provided-wallet field to
  `PMRegistrationActivationPreparePayload`.
- [x] Pass the generated SeamsAuthMenu wallet into the activation surface.
- [x] Forward activation payload wallet into host `registerPasskey()`.
- [x] Add a static type fixture rejecting `server_allocated` in activation
  prepare payloads.

Validation evidence:

- [x] `pnpm -C packages/sdk-web build:sdk`
- [x] targeted `git diff --check`

## Phase 1: Introduce Registration Draft

- [x] Add a `PasskeyRegistrationDraft` type for SeamsAuthMenu registration.
- [x] Build the draft once from the generated visible wallet ID.
- [x] Keep auth method and signer selection in the existing SeamsWeb
  registration boundary.
- [x] Move readable wallet ID generation into a single draft builder.
- [x] Do not use `createServerAllocatedWalletId()` as the visible draft
  generator. Add a UI-named helper for generated readable wallet IDs so visible
  wallet naming is not confused with direct/headless server allocation.
- [x] Store the draft as controller state instead of storing only
  `generatedRegistrationWalletId`.
- [x] Render the input from `draft.wallet.walletId`.
- [x] Make reroll replace the full draft, not just a display string.
- [x] Reroll disposes/remounts the activation surface because the activation
  wallet prop changes, so the active
  postMessage payload cannot carry a stale wallet ID.
- [x] Keep sponsored named-account registration on its existing explicit input
  path; it should produce a provided-wallet draft only after the user supplies a
  valid wallet/name.
- [x] Keep direct registration fallback paths using the same draft wallet when
  `SeamsAuthMenu` is visible and iframe activation is unavailable.
- [x] Replace the visible menu `onRegister(options?)` callback with a
  discriminated `SeamsAuthMenuRegistrationRequest` so visible registration
  cannot submit without the provided wallet shown to the user.

## Phase 2: Activation Surface Requires Wallet For Visible Flows

- [x] Replace optional activation wallet inputs with a required provided-wallet
  input:

```ts
type CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: { kind: 'provided'; walletId: WalletId };
  options?: RegistrationHooksOptions;
  presentation: RegistrationActivationButtonPresentation;
};
```

- [x] Update `packages/sdk-web/src/SeamsWeb/publicApi/types.ts` so
  `CreatePasskeyRegistrationActivationSurfaceArgs.wallet` is required.
- [x] Update `packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts` so
  `PMRegistrationActivationPreparePayload.wallet` is required.
- [x] Update `packages/sdk-web/src/react/components/SeamsAuthMenu/client.tsx`
  and controller code to pass the draft wallet directly.
- [x] Update `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts` activation setup to call
  `initWalletIframe(String(args.wallet.walletId))` and
  `requireRouter(String(args.wallet.walletId))`.
- [x] Update `packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts` and
  `packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts` so activation
  prepare always sends the provided wallet.
- [x] Add a host-side parser for `PM_REGISTRATION_ACTIVATION_PREPARE` in
  `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts`.
- [x] The host parser rejects missing wallet, `server_allocated`, non-object
  wallet values, invalid `walletId`, and provided wallet IDs that do not parse as
  `WalletId`.
- [x] Host code passes the parsed provided wallet to
  `pm.registration.registerPasskey()` and avoid forwarding the raw postMessage
  payload object.
- [x] Keep direct `registration.registerPasskey()` as the only path that may use
  server allocation before display.

## Phase 3: Client WebAuthn Option Binding

- [x] Add a typed boundary check before browser credential creation:

```ts
type ExpectedPasskeyRegistrationUser = {
  walletId: WalletId;
};
```

- [x] Require expected wallet ID when requesting registration credential
  confirmation for visible passkey registration.
- [x] Replace `derivePasskeyRegistrationIntendedUserName(walletId)` with exact
  wallet ID usage in
  `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts`.
- [x] In
  `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt.ts`,
  construct `PublicKeyCredentialCreationOptions.user.name` and
  `user.displayName` exactly from `ExpectedPasskeyRegistrationUser.walletId`.
- [x] Reject before `navigator.credentials.create()` if `user.name` or
  `user.displayName` differs from the expected wallet ID.
- [x] Keep `user.id` signer-slot disambiguation if needed, while preserving exact
  display fields.
- [x] Update or delete lit/unit fixtures that expect shortened usernames such as
  `alice` when the current wallet ID is different.

## Phase 4: Server Route Assertions

- [x] In `packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts`, keep
  request parsing strict: normalized request intent wallet ID, digest, and grant
  must match.
- [x] In the active route-service implementations, verify passkey registration
  with `intent.walletId`, the intent digest challenge, expected origin, and
  passkey rpId before constructing registration authority.
- [x] In
  `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`,
  apply the same checks on the D1 path before consuming ceremony state.
- [x] Assert stored intent, stored preparation, and stored ceremony wallet IDs
  match the request intent wallet ID.
- [x] Keep these checks at route/service boundaries before HSS or signer state is
  touched.
- [x] Do not add server checks for WebAuthn `user.name` or `user.displayName`;
  the WebAuthn registration response does not carry those fields.
- [x] Add route tests for mismatched intent digest, mismatched stored intent,
  mismatched preparation scope, invalid rpId/origin, and wrong challenge.

## Phase 5: Behavioral Tests

- [x] Add a SeamsAuthMenu controller registration test that:
  - renders the generated wallet ID,
  - asserts `registrationActivationWallet.walletId` equals the visible wallet
    ID,
  - asserts direct fallback registration receives the same wallet ID.
- [x] Add a reroll test proving the activation wallet uses the rerolled wallet
  ID.
- [x] Add runtime host-handler tests proving activation prepare rejects omitted
  wallet, invalid wallet, and `server_allocated`.
- [x] Add a type fixture proving activation prepare cannot use
  `server_allocated`.
- [x] Add a test proving direct/headless `registerPasskey()` may still use
  server allocation without rendering a wallet ID first.
- [x] Add a WebAuthn-options test proving `user.name` and `displayName` match
  `intent.walletId`.
- [x] Add a test proving `SeamsWeb.createPasskeyRegistrationActivationSurface`
  initializes and requires the iframe router with the provided wallet ID.
- [x] Add a test proving cancellation/disposal during reroll cannot reuse a
  stale activation wallet.

## Phase 6: Source Guards

- [x] Add a temporary source guard for SeamsAuthMenu and iframe activation:
  - no `createReadableRegistrationWalletId()` outside the draft builder,
  - no `server_allocated` in activation surface/message code,
  - no optional `wallet` field in activation surface or activation message
    types,
  - no direct object literal activation payload without `wallet`,
  - no host registration activation path forwarding raw postMessage wallet
    payloads,
  - no WebAuthn registration username derived from anything except the expected
    draft wallet ID.
- [x] Record the guard in `docs/refactor-89-clean-source-guards.md` as removable
  after the draft model and tests have stabilized.

## Phase 7: Cleanup

- [x] Remove display-only wallet generation helpers from controller code after
  the draft builder owns generation.
- [x] Remove any old activation tests or fixtures that permit wallet omission.
- [x] Remove stale lit/unit fixtures that assert shortened passkey usernames.
- [x] Update `docs/refactor-8X-iframe-registration-button.md` to reference this
  wallet-binding invariant.
- [x] Add a short completed implementation note to this plan with validation
  commands and the files touched.
- [x] Rebuild SDK assets.

## Acceptance Criteria

- [x] A wallet ID shown in `SeamsAuthMenu` is the exact wallet ID shown in the
  browser passkey prompt.
- [x] Activation prepare payloads cannot omit wallet ID in visible registration
  flows.
- [x] Activation prepare payloads cannot carry `server_allocated`.
- [x] Host iframe code rejects malformed activation wallet payloads at the
  postMessage boundary.
- [x] WebAuthn creation options are rejected before prompt if `user.name` or
  `user.displayName` does not match the expected draft wallet ID.
- [x] Server routes reject mismatched intent, digest, challenge, rpId, origin, or
  ceremony wallet state before signer state is touched.
- [x] Rerolling wallet ID updates the activation wallet.
- [x] Direct/headless registration remains available for code-only flows.

## Implementation Review: June 30, 2026

- [x] Added `createReadableWalletId()` for visible wallet-name generation while
      leaving `server_allocated` for direct/headless flows.
- [x] Made iframe activation surfaces require a provided wallet ID at public API,
      postMessage, client router, and host parser boundaries.
- [x] Bound `SeamsAuthMenu` registration to one draft wallet and reroll by
      replacing the draft.
- [x] Changed WebAuthn registration display fields to the exact wallet ID and
      rejected mismatched `intendedUserName` before opening the native prompt.
- [x] Added runtime, type-fixture, lit, and source-guard coverage for the visible
      wallet-binding invariant.
- [x] Validation:
      `pnpm -C packages/sdk-web build:sdk`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/registrationCapabilitySubjects.guard.unit.test.ts unit/walletIframeHost.registrationActivation.unit.test.ts --reporter=line`;
      `pnpm -C tests exec playwright test wallet-iframe/router.registrationActivation.test.ts --reporter=line`;
      `pnpm -C tests exec playwright test lit-components/passkey-registration-btn.test.ts --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsAuthMenu.fouc.unit.test.ts -g "Passkey implicit registration shows generated wallet input" --reporter=line`;
      `git diff --check`.
- [x] Fixed the server intent boundary so implicit NEAR registration accepts a
      preselected readable wallet ID from visible iframe flows, reserves it with
      the same replay/collision guard as server allocation, and still rejects
      arbitrary provided wallet IDs.
- [x] Tightened the visible SeamsAuthMenu callback boundary:
      `onRegister` now receives either `{ kind: 'implicit_wallet', wallet }` or
      `{ kind: 'sponsored_named_near_account', wallet }`, with `wallet`
      required in both branches. Direct/headless SDK calls remain the only place
      `server_allocated` can be used.
- [x] Validation:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/relayWalletRegistration.intentModes.unit.test.ts --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts -g "stores wallet registration intents" --reporter=line`;
      `pnpm -C packages/sdk-web build:sdk`;
      `pnpm -C apps/seams-site -s typecheck`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsAuthMenu.fouc.unit.test.ts -g "Passkey implicit registration shows generated wallet input" --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line`;
      `git diff --check`.
## Implementation Review: July 3, 2026

- [x] Added D1 route-service wallet equality checks for stored intent,
      preparation, and ceremony authority before HSS or signer state is touched.
- [x] Added route/client tests for mismatched registration digest, invalid rpId,
      wrong WebAuthn challenge, invalid origin, stored-intent wallet mismatch,
      preparation wallet mismatch, and ceremony wallet mismatch.
- [x] Tightened `parseWebAuthnRpId()` so whitespace/control-character rpIds are
      rejected at the request boundary.
- [x] Added client coverage proving direct/headless passkey registration still
      sends `server_allocated`, public activation surfaces initialize and require
      the provided wallet-scoped router, and reroll cleanup disposes the stale
      activation surface before mounting the next wallet.
- [x] Validation:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/relayWalletRegistration.boundary.unit.test.ts -g "registration (start rejects mismatched intent digest|prepare rejects invalid passkey rpId)" --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts -g "(rejects passkey registration challenge and origin mismatches|rejects stored registration intent wallet mismatch|rejects stored registration preparation wallet mismatch|starts ECDSA wallet registration ceremonies)" --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts --reporter=line`;
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsAuthMenu.fouc.unit.test.ts -g "Passkey implicit registration (shows generated wallet input|reroll disposes stale activation surface)" --reporter=line`.
