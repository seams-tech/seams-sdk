# Refactor 114 — Recovery-Code Account Recovery

Status: proposed.

## Decision

Replace the login action labeled **Recover Account with Email** with
**Recover account**. The action opens a recovery view inside the existing auth
menu. A user supplies one saved recovery code for the selected `WalletId`, then
creates a replacement passkey that restores the wallet's existing signing
material.

The recovery code is the recovery authorization for this flow. Email OTP,
Google SSO, an existing passkey, and selection of an old credential are not
required. General Email OTP and Google authentication remain supported outside
wallet recovery.

This is an intentional security-model change from the Email OTP bootstrap
described in Refactor 100. Update that specification and its intended-behaviour
contract in the same change set.

## Meaning of “new signer”

Recovery creates a new WebAuthn passkey, authenticator record, wallet auth
binding, and custody envelope for the same `WalletId`. It reconstructs the
wallet custody seed from the recovery envelope and re-establishes every key set
in the stored wallet key manifest.

It does not create a new wallet custody seed, owner signing root, NEAR account,
registered NEAR public key, EVM address, `signingRootId`, or key-creation signer
slot. The recovered wallet must have the same public identities it had before
recovery.

## User Experience

### Entry point

- Show **Recover account** in login mode in both the React auth menu and the
  hosted Lit auth menu. Its visibility must not depend on Google or Email OTP
  configuration.
- Remove the envelope icon and email-specific wording. Use the existing key or
  recovery icon that best matches the auth-menu icon system.
- Keep the action in the existing **Other options** group, after device linking.
- Reuse the `WalletId` entered on the sign-in view. Opening recovery with an
  invalid or empty value keeps the user on sign-in, displays the existing
  `WalletId` validation error, and focuses that field.
- The loading skeleton uses the final **Recover account** label so it does not
  shift when the menu becomes interactive.

### Recovery view

Open a subview in the current auth dialog instead of stacking a second modal.
The view contains:

- heading: **Recover account**;
- supporting copy: **Enter one recovery code to create a new passkey for
  {walletId}.**;
- the selected `WalletId` as read-only context;
- a visible **Recovery code** label and a text input that permits typing and
  pasting;
- primary action: **Create new passkey**;
- secondary action: **Back to sign in**.

Accept lowercase letters, spaces, and hyphens at the input boundary. Normalize
once with the existing recovery-code decoder. Do not rewrite the field while
the user is typing. Clear the field from UI state as soon as decoding succeeds;
retain only the coordinator's zeroizable byte buffer for the active operation.

Validate on submission. A local format error explains the expected recovery
code format. Server refusals use one user-facing message for an unknown wallet,
wrong code, spent code, revoked code, or live reservation:

> That recovery code can’t be used. Check the wallet ID and code, then try
> again.

Do not disable the primary action merely because the field is empty. Disable it
only while a request or WebAuthn ceremony is running, preventing duplicate
submissions.

### Ceremony and completion

1. The server validates and reserves the code for a short-lived recovery
   operation.
2. The browser starts WebAuthn registration with the returned options.
3. The client opens the recovery envelope, reconstructs every manifest key set,
   and proves the required ECDSA material possession.
4. Finalization installs the replacement passkey and custody envelope, consumes
   exactly one reserved code, and retires the previous active passkey custody
   envelopes and bindings.
5. The SDK restores local signing continuity, emits an authenticated outcome
   with method `recovery_code`, closes the auth menu, and returns focus to the
   element that opened it.

Cancellation before finalization clears client-held secret material. Release a
reservation when the server can safely do so; expiry remains the fallback for a
closed tab, lost connection, or interrupted client. A code is consumed only by
the successful finalization commit.

If wallet recovery succeeds while local continuity persistence is incomplete,
report recovery as successful and require a normal unlock before signing. Do
not repeat finalization or return the consumed code to the active pool.

## Security Invariants

- Possession of a valid unused recovery code and knowledge of its `WalletId`
  authorizes replacement of the wallet's passkey signer. UI copy and active
  documentation must state this clearly when recovery codes are generated and
  backed up.
- The server validates the request `Origin` and requested WebAuthn RP ID against
  an existing binding for the wallet before issuing registration options.
- Unknown wallets and incorrect, spent, revoked, expired-reservation, or
  concurrently reserved codes use the existing indistinguishable refusal path.
- The raw recovery code never appears in logs, analytics, errors, audit payloads,
  authorization claims, durable challenge records, or operation identifiers.
- Decoded code bytes and replacement factor secrets are zeroized on success,
  cancellation, expiry, and every recoverable failure path.
- A reservation is operation-bound, origin-bound, RP-bound, short-lived, and
  replay-safe. Its authorization cannot be used for another wallet, another
  registration challenge, or a different capability operation.
- Finalization verifies the complete stored key manifest. Partial NEAR or ECDSA
  reconstruction cannot promote the replacement credential.
- The replacement passkey is bound to the same `WalletId` and RP ID. WebAuthn
  excludes every existing credential for that wallet and RP.
- One successful recovery consumes one code. Concurrent use of the same code
  admits at most one finalization.
- Previous active passkey custody envelopes and auth bindings are retired as
  part of the recovery transition. If current storage cannot make the complete
  transition atomic, implement a typed committed-with-retirement-pending state
  and a retryable server cleanup path; never present the old and replacement
  signers as an intentionally supported steady state.
- Recovery must not rotate or replace public wallet key identities.

## Domain and API Shape

### Recovery authorization

Replace the Email OTP bootstrap adapter in
`router/domains/passkeyCustody/walletRecoveryAuthorization.ts` with a dedicated
recovery-code authorization path.

- Add a `verified_wallet_operation_recovery_code_factor` branch to
  `VerifiedWalletOperationFactorResult`. Require the exact tenant, principal,
  `WalletId`, authority reference, origin, audience, reservation, operation,
  verification time, and expiry. The evidence receipt is a domain-separated
  digest over public operation bindings; it must not include the raw code.
- Build this factor only after `prepareWalletRecoveryWithCodeV1` has validated
  and atomically reserved the supplied code. Represent that result as a precise
  `VerifiedReservedRecoveryCode` server-only type rather than a boolean or raw
  request object.
- Use an operation principal scoped to recovery and the wallet. Derive the
  `WalletAuthAuthorityRef` from the verified recovery operation so the custody
  activation receipts stay bound to the recovered wallet without pretending
  the proof came from Email OTP.
- Admit the existing wallet-recovery capability operation from the verified
  recovery-code evidence. Bind the authorization token to the reservation,
  `WalletId`, tenant, origin, RP ID, operation fingerprint, and expiry.
- Extend every exhaustive factor-evidence switch, parser, digest builder, and
  server-only proof builder for the new branch. Add type fixtures that reject
  Email OTP fields on a recovery-code factor and reject recovery-code fields on
  passkey or Email OTP factors.

Delete the wallet-recovery-specific Email OTP bootstrap challenge, verification,
grant consumption, claims, client methods, public API methods, and route inputs.
Preserve the general Email OTP registration, login, unlock, step-up, escrow, and
account-sync systems.

### Prepare request

Replace the current prepare body with one exact boundary type:

```ts
type WalletRecoveryPrepareRequest = {
  readonly walletId: WalletId;
  readonly orgId: OrgId;
  readonly rpId: WebAuthnRpId;
  readonly recoveryCode: string;
  readonly reservationId: RecoveryCodeReservationId;
};
```

Parse and normalize this body once at the route boundary. Reject unknown fields.
Remove `challengeId`, `recoveryBootstrapGrant`, and
`replacedCredentialIdB64u` from public types, transport payloads, challenge
records, tokens, coordinators, fixtures, and source guards. No compatibility
request shape or deprecated overload remains.

Keep `recoveryCode` in the HTTPS request as the existing base64url-encoded
decoded bytes, then immediately convert it to a `Uint8Array` and zeroize it
after the reservation attempt. Never persist it.

### Server-selected replacement binding

A fresh device cannot reliably identify the credential being replaced. Move
that choice behind the server boundary:

1. Validate the requested `rpId` against the request `Origin` with the existing
   WebAuthn RP/origin policy.
2. After the code is reserved, load active credential bindings for the
   `WalletId` and RP ID.
3. Select the canonical source binding with a deterministic server rule. Prefer
   the most recently updated active binding, with credential ID as the stable
   tie-breaker.
4. Store its credential ID only in the server-side recovery registration
   challenge. Revalidate its wallet and RP scope during finalization.
5. Exclude all current credentials for that wallet and RP from registration.

The source binding supplies existing wallet key metadata to the replacement
record. Before issuing options, compare the wallet-critical metadata shared by
all active candidate bindings. A disagreement is a typed
`recovery_binding_conflict` operator error and the UI receives the generic
recovery refusal. Do not guess which wallet key identity is authoritative.

### Client coordinator

Rename `WalletRecoveryCoordinator.prepareWithBootstrap` to `prepareWithCode`.
Its required input is `walletId`, `orgId`, `rpId`, `relayUrl`, and
`recoveryCode`. It creates the reservation ID internally and owns the decoded
bytes until completion or disposal.

Keep the existing discriminated operation stages and make the UI-facing result
union cover these exact outcomes:

- `ready_for_passkey`;
- `code_refused`;
- `registration_unavailable`;
- `manifest_unavailable`;
- `expired`;
- `cancelled`;
- `failed`.

Continue to use the existing preparation, credential creation, manifest
recovery, possession, finalization, and local-continuity implementations. Do not
add a second recovery coordinator or duplicate recovery cryptography in either
UI renderer.

### Public and hosted outcomes

- Remove the public bootstrap challenge and verification methods that exist
  solely for wallet recovery.
- Rename the public preparation method to describe code-based recovery and give
  it the exact input above. Keep completion operation-bound through the opaque
  client recovery handle.
- Add `recovery_code` to the authenticated hosted-auth-menu outcome method and
  its parser. Recovery is neither registration of a new wallet nor Email OTP
  authentication.
- Update the iframe message unions and type fixtures exhaustively. Secret input
  remains inside the hosted wallet surface; do not forward recovery codes to a
  parent window or include them in outcome messages.

## Auth-Menu State Changes

### Hosted Lit menu

- Add a `recovery` branch to `AuthMenuViewModel` with exact `editing`,
  `submitting`, `creating_passkey`, `recovering_keys`, and `recoverable_error`
  states. Each branch carries only the fields valid at that stage.
- Add exhaustive intents for opening recovery, changing the code, submitting,
  retrying, and returning to sign-in. Reuse the existing back/return-state
  pattern used by device linking.
- Route side effects through the auth-menu session and existing wallet recovery
  coordinator. The Lit surface renders state and emits intents; it does not own
  the ceremony.
- Complete the session with the authenticated `recovery_code` outcome after
  finalization and local session establishment.

### React menu

- Replace `canRecoverAccountWithEmail` and
  `onRecoverAccountWithEmail` with recovery-code view state and handlers in the
  React controller.
- Remove the dependency between recovery visibility and
  `props.socialLogin.google`.
- Reuse the shared recovery coordinator and the same copy, result mapping, and
  lifecycle semantics as the hosted menu.
- Update the interactive component and skeleton together. Do not retain the old
  email callback as an alias.

### Accessibility and responsive behavior

- Use a native form, label, text input, and buttons. Allow paste and password
  manager interaction; do not block clipboard events.
- Set `autocomplete="off"`, `autocapitalize="characters"`, and spellcheck off
  for the recovery-code field. Do not use a password input because users must be
  able to compare a printed code accurately.
- On entry, move focus to the recovery heading or code field. On validation
  failure, focus the field, set `aria-invalid`, and connect the error with
  `aria-describedby`.
- Announce async stage changes and the stable error area without repeatedly
  reading the whole dialog. Keep the form mounted while an error is shown.
- Escape and **Back to sign in** return to the login view and restore focus to
  **Recover account**. Closing the outer dialog restores focus to its opener.
- Preserve the existing auth-dialog focus trap and reduced-motion behavior.
  Support keyboard-only use, 200% zoom, and a 320 CSS-pixel viewport without
  horizontal scrolling or clipped actions. Keep actionable targets at least
  44 by 44 CSS pixels where the auth-menu layout permits.

## Implementation Plan

### 1. Replace the server authorization boundary

- [ ] Add the recovery-code factor evidence branch and its static rejection
      fixtures.
- [ ] Make successful code reservation return a server-only verified reserved
      code value that is required to mint recovery authorization.
- [ ] Replace bootstrap-grant admission and claims with reservation-, origin-,
      RP-, and operation-bound recovery-code admission.
- [ ] Delete wallet-recovery Email OTP bootstrap routes, stores, methods, and
      public types while preserving unrelated Email OTP behavior.
- [ ] Add existing-infrastructure rate limiting for recovery preparation by
      tenant, origin, wallet digest, and network/client bucket. Store and log
      digests only; never the raw code.

### 2. Remove client-selected credential replacement

- [ ] Add `rpId` to the prepare boundary and validate it against `Origin`.
- [ ] Resolve and validate the canonical active source binding on the server.
- [ ] Remove `replacedCredentialIdB64u` from request and response wire types.
      Keep a server-internal source binding identifier in the short-lived
      challenge record.
- [ ] Ensure finalization retires previous active bindings and envelopes while
      preserving the wallet key manifest and public identities.

### 3. Simplify the recovery coordinator

- [ ] Rename bootstrap-oriented modules, functions, context types, and results
      to recovery-code terminology.
- [ ] Make `prepareWithCode` call the new prepare boundary directly.
- [ ] Preserve zeroization, reservation pruning, key-set reconstruction,
      possession proofs, atomic code consumption, and local-continuity restore.
- [ ] Add an explicit cancel/dispose operation that the auth-menu session calls
      on back, close, timeout, and session replacement.

### 4. Add the hosted recovery view

- [ ] Extend the auth-menu domain union, exhaustive readiness calculation,
      intents, session state, and return state.
- [ ] Render the recovery form and progress/error states in the hosted Lit
      surface.
- [ ] Connect submission to the coordinator and complete with a
      `recovery_code` authenticated outcome.
- [ ] Remove the existing hosted **Recover Account with Email** action and its
      routing to `external_auth`.

### 5. Add the React recovery view

- [ ] Replace the email-recovery controller fields and button with the shared
      recovery-code flow.
- [ ] Render the same recovery form, copy, progress states, error mapping, and
      back behavior.
- [ ] Update the skeleton and public React types. Delete old callback fields and
      tests that exist only for Google-backed “recovery.”

### 6. Update specifications and examples

- [ ] Revise the **Credential-Replacement Recovery Flow** in
      `docs/refactor-100-passkey-account-refactor.md`: the saved recovery code is
      the recovery authorization and Email OTP bootstrap is no longer part of
      the flow.
- [ ] Update `docs/intended-behaviours.md` with the exact recovery-code lifecycle,
      signer replacement semantics, code consumption point, and public-key
      continuity guarantee.
- [ ] In Refactor 130A, replace the UI-copy cleanup checkbox with a cross-link to
      Refactor 114. Refactor 114 must remain independent of the deferred Email
      Recovery V2 project in Refactor 130B.
- [ ] Update demo and SDK documentation to show saving codes during enrollment
      and using **Recover account** from a fresh browser profile.

## Test Plan

Read `tests/AGENTS.md` before changing tests. Classify old bootstrap and old
button-label coverage as `obsolete_test_or_fixture`; delete it with the retired
path. Preserve recovery-envelope and general Email OTP coverage that still owns
current behavior.

### Domain and route tests

- [ ] Correct `WalletId` plus an active code reserves the code and returns
      registration options without Email OTP evidence or an old credential ID.
- [ ] Empty, malformed, wrong, spent, revoked, live-reserved, and unknown-wallet
      attempts receive the intended indistinguishable refusal.
- [ ] Tenant, wallet, origin, RP, reservation, challenge, or operation mismatch
      rejects recovery authorization and finalization.
- [ ] The server chooses a deterministic active source binding, rejects
      cross-wallet/cross-RP bindings, and reports conflicting wallet metadata as
      an operator error without exposing it to the user.
- [ ] Two concurrent attempts with one code admit at most one reservation and
      one finalization.
- [ ] WebAuthn cancellation, timeout, malformed registration, incomplete key
      manifest, failed possession proof, and pre-commit server errors do not
      consume the code.
- [ ] Successful finalization atomically consumes one code, installs the new
      authenticator/binding/envelope, and retires the previous active signer
      state. Replay is idempotent and cannot create a second signer.
- [ ] Recovery preserves every NEAR and EVM-family public identity and leaves
      all unused codes active.
- [ ] Authorization, audit, logging, and challenge fixtures contain no raw
      recovery code.

### Type and wire tests

- [ ] Invalid auth-menu lifecycle objects and invalid recovery factor
      combinations fail with `@ts-expect-error` fixtures.
- [ ] Prepare payloads containing legacy `challengeId`,
      `recoveryBootstrapGrant`, or `replacedCredentialIdB64u` fail exact parsing.
- [ ] Hosted outcome parsing accepts `recovery_code` only on authenticated
      outcomes and rejects it on registration outcomes.
- [ ] Iframe requests and outcomes cannot carry a recovery code outside the
      hosted wallet surface.

### UI tests

- [ ] Both UI renderers and the skeleton show **Recover account** without Google
      configuration and only in login mode.
- [ ] Invalid `WalletId` entry keeps focus on the login field. A valid entry
      opens the recovery subview with the same wallet ID.
- [ ] Typing, pasting, normalization, local format errors, generic server errors,
      retry, back, Escape, duplicate-submit prevention, and focus restoration
      behave identically in React and Lit.
- [ ] Keyboard navigation, screen-reader labels and announcements, 200% zoom,
      reduced motion, and the 320 CSS-pixel layout remain usable.

### Intended-behaviour contract

Add one authoritative fresh-profile contract:

1. Register a wallet and save its generated recovery codes.
2. Record its NEAR public key/account and EVM-family address.
3. Clear local wallet state and begin from the login menu without Email OTP or
   Google configuration.
4. Enter the `WalletId` and one saved code, then create a new passkey.
5. Sign once with each configured key family and verify the recorded public
   identities are unchanged.
6. Verify the used code is consumed, remaining codes are active, and the old
   signer state is retired.
7. Verify reuse of the consumed code receives the generic refusal.

### Verification commands

- [ ] Run the narrow wallet-recovery attempt, prepare RPC, authorization,
      finalization, wire, key-manifest, possession, coordinator, React menu, and
      Lit surface tests touched by the change.
- [ ] Run the recovery intended-behaviour contract, then `pnpm test:intended`
      because the public authentication lifecycle and shared auth state change.
- [ ] Run `pnpm test:source-guards`; delete or revise only guards that encode the
      retired bootstrap/request shape.
- [ ] Run `pnpm check` and `git diff --check`.

## Non-Goals

- Email-based account recovery, recovery contacts, social recovery, help-desk
  override, or recovery-code delivery.
- Generating a new wallet or rotating owner signing roots during recovery.
- Supporting recovery without a previously saved unused code.
- Keeping Email OTP bootstrap endpoints, old button callbacks, deprecated
  symbols, request adapters, or compatibility payloads.
- Implementing Refactor 130B or adding placeholders for its future design.

## Completion Criteria

- Login exposes **Recover account** in both supported auth-menu renderers, and a
  user can complete code-based recovery from a fresh browser profile.
- The flow requires a valid `WalletId`, one unused recovery code, and successful
  creation of a replacement passkey. It has no Email OTP, Google, existing
  passkey, or old credential-selection dependency.
- Recovery restores the complete existing wallet key manifest and preserves all
  public wallet identities.
- Successful finalization consumes exactly one code and replaces the previous
  active passkey signer state. Interrupted pre-commit attempts do not burn a
  code.
- Recovery-specific Email OTP bootstrap code and legacy request fields are
  absent from production code, public types, tests, active documentation, and
  source guards.
- The recovery code and replacement factor secret are absent from logs and
  durable authorization data and are zeroized after use.
- Refactor 130A cleanup remains compatible with this flow, and Refactor 130B
  remains fully deferred.
