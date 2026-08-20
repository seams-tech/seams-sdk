# Refactor 114 — Recover Account with a Code

Status: proposed implementation plan.

## Decision

Add **Recover account** to the hosted login menu. A user enters a `WalletId`
and one saved recovery code, creates a replacement Passkey, then signs in with
that Passkey through the existing login path.

The recovery code is the sole recovery authorization. Email OTP, Google, an
existing Passkey assertion, a client-selected old credential, and the general
factor-evidence system are absent from this flow.

R114 covers the current single-method wallet model. Recovery proceeds only
when the wallet has exactly one active owner auth method and it is a Passkey
bound to the requested RP. Any other factor shape receives the generic refusal.
R109A replaces this gate when it defines recovery for multi-auth wallets.

Reuse the current recovery-code reservation, recovery ceremony, key-manifest
reconstruction, WebAuthn registration, possession verification, replay
handling, and local-continuity restoration. Keep one coordinator and one hosted
Lit UI.

## Gaps Found in the Current Implementation

- Prepare still requires the Email OTP bootstrap grant, `orgId`, bootstrap
  challenge, and a client-selected credential ID.
- Recovery still enters authorized-operation and Email OTP factor-evidence
  machinery. Its outer authorization JWT is redundant with the reserved code
  and server-side registration challenge.
- The server trusts a client-selected source binding and does not prove that it
  belongs to the one active Passkey auth method.
- Promotion inserts the WebAuthn authenticator and binding without installing
  the replacement `wallet_auth_methods` row. The new Passkey may therefore be
  unusable for normal login.
- Source auth-method revocation, source-envelope retirement, code consumption,
  and source Wallet Session revocation are not one atomic commit. The current
  best-effort retirement result can leave the replaced credential active.
- Local continuity is restored against the bootstrap authority. It must be
  bound to the replacement Passkey authority.
- Recovery completion does not establish a fresh Wallet Session. An
  `authenticated` hosted outcome is premature until normal Passkey login
  succeeds.
- The hosted login field is a saved-account selector, so recovery needs its own
  editable Wallet ID field.
- WebAuthn creation cannot safely follow the asynchronous code-prepare request
  in the same click. It needs a fresh **Create new passkey** activation.
- Supporting specs were stale: there was no intended-behaviour recovery
  contract and Refactor 100 described Email OTP recovery. This review aligns
  both documents with R114.

## User Flow

The hosted recovery view has five explicit stages:

```text
enter_code -> preparing -> passkey_ready -> finalizing -> sign_in_ready
```

1. **Recover account** opens an editable Wallet ID field and recovery-code
   field. The Wallet ID may be seeded from the selected saved account.
2. Submit validates both fields and prepares recovery. The code is cleared from
   the form as soon as preparation succeeds.
3. The view shows a fresh **Create new passkey** button. Its click calls
   `navigator.credentials.create()` synchronously, before the first `await`.
4. The coordinator reconstructs the complete key manifest and finalizes the
   replacement.
5. After the server commit succeeds, the view shows **Sign in with new
   passkey**. That fresh click enters the existing Passkey login path and mints
   a new Wallet Session.
6. Only successful login emits the existing `authenticated` outcome with
   method `passkey`.

The extra sign-in activation keeps Wallet Session creation on the established
Passkey login path. Recovery does not add a second session-minting design.

## Exact Prepare Boundary

The client derives `rpId` from trusted wallet configuration and sends exactly:

```ts
type WalletRecoveryPrepareRequest = {
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
};
```

The coordinator decodes the human-readable code once and sends its base64url
bytes over HTTPS. The route rejects unknown fields, decodes once, and clears
the decoded buffer in `finally`. The client retains zeroizable bytes only in
the active coordinator operation.

Delete `challengeId`, `recoveryBootstrapGrant`, `orgId`,
`replacedCredentialIdB64u`, and the outer `recoveryAuthorizationToken` from the
prepare/finalize boundary. No overload or compatibility request remains.

The successful prepare response keeps the existing wrap, single seed entry,
key manifest, registration options, reservation expiry, and store version. It
has no top-level source authority, source credential, or authorization token.

## Exact Finalize Boundary

Finalization sends exactly:

```ts
type WalletRecoveryFinalizeRequest = {
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: WebAuthnRegistrationCredential;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly ecdsaMaterialPossessionProofs: readonly WalletRecoveryEcdsaMaterialPossessionProofInputV1[];
};
```

The successful response contains only `{ ok: true, storeVersion }`. The client
classifies non-success as either definite rejection, retryable server conflict,
or transport uncertainty. UI copy remains generic for all three.

Use these exact client classifications at both boundaries:

```ts
type WalletRecoveryAttemptFailure =
  | { readonly kind: 'refused' }
  | { readonly kind: 'retryable_conflict' }
  | { readonly kind: 'transport_uncertain' };
```

`refused` is terminal. Finalization retains its operation for
`retryable_conflict` and `transport_uncertain`; preparation has no operation to
retain until it returns `prepared`. Server diagnostics never cross into hosted
menu copy.

## Server Preparation

The route performs one linear operation:

1. Parse the exact request and validate `Origin` against the requested RP with
   the existing WebAuthn policy.
2. Decode and atomically reserve the recovery code for the wallet.
3. Resolve exactly one active owner auth method for the wallet. Require a
   Passkey binding for the requested RP.
4. Create registration options that exclude every existing credential for the
   wallet and RP.
5. Store one short-lived recovery registration challenge containing the
   wallet, reservation, origin, RP, replacement ID, source auth-method ID,
   source credential ID, source authority digest, and expiry.
6. Load the current key manifest and return the existing recovery preparation.

The stored challenge has one exact shape:

```ts
type WebAuthnRecoveryRegistrationChallengeRecord = {
  readonly version: 'webauthn_recovery_registration_challenge_v1';
  readonly challengeId: string;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly origin: string;
  readonly rpId: WebAuthnRpId;
  readonly replacementId: string;
  readonly challengeB64u: string;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly sourceCredentialIdB64u: WebAuthnCredentialIdB64u;
  readonly sourceAuthorityDigestB64u: WalletAuthorityBindingDigest;
  readonly sourceAuthMethodUpdatedAtMs: number;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};
```

The source method ID, active state, and `updatedAtMs` form the finalization CAS
guard. Preparation requires exactly one active owner method, that method must
be a Passkey, and its binding RP must equal the requested RP.

The source credential ID may appear inside WebAuthn `excludeCredentials`. It
is never a standalone response field and never returns in a finalization
request.

ECDSA possession challenges bind the source authority digest stored by the
server. That digest identifies the recovery transaction's starting auth
method. The server derives it from the selected active method; the client never
supplies it as authorization input. It does not claim a Passkey assertion
occurred. After credential creation, the client derives the replacement
Passkey authority and uses that authority for restored local continuity.

The successful code reservation and server challenge are the recovery
authorization. Do not add a recovery grant, principal, JWT, factor-evidence
branch, or authorization store.

### Ed25519 recovery admission

The existing Ed25519 recovery admission still reads a per-key JWT minted from
the Email OTP bootstrap session. Remove that dependency in the same cut-over.
The first admission request carries the prepared recovery registration
`challengeId` in a dedicated internal header. The router loads that durable
challenge, verifies its active reservation and Wallet ID, derives the expected
Near key lifecycle from the reservation and key-set ID, and admits only an
exact binding match. Execute and activate continue from the existing admission
receipt. The challenge header is never used by ordinary signing or returned by
finalization.

This is the smallest JWT-free bridge: it reuses the one stored challenge that
already authorizes recovery and adds no grant, session, token format, or
persistence record.

Malformed or incorrect code, unknown wallet, spent code, active reservation,
missing binding, wrong factor count, and RP mismatch use the same refusal.
Never store or log the raw code.

## Atomic Finalization

Finalization reads every source fact from the stored challenge and verifies:

- wallet, reservation, origin, RP, replacement ID, and expiry;
- the WebAuthn registration response and replacement credential;
- the complete key manifest, recovery envelopes, ECDSA possession proofs, and
  activation receipts;
- that the reserved recovery code and source auth method still have the state
  observed during preparation.

One D1 commit then:

- installs the replacement authenticator, binding, active auth-method row, and
  custody envelope;
- consumes exactly one reserved recovery code;
- revokes the source auth method and every Wallet Session it issued;
- retires the source custody envelope; and
- deletes the registration challenge.

Any failed statement leaves the commit unapplied and the reservation retryable.
Delete best-effort `retireFailures`; the single source factor is either replaced
completely or the operation does not commit. Replay succeeds only when the
replacement is active, the source is revoked, its envelope is retired, and the
same reservation is consumed.

The transaction uses compare-and-swap guards for the stored challenge, the
reserved recovery-set version, and the source auth method's ID, active state,
and `updatedAtMs`. A changed guard yields `retryable_conflict`; it never falls
through to a partial cleanup path.

## Coordinator Lifetime

Rename `prepareWithBootstrap` to `prepareWithCode`. Keep the current
`prepared`, `credential_created`, and `manifest_recovered` operation branches.

Add `cancel(recoveryOperationId)`. It removes the operation and zeroizes the
recovery bytes and replacement factor secret. The hosted session calls it on
Back, recovery-specific Escape, close, timeout, or session replacement.

A definite precommit refusal or failure cancels immediately. A transport
failure during finalization retains the operation until explicit cancellation
or reservation expiry so the same finalization can be replayed safely. A
successful finalization disposes the recovery operation before normal Passkey
login begins.

Keep recovery inside the wallet iframe. Delete recovery-specific public SDK,
React, parent-message, iframe RPC, and Email OTP bootstrap APIs. General Email
OTP behavior is unchanged.

## Frozen Host-Internal Port

Before parallel implementation, add
`walletIframe/host/recovery-port.ts`, a host-only port outside the auth-menu
subtree. The hosted UI imports only this port and narrow discriminated handles. It
does not import coordinator, relayer, custody, challenge, or WebAuthn response
types.

```ts
type HostedRecoveryFailure = { readonly kind: 'dismissed' } | WalletRecoveryAttemptFailure;

type HostedRecoveryPrepared = {
  readonly kind: 'hosted_recovery_prepared';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
};

type HostedRecoveryCredentialCreated = {
  readonly kind: 'hosted_recovery_credential_created';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
};

type HostedRecoveryPort = {
  prepare(input: {
    readonly walletId: string;
    readonly recoveryCode: string;
    readonly signal: AbortSignal;
  }): Promise<HostedRecoveryPrepared | HostedRecoveryFailure>;

  createPasskey(
    operation: HostedRecoveryPrepared,
  ): Promise<HostedRecoveryCredentialCreated | HostedRecoveryFailure>;

  finalize(
    operation: HostedRecoveryCredentialCreated,
  ): Promise<
    { readonly kind: 'ready_for_sign_in'; readonly walletId: WalletId } | HostedRecoveryFailure
  >;

  cancel(operation: HostedRecoveryPrepared | HostedRecoveryCredentialCreated): Promise<void>;
};
```

`createPasskey()` invokes `navigator.credentials.create()` before its first
`await` and stores credential material inside the coordinator. The UI receives
no PRF secret, recovery bytes, registration response, relay URL, challenge, or
server message. After `ready_for_sign_in`, the controller prepares normal login
for that exact Wallet ID. It must not fall back to account sync merely because
the fresh browser has no recent-unlock record.

## Hosted Auth Menu Contract

Add one `recovery` view with required Wallet ID, code, stage, and validation
state. Add only these recovery intents:

- `recovery_open`;
- `recovery_wallet_id_changed`;
- `recovery_code_changed`;
- `recovery_submit`;
- `recovery_create_passkey`;
- `recovery_sign_in`.

Use the existing `back` intent for **Back to sign in**. Recovery-specific
Escape has the same behavior and restores focus to **Recover account**. Global
menu Escape behavior does not change.

Use native forms and buttons, visible labels for both fields, and input text of
at least 16px. Validate on submit, set `aria-invalid` and stable
`aria-describedby`, focus the first invalid field, allow paste, and announce
the generic server refusal in the existing live region. The iframe surface
owns the recovery focus trap and focus restoration.

Map every prepare/finalize server refusal to exactly:

> That recovery code can’t be used. Check the wallet ID and code, then try
> again.

Do not place the code or server detail in DOM text, outcomes, parent messages,
or logs. A post-recovery Passkey login failure uses the existing Passkey login
error because the code has already been consumed.

## Security Invariants

- One active recovery code plus its `WalletId` authorizes one replacement
  operation for a single-Passkey wallet.
- Origin and RP policy are verified before registration options are issued.
- Concurrent attempts with one code admit at most one successful finalization.
- The raw code is absent from logs, durable challenges, errors, and outcomes.
- Finalization preserves every public wallet identity and verifies the complete
  stored key manifest.
- Successful finalization atomically installs the replacement and revokes the
  source factor. Precommit cancellation and failure do not consume the code.
- A fresh Wallet Session comes only from normal login with the replacement
  Passkey.

## Phased TODO

### Phase 0 — Freeze the cut-over contract

- [ ] Land one small lead-owned contract commit containing
      `walletIframe/host/recovery-port.ts` and
      `tests/helpers/walletRecoveryBoundary.fixtures.ts`. Subagents import these
      files and do not revise them.
- [ ] Record the exact prepare request, server challenge, finalization request,
      success responses, and failure unions in those fixtures.
- [ ] Confirm the single-active-Passkey gate against current persisted records.
- [ ] List every recovery-bootstrap symbol and assign each file to one owner.
- [ ] Mark old bootstrap request fixtures as `obsolete_test_or_fixture`; retain
      only behavior that remains valid.
- [ ] Capture the existing dirty-worktree diff for every owned file. Each owner
      preserves those edits and never rewrites another owner's files.

### Phase 1 — Four parallel workstreams

Every subagent owns its production files and its named tests. No separate test
owner waits on the implementation, and no two subagents edit the same file.

#### Subagent 1 — Server transport and bootstrap deletion

Owns these server files:

- `router/transport/fetch/routes/passkeyCustody.ts`;
- `router/transport/fetch/routes/sessions.ts` and route registration;
- `router/framework/authServicePort.ts`;
- `router/cloudflare/d1/auth/d1RouterApiAuthService.ts`;
- recovery-specific branches in `router/cloudflare/d1/emailOtp/**` and the
  matching `core/EmailOtpRecords.ts` / `core/EmailOtpStores.ts` boundaries;
- the Ed25519 recovery admission transport and authorization adapter only;
- `router/domains/passkeyCustody/walletRecoveryAuthorization.ts`, which is
  deleted after its remaining imports are removed.

Tasks:

- [ ] Parse exact prepare/finalize bodies, reject unknown fields, validate
      Origin/RP before preparation, and zero decoded code bytes in `finally`.
- [ ] Map the frozen domain results to exact HTTP responses and generic refusal.
- [ ] Remove the outer recovery JWT and authorized-operation/factor-evidence
      calls.
- [ ] Replace the Ed25519 recovery admission JWT with the prepared recovery
      challenge lookup described above; leave execute and activate unchanged.
- [ ] Delete only wallet-account-recovery Email OTP bootstrap routes, records,
      ports, and assembly. Preserve unrelated Email OTP and Router-AB warm recovery.
- [ ] Own `tests/unit/walletRecoveryPrepareRoute.unit.test.ts` and any focused
      server-boundary test changed by those deletions.

Must not edit the D1 Passkey custody service, WebAuthn store, finalizer, commit
store, wallet client, or hosted UI.

#### Subagent 2 — Server recovery state and atomic promotion

Owns these server files:

- `router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService.ts`;
- `router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore.ts`;
- `router/cloudflare/d1/webauthn/d1WebAuthnStore.ts` and
  `d1WebAuthnRecords.ts`;
- `router/domains/passkeyCustody/walletRecoveryAttempt.ts`,
  `walletRecoveryFinalization.ts`, and `walletRecoveryKeyManifest.ts`;
- the narrow wallet-auth-method store/service statement builders needed for
  active-method selection and atomic revocation.

Tasks:

- [ ] Resolve exactly one active Passkey method and matching RP binding, reserve
      the code, and persist the frozen challenge.
- [ ] Derive the source authority digest server-side and return no standalone
      source credential or authority.
- [ ] Implement the guarded atomic promotion and strict replay readback.
- [ ] Delete `retireFailures` and best-effort retirement.
- [ ] Own `tests/unit/walletRecoveryFinalization.unit.test.ts`,
      `tests/unit/d1WalletCustodyCommitStore.unit.test.ts`, and one focused
      source-selection test.

Must not edit HTTP route files, auth-service assembly, Email OTP files, wallet
client code, or hosted UI.

#### Subagent 3 — Client coordinator, wire clients, and obsolete API deletion

Owns:

- `SeamsWeb/operations/recovery/**`;
- `core/rpcClients/relayer/walletRecoveryPrepare.ts` and
  `walletRecoveryFinalize.ts`; delete `walletRecoveryBootstrap.ts`;
- recovery-specific `SeamsWeb.ts`, public API, React flow, iframe message,
  client router, host request-router, and non-auth-menu handler branches;
- one new `walletIframe/host/recovery-entrypoint.ts` implementing the frozen
  `HostedRecoveryPort`.

Tasks:

- [ ] Implement `prepareWithCode`, exact parsers, trusted RP derivation,
      replacement authority derivation, staged creation/finalization, and cancel.
- [ ] Preserve retryable finalization state and wipe secrets on every terminal
      branch.
- [ ] Remove bootstrap, old-credential, outer-token, public SDK, React, and
      parent-message recovery paths. Add no replacement `PM_*` messages.
- [ ] Own `tests/unit/walletRecoveryPrepareRpc.unit.test.ts`,
      `tests/unit/walletRecoveryFinalizeWire.unit.test.ts`, and one coordinator
      cancellation/replay test.

Must not edit `walletIframe/host/auth-menu/**`, Lit auth-menu files, server code,
or the intended-behaviour harness.

#### Subagent 4 — Hosted recovery UI and operating-path contract

Owns:

- `walletIframe/host/auth-menu/controller.ts` and `session.ts`;
- `walletIframe/host/lit-ui/auth-menu/auth-menu-domain.ts`,
  `seams-auth-menu-surface.ts`, `auth-menu.css`, and their local index;
- `tests/lit-components/auth-menu.surface.test.ts`;
- a focused `tests/unit/authMenuRecoveryContinuation.unit.test.ts`;
- the recovery contract and required harness additions under
  `tests/e2e/intended-behaviours/**`.

Tasks:

- [ ] Implement the exhaustive recovery view, stages, and six intents against a
      fake `HostedRecoveryPort` first.
- [ ] Add the editable fields, separate prepare/create/sign-in activations,
      cancellation, refusal mapping, focus restoration, stable live region,
      keyboard behavior, and 320px reflow.
- [ ] After `ready_for_sign_in`, prepare normal Passkey login for the exact
      recovered Wallet ID and emit `authenticated/passkey` only after it succeeds.
- [ ] Add the fresh-browser contract and assert unchanged identities, one
      consumed code, remaining active codes, source-session revocation, and generic
      refusal on reuse.

Must not edit coordinator/RPC files, iframe messages, client router, public API,
server code, or `walletIframe/host/auth-menu/passkey.ts`.

### Phase 2 — Integrate the operating path

- [ ] Integrate Subagents 1 and 2 at the frozen server-service seam, then
      Subagent 3 at the frozen wire seam.
- [ ] Supply Subagent 3's real host port to Subagent 4's controller. The UI
      implementation remains unchanged from its fake-port tests.
- [ ] Send every mismatch back to the owner of that file. Add no adapters,
      overloads, compatibility fields, or cross-owner cleanup edits.
- [ ] Run the fresh-browser recovery contract once and repair only observed
      failures.
- [ ] Delete stale fixtures, mocks, guards, and bootstrap-only code found by the
      cut-over in their owning workstreams. Do not preserve them behind
      compatibility branches.
- [x] Align Refactor 100, its manual verification, Refactor 103, and
      `docs/intended-behaviours.md` with R114.

### Phase 3 — Verification

- [ ] Run the focused recovery, finalization, coordinator, and Lit tests.
- [ ] Run `pnpm test:intended`.
- [ ] Run `pnpm test:source-guards`, updating or deleting stale guards.
- [ ] Run `pnpm check` and `git diff --check`.
- [ ] Search for every deleted bootstrap symbol and old request field; expect no
      production, public-type, active-test, or active-doc hits.

## Non-Goals

- Multi-auth sibling preservation or replacement policy; R109A owns it.
- Email, social, contact, or help-desk recovery.
- A recovery grant, general factor kind, coordinator, session mint, React form,
  or hosted outcome method.
- New key derivation, wallet identities, signing roots, accounts, or addresses.

## Completion Criteria

- A fresh browser recovers a single-Passkey wallet from the hosted login menu
  with its Wallet ID, one unused recovery code, and a new Passkey.
- The source Passkey, its envelope, and its Wallet Sessions are revoked in the
  same commit that installs the replacement and consumes one code.
- Normal login with the replacement creates a fresh Wallet Session and every
  configured key family signs with unchanged public identity.
- Recovery-specific Email OTP bootstrap code and retired request fields are
  absent from production code, public types, active tests, and active docs.
- The intended-behaviour contract and repository gates pass.
