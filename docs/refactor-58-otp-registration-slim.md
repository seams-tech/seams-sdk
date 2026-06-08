# Refactor 58: OTP Registration Slim

Date created: 2026-06-06
Status: core behavior implemented; hardening tasks remain open
Owner: SDK auth flows, relayer auth routes, wallet iframe

## Dependency

Start this refactor after the Refactor 56 headless auth flow is stable and the
Refactor 57 recovery-code backup UI is available.

Reason: this plan changes the Google SSO registration lifecycle. It depends on
the headless/direct/iframe split from Refactor 56 and on wallet-owned recovery
code backup from Refactor 57.

## Problem

The standard Google SSO registration path currently asks the user to complete an
Email OTP challenge after Google has already verified the Google account. That
adds friction, makes registration look like wallet unlock, and leaks old login
lifecycle concepts into the registration API.

Registration needs one verified identity proof and one wallet backup step:

```text
Google SSO proof -> wallet registration -> recovery-code backup -> success
```

Login and existing-wallet unlock still need fresh inbox proof:

```text
Google SSO proof -> Email OTP challenge -> unlock
```

## Goals

- Remove the blocking Email OTP prompt from standard Google SSO registration.
- Keep Email OTP as the fresh login/unlock proof for existing wallets.
- Make registration and login separate typed lifecycles in public/headless SDK
  results.
- Keep wallet id allocation and reroll server-owned.
- Preserve recovery-code backup and acknowledgement before registration success.
- Remove obsolete register-mode OTP fixtures and tests.
- Keep low-level Email OTP challenge APIs available only for advanced/custom
  flows.

## Non-Goals

- Remove Email OTP login.
- Remove the Google SSO step from registration.
- Add a generic OAuth provider framework.
- Add compatibility flags for old register-mode OTP prompts.
- Expose recovery codes, app-session JWT internals, runtime policy internals, or
  bootstrap material to app-visible results.

## Security Model

Google SSO registration is valid only when the server verifies the Google ID
token and derives the identity from server-validated claims. Client-provided
email, subject, wallet id, or verification status must not influence control
flow.

The server boundary must verify:

- Google issuer.
- Google audience/client id.
- Token expiry and issued-at skew.
- Google nonce/state binding when the Google adapter can request one.
- Stable provider subject.
- Email claim presence.
- `email_verified === true`.
- Runtime policy scope.
- Server-owned wallet id allocation or reroll state.

The registration attempt must bind:

- `providerSubject`.
- Canonical email.
- Wallet id.
- `runtimePolicyScope`.
- Registration attempt id.
- App or relayer session identity used by the route.

Email OTP remains the fresh inbox proof for login and existing-wallet unlock.
When a register request resolves to an existing wallet, the flow must pivot to
login and require Email OTP.

Provider subject is the account identity. Email is verified display and delivery
metadata. Do not merge or recover accounts by email alone.

### Current Replay Boundary

The current React Google adapter surface is app-supplied:
`getGoogleIdToken({ mode }) => Promise<string>`. It does not carry a
server-issued nonce or state value through the SDK boundary yet.

Until that adapter grows nonce/state support, the route relies on these bounds:

- Google ID token signature, issuer, audience, expiry, optional `nbf`, stable
  `sub`, and `email_verified === true` are verified server-side.
- The route derives `providerSubject` from Google `sub`; client-provided
  subject, email, wallet id, OTP fields, and verification status are ignored or
  rejected for registration control flow.
- The relayer creates the registration attempt, binds it to
  `providerSubject`, canonical email, wallet id, `runtimePolicyScope`, and app
  session scope, and sets a 30 minute expiry.
- Live same-subject registration refresh or restart fails the prior unacknowledged
  attempt and creates a fresh server-owned wallet id. User reroll uses the same
  replacement behavior with an explicit reroll failure code on the prior attempt.
- Registration finalize rechecks attempt id, provider subject, email, wallet id,
  state, expiry, and runtime policy scope before activation.

### Registration Attempt Rate Limits

Google SSO registration attempt creation, refresh replacement, and wallet-id
reroll use the Email OTP rate-limiter backend with scope
`googleRegistrationAttempt`.

The limiter consumes buckets for:

- Source IP.
- Verified Google provider subject.
- App/session user id from the verified Google exchange.
- Tenant org id from `runtimePolicyScope`.

Defaults stay local-friendly and production-conservative:

- Development: 200 attempts per 60 seconds.
- Production: 12 attempts per 10 minutes.

Operators can override these with
`EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX` and
`EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS`.

### Naming Decision

Public flow names keep `GoogleEmailOtpWalletAuth` because the same auth method
still owns login/unlock and recovery. Registration UI copy should describe the
standard path as Google-verified wallet creation, not Email OTP unlock.

## Target Flow

New-wallet registration:

1. App or adapter obtains a Google ID token.
2. SDK sends the ID token to the relayer registration/session-exchange route.
3. Relayer verifies the Google token and resolves the Google identity.
4. Relayer allocates or rerolls a wallet id for the registration attempt.
5. SDK completes the existing Email OTP wallet-registration material flow without
   issuing an Email OTP challenge.
6. Wallet-owned UI displays recovery codes.
7. User completes backup action and acknowledgement.
8. Server acknowledges backup and completes registration.
9. SDK returns non-secret completion metadata.

Existing-wallet resolution:

1. App or adapter obtains a Google ID token.
2. Relayer verifies the Google token and resolves an existing wallet.
3. SDK returns a login OTP lifecycle.
4. User completes Email OTP.
5. SDK restores or activates signing material and returns login success.

## Public Lifecycle Shape

Use a discriminated union that makes invalid branch calls unrepresentable. The
exact names can change during implementation, but the branches must keep
registration completion separate from OTP unlock.

```ts
type GoogleEmailOtpWalletAuthFlow =
  | {
      kind: 'registration_ready';
      walletId: WalletId;
      email: VerifiedGoogleEmail;
      providerSubject: GoogleProviderSubject;
      rerollWalletId: () => Promise<GoogleEmailOtpWalletAuthFlow>;
      completeRegistration: () => Promise<GoogleEmailOtpRegistrationCompleted>;
      submit?: never;
      resend?: never;
      delivery?: never;
    }
  | {
      kind: 'login_otp_required';
      walletId: WalletId;
      email: VerifiedGoogleEmail;
      delivery: EmailOtpDeliveryState;
      submit: (input: EmailOtpCodeInput) => Promise<GoogleEmailOtpLoginResult>;
      resend: () => Promise<GoogleEmailOtpWalletAuthFlow>;
      completeRegistration?: never;
      rerollWalletId?: never;
    };
```

Boundary parsers may accept raw route or iframe payloads. Core SDK and UI code
must accept only the normalized lifecycle branches.

## Review Notes Added To This Plan

The moved checklist needed a few extra specs before implementation:

- The Google token verification matrix must be explicit enough that removing OTP
  does not accidentally turn registration into client-trusted email input.
- The Google ID token replay boundary must be explicit. Prefer a nonce/state
  verified against the session exchange; if the current adapter cannot request
  one, document the short-lived bearer-token bounds and one-time registration
  attempt semantics before code lands.
- Registration attempt idempotency needs a rule for refresh, iframe close, and
  abandoned attempts after recovery codes are generated but before backup ACK.
- The reroll contract should be wallet-id only. It should not expose Email OTP
  delivery, reused-code, resend, or challenge semantics.
- Direct and wallet-iframe modes need the same non-secret result contract.
- UI copy should stop describing new registration as wallet unlock. The register
  path should show registration progress and the shuffle account-name control.
- Refactor 56 tests that assert register-mode OTP prompts become obsolete under
  this behavior and should be deleted rather than preserved.

## Phase 0: Spec Lock Before Code

Tasks:

- [x] Confirm the current Google Identity adapter can request and return a nonce
      or state value. If it can, require server verification against the session
      exchange record.
- [x] If nonce/state is unavailable, write the exact replay bounds into the route
      contract: accepted token lifetime, one-time registration attempt creation,
      provider-subject idempotency, and duplicate-attempt rejection.
- [x] Specify that provider subject, not email, is the durable identity key.
      Email changes or aliases must not create account takeover or accidental merge
      paths.
- [x] Define direct-mode recovery-code ownership. Public app results must strip
      codes; any temporary in-process backup UI or callback must be clearly
      wallet-owned or SDK-owned.
- [x] Define rate limits for registration attempt creation, wallet-id reroll, and
      abandoned-attempt replacement by IP, app/relayer session, and provider subject.
- [x] Decide whether public copy and method names should say `Google SSO
registration` instead of `Email OTP registration` in standard registration
      surfaces.

Acceptance:

- The implementation has no unresolved replay, identity-merge, or backup-owner
  ambiguity before route changes start.
- The plan distinguishes standard registration from advanced/custom Email OTP
  challenge APIs.

## Phase 1: Relayer Boundary And Registration Attempt

Tasks:

- [x] Update the Google SSO registration/session-exchange route so register mode
      can produce a registration attempt without issuing an Email OTP challenge.
- [x] Add a boundary parser for server-verified Google identity that requires
      issuer, audience, expiry, stable subject, email, and `email_verified === true`.
- [x] Normalize Google email and provider subject into branded domain values at
      the relayer boundary.
- [x] Bind registration attempt records to `providerSubject`, canonical email,
      wallet id, `runtimePolicyScope`, registration attempt id, and app/relayer
      session identity.
- [x] Keep wallet id allocation and reroll server-owned. Reject client-selected
      wallet ids except through the existing validated registration naming surface.
- [x] Enforce registration creation, reroll, and abandoned-attempt replacement
      rate limits at the route boundary.
- [x] Define stale pending behavior for abandoned registration attempts. Refresh
      or iframe close before recovery backup ACK must abandon the incomplete attempt
      and require a fresh registration attempt.
- [x] Ensure existing-wallet resolution from register mode returns a login OTP
      lifecycle rather than a registration lifecycle.
- [x] Reject register-mode route payloads that include OTP challenge id, OTP code,
      OTP resend state, or OTP delivery metadata.

Acceptance:

- Register-mode Google SSO can create a registration attempt without OTP.
- Server-side Google verification is the only source of provider subject, email,
  and verified-email status.
- A registration attempt cannot be completed for a different Google identity,
  wallet id, or runtime policy scope.
- Existing-wallet register resolution requires Email OTP unlock.

## Phase 2: SDK Lifecycle And Direct Browser Flow

Tasks:

- [x] Replace register-mode headless results with distinct
      `registration_ready` and `registration_completed` branches.
- [x] Remove `submit`, `resend`, `delivery`, and OTP challenge data from
      registration branches using `never` fields or separate types.
- [x] Keep login and existing-wallet branches as the only Google SSO paths that
      expose `submit`, `resend`, and `delivery`.
- [x] Update direct browser mode so successful register-mode Google SSO invokes
      the existing Email OTP wallet-registration material flow immediately after the
      registration attempt is prepared.
- [x] Preserve recovery-code backup before registration completion. Direct-mode
      app-visible results must never include `recoveryKeys`.
- [x] Redesign register-mode reroll as `rerollWalletId` or equivalent wallet-id
      reroll only.
- [x] Delete obsolete SDK helpers whose only purpose is register-mode OTP
      challenge setup.

Acceptance:

- Standard Google SSO registration does not return `kind: 'otp_flow'`.
- Registration branch types cannot call OTP submit or resend.
- Login branch types still require Email OTP submit.
- Direct-mode registration success contains only non-secret metadata.

## Phase 3: Wallet Iframe Flow

Tasks:

- [x] Update wallet-iframe register mode so completion happens inside the iframe
      after Google SSO registration attempt preparation.
- [x] Keep recovery-code display, backup actions, acknowledgement, and completion
      wallet-owned.
- [x] Strip recovery codes and bootstrap material before any host-visible result.
- [x] Keep iframe login/existing-wallet mode on the OTP unlock lifecycle.
- [x] Add iframe message types that distinguish registration completion from OTP
      unlock. Avoid optional bags that allow a mixed registration/login payload.
- [x] Reject iframe registration messages that carry OTP challenge id, OTP code,
      resend state, or delivery metadata.

Acceptance:

- Iframe registration can complete without an OTP prompt.
- Host-visible iframe results contain non-secret completion metadata only.
- Iframe login still requires OTP.

## Phase 4: React UI And Demo

Tasks:

- [x] Update `PasskeyAuthMenu` so Google SSO register mode renders registration
      progress and recovery-code backup, not the OTP digit prompt.
- [x] Preserve the shuffle account-name button for new-wallet registration.
- [x] Render the wallet unlock OTP menu only when the relayer resolves the Google
      identity to an existing wallet or the caller starts login mode.
- [x] Update UI copy so new registration is not described as unlocking a wallet.
- [x] Update the demo integration to handle the registration completion result
      shape directly instead of `kind: 'otp_flow'`.
- [x] Keep advanced/custom Email OTP challenge APIs out of the default React
      registration path.

Acceptance:

- New Google SSO registration shows registration UI with account-name reroll.
- Existing-wallet register resolution shows unlock UI and no reroll control.
- Demo code no longer needs to understand register-mode OTP delivery state.

## Phase 5: Tests, Fixtures, And Guards

Tasks:

- [x] Delete obsolete tests and fixtures that assert register-mode OTP prompt,
      register-mode OTP delivery, register-mode OTP resend, or reused-code behavior.
- [x] Add a regression test proving Google SSO register completes without
      creating or submitting an Email OTP challenge.
- [x] Add a regression test proving Google SSO register requires server-verified
      Google identity and verified email.
- [x] Add a regression test proving registration binds `providerSubject`, email,
      wallet id, and `runtimePolicyScope`.
- [x] Add direct and iframe tests proving recovery-code backup is required and
      app-visible results strip recovery codes.
- [x] Add a regression test proving register-mode reroll changes only wallet-id
      state.
- [x] Add a regression test proving existing-wallet register resolution pivots to
      login OTP.
- [x] Add a regression test proving login mode still requires Email OTP submit.
- [x] Add or update source guards proving the standard Google SSO registration
      path does not call Email OTP challenge, resend, or OTP submit helpers.
- [x] Re-run focused React/headless validation and relayer session-exchange tests
      after deleting obsolete register-OTP fixtures.

Acceptance:

- Tests protect the new lifecycle rather than preserving compatibility with the
  old prompt behavior.
- Source guards prevent reintroducing register-mode OTP challenge calls.
- Relayer session-exchange fixtures match current route behavior only.

## Phase 6: Registration Offer And RTT Reduction

Goal: keep Google SSO registration server-owned while reducing the happy path to
one registration offer RTT plus one finalize RTT after Google token acquisition.
User account-name shuffle must not require another relayer round trip.

Architecture delta from the old flow:

- Old standard Google SSO registration still behaved like an unlock-style Email
  OTP flow. After Google verification, register mode could create or submit an
  Email OTP challenge, render wallet-unlock UI, and treat account-name reroll as
  another backend lifecycle step.
- The new flow makes Google SSO registration an offer-plus-finalize lifecycle.
  After the app obtains a Google ID token, the first backend RTT is
  `session/exchange`: the relayer verifies Google SSO, creates a Google Email
  OTP registration attempt, and returns a short-lived registration offer with
  server-owned wallet candidates.
- The middle phase is local. The SDK prewarms Email OTP registration material,
  React displays registration UI, account-name shuffle rotates only through
  candidates already present in the active offer, and recovery-code backup is
  completed in wallet-owned UI. This phase must not call the relayer for reroll.
- The second backend RTT is finalize. The SDK sends the selected `candidateId`,
  typed Google SSO registration authority, Email OTP enrollment material, and
  backup acknowledgement. The server revalidates the offer binding and activates
  wallet, enrollment, backup, identity-link, and registration-attempt state.
- Register mode no longer borrows login's OTP lifecycle. Registration exposes
  `completeRegistration` and optional local `rerollWalletId`; login/existing
  wallet unlock remains the branch that exposes `delivery`, `resend`, and
  `submit` for Email OTP.
- Google SSO Email OTP registration is Email OTP-only by type and route
  boundary. It must not return passkey/WebAuthn registration options, OTP
  challenge ids, OTP codes, or raw runtime/app-session internals.

Backend round-trip target:

```text
Google token acquired
  -> RTT 1: exchange token, receive registration offer
  -> local: choose/shuffle wallet id, backup recovery codes
  -> RTT 2: finalize wallet registration
```

Target registration shape:

1. App obtains Google ID token.
2. `session/exchange` verifies Google SSO and returns a short-lived registration
   offer with multiple server-issued wallet candidates.
3. React shuffles locally between candidates from the active offer.
4. User completes wallet registration and recovery-code backup.
5. Finalize consumes the selected offer candidate, backup acknowledgement, and
   registration material atomically.

Security requirements:

- The client may select only a `candidateId` from the active server-issued offer.
- The server must never accept arbitrary client-selected wallet ids.
- The offer must bind Google provider subject, canonical verified email, org,
  runtime policy scope, app/relayer session identity, and expiry.
- Finalize must consume the offer exactly once and reject stale, replaced,
  expired, cross-scope, or cross-identity candidates.
- Candidate reservation must either be created at offer time with a short TTL or
  be checked and reserved atomically at finalize. Prefer offer-time reservation
  if the store can expire abandoned candidates cleanly.
- Recovery-code backup acknowledgement must be part of finalize or an immediate
  prerequisite that cannot leave an active wallet without backed-up codes.

Offer contract details:

- Generate a fixed small candidate set per offer. Start with 5 candidates unless
  UX testing proves a different number is needed. The candidate list must be
  non-empty by type.
- `candidateId` must be an opaque server-random identifier. It must not be a
  wallet id, hash of a wallet id, index, or predictable counter.
- Candidate display order may be randomized by the server. Local shuffle may
  rotate or randomize only within the offered candidate set.
- Offer expiry should be shorter than the old registration-attempt expiry.
  Target 10 minutes for production and keep local override support for tests.
- Repeated register-mode `session/exchange` for the same verified Google
  identity, app/relayer session, org, and runtime policy scope should return the
  same active offer. Create a new offer only for an explicit restart after
  abandoning the prior offer.
- Explicit restart must mark the prior active offer abandoned and release any
  candidate reservations before returning a new candidate set.
- Finalize must include an idempotency key scoped to the offer. A network retry
  after a successful finalize should return the same non-secret completion
  metadata instead of creating a second wallet or failing as an ambiguous
  consumed-offer error.
- Concurrent finalize attempts for the same offer must be serialized by the
  store. Exactly one selected candidate can win; losing attempts return a typed
  `offer_consumed`, `candidate_unavailable`, or cached idempotent completion
  result.
- If a selected candidate becomes unavailable before finalize, return a typed
  `candidate_unavailable` result. Do not silently pick a different wallet id on
  the server.

Backup acknowledgement contract:

- Backup ACK payloads may contain only `offerId`, selected `candidateId`,
  `recoveryCodesIssuedAtMs`, a non-secret backup action kind, client
  acknowledgement timestamp, and an idempotency key.
- Backup ACK payloads must reject recovery codes, recovery-key arrays,
  enrollment secrets, bootstrap material, app-session JWTs, OTP challenge ids,
  OTP codes, WebAuthn fields, and arbitrary wallet ids.
- Server activation must be atomic with successful candidate consume, Email OTP
  enrollment persistence, stale pending cleanup, and backup ACK recording.
- If local Email OTP material preparation or recovery-code backup fails, the
  offer remains unconsumed and expires or is explicitly abandoned. No active
  wallet should exist for that candidate.

Tasks:

- [x] Add a `GoogleEmailOtpRegistrationOffer` domain type with `offerId`,
      `expiresAtMs`, bound identity metadata, and a non-empty fixed-size candidate
      list containing `candidateId` plus display-safe `walletId`.
- [x] Replace single-attempt reroll creation with server-issued candidate
      generation during register-mode `session/exchange`.
- [x] Store offer/candidate lifecycle as a discriminated union: `started` and
      `key_finalized` are pending offer branches, `active` is the completed branch,
      and `abandoned`/`failed`/`expired` are terminal branches; make finalize accept
      only pending offer branches.
- [x] Bind the offer to app/relayer session identity and verify the binding again
      when completing wallet registration.
- [x] Decide and implement the reservation strategy: short-lived reservations for
      all candidates at offer creation, or atomic selected-candidate reservation at
      finalize with a typed conflict result.
- [x] Change the SDK registration flow so `rerollWalletId` or its replacement
      rotates through offer candidates locally and never calls `session/exchange`.
- [x] Make registration completion submit `offerId` and selected `candidateId`
      instead of trusting a client-provided wallet id.
- [x] Add a registration finalize idempotency key and cached non-secret
      completion result for safe client retries after timeout or network loss.
- [x] Move recovery-code backup acknowledgement into the registration finalize
      boundary, or enforce it as a consumed prerequisite before the server marks the
      registration active.
- [x] Make stale offer cleanup release candidate reservations by moving replaced
      offers out of the pending branches, and keep Email OTP recovery enrollment
      material request-local until registration finalize writes it so abandoned
      offers have no server-side material to clean up.
- [x] Update wallet iframe wire messages so hosts see only offer/candidate
      display metadata and never see app-session JWTs, runtime policy scope,
      recovery codes, bootstrap material, or raw offer binding internals.
- [x] Keep the old low-level reroll route/helper deleted after the offer flow
      lands. No compatibility path is needed for register-mode reroll.
- [x] Add a source guard proving register-mode reroll does not call
      `exchangeGoogleEmailOtpSession`, Email OTP challenge helpers, OTP submit, or
      resend helpers.
- [x] Add direct, iframe, and React tests proving local shuffle is zero-RTT,
      plus server-side authority/finalize-gate tests proving stale, replaced,
      expired, and mismatched offer candidates fail closed.
- [x] Add direct headless-flow coverage proving register-mode reroll rotates
      locally without a second `session/exchange`.
- [x] Add wallet-iframe handle coverage proving registration reroll replaces the
      active handle without exposing secrets to the host.
- [x] Add React prompt coverage proving register-mode Google SSO shows the
      shuffle/reroll UI and existing-wallet resolution shows unlock UI.
- [x] Add service/relayer tests for same-session offer idempotency, explicit
      restart, retry-after-success, stale/replaced/expired fail-closed behavior,
      and candidate-conflict behavior.
- [x] Add one focused concurrent finalize test proving only one registration
      commit can consume an offer; keep this at the service/store boundary to
      avoid a broad route harness.
- [x] Add AuthService coverage for same-session offer reuse and explicit
      reroll/restart creating a fresh offer.

Optional login RTT reduction:

- [x] Evaluate combining existing-wallet `session/exchange` and
      `requestEmailOtpChallenge` so a verified Google SSO login response can send
      the Email OTP challenge in the same RTT.
- [x] If implemented, keep rate-limit checks and verified Google identity before
      any OTP send side effect.
- [x] If implemented, make the combined login exchange a POST-only side-effecting
      route for existing-wallet Google Email OTP login.
- [x] If implemented, return typed delivery state for `sent`, `reused`, and
      `rate_limited`; do not infer delivery from timestamps or challenge ids.
- [x] Add challenge idempotency for retrying the same verified Google identity,
      wallet id, app/relayer session, and operation scope; model replay with an
      explicit `reused` delivery branch.
- [x] Preserve the current login flow type shape: login still exposes
      `delivery`, `resend`, and `submit`, while registration does not.
- [x] Add tests proving register mode never sends OTP and existing-wallet login
      sends OTP only after verified Google SSO and rate-limit approval.

Acceptance:

- New-wallet Google SSO registration has no network call for account-name
  shuffle after the initial exchange.
- Registration happy path is two backend phases after Google token acquisition:
  registration offer, then finalize with selected candidate and backup ACK.
- The server remains the sole authority for wallet candidates and registration
  lifecycle state.
- A captured candidate id, stale offer, expired offer, or cross-identity offer
  cannot create or activate a wallet.
- Registration finalize is retry-safe and concurrent-tab safe.
- Backup ACK, candidate consume, Email OTP enrollment persistence, and wallet
  activation are atomic from the caller's perspective.
- Existing-wallet login can be reduced to two backend phases only if OTP send is
  still gated by verified Google SSO and rate limits.

Validation:

- Direct flow tests for offer creation, local candidate shuffle, finalize, and
  stale candidate rejection.
- Wallet iframe handle tests for offer serialization, candidate selection, and
  secret stripping.
- React component test proving reroll/shuffle does not call the social-login
  handler or SDK exchange method again.
- Relayer route tests for offer binding, one-time consume, expiry, reservation
  conflict, and cross-scope rejection.
- Source guard for zero-RTT register-mode reroll.
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`

## Phase 7: OTP-Only Registration Latency Path

Goal: keep the optimized Google SSO registration path strictly scoped to Email
OTP wallet registration. The Google SSO register response should return identity
verification, a registration offer, server-owned wallet candidates, and Email
OTP registration metadata only.

This phase exists to prevent the RTT work from pulling in passkey/WebAuthn
registration concepts. Google SSO Email OTP registration does not create
passkeys, request WebAuthn registration options, or run a passkey ceremony.

Target OTP-only registration path:

1. App obtains Google ID token.
2. `session/exchange` verifies Google SSO, creates an Email OTP registration
   offer, reserves or prepares wallet candidates, and returns display-safe
   candidate metadata.
3. Client locally prepares Email OTP enrollment/key material while the user
   reviews or shuffles the offered wallet candidates.
4. Client shows recovery codes and requires the backup action/acknowledgement.
5. Finalize submits the selected `candidateId`, Email OTP enrollment material,
   and backup acknowledgement in one server call.
6. Server consumes the offer and activates the wallet only after all OTP
   registration and backup requirements pass.

OTP-only domain shape:

```ts
type GoogleEmailOtpRegistrationOffer = {
  kind: 'google_email_otp_registration_offer_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  expiresAtMs: number;
  emailHint: VerifiedGoogleEmailDisplay;
  candidates: readonly [
    GoogleEmailOtpRegistrationCandidate,
    ...GoogleEmailOtpRegistrationCandidate[],
  ];
  selectedCandidateId: GoogleEmailOtpRegistrationCandidateId;
  delivery?: never;
  challengeId?: never;
  otpCode?: never;
  webauthn?: never;
  passkey?: never;
};

type GoogleEmailOtpRegistrationCandidate = {
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  walletId: WalletId;
};

type GoogleEmailOtpRegistrationFinalizeInput = {
  kind: 'google_email_otp_registration_finalize_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;
  emailOtpEnrollment: EmailOtpEnrollmentMaterial;
  backupAck: EmailOtpRecoveryCodeBackupAck;
  walletId?: never;
  otpCode?: never;
  challengeId?: never;
  webauthn?: never;
  passkey?: never;
};
```

The exact type names can change, but the invalid combinations must remain
unrepresentable in SDK code and rejected at route boundaries.

Material ownership:

- Email OTP enrollment/key material is prepared in the Email OTP auth-method
  operation. React may hold UI state, but it must not construct protocol
  enrollment payloads itself.
- Recovery codes may be shown only in wallet-owned UI or SDK-owned direct UI.
  App-visible completion results must contain status metadata only.
- Prepared local material must be tied to the active `offerId` and selected
  `candidateId`. If the user selects a different candidate after material prep,
  either rebuild material for that candidate or prove the material is candidate
  independent and keep that invariant in the type name.
- Closing the iframe, cancelling the prompt, or letting the offer expire must
  clear in-memory secrets and leave the server offer unconsumed.

Tasks:

- [x] Audit the Google SSO registration exchange response and remove any
      WebAuthn/passkey registration option, authenticator option, credential
      creation, or passkey ceremony field from the standard Email OTP path.
- [x] Add an Email OTP registration-offer response type that carries only
      display-safe wallet candidates, offer expiry, delivery-free registration
      metadata, and non-secret status fields.
- [x] Add a boundary parser for the offer response so React, wallet iframe, and
      SDK operation code receive the same OTP-only normalized type.
- [x] Start local Email OTP enrollment/key material preparation after the offer
      is received and before the user presses create, without adding an extra server
      round trip.
- [x] Tie prepared local Email OTP material to the active offer and candidate, or
      encode candidate-independent material explicitly so candidate changes cannot
      reuse material with ambiguous identity.
- [x] Keep recovery-code generation and backup UI in the Email OTP auth-method
      implementation under `operations/authMethods/emailOtp/`.
- [x] Combine selected candidate, Email OTP enrollment material, and backup ACK
      into the registration finalize request.
- [x] Clear in-memory enrollment secrets and recovery codes on cancel, iframe
      close, offer expiry, failed finalize, and successful finalize.
- [x] Make finalize reject payloads containing WebAuthn/passkey registration
      option fields, credential creation output, OTP challenge ids, OTP codes,
      resend metadata, or arbitrary wallet ids.
- [x] Update wallet iframe messages so the host sees only OTP registration offer
      display data and stripped completion metadata.
- [x] Add a source guard proving the Google SSO Email OTP registration path does
      not import from `operations/authMethods/passkey/`, WebAuthn option builders,
      passkey registration authority helpers, or passkey ceremony code.
- [x] Add type fixtures proving registration-offer and finalize payloads cannot
      mix Email OTP registration fields with WebAuthn/passkey registration fields.
- [x] Add focused direct, iframe, and React tests proving the optimized
      registration path creates no OTP challenge, no OTP submit, no WebAuthn
      options, and no passkey ceremony.

Acceptance:

- Google SSO Email OTP registration has a two-backend-phase happy path after
  Google token acquisition: offer, then finalize.
- Account-name shuffle is local over server-issued candidates.
- The registration offer and finalize request are Email OTP-only by type and by
  route validation.
- The optimized path does not depend on passkey/WebAuthn registration code.
- Recovery-code backup remains required before server activation.
- Local material and recovery-code secrets do not survive cancel, expiry,
  iframe close, failed finalize, or successful finalize.

Validation:

- Direct flow test for OTP-only offer and finalize.
- Wallet iframe serialization test for OTP-only offer/result shapes.
- React component test for local shuffle plus create without OTP/WebAuthn UI.
- Direct and iframe tests proving cancel, expiry, and finalize clear in-memory
  recovery codes and prepared enrollment material.
- Source guard excluding passkey/WebAuthn imports from the Google SSO Email OTP
  registration operation.
- Type fixture rejecting mixed OTP/passkey registration payloads.
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`

## Phase 8: Slim Registration Correctness Hardening

Goal: close the correctness gaps found after the slim registration
implementation. These fixes should preserve the two-backend-phase registration
shape while making activation atomic, retries explicit, offer expiry fail
closed, and Email OTP registration types unambiguous.

This phase should avoid broad new facades. Put validation at route and store
boundaries, keep core functions on narrow domain states, and delete stale
fixtures that encode the old OTP-challenge registration behavior.

### Atomic Activation

Spec:

- Wallet creation, Email OTP enrollment persistence, recovery-code backup ACK
  activation, stale pending cleanup, Google identity-link creation, registration
  attempt activation, and ceremony consume must be one service-owned commit
  boundary.
- In Postgres-backed deployments, the above writes must happen inside the same
  transaction as ceremony consume.
- Non-Postgres stores may remain best-effort, but the service API must expose a
  single persistence boundary and run conflict checks before making the wallet
  visible.
- A failure to link `wallet:${providerSubject}` or activate the Google
  registration attempt must not leave a visible active wallet without the
  matching Google Email OTP identity state.

Tasks:

- [x] Move Google Email OTP registration authority completion into
      `consumeRegistrationCeremonyAndPersist(...)` or an equivalent single
      persistence boundary.
- [x] Add executor-backed Postgres helpers for identity-link creation and
      Google registration-attempt activation, then call them in the same
      transaction as wallet/enrollment persistence.
- [x] Keep generic store behavior behind the same service method and reorder
      conflict-prone checks before wallet/enrollment writes where transactional
      rollback is unavailable.
- [x] Remove the post-persist `completeGoogleEmailOtpRegistrationAuthority(...)`
      calls from each finalize branch.
- [x] Add service coverage where identity-link creation fails and assert the
      wallet/enrollment is not visible in the transactional path.
- [x] Fixed non-Postgres activation ordering: generic-store registration now
      preflights Google identity-link conflicts, activates the Google identity
      link and registration attempt before publishing registration persistence,
      and writes the wallet subject last for Google Email OTP activation. This
      was a real consistency/security issue because a non-Postgres store failure
      could previously leave a visible wallet without the matching Google
      identity-link or active registration attempt.
- [x] Added a focused Refactor 58 source guard proving the non-Postgres path
      activates Google Email OTP registration before generic persistence and
      keeps wallet subject visibility as the final generic-store write.

### Finalize Retry Semantics

Spec:

- Idempotency replay must not return a generic successful registration result
  when the replay response lacks the session material needed by the SDK to
  finish local login/session setup.
- Server replay responses must be typed as either a full first-time finalize
  success or an already-finalized state that requires session restoration.
- Client code must handle already-finalized replay as a recoverable state,
  routing through the existing login/session restore path or returning a typed
  recoverable result to React.
- Session JWT or other secret session material must not be stored in long-lived
  replay records.

Tasks:

- [x] Replace stripped success replay with an explicit
      `already_finalized_restore_required` finalize result for Google Email OTP
      registration replay when session material cannot be replayed.
- [x] Update direct SDK and wallet-iframe registration handling so replay after
      a lost response recovers through session restore or reports the typed
      recoverable state.
- [x] Add direct-flow coverage for lost-response retry after server finalize.
- [x] Add a route/service test proving replay records do not retain session
      secrets.
      - Added service coverage to the Google Email OTP finalize idempotency path:
        the cached replay record is inspected through the registration ceremony
        store and asserted to exclude app-session JWTs, session objects, and
        wallet signing session identifiers.

### Offer Expiry And Scope

Spec:

- Registration offers require a valid server-provided expiry. The SDK must fail
  closed when the expiry is missing, malformed, or already expired.
- Expired or invalid offers must clear prewarmed Email OTP enrollment material
  and recovery-code references.
- Pending offer reuse must be scoped to the intended registration boundary:
  provider subject, verified email, org id, app session version, and runtime
  policy scope.
- Cross-session or cross-scope stale cleanup must be explicit, with a lifecycle
  state such as `abandoned` and a clear failure code.

Tasks:

- [x] Replace the local TTL fallback for registration offers with strict parsing
      of the server expiry.
- [x] Normalize route responses to one canonical expiry field before SDK
      parsing, preferably `expiresAtMs`.
- [x] Clear prewarmed material immediately when a registration offer parses as
      expired or invalid.
- [x] Scope `findStartedGoogleEmailOtpRegistrationAttempt(...)` by org id, app
      session version, and runtime policy scope, or update the spec if global
      one-pending-offer-per-Google-identity behavior is deliberately chosen.
- [x] Add tests for missing expiry, malformed expiry, expired offer cleanup, and
      cross-session offer isolation or explicit abandonment.
      - Added SDK coverage for missing expiry, malformed expiry, expired-flow
        prewarmed material disposal, and reroll disposal of stale prewarmed
        recovery-code material.
      - Cross-session isolation already has AuthService coverage in
        `oidc-exchange.authservice.test.ts`: starting a second Google Email OTP
        registration for the same identity abandons the first attempt and the
        old authority verifies as `registration_attempt_not_started`.

### Domain Naming And Invalid States

Spec:

- `challengeId` must mean an actual Email OTP challenge id.
- Slim Google SSO registration must use a registration authority id, attempt id,
  or enrollment authority id for its authority binding.
- Google SSO registration finalize payloads must reject OTP challenge ids, OTP
  codes, resend metadata, passkey fields, and WebAuthn fields at the route
  boundary.
- Type fixtures must make mixed OTP challenge registration and Google SSO
  registration finalize states unrepresentable.

Tasks:

- [x] Split Email OTP backed-up enrollment types into challenge-backed and
      Google SSO registration-backed variants.
- [x] Rename the slim registration field from `challengeId` to
      `registrationAuthorityId` or `enrollmentAuthorityId`.
- [x] Update `parseGoogleEmailOtpRegistrationFinalizeInput(...)` and route
      parsing to reject challenge fields except at compatibility/request
      boundaries that immediately normalize to the new type.
- [x] Delete or update fixtures that use `challengeId` as a generic authority id.
      Remaining `challengeId` fixture hits are actual OTP challenge proofs,
      login challenges, or route-boundary rejection cases.
- [x] Add type fixtures proving Google SSO registration enrollment cannot be
      constructed with `challengeId`, `otpCode`, passkey, or WebAuthn fields.
- [x] Add route parser tests proving slim Google SSO registration finalize
      rejects OTP challenge fields before service execution.
- [x] Fixed direct SDK backup material construction so Google SSO registration
      carries `registrationAuthorityId` and rejects `challengeId` at the type
      boundary with `challengeId?: never`. This was a real design bug because
      `challengeId` must represent an actual Email OTP challenge, and using a
      registration authority id in that field made future challenge-backed
      control flow ambiguous.
- [x] Added a focused Refactor 58 source guard proving direct Google SSO Email
      OTP registration backup does not manufacture `challengeId` from
      `registrationAuthorityId`.

### Local Material Disposal

Spec:

- Prewarmed Email OTP registration material must have one producer-owned
  disposer that clears all SDK-held references to recovery codes, wrapped
  enrollment escrows, client handles, and other retained registration material.
- The disposer must be invoked on cancel, iframe close, offer expiry, candidate
  replacement, failed finalize, successful finalize, and already-finalized
  replay recovery.
- The code should state that JavaScript string contents cannot be reliably
  zeroized; this cleanup drops SDK references and clears mutable containers.

Tasks:

- [x] Move disposal logic next to the Email OTP material producer and expose a
      domain-specific disposer instead of casting branded recovery-code tuples
      to `string[]`.
- [x] Make the prewarmed-material holder transition to a disposed state so
      disposed material cannot be reused.
- [x] Call the disposer on every cancellation, expiry, candidate replacement,
      failed finalize, successful finalize, and replay-recovery path.
- [x] Add focused tests proving disposed prewarmed material cannot be read or
      reused after cleanup.
- [x] Fixed wallet-iframe expired handle cleanup so `takeFlow(...)` invokes the
      flow-owned `cancel()` disposer before rejecting an expired handle. This was
      a real lifecycle leak because the handle was burned while registration
      prewarm disposal was skipped.
- [x] Added wallet-iframe handle coverage proving an expired registration
      handle calls `flow.cancel()`.

Acceptance:

- A Google SSO Email OTP registration cannot create a visible wallet unless the
  Google identity link and registration attempt activation succeed in the same
  persistence boundary.
- Retry after a lost finalize response produces either full session-restorable
  success or a typed recoverable state, never a stripped generic success that
  later fails an SDK login assertion.
- Registration offers fail closed on missing, malformed, expired, or
  cross-scope expiry/attempt data.
- `challengeId` is used only for real OTP challenges.
- Local prewarmed registration material is disposed on every terminal or
  replacement path.
- No passkey/WebAuthn or OTP challenge fields are accepted in slim Google SSO
  registration finalize payloads.

Validation:

- Focused AuthService transactional registration tests for Google Email OTP
  identity-link failure and one-time activation.
- Focused direct-flow test for lost-response finalize replay.
- Direct/iframe tests for offer expiry cleanup and prewarmed-material disposal.
- Route parser tests for forbidden challenge/passkey/WebAuthn fields.
- Type fixtures for Google SSO registration enrollment invalid states.
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`
- `git diff --check`

## Validation

- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts`
- `tests/unit/passkeyAuthMenu.fouc.unit.test.ts`
- `tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts`
- `tests/unit/recoveryCodesModal.behavior.unit.test.ts`
- `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts`
- `pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/express-router.test.ts ./relayer/cloudflare-router.test.ts --reporter=line --grep "session/exchange"`
- `pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit`
- `git diff --check`
