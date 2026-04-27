# Polish Email OTP Wallet Flows

## Purpose

Polish the wallet flows so auth prompts match the account's active signing method:

1. Passkey-created accounts use WebAuthn/Touch ID for login, transaction confirmation, and sensitive operations.
2. Google SSO + Email OTP accounts use Google SSO for app authentication and a 6-digit Email OTP for wallet unlock/signing authorization.
3. Email OTP accounts must never fall through to a WebAuthn prompt unless the account actually has a passkey key and the operation is intentionally requiring passkey step-up.
4. Passkey accounts must not be silently downgraded to Email OTP unless the account explicitly added Email OTP as a separate key in the future add-key flow.

This plan is only for polishing the core wallet behavior. OTP-to-passkey add-key flows remain out of scope until the core Email OTP system is stable.

## Current Model

### Account Types

Passkey account:

1. user created or unlocked the wallet with a passkey
2. WebAuthn PRF output derives client-side threshold material
3. Touch ID/WebAuthn is the normal fresh-auth mechanism
4. key export can use passkey PRF-gated export paths

Email OTP account:

1. Google SSO authenticates the app/user session
2. Email OTP authorizes server-assisted `shamir3pass` unseal
3. the Email OTP worker recovers `S`, derives signing material, and owns secret-bearing runtime state
4. `WarmSessionManager` applies the `session` or `per_operation` signing-session policy
5. Email OTP is lower assurance than passkey and must be presented that way in UI copy

### Email OTP Policies

`email_otp_auth_policy = session`:

1. OTP is entered once during login/unlock
2. recovered signing capability stays in memory until TTL, revocation, logout, or invalidation
3. ordinary signing should not prompt again
4. transaction UI should not show a passkey halo or WebAuthn copy

`email_otp_auth_policy = per_operation`:

1. each signing operation requires a fresh Email OTP
2. the transaction confirmer must show a 6-digit OTP input
3. the server sends/logs a transaction-scoped OTP challenge
4. worker-owned signing material is discarded immediately after the operation

## Flow Matrix

### Login And Wallet Unlock

| Account state | Login action | Required prompt | Expected result |
| --- | --- | --- | --- |
| Passkey account | Continue with Passkey | WebAuthn/Touch ID | wallet session active |
| Email OTP account | Sign in with Google SSO | Google SSO, then 6-digit Email OTP | wallet session active |
| Email OTP account, session policy | Submit OTP once | Email OTP input in `PasskeyAuthMenu` | warm session cached in memory |
| Email OTP account, per-operation policy | Submit OTP once for unlock if required by product | Email OTP input in `PasskeyAuthMenu` | no reusable signing capability beyond configured single-use scope |
| Unknown Google account | Sign in with Google SSO in login mode | no OTP until account mapping exists | show register-with-Google path |

### Transaction Signing

| Chain/signing path | Passkey account | Email OTP session policy | Email OTP per-operation policy |
| --- | --- | --- | --- |
| NEAR Ed25519 threshold | WebAuthn only when no valid warm session exists | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |
| EVM secp256k1 threshold | WebAuthn/Touch ID when fresh passkey auth is required | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |
| Tempo secp256k1 threshold | WebAuthn/Touch ID when fresh passkey auth is required | use active Email OTP warm session, no WebAuthn prompt | show Email OTP input in tx confirmer, sign once, discard |

### Key Export

Key export is a sensitive operation.

Default security posture:

1. passkey accounts may export through WebAuthn/Touch ID + PRF-gated export flows
2. Email OTP-only accounts may export Ed25519 and ECDSA keys only after a fresh `per_operation` Email OTP step-up
3. server policy must explicitly allow the `export_key` operation for the current account, project, wallet, and session
4. export-specific challenges must bind `accountId`, `walletId`, curve, key id, operation, challenge id, and current app-session context
5. the UI must show a 6-digit Email OTP input for Email OTP-only accounts, never a WebAuthn prompt that cannot succeed
6. recovered secret/export material must be discarded immediately after the export viewer closes

Mixed passkey plus Email OTP accounts default to passkey for sensitive actions. The UI may offer a small "use one-time password" text link when project policy allows Email OTP as an alternate step-up method.

Step-up is not part of ordinary transaction signing. After wallet unlock, passkey and Email OTP sessions both follow the configured auth-method-neutral signing-session policy: `session` reuses the warm session until expiry/use exhaustion, and `per_operation` re-authenticates per operation.

Sensitive-operation policy is separate:

```ts
type SensitiveOperationPolicy =
  | 'inherit_session_policy'
  | 'require_fresh_same_method'
  | 'require_passkey'
  | 'deny_email_otp';
```

### Link Device / Add Signer

Link-device and add-signer flows are sensitive operations, not ordinary transaction signing.

1. Device1 authorization must require fresh same-method auth.
2. Passkey accounts satisfy this with fresh passkey authentication.
3. Email OTP accounts satisfy this with a fresh Email OTP verification.
4. A valid session-mode warm signing session must not silently authorize adding another signer.
5. The implementation now passes `require_fresh_same_method` into the NEAR add-key authorization path used by link-device.

## Architecture Boundary

Server is authoritative for:

1. OTP challenge TTL, counters, lockouts, and revocation
2. app-session and wallet-session authorization
3. operation policy: `inherit_session_policy`, `require_fresh_same_method`, `require_passkey`, and `deny_email_otp`
4. audit events for OTP challenge issuance, verification, signing, export attempts, and denial

Client is authoritative for:

1. in-memory warm-session lifecycle
2. displaying the correct auth prompt for the active method
3. clearing worker-owned warm material on logout, expiry, operation completion, and invalidation
4. treating server policy as upper bounds, not optional hints

Workers are authoritative for:

1. Email OTP secret-bearing unseal and derivation
2. worker-owned ECDSA and Ed25519 Email OTP signing material
3. single-use discard and practical zeroization
4. avoiding recovered `S` or Email OTP-derived shares crossing into JS main thread

## Implementation Plan

### Phase 1: Account Auth-Mode Source Of Truth

Goal: every flow can decide whether the current wallet session is passkey-backed or Email OTP-backed without guessing from UI state.

Tasks:

1. [x] Add or verify a canonical `authMethod` field in wallet session/readiness metadata with values `passkey` and `email_otp`.
2. [x] Ensure direct SDK mode and wallet-iframe mode expose the same auth-mode metadata.
3. [x] Persist only nonsecret auth-mode metadata in wallet-origin storage.
4. [x] Ensure Email OTP ECDSA and Ed25519 sessions carry nonsecret signing-session metadata; low-level stores may still encode this as `session` or `single_use`.
5. [x] Add tests proving login state refresh preserves auth mode after page reload and iframe reconnect.
6. [x] Remove any code path that infers Email OTP solely from account-id format or stale UI mode.

### Phase 2: Login And Wallet Unlock Polish

Goal: Email OTP login should complete wallet unlock without blank screens, stale passkey account ids, or WebAuthn fallback.

Tasks:

1. [x] Audit `PasskeyAuthMenu` state transitions for register/login mode, remembered account id, remembered auth method, and Google SSO enrollment-not-found handling.
2. [x] Ensure Google SSO login mode reuses persisted Google-subject-to-wallet mapping and never allocates a new wallet id.
3. [x] Ensure Google SSO registration creates a valid relayer subaccount instead of a top-level `*.testnet` account.
4. [x] Treat stale Google mappings to old top-level `*.testnet` accounts as not enrolled for login, and move them to relayer subaccounts during re-registration.
5. [x] Replace email-derived and timestamped Google SSO wallet ids with privacy-preserving HMAC readable slugs.
6. [x] After successful Email OTP submit, refresh wallet session state and require the session to be UI-ready before transitioning out of the OTP screen.
7. [x] Ensure wallet-iframe mode performs Google SSO session exchange and Email OTP login through wallet-origin SDK calls.
8. [x] Ensure app-origin IndexedDB disabled mode still completes Email OTP login/unlock.
9. [x] Add regression coverage for Email OTP login success updating React SDK login state and demo carousel routing.
10. [x] Add copy that says: "Google signs you in. A 6-digit email code unlocks wallet signing for this session."

Audit result:

1. `PasskeyAuthMenu` state does not decide Email OTP vs passkey from account-id format. It delegates Google SSO to the social handler and receives an OTP prompt when required.
2. Recent account prefill still derives the displayed username from the stored NEAR account id prefix. That is display/input prefill only, not auth routing.
3. Google SSO registration now defaults to a stable relayer subaccount id generated from a keyed HMAC readable slug; raw email and timestamped wallet ids are no longer supported.

### Phase 3: Transaction Confirmation Auth Routing

Goal: the transaction confirmer renders the correct prompt for the active auth method.

Tasks:

1. [x] Define a single `SigningAuthMode` surface for transaction confirmation: `webauthn`, `emailOtp`, and `warmSession`.
2. [x] Ensure passkey transactions use `webauthn` only when fresh WebAuthn auth is needed.
3. [x] Ensure Email OTP `session` transactions use `warmSession` or an Email OTP session presentation, never WebAuthn copy.
4. [x] Ensure Email OTP `per_operation` transactions request an Email OTP challenge before user confirmation.
5. [x] Ensure the Tx Confirmer modal/drawer shows a 6-digit OTP input for `emailOtp`.
6. [x] Ensure entered OTP is bound to the preissued challenge id and operation being confirmed.
7. [x] Ensure the server logs/sends the dev OTP for local testing through the normal Email OTP challenge route.
8. [x] Ensure operation cancellation invalidates or abandons unused per-operation challenges cleanly.

### Phase 4: ECDSA Signing Polish

Goal: EVM and Tempo threshold signing behave correctly under both passkey and Email OTP accounts.

Tasks:

1. [x] Verify EVM `per_operation` signing prompts for Email OTP in the Tx Confirmer, signs once, and rejects a second sign until a fresh OTP completes.
2. [x] Verify Tempo `per_operation` signing has the same behavior.
3. [x] Verify EVM and Tempo `session` signing does not prompt for WebAuthn after Email OTP login.
4. [x] Ensure wallet-iframe EVM and Tempo signing use wallet-origin Email OTP challenge and bootstrap calls.
5. [x] Ensure direct SDK EVM and Tempo signing use the same policy model as wallet-iframe mode.
6. [x] Ensure Email OTP-derived ECDSA signing material remains behind worker-owned opaque handles.
7. [x] Add tests for cancellation, invalid OTP, expired OTP, and retry after expired challenge.
8. [x] Keep the existing signing-root binding issue separate: ECDSA persisted-key replay must validate `signingRootId` and `signingRootVersion` before release.

### Phase 5: Ed25519 Signing Polish

Goal: NEAR threshold Ed25519 signing follows the same auth-mode model as ECDSA.

Tasks:

1. [x] Audit NEAR transaction signing for Email OTP account sessions.
2. [x] Ensure Email OTP `session` mode can sign NEAR transactions using the active worker-owned warm capability.
3. [x] Ensure Email OTP `per_operation` mode shows a 6-digit OTP input in the NEAR transaction confirmer.
4. [x] Ensure passkey NEAR signing still uses WebAuthn/Touch ID when fresh passkey auth is required.
5. [x] Ensure missing/expired Email OTP Ed25519 warm sessions produce a clear "verify Email OTP again" error, not "passkey required."
6. [x] Add focused NEAR Ed25519 tests for Email OTP session signing and per-operation signing.
7. [x] Add wallet-iframe coverage for NEAR Ed25519 Email OTP signing with app-origin IndexedDB disabled.

### Phase 6: Key Export Polish

Goal: export flows do not show impossible or misleading prompts.

Coordination note:

1. `docs/refactor-signer-slot.md` Phase 14/15 is complete for the Email OTP export-lane implementation.
2. This plan now owns remaining Email OTP release polish, validation, route cleanup, and E2E coverage.
3. Avoid reopening signer-slot lifecycle design unless a new bug proves the account auth-mode resolver or signer metadata model is incorrect.

Tasks:

1. [x] Add auth-mode detection before `exportKeypairWithUI` chooses an export path.
2. [x] For passkey accounts, keep existing WebAuthn/Touch ID export authorization.
3. [x] Replace the temporary Email OTP-only export fail-closed behavior with policy-gated Email OTP export.
4. [x] Ensure Email OTP-only ECDSA export requests a fresh export-scoped Email OTP challenge instead of `requestThresholdEcdsaExportAuthorization`.
5. [x] Ensure Email OTP-only Ed25519 export requests a fresh export-scoped Email OTP challenge instead of `requestNearEd25519ExportAuthorization`.
6. [x] Add tests proving Email OTP-only export attempts do not open WebAuthn prompts.
7. [x] Add tests proving passkey export flows still open WebAuthn and still export Ed25519/ECDSA when authorized.
8. [x] Add server-side policy enforcement for Email OTP `export_key`, including TTL, replay protection, audit events, and abuse counters.
9. [x] Add tests proving Email OTP-only Ed25519 and ECDSA export use OTP UI, bind the export challenge, and discard material after viewer close.

### Phase 7: UI Copy And Product Clarity

Goal: users can tell which auth method is active and why a prompt appears.

Tasks:

1. [x] In transaction confirm UI, label passkey prompts as "Confirm with Passkey."
2. [x] In transaction confirm UI, label Email OTP prompts as "Enter email code to sign."
3. [x] In Email OTP session-mode transaction UI, avoid passkey halo visuals if no WebAuthn ceremony will run.
4. [x] In AccountMenu export UI, allow Email OTP accounts to open export and use OTP-specific export authorization.
5. [x] In PasskeyAuthMenu, avoid prefilled passkey account ids confusing Google SSO registration.
6. [x] Add explicit lower-assurance copy for Email OTP: "Passkey is recommended for stronger security."
7. [x] Ensure errors distinguish "fresh Email OTP required", "passkey step-up required", and "operation blocked by policy."

### Phase 8: Robust Google SSO Registration Architecture

Goal: Google SSO identity resolution, wallet allocation, signer activation, and Email OTP enrollment are separate lifecycle steps so stale mappings and dev wallet collisions cannot send users through the wrong flow.

Problem statement:

1. Google SSO authenticates the app/user, but does not by itself prove that a wallet should be created.
2. A stable Google subject can already be linked to a wallet whose NEAR account exists on-chain.
3. Re-running registration against that existing wallet can finalize a new threshold Ed25519 key that is not an active NEAR access key.
4. The server correctly refuses activation, but the user-facing flow should have switched to login or created a fresh dev registration attempt before key generation.

Target architecture:

1. `GoogleIdentity`: provider, subject, email, and app-session claims only.
2. `WalletAccount`: canonical wallet id plus lifecycle state: `reserved`, `provisioning`, `active`, `failed`, or `orphaned_dev`.
3. `AccountSigner`: auth method, curve, public key, and lifecycle state: `pending`, `key_finalized`, `onchain_key_active`, `active`, or `failed`.
4. `EmailOtpEnrollment`: wallet-scoped enrollment linked to a signer, with `pending`, `active`, and `revoked` states.
5. `GoogleEmailOtpRegistrationAttempt`: short-lived registration attempt containing `attemptId`, Google subject, proposed wallet id, finalized Ed25519 key if available, status, failure code, and expiry.

Tasks:

1. [x] Add an explicit Google Email OTP resolution step that returns typed outcomes: `existing_wallet`, `register_started`, `wallet_id_collision`, and `registration_incomplete`.
2. [x] Stop permanently binding the Google subject to a wallet during `/session/exchange` registration. Treat exchange as identity-session creation plus resolution only.
3. [x] Add `GoogleEmailOtpRegistrationAttempt` persistence with attempt id, proposed wallet id, Google subject, email, runtime policy scope, status, expiry, and failure code.
4. [x] Bind the Google subject to the wallet only after account provisioning, signer activation, and Email OTP enrollment have all succeeded.
5. [x] If registration finds an existing active wallet for the Google subject, return `existing_wallet` and make the frontend switch to login OTP instead of starting HSS/key generation.
6. [x] If registration finds a pending or failed attempt, either safely resume it or expire it before starting a new attempt; do not treat it as an active wallet.
7. [x] If the proposed NEAR account exists but the finalized threshold Ed25519 key is not active, fail with `wallet_id_collision`, leave identity mapping unchanged, and mark the registration attempt failed.
8. [x] Replace ambiguous challenge routing with explicit route/API names for login OTP challenge, registration OTP challenge, and registration finalize.
9. [x] Keep login strict: `account_mode=login` must require an active wallet mapping and active Email OTP enrollment, and must never allocate a wallet id or start registration.
10. [x] Remove the dev wallet-id setting that switched between stable and timestamped Google SSO wallet ids.
11. [x] Use deterministic HMAC readable slugs for new Google SSO Email OTP registration attempts.
12. [x] Remove the explicit dev-only "force new dev wallet" path; duplicate-wallet testing should use distinct test identities or reset local state.
13. [x] Update `PasskeyAuthMenu` and the demo social handler to follow the server's typed resolution mode instead of inferring enroll vs login from the segmented-control tab.
14. [x] Add UI copy for `existing_wallet`, `wallet_id_collision`, and `registration_incomplete` so users see whether to login, retry with a fresh dev wallet, or reset stale local state.
15. [x] Add cleanup tooling for stale local dev registration attempts and orphaned dev wallet mappings.
16. [x] Add unit tests proving Google SSO registration with an existing active wallet switches to login and does not run HSS registration.
17. [x] Add unit tests proving login mode never creates wallets and never starts Email OTP enrollment.
18. [x] Add unit tests proving HMAC readable wallet ids do not contain raw email substrings and keep existing-wallet login semantics.
19. [x] Add relayer tests proving identity mappings are committed only after successful wallet provisioning and signer activation.
20. [ ] Add E2E coverage for HMAC-readable registration, existing-wallet login handoff, stale-attempt retry, and wallet-id collision errors.

Implementation notes:

1. Google Email OTP registration attempts now use the Email OTP store layer: Postgres when configured, in-memory otherwise.
2. Email OTP routes now use explicit login and registration names; old ambiguous route names were removed rather than aliased.
3. Google Email OTP registration derives public NEAR account ids from `ACCOUNT_ID_DERIVATION_SECRET`; login never allocates wallet ids.
4. Local development cleanup is exposed as `POST /wallet/email-otp/dev/cleanup-google-registration`; it verifies the Google id token, deletes expired registration attempts, and removes only orphaned Google-to-relayer-wallet mappings with no active Email OTP enrollment.
5. Email OTP login operation parsing is centralized in `server/src/router/emailOtpRequestValidation.ts`. Login challenge/verify routes accept only `wallet_unlock`, `transaction_sign`, and `export_key`; registration routes do not accept login operations and remain `registration`-scoped through `AuthService`.

### Phase 9: Release-Gate Tests

Goal: lock the auth-routing behavior with tests before adding new account-upgrade features.

Tasks:

1. [x] Unit test auth-mode resolution for wallet session metadata.
2. [x] Unit test Tx Confirmer rendering for `webauthn`, `emailOtp`, and `warmSession`.
3. [x] Unit test EVM Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
4. [x] Unit test Tempo Email OTP `per_operation` challenge, submit, sign, discard, and replay rejection.
5. [x] Unit test NEAR Ed25519 Email OTP session and per-operation signing paths.
6. [x] Unit test Email OTP-only Ed25519 and ECDSA key export with fresh OTP step-up.
7. [x] E2E smoke test Google SSO + Email OTP registration, login, NEAR sign, EVM sign, Tempo sign.
        Covered by the Google SSO Email OTP E2E cases for registration/login,
        NEAR signing, normal EVM signing, Tempo signing, and Ed25519/ECDSA
        export with resend.
8. [x] E2E smoke test passkey registration, login, NEAR sign, EVM sign, Tempo sign, Ed25519 export, ECDSA export.
        Completed manually: passkey registration, wallet unlock, Ed25519 threshold signing, ECDSA threshold signing, Drip fee token claim on Tempo, Ed25519 export, and ECDSA export.
9. [ ] E2E smoke test wallet-iframe mode with app-origin IndexedDB disabled.
10. [x] Add regression assertions that Email OTP flows do not display WebAuthn prompts unless passkey step-up is explicitly required.

## Acceptance Criteria

1. Passkey accounts continue to use WebAuthn/Touch ID for fresh auth.
2. Email OTP login and unlock never ask for WebAuthn.
3. Email OTP `session` signing does not ask for WebAuthn after login.
4. Email OTP `per_operation` signing displays a 6-digit OTP input in the Tx Confirmer.
5. Email OTP `per_operation` signing consumes the single-use capability and requires a fresh OTP for the next operation.
6. Email OTP-only key export does not open a WebAuthn prompt and requires fresh export-scoped Email OTP step-up.
7. Wallet-iframe mode and direct SDK mode behave the same at the public API boundary.
8. The app origin never receives recovered `S` or Email OTP-derived signing shares.
9. Error messages identify the required auth method instead of using generic "session not ready" or "passkey required" messages.
10. The release-gate test matrix covers Passkey and Email OTP across login/unlock, signing, and export decisions.


## Refactor: Shared Wallet Signing Session Budget

Goal:

Transaction signing must use one wallet-level signing-session budget shared by Ed25519 and ECDSA capabilities. The curves may keep separate threshold sessions, JWTs, and secret material, but TTL and `remainingUses` must be consumed from one wallet signing session.

Required invariants:

1. Ed25519 and ECDSA transaction signing consume the same `walletSigningSessionId` budget.
2. A NEAR Ed25519 sign decrements the same `remainingUses` counter as an EVM/Tempo/Arc ECDSA sign.
3. TTL expiry invalidates both Ed25519 and ECDSA transaction signing capabilities.
4. Use-count exhaustion invalidates both Ed25519 and ECDSA transaction signing capabilities.
5. Private-key export and link-device/add-signer flows use operation-scoped auth and must not replace, decrement, or invalidate the active transaction signing session.
6. When the shared signing session is expired or exhausted, the Tx Confirmer must request fresh auth using the account's registered auth method:
   - Email OTP account: show 6-digit Email OTP input and dispatch an Email OTP challenge.
   - Passkey account: show WebAuthn/passkey prompt.
   - Mixed account: default to passkey, with Email OTP fallback only if project policy allows it.
7. Email OTP-only accounts must never fall through to WebAuthn prompts for normal transaction signing.
8. Passkey accounts must never silently downgrade to Email OTP unless Email OTP was explicitly added as a separate signer and policy allows fallback.

Architecture:

1. Introduce a first-class `walletSigningSessionId` separate from curve-specific `thresholdSessionId` values.
2. Model a `WalletSigningSession` record with:
   - `walletSigningSessionId`
   - `walletId` / account id
   - `authMethod`
   - `policy`
   - `expiresAtMs`
   - `remainingUses`
   - `signingRootId`
   - revocation / consumed state
3. Keep Ed25519 and ECDSA threshold capabilities curve-specific, but require both to reference the same `walletSigningSessionId` for a wallet unlock/session.
4. Keep server-side enforcement authoritative for TTL, remaining uses, revocation, and abuse controls.
5. Keep client-side worker/session state authoritative only for in-memory secret lifecycle and prompt readiness.
6. Treat server-issued policy and counters as upper bounds; the client may clear earlier but must not extend TTL or uses.
7. Keep export/link-device operation auth separate from `walletSigningSessionId` so sensitive operations cannot clobber transaction signing state.

Todo:

1. [x] Add `walletSigningSessionId` to Ed25519 and ECDSA session metadata records and key refs.
2. [x] Add a wallet-level signing-session store or extend the existing threshold auth-session stores so Ed25519 and ECDSA consume one server-authoritative budget.
3. [x] Update Email OTP bootstrap to mint one wallet signing session during wallet unlock, then attach both Ed25519 and ECDSA threshold sessions to it.
4. [x] Update passkey warm-session bootstrap to use the same wallet signing-session budget abstraction.
5. [x] Update the Email OTP worker warm-session model so secret-bearing Ed25519 and ECDSA material remains separate, but both check and consume the same `walletSigningSessionId` budget.
6. [x] Update `WarmSessionManager` to resolve readiness from the wallet signing session first, then curve-specific capability readiness second.
7. [x] Update NEAR Ed25519 transaction signing to consume from the shared wallet budget instead of only the Ed25519 threshold session counter.
8. [x] Update EVM, Tempo, and Arc ECDSA transaction signing to consume from the shared wallet budget instead of only the ECDSA threshold session counter.
9. [x] Update Tx Confirmer routing so shared-budget exhaustion produces auth-method-specific reauth instead of generic session-not-ready errors.
10. [x] Ensure Email OTP exhausted-session reauth opens the Tx Confirmer OTP input and dispatches a transaction-sign Email OTP challenge.
11. [x] Ensure passkey exhausted-session reauth opens WebAuthn/passkey confirmation.
12. [x] Ensure export Ed25519 and export ECDSA use fresh operation-scoped auth and do not mutate `walletSigningSessionId`, `remainingUses`, or transaction-session worker material.
13. [ ] Ensure link-device/add-signer flows use fresh operation-scoped auth and do not mutate the transaction signing session unless the operation explicitly creates/replaces a signer.
14. [x] Add unit tests proving Ed25519 and ECDSA resolve against the same wallet signing-session budget.
15. [ ] Add unit tests proving TTL expiry invalidates both Ed25519 and ECDSA capabilities.
16. [ ] Add unit tests proving export and link-device auth do not clobber the active wallet signing session.
17. [ ] Add Tx Confirmer tests proving Email OTP exhausted sessions show OTP UI and passkey exhausted sessions show WebAuthn UI.
18. [ ] Add E2E coverage for Email OTP shared-budget exhaustion:
    - register/login with Google SSO + Email OTP
    - sign at least one NEAR Ed25519 transaction
    - sign at least one Tempo ECDSA transaction
    - sign at least one Arc ECDSA transaction
    - exhaust the shared `walletSigningSessionId` budget across those signers
    - assert the next NEAR, Tempo, and Arc sign attempts open the Tx Confirmer Email OTP prompt
    - assert the server dispatches/logs a transaction-sign Email OTP challenge for the reauth
19. [ ] Add E2E coverage for passkey shared-budget exhaustion:
    - register/login with passkey
    - sign at least one NEAR Ed25519 transaction
    - sign at least one Tempo ECDSA transaction
    - sign at least one Arc ECDSA transaction
    - exhaust the shared `walletSigningSessionId` budget across those signers
    - assert the next NEAR, Tempo, and Arc sign attempts open the WebAuthn/passkey prompt
    - assert Email OTP UI is not shown unless the account has explicitly enabled Email OTP fallback and project policy allows it
20. [ ] Add E2E coverage proving Ed25519 and ECDSA key export do not clobber a still-valid transaction signing session:
    - login with an active transaction signing session
    - export Ed25519 with fresh operation-scoped auth
    - sign another NEAR transaction without reauth if the original transaction budget remains valid
    - export ECDSA with fresh operation-scoped auth
    - sign another Tempo and Arc transaction without reauth if the original transaction budget remains valid
    - assert export auth uses a separate operation-scoped session and does not replace `walletSigningSessionId`
21. [ ] Add E2E coverage proving Email OTP-only normal transaction reauth never opens WebAuthn:
    - login with an Email OTP-only account
    - exhaust or expire the transaction signing session
    - attempt NEAR, Tempo, and Arc signing
    - assert each flow opens the Tx Confirmer Email OTP prompt
    - assert no WebAuthn/passkey prompt is opened for normal transaction signing
22. [ ] Add E2E coverage for full link-device/add-signer operation-scoped auth isolation:
    - start with a valid transaction signing session
    - run link-device/add-signer with fresh operation-scoped auth
    - assert the operation does not decrement, replace, or invalidate the active transaction `walletSigningSessionId`
    - assert the newly linked signer is visible only after successful operation finalization
    - assert failed or canceled operation-scoped auth does not mutate the wallet signing session or signer list
23. [x] Update `docs/sso-otp-shamir3pass-signing.md` to specify that Email OTP `session` mode creates one wallet-level signing-session budget shared by Ed25519 and ECDSA.
24. [x] Update `docs/signing-sessions.md` to define `walletSigningSessionId`, how it differs from `app_session` and curve-specific `threshold_session`, and which routes consume it.
25. [x] Update this plan after implementation with the exact files and tests that enforce the invariant.

Implementation notes:

1. `walletSigningSessionId` is now carried through Ed25519 and ECDSA client session metadata, key refs, Email OTP worker bootstrap payloads, passkey warm-session bootstrap, relayer response parsing, and server session JWT claims.
2. Server-side Ed25519 and ECDSA session mint/authorize paths now attach to a shared wallet signing-session budget keyed by `walletSigningSessionId`; TTL and remaining-use consumption are enforced by the server as the authoritative source.
3. `WarmSessionManager` now scopes local readiness by `walletSigningSessionId` before curve-specific readiness, so a locally exhausted/expired wallet budget is reflected across Ed25519 and ECDSA capability status.
4. EVM-family signing now resolves the active signer auth method from local signer metadata before falling back to record heuristics. If a threshold ECDSA session expires or exhausts mid-sign, the flow retries once with fresh auth; Email OTP accounts open the OTP Tx Confirmer and passkey accounts continue to WebAuthn.
5. Export flows remain operation-scoped and do not reuse or replace the transaction-signing `walletSigningSessionId`.
6. `docs/sso-otp-shamir3pass-signing.md` and `docs/signing-sessions.md` now document the shared `walletSigningSessionId` budget and app-session vs threshold-session separation.

Verification:

1. `pnpm build:sdk` passes.
2. `pnpm -C tests exec playwright test ./unit/warmSessionManager.emailOtpPolicy.unit.test.ts ./unit/warmSessionReadModel.unit.test.ts --reporter=line` passes.
3. `pnpm -s type-check:sdk` still reports existing test-fixture drift around signer-slot/signing-root refactors, but not in the modified EVM signing path or `walletSigningSessionId` implementation.

Release gate:

This refactor is complete only when a single configured signing-session budget can be consumed in any mix of NEAR Ed25519 and EVM/Tempo/Arc ECDSA transaction signing, and when sensitive operation auth cannot consume or replace that transaction-signing budget.

## Release Hardening TODO

Goal:

Move Email OTP from local/dev functional completeness to release-ready robustness. These tasks are not new product features; they are security, abuse-control, production-delivery, and regression-test hardening required before treating Google SSO + Email OTP as production-ready.

### Production Email Delivery

1. [ ] Replace the current development-only `email_provider` stub with a provider-backed adapter.
2. [ ] Keep `memory` and `log` OTP delivery modes restricted to local development and tests.
3. [ ] Fail production startup if Email OTP delivery is configured to a dev-only mode.
4. [ ] Add provider-adapter tests for successful send, provider failure, retry-safe error handling, and production-mode rejection of dev delivery.
5. [ ] Add relayer route tests proving OTP challenge creation reports delivery failures without creating unverifiable challenge state.

### OTP Code Format And Storage

1. [ ] Freeze first-release Email OTP codes to exactly six decimal digits everywhere.
2. [ ] Remove production support for configurable 7- or 8-digit OTP codes.
3. [ ] Validate submitted OTP codes as `^[0-9]{6}$` at every route and service verification boundary.
4. [ ] Add negative tests for empty, non-decimal, short, long, whitespace-padded, and Unicode digit inputs.
5. [ ] Stop storing plaintext OTP codes in challenge records.
6. [ ] Store a keyed OTP verifier instead of `otpCode` in primary challenge storage.
7. [ ] Use fixed-length, constant-time comparison for OTP verifier checks.
8. [ ] Preserve dev outbox/log visibility without storing plaintext OTP in the primary challenge record.
9. [ ] Replace modulo-based OTP digit generation with rejection sampling to avoid modulo bias.
10. [ ] Add deterministic tests for OTP format and statistical smoke tests around digit generation boundaries.

### Seal-Key And Server Custody Posture

1. [ ] Fail production startup if Email OTP server seal material is sourced only from plaintext `SIGNING_SESSION_SEAL_E_S_B64U` or `SIGNING_SESSION_SEAL_D_S_B64U` env vars.
2. [ ] Add a KMS/HSM/equivalent resolver for production Email OTP server seal material.
3. [ ] Keep plaintext seal-key config available only for local development, tests, and bootstrap environments.
4. [ ] Add config tests proving production rejects plaintext-seal-key-only configuration.
5. [ ] Add key-version handling tests for active, previous, and unknown seal-key versions.
6. [ ] Add audit events for seal apply/remove, key-version mismatch, and seal-key resolver failures.

### Signing-Root And Session Binding

1. [ ] Bind Email OTP challenge, grant, enrollment, and unlock-challenge records to the final signing-root scope.
2. [ ] Bind verification and grant consumption to `userId`, `walletId`, signing root, stable app-session hash, session version, and operation.
3. [ ] Add mismatch tests for cross-project, cross-environment, stale-session, wrong-wallet, wrong-user, and wrong-operation attempts.
4. [ ] Ensure client-supplied binding metadata is treated only as an assertion and is checked against server-derived session state.
5. [ ] Add route-level negative tests for app-session JWTs presented to threshold-session routes and threshold-session JWTs presented to app-session Email OTP routes.

### Worker Boundary And Secret Material

1. [ ] Audit all active Email OTP paths for plaintext `S`, `signing_session_secret32`, `clientRootShare32`, `clientAdditiveShare32B64u`, and equivalent secret-derived share material crossing into the JS main thread.
2. [ ] Move any remaining Email OTP-derived secret material behind worker-owned opaque handles unless there is a documented temporary compatibility exception.
3. [ ] If a compatibility exception remains, document the owner, transfer path, lifetime, single-use semantics, and zeroization point in the Email OTP specs.
4. [ ] Add tests proving app-origin iframe flows never receive recovered `S`, `clientRootShare32`, `clientAdditiveShare32B64u`, or equivalent secret-derived share strings.
5. [ ] Add zeroization tests for failed OTP verify, canceled transaction confirmation, expired session, logout, account switch, and worker teardown.

### Shared Wallet Signing Session Budget

1. [ ] Ensure link-device/add-signer flows use fresh operation-scoped auth and do not mutate the transaction signing session unless the operation explicitly creates or replaces a signer.
2. [ ] Add unit tests proving TTL expiry invalidates both Ed25519 and ECDSA capabilities tied to the same `walletSigningSessionId`.
3. [ ] Add unit tests proving export auth does not clobber the active wallet signing session.
4. [ ] Add unit tests proving link-device/add-signer auth does not clobber the active wallet signing session.
5. [ ] Add Tx Confirmer tests proving exhausted Email OTP sessions show OTP UI and exhausted passkey sessions show WebAuthn UI.
6. [ ] Add E2E coverage for shared-budget exhaustion across NEAR Ed25519, Tempo ECDSA, and Arc ECDSA for Email OTP accounts.
7. [ ] Add E2E coverage for shared-budget exhaustion across NEAR Ed25519, Tempo ECDSA, and Arc ECDSA for passkey accounts.
8. [ ] Add E2E coverage proving Ed25519 and ECDSA key export do not clobber a still-valid transaction signing session.
9. [ ] Add E2E coverage proving Email OTP-only normal transaction reauth never opens WebAuthn.
10. [ ] Add E2E coverage for full link-device/add-signer operation-scoped auth isolation.

### Google SSO Registration And Wallet Identity

1. [ ] Add E2E coverage for HMAC-readable Google SSO registration.
2. [ ] Add E2E coverage for existing-wallet login handoff.
3. [ ] Add E2E coverage for stale registration-attempt retry.
4. [ ] Add E2E coverage for wallet-id collision errors.
5. [ ] Add tests proving repeated Google SSO registration attempts do not create duplicate Email OTP accounts by default.
6. [ ] Keep raw email and timestamp-derived account IDs out of hosted Google SSO wallet-id generation.

### Wallet-Iframe And Storage Modes

1. [ ] Add E2E smoke coverage for wallet-iframe mode with app-origin IndexedDB disabled.
2. [ ] Add storage assertions proving app-origin IndexedDB does not contain Email OTP secret material.
3. [ ] Add storage assertions proving wallet-origin storage contains only nonsecret metadata and approved sealed-refresh artifacts.
4. [ ] Add reload tests for the current default behavior: Email OTP in-memory warm material is lost on refresh and routes to Email OTP reauth, not WebAuthn.
5. [ ] Keep the sealed-refresh feature tracked separately in `docs/otp-persist-session.md`; do not treat reload persistence as part of the current core release gate.

### OTP Resend And Abuse Controls

1. [ ] Add E2E coverage for transaction-signing OTP resend in `per_operation` mode.
2. [ ] Add resend tests proving multiple valid unexpired OTP codes can coexist when policy allows it.
3. [ ] Add resend debounce tests for UI cooldown behavior.
4. [ ] Add server rate-limit tests for challenge creation, resend, verify failure, verify success, and lockout reset.
5. [ ] Add abuse audit events for resend, rate-limit, lockout, replay, expired challenge, wrong operation, and wrong session.

### Release Gate Command Matrix

1. [ ] Define one documented local release-gate command matrix for Email OTP unit, relayer, wallet-iframe, and E2E tests.
2. [ ] Include SDK build in the release gate.
3. [ ] Include static guards for legacy PRF/seal/session names.
4. [ ] Include static guards for hard-coded Email OTP wire literals outside shared domain modules.
5. [ ] Include storage/secret-surface tests proving no plaintext `S`, `signing_session_secret32`, or enrollment escrow mirror is written to browser storage.

## ECDSA Signing-Root Binding Status

The persisted ECDSA HSS replay/reconstruction path now carries `signingRootId`
and optional `signingRootVersion` in the server finalize response, client key
ref, canonical session record, and persisted lane key. Stored rows whose lane
binding does not match the record binding are ignored before replay.

Recommendation:

1. Keep this separate from Email OTP auth polish because it is a custody-domain binding issue, not an OTP prompt or warm-session lifecycle issue.
2. Keep the binding tests as release gates for persisted ECDSA HSS signing/export, especially self-hosted or multi-project deployments.
3. Continue tracking follow-up hardening in the signer-slot/signing-root refactor lane.
4. Do not hide it behind a compatibility fallback; development can tolerate breaking schema/test updates.

Release-blocker tracking:

1. [x] Before enabling persisted ECDSA HSS replay/reconstruction in production, bind every persisted ECDSA HSS record to `signingRootId` and `signingRootVersion`.
2. [x] Reject persisted ECDSA HSS signing/export records when stored signing-root metadata differs from the authenticated runtime scope.
3. [x] Add fixtures and tests covering matching scope, mismatched `signingRootId`, mismatched `signingRootVersion`, missing metadata, and wrong account replay.

## Cleanup: JWT-Kind And Route Auth Boundaries

Root cause:

ECDSA Email OTP export uses two different authorization lanes:

1. Email OTP `export_key` challenge and verification are bound to fresh operation auth. During a live login this is normally app-session auth; after sealed refresh it may be requested through restored signing-session authority without reviving a JS-readable app-session JWT.
2. ECDSA HSS export prepare/respond/finalize are authorized by the threshold-session JWT.

See `docs/signing-sessions.md` for the canonical app-session vs threshold-session model and `docs/sso-otp-shamir3pass-signing.md` for the Email OTP flow diagram.

Using one generic `authorizationJwt` field made those lanes easy to confuse. The server then correctly rejected OTP and ECDSA export requests when a token from one lane was presented to a route that required the other lane.

Todo:

1. [x] Add shared JWT-kind helpers for app-session and threshold-session tokens.
2. [x] Remove unsafe `SigningEngine` fallbacks that substitute a threshold-session JWT where an app-session JWT is required, or substitute an app-session JWT where ECDSA HSS needs threshold-session authorization.
3. [x] Rename the active Email OTP / ECDSA HSS `authorizationJwt` plumbing to explicit route auth fields.
4. [x] Introduce discriminated auth objects at new/changed ECDSA HSS boundaries: `{ kind: 'app_session', jwt }`, `{ kind: 'threshold_session', jwt }`, `{ kind: 'cookie' }`, `{ kind: 'bootstrap_grant', token }`, and `{ kind: 'publishable_key', token }`.
5. [x] Add negative misuse tests proving app-session JWTs are rejected at threshold-session boundaries and threshold-session JWTs are rejected at app-session boundaries.
6. [x] Re-run focused Email OTP login/sign/export coverage for Ed25519 and ECDSA.
7. [x] Re-run focused relayer Email OTP route coverage for export-scoped challenge verification and refreshed app-session binding.
8. [x] Rebuild the SDK after the boundary rename.

## Cleanup: Domain Literal Constants

Recommendation:

1. Keep small local TypeScript-only discriminated unions when they are private to one function/module and are not parsed from JSON, persisted, or shared across router/client/server boundaries.
2. Replace repeated string unions with exported domain constants and derived types when the values are wire-level, persisted, audited, or shared across packages.
3. Prefer `as const` domain maps/arrays plus derived union types for most TypeScript code. Use a real `enum` only when runtime enum semantics are explicitly useful, such as generated API clients, Rust/WASM binding symmetry, or UI option iteration that benefits from a named runtime object.
4. Centralize parsers next to the domain constants so request handling cannot silently coerce unknown strings into defaults.
5. Use shared validation and normalization helpers from `shared/src/utils/validation.ts` and `shared/src/utils/normalize.ts` instead of redefining equivalent local helpers.
6. Treat Express and Cloudflare Email OTP route duplication as a drift risk; extract shared server helpers when the behavior must remain identical.

Todo:

1. [x] Add a shared Email OTP domain module with channel, login-operation, registration-operation, action constants, derived types, and parser predicates.
2. [x] Update the Email OTP request parser, export-policy audit payload, Express/Cloudflare export-policy routes, client Email OTP helper, AuthService challenge/verify path, and Email OTP store normalization to use shared Email OTP constants instead of local string unions.
3. [x] Finish auditing Email OTP domain literals and consolidate remaining server/client values such as `email_otp`, `wallet_unlock`, `transaction_sign`, `export_key`, `registration`, `wallet_email_otp_login`, and `wallet_email_otp_registration`.
        Email OTP wire surfaces now use shared `emailOtpDomain` constants and
        derived types across request parsing, AuthService challenge/verify,
        Express/Cloudflare session routes, threshold-ECDSA enrollment claim
        injection, client SDK auth APIs, wallet-iframe messages/router,
        SigningEngine Email OTP auth calls, and Email OTP worker message
        payloads.
4. [x] Audit wallet auth and signer-slot domain literals such as `passkey`, `session`, `email_otp`, `threshold-ed25519`, `threshold-ecdsa`, `passkey_registration`, and `email_otp_registration`; shared `signerDomain` now owns the wallet-auth method, wallet-auth proof method, signer kind, signer auth method, signer source, signing-session policy, and sensitive-operation policy domains.
5. [x] Update remaining router/client/server call sites to use the shared constants instead of repeated inline string unions.
        Guard coverage now includes server parser/store/routes plus client SDK,
        wallet-iframe, SigningEngine, and Email OTP worker boundaries, so
        shared wire literals cannot be reintroduced in those surfaces.
6. [x] Add a guard test preventing Email OTP parser/client/store modules from redeclaring shared Email OTP wire literal types.
7. [x] Add guard tests that fail on duplicated hard-coded literals in wallet auth-mode resolution and signer-slot lifecycle code.
8. [x] Avoid compatibility aliases for renamed values; this codebase is still in development, so breaking cleanup is preferred over legacy symbols.
        Email OTP route names, operation names, signer-slot names, and shared
        domain values now use the current names directly. No compatibility
        aliases were kept for renamed Email OTP/signing values; route aliases
        remain only for explicitly configurable route paths, not renamed
        request fields or legacy symbols.
9. [x] Decide whether any shared string-union domains should become real enums. Default to `as const` maps plus derived types; use enums only when runtime enum semantics are actually needed.
10. [x] Replace local helper copies such as `toOptionalTrimmedString`, `optionalClaimString`, local object/string guards, and equivalent normalizers with shared validation/normalization helpers where behavior matches.
        `optionalClaimString` was removed from
        both session routers and `relayWebhooks.ts` now imports shared string
        normalization. Matching non-array object guards now use shared
        `isPlainObject`; local helpers remain only where semantics differ or
        where the helper is the central router utility.
11. [x] Extract duplicated Email OTP server route logic shared by Express and Cloudflare: request validation, app-session claim extraction, export-policy authorization, audit payload construction, and response shaping.
        Completed slices: request parsing, export-policy authorization/audit
        payloads, status mapping, wallet-id claim extraction, Google OIDC
        detection, OIDC account-mode parsing, Email OTP wire constants, and
        Email OTP challenge response shaping are shared. The final pass also
        extracted stable app-session claim hashing used by both Express and
        Cloudflare routes. Future enrollment-finalize, unseal, or dev-outbox
        response shaping should be extracted only if those route bodies start
        drifting again.
12. [x] Add guard tests preventing route files from reintroducing local copies of generic validation or claim-normalization helpers.
